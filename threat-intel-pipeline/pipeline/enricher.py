"""
IoC enrichment module.

After collection, IoCs are enriched with contextual information:
  - IP geolocation and ASN data (ip-api.com — free, no key needed)
  - Domain WHOIS registration info (via RDAP — no key needed)
  - Hash lookups (VirusTotal free tier, if key configured)
  - CVE details (NVD API — no key needed for basic access)

Enrichment is best-effort: failures are logged but don't block ingestion.
Results are cached in memory to avoid hammering free APIs.
"""

import logging
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

import requests

from .models import IoC, IoCType, Severity

logger = logging.getLogger(__name__)

# ip-api free tier: 45 requests/minute, no key
IP_API_URL = "https://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,org,as,hosting,proxy,tor"
# RDAP for domain registration info
RDAP_URL = "https://rdap.org/domain/{domain}"
# NVD API for CVE details (rate-limited to 5 req/30s without key)
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RATE_LIMIT_DELAY = 1.5  # seconds between IP API calls


class Enricher:
    """
    Enriches IoCs with contextual threat data from free public APIs.
    Uses a simple in-memory LRU cache to minimize redundant API calls.
    """

    def __init__(self, config: dict):
        self.config = config
        self.vt_api_key: Optional[str] = config.get("virustotal_api_key")
        self.nvd_api_key: Optional[str] = config.get("nvd_api_key")
        self._session = requests.Session()
        self._session.headers["User-Agent"] = (
            "ThreatIntelPipeline/1.0 IoC-Enricher"
        )
        self._ip_cache: dict[str, dict] = {}
        self._last_ip_call: float = 0

    def enrich(self, ioc: IoC) -> IoC:
        """Enrich a single IoC in place. Returns the same object."""
        try:
            if ioc.type in (IoCType.IPV4, IoCType.IPV6):
                self._enrich_ip(ioc)
            elif ioc.type == IoCType.DOMAIN:
                self._enrich_domain(ioc)
            elif ioc.type in (IoCType.MD5, IoCType.SHA1, IoCType.SHA256):
                if self.vt_api_key:
                    self._enrich_hash_vt(ioc)
            elif ioc.type == IoCType.CVE:
                self._enrich_cve(ioc)
        except Exception as e:
            logger.debug("Enrichment failed for %s/%s: %s", ioc.type.value, ioc.value, e)
        return ioc

    def enrich_batch(self, iocs: list[IoC], max_enrichments: int = 500) -> list[IoC]:
        """
        Enrich a batch of IoCs.
        Limits total API calls to avoid rate-limiting free tiers.
        """
        enrichable = [
            ioc for ioc in iocs
            if ioc.type in (IoCType.IPV4, IoCType.DOMAIN, IoCType.CVE)
            or (ioc.type in (IoCType.MD5, IoCType.SHA256) and self.vt_api_key)
        ]
        to_enrich = enrichable[:max_enrichments]

        logger.info("Enriching %d IoCs (of %d total)", len(to_enrich), len(iocs))
        for ioc in to_enrich:
            self.enrich(ioc)

        return iocs

    # ------------------------------------------------------------------
    # IP enrichment
    # ------------------------------------------------------------------

    def _enrich_ip(self, ioc: IoC) -> None:
        if "/" in ioc.value:
            return  # skip CIDR blocks

        ip = ioc.value
        if ip in self._ip_cache:
            data = self._ip_cache[ip]
        else:
            # Respect rate limit
            elapsed = time.time() - self._last_ip_call
            if elapsed < RATE_LIMIT_DELAY:
                time.sleep(RATE_LIMIT_DELAY - elapsed)

            resp = self._session.get(
                IP_API_URL.format(ip=ip), timeout=10
            )
            self._last_ip_call = time.time()
            if resp.status_code != 200:
                return
            data = resp.json()
            if data.get("status") != "success":
                return
            self._ip_cache[ip] = data

        ioc.country = data.get("countryCode") or data.get("country")
        ioc.asn = data.get("as")
        ioc.asn_org = data.get("org")
        ioc.hosting_provider = "hosting" if data.get("hosting") else None

        # Adjust confidence/severity for Tor exit nodes
        if data.get("tor"):
            ioc.tags = list(set(ioc.tags + ["tor"]))

        # Hosting providers often used for C2/phishing
        if data.get("hosting") and ioc.confidence < 70:
            ioc.confidence = min(ioc.confidence + 10, 100)

    # ------------------------------------------------------------------
    # Domain enrichment
    # ------------------------------------------------------------------

    def _enrich_domain(self, ioc: IoC) -> None:
        domain = ioc.value
        try:
            resp = self._session.get(
                RDAP_URL.format(domain=domain), timeout=10
            )
            if resp.status_code != 200:
                return
            data = resp.json()
        except Exception:
            return

        # Extract registrar
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcards = entity.get("vcardArray", [None, []])[1]
                for card in vcards:
                    if card[0] == "fn":
                        ioc.registrar = card[3]
                        break

        # Extract registration dates
        events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}
        if "registration" in events and not ioc.first_seen:
            try:
                ioc.first_seen = datetime.fromisoformat(
                    events["registration"].rstrip("Z")
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        # Newly registered domains (< 30 days) are suspicious
        if ioc.first_seen:
            age_days = (datetime.now(timezone.utc) - ioc.first_seen).days
            if age_days < 30:
                ioc.tags = list(set(ioc.tags + ["newly-registered-domain"]))
                ioc.confidence = min(ioc.confidence + 15, 100)
                if ioc.severity == Severity.LOW:
                    ioc.severity = Severity.MEDIUM

    # ------------------------------------------------------------------
    # Hash enrichment (VirusTotal)
    # ------------------------------------------------------------------

    def _enrich_hash_vt(self, ioc: IoC) -> None:
        if not self.vt_api_key:
            return

        headers = {"x-apikey": self.vt_api_key}
        url = f"https://www.virustotal.com/api/v3/files/{ioc.value}"
        resp = self._session.get(url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return
        if resp.status_code == 429:
            logger.warning("VirusTotal rate limit hit")
            return
        resp.raise_for_status()

        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        if total > 0:
            vt_confidence = int((malicious / total) * 100)
            ioc.confidence = max(ioc.confidence, vt_confidence)

        popular_name = data.get("popular_threat_classification", {})
        if popular_name:
            suggested = popular_name.get("suggested_threat_label", "")
            if suggested and not ioc.malware_family:
                ioc.malware_family = suggested.split(".")[0]

        names = data.get("names", [])
        if names:
            ioc.tags = list(set(ioc.tags + names[:3]))

        if malicious >= 10:
            ioc.severity = Severity.HIGH
        elif malicious >= 5:
            ioc.severity = Severity.MEDIUM

    # ------------------------------------------------------------------
    # CVE enrichment (NVD API)
    # ------------------------------------------------------------------

    def _enrich_cve(self, ioc: IoC) -> None:
        params = {"cveId": ioc.value}
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        resp = self._session.get(NVD_URL, params=params, headers=headers, timeout=15)
        if resp.status_code == 404:
            return
        if resp.status_code == 429:
            logger.warning("NVD rate limit hit — consider getting a free API key")
            return
        resp.raise_for_status()

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return

        cve_data = vulns[0].get("cve", {})
        metrics = cve_data.get("metrics", {})

        # Prefer CVSSv3.1, fall back to v3.0, then v2
        cvss_score: Optional[float] = None
        for version in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(version, [])
            if entries:
                cvss_score = entries[0].get("cvssData", {}).get("baseScore")
                break
        if cvss_score is None:
            entries = metrics.get("cvssMetricV2", [])
            if entries:
                cvss_score = entries[0].get("cvssData", {}).get("baseScore")

        if cvss_score is not None:
            if cvss_score >= 9.0:
                ioc.severity = Severity.CRITICAL
                ioc.confidence = max(ioc.confidence, 90)
            elif cvss_score >= 7.0:
                ioc.severity = Severity.HIGH
            elif cvss_score >= 4.0:
                ioc.severity = Severity.MEDIUM
            ioc.tags = list(set(ioc.tags + [f"cvss:{cvss_score}"]))

        # Extract CWE for TTP context
        weaknesses = cve_data.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                cwe = desc.get("value", "")
                if cwe.startswith("CWE-"):
                    ioc.tags = list(set(ioc.tags + [cwe]))
