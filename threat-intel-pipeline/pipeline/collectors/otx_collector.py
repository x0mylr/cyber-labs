"""
AlienVault OTX (Open Threat Exchange) collector.

OTX is one of the largest open threat intelligence communities.
It provides:
  - IoC pulses from thousands of security researchers
  - Threat actor profiles
  - Malware family associations
  - MITRE ATT&CK TTP mapping

Free API key required: https://otx.alienvault.com/
Set OTX_API_KEY in your environment or config.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..models import IoC, IoCType, Severity, ThreatType
from .base import BaseCollector

logger = logging.getLogger(__name__)

OTX_TYPE_MAP = {
    "IPv4": IoCType.IPV4,
    "IPv6": IoCType.IPV6,
    "domain": IoCType.DOMAIN,
    "hostname": IoCType.DOMAIN,
    "URL": IoCType.URL,
    "FileHash-MD5": IoCType.MD5,
    "FileHash-SHA1": IoCType.SHA1,
    "FileHash-SHA256": IoCType.SHA256,
    "email": IoCType.EMAIL,
    "CVE": IoCType.CVE,
}

ADVERSARY_KEYWORDS = {
    "ransomware": ThreatType.RANSOMWARE,
    "phishing": ThreatType.PHISHING,
    "c2": ThreatType.C2,
    "botnet": ThreatType.BOTNET,
    "cryptomining": ThreatType.CRYPTOMINING,
    "miner": ThreatType.CRYPTOMINING,
    "exploit": ThreatType.EXPLOIT,
    "scan": ThreatType.SCANNER,
}


def _infer_threat_type(pulse: dict) -> ThreatType:
    text = " ".join([
        pulse.get("name", ""),
        pulse.get("description", ""),
        " ".join(pulse.get("tags", [])),
    ]).lower()
    for kw, tt in ADVERSARY_KEYWORDS.items():
        if kw in text:
            return tt
    return ThreatType.MALWARE


def _pulse_severity(pulse: dict) -> Severity:
    """Infer severity from pulse TLP and subscriber count."""
    tlp = pulse.get("tlp", "white").lower()
    if tlp == "red":
        return Severity.CRITICAL
    if tlp == "amber":
        return Severity.HIGH
    subscriber_count = pulse.get("subscriber_count", 0)
    if subscriber_count > 1000:
        return Severity.HIGH
    return Severity.MEDIUM


class OTXCollector(BaseCollector):
    """
    Pulls recent subscribed pulses from AlienVault OTX.
    Requires a free OTX API key.
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    @property
    def name(self) -> str:
        return "alienvault_otx"

    @property
    def description(self) -> str:
        return "AlienVault OTX — community threat intelligence pulses"

    def _configure_auth(self, session, api_key: str) -> None:
        session.headers["X-OTX-API-KEY"] = api_key

    def _get_pulses(self, since: datetime) -> list[dict]:
        """Fetch all pulses modified since the given datetime."""
        pulses = []
        url = f"{self.BASE_URL}/pulses/subscribed"
        params = {
            "modified_since": since.strftime("%Y-%m-%dT%H:%M:%S"),
            "limit": 50,
        }

        while url:
            resp = self.get(url, params=params)
            data = resp.json()
            pulses.extend(data.get("results", []))
            url = data.get("next")
            params = {}  # pagination URL already contains params

            if len(pulses) > self.config.get("max_pulses", 200):
                logger.info("[%s] Reached max_pulses limit", self.name)
                break

        return pulses

    def collect(self) -> list[IoC]:
        api_key = self.config.get("api_key")
        if not api_key:
            logger.warning("[%s] No OTX_API_KEY configured — skipping", self.name)
            return []

        lookback_days = self.config.get("lookback_days", 7)
        since = datetime.now(timezone.utc) - timedelta(days=lookback_days)

        pulses = self._get_pulses(since)
        logger.info("[%s] Fetched %d pulses", self.name, len(pulses))

        iocs: list[IoC] = []
        for pulse in pulses:
            threat_type = _infer_threat_type(pulse)
            severity = _pulse_severity(pulse)
            tags = pulse.get("tags", [])
            adversary = pulse.get("adversary") or None
            malware_families = pulse.get("malware_families", [])
            malware = malware_families[0].get("display_name") if malware_families else None
            ttps = [
                a.get("id", "")
                for a in pulse.get("attack_ids", [])
                if a.get("id")
            ]
            pulse_id = pulse.get("id", "")

            for indicator in pulse.get("indicators", []):
                ioc_type_raw = indicator.get("type", "")
                ioc_type = OTX_TYPE_MAP.get(ioc_type_raw)
                if not ioc_type:
                    continue

                value = indicator.get("indicator", "").strip()
                if not value:
                    continue

                created = indicator.get("created")
                expiry = indicator.get("expiration")

                ioc = IoC(
                    type=ioc_type,
                    value=value,
                    source_feed=self.name,
                    source_id=f"{pulse_id}:{indicator.get('id', '')}",
                    threat_type=threat_type,
                    malware_family=malware,
                    threat_actor=adversary,
                    tags=tags,
                    confidence=indicator.get("confidence", 70),
                    severity=severity,
                    first_seen=datetime.fromisoformat(created.rstrip("Z")).replace(
                        tzinfo=timezone.utc
                    ) if created else None,
                    expiry=datetime.fromisoformat(expiry.rstrip("Z")).replace(
                        tzinfo=timezone.utc
                    ) if expiry else None,
                    ttps=ttps,
                    raw={"pulse_name": pulse.get("name"), "pulse_id": pulse_id},
                )
                iocs.append(ioc)

        logger.info("[%s] Parsed %d IoCs from %d pulses", self.name, len(iocs), len(pulses))
        return iocs


class OTXDirectPulseCollector(BaseCollector):
    """
    Pulls IoCs from specific high-value OTX pulses by ID.
    Useful for targeting known-good intelligence sources like
    government CERTs and major security vendors.
    """

    BASE_URL = "https://otx.alienvault.com/api/v1"

    @property
    def name(self) -> str:
        return "alienvault_otx_direct"

    @property
    def description(self) -> str:
        return "AlienVault OTX — targeted high-value pulse collection"

    def _configure_auth(self, session, api_key: str) -> None:
        session.headers["X-OTX-API-KEY"] = api_key

    def collect(self) -> list[IoC]:
        api_key = self.config.get("api_key")
        if not api_key:
            return []

        pulse_ids: list[str] = self.config.get("pulse_ids", [])
        if not pulse_ids:
            logger.info("[%s] No pulse_ids configured", self.name)
            return []

        iocs: list[IoC] = []
        for pulse_id in pulse_ids:
            try:
                resp = self.get(f"{self.BASE_URL}/pulses/{pulse_id}/indicators")
                data = resp.json()
                for indicator in data.get("results", []):
                    ioc_type = OTX_TYPE_MAP.get(indicator.get("type", ""))
                    if not ioc_type:
                        continue
                    value = indicator.get("indicator", "").strip()
                    if not value:
                        continue
                    ioc = IoC(
                        type=ioc_type,
                        value=value,
                        source_feed=self.name,
                        source_id=f"{pulse_id}:{indicator.get('id', '')}",
                        confidence=75,
                        severity=Severity.MEDIUM,
                        raw={"pulse_id": pulse_id},
                    )
                    iocs.append(ioc)
            except Exception as e:
                logger.warning("[%s] Failed to fetch pulse %s: %s", self.name, pulse_id, e)

        return iocs
