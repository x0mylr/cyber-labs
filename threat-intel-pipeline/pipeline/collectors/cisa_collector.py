"""
CISA (Cybersecurity and Infrastructure Security Agency) collectors.

Two feeds:
  1. Known Exploited Vulnerabilities (KEV) catalog
     — CVEs that CISA has confirmed are actively exploited in the wild.
       Federal agencies MUST patch these; high-value for any org.
     URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

  2. CISA Alerts / Advisories (AA series)
     — Structured threat intelligence for nation-state campaigns,
       critical infrastructure attacks, etc.
     RSS: https://www.cisa.gov/uscert/ncas/alerts.xml

No API key required.
"""

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

from ..models import IoC, IoCType, Severity, ThreatType
from .base import BaseCollector

logger = logging.getLogger(__name__)

RANSOMWARE_FAMILIES = {
    "LockBit", "BlackCat", "ALPHV", "Hive", "Conti", "REvil", "DarkSide",
    "Vice Society", "Royal", "BianLian", "Clop", "Play", "8Base", "Akira",
    "Black Basta", "Rhysida", "Hunters International", "Medusa",
}


def _cvss_to_severity(cvss: Optional[float]) -> Severity:
    if cvss is None:
        return Severity.HIGH  # KEV entries are at least HIGH by definition
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


class CISAKEVCollector(BaseCollector):
    """
    CISA Known Exploited Vulnerabilities catalog.
    Returns CVE IoCs enriched with patch-by dates and affected vendor/product.
    """

    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    @property
    def name(self) -> str:
        return "cisa_kev"

    @property
    def description(self) -> str:
        return "CISA KEV — actively exploited CVEs requiring mandatory patching"

    def collect(self) -> list[IoC]:
        resp = self.get(self.FEED_URL)
        data = resp.json()

        # Optionally limit to vulns added within the last N days
        lookback_days = self.config.get("lookback_days", 30)
        cutoff: Optional[datetime] = None
        if lookback_days:
            from datetime import timedelta
            cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)

        iocs: list[IoC] = []
        for entry in data.get("vulnerabilities", []):
            cve_id = entry.get("cveID", "").strip()
            if not cve_id:
                continue

            date_added_str = entry.get("dateAdded", "")
            date_added: Optional[datetime] = None
            if date_added_str:
                try:
                    date_added = datetime.strptime(date_added_str, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    pass

            if cutoff and date_added and date_added < cutoff:
                continue

            due_date_str = entry.get("dueDate", "")
            due_date: Optional[datetime] = None
            if due_date_str:
                try:
                    due_date = datetime.strptime(due_date_str, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    pass

            vendor = entry.get("vendorProject", "")
            product = entry.get("product", "")
            notes = entry.get("notes", "")
            ransomware_use = entry.get("knownRansomwareCampaignUse", "Unknown")

            tags = [vendor, product]
            tags = [t for t in tags if t]

            # Known ransomware use bumps severity to critical
            severity = Severity.CRITICAL if ransomware_use == "Known" else Severity.HIGH

            # Look for known ransomware family mentions
            malware_family = None
            combined_text = f"{notes} {entry.get('shortDescription', '')}".lower()
            for family in RANSOMWARE_FAMILIES:
                if family.lower() in combined_text:
                    malware_family = family
                    break

            threat_type = (
                ThreatType.RANSOMWARE if ransomware_use == "Known" else ThreatType.EXPLOIT
            )

            ioc = IoC(
                type=IoCType.CVE,
                value=cve_id,
                source_feed=self.name,
                source_id=cve_id,
                threat_type=threat_type,
                malware_family=malware_family,
                tags=tags,
                confidence=95,  # CISA-confirmed exploited = very high confidence
                severity=severity,
                first_seen=date_added,
                expiry=due_date,  # patch deadline used as expiry signal
                raw={
                    "vendorProject": vendor,
                    "product": product,
                    "shortDescription": entry.get("shortDescription", ""),
                    "dueDate": due_date_str,
                    "knownRansomwareCampaignUse": ransomware_use,
                    "notes": notes,
                },
            )
            iocs.append(ioc)

        logger.info("[%s] Parsed %d KEV entries", self.name, len(iocs))
        return iocs


class CISAAlertCollector(BaseCollector):
    """
    CISA Cybersecurity Alerts RSS feed.
    Extracts CVEs and keywords mentioned in official advisories.
    """

    RSS_URL = "https://www.cisa.gov/uscert/ncas/alerts.xml"

    @property
    def name(self) -> str:
        return "cisa_alerts"

    @property
    def description(self) -> str:
        return "CISA Cybersecurity Alerts — US-CERT advisory feed"

    def collect(self) -> list[IoC]:
        import re
        resp = self.get(self.RSS_URL)
        root = ET.fromstring(resp.content)
        ns = ""

        # RSS 2.0 items
        channel = root.find("channel")
        if channel is None:
            return []

        iocs: list[IoC] = []
        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

        for item in list(channel.findall("item"))[:self.config.get("max_items", 20)]:
            title = (item.findtext("title") or "").strip()
            description = (item.findtext("description") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date_str = item.findtext("pubDate") or ""

            pub_date: Optional[datetime] = None
            if pub_date_str:
                try:
                    from email.utils import parsedate_to_datetime
                    pub_date = parsedate_to_datetime(pub_date_str).replace(tzinfo=timezone.utc)
                except Exception:
                    pass

            # Extract CVEs from the advisory text
            combined = f"{title} {description}"
            cves = list(set(cve_pattern.findall(combined)))
            for cve_id in cves:
                ioc = IoC(
                    type=IoCType.CVE,
                    value=cve_id.upper(),
                    source_feed=self.name,
                    source_id=link,
                    threat_type=ThreatType.EXPLOIT,
                    tags=["cisa-advisory"],
                    confidence=80,
                    severity=Severity.HIGH,
                    first_seen=pub_date,
                    raw={"title": title, "link": link},
                )
                iocs.append(ioc)

        logger.info("[%s] Extracted %d CVEs from alerts", self.name, len(iocs))
        return iocs
