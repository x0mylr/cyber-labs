"""
MISP (Malware Information Sharing Platform) feed collectors.

Two modes:
  1. Public MISP feeds (CIRCL, etc.) — no auth needed, fetch JSON directly
  2. Private MISP instance — requires API key and base URL

MISP is the de-facto standard for sharing structured threat intelligence
in ISACs, CERTs, and enterprise security teams. STIX 2.1, OpenIOC, and
MISP's own format are all supported.

Public OSINT feeds:
  - CIRCL OSINT feed: https://www.circl.lu/doc/misp/feed-osint/
  - MISP OSINT community feeds: various public sources
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from ..models import IoC, IoCType, Severity, ThreatType
from .base import BaseCollector

logger = logging.getLogger(__name__)

# MISP attribute type → our IoCType
MISP_TYPE_MAP = {
    "ip-src": IoCType.IPV4,
    "ip-dst": IoCType.IPV4,
    "ip-src|port": IoCType.IPV4,
    "ip-dst|port": IoCType.IPV4,
    "domain": IoCType.DOMAIN,
    "hostname": IoCType.DOMAIN,
    "domain|ip": IoCType.DOMAIN,
    "url": IoCType.URL,
    "md5": IoCType.MD5,
    "sha1": IoCType.SHA1,
    "sha256": IoCType.SHA256,
    "email": IoCType.EMAIL,
    "email-src": IoCType.EMAIL,
    "email-dst": IoCType.EMAIL,
    "vulnerability": IoCType.CVE,
}

# MISP category → threat type inference
CATEGORY_MAP = {
    "Network activity": ThreatType.C2,
    "Payload delivery": ThreatType.MALWARE,
    "Malware": ThreatType.MALWARE,
    "Payload installation": ThreatType.MALWARE,
    "C2": ThreatType.C2,
    "Phishing": ThreatType.PHISHING,
    "Email": ThreatType.PHISHING,
    "External analysis": ThreatType.MALWARE,
    "Artifacts dropped": ThreatType.MALWARE,
}


def _parse_misp_datetime(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        ts = int(s)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, TypeError):
        pass
    try:
        return datetime.fromisoformat(str(s).rstrip("Z")).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# Well-known public MISP feeds with good signal
PUBLIC_MISP_FEEDS = [
    {
        "name": "circl_osint",
        "url": "https://www.circl.lu/doc/misp/feed-osint/",
        "description": "CIRCL OSINT feed",
        "manifest_url": "https://www.circl.lu/doc/misp/feed-osint/manifest.json",
    },
]


class MISPPublicFeedCollector(BaseCollector):
    """
    Fetches IoCs from public MISP-format JSON feeds.
    Downloads the manifest, then fetches recent event files.
    """

    @property
    def name(self) -> str:
        return "misp_public"

    @property
    def description(self) -> str:
        return "MISP public OSINT feeds (CIRCL and community sources)"

    def _parse_misp_event(self, event_data: dict, feed_name: str) -> list[IoC]:
        iocs = []
        event = event_data.get("Event", event_data)
        event_info = event.get("info", "")
        event_tags = [t.get("name", "") for t in event.get("Tag", []) if t.get("name")]
        threat_level = event.get("threat_level_id", "2")  # 1=High,2=Med,3=Low,4=Undef

        severity_map = {"1": Severity.HIGH, "2": Severity.MEDIUM, "3": Severity.LOW}
        severity = severity_map.get(str(threat_level), Severity.MEDIUM)

        for attr in event.get("Attribute", []):
            attr_type = attr.get("type", "")
            ioc_type = MISP_TYPE_MAP.get(attr_type)
            if not ioc_type:
                continue

            value = attr.get("value", "").strip()
            if not value:
                continue

            # Handle "domain|ip" compound attributes — take the domain
            if "|" in value:
                value = value.split("|")[0].strip()
            # Handle "ip|port" — take the IP
            if attr_type in ("ip-src|port", "ip-dst|port") and "|" in value:
                value = value.split("|")[0].strip()

            category = attr.get("category", "")
            threat_type = CATEGORY_MAP.get(category, ThreatType.MALWARE)
            to_ids = attr.get("to_ids", False)

            # Only include attributes explicitly marked as IoCs (to_ids=True)
            # unless configured to include all
            if not to_ids and not self.config.get("include_all_attributes", False):
                continue

            attr_tags = [t.get("name", "") for t in attr.get("Tag", []) if t.get("name")]
            all_tags = list(set(event_tags + attr_tags))

            # Infer malware family from event info
            malware_family = None
            info_lower = event_info.lower()
            for keyword in ["ransomware", "trojan", "rat", "stealer", "loader", "banker"]:
                if keyword in info_lower:
                    words = event_info.split()
                    # Try to find the word before/after the keyword
                    for i, w in enumerate(words):
                        if keyword in w.lower() and i > 0:
                            malware_family = words[i - 1]
                            break
                    break

            ioc = IoC(
                type=ioc_type,
                value=value,
                source_feed=self.name,
                source_id=attr.get("uuid"),
                threat_type=threat_type,
                malware_family=malware_family,
                tags=all_tags,
                confidence=85 if to_ids else 50,
                severity=severity,
                first_seen=_parse_misp_datetime(attr.get("timestamp")),
                raw={"event_info": event_info, "category": category, "feed": feed_name},
            )
            iocs.append(ioc)
        return iocs

    def collect(self) -> list[IoC]:
        feeds_config = self.config.get("feeds", PUBLIC_MISP_FEEDS)
        max_events = self.config.get("max_events_per_feed", 10)
        all_iocs: list[IoC] = []

        for feed in feeds_config:
            manifest_url = feed.get("manifest_url") or feed.get("url", "").rstrip("/") + "/manifest.json"
            feed_name = feed.get("name", "unknown")

            try:
                resp = self.get(manifest_url)
                manifest = resp.json()
            except Exception as e:
                logger.warning("[%s] Failed to fetch manifest for %s: %s", self.name, feed_name, e)
                continue

            # Sort by timestamp descending to get recent events first
            events_sorted = sorted(
                manifest.items(),
                key=lambda x: x[1].get("timestamp", "0"),
                reverse=True,
            )[:max_events]

            base_url = feed.get("url", "").rstrip("/")
            for event_uuid, meta in events_sorted:
                event_url = f"{base_url}/{event_uuid}.json"
                try:
                    resp = self.get(event_url)
                    event_data = resp.json()
                    batch = self._parse_misp_event(event_data, feed_name)
                    all_iocs.extend(batch)
                except Exception as e:
                    logger.debug("[%s] Failed event %s: %s", self.name, event_uuid, e)

        logger.info("[%s] Collected %d IoCs from public MISP feeds", self.name, len(all_iocs))
        return all_iocs


class MISPInstanceCollector(BaseCollector):
    """
    Fetches IoCs from a private/corporate MISP instance.
    Requires MISP_URL and MISP_API_KEY in config.
    """

    @property
    def name(self) -> str:
        return "misp_instance"

    @property
    def description(self) -> str:
        return "Private MISP instance — internal threat sharing platform"

    def _configure_auth(self, session, api_key: str) -> None:
        session.headers.update({
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def collect(self) -> list[IoC]:
        base_url = self.config.get("base_url", "").rstrip("/")
        if not base_url or not self.config.get("api_key"):
            logger.info("[%s] No MISP instance configured — skipping", self.name)
            return []

        from datetime import timedelta
        lookback_days = self.config.get("lookback_days", 7)
        since_ts = int(
            (datetime.now(timezone.utc) - timedelta(days=lookback_days)).timestamp()
        )

        payload = {
            "returnFormat": "json",
            "timestamp": since_ts,
            "to_ids": True,
            "limit": self.config.get("limit", 1000),
        }

        try:
            resp = self.post(f"{base_url}/attributes/restSearch", json=payload)
            data = resp.json()
        except Exception as e:
            logger.error("[%s] API call failed: %s", self.name, e)
            return []

        all_iocs: list[IoC] = []
        for attr in data.get("response", {}).get("Attribute", []):
            ioc_type = MISP_TYPE_MAP.get(attr.get("type", ""))
            if not ioc_type:
                continue
            value = attr.get("value", "").strip()
            if not value:
                continue

            category = attr.get("category", "")
            threat_type = CATEGORY_MAP.get(category, ThreatType.MALWARE)

            ioc = IoC(
                type=ioc_type,
                value=value,
                source_feed=self.name,
                source_id=attr.get("uuid"),
                threat_type=threat_type,
                confidence=85,
                severity=Severity.HIGH,
                first_seen=_parse_misp_datetime(attr.get("timestamp")),
                raw={"category": category, "event_id": attr.get("event_id")},
            )
            all_iocs.append(ioc)

        logger.info("[%s] Collected %d IoCs from MISP instance", self.name, len(all_iocs))
        return all_iocs
