"""
Abuse.ch collectors — three separate feeds from the same organization.

ThreatFox  – malware IoCs with confidence scores (IPs, domains, URLs, hashes)
URLhaus    – malicious URLs actively distributing malware
MalwareBazaar – malware sample hashes with family classification

All three are free, require no API key, and return JSON.
Docs: https://threatfox.abuse.ch/api/  https://urlhaus-api.abuse.ch/
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from ..models import IoC, IoCType, Severity, ThreatType
from .base import BaseCollector

logger = logging.getLogger(__name__)


def _parse_datetime(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(s.replace(" UTC", ""), fmt.replace(" UTC", ""))
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _confidence_to_severity(confidence: int) -> Severity:
    if confidence >= 80:
        return Severity.HIGH
    elif confidence >= 50:
        return Severity.MEDIUM
    return Severity.LOW


THREATFOX_TYPE_MAP = {
    "ip:port": IoCType.IPV4,
    "domain": IoCType.DOMAIN,
    "url": IoCType.URL,
    "md5_hash": IoCType.MD5,
    "sha256_hash": IoCType.SHA256,
}

THREAT_TYPE_MAP = {
    "botnet_cc": ThreatType.C2,
    "payload": ThreatType.MALWARE,
    "payload_delivery": ThreatType.MALWARE,
    "c2": ThreatType.C2,
    "phishing": ThreatType.PHISHING,
}


class ThreatFoxCollector(BaseCollector):
    """
    Abuse.ch ThreatFox — pulls the last N days of IoCs.
    Free API, no key required for basic access.
    """

    API_URL = "https://threatfox-api.abuse.ch/api/v1/"

    @property
    def name(self) -> str:
        return "abusech_threatfox"

    @property
    def description(self) -> str:
        return "Abuse.ch ThreatFox — malware IoCs with confidence scores"

    def collect(self) -> list[IoC]:
        days = self.config.get("lookback_days", 3)
        payload = {"query": "get_iocs", "days": days}
        resp = self.post(self.API_URL, json=payload)
        data = resp.json()

        if data.get("query_status") != "ok":
            logger.warning("[%s] Unexpected status: %s", self.name, data.get("query_status"))
            return []

        iocs: list[IoC] = []
        for entry in data.get("data", []) or []:
            ioc_type_raw = entry.get("ioc_type", "")
            ioc_type = THREATFOX_TYPE_MAP.get(ioc_type_raw)
            if not ioc_type:
                continue

            value = entry.get("ioc", "").strip()
            # ThreatFox stores IP:port — we strip the port for the IP type
            if ioc_type == IoCType.IPV4 and ":" in value:
                value = value.split(":")[0]

            if not value:
                continue

            confidence = entry.get("confidence_level", 50)
            threat_type_raw = entry.get("threat_type", "")
            threat_type = THREAT_TYPE_MAP.get(threat_type_raw, ThreatType.MALWARE)

            tags = entry.get("tags") or []
            malware = entry.get("malware", None)
            if malware:
                # normalize "Win.Ransomware.Conti" → "Conti"
                malware = malware.split(".")[-1] if "." in malware else malware

            ioc = IoC(
                type=ioc_type,
                value=value,
                source_feed=self.name,
                source_id=str(entry.get("id", "")),
                threat_type=threat_type,
                malware_family=malware,
                tags=tags if isinstance(tags, list) else [],
                confidence=confidence,
                severity=_confidence_to_severity(confidence),
                first_seen=_parse_datetime(entry.get("first_seen")),
                last_seen=_parse_datetime(entry.get("last_seen")),
                raw=entry,
            )
            iocs.append(ioc)

        logger.info("[%s] Parsed %d IoCs from %d-day lookback", self.name, len(iocs), days)
        return iocs


class URLhausCollector(BaseCollector):
    """
    Abuse.ch URLhaus — active malware distribution URLs.
    Uses the recent-URL CSV export (no API key needed).
    """

    # Returns the last ~1000 active URLs as JSON
    API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/"

    @property
    def name(self) -> str:
        return "abusech_urlhaus"

    @property
    def description(self) -> str:
        return "Abuse.ch URLhaus — active malware distribution URLs"

    def collect(self) -> list[IoC]:
        resp = self.post(self.API_URL)
        data = resp.json()

        if data.get("query_status") != "ok":
            return []

        iocs: list[IoC] = []
        for entry in data.get("urls", []) or []:
            if entry.get("url_status") != "online":
                continue  # skip already-offline URLs

            url = entry.get("url", "").strip()
            if not url:
                continue

            tags = entry.get("tags") or []
            threat = entry.get("threat", "malware_download")
            malware = entry.get("url_info", {}).get("filename") if entry.get("url_info") else None

            ioc = IoC(
                type=IoCType.URL,
                value=url,
                source_feed=self.name,
                source_id=entry.get("id"),
                threat_type=ThreatType.MALWARE,
                malware_family=malware,
                tags=tags if isinstance(tags, list) else [],
                confidence=75,
                severity=Severity.HIGH,
                first_seen=_parse_datetime(entry.get("date_added")),
                last_seen=_parse_datetime(entry.get("last_online")),
                raw=entry,
            )
            iocs.append(ioc)

        logger.info("[%s] Parsed %d active URLs", self.name, len(iocs))
        return iocs


class MalwareBazaarCollector(BaseCollector):
    """
    Abuse.ch MalwareBazaar — malware sample hashes with family tags.
    Returns last 100 samples from the recent-samples endpoint.
    """

    API_URL = "https://mb-api.abuse.ch/api/v1/"

    @property
    def name(self) -> str:
        return "abusech_malwarebazaar"

    @property
    def description(self) -> str:
        return "Abuse.ch MalwareBazaar — malware sample SHA256 hashes"

    def collect(self) -> list[IoC]:
        # Get most recent 100 samples
        resp = self.post(self.API_URL, data={"query": "get_recent", "selector": "100"})
        data = resp.json()

        if data.get("query_status") != "ok":
            return []

        iocs: list[IoC] = []
        for entry in data.get("data", []) or []:
            sha256 = entry.get("sha256_hash", "").strip()
            if not sha256:
                continue

            tags = entry.get("tags") or []
            malware = entry.get("signature") or entry.get("file_type_mime")
            file_type = entry.get("file_type", "")

            # Also emit MD5 if present
            for hash_type, hash_val in [
                (IoCType.SHA256, sha256),
                (IoCType.MD5, entry.get("md5_hash", "")),
                (IoCType.SHA1, entry.get("sha1_hash", "")),
            ]:
                if not hash_val:
                    continue
                ioc = IoC(
                    type=hash_type,
                    value=hash_val.lower(),
                    source_feed=self.name,
                    source_id=entry.get("sha256_hash"),
                    threat_type=ThreatType.MALWARE,
                    malware_family=malware,
                    tags=tags if isinstance(tags, list) else [],
                    confidence=85,
                    severity=Severity.HIGH,
                    first_seen=_parse_datetime(entry.get("first_seen")),
                    last_seen=_parse_datetime(entry.get("last_seen")),
                    raw=entry if hash_type == IoCType.SHA256 else None,
                )
                iocs.append(ioc)

        logger.info("[%s] Parsed %d hashes", self.name, len(iocs))
        return iocs
