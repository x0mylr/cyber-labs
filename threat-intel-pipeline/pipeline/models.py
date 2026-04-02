"""
Core data models for the threat intelligence pipeline.
All IoCs are normalized into a common schema before storage.
STIX 2.1 field names are used where applicable.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class IoCType(str, Enum):
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    DOMAIN = "domain-name"
    URL = "url"
    MD5 = "file:hashes.MD5"
    SHA1 = "file:hashes.SHA-1"
    SHA256 = "file:hashes.SHA-256"
    EMAIL = "email-addr"
    CVE = "vulnerability"
    CIDR = "ipv4-addr"  # treat CIDR blocks as IP type


class ThreatType(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    C2 = "command-and-control"
    BOTNET = "botnet"
    RANSOMWARE = "ransomware"
    EXPLOIT = "exploit"
    SCANNER = "scanner"
    SPAM = "spam"
    BRUTE_FORCE = "brute-force"
    DATA_EXFIL = "data-exfiltration"
    CRYPTOMINING = "cryptomining"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class IoC:
    """
    Normalized Indicator of Compromise.

    This is the canonical data model used throughout the pipeline.
    Fields map to STIX 2.1 where possible.
    """

    # Core identity
    type: IoCType
    value: str

    # Source metadata
    source_feed: str
    source_id: Optional[str] = None  # original ID in the source feed

    # Threat context
    threat_type: ThreatType = ThreatType.UNKNOWN
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    # Confidence and severity
    confidence: int = 50            # 0-100 scale
    severity: Severity = Severity.MEDIUM

    # Temporal
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expiry: Optional[datetime] = None

    # Enrichment fields (populated after collection)
    asn: Optional[str] = None
    asn_org: Optional[str] = None
    country: Optional[str] = None
    registrar: Optional[str] = None
    hosting_provider: Optional[str] = None

    # MITRE ATT&CK
    ttps: list[str] = field(default_factory=list)  # e.g. ["T1566.001", "T1059"]

    # Raw payload from source for audit trail
    raw: Optional[dict] = None

    # Pipeline-assigned
    ioc_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def fingerprint(self) -> str:
        """Deterministic ID based on type + value, used for deduplication."""
        key = f"{self.type.value}:{self.value.lower()}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_stix_indicator(self) -> dict:
        """
        Produce a minimal STIX 2.1 Indicator object.
        Full STIX serialization requires the stix2 library; this is a
        lightweight representation suitable for API responses.
        """
        pattern_map = {
            IoCType.IPV4: f"[ipv4-addr:value = '{self.value}']",
            IoCType.IPV6: f"[ipv6-addr:value = '{self.value}']",
            IoCType.DOMAIN: f"[domain-name:value = '{self.value}']",
            IoCType.URL: f"[url:value = '{self.value}']",
            IoCType.MD5: f"[file:hashes.MD5 = '{self.value}']",
            IoCType.SHA1: f"[file:hashes.'SHA-1' = '{self.value}']",
            IoCType.SHA256: f"[file:hashes.'SHA-256' = '{self.value}']",
            IoCType.EMAIL: f"[email-addr:value = '{self.value}']",
            IoCType.CVE: f"[vulnerability:name = '{self.value}']",
        }
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{self.ioc_id}",
            "name": f"{self.type.value}: {self.value}",
            "indicator_types": [self.threat_type.value],
            "pattern": pattern_map.get(self.type, f"[x-custom:value = '{self.value}']"),
            "pattern_type": "stix",
            "valid_from": (self.first_seen or self.ingested_at).isoformat(),
            "confidence": self.confidence,
            "labels": self.tags,
            "created": self.ingested_at.isoformat(),
            "modified": self.ingested_at.isoformat(),
            "x_source_feed": self.source_feed,
            "x_malware_family": self.malware_family,
            "x_severity": self.severity.value,
            "x_ttps": self.ttps,
        }


@dataclass
class ThreatReport:
    """
    AI-generated threat intelligence brief produced by the analysis agent.
    One report covers a batch of IoCs from a collection run.
    """

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    title: str = ""
    executive_summary: str = ""
    key_findings: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    ioc_count: int = 0
    source_feeds: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    severity_breakdown: dict = field(default_factory=dict)
    raw_analysis: str = ""
    model_used: str = ""


@dataclass
class FeedHealth:
    """Tracks the operational status of each feed collector."""

    feed_name: str
    last_run: Optional[datetime] = None
    last_success: Optional[datetime] = None
    iocs_collected: int = 0
    consecutive_failures: int = 0
    last_error: Optional[str] = None
    is_enabled: bool = True
