"""
Emerging Threats (Proofpoint ET) open-source threat intelligence feeds.

These are IP reputation lists published by Proofpoint's ET Labs team.
No API key required.

Available lists:
  - compromised-ips.txt  — IPs known to be compromised/actively attacking
  - tor.txt              — Tor exit nodes
  - fwip.txt             — Firewall block list (high confidence malicious IPs)

Full list: https://rules.emergingthreats.net/
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from ..models import IoC, IoCType, Severity, ThreatType
from .base import BaseCollector

logger = logging.getLogger(__name__)

# (url, threat_type, confidence, severity, tags, description)
ET_FEEDS = [
    (
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        ThreatType.MALWARE,
        75,
        Severity.HIGH,
        ["compromised", "emerging-threats"],
        "Compromised IPs actively attacking",
    ),
    (
        "https://rules.emergingthreats.net/blockrules/emerging-botcc.txt",
        ThreatType.C2,
        85,
        Severity.HIGH,
        ["botnet-c2", "emerging-threats"],
        "Botnet C2 servers",
    ),
    (
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        ThreatType.MALWARE,
        80,
        Severity.HIGH,
        ["block-list", "emerging-threats"],
        "High-confidence malicious IPs (firewall block list)",
    ),
    (
        "https://rules.emergingthreats.net/blockrules/tor.txt",
        ThreatType.UNKNOWN,
        60,
        Severity.LOW,
        ["tor", "anonymization", "emerging-threats"],
        "Tor exit nodes",
    ),
]

# Regex patterns
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
COMMENT_RE = re.compile(r"^\s*#")


class EmergingThreatsCollector(BaseCollector):
    """
    Collects IP reputation data from Emerging Threats open-source feeds.
    Handles both individual IPs and CIDR blocks.
    """

    @property
    def name(self) -> str:
        return "emerging_threats"

    @property
    def description(self) -> str:
        return "Proofpoint ET Labs — IP reputation and C2 blocklists"

    def _parse_ip_list(
        self,
        text: str,
        threat_type: ThreatType,
        confidence: int,
        severity: Severity,
        tags: list[str],
        feed_url: str,
    ) -> list[IoC]:
        iocs: list[IoC] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or COMMENT_RE.match(line):
                continue

            # Some lines have inline comments: "1.2.3.4 # country info"
            ip_part = line.split("#")[0].strip()
            if not IP_RE.match(ip_part):
                continue

            ioc = IoC(
                type=IoCType.CIDR if "/" in ip_part else IoCType.IPV4,
                value=ip_part,
                source_feed=self.name,
                source_id=None,
                threat_type=threat_type,
                tags=tags[:],
                confidence=confidence,
                severity=severity,
                ingested_at=datetime.now(timezone.utc),
                raw={"feed_url": feed_url},
            )
            iocs.append(ioc)
        return iocs

    def collect(self) -> list[IoC]:
        enabled_feeds = self.config.get("feeds", ["compromised", "botcc", "block"])
        feed_filter = {
            "compromised": ET_FEEDS[0],
            "botcc": ET_FEEDS[1],
            "block": ET_FEEDS[2],
            "tor": ET_FEEDS[3],
        }

        all_iocs: list[IoC] = []
        for key in enabled_feeds:
            feed = feed_filter.get(key)
            if not feed:
                continue
            url, threat_type, confidence, severity, tags, desc = feed
            try:
                resp = self.get(url)
                batch = self._parse_ip_list(
                    resp.text, threat_type, confidence, severity, tags, url
                )
                logger.info("[%s] %s → %d IPs", self.name, desc, len(batch))
                all_iocs.extend(batch)
            except Exception as e:
                logger.warning("[%s] Failed to fetch %s: %s", self.name, url, e)

        return all_iocs
