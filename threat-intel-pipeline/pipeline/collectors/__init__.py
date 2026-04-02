"""
Threat intelligence feed collectors.

Each collector inherits from BaseCollector and returns list[IoC].
Add new collectors here and register them in config/feeds.yaml.
"""

from .abusech_collector import MalwareBazaarCollector, ThreatFoxCollector, URLhausCollector
from .base import BaseCollector
from .cisa_collector import CISAAlertCollector, CISAKEVCollector
from .emerging_threats_collector import EmergingThreatsCollector
from .misp_collector import MISPInstanceCollector, MISPPublicFeedCollector
from .otx_collector import OTXCollector, OTXDirectPulseCollector

__all__ = [
    "BaseCollector",
    "ThreatFoxCollector",
    "URLhausCollector",
    "MalwareBazaarCollector",
    "CISAKEVCollector",
    "CISAAlertCollector",
    "EmergingThreatsCollector",
    "MISPPublicFeedCollector",
    "MISPInstanceCollector",
    "OTXCollector",
    "OTXDirectPulseCollector",
]

# Registry: feed_name → collector class
COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    "abusech_threatfox": ThreatFoxCollector,
    "abusech_urlhaus": URLhausCollector,
    "abusech_malwarebazaar": MalwareBazaarCollector,
    "cisa_kev": CISAKEVCollector,
    "cisa_alerts": CISAAlertCollector,
    "emerging_threats": EmergingThreatsCollector,
    "misp_public": MISPPublicFeedCollector,
    "misp_instance": MISPInstanceCollector,
    "alienvault_otx": OTXCollector,
    "alienvault_otx_direct": OTXDirectPulseCollector,
}
