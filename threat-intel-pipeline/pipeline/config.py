"""
Pipeline configuration loader.

Reads from:
  1. config/config.yaml — base configuration
  2. Environment variables — override any setting (12-factor app style)

Environment variables follow the pattern:
  TIPL_<SECTION>_<KEY>  e.g. TIPL_STORAGE_DB_PATH, TIPL_AGENT_MODEL
  ANTHROPIC_API_KEY     — Claude API key (standard env var)
  OTX_API_KEY           — AlienVault OTX key
  VT_API_KEY            — VirusTotal API key
  NVD_API_KEY           — NIST NVD API key
  MISP_URL              — Private MISP instance URL
  MISP_API_KEY          — Private MISP API key
"""

import logging
import os
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "storage": {
        "db_path": "data/threat_intel.db",
    },
    "scheduler": {
        "enabled": True,
        "interval_minutes": 60,
        "report_interval_hours": 6,
    },
    "api": {
        "host": "0.0.0.0",
        "port": 8000,
        "debug": False,
        "cors_origins": ["http://localhost:3000"],
    },
    "agent": {
        "model": "claude-opus-4-6",
        "fast_model": "claude-haiku-4-5-20251001",
        "report_lookback_hours": 24,
        "min_confidence": 50,
    },
    "enrichment": {
        "enabled": True,
        "max_per_run": 200,
        "virustotal_api_key": None,
        "nvd_api_key": None,
    },
    "collectors": {
        "abusech_threatfox": {
            "enabled": True,
            "lookback_days": 3,
        },
        "abusech_urlhaus": {
            "enabled": True,
        },
        "abusech_malwarebazaar": {
            "enabled": True,
        },
        "cisa_kev": {
            "enabled": True,
            "lookback_days": 30,
        },
        "cisa_alerts": {
            "enabled": True,
            "max_items": 20,
        },
        "emerging_threats": {
            "enabled": True,
            "feeds": ["compromised", "botcc", "block"],
        },
        "misp_public": {
            "enabled": True,
            "max_events_per_feed": 10,
            "include_all_attributes": False,
        },
        "misp_instance": {
            "enabled": False,
            "base_url": None,
            "api_key": None,
            "lookback_days": 7,
        },
        "alienvault_otx": {
            "enabled": False,  # requires API key
            "api_key": None,
            "lookback_days": 7,
            "max_pulses": 200,
        },
        "alienvault_otx_direct": {
            "enabled": False,
            "api_key": None,
            "pulse_ids": [],
        },
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        "file": None,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = base.copy()
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _apply_env_overrides(config: dict) -> dict:
    """Apply environment variable overrides."""
    # Standard well-known keys
    env_mappings = {
        "ANTHROPIC_API_KEY": ("agent", "anthropic_api_key"),
        "OTX_API_KEY": ("collectors", "alienvault_otx", "api_key"),
        "VT_API_KEY": ("enrichment", "virustotal_api_key"),
        "NVD_API_KEY": ("enrichment", "nvd_api_key"),
        "MISP_URL": ("collectors", "misp_instance", "base_url"),
        "MISP_API_KEY": ("collectors", "misp_instance", "api_key"),
        "TIPL_DB_PATH": ("storage", "db_path"),
        "TIPL_API_PORT": ("api", "port"),
        "TIPL_LOG_LEVEL": ("logging", "level"),
        "TIPL_SCHEDULE_MINUTES": ("scheduler", "interval_minutes"),
    }

    for env_var, path in env_mappings.items():
        val = os.environ.get(env_var)
        if val is None:
            continue

        # Navigate to the correct config section
        target = config
        for key in path[:-1]:
            target = target.setdefault(key, {})
        last_key = path[-1]

        # Type coercion
        existing = target.get(last_key)
        if isinstance(existing, int):
            try:
                val = int(val)
            except ValueError:
                pass
        elif isinstance(existing, bool):
            val = val.lower() in ("1", "true", "yes")

        target[last_key] = val

    # Auto-enable collectors when API keys are provided
    if config.get("collectors", {}).get("alienvault_otx", {}).get("api_key"):
        config["collectors"]["alienvault_otx"]["enabled"] = True
    if config.get("collectors", {}).get("misp_instance", {}).get("api_key"):
        config["collectors"]["misp_instance"]["enabled"] = True

    return config


def load_config(config_path: Optional[str] = None) -> dict:
    """
    Load configuration from YAML file and apply environment overrides.
    Falls back to defaults for any missing keys.
    """
    config = DEFAULT_CONFIG.copy()

    # Load from file if provided or auto-detected
    search_paths = [
        config_path,
        os.environ.get("TIPL_CONFIG"),
        "config/config.yaml",
        "/etc/threat-intel-pipeline/config.yaml",
    ]

    for path in search_paths:
        if not path:
            continue
        p = Path(path)
        if p.exists():
            try:
                with open(p) as f:
                    file_config = yaml.safe_load(f) or {}
                config = _deep_merge(config, file_config)
                logger.info("Loaded config from %s", p)
                break
            except Exception as e:
                logger.warning("Failed to load config from %s: %s", p, e)

    config = _apply_env_overrides(config)
    return config


def setup_logging(config: dict) -> None:
    log_cfg = config.get("logging", {})
    level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
    fmt = log_cfg.get("format", "%(asctime)s [%(levelname)s] %(name)s — %(message)s")

    handlers = [logging.StreamHandler()]
    log_file = log_cfg.get("file")
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)
    # Quiet noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
