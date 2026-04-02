"""
Abstract base class for all threat intelligence feed collectors.

Each collector is responsible for:
  1. Fetching raw data from a specific feed
  2. Parsing the feed-specific format
  3. Returning a list of normalized IoC objects

Collectors are intentionally stateless — persistence is handled by Storage.
"""

import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

import requests

from ..models import FeedHealth, IoC

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30          # seconds per HTTP request
DEFAULT_USER_AGENT = (
    "ThreatIntelPipeline/1.0 (agentic threat intelligence aggregator; "
    "contact your-security-team@example.com)"
)


class BaseCollector(ABC):
    """
    All feed collectors inherit from this class.

    Subclasses must implement:
      - name (property)  – unique feed identifier used in storage
      - collect()        – fetch and parse the feed, return list[IoC]

    The run() method wraps collect() with error handling and health tracking.
    """

    def __init__(self, config: dict):
        self.config = config
        self.health = FeedHealth(feed_name=self.name)
        self._session: Optional[requests.Session] = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this feed, e.g. 'abusech_threatfox'."""
        ...

    @property
    def description(self) -> str:
        return f"Feed: {self.name}"

    @abstractmethod
    def collect(self) -> list[IoC]:
        """Fetch from the feed and return normalized IoCs."""
        ...

    @property
    def session(self) -> requests.Session:
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
            api_key = self.config.get("api_key")
            if api_key:
                self._configure_auth(self._session, api_key)
        return self._session

    def _configure_auth(self, session: requests.Session, api_key: str) -> None:
        """Override to set feed-specific auth headers."""
        pass

    def get(self, url: str, **kwargs) -> requests.Response:
        """GET with retry on transient failures."""
        timeout = self.config.get("timeout", DEFAULT_TIMEOUT)
        for attempt in range(3):
            try:
                resp = self.session.get(url, timeout=timeout, **kwargs)
                resp.raise_for_status()
                return resp
            except requests.exceptions.Timeout:
                logger.warning("[%s] Timeout on attempt %d for %s", self.name, attempt + 1, url)
                if attempt < 2:
                    time.sleep(2 ** attempt)
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    wait = int(e.response.headers.get("Retry-After", 60))
                    logger.warning("[%s] Rate limited, waiting %ds", self.name, wait)
                    time.sleep(wait)
                else:
                    raise
        raise requests.exceptions.ConnectionError(f"[{self.name}] All retry attempts failed for {url}")

    def post(self, url: str, **kwargs) -> requests.Response:
        """POST with basic retry."""
        timeout = self.config.get("timeout", DEFAULT_TIMEOUT)
        resp = self.session.post(url, timeout=timeout, **kwargs)
        resp.raise_for_status()
        return resp

    def run(self) -> tuple[list[IoC], FeedHealth]:
        """
        Execute the collector with health tracking.
        Always returns a FeedHealth record regardless of success/failure.
        """
        self.health.last_run = datetime.now(timezone.utc)
        try:
            logger.info("[%s] Starting collection", self.name)
            iocs = self.collect()
            self.health.last_success = datetime.now(timezone.utc)
            self.health.iocs_collected = len(iocs)
            self.health.consecutive_failures = 0
            self.health.last_error = None
            logger.info("[%s] Collected %d IoCs", self.name, len(iocs))
            return iocs, self.health
        except Exception as exc:
            self.health.consecutive_failures += 1
            self.health.last_error = str(exc)
            self.health.iocs_collected = 0
            logger.error("[%s] Collection failed: %s", self.name, exc, exc_info=True)
            return [], self.health

    def is_healthy(self) -> bool:
        return self.health.consecutive_failures < 3 and self.health.is_enabled
