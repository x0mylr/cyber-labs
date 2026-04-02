"""
Pipeline scheduler — orchestrates collection, enrichment, and analysis runs.

Runs two loops:
  1. Collection loop — fetches feeds every N minutes (default: 60)
  2. Report loop — triggers AI analysis every M hours (default: 6)

Designed to be lightweight enough to run continuously on a Raspberry Pi.
Uses threading (not asyncio) for simplicity and broad compatibility.
"""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from .collectors import COLLECTOR_REGISTRY
from .collectors.base import BaseCollector
from .config import load_config
from .enricher import Enricher
from .models import IoC
from .storage import Storage

logger = logging.getLogger(__name__)


class PipelineScheduler:
    """
    Orchestrates the full threat intelligence pipeline:
    Collect → Enrich → Store → Analyze
    """

    def __init__(self, config: Optional[dict] = None):
        self.config = config or load_config()
        self.storage = Storage(self.config["storage"]["db_path"])
        self.enricher = Enricher(self.config.get("enrichment", {}))
        self._collectors: list[BaseCollector] = self._build_collectors()
        self._stop_event = threading.Event()
        self._collection_thread: Optional[threading.Thread] = None
        self._report_thread: Optional[threading.Thread] = None

    def _build_collectors(self) -> list[BaseCollector]:
        collectors = []
        collector_configs = self.config.get("collectors", {})

        for feed_name, collector_class in COLLECTOR_REGISTRY.items():
            feed_config = collector_configs.get(feed_name, {})
            if not feed_config.get("enabled", True):
                logger.debug("Collector %s is disabled", feed_name)
                continue
            collectors.append(collector_class(config=feed_config))
            logger.info("Registered collector: %s", feed_name)

        return collectors

    def run_collection(self) -> dict:
        """
        Run a single collection cycle across all enabled collectors.
        Returns a summary dict with counts per feed.
        """
        summary = {}
        enrich_cfg = self.config.get("enrichment", {})
        do_enrich = enrich_cfg.get("enabled", True)

        for collector in self._collectors:
            if not collector.is_healthy():
                logger.warning("Skipping unhealthy collector: %s", collector.name)
                continue

            iocs, health = collector.run()

            if iocs and do_enrich:
                max_enrich = enrich_cfg.get("max_per_run", 200)
                self.enricher.enrich_batch(iocs, max_enrichments=max_enrich)

            inserted, updated = self.storage.bulk_upsert(iocs)
            self.storage.update_feed_health(health)

            summary[collector.name] = {
                "collected": len(iocs),
                "inserted": inserted,
                "updated": updated,
                "status": "ok" if health.consecutive_failures == 0 else "failed",
                "error": health.last_error,
            }

        total_iocs = sum(v["collected"] for v in summary.values())
        total_new = sum(v["inserted"] for v in summary.values())
        logger.info(
            "Collection cycle complete: %d IoCs collected, %d new",
            total_iocs, total_new,
        )
        return summary

    def run_analysis(self, hours: int = 24) -> Optional[object]:
        """
        Trigger the AI analysis agent to generate a threat brief.
        Returns the ThreatReport or None if agent is not configured.
        """
        agent_config = self.config.get("agent", {})
        api_key = agent_config.get("anthropic_api_key")

        if not api_key:
            import os
            api_key = os.environ.get("ANTHROPIC_API_KEY")

        if not api_key:
            logger.info("ANTHROPIC_API_KEY not set — skipping AI analysis")
            return None

        try:
            from .agent import ThreatIntelAgent
            agent = ThreatIntelAgent(self.storage, {**agent_config, "anthropic_api_key": api_key})
            report = agent.generate_threat_brief(
                hours=hours,
                min_confidence=agent_config.get("min_confidence", 50),
            )
            logger.info("Analysis complete: %s", report.title)
            return report
        except Exception as e:
            logger.error("Analysis failed: %s", e, exc_info=True)
            return None

    def _collection_loop(self) -> None:
        interval = self.config["scheduler"]["interval_minutes"] * 60
        logger.info("Collection loop started (interval: %dm)", interval // 60)

        while not self._stop_event.is_set():
            try:
                self.run_collection()
            except Exception as e:
                logger.error("Collection cycle error: %s", e, exc_info=True)

            # Wait for next interval or until stopped
            self._stop_event.wait(timeout=interval)

    def _report_loop(self) -> None:
        interval = self.config["scheduler"]["report_interval_hours"] * 3600
        logger.info("Report loop started (interval: %dh)", interval // 3600)

        # Initial delay — let the first collection run finish
        self._stop_event.wait(timeout=120)

        while not self._stop_event.is_set():
            try:
                hours = self.config["scheduler"]["report_interval_hours"]
                self.run_analysis(hours=hours)
            except Exception as e:
                logger.error("Report generation error: %s", e, exc_info=True)

            self._stop_event.wait(timeout=interval)

    def start(self) -> None:
        """Start background collection and reporting threads."""
        if not self.config["scheduler"]["enabled"]:
            logger.info("Scheduler disabled — run collection manually via CLI")
            return

        self._collection_thread = threading.Thread(
            target=self._collection_loop,
            name="collection-loop",
            daemon=True,
        )
        self._report_thread = threading.Thread(
            target=self._report_loop,
            name="report-loop",
            daemon=True,
        )

        self._collection_thread.start()
        self._report_thread.start()
        logger.info("Pipeline scheduler started")

    def stop(self) -> None:
        """Gracefully stop background threads."""
        logger.info("Stopping pipeline scheduler...")
        self._stop_event.set()
        if self._collection_thread:
            self._collection_thread.join(timeout=30)
        if self._report_thread:
            self._report_thread.join(timeout=10)
        logger.info("Pipeline scheduler stopped")

    def run_once(self, analyze: bool = True) -> dict:
        """
        Run a single complete pipeline cycle (collect + analyze).
        Useful for manual runs, cron jobs, or testing.
        """
        logger.info("Running single pipeline cycle")
        summary = self.run_collection()

        report = None
        if analyze:
            report = self.run_analysis()

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "collection": summary,
            "report_title": report.title if report else None,
            "report_id": report.report_id if report else None,
        }
