"""
SQLite-backed storage layer for the threat intelligence pipeline.

Design goals:
  - Zero external services required (runs on a Raspberry Pi without Postgres/Redis)
  - Efficient deduplication via fingerprint hashing
  - Fast IoC lookup for enrichment and API queries
  - Time-series friendly for trend analysis
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

from .models import FeedHealth, IoC, IoCType, Severity, ThreatReport, ThreatType

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS iocs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL UNIQUE,
    ioc_id        TEXT NOT NULL,
    type          TEXT NOT NULL,
    value         TEXT NOT NULL,
    source_feed   TEXT NOT NULL,
    source_id     TEXT,
    threat_type   TEXT NOT NULL DEFAULT 'unknown',
    malware_family TEXT,
    threat_actor  TEXT,
    campaign      TEXT,
    tags          TEXT DEFAULT '[]',   -- JSON array
    confidence    INTEGER DEFAULT 50,
    severity      TEXT DEFAULT 'medium',
    first_seen    TEXT,
    last_seen     TEXT,
    expiry        TEXT,
    asn           TEXT,
    asn_org       TEXT,
    country       TEXT,
    registrar     TEXT,
    hosting_provider TEXT,
    ttps          TEXT DEFAULT '[]',   -- JSON array
    raw           TEXT,               -- JSON blob
    ingested_at   TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_iocs_type     ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value    ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_source   ON iocs(source_feed);
CREATE INDEX IF NOT EXISTS idx_iocs_threat   ON iocs(threat_type);
CREATE INDEX IF NOT EXISTS idx_iocs_severity ON iocs(severity);
CREATE INDEX IF NOT EXISTS idx_iocs_ingested ON iocs(ingested_at);
CREATE INDEX IF NOT EXISTS idx_iocs_country  ON iocs(country);

CREATE TABLE IF NOT EXISTS threat_reports (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id          TEXT NOT NULL UNIQUE,
    generated_at       TEXT NOT NULL,
    title              TEXT NOT NULL,
    executive_summary  TEXT,
    key_findings       TEXT DEFAULT '[]',
    threat_actors      TEXT DEFAULT '[]',
    malware_families   TEXT DEFAULT '[]',
    ttps               TEXT DEFAULT '[]',
    ioc_count          INTEGER DEFAULT 0,
    source_feeds       TEXT DEFAULT '[]',
    recommendations    TEXT DEFAULT '[]',
    severity_breakdown TEXT DEFAULT '{}',
    raw_analysis       TEXT,
    model_used         TEXT
);

CREATE TABLE IF NOT EXISTS feed_health (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_name             TEXT NOT NULL UNIQUE,
    last_run              TEXT,
    last_success          TEXT,
    iocs_collected        INTEGER DEFAULT 0,
    consecutive_failures  INTEGER DEFAULT 0,
    last_error            TEXT,
    is_enabled            INTEGER DEFAULT 1
);
"""


class Storage:
    """Thread-safe SQLite storage with WAL mode for concurrent reads."""

    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            row = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").fetchone()
            current = row[0] if row else 0
            if current < SCHEMA_VERSION:
                conn.execute(
                    "INSERT OR REPLACE INTO schema_version VALUES (?, ?)",
                    (SCHEMA_VERSION, datetime.now(timezone.utc).isoformat()),
                )
        logger.info("Storage initialized at %s", self.db_path)

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # IoC write operations
    # ------------------------------------------------------------------

    def upsert_ioc(self, ioc: IoC) -> tuple[bool, bool]:
        """
        Insert or update an IoC.
        Returns (was_inserted, was_updated).
        New IoCs are inserted; duplicates update confidence/last_seen/tags.
        """
        fp = ioc.fingerprint()
        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id, confidence, tags, ttps FROM iocs WHERE fingerprint = ?", (fp,)
            ).fetchone()

            if existing is None:
                conn.execute(
                    """
                    INSERT INTO iocs (
                        fingerprint, ioc_id, type, value, source_feed, source_id,
                        threat_type, malware_family, threat_actor, campaign,
                        tags, confidence, severity, first_seen, last_seen, expiry,
                        asn, asn_org, country, registrar, hosting_provider,
                        ttps, raw, ingested_at, updated_at
                    ) VALUES (
                        ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
                    )
                    """,
                    (
                        fp,
                        ioc.ioc_id,
                        ioc.type.value,
                        ioc.value,
                        ioc.source_feed,
                        ioc.source_id,
                        ioc.threat_type.value,
                        ioc.malware_family,
                        ioc.threat_actor,
                        ioc.campaign,
                        json.dumps(ioc.tags),
                        ioc.confidence,
                        ioc.severity.value,
                        ioc.first_seen.isoformat() if ioc.first_seen else None,
                        ioc.last_seen.isoformat() if ioc.last_seen else None,
                        ioc.expiry.isoformat() if ioc.expiry else None,
                        ioc.asn,
                        ioc.asn_org,
                        ioc.country,
                        ioc.registrar,
                        ioc.hosting_provider,
                        json.dumps(ioc.ttps),
                        json.dumps(ioc.raw) if ioc.raw else None,
                        ioc.ingested_at.isoformat(),
                        now,
                    ),
                )
                return (True, False)
            else:
                # Merge tags and TTPs; take max confidence
                existing_tags = set(json.loads(existing["tags"] or "[]"))
                merged_tags = list(existing_tags | set(ioc.tags))
                existing_ttps = set(json.loads(existing["ttps"] or "[]"))
                merged_ttps = list(existing_ttps | set(ioc.ttps))
                new_conf = max(existing["confidence"], ioc.confidence)

                conn.execute(
                    """
                    UPDATE iocs
                    SET last_seen = ?, confidence = ?, tags = ?,
                        ttps = ?, updated_at = ?
                    WHERE fingerprint = ?
                    """,
                    (
                        (ioc.last_seen or ioc.ingested_at).isoformat(),
                        new_conf,
                        json.dumps(merged_tags),
                        json.dumps(merged_ttps),
                        now,
                        fp,
                    ),
                )
                return (False, True)

    def bulk_upsert(self, iocs: list[IoC]) -> tuple[int, int]:
        """Upsert a list of IoCs. Returns (inserted, updated) counts."""
        inserted = updated = 0
        for ioc in iocs:
            i, u = self.upsert_ioc(ioc)
            inserted += i
            updated += u
        logger.debug("Bulk upsert: %d inserted, %d updated", inserted, updated)
        return inserted, updated

    # ------------------------------------------------------------------
    # IoC read operations
    # ------------------------------------------------------------------

    def _row_to_ioc(self, row: sqlite3.Row) -> IoC:
        return IoC(
            type=IoCType(row["type"]),
            value=row["value"],
            source_feed=row["source_feed"],
            source_id=row["source_id"],
            threat_type=ThreatType(row["threat_type"]),
            malware_family=row["malware_family"],
            threat_actor=row["threat_actor"],
            campaign=row["campaign"],
            tags=json.loads(row["tags"] or "[]"),
            confidence=row["confidence"],
            severity=Severity(row["severity"]),
            first_seen=datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            expiry=datetime.fromisoformat(row["expiry"]) if row["expiry"] else None,
            asn=row["asn"],
            asn_org=row["asn_org"],
            country=row["country"],
            registrar=row["registrar"],
            hosting_provider=row["hosting_provider"],
            ttps=json.loads(row["ttps"] or "[]"),
            raw=json.loads(row["raw"]) if row["raw"] else None,
            ioc_id=row["ioc_id"],
            ingested_at=datetime.fromisoformat(row["ingested_at"]),
        )

    def get_ioc_by_value(self, value: str) -> Optional[IoC]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM iocs WHERE value = ?", (value,)).fetchone()
        return self._row_to_ioc(row) if row else None

    def query_iocs(
        self,
        ioc_type: Optional[str] = None,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_feed: Optional[str] = None,
        country: Optional[str] = None,
        min_confidence: int = 0,
        since_hours: Optional[int] = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[IoC]:
        clauses = ["confidence >= ?"]
        params: list = [min_confidence]

        if ioc_type:
            clauses.append("type = ?")
            params.append(ioc_type)
        if threat_type:
            clauses.append("threat_type = ?")
            params.append(threat_type)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if source_feed:
            clauses.append("source_feed = ?")
            params.append(source_feed)
        if country:
            clauses.append("country = ?")
            params.append(country)
        if since_hours:
            cutoff = datetime.now(timezone.utc)
            from datetime import timedelta
            cutoff -= timedelta(hours=since_hours)
            clauses.append("ingested_at >= ?")
            params.append(cutoff.isoformat())

        where = " AND ".join(clauses)
        params.extend([limit, offset])

        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM iocs WHERE {where} ORDER BY ingested_at DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._row_to_ioc(r) for r in rows]

    def get_stats(self) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            by_type = {r[0]: r[1] for r in conn.execute(
                "SELECT type, COUNT(*) FROM iocs GROUP BY type"
            ).fetchall()}
            by_severity = {r[0]: r[1] for r in conn.execute(
                "SELECT severity, COUNT(*) FROM iocs GROUP BY severity"
            ).fetchall()}
            by_threat = {r[0]: r[1] for r in conn.execute(
                "SELECT threat_type, COUNT(*) FROM iocs GROUP BY threat_type"
            ).fetchall()}
            by_feed = {r[0]: r[1] for r in conn.execute(
                "SELECT source_feed, COUNT(*) FROM iocs GROUP BY source_feed"
            ).fetchall()}
            recent_24h = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE ingested_at >= datetime('now', '-1 day')"
            ).fetchone()[0]
            top_countries = conn.execute(
                "SELECT country, COUNT(*) as n FROM iocs WHERE country IS NOT NULL "
                "GROUP BY country ORDER BY n DESC LIMIT 10"
            ).fetchall()
            top_malware = conn.execute(
                "SELECT malware_family, COUNT(*) as n FROM iocs WHERE malware_family IS NOT NULL "
                "GROUP BY malware_family ORDER BY n DESC LIMIT 10"
            ).fetchall()

        return {
            "total_iocs": total,
            "ingested_last_24h": recent_24h,
            "by_type": by_type,
            "by_severity": by_severity,
            "by_threat_type": by_threat,
            "by_feed": by_feed,
            "top_countries": [{"country": r[0], "count": r[1]} for r in top_countries],
            "top_malware_families": [{"family": r[0], "count": r[1]} for r in top_malware],
        }

    # ------------------------------------------------------------------
    # Threat reports
    # ------------------------------------------------------------------

    def save_report(self, report: ThreatReport) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO threat_reports (
                    report_id, generated_at, title, executive_summary,
                    key_findings, threat_actors, malware_families, ttps,
                    ioc_count, source_feeds, recommendations,
                    severity_breakdown, raw_analysis, model_used
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    report.report_id,
                    report.generated_at.isoformat(),
                    report.title,
                    report.executive_summary,
                    json.dumps(report.key_findings),
                    json.dumps(report.threat_actors),
                    json.dumps(report.malware_families),
                    json.dumps(report.ttps),
                    report.ioc_count,
                    json.dumps(report.source_feeds),
                    json.dumps(report.recommendations),
                    json.dumps(report.severity_breakdown),
                    report.raw_analysis,
                    report.model_used,
                ),
            )

    def get_latest_report(self) -> Optional[ThreatReport]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM threat_reports ORDER BY generated_at DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        return ThreatReport(
            report_id=row["report_id"],
            generated_at=datetime.fromisoformat(row["generated_at"]),
            title=row["title"],
            executive_summary=row["executive_summary"] or "",
            key_findings=json.loads(row["key_findings"] or "[]"),
            threat_actors=json.loads(row["threat_actors"] or "[]"),
            malware_families=json.loads(row["malware_families"] or "[]"),
            ttps=json.loads(row["ttps"] or "[]"),
            ioc_count=row["ioc_count"],
            source_feeds=json.loads(row["source_feeds"] or "[]"),
            recommendations=json.loads(row["recommendations"] or "[]"),
            severity_breakdown=json.loads(row["severity_breakdown"] or "{}"),
            raw_analysis=row["raw_analysis"] or "",
            model_used=row["model_used"] or "",
        )

    def list_reports(self, limit: int = 20) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT report_id, generated_at, title, ioc_count, model_used "
                "FROM threat_reports ORDER BY generated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Feed health
    # ------------------------------------------------------------------

    def update_feed_health(self, health: FeedHealth) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO feed_health (
                    feed_name, last_run, last_success, iocs_collected,
                    consecutive_failures, last_error, is_enabled
                ) VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(feed_name) DO UPDATE SET
                    last_run = excluded.last_run,
                    last_success = excluded.last_success,
                    iocs_collected = excluded.iocs_collected,
                    consecutive_failures = excluded.consecutive_failures,
                    last_error = excluded.last_error,
                    is_enabled = excluded.is_enabled
                """,
                (
                    health.feed_name,
                    health.last_run.isoformat() if health.last_run else None,
                    health.last_success.isoformat() if health.last_success else None,
                    health.iocs_collected,
                    health.consecutive_failures,
                    health.last_error,
                    1 if health.is_enabled else 0,
                ),
            )

    def get_all_feed_health(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM feed_health ORDER BY feed_name").fetchall()
        return [dict(r) for r in rows]
