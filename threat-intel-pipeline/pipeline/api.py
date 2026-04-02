"""
REST API for the threat intelligence pipeline.

Built with Flask (lightweight, runs well on Raspberry Pi).
Provides endpoints for:
  - Querying IoCs
  - Triggering collection runs
  - Fetching AI-generated threat reports
  - IoC triage (on-demand)
  - Feed health status
  - Statistics and dashboard data

Authentication: Bearer token (set TIPL_API_TOKEN env var).
If no token is set, the API runs without auth (development mode).
"""

import logging
import os
from datetime import datetime, timezone
from functools import wraps
from typing import Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

from .config import load_config
from .models import IoC
from .scheduler import PipelineScheduler
from .storage import Storage

logger = logging.getLogger(__name__)


def create_app(config: Optional[dict] = None, scheduler: Optional[PipelineScheduler] = None) -> Flask:
    cfg = config or load_config()
    app = Flask(__name__)

    # CORS for the frontend dashboard
    cors_origins = cfg.get("api", {}).get("cors_origins", ["*"])
    CORS(app, origins=cors_origins)

    storage = Storage(cfg["storage"]["db_path"])
    api_token = os.environ.get("TIPL_API_TOKEN")

    # ------------------------------------------------------------------
    # Auth middleware
    # ------------------------------------------------------------------

    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not api_token:
                return f(*args, **kwargs)  # no auth configured
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer ") or auth_header[7:] != api_token:
                return jsonify({"error": "Unauthorized"}), 401
            return f(*args, **kwargs)
        return decorated

    # ------------------------------------------------------------------
    # Health & Status
    # ------------------------------------------------------------------

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})

    @app.route("/api/v1/status")
    @require_auth
    def status():
        stats = storage.get_stats()
        feeds = storage.get_all_feed_health()
        return jsonify({
            "status": "operational",
            "stats": stats,
            "feeds": feeds,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # ------------------------------------------------------------------
    # IoC endpoints
    # ------------------------------------------------------------------

    @app.route("/api/v1/iocs")
    @require_auth
    def list_iocs():
        """
        Query IoCs with optional filters.
        Query params: type, threat_type, severity, source_feed, country,
                      min_confidence, since_hours, limit, offset
        """
        iocs = storage.query_iocs(
            ioc_type=request.args.get("type"),
            threat_type=request.args.get("threat_type"),
            severity=request.args.get("severity"),
            source_feed=request.args.get("source_feed"),
            country=request.args.get("country"),
            min_confidence=int(request.args.get("min_confidence", 0)),
            since_hours=int(request.args.get("since_hours")) if request.args.get("since_hours") else None,
            limit=min(int(request.args.get("limit", 100)), 1000),
            offset=int(request.args.get("offset", 0)),
        )
        return jsonify({
            "count": len(iocs),
            "iocs": [ioc.to_stix_indicator() for ioc in iocs],
        })

    @app.route("/api/v1/iocs/<path:value>")
    @require_auth
    def get_ioc(value: str):
        """Look up a specific IoC by value."""
        ioc = storage.get_ioc_by_value(value)
        if not ioc:
            return jsonify({"error": "IoC not found", "value": value}), 404
        return jsonify(ioc.to_stix_indicator())

    @app.route("/api/v1/iocs/<path:value>/triage", methods=["POST"])
    @require_auth
    def triage_ioc(value: str):
        """
        On-demand AI triage for a specific IoC.
        Returns Claude's threat assessment.
        """
        agent_config = cfg.get("agent", {})
        api_key = agent_config.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return jsonify({"error": "AI analysis not configured (ANTHROPIC_API_KEY missing)"}), 503

        try:
            from .agent import ThreatIntelAgent
            agent = ThreatIntelAgent(storage, {**agent_config, "anthropic_api_key": api_key})
            result = agent.triage_ioc(value)
            return jsonify(result)
        except Exception as e:
            logger.error("Triage failed for %s: %s", value, e)
            return jsonify({"error": str(e)}), 500

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    @app.route("/api/v1/reports")
    @require_auth
    def list_reports():
        reports = storage.list_reports(limit=int(request.args.get("limit", 20)))
        return jsonify({"reports": reports})

    @app.route("/api/v1/reports/latest")
    @require_auth
    def latest_report():
        report = storage.get_latest_report()
        if not report:
            return jsonify({"error": "No reports generated yet"}), 404
        return jsonify({
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "title": report.title,
            "executive_summary": report.executive_summary,
            "key_findings": report.key_findings,
            "threat_actors": report.threat_actors,
            "malware_families": report.malware_families,
            "ttps": report.ttps,
            "ioc_count": report.ioc_count,
            "source_feeds": report.source_feeds,
            "recommendations": report.recommendations,
            "severity_breakdown": report.severity_breakdown,
            "model_used": report.model_used,
        })

    @app.route("/api/v1/reports/generate", methods=["POST"])
    @require_auth
    def generate_report():
        """
        Trigger an on-demand AI threat brief.
        Body params: hours (default 24), min_confidence (default 50)
        """
        body = request.get_json(silent=True) or {}
        hours = int(body.get("hours", 24))
        min_confidence = int(body.get("min_confidence", 50))

        agent_config = cfg.get("agent", {})
        api_key = agent_config.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return jsonify({"error": "AI analysis not configured"}), 503

        try:
            from .agent import ThreatIntelAgent
            agent = ThreatIntelAgent(storage, {**agent_config, "anthropic_api_key": api_key})
            report = agent.generate_threat_brief(hours=hours, min_confidence=min_confidence)
            return jsonify({
                "report_id": report.report_id,
                "title": report.title,
                "ioc_count": report.ioc_count,
                "generated_at": report.generated_at.isoformat(),
            }), 201
        except Exception as e:
            logger.error("Report generation failed: %s", e)
            return jsonify({"error": str(e)}), 500

    # ------------------------------------------------------------------
    # Analysis endpoints
    # ------------------------------------------------------------------

    @app.route("/api/v1/analyze/correlate", methods=["POST"])
    @require_auth
    def correlate():
        """Run IoC correlation analysis."""
        body = request.get_json(silent=True) or {}
        hours = int(body.get("hours", 48))

        agent_config = cfg.get("agent", {})
        api_key = agent_config.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return jsonify({"error": "AI analysis not configured"}), 503

        try:
            from .agent import ThreatIntelAgent
            agent = ThreatIntelAgent(storage, {**agent_config, "anthropic_api_key": api_key})
            result = agent.correlate_iocs(hours=hours)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/v1/analyze/ask", methods=["POST"])
    @require_auth
    def ask_analyst():
        """
        Free-form analyst Q&A.
        Body: { "question": "...", "context_hours": 24 }
        """
        body = request.get_json(silent=True) or {}
        question = body.get("question", "").strip()
        if not question:
            return jsonify({"error": "question is required"}), 400

        agent_config = cfg.get("agent", {})
        api_key = agent_config.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return jsonify({"error": "AI analysis not configured"}), 503

        try:
            from .agent import ThreatIntelAgent
            agent = ThreatIntelAgent(storage, {**agent_config, "anthropic_api_key": api_key})
            answer = agent.ask(question, context_hours=int(body.get("context_hours", 24)))
            return jsonify({"question": question, "answer": answer})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ------------------------------------------------------------------
    # Collection triggers
    # ------------------------------------------------------------------

    @app.route("/api/v1/collect", methods=["POST"])
    @require_auth
    def trigger_collection():
        """Manually trigger a collection cycle."""
        if scheduler:
            try:
                summary = scheduler.run_collection()
                return jsonify({"status": "ok", "summary": summary})
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        return jsonify({"error": "Scheduler not initialized"}), 503

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    @app.route("/api/v1/stats")
    @require_auth
    def stats():
        return jsonify(storage.get_stats())

    @app.route("/api/v1/feeds")
    @require_auth
    def feed_health():
        return jsonify({"feeds": storage.get_all_feed_health()})

    return app
