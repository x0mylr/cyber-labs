#!/usr/bin/env python3
"""
Threat Intelligence Pipeline — main entry point.

Usage:
  python main.py serve          # Start the API server with background scheduler
  python main.py collect        # Run a single collection cycle and exit
  python main.py analyze        # Generate a threat brief from stored IoCs
  python main.py correlate      # Run IoC correlation analysis
  python main.py ask "question" # Ask the AI analyst a question
  python main.py triage <ioc>   # Triage a specific IoC
  python main.py stats          # Print pipeline statistics

Environment variables:
  ANTHROPIC_API_KEY   — Required for AI analysis features
  OTX_API_KEY         — AlienVault OTX (optional, enables OTX collector)
  VT_API_KEY          — VirusTotal (optional, enables hash enrichment)
  TIPL_API_TOKEN      — API bearer token (optional, secures REST API)

See config/config.yaml for all configuration options.
"""

import json
import logging
import sys

from pipeline.config import load_config, setup_logging

logger = logging.getLogger(__name__)


def cmd_serve(cfg: dict) -> None:
    """Start the API server with background collection and analysis."""
    from pipeline.api import create_app
    from pipeline.scheduler import PipelineScheduler

    scheduler = PipelineScheduler(config=cfg)
    scheduler.start()

    app = create_app(config=cfg, scheduler=scheduler)
    api_cfg = cfg.get("api", {})

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║      Threat Intelligence Pipeline — API Server               ║
╠══════════════════════════════════════════════════════════════╣
║  API:       http://{api_cfg.get('host','0.0.0.0')}:{api_cfg.get('port',8000)}                        ║
║  Health:    /health                                          ║
║  IoCs:      /api/v1/iocs                                     ║
║  Reports:   /api/v1/reports/latest                           ║
║  Stats:     /api/v1/stats                                    ║
╚══════════════════════════════════════════════════════════════╝
""")

    try:
        app.run(
            host=api_cfg.get("host", "0.0.0.0"),
            port=api_cfg.get("port", 8000),
            debug=api_cfg.get("debug", False),
            use_reloader=False,  # reloader conflicts with background threads
        )
    finally:
        scheduler.stop()


def cmd_collect(cfg: dict) -> None:
    """Run a single collection cycle."""
    from pipeline.scheduler import PipelineScheduler
    scheduler = PipelineScheduler(config=cfg)
    summary = scheduler.run_collection()
    print("\nCollection Summary:")
    print(json.dumps(summary, indent=2))
    total = sum(v.get("collected", 0) for v in summary.values())
    new_iocs = sum(v.get("inserted", 0) for v in summary.values())
    print(f"\nTotal: {total} IoCs collected, {new_iocs} new")


def cmd_analyze(cfg: dict, hours: int = 24) -> None:
    """Generate a threat brief from stored IoCs."""
    from pipeline.scheduler import PipelineScheduler
    scheduler = PipelineScheduler(config=cfg)
    report = scheduler.run_analysis(hours=hours)

    if not report:
        print("Analysis not available (check ANTHROPIC_API_KEY)")
        return

    print(f"\n{'='*60}")
    print(f"THREAT INTELLIGENCE BRIEF")
    print(f"{'='*60}")
    print(f"Title:    {report.title}")
    print(f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"IoCs analyzed: {report.ioc_count}")
    print(f"\nEXECUTIVE SUMMARY\n{report.executive_summary}")
    print(f"\nKEY FINDINGS")
    for i, finding in enumerate(report.key_findings, 1):
        print(f"  {i}. {finding}")
    print(f"\nTHREAT ACTORS: {', '.join(report.threat_actors) or 'None identified'}")
    print(f"MALWARE: {', '.join(report.malware_families) or 'None identified'}")
    print(f"TTPS: {', '.join(report.ttps) or 'None identified'}")
    print(f"\nRECOMMENDATIONS")
    for i, rec in enumerate(report.recommendations, 1):
        print(f"  {i}. {rec}")
    print(f"\nSEVERITY BREAKDOWN: {json.dumps(report.severity_breakdown)}")
    print(f"\nModel: {report.model_used}")


def cmd_correlate(cfg: dict, hours: int = 48) -> None:
    """Run IoC correlation analysis."""
    import os
    agent_config = cfg.get("agent", {})
    api_key = agent_config.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set")
        sys.exit(1)

    from pipeline.agent import ThreatIntelAgent
    from pipeline.storage import Storage
    storage = Storage(cfg["storage"]["db_path"])
    agent = ThreatIntelAgent(storage, {**agent_config, "anthropic_api_key": api_key})
    result = agent.correlate_iocs(hours=hours)
    print(json.dumps(result, indent=2))


def cmd_ask(cfg: dict, question: str) -> None:
    """Ask the AI analyst a question."""
    import os
    agent_config = cfg.get("agent", {})
    api_key = agent_config.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set")
        sys.exit(1)

    from pipeline.agent import ThreatIntelAgent
    from pipeline.storage import Storage
    storage = Storage(cfg["storage"]["db_path"])
    agent = ThreatIntelAgent(storage, {**agent_config, "anthropic_api_key": api_key})
    answer = agent.ask(question)
    print(f"\nQ: {question}\n")
    print(f"A: {answer}")


def cmd_triage(cfg: dict, ioc_value: str) -> None:
    """Triage a specific IoC."""
    import os
    agent_config = cfg.get("agent", {})
    api_key = agent_config.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: ANTHROPIC_API_KEY not set")
        sys.exit(1)

    from pipeline.agent import ThreatIntelAgent
    from pipeline.storage import Storage
    storage = Storage(cfg["storage"]["db_path"])
    agent = ThreatIntelAgent(storage, {**agent_config, "anthropic_api_key": api_key})
    result = agent.triage_ioc(ioc_value)
    print(json.dumps(result, indent=2))


def cmd_stats(cfg: dict) -> None:
    """Print pipeline statistics."""
    from pipeline.storage import Storage
    storage = Storage(cfg["storage"]["db_path"])
    stats = storage.get_stats()
    feeds = storage.get_all_feed_health()

    print(f"\nPIPELINE STATISTICS")
    print(f"{'='*40}")
    print(f"Total IoCs: {stats['total_iocs']:,}")
    print(f"Last 24h:   {stats['ingested_last_24h']:,}")
    print(f"\nBy Severity:")
    for sev, count in sorted(stats.get("by_severity", {}).items()):
        print(f"  {sev:10s}: {count:,}")
    print(f"\nBy Feed:")
    for feed, count in sorted(stats.get("by_feed", {}).items()):
        print(f"  {feed:35s}: {count:,}")
    print(f"\nTop Malware Families:")
    for item in stats.get("top_malware_families", [])[:10]:
        print(f"  {item['family']:25s}: {item['count']:,}")
    print(f"\nTop Source Countries:")
    for item in stats.get("top_countries", [])[:10]:
        print(f"  {item['country']:5s}: {item['count']:,}")
    print(f"\nFeed Health:")
    for feed in feeds:
        status = "OK" if feed.get("consecutive_failures", 0) == 0 else "DEGRADED"
        print(f"  [{status:8s}] {feed['feed_name']}: {feed.get('iocs_collected', 0):,} last run")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cfg = load_config()
    setup_logging(cfg)

    command = sys.argv[1].lower()

    if command == "serve":
        cmd_serve(cfg)
    elif command == "collect":
        cmd_collect(cfg)
    elif command == "analyze":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        cmd_analyze(cfg, hours=hours)
    elif command == "correlate":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 48
        cmd_correlate(cfg, hours=hours)
    elif command == "ask":
        if len(sys.argv) < 3:
            print("Usage: python main.py ask \"your question here\"")
            sys.exit(1)
        cmd_ask(cfg, question=" ".join(sys.argv[2:]))
    elif command == "triage":
        if len(sys.argv) < 3:
            print("Usage: python main.py triage <ioc_value>")
            sys.exit(1)
        cmd_triage(cfg, ioc_value=sys.argv[2])
    elif command == "stats":
        cmd_stats(cfg)
    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
