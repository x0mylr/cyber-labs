"""
AI Threat Intelligence Analysis Agent powered by Claude.

This agent consumes normalized IoCs from the pipeline database and produces:
  - Executive threat briefs (suitable for C-suite distribution)
  - Technical analyst reports (for SOC teams)
  - Prioritized remediation recommendations
  - Pattern analysis across feeds (correlated campaigns, shared infrastructure)
  - MITRE ATT&CK technique mapping summaries

The agent uses the Anthropic Messages API with structured prompting.
Requires ANTHROPIC_API_KEY in the environment.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import anthropic

from .models import IoC, IoCType, Severity, ThreatReport, ThreatType
from .storage import Storage

logger = logging.getLogger(__name__)

# Use a capable model for security analysis
ANALYSIS_MODEL = "claude-opus-4-6"
FAST_MODEL = "claude-haiku-4-5-20251001"

SYSTEM_PROMPT = """You are an expert threat intelligence analyst with 15+ years of experience in:
- Malware analysis and reverse engineering
- Network intrusion detection and incident response
- Threat actor attribution and campaign tracking
- MITRE ATT&CK framework mapping
- Vulnerability research and exploit analysis

You are analyzing IoCs (Indicators of Compromise) collected from multiple open-source and
commercial threat intelligence feeds. Your analysis must be:
- Accurate and evidence-based (cite the source feeds)
- Actionable (prioritize by business impact)
- Concise (security teams are busy — get to the point)
- Structured (use the exact JSON format requested)

Do not invent threat actors, malware families, or TTPs not supported by the data.
When confidence is low, say so clearly."""


BRIEF_PROMPT_TEMPLATE = """Analyze the following threat intelligence data collected in the last {hours} hours.

## Collection Statistics
{stats_json}

## Sample IoCs (top {sample_count} by severity/confidence)
{iocs_json}

## Feed Source Summary
{feed_summary}

Produce a threat intelligence brief in the following JSON format:
{{
  "title": "Brief, descriptive title for this threat period",
  "executive_summary": "2-3 sentence non-technical summary for leadership",
  "key_findings": [
    "Finding 1 with evidence",
    "Finding 2 with evidence",
    "Finding 3 with evidence"
  ],
  "threat_actors": ["Actor1", "Actor2"],
  "malware_families": ["Family1", "Family2"],
  "ttps": ["T1566.001", "T1059.003"],
  "severity_breakdown": {{
    "critical": <count>,
    "high": <count>,
    "medium": <count>,
    "low": <count>
  }},
  "recommendations": [
    "Immediate action recommendation 1",
    "Short-term recommendation 2",
    "Strategic recommendation 3"
  ],
  "notable_patterns": "Description of any correlated activity, shared infrastructure, or campaign indicators"
}}

Return ONLY the JSON object, no markdown code blocks."""


CORRELATION_PROMPT = """You are analyzing {count} IoCs to identify correlated threat activity.

IoC data:
{iocs_json}

Identify:
1. Shared infrastructure (IPs/domains serving multiple malware families)
2. Campaign indicators (similar TTPs, timing, targeting patterns)
3. Threat actor fingerprints (known tooling, staging patterns)
4. Geographic concentration of attacks
5. Industry/sector targeting patterns

Format your response as JSON:
{{
  "correlated_campaigns": [
    {{
      "campaign_id": "CAMP-001",
      "name": "Descriptive name",
      "ioc_count": 5,
      "indicators": ["ioc1", "ioc2"],
      "confidence": 70,
      "description": "What makes these IoCs related"
    }}
  ],
  "shared_infrastructure": [
    {{
      "pivot_point": "IP or domain",
      "associated_malware": ["family1"],
      "iocs": ["ioc1", "ioc2"]
    }}
  ],
  "top_threats": [
    {{
      "threat": "Threat name",
      "severity": "high",
      "ioc_count": 10,
      "recommended_action": "Block/monitor/escalate"
    }}
  ]
}}"""


def _build_ioc_summary(iocs: list[IoC], max_iocs: int = 100) -> list[dict]:
    """Convert IoC objects to a concise dict representation for the prompt."""
    # Prioritize: critical > high > medium > low, then by confidence
    severity_order = {
        Severity.CRITICAL: 4,
        Severity.HIGH: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    sorted_iocs = sorted(
        iocs,
        key=lambda x: (severity_order.get(x.severity, 0), x.confidence),
        reverse=True,
    )[:max_iocs]

    return [
        {
            "type": ioc.type.value,
            "value": ioc.value,
            "threat_type": ioc.threat_type.value,
            "malware_family": ioc.malware_family,
            "threat_actor": ioc.threat_actor,
            "severity": ioc.severity.value,
            "confidence": ioc.confidence,
            "source": ioc.source_feed,
            "country": ioc.country,
            "tags": ioc.tags[:5],  # limit tags to avoid token bloat
            "ttps": ioc.ttps[:5],
            "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        }
        for ioc in sorted_iocs
    ]


class ThreatIntelAgent:
    """
    Claude-powered threat intelligence analysis agent.

    Consumes IoCs from the pipeline storage and produces structured
    threat intelligence reports suitable for SOC teams and leadership.
    """

    def __init__(self, storage: Storage, config: dict):
        self.storage = storage
        self.config = config
        api_key = config.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY not found. Set it in your environment or config."
            )
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = config.get("model", ANALYSIS_MODEL)
        self.fast_model = config.get("fast_model", FAST_MODEL)

    def generate_threat_brief(
        self,
        hours: int = 24,
        min_confidence: int = 50,
        use_fast_model: bool = False,
    ) -> ThreatReport:
        """
        Generate a comprehensive threat intelligence brief for the last N hours.
        This is the primary output of the pipeline for SOC consumption.
        """
        logger.info("Generating threat brief for last %d hours", hours)

        # Fetch recent IoCs from storage
        iocs = self.storage.query_iocs(
            min_confidence=min_confidence,
            since_hours=hours,
            limit=1000,
        )

        if not iocs:
            logger.warning("No IoCs found for the last %d hours", hours)
            return ThreatReport(
                title="No Threat Activity Detected",
                executive_summary=f"No IoCs with confidence >= {min_confidence} were collected in the last {hours} hours.",
                ioc_count=0,
            )

        stats = self.storage.get_stats()
        feed_summary = stats.get("by_feed", {})

        ioc_dicts = _build_ioc_summary(iocs, max_iocs=150)

        prompt = BRIEF_PROMPT_TEMPLATE.format(
            hours=hours,
            stats_json=json.dumps(stats, indent=2),
            sample_count=len(ioc_dicts),
            iocs_json=json.dumps(ioc_dicts, indent=2),
            feed_summary=json.dumps(feed_summary, indent=2),
        )

        model = self.fast_model if use_fast_model else self.model

        response = self.client.messages.create(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        raw_analysis = response.content[0].text.strip()

        # Parse the structured JSON response
        try:
            analysis = json.loads(raw_analysis)
        except json.JSONDecodeError:
            # Try to extract JSON from the response if it has surrounding text
            import re
            match = re.search(r"\{[\s\S]*\}", raw_analysis)
            if match:
                analysis = json.loads(match.group())
            else:
                logger.error("Failed to parse agent response as JSON")
                analysis = {
                    "title": "Threat Intelligence Brief",
                    "executive_summary": raw_analysis[:500],
                    "key_findings": [],
                    "recommendations": [],
                }

        severity_counts = {s.value: 0 for s in Severity}
        for ioc in iocs:
            severity_counts[ioc.severity.value] = severity_counts.get(ioc.severity.value, 0) + 1

        report = ThreatReport(
            title=analysis.get("title", "Threat Intelligence Brief"),
            executive_summary=analysis.get("executive_summary", ""),
            key_findings=analysis.get("key_findings", []),
            threat_actors=analysis.get("threat_actors", []),
            malware_families=analysis.get("malware_families", []),
            ttps=analysis.get("ttps", []),
            ioc_count=len(iocs),
            source_feeds=list(feed_summary.keys()),
            recommendations=analysis.get("recommendations", []),
            severity_breakdown=analysis.get("severity_breakdown", severity_counts),
            raw_analysis=raw_analysis,
            model_used=model,
        )

        self.storage.save_report(report)
        logger.info("Threat brief generated: %s (%d IoCs)", report.title, report.ioc_count)
        return report

    def correlate_iocs(self, hours: int = 48) -> dict:
        """
        Run correlation analysis on recent IoCs to identify campaigns
        and shared infrastructure.
        """
        logger.info("Running IoC correlation analysis for last %d hours", hours)

        iocs = self.storage.query_iocs(
            min_confidence=60,
            since_hours=hours,
            limit=500,
        )

        if len(iocs) < 5:
            return {"correlated_campaigns": [], "shared_infrastructure": [], "top_threats": []}

        ioc_dicts = _build_ioc_summary(iocs, max_iocs=200)
        prompt = CORRELATION_PROMPT.format(
            count=len(ioc_dicts),
            iocs_json=json.dumps(ioc_dicts, indent=2),
        )

        response = self.client.messages.create(
            model=self.fast_model,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        try:
            return json.loads(response.content[0].text.strip())
        except json.JSONDecodeError:
            return {"error": "Failed to parse correlation response", "raw": response.content[0].text}

    def ask(self, question: str, context_hours: int = 24) -> str:
        """
        Free-form Q&A interface for analysts.
        Provides current threat data as context for ad-hoc questions.

        Examples:
          agent.ask("Are there any indicators related to the MOVEit vulnerability?")
          agent.ask("What C2 infrastructure is most active right now?")
          agent.ask("Summarize the ransomware activity in the last 24 hours")
        """
        iocs = self.storage.query_iocs(since_hours=context_hours, limit=300)
        stats = self.storage.get_stats()

        context = f"""Current threat intelligence context ({context_hours}h window):

Stats: {json.dumps(stats, indent=2)}

Recent IoCs ({len(iocs)} total):
{json.dumps(_build_ioc_summary(iocs, max_iocs=100), indent=2)}

Analyst question: {question}

Provide a direct, evidence-based answer. Reference specific IoCs where relevant."""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": context}],
        )
        return response.content[0].text

    def triage_ioc(self, ioc_value: str) -> dict:
        """
        On-demand triage of a specific IoC.
        Looks up the IoC in storage and asks Claude to assess its risk.
        """
        ioc = self.storage.get_ioc_by_value(ioc_value)

        if not ioc:
            return {
                "found": False,
                "value": ioc_value,
                "verdict": "Not in local threat database",
                "recommendation": "Check VirusTotal, Shodan, and passive DNS for context",
            }

        prompt = f"""Triage this IoC and provide a structured risk assessment:

IoC: {json.dumps(ioc.to_stix_indicator(), indent=2)}

Additional context:
- Country: {ioc.country}
- ASN: {ioc.asn_org}
- Malware family: {ioc.malware_family}
- Threat actor: {ioc.threat_actor}
- Source feeds: {ioc.source_feed}
- Tags: {ioc.tags}
- TTPs: {ioc.ttps}

Respond in JSON:
{{
  "verdict": "malicious|suspicious|unknown",
  "confidence": <0-100>,
  "severity": "critical|high|medium|low",
  "threat_context": "What this IoC is associated with",
  "recommended_actions": ["Block at firewall", "Notify SOC", ...],
  "false_positive_indicators": ["Reason this might be FP if any"],
  "pivoting_suggestions": ["What to investigate next"]
}}"""

        response = self.client.messages.create(
            model=self.fast_model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )

        try:
            result = json.loads(response.content[0].text.strip())
            result["found"] = True
            result["value"] = ioc_value
            result["ioc_data"] = ioc.to_stix_indicator()
            return result
        except json.JSONDecodeError:
            return {
                "found": True,
                "value": ioc_value,
                "verdict": "analysis_failed",
                "raw": response.content[0].text,
            }
