# Lab 08 — Build an Agentic Threat Intelligence Pipeline
**Tool:** Python · SQLite · Flask · Claude AI · Docker
**Scenario:** Your SOC manager wants a system that automatically aggregates threat intelligence from multiple open-source feeds, enriches the data, and uses an AI agent to generate daily threat briefs — all running on your Raspberry Pi.

---

## What You Will Build

A full threat intelligence aggregation pipeline with five layers:

```
┌─────────────────────────────────────────────────────────────┐
│                  THREAT INTEL PIPELINE                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [Feeds]  →  [Collectors]  →  [Normalizer]  →  [Storage]  │
│                                                             │
│  Abuse.ch      Python         IoC Model       SQLite DB    │
│  CISA KEV      classes        (STIX 2.1)                   │
│  ET Labs                                                    │
│  MISP OSINT        ↓               ↓              ↓        │
│  AlienVault  [Enrichment]  →  [AI Agent]  →  [REST API]    │
│                                                             │
│              ip-api.com       Claude          Flask         │
│              RDAP             Opus 4.6        /api/v1/      │
│              NVD              Analysis        IoCs          │
│              VirusTotal       Reports         Reports       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**IoC types collected:** IPv4, domain, URL, MD5/SHA1/SHA256, CVE

---

## Background: What Is Threat Intelligence?

Threat intelligence (TI) is evidence-based knowledge about threats — who is attacking, how they operate, and what indicators they leave behind.

### Indicators of Compromise (IoCs)

An IoC is a forensic artifact that suggests a system may have been compromised:

| IoC Type | Example | What It Means |
|----------|---------|---------------|
| IP address | `185.234.219.8` | Server actively serving malware |
| Domain | `update-windows-security[.]ru` | Phishing or C2 domain |
| URL | `http://malicious.site/payload.exe` | Direct malware download link |
| File hash (SHA256) | `a3f5d2...` | Known malicious executable |
| CVE | `CVE-2024-3400` | Actively exploited vulnerability |

### The STIX 2.1 Standard

**STIX** (Structured Threat Information eXpression) is the industry standard format for sharing threat intelligence. Our pipeline normalizes all IoCs to a STIX-compatible schema so they can be shared with MISP, OpenCTI, or any other TI platform.

### MITRE ATT&CK

**MITRE ATT&CK** is a knowledge base of adversary tactics and techniques. TTPs (Tactics, Techniques, and Procedures) like `T1566.001` (spearphishing with attachment) map IoCs to the attacker's playbook.

---

## Feed Sources Used

| Feed | Provider | Type | Key Required? |
|------|----------|------|---------------|
| ThreatFox | Abuse.ch | IoCs with confidence scores | No |
| URLhaus | Abuse.ch | Active malware distribution URLs | No |
| MalwareBazaar | Abuse.ch | Malware sample hashes | No |
| KEV Catalog | CISA | Actively exploited CVEs | No |
| Security Alerts | CISA | US-CERT advisories | No |
| ET Compromised | Proofpoint | Compromised IP lists | No |
| ET Botnet C2 | Proofpoint | Command-and-control servers | No |
| OSINT Feeds | CIRCL/MISP | Community threat intelligence | No |
| OTX Pulses | AlienVault | Community TI from 200k+ users | Yes (free) |

---

## Part 1 — Set Up the Environment

### Step 1: Clone and enter the lab directory

```bash
cd ~/cyber-labs
ls threat-intel-pipeline/
```

You should see:
```
threat-intel-pipeline/
├── Dockerfile
├── docker-compose.yml
├── main.py
├── requirements.txt
├── .env.example
├── config/
│   └── config.yaml
└── pipeline/
    ├── models.py       ← IoC data model (STIX-compatible)
    ├── storage.py      ← SQLite database layer
    ├── enricher.py     ← IoC enrichment (GeoIP, WHOIS, VirusTotal)
    ├── agent.py        ← Claude AI analysis agent
    ├── api.py          ← Flask REST API
    ├── scheduler.py    ← Background collection orchestrator
    ├── config.py       ← Configuration loader
    └── collectors/
        ├── base.py                     ← Abstract base class
        ├── abusech_collector.py        ← ThreatFox, URLhaus, MalwareBazaar
        ├── cisa_collector.py           ← KEV + Alerts
        ├── emerging_threats_collector.py ← ET Labs IP lists
        ├── misp_collector.py           ← MISP feeds
        └── otx_collector.py            ← AlienVault OTX
```

### Step 2: Configure your API keys

```bash
cd threat-intel-pipeline
cp .env.example .env
nano .env
```

**Minimum required for AI features:**
```
ANTHROPIC_API_KEY=sk-ant-api03-...
```

**Optional (enable with free signup):**
- `OTX_API_KEY` — from https://otx.alienvault.com/ (free account)
- `VT_API_KEY` — from https://www.virustotal.com/ (free account, 1000/day)

> The pipeline is fully functional without optional keys — it will simply skip those collectors.

### Step 3: Install Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Part 2 — Understand the Data Model

Before running anything, study the core IoC model.

### Read the models file

```bash
cat pipeline/models.py
```

Look for the `IoC` dataclass. Notice:
- `type` uses STIX 2.1 vocabulary (`ipv4-addr`, `domain-name`, etc.)
- `confidence` is a 0-100 score from the source feed
- `severity` is our assessment: `critical/high/medium/low`
- `fingerprint()` creates a deduplication hash based on type + value
- `to_stix_indicator()` exports to STIX 2.1 JSON format

**Checkpoint questions:**
1. What is the purpose of the `fingerprint()` method?
2. Why do we have both `first_seen` and `last_seen` timestamps?
3. What are TTPs and why are they important for an analyst?

---

## Part 3 — Run Your First Collection

### Step 4: Collect from all enabled feeds

```bash
python main.py collect
```

Expected output (times and counts will vary):
```
2026-04-02 10:00:01 [INFO] pipeline.collectors — [abusech_threatfox] Starting collection
2026-04-02 10:00:03 [INFO] pipeline.collectors — [abusech_threatfox] Collected 247 IoCs
2026-04-02 10:00:04 [INFO] pipeline.collectors — [abusech_urlhaus] Collected 891 URLs
...

Collection Summary:
{
  "abusech_threatfox": {"collected": 247, "inserted": 245, "updated": 2, "status": "ok"},
  "abusech_urlhaus":   {"collected": 891, "inserted": 889, "updated": 2, "status": "ok"},
  "cisa_kev":          {"collected": 18,  "inserted": 0,   "updated": 18, "status": "ok"},
  ...
}
Total: 2,847 IoCs collected, 2,198 new
```

> The CISA KEV shows 0 new inserts because those CVEs are already in the catalog — they just get `updated` to refresh `last_seen`. This is the deduplication system working correctly.

### Step 5: Check the statistics

```bash
python main.py stats
```

You should see a breakdown by type, severity, feed, malware family, and source country.

**Checkpoint:** How many unique IoCs are in the database? Which feed contributed the most?

---

## Part 4 — Explore the Database Directly

### Step 6: Query the SQLite database

```bash
sqlite3 data/threat_intel.db
```

```sql
-- How many IoCs of each type?
SELECT type, COUNT(*) as count FROM iocs GROUP BY type ORDER BY count DESC;

-- Most common malware families
SELECT malware_family, COUNT(*) as count
FROM iocs
WHERE malware_family IS NOT NULL
GROUP BY malware_family
ORDER BY count DESC
LIMIT 10;

-- High-confidence C2 servers
SELECT value, country, asn_org, malware_family, confidence
FROM iocs
WHERE threat_type = 'command-and-control'
  AND confidence >= 80
ORDER BY confidence DESC
LIMIT 20;

-- CVEs with critical severity
SELECT value, tags, source_feed
FROM iocs
WHERE type = 'vulnerability'
  AND severity = 'critical'
ORDER BY first_seen DESC;

-- IPs from the top 5 source countries
SELECT country, COUNT(*) as count
FROM iocs
WHERE type = 'ipv4-addr'
GROUP BY country
ORDER BY count DESC
LIMIT 5;
```

```bash
.quit
```

**Checkpoint:** What are the top 3 malware families in your database right now?

---

## Part 5 — AI Threat Analysis

### Step 7: Generate your first threat brief

> This step requires `ANTHROPIC_API_KEY` to be set.

```bash
python main.py analyze 24
```

Claude will analyze the IoCs collected in the last 24 hours and produce a structured brief including:
- Executive summary (for leadership)
- Key findings with evidence
- Identified threat actors and malware families
- MITRE ATT&CK techniques
- Prioritized recommendations

### Step 8: Triage a specific IoC

Pick an IP address from your database:

```bash
# Get a high-confidence C2 IP
sqlite3 data/threat_intel.db \
  "SELECT value FROM iocs WHERE threat_type='command-and-control' AND confidence >= 80 LIMIT 1;"
```

Then triage it:
```bash
python main.py triage 185.234.219.8   # replace with your actual IP
```

The AI will provide:
- Verdict (malicious/suspicious/unknown)
- Threat context
- Recommended actions
- Pivoting suggestions (what to investigate next)

### Step 9: Ask the analyst a question

```bash
python main.py ask "What ransomware families are most active in the last 24 hours?"
python main.py ask "Are there any indicators related to Cobalt Strike?"
python main.py ask "Which C2 servers should I prioritize blocking first?"
```

---

## Part 6 — REST API

### Step 10: Start the API server

```bash
python main.py serve
```

In a second terminal:

```bash
# Health check
curl http://localhost:8000/health

# Get statistics
curl http://localhost:8000/api/v1/stats | python3 -m json.tool

# Query high-severity IoCs
curl "http://localhost:8000/api/v1/iocs?severity=high&limit=10" | python3 -m json.tool

# Query C2 servers only
curl "http://localhost:8000/api/v1/iocs?threat_type=command-and-control&min_confidence=70" \
  | python3 -m json.tool

# Get the latest threat brief
curl http://localhost:8000/api/v1/reports/latest | python3 -m json.tool

# Triage an IoC via API
curl -X POST http://localhost:8000/api/v1/iocs/185.234.219.8/triage | python3 -m json.tool

# Ask the AI analyst
curl -X POST http://localhost:8000/api/v1/analyze/ask \
  -H "Content-Type: application/json" \
  -d '{"question": "What are the top threats right now?"}' \
  | python3 -m json.tool
```

**Notice the STIX 2.1 format in the IoC responses** — every IoC includes a `pattern` field in STIX pattern language, making it immediately usable with MISP, Sigma, or any STIX-compatible tool.

---

## Part 7 — Docker Deployment

### Step 11: Build and run with Docker Compose

```bash
# Build the image
docker compose build

# Start in the background
docker compose up -d

# Watch the logs
docker compose logs -f pipeline

# Run a manual collection from inside the container
docker compose exec pipeline python main.py collect

# Check stats inside the container
docker compose exec pipeline python main.py stats

# Stop
docker compose down
```

Docker Compose automatically:
- Mounts a persistent volume for the SQLite database
- Loads your `.env` file for API keys
- Exposes port 8000 externally
- Restarts the pipeline on failure
- Health-checks the API every 30 seconds

---

## Part 8 — Automate with Cron (Alternative to Docker)

If you want to run collection without keeping a server up:

```bash
# Edit crontab
crontab -e
```

Add these lines:
```cron
# Collect threat intel every hour
0 * * * * cd /home/pi/cyber-labs/threat-intel-pipeline && \
  source .venv/bin/activate && \
  python main.py collect >> logs/collect.log 2>&1

# Generate AI threat brief every 6 hours
0 */6 * * * cd /home/pi/cyber-labs/threat-intel-pipeline && \
  source .venv/bin/activate && \
  python main.py analyze 6 >> logs/analyze.log 2>&1
```

---

## Part 9 — Add a New Feed Collector (Bonus Challenge)

The collector architecture is designed for extension. Add a new feed:

### Step 12: Create a new collector

```bash
cat > pipeline/collectors/phishtank_collector.py << 'EOF'
"""PhishTank collector — verified phishing URLs."""
import csv, io
from ..models import IoC, IoCType, ThreatType, Severity
from .base import BaseCollector

class PhishTankCollector(BaseCollector):
    URL = "https://data.phishtank.com/data/online-valid.csv"

    @property
    def name(self): return "phishtank"

    def collect(self):
        resp = self.get(self.URL)
        reader = csv.DictReader(io.StringIO(resp.text))
        iocs = []
        for row in list(reader)[:500]:  # limit to 500
            url = row.get("url", "").strip()
            if url:
                iocs.append(IoC(
                    type=IoCType.URL,
                    value=url,
                    source_feed=self.name,
                    threat_type=ThreatType.PHISHING,
                    confidence=90,  # PhishTank is community-verified
                    severity=Severity.HIGH,
                ))
        return iocs
EOF
```

### Step 13: Register it

Edit `pipeline/collectors/__init__.py` and add:
```python
from .phishtank_collector import PhishTankCollector
COLLECTOR_REGISTRY["phishtank"] = PhishTankCollector
```

### Step 14: Enable it in config

Edit `config/config.yaml` and add:
```yaml
collectors:
  phishtank:
    enabled: true
```

Then run `python main.py collect` — your new feed is live.

---

## How the AI Agent Works

The `ThreatIntelAgent` class (`pipeline/agent.py`) follows this pattern:

```
1. Query storage for recent IoCs (filtered by time + confidence)
2. Sort by severity/confidence (most critical first)
3. Truncate to fit in Claude's context window
4. Build a structured prompt with:
   - System role: "expert threat intelligence analyst"
   - Statistics summary (feed coverage, type breakdown)
   - IoC sample in structured JSON
5. Call Claude API (claude-opus-4-6 for analysis)
6. Parse structured JSON response
7. Save report to SQLite
```

The agent supports four operations:
| Method | Use Case |
|--------|----------|
| `generate_threat_brief()` | Scheduled daily/weekly TI brief |
| `correlate_iocs()` | Campaign and infrastructure correlation |
| `ask(question)` | Free-form analyst Q&A |
| `triage_ioc(value)` | On-demand single IoC assessment |

---

## Understanding the Pipeline Output

### STIX 2.1 Indicator Example

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--550e8400-e29b-41d4-a716-446655440000",
  "name": "ipv4-addr: 185.234.219.8",
  "indicator_types": ["command-and-control"],
  "pattern": "[ipv4-addr:value = '185.234.219.8']",
  "pattern_type": "stix",
  "valid_from": "2026-04-01T08:00:00+00:00",
  "confidence": 85,
  "labels": ["botnet-c2", "emerging-threats"],
  "x_source_feed": "emerging_threats",
  "x_malware_family": "Mirai",
  "x_severity": "high",
  "x_ttps": ["T1071.001"]
}
```

This format can be:
- Imported directly into MISP or OpenCTI
- Used in SIEM correlation rules
- Fed into EDR/firewall blocklists
- Shared with ISACs and partner organizations

---

## Bonus Challenges

### Challenge 1 — Export to a Blocklist
Write a script that exports all high-confidence IPs to a format your Pi-hole can use as a custom blocklist (from Lab 01).

```bash
sqlite3 data/threat_intel.db \
  "SELECT value FROM iocs WHERE type='ipv4-addr' AND confidence >= 80" \
  > /tmp/threat-ips.txt
```

### Challenge 2 — Snort Rule Generation
Ask the AI to generate Snort rules for the top C2 servers:
```bash
python main.py ask "Generate 5 Snort IDS rules for the top C2 IPs in the database. Format as valid Snort rule syntax."
```

### Challenge 3 — Scheduled Weekly Report
Set up a cron job to email yourself (or save to file) a weekly threat brief every Monday at 08:00.

### Challenge 4 — Integrate with Lab 04 (Snort)
The pipeline's REST API means your Snort IDS from Lab 04 could query it.  
Design (on paper) how you would:
1. Have Snort alert on an IP
2. Query `/api/v1/iocs/{ip}` automatically
3. If the IP is in the threat database, escalate the alert severity

---

## Certification Objectives Covered

| Certification | Objective |
|---------------|-----------|
| CompTIA CySA+ CS0-003 | 1.1 — Explain importance of threat data and intelligence |
| CompTIA CySA+ CS0-003 | 1.2 — Utilize threat intelligence to support organizational security |
| CompTIA CySA+ CS0-003 | 2.1 — Analyze data as part of continuous security monitoring |
| CompTIA CySA+ CS0-003 | 2.2 — Implement configuration changes to existing controls |
| CompTIA Security+ SY0-701 | 2.1 — Summarize threat intelligence concepts |
| CompTIA Security+ SY0-701 | 4.4 — Appropriate tools to assess organizational security |
| CompTIA PenTest+ PT0-003 | 1.3 — Given a scenario, use appropriate passive recon techniques |

---

## Key Vocabulary

| Term | Definition |
|------|-----------|
| IoC | Indicator of Compromise — forensic artifact suggesting a breach |
| TTP | Tactics, Techniques, and Procedures — attacker's playbook |
| STIX 2.1 | Structured Threat Information eXpression — sharing standard |
| TAXII | Transport layer for sharing STIX objects between organizations |
| MISP | Malware Information Sharing Platform — open-source TI hub |
| CTI | Cyber Threat Intelligence — actionable intelligence about threats |
| KEV | Known Exploited Vulnerabilities — CISA's must-patch CVE list |
| TLP | Traffic Light Protocol — classification for sharing sensitivity |
| OSINT | Open-Source Intelligence — publicly available threat data |
| Feed | A regularly updated source of threat indicators |
| Enrichment | Adding context to an IoC (GeoIP, WHOIS, VT score) |
| Deduplication | Preventing the same IoC from being stored multiple times |
| False Positive | A benign indicator incorrectly flagged as malicious |

---

## Instructor Sign-Off

### Skills Demonstrated
- [ ] I can explain what an IoC is and give three examples of different types
- [ ] I ran the pipeline and collected IoCs from at least 3 different feeds
- [ ] I queried the SQLite database directly using SQL to find specific IoC types
- [ ] I generated an AI threat brief and explained one key finding to my instructor
- [ ] I used the triage endpoint to assess a specific IoC
- [ ] I can explain what STIX 2.1 is and why a standard format matters
- [ ] I can describe the difference between strategic, operational, and tactical threat intelligence
- [ ] I successfully added a new collector (Bonus Challenge)

**Date Completed:** _______________________

**Instructor Initials:** _______________________

**Notes:** _______________________________________________

---

*Cybersecurity & Networking Essentials | Raspberry Pi Lab Series*
