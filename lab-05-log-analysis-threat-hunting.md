# Lab 05: Follow the Breadcrumbs — Log Analysis & Threat Hunting
### AI-Enabled Security | Raspberry Pi Lab Series

> **Status: Coming Soon**

---

## The Scenario

> It is Monday morning. Your Snort IDS from Lab 04 fired several alerts over the weekend. Your manager wants answers: *"What happened? When did it start? Did they get in? What did they touch?"*
>
> The answer is in the **logs**. Every device on a network leaves a trail — login attempts, file access, DNS queries, web requests, errors. A threat hunter's job is to follow those breadcrumbs and reconstruct exactly what happened. This is also how evidence is gathered for legal proceedings, insurance claims, and post-incident reports.

---

## What You Will Learn

- [ ] Explain what system logs are and where to find them on Linux
- [ ] Use `journalctl` and standard Linux log files to investigate system activity
- [ ] Centralize logs from multiple sources using a log aggregator
- [ ] Write log search queries to find suspicious patterns
- [ ] Build a basic timeline of events from log data
- [ ] Identify signs of brute-force login attempts in authentication logs
- [ ] Understand how SIEM systems work and why they exist

---

## Topics Covered

| Topic | Real-World Application |
|-------|----------------------|
| Linux system logs (`/var/log/`) | First stop in any Linux incident investigation |
| `journalctl` queries | Searching logs by time, service, and priority |
| Failed SSH login analysis | Detecting brute-force attacks against your Pi |
| Log aggregation with Graylog or Loki | How enterprises collect logs from hundreds of machines |
| Timeline reconstruction | Building a chronological incident report |
| SIEM concepts | Understanding the category of tools that power SOC operations |

---

## Prerequisites

- Lab 01 (Docker) — **Required**
- Lab 02 (Wireshark) — Recommended
- Lab 03 (Nmap) — Recommended
- Lab 04 (Snort) — **Required**: Snort alert logs will be one of the sources analyzed in this lab

---

## Sneak Peek: What You Will Investigate

You will analyze real logs from your Raspberry Pi and answer questions like:

```bash
# Who tried to log into your Pi via SSH last night?
sudo journalctl -u ssh --since "yesterday" | grep "Failed password"

# How many times did they try?
sudo journalctl -u ssh --since "yesterday" | grep -c "Failed password"

# Where did the attempts come from?
sudo journalctl -u ssh --since "yesterday" | grep "Failed password" | \
  grep -oP 'from \K[\d.]+'  | sort | uniq -c | sort -rn
```

Sample output from an actual internet-facing Pi:
```
     847 185.234.219.x   ← 847 attempts from one IP — that's a bot
      23 45.142.212.x
      11 103.74.193.x
```

---

## Real-World Connection

The logs you analyze in this lab are the same logs that forensic investigators use when responding to data breaches. Knowing how to read system logs is a fundamental skill for:
- SOC Analysts
- Incident Responders
- Digital Forensics Examiners
- System Administrators

---

*Lab 05 | AI-Enabled Security | Raspberry Pi Lab Series*
*Coming Soon — check back or run `git pull` to get new labs*
