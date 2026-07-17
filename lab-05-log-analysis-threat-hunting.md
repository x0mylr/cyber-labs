# Lab 05: Follow the Breadcrumbs — Log Analysis & Threat Hunting
### AI-Enabled Security | Raspberry Pi Lab Series

---

> **STATUS: COMING SOON**
> This lab is under development. Complete Labs 01–04 first.

---

## The Scenario

> It's Monday morning at **Riverside Medical Clinic** (back from Lab 02). Your manager pulls you aside:
>
> *"Something happened over the weekend. The firewall blocked a bunch of login attempts on Friday night, and one of our workstations was accessing files it normally never touches. We don't know if anything was taken. I need a timeline — what happened, when, and in what order."*
>
> The answer is in the **logs**. Every device on a network leaves a trail — login attempts, file accesses, DNS queries, web requests, error messages, and system events. A threat hunter's job is to follow those breadcrumbs and reconstruct exactly what happened.
>
> This is also how digital evidence is gathered for legal proceedings, insurance claims, and post-incident reports.

---

## What You Will Learn

| Skill | Real-World Use |
|-------|---------------|
| Reading Linux system logs | First stop in any Linux incident investigation |
| `journalctl` queries | Search logs by time, service, and severity |
| Failed SSH login analysis | Detect brute-force attacks against your systems |
| Log correlation across sources | Connect events from multiple devices |
| Timeline reconstruction | Build a chronological incident narrative |
| SIEM concepts | Understand the tools that power enterprise SOC operations |

---

## Learning Objectives

By the end of this lab, you will be able to:

- [ ] Explain what system logs are and where to find them on Linux
- [ ] Use `journalctl` to search logs by time, service, and severity
- [ ] Identify brute-force SSH login attempts in authentication logs
- [ ] Correlate log events across multiple sources to build a timeline
- [ ] Explain what a SIEM is and why organizations use them
- [ ] Write a chronological incident timeline from log data

---

## The Tools

| Tool | Purpose |
|------|---------|
| `journalctl` | Query the systemd journal (modern Linux logs) |
| `grep`, `awk`, `cut` | Parse and filter log output |
| `/var/log/auth.log` | Authentication events (logins, sudo, SSH) |
| `/var/log/syslog` | General system events |

No additional installation needed — these are built into Raspberry Pi OS.

---

## Lab Outline

### Part 1 — Where Are the Logs?

Linux logs live in two places:
- **Traditional flat files** under `/var/log/` — human-readable text
- **The systemd journal** — queryable with `journalctl`

You'll explore both and understand what each records.

### Part 2 — Your First Log Query

```bash
# What happened on this Pi in the last hour?
journalctl --since "1 hour ago"

# What services are logging right now?
journalctl -f
```

### Part 3 — Find the Attack: SSH Brute Force

This is one of the most common real-world attacks. Internet-facing servers receive hundreds of SSH login attempts every day. Your Pi can show you this happening live:

```bash
# Who tried to log in via SSH?
sudo journalctl -u ssh --since "yesterday" | grep "Failed password"

# Count attempts per IP address
sudo journalctl -u ssh --since "7 days ago" | \
  grep "Failed password" | \
  grep -oP 'from \K[\d.]+' | \
  sort | uniq -c | sort -rn | head -10
```

Sample output from a real internet-facing Pi — this is not simulated:
```
     847 185.234.219.x    ← 847 login attempts from one bot
      23 45.142.212.x
      11 103.74.193.x
       4 218.92.0.x
```

### Part 4 — Correlate Events: Build a Timeline

Using log timestamps, reconstruct the sequence of events from a simulated incident:
- When did the first failed login attempt occur?
- When (if ever) did a login succeed?
- What happened immediately after a successful login?
- What files or services were accessed?

### Part 5 — Introduction to SIEM

Manual log grepping works for a single machine. But what if you have 50 workstations, 3 servers, and 2 firewalls — all generating logs? This is what **SIEM (Security Information and Event Management)** systems solve.

You'll set up a lightweight log viewer using Docker (from Lab 01) and send your Pi's logs to it — experiencing the concept firsthand at small scale.

### Part 6 — Write the Incident Timeline

Produce a document answering:
- When did suspicious activity begin?
- What systems were involved?
- What was the sequence of events?
- What evidence supports each conclusion?

---

## Real-World Connection

Log analysis is foundational to every security role:
- **SOC Analysts** spend most of their time reading logs
- **Incident Responders** reconstruct attacks from log evidence
- **Forensics Examiners** use logs as legal evidence
- **HIPAA, PCI-DSS, and SOX** all require log retention and monitoring

The 2013 Target breach involved 40 million credit cards — and all of it was in the logs. The problem was no one was watching them in real time.

---

## Verification

A verification script will be provided at `scripts/lab-05-verify.sh`. It will check:
- [ ] `journalctl` is accessible
- [ ] Authentication log analysis commands ran successfully
- [ ] A log query output file was saved
- [ ] An incident timeline document was completed

---

## Prerequisites

- Lab 01 required (Docker, for the optional SIEM component)
- Lab 02 recommended (you'll recognize pcap data referenced in the timeline)
- Lab 03 recommended (Nmap scan logs will be referenced)
- Lab 04 recommended (web scan findings will be part of the incident scenario)

---

*Co-Lin Cyber Labs | AI-Enabled Security | Raspberry Pi Lab Series*
*Lab 05 of 06 | Next Up: Lab 06 — Intrusion Detection with Suricata*
