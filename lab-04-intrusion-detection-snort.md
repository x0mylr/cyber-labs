# Lab 04: Catch the Attacker — Intrusion Detection with Snort
### AI-Enabled Security | Raspberry Pi Lab Series

> **Status: Coming Soon**

---

## The Scenario

> Your network inventory from Lab 03 is complete and sitting on your manager's desk. Three days later, they walk back in: *"One of our servers tripped an alert at 2 AM last night — someone or something was scanning it. We need eyes on the network 24/7. Set up an IDS."*
>
> An **Intrusion Detection System (IDS)** watches network traffic and fires an alert whenever it sees something suspicious — a port scan, a known exploit attempt, a malware signature, suspicious login patterns. It is the network's alarm system.

---

## What You Will Learn

- [ ] Explain the difference between an IDS (detection) and an IPS (prevention)
- [ ] Deploy Snort using Docker on your Raspberry Pi
- [ ] Understand how Snort rules are structured
- [ ] Write a basic Snort rule from scratch
- [ ] Trigger your own alerts using Nmap (from Lab 03) and verify detection
- [ ] Read and interpret Snort alert logs
- [ ] Understand the concept of false positives and why tuning matters

---

## Topics Covered

| Topic | Real-World Application |
|-------|----------------------|
| Snort rule syntax | Writing custom detection signatures for your environment |
| Network detection modes | Inline (blocking) vs. passive (alerting only) |
| Alert log analysis | Investigating and triaging IDS alerts |
| Rule tuning | Reducing false positives without missing real threats |
| Community rules | Leveraging shared threat intelligence (like Pi-hole's blocklists, but for traffic patterns) |

---

## Prerequisites

- Lab 01 (Docker) — **Required**
- Lab 02 (Wireshark) — **Required**
- Lab 03 (Nmap) — **Required**: You will use Nmap to intentionally trigger Snort alerts

---

## Sneak Peek: What You Will Build

A working Snort IDS running in Docker that monitors your network interface and generates alerts when:

- A port scan is detected
- An ICMP ping flood is detected
- A custom rule you write is matched

```
[**] [1:1000001:1] LAB04: ICMP Ping Flood Detected [**]
[Priority: 2]
03/27-09:15:33.123456 192.168.1.100 -> 192.168.1.42
ICMP TTL:64 TOS:0x0 ID:1234 IpLen:20 DgmLen:84
Type:8  Code:0  ID:1   Seq:1  ECHO
```

---

## The Rule You Will Write

By the end of this lab, you will understand exactly what this means and have written several rules of your own:

```
alert icmp any any -> $HOME_NET any (msg:"LAB04: ICMP Ping Flood"; \
  threshold: type both, track by_src, count 10, seconds 5; \
  sid:1000001; rev:1;)
```

---

## Key Tool

**Snort** — one of the most widely deployed open-source intrusion detection systems in the world. Used by enterprises, government agencies, and ISPs. The rules format created by Snort has become an industry standard also used by Suricata and other tools.

---

*Lab 04 | AI-Enabled Security | Raspberry Pi Lab Series*
*Coming Soon — check back or run `git pull` to get new labs*
