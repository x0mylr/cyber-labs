# Co-Lin Cyber Labs
### AI-Enabled Security | Raspberry Pi Lab Series
**Copiah-Lincoln Community College — Wesson Campus**

---

## About This Repo

This repository contains hands-on lab documents for the AI-Enabled Security course.
Labs are designed for students with little to no prior technical experience.
Each lab builds on the last — work through them in order.

---

## Getting Started

Run these commands on your Raspberry Pi:

```bash
sudo apt install git -y
git clone https://github.com/x0mylr/cyber-labs.git
cd cyber-labs
ls
```

To pull new or updated labs later:

```bash
cd cyber-labs
git pull
```

---

## Labs

| Lab | Title | Topics | Status |
|-----|-------|--------|--------|
| 01 | Build Your Own Network Ad Blocker | DNS, Pi-hole, Docker Compose | ✅ Available |
| 02 | Catching What's on the Wire | Wireshark, Packet Capture, tshark, Traffic Analysis | ✅ Available |
| 03 | Know Your Network | Nmap, Network Scanning, Host Discovery, Reconnaissance | 🔜 Coming Soon |
| 04 | Catch the Attacker | Snort, Intrusion Detection, IDS Rules, Alert Analysis | 🔜 Coming Soon |
| 05 | Follow the Breadcrumbs | Log Analysis, Threat Hunting, System Logs, Timeline Reconstruction | 🔜 Coming Soon |
| 06 | Find the Holes | OpenVAS, Vulnerability Scanning, CVSS, Remediation | 🔜 Coming Soon |

---

## How the Labs Connect

```
Lab 01: Pi-hole         → Block malicious DNS traffic before it reaches your network
         ↓
Lab 02: Wireshark       → Capture and analyze exactly what is on the wire
         ↓
Lab 03: Nmap            → Inventory your network and discover every open port
         ↓
Lab 04: Snort           → Detect attacks and suspicious traffic in real time
         ↓
Lab 05: Log Analysis    → Investigate what happened after a security event
         ↓
Lab 06: OpenVAS         → Proactively find weaknesses before an attacker does
```

---

## What You Will Need

- Raspberry Pi 4 (any RAM configuration)
- Raspberry Pi OS (64-bit recommended)
- Internet connection (classroom network)
- A browser on the Pi desktop
- That's it — all tools are free and installed during each lab

---

## Reading a Lab

```bash
cat lab-01-pihole-docker.md
```

Or open any `.md` file in a text editor on the Pi desktop.

---

*Questions? See your instructor.*
