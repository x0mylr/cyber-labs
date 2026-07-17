# Cyber Labs
### Cybersecurity & Networking Essentials | Raspberry Pi Lab Series

---

## About This Repo

This repository contains hands-on lab documents for the Cybersecurity & Networking Essentials course.
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
| 01 | [Build Your Own Network Ad Blocker](lab-01-pihole-docker.md) | DNS, Pi-hole, Docker Compose | ✅ Available |
| 02 | [Network Traffic Analysis with Wireshark](lab-02-network-traffic-analysis.md) | tshark, Packet Capture, Display Filters, C2 Beaconing Detection | ✅ Available |
| 03 | [Network Scanning & Asset Discovery](lab-03-nmap-network-scanning.md) | Nmap, Host Discovery, Port Scanning, Asset Inventory | 🔜 Coming Soon |
| 04 | [Intrusion Detection with Snort](lab-04-intrusion-detection-snort.md) | Snort, IDS Rules, Alert Analysis, Rule Tuning | 🔜 Coming Soon |
| 04B | [Web Application Vulnerability Scanning](lab-04-web-vulnerability-scanning.md) | Nikto, DVWA, OWASP Top 10, CVE Lookup | 🔜 Coming Soon |
| 05 | [Log Analysis & Threat Hunting](lab-05-log-analysis-threat-hunting.md) | journalctl, Auth Logs, Brute-Force Detection, Timeline Reconstruction | 🔜 Coming Soon |
| 06 | [Network Vulnerability Scanning with OpenVAS](lab-06-vulnerability-scanning-openvas.md) | OpenVAS/Greenbone, CVSS Scoring, Remediation Reporting | 🔜 Coming Soon |
| 07 | [System Compromise — Recon to Root](lab-07-system-compromise.md) | Pentesting Methodology, Privilege Escalation, Capture the Flag | ✅ Available |
| 08 | [Identity & Access Management](lab-08-identity-access-management.md) | IAM, Authentication Types, MFA, Password Security, Access Control | ✅ Available |

---

## How the Labs Connect

```
Lab 01: Pi-hole         → Block known-bad DNS before it reaches your network
         ↓
Lab 02: Wireshark       → Capture and analyze exactly what is on the wire
         ↓
Lab 03: Nmap            → Inventory your network; find every device and open port
         ↓
Lab 04: Snort           → Detect attacks and suspicious patterns in real time
Lab 04B: Nikto/DVWA    → Find vulnerabilities in web applications (bonus lab)
         ↓
Lab 05: Log Analysis    → Investigate what happened after a security event
         ↓
Lab 06: OpenVAS         → Proactively find weaknesses before an attacker does
         ↓
Lab 07: Compromise Lab  → Think like an attacker — recon to root on your own Pi
         ↓
Lab 08: IAM             → Control who gets in and what they are allowed to do
```

---

## What You Will Need

- Raspberry Pi 4 (any RAM configuration) — *Lab 08 also works on Windows, macOS, or any device with a browser*
- Raspberry Pi OS (64-bit recommended)
- Internet connection (classroom network)
- A browser on the Pi desktop
- That's it — all tools are free and installed during each lab

---

## Verification Scripts

Labs 02 and later include verification scripts that check your work at each step. Run them when the lab says to — they print `[PASS]` or `[FAIL]` with instructions for fixing any failures.

```bash
# Check a specific step
bash scripts/lab-02-verify.sh check-install

# Run all checks for a lab at once
bash scripts/lab-02-verify.sh all
```

---

## Reading a Lab

```bash
cat lab-01-pihole-docker.md
```

Or open any `.md` file in a text editor on the Pi desktop.

---

*Questions? See your instructor.*
