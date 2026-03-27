# Lab 03: Know Your Network — Reconnaissance & Scanning with Nmap
### AI-Enabled Security | Raspberry Pi Lab Series

> **Status: Coming Soon**

---

## The Scenario

> You have just started as an IT security intern at a small logistics company. Your manager drops a sticky note on your desk: *"Nobody has ever done a real inventory of what's on our network. We don't know what's running, what ports are open, or what OS half these machines are on. Find out."*
>
> This is **network reconnaissance** — and it is one of the first things both defenders and attackers do. Defenders use it to know what they are protecting. Attackers use it to find what they can exploit. Today, you are the defender.

---

## What You Will Learn

- [ ] Explain the difference between active and passive reconnaissance
- [ ] Use Nmap to discover live hosts on a local network
- [ ] Identify open ports and running services on a target device
- [ ] Perform OS detection and service version fingerprinting
- [ ] Understand common port numbers and what they indicate
- [ ] Interpret Nmap results to build a basic network inventory
- [ ] Recognize what your Pi "looks like" to an outside scanner

---

## Topics Covered

| Topic | Real-World Application |
|-------|----------------------|
| Host discovery (`-sn`) | Building an asset inventory before a security audit |
| TCP SYN scan (`-sS`) | Standard port scanning used in penetration tests |
| Service/version detection (`-sV`) | Identifying outdated or vulnerable software versions |
| OS detection (`-O`) | Understanding what you are dealing with on an unknown device |
| Nmap scripting engine (`--script`) | Automated checks for common vulnerabilities |
| Firewall/filter detection | Understanding why some hosts don't respond |

---

## Prerequisites

- Lab 01 (Docker & DNS) — Helpful
- Lab 02 (Wireshark) — **Required**: You will capture your own Nmap scans in Wireshark to see what scanning traffic looks like from a defender's perspective

---

## Sneak Peek: What You Will Build

By the end of this lab, you will have a **network inventory report** listing every discoverable device on your classroom network — their IP addresses, open ports, running services, and operating system. This is the same output format used in professional penetration testing engagements.

```
Nmap scan report for 192.168.1.42
Host: Up (0.0012s latency)

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.4p1 Debian
80/tcp   open  http        Pi-hole HTTP Dashboard
53/tcp   open  domain      Pi-hole DNS (Pi-hole v5.x)

OS Detection: Linux 5.x (Raspberry Pi OS)
```

---

## Key Tool

**Nmap** (Network Mapper) — the most widely used network scanning tool in the world. Used by security professionals, system administrators, and penetration testers. Free, open-source, and available on every major operating system.

```bash
# Installation preview
sudo apt install nmap -y
```

---

*Lab 03 | AI-Enabled Security | Raspberry Pi Lab Series*
*Coming Soon — check back or run `git pull` to get new labs*
