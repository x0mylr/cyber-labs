# Cybersecurity & Networking Essentials
## Student Skill Passport
### Raspberry Pi Lab Series

---

**Student Name:** _______________________________________________

**Date Started:** _______________________________________________

**Instructor:** _______________________________________________

---

> This passport tracks your progress through the lab series. After completing each lab, bring this document to your instructor for sign-off. Each completed lab demonstrates real skills used by cybersecurity professionals in the field.

---

## How to Use This Passport

1. Work through each lab in order — they build on each other
2. Check off each objective as you complete it
3. Show your instructor your completed checkpoints before requesting sign-off
4. Keep this document — it is a record of what you can do, not just what you sat through

---

---

## Lab 01 — Build Your Own Network Ad Blocker
**Tool:** Pi-hole · Docker Compose · DNS
**Scenario:** Deploy a network-level ad and malware blocker for a home or small office

### Skills Demonstrated
- [ ] I can explain what DNS is and how it translates domain names to IP addresses
- [ ] I used Docker Compose to deploy a real security tool from a configuration file
- [ ] I accessed and navigated the Pi-hole web dashboard
- [ ] I verified that DNS-level blocking was working using `nslookup`
- [ ] I connected a device to use Pi-hole as its DNS server
- [ ] I updated Pi-hole's blocklists using `pihole -g`
- [ ] I can explain the difference between `docker compose up` and `docker compose up -d`

### Certification Objectives Covered
| Certification | Objective |
|---------------|-----------|
| CompTIA Network+ (N10-009) | 1.2 — Network protocols and services (DNS) |
| CompTIA Network+ (N10-009) | 2.1 — Compare and contrast network devices and features |
| CompTIA Security+ (SY0-701) | 3.2 — Network-level filtering and asset management |
| CompTIA Security+ (SY0-701) | 4.4 — Tools to assess organizational security |

### Instructor Sign-Off

**Date Completed:** _______________________

**Instructor Initials:** _______________________

**Notes:** _______________________________________________

---

---

## Lab 02 — Catching What's on the Wire
**Tool:** Wireshark · tshark
**Scenario:** SOC analyst investigating a slow or suspicious network by capturing and analyzing live traffic

### Skills Demonstrated
- [ ] I can explain what a packet is and why packet capture matters for security
- [ ] I installed Wireshark and tshark on a Raspberry Pi
- [ ] I identified my network interface and confirmed it had an active IP address
- [ ] I captured live traffic using `tshark` and saved it to a `.pcap` file
- [ ] I opened a capture file in the Wireshark GUI and identified the three main panels
- [ ] I applied display filters to isolate specific protocols (DNS, ICMP, HTTP, TCP)
- [ ] I used `Follow TCP Stream` to reconstruct a full network conversation
- [ ] I used `tshark` to export packet fields to a CSV file
- [ ] I can identify at least two traffic patterns that would warrant further investigation
- [ ] I can explain what TCP Reset packets indicate and why they may be suspicious

### Certification Objectives Covered
| Certification | Objective |
|---------------|-----------|
| CompTIA Network+ (N10-009) | 1.1 — OSI model layers and encapsulation |
| CompTIA Network+ (N10-009) | 5.3 — Network troubleshooting tools (packet analysis) |
| CompTIA Security+ (SY0-701) | 4.4 — Tools to assess organizational security |
| CompTIA CySA+ (CS0-003) | 2.2 — Analyze data as part of security monitoring |

### Instructor Sign-Off

**Date Completed:** _______________________

**Instructor Initials:** _______________________

**Notes:** _______________________________________________

---

---

## Lab 03 — Know Your Network *(Coming Soon)*
**Tool:** Nmap
**Scenario:** Build a network inventory for a company that has never done a security audit

### Skills Demonstrated
- [ ] I can explain the difference between active and passive reconnaissance
- [ ] I used Nmap to discover all live hosts on the classroom network
- [ ] I identified open ports and running services on a target device
- [ ] I performed OS detection and service version fingerprinting
- [ ] I interpreted Nmap output to produce a basic network inventory
- [ ] I captured my own Nmap scan in Wireshark to see what scanning traffic looks like

### Certification Objectives Covered
| Certification | Objective |
|---------------|-----------|
| CompTIA Security+ (SY0-701) | 4.3 — Explain vulnerability scanning techniques |
| CompTIA Security+ (SY0-701) | 4.4 — Appropriate tools to assess organizational security |
| CompTIA PenTest+ (PT0-003) | 3.1 — Network scanning and enumeration |

### Instructor Sign-Off

**Date Completed:** _______________________

**Instructor Initials:** _______________________

**Notes:** _______________________________________________

---

---

## Lab 04 — Catch the Attacker *(Coming Soon)*
**Tool:** Snort IDS · Docker
**Scenario:** Set up 24/7 intrusion detection after a server is scanned overnight

### Skills Demonstrated
- [ ] I can explain the difference between an IDS (detection) and an IPS (prevention)
- [ ] I deployed Snort using Docker
- [ ] I read and interpreted the structure of a Snort rule
- [ ] I wrote a basic Snort rule from scratch
- [ ] I intentionally triggered my own alerts using Nmap and verified detection
- [ ] I read and interpreted Snort alert logs
- [ ] I can explain what a false positive is and why tuning matters

### Certification Objectives Covered
| Certification | Objective |
|---------------|-----------|
| CompTIA Security+ (SY0-701) | 4.5 — Explain the techniques used in security assessments |
| CompTIA CySA+ (CS0-003) | 1.1 — Explain the importance of threat data and intelligence |
| CompTIA CySA+ (CS0-003) | 2.1 — Analyze data as part of continuous security monitoring |

### Instructor Sign-Off

**Date Completed:** _______________________

**Instructor Initials:** _______________________

**Notes:** _______________________________________________

---

---

## Lab 05 — Follow the Breadcrumbs *(Coming Soon)*
**Tool:** journalctl · Linux system logs · Log aggregation
**Scenario:** Investigate weekend IDS alerts using system and security logs

### Skills Demonstrated
- [ ] I can locate and read key Linux system log files
- [ ] I used `journalctl` to search logs by time, service, and priority
- [ ] I identified failed SSH login attempts in authentication logs
- [ ] I determined the source IP of repeated login attempts
- [ ] I built a chronological timeline of events from log data
- [ ] I can explain what a SIEM is and why organizations use them

### Certification Objectives Covered
| Certification | Objective |
|---------------|-----------|
| CompTIA Security+ (SY0-701) | 4.8 — Explain the key aspects of digital forensics |
| CompTIA CySA+ (CS0-003) | 2.2 — Analyze data as part of security monitoring activities |
| CompTIA CySA+ (CS0-003) | 4.1 — Explain the importance of the incident response process |

### Instructor Sign-Off

**Date Completed:** _______________________

**Instructor Initials:** _______________________

**Notes:** _______________________________________________

---

---

## Lab 06 — Find the Holes *(Coming Soon)*
**Tool:** OpenVAS / Greenbone · Docker
**Scenario:** Produce a vulnerability assessment report required for cyber insurance renewal

### Skills Demonstrated
- [ ] I can explain the difference between a vulnerability scan and a penetration test
- [ ] I deployed OpenVAS using Docker and ran a scan against a target
- [ ] I read a vulnerability report and interpreted CVSS severity scores
- [ ] I looked up a CVE number and found its description in the National Vulnerability Database
- [ ] I prioritized which vulnerabilities to remediate first based on risk
- [ ] I can explain what compliance frameworks like PCI-DSS and HIPAA require regarding vulnerability scanning

### Certification Objectives Covered
| Certification | Objective |
|---------------|-----------|
| CompTIA Security+ (SY0-701) | 4.3 — Explain vulnerability scanning techniques and concepts |
| CompTIA Security+ (SY0-701) | 5.1 — Summarize elements of effective security governance |
| CompTIA PenTest+ (PT0-003) | 3.2 — Perform vulnerability scanning |
| CompTIA CySA+ (CS0-003) | 3.1 — Explain vulnerability management activities |

### Instructor Sign-Off

**Date Completed:** _______________________

**Instructor Initials:** _______________________

**Notes:** _______________________________________________

---

---

## Passport Complete

When all six labs are signed off, you have demonstrated foundational skills across the full security operations lifecycle:

```
Prevent  →  Detect  →  Capture  →  Scan  →  Investigate  →  Assess
(Lab 01)   (Lab 04)   (Lab 02)   (Lab 03)   (Lab 05)       (Lab 06)
```

### What These Skills Lead To

| Next Step | Details |
|-----------|---------|
| CompTIA Network+ | Entry-level networking certification, ~$369 exam |
| CompTIA Security+ | DoD-approved security certification, most in-demand entry cert |
| CompTIA CySA+ | Intermediate analyst certification, builds directly on this series |
| Entry-Level Roles | SOC Analyst, IT Security Technician, Network Administrator |

---

## Full Certification Objective Index

Use this table to find which lab covers a specific CompTIA objective:

| Certification | Objective | Lab(s) |
|---------------|-----------|--------|
| Network+ N10-009 | 1.1 — OSI model and encapsulation | Lab 02 |
| Network+ N10-009 | 1.2 — Network protocols and services (DNS) | Lab 01 |
| Network+ N10-009 | 2.1 — Network devices and features | Lab 01 |
| Network+ N10-009 | 5.3 — Network troubleshooting tools | Lab 02 |
| Security+ SY0-701 | 3.2 — Network-level filtering | Lab 01 |
| Security+ SY0-701 | 4.3 — Vulnerability scanning techniques | Labs 03, 06 |
| Security+ SY0-701 | 4.4 — Tools to assess organizational security | Labs 01, 02 |
| Security+ SY0-701 | 4.5 — Security assessment techniques | Lab 04 |
| Security+ SY0-701 | 4.8 — Digital forensics | Lab 05 |
| Security+ SY0-701 | 5.1 — Security governance | Lab 06 |
| CySA+ CS0-003 | 1.1 — Threat data and intelligence | Lab 04 |
| CySA+ CS0-003 | 2.1 — Continuous security monitoring | Lab 04 |
| CySA+ CS0-003 | 2.2 — Security monitoring and analysis | Labs 02, 05 |
| CySA+ CS0-003 | 3.1 — Vulnerability management | Lab 06 |
| CySA+ CS0-003 | 4.1 — Incident response process | Lab 05 |
| PenTest+ PT0-003 | 3.1 — Network scanning and enumeration | Lab 03 |
| PenTest+ PT0-003 | 3.2 — Vulnerability scanning | Lab 06 |

---

*Cybersecurity & Networking Essentials | Raspberry Pi Lab Series*
