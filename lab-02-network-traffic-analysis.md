# Lab 02: Network Traffic Analysis with Wireshark & tshark
### AI-Enabled Security | Raspberry Pi Lab Series

---

## The Scenario

> You've just started your first week as a junior security analyst at **Riverside Medical Clinic**. On Tuesday morning, your manager Sarah stops by your desk:
>
> *"Hey — our firewall has been logging periodic outbound connections to an IP address we don't recognize. It happens every 30 seconds like clockwork, but only during business hours. The connections are small, but the regularity is what's weird. I need you to set up a packet capture on one of our workstations and find out what's going on."*
>
> Your job: capture and analyze network traffic to identify the suspicious pattern and document your findings.

This is a real scenario. Periodic, regular connections from a machine to an external server are one of the most common signs of **malware Command & Control (C2) beaconing** — the way malware phones home to receive instructions. In this lab, you'll learn the exact skill set used to detect it.

---

## Learning Objectives

By the end of this lab, you will be able to:

- [ ] Explain what network packets are and how they travel across a network
- [ ] Install Wireshark and tshark on Raspberry Pi OS
- [ ] Capture live network traffic using command-line tools
- [ ] Apply display filters to isolate specific traffic types
- [ ] Identify suspicious beaconing patterns in a packet capture
- [ ] Write a basic security incident summary

---

## Background

### From Lab 01 to Lab 02: Going Deeper

In Lab 01, we intercepted DNS requests at the **application layer** — Pi-hole checked domain names against a blocklist before any real connection was made. That's powerful, but it only sees domain names, not the actual data being exchanged.

In this lab, we go deeper. We'll capture the raw **packets** that make up every connection on your network — not just the "phone book lookup," but the actual letters being sent and received.

---

### What is a Network Packet?

Think of sending a large document by mail. You don't fit it in one envelope — you break it into pages, number them, and mail each separately. The recipient reassembles them in order. Network **packets** work exactly the same way.

```
You type: "load google.com"
              |
              v
   [Browser breaks request into packets]
              |
   +----------+----------+----------+
   | Packet 1 | Packet 2 | Packet 3 |
   | (#1 of 3)| (#2 of 3)| (#3 of 3)|
   +----------+----------+----------+
              |
   [Routed across internet, reassembled at destination]
```

Each packet has two parts:
- **Header** — routing information (where it's from, where it's going, what protocol, how big)
- **Payload** — the actual data

Wireshark lets you read both parts of every packet your network interface sees.

---

### The OSI Model (The Layers of a Network)

Network communication is organized into layers. Each layer handles a different job. You don't need to memorize all seven — just understand that Wireshark can show you all of them at once.

| Layer | Name | What It Does | Real Example |
|-------|------|-------------|--------------|
| 7 | Application | The actual content | HTTP webpage, DNS query |
| 4 | Transport | Delivery rules | TCP (reliable), UDP (fast) |
| 3 | Network | Addressing | IP addresses |
| 2 | Data Link | Device-to-device | MAC addresses |
| 1 | Physical | The wire/radio | Ethernet cable, WiFi |

---

### What is Wireshark?

Wireshark is the world's most widely used network protocol analyzer. It captures raw packets from your network interface and lets you read every field in every header and every byte of payload.

Security professionals use it to:
- Investigate security incidents
- Identify malware communication patterns
- Verify that encryption is actually working
- Debug connectivity problems
- Understand how protocols work

**tshark** is Wireshark's command-line sibling — it does everything Wireshark does but runs entirely in a terminal, making it perfect for Raspberry Pi and for scripting.

> **Why not use Wireshark in Docker this time?**
> Packet capture requires direct access to your host network interfaces. Running tshark inside a container would only see traffic inside the container — not the real network traffic we're investigating. This is one case where native installation is the right tool for the job.

---

## Lab Requirements

- **Hardware:** Raspberry Pi 4 (any RAM) with network connection
- **OS:** Raspberry Pi OS (64-bit Bookworm recommended)
- **Network:** Ethernet or WiFi (Ethernet preferred — more traffic to capture)
- **Time:** 45–60 minutes
- **Accounts needed:** None
- **Prior labs:** Lab 01 recommended but not required

> You'll need `sudo` access to capture network traffic. This is expected — raw packet capture is a privileged operation on all operating systems.

---

## Part 1: Install Wireshark and tshark

### Step 1.1: Update Your Package List

Always update before installing new software:

```bash
sudo apt update
```

Expected output:
```
Hit:1 http://deb.debian.org/debian bookworm InRelease
...
Reading package lists... Done
```

### Step 1.2: Install Wireshark and tshark

```bash
sudo apt install -y wireshark tshark
```

**During installation you will see a configuration prompt:**

```
┌──────────────────────────────────────────────────────────────┐
│ Configuring wireshark-common                                 │
│                                                              │
│ Should non-superusers be able to capture packets?            │
│                                                              │
│    <Yes>                           <No>                      │
└──────────────────────────────────────────────────────────────┘
```

**Select `<Yes>` using the arrow keys, then press Enter.**

This grants packet capture capability to members of the `wireshark` group without requiring full root access — a security best practice (least privilege).

### Step 1.3: Add Your User to the Wireshark Group

Your user account now needs to be added to the `wireshark` group to use that permission:

```bash
sudo usermod -aG wireshark $USER
```

Apply the group change in your current session without logging out:

```bash
newgrp wireshark
```

### Step 1.4: Verify Installation

```bash
tshark --version
```

Expected output (version numbers will vary):
```
TShark (Wireshark) 4.0.x

Copyright 1998-2023 Gerald Combs <gerald@wireshark.org> and contributors.
...
```

> If you see `command not found`, see [Appendix A.1](#a1-tshark-not-found-after-installation).

### Step 1.5: Create the Lab Working Directories

```bash
mkdir -p ~/cyber-labs/captures
mkdir -p ~/cyber-labs/reports
```

---

### Checkpoint 1 — Verify Your Installation

Run the lab verification script to confirm everything is properly set up:

```bash
bash ~/cyber-labs/scripts/lab-02-verify.sh check-install
```

Expected output:
```
[PASS] tshark is installed
[PASS] wireshark is installed
[PASS] User 'pi' is in the wireshark group
[PASS] Captures directory exists
[PASS] Reports directory exists
[INFO] Installation check complete. Ready to capture packets.
```

> If any item shows `[FAIL]`, stop and fix it before continuing. The Appendix has solutions for each failure type.

---

## Part 2: Understand Your Network Interfaces

Before capturing traffic, you need to know **which network interface** to capture on. Your Raspberry Pi likely has more than one.

### Step 2.1: List Available Interfaces

```bash
ip link show
```

Expected output (your exact names and details will differ):
```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP
    link/ether dc:a6:32:xx:xx:xx brd ff:ff:ff:ff:ff:ff
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP
    link/ether dc:a6:32:xx:xx:xx brd ff:ff:ff:ff:ff:ff
```

**What you're looking at:**

| Interface | Type | When to use it |
|-----------|------|----------------|
| `lo` | Loopback | Internal Pi-to-Pi traffic only (127.0.0.1) — skip this |
| `eth0` | Ethernet | Use this if you have an Ethernet cable plugged in |
| `wlan0` | WiFi | Use this if you're connected wirelessly |

Look for `state UP` — that tells you the interface is active.

### Step 2.2: Ask tshark to List Capture Interfaces

```bash
tshark -D
```

Expected output:
```
1. eth0
2. wlan0
3. lo (Loopback)
4. any
5. bluetooth-monitor
...
```

The `any` option captures from all interfaces at once — useful for troubleshooting but produces more noise.

> **Write down your active interface name here: _______________**
>
> You will use this in every capture command in this lab. Most students on Ethernet will use `eth0`; WiFi users will use `wlan0`.

### Step 2.3: Check What IP Address Your Interface Has

```bash
ip addr show eth0
```

(Replace `eth0` with your interface name.)

Expected output:
```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.1.105/24 brd 192.168.1.255 scope global dynamic eth0
```

The `inet` line shows your Pi's IP address (`192.168.1.105` in this example). Write this down too — you'll see it in your captures.

> **Your Pi's IP address: _______________**

---

### Checkpoint 2 — Verify Network Interfaces

```bash
bash ~/cyber-labs/scripts/lab-02-verify.sh check-interfaces
```

Expected output:
```
[INFO] Available interfaces detected by tshark:
  1. eth0
  2. wlan0
  3. lo (Loopback)
[PASS] At least one non-loopback interface found
[INFO] Interface check complete.
```

---

## Part 3: Your First Packet Capture

Let's capture real traffic so you can see what raw packet data looks like.

### Step 3.1: Understand the tshark Command

The basic syntax is:
```
tshark -i <interface> [options] -w <output_file>
```

Key flags you'll use:

| Flag | Meaning |
|------|---------|
| `-i eth0` | Capture on the `eth0` interface |
| `-a duration:30` | Auto-stop after 30 seconds |
| `-w file.pcap` | Save captured packets to file |
| `-r file.pcap` | Read packets from a saved file |
| `-Y "filter"` | Apply a display filter |
| `-c 100` | Stop after capturing 100 packets |

### Step 3.2: Capture a 30-Second Baseline

Run this command (use your actual interface name):

```bash
tshark -i eth0 -a duration:30 -w ~/cyber-labs/captures/baseline.pcap
```

**While the capture is running (30 seconds), open a second terminal and generate some traffic:**

```bash
# In a second terminal:
curl -s https://example.com > /dev/null
curl -s https://google.com > /dev/null
ping -c 4 8.8.8.8
```

tshark will print a running count and then stop:
```
Capturing on 'eth0'
 ** (process:XXXXX) 15:42:01.234567 [Main MESSAGE] -- Capture started.
    30 packets captured
```

### Step 3.3: Verify the Capture File

Check the file was created and contains data:

```bash
ls -lh ~/cyber-labs/captures/baseline.pcap
```

Expected (size will vary):
```
-rw-r--r-- 1 pi pi 14K Mar 27 10:31 baseline.pcap
```

Count how many packets were captured:
```bash
tshark -r ~/cyber-labs/captures/baseline.pcap | wc -l
```

This number should be greater than 0. Even a Pi doing nothing captures background network chatter (router announcements, mDNS probes, etc.).

### Step 3.4: Read the Capture Back

Display the captured packets on screen:

```bash
tshark -r ~/cyber-labs/captures/baseline.pcap | head -20
```

Expected output (yours will look different — the content depends on your network):
```
    1   0.000000  192.168.1.105 → 8.8.8.8      DNS  75 Standard query A example.com
    2   0.021451  8.8.8.8 → 192.168.1.105      DNS  91 Standard query response A 93.184.216.34
    3   0.022002  192.168.1.105 → 93.184.216.34 TCP  74 52301 → 443 [SYN] Seq=0
    4   0.098334  93.184.216.34 → 192.168.1.105 TCP  74 443 → 52301 [SYN, ACK]
    5   0.098800  192.168.1.105 → 93.184.216.34 TCP  66 52301 → 443 [ACK]
```

**Read that output left-to-right:**
`[packet #]  [timestamp]  [source] → [destination]  [protocol]  [size]  [description]`

You're looking at a DNS query (#1), the response (#2), and then a TCP connection being set up (#3-5). That's a browser loading a website.

---

### Checkpoint 3 — Verify Your First Capture

```bash
bash ~/cyber-labs/scripts/lab-02-verify.sh check-capture
```

Expected output:
```
[PASS] Captures directory exists
[PASS] baseline.pcap exists
[PASS] baseline.pcap is non-empty (>1KB)
[PASS] baseline.pcap is a valid pcap file
[INFO] Capture check complete.
```

---

## Part 4: Simulate the Clinic Scenario

> **Sarah, the IT manager, checks back in:** *"I've confirmed this machine is making those weird outbound connections. I need you to capture traffic from this workstation and document the pattern so we can write an incident report."*

To give you hands-on experience finding malware-like patterns without actual malware, we'll run an educational script that mimics the behavior. This is standard training practice — security analysts regularly practice against simulated threats.

### What Makes C2 Beaconing Distinctive?

Real malware that uses beaconing has these characteristics:
1. **Regular interval** — connections happen on a predictable schedule (every 30s, 60s, etc.)
2. **Small payload** — the check-in itself doesn't need much data
3. **External destination** — it connects out to a remote server
4. **Persistence** — it continues even when the user isn't actively doing anything

Our simulation script reproduces all four characteristics.

### Step 4.1: Read the Simulation Script First

Before running any script, you should always understand what it does:

```bash
cat ~/cyber-labs/scripts/lab-02-simulate-traffic.py
```

Read through it. Notice:
- It connects to `example.com` (a harmless public test site)
- It does this every 30 seconds
- It includes a basic user-agent string
- It stops when you press Ctrl+C

### Step 4.2: Open Two Terminals Side by Side

You need two terminals running at the same time. On a Raspberry Pi desktop, right-click and open a second terminal. On SSH, use `tmux`:

```bash
# Optional: start tmux for split-screen
tmux new-session \; split-window -h
# Use Ctrl+B then arrow keys to switch between panes
```

### Step 4.3: Start the Packet Capture (Terminal 1)

In the first terminal, start a 2-minute capture:

```bash
tshark -i eth0 -a duration:120 -w ~/cyber-labs/captures/scenario.pcap
```

### Step 4.4: Start the Beacon Simulation (Terminal 2)

In the second terminal, start the simulation:

```bash
python3 ~/cyber-labs/scripts/lab-02-simulate-traffic.py
```

You'll see output like:
```
[Beacon Simulator] Starting... (press Ctrl+C to stop)
[00:00] Sending beacon #1 to example.com...
[00:00] Response: 200 OK (1256 bytes)
[00:30] Sending beacon #2 to example.com...
[00:30] Response: 200 OK (1256 bytes)
[01:00] Sending beacon #3 to example.com...
```

**Let both run for the full 2 minutes.** The capture will auto-stop; the simulation will keep going until you press Ctrl+C.

After the capture stops:
1. Press Ctrl+C in Terminal 2 to stop the simulation
2. Verify your capture file: `ls -lh ~/cyber-labs/captures/scenario.pcap`

---

### Checkpoint 4 — Verify the Scenario Capture

```bash
bash ~/cyber-labs/scripts/lab-02-verify.sh check-scenario
```

Expected output:
```
[PASS] scenario.pcap exists
[PASS] scenario.pcap is non-empty
[PASS] scenario.pcap is a valid pcap file
[PASS] scenario.pcap contains HTTP or HTTPS traffic
[INFO] Scenario capture check complete.
```

---

## Part 5: Analyze the Traffic — Find the Beacon

Now the actual investigation begins. You have a packet capture — let's find the suspicious pattern.

### Step 5.1: Get a High-Level Summary

Start with a protocol breakdown of everything in the capture:

```bash
tshark -r ~/cyber-labs/captures/scenario.pcap -qz io,phs
```

Expected output:
```
===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:222 bytes:28932
  ip                                     frames:218 bytes:28120
    tcp                                  frames:168 bytes:23440
      http                               frames:24 bytes:8960
        http.response                    frames:4 bytes:5120
        http.request                     frames:4 bytes:720
      tls                                frames:144 bytes:14480
    udp                                  frames:50 bytes:4680
      dns                                frames:50 bytes:4680
===================================================================
```

This tells you the mix of traffic: DNS (UDP/53), encrypted web (TLS), and some plain HTTP.

### Step 5.2: Find All Destination IPs — Spot the Outlier

Count connections to each unique destination:

```bash
tshark -r ~/cyber-labs/captures/scenario.pcap \
  -T fields -e ip.dst | sort | uniq -c | sort -rn | head -15
```

**Command breakdown:**

| Part | What it does |
|------|-------------|
| `-T fields` | Output specific fields only (no decorators) |
| `-e ip.dst` | Extract the destination IP field from each packet |
| `sort` | Group identical IPs together |
| `uniq -c` | Count how many times each IP appears |
| `sort -rn` | Sort by count, highest first |
| `head -15` | Show only the top 15 results |

Expected output (IPs will vary):
```
     48 93.184.216.34       ← example.com — suspiciously high!
     22 8.8.8.8             ← Google DNS
     18 192.168.1.1         ← Your router
     12 142.250.80.46       ← Google services
      6 239.255.255.250     ← mDNS multicast (normal)
```

> **Write down the IP with the most connections: _______________**
>
> That's your suspect.

### Step 5.3: Look at the Timing — Prove It's Periodic

This is the key step. Filter for traffic to your suspect IP and show the timestamps:

```bash
# Replace 93.184.216.34 with the IP you identified
tshark -r ~/cyber-labs/captures/scenario.pcap \
  -Y "ip.dst == 93.184.216.34" \
  -T fields -e frame.time_relative -e ip.proto -e tcp.dstport
```

Expected output:
```
1.234567    6    80
31.489012   6    80
61.723456   6    80
91.958901   6    80
122.192345  6    80
```

**Look at the time values in the first column.** Calculate the difference between each:
- 31.48 − 1.23 = **30.25 seconds**
- 61.72 − 31.48 = **30.23 seconds**
- 91.96 − 61.72 = **30.24 seconds**

The interval is consistent to within a fraction of a second. **Random normal traffic does not look like this.** This is the beacon signature.

### Step 5.4: Examine What Data Is Being Sent

Look at the actual HTTP request being made:

```bash
tshark -r ~/cyber-labs/captures/scenario.pcap \
  -Y "http.request and ip.dst == 93.184.216.34" \
  -T fields -e http.request.method -e http.host -e http.request.uri -e http.user_agent
```

Expected output:
```
GET  example.com  /  python-requests/2.28.0
GET  example.com  /  python-requests/2.28.0
GET  example.com  /  python-requests/2.28.0
```

The user-agent `python-requests` tells you this is a scripted request — not a human browsing. In a real investigation, you'd look up the destination IP in threat intel databases to see if it's a known C2 server.

### Step 5.5: Check for Exposed Plaintext (HTTP vs HTTPS)

One critical skill for security analysts is recognizing when sensitive data is being sent without encryption.

Generate a test HTTP request (plain, not encrypted):

```bash
curl -v http://httpbin.org/get 2>&1 | head -30
```

Notice the URL starts with `http://` — no encryption. Now capture that traffic:

```bash
# Terminal 1: capture 15 seconds
tshark -i eth0 -a duration:15 -Y "http" -T fields \
  -e http.request.method -e http.host -e http.request.uri 2>/dev/null

# Terminal 2: make the request while Terminal 1 captures
curl -s http://httpbin.org/get?username=jsmith > /dev/null
```

You can read the URL parameters — including the username — directly from the packet capture. This is why HTTPS matters: TLS encryption prevents this kind of inspection.

### Step 5.6: Look for Traffic on Unusual Ports

Malware sometimes uses non-standard ports to avoid detection. Check for traffic on ports other than 80 (HTTP), 443 (HTTPS), and 53 (DNS):

```bash
tshark -r ~/cyber-labs/captures/scenario.pcap \
  -Y "tcp.port != 80 and tcp.port != 443 and udp.port != 53 and not arp" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport | sort | uniq -c | sort -rn
```

---

### Checkpoint 5 — Verify Your Analysis

```bash
bash ~/cyber-labs/scripts/lab-02-verify.sh check-analysis
```

Expected output:
```
[PASS] scenario.pcap exists and is non-empty
[PASS] scenario.pcap contains TCP traffic
[PASS] scenario.pcap contains DNS traffic
[INFO] Analysis check complete. Proceed to report writing.
```

---

## Part 6: Wireshark Filters — A Practical Reference

Display filters let you cut through noise to see exactly what you need. Here's a practical reference card for filters you'll use in real investigations.

### Protocol Filters

```bash
# Show only DNS traffic
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "dns"

# Show only HTTP requests (not responses)
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "http.request"

# Show only TLS (encrypted HTTPS) handshakes
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "tls.handshake"

# Show ICMP (ping traffic)
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "icmp"
```

### Address and Port Filters

```bash
# Traffic from a specific source
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "ip.src == 192.168.1.105"

# Traffic to OR from an address
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "ip.addr == 8.8.8.8"

# Traffic on a specific port
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "tcp.port == 443"

# Combine conditions with 'and', 'or', 'not'
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "http and ip.dst == 93.184.216.34"
```

### Suspicious Traffic Filters

```bash
# Large packets that could indicate data exfiltration
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "frame.len > 1400"

# Connections that were refused (RST flag — closed port scans look like this)
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "tcp.flags.reset == 1"

# DNS queries for non-existent domains (NXDOMAIN — could be DGA malware)
tshark -r ~/cyber-labs/captures/scenario.pcap -Y "dns.flags.rcode == 3"
```

### Quick Filter Reference Card

| What you want to find | Filter |
|-----------------------|--------|
| All DNS activity | `dns` |
| Web browsing (unencrypted) | `http` |
| Encrypted web | `tls` |
| Pings | `icmp` |
| Traffic from your Pi | `ip.src == YOUR.IP` |
| Traffic to a suspect IP | `ip.dst == SUSPECT.IP` |
| HTTP only (skip HTTPS) | `http and not tls` |
| Port 80 traffic | `tcp.port == 80` |
| Any non-standard port | `tcp.port != 80 and tcp.port != 443` |
| Refused connections | `tcp.flags.reset == 1` |
| Failed DNS lookups | `dns.flags.rcode == 3` |

---

## Part 7: Write the Incident Report

A security analyst's work is only complete when it's documented. Even in a small clinic, findings that aren't written down can't be acted on. Your incident report is what the IT manager uses to brief leadership, contact vendors, or open a helpdesk ticket.

### Step 7.1: Create Your Report File

```bash
nano ~/cyber-labs/reports/lab-02-incident-report.txt
```

### Step 7.2: Fill in the Template

Use your actual observations from Parts 5 and 6 to complete every field:

```
================================================================
         NETWORK SECURITY INCIDENT SUMMARY REPORT
================================================================

Analyst Name:     [Your Name]
Date:             [Today's Date]
Organization:     Riverside Medical Clinic (Lab Simulation)
Analyst System:   Raspberry Pi 4

----------------------------------------------------------------
INCIDENT DESCRIPTION
----------------------------------------------------------------
IT management reported periodic outbound connections from an
internal workstation to an unknown external IP address, occurring
at regular intervals during business hours.

----------------------------------------------------------------
INVESTIGATION METHODOLOGY
----------------------------------------------------------------
Tools used:       tshark (Wireshark CLI), ip, curl
Capture file:     ~/cyber-labs/captures/scenario.pcap
Capture duration: 120 seconds
Capture interface: [Your interface, e.g. eth0]

----------------------------------------------------------------
FINDINGS
----------------------------------------------------------------

1. SUSPICIOUS DESTINATION IP
   IP Address Identified:      ___________________________
   Number of Connections:      ___________________________
   Destination Port:           ___________________________
   Protocol:                   ___________________________

2. TIMING ANALYSIS
   First Connection Timestamp: ___________________________
   Average Interval (seconds): ___________________________
   Is Interval Consistent?:    [ ] Yes   [ ] No
   Conclusion: Regular, machine-timed interval is inconsistent
               with normal human browsing behavior.

3. PAYLOAD ANALYSIS
   HTTP Method Used:           ___________________________
   User-Agent String:          ___________________________
   Data Sent Per Beacon:       ___________________________
   Was Sensitive Data Exposed?: [ ] Yes (describe): _______
                                [ ] No

4. OVERALL ASSESSMENT
   [ ] Traffic appears benign (explain below)
   [ ] Traffic is suspicious — further investigation needed
   [ ] Traffic is consistent with malware C2 beaconing

   Assessment Notes:
   _____________________________________________________________
   _____________________________________________________________

----------------------------------------------------------------
RECOMMENDED ACTIONS
----------------------------------------------------------------
1. Block destination IP _______________ at the perimeter firewall
2. Isolate the affected workstation from the network
3. Submit the capture file to an antivirus vendor for analysis
4. Scan all other workstations for similar outbound patterns
5. Preserve the pcap file as evidence (do NOT delete it)
6. Notify [clinic's HIPAA compliance officer] per breach protocol

----------------------------------------------------------------
EVIDENCE FILES
----------------------------------------------------------------
- ~/cyber-labs/captures/scenario.pcap (preserve, do not delete)
- This report

================================================================
```

### Step 7.3: Save and Verify the Report

Press `Ctrl+X`, then `Y`, then `Enter` to save in nano.

Verify your report exists and has content:

```bash
wc -l ~/cyber-labs/reports/lab-02-incident-report.txt
```

---

### Checkpoint 6 — Verify Your Report

```bash
bash ~/cyber-labs/scripts/lab-02-verify.sh check-report
```

Expected output:
```
[PASS] Reports directory exists
[PASS] lab-02-incident-report.txt exists
[PASS] lab-02-incident-report.txt is non-empty
[INFO] Report check complete.
```

---

## Part 8: Clean Up

### Step 8.1: Stop Any Running Processes

If the beacon simulation is still running, stop it:

```bash
pkill -f lab-02-simulate-traffic.py
```

### Step 8.2: Review Your Work

```bash
ls -lh ~/cyber-labs/captures/
ls -lh ~/cyber-labs/reports/
```

### Step 8.3: Optionally Remove Large Capture Files

Pcap files can use significant disk space. After reviewing your work:

```bash
# Check the size
du -sh ~/cyber-labs/captures/

# Remove when done (only after you've completed all analysis)
rm ~/cyber-labs/captures/*.pcap
```

> **Real-world note:** In a real security incident, pcap files are **evidence**. You would never delete them without approval and proper chain-of-custody documentation.

---

## Lab Reflection Questions

Answer these in your lab notebook or as a class discussion:

1. **Describe what a network packet is in your own words. How is it different from the complete data being transmitted?**

2. **You could read the content of HTTP traffic in your captures, but HTTPS (TLS) traffic appeared as unreadable ciphertext. Why does this matter for users and attackers alike?**

3. **What specific pattern made the beacon traffic suspicious — and how would you distinguish it from a legitimate application that also connects to the internet regularly (like a software update check)?**

4. **Wireshark required elevated privileges to capture packets. What security risk would exist if any process on the system could capture all network traffic without authorization?**

5. **Your incident report recommended blocking the destination IP at the firewall. What are the limitations of this response? What else should the clinic do?**

---

## Bonus Challenges

**Challenge 1 — Open the GUI in Wireshark (Desktop Required)**

If your Pi is connected to a monitor:
```bash
wireshark ~/cyber-labs/captures/scenario.pcap
```
Open the capture file and apply filters using the colored graphical interface. The color coding (green for established TCP, blue for DNS, dark yellow for HTTP) makes patterns visually obvious. Try the filter bar at the top — same filter syntax as tshark.

**Challenge 2 — Detect the Beacon with a Script**

Write a shell script that reads a pcap file, counts connections per destination IP per 60-second window, and prints a warning if any IP is contacted more than 3 times in that window. This is primitive intrusion detection logic.

**Challenge 3 — Combine Labs 01 and 02**

Start Pi-hole from Lab 01 (`cd ~/pihole && docker compose up -d`). Then run tshark at the same time and capture DNS traffic. Can you see Pi-hole's NXDOMAIN responses for blocked domains in your packet capture? Compare what you see in the Pi-hole log versus what tshark shows.

---

## Appendix A: Troubleshooting

### A.1: tshark Not Found After Installation

**Symptom:** `bash: tshark: command not found`

**Fix:**
```bash
sudo apt install -y tshark
which tshark
```
If apt returns errors, first run `sudo apt update`.

---

### A.2: Permission Denied When Capturing

**Symptom:**
```
tshark: The capture session could not be initiated on interface 'eth0'
(You don't have permission to capture on that device).
```

**Fix — Option 1 (preferred):** Add user to wireshark group:
```bash
sudo usermod -aG wireshark $USER
newgrp wireshark
```

**Fix — Option 2:** Run tshark with sudo:
```bash
sudo tshark -i eth0 -a duration:30 -w ~/cyber-labs/captures/test.pcap
```

---

### A.3: Interface Name Not `eth0` or `wlan0`

**Symptom:**
```
tshark: There is no device with the address or name 'eth0'
```

**Fix:** Get the correct name from tshark's interface list:
```bash
tshark -D
ip link show
```
Use the exact name printed — it might be `enp3s0`, `ens33`, or similar on some systems.

---

### A.4: Capture File Is Empty or Very Small

**Symptom:** `ls -lh` shows the file is 0 bytes or only a few hundred bytes.

**Causes and fixes:**
- Wrong interface: re-run `tshark -D` and verify your interface name
- No traffic: generate traffic while capturing — open a browser, run `curl https://example.com`
- Interface is down: check `ip link show eth0 | grep UP`

---

### A.5: Python Not Found (Simulation Script Error)

**Symptom:** `bash: python3: command not found`

**Fix:**
```bash
sudo apt install -y python3
python3 --version
```

---

### A.6: No HTTP Traffic Appearing in Filters

**Symptom:** Filter `http` returns no results even though you browsed the web.

**Explanation:** This is increasingly common and is actually good news — most websites now use HTTPS (encrypted). Plain HTTP traffic on port 80 is rare on modern networks.

**For this lab:** The simulation script targets `http://example.com` specifically to generate plain HTTP for analysis. If you need to verify HTTP capture is working:
```bash
curl -s http://neverssl.com > /dev/null
```
`neverssl.com` is a site maintained specifically to always serve plain HTTP (no redirect to HTTPS). It's used for exactly this kind of testing.

---

### A.7: Scenario Capture Is Too Short / Missing Beacons

**Symptom:** Your scenario.pcap has traffic but you can only see 1-2 connections to the suspect IP.

**Fix:** The simulation sends a beacon every 30 seconds. For 120 seconds of capture, you should see 3-4 beacons. If the capture ended before enough ran:
```bash
# Run a longer capture
tshark -i eth0 -a duration:180 -w ~/cyber-labs/captures/scenario.pcap &
python3 ~/cyber-labs/scripts/lab-02-simulate-traffic.py
```
Wait for 3+ beacon messages in the simulation output, then stop the simulation and let the capture finish.

---

### A.8: Researching Errors You Haven't Seen Before

When you encounter an error not in this guide:

1. **Copy the exact error message** — not a paraphrase, the exact text
2. **Search with context:** `"<exact error>" tshark raspberry pi`
3. **Check the tshark man page:** `man tshark` (press `q` to quit)
4. **Check Wireshark's wiki:** https://wiki.wireshark.org
5. **Ask your instructor** with: what you were trying to do, the exact command you ran, and the exact error output

---

## Key Terms

| Term | Definition |
|------|-----------|
| **Packet** | A small, fixed-size chunk of data transmitted across a network |
| **pcap** | Packet Capture — the standard file format for saving network captures |
| **tshark** | The command-line version of Wireshark; ideal for scripting and terminals |
| **Wireshark** | A graphical network protocol analyzer; the industry standard tool |
| **OSI Model** | A 7-layer framework describing how network protocols are organized |
| **Display Filter** | A Wireshark/tshark expression applied when reading a capture file |
| **Beaconing** | Periodic, automated network check-ins — a hallmark of C2 malware |
| **C2 (Command & Control)** | A server used by attackers to issue commands to compromised machines |
| **Protocol** | A standardized set of rules governing how data is formatted and exchanged |
| **TLS** | Transport Layer Security — the encryption used by HTTPS |
| **Plaintext** | Unencrypted data readable by anyone who intercepts the packets |
| **User-Agent** | A string sent by HTTP clients identifying what software made the request |

---

*Co-Lin Cyber Labs | AI-Enabled Security | Raspberry Pi Lab Series*
*Lab 02 of 06 | Next Up: Lab 03 — Network Scanning & Asset Discovery with Nmap*
