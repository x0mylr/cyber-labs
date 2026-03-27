# Lab 02: Catching What's on the Wire — Network Traffic Analysis with Wireshark
### Cybersecurity & Networking Essentials | Raspberry Pi Lab Series

---

## The Scenario

> **You are a junior SOC analyst at a small regional company.**
>
> The office manager calls in a ticket: *"The internet has been really slow all morning. Someone said they heard about companies getting hacked through their network — is something wrong with ours?"*
>
> Your job: plug in, capture the traffic, and find out what's on the wire. You will use **Wireshark** — the industry-standard tool that network analysts, penetration testers, and incident responders all rely on when they need to see exactly what is traveling across a network.

This is not a hypothetical exercise. Wireshark is used by real security teams every day to investigate slow networks, catch data leaks, detect malware phoning home, and reconstruct what happened during an incident.

---

## Learning Objectives

By the end of this lab, you will be able to:

- [ ] Explain what packet capture is and why it matters in security
- [ ] Install and launch Wireshark on a Raspberry Pi
- [ ] Capture live network traffic on a selected interface
- [ ] Read and interpret basic packet information (source, destination, protocol)
- [ ] Apply display filters to isolate specific types of traffic
- [ ] Use `tshark` (the command-line version of Wireshark) to capture and search traffic
- [ ] Save and re-open a packet capture file for later analysis
- [ ] Identify indicators that warrant further investigation

---

> **Certification Alignment**
> Skills in this lab map to the following industry certifications:
> - **CompTIA Network+ (N10-009):** 1.1 — Explain the OSI model layers and encapsulation concepts · 5.3 — Use the appropriate network troubleshooting methodology and tools (packet capture, protocol analysis)
> - **CompTIA Security+ (SY0-701):** 4.4 — Use appropriate tools to assess organizational security (traffic analysis, packet capture)
> - **CompTIA CySA+ (CS0-003):** 2.2 — Analyze data as part of security monitoring activities (network forensics, packet analysis, IOC identification)

---

## Background: What is a Packet?

Every piece of data that travels across a network is broken into small chunks called **packets**. Think of it like sending a book through the mail — instead of shipping the whole thing at once, you tear out each chapter and put it in a separate envelope. Each envelope has a label showing where it came from, where it is going, and which chapter it contains.

Wireshark lets you intercept and read every one of those envelopes as they pass by on your network interface.

```
What Wireshark Does:

Network Cable/Wi-Fi
       │
       ▼
  [Your Device's Network Interface]
       │
       │  ← Wireshark sits here, reading copies of every packet
       │
       ▼
 The Rest of the Network
```

> **Important:** On your own network or a network you have permission to monitor, this is a legitimate and essential skill. On a network you do not own or have permission to monitor, packet capture is illegal. We are capturing traffic from our own Raspberry Pi on the classroom network.

---

## Lab Requirements

| Item | Details |
|------|---------|
| Hardware | Raspberry Pi 4 with desktop (GUI) access |
| OS | Raspberry Pi OS (64-bit) |
| Network | Connected to your classroom network (wired or Wi-Fi) |
| Prerequisites | Lab 01 complete (Docker familiarity helps but is not required here) |
| Time | ~45–60 minutes |

---

## Part 1: Install Wireshark

### Step 1.1 — Open a Terminal

On your Raspberry Pi desktop, right-click and choose **Open Terminal**, or find it in the application menu.

You should see:
```
pi@raspberrypi:~ $
```

---

### Step 1.2 — Update Your Package List

Before installing anything, update the list of available packages:

```bash
sudo apt update
```

You will see a list of packages being refreshed. This usually takes 30–60 seconds.

> **What is `sudo`?** It stands for "superuser do" — it runs the command with administrator (root) privileges. Installing software requires these elevated permissions.

---

### Step 1.3 — Install Wireshark

```bash
sudo apt install wireshark tshark -y
```

> **What are we installing?**
> - `wireshark` — the full graphical application
> - `tshark` — the command-line version of Wireshark (useful for scripting and remote systems)
> - `-y` — automatically answers "yes" to any prompts

During installation, you may be asked:

```
Should non-superusers be able to capture packets? [yes/no]
```

**Select "Yes"** using the arrow keys, then press Enter. This allows your regular `pi` user account to capture packets without needing `sudo` every time.

---

### Step 1.4 — Add Your User to the Wireshark Group

For the permission change to take effect, your user account needs to be added to the `wireshark` group:

```bash
sudo usermod -aG wireshark $USER
```

> **Breaking this down:**
> - `usermod` = modify a user account
> - `-aG wireshark` = append (add) to the `wireshark` group
> - `$USER` = a variable that automatically fills in your current username (`pi`)

Then apply the group change without logging out:

```bash
newgrp wireshark
```

---

### ✅ Checkpoint 1 — Verify the Installation

Run each of these and confirm the expected output:

**Check 1 — Wireshark is installed:**
```bash
wireshark --version
```

Expected output (version may differ):
```
Wireshark 4.x.x (Git ...)
```

**Check 2 — tshark is installed:**
```bash
tshark --version
```

Expected output:
```
TShark (Wireshark) 4.x.x
```

**Check 3 — Your user is in the wireshark group:**
```bash
groups $USER
```

Expected output (must include `wireshark`):
```
pi adm dialout cdrom sudo audio video ... wireshark ...
```

> **If `wireshark` is not in the list:** Log out of the desktop and log back in, then re-check. Group membership changes require a fresh login to fully apply.

---

## Part 2: Understand Your Network Interfaces

Before you capture anything, you need to know which network interface to listen on. Think of interfaces like different roads into your computer — traffic arrives on one road or another depending on whether you are using a network cable or Wi-Fi.

### Step 2.1 — List Available Interfaces

```bash
ip link show
```

You will see output similar to this:

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
```

| Interface | What It Is |
|-----------|-----------|
| `lo` | Loopback — internal traffic only, never leaves the machine |
| `eth0` | Wired Ethernet connection |
| `wlan0` | Wireless (Wi-Fi) connection |

> **Write down which interface you are using** — whichever one has an IP address assigned is the active one.

### Step 2.2 — Confirm Your Interface Has an IP Address

```bash
ip addr show eth0
```
or if using Wi-Fi:
```bash
ip addr show wlan0
```

Look for a line starting with `inet` — that is your IP address:

```
inet 192.168.1.42/24 brd 192.168.1.255 scope global eth0
```

> **Write down your IP address** — you will use it later to filter your own traffic from others.

### ✅ Checkpoint 2 — Interface Ready

```bash
ip route show default
```

Expected output:
```
default via 192.168.1.1 dev eth0 ...
```

This confirms your Pi has a default route, meaning it can send and receive network traffic. The interface after `dev` (`eth0` in this example) is the one you will capture on.

---

## Part 3: Capture Live Traffic with tshark

We will start with `tshark` in the terminal before moving to the graphical Wireshark. This is how analysts often work when connected to remote servers — there is no GUI, so you need to know the command-line tools.

### Step 3.1 — Generate Some Test Traffic

Open a **second terminal window** and run these commands to generate a few different types of traffic. We will capture this traffic in our first terminal and find it later.

```bash
# Make a DNS query
nslookup google.com

# Send a ping (ICMP traffic)
ping -c 4 8.8.8.8

# Make an HTTP request
curl -s http://example.com > /dev/null
```

> We are generating three different types of traffic on purpose: **DNS** (looking up a name), **ICMP** (ping/echo), and **HTTP** (web request). Each one looks different in a packet capture, and being able to identify them is a core analyst skill.

---

### Step 3.2 — Start a Capture with tshark

Go back to your first terminal. Replace `eth0` with your interface name if different:

```bash
tshark -i eth0 -c 50
```

> **What this does:**
> - `-i eth0` = capture on the `eth0` interface
> - `-c 50` = capture 50 packets then stop automatically

While it runs, go back to your second terminal and run the ping command again:

```bash
ping -c 4 8.8.8.8
```

You will see packets scroll by in the first terminal:

```
    1 0.000000000 192.168.1.42 → 8.8.8.8      ICMP 98 Echo (ping) request  id=0x0001, seq=1/256, ttl=64
    2 0.015234123      8.8.8.8 → 192.168.1.42  ICMP 98 Echo (ping) reply    id=0x0001, seq=1/256, ttl=117
    3 0.021456789 192.168.1.42 → 192.168.1.1   DNS  71 Standard query 0x1a2b A google.com
    4 0.038901234  192.168.1.1 → 192.168.1.42  DNS  87 Standard query response 0x1a2b A 142.250.x.x
```

Let's read one line together:

| Column | Meaning |
|--------|---------|
| `1` | Packet number |
| `0.000000` | Timestamp (seconds since capture started) |
| `192.168.1.42` | Source IP (your Pi — the sender) |
| `8.8.8.8` | Destination IP (Google DNS — the receiver) |
| `ICMP` | Protocol used |
| `Echo (ping) request` | What type of packet this is |

---

### Step 3.3 — Capture to a File

Real analysts save their captures for later analysis, sharing with colleagues, or use as evidence. Save a capture to a file using `-w`:

```bash
tshark -i eth0 -c 100 -w ~/captures/lab02-capture.pcap
```

First create the directory:

```bash
mkdir ~/captures
tshark -i eth0 -c 100 -w ~/captures/lab02-capture.pcap
```

While it captures, generate traffic in your second terminal:

```bash
ping -c 5 8.8.8.8
nslookup github.com
curl -s http://example.com > /dev/null
```

Wait for `tshark` to finish collecting 100 packets, then move on.

---

### ✅ Checkpoint 3 — Verify the Capture File

```bash
ls -lh ~/captures/lab02-capture.pcap
```

Expected output (size will vary):
```
-rw-r--r-- 1 pi pi 24K Mar 27 09:15 /home/pi/captures/lab02-capture.pcap
```

Confirm it is a valid capture file:

```bash
tshark -r ~/captures/lab02-capture.pcap -c 5
```

You should see the first 5 packets listed. If you get an error or see nothing, re-run the capture from Step 3.3.

---

## Part 4: Analyze Traffic with Wireshark (GUI)

Now let's open the capture file in the full graphical Wireshark for a deeper look.

### Step 4.1 — Launch Wireshark

In your terminal:

```bash
wireshark ~/captures/lab02-capture.pcap &
```

> The `&` at the end runs Wireshark in the background, leaving your terminal free to use.

Wireshark will open with your capture file loaded. You will see three main panels:

```
┌─────────────────────────────────────────────────────────┐
│  Packet List   (one row per packet — the summary view)  │
├─────────────────────────────────────────────────────────┤
│  Packet Details  (expandable tree view of packet layers)│
├─────────────────────────────────────────────────────────┤
│  Packet Bytes  (raw hex — the actual bytes on the wire) │
└─────────────────────────────────────────────────────────┘
```

---

### Step 4.2 — Explore a Packet

Click on any ICMP packet (look for packets with "Echo" in the Info column). Watch how all three panels update.

In the **Packet Details** panel, expand these sections by clicking the arrows:

- **Frame** — physical layer information (when it arrived, how big)
- **Ethernet II** — hardware addresses (MAC addresses) of sender and receiver
- **Internet Protocol** — IP addresses and routing info
- **Internet Control Message Protocol** — the ICMP-specific data (ping content)

> **This is the OSI model in action.** Each layer wraps the one above it — just like an envelope inside an envelope inside a box. Wireshark lets you unwrap each layer and see exactly what is inside.

---

### Step 4.3 — Understanding the Color Coding

Wireshark uses colors to quickly identify packet types:

| Color | Meaning |
|-------|---------|
| Light green | TCP traffic (most web traffic) |
| Light blue | UDP traffic (DNS, video streaming) |
| Light purple | TCP reassembly (fragments being put together) |
| Black with red text | Errors or problematic packets |
| Dark green | HTTP traffic |

> **Pro tip:** Black/red packets deserve a closer look — they often indicate connection resets, retransmissions, or errors that could be caused by congestion, misconfigurations, or active interference.

---

### Step 4.4 — Exploration Checkpoint

Click through your capture and fill out this table:

| Question | Your Answer |
|----------|-------------|
| What is the most common protocol you see? | |
| What is your Pi's IP address (look at source column)? | |
| What is your gateway/router's IP address? | |
| Can you find a DNS query? What domain was queried? | |
| Can you find a DNS response? What IP was returned? | |
| Do you see any packets with errors (black/red)? | |

---

## Part 5: Filtering — Finding the Needle in the Haystack

In a real investigation, you might have thousands or millions of packets. Filters let you zero in on exactly what you need.

### Step 5.1 — The Display Filter Bar

At the top of Wireshark, find the **Display Filter** bar (it shows "Apply a display filter..." in light text). This is where you type filter expressions. Filters turn **green** when valid, **red** when there is a syntax error, and **yellow** when Wireshark is unsure.

---

### Step 5.2 — Filter by Protocol

Type each of these into the filter bar and press Enter. Observe how the packet list changes.

**Show only ICMP (ping) traffic:**
```
icmp
```

**Show only DNS traffic:**
```
dns
```

**Show only HTTP traffic:**
```
http
```

**Show only TCP traffic:**
```
tcp
```

**Show only UDP traffic:**
```
udp
```

Clear the filter by clicking the **X** button on the right side of the filter bar.

---

### Step 5.3 — Filter by IP Address

**Show only traffic from your Pi:**
```
ip.src == 192.168.1.42
```
*(Replace with your actual Pi IP address)*

**Show only traffic TO your Pi:**
```
ip.dst == 192.168.1.42
```

**Show all traffic involving your Pi (in either direction):**
```
ip.addr == 192.168.1.42
```

---

### Step 5.4 — Combine Filters with AND / OR

**Show DNS traffic from your Pi:**
```
dns && ip.src == 192.168.1.42
```

**Show either ICMP or DNS traffic:**
```
icmp || dns
```

**Show everything EXCEPT your Pi's traffic:**
```
!ip.addr == 192.168.1.42
```

> **The `&&`, `||`, and `!` operators** work exactly like they do in programming — AND, OR, and NOT. Once you know these three, you can build almost any filter you need.

---

### Step 5.5 — Follow a TCP Stream

One of Wireshark's most powerful features lets you reconstruct an entire conversation between two hosts.

1. Right-click on any HTTP or TCP packet
2. Click **Follow → TCP Stream**
3. A new window opens showing the full conversation in plain text

> **In a real investigation**, this is how analysts reconstruct what a compromised machine was sending to an attacker's server, or verify that sensitive data was transmitted unencrypted.

---

### ✅ Checkpoint 4 — Filter Verification

Complete each filter task and record what you found:

| Filter Task | Filter Used | What Did You Find? |
|-------------|-------------|-------------------|
| Show only DNS queries | | |
| Show only packets to Google's DNS (8.8.8.8) | | |
| Show all traffic NOT from your Pi | | |
| Show packets larger than 500 bytes | `frame.len > 500` | |

---

## Part 6: Live Capture with Wireshark GUI

Now let's capture live traffic directly from the Wireshark interface.

### Step 6.1 — Start a Live Capture

1. Close your current capture file (File → Close)
2. On the Wireshark start screen, find your active interface (`eth0` or `wlan0`) — you will see a live waveform next to it showing current activity
3. Double-click the interface to start capturing

Packets will begin scrolling immediately.

---

### Step 6.2 — Generate Traffic While Capturing

In your terminal, run:

```bash
# DNS queries to different servers
nslookup amazon.com 8.8.8.8
nslookup github.com 1.1.1.1

# Multiple pings
ping -c 3 1.1.1.1
ping -c 3 8.8.8.8

# Web request
curl -v http://example.com 2>&1 | head -20
```

Watch the Wireshark window — you should see your traffic appear in real time!

---

### Step 6.3 — Stop and Save the Live Capture

1. Click the **red square** (Stop) button in Wireshark
2. Go to **File → Save As**
3. Save the file to: `/home/pi/captures/lab02-live.pcap`

---

### ✅ Checkpoint 5 — Live Capture Verification

In the terminal, confirm your live capture was saved:

```bash
tshark -r ~/captures/lab02-live.pcap -Y "dns" -T fields -e dns.qry.name 2>/dev/null | sort -u
```

> **What this does:**
> - `-Y "dns"` = filter for only DNS packets
> - `-T fields -e dns.qry.name` = extract just the domain name field
> - `sort -u` = sort and remove duplicates

Expected output — you should see the domains you queried:
```
amazon.com
github.com
example.com
```

If you see your queried domains in the output, your live capture is working correctly.

---

## Part 7: Threat Hunting Basics — Spotting Suspicious Traffic

Now let's apply what you have learned to a realistic analyst task. Below are patterns that SOC analysts look for when investigating potential incidents.

### Step 7.1 — Generate Some "Interesting" Traffic to Investigate

Run these commands to create traffic you will hunt for:

```bash
# Simulate repeated DNS lookups (could indicate beacon behavior)
for i in 1 2 3 4 5; do nslookup google.com; sleep 1; done

# Simulate a connection attempt to an unusual port
# (curl will fail — that's okay, we want to see the TCP SYN in the capture)
curl --connect-timeout 3 http://192.168.1.1:8443 2>/dev/null || true
```

Start a new capture in Wireshark or tshark while running these commands, then stop after 30 seconds.

---

### Step 7.2 — Hunt for the Patterns

Use Wireshark filters to investigate:

**Hunt 1 — Find repeated DNS queries to the same domain:**
```
dns.qry.name == "google.com"
```
Count how many times the same domain was queried. Malware that "phones home" often makes DNS requests at regular intervals — called **beaconing**.

**Hunt 2 — Find failed connection attempts (TCP RST):**
```
tcp.flags.reset == 1
```
A flood of TCP resets can indicate a port scan or a device trying to reach something that is not responding.

**Hunt 3 — Find connections to unusual ports:**
```
tcp.port != 80 && tcp.port != 443 && tcp.port != 53 && tcp.port != 22
```
Legitimate traffic mostly uses well-known ports. Connections to unusual high-numbered ports can be suspicious.

---

### Step 7.3 — SOC Analyst Worksheet

For each item you find, answer the following in your notes:

| Question | Your Observations |
|----------|------------------|
| Source IP of the traffic | |
| Destination IP of the traffic | |
| Protocol and port being used | |
| Is this traffic expected or unusual? Why? | |
| What would you do next if this were a real alert? | |

> **In a real SOC**, this process is called **triage** — quickly assessing whether something is benign or worth escalating. You would document your findings in a ticketing system and either close the ticket or escalate it to a senior analyst.

---

## Part 8: Command-Line Analysis with tshark (Analyst's Toolkit)

When you are working on a remote server with no GUI, `tshark` is your best friend. Here are the essential commands every analyst should know.

### Step 8.1 — Read a Saved File

```bash
tshark -r ~/captures/lab02-capture.pcap
```

---

### Step 8.2 — Count Packets by Protocol

```bash
tshark -r ~/captures/lab02-capture.pcap -q -z io,phs
```

> `-z io,phs` means "protocol hierarchy statistics" — it breaks down what percentage of traffic is DNS vs TCP vs UDP etc. This is often the first thing an analyst runs to understand what kind of traffic is in a capture.

---

### Step 8.3 — List All Unique IP Conversations

```bash
tshark -r ~/captures/lab02-capture.pcap -q -z conv,ip
```

Expected output (example):
```
IPv4 Conversations
                |       <-      | |       ->      | |     Total     |
                | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |
192.168.1.42 <-> 8.8.8.8      8     672        8     672       16    1344
192.168.1.42 <-> 192.168.1.1   4     336        4     336        8     672
```

> This view shows every unique pair of IPs that talked to each other. It is a fast way to see who a device was communicating with.

---

### Step 8.4 — Export Specific Fields to CSV

```bash
tshark -r ~/captures/lab02-capture.pcap \
  -T fields \
  -e frame.number \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e ip.proto \
  -e frame.len \
  -E header=y \
  -E separator=, \
  > ~/captures/lab02-export.csv
```

View the first few lines:

```bash
head -10 ~/captures/lab02-export.csv
```

> **This is how you feed packet data into a spreadsheet or SIEM.** Many real analyst workflows involve exporting tshark fields as CSV and importing them into tools like Splunk, Excel, or Python scripts for further analysis.

---

### ✅ Checkpoint 6 — tshark Verification

Run this command to verify your export worked:

```bash
wc -l ~/captures/lab02-export.csv
```

You should see a line count greater than 1 (at least a header row plus some data rows). Then check the header line looks correct:

```bash
head -1 ~/captures/lab02-export.csv
```

Expected:
```
frame.number,frame.time_relative,ip.src,ip.dst,ip.proto,frame.len
```

---

## Part 9: Clean Up

### Step 9.1 — Close Wireshark

Close the Wireshark GUI window, or press `Ctrl+Q`.

### Step 9.2 — Keep Your Capture Files

Unlike Pi-hole in Lab 01, there is nothing to "stop" here — Wireshark is a passive analysis tool, not a running service. Your capture files are stored in `~/captures/` for reference:

```bash
ls -lh ~/captures/
```

### Step 9.3 — (Optional) Remove Captures When Done

If you want to free up space later:

```bash
rm -rf ~/captures/
```

> **Do not run this during the lab** — you may need the files for the reflection questions!

---

## Lab Reflection Questions

Answer these in your own words:

1. **What is the difference between Wireshark and tshark? When would you use one over the other?**

2. **You captured traffic and saw that your Pi was making DNS queries. What does a DNS query tell an attacker or analyst about what a device is doing?**

3. **In Step 7.2, you filtered for TCP Reset (RST) packets. What does a TCP Reset mean, and why might seeing many of them be suspicious?**

4. **A manager says: "If we encrypt all our traffic with HTTPS, Wireshark won't be able to see anything." Is this true or false? What can Wireshark still reveal even when traffic is encrypted?**

5. **You are a SOC analyst and you notice a workstation is making DNS requests to an unusual domain every 30 seconds, even at 3 AM when no one is in the office. What might this indicate, and what would your next steps be?**

---

## Bonus Challenges

**Challenge 1 — Capture Only DNS Traffic from the Start**
Instead of capturing everything and filtering after, use a capture filter (not a display filter) to record only DNS packets from the start:
```bash
tshark -i eth0 -f "udp port 53" -c 20
```
Notice the difference: `-f` applies the filter during capture (less data saved), while `-Y` in Wireshark applies it to data already captured. When would each approach be better?

**Challenge 2 — Time-Based Analysis**
Find out what time your earliest and latest packet was captured:
```bash
tshark -r ~/captures/lab02-capture.pcap -T fields -e frame.time | head -1
tshark -r ~/captures/lab02-capture.pcap -T fields -e frame.time | tail -1
```
In incident response, reconstructing the timeline is critical. How might you use timestamps to determine when an attacker first accessed a system?

**Challenge 3 — Find Your Router's MAC Address**
In Wireshark, apply this filter:
```
arp
```
ARP packets reveal MAC addresses — the hardware identifiers of devices on your network. Find your router's MAC address and look up the manufacturer at [https://www.macvendors.com](https://www.macvendors.com). What does it show?

---

## Troubleshooting Reference

| Problem | Possible Fix |
|---------|-------------|
| `tshark: permission denied` | Run: `sudo usermod -aG wireshark $USER` then `newgrp wireshark` |
| Wireshark won't open (no display) | Make sure you are using the Pi's desktop, not SSH. For SSH: use `tshark` instead |
| No packets appearing in capture | Confirm your interface name with `ip link show` — use `eth0` or `wlan0` |
| Capture file is 0 bytes | Generate traffic while capturing; the capture may have stopped before any packets arrived |
| `wireshark: command not found` | Run: `sudo apt install wireshark -y` |
| Wireshark shows "You don't have permission to capture on that device" | Restart your terminal after running the `usermod` command |
| Display filter turns red | Check your filter syntax — field names must match Wireshark's exact naming (use Ctrl+Space for autocomplete) |

---

## Appendix A: Essential Wireshark Filters Reference

Keep this as a reference sheet for future labs and real-world use:

### Protocol Filters
```
icmp            — Ping and ICMP messages
dns             — DNS queries and responses
http            — Unencrypted web traffic
tcp             — All TCP traffic
udp             — All UDP traffic
arp             — Address Resolution Protocol (finds MAC addresses)
```

### IP Address Filters
```
ip.addr == X.X.X.X       — Any traffic involving this IP
ip.src == X.X.X.X        — Traffic FROM this IP
ip.dst == X.X.X.X        — Traffic TO this IP
!(ip.addr == X.X.X.X)    — Exclude this IP
```

### Port Filters
```
tcp.port == 80            — HTTP
tcp.port == 443           — HTTPS
tcp.port == 22            — SSH
tcp.dstport == 8080       — Connections to port 8080
```

### Packet Characteristic Filters
```
frame.len > 1000          — Large packets
tcp.flags.syn == 1        — TCP connection starts
tcp.flags.reset == 1      — TCP connection resets (errors/refusals)
tcp.analysis.retransmission — Packets being resent (often means congestion or packet loss)
```

### Combining Filters
```
&&    — AND (both must be true)
||    — OR (either can be true)
!     — NOT (exclude this)

Example: dns && ip.src == 192.168.1.42 && !ip.dst == 8.8.8.8
```

---

## Key Terms Glossary

| Term | Definition |
|------|-----------|
| **Packet** | A small chunk of data with headers indicating source, destination, and protocol |
| **Packet Capture (PCAP)** | A recording of network packets saved to a file for later analysis |
| **Wireshark** | Open-source graphical tool for capturing and analyzing network packets |
| **tshark** | Command-line version of Wireshark, used when a GUI is unavailable |
| **Display Filter** | A filter applied in Wireshark after packets are captured, to narrow what is shown |
| **Capture Filter** | A filter applied during capture to limit which packets are recorded |
| **Protocol** | A set of rules defining how data is formatted and transmitted (TCP, UDP, DNS, etc.) |
| **TCP Reset (RST)** | A signal that abruptly terminates a TCP connection, often due to an error or refusal |
| **Beaconing** | Regular, periodic network connections made by malware to a command-and-control server |
| **SOC** | Security Operations Center — the team responsible for monitoring and responding to threats |
| **Triage** | The process of quickly assessing and prioritizing security alerts |
| **PCAP file** | Packet CAPture file — the standard format for saving captured network traffic |

---

*Lab 02 | Cybersecurity & Networking Essentials | Raspberry Pi Lab Series*
*Next Up: Lab 03 — Network Scanning & Reconnaissance with Nmap*
