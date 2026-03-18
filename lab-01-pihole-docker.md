# Lab 01: Build Your Own Network Ad Blocker with Pi-hole & Docker
### AI-Enabled Security | Raspberry Pi Lab Series

---

## What Are We Building?

Imagine having a **security guard** stationed at the front door of your home network. Every time a website tries to load an advertisement, a tracker, or a known malicious domain, the guard stops it before it even reaches your device. That security guard is **Pi-hole**.

Pi-hole is a **DNS sinkhole** — a tool that intercepts domain name requests and blocks the bad ones. Before a website can load, your computer first has to ask "where does this domain live?" Pi-hole answers that question — and for domains on its blocklist, it simply says **"nowhere."**

The best part? We are going to deploy Pi-hole the same way you deployed your virtual network before spring break — using **Docker**!

---

## Learning Objectives

By the end of this lab, you will be able to:

- [ ] Explain what DNS is and how Pi-hole uses it
- [ ] Use Docker Compose to deploy a real security tool
- [ ] Access and navigate the Pi-hole web dashboard
- [ ] Verify that DNS-level ad blocking is working
- [ ] Connect a device to use Pi-hole as its DNS server

---

## Background Knowledge Check

Before we start, let's make sure we remember a few things from our Docker lab:

> **Quick Recap:**
> - A **container** is like a lightweight virtual machine — an isolated box where an application runs
> - **Docker Compose** lets us define and run multi-container apps using a `docker-compose.yml` file
> - A **network** in Docker lets containers talk to each other (and to the outside world)

If any of that feels fuzzy, no worries — you'll see it all in action again today!

---

## What is DNS? (The Phone Book of the Internet)

DNS stands for **Domain Name System**. Here is the simple version:

When you type `google.com` into your browser, your computer doesn't actually know where that is. It needs an **IP address** (like `142.250.80.46`) to connect. DNS is what translates the name into the address — just like a phone book turns a person's name into their phone number.

Pi-hole sits between your device and the DNS server. When your device asks "where is `ads.tracker.com`?", Pi-hole checks its blocklist. If that domain is on the list, Pi-hole says **"that doesn't exist"** — and the ad or tracker never loads.

```
Normal DNS Flow:
Your Device → DNS Server → "Here is the IP!" → Website Loads

Pi-hole DNS Flow:
Your Device → Pi-hole → [Blocklist Check]
                          ├── Not blocked? → Forwards to DNS Server → Loads
                          └── Blocked? → "NXDOMAIN" → Nothing loads
```

---

## Lab Requirements

| Item | Details |
|------|---------|
| Hardware | Raspberry Pi (any model with network access) |
| OS | Raspberry Pi OS (64-bit recommended) |
| Software | Docker & Docker Compose (already installed) |
| Network | Pi must be connected to your local network |
| Time | ~30–45 minutes |

---

## Part 1: Prepare Your Raspberry Pi

### Step 1.1 — Open a Terminal

On your Raspberry Pi, open the terminal application. You should see a command prompt that looks something like this:

```
pi@raspberrypi:~ $
```

> **What does this mean?**
> - `pi` = your username
> - `raspberrypi` = the device's hostname (its name on the network)
> - `~` = you are in your home directory
> - `$` = ready for your command!

---

### Step 1.2 — Confirm Docker is Running

Let's make sure Docker is up and ready to go. Run this command:

```bash
docker --version
```

You should see output similar to:
```
Docker version 24.0.7, build afdd53b
```

Now check Docker Compose:

```bash
docker compose version
```

Expected output:
```
Docker Compose version v2.21.0
```

> **If you get an error:** Raise your hand and let your instructor know. Docker may need to be started with `sudo systemctl start docker`.

---

### Step 1.3 — Find Your Pi's IP Address

Pi-hole needs to know your Pi's IP address so it can listen for DNS requests on your network. Run:

```bash
hostname -I
```

You will see output like:
```
192.168.1.42 172.17.0.1
```

> **Write down the first IP address** — the one that starts with `192.168.x.x` (or `10.x.x.x`). This is your Pi's address on your local network. You will need it in a few steps!

---

### Step 1.4 — Create a Project Folder

Let's keep things organized. Create a new folder for this project:

```bash
mkdir ~/pihole-lab && cd ~/pihole-lab
```

> **Breaking this down:**
> - `mkdir` = make directory (create a folder)
> - `~/pihole-lab` = create it in your home folder, name it `pihole-lab`
> - `&&` = "if that worked, then also do the next thing"
> - `cd ~/pihole-lab` = change directory into the new folder

Confirm you are in the right place:

```bash
pwd
```

Expected output:
```
/home/pi/pihole-lab
```

---

## Part 2: Create the Docker Compose File

This is where the magic happens. We are going to write a `docker-compose.yml` file that tells Docker exactly how to set up Pi-hole.

### Step 2.1 — Create the File

```bash
nano docker-compose.yml
```

> `nano` is a simple text editor built into Linux. It opens right in the terminal!

---

### Step 2.2 — Type in the Configuration

Carefully type (or copy) the following into the nano editor. **Replace `YOUR_PI_IP` with the IP address you wrote down in Step 1.3!**

```yaml
version: "3"

services:
  pihole:
    container_name: pihole
    image: pihole/pihole:latest
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "80:80/tcp"
    environment:
      TZ: "America/Chicago"
      WEBPASSWORD: "securelab2024"
    volumes:
      - "./etc-pihole:/etc/pihole"
      - "./etc-dnsmasq.d:/etc/dnsmasq.d"
    restart: unless-stopped
    networks:
      pihole_net:
        ipv4_address: 172.20.0.2

networks:
  pihole_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

---

### Step 2.3 — Understanding What We Just Wrote

Let's break down the important parts:

| Setting | What It Does |
|---------|-------------|
| `image: pihole/pihole:latest` | Pulls the official Pi-hole image from Docker Hub |
| `ports: "53:53"` | Port 53 is the DNS port — this is how devices send DNS queries to Pi-hole |
| `ports: "80:80"` | Port 80 is HTTP — this opens the web dashboard |
| `WEBPASSWORD` | The password you will use to log into the Pi-hole dashboard |
| `TZ` | Sets the timezone so Pi-hole logs show the correct time |
| `volumes` | Saves Pi-hole's settings to your Pi even if the container restarts |
| `restart: unless-stopped` | Docker will automatically restart Pi-hole if it crashes |
| `networks` | Creates a private Docker network just for Pi-hole |

> **Security Note:** In a real deployment, you would use a much stronger password than `securelab2024`. For this lab it's fine, but always use strong, unique passwords in production!

---

### Step 2.4 — Save and Exit Nano

1. Press `Ctrl + X` to exit
2. Press `Y` to confirm you want to save
3. Press `Enter` to keep the filename

You should be back at the terminal prompt.

---

### Step 2.5 — Verify the File Was Created

```bash
cat docker-compose.yml
```

This will print the contents of your file. Make sure it looks correct!

---

## Part 3: Launch Pi-hole!

### Step 3.1 — Pull the Pi-hole Image

First, let's download the Pi-hole Docker image. This might take a minute or two depending on your internet speed:

```bash
docker compose pull
```

You will see Docker downloading the image layer by layer. This is normal!

---

### Step 3.2 — Start Pi-hole

```bash
docker compose up -d
```

> **What does `-d` mean?**
> The `-d` flag stands for **detached mode** — it runs the container in the background so your terminal stays free. Without it, the container's logs would flood your screen.

Expected output:
```
[+] Running 2/2
 ✔ Network pihole-lab_pihole_net  Created
 ✔ Container pihole               Started
```

---

### Step 3.3 — Check That Pi-hole is Running

```bash
docker ps
```

You should see `pihole` listed with a status of `Up`:

```
CONTAINER ID   IMAGE                  COMMAND      STATUS          PORTS
a1b2c3d4e5f6   pihole/pihole:latest   "/s6-init"   Up 2 minutes    0.0.0.0:53->53/tcp, ...
```

> **If the container is not running**, check the logs for errors:
> ```bash
> docker compose logs pihole
> ```

---

## Part 4: Access the Pi-hole Dashboard

### Step 4.1 — Open a Web Browser

On any device connected to the **same network as your Raspberry Pi**, open a web browser and navigate to:

```
http://YOUR_PI_IP/admin
```

> Replace `YOUR_PI_IP` with the IP address from Step 1.3.
> **Example:** `http://192.168.1.42/admin`

---

### Step 4.2 — Log In

1. You will see the Pi-hole login page
2. Enter the password: `securelab2024`
3. Click **Log In**

Welcome to your Pi-hole dashboard! Take a moment to explore what you see.

---

### Step 4.3 — Dashboard Exploration Checkpoint

Locate the following items on your dashboard and write down what you find:

| Item to Find | Your Answer |
|--------------|-------------|
| Total DNS Queries Today | |
| Queries Blocked Today | |
| Percentage Blocked | |
| Number of Domains on Blocklist | |

> **At this point the numbers may be low or zero** — that's because no devices are using Pi-hole as their DNS server yet. We'll fix that next!

---

## Part 5: Configure a Device to Use Pi-hole

To actually block ads, a device needs to send its DNS queries to Pi-hole instead of the default DNS server (usually provided by your router).

### Step 5.1 — Configure Your Raspberry Pi Itself

The easiest device to test with is the Pi itself! Let's point the Pi's DNS at Pi-hole.

```bash
sudo nano /etc/resolv.conf
```

Find the line that starts with `nameserver` and change it to point to Pi-hole's IP on our Docker network:

```
nameserver 127.0.0.1
```

> This tells the Pi: "When you need to look up a DNS name, ask the service running on this very machine (localhost)."

Save and exit with `Ctrl+X`, then `Y`, then `Enter`.

---

### Step 5.2 — Test DNS Resolution Through Pi-hole

Run a DNS lookup for a known ad domain:

```bash
nslookup doubleclick.net
```

If Pi-hole is blocking it, you will see it resolve to `0.0.0.0` instead of a real IP address — that's Pi-hole doing its job!

Try a legitimate domain too:

```bash
nslookup google.com
```

This should resolve to a real IP address like `142.250.x.x`.

---

### Step 5.3 — Watch the Dashboard Update

Go back to the Pi-hole dashboard in your browser and refresh the page. You should now see DNS query counts increasing!

---

## Part 6: Explore Pi-hole's Features

### Step 6.1 — View the Query Log

In the Pi-hole dashboard, click **Query Log** in the left sidebar. You will see a live feed of every DNS query being made. Notice:

- **Green entries** = allowed (forwarded to upstream DNS)
- **Red entries** = blocked (Pi-hole said "no")

---

### Step 6.2 — Add a Custom Block

Let's manually block a domain to see how the blocklist works:

1. In the dashboard, click **Blacklist** (or **Domains** depending on version)
2. Type in a domain you want to block, for example: `example-ads.com`
3. Click **Add**

Now try to resolve it from your terminal:

```bash
nslookup example-ads.com
```

It should return `0.0.0.0` — blocked!

---

### Step 6.3 — Check the Blocklist Stats

Run this command from the terminal to see Pi-hole's statistics directly:

```bash
docker exec pihole pihole -c
```

> **Breaking this down:**
> - `docker exec pihole` = run a command inside the running Pi-hole container
> - `pihole -c` = run Pi-hole's built-in statistics display (like a mini dashboard in the terminal!)

Press `Ctrl+C` to exit the stats display.

---

### Step 6.4 — Update the Blocklists

Pi-hole pulls its blocklists from community-maintained sources. Let's update them to get the latest blocked domains:

```bash
docker exec pihole pihole -g
```

> This triggers Pi-hole to **gravity** update — it re-downloads all blocklist sources and rebuilds its database. You might see it pull in hundreds of thousands of blocked domains!

---

## Part 7: Clean Up (Bonus / End of Lab)

When you are done with the lab, you can stop Pi-hole without deleting it:

```bash
docker compose stop
```

To remove the containers entirely (the configuration files stay on your Pi):

```bash
docker compose down
```

To start it back up again later:

```bash
docker compose up -d
```

---

## Lab Reflection Questions

Answer these in your own words:

1. **What is DNS, and why is it important to how the internet works?**

2. **How does Pi-hole use DNS to block ads and trackers without installing anything on each individual device?**

3. **What is the difference between `docker compose up` and `docker compose up -d`?**

4. **In the query log, you saw both allowed and blocked domains. What criteria does Pi-hole use to decide which domains to block?**

5. **If you were setting up Pi-hole for a real home network, what would you do differently for security? (Hint: think about the password we used!)**

---

## Bonus Challenges

Ready for more? Try these if you finish early:

**Challenge 1 — Custom Upstream DNS**
By default Pi-hole forwards allowed queries to Google DNS (8.8.8.8). Change it to use Cloudflare's privacy-focused DNS (1.1.1.1) instead. Find where to do this in the dashboard's **Settings** page.

**Challenge 2 — Add Another Blocklist**
Pi-hole's power comes from its blocklists. Visit [https://firebog.net](https://firebog.net) and add one additional blocklist to your Pi-hole. Then run the gravity update again and see how many more domains are now blocked.

**Challenge 3 — Container Inspection**
Use what you know about Docker to inspect the Pi-hole container:
```bash
docker inspect pihole
```
Find the container's IP address, its network settings, and the mounted volumes in the output. What do you notice?

---

## Troubleshooting Reference

| Problem | Possible Fix |
|---------|-------------|
| `docker compose up` fails with port 53 error | Another service is using port 53. Run: `sudo systemctl stop systemd-resolved` |
| Dashboard won't load | Check Pi is on the network, check container is running with `docker ps` |
| DNS not blocking ads | Confirm your device is using the Pi's IP as its DNS server |
| Forgot dashboard password | Reset it: `docker exec pihole pihole -a -p newpassword` |
| Container exits immediately | Check logs: `docker compose logs pihole` |

---

## Appendix A: Troubleshooting Guide

Something broke? That is completely normal — troubleshooting is one of the most important skills in technology. Work through this appendix top to bottom for whichever issue you are hitting.

---

### A.1 — Port 53 Already in Use

**Symptom:**
```
Error: bind: address already in use
```

**What's happening:** Port 53 is the DNS port. On most Linux systems, a background service called `systemd-resolved` is already listening on it. Pi-hole and that service cannot both own the same port.

**Fix:**
```bash
# Stop the conflicting service
sudo systemctl stop systemd-resolved

# Prevent it from starting again on reboot
sudo systemctl disable systemd-resolved

# Now retry launching Pi-hole
docker compose up -d
```

**How to verify it worked:**
```bash
# Should show nothing listening on port 53 before Pi-hole starts
sudo ss -tulpn | grep :53
```

**Learn more:** Search `"systemd-resolved port 53 conflict docker"` — you will find this is one of the most common Pi-hole setup issues, and the Pi-hole community forums have extensive documentation on it.

---

### A.2 — Container Exits Immediately or Shows "Restarting"

**Symptom:** `docker ps` shows the container status as `Restarting` or it does not appear at all.

**First, read the logs — this is always step one:**
```bash
docker compose logs pihole
```

**Common causes and fixes:**

| What you see in the logs | What to do |
|--------------------------|------------|
| `address already in use` | See Section A.1 above |
| `permission denied` | Run: `sudo chown -R pi:pi ~/pihole-lab` |
| `YAML syntax error` | Re-check your `docker-compose.yml` — a misplaced space or tab will break it |
| No logs at all | The image may not have pulled correctly. Run: `docker compose pull` then try again |

**How to research further:** Copy the exact error line from the logs and paste it into a search engine with the word `pihole docker`. Error messages are designed to be searched — you are not expected to memorize them.

---

### A.3 — YAML File Errors

**Symptom:**
```
Error: yaml: line X: did not find expected key
```

YAML is extremely sensitive to indentation. One wrong space will break the entire file.

**Fix — reopen and carefully inspect your file:**
```bash
nano docker-compose.yml
```

**Things to check:**
- Use **spaces only** — no tab characters (nano may insert tabs if you press the Tab key)
- Every level of indentation should be **2 spaces**
- Colons must be followed by a space: `key: value` not `key:value`
- Port entries must be in quotes: `"53:53/tcp"` not `53:53/tcp`

**Validation tool:** If you have internet access, copy your YAML into [https://www.yamllint.com](https://www.yamllint.com) — it will tell you exactly which line has a problem.

---

### A.4 — Pi-hole Dashboard Won't Load

**Symptom:** Browser shows "This site can't be reached" when you go to `http://YOUR_PI_IP/admin`.

**Work through these checks in order:**

**Check 1 — Is the container running?**
```bash
docker ps
```
Pi-hole should be in the list with status `Up`. If not, see Section A.2.

**Check 2 — Is port 80 open?**
```bash
sudo ss -tulpn | grep :80
```
You should see Docker listening on port 80. If something else is using it (like Apache or nginx), you will need to stop that service or change Pi-hole's port in `docker-compose.yml` from `"80:80"` to something like `"8080:80"` — then access the dashboard at `:8080/admin`.

**Check 3 — Are you on the same network?**
The device you are browsing from must be on the same local network as the Pi. Confirm the Pi's IP with `hostname -I` and make sure the first three sections of the IP match your device's IP.

**Check 4 — Try pinging the Pi:**
```bash
ping YOUR_PI_IP
```
If there is no response, the Pi itself is not reachable — check its network cable or Wi-Fi connection.

---

### A.5 — DNS Queries Not Showing in the Dashboard

**Symptom:** Pi-hole is running but the query log is empty or stuck at zero.

**What's happening:** Pi-hole is running, but no devices are actually sending their DNS traffic to it yet.

**Fix — confirm your device is pointed at Pi-hole:**

On the Raspberry Pi itself:
```bash
cat /etc/resolv.conf
```
The `nameserver` line must show `127.0.0.1`. If it shows something else (like `8.8.8.8` or `192.168.1.1`), edit the file:
```bash
sudo nano /etc/resolv.conf
```
Change the nameserver line to:
```
nameserver 127.0.0.1
```

**Test that DNS is routing through Pi-hole:**
```bash
nslookup google.com 127.0.0.1
```
If this returns a valid IP, Pi-hole is receiving queries. Refresh the dashboard — you should see the count increase.

---

### A.6 — Pi-hole Blocks Too Much / Breaks Websites

**Symptom:** A legitimate website won't load after Pi-hole is running.

**Fix — whitelist the domain:**
```bash
docker exec pihole pihole -w the-broken-site.com
```

Or do it from the dashboard: **Whitelist → Add Domain**.

**How to identify which domain is being blocked:** Open the Pi-hole **Query Log** and filter by your device's IP. Look for red (blocked) entries that appeared at the same time the site broke. That is the domain to whitelist.

---

### A.7 — How to Research Any Error You Don't Recognize

When you hit an error that isn't covered here, use this process:

1. **Read the full error message.** Do not skip past it — it usually tells you exactly what went wrong.

2. **Copy the key part of the error** (skip the parts specific to your machine like file paths) and search for it. Add context words like `pihole docker raspberry pi`.

3. **Check these sources first:**
   - Pi-hole official docs: search `"pi-hole docs"`
   - Pi-hole community forum: search `"pi-hole discourse"`
   - Docker docs: search `"docker docs compose"`
   - Stack Overflow: paste your error directly

4. **Check the container logs** — almost every Docker problem leaves a clue there:
   ```bash
   docker compose logs pihole --tail 50
   ```
   The `--tail 50` flag shows the last 50 lines so you are not overwhelmed.

5. **Check system logs** if Docker logs don't help:
   ```bash
   sudo journalctl -xe | tail -30
   ```

6. **Ask a specific question.** Instead of "it doesn't work," describe: what command you ran, what you expected to happen, and the exact error message you got. This is how professional engineers ask for help too.

---

## Key Terms Glossary

| Term | Definition |
|------|-----------|
| **DNS** | Domain Name System — translates domain names to IP addresses |
| **DNS Sinkhole** | A DNS server that returns fake results for blocked domains |
| **Pi-hole** | Open-source network-wide ad blocker using DNS filtering |
| **Docker** | Platform for running applications in isolated containers |
| **Docker Compose** | Tool for defining and running multi-container Docker applications |
| **Container** | A lightweight, isolated environment for running an application |
| **Volume** | A way to persist data from a container to the host filesystem |
| **Port** | A numbered "door" on a computer where specific types of traffic enter/exit |
| **NXDOMAIN** | DNS response meaning "this domain does not exist" |
| **Gravity** | Pi-hole's process of updating and compiling its blocklists |

---

*Lab 01 | AI-Enabled Security | Raspberry Pi Lab Series*
*Next Up: Lab 02 — Network Traffic Analysis with Wireshark in Docker*
