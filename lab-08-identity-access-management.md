# Lab 08: Who Are You? — Identity & Access Management (IAM)
### Cybersecurity & Networking Essentials | Security+ Module 7

---

## What Are We Investigating?

Every time you unlock your phone, log into a school account, or swipe a badge to enter a building, you are participating in **Identity and Access Management (IAM)** — whether you know it or not.

Think of IAM as the security system for the digital world. It answers two fundamental questions:

1. **"Who are you?"** — *Authentication*: proving your identity
2. **"What are you allowed to do?"** — *Authorization*: controlling what resources you can access

In this lab, you will explore the core building blocks of IAM: the types of credentials used to prove identity, how passwords are attacked and protected, how multi-factor authentication works, and how access control systems decide who gets in and who doesn't.

---

## Learning Objectives

By the end of this lab, you will be able to:

- [ ] Identify and describe the seven types of authentication credentials
- [ ] Explain common password attacks and how salting/key stretching defend against them
- [ ] Set up and use a software-based one-time password (OTP) authenticator
- [ ] Distinguish between DAC, MAC, RBAC, and ABAC access control schemes
- [ ] Interpret file permission settings on your operating system

---

> **Certification Alignment**
> Skills in this lab map to the following industry certifications:
> - **CompTIA Security+ (SY0-701):** 2.4 — Analyze indicators of malicious activity (credential attacks) · 4.6 — Implement identity and access management (authentication types, MFA, access controls)
> - **CompTIA Network+ (N10-009):** 4.1 — Explain common security concepts (authentication, authorization, access control)

---

## Platform Note

> **No Linux? No problem.**
> This lab is designed to work on **Windows, macOS, or Linux**. Every section includes a path for each platform. Optional terminal steps are clearly labeled — if you don't have a terminal available, the browser-based and GUI activities cover the same concepts.

---

## Background: The Authentication Framework

Before you touch anything, let's build a shared vocabulary. Authentication credentials fall into **seven categories** — security professionals call these the "elements of authentication":

| Element | What It Means | Real-World Example |
|---------|--------------|-------------------|
| **Something you know** | Knowledge only you possess | Password, PIN, security question |
| **Something you have** | A physical or digital object | Badge, phone, hardware token |
| **Something you are** | Unique biological characteristic | Fingerprint, retina, face |
| **Somewhere you are** | A specific physical location | Military base, VPN-gated network |
| **Someone you know** | Validation by another person | Security clearance sponsorship |
| **Something you exhibit** | A genetically determined trait | Hair color, body shape |
| **Something you can do** | An action that cannot be exactly copied | Handwritten signature, gait |

Most systems today use the first three. The magic happens when you combine more than one — that's **Multi-Factor Authentication (MFA)**.

> **Key Rule:** MFA requires credentials from **at least two different categories**. A password + a PIN is *not* MFA (both are "something you know"). A password + a code from your phone *is* MFA (something you know + something you have).

---

## Lab Requirements

| Item | Details |
|------|---------|
| Hardware | Any computer (PC, Mac, Chromebook, or Pi) |
| Browser | Chrome, Firefox, or Edge |
| Optional | Terminal (Command Prompt, PowerShell, bash, or zsh) |
| App Store Access | For Part 3 (smartphone or browser-based alternative available) |
| Time | ~45–60 minutes |

---

## Part 1: Mapping Authentication Types

**Goal:** Recognize the seven authentication elements in real systems you use every day.

---

### Step 1.1 — Authentication Scavenger Hunt

Open a browser and visit any **two** of the following websites. For each site, identify the authentication type(s) used at login:

- `google.com`
- `github.com`
- `canvas.instructure.com` (or your school's LMS)
- A banking website of your choice

For each site, complete this table in your lab notes:

| Site | Credential Type(s) Required | MFA Available? (Y/N) | MFA Type if Yes |
|------|----------------------------|----------------------|-----------------|
| | | | |
| | | | |

> **Hint:** Click "Sign In" and look at every step of the login process. Some sites only reveal MFA options after you enter a password.

---

### Step 1.2 — Real-World Scenario Analysis

For each scenario below, identify **which authentication element is being used**:

1. You press your thumb on your phone screen to unlock it.
2. A nurse swipes a hospital ID badge to enter a medication room.
3. A bank asks for your mother's maiden name after the password fails.
4. A VPN requires that your device be connected from the corporate office network.
5. You receive a 6-digit code via text message to complete a login.
6. A building's camera system identifies an employee by how they walk.

Write your answers in your lab notes. We'll review these as a class.

---

## Part 2: Password Attacks and Defenses

**Goal:** Understand how attackers crack passwords and how proper storage defends against it.

---

### Step 2.1 — Understand the Threat

When you create a password, the system doesn't store it in plain text. It runs it through a **hash function** — a one-way mathematical operation that produces a fixed-length "digest." When you log in later, your input is hashed again and compared to the stored digest.

Here is what several common passwords look like after MD5 hashing:

```
password    →  5f4dcc3b5aa765d61d8327deb882cf99
123456      →  e10adc3949ba59abbe56e057f20f883e
letmein     →  0d107d09f5bbe40cade3de5c71e9e9b7
```

> **Why does this matter?** Attackers who steal a password database don't get passwords — they get hashes. But that's only half the story. Hashing alone isn't enough.

---

### Step 2.2 — See How Password Attacks Work

Visit **[CrackStation](https://crackstation.net)** — a legitimate password security research tool. It uses a precomputed table of over 1.5 billion hashes.

Paste each of the MD5 hashes from Step 2.1 into CrackStation and submit. Record what you see:

| Hash | Was It Cracked? | Recovered Password |
|------|-----------------|--------------------|
| `5f4dcc3b5aa765d61d8327deb882cf99` | | |
| `e10adc3949ba59abbe56e057f20f883e` | | |
| `0d107d09f5bbe40cade3de5c71e9e9b7` | | |

> **What just happened?** CrackStation uses a **rainbow table** — a massive precomputed lookup table of hashes. Common passwords are cracked in milliseconds because the hash was already computed and stored.

This is why modern systems add a **salt**: a unique random string added to your password *before* it is hashed. The same password now produces a completely different hash for every user, making rainbow tables useless.

---

### Step 2.3 — Evaluate a Password's Strength

Visit **[How Secure Is My Password](https://www.security.org/how-secure-is-my-password/)** and test the following passwords. Record the estimated crack time for each:

| Password | Estimated Crack Time |
|----------|---------------------|
| `password` | |
| `P@ssword1` | |
| `correct-horse-battery-staple` | |
| `Tr0ub4dor&3` | |
| A passphrase you invent (4+ random words) | |

> **Discussion question for your notes:** Which type of password resisted cracking best — a short complex password, or a long passphrase of simple words? What does this tell you about password length vs. complexity?

---

### Step 2.4 — Password Attack Reference

Match each attack type to its description. Write the letter next to the number in your notes:

**Attacks:**
1. Brute Force
2. Dictionary Attack
3. Password Spraying
4. Credential Stuffing
5. Rule Attack

**Descriptions:**
- A. Takes a sample of leaked passwords, runs statistical analysis, then generates optimized masks to crack the most passwords possible
- B. Tries one common password (like `Summer2024!`) against thousands of different user accounts to avoid account lockout
- C. Creates hashes of common dictionary words and compares them to a stolen hash file
- D. Takes username/password pairs stolen from one breach and tries them on other websites
- E. Tries every possible combination of characters until the correct one is found

---

### Step 2.5 — Optional Terminal: Generate and Observe Hashes

> **Skip this step if you don't have a terminal.** The concepts above cover the same material.

**Linux / macOS:**
```bash
# Hash the word "password" using SHA-256
echo -n "password" | sha256sum

# Now add a salt and see how different the result is
echo -n "password_randomsalt42" | sha256sum

# Compare the two outputs - same word, completely different hash
```

**Windows (PowerShell):**
```powershell
# Hash the word "password" using SHA-256
$bytes = [System.Text.Encoding]::UTF8.GetBytes("password")
[System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)) -replace '-',''

# Now hash it with a salt
$bytes2 = [System.Text.Encoding]::UTF8.GetBytes("passwordrandomsalt42")
[System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes2)) -replace '-',''
```

Record both outputs. They should be completely different — this is salting in action.

> **Reflection:** If two users both use the password `Summer2024!`, a salted system gives them completely different stored hashes. What problem does this solve?

---

## Part 3: Multi-Factor Authentication (MFA) in Action

**Goal:** Set up and use a software OTP token — the same type used by most corporate environments.

---

### Step 3.1 — Install an Authenticator App

A **software OTP token** generates a 6-digit code that changes every 30 seconds. This code is your "something you have" factor.

**Choose one option:**

**Option A — Smartphone App (recommended):**
Install one of the following on your phone:
- Google Authenticator (iOS / Android)
- Microsoft Authenticator (iOS / Android)
- Authy (iOS / Android)

**Option B — Browser Extension (no phone needed):**
Install **Authenticator** by Authenticator.cc in Chrome or Firefox. This works identically but lives in your browser.

---

### Step 3.2 — Connect to a Demo Account

> **Important:** Use only test/demo accounts for this exercise. Never add your personal accounts to a shared or lab device.

**Using a test account:**

1. Navigate to **[2FA Demo by Philip Camilleri](https://www.totp.danhersam.com/)** — a free TOTP demo site
2. A QR code will appear on the page along with a secret key
3. In your authenticator app, tap **+** or **Add Account** and scan the QR code
4. Your app will now show a 6-digit code that changes every 30 seconds

> **If QR scanning doesn't work:** Most authenticator apps also allow manual entry. Use the secret key displayed on the page.

---

### Step 3.3 — Verify the Code

On the demo page, type the 6-digit code from your authenticator app into the verification field. The site will confirm whether it is valid.

Observe the following:

- How often does the code change?
- What happens when you try to use a code that just expired?
- Could you share this code with someone and have them log in as you? What time window would they have?

> **Why this matters in the real world:** Even if an attacker steals your password, they cannot log in without the current OTP. The code expires in 30 seconds and requires physical possession of your device.

---

### Step 3.4 — Understanding the Technology

Answer the following in your lab notes:

1. TOTP stands for *Time-based One-Time Password*. What makes it "time-based"?
2. How is a software OTP (like what you just used) different from an SMS text code? Which is more secure, and why?
3. A **security key** (like a YubiKey) is a hardware alternative. What advantage does hardware have over software authenticators?
4. What is **attestation** on a security key, and why is it useful for organizations?

---

## Part 4: Access Control Schemes

**Goal:** Understand the major frameworks that control who can access what, and see them in action on your own system.

---

### Step 4.1 — The Four Core Schemes

Before you look at real files, understand the models:

**Discretionary Access Control (DAC) — "The owner decides"**
- Every file/object has an owner
- The owner sets permissions however they choose
- Most common in personal computing (Windows, Linux home directories)
- *Weakness:* Relies on users making good decisions. A careless user can share anything.

**Mandatory Access Control (MAC) — "The system decides"**
- Users cannot change permissions on objects — only the system administrator/custodian can
- Uses security labels (e.g., TOP SECRET, SECRET, UNCLASSIFIED)
- Used in government and military systems
- *Strength:* No user can accidentally or intentionally over-share data

**Role-Based Access Control (RBAC) — "Your job title decides"**
- Permissions are assigned to *roles*, not individuals
- Users are assigned to roles (e.g., "HR Staff," "Network Admin," "Read-Only Analyst")
- When an employee changes jobs, you change their role — not hundreds of individual permissions
- Most common in enterprise environments

**Attribute-Based Access Control (ABAC) — "Context decides"**
- The most flexible model
- Access is granted based on combinations of attributes: the user's department, device type, time of day, location, data classification, and more
- Example: "Allow access to the patient record if the user is a doctor AND is on the hospital network AND the patient is in their care"

---

### Step 4.2 — See DAC on Your Own Machine

Pick the path for your operating system:

---

**Windows Path:**

1. Open **File Explorer** and navigate to your Documents folder
2. Create a new text file called `iam-test.txt`
3. Right-click the file → **Properties** → **Security** tab
4. You will see a list of users and groups, with checkboxes for:
   - Full control
   - Modify
   - Read & execute
   - Read
   - Write

Answer in your notes:
- Who currently has access to this file?
- Who is listed as the owner? (Click **Advanced** to see the owner)
- What would happen if you unchecked "Read" for "Users"?

> **This is DAC in action.** You, as the file's owner, are choosing who can access it and what they can do.

---

**Linux / macOS Path:**

Open a terminal and run:

```bash
# Create a test file
touch ~/iam-test.txt

# View its permissions
ls -la ~/iam-test.txt
```

You will see output like:
```
-rw-r--r--  1 yourname  staff  0 Apr 2 10:00 iam-test.txt
```

Decode the permission string:

```
- rw- r-- r--
│  │   │   └── Others: read only
│  │   └────── Group: read only
│  └────────── Owner: read and write
└───────────── File type (- = regular file)
```

Now experiment:

```bash
# Remove all permissions from "others"
chmod o-r ~/iam-test.txt
ls -la ~/iam-test.txt

# Add execute permission for the owner
chmod u+x ~/iam-test.txt
ls -la ~/iam-test.txt

# Set permissions using numeric notation (rw-r--r-- = 644)
chmod 644 ~/iam-test.txt
ls -la ~/iam-test.txt
```

> **The numeric notation explained:**
> Each permission group (owner, group, others) is represented as a sum:
> - Read = 4
> - Write = 2
> - Execute = 1
>
> So `chmod 754` = owner gets 4+2+1=7 (rwx), group gets 4+0+1=5 (r-x), others get 4 (r--)

---

### Step 4.3 — RBAC in the Real World

Visit your school's Canvas LMS (or another platform you use). Consider the following:

- **Students** can submit assignments, view their own grades, post to discussions
- **Instructors** can create assignments, view all grades, publish content
- **Admins** can enroll/drop students, reset passwords, manage courses

Answer in your notes:
1. Is this a DAC, MAC, RBAC, or ABAC system? How do you know?
2. What would happen if a student was accidentally given the "Instructor" role?
3. Why is it easier to manage permissions by role rather than by individual user in an organization with hundreds of employees?

---

### Step 4.4 — Access Control Lists (ACLs)

An **Access Control List (ACL)** is the actual mechanism behind DAC. It is a list attached to each object that specifies:
- *Who* can access it (a user or group)
- *What* they can do (read, write, execute, delete, etc.)

You already saw an ACL in Step 4.2 — both the Windows Security tab and the `ls -la` output are displaying ACL information.

**Scenario analysis:**

A hospital file server stores patient records. The IT admin sets the following ACL on the folder `/records/patient-files/`:

| User / Group | Read | Write | Delete | Execute |
|-------------|------|-------|--------|---------|
| Doctors | ✓ | ✓ | ✗ | ✗ |
| Nurses | ✓ | ✗ | ✗ | ✗ |
| Billing | ✓ | ✗ | ✗ | ✗ |
| IT Admin | ✓ | ✓ | ✓ | ✓ |
| All Others | ✗ | ✗ | ✗ | ✗ |

Answer in your notes:
1. A nurse tries to edit a patient's file. What happens?
2. A billing staff member accidentally downloads patient records to a personal USB drive. What *access control failure* allowed this? What would prevent it?
3. A doctor needs to permanently delete a corrupted record. What needs to change in the ACL?
4. Which access control model (DAC, MAC, RBAC, ABAC) does this ACL most closely resemble? Justify your answer.

---

## Part 5: Putting It Together — Single Sign-On

**Goal:** Understand how SSO and federated identity reduce credential sprawl.

---

### Step 5.1 — The Password Sprawl Problem

Think about how many accounts you have: school, email, social media, streaming, gaming, banking. Each one is a separate username and password. This creates problems:

- Users reuse passwords across sites (credential stuffing becomes devastating)
- IT departments can't centrally enforce policy across external sites
- Forgotten passwords = helpdesk tickets

**Single Sign-On (SSO)** solves this by letting a single trusted **Identity Provider (IdP)** handle authentication for many applications. The applications trust the IdP's word instead of checking credentials themselves.

---

### Step 5.2 — Recognize SSO in the Wild

You have almost certainly used SSO without realizing it. Look for these buttons on login pages:

- "Sign in with Google"
- "Continue with Apple"
- "Log in with your school account"

These are **federated identity** flows. The website is delegating authentication to a trusted third party.

The underlying protocol is typically:
- **SAML** (Security Assertion Markup Language) — common in enterprise, government, and education
- **OAuth 2.0 / OpenID Connect** — common in consumer apps ("Sign in with Google")

**Quick activity:** Find one website you use that offers "Sign in with Google" or another SSO option. In your notes, diagram the flow:

```
You → [Site's Login Page] → [Redirected to Google] → [Google verifies you] → [Token returned to site] → [Access granted]
```

Who is the **Identity Provider** in this flow? Who is the **Service Provider**?

---

### Step 5.3 — Passkeys: The Future of Authentication

Passkeys represent the next evolution of authentication. Instead of a password, your device generates a **cryptographic key pair**:
- The **private key** never leaves your device
- The **public key** is registered with the website

When you log in, the site sends a challenge. Your device signs it with the private key. The site verifies the signature with the public key. No password is ever transmitted or stored.

**Key advantages:**
- No password to steal or phish
- Combines "something you have" (the device) with "something you are" (biometric to unlock the device)
- "Discoverable" — passkeys can sync between your trusted devices via the cloud

Visit **[passkeys.io](https://www.passkeys.io)** and try the demo. Note the experience compared to a traditional password login.

---

## Reflection Questions

Answer the following in your lab notes. These may be used for class discussion:

1. You are designing authentication for a hospital's electronic health record system. Which authentication factors would you require, and why? Would you use the same factors for doctors, nurses, and administrative staff?

2. A company stores all employee passwords as unsalted MD5 hashes. They are breached and the hash file is stolen. Explain step-by-step how an attacker could recover plaintext passwords. What should the company have done instead?

3. Describe a scenario where **ABAC** would be more appropriate than **RBAC**. What attributes would your policy combine?

4. An employee leaves the company. Under **RBAC**, what is the minimum action an IT admin must take to revoke all of that employee's access? Why is this simpler than under a pure DAC model?

5. Your friend argues: "I use the same strong password everywhere — it's 20 characters with symbols, so it can never be cracked." Identify at least two attacks that would still compromise their accounts, and explain why password uniqueness matters even for strong passwords.

---

## Bonus Challenges

**Bonus A — Password Manager Setup**
Install **Bitwarden** (free, open-source) as a browser extension. Create a test account, generate a 20-character random password for a new entry, and screenshot the strength indicator. What makes a password manager fundamentally safer than memorizing passwords?

**Bonus B — Hash Type Identification**
Identify the hash algorithm used for each digest below based on its length and characteristics:

```
5f4dcc3b5aa765d61d8327deb882cf99
```
```
5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
```
```
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

Hint: MD5 = 32 hex chars, SHA-1 = 40 hex chars, SHA-256 = 64 hex chars

**Bonus C — Linux: Examine the Shadow File**
> **Requires Linux with sudo access.**

On a Linux system, password hashes are stored in `/etc/shadow`. The format reveals the hashing algorithm used:

```bash
sudo cat /etc/shadow | grep your-username
```

Look at the hash prefix:
- `$1$` = MD5 (insecure)
- `$5$` = SHA-256
- `$6$` = SHA-512
- `$y$` = yescrypt (modern, key-stretching)

What algorithm is your system using? Is it one of the key-stretching algorithms mentioned in the module (bcrypt = `$2b$`, Argon2 = `$argon2`)?

---

## Verification Checklist

Before submitting, confirm you have completed the following:

- [ ] Authentication scavenger hunt table (Part 1.1)
- [ ] Scenario analysis answers (Part 1.2)
- [ ] CrackStation results table (Part 2.2)
- [ ] Password strength test results (Part 2.3)
- [ ] Password attack matching exercise (Part 2.4)
- [ ] Authenticator app set up and OTP verified (Part 3.2–3.3)
- [ ] MFA reflection questions answered (Part 3.4)
- [ ] File permission activity completed (Part 4.2)
- [ ] Hospital ACL scenario answered (Part 4.4)
- [ ] SSO flow diagram (Part 5.2)
- [ ] All five reflection questions answered

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| CrackStation times out | Try submitting one hash at a time; the site may be rate-limiting |
| QR code won't scan | Use manual entry with the secret key displayed on the page |
| Windows Security tab is grayed out | You are viewing a system file; create a new file in your Documents folder instead |
| `chmod` command not found | You are on Windows; use the Windows path in Step 4.2 |
| Passkeys demo fails | Try a different browser (Chrome has the best passkey support) |
| PowerShell hash command returns an error | Try running PowerShell as Administrator |

---

## Key Terms

| Term | Definition |
|------|-----------|
| **Authentication** | The process of proving you are who you claim to be |
| **Authorization** | The process of determining what you are allowed to do |
| **MFA** | Using credentials from two or more different authentication categories |
| **OTP** | One-Time Password — a code valid for a single login session or short time window |
| **Salt** | A random string added to a password before hashing to defeat rainbow tables |
| **Key Stretching** | A hashing technique intentionally designed to be slow (bcrypt, PBKDF2, Argon2) |
| **SSO** | Single Sign-On — one authentication credential grants access to multiple systems |
| **SAML** | XML-based protocol for exchanging authentication and authorization data |
| **DAC** | Discretionary Access Control — the owner controls permissions (least restrictive) |
| **MAC** | Mandatory Access Control — the system controls permissions via labels (most restrictive) |
| **RBAC** | Role-Based Access Control — permissions assigned to job roles |
| **ABAC** | Attribute-Based Access Control — flexible policies combining multiple attributes |
| **ACL** | Access Control List — the actual list of permissions attached to an object |
| **Passkey** | A cryptographic key pair that replaces passwords, tied to a device |
| **Federated Identity** | Sharing a single authentication credential across organizations |

---

*CompTIA Security+ Guide to Network Security Fundamentals, 8e — Module 7: Identity and Access Management*
*Lab developed for the Cybersecurity & Networking Essentials lab series.*
