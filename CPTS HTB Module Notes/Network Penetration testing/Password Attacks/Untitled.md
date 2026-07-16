#  Linux Authentication Process (HTB Detailed Notes)

> **Module:** Password Attacks – Linux Authentication Process  
> Source: User-provided study material

---

# Overview

Unlike Windows, Linux supports **multiple authentication mechanisms**. The most common authentication framework used by Linux distributions is **PAM (Pluggable Authentication Modules)**.

PAM acts as a bridge between applications (login, ssh, passwd, sudo, etc.) and the actual authentication methods.

---

# Linux Authentication Architecture

```text
                    User Login
                        │
                        ▼
               Login / SSH / Sudo
                        │
                        ▼
          PAM (Pluggable Authentication Modules)
                        │
        ┌───────────────┼─────────────────┐
        │               │                 │
        ▼               ▼                 ▼
   pam_unix.so      LDAP Module      Kerberos Module
        │
        ▼
 /etc/passwd   +   /etc/shadow
        │
        ▼
 User Authentication
```

---

# What is PAM?

**PAM (Pluggable Authentication Modules)** is a framework that handles authentication, authorization, session management, and password changes.

Instead of each application implementing authentication itself, it asks PAM to perform it.

Examples of applications using PAM:

- login
    
- ssh
    
- sudo
    
- passwd
    
- su
    
- gdm
    
- lightdm
    

---

# PAM Modules

On Debian-based systems, PAM modules are usually stored in

```bash
/usr/lib/x86_64-linux-gnu/security/
```

Common modules include:

|Module|Purpose|
|---|---|
|pam_unix.so|Local authentication|
|pam_unix2.so|Alternative Unix authentication|
|pam_ldap.so|LDAP authentication|
|pam_krb5.so|Kerberos authentication|
|pam_mount.so|Mount user directories|

---

# Authentication Flow

```text
User Types Password
        │
        ▼
 Login / SSH
        │
        ▼
      PAM
        │
        ▼
pam_unix.so
        │
        ▼
Read /etc/passwd
Read /etc/shadow
        │
        ▼
Password Verification
        │
        ▼
Access Granted
```

---

# What Happens When You Change Password?

Command

```bash
passwd
```

Workflow

```text
passwd
   │
   ▼
PAM
   │
   ▼
pam_unix.so
   │
   ▼
Update
/etc/shadow
```

PAM ensures:

- Password complexity
    
- Password history
    
- Secure hashing
    
- Proper permissions
    

---

# /etc/passwd

The **/etc/passwd** file stores information about every user on the system.

It is **world-readable**.

Example

```text
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash
```

---

# Structure of /etc/passwd

```text
Username : Password : UID : GID : GECOS : Home : Shell
```

---

# passwd File Fields

|Field|Example|Description|
|---|---|---|
|Username|htb-student|Login name|
|Password|x|Points to /etc/shadow|
|UID|1000|User ID|
|GID|1000|Primary Group ID|
|GECOS|,,,|User information|
|Home Directory|/home/htb-student|User home|
|Shell|/bin/bash|Default shell|

---

# passwd File Diagram

```text
Username
    │
Password Field
    │
UID
    │
GID
    │
User Information
    │
Home Directory
    │
Login Shell
```

---

# Password Field

Normally

```text
x
```

means

```text
Password stored inside

/etc/shadow
```

---

# Rare Scenario

Older Linux systems may store password hashes directly inside

```text
/etc/passwd
```

Since this file is readable by everyone,

an attacker could simply copy the hash and crack it offline.

---

# Dangerous Misconfiguration

Suppose root entry becomes

```text
root::0:0:root:/root:/bin/bash
```

Notice

```text
Password Field

↓

EMPTY
```

Now running

```bash
su
```

may allow login **without a password**.

---

# Security Warning

Administrators should never make

```text
/etc/passwd
```

or

```text
/etc
```

writable.

Doing so can lead to privilege escalation.

---

# /etc/shadow

To protect password hashes,

Linux stores them separately.

Location

```bash
/etc/shadow
```

Unlike passwd,

this file is readable only by **root**.

---

# Example Entry

```text
htb-student:$y$j9T$3QSBB6CbHEu...:18955:0:99999:7:::
```

---

# Structure of /etc/shadow

```text
Username
Password Hash
Last Password Change
Minimum Password Age
Maximum Password Age
Warning Period
Inactive Period
Expiration Date
Reserved
```

---

# Shadow File Fields

|Field|Description|
|---|---|
|Username|User|
|Password|Password Hash|
|Last Change|Days since password change|
|Min Age|Minimum age|
|Max Age|Password lifetime|
|Warning|Expiration warning|
|Inactive|Inactivity period|
|Expiration|Account expiration|
|Reserved|Reserved|

---

# Shadow Authentication Flow

```text
User Login
      │
      ▼
PAM
      │
      ▼
Read /etc/shadow
      │
      ▼
Compare Password Hash
      │
      ▼
Login Success
```

---

# Password Field Meanings

Password field may contain

## Normal Hash

```text
$6$hash
```

User can authenticate normally.

---

## !

```text
!
```

Account cannot log in using Unix password.

---

## *

```text
*
```

Password login disabled.

---

## Empty

No password required.

This is dangerous if password authentication is enabled.

---

# Hash Format

Linux hashes follow

```text
$id$salt$hash
```

Diagram

```text
$6$ABC123$EncryptedPassword

 │    │           │
 │    │           └── Hash
 │    └────────────── Salt
 └─────────────────── Algorithm ID
```

---

# Hash Algorithm IDs

|ID|Algorithm|
|---|---|
|1|MD5|
|2a|Blowfish|
|5|SHA-256|
|6|SHA-512|
|sha1|SHA1crypt|
|y|Yescrypt|
|gy|Gost-Yescrypt|
|7|Scrypt|

---

# Most Common Modern Algorithm

Most modern Linux distributions use

```text
Yescrypt

↓

ID = y
```

Older systems commonly use

```text
SHA-512

↓

ID = 6
```

---

# Hash Strength

```text
MD5
   │
Weak
   ▼
SHA-256
   ▼
SHA-512
   ▼
Yescrypt
   │
Strong
```

---

# /etc/security/opasswd

Linux can prevent password reuse.

Old passwords are stored inside

```bash
/etc/security/opasswd
```

Example

```text
cry0l1t3:1000:2:
$1$HjFA...
$1$kcUj...
```

---

# Why is opasswd Useful?

Suppose

Current Password

```text
Summer2025!
```

Old Password

```text
Summer2024!
```

Users often reuse similar passwords.

Finding old passwords helps predict future passwords.

---

# MD5 in opasswd

Notice

```text
$1$
```

means

```text
MD5
```

MD5 hashes are much easier to crack than SHA-512 or Yescrypt.

---

# Credential Hunting Workflow

```text
Root Access
      │
      ▼
Copy passwd
      │
      ▼
Copy shadow
      │
      ▼
Combine
      │
      ▼
Crack Hashes
```

---

# Copy Files

```bash
sudo cp /etc/passwd /tmp/passwd.bak
```

```bash
sudo cp /etc/shadow /tmp/shadow.bak
```

---

# unshadow

John the Ripper includes

```text
unshadow
```

Purpose

Combine passwd + shadow into one file.

Command

```bash
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

Workflow

```text
passwd
      │
      ▼
shadow
      │
      ▼
unshadow
      │
      ▼
Combined File
```

---

# Why Use unshadow?

Hashcat and John the Ripper require both

```text
Username

+

Password Hash
```

The combined file contains both.

---

# Cracking Hashes

Example

```bash
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

---

# Command Breakdown

|Option|Meaning|
|---|---|
|-m 1800|SHA-512 crypt|
|-a 0|Dictionary Attack|
|rockyou.txt|Wordlist|
|-o|Save cracked passwords|

---

# Complete Attack Flow

```text
Gain Root Access
        │
        ▼
Copy passwd
        │
        ▼
Copy shadow
        │
        ▼
Run unshadow
        │
        ▼
Combined Hash File
        │
        ▼
Hashcat / John
        │
        ▼
Plaintext Passwords
```

---

# Important Files

|File|Purpose|
|---|---|
|/etc/passwd|User Information|
|/etc/shadow|Password Hashes|
|/etc/security/opasswd|Previous Passwords|
|/usr/lib/.../security|PAM Modules|

---

# Important Commands

### View passwd

```bash
cat /etc/passwd
```

---

### View first line

```bash
head -n 1 /etc/passwd
```

---

### View shadow

```bash
sudo cat /etc/shadow
```

---

### View old passwords

```bash
sudo cat /etc/security/opasswd
```

---

### Backup passwd

```bash
sudo cp /etc/passwd /tmp/passwd.bak
```

---

### Backup shadow

```bash
sudo cp /etc/shadow /tmp/shadow.bak
```

---

### Combine Files

```bash
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

---

### Crack Hashes

```bash
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt
```

---

# Linux Authentication Summary

```text
User Login
      │
      ▼
Login / SSH / sudo
      │
      ▼
PAM
      │
      ▼
pam_unix.so
      │
      ▼
/etc/passwd
      │
      ▼
/etc/shadow
      │
      ▼
Password Verification
```

---

# Memory Tricks

### Linux Authentication

```text
PAM

↓

passwd

↓

shadow

↓

Login
```

---

### Files

```text
passwd

↓

User Information

---------------

shadow

↓

Password Hashes

---------------

opasswd

↓

Old Passwords
```

---

### Hash IDs

```text
1 → MD5

5 → SHA-256

6 → SHA-512

y → Yescrypt

7 → Scrypt
```

---

# HTB / Exam Questions

### Which framework manages Linux authentication?

✅ **PAM (Pluggable Authentication Modules)**

---

### Which PAM module handles local Unix authentication?

✅ **`pam_unix.so`**

---

### Which file stores user account information?

✅ **`/etc/passwd`**

---

### Which file stores password hashes?

✅ **`/etc/shadow`**

---

### Which file stores previous passwords?

✅ **`/etc/security/opasswd`**

---

### Which command combines passwd and shadow?

```bash
unshadow
```

---

### Which tool is commonly used with `unshadow` output to crack Linux password hashes?

✅ **Hashcat** or **John the Ripper (JtR)**

---

### Which hash ID represents SHA-512?

✅ **6**

---

### Which hash ID represents Yescrypt?

✅ **y**

---

### What does `x` in the password field of `/etc/passwd` indicate?

✅ The actual password hash is stored in **`/etc/shadow`**.

---

# 🔥 1-Minute Revision Sheet

```text
Linux Authentication
        │
        ▼
PAM
        │
        ▼
pam_unix.so
        │
        ▼
passwd + shadow

Files
─────
/etc/passwd → User Info
/etc/shadow → Password Hashes
/etc/security/opasswd → Old Passwords

Hash IDs
────────
1 → MD5
5 → SHA-256
6 → SHA-512
y → Yescrypt
7 → Scrypt

Commands
────────
cat /etc/passwd
cat /etc/shadow
cat /etc/security/opasswd
unshadow passwd shadow
hashcat -m 1800

Workflow
────────
Root Access
→ Copy passwd
→ Copy shadow
→ unshadow
→ Hashcat/JtR
→ Plaintext Passwords
```

These notes preserve the important concepts, commands, and file structures from your material while adding diagrams ("pics"), workflows, comparisons, memory tricks, and HTB/interview-focused explanations.