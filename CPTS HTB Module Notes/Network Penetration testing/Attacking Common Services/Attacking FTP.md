# 1. 📂 What Is FTP?

**FTP = File Transfer Protocol**

FTP is a standard network protocol used to **transfer files between computers**.

It can also perform file and directory operations such as:

- Changing the working directory
    
- Listing files
    
- Renaming files
    
- Deleting files
    
- Creating/managing directories
    
- Uploading files
    
- Downloading files
    

By default:

```text
FTP → TCP/21
```

### Basic FTP Architecture

```text
              FTP CLIENT
                  │
                  │ TCP/21
                  ▼
        ┌──────────────────┐
        │    FTP SERVER    │
        │                  │
        │  Files           │
        │  Directories     │
        │  Uploads         │
        │  Downloads       │
        └──────────────────┘
```

---

# 2. 🎯 Why Is FTP Interesting During an Assessment?

An FTP server can become interesting because of:

1. **Misconfiguration**
    
2. **Excessive privileges**
    
3. **Known vulnerabilities**
    
4. **Newly discovered vulnerabilities**
    

Therefore, after gaining access to an FTP service, we should carefully examine its contents.

The goal is not simply:

> “I got FTP access.”

Instead:

> **“What can this FTP access tell me about the target?”**

---

# 3. 🧠 FTP Attack Methodology

A useful workflow is:

```text
             FTP DISCOVERED
                    │
                    ▼
              ENUMERATION
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   Anonymous Access?       No Anonymous
          │                   │
          ▼                   ▼
     Enumerate Files       Assess Login
          │                   │
          └─────────┬─────────┘
                    ▼
             Analyze Content
                    │
                    ▼
          Search for Sensitive
              Information
                    │
                    ▼
        Check Authorized Attack
              Opportunities
```

---

# 4. 📁 FTP and Hierarchical File Systems

FTP provides a file-management system known by the operating system.

Files can be organized into:

```text
Folders
   └── Subfolders
          └── Files
```

This produces a **hierarchical directory structure**.

Example:

```text
/
├── etc/
├── bin/
├── lib/
├── pub/
└── incoming/
      ├── file1.txt
      └── file2.txt
```

This matters because FTP access can expose information stored in different directories.

---

# 5. 🏢 Why Companies Use FTP

The source notes that many companies use FTP for:

- Software development processes
    
- Website development processes
    
- File transfer
    
- Sharing files between systems
    

Therefore, FTP directories may contain:

```text
Source Code
Configuration
Documents
Backups
Development Files
Uploaded Files
```

This makes enumeration important.

---

# 6. 🔎 FTP Enumeration

The first step after discovering FTP is to enumerate it.

## Nmap

Nmap's default scripts:

```text
-sC
```

include the:

```text
ftp-anon
```

script.

The `ftp-anon` script checks whether an FTP server allows **anonymous login**.

The version enumeration option:

```text
-sV
```

can provide information such as:

- FTP banner
    
- Service version
    
- Software name
    

FTP normally listens on:

```text
TCP/21
```

---

# 7. 🧪 Nmap Enumeration

The source provides:

```bash
sudo nmap -sC -sV -p 21 192.168.2.142
```

### Breakdown

|Option|Meaning|
|---|---|
|`sudo`|Run with elevated privileges|
|`nmap`|Network scanning tool|
|`-sC`|Run Nmap's default scripts|
|`-sV`|Detect service/version information|
|`-p 21`|Scan TCP port 21|
|`192.168.2.142`|Target|

---

# 8. 📋 Understanding the Nmap Result

Important part:

```text
PORT   STATE SERVICE
21/tcp open  ftp
```

This tells us:

```text
Port → 21
State → open
Service → ftp
```

Then:

```text
ftp-anon: Anonymous FTP login allowed
```

This is an important finding.

It means the FTP server permits anonymous authentication.

---

# 9. 🖼️ Nmap → FTP Enumeration Flow

```text
             NMAP
               │
               ▼
      ┌────────────────┐
      │ TCP/21         │
      │ FTP            │
      └───────┬────────┘
              │
       ┌──────┴───────┐
       ▼              ▼
     -sC             -sV
       │              │
       ▼              ▼
 ftp-anon          Banner /
 Anonymous         Version
       │              │
       └──────┬───────┘
              ▼
       FTP Enumeration
```

---

# 10. 📂 Interesting Nmap Output

The supplied example shows:

```text
-rw-r--r--   1 1170     924            31 Mar 28  2001 .banner
d--x--x--x   2 root     root         1024 Jan 14  2002 bin
d--x--x--x   2 root     root         1024 Aug 10  1999 etc
drwxr-srwt   2 1170     924          2048 Jul 19 18:48 incoming [NSE: writeable]
d--x--x--x   2 root     root         1024 Jan 14  2002 lib
drwxr-sr-x   2 1170     924          1024 Aug  5  2004 pub
```

Notice:

```text
incoming [NSE: writeable]
```

This is particularly interesting because it indicates a **writable directory**.

---

# 11. ⚠️ What Should We Notice During Enumeration?

Don't just look for vulnerabilities.

Look for:

### Authentication

```text
Anonymous login?
Valid credentials?
```

### Permissions

```text
Read?
Write?
Upload?
Download?
Delete?
```

### Files

```text
Configuration?
Credentials?
Source code?
Backups?
Documents?
```

### Directories

```text
Writable?
Readable?
Restricted?
```

### Service Information

```text
FTP software?
Version?
Banner?
```

---

# 12. 🔐 FTP Anonymous Authentication

Anonymous authentication is one of the most important FTP misconfigurations.

To access using anonymous login, the source uses:

```text
Username:
anonymous
```

and no meaningful password is required.

Conceptually:

```text
              CLIENT
                 │
                 │ anonymous
                 ▼
          ┌──────────────┐
          │ FTP SERVER   │
          └──────┬───────┘
                 │
                 ▼
          Login Successful
```

---

# 13. 🧪 FTP Client — Anonymous Login

The source provides:

```bash
ftp 192.168.2.142
```

Then:

```text
Connected to 192.168.2.142.
220 (vsFTPd 2.3.4)
Name (192.168.2.142:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Important FTP response codes:

```text
220 → Service ready / banner
331 → Password required
230 → Login successful
```

---

# 14. 📋 Listing Files

Once logged in:

```text
ftp> ls
```

Example:

```text
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0               9 Aug 12 16:51 test.txt
226 Directory send OK.
```

We discovered:

```text
test.txt
```

The next step is to determine what information or access the file provides.

---

# 15. 🧰 Important FTP Commands

Once connected, FTP provides commands similar to basic filesystem operations.

|Command|Purpose|
|---|---|
|`ls`|List files/directories|
|`cd`|Change directory|
|`get`|Download one file|
|`mget`|Download multiple files|
|`put`|Upload one file|
|`mput`|Upload multiple files|
|`help`|Display FTP command help|

---

# 16. 📥 Downloading Files

To download one file:

```text
get
```

Example:

```text
ftp> get test.txt
```

For multiple files:

```text
mget
```

Example:

```text
ftp> mget *.txt
```

The important distinction:

```text
get  → Single file
mget → Multiple files
```

---

# 17. 📤 Uploading Files

To upload one file:

```text
put
```

Example:

```text
ftp> put test.txt
```

For multiple files:

```text
mput
```

Example:

```text
ftp> mput *.txt
```

Therefore:

```text
DOWNLOAD
   │
   ├── get
   └── mget

UPLOAD
   │
   ├── put
   └── mput
```

---

# 18. 🧭 Navigating FTP

FTP directory navigation is similar to Linux filesystem navigation.

### List:

```text
ls
```

### Change directory:

```text
cd directory
```

Example:

```text
ftp> cd pub
```

Then:

```text
ftp> ls
```

This lets us explore the directory hierarchy.

---

# 19. 🔥 Why Read/Write Permissions Matter

Anonymous authentication becomes much more dangerous when combined with incorrect permissions.

Consider:

```text
Anonymous User
       │
       ▼
      FTP
       │
       ├── Read ✓
       ├── Download ✓
       └── Upload ✓
```

If sensitive files are readable:

```text
Anonymous
    ↓
Sensitive Information
```

If writable directories exist:

```text
Anonymous
    ↓
Upload
    ↓
Potentially Dangerous File
```

Therefore:

# **Authentication + Permissions must always be analyzed together.**

---

# 20. 🚨 Sensitive Information on FTP

An FTP server may contain:

- Credentials
    
- Configuration files
    
- Source code
    
- Website files
    
- Backups
    
- Internal documents
    
- Usernames
    
- Other sensitive information
    

This connects directly to the previous topic:

> **Finding Sensitive Information**

So after gaining FTP access, don't stop at authentication.

---

# 21. 🧠 FTP Enumeration Mindset

Ask:

```text
1. Can I authenticate?
       ↓
2. What can I access?
       ↓
3. What directories exist?
       ↓
4. What files exist?
       ↓
5. What can I download?
       ↓
6. Can I upload?
       ↓
7. What information do the files contain?
       ↓
8. Does this information lead to another service?
```

---

# 22. ⚔️ Protocol-Specific Attacks

The source makes an important distinction:

> We are **not attacking the individual protocols themselves**, but rather the **services that use them**.

Why?

Because many different services can use the same protocol.

For example:

```text
FTP Protocol
     │
     ├── FTP Service A
     ├── FTP Service B
     ├── FTP Service C
     └── FTP Service D
```

Each service may process information differently.

Therefore:

```text
Same Protocol
      ≠
Same Vulnerability
```

---

# 23. 🔨 Brute Forcing FTP

If anonymous authentication isn't available, credentials may potentially be tested using a password list during an **authorized assessment**.

The source introduces:

# **Medusa**

Medusa is a tool that can perform login brute-force testing against supported services.

---

# 24. Medusa Options

The source identifies these options:

|Option|Meaning|
|---|---|
|`-u`|Single username|
|`-U`|Username list|
|`-P`|Password list|
|`-M`|Module/protocol|
|`-h`|Target hostname/IP|

For FTP:

```text
-M ftp
```

---

# 25. 🧪 Brute Force Example From the Source

The supplied example is:

```bash
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp
```

Breakdown:

```text
-u fiona
   ↓
Target username = fiona

-P /usr/share/wordlists/rockyou.txt
   ↓
Password wordlist

-h 10.129.203.7
   ↓
Target host

-M ftp
   ↓
FTP module
```

The source's example ultimately reports:

```text
ACCOUNT FOUND: [ftp] Host: 10.129.203.7 User: fiona Password: family [SUCCESS]
```

---

# 26. ⚠️ Brute Force vs Password Spraying

The source gives an important note:

> Although services may be vulnerable to brute force, most applications today prevent these types of attacks.

It identifies **Password Spraying** as a potentially more effective approach.

### Brute Force

Try:

```text
One User
+
Many Passwords
```

Example:

```text
fiona
 ├── password1
 ├── password2
 ├── password3
 └── password4
```

### Password Spraying

Try:

```text
One Password
+
Many Users
```

Conceptually:

```text
Password123
   │
   ├── User A
   ├── User B
   ├── User C
   └── User D
```

The key difference:

```text
Brute Force
→ Many passwords against one account

Password Spraying
→ One/few passwords against many accounts
```

---

# 27. 🧠 Why Modern Services Defend Against Brute Force

Modern services may implement:

- Rate limiting
    
- Account lockout
    
- Login throttling
    
- CAPTCHA
    
- Monitoring
    
- IP blocking
    
- Multi-factor authentication
    

Therefore, indiscriminate brute forcing can quickly trigger defenses.

In an authorized engagement, always respect the agreed rules of engagement.

---

# 28. 🌐 FTP Bounce Attack

An **FTP Bounce Attack** is a network attack that abuses an FTP server to send outbound traffic toward another device.

The attacker uses the FTP server as an intermediary.

Instead of:

```text
Attacker → Internal Target
```

the traffic can conceptually become:

```text
Attacker
   │
   ▼
FTP Server
   │
   ▼
Internal Target
```

---

# 29. 🖼️ FTP Bounce Concept

Imagine:

```text
             INTERNET
                 │
                 ▼
        ┌─────────────────┐
        │    ATTACKER     │
        └────────┬────────┘
                 │
                 │ FTP
                 ▼
        ┌─────────────────┐
        │    FTP_DMZ      │
        │ Public Server   │
        └────────┬────────┘
                 │
                 │ FTP Bounce
                 ▼
        ┌─────────────────┐
        │  Internal_DMZ   │
        │ Internal Server │
        └─────────────────┘
```

The important idea is:

# **The FTP server becomes a proxy for traffic toward another system.**

---

# 30. 🎯 Why FTP Bounce Is Useful to an Attacker

The source's scenario is:

```text
FTP_DMZ
```

is exposed to the Internet.

But:

```text
Internal_DMZ
```

isn't directly exposed.

If FTP bounce is enabled/misconfigured, the attacker may be able to use:

```text
FTP_DMZ
```

to interact with:

```text
Internal_DMZ
```

and determine information such as open ports.

---

# 31. 🔎 FTP Bounce and Port Scanning

The attack can therefore help discover:

```text
Internal Target
      │
      ├── Port 80
      ├── Port 22
      ├── Port 445
      └── ...
```

The information can then contribute to further **authorized assessment** of the internal infrastructure.

---

# 32. `Nmap -b`

The source explains that Nmap's:

```text
-b
```

option can be used for an FTP bounce attack.

The provided example is:

```bash
nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2
```

### Breakdown

```text
-Pn
```

Treat the target as online without host discovery.

```text
-v
```

Verbose output.

```text
-n
```

Disable DNS resolution.

```text
-p80
```

Scan TCP port 80.

```text
-b
```

Use FTP bounce.

```text
anonymous:password@10.10.110.213
```

FTP bounce server credentials/target.

```text
172.17.0.2
```

Target to be reached through the FTP server.

---

# 33. 🧪 Understanding the Example Output

The source shows:

```text
Resolved FTP bounce attack proxy to 10.10.110.213
```

Then:

```text
Attempting connection to
ftp://anonymous:password@10.10.110.213:21
```

Then:

```text
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
```

Then:

```text
Initiating Bounce Scan
```

Finally:

```text
Nmap scan report for 172.17.0.2

PORT   STATE  SERVICE
80/tcp open http
```

This indicates that port 80 on the target was reachable through the FTP bounce mechanism in the supplied example.

---

# 34. 🧩 FTP Bounce Attack Chain

```text
       ATTACKER
          │
          │ FTP connection
          ▼
   ┌───────────────┐
   │   FTP_DMZ     │
   │ FTP Server    │
   └───────┬───────┘
           │
           │ Bounce
           ▼
   ┌───────────────┐
   │ Internal_DMZ  │
   │               │
   │ Port 80  ✓    │
   │ Port ??  ?    │
   └───────────────┘
```

---

# 35. 🛡️ Modern FTP Bounce Protections

Modern FTP servers generally include protections that prevent FTP bounce attacks by default.

However:

```text
Modern Protection
       │
       ▼
Misconfiguration
       │
       ▼
Protection Disabled/Incorrect
       │
       ▼
Potential FTP Bounce
```

Therefore, the vulnerability is often associated with **misconfiguration of the FTP service** rather than the mere existence of FTP.

---

# 36. 🔥 Important Distinction

Remember:

```text
FTP exists
      ≠
FTP is vulnerable
```

For example:

```text
FTP + Anonymous Access
      ↓
Possible Misconfiguration
```

and:

```text
FTP + Writable Sensitive Directory
      ↓
Potentially Dangerous Configuration
```

and:

```text
FTP + Bounce Protections Misconfigured
      ↓
Potential FTP Bounce
```

The actual risk depends on the service configuration and version.

---

# 37. 🧠 Complete FTP Assessment Flow

```text
                   FTP
                    │
                    ▼
             TCP/21 OPEN?
                    │
                    ▼
               Nmap -sC
                    +
               Nmap -sV
                    │
                    ▼
            Identify Banner
                    │
                    ▼
         Anonymous Authentication?
              ┌─────┴─────┐
             YES          NO
              │            │
              ▼            ▼
         Login as       Authorized
         anonymous      credential test
              │
              ▼
          Enumerate
              │
       ┌──────┼──────┐
       ▼      ▼      ▼
      ls     cd    help
       │
       ▼
   Readable?
       │
       ▼
   Download?
       │
       ▼
   Writable?
       │
       ▼
   Upload?
       │
       ▼
Sensitive Information?
       │
       ▼
Cross-service correlation
       │
       ▼
Further authorized testing
```

---

# 38. 🗂️ FTP Command Cheat Sheet

|Command|Purpose|
|---|---|
|`ftp <IP>`|Connect to FTP server|
|`ls`|List directory contents|
|`cd <dir>`|Change directory|
|`get <file>`|Download one file|
|`mget <files>`|Download multiple files|
|`put <file>`|Upload one file|
|`mput <files>`|Upload multiple files|
|`help`|Display FTP help|

---

# 39. 🔎 Nmap Cheat Sheet

### Basic FTP enumeration

```bash
nmap -sC -sV -p 21 <TARGET>
```

### Important scripts/features

```text
-sC
  ↓
Default scripts
  ↓
ftp-anon
  ↓
Check anonymous authentication
```

```text
-sV
  ↓
Service/version detection
  ↓
FTP banner
```

---

# 40. 🧠 What To Look For After FTP Access

Once authenticated:

### Authentication

```text
Anonymous?
Valid user?
```

### Directories

```text
pub/
incoming/
etc/
```

### Permissions

```text
Read?
Write?
Upload?
```

### Files

```text
Credentials?
Configs?
Backups?
Source code?
Documents?
```

### Service information

```text
Banner
Version
FTP implementation
```

---

# 41. 🚨 High-Value Findings

During an authorized assessment, these should immediately attract attention:

```text
⭐ Anonymous login
⭐ Writable directory
⭐ Sensitive readable files
⭐ Credentials
⭐ Configuration files
⭐ Source code
⭐ Backup files
⭐ Unexpected upload permissions
⭐ Old/vulnerable FTP software
⭐ FTP bounce capability
```

---

# 42. 🎯 Exam / Viva Questions

### Q1. What is FTP?

**FTP (File Transfer Protocol)** is a standard network protocol used to transfer files between computers and perform file/directory operations.

### Q2. What port does FTP use by default?

```text
TCP/21
```

### Q3. What does Nmap's `ftp-anon` script do?

It checks whether an FTP server allows **anonymous login**.

### Q4. Which Nmap option performs default script scanning?

```text
-sC
```

### Q5. Which Nmap option performs version detection?

```text
-sV
```

### Q6. What clients can interact with FTP?

The source mentions:

```text
ftp
nc
```

### Q7. What username is commonly used for anonymous FTP?

```text
anonymous
```

### Q8. What command lists FTP files?

```text
ls
```

### Q9. What command changes directory?

```text
cd
```

### Q10. What command downloads one file?

```text
get
```

### Q11. What downloads multiple files?

```text
mget
```

### Q12. What uploads one file?

```text
put
```

### Q13. What uploads multiple files?

```text
mput
```

### Q14. What is an FTP Bounce Attack?

A network attack where an FTP server is abused to send outbound traffic toward another device, potentially allowing an attacker to interact with or scan an otherwise inaccessible target.

### Q15. Which Nmap option is used for FTP bounce?

```text
-b
```

### Q16. Why is anonymous FTP dangerous?

Because improperly configured read/write permissions may allow unauthenticated users to access sensitive files or upload potentially dangerous content.

### Q17. What are four ways FTP can be attacked according to the source?

```text
Misconfiguration
Excessive privileges
Known vulnerabilities
Newly discovered vulnerabilities
```

---

# 43. ⭐ Must-Memorize Concepts

## FTP Basics

```text
FTP
↓
File Transfer Protocol
↓
TCP/21
```

## Enumeration

```text
-sC → Default scripts
-sV → Version detection
ftp-anon → Anonymous login check
```

## FTP Commands

```text
ls    → List
cd    → Change directory
get   → Download one
mget  → Download multiple
put   → Upload one
mput  → Upload multiple
help  → Help
```

## Authentication

```text
anonymous
```

## Brute Force Tool

```text
Medusa
```

Important options:

```text
-u → username
-U → username list
-P → password list
-M → module
-h → target host
```

## FTP Bounce

```text
-b
```

---

# 🔥 44. The Most Important Attack Chains

### Chain 1 — Anonymous FTP

```text
TCP/21
   ↓
FTP
   ↓
Anonymous Login
   ↓
Directory Enumeration
   ↓
Sensitive Files
   ↓
Information Disclosure
```

### Chain 2 — Writable FTP

```text
FTP
 ↓
Anonymous/User Access
 ↓
Writable Directory
 ↓
Upload Capability
 ↓
Potentially Dangerous File
 ↓
Further Authorized Testing
```

### Chain 3 — Credential Discovery

```text
FTP
 ↓
Sensitive File
 ↓
Credentials
 ↓
Another Service
 ↓
Further Access
```

### Chain 4 — FTP Bounce

```text
Attacker
   ↓
FTP Server
   ↓
FTP Bounce
   ↓
Internal Target
   ↓
Port/Service Discovery
   ↓
Further Authorized Assessment
```

---

# 🧠 45. Final Revision — One Page

```text
                     ATTACKING FTP
                           │
                           ▼
                     TCP/21 OPEN
                           │
                           ▼
                     NMAP ENUM
                    /           \
                  -sC           -sV
                   │             │
                   ▼             ▼
              ftp-anon        Banner/
              Anonymous       Version
                   │
                   ▼
           Anonymous Login?
              /         \
            YES          NO
             │            │
             ▼            ▼
        Enumerate      Authorized
          Files       Credential Test
             │
             ▼
        ls / cd / help
             │
       ┌─────┴─────┐
       ▼           ▼
    Download     Upload
     get/mget    put/mput
       │           │
       └─────┬─────┘
             ▼
    Sensitive Information?
             │
             ▼
       Correlate Findings
             │
             ▼
      Further Assessment
```

### ⭐ Remember these five things:

**1. FTP normally listens on `TCP/21`.**

**2. `-sC` includes `ftp-anon`, which checks anonymous FTP access.**

**3. `-sV` helps identify the FTP service/version and banner.**

**4. Anonymous access + incorrect permissions can expose sensitive information or allow uploads.**

**5. FTP Bounce abuses a misconfigured FTP server as an intermediary for traffic toward another system.**

And the biggest mindset point:

> **Getting FTP access is only the beginning. Enumerate the directories, understand the permissions, examine the available files, and correlate anything interesting with the rest of the target environment.**