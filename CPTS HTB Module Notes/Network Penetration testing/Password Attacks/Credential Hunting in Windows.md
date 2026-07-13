# What is Credential Hunting?

**Credential Hunting** is the process of searching a compromised Windows system for stored credentials, passwords, API keys, tokens, configuration secrets, and sensitive files that may provide access to additional systems or services.

Unlike password cracking, credential hunting focuses on **finding existing secrets** rather than breaking encrypted ones.

---

# Why Perform Credential Hunting?

Once you gain access to a Windows machine (GUI or CLI), there may already be valuable credentials stored on the system.

These credentials can help you:

- Escalate privileges
    
- Access other servers
    
- Move laterally through the network
    
- Access cloud services
    
- Connect to databases
    
- Access development environments
    

---

# Credential Hunting Workflow

```text
                Initial Access
                      │
                      ▼
        Compromised Windows Machine
                      │
      ┌───────────────┼────────────────┐
      │               │                │
      ▼               ▼                ▼
 Search Files    Search Apps      Search Memory
      │               │                │
      ▼               ▼                ▼
 Passwords     Browser Creds      LSASS Secrets
      │
      ▼
 Lateral Movement
```

---

# Example Scenario

Suppose you compromise

```text
IT Administrator Workstation
```

What might an IT admin store?

- Domain Admin credentials
    
- RDP passwords
    
- WinSCP credentials
    
- VPN credentials
    
- Database passwords
    
- SSH keys
    
- Scripts containing passwords
    
- Configuration files
    

Because IT admins manage infrastructure, their systems are often **rich sources of credentials**.

---

# Search-Centric Methodology

Modern Windows provides powerful search functionality.

Instead of randomly browsing directories,

search intelligently.

Think first:

```text
Who owns this computer?

↓

What applications do they use?

↓

Where would passwords be stored?
```

---

# Search Strategy

```text
Compromised System
        │
        ▼
Identify User Role
        │
        ▼
Administrator?
Developer?
Database Admin?
Help Desk?
        │
        ▼
Search Relevant Locations
        │
        ▼
Recover Credentials
```

---

# Common Keywords to Search

These keywords often appear in configuration files and documents.

```text
password
passphrase
key
keys
username
user account
creds
users
passkeys
configuration
dbcredential
dbpassword
pwd
login
credentials
```

---

# Memory Trick

```text
Think:

P K U C

P → Password

K → Keys

U → Username

C → Credentials
```

---

# Windows Search

If GUI access is available,

Windows Search is often the fastest place to begin.

Search for terms like

```text
password

pass

credential

config

vpn

key
```

Windows Search scans

- Files
    
- Documents
    
- Applications
    
- Settings
    

---

# Windows Search Workflow

```text
Windows Search
       │
       ▼
Keyword
       │
       ▼
Matching Files
       │
       ▼
Potential Credentials
```

---

# LaZagne

One of the most useful credential recovery tools.

```text
LaZagne
```

Purpose

Automatically extracts stored credentials from dozens of applications.

---

# Why LaZagne?

Instead of manually searching

```text
Browser

↓

Email Client

↓

WiFi

↓

VPN

↓

Credential Manager
```

LaZagne does it automatically.

---

# LaZagne Architecture

```text
                 LaZagne
                     │
 ┌───────────────────┼────────────────────┐
 │                   │                    │
 ▼                   ▼                    ▼
Browsers          Windows           SysAdmin Apps
 │                   │                    │
 ▼                   ▼                    ▼
Chrome          Credential       WinSCP
Firefox         Manager          OpenVPN
Edge            LSA Secrets      etc.
```

---

# LaZagne Modules

## Browsers

Extracts passwords from

- Chrome
    
- Firefox
    
- Microsoft Edge
    
- Opera
    

---

## Chats

Supports

- Skype
    

---

## Mail

Extracts credentials from

- Outlook
    
- Thunderbird
    

---

## Memory

Searches memory for

- KeePass
    
- LSASS
    

---

## SysAdmin

Extracts credentials from

- WinSCP
    
- OpenVPN
    
- Other administration tools
    

---

## Windows

Targets

- Credential Manager
    
- LSA Secrets
    
- Windows Credentials
    

---

## WiFi

Extracts

- Saved Wireless Passwords
    

---

# LaZagne Modules Summary

|Module|Targets|
|---|---|
|browsers|Chrome, Firefox, Edge|
|chats|Skype|
|mails|Outlook, Thunderbird|
|memory|KeePass, LSASS|
|sysadmin|WinSCP, OpenVPN|
|windows|Credential Manager, LSA|
|wifi|WiFi Passwords|

---

# Why Browsers Matter

Most users save passwords inside browsers.

Examples

```text
Google Chrome

Microsoft Edge

Firefox
```

Although credentials are encrypted,

many public tools can decrypt them.

Examples

```text
firefox_decrypt

decrypt-chrome-passwords

LaZagne
```

---

# Running LaZagne

Transfer

```text
LaZagne.exe
```

to the target.

Run

```cmd
start LaZagne.exe all
```

This executes every supported module.

---

# Verbose Mode

```cmd
start LaZagne.exe all -vv
```

The

```text
-vv
```

option displays detailed information about every module being executed.

---

# Example Output

```text
Winscp passwords

URL:
10.129.202.51

Login:
admin

Password:
SteveisReallyCool123
```

This demonstrates that LaZagne successfully recovered stored credentials.

---

# Credential Hunting Flow

```text
Transfer LaZagne
        │
        ▼
Run All Modules
        │
        ▼
Browsers
Windows
WiFi
Mail
WinSCP
VPN
        │
        ▼
Recovered Credentials
```

---

# findstr

Windows includes another useful built-in tool

```text
findstr
```

Purpose

Search for text patterns inside files.

---

# Example

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

---

# Command Breakdown

|Option|Meaning|
|---|---|
|/S|Search subdirectories|
|/I|Ignore case|
|/M|Print only matching filenames|
|/C|Search exact string|

---

# File Types Worth Searching

```text
.txt

.ini

.cfg

.config

.xml

.git

.ps1

.yml
```

These frequently contain

- Passwords
    
- Tokens
    
- API Keys
    
- Database Credentials
    

---

# findstr Workflow

```text
findstr
      │
      ▼
Search Files
      │
      ▼
Keyword Match
      │
      ▼
Interesting File
      │
      ▼
Extract Credentials
```

---

# Other Valuable Locations

Credential hunting is not limited to browsers.

Always inspect

---

## SYSVOL Share

May contain

- Group Policy Passwords
    
- Login Scripts
    
- Deployment Scripts
    

---

## IT Shares

Look for

```text
scripts

backup scripts

deployment scripts
```

These often contain plaintext passwords.

---

## web.config

Common on

- IIS Servers
    
- Development Machines
    

May contain

```xml
Database Password

Connection String

Service Account Password
```

---

## unattend.xml

Windows deployment file.

May contain

```text
Administrator Password
```

---

## Active Directory Description Fields

Administrators sometimes store

```text
VPN Password

Server Password

Temporary Credentials
```

inside AD descriptions.

---

## KeePass Databases

Extensions

```text
.kdb

.kdbx
```

If the master password is recovered,

every stored password becomes accessible.

---

## User Documents

Look for files such as

```text
pass.txt

passwords.docx

passwords.xlsx

credentials.txt

vpn.txt
```

These are surprisingly common.

---

# Credential Hunting Checklist

```text
✓ Browser Passwords

✓ WinSCP

✓ VPN

✓ Outlook

✓ WiFi

✓ Credential Manager

✓ KeePass

✓ Scripts

✓ Configuration Files

✓ XML Files

✓ Group Policy

✓ SYSVOL

✓ User Documents

✓ SharePoint
```

---

# Complete Credential Hunting Workflow

```text
Gain Access
      │
      ▼
Identify User
      │
      ▼
Search Keywords
      │
      ▼
Windows Search
      │
      ▼
findstr
      │
      ▼
LaZagne
      │
      ▼
Browser Passwords
VPN
WinSCP
Credential Manager
WiFi
      │
      ▼
Additional Credentials
      │
      ▼
Privilege Escalation
      │
      ▼
Lateral Movement
```

---

# Important Commands

### Run LaZagne

```cmd
start LaZagne.exe all
```

---

### Verbose Mode

```cmd
start LaZagne.exe all -vv
```

---

### Search Files

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

---

# Important File Locations

|Location|Why Important|
|---|---|
|Browser Profiles|Saved passwords|
|Credential Manager|Windows credentials|
|WinSCP Config|SSH passwords|
|OpenVPN Config|VPN credentials|
|SYSVOL|GPO passwords & scripts|
|web.config|Database credentials|
|unattend.xml|Deployment passwords|
|KeePass|Password database|
|User Documents|Password files|

---

# Browser Credential Storage

```text
Chrome
    │
    ▼
Encrypted Password DB
    │
    ▼
LaZagne
    │
    ▼
Recovered Passwords
```

---

# Memory Tricks

### Think Like the User

```text
Who uses this PC?

↓

What applications do they use?

↓

Where are passwords likely stored?
```

---

### Search Formula

```text
Keyword

↓

findstr

↓

Interesting File

↓

Credential
```

---

### LaZagne Formula

```text
LaZagne

↓

All Modules

↓

Browsers

↓

WiFi

↓

Windows

↓

Mail

↓

VPN

↓

Passwords
```

---

# HTB / Exam Questions

### What is Credential Hunting?

✅ Searching a compromised system for stored credentials.

---

### Which built-in Windows feature can quickly locate password files?

✅ **Windows Search**

---

### Which tool extracts credentials from browsers, WiFi, WinSCP, Credential Manager, Outlook, and more?

✅ **LaZagne**

---

### Which LaZagne module targets WinSCP and OpenVPN?

✅ **sysadmin**

---

### Which module extracts browser passwords?

✅ **browsers**

---

### Which module extracts WiFi passwords?

✅ **wifi**

---

### Which Windows command searches text files for keywords?

```cmd
findstr
```

---

### Which file commonly stores IIS database credentials?

✅ **web.config**

---

### Which deployment file may contain Administrator credentials?

✅ **unattend.xml**

---

### Which password manager database should always be searched?

✅ **KeePass (.kdb/.kdbx)**

---

# 🔥 1-Minute Revision Sheet

```text
Credential Hunting
        │
        ▼
Search for:
✔ Passwords
✔ Keys
✔ Tokens
✔ Credentials

Keywords
────────
password
pwd
login
dbpassword
configuration

Tools
─────
Windows Search
LaZagne
findstr

LaZagne Modules
───────────────
Browsers
Windows
WiFi
Mail
Memory
SysAdmin

Interesting Files
─────────────────
web.config
unattend.xml
KeePass
Scripts
SYSVOL
passwords.txt
passwords.xlsx

Goal
────
Recover Credentials
→ Privilege Escalation
→ Lateral Movement
```

These notes preserve the important commands and concepts from your uploaded material while expanding them with detailed explanations, diagrams ("pics"), workflows, comparisons, memory tricks, and HTB/interview-oriented summaries.