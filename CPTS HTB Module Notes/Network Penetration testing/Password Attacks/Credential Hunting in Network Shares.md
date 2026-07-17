# What is Credential Hunting in Network Shares?

Most organizations use **network shares (SMB shares)** to store and exchange files between employees, departments, and servers.

These shared folders often contain:

- Configuration files
    
- Password files
    
- Deployment scripts
    
- Backups
    
- Database credentials
    
- SSH keys
    
- API tokens
    

If administrators accidentally leave sensitive information inside these shares, attackers may be able to recover it.

---

# Why Network Shares Matter

Network shares are one of the richest sources of credentials during an internal penetration test.

```text
             Active Directory
                    │
                    ▼
             Domain Controller
                    │
      ┌─────────────┼─────────────┐
      │             │             │
      ▼             ▼             ▼
      IT         Finance         HR
      │             │             │
      └─────────────┼─────────────┘
                    │
                    ▼
               SMB Network Shares
                    │
                    ▼
        Credentials • Scripts • Configs
```

---

# Why Do Credentials End Up in Shares?

Administrators commonly store:

✔ Deployment scripts

✔ Configuration files

✔ Password spreadsheets

✔ Automation scripts

✔ Backup files

✔ Documentation

Sometimes these files unintentionally expose sensitive credentials.

---

# Credential Hunting Workflow

```text
Compromise Domain User
        │
        ▼
Enumerate SMB Shares
        │
        ▼
Access Readable Shares
        │
        ▼
Search Interesting Files
        │
        ▼
Recover Credentials
        │
        ▼
Privilege Escalation
        │
        ▼
Lateral Movement
```

---

# What Should We Search For?

Searching every file manually is inefficient.

Instead, search for **patterns**.

---

## Important Keywords

```text
password

passw

user

username

token

secret

key

credential

cred

config

initial
```

These frequently appear inside configuration files and scripts.

---

# File Extensions Worth Hunting

Certain file types often contain credentials.

```text
.ini

.cfg

.env

.xlsx

.ps1

.bat
```

Also pay attention to:

- XML files
    
- YAML files
    
- PowerShell scripts
    
- Batch scripts
    
- Environment files
    

---

# Interesting File Names

File names often reveal valuable information.

Examples

```text
config.ini

passwords.xlsx

credentials.txt

users.xlsx

initial_setup.ps1

database.env

backup.cfg
```

---

# Domain-Specific Searches

Suppose the target domain is

```text
INLANEFREIGHT.LOCAL
```

Searching for

```text
INLANEFREIGHT\
```

may reveal

- Domain usernames
    
- Service accounts
    
- Administrator accounts
    
- UNC paths
    

---

# Localization Matters

Always search using the target organization's language.

Example

|English|German|
|---|---|
|User|Benutzer|
|Password|Passwort|
|Secret|Geheim|
|Credential|Zugangsdaten|

Searching with localized terms often produces better results.

---

# Prioritize High-Value Shares

Not every share is equally valuable.

```text
Company Photos
      │
      ▼
Low Value

---------------------

IT Share
Finance Share
Deployment Share
Backup Share
SYSVOL

      │
      ▼
High Value
```

---

# Basic Command-Line Search (Windows)

A quick way to search a network share is to use **PowerShell**.

Example pattern:

```powershell
Get-ChildItem -Recurse -Include *.ext \\Server\Share |
Select-String -Pattern "password"
```

This recursively searches files for the specified keyword.

---

# Hunting from Windows

Several tools automate SMB share discovery and credential hunting.

The HTB module highlights:

- Snaffler
    
- PowerHuntShares
    

---

# Snaffler

Snaffler is a **C# tool** that automatically:

✔ Enumerates Active Directory

✔ Finds accessible SMB shares

✔ Searches for interesting files

✔ Highlights potential credentials

---

# Snaffler Workflow

```text
Domain User
      │
      ▼
Active Directory
      │
      ▼
Find SMB Shares
      │
      ▼
Download Interesting Files
      │
      ▼
Credential Discovery
```

---

# Running Snaffler

Basic scan

```cmd
Snaffler.exe -s
```

This performs:

- Domain discovery
    
- DFS discovery
    
- SMB share enumeration
    
- File scanning
    

---

# Example Output

The scan may discover shares such as

```text
ADMIN$

C$

Company

Finance

HR

IT

Marketing

NETLOGON

Sales

SYSVOL
```

These are all potential credential hunting targets.

---

# Interesting Discovery

One example from the module

```text
Windows\Panther\unattend.xml
```

contained

```xml
<AdministratorPassword>
********
</AdministratorPassword>
```

This demonstrates why deployment files should always be inspected.

---

# Understanding Share Colors

Snaffler marks findings with colors.

|Color|Meaning|
|---|---|
|Green|Accessible Share|
|Yellow|Interesting File|
|Red|High-Value / Credential Match|

---

# Useful Snaffler Options

## User Enumeration

```text
-u
```

Retrieves Active Directory users and searches for references.

---

## Include Shares

```text
-i
```

Specify which shares to scan.

---

## Exclude Shares

```text
-n
```

Ignore specific shares.

---

# Why Use Filters?

Large domains may contain

```text
Thousands of Shares

↓

Millions of Files
```

Scanning everything wastes time.

Focus on

- IT
    
- Finance
    
- Development
    
- Backups
    
- SYSVOL
    

---

# PowerHuntShares

PowerHuntShares is a PowerShell-based SMB hunting tool.

Unlike Snaffler,

it generates an **HTML report**.

---

# What Does PowerHuntShares Do?

✔ Discovers computers

✔ Enumerates SMB shares

✔ Finds permissions

✔ Finds readable shares

✔ Finds writable shares

✔ Generates reports

---

# PowerHuntShares Workflow

```text
PowerShell
      │
      ▼
Domain Enumeration
      │
      ▼
SMB Shares
      │
      ▼
Permissions
      │
      ▼
Interesting Files
      │
      ▼
HTML Report
```

---

# Run PowerHuntShares

```powershell
Invoke-HuntSMBShares -Threads 100 -OutputDirectory C:\Users\Public
```

---

# Output

The report typically includes

- Critical Findings
    
- Sensitive Files
    
- Secrets
    
- Share Permissions
    
- Timeline Analysis
    

---

# Hunting from Linux

If you don't have a domain-joined Windows system,

Linux tools can search SMB shares remotely.

The HTB module discusses:

- MANSPIDER
    
- NetExec
    

---

# MANSPIDER

MANSPIDER is designed for remote SMB searching.

Recommended execution

```text
Docker Container
```

to avoid dependency issues.

---

# MANSPIDER Workflow

```text
Linux Host
      │
      ▼
Authenticate SMB
      │
      ▼
Read Shares
      │
      ▼
Search Keyword
      │
      ▼
Download Matches
```

---

# Running MANSPIDER

```bash
docker run --rm \
-v ./manspider:/root/.manspider \
blacklanternsecurity/manspider \
10.129.234.121 \
-c 'passw' \
-u 'mendres' \
-p 'Inlanefreight2025!'
```

---

# Important Parameters

|Parameter|Purpose|
|---|---|
|-c|Content to search|
|-u|Username|
|-p|Password|

---

# Example Output

MANSPIDER reports

```text
Successful Login

Searching by file content:

passw

Matching files downloaded
```

Downloaded files are stored locally for review.

---

# NetExec

NetExec is another powerful SMB enumeration framework.

It also supports **credential hunting**.

---

# NetExec Workflow

```text
Authenticate
      │
      ▼
SMB Share
      │
      ▼
Spider Files
      │
      ▼
Pattern Matching
      │
      ▼
Credential Discovery
```

---

# Running NetExec Spider

```bash
nxc smb 10.129.234.121 \
-u mendres \
-p 'Inlanefreight2025!' \
--spider IT \
--content \
--pattern "passw"
```

---

# Important Parameters

|Parameter|Purpose|
|---|---|
|--spider|Share to search|
|--content|Search file contents|
|--pattern|Search keyword|

---

# Manual Review is Important

All automated tools produce

```text
Many Results
      │
      ▼
False Positives
      │
      ▼
Manual Verification
```

Always verify findings before assuming they contain credentials.

---

# Tool Comparison

|Tool|Platform|Purpose|
|---|---|---|
|Snaffler|Windows|AD-aware SMB hunting|
|PowerHuntShares|Windows|SMB enumeration + HTML reports|
|MANSPIDER|Linux|Remote SMB searching|
|NetExec|Linux|SMB enumeration & spidering|

---

# Attack Workflow

```text
Gain Domain Credentials
        │
        ▼
Enumerate SMB Shares
        │
        ▼
Choose High-Value Shares
        │
        ▼
Search Keywords
        │
        ▼
Download Interesting Files
        │
        ▼
Review Results
        │
        ▼
Recover Credentials
        │
        ▼
Privilege Escalation
        │
        ▼
Lateral Movement
```

---

# Important Commands

### Snaffler

```cmd
Snaffler.exe -s
```

---

### Search AD Users

```text
-u
```

---

### Include Shares

```text
-i
```

---

### Exclude Shares

```text
-n
```

---

### PowerHuntShares

```powershell
Invoke-HuntSMBShares -Threads 100 -OutputDirectory C:\Users\Public
```

---

### MANSPIDER

```bash
docker run --rm \
-v ./manspider:/root/.manspider \
blacklanternsecurity/manspider \
TARGET \
-c "passw" \
-u USER \
-p PASSWORD
```

---

### NetExec Spider

```bash
nxc smb TARGET \
-u USER \
-p PASSWORD \
--spider SHARE \
--content \
--pattern "passw"
```

---

# High-Value Files

```text
unattend.xml

web.config

config.ini

database.env

passwords.xlsx

backup.ps1

deploy.bat

KeePass Database

SSH Keys
```

---

# Memory Tricks

### Search Formula

```text
SMB Share

↓

Interesting Files

↓

Keywords

↓

Credentials
```

---

### High-Value Departments

```text
IT

Finance

Development

Backups

SYSVOL

↓

Highest Chance of Credentials
```

---

### Tool Order

```text
Windows

↓

Snaffler

↓

PowerHuntShares

------------------

Linux

↓

MANSPIDER

↓

NetExec
```

---

# HTB / Exam Questions

### Which Windows tool automatically discovers SMB shares and searches for interesting files?

✅ **Snaffler**

---

### Which Snaffler option searches for Active Directory user references?

```text
-u
```

---

### Which options specify shares to include or exclude?

```text
-i

-n
```

---

### Which PowerShell tool generates an HTML report after SMB enumeration?

✅ **PowerHuntShares**

---

### Which Linux tool is recommended to run in Docker for SMB credential hunting?

✅ **MANSPIDER**

---

### Which NetExec option searches inside file contents?

```text
--content
```

---

### Which option specifies the search keyword in NetExec?

```text
--pattern
```

---

### Which directories are generally the most valuable during credential hunting?

✅ **IT, Finance, SYSVOL, NETLOGON, Development, Backup shares**

---

# 🔥 1-Minute Revision Sheet

```text
Credential Hunting in SMB Shares

            │
            ▼
Network Shares
            │
            ▼
Interesting Files
            │
            ▼
Credentials

Search Keywords
───────────────
password
passw
token
secret
key
config
cred

Interesting Extensions
──────────────────────
.ini
.cfg
.env
.xlsx
.ps1
.bat

Windows Tools
─────────────
Snaffler
PowerHuntShares

Linux Tools
───────────
MANSPIDER
NetExec

High-Value Shares
─────────────────
IT
Finance
SYSVOL
NETLOGON
Backups
Development

Goal
────
Recover Credentials
→ Privilege Escalation
→ Lateral Movement
```

These notes preserve the important concepts, commands, options, keywords, tools, and workflows from your uploaded HTB material while expanding them with diagrams ("pics"), comparisons, memory tricks, and HTB/exam-focused summaries.