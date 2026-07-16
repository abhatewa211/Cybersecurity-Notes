# What is Credential Hunting?

Credential Hunting is the process of **searching a compromised Linux system for usernames, passwords, SSH keys, API keys, tokens, configuration secrets, browser credentials, and authentication data** that can be used for:

- Privilege Escalation
    
- Lateral Movement
    
- Accessing Databases
    
- Accessing Cloud Resources
    
- SSH Authentication
    
- Service Authentication
    

Unlike password cracking, credential hunting focuses on **finding credentials that already exist on the system**.

---

# Why Perform Credential Hunting?

Once you've obtained a shell (e.g., via a vulnerable web application or SSH), there may already be sensitive credentials stored on the system.

```text
        Initial Access
              │
              ▼
      Linux Reverse Shell
              │
              ▼
     Credential Hunting
              │
 ┌────────────┼────────────┐
 │            │            │
 ▼            ▼            ▼
 Passwords   SSH Keys   Config Files
              │
              ▼
     Privilege Escalation
              │
              ▼
      Lateral Movement
```

---

# Credential Sources

Linux credentials generally fall into **four major categories**.

```text
                Credentials
                     │
     ┌───────────────┼────────────────┐
     │               │                │
     ▼               ▼                ▼
    Files         History        Memory/Cache
                     │
                     ▼
                 Keyrings
```

---

## 1. Files

The most common source.

Linux follows the philosophy:

> **Everything is a file.**

Potential files include:

- Configuration Files
    
- Databases
    
- Notes
    
- Scripts
    
- Cronjobs
    
- SSH Keys
    

---

## 2. History

History files reveal

- Commands executed
    
- Passwords typed
    
- Administrative activity
    

Examples

```text
.bash_history
.bashrc
.bash_profile
```

---

## 3. Memory

Credentials currently in use may still reside in memory.

Examples

- User passwords
    
- Browser credentials
    
- Session tokens
    

---

## 4. Keyrings

Linux password managers.

Examples

- GNOME Keyring
    
- KWallet
    
- Libsecret
    

---

# Credential Hunting Workflow

```text
Compromise Linux Host
        │
        ▼
Enumerate Files
        │
        ▼
Search Configs
        │
        ▼
Search Scripts
        │
        ▼
Search History
        │
        ▼
Search Logs
        │
        ▼
Search Memory
        │
        ▼
Browser Credentials
        │
        ▼
Recovered Passwords
```

---

# Configuration Files

Configuration files frequently contain

✔ Database Passwords

✔ API Keys

✔ Service Credentials

✔ Backup Credentials

✔ LDAP Credentials

✔ SMTP Passwords

---

## Common Extensions

```text
.conf

.config

.cnf
```

---

# Search Configuration Files

```bash
for l in $(echo ".conf .config .cnf");do
echo -e "\nFile extension: "$l;
find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core";
done
```

---

## Search Workflow

```text
Find Config Files
        │
        ▼
Inspect Contents
        │
        ▼
Look for:
user
password
pass
login
```

---

# Search for Passwords Inside Configs

```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do
echo -e "\nFile: "$i;
grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";
done
```

---

# Configuration File Diagram

```text
Application
      │
      ▼
Configuration File
      │
      ▼
Username
Password
Database
API Keys
```

---

# Database Files

Applications often store databases locally.

Interesting extensions

```text
.sql

.db

.*db

.db*
```

---

# Search Databases

```bash
for l in $(echo ".sql .db .*db .db*");do
echo -e "\nDB File extension: "$l;
find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";
done
```

---

# Why Search Databases?

Databases may contain

- Credentials
    
- Password hashes
    
- Tokens
    
- Session IDs
    

---

# Notes

Administrators often leave notes.

Examples

```text
passwords.txt

notes.txt

todo.txt

servers.txt
```

Search

```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

---

# Scripts

Scripts often automate administrative tasks.

Automation usually requires

✔ Passwords

✔ Tokens

✔ SSH Keys

✔ Database Credentials

---

## Common Script Extensions

```text
.sh

.py

.pl

.jar

.go

.c
```

---

## Search Scripts

```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do
echo -e "\nFile extension: "$l;
find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";
done
```

---

# Script Diagram

```text
Backup Script
      │
      ▼
Database Password
      │
      ▼
Privilege Escalation
```

---

# Cronjobs

Cronjobs execute tasks automatically.

Sometimes administrators embed credentials directly inside scripts.

---

## Cron Locations

```text
/etc/crontab

/etc/cron.daily

/etc/cron.hourly

/etc/cron.weekly

/etc/cron.monthly

/etc/cron.d
```

---

## Enumerate Cronjobs

```bash
cat /etc/crontab
```

```bash
ls -la /etc/cron.*/
```

---

# Cronjob Workflow

```text
Cron
 │
 ▼
Runs Script
 │
 ▼
Script Contains Password
 │
 ▼
Credential Found
```

---

# History Files

History files frequently expose

- Commands
    
- Passwords
    
- Secrets
    
- Scripts
    

Important files

```text
.bash_history

.bashrc

.bash_profile
```

---

## Example

```bash
tail -n5 /home/*/.bash*
```

Example Output

```text
su

/tmp/api.py cry0l1t3 6mX4UP1eWH3HXK
```

This immediately reveals a plaintext password passed as a command-line argument.

---

# History Diagram

```text
User Commands
       │
       ▼
.bash_history
       │
       ▼
Passwords
API Keys
Secrets
```

---

# Log Files

Linux stores almost everything inside logs.

Categories

- Application Logs
    
- Event Logs
    
- Service Logs
    
- System Logs
    

---

# Important Logs

|Log|Purpose|
|---|---|
|/var/log/messages|General activity|
|/var/log/syslog|System logs|
|/var/log/auth.log|Authentication|
|/var/log/secure|Authentication (RHEL)|
|/var/log/boot.log|Boot events|
|/var/log/kern.log|Kernel|
|/var/log/faillog|Failed logins|
|/var/log/cron|Cron jobs|
|/var/log/httpd|Apache|
|/var/log/mysqld.log|MySQL|

---

# Search Logs

```bash
for i in $(ls /var/log/* 2>/dev/null);do
grep "accepted\|failed\|sudo\|COMMAND=\|password changed" $i 2>/dev/null;
done
```

---

# Log Hunting Diagram

```text
Logs
 │
 ▼
Authentication
 │
 ▼
Accepted Login
Failed Login
sudo
Password Change
```

---

# Memory Hunting

Some applications keep credentials in RAM.

Examples

- SSH
    
- Browser Sessions
    
- GNOME Login
    
- Desktop Sessions
    

---

# Mimipenguin

Tool

```text
mimipenguin
```

Purpose

Extract credentials from Linux memory.

Requires

✔ Root privileges

---

## Command

```bash
sudo python3 mimipenguin.py
```

Example

```text
cry0l1t3

↓

Password

↓

WLpAEXFa0SbqOHY
```

---

# Memory Diagram

```text
Running Process
        │
        ▼
Memory
        │
        ▼
Mimipenguin
        │
        ▼
Recovered Password
```

---

# LaZagne

LaZagne also supports Linux.

Supports

- WiFi
    
- SSH
    
- Git
    
- AWS
    
- Docker
    
- Firefox
    
- Chromium
    
- Thunderbird
    
- Keepass
    
- Shadow
    
- Sessions
    
- Keyrings
    

---

# Run LaZagne

```bash
sudo python2.7 laZagne.py all
```

Example

```text
Login:
cry0l1t3

Password:
WLpAEXFa0SbqOHY
```

---

# LaZagne Workflow

```text
LaZagne
     │
 ┌───┼────────────────────┐
 │   │                    │
 ▼   ▼                    ▼
SSH Browser          Keyrings
 │
 ▼
Recovered Passwords
```

---

# Browser Credentials

Browsers save passwords locally.

Examples

- Firefox
    
- Chromium
    
- Chrome
    

---

# Firefox Credential Storage

Firefox stores credentials in

```text
logins.json
```

Profile location

```bash
.mozilla/firefox/
```

---

## Example

```bash
cat .mozilla/firefox/PROFILE/logins.json | jq .
```

Contains

```text
Hostname

Encrypted Username

Encrypted Password
```

---

# Firefox Storage Diagram

```text
Firefox
     │
     ▼
logins.json
     │
     ▼
Encrypted Credentials
```

---

# Firefox Decrypt

Tool

```text
firefox_decrypt.py
```

Purpose

Decrypt Firefox credentials.

Run

```bash
python3.9 firefox_decrypt.py
```

Example

```text
Website:
https://www.inlanefreight.com

Username:
cry0l1t3

Password:
FzXUxJemKm6g2lGh
```

---

# Browser Hunting with LaZagne

```bash
python3 laZagne.py browsers
```

Output

```text
URL:
https://www.inlanefreight.com

Login:
cry0l1t3

Password:
FzXUxJemKm6g2lGh
```

---

# Browser Workflow

```text
Browser
     │
     ▼
Saved Password
     │
     ▼
Encrypted
     │
     ▼
Firefox Decrypt
or
LaZagne
     │
     ▼
Recovered Password
```

---

# Credential Hunting Checklist

```text
✓ Configuration Files
✓ Databases
✓ Notes
✓ Scripts
✓ Cronjobs
✓ SSH Keys
✓ History Files
✓ Log Files
✓ Browser Passwords
✓ Memory
✓ Keyrings
✓ Environment Variables
✓ AWS Credentials
✓ Docker Secrets
```

---

# Important Commands

### Find Config Files

```bash
find / -name "*.conf" 2>/dev/null
```

---

### Search Passwords

```bash
grep "user\|password\|pass"
```

---

### Search Notes

```bash
find /home/* -type f -name "*.txt"
```

---

### View Cronjobs

```bash
cat /etc/crontab
```

---

### List Cron Directories

```bash
ls -la /etc/cron.*/
```

---

### View History

```bash
tail -n5 /home/*/.bash*
```

---

### Run Mimipenguin

```bash
sudo python3 mimipenguin.py
```

---

### Run LaZagne

```bash
sudo python2.7 laZagne.py all
```

---

### Browser Credentials

```bash
python3.9 firefox_decrypt.py
```

---

### Browser Module

```bash
python3 laZagne.py browsers
```

---

# HTB / Exam Questions

### What are the four major credential sources in Linux?

✅ Files, History, Memory, Keyrings.

---

### Which configuration file extensions are commonly searched?

✅ `.conf`, `.config`, `.cnf`

---

### Which file stores Firefox saved passwords?

✅ `logins.json`

---

### Which tool decrypts Firefox credentials?

✅ `firefox_decrypt.py`

---

### Which tool extracts credentials from Linux memory?

✅ `mimipenguin`

---

### Which tool supports SSH, browsers, AWS, Docker, Keyrings, and Firefox?

✅ **LaZagne**

---

### Which cron file defines system-wide scheduled jobs?

✅ `/etc/crontab`

---

### Which history file often reveals commands and secrets?

✅ `.bash_history`

---

### Which log file records authentication events on Debian?

✅ `/var/log/auth.log`

---

# 🔥 1-Minute Revision Sheet

```text
Credential Hunting
        │
        ▼
Sources
───────
Files
History
Memory
Keyrings

Files
─────
Configs
Databases
Notes
Scripts
Cronjobs
SSH Keys

History
───────
.bash_history
.bashrc
.bash_profile

Logs
────
auth.log
syslog
messages
cron

Tools
─────
grep
find
Mimipenguin
LaZagne
firefox_decrypt.py

Firefox
────────
logins.json

Goal
────
Recover Credentials
→ Privilege Escalation
→ Lateral Movement
```

These notes preserve the important commands, paths, tools, and concepts from your uploaded HTB material while expanding them with diagrams, workflows, comparisons, memory tricks, and exam/interview-focused summaries.