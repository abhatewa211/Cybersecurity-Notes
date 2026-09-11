# 🐧  — Detailed Notes


The **root account** on Linux systems provides **full administrative-level access** to the operating system. During an assessment, you may initially obtain a **low-privileged shell** and need to perform privilege escalation to reach the root account.

### 🎯 Basic concept

```text
Low-Privileged User
        │
        ▼
   ENUMERATION
        │
        ▼
Find Misconfigurations
        │
        ├── Sudo
        ├── Cron Jobs
        ├── SUID/SGID
        ├── Writable Files
        ├── Vulnerable Services
        ├── Credentials
        └── Vulnerable Software
        │
        ▼
Potential Privilege Escalation
        │
        ▼
       ROOT
```

### Why is root access important?

Full compromise of a Linux host can provide access to:

- Sensitive files
    
- System information
    
- Network traffic
    
- Credentials
    
- Other systems within the environment
    

If the Linux machine is **domain joined**, the source notes that an **NTLM hash** may potentially be obtained and used as a starting point for further Active Directory enumeration and attacks.

---

# 🔎 2. Enumeration

> ⭐ **Enumeration is the key to privilege escalation.**

There are helper scripts such as **LinEnum** that can assist with enumeration. However, it is important to understand **what information you are looking for** and to be able to perform enumeration manually.

When you first obtain shell access, systematically investigate the machine.

### Main enumeration areas

|Area|What you're looking for|
|---|---|
|🐧 OS Version|Distribution and version|
|⚙️ Kernel|Kernel version and vulnerabilities|
|🔧 Services|Services running as root|
|📦 Packages|Outdated/vulnerable software|
|👤 Users|Logged-in users|
|🏠 Home directories|Keys, configs, credentials|
|📜 Bash history|Commands and potentially sensitive information|
|🛡️ Sudo|Commands allowed as root|
|⚙️ Configuration|Passwords and secrets|
|🔐 Shadow/passwd|Password hashes|
|⏰ Cron|Scheduled tasks|
|💽 File systems|Additional/unmounted drives|
|⚡ SUID/SGID|Elevated binaries|
|✍️ Writable files|Files/scripts you can modify|

---

# 🐧 3. OS Version

Knowing the Linux distribution is important.

Examples mentioned in the source:

- Ubuntu
    
- Debian
    
- FreeBSD
    
- Fedora
    
- SUSE
    
- Red Hat
    
- CentOS
    

The OS version can tell you:

1. What tools may be available.
    
2. What software versions may be installed.
    
3. Whether known public exploits may exist for that particular version.
    

### 🧠 Remember

**OS Version → Identify platform → Research known vulnerabilities**

---

# ⚙️ 4. Kernel Version

The **kernel** is another important enumeration target.

A vulnerability may exist in a particular kernel version, potentially allowing privilege escalation.

### ⚠️ Important warning

Kernel exploits can:

- Cause system instability
    
- Crash the system
    
- Potentially affect production systems
    

Therefore, the source emphasizes that you should **fully understand an exploit and its ramifications before running it**, especially on production systems.

```text
Kernel Version
      │
      ▼
Known Vulnerability?
      │
   ┌──┴──┐
  YES    NO
   │      │
Research  Continue
carefully enumeration
```

---

# 🔧 5. Running Services

You should enumerate services running on the system, especially services running as **root**.

### Why?

A vulnerable or incorrectly configured service running with root privileges can potentially become a privilege-escalation path.

The source gives examples of services that have had vulnerabilities:

- Nagios
    
- Exim
    
- Samba
    
- ProFTPd
    

It also mentions **CVE-2016-9566**, a local privilege-escalation vulnerability in Nagios Core versions below 4.2.4.

### 🔍 Important idea

```text
Service
   │
   ├── Running as normal user → lower impact
   │
   └── Running as ROOT
             │
             ▼
     Vulnerable/Misconfigured?
             │
             ▼
       Possible LPE path
```

---

## List Current Processes

The source demonstrates:

```bash
ps aux | grep root
```

Example:

```text
root         1  1.3  0.1  37656  5664 ?        Ss   23:26   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    23:26   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    23:26   0:00 [ksoftirqd/0]
root         4  0.0  0.0      0     0 ?        S    23:26   0:00 [kworker/0:0]
```

### What to pay attention to

- Which processes run as `root`
    
- What programs are running
    
- Whether unusual services/processes are present
    
- Whether those programs are vulnerable or misconfigured
    

---

# 📦 6. Installed Packages & Versions

Just like running services, installed software should be checked for:

- Outdated versions
    
- Vulnerable versions
    
- Known privilege-escalation vulnerabilities
    

### Example: Screen

**Screen** is a terminal multiplexer, similar to `tmux`.

It allows users to maintain multiple windows or virtual terminals within a session.

The source specifically mentions **Screen 4.05.00** as having a privilege-escalation vulnerability that can potentially be leveraged for escalation.

### 🧠 Key point

```text
Installed Package
       ↓
Version
       ↓
Is it outdated/vulnerable?
       ↓
Potential attack path
```

---

# 👥 7. Logged-in Users

You should identify which other users are currently logged into the system.

Why?

Their activity may reveal:

- Other accounts
    
- Running processes
    
- Local lateral movement possibilities
    
- Potential privilege-escalation paths
    

---

## List Current Terminal-Attached Processes

Command from the source:

```bash
ps au
```

Example:

```text
USER            PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root            1256  0.0  0.1  65832  3364 tty1     Ss   23:26   0:00 /bin/login --
cliff.moore     1322  0.0  0.1  22600  5160 tty1     S    23:26   0:00 -bash
shared          1367  0.0  0.1  22568  5116 pts/0    Ss   23:27   0:00 -bash
root            1384  0.0  0.1  52700  3812 tty1     S    23:29   0:00 sudo su
root            1385  0.0  0.0  52284  3448 tty1     S    23:29   0:00 su
root            1386  0.0  0.0  21224  3764 tty1     S+   23:29   0:00 bash
```

### ⭐ Notice

The output shows multiple users and also a root shell:

```text
root → sudo su → su → bash
```

This can reveal useful information about how privileged sessions are being used.

---

# 🏠 8. User Home Directories

Check whether other users' home directories are accessible.

Home directories may contain:

🔑 SSH keys  
📜 Scripts  
⚙️ Configuration files  
🔐 Credentials  
📖 `.bash_history`

The source notes that credentials found here may potentially provide access to other systems or even an Active Directory environment.

---

## List Home Directories

```bash
ls /home
```

Example:

```text
backupsvc
bob.jones
cliff.moore
logger
mrb3n
shared
stacey.jenkins
```

---

## Inspect Individual User Directories

Example:

```bash
ls -la /home/stacey.jenkins/
```

Output includes:

```text
.bash_history
.bash_logout
.bashrc
config.json
.profile
.ssh
```

### 🚨 Interesting files

|File|Why it may matter|
|---|---|
|`.bash_history`|Previous commands|
|`.ssh/`|SSH keys/configuration|
|`.bashrc`|Shell configuration|
|`config.json`|May contain configuration/secrets|
|`.profile`|Shell environment/configuration|

---

# 🔑 9. SSH Keys

SSH keys can be particularly valuable during an assessment.

If an SSH key belonging to the current user is discovered, it could potentially provide:

- A stable SSH session
    
- A fully interactive shell
    
- Access to another system
    

The source also recommends checking the **ARP cache** to identify hosts being accessed and comparing those hosts against usable SSH private keys.

### Example

```bash
ls -l ~/.ssh
```

Output:

```text
-rw------- 1 mrb3n mrb3n 1679 Aug 30 23:37 id_rsa
-rw-r--r-- 1 mrb3n mrb3n  393 Aug 30 23:37 id_rsa.pub
```

### 🧠 Remember

```text
SSH Private Key
      ↓
Who owns it?
      ↓
What systems might use it?
      ↓
Could it provide another legitimate access path?
```

---

# 📜 10. Bash History

Bash history can provide considerable insight into what a user has been doing.

The source specifically mentions looking for:

- Passwords passed as command-line arguments
    
- Git repositories
    
- Cron jobs
    
- Commands related to system administration
    
- Other activity that may reveal privilege-escalation paths
    

### Example

```bash
history
```

Source example:

```text
1  id
2  cd /home/cliff.moore
3  exit
4  touch backup.sh
5  tail /var/log/apache2/error.log
6  ssh ec2-user@dmz02.inlanefreight.local
7  history
```

### 🔥 What can history reveal?

```text
Bash History
    │
    ├── Previous commands
    ├── Remote connections
    ├── Scripts
    ├── System administration
    ├── Cron-related activity
    └── Potential credentials
```

---

# 🛡️ 11. Sudo Privileges

One of the **most important enumeration checks** is determining what commands the current user can execute through `sudo`.

Question:

> **Can the current user run commands as another user or as root?**

### Check sudo privileges

```bash
sudo -l
```

Example:

```text
User sysadm may run the following commands on NIX02:

(root) NOPASSWD: /usr/sbin/tcpdump
```

---

## ⭐ What is `NOPASSWD`?

`NOPASSWD` means the user can execute the specified sudo command **without being prompted for a password**.

Example:

```text
(root) NOPASSWD: /usr/sbin/tcpdump
```

means the `sysadm` user can run that specified command as root without a password prompt.

### Important distinction

Not every sudo command automatically gives unrestricted root access.

However, if a user has **full sudo privileges**, the source notes that:

```bash
sudo su
```

can immediately provide a root session.

---

# ⚙️ 12. Configuration Files

Configuration files can contain a **wealth of information**.

Look for files with extensions such as:

```text
.conf
.config
```

Potential information includes:

- Usernames
    
- Passwords
    
- Credentials
    
- Other secrets
    

### 🧠 Think:

```text
Configuration
      ↓
Credentials?
      ↓
Secrets?
      ↓
Connections to other services?
```

---

# 🔐 13. Readable Shadow File

The Linux shadow file can contain password hashes.

If the shadow file is readable, you may be able to gather password hashes for users who have passwords configured.

These hashes can potentially be subjected to **offline brute-force attacks** to recover the cleartext password.

### Important

```text
Readable Shadow
       ↓
Password Hashes
       ↓
Offline Password Cracking
       ↓
Potential Credential Recovery
```

---

# 🔐 14. Password Hashes in `/etc/passwd`

Normally, `/etc/passwd` is readable by all users.

Occasionally, password hashes may appear directly in this file.

The source notes that this is:

- **Uncommon**
    
- Sometimes seen on **embedded devices and routers**
    

These hashes could potentially be subjected to offline password-cracking attacks.

### Example

```bash
cat /etc/passwd
```

A relevant example from the source:

```text
sysadm:$6$vdH7vuQIv6anIBWg$Ysk.UZzI7WxYUBYt8WRIWF0EzWlksOElDE0HLYinee38QI1A.0HW7WZCrUhZ9wwDz13bPpkTjNuRoUGYhwFE11:1007:1007::/home/sysadm:
```

### `/etc/passwd` structure

A typical entry follows:

```text
username : password-field : UID : GID : description : home : shell
```

For example:

```text
mrb3n:x:1000:1000:mrb3n,,,:/home/mrb3n:/bin/bash
```

---

# ⏰ 15. Cron Jobs

Cron jobs are similar to **Windows scheduled tasks**.

They are commonly used for:

- Maintenance
    
- Backups
    
- Automated tasks
    

### Why are cron jobs interesting?

A cron job can become a privilege-escalation path when combined with other misconfigurations such as:

- Weak permissions
    
- Relative paths
    
- Writable scripts/files
    

### Concept

```text
Cron Job
   │
   ▼
Runs Automatically
   │
   ▼
Runs with privileged account?
   │
   ▼
Script/file permissions
   │
   ▼
Can lower-privileged user modify it?
   │
   ▼
Potential escalation path
```

---

## Example: `/etc/cron.daily/`

```bash
ls -la /etc/cron.daily/
```

The source shows:

```text
-rwxr-xr-x  1 root root  376 ... apport
-rwxr-xr-x  1 root root 1474 ... apt-compat
-rwx--x--x  1 root root  379 ... backup
-rwxr-xr-x  1 root root  355 ... bsdmainutils
-rwxr-xr-x  1 root root 1597 ... dpkg
-rwxr-xr-x  1 root root  372 ... logrotate
...
```

### ⭐ Key thing to inspect

If a privileged cron job executes a script that an unprivileged user can modify, that **permission mismatch** is potentially significant.

---

# 💽 16. Unmounted File Systems & Additional Drives

Check whether the system contains:

- Additional drives
    
- Unmounted partitions
    
- Unmounted file systems
    

These may contain:

🔐 Sensitive files  
🔑 Passwords  
💾 Backups  
📁 Other useful information

### Command

```bash
lsblk
```

Example:

```text
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   30G  0 disk
├─sda1   8:1    0   29G  0 part /
├─sda2   8:2    0    1K  0 part
└─sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1  848M  0 rom
```

---

# ⚡ 17. SUID & SGID Permissions

**SETUID (SUID)** and **SETGID (SGID)** are special permissions associated with executable files.

The source explains that these permissions can allow a user to execute a command with elevated permissions, and that many binaries may contain functionality that can potentially be abused to obtain a root shell.

### 🧠 Core idea

```text
Normal execution
      ↓
Program runs with user's privileges

SUID/SGID
      ↓
Program can run with special owner/group privileges
      ↓
Potential security risk if misconfigured/vulnerable
```

### ⭐ Important for exams

**SUID/SGID binaries are always worth enumerating during Linux privilege-escalation assessment.**

---

# ✍️ 18. Writable Directories

Finding writable directories is important for multiple reasons.

For example, you may need a place to:

- Store files
    
- Download tools
    
- Examine scripts
    
- Identify files used by scheduled tasks
    

The source specifically highlights writable directories associated with cron jobs.

### Command

```bash
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```

Example results include:

```text
/dmz-backups
/tmp
/tmp/VMwareDnD
/tmp/.XIM-unix
/tmp/.Test-unix
/tmp/.X11-unix
/dev/shm
/var/tmp
/var/crash
/run/lock
```

### 🔥 Important relationship

```text
Writable Directory
       +
Privileged Scheduled Task
       +
Weak File Permissions
       ↓
Potential Privilege Escalation
```

---

# 📝 19. Writable Files

You should also determine whether scripts or configuration files are **world-writable**.

The source warns that changing configuration files can be extremely destructive, so modifications should be approached carefully.

However, writable scripts can sometimes provide a path to further access, particularly when they are executed by **root through cron jobs**.

### Command

```bash
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

Example:

```text
/etc/cron.daily/backup
/dmz-backups/backup.sh
...
/home/backupsvc/backup.sh
```

### ⭐ Extremely important relationship

```text
Writable Script
      │
      ▼
Executed by Cron?
      │
      ▼
Executed as Root?
      │
      ▼
Potential Privilege Escalation
```

---

# 🧠 20. Complete Enumeration Method

When you obtain a low-privileged Linux shell, think systematically:

```text
                    ┌───────────────┐
                    │ Initial Shell │
                    └───────┬───────┘
                            ↓
                    ┌───────────────┐
                    │ ENUMERATION   │
                    └───────┬───────┘
                            ↓
       ┌────────────┬───────┼────────┬────────────┐
       ↓            ↓       ↓        ↓            ↓
      OS          Kernel  Services  Users       Sudo
       │            │       │        │            │
       └────────────┴───────┼────────┴────────────┘
                            ↓
                  ┌──────────────────┐
                  │ Files & Configs  │
                  └────────┬─────────┘
                           ↓
              ┌────────────┼────────────┐
              ↓            ↓            ↓
            SSH          Cron       Credentials
              │            │            │
              └────────────┼────────────┘
                           ↓
                 ┌─────────────────┐
                 │ Permissions     │
                 └────────┬────────┘
                          ↓
                  SUID / SGID
                  Writable Files
                  Writable Dirs
                          ↓
                 Potential LPE Path
```

---

# 🔥 21. Most Important Things to Remember

### ⭐ TOP 10

**1. Enumeration is the key to privilege escalation.**

**2. Always identify the OS and kernel versions.**

**3. Pay special attention to services running as `root`.**

**4. Check installed software for outdated/vulnerable versions.**

**5. Inspect other users and their home directories.**

**6. Look at `.bash_history`, `.ssh`, scripts, and configuration files.**

**7. Run `sudo -l` and carefully inspect the results.**

**8. Check cron jobs for privileged execution + weak permissions.**

**9. Enumerate SUID/SGID binaries.**

**10. Find writable directories and files, especially anything executed by privileged processes.**

---

# 📌 Quick Revision Sheet

```text
LINUX PRIVILEGE ESCALATION
════════════════════════════════════

1. ENUMERATION
   ├── OS Version
   ├── Kernel Version
   ├── Running Services
   ├── Installed Packages
   ├── Logged-in Users
   ├── Home Directories
   ├── Bash History
   ├── Sudo Privileges
   ├── Configuration Files
   ├── Password Hashes
   ├── Cron Jobs
   ├── File Systems
   ├── SUID / SGID
   ├── Writable Directories
   └── Writable Files

2. IMPORTANT COMMANDS
   ├── ps aux | grep root
   ├── ps au
   ├── ls /home
   ├── ls -la /home/<user>/
   ├── ls -l ~/.ssh
   ├── history
   ├── sudo -l
   ├── cat /etc/passwd
   ├── ls -la /etc/cron.daily/
   ├── lsblk
   ├── find ... -type d -perm -o+w
   └── find ... -type f -perm -o+w

3. HIGH-VALUE AREAS
   ├── Sudo
   ├── Root services
   ├── Vulnerable packages
   ├── Credentials
   ├── Cron
   ├── SUID/SGID
   └── Writable privileged scripts
```

## 🎯 One-line concept

> **Get a low-privileged shell → enumerate everything → identify a misconfiguration/vulnerability → determine whether it provides a path to higher privileges.**

The source itself concludes that manual enumeration provides the information needed to identify and pursue various Linux local privilege-escalation techniques.