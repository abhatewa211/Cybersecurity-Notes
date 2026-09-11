## 🗺️ 1. Environment Enumeration — Big Picture

```text
                 INITIAL SHELL
                      │
                      ▼
             ┌─────────────────┐
             │  SITUATIONAL    │
             │    AWARENESS    │
             └────────┬────────┘
                      │
       ┌──────────────┼──────────────┐
       ▼              ▼              ▼
   SYSTEM          NETWORK         USERS
   INFO             INFO            INFO
       │              │              │
       ├─ OS          ├─ Interfaces  ├─ /etc/passwd
       ├─ Kernel      ├─ Routes      ├─ /etc/group
       ├─ CPU         ├─ ARP         ├─ /home
       ├─ PATH        └─ DNS         └─ Shells
       └─ Environment
                      │
                      ▼
              FILE SYSTEMS
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       Mounted     Unmounted    Hidden
        Files       Files        Files
          │           │           │
          └───────────┼───────────┘
                      ▼
             SENSITIVE DATA
                      │
                      ▼
          POTENTIAL ESCALATION /
             LATERAL MOVEMENT
```

The important point is that **the commands may differ between Linux distributions, but the underlying enumeration principles remain the same**.

---

# 🎯 2. Gaining Situational Awareness

Suppose you have just obtained access to a Linux host during an external penetration test.

After establishing a shell, the first goal is **not immediately exploitation**.

First:

> **Understand the environment you're in.**

Different operating systems require different commands and approaches:

- Ubuntu / Debian
    
- CentOS / RHEL
    
- FreeBSD
    
- Solaris
    
- HP-UX
    
- AIX
    

The source emphasizes developing a **thorough and repeatable process** rather than simply memorizing commands from a cheat sheet.

### 🧠 Golden Rule

> **Don't just memorize commands — understand what information each command gives you and why you need it.**

---

# ⚡ 3. First Commands to Run

The source recommends starting with a few basic commands:

|Command|Purpose|
|---|---|
|`whoami`|Shows the current user|
|`id`|Shows user's groups and IDs|
|`hostname`|Shows the server's hostname|
|`ifconfig` / `ip a`|Shows network interfaces/subnets|
|`sudo -l`|Shows sudo permissions|

### 🔄 Quick workflow

```text
whoami
   ↓
Who am I?

id
   ↓
What groups do I belong to?

hostname
   ↓
What is this machine called?

ip a / ifconfig
   ↓
Where am I on the network?

sudo -l
   ↓
What can I execute with elevated privileges?
```

### ⭐ Especially important: `sudo -l`

If the current user can execute something through `sudo`, particularly without requiring a password, this can sometimes be a very direct privilege-escalation path.

---

# 🐧 4. OS Version

The first detailed enumeration step is determining:

> **What operating system and version are we dealing with?**

### Command

```bash
cat /etc/os-release
```

Example from the source:

```text
NAME="Ubuntu"
VERSION="20.04.4 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.4 LTS"
VERSION_ID="20.04"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```

### Why does this matter?

Knowing the OS tells us:

- Which package manager may be present
    
- Which commands are likely to work
    
- Which tools may be available
    
- Whether the system is outdated
    
- Whether known vulnerabilities may apply
    

The source example identifies the target as **Ubuntu 20.04.4 LTS ("Focal Fossa")** and discusses checking its support lifecycle before considering vulnerabilities.

---

# 🛣️ 5. PATH Variable

The **PATH** variable tells Linux where to look for executable programs when you type a command.

For example, when you type:

```bash
id
```

Linux searches the directories listed in `$PATH` until it finds the executable.

### Command

```bash
echo $PATH
```

Example:

```text
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

### 🚨 Why is PATH important?

A **misconfigured PATH variable** can potentially be leveraged for privilege escalation.

```text
Command executed
       │
       ▼
Linux searches PATH
       │
       ▼
Directory 1 → Directory 2 → Directory 3...
       │
       ▼
Executable found
```

If the search order or writable directories are improperly configured, this can become security-relevant. The source says to record the PATH for later analysis.

---

# 🌱 6. Environment Variables

Environment variables may contain useful information about the current user/session.

### Command

```bash
env
```

Example:

```text
SHELL=/bin/bash
PWD=/home/htb-student
LOGNAME=htb-student
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/htb-student
LANG=en_US.UTF-8
```

### 🔎 What are we looking for?

Potentially sensitive information such as:

- Passwords
    
- Tokens
    
- Application configuration
    
- Paths
    
- User information
    
- Session information
    

The source specifically notes that we may get lucky and find something sensitive, such as a password.

---

# ⚙️ 7. Kernel Version

Next, identify the Linux kernel version.

### Command

```bash
uname -a
```

Alternative mentioned in the source:

```bash
cat /proc/version
```

Example:

```text
Linux nixlpe02 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

### Why?

A particular kernel version may contain a known vulnerability with a public exploit PoC.

### ⚠️ WARNING

Kernel exploits can cause:

- System instability
    
- Complete system crashes
    

So:

> **Always understand the exploit and its possible ramifications before running it, especially on production systems.**

---

# 🧠 8. CPU Information

We can gather information about the processor using:

```bash
lscpu
```

Example information from the source:

```text
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
CPU(s):              2
Core(s) per socket:  2
Socket(s):           1
Vendor ID:           AuthenticAMD
Model name:          AMD EPYC 7302P 16-Core Processor
Hypervisor vendor:   VMware
```

### 🔎 Why enumerate CPU information?

It can tell us:

- Architecture
    
- 32/64-bit support
    
- Number of CPUs/cores
    
- CPU vendor/model
    
- Whether we're running inside a hypervisor
    

---

# 🐚 9. Login Shells

We should determine which login shells exist on the system.

### Command

```bash
cat /etc/shells
```

Example:

```text
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/tmux
/usr/bin/screen
```

### ⭐ Important

The source specifically highlights that **Tmux** and **Screen** are available.

Shell versions can also matter because outdated software may contain vulnerabilities.

---

# 🛡️ 10. Security Defenses

We should check whether security mechanisms are present on the system.

The source lists:

- **Exec Shield**
    
- **iptables**
    
- **AppArmor**
    
- **SELinux**
    
- **Fail2ban**
    
- **Snort**
    
- **UFW (Uncomplicated Firewall)**
    

### Why enumerate defenses?

You may not have permission to inspect their complete configurations.

However, knowing **what defenses exist** can prevent you from wasting time on approaches that are unlikely to work.

```text
Target
  │
  ├── AppArmor?
  ├── SELinux?
  ├── Firewall?
  ├── Fail2ban?
  ├── IDS?
  └── Other protections?
```

---

# 💽 11. Drives & Block Devices

Use:

```bash
lsblk
```

This enumerates **block devices**, such as:

- Hard disks
    
- USB drives
    
- Optical drives
    
- Partitions
    

Example:

```text
NAME                      SIZE TYPE MOUNTPOINT
loop0                       55M loop /snap/core18/1705
loop1                       69M loop /snap/lxd/14804
sda                         20G disk
├─sda1                       1M part
├─sda2                       1G part /boot
└─sda3                      19G part
  └─ubuntu--vg-ubuntu--lv  18G lvm /
sr0                        908M rom
```

### 🚨 Why are additional drives interesting?

An additional or unmounted filesystem could contain:

- Sensitive files
    
- Passwords
    
- Backups
    
- Documentation
    
- Applications
    

---

# 🖨️ 12. Printers

The command:

```bash
lpstat
```

can be used to gather information about printers attached to the system.

### Interesting question:

> Are there active or queued print jobs that could contain sensitive information?

---

# 📂 13. `/etc/fstab`

`/etc/fstab` contains **static filesystem information**.

### Command

```bash
cat /etc/fstab
```

Example:

```text
UUID=5bf16727-fcdf-4205-906c-0620aa4a058f  /          ext4  errors=remount-ro  0  1
UUID=BE56-AAE0                             /boot/efi  vfat  umask=0077         0  1
/swapfile                                  none       swap  sw                 0  0
```

### 🔎 What are we interested in?

The source suggests looking for credentials related to mounted drives, including keywords such as:

```text
password
username
credential
```

---

# 🌐 14. Network Interfaces

One of the first basic commands is:

```bash
ifconfig
```

or:

```bash
ip a
```

This helps identify:

- IP addresses
    
- Network interfaces
    
- Subnets
    
- Additional NICs
    

### Network visualization

```text
             Linux Host
                 │
       ┌─────────┴─────────┐
       │                   │
    ens192               eth1
       │                   │
  Network A            Network B
       │                   │
       ▼                   ▼
 Other Hosts          Other Hosts
```

An additional network interface can be particularly interesting because it may indicate connectivity to another subnet.

---

# 🧭 15. Routing Table

Check the routing table using:

```bash
route
```

or:

```bash
netstat -rn
```

Example:

```text
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref Use Iface
default         _gateway        0.0.0.0         UG    0      0   0   ens192
10.129.0.0      0.0.0.0         255.255.0.0    U     0      0   0   ens192
```

### 🧠 What does this tell us?

It helps determine:

- Which networks are reachable
    
- Which gateway is used
    
- Which interface handles traffic
    
- Whether the host has access to additional networks
    

---

# 🌐 16. `/etc/resolv.conf` — DNS

In a domain environment, check:

```bash
cat /etc/resolv.conf
```

The source emphasizes that if the host uses **internal DNS**, this can be a starting point for querying the Active Directory environment.

### Concept

```text
Linux Host
    │
    ▼
Internal DNS
    │
    ▼
Domain Environment
    │
    ▼
Potential AD Information
```

---

# 📡 17. ARP Table

Check the ARP table:

```bash
arp -a
```

Example:

```text
_gateway (10.129.0.1) at 00:50:56:b9:b9:fc [ether] on ens192
```

### Why?

The ARP table can show other hosts the target has recently communicated with.

This can help identify:

- Gateways
    
- Nearby hosts
    
- Potential internal systems
    

---

# 👥 18. Enumerating Users

User enumeration is an important part of environment enumeration.

Why?

Applications and services often create dedicated users so that they don't have to run with `root` privileges.

### 🔥 Why is running services as root dangerous?

```text
Service
   │
   ▼
Runs as ROOT
   │
   ▼
Service compromised
   │
   ▼
Attacker gains highest privileges
   │
   ▼
Entire system potentially compromised
```

The source explains that if a service running with the highest privileges (`root`) is brought under an attacker's control, the attacker automatically has the highest rights over the system.

---

# 📄 19. `/etc/passwd`

All users on the system are stored in:

```text
/etc/passwd
```

### The 7 fields

The source identifies:

1. **Username**
    
2. **Password**
    
3. **User ID (UID)**
    
4. **Group ID (GID)**
    
5. **User ID information**
    
6. **Home directory**
    
7. **Shell**
    

### Structure

```text
username : password : UID : GID : user-info : home : shell
```

### Example

```text
mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
```

---

# 🔐 20. Password Hashes in `/etc/passwd`

Occasionally, password hashes can appear directly in `/etc/passwd`.

Normally this is **not common**.

The source notes that this can sometimes be seen on:

- Embedded devices
    
- Routers
    

Because `/etc/passwd` is readable by all users, exposed hashes could potentially be subjected to offline password cracking.

---

# 🔢 21. Extracting Usernames

The source demonstrates:

```bash
cat /etc/passwd | cut -f1 -d:
```

This extracts the first field — the username.

Example:

```text
root
daemon
bin
sys
...
mrb3n
lxd
bjones
administrator.ilfreight
backupsvc
cliff.moore
logger
shared
stacey.jenkins
htb-student
```

### 🧠 Why?

It gives a quick list of accounts that can then be investigated individually.

---

# 🔢 22. Linux Password Hash Algorithms

Linux can use several password-hashing algorithms.

The source gives these identifiers:

|Algorithm|Hash prefix|
|---|---|
|**Salted MD5**|`$1$...`|
|**SHA-256**|`$5$...`|
|**SHA-512**|`$6$...`|
|**BCrypt**|`$2a$...`|
|**Scrypt**|`$7$...`|
|**Argon2**|`$argon2i$...`|

### ⭐ Remember

The beginning of a hash can help identify which hashing algorithm was used.

```text
$1$       → Salted MD5
$5$       → SHA-256
$6$       → SHA-512
$2a$      → BCrypt
$7$       → Scrypt
$argon2i$ → Argon2
```

---

# 🐚 23. Users With Login Shells

We should identify which users have actual login shells.

### Command

```bash
grep "sh$" /etc/passwd
```

Example:

```text
root:x:0:0:root:/root:/bin/bash
mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
bjones:x:1001:1001::/home/bjones:/bin/sh
administrator.ilfreight:x:1002:1002::/home/administrator.ilfreight:/bin/sh
backupsvc:x:1003:1003::/home/backupsvc:/bin/sh
cliff.moore:x:1004:1004::/home/cliff.moore:/bin/bash
logger:x:1005:1005::/home/logger:/bin/sh
shared:x:1006:1006::/home/shared:/bin/sh
stacey.jenkins:x:1007:1007::/home/stacey.jenkins:/bin/bash
htb-student:x:1008:1008::/home/htb-student:/bin/bash
```

### 🚨 Why is shell version important?

The source gives **Bash 4.1** as an example of an outdated version vulnerable to **Shellshock**.

So:

```text
User
 ↓
Login Shell
 ↓
Shell Version
 ↓
Known Vulnerability?
```

---

# 👨‍👩‍👧‍👦 24. Groups

Every Linux user belongs to one or more groups.

Groups provide additional permissions.

### Example

Imagine:

```text
/dev
```

is intended only for developers.

A user would need membership in the appropriate group to access it.

Group information is stored in:

```text
/etc/group
```

---

# 📋 25. `/etc/group`

Command:

```bash
cat /etc/group
```

Example:

```text
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,htb-student
tty:x:5:syslog
disk:x:6:
...
sudo:x:27:mrb3n,htb-student
...
```

### ⭐ Interesting groups

Pay attention to groups that may provide significant privileges.

For example:

```text
sudo:x:27:mrb3n,htb-student
```

indicates those users belong to the `sudo` group.

---

# 🔎 26. Enumerating Group Members

Use:

```bash
getent group sudo
```

Example:

```text
sudo:x:27:mrb3n
```

### 🧠 Simple concept

```text
/etc/group
     ↓
Interesting Group
     ↓
getent group <group>
     ↓
Group Members
     ↓
Investigate privileges
```

---

# 🏠 27. `/home` Directories

Check:

```bash
ls /home
```

Example:

```text
administrator.ilfreight
bjones
htb-student
mrb3n
stacey.jenkins
backupsvc
cliff.moore
logger
shared
```

### 🔎 What should we inspect?

For each interesting user:

```text
/home/<user>/
```

Look for:

- `.bash_history`
    
- Configuration files
    
- Password-containing files
    
- SSH keys
    
- Scripts
    
- Sensitive documents
    

The source notes that SSH keys can potentially help with **persistence**, privilege escalation, pivoting, and port forwarding further into an internal network.

---

# 🔑 28. SSH Keys

SSH keys are particularly important during enumeration.

They may potentially be useful for:

- Persistence
    
- Access to another account/system
    
- Privilege escalation paths
    
- Pivoting
    
- Port forwarding
    

The source recommends at minimum checking the **ARP cache** and cross-referencing hosts with usable private keys.

```text
SSH Key
  │
  ▼
Identify Owner
  │
  ▼
Identify Known Hosts
  │
  ▼
Compare with ARP/network information
  │
  ▼
Potential access/pivot path
```

---

# 📜 29. Configuration Files

Configuration files can contain a **wealth of information**.

Search for files ending in:

```text
.conf
.config
```

Potential information:

- Usernames
    
- Passwords
    
- Credentials
    
- Other secrets
    

---

# 🔐 30. Password Reuse

If you discover a password during enumeration, the source suggests checking whether it is reused across users on the system.

Why?

> **Password reuse is common.**

Therefore, discovering one valid password may potentially provide access to additional accounts.

---

# 💾 31. Mounted File Systems

A **mounted file system** is attached to a directory and accessed through that directory.

Examples of filesystem types mentioned:

- ext4
    
- NTFS
    
- FAT32
    

Some filesystems may be read-only, while others can be read/write.

### Command

```bash
df -h
```

This can show mounted filesystems and their disk usage.

Example:

```text
Filesystem      Size  Used Avail Use% Mounted on
udev            1.9G     0  1.9G   0% /dev
tmpfs           389M   1.8M  388M   1% /run
/dev/sda5        20G   7.9G   11G  44% /
...
/dev/sda1       511M   4.0K  511M   1% /boot/efi
```

---

# 💽 32. Unmounted File Systems

An unmounted filesystem is not currently accessible through the normal filesystem hierarchy.

Reasons may include:

- Disk removed
    
- Filesystem no longer needed
    
- Sensitive information intentionally kept inaccessible to standard users
    

The source notes that if privileges are elevated to root, these filesystems could potentially be mounted and examined.

### Check `/etc/fstab`

```bash
cat /etc/fstab | grep -v "#" | column -t
```

Example:

```text
UUID=5bf16727-fcdf-4205-906c-0620aa4a058f  /          ext4  errors=remount-ro  0  1
UUID=BE56-AAE0                             /boot/efi  vfat  umask=0077         0  1
/swapfile                                  none       swap  sw                 0  0
```

---

# 🕵️ 33. Hidden Files

Linux contains many hidden files and directories.

They are hidden primarily so they aren't immediately obvious and accidental editing can be prevented.

### 🚨 Why enumerate them?

Even if you only have **read permissions**, hidden files may contain sensitive information.

---

## Find Hidden Files

```bash
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
```

Example results:

```text
/home/htb-student/.bashrc
/home/htb-student/.wget-hsts
/home/htb-student/.bash_history
/home/htb-student/.profile
/home/htb-student/.sudo_as_admin_successful
/home/htb-student/.bash_logout
/home/htb-student/.notes
```

### ⭐ Interesting hidden files

|File|Potential significance|
|---|---|
|`.bash_history`|Command history|
|`.ssh`|SSH configuration/keys|
|`.config`|Application configuration|
|`.notes`|Potential user-created information|
|`.gnupg`|GPG-related information|

---

# 📁 34. Hidden Directories

Command:

```bash
find / -type d -name ".*" -ls 2>/dev/null
```

The source finds directories including:

```text
/home/htb-student/.gnupg
/home/htb-student/.ssh
/home/htb-student/.cache
/home/htb-student/CVE-2021-3156/.git
/home/htb-student/.config
/home/htb-student/.local
/var/lib/gdm3/.cache
/var/lib/gdm3/.config
...
```

### 🔎 Things that stand out

```text
.ssh
.gnupg
.config
.git
```

These can contain configuration, credentials, keys, source code, or other useful information depending on the environment.

---

# 🗑️ 35. Temporary Files

Three default locations are particularly relevant:

```text
/tmp
/var/tmp
/dev/shm
```

The source explains that these locations are visible/readable by users and can contain temporary logs or script output.

### `/tmp` vs `/var/tmp`

|Directory|Retention|
|---|---|
|`/tmp`|Shorter-term temporary storage|
|`/var/tmp`|Data retained longer|
|`/dev/shm`|Temporary shared-memory filesystem|

According to the source, `/var/tmp` retains data for up to **30 days by default**, while `/tmp` data is automatically deleted after **10 days**. It also states that `/tmp` contents are deleted when the system restarts, while `/var/tmp` is intended for temporary data that needs to survive reboots.

---

## Temporary Files Example

```bash
ls -l /tmp /var/tmp /dev/shm
```

Example:

```text
/dev/shm:
total 0

/tmp:
total 52
-rw------- 1 htb-student htb-student    0 ... config-err-v8LfEU
drwx------ 3 root        root        4096 ... snap.snap-store
drwx------ 2 htb-student htb-student 4096 ... ssh-OKlLKjlc98xh
...

/var/tmp:
total 28
drwx------ 3 root root 4096 ... systemd-private-...-colord.service...
drwx------ 3 root root 4096 ... systemd-private-...-ModemManager.service...
```

---

# 🔥 36. Complete Enumeration Checklist

When you first land on a Linux machine, follow a repeatable process:

### 👤 Identity

```bash
whoami
id
hostname
```

### 🐧 System

```bash
cat /etc/os-release
uname -a
lscpu
```

### 🛣️ Environment

```bash
echo $PATH
env
cat /etc/shells
```

### 🌐 Network

```bash
ifconfig
ip a
route
netstat -rn
cat /etc/resolv.conf
arp -a
```

### 🛡️ Privileges

```bash
sudo -l
```

### 👥 Users & Groups

```bash
cat /etc/passwd
cat /etc/group
getent group sudo
```

### 🏠 User Data

```bash
ls /home
```

Then inspect interesting user directories.

### 💾 Storage

```bash
lsblk
df -h
cat /etc/fstab
```

### 🕵️ Hidden Files

```bash
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null
```

### 📁 Hidden Directories

```bash
find / -type d -name ".*" -ls 2>/dev/null
```

### 🗑️ Temporary Locations

```bash
ls -l /tmp /var/tmp /dev/shm
```

---

# 🧠 37. The Enumeration Mindset

Don't think:

> ❌ "Which command gives me root?"

Think:

> ✅ **"What information can I gather that tells me how this machine is configured?"**

```text
                 ENUMERATION
                     │
      ┌──────────────┼──────────────┐
      ▼              ▼              ▼
    SYSTEM         USERS          NETWORK
      │              │              │
      ▼              ▼              ▼
 OS / Kernel     Groups / Home   Routes / DNS
 CPU / Shells    SSH / History   ARP / NICs
 PATH / ENV      Configs         Subnets
      │              │              │
      └──────────────┼──────────────┘
                     ▼
               FILE SYSTEM
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Mounted   Unmounted    Hidden
                     │
                     ▼
             Sensitive Data
                     │
                     ▼
          Possible Attack Paths
```

---

# ⭐ 38. MOST IMPORTANT POINTS — EXAM/REVISION

### 🔴 Must Remember

**1. Enumeration is the key to privilege escalation.**

**2. Don't rely entirely on automated scripts — understand manual enumeration.**

**3. `whoami` → identifies your current user.**

**4. `id` → identifies groups and IDs.**

**5. `hostname` → identifies the machine name.**

**6. `ip a` / `ifconfig` → identifies network interfaces and subnets.**

**7. `sudo -l` → checks sudo permissions.**

**8. `/etc/os-release` → identifies the operating system/version.**

**9. `uname -a` → identifies kernel information.**

**10. `$PATH` is important because a misconfigured PATH can potentially lead to privilege escalation.**

**11. `env` may contain sensitive information.**

**12. `lsblk` → enumerates block devices.**

**13. `/etc/fstab` → provides filesystem configuration information.**

**14. `route` / `netstat -rn` → shows routing information.**

**15. `/etc/resolv.conf` → can reveal internal DNS configuration.**

**16. `arp -a` → shows hosts the machine has communicated with.**

**17. `/etc/passwd` → contains information about system users.**

**18. `/etc/group` → contains groups and their members.**

**19. Login shells should be enumerated because vulnerable shell versions may exist.**

**20. Always inspect `/home` for sensitive information and SSH keys.**

**21. Search `.conf` and `.config` files for credentials/secrets.**

**22. Check mounted and unmounted filesystems.**

**23. Hidden files and directories can contain sensitive information.**

**24. Don't forget `/tmp`, `/var/tmp`, and `/dev/shm`.**

**25. Automated tools like LinPEAS are useful, but manual enumeration is essential because tools can fail or may not be available.**

---

# 📝 39. Ultra-Short Revision

```text
LINUX ENVIRONMENT ENUMERATION
══════════════════════════════════

IDENTITY
→ whoami
→ id
→ hostname

SYSTEM
→ cat /etc/os-release
→ uname -a
→ lscpu
→ cat /etc/shells

ENVIRONMENT
→ echo $PATH
→ env

NETWORK
→ ip a
→ route
→ netstat -rn
→ /etc/resolv.conf
→ arp -a

PRIVILEGES
→ sudo -l

USERS
→ /etc/passwd
→ /etc/group
→ getent group <group>
→ /home/*

STORAGE
→ lsblk
→ df -h
→ /etc/fstab

HIDDEN DATA
→ hidden files
→ hidden directories
→ .ssh
→ .config
→ .gnupg
→ .bash_history

TEMPORARY
→ /tmp
→ /var/tmp
→ /dev/shm

TOOLS
→ LinPEAS
→ LinEnum
```

### 🎯 Final takeaway

**The goal of environment enumeration is to build a complete picture of the Linux host — its OS, kernel, users, groups, permissions, network, filesystems, hidden data, and configuration — so that later privilege-escalation and lateral-movement decisions are based on evidence rather than guesswork.** The source then moves on to examining permissions on directories, scripts, binaries, and other objects.