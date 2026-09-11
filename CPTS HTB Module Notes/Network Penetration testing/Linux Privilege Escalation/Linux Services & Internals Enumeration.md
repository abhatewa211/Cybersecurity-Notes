## 🧭 1. What Is This Phase About?

After performing basic environment enumeration, the next step is to go **deeper into the internal configuration and operation of the Linux host**.

The objective is to understand:

- What services and applications are installed?
    
- What services are currently running?
    
- What sockets are being used?
    
- Which users, administrators, and groups exist?
    
- Who is currently logged in?
    
- Who logged in recently?
    
- What password policies are enforced?
    
- Is the host part of an Active Directory domain?
    
- What useful information exists in history, logs, and backups?
    
- Which files were recently modified?
    
- Are there patterns suggesting a cron job?
    
- What IP addresses and interfaces exist?
    
- Is `/etc/hosts` interesting?
    
- What network connections exist?
    
- What useful tools are installed?
    
- Can other users' `bash_history` files be read?
    
- Are there cron jobs that could potentially be hijacked?
    

### 🧠 Main idea

```text
        BASIC ENUMERATION
               │
               ▼
      SERVICES & INTERNALS
               │
       ┌───────┼────────┐
       ▼       ▼        ▼
    NETWORK   USERS   PROCESSES
       │       │        │
       └───────┼────────┘
               ▼
       CONFIGURATION
               │
       ┌───────┼────────┐
       ▼       ▼        ▼
     FILES    CRON    SERVICES
               │
               ▼
       POSSIBLE ATTACK PATHS
```

---

# 🌐 2. Network Information

Network enumeration becomes especially important because the compromised host may have access to networks that your original attack machine cannot directly reach.

The module specifically asks:

> What is our current IP address?

and:

> Does the system have other interfaces that could potentially allow us to pivot into another subnet?

### Commands

```bash
ip a
```

or:

```bash
ifconfig
```

### ⚠️ `ifconfig` may not work

On some systems, `ifconfig` may be unavailable because the **`net-tools` package** isn't installed. In those cases, `ip a` is the better option.

---

# 🔌 3. Network Interfaces

The module begins its internal enumeration with the interfaces through which the host communicates.

### Command

```bash
ip a
```

Example:

```text
1: lo: <LOOPBACK,UP,LOWER_UP>
    inet 127.0.0.1/8 scope host lo

2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 10.129.203.168/16
```

### Important fields

|Field|Meaning|
|---|---|
|`lo`|Loopback interface|
|`ens192`|Network interface|
|`127.0.0.1`|Localhost|
|`10.129.203.168`|Host IP|
|`/16`|Network prefix|
|`link/ether`|MAC address|
|`inet6`|IPv6 address|

### ⭐ What are we looking for?

```text
Network Interface
       │
       ├── IP address
       ├── Subnet
       ├── MAC address
       └── Additional interfaces
                         │
                         ▼
                  Possible subnet
                         │
                         ▼
                       Pivot
```

An additional interface may provide access to a subnet that was previously unreachable from the attack host.

---

# 🏠 4. `/etc/hosts`

Another useful file is:

```bash
cat /etc/hosts
```

Example:

```text
127.0.0.1 localhost
127.0.1.1 nixlpe02

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

### 🧠 Why check it?

The module specifically asks whether there is **anything interesting in `/etc/hosts`**.

Hostname-to-IP mappings can sometimes reveal systems that are important to the environment.

---

# 👤 5. Last Login Information

Knowing when users last logged in can give insight into how frequently the system is used.

### Command

```bash
lastlog
```

Example:

```text
Username          Port    From          Latest

root                              Never logged in
mrb3n             pts/1   10.10.14.15  Tue Aug 2 19:33
cliff.moore       pts/0   127.0.0.1    Tue Aug 2 19:32
stacey.jenkins    pts/0   10.10.14.15  Tue Aug 2 18:29
htb-student       pts/0   10.10.14.15  Wed Aug 3 13:37
```

### 🔎 Why does this matter?

It can help determine:

- Which accounts are actually used
    
- How frequently users access the system
    
- Whether the machine is heavily used
    
- Whether there may be messy directories or command histories
    
- Which users may be worth investigating further
    

The module specifically notes that frequent usage can increase the possibility of **misconfigurations, messy directories, or useful command histories**.

---

# 👥 6. Currently Logged-In Users

You should also check who is currently logged into the machine.

### Command

```bash
w
```

Another command mentioned:

```bash
who
```

On some systems:

```bash
finger
```

may also provide this information.

Example:

```text
12:27:21 up 1 day, 16:55, 1 user

USER      TTY    FROM          LOGIN@   IDLE
cliff.mo  pts/0  10.10.14.16  Tue19    40:54m
```

### ⭐ Why is this useful?

You may discover another user currently working on the system.

That gives you additional context about:

- Active accounts
    
- Remote connections
    
- User activity
    
- Potentially interesting processes or sessions
    

---

# 📜 7. Bash History

This is one of the **most important areas to check**.

The module explains that users may:

- Pass passwords as command-line arguments
    
- Work with Git repositories
    
- Set up cron jobs
    
- Run administrative commands
    
- Interact with other systems
    

Reviewing command history can therefore reveal how the server is being used and potentially point toward privilege-escalation paths.

### Command

```bash
history
```

Example:

```text
1  id
2  cd /home/cliff.moore
3  exit
4  touch backup.sh
5  tail /var/log/apache2/error.log
6  ssh ec2-user@dmz02.inlanefreight.local
7  history
```

### 🚨 Pay attention to

```text
passwords
SSH commands
backup scripts
cron-related commands
Git commands
internal hostnames
IP addresses
administrative commands
```

---

# 🔍 8. Finding Other History Files

Not all history is necessarily stored in `.bash_history`.

Scripts and programs may create their own history files.

### Command

```bash
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```

Example:

```text
-rw------- 1 htb-student htb-student 387 \
/home/htb-student/.bash_history
```

### 🧠 Concept

```text
History
  │
  ├── .bash_history
  ├── *_hist
  └── *_history
       │
       ▼
Potentially useful commands
       │
       ▼
Credentials / hosts / scripts / clues
```

---

# ⏰ 9. Cron Jobs

Cron jobs are extremely important in Linux privilege escalation.

The module compares Linux cron jobs to **Windows scheduled tasks**.

Cron jobs are commonly used for:

- Maintenance
    
- Backups
    
- Automated tasks
    
- Periodic scripts
    

### 🚨 Why are cron jobs interesting?

A scheduled task may run automatically with elevated privileges.

If that task has a weakness such as:

- Relative paths
    
- Weak file permissions
    
- Writable scripts/files
    

it may create a privilege-escalation opportunity.

The module explicitly notes that such misconfigurations can potentially be leveraged when the scheduled cron job executes.

---

## 📂 Checking Cron

Example:

```bash
ls -la /etc/cron.daily/
```

Output:

```text
-rwxr-xr-x 1 root root  376 ... apport
-rwxr-xr-x 1 root root 1478 ... apt-compat
-rwxr-xr-x 1 root root  355 ... bsdmainutils
-rwxr-xr-x 1 root root 1187 ... dpkg
-rwxr-xr-x 1 root root  377 ... logrotate
-rwxr-xr-x 1 root root 1123 ... man-db
-rwxr-xr-x 1 root root 4574 ... popularity-contest
-rwxr-xr-x 1 root root  214 ... update-notifier-common
```

### ⭐ What should you ask?

```text
Who runs it?
     ↓
What script/binary does it execute?
     ↓
What files does it access?
     ↓
Can those files be modified?
     ↓
Are relative paths being used?
```

---

# 🧬 10. `/proc` — The Process Filesystem

`proc` or `procfs` is a special Linux filesystem containing information about:

- Running processes
    
- Hardware
    
- System information
    
- Kernel parameters
    
- Memory
    
- Devices
    

### ⚠️ Important

`/proc` is **virtual**.

It isn't a traditional filesystem stored on disk.

Instead, the kernel dynamically generates its contents.

```text
             Linux Kernel
                  │
                  ▼
              /proc
                  │
       ┌──────────┼───────────┐
       ▼          ▼           ▼
   Processes    Memory      Hardware
       │
       ▼
   System information
```

---

# 🔎 11. Enumerating Processes Through `/proc`

The module demonstrates:

```bash
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
```

This can expose command lines of running processes.

Example output contains information such as:

```text
root@10.129.14.200
ssh
root
sshd:
htb-student
[priv]
/usr/bin/ssh-agent
...
```

### ⭐ Why is this useful?

Command lines can reveal:

- Running programs
    
- Arguments
    
- Remote hosts
    
- Usernames
    
- SSH activity
    
- Scripts
    
- Potentially sensitive parameters
    

---

# 📦 12. Installed Packages

Older Linux systems are more likely to contain vulnerable packages.

However:

> **Even current Linux distributions can contain older vulnerable software/packages.**

Therefore, enumerate installed packages.

### Ubuntu/Debian command

```bash
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
```

This creates a package list that can later be examined for potentially dangerous or vulnerable software.

---

# 🔐 13. Sudo Version

Don't only check `sudo -l`.

The **version of sudo itself** can also matter.

### Command

```bash
sudo -V
```

Example:

```text
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

### 🧠 Why?

A particular version of sudo may have known vulnerabilities.

So:

```text
sudo permissions
        +
sudo version
        ↓
Complete sudo assessment
```

---

# ⚙️ 14. Binaries

Not every useful program is necessarily installed through the package manager.

Some programs may be compiled manually and exist simply as executable binaries.

The module describes these as programs that can execute directly without requiring conventional installation.

### Command

```bash
ls -l /bin /usr/bin/ /usr/sbin/
```

Example:

```text
/usr/bin/:
aa-enabled
aa-exec
aconnect
acpi_listen
add-apt-repository
addpart
addr2line
...
```

### 🔎 Why enumerate binaries?

You want to know what tools are available locally.

Some binaries may:

- Have known vulnerabilities
    
- Have unusual privileges
    
- Be useful in certain configurations
    
- Provide unexpected functionality
    

---

# 💥 15. GTFOBins

The module introduces **GTFOBins** as a resource containing binaries that can potentially be abused for privilege escalation.

The idea is:

```text
Installed binaries
       │
       ▼
Compare with GTFOBins
       │
       ▼
Interesting binaries
       │
       ▼
Investigate later
```

The module demonstrates comparing installed binaries against the GTFOBins API and produces entries such as:

```text
Check GTFO for: apt
Check GTFO for: awk
Check GTFO for: bash
Check GTFO for: busybox
Check GTFO for: cat
Check GTFO for: cp
Check GTFO for: curl
Check GTFO for: dash
Check GTFO for: dd
...
```

### ⭐ Important

Finding a binary in GTFOBins **does not automatically mean it is exploitable**.

You still need to investigate:

- How it can be executed
    
- Under which user
    
- What permissions exist
    
- What sudo rules apply
    
- Whether the particular technique applies
    

---

# 🔬 16. `strace`

`strace` is a diagnostic tool for Linux.

It can:

- Track system calls
    
- Analyze signal processing
    
- Follow program behavior
    
- Show how programs access system resources
    
- Show communication with the OS
    
- Help identify security-related activity
    

### Example

```bash
strace ping -c1 10.129.112.20
```

The output can show system calls such as:

```text
execve(...)
access(...)
openat(...)
read(...)
socket(...)
connect(...)
sendto(...)
recvmsg(...)
write(...)
close(...)
exit_group(...)
```

---

## 🧠 Understanding `strace`

Think of it as watching a program interact with the operating system:

```text
             PROGRAM
                │
        ┌───────┼────────┐
        ▼       ▼        ▼
      files   sockets   memory
        │       │        │
        └───────┼────────┘
                ▼
          SYSTEM CALLS
                │
                ▼
              strace
                │
                ▼
          Observable output
```

The module also notes that `strace` output can be written to a file for later analysis.

---

# 📄 17. Configuration Files

Configuration files are extremely valuable during enumeration.

The module explains that users can often read many configuration files when administrators have left their permissions unchanged.

These files may reveal:

- Service configuration
    
- Keys
    
- Paths
    
- Sensitive information
    
- Locations of files that aren't otherwise obvious
    

### 🚨 Important permission concept

A file may be readable even if you cannot read its parent directory, **if the file itself has appropriate read permissions**.

The module specifically highlights this scenario.

---

## Find `.conf` and `.config`

```bash
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
```

Example:

```text
-rw-r--r-- 1 root root 448 ... /run/tmpfiles.d/static-nodes.conf
-rw-r--r-- 1 root root  71 ... /run/NetworkManager/resolv.conf
-rw-r--r-- 1 root root  72 ... /run/NetworkManager/no-stub-resolv.conf
...
```

---

# 📜 18. Scripts

Scripts are similar to configuration files in terms of their importance.

Administrators may create scripts for:

- Automation
    
- Maintenance
    
- Monitoring
    
- Backups
    
- Network tasks
    
- System administration
    

The module points out that poorly restricted script permissions can become important later, but **even simply reading scripts can reveal useful information** about internal processes.

### Find shell scripts

```bash
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```

Example:

```text
/home/htb-student/automation.sh
/etc/wpa_supplicant/action_wpa.sh
/etc/wpa_supplicant/ifupdown.sh
/etc/wpa_supplicant/functions.sh
/etc/init.d/keyboard-setup.sh
/etc/init.d/console-setup.sh
/etc/init.d/hwclock.sh
```

---

# ⚙️ 19. Processes & Running Services

The process list can reveal:

- Which scripts are running
    
- Which binaries are running
    
- Which user owns the process
    
- Which services are running as root
    

### Example

```bash
ps aux | grep root
```

Example output includes:

```text
root ... /sbin/init splash
root ... /lib/systemd/systemd-journald
root ... /lib/systemd/systemd-udevd
root ... vmware-vmblock-fuse
root ... /usr/bin/VGAuthService
root ... /usr/bin/vmtoolsd
root ... /usr/sbin/acpid
root ... /usr/sbin/anacron
root ... /usr/sbin/cron -f
root ... /usr/sbin/cupsd -l
root ... /usr/sbin/NetworkManager --no-daemon
root ... /usr/bin/python3 /usr/bin/networkd-dispatcher
root ... /usr/lib/policykit-1/polkitd --no-debug
root ... /usr/lib/snapd/snapd
root ... /usr/sbin/gdm3
```

---

# 🔥 20. Why Root Processes Matter

This is a critical concept.

```text
Process
   │
   ▼
Which user runs it?
   │
   ├── Normal user
   │
   └── root
         │
         ▼
   What does it execute?
         │
         ▼
   What files does it access?
         │
         ▼
   Are those files/scripts restricted?
```

A root-owned process or script deserves additional investigation because weaknesses in its configuration can potentially become privilege-escalation paths.

---

# 🧩 21. Complete Enumeration Methodology

Here's the methodology you should remember from this module:

```text
                 LINUX INTERNAL ENUMERATION
                           │
                           ▼
                    NETWORK INTERFACES
                           │
                    ┌──────┴──────┐
                    ▼             ▼
                 IPs/NICs      /etc/hosts
                    │
                    ▼
                 USERS
                    │
             ┌──────┴──────┐
             ▼             ▼
          Lastlog        Logged in
             │             │
             └──────┬──────┘
                    ▼
                HISTORY
                    │
                    ▼
                  CRON
                    │
                    ▼
                 /proc
                    │
                    ▼
            INSTALLED PACKAGES
                    │
                    ▼
                SUDO VERSION
                    │
                    ▼
                 BINARIES
                    │
                    ▼
               GTFOBins
                    │
                    ▼
                 STRACE
                    │
                    ▼
           CONFIGURATION FILES
                    │
                    ▼
                  SCRIPTS
                    │
                    ▼
             RUNNING SERVICES
                    │
                    ▼
            PROCESS OWNERSHIP
                    │
                    ▼
            POSSIBLE ATTACK PATHS
```

---

# 🧠 22. High-Value Things to Look For

When you perform this enumeration in a lab, don't blindly run commands. Ask **what each result means**.

### 🌐 Network

Look for:

- Additional interfaces
    
- Additional subnets
    
- Interesting `/etc/hosts` entries
    
- Internal connections
    

### 👤 Users

Look for:

- Active users
    
- Recently logged-in users
    
- Administrative users
    
- Service accounts
    

### 📜 History

Look for:

- Passwords
    
- SSH connections
    
- Internal hostnames
    
- Backup scripts
    
- Cron configuration
    
- Git activity
    

### ⏰ Cron

Look for:

- Root-owned jobs
    
- Scripts executed periodically
    
- Weak permissions
    
- Relative paths
    

### 📦 Packages

Look for:

- Outdated software
    
- Vulnerable versions
    
- Unusual packages
    

### ⚙️ Binaries

Look for:

- Interesting binaries
    
- Manually compiled binaries
    
- GTFOBins entries
    
- Unusual permissions
    

### 📄 Configuration

Look for:

- Credentials
    
- Keys
    
- Paths
    
- Service configuration
    

### 📜 Scripts

Look for:

- Automation
    
- Backups
    
- Monitoring
    
- Administrative scripts
    
- Scripts executed by privileged users
    

### 🔥 Processes

Look for:

- Root processes
    
- Scripts running as root
    
- Unusual binaries
    
- Network connections
    
- Interesting command-line arguments
    

---

# ⭐ 23. Commands You Should Memorize

## Network

```bash
ip a
ifconfig
cat /etc/hosts
```

## Users

```bash
lastlog
who
w
```

## History

```bash
history

find / -type f \( -name *_hist -o -name *_history \) \
-exec ls -l {} \; 2>/dev/null
```

## Cron

```bash
ls -la /etc/cron.daily/
```

## Processes

```bash
ps aux
ps aux | grep root
```

## Packages

```bash
apt list --installed
```

## Sudo

```bash
sudo -V
```

## Binaries

```bash
ls -l /bin /usr/bin/ /usr/sbin/
```

## Configuration

```bash
find / -type f \( -name *.conf -o -name *.config \) \
-exec ls -l {} \; 2>/dev/null
```

## Scripts

```bash
find / -type f -name "*.sh" 2>/dev/null
```

## `/proc`

```bash
find /proc -name cmdline -exec cat {} \; 2>/dev/null
```

---

# 🔴 24. MUST-KNOW Points

If you're preparing for the HTB questions, these are the concepts I'd mark **RED**:

### 🔴 `ip a`

Used to enumerate network interfaces and IP addresses.

### 🔴 `/etc/hosts`

Check for interesting hostname/IP mappings.

### 🔴 `lastlog`

Shows users' most recent login information.

### 🔴 `w` / `who`

Shows currently logged-in users.

### 🔴 `history`

Can reveal commands, credentials, SSH activity, scripts, Git activity, etc.

### 🔴 Cron

Cron is Linux's equivalent of scheduled tasks and can become a privilege-escalation path when combined with weaknesses such as **relative paths or weak permissions**.

### 🔴 `/proc`

A virtual filesystem containing information about processes, hardware, memory, devices, and kernel/system information.

### 🔴 Installed packages

Older or outdated packages may contain vulnerabilities.

### 🔴 `sudo -V`

Checks the installed sudo version, which may itself have vulnerabilities.

### 🔴 GTFOBins

Useful for identifying binaries that may have privilege-escalation techniques applicable to them.

### 🔴 `strace`

Tracks system calls and helps understand how a program interacts with the operating system.

### 🔴 Configuration files

Can reveal service configuration, keys, paths, and other sensitive information.

### 🔴 Scripts

Even when you cannot execute them, **reading scripts can reveal how the system works**.

### 🔴 Root processes

Always pay attention to **which user owns a process**, especially processes running as `root`.

---

# 🧪 25. How This Connects to the Previous Module

Your previous module was **Environment Enumeration**.

The progression is:

```text
MODULE 1
Environment Enumeration
        │
        ▼
Who am I?
What OS?
What kernel?
What groups?
What files?
What network?
        │
        ▼
MODULE 2
Services & Internals Enumeration
        │
        ▼
What is running?
Who is running it?
What packages exist?
What binaries exist?
What scripts exist?
What does /proc reveal?
What cron jobs exist?
What configs exist?
        │
        ▼
NEXT
Permissions & Exploitation Paths
```

The uploaded module ends by saying that this enumeration provides a strong overview of the target and the next step is to investigate the **individual permissions of the components discovered**.

---

## 🧠 Mentor Tip

Since you're working through these Linux privilege-escalation labs, **don't memorize this as one giant command list**.

Memorize the **questions**:

> **Who am I? → What's around me? → Who else is here? → What's running? → What runs as root? → What is installed? → What files/scripts/configs exist? → What's automated? → What can I read/write? → What can potentially be abused?**

That's the actual enumeration methodology. The commands are just how you answer those questions.