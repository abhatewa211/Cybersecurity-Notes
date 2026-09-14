Linux hardening is the **defensive counterpart** to the privilege-escalation techniques you've been studying.

The goal is to remove or reduce the paths an attacker could use to escalate from:

```text
Low-privileged user
       │
       ▼
Privilege escalation vector
       │
       ▼
      root
```

Hardening tries to make that path:

```text
Low-privileged user
       │
       ▼
     Blocked
       │
       X
      root
```

---

# 1. Updates and Patching

One of the easiest ways to reduce privilege-escalation risk is to keep:

- Linux kernels updated
    
- Built-in services updated
    
- Third-party services updated
    
- Security patches applied regularly
    

Outdated systems may contain publicly known vulnerabilities with ready-made exploits.

### Ubuntu

The module mentions:

```text
unattended-upgrades
```

It is installed by default on Ubuntu from **18.04 onwards** according to the source.

Its purpose is to automate security updates.

### Red Hat-based systems

The module mentions:

```text
yum-cron
```

as a similar mechanism.

### CPTS connection

You've studied:

```text
Dirty Pipe       → CVE-2022-0847
PwnKit           → CVE-2021-4034
Sudo             → CVE-2021-3156
Netfilter        → several kernel CVEs
Dirty COW        → CVE-2016-5195
```

Regular patching is specifically designed to eliminate these kinds of known-vulnerability paths.

---

# 2. Configuration Management

Several simple configuration controls can eliminate common Linux privilege-escalation vectors.

## A. Audit writable files and SUID binaries

Attackers look for:

```bash
find / -perm -4000 2>/dev/null
```

and writable files/directories.

Why?

```text
Writable privileged file
        │
        ▼
Attacker modifies it
        │
        ▼
Privileged execution
        │
        ▼
Privilege escalation
```

### Hardening

- Remove unnecessary SUID bits.
    
- Ensure sensitive files aren't writable by low-privileged users.
    
- Audit world-writable directories.
    

---

# 3. Use Absolute Paths

Cron jobs and sudo rules should specify the **absolute path** of binaries.

Bad:

```text
tar *
```

or:

```text
nc
```

Better:

```text
/usr/bin/tar *
```

and:

```text
/bin/nc
```

### Why?

This helps prevent **PATH abuse**.

Recall:

```text
PATH
 ↓
Attacker-controlled directory
 ↓
Malicious executable
 ↓
Privileged program executes it
 ↓
root
```

Therefore:

> **Privileged scripts should not rely on an attacker-influenced PATH.**

---

# 4. Don't Store Cleartext Credentials

Avoid storing passwords and other credentials in:

```text
World-readable configuration files
Shell scripts
Backup files
History files
Application configs
```

You've already studied credential hunting:

```text
.conf
.config
.xml
.sh
.bak
database files
bash history
web configuration
```

Hardening means reducing the amount of sensitive information an attacker can discover.

---

# 5. Clean Home Directories and Bash History

Attackers commonly inspect:

```text
~/.bash_history
```

because users may accidentally leave:

```text
passwords
API keys
tokens
commands
connection strings
```

Hardening should therefore include reviewing and cleaning sensitive information from home directories and shell history.

---

# 6. Protect Custom Libraries

This connects directly to the **Shared Object Hijacking** module.

Dangerous situation:

```text
SUID root binary
      │
      ▼
Custom library
      │
      ▼
Writable by low-privileged user
      │
      ▼
Replace library
      │
      ▼
Malicious code executes as root
```

Hardening:

> Ensure low-privileged users cannot modify custom libraries called by privileged programs.

This also connects to **Python Library Hijacking**:

```text
Privileged Python
      │
      ▼
Imports module
      │
      ▼
Module writable by attacker
      │
      ▼
Attacker-controlled code
      │
      ▼
root
```

---

# 7. Remove Unnecessary Packages and Services

Every installed service or package can potentially increase the **attack surface**.

```text
More services
     │
     ▼
More code
     │
     ▼
More vulnerabilities / misconfigurations
     │
     ▼
Larger attack surface
```

Hardening principle:

> **If a service isn't required, consider removing or disabling it.**

---

# 8. SELinux

The module recommends considering:

```text
SELinux
```

SELinux provides additional access controls beyond traditional Unix permissions.

Traditional permissions:

```text
User
Group
Other
```

SELinux adds policy-based controls that can restrict what processes are allowed to access or execute.

Think of it as an additional security layer:

```text
Traditional permissions
          +
      SELinux policy
          │
          ▼
      Access decision
```

---

# 9. User Management

User management is another important hardening area.

### Limit accounts

Only create the accounts that are actually needed.

Also limit the number of:

```text
Administrative users
Privileged users
Sudo users
```

---

# 10. Monitor Login Attempts

Both successful and unsuccessful login attempts should be logged and monitored.

This can help detect:

```text
Brute force
Credential attacks
Compromised accounts
Suspicious login behavior
```

---

# 11. Strong Password Policy

The module recommends:

> Prefer longer memorized secrets or passphrases rather than relying on arbitrary periodic password changes.

So the focus should be on:

```text
Longer secrets
      +
Strong authentication
      +
Prevent password reuse
```

rather than simply forcing users to change passwords every arbitrary period.

---

# 12. Prevent Password Reuse

The module mentions:

```text
/etc/security/opasswd
```

with the PAM module.

This can be used to prevent users from reusing previous passwords.

Conceptually:

```text
New password
     │
     ▼
Compare against previous passwords
     │
 ┌───┴────┐
 ▼        ▼
Used    Not used
 │        │
 ▼        ▼
Reject   Accept
```

---

# 13. Control Group Membership

This is especially important given the privilege-escalation techniques you've studied.

A user may not have `sudo`, but membership in a privileged group can still provide powerful access.

Examples from your previous modules:

```text
lxd
docker
disk
adm
```

For example:

```text
docker
  ↓
Docker daemon control
  ↓
Host filesystem access
  ↓
root-equivalent access
```

Hardening principle:

> **Users should only belong to groups required for their day-to-day tasks.**

---

# 14. Least Privilege with Sudo

Don't give users unnecessary sudo permissions.

Bad:

```text
user ALL=(ALL) NOPASSWD: ALL
```

Better:

```text
user ALL=(root) /specific/required/program
```

And even then, carefully consider whether the permitted program itself can be abused.

Remember your methodology:

```text
sudo -l
   ↓
Allowed command
   ↓
Check its functionality
   ↓
GTFOBins / configuration
   ↓
Potential root
```

So simply restricting sudo to one binary isn't always sufficient.

---

# 15. Configuration Management Automation

The module mentions tools such as:

```text
Puppet
SaltStack
Zabbix
Nagios
```

These can automate security/configuration checks across multiple systems.

They can help identify and sometimes automatically remediate issues.

For example:

```text
Fleet of Linux systems
        │
        ▼
Configuration management
        │
        ├── Check permissions
        ├── Check versions
        ├── Check configuration
        └── Remediate problems
```

### Zabbix

The source specifically mentions checksum verification using:

```text
vfs.file.cksum
```

This can help verify that sensitive binaries have not been tampered with.

---

# 16. Auditing

Hardening shouldn't be a one-time activity.

Perform **periodic security and configuration checks**.

Useful security baselines include:

```text
DISA STIGs
ISO 27001
PCI-DSS
HIPAA
```

However, the module makes an important point:

> These should be used as reference guides, not as the sole basis of a security program.

Security controls should be adapted to:

- Organization
    
- Operating environment
    
- Data being stored
    
- Applications
    
- Threat model
    

---

# 17. Audit ≠ Penetration Test

This distinction is important.

### Configuration audit

Asks:

```text
"Is the system configured according to our security baseline?"
```

### Penetration test

Asks:

```text
"Can an attacker actually exploit this system?"
```

Therefore:

```text
Audit
  +
Vulnerability scanning
  +
Penetration testing
  +
Patch management
  +
Configuration management
```

provide much stronger coverage together.

---

# 18. Lynis

The module introduces **Lynis** as a security auditing tool for Unix-based systems.

It can audit:

- Linux
    
- macOS
    
- BSD
    
- Other Unix-based systems
    

It evaluates the current configuration and provides hardening recommendations.

---

## Running Lynis

After obtaining the repository:

```bash
./lynis audit system
```

Example:

```text
Lynis 3.0.1
Operating system: Linux
Operating system name: Ubuntu
Operating system version: 16.04
Kernel version: 4.4.0
Hardware platform: x86_64
```

---

# 19. Lynis Warnings

Lynis reports problems as **Warnings**.

Example:

```text
Warnings (2):

! Found one or more cronjob files with incorrect file permissions
! systemd-timesyncd never successfully synchronized time
```

The first warning is particularly relevant to your privilege-escalation studies.

You learned:

```text
Writable root cron script
       ↓
Modify script
       ↓
Cron executes as root
       ↓
root
```

Therefore, incorrect cron permissions can be a serious security finding.

---

# 20. Lynis Suggestions

Lynis also provides **Suggestions**.

Examples from the module:

```text
Set a password on GRUB boot loader
```

This helps prevent attackers from altering boot configuration.

Another:

```text
Disable core dumps if not required
```

And:

```text
Run pwck manually and correct errors
```

And:

```text
Configure minimum encryption algorithm rounds
```

Important distinction:

```text
Warnings
   ↓
Specific security problems detected

Suggestions
   ↓
Recommended hardening improvements
```

---

# 21. Lynis Hardening Index

The example reports:

```text
Hardening index : 60
Tests performed : 256
Plugins enabled : 2
```

The **Hardening Index** provides an overall indication of the system's hardening level.

The example also shows:

```text
Scan mode:
Pentest [V]
```

and:

```text
NON-PRIVILEGED SCAN MODE
```

This matters because some tests require root privileges.

Therefore:

```text
Lynis as normal user
      ↓
Some tests skipped / limited

Lynis as root
      ↓
More comprehensive checks
```

---

# 22. Lynis Is a Supplement, Not a Replacement

This is a key sentence to remember for CPTS:

> **Automated tools should supplement, not replace, manual enumeration and testing.**

Why?

Because an automated scanner may identify:

```text
"Potential issue"
```

but a penetration tester still needs to determine:

```text
Is it exploitable?
How?
Under what conditions?
What is the impact?
```

This is exactly what you've been practicing throughout Linux privilege escalation.

---

# 🔥 Connect Hardening to Everything You've Learned

|Attack vector|Hardening|
|---|---|
|Outdated kernel|Patch/update|
|SUID abuse|Audit/remove unnecessary SUID|
|PATH abuse|Use absolute paths|
|Wildcard abuse|Avoid unsafe wildcard usage|
|Cron abuse|Secure script permissions + absolute paths|
|Sudo abuse|Least privilege + exact paths|
|Credential hunting|Don't store cleartext credentials|
|Shared object hijacking|Protect library directories|
|Python hijacking|Protect modules/search paths|
|Docker/LXD abuse|Restrict privileged group membership|
|NFS abuse|Secure exports and root mapping|
|Kernel exploits|Keep kernel patched|
|Polkit/PwnKit|Keep packages patched|
|Dirty Pipe|Keep kernel patched|
|Logrotate abuse|Secure log/config permissions|
|Tmux hijacking|Protect privileged sockets|

---

# 🧠 Final CPTS Hardening Model

Think of Linux hardening as **removing the exact things you've been hunting for**:

```text
                 LINUX HARDENING
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
    PATCHING       PERMISSIONS      USERS/GROUPS
       │               │                │
       ▼               ▼                ▼
  Kernel/CVEs      SUID/SGID        Least privilege
  Services         Writable files   Sudo restrictions
  Packages         Libraries        Group auditing
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                 AUDIT + MONITOR
                       │
              ┌────────┴────────┐
              ▼                 ▼
           Manual            Lynis
           testing          scanning
              │                 │
              └────────┬────────┘
                       ▼
                 Harden + Verify
```

### ⭐ The biggest CPTS takeaway

Your privilege-escalation methodology and hardening methodology are essentially **opposites**:

> **As an attacker, find unnecessary privilege, weak permissions, outdated software, and attacker-controlled inputs. As a defender, remove those conditions and continuously verify that they stay removed.**