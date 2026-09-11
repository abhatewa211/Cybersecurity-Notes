# 1. 🧠 The Three Special Permission Bits

The important special permissions are:

```text
Special Permissions
       │
       ├── SUID  → Set User ID
       │
       ├── SGID  → Set Group ID
       │
       └── Sticky Bit
```

This section focuses primarily on:

- **SUID / setuid**
    
- **SGID / setgid**
    
- **GTFOBins**
    

---

# 2. 🔴 SUID — Set User ID

**Set User ID upon Execution (`setuid`)** allows a user to execute a program or script with the permissions of **another user**, typically a user with elevated privileges.

The important part:

> The program runs with the permissions of its **owner**.

If the owner is `root`, a vulnerable SUID program may execute with root privileges.

---

# 3. 👀 How Does SUID Look?

The SUID bit appears as:

```text
s
```

For example:

```text
-rwsr-xr-x
```

Look at the owner permission section:

```text
rws
  │
  └── s = SUID
```

Compare:

```text
-rwxr-xr-x
```

with:

```text
-rwsr-xr-x
```

The `s` replaces the owner's normal `x`.

---

# 4. 🎯 Why SUID Is Dangerous

Normally:

```text
User
 │
 ▼
Execute program
 │
 ▼
Program runs with user's privileges
```

With SUID:

```text
User
 │
 ▼
Execute SUID program
 │
 ▼
Program runs with owner's privileges
 │
 ▼
If owner = root
 │
 ▼
Potential root-level execution
```

So:

```text
SUID binary
      +
Owner = root
      +
Vulnerable/misconfigured functionality
      =
Potential privilege escalation
```

---

# 5. 🔎 Finding SUID Files

The module gives this command:

```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

Let's break it down.

```text
find /
 │
 └── Search entire filesystem

-user root
 │
 └── Files owned by root

-perm -4000
 │
 └── SUID permission

-exec ls -ldb {} \;
 │
 └── Display detailed information

2>/dev/null
 │
 └── Hide errors
```

### ⭐ This is a command worth memorizing.

---

# 6. 📋 Example SUID Results

The module gives examples such as:

```text
-rwsr-xr-x 1 root root ... /bin/mount
-rwsr-xr-x 1 root root ... /bin/su
-rwsr-xr-x 1 root root ... /bin/umount
-rwsr-xr-x 1 root root ... /bin/ping
-rwsr-xr-x 1 root root ... /usr/bin/passwd
-rwsr-xr-x 1 root root ... /usr/bin/sudo
-rwsr-xr-x 1 root root ... /usr/bin/pkexec
```

And notably:

```text
-rwsr-xr-x 1 root root ... /usr/bin/screen-4.5.0
```

The key thing isn't:

> "Every SUID binary is exploitable."

That is **wrong**.

Many legitimate Linux programs require SUID.

Instead:

> **Find unusual, outdated, custom, or vulnerable SUID binaries and investigate their functionality.**

---

# 7. 🚨 SUID Does NOT Automatically Mean Vulnerable

This distinction is extremely important for CPTS.

Suppose you find:

```text
/usr/bin/passwd
```

with SUID.

That's expected because `passwd` needs to perform privileged operations to change passwords.

Finding:

```text
/home/user/custom_program
```

with:

```text
-rwsr-xr-x root root
```

is much more interesting.

### Think:

```text
SUID found
    │
    ▼
Who owns it?
    │
    ▼
What does it do?
    │
    ▼
Is it custom/unusual?
    │
    ▼
Is its version vulnerable?
    │
    ▼
Can its functionality execute commands?
    │
    ▼
Can that functionality be abused?
```

---

# 8. 🧪 Reverse Engineering SUID Programs

The module states:

> It may be possible to reverse engineer the program with the SETUID bit set, identify a vulnerability, and exploit this to escalate privileges.

This is particularly relevant for **custom binaries**.

For example:

```text
/home/htb-student/shared_obj_hijack/payroll
```

appears in the SUID results.

A custom binary like `payroll` deserves much more attention than a standard system utility.

You would investigate:

```text
What does it execute?
What libraries does it use?
What files does it access?
Does it call external commands?
Does it trust environment variables?
Does it load shared libraries?
Does it have unsafe permissions?
```

---

# 9. 🟠 SGID — Set Group ID

The other major special permission is:

**Set-Group-ID (`setgid`)**

SGID allows a binary to execute with the permissions associated with its **group**.

Conceptually:

```text
SUID
User executes program
        ↓
Program gets owner's privileges


SGID
User executes program
        ↓
Program gets associated group's privileges
```

So:

```text
SUID → Owner privileges

SGID → Group privileges
```

---

# 10. 🔎 Finding SGID Files

The module gives:

```bash
find / -uid 0 -perm -6000 -type f 2>/dev/null
```

It also demonstrates:

```bash
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

Example:

```text
-rwsr-sr-x 1 root root 85832 Nov 30 2017 /usr/lib/snapd/snap-confine
```

Notice:

```text
rwsr-sr-x
   │    │
   │    └── s = SGID
   │
   └────── s = SUID
```

So this particular file has **both SUID and SGID**.

---

# 11. 🧠 Understanding `rwsr-sr-x`

This permission string:

```text
rwsr-sr-x
```

can be visualized as:

```text
Owner          Group          Others
 │               │              │
 ▼               ▼              ▼
rws             r-s            r-x
│ │              │              │
│ └─ SUID        └─ SGID        └─ normal execute
└── read
```

The two special bits are:

```text
s in owner position → SUID
s in group position → SGID
```

---

# 12. 🔥 SUID vs SGID

|Permission|Meaning|Potential impact|
|---|---|---|
|**SUID**|Execute as file owner|Potentially elevated user privileges|
|**SGID**|Execute with file's group privileges|Potentially elevated group privileges|

### Memory trick

```text
U → User → SUID

G → Group → SGID
```

---

# 13. 🧰 GTFOBins

Now we reach one of the **most useful resources for HTB privilege escalation**:

**GTFOBins**

The module describes GTFOBins as a curated list of binaries and scripts that can be used to bypass security restrictions.

It categorizes useful functionality including:

```text
GTFOBins
   │
   ├── Shell escape
   ├── Privilege escalation
   ├── Reverse shell
   ├── File transfer
   └── Restricted-shell escape
```

The key skill isn't memorizing every GTFOBin.

It's learning to recognize:

> **"I have a binary with elevated privileges — does GTFOBins document an abuse technique for it?"**

---

# 14. 🧠 Why GTFOBins Is So Useful

Imagine enumeration gives you:

```text
/usr/bin/apt-get
```

and you discover that you can execute it with elevated privileges.

Instead of manually researching everything from scratch:

```text
apt-get
   │
   ▼
GTFOBins
   │
   ▼
Known abuse techniques
   │
   ▼
Potential privilege escalation
```

That's why the module recommends becoming familiar with as many GTFOBins as possible.

---

# 15. 💥 Module Example — `apt-get`

The module provides:

```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

The relevant idea is that `apt-get` has a **Pre-Invoke** configuration mechanism.

The example results in:

```text
# id
uid=0(root) gid=0(root) groups=0(root)
```

So the user ends up with a root shell.

### Conceptual chain

```text
sudo permission
      │
      ▼
apt-get
      │
      ▼
Pre-Invoke option
      │
      ▼
/bin/sh
      │
      ▼
root shell
```

---

# 16. ⚔️ Special Permissions + GTFOBins

These two topics fit together extremely well.

Suppose you find:

```text
/usr/bin/somebinary
```

with:

```text
-rwsr-xr-x root root
```

Your thought process should be:

```text
SUID binary
    │
    ▼
Owned by root
    │
    ▼
What binary is it?
    │
    ▼
Check functionality
    │
    ▼
Check GTFOBins
    │
    ├── Shell?
    ├── Command execution?
    ├── File read/write?
    ├── Environment manipulation?
    └── Other escape functionality?
```

If the binary provides command execution while running as root:

```text
SUID root
    +
Command execution
    =
🚨 Potential root
```

---

# 17. 🧭 Your HTB Workflow

When you get a shell, special permissions should become part of your standard enumeration.

### Step 1 — Find SUID

```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

### Step 2 — Find SGID

```bash
find / -uid 0 -perm -6000 -type f 2>/dev/null
```

### Step 3 — Identify unusual binaries

Pay particular attention to:

```text
Custom binaries
Old binaries
Unexpected locations
Programs with dangerous functionality
```

### Step 4 — Investigate

Ask:

```text
What does the binary do?
```

### Step 5 — Check known abuse techniques

Use GTFOBins when appropriate.

### Step 6 — Determine exploitability

Don't stop at:

> "I found SUID."

You need:

> **"I found a root-owned SUID binary, identified functionality that can be abused, and determined how that functionality could affect privileges."**

---

# 🔥 STRICT MENTOR — What I Want You to See

Here's the progression:

```text
Enumeration
    │
    ▼
Find SUID / SGID
    │
    ▼
Identify owner/group
    │
    ▼
Identify binary
    │
    ▼
Standard or custom?
    │
    ▼
Understand functionality
    │
    ▼
GTFOBins / vulnerability research
    │
    ▼
Determine abuse path
    │
    ▼
Privilege escalation
```

---

# 🧠 CPTS MUST-KNOW

### SUID

```text
Set User ID
```

Allows execution with the **file owner's privileges**.

Usually seen as:

```text
-rwsr-xr-x
```

---

### SGID

```text
Set Group ID
```

Allows execution with the **file's group privileges**.

Usually seen as:

```text
-rwxr-sr-x
```

---

### SUID enumeration

```bash
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

### SGID/SUID enumeration

```bash
find / -uid 0 -perm -6000 -type f 2>/dev/null
```

### GTFOBins

Use it to quickly identify **known ways legitimate binaries can be abused** for:

- Privilege escalation
    
- Shell spawning
    
- Restricted-shell escape
    
- File operations
    
- Reverse shells
    
- Other security bypasses
    

---

# 📝 Final Revision Card

```text
                 SPECIAL PERMISSIONS
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
          SUID                       SGID
            │                         │
       User/owner                  Group
       privileges                 privileges
            │                         │
            └────────────┬────────────┘
                         ▼
                 Find unusual binaries
                         │
                         ▼
                  Understand binary
                         │
                         ▼
                     GTFOBins
                         │
                         ▼
                Known abuse technique
                         │
                         ▼
              Potential privilege
                    escalation
```

### ⭐ The single most important rule:

> **A SUID/SGID bit is an opportunity to investigate, not proof of exploitation.**

And for your CPTS prep, connect this with the previous modules:

**Environment Enumeration → Services → Credentials → PATH → Wildcards → Restricted Shells → Special Permissions → GTFOBins**

You're basically building the **Linux privilege-escalation methodology** one technique at a time.