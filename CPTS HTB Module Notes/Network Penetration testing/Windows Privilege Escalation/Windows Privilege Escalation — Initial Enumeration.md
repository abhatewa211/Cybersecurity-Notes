The core principle is:

> **Enumeration is the key to privilege escalation.**

After gaining initial access, you need to understand the OS, patch level, installed software, privileges, groups, users, services, network connections, and other relevant information before choosing an escalation path.

---

# 🧠 1. What Happens After Initial Access?

Suppose you obtain:

```text
Low-Privileged Shell
        │
        ▼
Initial Enumeration
        │
        ├── System Information
        ├── Network Information
        ├── Running Processes
        ├── Services
        ├── Users
        ├── Groups
        ├── Privileges
        ├── Password Policy
        ├── Installed Software
        └── Patches
                │
                ▼
        Identify Weakness
                │
                ▼
       Privilege Escalation
```

Fully compromising the host may provide access to:

- Sensitive files
    
- File shares
    
- Network traffic
    
- Credentials
    
- Other systems
    
- Potentially higher privileges in Active Directory
    

The source specifically notes that escalation can potentially lead as far as **Domain Admin** depending on the environment and discovered information.

---

# 🎯 2. Possible Privilege-Escalation Targets

Depending on the configuration, you may be able to escalate to:

|Target|Importance|
|---|---|
|`NT AUTHORITY\SYSTEM`|⭐ Extremely privileged local account|
|Built-in `administrator`|⭐ Local administrative access|
|Another local Administrator|⭐ Same privileges as local Administrator|
|Standard domain user in local Administrators|⭐ Local administrative privileges|
|Domain Admin in local Administrators|🔥 Extremely powerful in AD|

The source specifically states that any account belonging to the local `Administrators` group has the same privileges as the built-in local administrator account.

---

# ⭐ 3. Enumeration Is the Key

This is probably the **single most important sentence in this section**:

> **Enumeration is the key to privilege escalation.**

After getting a shell, immediately start building **situational awareness**.

You want answers to questions such as:

```text
What OS is this?
        ↓
What version/build?
        ↓
What patches are installed?
        ↓
What software is installed?
        ↓
What services are running?
        ↓
What user am I?
        ↓
What privileges do I have?
        ↓
What groups am I in?
        ↓
Who else uses this machine?
        ↓
What interesting users/groups exist?
        ↓
What is listening on the network?
```

---

# 🖥️ 4. Key Data Points

The source highlights three particularly important starting points:

### `OS Name`

### `Version`

### `Running Services`

Let's break these down.

---

# 🪟 5. OS Name

Knowing the exact Windows operating system is important.

For example:

```text
Windows 7
Windows 10
Windows Server 2008
Windows Server 2012
Windows Server 2016
Windows Server 2019
```

The OS can tell you:

- What functionality is available
    
- Which PowerShell versions may exist
    
- Whether you're dealing with an old/legacy system
    
- Which vulnerabilities may apply
    
- Which tools may work
    

### ⭐ CPTS habit

Always identify the OS **before searching for exploits**.

---

# 🔢 6. OS Version / Build

The specific Windows version/build can be important because vulnerabilities may affect only particular versions.

For example:

```text
Windows Server 2016
Build 14393
```

The source warns that kernel/system exploits can potentially cause:

- System instability
    
- Complete system crashes
    

Therefore, understand an exploit before using it against a production system.

### Important professional rule

```text
Known vulnerability
        ≠
Safe to exploit immediately
```

You need to consider the environment and impact.

---

# ⚙️ 7. Running Services

Running services are extremely important.

Why?

A service may be running as:

```text
NT AUTHORITY\SYSTEM
```

or another administrative account.

If that service is:

- Vulnerable
    
- Misconfigured
    
- Modifiable by a low-privileged user
    

it may provide a privilege-escalation path.

### Think:

```text
Low Privileged User
        │
        ▼
Interesting Service
        │
        ▼
Service runs as SYSTEM
        │
        ▼
Weak Configuration?
        │
        ▼
Potential Privilege Escalation
```

---

# 🔬 8. System Information

The source recommends looking at the system itself to understand:

- Exact OS version
    
- Hardware
    
- Installed programs
    
- Security updates
    

This helps narrow down missing patches and associated CVEs.

---

# 🧵 9. `tasklist /svc`

One useful command is:

```cmd
tasklist /svc
```

Example:

```cmd
C:\htb> tasklist /svc
```

This displays running processes along with the services associated with them.

### Example from the source

```text
Image Name             PID    Services
------------------------------------------------
lsass.exe              672    KeyIso, SamSs, VaultSvc
svchost.exe            972    TermService
spoolsv.exe            1884   Spooler
svchost.exe            1988   W3SVC, WAS
ftpsvc
FileZilla Server.exe   1140   FileZilla Server
MsMpEng.exe            2136   WinDefend
```

---

# 🧠 10. Know Standard Windows Processes

You should become familiar with common Windows processes:

|Process|Meaning|
|---|---|
|`smss.exe`|Session Manager Subsystem|
|`csrss.exe`|Client Server Runtime Subsystem|
|`winlogon.exe`|Windows Logon|
|`lsass.exe`|Local Security Authority Subsystem Service|
|`svchost.exe`|Service Host|
|`services.exe`|Service Control Manager|
|`wininit.exe`|Windows Initialization|

The source emphasizes that knowing standard processes allows you to quickly identify **non-standard processes/services**, which may be more interesting for privilege escalation.

---

# 🚨 11. Spotting Non-Standard Services

In the example, the source highlights:

```text
FileZilla Server
```

as something worth investigating.

Why?

You could enumerate:

- Its version
    
- Configuration
    
- Permissions
    
- Exposed functionality
    
- Potential vulnerabilities
    
- Potential anonymous FTP access
    

### CPTS mindset

Don't memorize:

> "FileZilla = vulnerability."

Instead memorize:

> **Unusual service → identify it → identify version → inspect configuration → determine whether it creates an attack path.**

---

# 🛡️ 12. Identifying Security Software

Another interesting process in the output is:

```text
MsMpEng.exe
```

This is associated with **Windows Defender**.

Security processes are important because they tell you what protections are running on the host.

So while enumerating processes, don't only look for vulnerable software.

Also look for:

```text
AV
EDR
Security agents
Monitoring software
```

---

# 🌳 13. Environment Variables

Windows provides the:

```cmd
set
```

command to display environment variables.

Example:

```cmd
C:\htb> set
```

---

# ⭐ 14. Why Is `PATH` Important?

One of the most important environment variables is:

```text
PATH
```

Windows uses the PATH to locate executable programs.

The source highlights an important behavior:

> Windows looks in the **Current Working Directory (CWD)** first, then searches the PATH from left to right.

Conceptually:

```text
Execute Program
      │
      ▼
Current Working Directory
      │
      │ Not found
      ▼
PATH entry #1
      │
      │ Not found
      ▼
PATH entry #2
      │
      ▼
...
```

---

# ⚠️ 15. Writable PATH Directories

This becomes interesting if a directory in the PATH is writable by your user.

For example:

```text
PATH =
C:\CustomTools;
C:\Windows\System32;
C:\Windows;
```

If:

```text
C:\CustomTools
```

is writable by a low-privileged user, it may create security risks.

The source specifically mentions that a writable PATH directory can potentially enable **DLL injection** against other applications.

### ⭐ Very important

A custom PATH directory located **before**:

```text
C:\Windows\System32
```

is potentially more interesting than one placed later in the PATH.

---

# 🏠 16. `HOMEDRIVE` and `HOMEPATH`

The `set` command can reveal additional useful information.

For example:

```text
HOMEDRIVE=C:
HOMEPATH=\Users\Administrator
```

In enterprise environments, a user's home drive may point to a **file share**.

That share could contain:

- Directories
    
- Scripts
    
- Documents
    
- Inventory files
    
- Credentials
    

The source even gives an example of an IT directory containing an inventory spreadsheet with passwords.

---

# 🚨 17. Startup Folder & Roaming Profiles

This is a very interesting concept.

The source explains that users may have roaming profiles or home directories.

A malicious item placed in:

```text
USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup
```

could execute when that user logs into another machine.

### Concept

```text
User Profile
     │
     ▼
Roaming / Shared Profile
     │
     ▼
Startup Folder
     │
     ▼
User logs into another machine
     │
     ▼
Startup item executes
```

This demonstrates how **local filesystem findings can potentially become relevant to other machines**.

---

# 🖥️ 18. `systeminfo`

One of the most important commands in this section:

```cmd
systeminfo
```

The source uses it to gather:

- OS information
    
- Build
    
- Patch information
    
- Hardware
    
- Boot time
    
- Installed hotfixes
    
- Network cards
    
- Domain/workgroup information
    
- Virtualization information
    

---

# 🔥 19. Why Is `systeminfo` So Important?

The output can help determine whether the system is:

### Old / unpatched

which may indicate possible known vulnerabilities.

### Virtualized

which helps understand the environment.

### Recently patched

which can eliminate certain vulnerability paths.

### Dual-homed

which may reveal multiple network paths.

---

# 📋 20. Reading the Example `systeminfo`

The example reports:

```text
OS Name:
Microsoft Windows Server 2016 Standard

OS Version:
10.0.14393 N/A Build 14393

System Manufacturer:
VMware, Inc.

System Type:
x64-based PC

Domain:
WORKGROUP

Hotfix(s):
3 Hotfix(s) Installed

Network Card(s):
2 NIC(s) Installed
```

### 🚨 Notice something important

It has:

```text
2 NIC(s) Installed
```

with:

```text
10.129.43.8
192.168.20.56
```

That reinforces our earlier discovery of a **dual-homed machine**.

---

# 🔄 21. System Boot Time

The source suggests looking at:

```text
System Boot Time
```

and the OS version when assessing patch level.

The reasoning presented is that if a machine hasn't restarted for a very long period, it may also not have been patched recently.

### Important nuance

Don't treat this as proof.

```text
Old boot time
    ≠
Definitely unpatched
```

It's simply an **indicator worth investigating**.

---

# 🔧 22. Checking Patches — `wmic qfe`

If `systeminfo` doesn't provide sufficient hotfix information, the source shows:

```cmd
wmic qfe
```

This displays installed Windows updates/hotfixes.

Example:

```text
HotFixID
KB3199986
KB5001078
KB4103723
```

---

# 🟦 23. PowerShell — `Get-HotFix`

The PowerShell equivalent shown is:

```powershell
Get-HotFix | ft -AutoSize
```

### Remember:

```text
CMD:
wmic qfe

PowerShell:
Get-HotFix
```

Both can help enumerate installed patches.

---

# 🧩 24. Patch Enumeration Methodology

Think:

```text
systeminfo
    ↓
OS Version / Build
    ↓
Hotfixes
    ↓
Identify Missing Updates
    ↓
Research Applicable Vulnerabilities
    ↓
Determine Whether an Escalation Path Exists
```

The source specifically describes using installed KB information to understand when the system was patched and identify potential vulnerabilities.

---

# 📦 25. Installed Programs

Installed software can reveal additional attack paths.

The source explains that WMI can be used to display installed software and that this information can help identify difficult-to-find exploits.

Example:

```cmd
wmic product get name
```

---

# 🔍 26. What Should You Look For?

Suppose you find:

```text
FileZilla
PuTTY
Java
SQL Server
VMware Tools
```

Don't immediately assume they're vulnerable.

Instead:

```text
Installed Software
       ↓
Identify Version
       ↓
Check Configuration
       ↓
Check Credentials
       ↓
Check Services
       ↓
Research Vulnerabilities
```

The source specifically mentions that software may also be installed and running as a service that could be vulnerable.

---

# 🟪 27. PowerShell — Installed Programs

The source also provides:

```powershell
Get-WmiObject -Class Win32_Product | select Name, Version
```

This can display installed software along with versions.

Example from the source includes:

```text
SQL Server 2016
Java 8
Microsoft OLE DB Driver
SQL Server Management Studio
```

This could immediately give you areas to investigate.

---

# 🌐 28. `netstat -ano`

Another extremely important command:

```cmd
netstat -ano
```

The source explains that `netstat` displays active TCP/UDP connections and helps identify services listening on ports.

Example:

```text
TCP  0.0.0.0:21     LISTENING
TCP  0.0.0.0:80     LISTENING
TCP  0.0.0.0:135    LISTENING
TCP  0.0.0.0:445    LISTENING
TCP  0.0.0.0:1433   LISTENING
TCP  0.0.0.0:3389   LISTENING
```

---

# 🔥 29. Why `netstat -ano` Matters

The `-o` option gives you the **PID** associated with the connection.

So you can connect:

```text
PORT
 ↓
PID
 ↓
PROCESS
 ↓
SERVICE
```

For example:

```text
1433
 ↓
PID 3520
 ↓
SQL Server process
 ↓
Investigate SQL Server
```

### ⭐ CPTS habit

Don't just look at:

> "Port 1433 is open."

Ask:

> **What process owns that port?**

---

# 👥 30. User & Group Information

The source describes users as potentially being the **weakest link** in an organization.

You need to understand:

- Current user
    
- Other users
    
- Groups
    
- Privileges
    
- Logged-in users
    
- Password policy
    
- Administrative group membership
    

---

# 👤 31. Logged-In Users

Command:

```cmd
query user
```

Example:

```text
USERNAME       SESSIONNAME    ID   STATE
administrator  rdp-tcp#2      1    Active
```

This tells you:

- Username
    
- Session
    
- Session ID
    
- Whether active/idle
    
- Logon time
    

---

# ⚠️ 32. Why Are Logged-In Users Interesting?

You might discover:

```text
Administrator
IT Admin
Domain Admin
Helpdesk
```

actively logged in.

This doesn't automatically mean you should interact with them.

But it gives you **situational awareness**.

The source notes that user-targeting can be more challenging and that during an evasive engagement you need to be especially careful around actively working users to avoid detection.

---

# 👤 33. Current User

One of the **first commands you should run** after obtaining a shell:

```cmd
echo %USERNAME%
```

Example:

```text
C:\htb> echo %USERNAME%

htb-student
```

But don't stop there.

The real question is:

> **What privileges does this user have?**

---

# 🔐 34. Current User Privileges

Command:

```cmd
whoami /priv
```

Example:

```text
Privilege Name
----------------------------
SeChangeNotifyPrivilege
SeIncreaseWorkingSetPrivilege
```

with states such as:

```text
Enabled
Disabled
```

---

# ⭐ 35. Why `whoami /priv` Is Important

A user's privileges can provide **direct escalation opportunities**.

A particularly important example from the broader material is:

```text
SeImpersonatePrivilege
```

If you're operating as a service account and discover certain powerful privileges, you should investigate whether they provide an escalation path.

### CPTS rule:

```text
whoami
   ↓
whoami /priv
   ↓
whoami /groups
```

Make this a habit.

---

# 👥 36. Current User Groups

Command:

```cmd
whoami /groups
```

This tells you what groups the current user belongs to.

Example groups include:

```text
Everyone
BUILTIN\Remote Desktop Users
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\INTERACTIVE
```

---

# 🔥 37. Why Group Membership Matters

A user's permissions may come from **group membership**.

For example:

```text
User
  ↓
Member of Group
  ↓
Group has special permissions
  ↓
User inherits those rights
```

The source specifically asks whether the user has inherited rights through group membership or has privileges in the Active Directory environment that could provide access to additional systems.

---

# 👥 38. Get All Local Users

Command:

```cmd
net user
```

Example:

```text
Administrator
DefaultAccount
Guest
helpdesk
htb-student
jordan
sarah
secsvc
```

### Why enumerate users?

A user may have:

- Interesting files
    
- Credentials
    
- SSH keys
    
- Scripts
    
- Administrative privileges
    
- Reused passwords
    

The source specifically recommends checking user profile directories for valuable files such as passwords or SSH keys.

---

# 👥 39. Get All Local Groups

Command:

```cmd
net localgroup
```

Example groups:

```text
Administrators
Backup Operators
Hyper-V Administrators
Network Configuration Operators
Power Users
Print Operators
Remote Desktop Users
Remote Management Users
Users
```

---

# 🚨 40. Why Non-Standard Groups Matter

The source says non-standard groups can help reveal:

- What the host is used for
    
- How heavily accessed it is
    
- Potential misconfigurations
    

For example, if **Domain Users** are incorrectly placed into:

```text
Remote Desktop Users
```

or:

```text
Administrators
```

that could be significant.

---

# 🔎 41. Enumerate Administrators Group

Command:

```cmd
net localgroup administrators
```

Example:

```text
Members

Administrator
helpdesk
sarah
secsvc
```

This is **high-value information**.

You immediately know which accounts have local administrative privileges.

---

# 💡 42. Think About Credential Reuse

Suppose:

```text
Current access:
bob
```

and you discover:

```text
bob_adm
```

in the Administrators group.

The source suggests investigating possible **credential reuse**.

Conceptually:

```text
Known User
   ↓
Related Admin Account
   ↓
Credential Reuse?
   ↓
Potential Higher Privileges
```

Again, in an authorized assessment, validate only within scope.

---

# 🔑 43. Password Policy

Command:

```cmd
net accounts
```

The example shows:

```text
Minimum password age:       0
Maximum password age:       42
Minimum password length:    0
Password history:           None
Lockout threshold:          Never
Lockout duration:           30
```

### 🚨 Interesting observations

A weak password policy may include:

```text
Minimum password length = 0
No password history
No lockout threshold
```

The source provides these values as an example from the lab environment. Don't assume the same configuration exists elsewhere.

---

# 🧠 44. Complete Initial Enumeration Workflow

Now let's combine everything.

![Image](https://images.openai.com/static-rsc-4/Wo-wohqNlT6poRWnyRtMNvKBKEGQ3rA4ZPDF-y-0zgoAAaVx7o7RQQStnRAv0-wvYlIRBRVEyaBh7A7cSgvF2eXinAxx9Ee25bDO7TB7vdxBBZSgSqz_jcsOEfG3hJAdzmdByYHV5DS08yt1lnJaAmn1Q8E4yHuArkvCNtR9_soLnEKVYoDRzV9r6Uwd6_7C?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4bBrQUhcMjny7ubwkPAz7Gq0GuIRRe1evDopVBv5CTLhgmGqnPvU9_yeH84-TKDrmoTnHhdEkqX45vIOX5_hXocgwlsYgAalgiRsFnecSV2dhbZ2dEDkt2qeW2-T8b_HemH7TNSwhd4opx7mKeEn_6fDBmEITZjLxrtxhWjgQwhwzH3XhQBjT_C_VSO_Uah9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QYmi-rmqykLMREWqsQ2E11kqDBgJMq0CiWxQEtbpKMYKwV5R8AgsOCKY7OhtwLdQtAqSaxp-FYCyjZk6TqEZ1V1TzDIk7MOyGPGk_pULeScirNruz0p1P3OAAOwlYvlDGtCBwriMNZASN4r20XOjbGWy4-8TUhea3YdWIYuO0DEBhaQ7qRVEV9iH3QPtmG2Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_zxx9NYv1wv9XHND7PwmHm0PvJs8xZrng4q7h_aHqqAAMpqNlmma-rlsPgJ5Ia3_Qa-eYDuDqDYZypUoJqTLWokucJ4QcT9PwE9mIdu4XKnEAC27k2iaO7kRkQoEGV4CNHKXlYUzM4q4Xnsmkq2SdQA-hbiZVXgwitfdeQT4YRC7l2hYxSFmRts1Rqft68vI?purpose=fullsize)

```text
                    INITIAL ACCESS
                         │
                         ▼
                  WHO AM I?
                         │
                         ▼
              echo %USERNAME%
                         │
                         ▼
               SYSTEM INFORMATION
                         │
                  systeminfo
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
       NETWORK         PATCHES       SOFTWARE
     ipconfig         wmic qfe       wmic product
     arp -a           Get-HotFix     Get-WmiObject
     route print
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                    PROCESSES
                    tasklist /svc
                         │
                         ▼
                     SERVICES
                         │
                         ▼
                      PORTS
                    netstat -ano
                         │
                         ▼
                 USER / GROUP INFO
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
      whoami /priv   whoami /groups   net user
                                          │
                                          ▼
                                  net localgroup
                                          │
                                          ▼
                              net localgroup administrators
                                          │
                                          ▼
                              net accounts
                                          │
                                          ▼
                              IDENTIFY ESCALATION PATH
```

---

# ⭐ 45. Your Windows Initial Enumeration Cheat Sheet

## 🖥️ Identity

```cmd
echo %USERNAME%
```

```cmd
whoami
```

---

## 🔐 Privileges

```cmd
whoami /priv
```

---

## 👥 Groups

```cmd
whoami /groups
```

---

## 👤 Users

```cmd
net user
```

---

## 👥 Groups on System

```cmd
net localgroup
```

---

## 👑 Administrators

```cmd
net localgroup administrators
```

---

## 🔑 Password Policy

```cmd
net accounts
```

---

## 🖥️ System Information

```cmd
systeminfo
```

---

## 🔧 Patches

```cmd
wmic qfe
```

PowerShell:

```powershell
Get-HotFix
```

---

## 📦 Installed Software

```cmd
wmic product get name
```

PowerShell:

```powershell
Get-WmiObject -Class Win32_Product | select Name, Version
```

---

## ⚙️ Processes + Services

```cmd
tasklist /svc
```

---

## 🌐 Network Connections

```cmd
netstat -ano
```

---

## 🌳 Environment Variables

```cmd
set
```

---

# 🧠 46. What You Should Look For

Don't just run commands.

For every command, know **what you're looking for**.

|Command|Question|
|---|---|
|`echo %USERNAME%`|**Who am I?**|
|`whoami /priv`|**What privileges do I have?**|
|`whoami /groups`|**What groups am I in?**|
|`net user`|**Who else has accounts?**|
|`net localgroup`|**What groups exist?**|
|`net localgroup administrators`|**Who is an administrator?**|
|`net accounts`|**What is the password policy?**|
|`systeminfo`|**What OS/build/patches/hardware?**|
|`wmic qfe`|**What patches are installed?**|
|`wmic product get name`|**What software exists?**|
|`tasklist /svc`|**What processes/services are running?**|
|`netstat -ano`|**What ports/connections exist?**|
|`set`|**What environment configuration exists?**|

---

# 🔥 47. CPTS — The Mental Model

When you get a shell, don't think:

> ❌ "Which exploit do I run?"

Think:

> ✅ **"What information can I collect that tells me which escalation path is realistic?"**

For example:

```text
systeminfo
    ↓
Windows Server 2016
    ↓
Old patches?
    ↓
Potential vulnerability

tasklist /svc
    ↓
Unusual service
    ↓
Runs as SYSTEM?
    ↓
Weak permissions?
    ↓
Potential service escalation

whoami /priv
    ↓
Interesting privilege?
    ↓
Potential privilege escalation

whoami /groups
    ↓
Interesting group?
    ↓
Inherited permissions?

net user
    ↓
Interesting account?
    ↓
Credential reuse?

netstat -ano
    ↓
Interesting local service?
    ↓
Investigate service

set
    ↓
Interesting PATH/share?
    ↓
Potential file/DLL attack path
```

---

# 📝 48. FINAL REVISION NOTES

### ⭐ The most important commands:

```cmd
systeminfo
```

**→ OS + build + patches + hardware + network**

```cmd
tasklist /svc
```

**→ Processes + associated services**

```cmd
set
```

**→ Environment variables + PATH + home directories**

```cmd
wmic qfe
```

**→ Installed Windows hotfixes**

```powershell
Get-HotFix
```

**→ PowerShell patch enumeration**

```cmd
wmic product get name
```

**→ Installed software**

```cmd
netstat -ano
```

**→ Listening ports + PID**

```cmd
query user
```

**→ Logged-in users**

```cmd
whoami /priv
```

**→ Current user's privileges**

```cmd
whoami /groups
```

**→ Current user's groups**

```cmd
net user
```

**→ Local user accounts**

```cmd
net localgroup
```

**→ Local groups**

```cmd
net localgroup administrators
```

**→ Local administrators**

```cmd
net accounts
```

**→ Password/account policy**

---

# 🏆 49. CPTS Golden Rule

> **Enumerate → Understand → Verify → Identify the Attack Path → Escalate**

Not:

> **Run tool → See red text → Run random exploit**

The source closes this section by emphasizing that the listed commands aren't exhaustive. Enumeration tools can make the process faster and more comprehensive, but you should **study the tools and their output and create your own command cheat sheet** so you can operate in environments where most or all enumeration must be performed manually.

**For your CPTS preparation, this is the section I'd memorize practically:** know what each command does, what output matters, and **why that output could lead to privilege escalation**.