## 1. 🎯 What Are We Trying to Escalate To?

After gaining a low-privileged shell, possible privilege targets include:

|Target|Why it matters|
|---|---|
|`NT AUTHORITY\SYSTEM`|Extremely privileged Windows account|
|Local `Administrator`|Full administrative access|
|Local user in `Administrators`|Same effective privileges as local Administrator|
|Domain user in local `Administrators`|Local administrative access|
|Domain Admin in local `Administrators`|Potentially extremely powerful AD access|

The exact target depends on the system configuration.

![Image](https://images.openai.com/static-rsc-4/skf73JECiBBiDqj0u8EoKv_QybZcyGbiSCKCx27iIVWiJpGyArXbTDqieEu4jI0qTVvsDbhyzUr--J_39P93BjkhCBxFQoki-wznRqp-9mASUiH5vfWKEMM9Yy8RGZ7NTvOqgTZyNdVb-bSLyju3pFMgliReHBklZPocFhdwjXogLHrvPQqbF7YYw4FgLIFi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QjbkN66FvmsSNa-9PyHp_68zTXKcj1wCvOK6pju3sMVf-vtexagU7j3wbqwp6_-TqMUY7hC0JFz5X264MCEWG0RjCYFGCx3Ox19ZUTHsxUB8PNw-FFRd3fJaYbWMEF1amnT4sXDATIbPZGm5T6ik-4nQWVqYdueNsEkKOcADnmbzqhfHpTKILfN9d4jf7Krv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/y75T5_hPKz02HYuUhRWbf5OqjmnQBRLSqoK48LcAP3nt5WiwowaSuzLsEYLhVsEaOs2NssVky29BZc9kBnbTZZ_jgUH-8ubu8IjBIUEXfPsTM59GcCNfW9weFHiF5Tjjflyu_fkb9cnteAmA8t9bYU47q94iltmvnJ6xBITB3igsx0jCoJQJFTM2WsXWFSmI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QYmi-rmqykLMREWqsQ2E11kqDBgJMq0CiWxQEtbpKMYKwV5R8AgsOCKY7OhtwLdQtAqSaxp-FYCyjZk6TqEZ1V1TzDIk7MOyGPGk_pULeScirNruz0p1P3OAAOwlYvlDGtCBwriMNZASN4r20XOjbGWy4-8TUhea3YdWIYuO0DEBhaQ7qRVEV9iH3QPtmG2Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Fe-dlErfMUo3uJphYPw3wXiLWuJA19t6U3RPpTNNXrf45ZjS4bUEVdBoKb9VvJbj4-sl3K-ld81LoOd_VmODq6EzVFlZ3aDu61zNzoNu-t9SFwrWYiHycxHy2cAT7Y1UHpW8qXOqwAtm0SnXy0p5-VxJhwmB-lyr4BTsr12_Gy_9OQJSUF7im_vkI7xFBf_7?purpose=fullsize)

---

# 2. 🧠 Enumeration Mindset

Don't immediately start throwing exploits at the machine.

First answer:

### System

- What Windows version?
    
- What build?
    
- Server or workstation?
    
- Is it a VM?
    
- When was it last rebooted?
    
- What patches are installed?
    

### Applications

- What software is installed?
    
- What services are running?
    
- What versions are they?
    
- Are any unusual services running?
    

### Network

- What ports are listening?
    
- Which services are bound to those ports?
    
- Is there a locally accessible service that isn't exposed externally?
    

### User

- Who am I?
    
- What privileges do I have?
    
- What groups am I in?
    
- Who else is logged in?
    
- Who are the local users?
    
- Which users are administrators?
    

### Security

- Is Windows Defender running?
    
- What security controls are present?
    
- Are there application restrictions?
    

This is why the module emphasizes learning **manual enumeration**, because enumeration scripts may not always be usable due to network restrictions, lack of Internet access, or security protections.

---

# 3. 🖥️ OS Name & Version

Knowing the OS is important because:

- Different Windows versions have different vulnerabilities.
    
- Available PowerShell versions can differ.
    
- Legacy systems may expose older attack paths.
    
- Public exploits may target specific Windows versions/builds.
    

For example:

```text
Windows 7
Windows 10
Windows Server 2008
Windows Server 2012
Windows Server 2016
Windows Server 2019
```

The source specifically warns that Windows exploits can cause instability or crashes, especially on production systems.

### CPTS mindset

Don't just record:

```text
Windows Server 2016
```

Record:

```text
OS       → Windows Server 2016 Standard
Version  → 10.0.14393
Build    → 14393
Arch     → x64
```

Then correlate the build/patch information with potential vulnerabilities.

---

# 4. ⚙️ Enumerating Running Processes

A very useful command:

```cmd
tasklist /svc
```

It displays:

- Process name
    
- PID
    
- Associated services
    

Example from the lab:

```text
System
smss.exe
csrss.exe
winlogon.exe
lsass.exe
svchost.exe
spoolsv.exe
FileZilla Server.exe
inetinfo.exe
MsMpEng.exe
```

---

## 🔎 Learn the Standard Processes

You should become comfortable recognizing common Windows processes:

```text
smss.exe       → Session Manager
csrss.exe      → Client Server Runtime
winlogon.exe   → Windows logon process
lsass.exe      → Local Security Authority
svchost.exe    → Service Host
services.exe   → Service Control Manager
```

The important enumeration principle is:

> **Recognize normal processes quickly so you can focus on unusual ones.**

---

# 5. 🚨 Non-Standard Services = Interesting

In the example, notice:

```text
FileZilla Server.exe
```

This immediately deserves investigation.

Questions to ask:

```text
What version?
What service account?
What configuration?
Is authentication required?
Is anonymous FTP enabled?
Are there known vulnerabilities?
Where is the configuration stored?
```

The source specifically uses FileZilla as an example of a service worth investigating for version information and possible misconfigurations such as anonymous FTP access.

### Important mindset

Don't think:

```text
"I found FileZilla → exploit it."
```

Think:

```text
FileZilla
   ↓
Version
   ↓
Configuration
   ↓
Privileges/service account
   ↓
Misconfiguration/vulnerability
   ↓
Possible privilege escalation
```

---

# 6. 🛡️ Identify Security Software

Another interesting process:

```text
MsMpEng.exe
```

This is associated with **Windows Defender**.

Why care?

Because knowing what protections are present helps you understand the security environment and what restrictions may affect your enumeration or subsequent testing.

---

# 7. 🌎 Environment Variables

Command:

```cmd
set
```

This displays environment variables.

Important variables include:

```text
PATH
HOMEDRIVE
HOMEPATH
USERPROFILE
USERNAME
USERDOMAIN
TEMP
TMP
ProgramFiles
SystemRoot
```

---

# 8. 🔥 PATH — Very Important for CPTS

This is one of the most important concepts in this section.

Example:

```text
Path=C:\Windows\system32;
C:\Windows;
C:\Windows\System32\Wbem;
C:\Windows\System32\WindowsPowerShell\v1.0\;
...
```

When Windows searches for a program, it generally checks:

```text
1. Current Working Directory
          ↓
2. PATH directories
          ↓
3. PATH searched from left → right
```

So imagine:

```text
PATH=
C:\Users\Public\Tools;
C:\Windows\System32;
```

If:

```text
C:\Users\Public\Tools
```

is writable by your user, this could become interesting.

The source specifically notes that a writable directory in the PATH can create opportunities involving DLL injection, and that a custom path appearing before `C:\Windows\System32` is more dangerous.

### CPTS exam takeaway

Whenever you see:

```text
PATH
```

ask:

> **Can I write to any directory in PATH?**

---

# 9. 🏠 HOMEDRIVE / HOMEPATH

Look for:

```text
HOMEDRIVE
HOMEPATH
```

Example:

```text
HOMEDRIVE=C:
HOMEPATH=\Users\Administrator
```

In enterprise environments, a home drive can point to a network share.

That can expose:

- Shared directories
    
- IT directories
    
- Documents
    
- Scripts
    
- Inventory files
    
- Potentially credentials
    

The source specifically mentions the possibility of finding an IT directory containing an inventory spreadsheet with passwords.

---

# 10. 🚨 Startup Folder + Roaming Profiles

The source highlights another interesting location:

```text
USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup
```

If a malicious file is placed there and the profile roams to another machine, it may execute when the user logs in.

### Remember

```text
Roaming Profile
      ↓
User logs into another machine
      ↓
Profile/files follow user
      ↓
Startup location may execute content
```

This is an **environment/configuration-dependent** attack path, not something to assume will always work.

---

# 11. 🖥️ `systeminfo`

Command:

```cmd
systeminfo
```

This is one of your **must-know Windows enumeration commands**.

It can provide:

- Hostname
    
- OS name
    
- OS version
    
- Build
    
- Architecture
    
- Manufacturer
    
- Model
    
- Boot time
    
- Installed hotfixes
    
- Memory
    
- Domain/workgroup
    
- Network adapters
    
- IP addresses
    
- Virtualization information
    

Example:

```text
OS Name:        Microsoft Windows Server 2016 Standard
OS Version:     10.0.14393
System Type:    x64-based PC
System Model:   VMware7,1
Domain:         WORKGROUP
```

The supplied example also has **two NICs**:

```text
Ethernet0 → 10.129.43.8
Ethernet1 → 192.168.20.56
```

That is something worth noticing because multiple network interfaces can indicate a machine connected to different networks.

![Image](https://images.openai.com/static-rsc-4/dN6CnPHldik9FIz8VHnc3d62Km9-rlesfmiLbsEV6qF97ZON08e7ID8k6EFDSgZE5gvS1NksIXeZky8TfHP_SKZI3ch5--JGOyWeIM98NUG1ZyqyyrEnLuE9IkUTyTpjcrPL8dFPrqDIQ1WN3qzAFr_O7Hrpd6klQAgzVY4xhyVdVtR4VfXEHU6W9zh1KAUg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/X-zjopgdirrbsyaaTeQQ3-NyUhqePmKdLaS5_V9nlGrpQjnHYcqog4tI8Viq7wbpy_SsVE60qyGhn5H6gizTXYgBGG6JDNJVxgRBjZYfzskQ4Raqc0lGbP8k0JliabicxEecx12aufqblyd8lbpf5euriKDUmntRE9kSIt_SbRDfDJK2qfe9veh351XT7r_O?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/glIerEH0XKQCBdQkSfmQyHGH5xGvmpz7BSKSCNuYjX0IDbECSDmdlzjlbUIfMkcmIoQfyyOhFo_v-ku9qwrWKk0Ji3HgDcqFY2x--LwfQBE304-mh7Lm8TWlntdC7GZIP9ysFpN8bWZPi7quu0Yx9cFIe7UmXhuHwTBFTWnmgADC7juOxxDxX4v9GDvYRHjm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/GTpI2a97IZQcpBtumFXFK4mtcqu-nwc45eHEfR-k1WCugfX0WkCI78YUKHPd1v3J4Fj2bV8IClDhcAUB-tc0cT_9gTWksPrRUTWjgIz_2b638QjqBsVQcEfO1Ao5XXaXEH99ue3ZmwAohf5jkoZb6BvVAZDiRNA25DrNtushBXnEJ5JL9eD6WXCROpcVlq8E?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/SkZr5341vLTBhcTN3cEuobZvPxITqiXAQEAb6ugk2iMKCmn2Kd6vUDaKQhXoq-lNplidOE8n9dpIrmrdgK_ln3dByWFp9IvVqZpY8-nGOlychFmRmT7Xv-dEdtC6wtqapBTdZqzWRsmNw_ZQeR5oHC4OgaRT2hHidq0UlWY8EVlNUlqYzK7XiXS4EDVGdUTy?purpose=fullsize)

---

# 12. 🔄 System Boot Time

Look at:

```text
System Boot Time
```

Why?

A machine that hasn't rebooted for a long time may not have been regularly patched.

The source notes that a system that hasn't restarted for many months **may** also have missed patches, but this is only an indicator—not proof.

---

# 13. 🩹 Patch Enumeration

First:

```cmd
systeminfo
```

If hotfix information isn't sufficient, use:

```cmd
wmic qfe
```

PowerShell:

```powershell
Get-HotFix | ft -AutoSize
```

### What are we looking for?

```text
Installed KBs
        ↓
Patch dates
        ↓
Missing security updates
        ↓
Potential vulnerable OS/software versions
        ↓
Research relevant CVEs
```

---

# 14. 📦 Installed Programs

Command:

```cmd
wmic product get name
```

PowerShell:

```powershell
Get-WmiObject -Class Win32_Product | select Name, Version
```

Look for:

```text
FileZilla
PuTTY
Java
SQL Server
VMware Tools
Old software
Custom applications
Security software
Development tools
```

The important information is:

```text
Application
Version
Configuration
Privileges
Known vulnerabilities
Stored credentials
```

The source notes that installed applications can lead to hard-to-find exploit paths and may also have stored credentials worth investigating.

---

# 15. 🌐 Network Connections — `netstat`

Command:

```cmd
netstat -ano
```

This gives:

```text
Proto
Local Address
Foreign Address
State
PID
```

Example:

```text
TCP    0.0.0.0:21       LISTENING    1096
TCP    0.0.0.0:80       LISTENING    4
TCP    0.0.0.0:135      LISTENING    840
TCP    0.0.0.0:445      LISTENING    4
TCP    0.0.0.0:1433     LISTENING    3520
TCP    0.0.0.0:3389     LISTENING    968
```

### Why `-ano`?

```text
-a → all connections/listening ports
-n → numerical addresses/ports
-o → owning process PID
```

The PID is particularly useful because you can correlate:

```text
Port 1433
   ↓
PID 3520
   ↓
Process/service
   ↓
Application/version
   ↓
Configuration
```

---

# 16. 👥 User Enumeration

Users can be an important part of privilege escalation.

Start with:

```cmd
query user
```

This shows currently logged-in users.

Example:

```text
USERNAME       SESSIONNAME    ID    STATE
administrator  rdp-tcp#2      1     Active
```

### Questions

```text
Who is logged in?
Is the user active?
Is the user idle?
What access does the user have?
Is this an interesting administrative account?
```

---

# 17. 👤 Who Am I?

Always check your current account.

```cmd
echo %USERNAME%
```

Example:

```text
htb-student
```

Also useful:

```cmd
whoami
```

and:

```cmd
whoami /priv
whoami /groups
```

---

# 18. 🔐 Current User Privileges

Command:

```cmd
whoami /priv
```

Example:

```text
Privilege Name                  State
------------------------------------------------
SeChangeNotifyPrivilege         Enabled
SeIncreaseWorkingSetPrivilege   Disabled
```

### Very important

Don't just look at the username.

A user called:

```text
svc-backup
```

might have interesting privileges.

A normal-looking user may have a powerful Windows privilege.

---

# 19. 🍯 `SeImpersonatePrivilege`

The source specifically highlights:

```text
SeImpersonatePrivilege
```

Service accounts may possess this privilege, and under appropriate conditions it can be abused for privilege escalation. The source gives **Juicy Potato** as an example tool.

For CPTS, remember:

```text
whoami /priv
       ↓
Look for interesting privileges
       ↓
Research privilege-specific escalation techniques
```

Don't automatically assume that possessing a privilege means exploitation is guaranteed; the exact OS/version/context matters.

---

# 20. 👥 Current User Groups

Command:

```cmd
whoami /groups
```

This tells you what groups your current account belongs to.

Example groups include:

```text
BUILTIN\Remote Desktop Users
BUILTIN\Users
NT AUTHORITY\Authenticated Users
...
```

### Why groups matter

Your privileges may come from **group membership**, not directly from the user account.

Think:

```text
User
 ↓
Group membership
 ↓
Inherited permissions
 ↓
Potential access
```

---

# 21. 📋 Enumerate All Users

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

Then investigate interesting accounts.

For example:

```text
helpdesk
secsvc
admin-like accounts
service accounts
```

Look for:

- User profiles
    
- Scripts
    
- Documents
    
- Desktop files
    
- Downloads
    
- SSH keys
    
- Configuration files
    
- Credential artifacts
    

The source specifically highlights the possibility of finding passwords or SSH keys in user directories.

---

# 22. 👥 Enumerate Local Groups

Command:

```cmd
net localgroup
```

Example groups:

```text
Administrators
Backup Operators
Certificate Service DCOM Access
Cryptographic Operators
Hyper-V Administrators
IIS_IUSRS
Network Configuration Operators
Power Users
Print Operators
Remote Desktop Users
Remote Management Users
...
```

### ⭐ CPTS Tip

Don't only look for:

```text
Administrators
```

Also investigate groups such as:

```text
Backup Operators
Print Operators
Server Operators
Remote Management Users
Hyper-V Administrators
Certificate-related groups
```

Their significance depends on the actual system configuration and permissions.

---

# 23. 🔥 Who Is in Administrators?

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

This is a **high-priority command**.

If you discover:

```text
helpdesk
sarah
secsvc
```

inside Administrators, investigate those accounts.

Why?

Because a seemingly ordinary account may have administrative privileges through group membership.

---

# 24. 🔑 Password Policy

Command:

```cmd
net accounts
```

Example:

```text
Minimum password age:              0
Maximum password age:              42
Minimum password length:            0
Password history:                  None
Lockout threshold:                 Never
Lockout duration:                  30
```

### What does this tell you?

It helps you understand the authentication environment.

For example:

```text
Minimum password length = 0
```

is obviously weak configuration.

And:

```text
Lockout threshold = Never
```

means the example system doesn't enforce account lockout after failed attempts.

**However:** whether and how to perform authentication testing depends on the engagement scope and rules.

---

# 🧠 The CPTS Enumeration Flow

Memorize this:

```text
LOW-PRIV SHELL
      │
      ▼
┌─────────────────┐
│ WHO AM I?       │
│ whoami          │
│ whoami /priv    │
│ whoami /groups  │
└────────┬────────┘
         ▼
┌─────────────────┐
│ SYSTEM INFO     │
│ systeminfo      │
│ tasklist /svc   │
└────────┬────────┘
         ▼
┌─────────────────┐
│ PATCHES         │
│ wmic qfe        │
│ Get-HotFix      │
└────────┬────────┘
         ▼
┌─────────────────┐
│ SOFTWARE        │
│ wmic product    │
│ Get-WmiObject   │
└────────┬────────┘
         ▼
┌─────────────────┐
│ NETWORK         │
│ netstat -ano    │
└────────┬────────┘
         ▼
┌─────────────────┐
│ USERS           │
│ net user        │
│ query user      │
└────────┬────────┘
         ▼
┌─────────────────┐
│ GROUPS          │
│ net localgroup  │
│ administrators   │
└────────┬────────┘
         ▼
┌─────────────────┐
│ ENVIRONMENT     │
│ set             │
│ PATH            │
│ HOME            │
└────────┬────────┘
         ▼
    FIND ATTACK PATH
         │
         ▼
 PRIVILEGE ESCALATION
```

---

# 📝 CPTS Must-Know Command Sheet

|Purpose|Command|
|---|---|
|Current username|`echo %USERNAME%`|
|Current identity|`whoami`|
|User privileges|`whoami /priv`|
|User groups|`whoami /groups`|
|Logged-in users|`query user`|
|All users|`net user`|
|All local groups|`net localgroup`|
|Administrators|`net localgroup administrators`|
|Password policy|`net accounts`|
|Processes + services|`tasklist /svc`|
|System information|`systeminfo`|
|Patches|`wmic qfe`|
|PowerShell patches|`Get-HotFix`|
|Installed programs|`wmic product get name`|
|Installed programs + versions|`Get-WmiObject -Class Win32_Product \| select Name, Version`|
|Network connections|`netstat -ano`|
|Environment variables|`set`|

---

# 🧪 How I'd Approach a CPTS Box

When you get a Windows shell, don't randomly run commands.

### Phase 1 — Identity

```cmd
whoami
echo %USERNAME%
whoami /priv
whoami /groups
```

### Phase 2 — Users

```cmd
query user
net user
net localgroup
net localgroup administrators
```

### Phase 3 — System

```cmd
systeminfo
tasklist /svc
```

### Phase 4 — Network

```cmd
ipconfig /all
netstat -ano
```

### Phase 5 — Software

```cmd
wmic product get name
```

### Phase 6 — Environment

```cmd
set
```

Then specifically inspect:

```text
PATH
HOMEDRIVE
HOMEPATH
USERPROFILE
TEMP
TMP
```

### Phase 7 — Patches

```cmd
wmic qfe
```

or:

```powershell
Get-HotFix
```

### Phase 8 — Build hypotheses

Now ask:

```text
What is unusual?
        ↓
Why is it unusual?
        ↓
What permissions does it have?
        ↓
Can my current user interact with it?
        ↓
Is there a misconfiguration?
        ↓
Is there a documented vulnerability?
        ↓
Can it lead to higher privileges?
```

That's the real skill behind Windows privilege escalation—not memorizing 500 commands.

---

## 🔥 Top 10 Things to Memorize for CPTS

```text
1. whoami
2. whoami /priv
3. whoami /groups
4. query user
5. net user
6. net localgroup
7. net localgroup administrators
8. systeminfo
9. tasklist /svc
10. netstat -ano
```

And don't forget:

```text
set
wmic qfe
Get-HotFix
wmic product get name
```

The module itself emphasizes building your own manual Windows privilege-escalation cheat sheet because you may encounter environments where automated enumeration tools cannot be used.

### 🎯 One-line CPTS memory trick

**IDENTITY → PRIVILEGES → GROUPS → USERS → SYSTEM → SERVICES → SOFTWARE → PATCHES → NETWORK → ENVIRONMENT → ATTACK PATH**

This is the sequence I recommend you internalize rather than simply memorizing commands.