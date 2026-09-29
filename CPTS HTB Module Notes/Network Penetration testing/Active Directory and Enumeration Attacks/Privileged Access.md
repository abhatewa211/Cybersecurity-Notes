## 1. Overview

Once we gain a foothold in the domain, our goal shifts to advancing our position further by:

- Moving **laterally** to other hosts.
    
- Moving **vertically** to obtain higher privileges.
    
- Eventually achieving **domain compromise** or another assessment objective.
    

One common method is **Pass-the-Hash**.

If we take over an account with **local administrator rights** over one or more hosts, we can use a `Pass-the-Hash` attack to authenticate through the **SMB protocol**.

> **Important:** Local administrator access is not the only way to move around a Windows domain.

---

# 2. Other Lateral Movement Methods

If we do not have local administrator rights on any hosts, several other forms of remote access may still be available.

### Main methods

|Method|Description|
|---|---|
|**RDP**|Remote Desktop Protocol provides GUI access to a target host.|
|**PowerShell Remoting / WinRM**|Allows commands or interactive PowerShell sessions on a remote host.|
|**MSSQL Server**|An account with `sysadmin` privileges can remotely access SQL Server and potentially execute operating-system commands through the SQL Server service account.|

---

# 3. Enumerating Remote Access with BloodHound

BloodHound can help identify remote access privileges.

Important BloodHound edges:

- `CanRDP`
    
- `CanPSRemote`
    
- `SQLAdmin`
    

These relationships help identify which users/groups can remotely access which computers.

Other tools can also enumerate these privileges, including:

- PowerView
    
- Built-in Windows tools
    

---

# 4. Scenario Setup

The module works between:

- A **Windows attack host**
    
- A **Linux attack host**
    

The Windows attack host is:

`MS01`

For Linux-based portions involving:

- `mssqlclient.py`
    
- `evil-winrm`
    

a PowerShell console on MS01 can be used to SSH to:

`172.16.5.225`

Credentials used in the lab:

```text
Username: htb-student
Password: HTB_@cademy_stdnt!
```

The module recommends practicing all demonstrated methods:

- `Enter-PSSession`
    
- `PowerUpSQL`
    
- `evil-winrm`
    
- `mssqlclient.py`
    

---

# 5. Remote Desktop Protocol (RDP)

## What is RDP?

**Remote Desktop Protocol (RDP)** provides graphical remote access to Windows systems.

Normally, if we control a local administrator account on a machine, we may be able to access it through RDP.

However, an important situation is:

> We may obtain a foothold with a user who does **not** have local administrator rights anywhere, but who does have permission to RDP into one or more machines.

This access can still be extremely useful.

### Why RDP access matters

Once we obtain RDP access, we may be able to:

1. Launch further attacks.
    
2. Escalate privileges.
    
3. Obtain credentials belonging to higher-privileged users.
    
4. Search the host for sensitive information.
    
5. Discover credentials or other secrets.
    
6. Find a local privilege-escalation path.
    

---

# 6. Enumerating the Remote Desktop Users Group

PowerView can be used to enumerate members of the:

```text
Remote Desktop Users
```

group.

### Command

```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

### Example output

```text
ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN
```

### Important observation

The output shows:

```text
INLANEFREIGHT\Domain Users
```

as a member of the `Remote Desktop Users` group.

This means that **all Domain Users** can RDP to this host.

This type of configuration can commonly be found on:

- Remote Desktop Services (RDS) hosts
    
- Jump hosts
    

---

# 7. Why Domain Users → RDP Is Important

A server allowing all domain users to RDP can become an interesting target.

Because the server may be heavily used, it could contain:

- Credentials
    
- Sensitive files
    
- Configuration information
    
- Cached information
    
- Passwords
    
- Other secrets
    

We may also find a **local privilege escalation** vulnerability.

This could allow us to:

```text
Low-privileged domain user
        ↓
RDP access
        ↓
Access target host
        ↓
Local privilege escalation
        ↓
Local Administrator
        ↓
Credential theft
        ↓
Higher-privileged account
```

### Key BloodHound question

After importing BloodHound data, one of the first things to check is:

> Does the `Domain Users` group have local administrator rights or execution rights such as RDP or WinRM over one or more hosts?

---

# 8. BloodHound — Checking RDP Rights

BloodHound can visualize relationships such as:

```text
DOMAIN USERS
     |
     | CanRDP
     ↓
ACADEMY-EA-MS01
```

The `CanRDP` relationship indicates that the user/group has RDP access to the computer.

If we compromise a user through attacks such as:

- LLMNR/NBT-NS Response Spoofing
    
- Kerberoasting
    

we can search for that username in BloodHound.

Then inspect the user's:

```text
Execution Rights
```

to determine whether they have remote access directly or through group membership.

---

# 9. BloodHound Analysis Queries

BloodHound provides pre-built queries that can quickly identify this type of access.

Examples:

```text
Find Workstations where Domain Users can RDP
```

and:

```text
Find Servers where Domain Users can RDP
```

BloodHound is useful because it helps penetration testers quickly identify remote access rights in large environments.

It can also help defenders audit:

- Unintended RDP access
    
- Excessive Domain Users permissions
    
- Remote access granted to groups
    
- Specific users with unexpected access
    

---

# 10. Testing RDP Access

From a Linux/Pwnbox environment, possible RDP clients include:

```text
xfreerdp
```

or:

```text
Remmina
```

From Windows:

```text
mstsc.exe
```

---

# 11. WinRM / PowerShell Remoting

## What is WinRM?

**Windows Remote Management (WinRM)** allows remote command execution and PowerShell sessions.

Like RDP, WinRM access may be granted to:

- A specific user
    
- A group
    
- Multiple users
    

The access does **not necessarily mean local administrator access**.

Even low-privileged WinRM access can be valuable because it may allow us to:

- Search for sensitive information.
    
- Hunt for credentials.
    
- Perform local enumeration.
    
- Find privilege-escalation opportunities.
    
- Potentially obtain local administrator access.
    

---

# 12. Remote Management Users Group

PowerView can enumerate the:

```text
Remote Management Users
```

group.

This group has existed since:

- Windows 8
    
- Windows Server 2012
    

It allows WinRM access without necessarily granting local administrator privileges.

### Command

```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```

### Example output

```text
ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```

This tells us that:

```text
INLANEFREIGHT\forend
```

has membership in the `Remote Management Users` group.

Therefore, the account may have WinRM/PowerShell Remoting access to the host.

---

# 13. BloodHound — Finding WinRM Access

A custom Cypher query can be used to identify users with `CanPSRemote` access.

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

### What the query does

It identifies:

```text
User
 ↓
Group membership
 ↓
Computer
```

where the user has:

```text
CanPSRemote
```

access.

---

# 14. Adding Custom Queries to BloodHound

If a Cypher query is useful repeatedly, it can be added as a custom query in BloodHound.

This is useful during assessments because frequently used searches can be saved and reused.

---

# 15. Establishing a WinRM Session from Windows

PowerShell's:

```powershell
Enter-PSSession
```

can establish an interactive remote PowerShell session.

### Example

```powershell
$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```

After connecting:

```powershell
[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-MS01
```

To terminate the session:

```powershell
Exit-PSSession
```

### Basic workflow

```text
Create secure password
        ↓
Create PSCredential object
        ↓
Enter-PSSession
        ↓
Remote PowerShell session
        ↓
Perform enumeration
        ↓
Exit-PSSession
```

---

# 16. Evil-WinRM

From a Linux attack host, we can use:

```text
evil-winrm
```

to connect to a Windows system through WinRM.

## Installing Evil-WinRM

```bash
gem install evil-winrm
```

---

# 17. Evil-WinRM Help

Running:

```bash
evil-winrm
```

without required parameters displays the help menu.

Important syntax:

```text
evil-winrm -i IP -u USER
```

### Important options

|Option|Meaning|
|---|---|
|`-i`|Remote IP/hostname|
|`-u`|Username|
|`-p`|Password|
|`-H`|NT hash|
|`-P`|Port|
|`-S`|Enable SSL|
|`-r`|Kerberos realm|
|`-s`|PowerShell scripts path|
|`-e`|Executables path|
|`-l`|Log the WinRM session|
|`-k`|Private key|
|`-c`|Public key certificate|
|`-U`|Remote URL|
|`-h`|Help|

Default WinRM port:

```text
5985
```

---

# 18. Connecting with Evil-WinRM

Example:

```bash
evil-winrm -i 10.129.201.234 -u forend
```

The tool then prompts for the password.

After successful authentication:

```text
*Evil-WinRM* PS C:\Users\forend.INLANEFREIGHT\Documents> hostname
ACADEMY-EA-MS01
```

This confirms that we have obtained a remote PowerShell session.

---

# 19. Why WinRM Access Is Valuable

Once connected through WinRM, we can begin host enumeration.

Possible objectives include:

- Identify the current user.
    
- Enumerate privileges.
    
- Search for credentials.
    
- Search for sensitive files.
    
- Enumerate services.
    
- Identify privilege escalation opportunities.
    
- Determine the next lateral movement path.
    

---

# 20. SQL Server Admin / MSSQL

SQL servers are commonly encountered during internal penetration tests.

It is common to find:

- User accounts
    
- Service accounts
    

with:

```text
sysadmin
```

privileges on SQL Server instances.

---

# 21. How SQL Credentials May Be Obtained

Credentials for SQL accounts may be obtained through several attacks, including:

- Kerberoasting
    
- LLMNR/NBT-NS Response Spoofing
    
- Password spraying
    

Another source is configuration files.

For example:

```text
web.config
```

or other application configuration files may contain SQL Server connection strings.

### Snaffler

The module mentions:

```text
Snaffler
```

as a tool that can search for configuration files containing SQL Server connection strings.

---

# 22. BloodHound SQLAdmin Edge

BloodHound has an:

```text
SQLAdmin
```

edge.

This can show users who have SQL administrator privileges over a computer.

The Node Info tab can show:

```text
SQL Admin Rights
```

---

# 23. BloodHound SQLAdmin Cypher Query

The following custom Cypher query can be used:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

The query identifies users with:

```text
SQLAdmin
```

rights over computers.

Example from the module:

```text
damundsen
     |
     | SQLAdmin
     ↓
ACADEMY-EA-DB01
```

---

# 24. PowerUpSQL

`PowerUpSQL` can be used to enumerate SQL Server instances and interact with MSSQL.

The module demonstrates using ACL rights to authenticate as the `wley` user, change the password of the `damundsen` user, and then authenticate to the target.

Example assumed password:

```text
SQL1234!
```

---

# 25. Enumerating MSSQL Instances

First navigate to PowerUpSQL:

```powershell
cd .\PowerUpSQL\
```

Import the module:

```powershell
Import-Module .\PowerUpSQL.ps1
```

Enumerate domain SQL instances:

```powershell
Get-SQLInstanceDomain
```

### Example output

```text
ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```

### Important information

The output provides:

- SQL server hostname
    
- SQL instance
    
- Port
    
- Domain account
    
- Service
    
- SPN
    
- Last logon
    

Default MSSQL port shown:

```text
1433
```

---

# 26. Running SQL Queries with PowerUpSQL

Once authenticated, we can execute SQL queries.

Example:

```powershell
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

Example result:

```text
VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```

This confirms successful SQL Server connectivity.

---

# 27. MSSQL from Linux — mssqlclient.py

From a Linux attack host, we can use:

```text
mssqlclient.py
```

from the **Impacket** toolkit.

Running:

```bash
mssqlclient.py
```

displays its options.

Basic target format:

```text
[[domain/]username[:password]@]<targetName or address>
```

Important options include:

```text
-port
-db
-windows-auth
-debug
-file
-hashes
-no-pass
-k
-aesKey
-dc-ip
```

---

# 28. Connecting to MSSQL with mssqlclient.py

Example:

```bash
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```

Then enter the password.

Successful connection output includes:

```text
[*] Encryption required, switching to TLS
```

and:

```text
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS)
```

The SQL shell is then available.

---

# 29. mssqlclient.py Help

After connecting:

```text
SQL> help
```

Important commands include:

```text
lcd {path}
```

Changes the local directory.

```text
exit
```

Terminates the SQL session.

```text
enable_xp_cmdshell
```

Enables `xp_cmdshell`.

```text
disable_xp_cmdshell
```

Disables `xp_cmdshell`.

```text
xp_cmdshell {cmd}
```

Executes an operating-system command using `xp_cmdshell`.

```text
sp_start_job {cmd}
```

Executes a command using SQL Server Agent.

```text
! {cmd}
```

Executes a local shell command.

---

# 30. xp_cmdshell

`xp_cmdshell` is a SQL Server stored procedure that can execute operating-system commands.

The module demonstrates:

```text
enable_xp_cmdshell
```

Output:

```text
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185:
Configuration option 'show advanced options' changed from 0 to 1.
Run the RECONFIGURE statement to install.

[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185:
Configuration option 'xp_cmdshell' changed from 0 to 1.
Run the RECONFIGURE statement to install.
```

### Important concept

If the authenticated SQL account has the necessary permissions, `xp_cmdshell` allows commands to be executed in the context of the SQL Server service account.

Conceptually:

```text
SQL Authentication
       ↓
SQL Server
       ↓
xp_cmdshell
       ↓
Operating System Command
       ↓
SQL Server Service Account Context
```

---

# 31. Enumerating Windows Privileges Through xp_cmdshell

The module demonstrates:

```text
xp_cmdshell whoami /priv
```

The output shows the privileges of the account executing the operating-system command.

Important privileges from the example:

```text
SeAssignPrimaryTokenPrivilege
```

Description:

```text
Replace a process level token
```

State:

```text
Disabled
```

---

```text
SeIncreaseQuotaPrivilege
```

Description:

```text
Adjust memory quotas for a process
```

State:

```text
Disabled
```

---

```text
SeChangeNotifyPrivilege
```

Description:

```text
Bypass traverse checking
```

State:

```text
Enabled
```

---

```text
SeManageVolumePrivilege
```

Description:

```text
Perform volume maintenance tasks
```

State:

```text
Enabled
```

---

```text
SeImpersonatePrivilege
```

Description:

```text
Impersonate a client after authentication
```

State:

```text
Enabled
```

---

```text
SeCreateGlobalPrivilege
```

Description:

```text
Create global objects
```

State:

```text
Enabled
```

---

```text
SeIncreaseWorkingSetPrivilege
```

Description:

```text
Increase a process working set
```

State:

```text
Disabled
```

---

# 32. SeImpersonatePrivilege

One particularly important privilege shown in the module is:

```text
SeImpersonatePrivilege
```

The module explains that this privilege can potentially be leveraged with tools such as:

```text
JuicyPotato
PrintSpoofer
RoguePotato
```

depending on the target system.

The objective can be privilege escalation to:

```text
SYSTEM
```

This topic is covered more extensively in the:

```text
Windows Privilege Escalation
```

module, specifically the:

```text
SeImpersonate and SeAssignPrimaryToken
```

section.

---

# 33. Complete Lateral Movement Workflow

A useful mental model from this module is:

```text
Initial Domain Foothold
        │
        ▼
Enumerate User / Group Rights
        │
        ├───────────────┐
        ▼               ▼
      CanRDP       CanPSRemote
        │               │
        ▼               ▼
       RDP           WinRM
        │               │
        └───────┬───────┘
                ▼
          Enumerate Host
                │
                ▼
       Search for Credentials
                │
                ▼
        Privilege Escalation
                │
                ▼
       Additional Credentials
                │
                ▼
       Further Lateral Movement
```

Another possible path:

```text
SQL Credentials
      ↓
MSSQL Authentication
      ↓
SQLAdmin
      ↓
xp_cmdshell
      ↓
OS Command Execution
      ↓
whoami /priv
      ↓
SeImpersonatePrivilege
      ↓
Potential Privilege Escalation
```

---

# 34. Important BloodHound Edges to Remember

|Edge|Meaning|
|---|---|
|`CanRDP`|User/group can RDP to a computer|
|`CanPSRemote`|User/group can use PowerShell Remoting / WinRM|
|`SQLAdmin`|User has SQL administrator privileges|

### Memorize these three

```text
CanRDP       → RDP
CanPSRemote  → WinRM
SQLAdmin     → MSSQL
```

---

# 35. Important Commands Cheat Sheet

## RDP Group Enumeration

```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

## WinRM Group Enumeration

```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"
```

## WinRM — Windows

```powershell
Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred
```

Exit:

```powershell
Exit-PSSession
```

## Install Evil-WinRM

```bash
gem install evil-winrm
```

## Evil-WinRM

```bash
evil-winrm -i 10.129.201.234 -u forend
```

## PowerUpSQL

```powershell
Import-Module .\PowerUpSQL.ps1
```

Enumerate SQL instances:

```powershell
Get-SQLInstanceDomain
```

Run SQL query:

```powershell
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

## MSSQL from Linux

```bash
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```

## SQL Shell

```text
help
```

Enable `xp_cmdshell`:

```text
enable_xp_cmdshell
```

Execute Windows command:

```text
xp_cmdshell whoami /priv
```

---

# 36. Important BloodHound Cypher Queries

## Find CanPSRemote Access

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

## Find SQLAdmin Access

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

---

# 37. Key Lessons

### 1. Do not focus only on local administrator access.

A normal domain user may still have:

```text
RDP
WinRM
SQL
```

access to important hosts.

### 2. Always enumerate remote access rights.

After compromising an account, check:

```text
CanRDP
CanPSRemote
SQLAdmin
```

### 3. Remote access can become privilege escalation.

A low-privileged account may be able to access a machine containing:

- Credentials
    
- Sensitive files
    
- Configuration files
    
- Privileged user information
    

### 4. SQL credentials are valuable.

If SQL credentials are found in:

- Scripts
    
- `web.config`
    
- Connection strings
    
- Other configuration files
    

test whether they provide access to MSSQL servers in the environment.

### 5. Re-enumerate after every compromise.

This is one of the most important concepts in the module:

> **Enumerating and attacking is an iterative process.**

Whenever we gain control over:

- A new user
    
- A new host
    
- A new credential
    

we should repeat enumeration.

The new account or host may provide completely different access.

---

# 38. Final Module Takeaway

The module demonstrates several lateral movement techniques in an Active Directory environment.

The overall process is:

```text
Gain Foothold
     ↓
Enumerate
     ↓
Identify Remote Access
     ↓
RDP / WinRM / MSSQL
     ↓
Enumerate Target Host
     ↓
Find Sensitive Data / Credentials
     ↓
Privilege Escalation
     ↓
Obtain More Access
     ↓
Repeat Enumeration
```

**Never overlook remote access rights simply because a user is not a local administrator on the target.**

A user with RDP or WinRM access may still provide a valuable position for:

- Further enumeration
    
- Credential discovery
    
- Privilege escalation
    
- Lateral movement
    

And when SQL credentials are discovered, they should be investigated against MSSQL servers in the environment.

---

# 39. Quick Revision — Exam Perspective

### Q: What BloodHound edge represents RDP access?

```text
CanRDP
```

### Q: What BloodHound edge represents WinRM access?

```text
CanPSRemote
```

### Q: What BloodHound edge represents SQL administrator access?

```text
SQLAdmin
```

### Q: Which group is associated with RDP access?

```text
Remote Desktop Users
```

### Q: Which group can provide WinRM access without necessarily granting local admin?

```text
Remote Management Users
```

### Q: What PowerShell command establishes an interactive remote PowerShell session?

```powershell
Enter-PSSession
```

### Q: What Linux tool can be used for WinRM access?

```text
evil-winrm
```

### Q: What tool can enumerate MSSQL instances from PowerShell?

```text
PowerUpSQL
```

### Q: What Impacket tool can connect to MSSQL?

```text
mssqlclient.py
```

### Q: What SQL Server feature can execute operating-system commands?

```text
xp_cmdshell
```

### Q: What command was used to enumerate Windows privileges?

```text
xp_cmdshell whoami /priv
```

### Q: Which privilege shown in the module can potentially be abused for SYSTEM-level privilege escalation?

```text
SeImpersonatePrivilege
```

### Q: What is the most important methodology lesson?

```text
Enumerating and attacking is an iterative process.
```

After every newly compromised account or host:

```text
STOP → ENUMERATE → IDENTIFY NEW RIGHTS → MOVE → ENUMERATE AGAIN
```

# End of Privileged Access Notes