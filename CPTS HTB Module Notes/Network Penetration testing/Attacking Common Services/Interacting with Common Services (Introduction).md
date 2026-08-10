# 1. 🔥 Core Concept — Interacting With Services

Vulnerabilities are commonly discovered by people who **use and understand technology, a protocol, or a service**.

As we progress in cybersecurity, we will encounter different services. Therefore, we need to continuously learn:

- What the service is used for
    
- How the service works
    
- How to interact with it
    
- What authentication it supports
    
- What tools can communicate with it
    
- What information can be enumerated
    
- What actions are possible with our privileges
    

The basic methodology is:

```text
        Identify Service
              ↓
       Understand Purpose
              ↓
       Identify Protocol
              ↓
     Determine Authentication
              ↓
       Connect to Service
              ↓
          Enumerate
              ↓
     Analyze Interesting Data
              ↓
       Troubleshoot / Exploit
```

The source specifically emphasizes that successful interaction with a service requires understanding its **purpose, interaction methods, available tools, and capabilities**.

---

# 2. 📂 File Share Services

A **file sharing service** provides, mediates, and monitors the transfer of computer files.

Common internal file-sharing services include:

|Service|Common Environment|
|---|---|
|**SMB**|Windows networks|
|**NFS**|Linux/Unix networks|
|**FTP**|File transfer|
|**TFTP**|Simple file transfer|
|**SFTP**|Secure file transfer|

Modern companies may additionally use cloud-based storage such as:

- Dropbox
    
- Google Drive
    
- OneDrive
    
- SharePoint
    
- AWS S3
    
- Azure Blob Storage
    
- Google Cloud Storage
    

The important idea is that during an assessment we may encounter a mixture of **internal and external file-sharing services**.

---

# 3. 🖥️ SMB — Server Message Block

## What is SMB?

**SMB (Server Message Block)** is commonly used in **Windows networks**.

It allows computers to access shared:

- Files
    
- Directories
    
- Folders
    
- Network resources
    

A typical SMB share might look like:

```text
\\192.168.220.129\Finance\
```

Here:

```text
192.168.220.129     → Target IP
Finance             → Share name
```

SMB can be accessed using:

- Windows GUI
    
- Windows CMD
    
- Windows PowerShell
    
- Linux CLI
    
- SMB-specific tools
    

---

## 🖼️ SMB Interaction Flow

```text
┌──────────────────┐
│ Windows / Linux  │
│     Client       │
└────────┬─────────┘
         │
         │ SMB / CIFS
         ▼
┌──────────────────┐
│   SMB Server     │
│   Shared Folder  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Files & Folders  │
└──────────────────┘

Authentication:
Anonymous OR Authenticated User
```

---

# 4. 🪟 SMB — Windows GUI

On Windows, we can access an SMB share through the Run dialog.

Press:

```text
WINKEY + R
```

Then enter:

```text
\\192.168.220.129\Finance\
```

If:

- Anonymous authentication is allowed, **OR**
    
- The currently authenticated user has permissions
    

we can access the share without receiving another authentication prompt.

If we don't have access, Windows will request credentials.

---

# 5. 💻 Windows CMD

Windows has two primary command-line environments:

### Command Shell

```text
CMD
```

### PowerShell

```text
PowerShell
```

The Command Shell provides direct communication with Windows and can be used for routine operations and automation.

---

# 6. `dir` — List SMB Share Contents

The `dir` command displays:

- Files
    
- Directories
    
- Subdirectories
    

Example:

```cmd
C:\htb> dir \\192.168.220.129\Finance\
```

Example output:

```text
Volume in drive \\192.168.220.129\Finance has no label.
Volume Serial Number is ABCD-EFAA

Directory of \\192.168.220.129\Finance

02/23/2022  11:35 AM    <DIR>          Contracts
               0 File(s)          4,096 bytes
               1 Dir(s)  15,207,469,056 bytes free
```

The important concept:

> `dir` can directly enumerate a remote SMB share using its UNC path.

---

# 7. 🔗 `net use` — Map an SMB Share

`net use` can:

- Connect to a shared resource
    
- Disconnect from a shared resource
    
- Display existing connections
    
- Map a network share to a drive letter
    

Example:

```cmd
C:\htb> net use n: \\192.168.220.129\Finance
```

Output:

```text
The command completed successfully.
```

Now the SMB share is available through:

```text
N:
```

---

## Authentication with `net use`

A username and password can also be supplied:

```cmd
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123
```

The source uses this as an example of authenticated SMB access.

> **Security note:** Avoid exposing real credentials directly on command lines in real environments because command history/process inspection can expose them.

---

# 8. 🔎 Searching a Large SMB Share

After mapping the share to `N:`, normal Windows commands can be used.

For example, the source demonstrates finding the total number of files:

```cmd
C:\htb> dir n: /a-d /s /b | find /c ":\"
```

Output:

```text
29302
```

So there are:

```text
29,302 files
```

---

# 9. Understanding the `dir` Command

Command:

```cmd
dir n: /a-d /s /b
```

### Breakdown

|Option|Meaning|
|---|---|
|`dir`|Application/command|
|`n:`|Drive/directory being searched|
|`/a-d`|`/a` = attributes, `-d` = exclude directories|
|`/s`|Include specified directory and all subdirectories|
|`/b`|Bare format — removes headings/summary|

Then:

```text
|
```

pipes the output into another command.

```cmd
find /c ":\"
```

counts the matching output lines.

---

# 10. 🎯 Searching for Interesting Files

Searching thousands of files manually isn't efficient.

The source recommends searching for potentially interesting names such as:

```text
cred
password
users
secrets
key
```

Also consider source-code extensions:

```text
.cs
.c
.go
.java
.php
.asp
.aspx
.html
```

Example:

```cmd
C:\htb>dir n:\*cred* /s /b
```

Result:

```text
n:\Contracts\private\credentials.txt
```

Another:

```cmd
C:\htb>dir n:\*secret* /s /b
```

Result:

```text
n:\Contracts\private\secret.txt
```

---

# 11. 🔍 `findstr`

`findstr` can search for a specific word or pattern inside text files.

Example:

```cmd
c:\htb>findstr /s /i cred n:\*.*
```

Output:

```text
n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!
```

### Important switches

```text
/s → Search subdirectories
/i → Case-insensitive search
```

This makes `findstr` useful when you need to search **file contents rather than filenames**.

---

# 12. ⚡ PowerShell

PowerShell extends the capabilities of the Command shell.

PowerShell provides **cmdlets**, which are more extensible than traditional Windows commands.

Important commands from the source:

```text
Get-ChildItem
gci
New-PSDrive
Select-String
```

---

# 13. PowerShell — `Get-ChildItem`

Equivalent to listing directory contents.

Example:

```powershell
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\
```

Example:

```text
Directory: \\192.168.220.129\Finance

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/23/2022   3:27 PM                Contracts
```

Short form:

```powershell
gci
```

---

# 14. 🔗 PowerShell — `New-PSDrive`

Instead of:

```cmd
net use
```

PowerShell can use:

```powershell
New-PSDrive
```

Example:

```powershell
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

This creates a PowerShell drive:

```text
N:
```

---

# 15. 🔐 PowerShell — PSCredential

For authenticated access, PowerShell can create a `PSCredential` object.

Example from the source:

```powershell
$username = 'plaintext'
$password = 'Password123'

$secpassword = ConvertTo-SecureString $password -AsPlainText -Force

$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword

New-PSDrive -Name "N" `
  -Root "\\192.168.220.129\Finance" `
  -PSProvider "FileSystem" `
  -Credential $cred
```

The flow is:

```text
Username
   ↓
Password
   ↓
SecureString
   ↓
PSCredential
   ↓
New-PSDrive
   ↓
Authenticated SMB Share
```

---

# 16. 📊 Count Files With PowerShell

Once inside `N:`:

```powershell
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count
```

Output:

```text
29302
```

### Breakdown

```text
Get-ChildItem
      ↓
-FILE
      ↓
-Recurse
      ↓
Measure-Object
      ↓
.Count
```

---

# 17. 🔎 Search Filenames With `-Include`

Example:

```powershell
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

Example output:

```text
Directory: N:\Contracts\private

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2022   4:36 PM             25 credentials.txt
```

---

# 18. 🔍 `Select-String`

`Select-String` searches text patterns using regular expressions.

It can be thought of as a PowerShell equivalent to tools such as:

```text
grep
findstr
```

Example:

```powershell
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```

Output:

```text
N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```

---

# 19. 🐧 Linux — SMB

Linux can also browse and mount SMB shares.

The target may be:

- Windows SMB server
    
- Samba server
    

Linux can mount the share and then interact with it as a local directory.

---

# 20. Mount SMB Share on Linux

First create a mount point:

```bash
sudo mkdir /mnt/Finance
```

Then mount:

```bash
sudo mount -t cifs \
-o username=plaintext,password=Password123,domain=. \
 //192.168.220.129/Finance \
 /mnt/Finance
```

Conceptually:

```text
SMB Server
    │
    │ CIFS
    ▼
/mnt/Finance
    │
    ├── Contracts
    ├── Files
    └── Directories
```

---

# 21. 🔐 SMB Credential File

Instead of supplying credentials directly in the mount command, a credential file can be used.

```bash
mount -t cifs //192.168.220.129/Finance \
/mnt/Finance \
-o credentials=/path/credentialfile
```

The credential file structure:

```text
username=plaintext
password=Password123
domain=.
```

### Required package

The source notes that `cifs-utils` is required:

```bash
sudo apt install cifs-utils
```

---

# 22. 🔎 Linux `find`

Once mounted:

```bash
find /mnt/Finance/ -name *cred*
```

Example:

```text
/mnt/Finance/Contracts/private/credentials.txt
```

`find` searches for filenames matching the supplied pattern.

---

# 23. 🔍 Linux `grep`

To search file contents:

```bash
grep -rn /mnt/Finance/ -ie cred
```

Example:

```text
/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```

Important options:

```text
-r → recursive
-n → show line numbers
-i → case-insensitive
-e → pattern/expression
```

---

# 24. 🧠 SMB Enumeration Workflow

For labs and authorized assessments, remember this workflow:

```text
             SMB Found
                 │
                 ▼
       ┌──────────────────┐
       │ Can I authenticate│
       │ anonymously?      │
       └────────┬─────────┘
                │
        ┌───────┴───────┐
        ▼               ▼
       YES              NO
        │               │
        ▼               ▼
 Enumerate shares   Obtain/use
                    authorized creds
        │               │
        └───────┬───────┘
                ▼
        Enumerate files
                │
                ▼
     Search interesting names
                │
                ▼
       Search file contents
                │
                ▼
       Analyze permissions
```

---

# 25. 📁 Other File-Sharing Services

Other services mentioned include:

### FTP

File Transfer Protocol.

### TFTP

Trivial File Transfer Protocol.

### NFS

Network File System.

### SFTP

Secure File Transfer Protocol.

The exact tools and commands differ between services, but the general concept remains:

```text
Identify Service
       ↓
Understand Protocol
       ↓
Authenticate
       ↓
Attach / Mount / Connect
       ↓
Enumerate Files
       ↓
Use Standard OS Tools
```

The source specifically emphasizes learning how each new file-sharing service works and which tools can interact with it.

---

# 26. 📧 Email Services

Email commonly requires:

### Sending

```text
SMTP
```

**SMTP = Simple Mail Transfer Protocol**

### Receiving

Two major protocols:

```text
POP3
IMAP
```

Therefore:

```text
                 EMAIL
                   │
          ┌────────┴────────┐
          ▼                 ▼
        SMTP             POP3/IMAP
       Sending            Receiving
```

---

# 27. 📬 Evolution Mail Client

The source uses **Evolution** as a mail client.

Install:

```bash
sudo apt-get install evolution
```

If Evolution produces:

```text
bwrap: Can't create file at ...
```

the source provides:

```bash
export WEBKIT_FORCE_SANDBOX=0 && evolution
```

---

# 28. 🔐 SMTP/IMAP Encryption

The source explains that we can connect using:

- Domain name
    
- IP address
    

If the server uses:

```text
SMTPS
IMAPS
```

we need the appropriate encryption method.

The source mentions:

```text
TLS
STARTTLS
```

### Important distinction

```text
SMTPS
   ↓
SMTP over TLS

IMAPS
   ↓
IMAP over TLS

STARTTLS
   ↓
Upgrade an existing connection
to use TLS
```

The source also mentions the **“Check for Supported Types”** option for determining supported authentication/encryption methods.

---

# 29. 🗄️ Databases

Databases are commonly used by enterprises to store and manage information.

The source mentions:

### Database categories

```text
Hierarchical
     │
     ├── NoSQL / Non-relational
     │
     └── SQL / Relational
```

The focus is on:

```text
MySQL
MSSQL
```

---

# 30. 🧩 Three Ways to Interact With Databases

The source identifies three common approaches:

|Method|Examples|
|---|---|
|**Command Line Utilities**|`mysql`, `sqsh`|
|**Programming Languages**|Application/database libraries|
|**GUI Applications**|HeidiSQL, MySQL Workbench, SSMS|

---

# 31. 🖥️ MSSQL

**MSSQL = Microsoft SQL Server**

On Linux:

```text
sqsh
```

On Windows:

```text
sqlcmd
```

can be used.

---

# 32. `sqsh` — Linux

Example:

```bash
sqsh -S 10.129.20.13 -U username -P Password123
```

Meaning:

```text
-S → Server
-U → Username
-P → Password
```

The source describes `sqsh` as providing functionality such as:

- Variables
    
- Aliasing
    
- Redirection
    
- Pipes
    
- Backgrounding
    
- Job control
    
- History
    
- Command substitution
    
- Dynamic configuration
    

---

# 33. `sqlcmd` — Windows

Example:

```cmd
C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
```

`sqlcmd` can be used:

- At the command prompt
    
- In Query Editor in SQLCMD mode
    
- In Windows script files
    
- In SQL Server Agent operating-system job steps
    

---

# 34. 🐬 MySQL

MySQL can be accessed through:

```text
Linux → mysql
Windows → mysql.exe
```

Linux example:

```bash
mysql -u username -pPassword123 -h 10.129.20.13
```

Windows:

```cmd
mysql.exe -u username -pPassword123 -h 10.129.20.13
```

### Parameters

```text
-u → Username
-p → Password
-h → Host
```

> In real-world usage, avoid placing sensitive passwords directly in shell commands where possible.

---

# 35. 🖥️ GUI Database Applications

Common GUI applications mentioned:

### MySQL

```text
MySQL Workbench
```

### Microsoft SQL Server

```text
SQL Server Management Studio
SSMS
```

### Cross-platform

```text
DBeaver
```

DBeaver supports:

- MSSQL
    
- MySQL
    
- PostgreSQL
    
- Other database engines
    

---

# 36. Installing DBeaver

The source describes installing the `.deb` package:

```bash
sudo dpkg -i dbeaver-<version>.deb
```

Then start it:

```bash
dbeaver &
```

---

# 37. 🔌 Database Connection Requirements

To connect to a database, the source identifies the following requirements:

```text
Credentials
    +
Target IP
    +
Target Port
    +
Database Engine
```

For example:

```text
Username: ...
Password: ...
IP: 10.129.20.13
Port: ...
Engine: MySQL / MSSQL
```

---

# 38. 🗃️ After Database Access

Once access is established through a CLI or GUI, SQL statements can be used to enumerate:

```text
Databases
    ↓
Tables
    ↓
Records / Data
```

The source specifically notes that databases may contain sensitive information such as:

```text
Usernames
Passwords
```

With sufficient privileges, MSSQL may potentially allow command execution as the MSSQL service account. The source says later material covers common Transact-SQL statements and attacks for MSSQL and MySQL.

---

# 39. 🛠️ Tools to Interact With Common Services

The source emphasizes becoming familiar with **default command-line utilities first**, then learning community-created tools that improve efficiency.

## SMB

```text
smbclient
CrackMapExec
SMBMap
Impacket
psexec.py
smbexec.py
```

## FTP

```text
ftp
lftp
ncftp
filezilla
crossftp
```

## Email

```text
Thunderbird
Claws
Geary
MailSpring
mutt
mailutils
sendEmail
swaks
sendmail
```

## Databases

```text
mssql-cli
mycli
mssqlclient.py
dbeaver
MySQL Workbench
SQL Server Management Studio / SSMS
```

These tools are explicitly listed in the supplied material.

---

# 40. 🚨 General Troubleshooting

When interacting with services, different Windows/Linux versions and target configurations can produce different errors.

The source identifies **five major reasons** why access may fail:

### 1. Authentication

```text
Are the supplied credentials valid?
```

### 2. Privileges

```text
Does the account have permission?
```

### 3. Network Connection

```text
Can we actually reach the service?
```

### 4. Firewall Rules

```text
Is traffic being blocked?
```

### 5. Protocol Support

```text
Does the client support the protocol/version
required by the server?
```

---

# 41. 🧠 Troubleshooting Flowchart

```text
             CONNECTION FAILED
                    │
                    ▼
          ┌───────────────────┐
          │ Network reachable?│
          └─────────┬─────────┘
                    │
                    ▼
          ┌───────────────────┐
          │ Firewall blocking?│
          └─────────┬─────────┘
                    │
                    ▼
          ┌───────────────────┐
          │ Authentication OK?│
          └─────────┬─────────┘
                    │
                    ▼
          ┌───────────────────┐
          │ Privileges enough?│
          └─────────┬─────────┘
                    │
                    ▼
          ┌───────────────────┐
          │ Protocol supported│
          │ by client/server? │
          └─────────┬─────────┘
                    │
                    ▼
                CONNECT
```

The source recommends using **error codes/messages as useful clues** and searching official documentation or reliable forums for similar problems.

---

# 42. 🧾 ⭐ Quick Revision Table

|Service|Purpose|Main Tools/Commands|
|---|---|---|
|**SMB**|Windows file sharing|`dir`, `net use`, `smbclient`, `SMBMap`|
|**NFS**|Network filesystem|Mount/NFS utilities|
|**FTP**|File transfer|`ftp`, `lftp`, FileZilla|
|**TFTP**|Simple file transfer|TFTP clients|
|**SFTP**|Secure file transfer|SFTP clients|
|**SMTP**|Send email|Mail clients / SMTP tools|
|**POP3**|Receive email|Mail clients|
|**IMAP**|Receive/sync email|Mail clients|
|**MSSQL**|Relational database|`sqsh`, `sqlcmd`, SSMS|
|**MySQL**|Relational database|`mysql`, MySQL Workbench|
|**Multiple DBs**|Database management|DBeaver|

---

# 43. 🧠 ⭐ Commands You Should Remember

### Windows SMB

```cmd
dir \\192.168.220.129\Finance\
```

```cmd
net use n: \\192.168.220.129\Finance
```

```cmd
dir n: /a-d /s /b
```

```cmd
findstr /s /i cred n:\*.*
```

---

### PowerShell

```powershell
Get-ChildItem \\192.168.220.129\Finance\
```

```powershell
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

```powershell
Get-ChildItem -File -Recurse
```

```powershell
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

```powershell
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```

---

### Linux SMB

```bash
sudo mkdir /mnt/Finance
```

```bash
sudo mount -t cifs //192.168.220.129/Finance /mnt/Finance
```

```bash
find /mnt/Finance/ -name *cred*
```

```bash
grep -rn /mnt/Finance/ -ie cred
```

---

### MSSQL

```bash
sqsh -S 10.129.20.13 -U username -P Password123
```

```cmd
sqlcmd -S 10.129.20.13 -U username -P Password123
```

---

### MySQL

```bash
mysql -u username -pPassword123 -h 10.129.20.13
```

```cmd
mysql.exe -u username -pPassword123 -h 10.129.20.13
```

---

# 44. 🎯 Exam / Viva Points

### Q1. What is SMB?

**SMB (Server Message Block)** is a protocol commonly used for file and resource sharing in Windows networks.

### Q2. How can you access an SMB share from Windows?

Using a UNC path:

```text
\\IP\Share
```

or through commands such as:

```cmd
net use
```

### Q3. What does `net use` do?

It connects/disconnects a computer from a shared resource or displays information about existing connections.

### Q4. What does `/s` do in `dir`?

It searches the specified directory **and all subdirectories**.

### Q5. What does `/a-d` do?

It excludes directories, allowing us to focus on files.

### Q6. What is `findstr`?

A Windows command used to search for text patterns inside files.

### Q7. What is the PowerShell equivalent commonly used for file enumeration?

```powershell
Get-ChildItem
```

or:

```powershell
gci
```

### Q8. What is `Select-String`?

A PowerShell cmdlet used to search for text patterns in input and files.

### Q9. How can Linux mount an SMB share?

Using:

```bash
mount -t cifs
```

### Q10. What package is required for SMB/CIFS mounting?

```bash
cifs-utils
```

### Q11. What protocol sends email?

```text
SMTP
```

### Q12. What protocols retrieve email?

```text
POP3
IMAP
```

### Q13. What are two databases covered?

```text
MySQL
MSSQL
```

### Q14. What is `sqsh`?

A command-line utility used to interact with MSSQL from Linux.

### Q15. What is `sqlcmd`?

A Microsoft command-line utility used to interact with SQL Server.

### Q16. What are the five major troubleshooting areas?

```text
Authentication
Privileges
Network Connection
Firewall Rules
Protocol Support
```

---

# 🔥 45. The Most Important Concept to Remember

Don't memorize the commands as isolated commands.

Remember this **service-interaction methodology**:

```text
┌───────────────────────────────┐
│       1. IDENTIFY             │
│       What service is it?     │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│       2. UNDERSTAND           │
│       What does it do?        │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│       3. CONNECT              │
│       Which client/tool?      │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│       4. AUTHENTICATE         │
│       Anonymous / credentials │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│       5. ENUMERATE            │
│       Files / data / shares   │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│       6. SEARCH               │
│       Find interesting data   │
└───────────────┬───────────────┘
                ↓
┌───────────────────────────────┐
│       7. TROUBLESHOOT         │
│       Errors → clues          │
└───────────────────────────────┘
```

**This is the main lesson of the entire section:** learn how a service works, learn its native interaction method, enumerate systematically, and use errors to guide troubleshooting.