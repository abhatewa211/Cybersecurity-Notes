# 1. 📂 What is SMB?

**SMB = Server Message Block**

SMB is a communication protocol used to provide **shared access to files and printers across nodes on a network**. Microsoft describes SMB as a network file-sharing protocol that also supports operations involving files, directories, authentication, printing, and other shared resources. ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview?utm_source=chatgpt.com "Microsoft SMB Protocol and CIFS Protocol Overview - Win32 apps | Microsoft Learn"))

![Image](https://images.openai.com/static-rsc-4/uAcuSN6xuSTeCZbLpBJsRDKkM4uKkDxuZhox9BEa9C6LfA1NEOwDtSWLEb-Xn6U9K6S4PydJXv5x9xx-DUCXfo1rCMq7G6EtCO7EfigQhXkEExKocnXAXyV5DtGb5t-VnhAMu4evGY0IDMLiCMSU2-7-aQ6WfUHnyffpcTYN5HZV-uEDjwy7Zk2elJXtAbF6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vIn0x7yEQqMFM462lOao1hs_VbqXbvhjk6S4D8OSAXELby5mMaTcQkb_s316JM_M2DTYmxN_RKHlJhBRGDrfAC-h1UPnJ2JRozFfe0h2uWC34whBRjXmMMuqshjXu8thYt4qxiTkmkQsXZZC1tqilon98eFZPJawQWXDpyIi4Tq5RbrSqd-1h7GeTV-GxHVM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cn9lwlW7hUyYcZnFgrhxqoGzfqgG2Mgvrw2LXX-YUnyUf2Davvf-6Oi3MHyTkbXw0dOWQhwYbG4TP2jAhkh9yuXpgoAEwTp80AQoDBM7G6JJtLrAW2AeyqAYomsmWPns1hjP3uX-u-YPLEjBgHwVBfYaeKMjzXPXcq7OLSUMKJOBCck7Izggax11e9yO8EXF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EvxlhsRQKqfYyPRnR89cSH6SSSX_aRu6V6DFC0Ocs1DS0IaGm_ei-1hjgJ_OqMNxoWSqvtGlFqpCRzbWf6OjWkOne6JZXXb1zSQnTFK2oRF-Qfx2ztWz3WwibdYcAoIRAQBoZ6Ebxb7k-SIrO6GDSV1382JISfiy_xoCruMHg7XU3Go0N6gR9OUpDQqxFmQ3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nqXtmuE7kPVJaQHKJVnBk23BXYKBRqF03uQLigdAji83Ei-yrXp6ka79jGY8JIJSZUBrQu5wK8Ho0nVyYa_UJRPjhviZ1q0TC3tZaxhQruhKo_eMSfVcQUh8dF4ijK54Q9D09P3aWGYXEJBps1m6Sk-thYWK9JXiE7JmG5rIsXO5PKHy6qGrogVezo5ItiIN?purpose=fullsize)

### SMB can provide:

- File sharing
    
- Directory access
    
- Printer sharing
    
- Authentication
    
- Remote resource access
    
- Named-pipe communication
    
- RPC functionality
    

The basic concept is:

```text
                 NETWORK
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
   SMB CLIENT              SMB SERVER
        │                       │
        │────── SMB ───────────►│
        │                       │
        │◄──── SMB Response ────│
        │                       │
        ▼                       ▼
     Access                Shared Resources
                          ├── Files
                          ├── Folders
                          └── Printers
```

---

# 2. 🌐 SMB Ports

Historically, SMB was designed to run over **NetBIOS over TCP/IP (NBT)**.

Important ports:

|Port|Protocol|Purpose|
|---|---|---|
|`137`|UDP|NetBIOS Name Service|
|`138`|UDP|NetBIOS Datagram Service|
|`139`|TCP|NetBIOS Session Service / SMB over NetBIOS|
|`445`|TCP|SMB directly over TCP/IP|

The source explains that Windows 2000 introduced the ability to run SMB directly over TCP/IP on **TCP/445**, without the additional NetBIOS layer. Modern Windows systems use SMB directly over TCP while still supporting NetBIOS in some situations.

Microsoft documentation likewise identifies **TCP/445** as the direct-hosted SMB transport, while NetBIOS traditionally uses UDP/137, UDP/138, and TCP/139. ([Microsoft Learn](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/direct-hosting-of-smb-over-tcpip?utm_source=chatgpt.com "Direct host Server Message Block (SMB) over TCP/IP - Windows Server | Microsoft Learn"))

### ⭐ Memorize:

```text
137/UDP → NetBIOS Name
138/UDP → NetBIOS Datagram
139/TCP → SMB over NetBIOS
445/TCP → Direct SMB
```

---

# 3. 🐧 What is Samba?

**Samba** is an open-source Unix/Linux implementation of SMB.

It allows:

```text
Linux/Unix
     │
     │ SMB
     ▼
Windows Clients
```

and can also allow Windows systems to communicate with Linux-based SMB servers.

The source's example identifies:

```text
Samba smbd 4.6.2
```

as the SMB implementation discovered during enumeration.

---

# 4. 🔗 SMB and MSRPC

Another protocol commonly associated with SMB is:

# **MSRPC — Microsoft Remote Procedure Call**

RPC provides developers with a way to execute a procedure/function locally or remotely without having to directly understand all of the underlying network communication.

SMB can provide the underlying transport for RPC through **named pipes**.

Conceptually:

```text
             SMB
              │
              ▼
        Named Pipes
              │
              ▼
            RPC
              │
              ▼
      Remote Procedure
         Execution
```

The important relationship:

```text
SMB
 │
 └── Named Pipes
       │
       └── MSRPC
```

---

# 5. 🎯 SMB Attack Surface

When assessing an SMB server, we need to understand:

1. SMB implementation
    
2. Operating system
    
3. Available shares
    
4. Authentication requirements
    
5. User permissions
    
6. RPC/NetBIOS exposure
    
7. Service configuration
    
8. Known vulnerabilities
    

The source emphasizes that, like other services, SMB can be attacked through:

```text
Misconfiguration
      +
Excessive Privileges
      +
Known Vulnerabilities
      +
New Vulnerabilities
```

After gaining access, we also need to inspect the contents of shared folders and determine what information or actions are available.

---

# 6. 🔎 SMB Enumeration

The first major step is:

# **Enumeration**

The source recommends looking at:

```text
TCP/139
TCP/445
```

using Nmap.

Example:

```bash
sudo nmap 10.129.14.128 -sV -sC -p139,445
```

### Breakdown

|Option|Meaning|
|---|---|
|`sudo`|Run with elevated privileges|
|`nmap`|Network scanner|
|`10.129.14.128`|Target|
|`-sV`|Service/version detection|
|`-sC`|Default NSE scripts|
|`-p139,445`|Scan SMB-related ports|

---

# 7. 📋 Example Nmap Result

The source gives:

```text
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
```

Additional information:

```text
NetBIOS name: HTB
```

and:

```text
Message signing enabled but not required
```

---

# 8. 🧠 What Can We Learn From the Nmap Scan?

The source identifies three important pieces of information:

### 1. SMB Version

```text
Samba smbd 4.6.2
```

### 2. Hostname

```text
HTB
```

### 3. Operating System

The SMB implementation suggests that the target is:

```text
Linux-based
```

### Important mindset:

Don't just record:

```text
445 OPEN
```

Instead ask:

```text
What implementation?
What version?
What hostname?
What OS?
What authentication?
What shares?
What permissions?
```

---

# 9. ⚠️ SMB Misconfiguration — Null Session

One of the most important SMB misconfigurations is:

# **Null Session**

A null session means SMB can be accessed **without a username or password**.

Conceptually:

```text
Normal:

Client
  │
  ├── Username
  ├── Password
  ▼
SMB Server


Null Session:

Client
  │
  ├── No Username
  └── No Password
  ▼
SMB Server
```

The source states that a server configured this way may expose information such as:

- Shares
    
- Usernames
    
- Groups
    
- Permissions
    
- Policies
    
- Services
    

---

# 10. 🔓 Anonymous / Null Authentication

Tools that can interact with SMB using null sessions include:

- `smbclient`
    
- `smbmap`
    
- `rpcclient`
    
- `enum4linux`
    

These tools can be used to enumerate different parts of the SMB environment.

---

# 11. 📁 SMB File Shares

A **share** is a network-accessible resource exposed by the SMB server.

Examples from the source:

```text
ADMIN$
C$
notes
IPC$
```

### Important special shares

|Share|General purpose|
|---|---|
|`ADMIN$`|Remote administration|
|`C$`|Default administrative share|
|`IPC$`|Inter-Process Communication|
|`notes`|Regular/custom share in the example|

---

# 12. 🧪 Enumerating Shares With `smbclient`

The source uses:

```bash
smbclient -N -L //10.129.14.128
```

### Important options:

```text
-N
 ↓
No password / null session

-L
 ↓
List available shares
```

Example result:

```text
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
notes           Disk      CheckIT
IPC$            IPC       IPC Service (DEVSM)
```

---

# 13. 🖼️ SMB Share Enumeration Flow

```text
                  SMB SERVER
                      │
                      ▼
                Null Session
                      │
                      ▼
              Enumerate Shares
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
      ADMIN$          C$          notes
        │             │             │
   Remote Admin   Default Share   Custom Share
```

---

# 14. 🗺️ SMBMap

Another important tool:

# `smbmap`

The source describes `smbmap` as a tool that helps enumerate network shares and associated permissions.

One of its major advantages is that it displays the permissions for each shared folder.

Example:

```bash
smbmap -H 10.129.14.128
```

Output:

```text
Disk        Permissions     Comment
----        -----------     -------
ADMIN$      NO ACCESS       Remote Admin
C$          NO ACCESS       Default share
IPC$        READ ONLY       IPC Service (DEVSM)
notes       READ, WRITE     CheckIT
```

---

# 15. ⭐ Why Permissions Are Important

The previous result tells us:

```text
notes → READ, WRITE
```

This is particularly interesting.

### READ

Potentially allows:

```text
Read files
Download files
Enumerate directories
```

### WRITE

Potentially allows:

```text
Upload files
Modify/write files
```

So:

```text
READ + WRITE
     ↓
Greater Attack Surface
```

---

# 16. 🔍 Recursive Share Enumeration

`smbmap` can recursively browse a share using:

```text
-r
```

or:

```text
-R
```

Example:

```bash
smbmap -H 10.129.14.128 -r notes
```

The source shows files/directories such as:

```text
LDOUJZWBSG
note.txt
SDT65CB.tmp
TPLRNSMWHQ
WDJEQFZPNO
WindowsImageBackup
```

---

# 17. 📥 Downloading SMB Files

Because the example share is:

```text
READ, WRITE
```

the source demonstrates downloading:

```bash
smbmap -H 10.129.14.128 --download "notes\note.txt"
```

Output:

```text
Starting download: notes\note.txt
File output to:
/htb/10.129.14.128-notes_note.txt
```

---

# 18. 📤 Uploading SMB Files

The source also demonstrates uploading:

```bash
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```

Output:

```text
Starting upload: test.txt
Upload complete.
```

### Remember:

```text
READ
 ↓
Download

WRITE
 ↓
Upload

READ + WRITE
 ↓
Download + Upload
```

---

# 19. 🛰️ RPC Enumeration

Another important component is:

# **Remote Procedure Call (RPC)**

The source explains that `rpcclient` can be used with a null session to enumerate a workstation or Domain Controller.

Example:

```bash
rpcclient -U'%' 10.10.110.17
```

Then:

```text
rpcclient $> enumdomusers
```

Example:

```text
user:[mhope]
user:[svc-ata]
user:[svc-bexec]
user:[roleary]
user:[smorgan]
```

---

# 20. 🧠 What Is `-U'%'`?

In the supplied example:

```text
-U'%'
```

is used to establish the null-session style connection.

The important concept for your notes is:

```text
rpcclient
    +
Null Session
    ↓
RPC Enumeration
```

---

# 21. 🔎 What Can RPC Reveal?

Depending on configuration and permissions, RPC can expose information about:

- Users
    
- Groups
    
- Domain information
    
- System configuration
    
- Policies
    
- Other SMB/RPC-related information
    

It can also expose functions that may modify server attributes when sufficient permissions/configuration allow it.

---

# 22. 🧰 Enum4linux

Another SMB enumeration utility is:

# `enum4linux`

The source explains that it can automate common SMB enumeration tasks using tools including:

```text
nmblookup
net
rpcclient
smbclient
```

---

# 23. 📋 What Can Enum4linux Enumerate?

The source specifically lists:

```text
Workgroup / Domain name
Users
Operating System information
Groups
Shared folders
Password policy information
```

### Think:

```text
ENUM4LINUX
    │
    ├── Domain
    ├── Users
    ├── Groups
    ├── Shares
    ├── OS
    └── Password Policy
```

---

# 24. 🧪 Enum4linux-ng

The source demonstrates:

```bash
./enum4linux-ng.py 10.10.11.45 -A -C
```

The output identifies things such as:

```text
Target
Username
Password
SMB accessibility
NetBIOS
Workgroup
SMB dialect
```

Example:

```text
WORKGROUP
WIN-752039204
```

---

# 25. 🔥 SMB Enumeration Toolkit

|Tool|Main Use|
|---|---|
|`nmap`|Port/service enumeration|
|`smbclient`|Enumerate/interact with shares|
|`smbmap`|Shares + permissions|
|`rpcclient`|RPC enumeration|
|`enum4linux-ng`|Automated SMB enumeration|

### Quick memory trick:

```text
NMAP
 ↓
Is SMB there?

SMBCLIENT
 ↓
What shares exist?

SMBMAP
 ↓
What permissions exist?

RPCCLIENT
 ↓
What RPC information exists?

ENUM4LINUX
 ↓
Automate enumeration
```

---

# 26. 🔐 When Null Session Is Not Available

If anonymous/null authentication is disabled:

```text
Null Session
    ❌
```

we need valid credentials.

The source identifies two common approaches:

1. **Brute forcing**
    
2. **Password spraying**
    

---

# 27. 🔨 Brute Force vs Password Spraying

## Brute Force

Try many passwords against one account.

```text
User: Administrator

Password 1
Password 2
Password 3
Password 4
...
```

Potential problem:

```text
Too many attempts
       ↓
Account Lockout
```

The source therefore warns against brute forcing when the lockout threshold is unknown.

---

# 28. 🎯 Password Spraying

Password spraying reverses the approach.

Instead of:

```text
ONE USER
+
MANY PASSWORDS
```

we use:

```text
MANY USERS
+
ONE COMMON PASSWORD
```

Example:

```text
Company01!

      │
 ┌────┼─────┬─────┐
 ▼    ▼     ▼     ▼
User1 User2 User3 User4
```

The source describes this as a better alternative for reducing account-lockout risk and notes that attempts should respect the target's lockout policy.

---

# 29. 🧰 CrackMapExec

The source introduces:

# **CrackMapExec (CME)**

It can target multiple systems and use lists of users/passwords.

For password spraying, the source explains:

```text
-u
 ↓
User list

-p
 ↓
Password
```

Example from the material:

```bash
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth
```

---

# 30. ⭐ Important CME Note

The source states:

```text
--continue-on-success
```

can be used to continue spraying even after finding a valid password.

It also notes:

```text
--local-auth
```

is needed when targeting a non-domain-joined computer.

---

# 31. 🖥️ Linux SMB vs Windows SMB

The source makes an important distinction:

```text
Linux SMB
     vs
Windows SMB
```

On Linux environments, typical paths may involve:

- Filesystem access
    
- Privilege abuse
    
- Known vulnerabilities
    

Windows SMB generally exposes a **larger attack surface**.

---

# 32. 🔥 Windows SMB — Important Capabilities

If a compromised Windows account has sufficient privileges, the source identifies possible operations including:

### 1. Remote Command Execution

```text
RCE
```

### 2. Extract Hashes

From:

```text
SAM Database
```

### 3. Enumerate Logged-on Users

```text
Who is currently logged in?
```

### 4. Pass-the-Hash

```text
NTLM Hash
    ↓
Authentication
```

---

# 33. 🖼️ Windows SMB Attack Chain

```text
                 SMB
                  │
                  ▼
          Valid Credentials
                  │
                  ▼
          Privileged Account
                  │
        ┌─────────┼──────────┐
        ▼         ▼          ▼
       RCE       SAM       Logged-on
                Hashes       Users
        │         │
        │         ▼
        │      NTLM Hash
        │         │
        │         ▼
        │     Pass-the-Hash
        │
        ▼
   Remote System
```

---

# 34. 💻 Remote Code Execution — PsExec

The source introduces:

# **PsExec**

PsExec is part of Microsoft's **Sysinternals** suite.

Sysinternals provides utilities for:

- Managing Windows systems
    
- Diagnosing systems
    
- Troubleshooting
    
- Monitoring systems
    

---

# 35. ⚙️ How PsExec Works

This is an important concept.

The source explains that PsExec:

1. Contains a Windows service image
    
2. Deploys the service to the `ADMIN$` share
    
3. Uses DCE/RPC over SMB
    
4. Accesses the Windows Service Control Manager API
    
5. Starts the service
    
6. Uses a named pipe to communicate with the system
    

### Visual:

```text
             ATTACKER
                │
                │ SMB
                ▼
             ADMIN$
                │
                ▼
       Upload Service Binary
                │
                ▼
       Service Control Manager
                │
                ▼
          Start Service
                │
                ▼
          Named Pipe
                │
                ▼
        Remote Command Shell
```

---

# 36. 🧰 PsExec Implementations Mentioned

The source lists:

- Microsoft PsExec
    
- Impacket `psexec`
    
- Impacket `smbexec`
    
- Impacket `atexec`
    
- CrackMapExec
    
- Metasploit PsExec
    

---

# 37. 🐍 Impacket PsExec

The source introduces:

```text
impacket-psexec
```

It requires target authentication information and the target machine.

General syntax shown by the tool:

```text
[[domain/]username[:password]@]<target>
```

and can execute a command on the target.

---

# 38. 🔑 Important Impacket Authentication Options

The source lists:

```text
-hashes LMHASH:NTHASH
```

for NTLM hash authentication.

```text
-no-pass
```

to avoid asking for a password in applicable scenarios.

```text
-k
```

for Kerberos authentication.

```text
-aesKey
```

for Kerberos AES key authentication.

---

# 39. 🧪 PsExec Example

The source provides:

```bash
impacket-psexec administrator:'Password123!'@10.10.110.17
```

The resulting process:

```text
Requesting shares
      ↓
Found writable ADMIN$
      ↓
Uploading file
      ↓
Opening SVCManager
      ↓
Creating service
      ↓
Starting service
      ↓
Remote shell
```

The final example shows:

```text
C:\Windows\system32>whoami && hostname

nt authority\system
WIN7BOX
```

---

# 40. ⭐ Why `ADMIN$` Matters

Remember from earlier:

```text
ADMIN$
```

is a default administrative share.

PsExec's mechanism relies on being able to write/deploy its service component through an administrative share and then interact with the service manager.

So:

```text
ADMIN$ writable
       +
Administrative privileges
       ↓
PsExec-style remote execution
```

---

# 41. ⚡ CrackMapExec — Remote Commands

The source also introduces CrackMapExec for running:

- CMD commands
    
- PowerShell commands
    

Important options:

```text
-x
 ↓
CMD command

-X
 ↓
PowerShell command
```

Example:

```bash
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

---

# 42. 👤 Enumerating Logged-on Users

The source gives an example of enumerating logged-on users across a network:

```bash
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

The output identifies users logged onto different machines.

Example:

```text
WIN7BOX\Administrator
WIN7BOX\jurena

WIN10BOX\Administrator
WIN10BOX\demouser
```

### Why is this useful?

In an authorized assessment, it can help understand:

```text
Which systems are active?
Who is logged in?
Where are privileged users?
```

---

# 43. 🔐 SAM Database

**SAM = Security Account Manager**

The source describes SAM as a database file containing information used for local Windows user authentication.

With sufficient administrative privileges, SAM hashes may be extracted for purposes including:

- Authentication as another user
    
- Password cracking
    
- Password reuse
    
- Pass-the-Hash
    

---

# 44. 🧠 SAM Attack Concept

```text
Administrative Access
        │
        ▼
    SAM Database
        │
        ▼
    NTLM Hashes
        │
   ┌────┴────┐
   ▼         ▼
Cracking   Pass-the-Hash
   │
   ▼
Password
```

---

# 45. 🧪 SAM Extraction Example

The source uses:

```bash
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

The resulting output includes accounts such as:

```text
Administrator
Guest
DefaultAccount
WDAGUtilityAccount
jurena
demouser
```

and their corresponding hash material.

---

# 46. 🔑 Pass-the-Hash (PtH)

One of the most important concepts in Windows SMB attacks:

# **Pass-the-Hash**

If an NTLM hash is obtained but cannot be cracked, it may still be usable for authentication in environments/protocols that accept NTLM.

Instead of:

```text
Username + Password
```

the attacker uses:

```text
Username + NTLM Hash
```

The source describes this as authenticating to a remote service using the underlying NTLM hash rather than the plaintext password.

---

# 47. 🖼️ Pass-the-Hash Concept

```text
             SAM
              │
              ▼
         NTLM Hash
              │
              │
      ┌───────┴────────┐
      │                │
      ▼                ▼
 Crack Hash         Use Hash
      │                │
      ▼                ▼
 Password          Pass-the-Hash
      │                │
      └───────┬────────┘
              ▼
        Authentication
```

---

# 48. 🧪 PtH Example

The source demonstrates:

```bash
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

The important option is:

```text
-H
 ↓
NTLM hash
```

The supplied output shows successful authentication as:

```text
WIN7BOX\Administrator
```

---

# 49. 🎣 Forced Authentication Attacks

The next major concept is:

# **Forced Authentication**

The source explains that SMB can be abused by creating a fake SMB server capable of capturing **NetNTLM v1/v2** authentication material.

A commonly used tool in the source is:

# **Responder**

---

# 50. 🧰 Responder

Responder is described as an:

> LLMNR, NBT-NS, and MDNS poisoner

It can set up fake services, including SMB, to capture NetNTLM authentication material.

Conceptually:

```text
Windows Client
      │
      │ Name Resolution
      ▼
LLMNR / NBT-NS / MDNS
      │
      ▼
Responder
(Fake Service)
      │
      ▼
NetNTLM Challenge/Response
```

---

# 51. 🧠 Why Name Resolution Matters

When Windows needs to resolve a hostname, the source describes a rough sequence:

```text
1. Local hosts file
        ↓
2. DNS cache
        ↓
3. Configured DNS server
        ↓
4. Multicast query
```

---

# 52. 🚨 Mistyped SMB Share Example

Suppose a user enters:

```text
\\mysharefoder\
```

instead of:

```text
\\mysharedfolder\
```

If normal name resolution fails, the system may issue a multicast query.

A malicious system listening for that request can respond as though it were the requested server.

Conceptually:

```text
Victim
  │
  │ "Where is mysharefoder?"
  ▼
LLMNR/NBT-NS/MDNS
  │
  ▼
Responder
  │
  │ Fake response
  ▼
Victim connects to attacker
  │
  ▼
Authentication material exposed
```

The source explains that this can be abused to capture credentials/NetNTLM hashes.

---

# 53. 🖼️ Responder Attack Flow

```text
              VICTIM
                 │
                 │ Requests hostname
                 ▼
       ┌──────────────────┐
       │ Name Resolution  │
       │ LLMNR/NBT-NS/MDNS│
       └────────┬─────────┘
                │
                │ Query
                ▼
          ┌───────────┐
          │ Responder │
          │ Fake SMB  │
          └─────┬─────┘
                │
                │ Spoofed Response
                ▼
             VICTIM
                │
                │ Authentication
                ▼
          NetNTLMv1/v2
```

---

# 54. 🧪 Responder Command

The source gives:

```bash
responder -I <interface name>
```

Example:

```bash
sudo responder -I ens33
```

The example output shows multiple poisoners and servers enabled, including:

```text
LLMNR
NBT-NS
DNS/MDNS
SMB
HTTP
FTP
LDAP
RDP
WinRM
```

---

# 55. 🎯 Captured NetNTLMv2 Information

The source shows Responder capturing:

```text
NTLMv2-SSP Client
NTLMv2-SSP Username
NTLMv2-SSP Hash
```

For example:

```text
Username:
WIN7BOX\demouser
```

and a corresponding NetNTLMv2 challenge/response value.

---

# 56. 🧠 NetNTLMv2 Is Not the Same as an NTLM Password Hash

This distinction is **very important**.

### NTLM hash

Can potentially be used directly in certain Pass-the-Hash scenarios.

### NetNTLMv2

Is a **challenge-response authentication exchange**.

Conceptually:

```text
Password
   │
   ▼
NTLM-based authentication
   │
   ├── Challenge
   ├── Response
   └── Authentication material
```

The captured NetNTLMv2 response may be subjected to offline password guessing if the password is weak.

---

# 57. 🔨 Cracking Captured NetNTLMv2

The source explains that captured hashes can be cracked using:

# Hashcat

The material uses:

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Important:

```text
-m 5600
   ↓
NetNTLMv2
```

The example eventually reports:

```text
Status: Cracked
Hash.Name: NetNTLMv2
```

and obtains:

```text
P@ssword
```

---

# 58. 🧠 Why Multiple NetNTLMv2 Hashes Can Look Different

The source provides an important note:

NTLMv2 uses client-side and server-side challenges that are randomized for each interaction.

Therefore, the resulting authentication material can differ between authentication attempts even when the underlying password is the same.

### Remember:

```text
Same Password
      +
Different Challenge
      ↓
Different NetNTLMv2 Response
```

---

# 59. 🔄 NTLM Relay

If the captured NetNTLM material cannot be cracked, the source explains that it may potentially be **relayed** to another machine.

Tools mentioned:

- `impacket-ntlmrelayx`
    
- Responder `MultiRelay.py`
    

---

# 60. 🧠 NTLM Relay Concept

```text
          VICTIM
             │
             │ Authentication
             ▼
        ATTACKER
             │
             │ Relay
             ▼
       TARGET SERVER
             │
             ▼
      Authentication
      using victim's
      NTLM exchange
```

The important difference:

```text
Cracking
   ↓
Recover password

Relay
   ↓
Reuse authentication exchange
```

---

# 61. ⚙️ NTLMRelayx Concept

The source first disables SMB in the Responder configuration:

```text
SMB = Off
```

Then uses `impacket-ntlmrelayx` in relay mode.

The supplied example shows successful authentication against the target and SAM extraction.

---

# 62. 🚨 Why Disable SMB in Responder?

The source's workflow is essentially:

```text
Responder
   │
   └── Capture/poison
         │
         ▼
     NTLM Relay
         │
         ▼
  impacket-ntlmrelayx
```

Therefore, the SMB server component of Responder is disabled so the authentication can be handled by the relay tool in the demonstrated setup.

---

# 63. 💥 NTLM Relay → SAM Example

The supplied example shows:

```text
Connection from Administrator
       ↓
Authentication succeeds
       ↓
RemoteRegistry
       ↓
SAM extraction
       ↓
Local SAM hashes
```

This demonstrates how a successful relay against a sufficiently privileged target can lead to further administrative operations.

---

# 64. 🐚 NTLM Relay → Command Execution

The source then demonstrates that a command can be supplied to `ntlmrelayx` with:

```text
-c
```

The material uses a PowerShell reverse-shell payload in the lab example.

The resulting connection shows:

```text
PS C:\Windows\system32> whoami;hostname

nt authority\system
WIN11BOX
```

### Conceptual chain:

```text
Forced Authentication
        ↓
NetNTLM Authentication
        ↓
Relay
        ↓
Privileged Target
        ↓
Command Execution
```

---

# 65. 🛰️ RPC — Beyond Enumeration

The source concludes by returning to RPC.

RPC isn't only useful for enumeration.

Depending on configuration and permissions, it can potentially be used to make system changes such as:

- Change a user's password
    
- Create a new domain user
    
- Create a new shared folder
    

### Important:

These operations require **specific configurations and permissions**.

---

# 66. 🧠 Complete SMB Attack Methodology

Here's the entire module condensed into one workflow:

```text
                       SMB
                        │
                        ▼
                 TCP/139 or 445
                        │
                        ▼
                  Nmap Scan
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
          SMB Info             NetBIOS
              │                   │
              └─────────┬─────────┘
                        ▼
               Authentication
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
        Null Session          Credentials
              │                   │
              ▼                   ▼
       Share Enumeration    Spray / Brute Force
              │                   │
              ▼                   ▼
        smbclient/smbmap      Valid Account
              │                   │
              └─────────┬─────────┘
                        ▼
                   Permissions
                        │
             ┌──────────┼───────────┐
             ▼          ▼           ▼
            READ       WRITE      ADMIN
             │          │           │
             ▼          ▼           ▼
        Download     Upload       RCE
             │                      │
             │                      ▼
             │                 SAM Hashes
             │                      │
             │               ┌──────┴──────┐
             │               ▼             ▼
             │            Cracking        PtH
             │
             ▼
       Sensitive Info
```

---

# 67. 🔥 Forced Authentication Branch

Keep this separate from normal share enumeration:

```text
                SMB
                 │
                 ▼
       Name Resolution Issue
                 │
                 ▼
       LLMNR/NBT-NS/MDNS
                 │
                 ▼
             Responder
                 │
                 ▼
       Fake SMB Service
                 │
                 ▼
        NetNTLMv2 Capture
                 │
          ┌──────┴───────┐
          ▼              ▼
       Crack            Relay
          │              │
          ▼              ▼
      Password      Target Authentication
```

---

# 68. 🧰 SMB Tool Cheat Sheet

|Tool|Purpose|
|---|---|
|`nmap`|Discover SMB and enumerate service information|
|`smbclient`|List/interact with SMB shares|
|`smbmap`|Enumerate shares and permissions|
|`rpcclient`|RPC enumeration|
|`enum4linux-ng`|Automated SMB enumeration|
|`CrackMapExec`|SMB authentication, spraying, enumeration, command execution|
|`PsExec`|Remote command execution through Windows service mechanism|
|`Impacket-psexec`|Linux implementation of PsExec-style execution|
|`impacket-smbexec`|SMB-based remote execution|
|`impacket-atexec`|Remote execution through Task Scheduler|
|`Responder`|LLMNR/NBT-NS/MDNS poisoning and credential capture|
|`Hashcat`|Offline password/hash cracking|
|`impacket-ntlmrelayx`|NTLM relay|

---

# 69. ⭐ Important Commands From the Module

## SMB Enumeration

```bash
sudo nmap <TARGET> -sV -sC -p139,445
```

## List SMB Shares

```bash
smbclient -N -L //<TARGET>
```

## SMBMap

```bash
smbmap -H <TARGET>
```

## Recursive Enumeration

```bash
smbmap -H <TARGET> -r <SHARE>
```

## Download

```bash
smbmap -H <TARGET> --download "<SHARE>\file"
```

## Upload

```bash
smbmap -H <TARGET> --upload file "<SHARE>\file"
```

## RPC Null Session

```bash
rpcclient -U'%' <TARGET>
```

## Domain Users

```text
enumdomusers
```

## Enum4linux-ng

```bash
./enum4linux-ng.py <TARGET> -A -C
```

---

# 70. 🔐 Credential Testing Concepts

### Brute Force

```text
ONE ACCOUNT
     +
MANY PASSWORDS
```

### Password Spray

```text
MANY ACCOUNTS
     +
ONE/Few PASSWORDS
```

### Pass-the-Hash

```text
USERNAME
   +
NTLM HASH
   ↓
AUTHENTICATION
```

### NTLM Relay

```text
VICTIM AUTHENTICATION
        ↓
      RELAY
        ↓
TARGET AUTHENTICATION
```

---

# 71. 🧠 Important Differences

|Concept|Main Idea|
|---|---|
|Null Session|Access SMB/RPC without credentials|
|Share Enumeration|Discover available network shares|
|Permission Enumeration|Determine READ/WRITE/NO ACCESS|
|Brute Force|Many passwords → one account|
|Password Spraying|One/few passwords → many accounts|
|PsExec|Execute commands through Windows service mechanism|
|SAM Dump|Obtain local account hash material|
|Pass-the-Hash|Authenticate using NTLM hash|
|Responder|Poison name resolution / capture authentication|
|NetNTLMv2 Cracking|Recover password from captured challenge-response|
|NTLM Relay|Relay captured authentication to another target|
|RPC|Remote procedure functionality and enumeration|

---

# 72. 🎯 Exam/Viva Questions

### Q1. What is SMB?

SMB is a network communication protocol used primarily for shared access to files, directories, printers, and other network resources.

### Q2. What are the main SMB ports?

```text
139/TCP
445/TCP
```

### Q3. What is Samba?

An open-source Unix/Linux implementation of SMB.

### Q4. What is a null session?

An SMB connection that does not require a username or password.

### Q5. Which tool lists SMB shares?

```text
smbclient
```

### Q6. Which option lists shares using smbclient?

```text
-L
```

### Q7. Which option specifies a null session?

```text
-N
```

### Q8. What is `smbmap` used for?

To enumerate SMB shares and their associated permissions.

### Q9. What does `READ, WRITE` indicate?

The account/session can potentially read/download and write/upload content in that share.

### Q10. What does `-r` do in smbmap?

It recursively enumerates a share's directories/files.

### Q11. What is RPC?

Remote Procedure Call, a mechanism for executing procedures/functions remotely.

### Q12. What is `rpcclient`?

A tool used to interact with SMB/RPC services and perform enumeration and other permitted RPC functions.

### Q13. What is enum4linux-ng?

An automated SMB enumeration utility.

### Q14. What is password spraying?

Trying one/few passwords against many accounts rather than many passwords against one account.

### Q15. What is PsExec?

A tool that can execute processes remotely using a Windows service mechanism.

### Q16. What is SAM?

Security Account Manager, which stores information associated with local Windows accounts and authentication.

### Q17. What is Pass-the-Hash?

Using an NTLM hash to authenticate instead of using the plaintext password.

### Q18. What is Responder?

A tool that can poison LLMNR/NBT-NS/MDNS and provide fake services to capture authentication material.

### Q19. What is NetNTLMv2?

A challenge-response authentication mechanism whose captured exchange can potentially be cracked offline if the password is weak.

### Q20. What is NTLM relay?

Relaying captured NTLM authentication to another service/host instead of cracking the password.

---

# 73. 🧠 Most Important Things to Memorize

## Ports

```text
137/UDP → NetBIOS Name
138/UDP → NetBIOS Datagram
139/TCP → SMB over NetBIOS
445/TCP → Direct SMB
```

## Enumeration

```text
Nmap
  ↓
139 / 445
```

## Null Session

```text
No Username
+
No Password
↓
SMB/RPC Enumeration
```

## Shares

```text
smbclient
   ↓
Shares

smbmap
   ↓
Shares + Permissions
```

## RPC

```text
rpcclient
   ↓
RPC Enumeration
```

## Automation

```text
enum4linux-ng
   ↓
SMB Enumeration
```

## Windows SMB

```text
Credentials
    ↓
Privileges
    ↓
RCE / SAM / Logged-on Users / PtH
```

## Authentication Attacks

```text
Brute Force
Password Spraying
Pass-the-Hash
NTLM Relay
```

## Forced Authentication

```text
LLMNR
NBT-NS
MDNS
   ↓
Responder
   ↓
NetNTLMv2
```

---

# 74. 🏆 Final SMB Mind Map

```text
                         SMB
                          │
            ┌─────────────┴─────────────┐
            │                           │
        PORTS                         TOOLS
            │                           │
       ┌────┴────┐            ┌─────────┼─────────┐
       │         │            │         │         │
     139       445         smbclient  smbmap  rpcclient
       │         │                         │
       │         │                         │
       └────┬────┘                    Permissions
            │
            ▼
       ENUMERATION
            │
       ┌────┴─────┐
       ▼          ▼
     NULL       CREDS
    SESSION       │
       │      ┌───┴────┐
       │      ▼        ▼
       │    Spray    Brute
       │
       ▼
     SHARES
       │
   ┌───┴────┐
   ▼        ▼
 READ      WRITE
   │        │
Download   Upload
   │        │
   └───┬────┘
       ▼
 WINDOWS SMB
       │
 ┌─────┼─────────┬─────────┐
 ▼     ▼         ▼         ▼
RCE   SAM    Logged-on    PtH
      Hashes   Users
       │
       ▼
    NTLM HASH
       │
  ┌────┴─────┐
  ▼          ▼
Crack       PtH

FORCED AUTHENTICATION
       │
       ▼
LLMNR/NBT-NS/MDNS
       │
       ▼
   Responder
       │
       ▼
  NetNTLMv2
       │
  ┌────┴─────┐
  ▼          ▼
Crack       Relay
```

# 🔥 Final Revision — SMB in 60 Seconds

> **SMB = Server Message Block**, primarily used for network file and printer sharing.

```text
TCP/139 → SMB over NetBIOS
TCP/445 → Direct SMB
```

### Enumeration:

```text
nmap -sV -sC -p139,445
```

### Null session:

```text
No username/password
```

### Shares:

```text
smbclient → enumerate/interact
smbmap    → shares + permissions
```

### RPC:

```text
rpcclient
enum4linux-ng
```

### If credentials are required:

```text
Brute Force
Password Spraying
```

### Windows SMB with sufficient privileges:

```text
PsExec
RCE
SAM extraction
Logged-on user enumeration
Pass-the-Hash
```

### Forced authentication:

```text
LLMNR/NBT-NS/MDNS
        ↓
Responder
        ↓
NetNTLMv2
        ↓
Crack OR Relay
```

### The single most important attack mindset:

```text
DISCOVER SMB
     ↓
IDENTIFY VERSION/OS
     ↓
CHECK NULL ACCESS
     ↓
ENUMERATE SHARES
     ↓
CHECK PERMISSIONS
     ↓
ENUMERATE USERS/RPC
     ↓
VALIDATE CREDENTIALS
     ↓
ASSESS PRIVILEGES
     ↓
WINDOWS-SPECIFIC ATTACK PATHS
     ↓
SAM / PtH / RCE / RELAY
```

This keeps the original module's progression intact while making the relationships between **SMB → shares → permissions → credentials → Windows privileges → NTLM attacks** much easier to revise.