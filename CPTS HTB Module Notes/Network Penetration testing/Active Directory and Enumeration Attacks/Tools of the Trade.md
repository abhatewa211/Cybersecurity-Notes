This section is the **toolkit/reference section** for the Active Directory module. I’ve kept the original tool names and their important purposes intact, while organizing them by what you should actually use them for during an AD assessment. The module states that Windows-host tools are available under `C:\Tools`, while the Parrot Linux attack host has the required tools installed or available under `/opt`.

---

# 1. 🧠 The Big Picture

Don't memorize this section as a random list of 40+ tools.

Think of the AD pentesting workflow:

```text
                         AD ASSESSMENT
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
   ENUMERATION           CREDENTIALS            ATTACK
        │                     │                     │
   ┌────┼────┐           ┌────┼────┐          ┌────┼────┐
   ▼    ▼    ▼           ▼    ▼    ▼          ▼    ▼    ▼
 LDAP  SMB   RPC       Kerberos NTLM Hashes   SMB  WMI  WinRM
   │    │    │           │      │      │       │    │    │
   └────┼────┘           └──────┼──────┘       └────┼────┘
        │                       │                   │
        └───────────────────────┼───────────────────┘
                                ▼
                           BLOODHOUND
                                │
                                ▼
                         ATTACK PATHS
                                │
                                ▼
                     PRIVILEGE ESCALATION
```

The important skill is understanding **which tool answers which question**.

---

# 2. 🪟 Windows vs 🐧 Linux Toolkit

![Image](https://images.openai.com/static-rsc-4/1SuWoTDOmuNvQ1O3Rh_VmXxc9gPauU2d1qBmJY-_8wFvUcjr2yI_SlTmsvCEO63v88-BA3h0IPl1Qa989HAVpMcSbMSksSEzkS3oDoV138PyLS5eq2WHgbnPeyG4h67VpjohtoV8Qfpbv0WTr1dvT-VRqyznwNBsF8MfWupnfqGrhuHXvNt6cuyEkBTReqpI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gIp3gmSklxXC6o3EXBYn5l9saskwEJ_gJtMngn8Z5dCi4Pdc0z5_JXDRiGCgU0ifDjj4maUs_yBlhZFQZaavqLFL2zpFim9Ll4fqRKPFqQtMPZ0QPmtgzaDahzS3RfT8-KAfjhVGxoPC7fYuzf0w2TkfIQoD-LIjbqBZDUeZQ0vnqcOAtEHfWEbm-fj3dv34?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/miMVjL744KwOpptBMlmgZ5OXker7GB-qYckn6q4E553uKf_egKL6AdcsuQKS8yxf59JPm0HcYn7nwQMZ2JM3-odcttbuRb9N0k6PufLLFJOxHVG1Txlf78QmYnNtb0MXuRx37CKuQNrv0VFA-2UV1qmyC7ELMIG8e_PDvVgScAYumMeJUAJYjipfRsy9zELu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0BJJ3X6sU1EhSIxHwC5vfJr62zc_VhWc4yOBfXSY0olznnwaAVvXyPSiojXV7jHZbYklfHUm4xh9T85BIcsmwA29E2LpI3GrAdrz7lrX3vMdm41jAsOWsoNDWTooPa0eabN74u14Hz98YnSCxnJgP7470WTmHAif91811u0swSdqV4j_FLYJGRu4uzxlMXHu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0p6bNI_gwSm9V385189ndq3iuecWJ7bWpvn-RR-IbV-4r6HCAKrsGDbk3xZC6UEuXXsP2ic5ZwyjUC1LstI6fMPXPMHF3fG7MIoKWxePOduSkozAEDL_hgz0cYz7BFhxQqNl99xleSgZUXYjLdOhz_6m8h1Vooo9XsN5V22oQRZS7EHETBz3V35RjV8f9mUP?purpose=fullsize)

### Windows attack host

Tools are provided under:

```text
C:\Tools
```

This environment is useful when you want to use:

- PowerShell
    
- PowerView
    
- SharpView
    
- BloodHound/SharpHound
    
- Rubeus
    
- Mimikatz
    
- Inveigh
    
- Native Windows AD utilities
    

### Linux attack host

The module provides a customized **Parrot Linux** host.

Tools are either:

```text
installed / PATH
```

or:

```text
/opt
```

---

# 3. ⭐ PowerView / SharpView

## PowerView

**PowerView** is a PowerShell tool used to gain **situational awareness in Active Directory**.

## SharpView

**SharpView** is a .NET port of PowerView.

The module describes these as replacements/supplements for various Windows `net*` commands and useful for gathering AD information.

### What are they useful for?

They can help enumerate:

```text
Users
Groups
Computers
Domains
Sessions
Permissions
Trusts
SPNs
```

They can also be useful when:

- You have new credentials.
    
- You want to check what those credentials can access.
    
- You're targeting a particular user.
    
- You're targeting a particular computer.
    
- You're looking for potential Kerberoasting targets.
    
- You're looking for potential ASREPRoasting targets.
    

### 🧠 Mentor Tip

PowerView is important because it teaches you **manual AD enumeration**.

Don't just run BloodHound and wait for an attack path.

Learn to ask:

```text
Who am I?
What domain am I in?
What users exist?
What groups exist?
What computers exist?
What sessions exist?
What permissions do I have?
```

---

# 4. 🩸 BloodHound

**BloodHound** is one of the most important tools in this module.

Its purpose is to:

> **Visually map out AD relationships and help plan attack paths that may otherwise go unnoticed.**

The module explains that BloodHound uses **SharpHound** as an ingestor/collector, with collected data subsequently analyzed through the BloodHound application and Neo4j database.

![Image](https://images.openai.com/static-rsc-4/6H0tAcHWatXzMDK9jr644zXdF-8s7XTrE1YONjcWIu_kPifepXOaA8_4lrnRSIE1m93QhF4OPrMH8JT5eoZ57ssYqhn_pG3LNUS_9ecKN0njcaWFluBoDQb9G-OkoqNy3e-_JsT2bbJrtxWQdeNSroRfdMT70XFKv5E0bxlEiDWsYI-11faBgJ_nArlZUskd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DTvGz1mQOOguoadDBjp9UQKrIkiFtaIaVZMj8UIrqjvXYkdOdLqpHGhfa1bPr2cuxecmoc3tyeCvIM8BA92_7zbdrcF12RgoiDxOiAjtURYltw2kOaz5WdAf0_4VxwUWeC-oIBxXAHsRIs_Awr56avmgF8eaY-plsgunpExmKwDQygglTVvvlFZlqAU5F1Tw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0hkVn3R05iGcXFvXsvwG-Xl1LdEq6ok92AIcpHfrJx1ed2fdINSfJ7fml3DOz-8_1fvxYJk5icuoCNM_dmGkO0bsSiwLCGgOGqOmRP5zD6qXW_3-3_C1FS8NjCaopqZwi2EcUjJa00KP5jno7zr4TyQz_PRmq0ZTsqWzJRG6rWkPlMOaU4GjSbp7DUeNqJnQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8SE4htFMifwdIebtxIrvPC5x-G6gEjfwKfkgovgF5hWyE8x1qu759zEfRirDNCbdkpcE6E16fSu2E-c_JtGHoROzbmpe8F70QZ0Vaf2qoxeyq8kV6b-wNddilw-oMKUHKgCFTucns9SXVG_IGREX0SHycPenE0y4K0jLP9HWEJ66giteN5BgMakownFyzPlo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/klBNlv43TgdJIpphdpV2J3UQX59kuMqIKAtZLUdwX8fRvlzPbSOOpbB78tuDrRBgdcuWhNa0amByr8efVoVAqHRWsf1jmn3gc-rcyEdnGJ5fY3IxQX93N_iHnaiikaWPKrDkE83pj48KvuF3Kt2ls9DzNTREALIm9rT3J2BtlQESp_7b9HxB84_99WRni0Al?purpose=fullsize)

### Think of BloodHound as:

```text
Raw AD information
       ↓
Relationships
       ↓
Graph
       ↓
Attack paths
```

For example:

```text
User
 │
 └── MemberOf ──► Help Desk
                       │
                       └── GenericAll ──► Group
                                             │
                                             └──► High Privilege
```

### 🔥 Important

BloodHound doesn't magically create a vulnerability.

It **visualizes relationships and permissions that already exist in the environment**.

---

# 5. SharpHound

**SharpHound** is the **C# data collector** used to gather information from Active Directory.

It can collect information about:

- Users
    
- Groups
    
- Computers
    
- ACLs
    
- GPOs
    
- User attributes
    
- Computer attributes
    
- User sessions
    
- Other AD relationships
    

The resulting data is produced as **JSON files**, which can then be imported into BloodHound for analysis.

### Architecture

```text
                 Active Directory
                       │
                       ▼
                  SharpHound
                       │
                       ▼
                  JSON Files
                       │
                       ▼
                  BloodHound
                       │
                       ▼
                    Neo4j
                       │
                       ▼
                 Graph Analysis
```

### Remember

```text
SharpHound = Collector
BloodHound = Analysis / Visualization
```

---

# 6. 🐍 BloodHound.py

**BloodHound.py** is a Python-based BloodHound ingestor based on the **Impacket toolkit**.

A particularly important feature from the module:

> It can run from a **non-domain-joined attack host**.

This makes it especially useful when your Linux attack machine isn't joined to the target domain.

### Mental model

```text
Linux Attack Host
       │
       │ BloodHound.py
       ▼
AD Enumeration
       │
       ▼
Collection Data
       │
       ▼
BloodHound
```

---

# 7. 🔑 Kerbrute

**Kerbrute** is written in Go and uses **Kerberos Pre-Authentication**.

The module identifies three major uses:

- AD account enumeration
    
- Password spraying
    
- Brute-forcing
    

### Common workflow

```text
Potential usernames
       ↓
Kerbrute
       ↓
Valid AD accounts
       ↓
Targeted password spray
```

### 🧠 Important

Username enumeration can be valuable because you don't want to blindly spray random usernames.

The more accurate your user list is, the more controlled your testing can be.

---

# 8. 🧰 Impacket

**Impacket** is a collection of Python tools for interacting with network protocols.

The module highlights its extensive use for:

> **Enumerating and attacking Active Directory.**

You'll encounter many Impacket tools throughout AD labs.

Important examples in this module include:

```text
GetUserSPNs.py
GetNPUsers.py
psexec.py
wmiexec.py
secretsdump.py
mssqlclient.py
ntlmrelayx.py
rpcdump.py
lookupsid.py
ticketer.py
raiseChild.py
smbserver.py
```

### 🧠 Mentor Tip

Don't learn "Impacket" as one tool.

Think:

```text
Impacket
   │
   ├── Kerberos
   ├── SMB
   ├── RPC
   ├── WMI
   ├── LDAP
   ├── NTLM
   └── Other Windows protocols
```

---

# 9. 📡 Responder

**Responder** is designed to poison:

- LLMNR
    
- NBT-NS
    
- mDNS
    

and perform various related functions.

### Basic concept

```text
Windows Host
     │
     │ Name resolution request
     ▼
Network
     │
     ▼
Responder
     │
     ▼
Spoofed response
     │
     ▼
Authentication attempt
     │
     ▼
Captured authentication material
```

This is particularly important in internal network assessments.

---

# 10. Inveigh.ps1

**Inveigh** is a PowerShell-based tool similar to Responder.

It performs various:

- Network spoofing
    
- Network poisoning
    
- Authentication capture
    

operations.

### Why learn it?

Because you may be operating from:

```text
Windows
```

where using PowerShell-native tooling may be more practical than deploying Linux tools.

---

# 11. InveighZero

**InveighZero** is the C# version of Inveigh.

The module highlights its semi-interactive console for interacting with captured information such as:

```text
Usernames
Password hashes
```

---

# 12. RPC Tools

## rpcinfo

`rpcinfo` can:

- Query the status of an RPC program.
    
- Enumerate available RPC services on a remote host.
    

The module gives:

```bash
rpcinfo -p 10.0.0.1
```

as an example.

The `-p` option specifies the target host.

### Think:

```text
Target
  ↓
RPC Endpoint
  ↓
rpcinfo
  ↓
Available RPC services
```

---

# 13. rpcclient

`rpcclient` is part of the Samba suite on Linux.

It can perform various **Active Directory enumeration tasks through remote RPC services**.

This is an important tool when you're investigating:

```text
SMB/RPC
```

from Linux.

---

# 14. CrackMapExec (CME)

The module describes **CrackMapExec (CME)** as an:

- Enumeration toolkit
    
- Attack toolkit
    
- Post-exploitation toolkit
    

It can help with enumeration and attacks using information gathered from the environment.

It also attempts to:

> **"live off the land"**

and abuse built-in AD protocols/features such as:

- SMB
    
- WMI
    
- WinRM
    
- MSSQL
    

### Mental model

```text
Credentials
     │
     ▼
CME
     │
 ┌───┼────┬─────┐
 ▼   ▼    ▼     ▼
SMB WMI WinRM MSSQL
 │   │    │     │
 └───┴────┴─────┘
         │
         ▼
Enumeration / Access
```

> **Note:** The module refers to CME; in modern environments you may also encounter **NetExec (nxc)** as its successor/fork. That distinction is outside the uploaded source, so treat it as additional context rather than module material.

---

# 15. 🎟️ Rubeus

**Rubeus** is a C# tool specifically built for:

> **Kerberos abuse**

You will encounter Rubeus when studying things such as:

- Kerberos tickets
    
- TGTs
    
- TGSs
    
- Ticket extraction
    
- Ticket manipulation
    
- Kerberos-based attacks
    

### Mental model

```text
Active Directory
      │
      ▼
  Kerberos
      │
      ▼
    Rubeus
      │
 ┌────┼────┐
 ▼    ▼    ▼
TGT  TGS  Tickets
```

---

# 16. GetUserSPNs.py

This is an **Impacket module** designed to find:

> **Service Principal Names tied to normal users.**

### Why is that important?

Because SPNs are central to:

```text
Kerberoasting
```

So the conceptual chain is:

```text
GetUserSPNs.py
       ↓
Find SPNs
       ↓
Identify service accounts
       ↓
Kerberoasting opportunity
```

---

# 17. Hashcat

**Hashcat** is a password/hash cracking and recovery tool.

It becomes relevant when you've obtained crackable authentication material.

### Conceptual workflow

```text
Hash / Ticket Material
        ↓
Hashcat
        ↓
Candidate Passwords
        ↓
Hash Comparison
        ↓
Potential Password Recovery
```

### 🧠 Important

Hashcat does **not exploit AD itself**.

It is generally used after you have obtained authentication material that can be attacked offline.

---

# 18. enum4linux

`enum4linux` is used to enumerate information from:

- Windows systems
    
- Samba systems
    

It can be useful during early enumeration.

Think:

```text
Windows/Samba
     ↓
SMB/RPC
     ↓
enum4linux
     ↓
Users / Groups / Shares / Domain information
```

---

# 19. enum4linux-ng

`enum4linux-ng` is a rework of the original `enum4linux`.

The module notes that it works somewhat differently from the original version.

---

# 20. LDAP Enumeration

## ldapsearch

`ldapsearch` is an interface for interacting with the **LDAP protocol**.

This is important because AD exposes directory information through LDAP.

### Concept

```text
AD
│
└── LDAP
      │
      ▼
  ldapsearch
      │
      ▼
Directory Queries
      │
      ▼
Users / Groups / Computers / Attributes
```

---

# 21. windapsearch

**windapsearch** is a Python script for enumerating:

- AD users
    
- Groups
    
- Computers
    

using LDAP queries.

It is particularly useful for automating **custom LDAP queries**.

### Difference to remember

```text
ldapsearch
    ↓
General LDAP interface

windapsearch
    ↓
AD-focused Python enumeration
```

---

# 22. DomainPasswordSpray.ps1

This is a PowerShell tool designed to perform a:

> **Password spray attack against domain users.**

Conceptually:

```text
Domain Users
     │
     ▼
Password Spray
     │
     ▼
Potential Valid Credentials
```

### ⚠️ Important

Password spraying must be performed within the rules and constraints of the authorized assessment, especially regarding account lockout.

---

# 23. LAPSToolkit

**LAPSToolkit** contains PowerShell functions that leverage **PowerView** to audit and attack AD environments where Microsoft's:

> **Local Administrator Password Solution (LAPS)**

has been deployed.

### What is LAPS?

LAPS is designed to manage local administrator passwords on Windows computers.

From a security-testing perspective, you want to understand:

```text
LAPS deployed?
      ↓
Who can read LAPS passwords?
      ↓
Are permissions correctly configured?
      ↓
Could an unauthorized account obtain them?
```

---

# 24. smbmap

`smbmap` is used for:

> **SMB share enumeration across a domain.**

### Mental model

```text
Domain
  │
  ├── Host 1
  │    ├── Share A
  │    └── Share B
  │
  ├── Host 2
  │    └── Share C
  │
  └── Host 3
       └── Share D
```

`smbmap` helps you understand available SMB shares and your access to them.

---

# 25. psexec.py

`psexec.py` is an Impacket tool that provides:

> **PsExec-like functionality in the form of a semi-interactive shell.**

Conceptually:

```text
Valid Credentials
       ↓
SMB / Remote Service Mechanism
       ↓
Remote Command Execution
       ↓
Interactive Shell
```

---

# 26. wmiexec.py

`wmiexec.py` is another Impacket tool.

It provides:

> **Command execution over WMI.**

### Concept

```text
Attacker
   │
   ▼
WMI
   │
   ▼
Remote Windows Host
   │
   ▼
Command Execution
```

---

# 27. Snaffler

**Snaffler** is useful for finding information such as:

> **Credentials in Active Directory environments on computers with accessible file shares.**

### Why file shares matter

Organizations often accidentally store sensitive information in:

```text
\\SERVER\Share
```

Examples can include:

- Configuration files
    
- Scripts
    
- Credentials
    
- Documents
    
- Backups
    

During an authorized assessment, this can become an important source of information.

---

# 28. smbserver.py

`smbserver.py` is an Impacket tool that provides a:

> **Simple SMB server**

and makes it easy to transfer files between systems on a network.

Conceptually:

```text
Linux Attack Host
      │
      │ SMB
      ▼
Windows Host
```

---

# 29. setspn.exe

`setspn.exe` is a native Windows utility for:

- Adding SPNs
    
- Reading SPNs
    
- Modifying SPNs
    
- Deleting SPNs
    

for an Active Directory service account.

### Remember

```text
SPN
 ↓
Service ↔ Account mapping
```

And because SPNs are closely connected to Kerberos service authentication, they are important when studying:

**Kerberoasting.**

---

# 30. Mimikatz

**Mimikatz** is a highly capable credential and Windows security testing tool.

The module specifically highlights:

- Pass-the-Hash
    
- Extracting plaintext passwords
    
- Kerberos ticket extraction from memory
    

### Mental model

```text
Windows Memory
      │
      ▼
  Mimikatz
      │
 ┌────┼──────────┐
 ▼    ▼          ▼
NTLM Passwords  Kerberos
Hash  material   Tickets
```

---

# 31. secretsdump.py

`secretsdump.py` is an Impacket tool that can remotely dump:

- SAM secrets
    
- LSA secrets
    

from a host.

### Think:

```text
Windows Host
     │
     ├── SAM
     │
     └── LSA Secrets
            │
            ▼
      secretsdump.py
```

This becomes particularly important in credential-access and post-exploitation exercises.

---

# 32. evil-winrm

**evil-winrm** provides an interactive shell over:

> **Windows Remote Management (WinRM)**

Conceptually:

```text
Valid Credentials
       ↓
     WinRM
       ↓
evil-winrm
       ↓
Remote Windows Shell
```

---

# 33. mssqlclient.py

`mssqlclient.py` is part of Impacket and allows interaction with:

> **Microsoft SQL Server (MSSQL)**

This becomes relevant when MSSQL is exposed in an AD environment.

---

# 34. noPac.py

`noPac.py` is described in the module as an exploit combination involving:

```text
CVE-2021-42278
+
CVE-2021-42287
```

with the objective of impersonating a Domain Administrator from a standard domain user.

### Mental model

```text
Standard Domain User
        ↓
Vulnerable AD configuration/version
        ↓
CVE-2021-42278
        +
CVE-2021-42287
        ↓
Privilege escalation
        ↓
Domain Admin impersonation
```

This is an example where **version/configuration-specific vulnerabilities** can provide an alternative route to domain compromise.

---

# 35. rpcdump.py

`rpcdump.py` is an Impacket tool functioning as an:

> **RPC endpoint mapper**

Think:

```text
Remote Host
    ↓
RPC Endpoint Mapper
    ↓
rpcdump.py
    ↓
RPC endpoints/services
```

---

# 36. CVE-2021-1675.py — PrintNightmare

The module lists this Python proof-of-concept for:

> **PrintNightmare**

associated with **CVE-2021-1675**.

This represents another category of AD attack:

```text
Vulnerability
      ↓
Windows Print Spooler
      ↓
Potential Remote/Local Code Execution
      ↓
Privilege Escalation / Lateral Movement
```

---

# 37. ntlmrelayx.py

`ntlmrelayx.py` is an Impacket tool for performing:

> **SMB relay attacks**

### Conceptual attack chain

```text
Victim
  │
  │ NTLM Authentication
  ▼
Attacker
  │
  │ Relay
  ▼
Target Service
  │
  ▼
Authenticated Action
```

This is an important concept when studying **NTLM relay**.

---

# 38. PetitPotam.py

The module describes PetitPotam as a PoC for:

> **CVE-2021-36942**

It can coerce Windows hosts to authenticate to another machine using **MS-EFSRPC** functions such as `EfsRpcOpenFileRaw`.

Conceptually:

```text
Attacker
   │
   ▼
Coerce Windows Host
   │
   ▼
Forced Authentication
   │
   ▼
Attacker-controlled destination
   │
   ▼
NTLM Relay opportunities
```

This is especially relevant when studying coercion + relay attack chains.

---

# 39. gettgtpkinit.py

`gettgtpkinit.py` is part of PKINITtools.

The module describes it as a tool for manipulating:

- Certificates
    
- TGTs
    

### Key concept

```text
PKINIT
  ↓
Certificate-based Kerberos authentication
  ↓
TGT
```

---

# 40. getnthash.py

This tool uses an existing **TGT** to request a **PAC** for the current user using **U2U**.

Important terms:

```text
TGT
PAC
U2U
```

We'll break these down properly when the module reaches the relevant attack.

---

# 41. adidnsdump

**adidnsdump** is used to:

> Enumerate and dump DNS records from a domain.

The module compares its functionality conceptually to performing a DNS Zone transfer.

### Why DNS matters

DNS can reveal:

```text
Hosts
Servers
Services
Naming conventions
Infrastructure
```

So:

```text
AD Enumeration
      ↓
DNS Enumeration
      ↓
Infrastructure Discovery
```

---

# 42. gpp-decrypt

`gpp-decrypt` is designed to extract:

> **Usernames and passwords from Group Policy Preferences files.**

### Security concept

Historically, credentials stored in certain Group Policy Preferences could become an avenue for credential disclosure.

The key lesson is:

> **Configuration files can contain sensitive information.**

---

# 43. GetNPUsers.py — ASREPRoasting

This is an extremely important tool.

`GetNPUsers.py` is used to perform:

> **ASREPRoasting**

against users who have:

```text
Do not require Kerberos preauthentication
```

enabled.

The tool can list and obtain **AS-REP hashes**, which can then be passed to a tool such as Hashcat for offline password cracking.

### Attack chain

```text
User Account
      │
      ▼
Preauthentication Disabled
      │
      ▼
AS-REQ
      │
      ▼
AS-REP
      │
      ▼
AS-REP Hash
      │
      ▼
Hashcat
      │
      ▼
Potential Password Recovery
```

### ⭐ Remember

```text
Kerberoasting
    ↓
SPN / Service Account

ASREPRoasting
    ↓
Kerberos Preauthentication Disabled
```

This distinction is **very important for your exam and labs**.

---

# 44. lookupsid.py

`lookupsid.py` is described as a:

> **SID bruteforcing tool.**

This can help enumerate accounts and security identifiers when conditions permit.

---

# 45. ticketer.py

`ticketer.py` is used for:

- Creation of TGT/TGS tickets
    
- Ticket customization
    
- Golden Ticket creation
    
- Child-to-parent trust attacks
    

### Conceptual picture

```text
Kerberos
   │
   ▼
TGT / TGS
   │
   ▼
ticketer.py
   │
   ├── Ticket creation
   ├── Ticket customization
   └── Golden Ticket
```

---

# 46. raiseChild.py

`raiseChild.py` is an Impacket tool for:

> **Automated child-to-parent domain privilege escalation.**

This is related to AD trust/domain hierarchy concepts.

Think:

```text
Child Domain
     │
     │ Trust / privilege relationship
     ▼
Parent Domain
     │
     ▼
Higher-level privileges
```

---

# 47. Active Directory Explorer — AD Explorer

**AD Explorer** is a graphical:

> **Active Directory viewer and editor.**

It can:

- Navigate the AD database
    
- View object properties
    
- View attributes
    
- Save AD database snapshots
    
- Analyze snapshots offline
    
- Compare snapshots
    
- Identify changes to:
    
    - Objects
        
    - Attributes
        
    - Security permissions
        

### 🧠 Why this is useful

It gives you a more direct view of AD objects.

```text
AD Explorer
    ↓
Objects
    ↓
Attributes
    ↓
Permissions
    ↓
Snapshots
    ↓
Offline comparison
```

---

# 48. PingCastle

**PingCastle** is primarily an AD security auditing tool.

The module describes it as assessing the security level of an AD environment using:

> **A risk assessment and maturity framework**

adapted to AD security.

### Think:

```text
Active Directory
      ↓
PingCastle
      ↓
Security Assessment
      ↓
Risk / Maturity Findings
```

This is particularly relevant from a **defensive/GRC perspective**.

---

# 49. Group3r

**Group3r** is used for auditing and finding security misconfigurations in:

> **Active Directory Group Policy Objects (GPOs).**

### Mental model

```text
AD
 ↓
GPOs
 ↓
Group3r
 ↓
Misconfigurations
 ↓
Security Findings
```

---

# 50. ADRecon

**ADRecon** extracts various information from a target AD environment.

The output can be placed into:

> **Microsoft Excel format**

with summary views and analysis to help build an overall picture of the AD environment's security state.

### Think:

```text
Active Directory
       ↓
    ADRecon
       ↓
Large-scale Data Collection
       ↓
Excel Reports
       ↓
Environment Analysis
```

---

# 51. 🔥 Tool Categories — Memorize This

Instead of memorizing 40 individual tools, first memorize their **category**.

|Category|Important Tools|
|---|---|
|**AD Enumeration**|PowerView, SharpView, BloodHound, SharpHound|
|**LDAP**|ldapsearch, windapsearch|
|**SMB**|smbmap, enum4linux, enum4linux-ng|
|**RPC**|rpcclient, rpcinfo, rpcdump|
|**Kerberos**|Rubeus, Kerbrute, GetUserSPNs.py, GetNPUsers.py|
|**Credential Attacks**|Hashcat, Mimikatz, secretsdump.py|
|**Network Poisoning**|Responder, Inveigh|
|**Remote Execution**|psexec.py, wmiexec.py, evil-winrm|
|**SMB Relay**|ntlmrelayx.py|
|**Coercion**|PetitPotam.py|
|**DNS**|adidnsdump|
|**LAPS**|LAPSToolkit|
|**MSSQL**|mssqlclient.py|
|**GPO**|Group3r|
|**AD Auditing**|PingCastle, ADRecon|
|**AD GUI**|AD Explorer|
|**Ticket Manipulation**|ticketer.py|
|**Trust Escalation**|raiseChild.py|

---

# 52. 🧠 "Which Tool Should I Use?" Cheat Sheet

When you encounter a situation, think:

### "I need AD situational awareness."

➡️ **PowerView / SharpView**

### "I want graphical AD relationships."

➡️ **BloodHound**

### "I need to collect BloodHound data."

➡️ **SharpHound / BloodHound.py**

### "I need valid usernames."

➡️ **Kerbrute**

### "I need to enumerate LDAP."

➡️ **ldapsearch / windapsearch**

### "I need SMB information."

➡️ **enum4linux / smbmap**

### "I need RPC information."

➡️ **rpcclient / rpcinfo / rpcdump.py**

### "I need SPNs."

➡️ **GetUserSPNs.py / setspn.exe**

### "I need Kerberos abuse."

➡️ **Rubeus**

### "I need offline password cracking."

➡️ **Hashcat**

### "I need NTLM/network poisoning."

➡️ **Responder / Inveigh**

### "I need remote execution through SMB."

➡️ **psexec.py**

### "I need remote execution through WMI."

➡️ **wmiexec.py**

### "I need WinRM shell."

➡️ **evil-winrm**

### "I need SMB shares."

➡️ **smbmap**

### "I need to investigate file shares for sensitive information."

➡️ **Snaffler**

### "I need ASREPRoasting."

➡️ **GetNPUsers.py**

### "I need Kerberoasting enumeration."

➡️ **GetUserSPNs.py**

### "I need SAM/LSA secrets."

➡️ **secretsdump.py**

### "I need ticket creation/manipulation."

➡️ **ticketer.py**

### "I need GPO security auditing."

➡️ **Group3r**

### "I need an overall AD security assessment."

➡️ **PingCastle / ADRecon**

---

# 53. 🔥 Critical Tool Relationships

Some tools make much more sense when you connect them together.

## Kerberoasting

```text
GetUserSPNs.py
      ↓
    SPNs
      ↓
 Kerberoasting
      ↓
   Hashcat
```

## ASREPRoasting

```text
GetNPUsers.py
      ↓
AS-REP hashes
      ↓
   Hashcat
```

## BloodHound

```text
SharpHound
     ↓
Collection
     ↓
JSON
     ↓
BloodHound
     ↓
Relationships
     ↓
Attack Path
```

## NTLM Relay

```text
Responder / PetitPotam
          ↓
Authentication
          ↓
     NTLM Relay
          ↓
     ntlmrelayx
          ↓
 Target Service
```

## Remote Windows Access

```text
Credentials
     │
 ┌───┼──────────────┐
 ▼   ▼              ▼
SMB WMI            WinRM
 │   │              │
 ▼   ▼              ▼
psexec wmiexec    evil-winrm
```

---

# 54. ⭐ The Most Important Mentor Lesson

Don't memorize:

> "PowerView is for AD."

That's too vague.

Instead ask:

> **What information am I trying to obtain?**

For example:

```text
Question:
"What users exist?"

Possible approach:
LDAP / PowerView / enum4linux / BloodHound collection
```

Another:

```text
Question:
"Which accounts have SPNs?"

Possible approach:
GetUserSPNs.py / PowerView / setspn
```

Another:

```text
Question:
"What relationships could lead to privilege escalation?"

Possible approach:
BloodHound
```

Another:

```text
Question:
"Can I interact with the remote Windows host through WinRM?"

Possible approach:
evil-winrm
```

That's how a **pentester thinks**.

---

# 🧠 Final Revision Map

```text
                         ACTIVE DIRECTORY
                                │
               ┌────────────────┼────────────────┐
               │                │                │
               ▼                ▼                ▼
          ENUMERATION       CREDENTIALS       SERVICES
               │                │                │
      ┌────────┼───────┐    ┌───┼────┐     ┌────┼────┐
      ▼        ▼       ▼    ▼   ▼    ▼     ▼    ▼    ▼
     LDAP     SMB     RPC  NTLM Kerb Hash  SMB  WMI WinRM
      │        │       │    │    │    │      │    │    │
      ▼        ▼       ▼    ▼    ▼    ▼      ▼    ▼    ▼
 ldapsearch  smbmap rpcclient Responder Rubeus Hashcat psexec wmiexec evil-winrm
 windapsearch enum4linux
      │
      └──────────────────────┐
                             ▼
                        BLOODHOUND
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
                SharpHound       BloodHound.py
                    │                 │
                    └────────┬────────┘
                             ▼
                       ATTACK PATHS
                             │
          ┌──────────────────┼──────────────────┐
          ▼                  ▼                  ▼
     Kerberoasting       ASREPRoasting       NTLM Relay
          │                  │                  │
     GetUserSPNs        GetNPUsers          ntlmrelayx
          │                  │                  │
          └────────────┬─────┴──────────────────┘
                       ▼
                 HASH / TICKET
                    ATTACKS
                       │
            ┌──────────┼──────────┐
            ▼          ▼          ▼
         Hashcat    Mimikatz   Rubeus
                       │
                       ▼
                 PRIVILEGE
                 ESCALATION
                       │
                       ▼
                DOMAIN COMPROMISE
```

## 🎯 What I want you to remember before the exercises

**Tools are not the skill.**

The skill is:

**Question → Enumeration → Evidence → Interpretation → Attack path → Validation → Impact**

For example:

```text
"Can I find a service account?"
        ↓
Enumerate SPNs
        ↓
Find account
        ↓
Understand its privileges
        ↓
Determine whether Kerberoasting applies
        ↓
Obtain authorized test material
        ↓
Offline analysis
        ↓
Determine impact
```

The module's toolkit section contains the full list of tools we'll encounter, so we'll refer back to these notes as we reach each exercise.

**Next step:** send me the **next section/module content**, and I'll continue building these notes in the same format. After the notes are complete, we'll switch to **Exercise Mode** and solve the questions one at a time without skipping the reasoning.