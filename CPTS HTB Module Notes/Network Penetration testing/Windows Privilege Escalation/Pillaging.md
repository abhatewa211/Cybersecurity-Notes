This is a **high-value CPTS section** because it changes the mindset from _“How do I exploit this machine?”_ to:

> **“What information can I extract from this compromised system that helps me move further through the environment?”**

Pillaging means obtaining useful information from a compromised system, including credentials, infrastructure information, application data, network details, backups, and other information relevant to the penetration-test objectives.

---

# 1. What Is Pillaging?

After obtaining a foothold, you shouldn't immediately stop at:

```text
whoami
ipconfig
```

You should start building an **information profile** of the compromised environment.

Pillaging can reveal:

```text
Credentials
Passwords
Network information
Server information
Application configurations
Database information
Domain information
Source code
Backups
User information
Infrastructure details
```

The purpose is generally to support:

```text
Initial Foothold
      ↓
Pillaging
      ↓
Interesting Information
      ↓
Credentials / Infrastructure
      ↓
Lateral Movement
      ↓
Privilege Escalation
      ↓
Further Access
```

The source emphasizes that the information obtained should support the goals established during the penetration-test **pre-engagement** process.

---

# 2. Pillaging Data Sources

This is one of the most important lists to memorize.

The source identifies many potential sources:

|Category|Examples|
|---|---|
|Installed applications|mRemoteNG, browsers, Office, etc.|
|Installed services|Windows services|
|Websites|IIS/web applications|
|File shares|SMB/network shares|
|Databases|SQL databases|
|Directory services|AD / Azure AD|
|Name servers|DNS infrastructure|
|Deployment services|Software deployment|
|Certificate Authority|PKI infrastructure|
|Source Code Management|Git/source repositories|
|Virtualization|VMs/hypervisors|
|Messaging|Slack, Teams, etc.|
|Monitoring/logging|Logs and monitoring systems|
|Backups|Backup repositories|
|History files|Command/browser history|
|Documents|Office files, password files|
|Roles/privileges|User and service accounts|
|Web browsers|Cookies, saved information|
|IM clients|Chats and stored data|
|Keylogging|User input|
|Screen capture|Visual information|
|Network capture|Network traffic|
|Audit reports|Previous assessments|

### CPTS principle

> **Anything that provides information about the target can potentially be valuable.**

The source explicitly says the list isn't complete and that familiarity with applications and middleware is important because different applications store data in different formats and locations.

---

# 3. The Pillaging Mindset

After compromising a machine:

```text
          COMPROMISED HOST
                 │
     ┌───────────┼───────────┐
     ▼           ▼           ▼
 Applications  Users       Network
     │           │           │
     ▼           ▼           ▼
 Configs      Credentials  Hosts
     │           │           │
     └───────────┼───────────┘
                 ▼
             Databases
                 │
                 ▼
              Backups
                 │
                 ▼
        Further Information
```

Don't treat the host as an isolated machine.

Treat it as a **window into the organization**.

---

# 4. Installed Applications

One of the first things to investigate is:

> **What software is installed?**

Knowing the applications can reveal:

- Credential stores
    
- Configuration files
    
- Known vulnerabilities
    
- Network connections
    
- Remote-management tools
    
- Password databases
    
- Backup software
    
- Development tools
    

The source recommends quickly reviewing:

```text
C:\Program Files
C:\Program Files (x86)
```

using:

```cmd
dir "C:\Program Files"
```

Example applications discovered:

```text
Adobe
Corsair
Google
Microsoft Office
mRemoteNG
OpenVPN
Streamlabs OBS
TeamViewer
```

---

# 5. Better Installed-Software Enumeration

PowerShell can obtain more detailed information from the Windows Registry.

### 64-bit applications

```powershell
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, InstallLocation
```

### 32-bit applications

```powershell
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, InstallLocation
```

### Display the results

```powershell
$INSTALLED |
?{ $_.DisplayName -ne $null } |
sort-object -Property DisplayName -Unique |
Format-Table -AutoSize
```

### CPTS tip

Know **both** registry locations:

```text
HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
```

and:

```text
HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
```

---

# 6. mRemoteNG

The source discovers:

```text
mRemoteNG
```

mRemoteNG is a remote-management application used for connections such as:

- VNC
    
- RDP
    
- SSH
    
- Similar remote protocols
    

### Why is it interesting?

mRemoteNG stores connection information and credentials in:

```text
confCons.xml
```

The default configuration directory is:

```text
%USERPROFILE%\APPDATA\Roaming\mRemoteNG
```

---

# 7. Find mRemoteNG Configuration

Example:

```powershell
ls C:\Users\julio\AppData\Roaming\mRemoteNG
```

The source finds:

```text
Themes
confCons.xml
mRemoteNG.log
```

The important file is:

```text
confCons.xml
```

---

# 8. Understanding `confCons.xml`

The XML contains information such as:

```text
Username
Domain
Hostname
Protocol
Port
Password
```

The source's example includes:

```xml
<Node Name="RDP_Domain"
      Type="Connection"
      Username="administrator"
      Domain="test.local"
      Password="..."
      Hostname="10.0.0.10"
      Protocol="RDP"
      Port="3389">
```

### Important distinction

Most connection information is readable:

```text
Username
Domain
Hostname
Protocol
Port
```

but:

```text
Password
```

is encrypted.

The XML also contains:

```text
Protected
```

which is associated with the master-password protection mechanism.

---

# 9. mRemoteNG Decryption

The source uses:

```text
mRemoteNG-Decrypt
```

If the user didn't configure a custom master password, the source demonstrates:

```bash
python3 mremoteng_decrypt.py -s "<Password attribute>"
```

Example result:

```text
Password: ASDki230kasd09fk233aDA
```

### CPTS workflow

```text
Find installed application
        ↓
Identify credential storage
        ↓
Find configuration file
        ↓
Identify encryption
        ↓
Find default/custom protection
        ↓
Decrypt credential
        ↓
Validate credential
        ↓
Use for authorized lateral movement
```

---

# 10. Custom mRemoteNG Master Password

If the user configured a custom master password, attempting decryption without it produces:

```text
ValueError: MAC check failed
```

With the correct password:

```bash
python3 mremoteng_decrypt.py \
-s "<encrypted_password>" \
-p admin
```

the source successfully decrypts the password.

---

# 11. Cracking the Master Password

The source demonstrates testing passwords from a wordlist using a Bash loop:

```bash
for password in $(cat /usr/share/wordlists/fasttrack.txt); do
    echo $password
    python3 mremoteng_decrypt.py \
    -s "<encrypted_password>" \
    -p $password 2>/dev/null
done
```

The example finds:

```text
admin
```

as the correct custom password.

### Important concept

The source explains that you can attempt to crack:

```text
Protected
```

or:

```text
Password
```

directly.

---

# 12. IM Clients — Slack / Teams

Modern organizations heavily use:

- Slack
    
- Microsoft Teams
    
- Other messaging applications
    

If you compromise a user's account/session and gain access to an IM client, you may find valuable information in:

```text
Private chats
Group chats
Channels
Shared credentials
Internal discussions
```

The source specifically recommends searching for terms such as:

```text
password
credentials
PII
```

---

# 13. Credentials vs Cookies

Normally, you might authenticate to an application using:

```text
Username + Password
```

But what if:

```text
MFA enabled
```

or:

```text
plaintext password unavailable
```

The source discusses obtaining the user's **session/authentication cookies** instead.

### Mental model

```text
Password authentication
        │
        ▼
      Login
        │
        ▼
    Session Cookie
        │
        ▼
  Authenticated Browser
```

If an attacker obtains a valid authentication cookie, the cookie may provide access without requiring the plaintext password.

---

# 14. Slack Cookie Example

The source discusses a Slack cookie named:

```text
d
```

and explains that research had associated it with the user's authentication token. It also explicitly cautions that Slack's behavior may have changed since those older research articles.

### Important CPTS caveat

This is **version/application dependent**.

Don't memorize:

> "Slack always uses cookie X."

Instead memorize:

> **Investigate how the target application's current authentication/session mechanism works.**

---

# 15. Firefox Cookies

Firefox stores cookies in:

```text
cookies.sqlite
```

The source gives the location:

```text
%APPDATA%\Mozilla\Firefox\Profiles\<RANDOM>.default-release
```

The source copies the database using:

```powershell
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```

---

# 16. Extracting Cookies

The source uses:

```text
cookieextractor.py
```

Example:

```bash
python3 cookieextractor.py \
--dbpath "/home/plaintext/cookies.sqlite" \
--host slack \
--cookie d
```

The result contains the cookie value.

---

# 17. Using the Extracted Cookie

The source demonstrates importing the cookie into a browser using a cookie-management extension and then visiting:

```text
slack.com
```

After replacing the relevant cookie value and refreshing, the browser session can authenticate as the user in the lab scenario.

### Conceptual chain

```text
Compromised user
      ↓
Browser profile
      ↓
Cookie database
      ↓
Authentication cookie
      ↓
Browser session
      ↓
Application access
```

---

# 18. Why Cookies Are Valuable

A password can be protected by:

```text
MFA
Password policy
Authentication controls
```

but a stolen valid session/token may represent an already-authenticated session.

Therefore, during an authorized assessment, **session material can be just as important as passwords**.

---

# 19. Chromium-Based Browsers

Chromium-based browsers also store cookies in SQLite.

However, the source highlights an important difference:

> Cookie values are encrypted using **DPAPI**.

### DPAPI

You already encountered DPAPI earlier in credential-hunting material.

Conceptually:

```text
Chromium Cookie
      ↓
Encrypted
      ↓
DPAPI
      ↓
User/computer security context
```

The source uses:

```text
SharpChromium
```

to extract/decrypt cookies from the current user's browser context.

---

# 20. SharpChromium

The source demonstrates loading:

```powershell
Invoke-SharpChromium
```

and running:

```powershell
Invoke-SharpChromium -Command "cookies slack.com"
```

---

# 21. Browser Version / Path Problem

The initial extraction fails because the tool expects:

```text
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
```

while the actual Chrome database is located at:

```text
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies
```

The source works around this in the lab by copying:

```powershell
copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" `
"$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
```

### CPTS lesson

Tools can become outdated.

If:

```text
Tool says file doesn't exist
```

don't immediately assume:

```text
No cookies exist.
```

Check the actual application version and current file paths.

---

# 22. Chromium Cookie Extraction

After correcting the path, the source runs:

```powershell
Invoke-SharpChromium -Command "cookies slack.com"
```

and obtains cookie data including:

```text
domain
name
path
secure
expiration
value
```

The important cookie in the example is:

```text
name: d
```

with an authentication value.

---

# 23. Clipboard — Extremely Important

🔥 This is an easy thing to overlook during Windows enumeration.

Many administrators use password managers.

Instead of typing:

```text
Password
```

they:

```text
Copy → Paste
```

Therefore:

> **Keylogging may miss credentials that are pasted.**

The source explains that the clipboard can contain:

- Passwords
    
- Credentials
    
- 2FA software tokens
    
- RDP clipboard data
    

---

# 24. Clipboard Monitoring

The source uses:

```text
Invoke-Clipboard
```

and starts the logger:

```powershell
Invoke-ClipboardLogger
```

The example captures:

```text
https://portal.azure.com

Administrator@something.com

Sup9rC0mpl2xPa$$ws0921lk
```

### Mental model

```text
Password Manager
      ↓
Copy Password
      ↓
Windows Clipboard
      ↓
Clipboard Monitoring
      ↓
Credential Exposure
```

---

# 25. Keylogging vs Clipboard Monitoring

|Technique|Captures|
|---|---|
|Keylogger|Keys typed|
|Clipboard monitoring|Data copied/pasted|
|Network capture|Network authentication/data|
|Process monitoring|Command-line arguments|
|Browser extraction|Cookies/credentials|
|Config hunting|Stored credentials|

### CPTS takeaway

No single credential-hunting technique catches everything.

---

# 26. Roles and Services

Another major part of pillaging is understanding the **role of the compromised machine**.

A host may be:

```text
File Server
Print Server
Web Server
Database Server
Certificate Authority
Source Code Server
Backup Server
```

The source recommends creating a profile of each host, including:

```text
Service
Configuration
Purpose
Potential usefulness
```

---

# 27. Why Host Roles Matter

Suppose you compromise:

```text
WEB01
```

It may give you:

```text
Web configs
Database credentials
Application source code
Service accounts
```

But if you compromise:

```text
BACKUP01
```

you may gain access to:

```text
Historical files
Domain backups
Server backups
Configuration
Credentials
```

So:

> **The value of a compromised machine depends heavily on its role.**

---

# 28. Backup Servers

🔥 **Very important CPTS concept.**

A backup is a copy of data stored elsewhere so it can be restored after:

- Data loss
    
- Deletion
    
- Corruption
    
- Disaster
    

Backups may even contain complete systems such as:

```text
Active Directory
Database servers
Other Windows/Linux machines
```

---

# 29. Why Backup Accounts Are Powerful

Backup systems typically need an account capable of accessing the files being backed up.

The source notes that companies often give backup accounts:

```text
Local Administrator
```

privileges on target machines so they can access the necessary files.

Therefore:

```text
Compromise Backup System
        ↓
Access Backup Accounts
        ↓
Potentially Access Backups
        ↓
Restore Interesting Data
        ↓
Credentials / Configurations
        ↓
Further Access
```

---

# 30. Restic

The source uses:

```text
restic
```

as an example backup application.

Restic stores backups in a:

```text
repository
```

and uses:

```text
RESTIC_PASSWORD
```

if that environment variable is configured. Otherwise, it asks for the repository password.

---

# 31. Initialize a Restic Repository

Example:

```powershell
mkdir E:\restic2
restic.exe -r E:\restic2 init
```

The repository is then initialized with a password.

### Mental model

```text
Restic
  │
  └── Repository
          │
          ├── Password protected
          └── Snapshots
```

---

# 32. Back Up a Directory

The source sets:

```powershell
$env:RESTIC_PASSWORD = 'Password'
```

Then:

```powershell
restic.exe -r E:\restic2\ backup C:\SampleFolder
```

This creates a snapshot.

---

# 33. VSS + Restic

What if you want to back up files that are actively being used by Windows?

The source demonstrates:

```powershell
restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot
```

The `--use-fs-snapshot` option creates a **Volume Shadow Copy Service (VSS)** snapshot.

### Important

VSS creation does **not automatically mean you can read everything**.

The example still receives:

```text
Access is denied
```

when attempting to access the protected directory.

The source explicitly notes that if the user doesn't have permission to access/copy a directory, the backup may exist but contain no useful content from that location.

---

# 34. Enumerating Restic Snapshots

Use:

```powershell
restic.exe -r E:\restic2\ snapshots
```

Example snapshots include:

```text
C:\SampleFolder
C:\Windows\System32\config
C:\Users\jeff\Documents
```

This is extremely interesting from a pillaging perspective because **historical data may contain information that is no longer present on the live machine**.

---

# 35. Restoring a Snapshot

Use the snapshot ID:

```powershell
restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore
```

The restored directory structure can then be examined.

---

# 36. What to Look for in Backups

The source provides examples.

## Linux backup

Look for:

```text
/etc/shadow
```

because it may contain password hashes.

Also:

```text
.ssh/
```

for SSH keys.

And:

```text
web configuration files
```

for application credentials.

---

## Windows backup

Look for:

```text
SAM
SYSTEM
```

to potentially obtain local account hashes.

Also search:

```text
web.config
web application directories
credential/configuration files
```

### CPTS mental model

```text
Backup
  ↓
Historical copy of system
  ↓
Old credentials
Old configs
Old keys
Old databases
Old users
  ↓
Potential access
```

---

# 37. Backup Systems Are Bigger Than Restic

The source explicitly says restic is only an example.

There are hundreds of backup applications and methods.

Some environments use:

```text
Centralized backup console
        ↓
Repositories
        ↓
Backup jobs
        ↓
Multiple servers
```

So don't memorize:

> "Use restic."

Memorize:

> **Identify the backup technology, understand its architecture, locate repositories/snapshots, and determine what data the compromised account can access.**

---

# 🔥 Complete Pillaging Workflow

This is the workflow I want you to remember for CPTS:

```text
                 FOOTHOLD
                    │
                    ▼
          PROFILE THE HOST
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
 Applications     Users       Services
       │            │            │
       ▼            ▼            ▼
 Configs        Credentials    Roles
       │            │            │
       └────────────┼────────────┘
                    ▼
              Credential Stores
                    │
       ┌────────────┼─────────────┐
       ▼            ▼             ▼
   mRemoteNG      Browser       Clipboard
       │            │             │
       ▼            ▼             ▼
   Passwords     Cookies       Passwords
       │            │             │
       └────────────┼─────────────┘
                    ▼
                Backups
                    │
                    ▼
         Historical / Sensitive Data
                    │
                    ▼
       Lateral Movement / PrivEsc
```

---

# 🧠 Pillaging Checklist

After obtaining a Windows shell, run through this mentally:

### Applications

```text
□ Program Files
□ Program Files (x86)
□ Registry uninstall keys
□ Remote management software
□ Password managers
□ Backup applications
□ Browsers
□ IM clients
```

### Credential locations

```text
□ Configuration files
□ mRemoteNG
□ Browser credentials
□ Browser cookies
□ Clipboard
□ PowerShell history
□ Unattend files
□ Registry
□ Password managers
```

### Network

```text
□ Network configuration
□ Connected hosts
□ Shares
□ Remote-management software
□ Databases
□ DNS
```

### Host role

```text
□ File server?
□ Web server?
□ Database?
□ Domain-related?
□ CA?
□ Backup server?
□ Source-control server?
```

### Backups

```text
□ Backup software
□ Repository locations
□ Snapshot list
□ Historical user files
□ SAM/SYSTEM
□ SSH keys
□ web.config
□ Application credentials
```

---

# ⚡ High-Value Commands

### Installed applications

```cmd
dir "C:\Program Files"
dir "C:\Program Files (x86)"
```

### Registry-installed software

```powershell
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, InstallLocation

$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, InstallLocation

$INSTALLED |
?{ $_.DisplayName -ne $null } |
sort-object -Property DisplayName -Unique |
Format-Table -AutoSize
```

### mRemoteNG location

```powershell
ls C:\Users\<USER>\AppData\Roaming\mRemoteNG
```

### mRemoteNG decryption

```bash
python3 mremoteng_decrypt.py -s "<encrypted_password>"
```

With known master password:

```bash
python3 mremoteng_decrypt.py -s "<encrypted_password>" -p "<master_password>"
```

### Firefox cookies

```powershell
copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```

### Chromium cookie location from source

```text
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies
```

### Restic snapshots

```powershell
restic.exe -r E:\restic2\ snapshots
```

### Restore snapshot

```powershell
restic.exe -r E:\restic2\ restore <SNAPSHOT_ID> --target C:\Restore
```

---

# 🎯 The 5 Things I Would Memorize for CPTS

### 1. Installed software → credential stores

```text
mRemoteNG
    ↓
confCons.xml
    ↓
Encrypted credentials
    ↓
Decrypt
```

### 2. Browser → session

```text
Browser
   ↓
Cookie database
   ↓
Cookie
   ↓
Authenticated session
```

### 3. Clipboard → credentials

```text
Password Manager
   ↓
Copy
   ↓
Clipboard
   ↓
Credential exposure
```

### 4. Host role → attack surface

```text
Backup Server
      ↓
Backups
      ↓
Historical systems
      ↓
Credentials / Keys / Configs
```

### 5. Backup → historical information

```text
Current system
      ↓
Backup repository
      ↓
Old system state
      ↓
Old credentials/configs/data
      ↓
Potential new access
```

---

# 🧩 CPTS Viva Questions

**Q1. What is pillaging?**  
Obtaining useful information from a compromised system or network to support the objectives of an authorized penetration test.

**Q2. Give five possible pillaging sources.**

```text
Installed applications
File shares
Databases
Backups
Browsers
```

**Q3. Where does mRemoteNG store its configuration?**

```text
%USERPROFILE%\APPDATA\Roaming\mRemoteNG\confCons.xml
```

**Q4. What is stored in `confCons.xml`?**  
Connection information such as username, domain, hostname, protocol, port, and encrypted passwords.

**Q5. What is the importance of the `Protected` attribute?**  
It corresponds to the protection/master-password mechanism used for the configuration.

**Q6. What happens if the wrong mRemoteNG password is supplied?**

```text
MAC check failed
```

**Q7. Why are browser cookies valuable?**  
They can represent authenticated session material and, depending on the application and current implementation, may allow access without re-entering the user's password.

**Q8. Where are Firefox cookies stored?**

```text
cookies.sqlite
```

under the user's Firefox profile.

**Q9. What protects Chromium cookie values?**

```text
DPAPI
```

in the source's described environment.

**Q10. Why monitor the clipboard?**  
Administrators may copy credentials or 2FA-related information instead of typing it.

**Q11. Why are backup servers interesting?**  
Backup systems may contain historical copies of servers, applications, configurations, credentials, and other sensitive data.

**Q12. What is VSS?**  
Volume Shadow Copy Service; in this section it allows backup software such as restic to create a filesystem snapshot for backing up files that may be actively used.

**Q13. Does creating a VSS snapshot automatically bypass permissions?**  
No. The source's example still receives `Access is denied` when attempting to read protected files.

---

# 🔥 Final CPTS Mental Model

Don't think:

> **“I got a shell, now I need to exploit something.”**

Think:

> **“I got a shell. What does this machine know?”**

Then:

```text
WHO?
Users / Groups / Roles
        ↓
WHAT?
Applications / Services
        ↓
WHERE?
Shares / Databases / Backups
        ↓
HOW?
Credentials / Cookies / Keys / Configs
        ↓
WHEN?
Current + Historical Data
        ↓
WHY?
Lateral Movement / PrivEsc / Assessment Objective
```

That is the essence of **Pillaging**.