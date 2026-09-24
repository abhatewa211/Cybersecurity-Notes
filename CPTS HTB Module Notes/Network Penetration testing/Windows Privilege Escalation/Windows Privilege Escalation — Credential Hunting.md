This is a **high-value CPTS section**. The main idea is simple:

> **Credentials are often easier to find than to crack.**

During Windows privilege-escalation enumeration, credentials may give you:

```text
Credentials
    │
    ├── Local Administrator
    │
    ├── Another privileged local user
    │
    ├── Domain account
    │
    └── Privilege escalation inside Active Directory
```

The important skill is learning **where administrators and applications accidentally leave credentials behind**.

---

# 1. Credential Hunting Mental Model

After gaining a foothold, don't only search for vulnerabilities.

Also ask:

```text
Where does this machine store secrets?
```

Common locations from this section:

```text
Application config files
        │
        ├── .txt
        ├── .ini
        ├── .cfg
        ├── .config
        ├── .xml
        └── web.config

Dictionary files
        │
        └── Chrome Custom Dictionary.txt

Unattended installation files
        │
        └── unattend.xml

PowerShell history
        │
        └── ConsoleHost_history.txt

PowerShell credential files
        │
        └── Export-Clixml / Import-Clixml
```

---

# 2. Application Configuration Files

Applications frequently store configuration information in files.

Unfortunately, administrators sometimes store:

```text
username
password
connection strings
API keys
service credentials
```

in plaintext.

The source specifically points out that this can expose credentials for:

- The current user's administrator account
    
- Another privileged local account
    
- A domain account
    

---

# 3. Searching for Passwords with `findstr`

The source uses:

```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

### Understand the idea

You're searching files with extensions commonly associated with configuration/data:

```text
.txt
.ini
.cfg
.config
.xml
```

for:

```text
password
```

### CPTS mindset

Don't only search for:

```text
password
```

Depending on the environment, interesting terms can include:

```text
password
passwd
pwd
username
user
credential
credentials
connectionstring
secret
token
```

But the exact source command to remember is:

```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

---

# 4. IIS `web.config`

One particularly interesting Windows target is:

```text
web.config
```

For the default IIS website, the source gives:

```text
C:\inetpub\wwwroot\web.config
```

However, there can be multiple copies in different locations.

### Why is this interesting?

IIS applications may use configuration files containing sensitive information.

Think:

```text
IIS
 │
 └── web.config
       │
       ├── connection strings
       ├── application settings
       └── potentially credentials
```

So if you obtain access to a Windows web server, **searching for `web.config` should become routine**.

---

# 5. Dictionary Files

This is a sneaky credential-hunting technique.

Users may type passwords or other sensitive words into:

- Email clients
    
- Browser-based applications
    
- Other applications with spell-check functionality
    

If the application doesn't recognize the word, the user may add it to their custom dictionary.

That means a dictionary file can sometimes contain information that the user intended to keep private.

---

# 6. Chrome Custom Dictionary

The source uses:

```powershell
gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

Output:

```text
Password1234!
```

### Important idea

The file isn't designed to store passwords.

That's what makes this technique interesting.

The password ended up there because the user added it to their browser dictionary.

### CPTS lesson

Credential hunting isn't always:

```text
password.txt
```

Sometimes credentials hide in **unexpected application data**.

---

# 7. Unattended Installation Files

Another excellent place to hunt is:

```text
unattend.xml
```

Windows unattended installation files can contain configuration for:

- Automatic logon
    
- Accounts created during installation
    
- Installation settings
    
- Passwords
    

The source states that passwords in `unattend.xml` may be stored as:

```text
Plaintext
```

or:

```text
Base64 encoded
```

---

# 8. `unattend.xml` Example

The important section is:

```xml
<AutoLogon>
    <Password>
        <Value>local_4dmin_p@ss</Value>
        <PlainText>true</PlainText>
    </Password>
    <Enabled>true</Enabled>
    <LogonCount>2</LogonCount>
    <Username>Administrator</Username>
</AutoLogon>
```

Notice:

```text
Username = Administrator
Password = local_4dmin_p@ss
PlainText = true
```

This is extremely valuable if the file is accessible.

---

# 9. Why `unattend.xml` May Still Exist

Ideally, unattended installation files should be removed after installation.

But administrators may create copies during:

```text
Image development
Testing
Deployment
Troubleshooting
```

So you might find copies somewhere other than the expected installation location.

### CPTS mental model

```text
Windows installation
       │
       ▼
unattend.xml
       │
       ├── AutoLogon
       ├── Username
       └── Password
```

Therefore:

> **Search for configuration files, not just files named "password."**

---

# 10. PowerShell History

🔥 **This is one of the most important credential-hunting techniques in the section.**

PowerShell can save commands executed by users.

Starting with PowerShell 5.0 on Windows 10, PowerShell uses PSReadLine to save command history.

Default path:

```text
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

# 11. Find the History File Path

Instead of assuming the path, PowerShell can tell you where history is being saved:

```powershell
(Get-PSReadLineOption).HistorySavePath
```

Example:

```text
C:\Users\htb-student\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

# 12. Read PowerShell History

Once you know the path:

```powershell
gc (Get-PSReadLineOption).HistorySavePath
```

or:

```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath
```

The source's example history contains commands such as:

```text
dir
cd Temp
md backups
cp c:\inetpub\wwwroot\* .\backups\
...
wevtutil qe Application ... /u:WEB02\administrator /p:5erv3rAdmin! /r:WEB02
```

The critical discovery is:

```text
/u:WEB02\administrator
/p:5erv3rAdmin!
```

The user entered credentials directly on the command line.

Those credentials then became part of PowerShell history.

---

# 13. Why PowerShell History Is Dangerous

Consider:

```powershell
wevtutil ... /u:WEB02\administrator /p:Password123!
```

The administrator may think:

> "I'm only using these credentials for this command."

But PowerShell may record the command.

So later:

```text
Attacker
   ↓
Read PowerShell history
   ↓
Find command
   ↓
Recover username/password
```

This is why command-line credentials are dangerous.

---

# 14. Search Other Users' PowerShell History

The source provides a useful one-liner:

```powershell
foreach($user in ((ls C:\users).fullname)){
    cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue
}
```

Conceptually:

```text
C:\Users
   │
   ├── Administrator
   ├── user1
   ├── user2
   └── htb-student
          │
          ▼
   PSReadLine history
```

The command attempts to read each user's history file that the current account can access.

### Important CPTS point

If you're currently low privilege, you may not be able to read every user's history.

After obtaining **local administrator** access, it is worth checking again.

The source specifically emphasizes rechecking these files after gaining local admin if earlier access did not allow access to other users' histories.

---

# 15. Credential Hunting Timeline

A useful way to remember this:

```text
Initial Foothold
      │
      ▼
Credential hunting
      │
      ├── Current user's files
      │
      ├── Application configs
      │
      ├── Dictionary files
      │
      ├── Unattend files
      │
      └── PowerShell history
      │
      ▼
Find credentials
      │
      ▼
Authenticate as another account
      │
      ▼
Higher privileges / lateral movement
```

---

# 16. PowerShell Credentials

Now the section introduces a different situation.

PowerShell can store credentials using:

```text
Export-Clixml
```

These credentials are protected using:

```text
DPAPI
```

The source explains that this typically means they can only be decrypted by the same user on the same computer where they were created.

---

# 17. Example — `Connect-VC.ps1`

The source gives:

```powershell
# Connect-VC.ps1
# Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'

$encryptedPassword = Import-Clixml -Path 'C:\scripts\pass.xml'

$decryptedPassword =
    $encryptedPassword.GetNetworkCredential().Password

Connect-VIServer `
    -Server 'VC-01' `
    -User 'bob_adm' `
    -Password $decryptedPassword
```

The important file is:

```text
C:\scripts\pass.xml
```

---

# 18. How PowerShell Credential Storage Works

The original administrator might run something like:

```powershell
Get-Credential | Export-Clixml -Path 'C:\scripts\pass.xml'
```

The credential is stored in the XML file in a protected form.

Later:

```powershell
Import-Clixml
```

loads it.

The credential object can then expose the network credential.

---

# 19. Recovering the Credential

If you have command execution **as the same user who created the credential**, the source demonstrates:

```powershell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
```

Then:

```powershell
$credential.GetNetworkCredential().username
```

Output:

```text
bob
```

And:

```powershell
$credential.GetNetworkCredential().password
```

Output:

```text
Str0ng3ncryptedP@ss!
```

The key point is that DPAPI protection is tied to the relevant Windows user/computer context.

---

# 20. DPAPI Mental Model

Don't think:

```text
pass.xml = encrypted forever
```

Think:

```text
Credential
    │
    ▼
Export-Clixml
    │
    ▼
DPAPI protection
    │
    ▼
pass.xml
```

Then:

```text
Same user + same computer context
          │
          ▼
Import-Clixml
          │
          ▼
Credential object
          │
          ▼
GetNetworkCredential()
```

The source also notes that **abusing DPAPI** can be another route to recovering such credentials.

---

# 21. High-Value Credential Locations

🔥 Memorize this list for CPTS:

```text
1. Application configuration files

2. IIS web.config

3. Dictionary files

4. unattend.xml

5. PowerShell history

6. PowerShell Export-Clixml credential files
```

And think beyond these when doing real enumeration.

---

# 22. CPTS Credential Hunting Workflow

After obtaining a Windows foothold:

```text
                 FOOTHOLD
                    │
                    ▼
          Credential Hunting
                    │
       ┌────────────┼─────────────┐
       │            │             │
       ▼            ▼             ▼
 Config files   User files    Application data
       │            │             │
       ▼            ▼             ▼
 web.config    PS History     Dictionaries
       │
       └──────────────┐
                      ▼
               unattended files
                      │
                      ▼
                credentials
                      │
                      ▼
          Test valid authentication
                      │
             ┌────────┴────────┐
             ▼                 ▼
       Local privilege     Domain access
          escalation       / lateral movement
```

---

# 23. Commands to Memorize

### Search configuration files

```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

### Chrome dictionary

```powershell
gc 'C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt'
```

Search it:

```powershell
gc 'C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' | Select-String password
```

### Find PowerShell history location

```powershell
(Get-PSReadLineOption).HistorySavePath
```

### Read current user's PowerShell history

```powershell
gc (Get-PSReadLineOption).HistorySavePath
```

### Search histories accessible to current user

```powershell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

### Import PowerShell credential

```powershell
$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
```

### Username

```powershell
$credential.GetNetworkCredential().username
```

### Password

```powershell
$credential.GetNetworkCredential().password
```

---

# 24. Exam/Viva Questions

### Q1. Why is credential hunting important?

Because discovered credentials may provide local administrator access, domain access, or additional privilege-escalation/lateral-movement opportunities.

### Q2. What files should you search for plaintext credentials?

```text
.txt
.ini
.cfg
.config
.xml
web.config
```

### Q3. What command searches for `password`?

```powershell
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
```

### Q4. Where is the default PowerShell history file?

```text
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Q5. How do you determine the actual PowerShell history path?

```powershell
(Get-PSReadLineOption).HistorySavePath
```

### Q6. Why is PowerShell history valuable?

Administrators may accidentally execute commands containing usernames, passwords, connection strings, or other sensitive information.

### Q7. What is `unattend.xml`?

A Windows unattended installation configuration file that can contain auto-logon information and account/password configuration.

### Q8. How can credentials be stored by PowerShell?

Using:

```powershell
Export-Clixml
```

with protection provided by:

```text
DPAPI
```

### Q9. Under what condition can an exported PowerShell credential typically be decrypted?

The source states that it can typically be decrypted by the **same user on the same computer** where it was created.

### Q10. What should you do after gaining local administrator access?

Recheck credential locations that were previously inaccessible, especially other users' PowerShell histories and protected application/configuration files.

---

# 🔥 Final CPTS Cheat Sheet

```text
╔══════════════════════════════════════╗
║       WINDOWS CREDENTIAL HUNTING     ║
╚══════════════════════════════════════╝

CONFIG FILES
    ↓
.txt
.ini
.cfg
.config
.xml
web.config

SEARCH:
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml


DICTIONARY FILES
    ↓
Chrome Custom Dictionary.txt
    ↓
Search for interesting words/passwords


UNATTEND
    ↓
unattend.xml
    ↓
AutoLogon
Username
Password
PlainText / encoded


POWERSHELL HISTORY
    ↓
(Get-PSReadLineOption).HistorySavePath
    ↓
ConsoleHost_history.txt
    ↓
Look for credentials in commands


OTHER USERS
    ↓
C:\Users\<user>\
    ↓
PSReadLine history
    ↓
Read what current privileges allow


POWERSHELL CREDENTIALS
    ↓
Export-Clixml
    ↓
DPAPI
    ↓
pass.xml
    ↓
Import-Clixml
    ↓
GetNetworkCredential()
```

## 🧠 The CPTS lesson

Don't think of credential hunting as simply:

> **"Find password.txt."**

Think:

> **"Where could a human, administrator, script, or application have accidentally caused a credential to be persisted?"**

That mindset leads you to:

```text
Configuration
      ↓
Application data
      ↓
User history
      ↓
Installation files
      ↓
Credential stores
      ↓
Credentials
      ↓
New access
```

And that is what makes **Credential Hunting** such an important part of Windows post-exploitation.