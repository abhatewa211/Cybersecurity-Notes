## 1. Module Objective

In the previous section, we performed AD enumeration from a **Linux attack host** using valid domain credentials.

This section moves to a **Windows attack host** and introduces:

- **ActiveDirectory PowerShell module**
    
- **PowerView**
    
- **SharpView**
    
- **Snaffler**
    
- **SharpHound**
    
- **BloodHound**
    
- Built-in Windows/PowerShell enumeration techniques
    

The objective is to understand the domain from a Windows perspective and identify:

- Users
    
- Groups
    
- Computers
    
- Trusts
    
- SPNs
    
- Local administrator access
    
- Shares
    
- ACLs
    
- Sessions
    
- GPO relationships
    
- Potential lateral/vertical movement paths
    

HTB also emphasizes that enumeration isn't only about finding an immediate attack path. Some discoveries are useful as **security findings or reporting information**.

---

# 🧠 2. Big Picture

![Image](https://images.openai.com/static-rsc-4/MqBeK8MQ4ly_vym3GqEeRwZmOQ3Z0h-EnPfk3J2nSJuNJxWTc2PlsYkT-D1GW7qFeJG30CSvwI7hU9kL3h0LYYNF1sIZUj0ASz8L4I33TcVKOgq0swCys-KETSpcNCQuycjr2gd7KTDFT5Jo2d4nHyZ1ldzhYqCKnC-dlanEKBoKBuq__SHhAeqYrZ_rKQTO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sKpChRVRr3J524Z-aGG8yXCxC1dLj96_OlFNLM-2GvPgW_EXIK3fm-CsTTMwS50eX2hobrkAcPrspKPGVzNlxmV2KDZclx1wZ9vfgT3IS59MHymSXoY1U4cX0uXNbr97yV67n7yNeQ9ybXRoEcPYq3MpTMFH5hWSMCU3oH0QjwxFeO71-SEQWTsaHU2AzQ6t?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0p6bNI_gwSm9V385189ndq3iuecWJ7bWpvn-RR-IbV-4r6HCAKrsGDbk3xZC6UEuXXsP2ic5ZwyjUC1LstI6fMPXPMHF3fG7MIoKWxePOduSkozAEDL_hgz0cYz7BFhxQqNl99xleSgZUXYjLdOhz_6m8h1Vooo9XsN5V22oQRZS7EHETBz3V35RjV8f9mUP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8WvePbNqHWRhv24sujTcbkRXuIJdiNbG9rbKqiaskawUmlw2A7hJ48DGVEkfqhS7kCPIBQknmWiuquLZQ1yH9imn1lxzPPFq8tC0l2fr2UOYjuQPPYHmGPCrvDBs0f-rOvpN_rO2bvmNdqYWP-fiBbkEpbdECJeaRPgJAKeXflAhChRNVpI3Ye7mMWnJbC-P?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EiOGVD91DaxfKkg3-irp9S7V3bfxNvh5ZVF3A1igMM1bx_LDyyRYG5Ahxk24JU0VImxjSapmZIHyUrzR5Xdizx6B5ilCJ9qYRWnnlFCpubozZI9p6efxeNfW2cWPEUyJcc9AdC0c-WY8FR6YPCrHLG1_cKZuJLw6U8XkQLrGEecl8l2whAd4zM9aSiUheQD6?purpose=fullsize)

Think of the workflow like this:

```text
                Valid Domain Credentials
                         |
                         v
              Windows Attack Host
                         |
       +-----------------+-----------------+
       |                 |                 |
       v                 v                 v
 ActiveDirectory      PowerView        SharpView
 PowerShell              |                 |
       |                 |                 |
       +-----------------+-----------------+
                         |
              +----------+----------+
              |                     |
              v                     v
           Snaffler             SharpHound
              |                     |
              v                     v
         Shares/Files            AD Graph
              |                     |
              +----------+----------+
                         |
                         v
                     BloodHound
                         |
                         v
                   Attack Paths
```

---

# 🔥 3. ActiveDirectory PowerShell Module

The **ActiveDirectory PowerShell module** provides PowerShell cmdlets for administering and enumerating Active Directory.

HTB notes that it contains many cmdlets, but we focus on the ones particularly useful for AD enumeration.

---

## 4. Check Available PowerShell Modules

Use:

```powershell
Get-Module
```

This shows loaded modules.

If the ActiveDirectory module isn't loaded:

```powershell
Import-Module ActiveDirectory
```

Then:

```powershell
Get-Module
```

You should see:

```text
ActiveDirectory
Microsoft.PowerShell.Utility
PSReadline
```

### Remember

```text
Get-Module
    ↓
Check available/loaded modules

Import-Module ActiveDirectory
    ↓
Load AD cmdlets
```

---

# 🌐 5. Get-ADDomain

One of the first things we want is basic domain information.

Command:

```powershell
Get-ADDomain
```

The module's example provides information such as:

```text
DNSRoot
DomainSID
DomainMode
Forest
Domain Controllers
PDCEmulator
RIDMaster
ChildDomains
```

For example:

```text
DNSRoot        : INLANEFREIGHT.LOCAL
DomainMode     : Windows2016Domain
DomainSID      : S-1-5-21-3842939050-3880317879-2865463114
Forest         : INLANEFREIGHT.LOCAL
PDCEmulator    : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
RIDMaster      : ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

### Why this matters

Before deeper enumeration, establish:

```text
Domain
 ├── Domain SID
 ├── Forest
 ├── Domain Controllers
 ├── Child Domains
 ├── Functional Level
 └── RID Master
```

This gives you the domain's basic structure.

---

# 🎫 6. Finding Users With SPNs

An important enumeration technique is looking for accounts with a **Service Principal Name (SPN)**.

Command:

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

HTB explains that accounts with SPNs can potentially be relevant to **Kerberoasting**.

Example output:

```text
SamAccountName       ServicePrincipalName
---------------      --------------------
adfs                 adfsconnect/azure01.inlanefreight.local
backupagent          backupjob/veam001.inlanefreight.local
```

### Important concept

```text
User Account
     |
     +---- SPN exists
              |
              v
       Kerberos service account
              |
              v
       Potential Kerberoasting target
```

**Don't automatically assume every SPN account is vulnerable.** The SPN simply identifies an account associated with a service; further assessment is required.

---

# 🔗 7. Domain Trust Relationships

Use:

```powershell
Get-ADTrust -Filter *
```

This identifies trust relationships between domains.

The example identifies:

```text
INLANEFREIGHT.LOCAL
        |
        +---- LOGISTICS.INLANEFREIGHT.LOCAL
        |
        +---- FREIGHTLOGISTICS.LOCAL
```

The output tells you:

- Direction
    
- Trust type
    
- Trust attributes
    
- Target domain
    
- Whether the trust is inside the forest
    
- Whether it is forest-transitive
    

### Important fields

```text
Direction
TrustType
TrustAttributes
ForestTransitive
IntraForest
Name
Source
Target
```

---

# 🧠 8. Understanding Trust Direction

Example:

```text
Direction : BiDirectional
```

means the trust relationship operates in both directions.

Conceptually:

```text
Domain A  <==========>  Domain B
          Bidirectional
```

This can matter when evaluating cross-domain access paths.

---

# 👥 9. Enumerating Groups

Command:

```powershell
Get-ADGroup -Filter * | select name
```

This gives a list of groups.

Examples include:

```text
Administrators
Backup Operators
Remote Desktop Users
Domain Computers
Domain Controllers
Schema Admins
Enterprise Admins
Domain Admins
```

### High-value groups to understand

```text
Domain Admins
Enterprise Admins
Schema Admins
Administrators
Backup Operators
Remote Management Users
Remote Desktop Users
```

Don't just memorize names—understand what privileges membership can confer.

---

# 🔍 10. Detailed Group Information

Once you find an interesting group:

```powershell
Get-ADGroup -Identity "Backup Operators"
```

Example:

```text
GroupCategory   : Security
GroupScope      : DomainLocal
Name            : Backup Operators
SamAccountName  : Backup Operators
SID             : S-1-5-32-551
```

---

# 👤 11. Group Membership

To see who belongs to a group:

```powershell
Get-ADGroupMember -Identity "Backup Operators"
```

Example:

```text
name              : BACKUPAGENT
objectClass       : user
SamAccountName    : backupagent
```

### Why this matters

You might discover:

```text
Backup Operators
       |
       +---- backupagent
```

If `backupagent` can be compromised, its group membership may become relevant to further privilege escalation.

HTB explicitly highlights this relationship as something worth documenting.

---

# 🕵️ 12. PowerView

![Image](https://images.openai.com/static-rsc-4/0p6bNI_gwSm9V385189ndq3iuecWJ7bWpvn-RR-IbV-4r6HCAKrsGDbk3xZC6UEuXXsP2ic5ZwyjUC1LstI6fMPXPMHF3fG7MIoKWxePOduSkozAEDL_hgz0cYz7BFhxQqNl99xleSgZUXYjLdOhz_6m8h1Vooo9XsN5V22oQRZS7EHETBz3V35RjV8f9mUP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Glj938vbZLkQqnPaXrjFgWPK45MPwRcPogQicUlIE7xdUoyiuFjFs6urUTf3M1CzWlqjsK3ltuP3JBibTb0cYDbt5f472zJsyluCbwPZks8-88OPHGvNsw5CCqhQvT9wpVPXxLne2rb0DRxwAYzhUITA8szUwDqi3k8wwM4DKl0P91y7w3xA8vyX9VKQE4sd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QTpR8iZam7uMTGwlUH_k-XzP-rb_KkDRJSFbgQpplkhP1wHHJuppRHx4P1Z4qe_bP9veNzcYzWleeqi9pRDENO1Kj5iM6ECDahgFRCSFoI-Q9_TUxOwn_ib1ObIMqFDbVNI2v7zILLlxGwrfDZscs1SH9EWDfqjCndfXpgIfCNlng41wxMeisPahfJzDx_NO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/O1TmBpZ91_IbANVn_AlBma8g5owl0l4dvThYfQufS1-psKjhoWVYEQZeDOK4IUyuLJLO37WHhtRbH7eaSv2cLGQQd3tb_un2XcR89oMBnIMf2nnHQ0JgAHkO1pMhu2L0y4d4NVFkTc1NkrzUu-1Q-i5T8lykbXmevorwJfTnZUqtnefxER-ZQ2f2rXU7cmmD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hqNT8eahDJL9_B7ssaBPZOIBPQXuGjv6wc52C27N8n3HD7XhwvGzi6Zx7YcIHPjhSV5GTP8Y79ArFN9J56ONC2vL43x0QMsRxPQ0QMVg0ObcxgShQK9XZvIE0bMUXleM6L_8nPgvrCe3UA0CCHMkKQPgtFULRK5oVexACbweW5klGxOz0gN-rgEbo1XCE3F1?purpose=fullsize)

**PowerView** is a PowerShell tool designed to provide situational awareness in Active Directory.

It can enumerate:

- Users
    
- Computers
    
- Groups
    
- ACLs
    
- Trusts
    
- Sessions
    
- Shares
    
- Local administrator access
    
- SPNs
    
- GPOs
    
- File servers
    
- Interesting files
    

HTB describes it as highly versatile, while noting that it requires more manual analysis than BloodHound.

---

# 📚 13. PowerView Cheat Sheet

This table is **very important**. Keep it for revision.

|PowerView command|Purpose|
|---|---|
|`Export-PowerViewCSV`|Append results to CSV|
|`ConvertTo-SID`|Convert name to SID|
|`Get-Domain`|Domain information|
|`Get-DomainController`|Domain Controllers|
|`Get-DomainUser`|Users|
|`Get-DomainComputer`|Computers|
|`Get-DomainGroup`|Groups|
|`Get-DomainOU`|Organizational Units|
|`Find-InterestingDomainAcl`|Interesting ACLs|
|`Get-DomainGroupMember`|Group members|
|`Get-DomainFileServer`|File servers|
|`Get-DomainDFSShare`|DFS shares|
|`Get-DomainGPO`|GPOs|
|`Get-DomainPolicy`|Domain policy|
|`Get-NetLocalGroup`|Local groups|
|`Get-NetLocalGroupMember`|Local group members|
|`Get-NetShare`|Shares|
|`Get-NetSession`|Sessions|
|`Test-AdminAccess`|Test local admin access|
|`Find-DomainUserLocation`|Find user sessions|
|`Find-DomainShare`|Find accessible shares|
|`Find-InterestingDomainShareFile`|Search interesting files|
|`Find-LocalAdminAccess`|Find hosts where you have local admin|
|`Get-DomainTrust`|Domain trusts|
|`Get-ForestTrust`|Forest trusts|
|`Get-DomainForeignUser`|Foreign users|
|`Get-DomainForeignGroupMember`|Foreign group members|
|`Get-DomainTrustMapping`|Map trusts|

These functions and their descriptions come directly from the module.

---

# 👤 14. Get-DomainUser

To enumerate a specific user:

```powershell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local
```

You can select specific properties:

```powershell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local |
Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

The example reveals:

```text
name              : Matthew Morgan
samaccountname    : mmorgan
memberof          : ...
admincount        : 1
userprincipalname : mmorgan@inlanefreight.local
serviceprincipalname :
useraccountcontrol: NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

### Important fields

#### `samaccountname`

The actual Windows/AD logon account name.

#### `memberof`

Shows group memberships.

#### `admincount`

Can indicate that the account is or has been associated with a protected administrative group.

#### `serviceprincipalname`

Relevant when investigating service accounts and Kerberos.

#### `useraccountcontrol`

Contains account configuration flags.

---

# 🧬 15. Nested Group Membership

This is **very important**.

PowerView supports recursive group enumeration:

```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

The `-Recurse` option follows nested groups.

Imagine:

```text
Domain Admins
      |
      +---- Secadmins
                |
                +---- spong1990
```

Without recursion, you might see only:

```text
Domain Admins
    |
    +---- Secadmins
```

With recursion, you can discover:

```text
Domain Admins
    |
    +---- Secadmins
             |
             +---- spong1990
```

Therefore:

> **Nested group membership can inherit privileges.**

This is one of the most important AD enumeration concepts.

---

# 🌍 16. Trust Mapping with PowerView

Command:

```powershell
Get-DomainTrustMapping
```

Example:

```text
INLANEFREIGHT.LOCAL
        |
        +---- LOGISTICS.INLANEFREIGHT.LOCAL
        |
        +---- FREIGHTLOGISTICS.LOCAL
```

The module shows the relationships as bidirectional trusts.

---

# 👑 17. Testing Local Administrator Access

PowerView:

```powershell
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

Example:

```text
ComputerName        IsAdmin
------------        -------
ACADEMY-EA-MS01     True
```

This answers a very important question:

> **Does my current account have local administrator privileges on this host?**

Conceptually:

```text
Current User
     |
     | Test-AdminAccess
     v
Target Computer
     |
     +---- True  → Local Admin
     |
     +---- False → Not Local Admin
```

---

# 🎫 18. Finding Users With SPNs — PowerView

Command:

```powershell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

Example results include:

```text
adfsconnect/azure01.inlanefreight.local
backupjob/veam001.inlanefreight.local
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
MSSQLSvc/SPSJDB.inlanefreight.local:1433
```

with corresponding accounts:

```text
adfs
backupagent
sqldev
sqlprod
```

### Mental model

```text
SPN
 |
 +---- Service account
          |
          v
     Kerberos service
          |
          v
 Potential Kerberoasting target
```

---

# ⚡ 19. SharpView

**SharpView** is a .NET implementation/port of many PowerView capabilities.

It is useful when you want PowerView-style enumeration from a compiled executable rather than directly using the PowerShell implementation.

HTB demonstrates:

```powershell
.\SharpView.exe Get-DomainUser -Help
```

to see available arguments.

Example:

```powershell
.\SharpView.exe Get-DomainUser -Identity forend
```

This can return information such as:

```text
objectsid
samaccounttype
objectguid
useraccountcontrol
lastlogon
pwdlastset
badPasswordTime
name
distinguishedname
samaccountname
memberof
badpwdcount
logoncount
```

### Remember

```text
PowerView
   ↓
PowerShell

SharpView
   ↓
.NET executable
```

They provide many overlapping enumeration capabilities.

---

# 📂 20. SMB Shares

Shares are extremely important in AD environments.

Organizations use shares to distribute:

- Documents
    
- Scripts
    
- Configuration files
    
- Department information
    
- Software
    
- Administrative files
    

Poorly configured permissions can expose sensitive information.

HTB specifically mentions possible exposure of:

- Credentials
    
- SSH keys
    
- Passwords
    
- Configuration files
    
- HR/personnel information
    
- Legal/medical information
    

---

# 🧠 Share Enumeration Concept

```text
Domain User
     |
     v
Accessible Shares
     |
     +---- Documents
     +---- Scripts
     +---- Configuration
     +---- Credentials
     |
     v
Potential Sensitive Information
```

PowerView can help identify shares.

Useful commands include:

```powershell
Get-NetShare
```

and:

```powershell
Find-DomainShare
```

For more targeted file hunting:

```powershell
Find-InterestingDomainShareFile
```

---

# 🕷️ 21. Snaffler

![Image](https://images.openai.com/static-rsc-4/q7YIkqDZQax5baoXkdcMCnDOIEDd8dqVM_-cFxZCvbSkKQYDPK2w0Q0141Kl7lQQXjNN09WS63TokEAT2acTAvf1D3GNYHzF3USRZ6O8rQ0SdJmVZUv5fOW2nHtDC_kMAje8pBEJR3vrgFsJPUHl8IqSYMsYMnU8JByVC2qT_uFQS7Tzv3jVdlGT6uo5w-AB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-na-hRAZt1jMESvFyY_I1HNv2LnjAdnj7Ol6LYifw9BTUVQBbbPRY4rQtbAKMtVJDjRz_XtmV76F_AotYPpuEV9lfwmUiFRzaMaEBGtNM1vaQ9f566a0LgDsiSG44Rnvcf0Y-MH8NhRTpYHeQAgVPNflDp-AmVAndt_P5upiM9b1xh9IOYe1F6PnUUIM2Y8K?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/j3f3WkeaUY9ZsvBfrOSLPh1tGLDcoh40qZNC_p7TPGBwp2Jq_5Hq2iXoBni9gU0umI7DkfC31Mh_vm5rxuSE7WHVZpUZ6hcNTO0YSZqGuFupK-7uzOosag1arQo-psAzveIjG_RETc32zVmdj6vlAOSNSO9DIfc2sus0UyEU4qnuaqwaD4Z_p123CqxbfqeZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hN2z2GGJYnrHmvY3dxczuwcuZap1tQsCwc1hoSluf_vI0XCrm-FXdFWtRSK5OHI3cjjrMFsY_OfbYqkKy4Gte3gF357oZFt3Va8afI-NddsLwBgct6XCaghc1nIIh0Ht-BHeds0vGeOY27-9qSq9kuE94-Z0dQYr2L8FVSpKKkHyohrJljBHlRUVQzrAz7Fq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/oWaeSPMEfpUFkxMi58lXMGpH6YEj99nmmxc5rooP38CUczxwI1zSanxiZaumsXrLzsNhdIBP0Y7zo8n0bSB6oLhcw0rrHHwpC-52qGnPnj95gMf0uH8qyK9LKjdIDZiCH5mI8_7tQsV1IvYhTTAh1l8ZshGHlcrWhHuowJnXipCeMPuPObqi9npCdDtuuCGy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lYT8OCoKnPVGO6G8hUGgxuNSxjD3O1e989iXd51qWOIrCQkcD-Mn6GMfVpkwUwtrzfSda27Naj1AQm4mR5bdj27ltvZhDFT8mfidDJe_iaSZyJc5fFBWb8l-Q2Fmohr-Czpukgdx6cFVNaONX_xt5YkdxdDoYw5MuuIVtH0GIn-hxnoyzfROn96eeynQm-eK?purpose=fullsize)

**Snaffler** is designed to search an AD environment for sensitive information in accessible shares.

HTB describes its workflow as:

```text
Domain
  |
  v
Enumerate hosts
  |
  v
Enumerate shares
  |
  v
Find readable directories
  |
  v
Search files
  |
  v
Identify potentially sensitive data
```

Snaffler needs to run from a **domain-joined host or domain-user context**.

---

# 22. Snaffler Command

The module gives:

```powershell
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

Meaning:

|Option|Meaning|
|---|---|
|`-s`|Print results to console|
|`-d`|Domain|
|`-o`|Output logfile|
|`-v`|Verbosity|

HTB recommends logging the output because Snaffler can generate a large amount of information.

---

# 🚨 23. What Snaffler Can Find

The example identifies shares such as:

```text
Department Shares
User Shares
ZZZ_archive
CertEnroll
```

and files with extensions such as:

```text
.kdb
.key
.kwallet
.ppk
.sqldump
.keychain
.psafe3
.keypair
.mdf
```

These file types may potentially contain sensitive information, depending on their actual contents.

### Important principle

Don't assume:

```text
Interesting filename = valid credential
```

Instead:

```text
Interesting file
      ↓
Read/inspect it
      ↓
Determine what it contains
      ↓
Validate relevance
```

---

# 🩸 24. BloodHound

BloodHound is the **relationship-analysis component** of this section.

![Image](https://images.openai.com/static-rsc-4/6H0tAcHWatXzMDK9jr644zXdF-8s7XTrE1YONjcWIu_kPifepXOaA8_4lrnRSIE1m93QhF4OPrMH8JT5eoZ57ssYqhn_pG3LNUS_9ecKN0njcaWFluBoDQb9G-OkoqNy3e-_JsT2bbJrtxWQdeNSroRfdMT70XFKv5E0bxlEiDWsYI-11faBgJ_nArlZUskd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cNEkgM03hcFy7wGZERA5AwLTBkrkUGYxeTQM64_AxANk53tu9iRiCk_yoIf_g_eh0SY8NxTMgpg7_dmcQh9aWcPfnMnpd90JDQIuK7CQ1S8v9uyp48iPxcbV-_r8QcZypNBlxLO8PnsOnulDUXS3T6wg2TJIONUztX8X-58DdKCrvDcdnigOf01BBAv7LKeR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/o6ECvmCYfTTExAgepi1PKiEQcmttIEspsiXp9sJDMhPeLwS8Siyv_RF7i7svfS2k9h5SZID3EzsF2YcsHtOnsF0kYNKLFuWkrwYarXi8HZpf88ySjkI5CiKoj10Bl0XZUGwP1fM9NQG0QJfym7Pwwmdm1_UaeRlFQkf4Hk4oztyAdcskdLyXPXHheWdY4yni?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Krs7gGC6KWsVS4zBNL0FmvK-bWmtANwZFok0-RmGl26XnVIg-KD__kTFk3lrxPx-wzZYKUzzrwMLzd582LqnhdseMcN2VgdSkl8i9GkDMLsR1YlcQHQRD3Ng3ffBhL8R8th5JQKnoYoTTBxjq2jqmyi58OuaLcyMwfQ2XUxYC8t4mfcz4iBu1QI8fQnbTAFx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zuGtkwbu0iOM4jkZCSNM1nFjDUQTdk_olaowPYKOofJGVNODhgsaQSX8HDJ-Lu-tdsQSDoSvf2Fcl_Xi5D7lKyAlIdFQNyB11lcHQW4cPmY7F4T3zQyaUGTF6z0NLuZlFctMaoQkoZ4qZ6Wd9dQ5php_WMx2ZLEaOYHTtBGMr2ZaoCNWJ0DCX5ZTOtcYfXPV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8SE4htFMifwdIebtxIrvPC5x-G6gEjfwKfkgovgF5hWyE8x1qu759zEfRirDNCbdkpcE6E16fSu2E-c_JtGHoROzbmpe8F70QZ0Vaf2qoxeyq8kV6b-wNddilw-oMKUHKgCFTucns9SXVG_IGREX0SHycPenE0y4K0jLP9HWEJ66giteN5BgMakownFyzPlo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gRO5qynLog6F8yWe1oh2i-WwtBOUa8dyjSOrLT857l6MNRm4SF6YB5mWBR2j0F9tKyqVtG6oC7q83ada1-EtRXTFN_Lg-3F5iYj68EXtgiMyqrMWOtAgdAyX1jySCIirRPVNSz2PZcY5ZCwi8hxlIbIquLiucGS7syR2Nfy24BaZc6kvb6upqWKq03LT2VH1?purpose=fullsize)

BloodHound analyzes relationships between AD objects to identify potential attack paths.

It can visualize relationships involving:

```text
Users
Groups
Computers
ACLs
GPOs
Sessions
Local Admin rights
Trusts
RDP
WinRM/PSRemote
SPNs
```

HTB describes it as useful for both offensive security assessments and defensive analysis.

---

# 🐕 25. SharpHound

**SharpHound** is the collector.

Think:

```text
SharpHound
     ↓
Collect AD information
     ↓
JSON/ZIP dataset
     ↓
BloodHound
     ↓
Graph analysis
```

The module demonstrates checking available options:

```powershell
.\SharpHound.exe --help
```

Important collection options include:

```text
Container
Group
LocalGroup
GPOLocalGroup
Session
LoggedOn
ObjectProps
ACL
ComputerOnly
Trusts
Default
RDP
DCOM
DCOnly
```

---

# 26. SharpHound — Full Collection

The module uses:

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

This performs broad collection.

The example resolves collection methods including:

```text
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

---

# 🧠 27. SharpHound Options to Remember

```text
-c
```

Collection methods.

```text
-d
```

Specify domain.

```text
-s
```

Search the forest.

```text
--stealth
```

Stealth collection mode.

```text
-f
```

LDAP filter.

```text
--computerfile
```

Provide computers to enumerate.

---

# 📦 28. BloodHound Data Flow

```text
Windows Attack Host
        |
        v
   SharpHound.exe
        |
        v
 AD Enumeration
        |
        v
 JSON files
        |
        v
 ZIP dataset
        |
        v
 BloodHound
        |
        v
 Neo4j / Graph DB
        |
        v
Relationship Analysis
        |
        v
Potential Attack Paths
```

---

# 🔎 29. BloodHound Analysis Queries

One of the useful built-in queries in the module is:

```text
Find Computers with Unsupported Operating Systems
```

This can reveal legacy hosts.

The module warns that these hosts should be validated before assuming they are active because old records can remain in AD even when systems are no longer operational.

---

# ⚠️ 30. Unsupported Operating Systems

Why are they interesting?

Older operating systems may have:

- Unsupported software
    
- Missing security updates
    
- Legacy applications
    
- Known vulnerabilities
    

But:

> **Never immediately attack a legacy system simply because BloodHound shows it.**

The module specifically notes that these systems may run critical applications and recommends validating their status and discussing potential impact with the client during an assessment.

---

# 👑 31. Domain Users as Local Administrators

Another BloodHound query:

```text
Find Computers where Domain Users are Local Admin
```

This is a significant misconfiguration.

Conceptually:

```text
Domain Users
      |
      +----------------+
      |                |
      v                v
 Computer A        Computer B
 Local Admin       Local Admin
```

If **Domain Users** broadly have local administrator rights, compromising an ordinary domain account can potentially provide administrative access to those machines.

The module highlights this as a valuable relationship to investigate.

---

# 🧩 32. PowerShell vs PowerView vs SharpView vs BloodHound

|Tool|Think of it as|
|---|---|
|**ActiveDirectory module**|Native AD PowerShell cmdlets|
|**PowerView**|Deep manual AD reconnaissance|
|**SharpView**|.NET implementation of PowerView-style enumeration|
|**Snaffler**|Sensitive file/share hunting|
|**SharpHound**|Data collector|
|**BloodHound**|Relationship/attack-path analysis|

### Memory trick

```text
AD Module → Native enumeration

PowerView → Manual reconnaissance

SharpView → PowerView-style .NET

Snaffler → Find interesting files

SharpHound → Collect

BloodHound → Analyze
```

---

# 🎯 33. The Most Important Commands

### Load AD module

```powershell
Import-Module ActiveDirectory
```

### Domain information

```powershell
Get-ADDomain
```

### SPN users

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### Trusts

```powershell
Get-ADTrust -Filter *
```

### Groups

```powershell
Get-ADGroup -Filter * | select name
```

### Group information

```powershell
Get-ADGroup -Identity "Backup Operators"
```

### Group members

```powershell
Get-ADGroupMember -Identity "Backup Operators"
```

### PowerView user

```powershell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local
```

### Recursive group enumeration

```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

### Trust mapping

```powershell
Get-DomainTrustMapping
```

### Local admin test

```powershell
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

### SPN enumeration

```powershell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

### SharpView

```powershell
.\SharpView.exe Get-DomainUser -Identity forend
```

### Snaffler

```powershell
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```

### SharpHound

```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

---

# 🧠 34. What You Should Understand, Not Just Memorize

### Level 1 — Domain

```text
What domain am I in?
What is its SID?
What DCs exist?
What child domains exist?
```

Use:

```powershell
Get-ADDomain
```

---

### Level 2 — Users

```text
Who are the users?
Which users have SPNs?
Who belongs to privileged groups?
```

Use:

```text
Get-ADUser
Get-DomainUser
```

---

### Level 3 — Groups

```text
What groups exist?
Who belongs to them?
Are there nested groups?
```

Use:

```text
Get-ADGroup
Get-ADGroupMember
Get-DomainGroupMember -Recurse
```

---

### Level 4 — Trusts

```text
Does another domain trust this domain?
Is the trust bidirectional?
Is it inside the forest?
```

Use:

```text
Get-ADTrust
Get-DomainTrustMapping
```

---

### Level 5 — Hosts

```text
Where does a user have admin access?
Who is logged in?
What systems are accessible?
```

Use:

```text
Test-AdminAccess
BloodHound
```

---

### Level 6 — Files

```text
What shares can I access?
What interesting files exist?
```

Use:

```text
Get-NetShare
Find-DomainShare
Find-InterestingDomainShareFile
Snaffler
```

---

### Level 7 — Relationships

```text
How do all these objects connect?
Is there a path to higher privilege?
```

Use:

```text
SharpHound
      ↓
BloodHound
```

---

# 🔥 35. Final Mentor Cheat Sheet

```text
                    WINDOWS ATTACK HOST
                            |
                            v
                 VALID DOMAIN CREDENTIALS
                            |
        +-------------------+-------------------+
        |                   |                   |
        v                   v                   v
   AD MODULE             PowerView          SharpView
        |                   |                   |
        |                   +---------+---------+
        |                             |
        v                             v
     Domain                       Users
     Groups                       Groups
     Trusts                       ACLs
     Users                        Trusts
     SPNs                         Sessions
                                   |
                                   v
                               Local Admin
                                   |
                  +----------------+----------------+
                  |                                 |
                  v                                 v
               Snaffler                         SharpHound
                  |                                 |
                  v                                 v
             Shares/Files                     AD Dataset
                  |                                 |
                  +---------------+-----------------+
                                  |
                                  v
                              BloodHound
                                  |
                                  v
                         Relationship Analysis
                                  |
                                  v
                         Potential Attack Paths
```

## 🏆 The 10 Things I Want You to Memorize

1. `Get-ADDomain` → **domain information**
    
2. `Get-ADUser` → **AD users**
    
3. `Get-ADTrust` → **trust relationships**
    
4. `Get-ADGroup` → **groups**
    
5. `Get-ADGroupMember` → **group membership**
    
6. `Get-DomainUser` → **PowerView user enumeration**
    
7. `Get-DomainGroupMember -Recurse` → **nested group membership**
    
8. `Test-AdminAccess` → **local admin access**
    
9. `Snaffler` → **search accessible shares/files for sensitive data**
    
10. `SharpHound → BloodHound` → **collect and analyze AD relationships**
    

### ⭐ The core concept

Don't think:

> "I need to remember hundreds of commands."

Think:

> **Domain → Users → Groups → Trusts → Hosts → Shares → Privileges → Relationships → Attack Paths**

That mental model is much more important than memorizing syntax. The module itself concludes that after this enumeration phase, you should have a much clearer picture of users, groups, computers, GPOs, ACLs, local admin rights, RDP/WinRM access, SPNs, and other domain relationships.

**Next, we'll solve the module exercises exactly like we did with the previous module: you run the commands, show me your output, and I'll guide you toward the answer rather than immediately giving it to you.**