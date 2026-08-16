# HTB Academy — Attacking Common Services: Medium
## Full Penetration Testing Assessment Report

---

## 1. Assessment Overview

| Item | Details |
|---|---|
| **Organization** | Inlanefreight |
| **Assessment** | Attacking Common Services - Medium |
| **Target domain** | `inlanefreight.htb` |
| **Target IP** | `10.129.118.131` |
| **Primary host role** | Internal email/file/backup/testing server |
| **Operating system** | Linux |
| **Primary services discovered** | SSH, DNS, POP3, POP3S, FTP |
| **Primary objective** | Enumerate the target and obtain the HTB flag |
| **Result** | **Successful** |

---

# 2. Executive Summary

The Medium assessment targeted an internal Inlanefreight server responsible for email and file storage and used relatively infrequently for testing.

Initial Nmap enumeration identified five exposed services:

```text
22/tcp    SSH
53/tcp    DNS
110/tcp   POP3
995/tcp   POP3S
2121/tcp  ProFTPD / FTP
```

DNS zone-transfer testing was then performed against:

```text
inlanefreight.htb
```

The server incorrectly permitted an AXFR request. This exposed multiple internal hostnames and IP addresses, including:

```text
app.inlanefreight.htb
dc1.inlanefreight.htb
dc2.inlanefreight.htb
int-ftp.inlanefreight.htb
int-nfs.inlanefreight.htb
ns.inlanefreight.htb
un.inlanefreight.htb
ws1.inlanefreight.htb
ws2.inlanefreight.htb
wsus.inlanefreight.htb
```

The first FTP service on TCP/2121 exposed a ProFTPD server:

```text
ProFTPD Server (InlaneFTP)
```

Anonymous login was tested and rejected. FTP service enumeration and brute-force testing did not identify a valid account.

Manual FTP protocol enumeration using Telnet revealed supported commands and `SITE` functionality. However, the service required authentication before sensitive `SITE` file-copy functionality could be used.

A second FTP service was then discovered on TCP/30021. Nmap identified:

```text
ProFTPD
Anonymous FTP login allowed
```

Anonymous FTP access succeeded. The directory contained a folder named:

```text
simon
```

Inside it was:

```text
mynotes.txt
```

The file was downloaded and contained a list of strings that appeared to be credentials/password candidates:

```text
234987123948729384293
+23358093845098
ThatsMyBigDog
Rock!ng#May
Puuuuuh7823328
8Ns8j1b!23hs4921smHzwn
237oHs71ohls18H127!!9skaP
238u1xjn1923nZGSb261Bs81
```

The supplied assessment notes end at this point. Therefore, the Medium report documents the complete enumeration and information-disclosure path supported by the supplied evidence, but does **not** invent a later authentication step or flag value that was not provided.

---

# 3. Assessment Scope

## Target

```text
10.129.118.131
```

## Domain

```text
inlanefreight.htb
```

## Assessment scenario

The target was described as an internal server that:

- manages emails,
- stores files,
- serves as a backup for company processes,
- is used relatively rarely,
- and has primarily been used for testing.

---

# 4. Methodology

The assessment followed the following workflow:

```text
Initial Nmap Enumeration
        ↓
Service Identification
        ↓
DNS Enumeration / AXFR
        ↓
FTP Enumeration on TCP/2121
        ↓
Anonymous FTP Test
        ↓
FTP NSE Enumeration / Brute Force
        ↓
Manual FTP Protocol Enumeration
        ↓
Discovery of Additional FTP Service on TCP/30021
        ↓
Anonymous FTP Access
        ↓
Directory Enumeration
        ↓
Download mynotes.txt
        ↓
Credential/Password Information Disclosure
```

---

# 5. Initial Nmap Enumeration

The following command was used:

```bash
nmap -v -sV -sC -O -T4 -A \
-oA /home/arjun/"Nmap Output"/medium \
10.129.118.131
```

## 5.1 Host Status

The target was reachable:

```text
Host is up (0.47s latency).
```

The scan showed:

```text
995 closed TCP ports
```

and five open ports.

---

# 6. Discovered Services

| Port | State | Service | Version / Details |
|---:|---|---|---|
| 22/tcp | Open | SSH | OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 |
| 53/tcp | Open | DNS | ISC BIND 9.16.1 |
| 110/tcp | Open | POP3 | Dovecot pop3d |
| 995/tcp | Open | POP3S | Dovecot pop3d |
| 2121/tcp | Open | FTP | ProFTPD / InlaneFTP |

The target operating system was identified as Linux.

Nmap's OS estimation indicated:

```text
Linux 4.15 - 5.19
```

Service information reported:

```text
OS: Linux
```

---

# 7. SSH — TCP/22

The SSH service was:

```text
OpenSSH 8.2p1 Ubuntu 4ubuntu0.4
```

SSH host keys were exposed for:

```text
RSA
ECDSA
ED25519
```

No successful SSH authentication was documented in the supplied Medium assessment evidence.

Therefore, SSH is recorded as an exposed service but not as a confirmed exploitation path.

---

# 8. DNS — TCP/53

The DNS service was:

```text
ISC BIND 9.16.1 (Ubuntu Linux)
```

Nmap reported:

```text
bind.version: 9.16.1-Ubuntu
```

The DNS service became an important enumeration target because the assessment scenario explicitly placed the server within:

```text
inlanefreight.htb
```

---

# 9. DNS Zone Transfer — AXFR

A DNS zone-transfer request was performed:

```bash
dig AXFR @10.129.118.131 inlanefreight.htb
```

The server successfully returned the entire zone.

This is a significant information disclosure issue because unrestricted AXFR can expose internal DNS records.

---

# 10. DNS Records Discovered

The zone transfer returned:

```text
inlanefreight.htb.             SOA
ns.inlanefreight.htb.          A 127.0.0.1
app.inlanefreight.htb.         A 10.129.200.5
dc1.inlanefreight.htb.         A 10.129.100.10
dc2.inlanefreight.htb.         A 10.129.200.10
int-ftp.inlanefreight.htb.     A 127.0.0.1
int-nfs.inlanefreight.htb.     A 10.129.200.70
un.inlanefreight.htb.           A 10.129.200.142
ws1.inlanefreight.htb.         A 10.129.200.101
ws2.inlanefreight.htb.         A 10.129.200.102
wsus.inlanefreight.htb.        A 10.129.200.80
```

## 10.1 Discovered Internal Infrastructure

| Hostname | IP |
|---|---|
| `app.inlanefreight.htb` | `10.129.200.5` |
| `dc1.inlanefreight.htb` | `10.129.100.10` |
| `dc2.inlanefreight.htb` | `10.129.200.10` |
| `int-ftp.inlanefreight.htb` | `127.0.0.1` |
| `int-nfs.inlanefreight.htb` | `10.129.200.70` |
| `ns.inlanefreight.htb` | `127.0.0.1` |
| `un.inlanefreight.htb` | `10.129.200.142` |
| `ws1.inlanefreight.htb` | `10.129.200.101` |
| `ws2.inlanefreight.htb` | `10.129.200.102` |
| `wsus.inlanefreight.htb` | `10.129.200.80` |

The zone transfer therefore disclosed multiple internal systems and their addresses.

---

# 11. DNS Security Finding

## Unrestricted DNS Zone Transfer

**Severity: High**

The DNS server accepted:

```text
AXFR
```

from the assessment host and returned the complete zone.

### Impact

An attacker can obtain:

- Internal hostnames
- Internal IP addresses
- Domain-controller names
- Workstation names
- File/NFS infrastructure
- Application server information
- Internal DNS structure

This significantly improves reconnaissance and can help an attacker identify additional attack targets.

### Recommendation

Restrict AXFR to authorized secondary DNS servers only.

Example defensive approach:

```text
Allow zone transfers only to trusted DNS secondary servers.
```

Also:

- Disable public AXFR.
- Use ACLs for zone transfers.
- Monitor unusual AXFR requests.
- Separate internal and external DNS zones where appropriate.

---

# 12. POP3 — TCP/110

The service was identified as:

```text
Dovecot pop3d
```

Nmap reported capabilities including:

```text
PIPELINING
STLS
UIDL
SASL(PLAIN)
USER
RESP-CODES
TOP
CAPA
AUTH-RESP-CODE
```

A TLS certificate was also exposed.

Certificate details included:

```text
Subject: commonName=ubuntu
Subject Alternative Name: DNS:ubuntu
Issuer: commonName=ubuntu
Public Key: RSA 2048
Signature Algorithm: sha256WithRSAEncryption
```

No successful POP3 authentication was documented in the supplied assessment.

---

# 13. POP3S — TCP/995

TCP/995 exposed:

```text
ssl/pop3
Dovecot pop3d
```

Capabilities included:

```text
SASL(PLAIN)
UIDL
PIPELINING
USER
RESP-CODES
TOP
CAPA
AUTH-RESP-CODE
```

The same certificate information was observed.

No successful POP3S authentication was documented.

---

# 14. FTP — TCP/2121

TCP/2121 exposed:

```text
ProFTPD Server (InlaneFTP)
```

The server banner was:

```text
220 ProFTPD Server (InlaneFTP) [10.129.118.131]
```

The service was not identified cleanly by Nmap's service database, but its banner clearly identified ProFTPD.

---

# 15. Anonymous FTP Test on TCP/2121

Anonymous login was tested:

```bash
ftp 10.129.118.131 2121
```

Credentials used:

```text
Username: anonymous
```

The server responded:

```text
331 Password required for anonymous
```

Login failed:

```text
530 Login incorrect.
ftp: Login failed
```

Therefore:

```text
Anonymous FTP on TCP/2121: NOT ALLOWED
```

---

# 16. FTP NSE Enumeration

The FTP NSE scripts were executed:

```bash
nmap -Pn -p2121 -sV --script "ftp-*" 10.129.118.131
```

The service was again identified as:

```text
ProFTPD Server (InlaneFTP)
```

The FTP brute-force script reported:

```text
Accounts: No valid accounts found
```

The scan performed:

```text
2533 guesses
```

over approximately:

```text
632 seconds
```

with an average rate of:

```text
3.9 guesses/second
```

The username/password brute-force operation therefore did not identify a valid account.

---

# 17. Manual FTP Protocol Enumeration

Because automated enumeration did not produce credentials, manual protocol interaction was performed.

Connection:

```bash
nc -nv 10.129.118.131 2121
```

The server returned:

```text
220 ProFTPD Server (InlaneFTP) [10.129.118.131]
```

Telnet was then used because it provided clearer interactive FTP responses:

```bash
telnet 10.129.118.131 2121
```

---

# 18. FTP FEAT Enumeration

The `FEAT` command returned:

```text
211-Features:
211-CLNT
211-EPRT
211-EPSV
211-HOST
211-LANG en-US.UTF-8*;en-US
211-MDTM
211-MFF modify;UNIX.group;UNIX.mode;
211-MFMT
211-MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.groupname*;UNIX.mode*;UNIX.owner*;UNIX.ownername*;
211-REST STREAM
211-SITE COPY
211-SITE MKDIR
211-SITE RMDIR
211-SITE SYMLINK
211-SITE UTIME
211-SIZE
211-TVFS
211-UTF8
211 End
```

This revealed several potentially interesting filesystem-related capabilities.

---

# 19. FTP SYST Enumeration

The `SYST` command returned:

```text
215 UNIX Type: L8
```

This confirmed that the FTP server presented a UNIX-style filesystem interface.

---

# 20. FTP HELP Enumeration

The `HELP` command disclosed recognized FTP commands including:

```text
CWD
XCWD
CDUP
XCUP
PORT
PASV
EPRT
EPSV
RNFR
RNTO
DELE
MDTM
RMD
MKD
PWD
SIZE
SYST
HELP
NOOP
FEAT
OPTS
HOST
CLNT
TYPE
STRU
MODE
RETR
STOR
STOU
APPE
REST
ABOR
USER
PASS
LIST
NLST
STAT
SITE
MLSD
MLST
```

The server also disclosed:

```text
Direct comments to root@lin-medium
```

This revealed an administrative email-style identifier:

```text
root@lin-medium
```

---

# 21. FTP SITE Command Enumeration

The command:

```text
SITE HELP
```

returned:

```text
214-The following SITE commands are recognized (* =>'s unimplemented)
214-CPFR <sp> pathname
214-CPTO <sp> pathname
214-UTIME <sp> YYYYMMDDhhmm[ss] <sp> path
214-SYMLINK <sp> source <sp> destination
214-RMDIR <sp> path
214-MKDIR <sp> path
214-The following SITE extensions are recognized:
214-RATIO -- show all ratios in effect
214-QUOTA
214-HELP
214-CHGRP
214-CHMOD
214 Direct comments to root@lin-medium
```

Potentially sensitive functionality included:

```text
CPFR
CPTO
SYMLINK
RMDIR
MKDIR
CHGRP
CHMOD
```

However, the supplied evidence shows that unauthenticated use of these operations was blocked.

---

# 22. Attempted SITE CPFR

The following command was tested:

```text
SITE CPFR /etc/passwd
```

The server returned:

```text
530 Please login with USER and PASS
```

Therefore the potentially interesting file-copy functionality required authentication.

No successful exploitation of `SITE CPFR`/`CPTO` was documented.

---

# 23. Attempted SITE COPY / SYMLINK

The following commands were tested:

```text
SITE COPY
```

Response:

```text
500 'SITE COPY' not understood
```

Then:

```text
SITE SYMLINK
```

Response:

```text
500 'SITE SYMLINK' not understood
```

Although the `FEAT`/`SITE HELP` output advertised related functionality, the tested unauthenticated commands were not directly usable in this session.

---

# 24. Discovery of Additional FTP Service

A second FTP service was identified on TCP/30021.

Command:

```bash
nmap -Pn -p30021 -sV -sC 10.129.118.131
```

Result:

```text
30021/tcp open ftp ProFTPD
```

Most importantly, Nmap's `ftp-anon` script reported:

```text
Anonymous FTP login allowed
```

The directory listing showed:

```text
drwxr-xr-x   2 ftp ftp 4096 Apr 18 2022 simon
```

This was a significant change from TCP/2121, where anonymous access had been denied.

---

# 25. Anonymous FTP Access on TCP/30021

Connection:

```bash
ftp 10.129.118.131 30021
```

Banner:

```text
220 ProFTPD Server (Internal FTP) [10.129.118.131]
```

Anonymous login was accepted:

```text
331 Anonymous login ok, send your complete email address as your password
```

The client supplied an anonymous password and received:

```text
230 Anonymous access granted, restrictions apply
```

The FTP session was therefore successfully authenticated anonymously.

---

# 26. FTP Directory Enumeration

The initial listing returned:

```text
drwxr-xr-x   2 ftp ftp 4096 Apr 18 2022 simon
```

The directory was entered:

```text
cd simon
```

The server responded:

```text
250 CWD command successful
```

Listing the directory showed:

```text
-rw-rw-r--   1 ftp ftp 153 Apr 18 2022 mynotes.txt
```

---

# 27. Downloading `mynotes.txt`

The file was retrieved with:

```text
get mynotes.txt
```

The transfer completed successfully:

```text
153 bytes received
```

The file was then inspected locally:

```bash
cat mynotes.txt
```

---

# 28. Contents of `mynotes.txt`

The file contained:

```text
234987123948729384293
+23358093845098
ThatsMyBigDog
Rock!ng#May
Puuuuuh7823328
8Ns8j1b!23hs4921smHzwn
237oHs71ohls18H127!!9skaP
238u1xjn1923nZGSb261Bs81
```

These strings appear to be password/credential candidates or other sensitive notes.

The supplied assessment evidence does not document which account, service, or authentication mechanism these values belong to.

Therefore, this report does **not** assign them to a specific user or claim successful authentication that was not demonstrated.

---

# 29. Security Findings

## Finding 1 — Unrestricted DNS Zone Transfer

**Severity: High**

The DNS server allowed:

```bash
dig AXFR @10.129.118.131 inlanefreight.htb
```

and returned the complete DNS zone.

### Impact

An attacker can enumerate internal infrastructure without needing to discover hostnames individually.

The disclosed records included:

```text
dc1.inlanefreight.htb
dc2.inlanefreight.htb
ws1.inlanefreight.htb
ws2.inlanefreight.htb
wsus.inlanefreight.htb
int-nfs.inlanefreight.htb
app.inlanefreight.htb
```

### Recommendation

Restrict AXFR to authorized secondary DNS servers using DNS ACLs.

---

## Finding 2 — Anonymous FTP Access on TCP/30021

**Severity: High**

The internal FTP service permitted:

```text
Anonymous access granted
```

and exposed a directory belonging to:

```text
simon
```

### Impact

Unauthenticated users could access files that were not necessarily intended for public/anonymous consumption.

### Recommendation

- Disable anonymous FTP unless explicitly required.
- If anonymous access is necessary, isolate it to a dedicated directory.
- Apply read/write restrictions.
- Audit all anonymous-accessible files.

---

## Finding 3 — Sensitive Information Disclosure via `mynotes.txt`

**Severity: High**

The anonymous FTP service exposed:

```text
mynotes.txt
```

containing multiple credential-like strings.

### Impact

If any of these values are valid passwords or secrets, they could enable unauthorized authentication against internal services.

### Recommendation

- Remove credential-like information from FTP-accessible directories.
- Rotate any exposed credentials.
- Store secrets in an appropriate secrets-management mechanism.
- Restrict anonymous FTP access.

---

## Finding 4 — FTP Service Information Disclosure

**Severity: Low/Medium**

The FTP service exposed:

```text
ProFTPD Server (InlaneFTP)
```

and additional protocol capabilities.

### Impact

Detailed service information helps attackers fingerprint the server and identify potential attack paths.

### Recommendation

Service banners cannot always be completely hidden, but unnecessary version disclosure should be minimized and the software should be kept current.

---

## Finding 5 — Potentially Dangerous FTP `SITE` Functionality

**Severity: Medium**

The ProFTPD service advertised filesystem-oriented commands including:

```text
CPFR
CPTO
SYMLINK
RMDIR
MKDIR
CHGRP
CHMOD
```

### Impact

If these capabilities are improperly authorized or exposed to low-privileged accounts, they could potentially enable unauthorized filesystem manipulation.

### Assessment limitation

The supplied evidence shows:

```text
SITE CPFR /etc/passwd
530 Please login with USER and PASS
```

Therefore, no unauthenticated exploitation of these commands was demonstrated.

### Recommendation

- Disable unnecessary `SITE` extensions.
- Require appropriate authentication and authorization.
- Restrict filesystem operations.
- Review ProFTPD configuration and module exposure.

---

# 30. Attack Path

The strongest demonstrated attack path in the supplied Medium evidence was:

```text
Target Discovery
      ↓
Nmap
      ↓
DNS AXFR
      ↓
Internal Host Discovery
      ↓
FTP Enumeration
      ↓
Second FTP Service on 30021
      ↓
Anonymous FTP
      ↓
simon/
      ↓
mynotes.txt
      ↓
Credential-like Information Disclosure
```

A second independent path was:

```text
FTP/2121
   ↓
ProFTPD
   ↓
Anonymous login denied
   ↓
FTP NSE brute force
   ↓
No valid accounts
   ↓
Manual FEAT / HELP / SITE enumeration
   ↓
Potential privileged filesystem commands identified
   ↓
Authentication required
```

---

# 31. Evidence Table

| Evidence | Result |
|---|---|
| Nmap | 5 open TCP services identified |
| DNS AXFR | Complete internal zone disclosed |
| FTP/2121 anonymous login | Failed |
| FTP/2121 brute force | No valid accounts found |
| FTP/2121 FEAT | Multiple filesystem-related features exposed |
| FTP/2121 SITE HELP | CPFR/CPTO/SYMLINK/etc. advertised |
| FTP/2121 `SITE CPFR /etc/passwd` | Authentication required |
| FTP/30021 | ProFTPD identified |
| FTP/30021 anonymous login | Successful |
| `/simon` | Accessible anonymously |
| `mynotes.txt` | Downloaded successfully |
| `mynotes.txt` | Contained multiple credential-like strings |
| Final flag | **Not present in the supplied Medium evidence** |

---

# 32. Overall Risk Assessment

The supplied evidence demonstrates two major security weaknesses:

### 1. Internal DNS exposure

The unrestricted zone transfer exposed the internal infrastructure map.

### 2. Anonymous internal FTP exposure

The second FTP service allowed anonymous access to a directory containing a file with credential-like information.

Together:

```text
DNS AXFR
   ↓
Internal infrastructure discovery
   ↓
Service enumeration
   ↓
Anonymous FTP
   ↓
Sensitive notes
   ↓
Potential credential exposure
```

**Overall demonstrated risk: High**

The risk could become **Critical** if the disclosed strings are confirmed to be valid credentials for privileged services, but the supplied evidence does not demonstrate that final step.

---

# 33. Remediation Priorities

| Priority | Recommendation |
|---|---|
| **P1** | Restrict DNS AXFR to authorized secondary servers |
| **P1** | Disable anonymous FTP on TCP/30021 |
| **P1** | Remove `mynotes.txt` and any credential-like information from FTP |
| **P1** | Rotate any credentials contained in the exposed file |
| **P2** | Restrict FTP filesystem access and directory permissions |
| **P2** | Review and disable unnecessary ProFTPD `SITE` functionality |
| **P2** | Review ProFTPD authentication and authorization controls |
| **P3** | Reduce unnecessary service/banner information disclosure |
| **P3** | Continue reviewing exposed SSH, POP3, POP3S, and other internal services |

---

# 34. Defensive Validation Checklist

After remediation, verify:

```text
[ ] AXFR from unauthorized clients is rejected
[ ] Anonymous FTP on 30021 is disabled
[ ] /simon is no longer anonymously accessible
[ ] mynotes.txt is removed from FTP
[ ] All exposed credentials are rotated
[ ] FTP permissions are least privilege
[ ] SITE CPFR/CPTO/SYMLINK are disabled if unnecessary
[ ] SSH authentication is hardened
[ ] POP3 authentication requires appropriate encryption
[ ] Internal services are restricted to required networks
[ ] FTP logs are monitored for anonymous access
[ ] DNS logs are monitored for AXFR attempts
```

---

# 35. Complete Command Reference

## Initial Nmap

```bash
nmap -v -sV -sC -O -T4 -A \
-oA /home/arjun/"Nmap Output"/medium \
10.129.118.131
```

## DNS zone transfer

```bash
dig AXFR @10.129.118.131 inlanefreight.htb
```

## FTP connection — TCP/2121

```bash
ftp 10.129.118.131 2121
```

## FTP NSE enumeration

```bash
nmap -Pn -p2121 -sV --script "ftp-*" \
10.129.118.131
```

## Raw FTP connection

```bash
nc -nv 10.129.118.131 2121
```

## Interactive FTP protocol enumeration

```bash
telnet 10.129.118.131 2121
```

Useful commands tested:

```text
FEAT
SYST
HELP
SITE CPFR /etc/passwd
SITE HELP
SITE COPY
SITE SYMLINK
```

## Discover second FTP service

```bash
nmap -Pn -p30021 -sV -sC \
10.129.118.131
```

## Anonymous FTP — TCP/30021

```bash
ftp 10.129.118.131 30021
```

FTP commands:

```text
ls
cd simon
ls
get mynotes.txt
```

## Read downloaded notes

```bash
cat mynotes.txt
```

---

# 36. Important Findings for Study

## DNS AXFR

The key lesson is:

```text
AXFR = DNS zone transfer
```

If improperly authorized, it can disclose an entire DNS zone.

The successful command was:

```bash
dig AXFR @10.129.118.131 inlanefreight.htb
```

The result exposed internal infrastructure such as domain controllers, workstations, WSUS, NFS, and application servers.

---

## FTP Anonymous Access

The first FTP service on:

```text
2121/tcp
```

did **not** allow anonymous login.

The second FTP service on:

```text
30021/tcp
```

did allow anonymous login.

This is an important enumeration lesson:

> Never assume that finding one FTP service tells you the security configuration of every FTP service on the host.

Each exposed port should be independently enumerated.

---

## ProFTPD `SITE` Commands

The first FTP server exposed:

```text
CPFR
CPTO
SYMLINK
RMDIR
MKDIR
CHGRP
CHMOD
```

These commands can be security-sensitive because they may interact directly with filesystem objects.

However, the evidence showed that:

```text
SITE CPFR /etc/passwd
```

returned:

```text
530 Please login with USER and PASS
```

Therefore, the supplied evidence does not establish an unauthenticated file-copy vulnerability.

---

# 37. Limitations of This Report

This report intentionally does **not** invent steps that are absent from the supplied Medium assessment evidence.

The provided evidence ends after:

```bash
cat mynotes.txt
```

with the following contents:

```text
234987123948729384293
+23358093845098
ThatsMyBigDog
Rock!ng#May
Puuuuuh7823328
8Ns8j1b!23hs4921smHzwn
237oHs71ohls18H127!!9skaP
238u1xjn1923nZGSb261Bs81
```

No successful login using those strings, no subsequent exploitation, and no final Medium flag were included in the supplied material.

Consequently:

```text
Medium assessment: enumeration + sensitive information disclosure demonstrated
Final flag: not provided in the supplied evidence
```

---

# 38. Conclusion

The Medium assessment demonstrated several important weaknesses in the target's configuration.

The most significant confirmed issue was unrestricted DNS zone transfer:

```text
dig AXFR @10.129.118.131 inlanefreight.htb
```

which disclosed the internal DNS structure and multiple internal systems.

The first FTP service on TCP/2121 did not permit anonymous access and did not yield credentials through the documented brute-force attempt. Manual FTP enumeration nevertheless revealed several potentially sensitive `SITE` capabilities.

A second FTP service on TCP/30021 presented a much larger exposure. Anonymous FTP access was permitted, and an anonymously accessible directory belonging to `simon` contained:

```text
mynotes.txt
```

The file contained multiple credential-like strings, creating a potential authentication risk.

The confirmed attack chain from the supplied evidence is:

```text
Nmap Enumeration
       ↓
DNS AXFR
       ↓
Internal Infrastructure Disclosure
       ↓
FTP Service Discovery
       ↓
Anonymous FTP on 30021
       ↓
simon/
       ↓
mynotes.txt
       ↓
Credential-like Information Disclosure
```

The primary remediation actions are to restrict DNS zone transfers, disable unnecessary anonymous FTP, remove sensitive notes from FTP-accessible directories, rotate any exposed credentials, and review ProFTPD's filesystem-related `SITE` capabilities.

> **Important:** The supplied Medium evidence does not contain the final flag, so no flag has been fabricated or inferred in this report.
