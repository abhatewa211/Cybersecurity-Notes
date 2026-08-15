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

Step3. We will now need password as well we will enumerate it by using hydra and we will get our password.
