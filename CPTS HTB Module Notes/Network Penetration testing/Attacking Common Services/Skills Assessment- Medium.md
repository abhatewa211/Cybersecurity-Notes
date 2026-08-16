# Attacking Common Services - Medium

---

The second server is an internal server (within the `inlanefreight.htb` domain) that manages and stores emails and files and serves as a backup of some of the company's processes. From internal conversations, we heard that this is used relatively rarely and, in most cases, has only been used for testing purposes so far.
![[Pasted image 20260816103821.png]]

Steps to get flags

Step1. First we will nmap the open ports and also know the services running.
```bash
┌──(root㉿kali)-[~]
└─# nmap -v -sV -sC -O -T4 -A -oA /home/arjun/"Nmap Output"/medium 10.129.118.131
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 11:57 +0530
NSE: Loaded 158 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 11:57
Completed NSE at 11:57, 0.00s elapsed
Initiating NSE at 11:57
Completed NSE at 11:57, 0.00s elapsed
Initiating NSE at 11:57
Completed NSE at 11:57, 0.00s elapsed
Initiating Ping Scan at 11:57
Scanning 10.129.118.131 [4 ports]
Completed Ping Scan at 11:57, 0.26s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:57
Completed Parallel DNS resolution of 1 host. at 11:57, 0.50s elapsed
Initiating SYN Stealth Scan at 11:57
Scanning 10.129.118.131 [1000 ports]
Discovered open port 110/tcp on 10.129.118.131
Discovered open port 22/tcp on 10.129.118.131
Discovered open port 53/tcp on 10.129.118.131
Discovered open port 995/tcp on 10.129.118.131
Discovered open port 2121/tcp on 10.129.118.131
Completed SYN Stealth Scan at 11:57, 4.21s elapsed (1000 total ports)
Initiating Service scan at 11:57
Scanning 5 services on 10.129.118.131
Completed Service scan at 12:00, 177.74s elapsed (5 services on 1 host)
Initiating OS detection (try #1) against 10.129.118.131
Initiating Traceroute at 12:00
Completed Traceroute at 12:00, 0.73s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 12:00
Completed Parallel DNS resolution of 2 hosts. at 12:00, 0.50s elapsed
NSE: Script scanning 10.129.118.131.
Initiating NSE at 12:00
Completed NSE at 12:01, 20.12s elapsed
Initiating NSE at 12:01
Completed NSE at 12:01, 8.78s elapsed
Initiating NSE at 12:01
Completed NSE at 12:01, 0.00s elapsed
Nmap scan report for 10.129.118.131
Host is up (0.47s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE      VERSION
22/tcp   open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
53/tcp   open  domain       ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
110/tcp  open  pop3         Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: PIPELINING STLS UIDL SASL(PLAIN) USER RESP-CODES TOP CAPA AUTH-RESP-CODE
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-04-11T16:38:55
| Not valid after:  2032-04-08T16:38:55
| MD5:     a03e afe0 3b9e 242f 45ce 81ea 9205 485b
| SHA-1:   f95b c0ca f558 d268 5442 7213 80b6 ec09 2df5 55c0
|_SHA-256: d805 e97e 6bb7 0566 9929 f813 0e47 b059 95db ece5 89d6 e163 894c e4e5 db43 b361
995/tcp  open  ssl/pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: SASL(PLAIN) UIDL PIPELINING USER RESP-CODES TOP CAPA AUTH-RESP-CODE
| ssl-cert: Subject: commonName=ubuntu
| Subject Alternative Name: DNS:ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-04-11T16:38:55
| Not valid after:  2032-04-08T16:38:55
| MD5:     a03e afe0 3b9e 242f 45ce 81ea 9205 485b
| SHA-1:   f95b c0ca f558 d268 5442 7213 80b6 ec09 2df5 55c0
|_SHA-256: d805 e97e 6bb7 0566 9929 f813 0e47 b059 95db ece5 89d6 e163 894c e4e5 db43 b361
2121/tcp open  ccproxy-ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (InlaneFTP) [10.129.118.131]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port2121-TCP:V=7.99%I=7%D=8/16%Time=6A81586B%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,8D,"220\x20ProFTPD\x20Server\x20\(InlaneFTP\)\x20\[10\.129\.
SF:118\.131\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cre
SF:ative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creative
SF:\r\n");
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Uptime guess: 32.491 days (since Wed Jul 15 00:14:26 2026)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   727.25 ms 10.10.16.1
2   468.94 ms 10.129.118.131

NSE: Script Post-scanning.
Initiating NSE at 12:01
Completed NSE at 12:01, 0.00s elapsed
Initiating NSE at 12:01
Completed NSE at 12:01, 0.00s elapsed
Initiating NSE at 12:01
Completed NSE at 12:01, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 219.08 seconds
           Raw packets sent: 1150 (51.624KB) | Rcvd: 1143 (46.819KB)

```

Step2. We will first start with dns attacking we will do a zone transfer to get all the DNS records of the target machine by using dig command.
```bash
┌──(root㉿kali)-[~]
└─# dig AXFR @10.129.118.131 inlanefreight.htb

; <<>> DiG 9.20.26-1-Debian <<>> AXFR @10.129.118.131 inlanefreight.htb
; (1 server found)
;; global options: +cmd
inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.	604800	IN	NS	ns.inlanefreight.htb.
app.inlanefreight.htb.	604800	IN	A	10.129.200.5
dc1.inlanefreight.htb.	604800	IN	A	10.129.100.10
dc2.inlanefreight.htb.	604800	IN	A	10.129.200.10
int-ftp.inlanefreight.htb. 604800 IN	A	127.0.0.1
int-nfs.inlanefreight.htb. 604800 IN	A	10.129.200.70
ns.inlanefreight.htb.	604800	IN	A	127.0.0.1
un.inlanefreight.htb.	604800	IN	A	10.129.200.142
ws1.inlanefreight.htb.	604800	IN	A	10.129.200.101
ws2.inlanefreight.htb.	604800	IN	A	10.129.200.102
wsus.inlanefreight.htb.	604800	IN	A	10.129.200.80
inlanefreight.htb.	604800	IN	SOA	inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 935 msec
;; SERVER: 10.129.118.131#53(10.129.118.131) (TCP)
;; WHEN: Sun Aug 16 12:44:08 IST 2026
;; XFR size: 13 records (messages 1, bytes 372)

```

