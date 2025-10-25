
## **Step 1: Reconnaissance**

Before attacking, we need to gather information about the target.

### **1.1 Network Discovery**

First, identify the IP address of the Kioptrix machine on the network:

bash

```bash
netdiscover -r 192.168.1.0/24
```

As i run the above command i finally get my Machine **IP**.

**192.168.1.163   08:00:27:fb:c8:d7      1      42  PCS Systemtechnik GmbH**

### **1.2 Port Scanning with Nmap**

Perform an Nmap scan to discover open ports and services:

```bash
nmap -v -sV -sC -O -T4 -p- -A -oA /home/arjun/"Nmap Output"/kioptrix-2 192.168.1.104
```

###### **OUTPUT**

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 3.9p1 (protocol 1.99)
| ssh-hostkey: 
|   1024 8f:3e:8b:1e:58:63:fe:cf:27:a3:18:09:3b:52:cf:72 (RSA1)
|   1024 34:6b:45:3d:ba:ce:ca:b2:53:55:ef:1e:43:70:38:36 (DSA)
|_  1024 68:4d:8c:bb:b6:5a:bd:79:71:b8:71:47:ea:00:42:61 (RSA)
|_sshv1: Server supports SSHv1
80/tcp   open  http     Apache httpd 2.0.52 ((CentOS))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.0.52 (CentOS)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp  open  rpcbind  2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            605/udp   status
|_  100024  1            608/tcp   status
443/tcp  open  ssl/http Apache httpd 2.0.52 ((CentOS))
|_ssl-date: 2025-09-16T11:38:30+00:00; +3h59m59s from scanner time.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.0.52 (CentOS)
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: md5WithRSAEncryption
| Not valid before: 2009-10-08T00:10:47
| Not valid after:  2010-10-08T00:10:47
| MD5:   01de:29f9:fbfb:2eb2:beaf:e624:3157:090f
|_SHA-1: 560c:9196:6506:fb0f:fb81:66b1:ded3:ac11:2ed4:808a
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
608/tcp  open  status   1 (RPC #100024)
631/tcp  open  ipp      CUPS 1.1
|_http-title: 403 Forbidden
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS POST PUT
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/1.1
3306/tcp open  mysql    MySQL (unauthorized)

## **Step 2: Exploitation**

Now, let's exploit This machine by using, Apache httpd 2.0.52 ((CentOS)).

1. As we browse the IP on the browser a login page pop-up's.

![[Pasted image 20250923135723.png]]

2.  As we seen above there is a normal login page, so we will try basic SQL injection command       ' OR 1=1--.

![[Pasted image 20250923140137.png]]

3.  As we proceed with the basic SQL injection command ' OR 1=1-- we get a **Basic Administrative Web Console**.

![[Pasted image 20250923140447.png]]

4. As the above image depicts that we  can ping a machine lets test.

![[Pasted image 20250923140732.png]]

5. As you can see above i pinged my PC IP it works. So now we will add a reverse shell command to IP Pinging Box as attached below.

![[Pasted image 20250923141000.png]]

6.  Now we will start a listener in our main pc with the port 4444 and also run the command  in the browser as shown above.

![[Pasted image 20250923142211.png]]

7. Now  we have got the lower privilege shell as attached below.

![[Pasted image 20250923142426.png]]

8. Now we will escalate the privilege to root user using an kernel exploit as shown below. First we will check the OS on which the machine is running.

![[Pasted image 20250923143041.png]]

9. Now we will download the exploit from Exploit-DB Databse. Named 9542.c

![[Pasted image 20250923143244.png]]

10.  After downloading the  exploit we will transfer the exploit to the machine by starting a python http sever.

```bash
python3 -m http.server 8000
```

![[Pasted image 20250923165517.png]]

11. Let's transfer the exploit to machine by wget command.

![[Pasted image 20250923165835.png]]

12. Let's compile the exploit by c  lang command.

![[Pasted image 20250923170019.png]]

13. Let's run the  exploit. We have get the  root shell.

![[Pasted image 20250923170139.png]]




