![Image](https://www.openwall.com/john/cloud/aws-openwall-bundle-md5crypt.png)

![Image](https://www.varonis.com/hs-fs/hubfs/Imported_Blog_Media/Reasons-To-Use-John-The-Ripper.png?height=864&name=Reasons-To-Use-John-The-Ripper.png&width=1240)

![Image](https://cdn.sanity.io/images/3jwyzebk/production/57bfae028486dcd24e40b6fbddbee786ead91909-1502x988.png)

![Image](https://ars.els-cdn.com/content/image/3-s2.0-B9781597495707000121-f12-04.jpg)

### 📌 What is John the Ripper?

- **John the Ripper (JtR / john)** is a powerful **password cracking tool**
    
- Used in **penetration testing & security auditing**
    
- Initially released in **1996** for UNIX systems
    
- Open-source and widely used in the security industry
    

### 🚀 Jumbo Version (Recommended)

- Better performance
    
- Supports more hash formats
    
- Includes:
    
    - Multilingual wordlists
        
    - 64-bit optimization
        
    - Additional cracking features
        

### 🔧 Extra Tools Included:

- File converters (e.g., `zip2john`, `ssh2john`)
    
- Hash format utilities
    

📌 JtR supports **multiple attack modes**

---

# 🔓 Cracking Modes in John the Ripper

---

## 1️⃣ Single Crack Mode

![Image](https://www.cyberciti.biz/media/new/faq/2006/02/Understanding-etc-passwd-file-format-for-Linux-and-Unix-systems.png)

![Image](https://www.mdpi.com/computers/computers-14-00024/article_deploy/html/images/computers-14-00024-g002.png)

![Image](https://www.mdpi.com/applsci/applsci-10-07306/article_deploy/html/images/applsci-10-07306-g001.png)

![Image](https://www.mdpi.com/sensors/sensors-20-03106/article_deploy/html/images/sensors-20-03106-g001a.png)

### 📌 Definition:

- Rule-based attack using **user information**
    
- Targets:
    
    - Username
        
    - Full name (GECOS)
        
    - Home directory
        

### 📌 Example File:

```text
r0lf:$6$ues25dIanlctrWxg$...:0:0:Rolf Sebastian:/home/r0lf:/bin/bash
```

### 📌 Command:

```bash
john --single passwd
```

### ⚡ How it Works:

- Extracts:
    
    - `r0lf`
        
    - `Rolf Sebastian`
        
- Applies rules like:
    
    - `Smith1`
        
    - `Rolf123`
        

### ✅ Result:

- Password successfully cracked
    

### 🔑 Key Point:

- Very effective for **Linux password files**
    

---

## 2️⃣ Wordlist Mode (Dictionary Attack)

![Image](https://repository-images.githubusercontent.com/850837348/d40efb10-ce7c-4a90-aac8-142e10cbd71e)

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/6474e82e6f85eab93707b9e6_663%20Preview.jpg)

![Image](https://www.mdpi.com/applsci/applsci-13-05979/article_deploy/html/images/applsci-13-05979-g007.png)

![Image](https://marvel-b1-cdn.bc0a.com/f00000000310757/www.fortinet.com/content/dam/fortinet/images/cyberglossary/brute-force-attacks.png)

### 📌 Definition:

- Uses a **wordlist (dictionary)** of common passwords
    

### 📌 Command Syntax:

```bash
john --wordlist=<wordlist_file> <hash_file>
```

### 📌 Wordlist Format:

- Plain text
    
- One password per line
    

### ⚙️ Advanced Option:

```bash
john --wordlist=rockyou.txt --rules hashes.txt
```

### 🔧 Rules Feature:

- Modify words:
    
    - Add numbers → `password123`
        
    - Capitalize → `Password`
        
    - Add symbols → `Password!`
        

### 🔑 Key Point:

- Most **efficient and commonly used attack**
    

---

## 3️⃣ Incremental Mode (Advanced Brute Force)

![Image](https://media.springernature.com/full/springer-static/image/art%3A10.1038%2Fs41598-025-01080-5/MediaObjects/41598_2025_1080_Fig1_HTML.png)

![Image](https://www.mdpi.com/applsci/applsci-11-04607/article_deploy/html/images/applsci-11-04607-g001.png)

![Image](https://assets.esecurityplanet.com/uploads/2019/10/John-The-Ripper.png)

![Image](https://www.oreilly.com/api/v2/epubs/urn%3Aorm%3Abook%3A9781788623377/files/assets/53dab6c1-1fe2-4099-a81d-b7ab9b24c5e3.png)

### 📌 Definition:

- Advanced brute-force using **Markov chains**
    
- Generates passwords based on probability
    

### 📌 Command:

```bash
john --incremental <hash_file>
```

### ⚡ Features:

- No wordlist required
    
- Generates combinations dynamically
    
- Prioritizes **likely passwords first**
    

### 📂 Config Example:

```bash
grep '# Incremental modes' -A 100 /etc/john/john.conf
```

### 🔑 Key Points:

- More efficient than naive brute-force
    
- Still **time-consuming**
    
- Customizable:
    
    - Character set
        
    - Password length
        

---

# 🔍 Identifying Hash Formats

![Image](https://miro.medium.com/v2/da%3Atrue/resize%3Afit%3A1200/0%2AFGlOuA7OQIbuJoH1)

![Image](https://www.techtarget.com/rms/onlineImages/security-md5_hashing_mobile.jpg)

![Image](https://www.researchgate.net/publication/331380160/figure/fig2/AS%3A730919145070601%401551276112783/Comparison-between-different-hash-algorithms-19.png)

![Image](https://www.researchgate.net/profile/Radwa-Adel-2/publication/311019269/figure/tbl1/AS%3A738549632606208%401553095362224/Comparison-of-Hash-Function-for-Certain-Messages.png)

### 📌 Problem:

- Unknown hash format
    

### 📌 Example Hash:

```text
193069ceb0461e1d40d216e32c79c704
```

### 🔧 Tool: `hashid`

```bash
hashid -j 193069ceb0461e1d40d216e32c79c704
```

### 📊 Output Suggests:

- MD5
    
- NTLM
    
- RIPEMD-128
    
- Many others
    

### ⚠️ Reality:

- Sometimes **multiple possible formats**
    
- Use **context** to decide
    

### 📌 Solution:

- Specify format manually:
    

```bash
john --format=raw-md5 hashes.txt
```

📌 JtR supports **hundreds of hash formats**

---

# 📂 Cracking Password-Protected Files

![Image](https://assets.esecurityplanet.com/uploads/2019/10/John-The-Ripper.png)

![Image](https://www.mdpi.com/applsci/applsci-13-05979/article_deploy/html/images/applsci-13-05979-g008.png)

![Image](https://www.varonis.com/hs-fs/hubfs/Imported_Blog_Media/Reasons-To-Use-John-The-Ripper.png?height=864&name=Reasons-To-Use-John-The-Ripper.png&width=1240)

![Image](https://www.openwall.com/john/cloud/aws-openwall-bundle-md5crypt.png)

### 📌 Concept:

- Convert files → Hash → Crack
    

### 📌 General Syntax:

```bash
<tool> <file> > hash.txt
```

### 🔧 Common Tools:

|Tool|Purpose|
|---|---|
|`zip2john`|ZIP files|
|`rar2john`|RAR archives|
|`pdf2john`|PDF files|
|`ssh2john`|SSH keys|
|`keepass2john`|KeePass DB|

### 📌 Example:

```bash
zip2john file.zip > hash.txt
john hash.txt
```

### 📌 Many Tools Available:

```bash
locate *2john*
```

---

# ⚡ Summary of JtR Modes

|Mode|Type|Speed|Use Case|
|---|---|---|---|
|Single Mode|Rule-based|Fast|User-based guesses|
|Wordlist Mode|Dictionary|Very Fast|Common passwords|
|Incremental|Brute-force (AI)|Slow|Full coverage|

---

# 🔥 Key Takeaways

- JtR is a **powerful and flexible password cracking tool**
    
- **Wordlist mode = most practical**
    
- **Single mode = smart guessing using user data**
    
- **Incremental mode = last resort (heavy)**
    
- Hash format identification is **critical**
    
- File cracking requires **conversion tools**
---
