![Image](https://assets.esecurityplanet.com/uploads/2019/10/John-The-Ripper.png)

![Image](https://dl.flathub.org/media/com/openwall/John/468f777164078acad5ad8b58800b5d13/screenshots/image-1_orig.png)

![Image](https://delinea.com/hs-fs/hubfs/Imported_Blog_Media/Hashcat.gif?height=1080&name=Hashcat.gif&width=1512)

![Image](https://www.mdpi.com/sensors/sensors-20-03106/article_deploy/html/images/sensors-20-03106-g001a.png)

### 📌 Definition

- **John the Ripper (JtR / john)** is a **password cracking tool**
    
- Used in:
    
    - Penetration testing
        
    - Security auditing
        

### 📅 Background

- Released in **1996**
    
- Designed for **UNIX systems**
    
- Now supports multiple platforms
    

### 🚀 Jumbo Version (Important)

- Recommended version
    
- Provides:
    
    - Performance optimization
        
    - Multilingual wordlists
        
    - 64-bit support
        
    - More cracking features
        

### 🔧 Capabilities

- Supports:
    
    - Brute-force attacks
        
    - Dictionary attacks
        
- Includes tools to:
    
    - Convert files → hashes
        
    - Identify hash formats
        

📌 Regularly updated to match modern security trends

---

# 🔓 Cracking Modes

---

## 1️⃣ Single Crack Mode

![Image](https://www.cyberciti.biz/media/new/faq/2006/02/Understanding-etc-passwd-file-format-for-Linux-and-Unix-systems.png)

![Image](https://www.avast.com/hs-fs/hubfs/undefined-Feb-20-2026-02-57-49-8091-PM.png?height=1249&name=undefined-Feb-20-2026-02-57-49-8091-PM.png&width=1600)

![Image](https://assets.esecurityplanet.com/uploads/2019/10/John-The-Ripper.png)

![Image](https://media.springernature.com/full/springer-static/image/art%3A10.1038%2Fs41598-025-01080-5/MediaObjects/41598_2025_1080_Fig1_HTML.png)

### 📌 Definition

- Rule-based attack using **user-specific information**
    

### 🎯 Uses:

- Username
    
- Full name (GECOS)
    
- Home directory
    

---

### 📌 Example passwd Entry

```text
r0lf:$6$ues25dIanlctrWxg$...:0:0:Rolf Sebastian:/home/r0lf:/bin/bash
```

### 📌 Attack Command

```bash
john --single passwd
```

---

### ⚙️ How It Works

- Extracts:
    
    - `r0lf`
        
    - `Rolf Sebastian`
        
- Applies transformations:
    
    - `Rolf123`
        
    - `Sebastian1`
        
    - `r0lf2024`
        

---

### ✅ Result

- Password successfully cracked
    

### 🔑 Key Point

- Very effective for **Linux credential attacks**
    

---

## 2️⃣ Wordlist Mode (Dictionary Attack)

![Image](https://repository-images.githubusercontent.com/850837348/d40efb10-ce7c-4a90-aac8-142e10cbd71e)

![Image](https://delinea.com/hs-fs/hubfs/Imported_Blog_Media/7-CeWL-custom-wordlist-generator.png?height=267&name=7-CeWL-custom-wordlist-generator.png&width=657)

![Image](https://www.researchgate.net/profile/Al-Saraireh-J/publication/351679506/figure/fig1/AS%3A1045352912273408%401626242964308/Common-cybersecurity-keywords.png)

![Image](https://www.hackthebox.com/images/landingv3/og/og-hacking-glossary.png)

### 📌 Definition

- Uses a **wordlist of common passwords**
    

---

### 📌 Syntax

```bash
john --wordlist=<wordlist_file> <hash_file>
```

---

### 📌 Wordlist Requirements

- Plain text file
    
- One password per line
    
- Multiple lists can be combined
    

---

### ⚙️ Rules Feature

```bash
john --wordlist=rockyou.txt --rules hashes.txt
```

Transforms words like:

- `password` → `Password123`
    
- `admin` → `Admin@123`
    

---

### 🔑 Key Point

- **Most efficient and widely used attack**
    

---

## 3️⃣ Incremental Mode (Advanced Brute Force)

![Image](https://www.mdpi.com/applsci/applsci-11-04607/article_deploy/html/images/applsci-11-04607-g001.png)

![Image](https://www.researchgate.net/publication/221609438/figure/fig4/AS%3A669308778733578%401536587056232/Number-of-passwords-cracked-in-90-minutes-by-the-John-the-Ripper-password-cracker-tool.png)

![Image](https://discover.strongdm.com/hubfs/brute-force-attack.jpg)

![Image](https://www.fortinet.com/content/dam/fortinet/images/cyberglossary/brute-force-attacks.png)

### 📌 Definition

- Brute-force using **Markov chains (probability model)**
    

---

### 📌 Command

```bash
john --incremental <hash_file>
```

---

### ⚙️ Features

- No wordlist needed
    
- Generates passwords dynamically
    
- Prioritizes likely passwords
    

---

### 📂 Config Example

```bash
grep '# Incremental modes' -A 100 /etc/john/john.conf
```

---

### 🔑 Key Points

- Most **powerful mode**
    
- Also **slowest**
    
- Can be customized:
    
    - Charset
        
    - Length
        

📌 Resource-intensive for long passwords

---

# 🔍 Identifying Hash Formats

![Image](https://miro.medium.com/v2/da%3Atrue/resize%3Afit%3A1200/0%2AFGlOuA7OQIbuJoH1)

![Image](https://www.techtarget.com/rms/onlineImages/security-md5_hashing_mobile.jpg)

![Image](https://www.researchgate.net/publication/338956746/figure/fig1/AS%3A853567866941440%401580517846651/Flowchart-of-the-proposed-image-hashing-scheme.png)

![Image](https://www.researchgate.net/publication/362526607/figure/fig2/AS%3A11431281416042223%401746049438840/The-flow-chart-of-the-implemented-hash-algorithm.tif)

### 📌 Problem

- Unknown hash type
    

---

### 📌 Example Hash

```text
193069ceb0461e1d40d216e32c79c704
```

---

### 🔧 Tool: hashID

```bash
hashid -j 193069ceb0461e1d40d216e32c79c704
```

---

### 📊 Output Includes:

- MD5
    
- NTLM
    
- RIPEMD-128
    
- Many more
    

---

### ⚠️ Challenge

- Multiple possible formats
    

### 💡 Solution

- Use context (where hash came from)
    

---

### 📌 Specify Format Manually

```bash
john --format=raw-md5 hashes.txt
```

📌 JtR supports **hundreds of formats**

---

# 📂 Cracking Password-Protected Files

![Image](https://assets.esecurityplanet.com/uploads/2019/10/John-The-Ripper.png)

![Image](https://www.mdpi.com/applsci/applsci-13-05979/article_deploy/html/images/applsci-13-05979-g008.png)

![Image](https://media.springernature.com/full/springer-static/image/art%3A10.1038%2Fs41598-025-31792-7/MediaObjects/41598_2025_31792_Fig1_HTML.png)

![Image](https://www.researchgate.net/publication/345817049/figure/fig3/AS%3A957507891625996%401605299079714/The-workflow-of-the-upload-file-function.png)

### 📌 Concept

- Convert file → Extract hash → Crack
    

---

### 📌 General Syntax

```bash
<tool> <file> > file.hash
```

---

### 🔧 Common Tools

|Tool|Purpose|
|---|---|
|zip2john|ZIP files|
|rar2john|RAR files|
|pdf2john|PDF documents|
|ssh2john|SSH keys|
|keepass2john|KeePass DB|

---

### 📌 Example

```bash
zip2john file.zip > hash.txt
john hash.txt
```

---

### 📌 Find All Tools

```bash
locate *2john*
```

---

# ⚡ Summary Table

|Mode|Type|Speed|Usage|
|---|---|---|---|
|Single Mode|Rule-based|Fast|User info|
|Wordlist Mode|Dictionary|Very Fast|Common passwords|
|Incremental|Brute-force AI|Slow|Full attack|

---

# 🔥 Key Takeaways

- JtR is a **core tool in penetration testing**
    
- **Wordlist mode = most practical**
    
- **Single mode = smart guessing**
    
- **Incremental mode = exhaustive attack**
    
- Hash identification is **critical skill**
    
- File cracking requires **2john tools**
---
