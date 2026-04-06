
![Image](https://cdn.sanity.io/images/3jwyzebk/production/99e4a2b570f1e127ac7dc33232ef3c8b807fb662-800x333.png?auto=format&fit=max&q=75&w=1920)

![Image](https://miro.medium.com/1%2AM9IrtiQEoHkHYxzuA6yGgg.png)

![Image](https://supertokens.com/covers/password_hashing_and_salting.png)

![Image](https://upload.wikimedia.org/wikipedia/commons/2/2b/Cryptographic_Hash_Function.svg)

### 📌 What is Password Hashing?

- Passwords are **not stored in plain text**.
    
- Instead, they are converted into a **hash** using a mathematical function.
    
- A **hash function**:
    
    - Takes input (password)
        
    - Produces a fixed-size output (hash)
        

### 🔑 Common Hash Algorithms:

- **MD5**
    
- **SHA-256**
    

### 📌 Example:

```bash
echo -n Soccer06! | md5sum
40291c1d19ee11a7df8495c4cccefdfa

echo -n Soccer06! | sha256sum
a025dc6fabb09c2b8bfe23b5944635f9b68433ebd9a1a09453dd4fee00766d93
```

### ⚠️ Important Concept:

- Hashing is **one-way**
    
- You **cannot reverse** a hash directly
    
- Attempting to recover passwords = **Password Cracking**
    

---

# 🌈 Rainbow Tables

![Image](https://ic.nordcdn.com/v1/https%3A//sb.nordcdn.com/m/081947e569343b24/original/blog-rainbow-table-chain-new-asset-svg.svg)

![Image](https://yourbasic.org/algorithms/hash-table.png)

![Image](https://images.squarespace-cdn.com/content/v1/5ffe234606e5ec7bfc57a7a3/222be199-9926-4bac-9741-1b679ee6b346/image-asset.png)

![Image](https://figures.semanticscholar.org/9bd3bbff90d8b1eafd32ba4f42d67246375a5361/2-Table4-2-1.png)

### 📌 What are Rainbow Tables?

- Precomputed tables of:
    
    - Passwords → Hashes
        
- Used for **fast lookup attacks**
    

### 📊 Example Table:

|Password|MD5 Hash|
|---|---|
|123456|e10adc3949ba59abbe56e057f20f883e|
|password|5f4dcc3b5aa765d61d8327deb882cf99|
|rockyou|f806fc5a2a0d5ba2471600758452799c|

### ⚡ Advantage:

- Extremely fast (no computation needed)
    

### ❌ Limitation:

- Only works if hash exists in table
    

---

# 🧂 Salting (Defense Mechanism)

![Image](https://media.licdn.com/dms/image/v2/D5612AQFnYx2xrOgxfA/article-cover_image-shrink_720_1280/article-cover_image-shrink_720_1280/0/1709023819721?e=2147483647&t=kOvMakdfNke9xIVRBylUlcflnwmYrp5JH7FGW8Q9sQo&v=beta)

![Image](https://carlpaton.github.io/d/salted-hash/password-hash-salt-1.png)

![Image](https://www.mdpi.com/electronics/electronics-14-03769/article_deploy/html/images/electronics-14-03769-g008.png)

![Image](https://www.crowe.com/-/media/crowe/llp/sc10-media/insights/publications/cybersecurity-watch/content-2000x1125/1000x1643contentcsta2503002ofy25-cybersecurity-watch--communication-in-the-time-of-salt-typhoon3.jpg?hash=3AD08DC668704CA9B7F5D0FBDB56E12D&w=767)

### 📌 What is a Salt?

- A **random string added to password before hashing**
    

### 📌 Example:

```bash
echo -n Th1sIsTh3S@lt_Soccer06! | md5sum
90a10ba83c04e7996bc53373170b5474
```

### 🔑 Key Points:

- Salt is **not secret**
    
- Stored alongside hash
    
- Prevents rainbow table attacks
    

### 💡 Why it Works:

- Same password → Different hashes (due to salt)
    
- Forces attacker to recompute tables
    

### ⚠️ Important:

- Salt should be **unique per password**
    
- Even 1-byte salt increases combinations massively (×256)
    

---

# 💣 Brute-Force Attack

![Image](https://www.strongdm.com/hubfs/brute-force-attack.jpg)

![Image](https://www.loffler.com/hubfs/Blog%20Images/Five%20Common%20Cyberattacks.jpg)

![Image](https://www.fortinet.com/content/dam/fortinet/images/cyberglossary/brute-force-attacks.png)

![Image](https://media.springernature.com/full/springer-static/image/art%3A10.1038%2Fs41598-025-01080-5/MediaObjects/41598_2025_1080_Fig1_HTML.png)

### 📌 Definition:

- Tries **every possible combination** of characters
    

### 🔁 Example Attempts:

```
Sxejd → hash
Sxeje → hash
Sxejf → hash
...
```

### ⚡ Characteristics:

- ✅ 100% guaranteed (given enough time)
    
- ❌ Very slow for long passwords
    

### ⏱️ Performance Insight:

- MD5 → ~5 million guesses/sec
    
- DCC2 → ~10,000 guesses/sec
    

### ⚠️ Key Takeaway:

- Short passwords (<9 chars) = vulnerable
    

---

# 📚 Dictionary Attack (Wordlist Attack)

![Image](https://us.norton.com/content/dam/blogs/images/norton/am/dictionary-attacks-explained.png)

![Image](https://repository-images.githubusercontent.com/850837348/d40efb10-ce7c-4a90-aac8-142e10cbd71e)

![Image](https://static1.squarespace.com/static/5ffe234606e5ec7bfc57a7a3/t/68df1e93a7ac865209b69033/1759452819365/Hive%2BSystems%2BPassword%2BTable%2B-%2B2025%2BRectangular.png?format=1500w)

![Image](https://sosafe-awareness.com/sosafe-files/uploads/2023/07/230713_ChatGPT_Table.png)

### 📌 Definition:

- Uses a **predefined list of common passwords**
    

### 🔑 Popular Wordlists:

- `rockyou.txt`
    
- SecLists
    

### 📌 Example:

```bash
head /usr/share/wordlists/rockyou.txt
```

```
123456
12345
password
iloveyou
princess
abc123
```

### ⚡ Why It Works:

- Humans use predictable passwords
    

### 📊 Fact:

- `rockyou.txt` contains **14+ million real leaked passwords**
    

---

# ⚖️ Attack Comparison

|Attack Type|Speed|Efficiency|Use Case|
|---|---|---|---|
|Rainbow Tables|Very Fast|High|Precomputed hashes|
|Brute Force|Very Slow|Guaranteed|Last resort|
|Dictionary Attack|Fast|Very High|Most common|

---

# 🔥 Key Takeaways

- Hashing protects passwords but **is not foolproof**
    
- **Salting is essential** for security
    
- **Dictionary attacks are most practical**
    
- **Brute-force = fallback method**
    
- Weak passwords are the **biggest vulnerability**
    

---
