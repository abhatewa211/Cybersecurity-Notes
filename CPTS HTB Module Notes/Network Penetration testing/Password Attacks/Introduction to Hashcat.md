![Image](https://hashcat.net/hashcat/hashcat700.png)

![Image](https://www.infosecinstitute.com/globalassets/wpcontentmedia/122120-2.webp)

![Image](https://liora.io/app/uploads/sites/9/2026/02/hashcat-interface-software-security.jpg)

![Image](https://www.oreilly.com/api/v2/epubs/urn%3Aorm%3Abook%3A9781788623377/files/assets/827d5248-8803-4843-8424-3d1b7edbb124.png)

### 📌 Definition

- **Hashcat** is a powerful **password cracking tool**
    
- Works on:
    
    - Linux
        
    - Windows
        
    - macOS
        

### 📅 Background

- Proprietary (2009–2015) → Now **open-source**
    

### 🚀 Key Feature

- **GPU acceleration** → Extremely fast cracking
    

### 🔑 Capabilities

- Supports:
    
    - Multiple hash types
        
    - Multiple attack modes
        
- Similar to John the Ripper but **faster with GPU**
    

📌 Used widely in penetration testing

---

# 🧾 Basic Syntax

```bash
hashcat -a 0 -m 0 <hashes> [wordlist, rule, mask, ...]
```

### 📌 Parameters:

- `-a` → Attack mode
    
- `-m` → Hash type
    
- `<hashes>` → Hash or file of hashes
    
- `[wordlist/rule/mask]` → Depends on attack
    

---

# 🔢 Hash Types in Hashcat

![Image](https://i.imgur.com/X5SuTOW.jpg)

![Image](https://miro.medium.com/0%2AbnajEH3psosqHtH3.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1296/1%2A2JMqVHb9UdtLq0jiFKl5OA.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2Aq5wXN--iEO48MWrYnZPjtw.png)

### 📌 Important Hash IDs:

|ID|Algorithm|
|---|---|
|0|MD5|
|100|SHA1|
|1400|SHA256|
|1700|SHA512|

---

### 📌 Get Full List:

```bash
hashcat --help
```

---

### 🔍 Identify Hash Type:

```bash
hashid -m <hash>
```

Example:

```bash
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'
```

Output:

- MD5 Crypt → Mode 500
    

📌 Hashcat supports **hundreds of hash types**

---

# 🔓 Attack Modes in Hashcat

---

## 1️⃣ Dictionary Attack (-a 0)

![Image](https://www.infosecinstitute.com/globalassets/wpcontentmedia/122120-2.webp)

![Image](https://repository-images.githubusercontent.com/850837348/d40efb10-ce7c-4a90-aac8-142e10cbd71e)

![Image](https://divisions-prod-assets.resources.caltech.edu/imss/images/2023_Password_Table_Square.original.jpg)

![Image](https://assets.esecurityplanet.com/uploads/2019/10/John-The-Ripper.png)

### 📌 Definition

- Uses a **wordlist of passwords**
    

---

### 📌 Example Command

```bash
hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt
```

---

### ⚡ Result

- Hash cracked successfully
    

---

### 🔧 Rules Enhancement

```bash
hashcat -a 0 -m 0 <hash> rockyou.txt -r best64.rule
```

---

### 📂 Rule Files Location:

```bash
/usr/share/hashcat/rules
```

---

### 🔑 Key Point

- Wordlist alone may fail → **Rules improve success rate**
    

---

## 2️⃣ Mask Attack (-a 3)

![Image](https://hashcat.net/misc/p009_img/plus89_mh18.png)

![Image](https://www.researchgate.net/publication/379624465/figure/fig2/AS%3A11431281234681580%401712414089963/Work-architecture-of-Brute-Force-Attack7.ppm)

![Image](https://archive.smashing.media/assets/344dbf88-fdf9-42bb-adb4-46f01eedd629/ab085c7c-8f64-4270-9151-f2d103fd0d01/typing-masked-passwords.png)

![Image](https://www.researchgate.net/publication/335641413/figure/fig1/AS%3A898484525875201%401591226812105/The-Architecture-of-the-password-management-with-ternary-APG.png)

### 📌 Definition

- Custom brute-force using **pattern (mask)**
    

---

### 📌 Built-in Charset Symbols:

|Symbol|Meaning|
|---|---|
|?l|lowercase|
|?u|uppercase|
|?d|digits|
|?s|symbols|
|?a|all|

---

### 📌 Example Mask:

- Pattern:
    
    - 1 uppercase
        
    - 4 lowercase
        
    - 1 digit
        
    - 1 symbol
        

```bash
?u?l?l?l?l?d?s
```

---

### 📌 Example Command:

```bash
hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'
```

---

### ⚡ Result

- Password cracked efficiently
    

---

### 🔑 Key Points

- Faster than full brute-force
    
- Requires **partial knowledge of password pattern**
    

---

# ⚙️ Rules in Hashcat

### 📌 Purpose

- Modify passwords dynamically
    

### 📌 Examples:

- Add numbers → `password123`
    
- Replace letters → `p@ssw0rd`
    
- Add symbols → `admin!`
    

---

### 📂 Example Rule Files:

- `best64.rule`
    
- `rockyou-30000.rule`
    
- `leetspeak.rule`
    

---

# ⚡ Summary Table

|Attack Mode|Type|Speed|Use Case|
|---|---|---|---|
|-a 0|Dictionary|Fast|Common passwords|
|-a 3|Mask (Pattern)|Medium|Known structure|

---

# 🔥 Key Takeaways

- Hashcat is **GPU-powered → extremely fast**
    
- Requires correct:
    
    - Hash type (`-m`)
        
    - Attack mode (`-a`)
        
- **Dictionary attack = most common**
    
- **Mask attack = efficient brute-force**
    
- Rules significantly **increase success rate**
    

---

# 🧠 Final Understanding

- Hashcat = **Speed + Flexibility**
    
- JtR = **Ease + versatility**
    
- Best approach:
    
    - Start with **dictionary + rules**
        
    - Move to **mask**
        
    - Use brute-force as last resort
        

---
