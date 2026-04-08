![Image](https://identitymanagementinstitute.org/app/uploads/2025/03/Psychology-of-Cybersecurity-.png)

![Image](https://ui-patterns.com/uploads/image/file/808/best_old_40.jpg)

![Image](https://www.security.org/app/uploads/2021/09/Asset_1.png)

![Image](https://sb.nordcdn.com/m/4ad1d25794bc5b2d/original/females-password-habits-usa-750x526.svg)

---

## 📌 Understanding Human Password Behavior

- Users prioritize **simplicity over security**
    
- Even with password policies, users follow **predictable patterns**
    

### 🔐 Common Password Policy Requirements:

- Minimum length (usually **8+ characters**)
    
- Must include:
    
    - Uppercase letters
        
    - Numbers
        
    - Special characters
        

---

### ⚠️ Reality:

- Users still create **weak passwords**
    
- They use:
    
    - Company names
        
    - Personal info (pets, hobbies, etc.)
        
    - Predictable formats
        

📌 OSINT (Open Source Intelligence) can help gather such data

---

## 🔑 Common Password Patterns

![Image](https://img2.helpnetsecurity.com/posts2022/nordpass-29112022.jpg)

![Image](https://images.squarespace-cdn.com/content/v1/5ffe234606e5ec7bfc57a7a3/1719499399309-7FRIR5QNH5P4VHC1AGGP/Hive%2BSystems%2BPassword%2BTable%2B-%2B2024%2BRectangular.png)

|Description|Example|
|---|---|
|First letter uppercase|Password|
|Add numbers|Password123|
|Add year|Password2022|
|Add month|Password02|
|Add symbol|Password2022!|
|Leetspeak|P@ssw0rd2022!|

---

### 📌 Key Insight:

- Most passwords are **≤ 10 characters**
    
- Users make **small predictable changes**
    
    - Change year
        
    - Change month
        
    - Add symbol
        

---

# ⚙️ Creating Custom Rules (Hashcat)

![Image](https://www.infosecinstitute.com/globalassets/wpcontentmedia/122120-2.webp)

![Image](https://www.researchgate.net/profile/Zhiyu-Wang-10/publication/364771564/figure/fig2/AS%3A11431281167371757%401686636497009/Demonstration-of-a-password-mangling-rule-automatic-generator-based-on-clustering_Q320.jpg)

![Image](https://cdn.prod.website-files.com/633d92770fc68507890ca62d/65bbd4dedd3af6b7142c3fda_lhvPdfc3vkdfJFFp0OmSOuVJgoMZBWKxAtUSNi_Zwu-8-EFS-1TQTFdxA_hZ71BUnh_Tu4M0dES41pk_Acdn0SLY2Isfu9txrpqPBlOWoI-6tCJDE8oyLZsmWz68cm1QPBcg6VXcGTL9Yu53BgUkkhw.png)

![Image](https://datadog-docs.imgix.net/images/security/cspm/custom_rules/custom_rules_second_half.59cce2fead94f048a913bcc1d911fae3.png?auto=format&fit=max)

---

## 📌 Rule Functions

|Function|Description|
|---|---|
|`:`|Do nothing|
|`l`|Lowercase|
|`u`|Uppercase|
|`c`|Capitalize first letter|
|`sXY`|Replace X with Y|
|`$!`|Add `!` at end|

---

## 📌 Example Rule File

```bash
cat custom.rule
```

```text
:
c
so0
c so0
sa@
c sa@
c sa@ so0
$!
$! c
$! so0
$! sa@
$! c so0
$! c sa@
$! so0 sa@
$! c so0 sa@
```

---

## 📌 Apply Rules to Wordlist

```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

---

## 📌 Input Wordlist

```text
password
```

---

## 📌 Generated Output (15 Variants)

```text
password
Password
passw0rd
Passw0rd
p@ssword
P@ssword
P@ssw0rd
password!
Password!
passw0rd!
p@ssword!
Passw0rd!
P@ssword!
p@ssw0rd!
P@ssw0rd!
```

---

### 🔑 Key Point:

- Small input → Many possible passwords
    
- Rules **multiply attack efficiency**
    

📌 Hashcat & JtR both support rule-based mutations

---

# 📚 Pre-built Rule Sets

### 📌 Popular Rule:

- `best64.rule`
    

### ⚙️ What it does:

- Applies:
    
    - Number additions
        
    - Case changes
        
    - Symbol insertion
        

---

### 🔑 Key Point:

- Pre-built rules are **very effective in real attacks**
    

---

# 🎯 Targeted Wordlist Creation

![Image](https://blog.passwork.club/content/images/2026/03/dictionary_attack_diagram.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A2000/1%2AYY_2Ec0SwV823z8-tKDM1A.png)

![Image](https://www.mdpi.com/applsci/applsci-10-07306/article_deploy/html/images/applsci-10-07306-g001.png)

![Image](https://www.mdpi.com/entropy/entropy-25-01303/article_deploy/html/images/entropy-25-01303-g001.png)

---

## 📌 Strategy

Use **context-based guessing**:

### 🧠 Consider:

- Company name
    
- Industry
    
- Location
    
- Employee interests
    
- Dates (year/month)
    

---

### 📌 Example:

- Company: Inlanefreight
    
- Possible passwords:
    
    - Inlane2024!
        
    - Freight123
        
    - Inlane@01
        

---

### ⚠️ Important:

- Password cracking = **educated guessing**
    
- Better info = higher success rate
    

---

# 🌐 Generating Wordlists with CeWL

![Image](https://media.licdn.com/dms/image/v2/D4E22AQHyvlCbZ5E9uQ/feedshare-shrink_2048_1536/B4EZerQxDyGwAo-/0/1750924990158?e=2147483647&t=z8Ul1B0B5soHz3FWl26uUjXtqKIqnqs-9F33QNqeBsI&v=beta)

![Image](https://repository-images.githubusercontent.com/850837348/d40efb10-ce7c-4a90-aac8-142e10cbd71e)

![Image](https://www.oreilly.com/api/v2/epubs/urn%3Aorm%3Abook%3A9781784392918/files/graphics/B04027_Ch02_22.jpg)

![Image](https://www.oreilly.com/api/v2/epubs/urn%3Aorm%3Abook%3A9781787121829/files/assets/28ca2f77-8349-4e38-b55b-0abbdd363864.png)

---

## 📌 What is CeWL?

- Tool to **extract words from websites**
    
- Useful for **custom wordlists**
    

---

## 📌 Command Example

```bash
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
```

---

### 📌 Parameters:

- `-d 4` → Depth level
    
- `-m 6` → Minimum word length
    
- `--lowercase` → Convert to lowercase
    
- `-w` → Output file
    

---

## 📌 Count Words

```bash
wc -l inlane.wordlist
```

Output:

```
326
```

---

### 🔑 Key Point:

- Website → Relevant words → Better guesses
    

📌 Combines OSINT + password cracking

---

# ⚡ Summary

|Concept|Purpose|
|---|---|
|Rules|Modify passwords|
|Wordlists|Base guesses|
|OSINT|Gather user data|
|CeWL|Generate custom lists|

---

# 🔥 Key Takeaways

- Users create **predictable passwords**
    
- Rules help **simulate human behavior**
    
- Custom wordlists = **higher success rate**
    
- OSINT is **very powerful in cracking**
    
- CeWL helps automate **targeted wordlist creation**
    

---

# 🧠 Final Insight

- Password cracking is not random  
    ➡️ It is **pattern-based + intelligence-driven**
    

---
