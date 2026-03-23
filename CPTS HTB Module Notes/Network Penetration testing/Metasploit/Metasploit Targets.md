# 🎯 What are Targets in Metasploit?

![Image](https://www.varonis.com/hubfs/Imported_Blog_Media/metasploit-guide-set-up.png?hsLang=en)

![Image](https://www.offsec.com/_astro/msfconsolehelp-2_2mkfJx.webp)

![Image](https://miro.medium.com/1%2AsrairTVcbwgy9pvT9zq7rg.jpeg)

![Image](https://onlinelibrary.wiley.com/cms/asset/c0dff879-058d-455c-a936-1f58fb768c4f/sec1251987-fig-0002-m.jpg)

**Targets** in Metasploit are **specific operating system versions/configurations** that an exploit is designed to work against.

They define:

- OS version (Windows XP, 7, etc.)
    
- Service Pack (SP1, SP3, etc.)
    
- Application version (IE7, IE8, etc.)
    
- Architecture (x86, x64)
    

👉 In simple terms:

> A **target ensures the exploit runs correctly on a specific system version**.

---

# ⚠️ Why Targets Matter

Not all exploits work universally.

Different systems have:

- Different memory layouts
    
- Different return addresses
    
- Different protections
    

If the wrong target is selected:

❌ Exploit may fail  
❌ System may crash  
❌ No session will be created

---

# 🧾 Viewing Targets

## ❌ Without selecting a module

```bash
msf6 > show targets
```

Output:

```text
[-] No exploit module selected.
```

👉 You **must select an exploit module first**.

---

## ✅ After selecting a module

```bash
msf6 exploit(windows/smb/ms17_010_psexec) > options
```

You will see:

```text
Exploit target:

Id  Name
--  ----
0   Automatic
```

This means:

- Only one default target exists
    
- Metasploit will automatically detect the system
    

---

# 🔍 Example: Internet Explorer Exploit

Let’s analyze a more complex exploit:

```bash
use exploit/windows/browser/ie_execcommand_uaf
info
```

---

## 📖 Module Information

```text
Name: MS12-063 Microsoft Internet Explorer execCommand Use-After-Free Vulnerability
Platform: Windows
Rank: Good
Disclosed: 2012-09-14
```

👉 This exploit targets a **Use-After-Free vulnerability in Internet Explorer**.

---

# 📋 Viewing Available Targets

```bash
show targets
```

Output:

```text
Id  Name
--  ----
0   Automatic
1   IE 7 on Windows XP SP3
2   IE 8 on Windows XP SP3
3   IE 7 on Windows Vista
4   IE 8 on Windows Vista
5   IE 8 on Windows 7
6   IE 9 on Windows 7
```

---

# 🎯 Target Selection

## Automatic Target

```bash
set target 0
```

✔ Metasploit automatically detects:

- OS version
    
- Browser version
    
- Environment
    

---

## Manual Target Selection

If you already know the system details:

```bash
set target 6
```

Output:

```text
target => 6
```

👉 This selects:

- **IE 9 on Windows 7**
    

---

# ⚙️ How Targets Work Internally

Targets rely heavily on **memory addresses and exploit structure**.

Each target may require:

- Different return addresses
    
- Different payload offsets
    
- Different exploit chains
    

---

# 🧠 Return Addresses Explained

![Image](https://miro.medium.com/1%2AsrairTVcbwgy9pvT9zq7rg.jpeg)

![Image](https://www.researchgate.net/publication/361481656/figure/fig4/AS%3A1170058424401969%401655975075867/Stack-frame-layout-of-ret-to-libc_Q320.jpg)

![Image](https://upload.wikimedia.org/wikipedia/commons/thumb/4/4f/Stack_Overflow_2.png/250px-Stack_Overflow_2.png)

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/67b43310ef6bef8402765c28_60618356ed0c90a97885a568_Stack%2520Overflow%2520Attack.jpeg)

The **return address** is critical in exploitation.

It determines **where execution jumps after overflow**.

Common techniques:

- `jmp esp` → Jump to stack pointer
    
- `pop/pop/ret` → Bypass protections
    
- Direct register jumps
    

---

## ⚠️ Why Return Address Changes

Return addresses differ due to:

- OS version
    
- Service pack
    
- Installed patches
    
- Language version
    
- Memory randomization (ASLR)
    

👉 Even small changes can break an exploit.

---

# 🔍 Target Identification Process

To correctly identify a target:

### 1️⃣ Obtain Target Binaries

- Extract executable files
    
- Analyze program structure
    

---

### 2️⃣ Use Tools (e.g., msfpescan)

- Locate valid return addresses
    
- Identify memory offsets
    

---

### 3️⃣ Analyze Exploit Code

- Check comments in module
    
- Understand target dependencies
    

---

# 🧩 Target Types Variations

Targets may differ based on:

|Factor|Example|
|---|---|
|OS Version|Windows XP vs Windows 7|
|Service Pack|SP1 vs SP3|
|Application Version|IE7 vs IE9|
|Architecture|x86 vs x64|
|Language|English vs Japanese|

---

# ⚡ Practical Workflow

```text
Select Module → Show Targets → Identify Target → Set Target → Run Exploit
```

---

# 💻 Example Workflow

```bash
use exploit/windows/browser/ie_execcommand_uaf
show targets
set target 6
options
run
```

---

# 📌 Key Takeaways

✔ Targets define **which system the exploit works on**  
✔ Always use `show targets` after selecting a module  
✔ Use `set target <id>` for manual selection  
✔ Automatic mode works, but manual selection is more precise  
✔ Return addresses are critical for exploit success

---

# 💡 Pro Tip for Pentesters

> The more accurate your **target identification**, the higher your success rate.

Blind exploitation = ❌  
Precise targeting = ✅

---

# 🔥 Final Insight

Metasploit simplifies exploitation, but:

- Real success depends on **understanding the target system**
    
- You must combine:
    
    - Enumeration
        
    - Version detection
        
    - Manual analysis
        

---
