This section focuses on a very important Windows privilege-escalation concept:

> **Processes themselves can become a path to higher privileges.**

The two major areas here are:

1. **Network services / sockets**
    
2. **Named pipes**
    

---

# 1. 🔥 Processes Can Lead to Privilege Escalation

A process doesn't necessarily need to run directly as Administrator to be interesting.

For example:

```text
Web Server
     ↓
IIS / XAMPP
     ↓
Application/Web Shell
     ↓
Shell as web-server user
     ↓
SeImpersonatePrivilege
     ↓
Potato-style escalation
     ↓
SYSTEM
```

The source uses IIS/XAMPP as an example where gaining a shell as the web-server account can expose `SeImpersonate`, which may provide a path toward SYSTEM under suitable conditions.

### 🧠 CPTS takeaway

When you discover a process, don't ask only:

> "Is this Administrator?"

Also ask:

> **"What account is running it, what privileges does that account have, and how can I communicate with the process?"**

---

# 2. 🎟️ Windows Access Tokens

This is a **very important concept**.

Windows uses **access tokens** to describe the security context of a process or thread.

A token contains information about:

- User identity
    
- Privileges
    
- Security context
    

When a user authenticates, Windows assigns an access token. When the user interacts with a process, the token is used to determine the applicable privilege level.

![Image](https://images.openai.com/static-rsc-4/LvpwOSTLjiVCLVFda2jb4_-cMQ3uaONTXAn1965xGzWLYfA3b1lNTOBx42h0-Bh5ouixXB7U-t9D1lPA2_8s_Ydnkpy_Qa7PhdZpe4-FJEltFMNaqcZMcrGj7ApMVTMd0Q2-L3TVzk6pTUQ4LS1m3quE2BgRtinS5CD4Nr1cJRBEa38pkVYseCTQZ5ww-qvs?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Dj9mCttXWx8PpcHzQmq0RaJSiodxlERCCWskkljT3tQwf53cWIdky7pD33eUKEotx0f2xTD96-dWi0M_x3Xz-iCy6M8V-31jAcptKkCoy5rjx2v1BkZZLxCZqpX_ARwZojdDh8_IKxne__DuZ-BGDsbkSj5GN8bfVDm2bezA5pSsOKiYYS_iqr_Vfvur0VvH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2KLiYXD0fA5Cp5_bLf3jDFrHFij1rgHgau5qp238nyfQFf_AaOwbKHhVXI99AAX53RskyAbCunHapbG3-oY4kKg1N8RMJdjVWLshd9lNhZXB9HF_ok7t_J3Mb56AZnupuG_DHoYGRREJ7-Az28cuu7uZBdfFd0olygs8T2pt2wWZiKVGEuey0agStkdihKql?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZncmRrIsaBDE5GCmFr6OmSRqjV-XSg59kDNJL-2aahBnBxKMimHHbU7-vX5El7EX8BiL6ycpNtBGs01ph7_cdDLWCP-N9hRokVT1uhTp5Gv4KjBcnskArEq5w9U8WO1AB4ori59GvlWswEPVXP7Jv0T_9A-3hIJjFCCoxROku4jLF8M8kbK-4Hg8xqYFjWqJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7inNumTbt_fs2zJjm5H6uvgWZoGi6Qrt9HZbixJ2YUqjZfB1Ghkxy8pOwJq71PetbvcGbW8TpOW9Gw6Tawj4zgJDdFQ18RbZsXJ5ePG7rN5f4tbugjGtlxTRsHs6M7Biw6e3h2g6zGUw63Plab9r2gEeXatTUM6pN-eJdhl1MaQfATyN2NGYQknvIfjDcNPz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CODFt9zyAgQ3nkHb3O-j94zzBjerAMJdSzY_B8zQ31RklbhqGZWyYKHzoaB1GnnFWW39fgJcZLUv7LR-n2tDlduYN9GwiBPUXziWNAk4w9zYn3YwaOWQfK4letEaWoDPXjcS8IQ4RI79TqpVnNCGQa66dcb4GdSPPp-jvInFHgX1JIn2WaA881u8dypYMGJs?purpose=fullsize)

### Simple mental model

```text
USER
  │
  │ authentication
  ▼
ACCESS TOKEN
  │
  ├── Identity
  ├── Groups
  └── Privileges
        │
        ▼
     PROCESS
```

So when you're investigating a process, you're interested in the **security context under which that process runs**.

---

# 3. 🌐 Network Services

Processes commonly communicate through network sockets.

Examples:

```text
DNS
HTTP
SMB
FTP
WinRM
RDP
```

Use:

```cmd
netstat -ano
```

The source explains that this can reveal services listening locally or externally and potentially expose services accessible only from localhost.

---

# 4. 🔎 Reading `netstat -ano`

Example:

```text
Proto  Local Address       Foreign Address   State       PID
TCP    0.0.0.0:21          0.0.0.0:0         LISTENING   3812
TCP    0.0.0.0:80          0.0.0.0:0         LISTENING   4
TCP    0.0.0.0:445         0.0.0.0:0         LISTENING   4
TCP    0.0.0.0:5985        0.0.0.0:0         LISTENING   4
TCP    0.0.0.0:8080        0.0.0.0:0         LISTENING   5044
```

The supplied lab output also contains:

```text
127.0.0.1:14147
```

and:

```text
[::1]:14147
```

---

# 5. 🚨 The Most Important `netstat` Finding: Loopback

Pay special attention to:

```text
127.0.0.1
```

and:

```text
::1
```

These are **localhost/loopback addresses**.

The key idea from the module:

```text
External service:
0.0.0.0:PORT
       ↓
Potentially accessible from network

Local service:
127.0.0.1:PORT
       ↓
Potentially accessible only from the host
```

The source specifically tells us to look for services listening on `127.0.0.1` or `::1` but **not** on the host's normal network address or wildcard addresses.

### Why?

Developers/admins may assume:

> "It's only localhost, so it's safe."

That assumption can result in weakly protected administrative interfaces.

---

# 6. 🎯 FileZilla Example

The lab contains:

```text
127.0.0.1:14147
```

Port:

```text
14147
```

is identified in the source as the **FileZilla administrative interface**.

The module explains that connecting to this interface could potentially expose FTP passwords or allow creation of an FTP share, depending on its configuration and the privileges of the FileZilla service account.

### Enumeration chain

```text
netstat -ano
      ↓
127.0.0.1:14147
      ↓
PID 3812
      ↓
Identify process
      ↓
FileZilla
      ↓
Administrative interface
      ↓
Investigate authentication/configuration
```

This is exactly the type of **situational awareness** CPTS wants you to develop.

---

# 7. 🧩 Another Example — Splunk

The module gives **Splunk Universal Forwarder** as another example.

According to the source, an older/default configuration could allow application deployment without authentication, while the service ran as `SYSTEM`.

That combination is dangerous:

```text
Weak service interface
        +
Runs as SYSTEM
        ↓
Potential code execution
        ↓
SYSTEM privileges
```

The important lesson isn't "always exploit Splunk."

It's:

> **A locally accessible management interface + weak authentication + highly privileged service account = investigate immediately.**

---

# 8. 🐇 Erlang Port

Another example mentioned is:

```text
25672
```

Erlang applications can use this port for communication between nodes.

The source highlights the **Erlang cookie** as the secret used to join the cluster.

Potential problems include:

- Weak cookies
    
- Cookies stored insecurely
    
- Configuration files exposing the cookie
    

Examples mentioned include:

```text
RabbitMQ
SolarWinds
CouchDB
```

The source gives `rabbit` as an example of a default/weak RabbitMQ cookie.

### Mental model

```text
Erlang service
      ↓
Port 25672
      ↓
Erlang cookie
      ↓
Authentication to cluster
      ↓
Weak/exposed cookie?
      ↓
Investigate attack path
```

---

# 9. 🚰 Named Pipes

Now we move to the second major communication mechanism.

Windows processes can communicate using:

> **Named Pipes**

A named pipe can be thought of as an IPC mechanism that allows processes to communicate.

The source describes pipes as memory-based communication mechanisms and explains that Windows supports both named and anonymous pipes.

Example:

```text
\\.\pipe\ExampleNamedPipe
```

![Image](https://images.openai.com/static-rsc-4/YExkkLrlj3rWH1BaockRcR8APvwv4GwzrNZQs9xkwYPQ6lPu_VX0wY7YUUKC-9Fb0rAvUDixG1FoRmZmcUN5AeMFQFQ7tKcb8Xx4DE7sXjYjTe0e-bKxSq5TbknzONSzQfpxj1x6Xsd0Yo3YgMfQg1EyGyPUxho8EGLAcdKLPaueThfuGLuJ2gzM_WovSsRR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CMzDekQdp-bkSUv9IiaApHyJBFO8pQkdbDN43dExhe-HlJdV4i_p2nD-6RmXph21gFNOgZHqF2pO2H2BOhAfcykAuE7hVMj2ogRkchO1T7h2zIeLUFAUvnHl-BTRAGctiREXdrdJA2cNOHZbxPUd3Jfasfau8K5VAik_uYdziSt8e_sD2onHaStthi5T8B-k?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TU3J4L8QNRM70gCzGUH0AaijOZPV2HK8lkVvhkTJrsrD3IRGrqEyiyyFi4xFr0pXJP0TkJKxIdvi8RVmYv9N-lzQLeNVSmBdRZL9x9uG_eFy-zapan_kvPuUCSsO0WUh5t-K9LCpbnimHeaNBFxLSaVvNIdoF3C9ku7HfZmzsHWG4iPV80gn5jfIeqhCaHpf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Tt4UTjA5fKw-hvm-1dPQG3zrSqthj_kEgrELJoqHExkSBL5BjP4v2S7CCEjAfpslUXhkbs3D8vcfeceH1V1AP6znKmaQ_q6iMHpYCIdjVvvRnDCOSfBpDAsifaJ-0ckGnFm7meUhZc4-Cd1mdKbBSC5eN22tojD1qXyiBsj0rmBKaeFk28G5r26qTupviLDI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZgrNBX72tkuhsNGJzm-P1DC4s7kCB-DOhDC2lKxZGpZu_WMF9J6Wr7YU5UZcZdADDckRSD3uEglvxcoGCqiA5EcmTyPwi62D5z2Eo_5FFcELScbGvG041VLpQD0cJtfjOqlXbZ9CcmpTtrWdbDeLblNBRpBfigKoxSiTjmC8sZGqNi0PJOAA6UepNxVu-p6k?purpose=fullsize)

---

# 10. 🔄 Named Pipe Client/Server Model

Think of it like this:

```text
          NAMED PIPE
              │
       ┌──────┴──────┐
       │             │
    SERVER         CLIENT
       │             │
 Creates pipe    Connects pipe
       │             │
       └──────┬──────┘
              │
        Communication
```

The process creating the pipe is considered the **server**.

The process communicating with it is the **client**.

Named pipes can support:

### Half-duplex

```text
Client ─────────► Server
```

One-way communication.

### Duplex

```text
Client ◄────────► Server
```

Two-way communication.

The source explains both communication modes and notes that every active connection to a named-pipe server results in a pipe instance.

---

# 11. 🕵️ Enumerating Named Pipes

The module introduces Microsoft's **PipeList** from Sysinternals.

Command:

```cmd
pipelist.exe /accepteula
```

Example output:

```text
Pipe Name
---------
InitShutdown
lsass
ntsvcs
scerpc
epmapper
eventlog
spoolss
wkssvc
srvsvc
ROUTER
```

The goal isn't to memorize every pipe.

Instead:

> **Find unusual pipes and investigate their permissions.**

---

# 12. ⚡ PowerShell Method

You can also enumerate named pipes using:

```powershell
gci \\.\pipe\
```

`gci` is an alias for:

```powershell
Get-ChildItem
```

The source demonstrates this method for listing pipes under `\\.\pipe`.

So memorize:

```powershell
gci \\.\pipe\
```

---

# 13. 🔐 Named Pipe Permissions

Finding a pipe is only the beginning.

Next question:

> **Who can read/write to it?**

For this, the module uses:

```text
Accesschk
```

You can examine a specific pipe:

```cmd
accesschk.exe /accepteula \\.\Pipe\lsass -v
```

The source explains that Accesschk can inspect the DACL and determine who has permissions such as:

```text
READ
WRITE
MODIFY
EXECUTE
```

---

# 14. 🧪 LSASS Pipe Example

The lab checks:

```text
\\.\Pipe\lsass
```

and shows permissions including:

```text
Everyone
NT AUTHORITY\ANONYMOUS LOGON
BUILTIN\Administrators
```

with different effective rights.

The important observation from the source is that **Administrators have full access** to this pipe.

### Don't make this mistake

Seeing:

```text
Everyone
```

does **not automatically mean privilege escalation**.

You must examine:

```text
Who?
 ↓
What permissions?
 ↓
What does the pipe do?
 ↓
Which process owns it?
 ↓
What account is that process running as?
 ↓
Can the permissions be abused?
```

---

# 15. 💥 Named Pipe Privilege Escalation

The module then gives a concrete example involving:

```text
WindscribeService
```

The source demonstrates that the pipe allowed `Everyone` to have extensive access.

Enumeration command:

```cmd
accesschk.exe -accepteula -w \pipe\WindscribeService -v
```

Example:

```text
\\.\Pipe\WindscribeService

RW Everyone
    FILE_ALL_ACCESS
```

---

# 16. 🚨 Why `FILE_ALL_ACCESS` Is Interesting

`FILE_ALL_ACCESS` means the account/group has a broad set of possible access rights to that resource.

In the example:

```text
Everyone
     ↓
FILE_ALL_ACCESS
     ↓
WindscribeService pipe
     ↓
Lax permissions
     ↓
Potential privilege escalation
```

The source concludes that these lax permissions could be leveraged to escalate privileges to SYSTEM.

Again, the critical concept is **misconfigured IPC permissions**, not simply the presence of a named pipe.

---

# 🧠 The Complete Methodology

This section fits beautifully with the previous **Initial Enumeration** section.

Your workflow becomes:

```text
                 LOW PRIV SHELL
                       │
                       ▼
              Enumerate Processes
                       │
                       ▼
             tasklist /svc
                       │
              ┌────────┴────────┐
              ▼                 ▼
        Network Services     Named Pipes
              │                 │
              ▼                 ▼
        netstat -ano         pipelist
              │                 │
              ▼                 ▼
       Find interesting       Find unusual
          ports                pipes
              │                 │
              ▼                 ▼
        Identify PID       Check permissions
              │                 │
              ▼                 ▼
       Identify process      accesschk
              │                 │
              └────────┬────────┘
                       ▼
              Determine security
                  context
                       │
                       ▼
             Check privileges
                       │
                       ▼
             Find misconfiguration
                       │
                       ▼
            Potential escalation
```

---

# 🔥 CPTS: What You Should Actually Look For

When running:

```cmd
netstat -ano
```

don't blindly investigate every port.

### 🚩 High-interest findings

```text
127.0.0.1:PORT
::1:PORT
```

especially when the service isn't exposed externally.

Then:

```text
PORT
 ↓
PID
 ↓
PROCESS
 ↓
SERVICE
 ↓
SERVICE ACCOUNT
 ↓
PRIVILEGES
 ↓
CONFIGURATION
```

---

# 🚩 Named Pipe Checklist

When you enumerate pipes:

```powershell
gci \\.\pipe\
```

or:

```cmd
pipelist.exe /accepteula
```

ask:

### 1. Is the pipe unusual?

```text
Custom application?
Third-party software?
Security software?
Administrative service?
```

### 2. Who owns the process?

```text
SYSTEM?
Administrator?
Service account?
Normal user?
```

### 3. Who can access the pipe?

Use:

```cmd
accesschk.exe
```

### 4. What permissions exist?

Especially investigate:

```text
WRITE
READ/WRITE
MODIFY
FILE_ALL_ACCESS
```

### 5. Can those permissions actually affect the privileged process?

That's the key question.

---

# 📌 Commands From This Section

### Network

```cmd
netstat -ano
```

### Named pipes — PipeList

```cmd
pipelist.exe /accepteula
```

### Named pipes — PowerShell

```powershell
gci \\.\pipe\
```

### Check a specific pipe

```cmd
accesschk.exe /accepteula \\.\Pipe\lsass -v
```

### Search pipes with write access

```cmd
accesschk.exe -w \pipe\* -v
```

### Windscribe example

```cmd
accesschk.exe -accepteula -w \pipe\WindscribeService -v
```

These commands and their purpose are directly covered in the supplied material.

---

# 🎯 CPTS Exam Memory Sheet

## Network Process Enumeration

```text
netstat -ano
      ↓
Look for:
127.0.0.1
::1
      ↓
Identify PID
      ↓
Identify process
      ↓
Identify service
      ↓
Check privileges/configuration
```

## Named Pipe Enumeration

```text
pipelist.exe /accepteula
        OR
gci \\.\pipe\
        ↓
Find interesting pipe
        ↓
accesschk
        ↓
Check DACL
        ↓
Who can READ/WRITE?
        ↓
What process uses it?
        ↓
What account runs it?
        ↓
Potential escalation?
```

## ⭐ The big concept

> **A low-privileged process can sometimes interact with a more privileged process through an improperly secured communication mechanism.**

That is the connection between **processes → tokens → sockets → named pipes → privilege escalation** in this section.

### 🧠 Remember this chain:

**PROCESS → COMMUNICATION → PERMISSIONS → SECURITY CONTEXT → MISCONFIGURATION → PRIVILEGE ESCALATION**