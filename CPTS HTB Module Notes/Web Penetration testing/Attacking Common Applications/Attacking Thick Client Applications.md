This module is a **big shift from web attacks**. Instead of attacking only a web application, we're dealing with software that is **installed and executed locally**.

The main lesson is:

> **A thick client can contain secrets, communicate with backend services, and execute sensitive functionality locally—so the client itself becomes part of the attack surface.**

The attack methodology is:

```text
Thick Client
     │
     ├── Static Analysis
     │      ├── Strings
     │      ├── Decompiled source
     │      └── Hardcoded secrets
     │
     ├── Dynamic Analysis
     │      ├── Process Monitor
     │      ├── Memory
     │      └── File operations
     │
     └── Network Analysis
            ├── HTTP/HTTPS
            ├── TCP/UDP
            └── Backend services
                    │
                    ▼
             Sensitive data
                    │
                    ▼
             Lateral movement
```

---

# 1. What Is a Thick Client?

A **thick client** is an application installed locally on a computer.

Unlike a thin client, which relies heavily on a remote server and is commonly accessed through a browser, a thick client performs substantial processing locally.

The module describes thick clients as applications that:

- Run locally
    
- Can work without Internet access
    
- Use local processing power
    
- Use local memory
    
- Use local storage
    
- Are commonly found in enterprise environments
    

Examples include:

- Project management systems
    
- CRM systems
    
- Inventory management software
    
- Productivity applications
    

Common technologies include:

```text
Java
C++
.NET
Microsoft Silverlight
```

---

# 2. Thick Client vs Thin Client

Think about it like this:

### Thin client

```text
┌──────────────┐
│ User Browser │
└──────┬───────┘
       │
       │ HTTP/HTTPS
       ▼
┌──────────────┐
│ Application  │
│ Server       │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Database     │
└──────────────┘
```

Most processing happens remotely.

### Thick client

```text
┌─────────────────────┐
│ Local Application   │
│                     │
│ Processing          │
│ Storage             │
│ Business Logic      │
└──────────┬──────────┘
           │
           ▼
      Backend Server
           │
           ▼
        Database
```

A lot more functionality is present on the endpoint itself.

---

# 3. Why Thick Clients Are Interesting

The module lists several characteristics:

- **Independent software**
    
- **Can work without Internet access**
    
- **Stores data locally**
    
- **Less secure**
    
- **Consumes more resources**
    
- **More expensive**
    

From a pentester's perspective, the most interesting one is:

> **Stores data locally.**

Why?

Because local files, configuration files, memory, and binaries can potentially contain:

```text
Username
Password
API keys
Tokens
Connection strings
Server addresses
Database credentials
Application secrets
```

---

# 4. Java Security: Sandbox

The module discusses the **Java sandbox**.

The sandbox provides an isolated environment for untrusted code.

Its purpose is to prevent untrusted code from:

- Accessing unauthorized system resources
    
- Modifying protected resources
    
- Interacting with other applications without authorization
    

Other Java security mechanisms mentioned include:

```text
Java Sandbox
Java API restrictions
Code Signing
```

---

# 5. .NET Thick Clients

In .NET, the module also calls a thick client a:

```text
Rich client
Fat client
```

The key characteristic is that significant processing happens **on the client side** instead of relying entirely on the server.

This can provide:

- Better performance
    
- More features
    
- Better user experience
    

---

# 6. Examples of Thick Client Applications

The module gives examples such as:

- Web browsers
    
- Media players
    
- Chatting software
    
- Video games
    

Enterprise/custom thick clients may be distributed directly by an organization's IT department.

One major problem is deployment and maintenance:

```text
Application deployed
       ↓
Installed on 1000 PCs
       ↓
Security patch released
       ↓
Every local installation
must be updated
```

This makes patch management harder than with centralized applications.

---

# 7. Two-Tier vs Three-Tier Architecture

This is **very important**.

Thick clients can use either:

## Two-Tier

The client communicates directly with the database.

```text
┌───────────────┐
│ Thick Client  │
└───────┬───────┘
        │
        │ Direct DB connection
        ▼
┌───────────────┐
│   Database    │
└───────────────┘
```

The application and database communicate directly.

---

## Three-Tier

The thick client communicates with an application server, which then communicates with the database.

```text
┌───────────────┐
│ Thick Client  │
└───────┬───────┘
        │
        │ HTTP/HTTPS
        ▼
┌───────────────┐
│ Application   │
│ Server        │
└───────┬───────┘
        │
        ▼
┌───────────────┐
│   Database    │
└───────────────┘
```

The module considers three-tier architecture more secure because an attacker cannot communicate directly with the database through the client.

---

# 8. Thick Client Attack Surface

Thick clients can be vulnerable to many classes of attacks.

The module lists:

```text
Improper Error Handling
Hardcoded Sensitive Data
DLL Hijacking
Buffer Overflow
SQL Injection
Insecure Storage
Session Management
```

Notice something important:

### Web vulnerabilities aren't everything.

The module specifically notes that web-specific vulnerabilities such as:

```text
XSS
CSRF
Clickjacking
```

do not directly apply to thick clients in the same way.

But thick clients can still expose vulnerabilities through their local processing, storage, and server communications.

---

# 9. Thick Client Pentesting Methodology

The module breaks testing into three major areas:

```text
             Thick Client
                  │
       ┌──────────┼──────────┐
       ▼          ▼          ▼
 Information   Client      Network
 Gathering     Analysis    Analysis
       │          │          │
       ▼          ▼          ▼
 Architecture   Static     Traffic
 Technology     Dynamic    Protocols
 Entry points   Memory     Servers
```

---

# 10. Phase 1 — Information Gathering

First determine:

### Architecture

Is it:

```text
2-tier?
3-tier?
```

### Technologies

Identify:

- Programming language
    
- Frameworks
    
- Client-side technologies
    
- Server-side technologies
    

### Entry points

Find:

- User input
    
- Files
    
- Network communication
    
- Authentication mechanisms
    
- Backend services
    

The module recommends identifying how the application and infrastructure work before attacking it.

---

# 11. Information Gathering Tools

The module lists:

|Tool|Purpose|
|---|---|
|**CFF Explorer**|PE/binary inspection|
|**Detect It Easy**|Identify file/compiler/packer information|
|**Process Monitor**|Monitor filesystem/registry/process activity|
|**Strings**|Extract readable strings|

These are worth remembering.

---

# 12. Phase 2 — Client-Side Attacks

Thick clients do a lot locally.

Therefore, investigate both:

```text
Static Analysis
       +
Dynamic Analysis
```

---

# 13. Static Analysis

Static analysis means examining the application **without executing it**.

Potential targets:

```text
EXE
DLL
JAR
CLASS
WAR
.NET assemblies
Java applications
```

The module specifically notes that static analysis is necessary because credentials and other sensitive information can be stored in:

- Local files
    
- Source code
    
- Application binaries
    

---

# 14. What Are We Looking For?

During static analysis, search for:

```text
Hardcoded usernames
Hardcoded passwords
API keys
Tokens
Connection strings
Internal IP addresses
Hostnames
Database information
URLs
File paths
Commands
```

A particularly valuable finding is:

```text
Application
    ↓
Source / binary
    ↓
Hardcoded credential
    ↓
Backend service
    ↓
Authentication
```

---

# 15. Reverse Engineering Tools

The module lists:

```text
Ghidra
IDA
OllyDbg
Radare2
dnSpy
x64dbg
JADX
Frida
```

### Rough categorization

|Tool|Useful for|
|---|---|
|Ghidra|Reverse engineering|
|IDA|Disassembly/reverse engineering|
|OllyDbg|Windows debugging|
|Radare2|Reverse engineering|
|dnSpy|.NET analysis|
|x64dbg|Windows debugging|
|JADX|Java/Android decompilation|
|Frida|Dynamic instrumentation|

---

# 16. Static + Dynamic Analysis

Don't rely exclusively on static analysis.

The module specifically says:

> Thick clients can store sensitive information in memory.

Therefore:

```text
Static Analysis
     │
     ├── Binary
     ├── Source
     └── Strings
     
Dynamic Analysis
     │
     ├── Memory
     ├── Files
     ├── Registry
     └── Processes
```

---

# 17. Phase 3 — Network-Side Attacks

A thick client may communicate with:

- HTTP
    
- HTTPS
    
- TCP
    
- UDP
    

Network traffic analysis can reveal:

- How the application communicates
    
- What servers it connects to
    
- Data transmitted
    
- Authentication information
    
- API requests
    
- Protocol behavior
    

The module recommends:

```text
Wireshark
tcpdump
TCPView
Burp Suite
```

---

# 18. Phase 4 — Server-Side Attacks

Even though the application is a thick client, its backend can still be a traditional web/API/database environment.

The module says server-side attacks are similar to web application attacks, including many of the **OWASP Top Ten**.

So remember:

```text
Thick Client
     │
     ▼
Backend API
     │
     ▼
Web Application
     │
     ▼
Database
```

You potentially need to test **both sides**.

---

# 🔥 19. Hands-On Scenario — Hardcoded Credentials

This is the most important practical section.

The scenario begins after gaining access to an exposed:

```text
SMB service
```

The `NETLOGON` share contains:

```text
Restart-Oracle-Service.exe
```

The executable is downloaded and executed:

```cmd
C:\Apps>.\Restart-OracleService.exe
C:\Apps>
```

Nothing obvious happens.

This is where the methodology becomes interesting.

---

# 20. Don't Assume "Nothing Happened"

A common beginner mistake is:

```text
Run program
   ↓
No output
   ↓
"It doesn't do anything"
```

Instead:

```text
Run program
   ↓
Observe behavior
   ↓
Monitor process
   ↓
Monitor files
   ↓
Monitor registry
   ↓
Monitor network
```

The module uses:

```text
ProcMon64
```

from Sysinternals.

---

# 21. Process Monitor Discovery

ProcMon reveals that:

```text
Restart-Oracle-Service
        ↓
Creates temporary file
        ↓
C:\Users\Matt\AppData\Local\Temp
```

This is a huge clue.

The application is doing something even though it isn't showing anything to the user.

---

# 22. Capturing Temporary Files

The generated files are deleted quickly.

To preserve them, the module modifies the Temp folder permissions so the process cannot delete the files.

After running the application again, a file appears:

```text
C:\Users\cybervaca\AppData\Local\Temp\2\6F39.bat
```

There is also:

```text
6F39.tmp
```

The filename is randomized each time the service runs.

### Important concept

```text
Application
    ↓
Create temporary script
    ↓
Execute it
    ↓
Delete it
```

If you can observe the temporary artifact before deletion, you may uncover the application's hidden functionality.

---

# 23. Analyze the Batch File

The batch file contains:

```batch
@shift /0
@echo off

if %username% == matt goto correcto
if %username% == frankytech goto correcto
if %username% == ev4si0n goto correcto
goto error
```

This is extremely interesting.

The executable behaves differently depending on the current username.

Valid usernames include:

```text
matt
frankytech
ev4si0n
```

---

# 24. What Happens After Username Validation?

The batch script writes a large Base64 string into:

```text
c:\programdata\oracle.txt
```

Then creates:

```text
c:\programdata\monta.ps1
```

The PowerShell script reconstructs an executable:

```text
c:\programdata\restart-service.exe
```

Then:

```text
powershell.exe -exec bypass -file c:\programdata\monta.ps1
```

Finally, the script deletes:

```text
monta.ps1
oracle.txt
restart-service.exe
```

and executes the resulting program.

---

# 25. Understand the Obfuscation Chain

This is **very important for the exam**.

The application is effectively doing:

```text
Large Base64 data
       │
       ▼
oracle.txt
       │
       ▼
monta.ps1
       │
       ▼
Base64 decoding
       │
       ▼
restart-service.exe
       │
       ▼
Execute
       │
       ▼
Delete artifacts
```

So the original executable is hidden inside Base64 data.

---

# 26. Preventing Cleanup

The module modifies the batch script and removes the deletion commands.

Instead of:

```batch
del c:\programdata\monta.ps1
del c:\programdata\oracle.txt
del c:\programdata\restart-service.exe
```

the researcher preserves the generated files.

After execution:

```text
C:\ProgramData\

monta.ps1
oracle.txt
restart-service.exe
```

appear.

---

# 27. Analyze `monta.ps1`

The PowerShell script is:

```powershell
$salida = $null; $fichero = (Get-Content C:\ProgramData\oracle.txt) ; foreach ($linea in $fichero) {$salida += $linea }; $salida = $salida.Replace(" ",""); [System.IO.File]::WriteAllBytes("c:\programdata\restart-service.exe", [System.Convert]::FromBase64String($salida))
```

Its job is simple:

```text
Read oracle.txt
      ↓
Combine Base64 lines
      ↓
Remove spaces
      ↓
Base64 decode
      ↓
Write restart-service.exe
```

The module confirms this interpretation.

---

# 28. Resulting Files

The module shows:

```text
monta.ps1              273 bytes
oracle.txt             601066 bytes
restart-service.exe    432273 bytes
```

Now we finally have the actual executable to analyze.

---

# 29. Execute the Recovered Binary

Running:

```powershell
.\restart-service.exe
```

displays:

```text
Restart Oracle

by @HelpDesk 2010
```

At this point we know that the hidden binary is a custom application.

But we still haven't found the credentials.

---

# 30. Dynamic Analysis with ProcMon

Run the recovered executable through:

```text
ProcMon64
```

The module observes:

```text
RegQueryValue
CreateFile
```

and other registry operations.

However, ProcMon alone doesn't reveal the important secret.

So we move deeper.

---

# 31. Debugging with x64dbg

The module uses:

and configures it to break only at:

```text
Exit Breakpoint
```

Why?

Because if all breakpoints are enabled, debugging can take you through numerous DLLs loaded before the actual application code.

Disabling unnecessary breakpoints allows the researcher to focus more directly on the application.

---

# 32. Follow in Memory Map

After opening:

in x64dbg, the module uses:

This lets us inspect memory regions associated with the process.

One interesting region has:

```text
Size:       0000000000003000
Type:       MAP
Protection: -RW--
```

---

# 33. Why Memory Mapping Matters

A memory-mapped file allows an application to access file data through a memory region rather than explicitly reading/writing the entire file.

Conceptually:

```text
File
 │
 ▼
Memory Mapping
 │
 ▼
Memory region
 │
 ▼
Application reads/writes
```

The module identifies memory-mapped regions as a potential place to find:

> **Hardcoded credentials**

---

# 34. Magic Bytes — `MZ`

When inspecting the interesting memory region, the ASCII view contains:

```text
MZ
```

`MZ` is the signature/magic bytes associated with a Windows DOS/PE executable.

This is a useful reverse-engineering clue:

```text
MZ
 ↓
Likely Windows executable
 ↓
Potential PE file
```

### CPTS ⭐

Magic bytes can help identify file formats even when:

- File extension is missing
    
- Filename is misleading
    
- File is embedded inside another file
    
- Data is extracted from memory
    

---

# 35. Dump Memory to File

The module then:

```text
Memory Map
    ↓
Right click
    ↓
Dump Memory to File
    ↓
Extracted binary
```

The resulting dump can then be analyzed independently.

---

# 36. `strings`

Next:

```text
C:\TOOLS\Strings\strings64.exe .\restart-service_00000000001E0000.bin
```

The output reveals:

```text
.NETFramework,Version=v4.0,Profile=Client
FrameworkDisplayName
.NET Framework 4 Client Profile
```

This tells us the recovered executable is a **.NET application**.

---

# 37. De4Dot

Since we've identified a .NET executable, the module uses:

```text
De4Dot
```

The output:

```text
Detected Unknown Obfuscator
Cleaning ...
Renaming all obfuscated symbols
Saving ...-cleaned.bin
```

The purpose here is to make an obfuscated .NET binary easier to understand.

---

# 38. dnSpy

After cleaning the executable, the module opens it in:

```text
DnSpy
```

This allows the researcher to inspect the recovered C# source code.

The source reveals the critical fact:

> The binary is a custom-made `runas.exe` whose purpose is to restart the Oracle service using **hardcoded credentials**.

🔥 **That's the final discovery.**

---

# 39. The Entire Attack Chain

This is the most important diagram in this module:

```text
                Exposed SMB
                    │
                    ▼
             NETLOGON Share
                    │
                    ▼
       Restart-Oracle-Service.exe
                    │
                    ▼
              Execute binary
                    │
                    ▼
               No output
                    │
                    ▼
                ProcMon64
                    │
                    ▼
          Temporary file discovered
                    │
                    ▼
                  6F39.bat
                    │
                    ▼
             Observe hidden logic
                    │
                    ▼
              oracle.txt
                    │
                    ▼
               monta.ps1
                    │
                    ▼
              Base64 decode
                    │
                    ▼
          restart-service.exe
                    │
                    ▼
                x64dbg
                    │
                    ▼
             Memory Map
                    │
                    ▼
               MZ header
                    │
                    ▼
             Dump memory
                    │
                    ▼
                 strings
                    │
                    ▼
              .NET detected
                    │
                    ▼
                 De4Dot
                    │
                    ▼
                 dnSpy
                    │
                    ▼
            C# source recovered
                    │
                    ▼
          Hardcoded credentials
```

---

# 40. The Most Important Methodology Lesson

Notice that **no single tool solved the problem**.

The researcher chained multiple techniques:

```text
ProcMon
  ↓
Temporary file
  ↓
Batch analysis
  ↓
PowerShell analysis
  ↓
Base64 decoding
  ↓
x64dbg
  ↓
Memory analysis
  ↓
Strings
  ↓
De4Dot
  ↓
dnSpy
  ↓
Source code
  ↓
Credential discovery
```

That's exactly how real thick-client assessments often work.

---

# 41. Thick Client Testing Checklist

## 🔎 Information Gathering

-  Identify architecture
    
-  Two-tier or three-tier?
    
-  Identify programming language
    
-  Identify frameworks
    
-  Identify client-side technologies
    
-  Identify server-side technologies
    
-  Identify entry points
    
-  Identify user-controlled inputs
    

---

## 📁 Static Analysis

Look at:

```text
EXE
DLL
JAR
CLASS
WAR
.NET assemblies
```

Search for:

-  Hardcoded credentials
    
-  API keys
    
-  Tokens
    
-  URLs
    
-  IP addresses
    
-  Hostnames
    
-  Database strings
    
-  Connection strings
    
-  Commands
    
-  Sensitive configuration
    

Useful tools:

```text
Strings
CFF Explorer
Detect It Easy
Ghidra
IDA
dnSpy
JADX
```

---

## 🧪 Dynamic Analysis

Monitor:

-  Processes
    
-  Files
    
-  Temporary files
    
-  Registry
    
-  Memory
    
-  DLL loading
    
-  Network connections
    

Tools:

```text
ProcMon
x64dbg
OllyDbg
Frida
```

---

## 🌐 Network Analysis

Monitor:

-  HTTP
    
-  HTTPS
    
-  TCP
    
-  UDP
    
-  API requests
    
-  Authentication traffic
    
-  Backend server addresses
    
-  Sensitive information in transit
    

Tools:

```text
Wireshark
tcpdump
TCPView
Burp Suite
```

---

# 42. CPTS Exam Points ⭐⭐⭐

### ⭐ Thick client

Locally installed application performing significant client-side processing.

---

### ⭐ Two-tier

```text
Client → Database
```

Direct database communication.

---

### ⭐ Three-tier

```text
Client → Application Server → Database
```

---

### ⭐ Major thick-client vulnerabilities

```text
Improper Error Handling
Hardcoded Sensitive Data
DLL Hijacking
Buffer Overflow
SQL Injection
Insecure Storage
Session Management
```

---

### ⭐ Static Analysis

Analyze the application without executing it.

Look for:

```text
Credentials
Secrets
URLs
Logic
Configuration
```

---

### ⭐ Dynamic Analysis

Observe the application while it runs.

Look at:

```text
Memory
Files
Processes
Registry
Network
```

---

### ⭐ ProcMon

Extremely useful when:

```text
Application runs
+
No visible output
```

because it can reveal hidden file/registry/process activity.

---

### ⭐ Temporary files

Always investigate temporary files.

A program may:

```text
Create
   ↓
Execute
   ↓
Delete
```

something sensitive before you ever see it.

---

### ⭐ Base64 ≠ Encryption

In this module, the executable is stored as Base64 data.

Remember:

> **Base64 is encoding, not encryption.**

It can be decoded back into the original bytes.

---

### ⭐ `MZ`

```text
MZ
```

is a strong indicator of a Windows executable/PE file.

---

### ⭐ .NET identification

Strings revealing:

```text
.NETFramework,Version=v4.0
```

indicate a .NET application.

---

### ⭐ Reverse engineering chain

```text
Binary
 ↓
Memory
 ↓
Dump
 ↓
Strings
 ↓
De4Dot
 ↓
dnSpy
 ↓
Source code
```

---

# 🔥 Final Thick Client Cheat Sheet

```text
THICK CLIENT
─────────────
Installed locally
Client-side processing
Local storage

ARCHITECTURE
────────────
2-Tier:
Client → DB

3-Tier:
Client → App Server → DB

VULNERABILITIES
───────────────
Improper Error Handling
Hardcoded Data
DLL Hijacking
Buffer Overflow
SQLi
Insecure Storage
Session Management

INFORMATION GATHERING
──────────────────────
CFF Explorer
Detect It Easy
ProcMon
Strings

STATIC
──────
Ghidra
IDA
dnSpy
JADX

DYNAMIC
───────
ProcMon
x64dbg
OllyDbg
Frida

NETWORK
───────
Wireshark
tcpdump
TCPView
Burp Suite

IMPORTANT FINDINGS
───────────────────
Hardcoded credentials
API keys
Tokens
Connection strings
Internal hosts
Sensitive local files

HIDDEN FILES
────────────
Monitor Temp directories

MEMORY
──────
x64dbg
Memory Map
Dump Memory

FILE IDENTIFICATION
───────────────────
MZ → Windows executable

.NET
────
strings
   ↓
De4Dot
   ↓
dnSpy

GOAL
────
Understand the client
      ↓
Recover secrets
      ↓
Understand backend
      ↓
Validate access
      ↓
Potential lateral movement
```

## 🧠 Golden CPTS Mental Model

When you're given a suspicious thick-client executable, **don't just run it and stare at the screen**.

Think:

```text
          EXE
           │
           ▼
      "What is it?"
           │
      Detect It Easy
           │
           ▼
      "What does it contain?"
           │
       Strings
       Ghidra
       dnSpy
           │
           ▼
      "What does it do?"
           │
         ProcMon
         x64dbg
           │
           ▼
      "What does it touch?"
           │
     Files / Registry
     Memory / Network
           │
           ▼
      "What is hidden?"
           │
      Temp files
      Embedded data
      Base64
      Memory maps
           │
           ▼
      "What secrets?"
           │
       Credentials
       API keys
       Tokens
           │
           ▼
      "Where can they work?"
           │
      Backend / SMB /
      Database / Services
           │
           ▼
       Lateral Movement
```

The **biggest lesson from this module** is that thick-client testing is often an investigation rather than a single exploit: you follow the application's behavior through **files → processes → memory → binary formats → decompilation → source code → credentials** until the hidden attack path becomes visible.