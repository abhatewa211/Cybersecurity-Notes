![Image](https://images.openai.com/static-rsc-4/Y_t7oA3I4GMN0gttWWdGz_a0Vm2w8NTuMjdbX69Z7evrfEWeSJY_TQ-SFhkdTbEwp3Vla0uD1b3btmO-9dVMQn3VD0Ssm58iFWw1EpwLw4Xcv84qochSmfZN9rO6SfYI4KWK2u8ww0JlDqCuzbJI4Yg5i_gQrsFfIktenwpaGJoGbGhAW6AqPJrc_IhIzD81?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iPnNrfiWNBdIyEJBu8ZN-35ONbjM-_ukap6pr0Q4LgfkmhId5BACMfkhEcnVi_aCP5SldDRKL-VMwl1w2F-w00ZVeMBox9st05A1EI73ckpvPb_yL5vCT-alYr9B-o646grbqE9mVIKZSQPCUCO3JRmjtyKFljL7dca7eLae3J0wNiHvEUX-yIyBHIJ_-jRU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/i1TZrqaEdF5_87W43PTZyqX8dOqEfIrATe00sfJ0l2O-iiX7NO17vNQuCgzRWO_K9hBOEJ15nEa7nH3CfG9WYZ7Z-gUDI53G3mqlnzm6BN69EFf-7WwMkB3RDPdSHH6PlZbAVHGvgT1nymLRQxJVtKTGoyt2duTKPta4O82joy2ttgQFJqBuw31ztAd3d5Zq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ygat0DpcMoGTj3SBWR2smdW-kjDMbVVfQQNh5eDKJzdWfkbtIdeB1CWNgdI5eCZnmd0oyiVsIWwkeAvumkJMt5OgZR-dLc2CDNyXTZSDdG11lelEUiS7CYXeVqAtCOaE3OyrUOmsmkWJTDHXPoGs-MV0oIIOkHXRXqX6XcyBx2fYNNOdcXYcG08AiXVYmmf7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Je8Cxq-BbdHZlV7E5Gsy_oMtYF7jnTd3LoR1nU5jQHGEr84tO1YDNSYmUo8eDVF6cUlVreuiS5oMR21WnDmcj59Q55asR1IZsdmxTlbtqYAD6BQxuvAQ5GqmIqD2laJ4jUnN5E09fPgucWrKanR0T0h2GCLOrlmDMvEEu-JNC2yA3LlzaNinRR89AD3qoIpK?purpose=fullsize)

---

# 1. Core Concept

Imagine we discover an application:

```text
                Application
                     │
                     │ credentials
                     ▼
              ┌─────────────┐
              │   Database  │
              └─────────────┘
```

The application needs some form of:

```text
username
password
server
port
database
```

to connect.

Developers sometimes embed these details directly into:

- ELF binaries
    
- DLLs
    
- .NET assemblies
    
- Java JARs
    
- configuration files
    
- scripts
    
- source code
    

So instead of attacking the service immediately, we can investigate the **application that connects to it**.

---

# 2. Attack Philosophy

The module's central methodology is:

```text
Find application
      ↓
Identify external service
      ↓
Examine application
      ↓
Find connection string
      ↓
Recover credentials
      ↓
Test credentials against service
      ↓
Check credential reuse
      ↓
Potential lateral movement / privilege escalation
```

🔥 **Very important:**

> An application can act as a credential container for the service it communicates with.

And those credentials may sometimes work somewhere else too.

---

# 3. Scenario 1 — ELF Executable

The first example involves:

```text
octopus_checker
```

an ELF executable discovered on a remote machine.

Running it locally gives:

```bash
./octopus_checker
```

Output:

```text
Program had started..
Attempting Connection 
Connecting ... 

The driver reported the following diagnostics whilst running SQLDriverConnect

01000:1:0:[unixODBC][Driver Manager]Can't open lib 'ODBC Driver 17 for SQL Server' : file not found
connected
```

The important clue is:

```text
SQLDriverConnect
```

This strongly suggests the program is attempting to establish a database connection.

---

# 4. Why Examine the Binary?

The program probably needs a connection string similar to:

```text
DRIVER={ODBC Driver 17 for SQL Server};
SERVER=localhost,1401;
UID=username;
PWD=password;
```

If the developer embedded this information inside the executable, we may be able to recover it.

This is where **reverse engineering/debugging** becomes useful.

---

# 5. GDB / PEDA

The module uses:

**GDB — GNU Debugger**

with **PEDA (Python Exploit Development Assistance for GDB)**.

GDB allows us to:

- Run programs
    
- Pause execution
    
- Set breakpoints
    
- Inspect registers
    
- Examine memory
    
- Inspect variables
    
- Disassemble functions
    
- Follow program execution
    

The module loads the binary with:

```bash
gdb ./octopus_checker
```

---

# 6. Disassembly Flavor

Once inside GDB-PEDA:

```text
gdb-peda$ set disassembly-flavor intel
```

This selects **Intel syntax** for the assembly output.

Then:

```text
gdb-peda$ disas main
```

disassembles the `main()` function.

The output contains instructions such as:

```assembly
mov
lea
call
cmp
ret
```

and, importantly, several `call` instructions.

---

# 7. Understanding `call`

In assembly, a:

```assembly
call
```

instruction transfers execution to another function.

For example:

```assembly
call SQLDriverConnect@plt
```

means the program is calling the SQL connection function.

The module finds:

```assembly
call 0x5555555551b0 <SQLDriverConnect@plt>
```

This is a major clue.

---

# 8. SQLDriverConnect

The important function is:

```text
SQLDriverConnect
```

This is used to establish an ODBC database connection.

The module places a breakpoint on its address:

```text
gdb-peda$ b *0x5555555551b0
```

Then:

```text
gdb-peda$ run
```

When execution reaches that function, GDB pauses.

Now we can inspect the registers.

---

# 9. Register Inspection

The interesting register is:

```text
RDX
```

The module's output shows:

```text
RDX: 0x7fffffffda70
```

and, crucially:

```text
"DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost, 1401;UID=username;PWD=password;"
```

🔥 **Boom.**

The SQL connection string is visible directly in memory.

The recovered information is:

```text
Driver:
ODBC Driver 17 for SQL Server

Server:
localhost

Port:
1401

Username:
username

Password:
password
```

This is the key objective of the ELF examination.

---

# 10. Why the Register Matters

The important mental model is:

```text
Program
  │
  ▼
Builds connection string
  │
  ▼
Stores it in memory
  │
  ▼
Passes it to SQLDriverConnect
  │
  ▼
Breakpoint
  │
  ▼
Inspect registers
  │
  ▼
Recover connection string
```

You aren't necessarily searching the binary for a nice plaintext password.

Instead, you're catching the program **at the moment it uses the credential**.

---

# 11. Endianness

The module also discusses **endianness**.

Endianness determines the order in which bytes are interpreted by a system.

During static disassembly, strings may appear:

- fragmented
    
- out of order
    
- difficult to interpret
    
- affected by how values are represented in memory
    

Therefore, seeing apparently meaningless values in assembly doesn't necessarily mean the information isn't there.

A useful strategy is to follow execution until the relevant function is called and inspect memory/registers at that point.

---

# 12. Static vs Dynamic Analysis

This example demonstrates both approaches.

### Static analysis

You inspect the binary without executing it.

Examples:

```text
disassemble
strings
inspect functions
inspect references
```

### Dynamic analysis

You execute the binary under a debugger and observe it.

Examples:

```text
breakpoints
registers
memory
function arguments
```

### The powerful combination

```text
Static
  ↓
Find interesting function
  ↓
Dynamic
  ↓
Break at function
  ↓
Inspect arguments/registers
  ↓
Recover secret
```

🔥 This is an extremely useful reverse-engineering methodology.

---

# 13. Credential Reuse

Once credentials are recovered:

```text
UID=username
PWD=password
```

don't automatically assume they are only useful for the database.

The module specifically points out checking whether the password is **reused by users of the same network**.

So:

```text
Recovered credential
       │
       ├── Database
       │
       ├── SMB
       │
       ├── RDP
       │
       ├── SSH
       │
       ├── WinRM
       │
       └── Other services
```

The exact services depend on the environment.

This can turn a seemingly minor application discovery into a **lateral-movement opportunity**.

---

# 14. Scenario 2 — DLL Examination

The second example involves:

```text
MultimasterAPI.dll
```

A **DLL (Dynamically Linked Library)** contains code that other programs can load and call while running.

The module determines that this particular DLL is a:

```text
.NET assembly
```

---

# 15. Extracting Metadata

PowerShell is used:

```powershell
Get-FileMetaData .\MultimasterAPI.dll
```

The output contains clues such as:

```text
.NETFramework,Version=v4.6.1
```

and:

```text
api/getColleagues
```

as well as:

```text
http://localhost:8081
```

This already tells us a lot:

```text
.NET Framework 4.6.1
        │
        ▼
MultimasterAPI
        │
        ▼
HTTP API
        │
        ▼
localhost:8081
```

---

# 16. dnSpy

Because it's a .NET assembly, the module uses:

**dnSpy**

dnSpy allows us to:

- Decompile .NET assemblies
    
- View C# / Visual Basic source
    
- Debug assemblies
    
- Edit assemblies
    
- Inspect classes/methods
    
- Search through code
    

This is particularly powerful because instead of seeing raw machine code, we may get something very close to the application's original source code.

---

# 17. Inspecting the Controller

The module navigates to:

```text
MultimasterAPI.Controllers
        │
        ▼
ColleagueController
```

Inspection reveals a **database connection string containing a password**.

So the workflow is:

```text
DLL
 │
 ▼
Identify .NET assembly
 │
 ▼
Open in dnSpy
 │
 ▼
Navigate classes/controllers
 │
 ▼
Inspect database connection
 │
 ▼
Recover password
```

---

# 18. Why Application Components Are Valuable

Consider:

```text
                    Web Application
                          │
             ┌────────────┼────────────┐
             ▼            ▼            ▼
           API          DLL         Database
             │            │
             └──────┬─────┘
                    │
              credentials
                    │
                    ▼
              Other service
```

An application component may contain information that the service itself doesn't expose directly.

Therefore:

> **If you can't get useful information from the service, investigate the applications that communicate with it.**

---

# 19. Attack Chain

The entire module can be condensed into:

```text
       ┌─────────────────────┐
       │ Find application    │
       └──────────┬──────────┘
                  │
                  ▼
       ┌─────────────────────┐
       │ Identify connected  │
       │ service             │
       └──────────┬──────────┘
                  │
          ┌───────┴────────┐
          ▼                ▼
      ELF binary          .NET DLL
          │                │
          ▼                ▼
      GDB/PEDA           dnSpy
          │                │
          ▼                ▼
    Breakpoint/regs      Source code
          │                │
          └───────┬────────┘
                  ▼
          Connection string
                  │
                  ▼
             Credentials
                  │
          ┌───────┴────────┐
          ▼                ▼
       Database       Other services
                           │
                           ▼
                Lateral movement /
                privilege escalation
```

---

# 🧠 CPTS Exam Points

### ⭐ 1. Applications can leak credentials

Applications that connect to databases/services may contain:

```text
Connection strings
Usernames
Passwords
API endpoints
API keys
Service credentials
```

---

### ⭐ 2. ELF examination

For Linux ELF binaries:

```text
GDB / PEDA
```

can be used for debugging and dynamic examination.

---

### ⭐ 3. `disas main`

```text
disas main
```

disassembles the `main()` function.

---

### ⭐ 4. `SQLDriverConnect`

Seeing:

```text
SQLDriverConnect
```

is an important clue that the program is using an ODBC connection.

---

### ⭐ 5. Breakpoints

Example:

```text
b *0x5555555551b0
```

allows execution to be paused at a specific address.

Then:

```text
run
```

starts execution.

---

### ⭐ 6. Registers can contain function arguments

At the breakpoint, inspecting registers can reveal sensitive data being passed to a function.

In the module:

```text
RDX
```

contains the SQL connection string.

---

### ⭐ 7. .NET DLL

A `.NET` DLL can often be decompiled into understandable source code.

Useful tool:

```text
dnSpy
```

---

### ⭐ 8. Credential reuse

Recovered credentials should be assessed for reuse against other services **within the authorized scope**.

---

# 🔎 Pentesting Checklist

## Application discovery

-  Identify binaries/application components
    
-  Determine file type
    
-  Identify programming language/framework
    
-  Determine what external services they communicate with
    

## ELF

-  Run the binary safely
    
-  Observe connection/error messages
    
-  Load into GDB
    
-  Set appropriate disassembly syntax
    
-  Disassemble interesting functions
    
-  Search for service-related functions
    
-  Identify connection functions
    
-  Set breakpoints
    
-  Inspect registers/memory
    
-  Recover connection strings
    

## .NET

-  Determine whether DLL is a .NET assembly
    
-  Open in dnSpy
    
-  Inspect namespaces/classes/controllers
    
-  Search for connection strings
    
-  Search for database/API credentials
    
-  Identify connected services
    

## Credentials

-  Test against the intended service
    
-  Check authorized credential reuse
    
-  Look for lateral movement opportunities
    
-  Document where credentials were discovered
    
-  Avoid unnecessary credential exposure in reports
    

---

# ⚡ Quick Revision Cheat Sheet

```text
APPLICATION → SERVICE
       │
       ▼
Application may contain
connection strings
       │
       ├── ELF
       │    └── GDB / PEDA
       │          ├── disas main
       │          ├── find interesting calls
       │          ├── breakpoint
       │          └── inspect registers/memory
       │
       └── .NET DLL
            └── dnSpy
                  ├── decompile
                  ├── inspect classes
                  └── find connection strings
       
       ↓
   Credentials
       ↓
   Connected service
       ↓
Credential reuse
       ↓
Lateral movement /
Privilege escalation
```

## 🔥 Golden Mental Model

> **Don't only enumerate the service — enumerate the applications that connect to the service.**

If you find:

```text
Application → Database
```

the application itself may be the easiest place to find:

```text
SERVER
PORT
USERNAME
PASSWORD
```

And the really important CPTS mindset is:

**Service → Application → Credentials → Other Services → Lateral Movement.**