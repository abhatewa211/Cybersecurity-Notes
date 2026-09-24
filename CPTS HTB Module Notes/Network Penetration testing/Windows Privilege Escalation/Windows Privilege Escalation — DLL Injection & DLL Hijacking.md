This section is important for CPTS because it introduces several related concepts that are easy to mix up:

- **DLL Injection**
    
- **LoadLibrary injection**
    
- **Manual Mapping**
    
- **Reflective DLL Injection**
    
- **DLL Hijacking**
    
- **DLL Proxying**
    
- **Missing/Invalid DLL Hijacking**
    

The biggest distinction to remember is:

> **DLL Injection targets an already-running process, while DLL Hijacking abuses how an application searches for and loads DLLs.**

---

# 1. What Is DLL Injection?

A **DLL (Dynamic Link Library)** contains code that can be loaded into a process.

DLL injection means inserting a DLL/code into another **running process** so that the injected code executes within that process's context.

Conceptually:

```text
Your process
     │
     │ inject DLL
     ▼
┌──────────────────────┐
│ Target Process       │
│                      │
│ Existing code        │
│ Existing DLLs        │
│                      │
│ + Injected DLL       │
└──────────────────────┘
          │
          ▼
   Injected code executes
   in target context
```

This can provide access to:

- The target process's memory
    
- Its resources
    
- Its execution context
    

---

# 2. Legitimate Uses

DLL injection isn't inherently malicious.

The source gives **hot patching** as a legitimate use case.

Hot patching allows software to modify/update code without immediately restarting the running process.

So the technique itself isn't automatically malicious.

The security problem occurs when an attacker uses it to insert malicious code into a trusted process.

This can also make detection harder because the malicious code is executing inside a legitimate process.

---

# 3. LoadLibrary Injection

`LoadLibrary` is one of the most common DLL injection techniques.

Windows provides the:

```text
LoadLibrary
```

API for loading a DLL into a process's memory.

It returns a handle that can be used to locate functions inside the loaded DLL.

### Normal use

The source's first C example simply does:

```c
HMODULE hModule = LoadLibrary("example.dll");
```

This loads:

```text
example.dll
```

into the **current process**.

---

# 4. LoadLibrary-Based Remote DLL Injection

The interesting part is when we make another process load our DLL.

The source demonstrates the classic sequence:

```text
1. Open target process
2. Allocate memory inside target
3. Write DLL path into target memory
4. Find LoadLibraryA address
5. Create remote thread
6. Remote thread executes LoadLibraryA
7. DLL gets loaded
```

This is the core mechanism.

---

## Step 1 — Open Target Process

```c
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,
    FALSE,
    targetProcessId
);
```

You need a handle to the target process.

Conceptually:

```text
PID
 ↓
OpenProcess()
 ↓
Process Handle
```

---

## Step 2 — Allocate Memory

```c
VirtualAllocEx(...)
```

allocates memory **inside the target process**.

The purpose here is to create a location where we can place the DLL path.

```text
Target Process Memory

┌──────────────────────┐
│ Existing memory      │
│                      │
│ Existing DLLs        │
│                      │
│ [DLL path] ◄─────────┤
└──────────────────────┘
```

---

## Step 3 — Write DLL Path

```c
WriteProcessMemory(...)
```

writes the DLL path into the memory allocated in the target process.

For example, conceptually:

```text
C:\Tools\payload.dll
```

---

## Step 4 — Find LoadLibraryA

```c
GetProcAddress(
    GetModuleHandle("kernel32.dll"),
    "LoadLibraryA"
);
```

The injector obtains the address of:

```text
LoadLibraryA
```

from `kernel32.dll`.

---

## Step 5 — Create Remote Thread

```c
CreateRemoteThread(...)
```

creates a thread inside the target process.

The thread begins execution at:

```text
LoadLibraryA
```

and receives the DLL path as its argument.

### Complete LoadLibrary injection

```text
Attacker / Injector
       │
       ▼
OpenProcess()
       │
       ▼
VirtualAllocEx()
       │
       ▼
WriteProcessMemory()
       │
       ▼
GetProcAddress(LoadLibraryA)
       │
       ▼
CreateRemoteThread()
       │
       ▼
LoadLibraryA("payload.dll")
       │
       ▼
DLL loaded into target
```

### ⭐ CPTS must remember

The three APIs that should immediately come to mind are:

```text
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
```

with:

```text
LoadLibraryA
```

as the function used by the remote thread.

---

# 5. Manual Mapping

**Manual Mapping** is a more advanced DLL injection technique.

Instead of simply calling:

```text
LoadLibrary()
```

the injector manually loads the DLL into the target process's memory.

The source describes it as:

> manually loading a DLL into process memory while resolving imports and relocations.

### High-level process

```text
1. Load DLL as raw data
        ↓
2. Map DLL sections
        ↓
3. Inject shellcode
        ↓
4. Relocate DLL
        ↓
5. Resolve imports
        ↓
6. Execute TLS callbacks
        ↓
7. Call DLL entry point
```

The source specifically notes that Manual Mapping avoids direct use of `LoadLibrary`, which can make detection more difficult for security/anti-cheat systems.

### Key distinction

```text
LoadLibrary Injection
        ↓
Windows loader does much of the work

Manual Mapping
        ↓
Injector manually performs loader work
```

---

# 6. Reflective DLL Injection

Reflective DLL Injection takes the concept further.

The DLL itself contains the logic required to load itself into memory.

The source describes it as a technique where a library loads itself from memory using a minimal PE loader.

The central component is:

```text
ReflectiveLoader
```

---

# 7. Reflective DLL Injection Flow

The source gives a detailed sequence.

### 1. Transfer execution

Execution reaches:

```text
ReflectiveLoader
```

This can happen through:

```text
CreateRemoteThread()
```

or bootstrap shellcode.

### 2. Locate itself

The loader determines where its own image currently resides in memory.

### 3. Find required functions

It locates:

```text
LoadLibraryA
GetProcAddress
VirtualAlloc
```

through the `kernel32.dll` export table.

### 4. Allocate memory

A new memory region is allocated for the DLL.

### 5. Copy headers/sections

The DLL's:

```text
headers
+
sections
```

are loaded into their new locations.

### 6. Resolve imports

Imported libraries and functions are loaded/resolved.

### 7. Process relocations

The relocation table is processed.

### 8. Execute DllMain

The loader calls:

```text
DllMain
```

with:

```text
DLL_PROCESS_ATTACH
```

At this point the DLL has been loaded.

---

# 8. LoadLibrary vs Manual Mapping vs Reflective

|Technique|Main idea|
|---|---|
|**LoadLibrary injection**|Make target process call `LoadLibrary`|
|**Manual Mapping**|Manually map PE/DLL into memory|
|**Reflective DLL Injection**|DLL contains its own loader|

### Mental model

```text
LoadLibrary
    │
    ▼
Windows loader
    │
    ▼
DLL

Manual Mapping
    │
    ▼
Custom injector
    │
    ├── map sections
    ├── imports
    └── relocations
          │
          ▼
         DLL

Reflective
    │
    ▼
ReflectiveLoader inside DLL
    │
    ├── locate itself
    ├── resolve APIs
    ├── allocate
    ├── map
    ├── imports
    └── relocations
          │
          ▼
         DLL
```

---

# 9. DLL Hijacking

Now we move to a **different concept**.

DLL Injection:

> Put a DLL into a running process.

DLL Hijacking:

> Abuse the way an application searches for DLLs.

The source defines DLL Hijacking as taking advantage of Windows' DLL loading/search process when an application doesn't specify the full path to the required DLL.

This distinction is **very important for CPTS**.

---

# 10. DLL Hijacking Mental Model

Suppose an application does:

```text
LoadLibrary("x.dll")
```

instead of:

```text
LoadLibrary("C:\Windows\System32\x.dll")
```

Windows needs to figure out:

> Where is `x.dll`?

It searches through a defined order.

If an attacker can place a malicious DLL in a location searched **before the legitimate DLL**, the application may load the attacker's DLL.

```text
Application
    │
    ▼
Needs x.dll
    │
    ▼
Windows DLL search
    │
    ├── Location 1 → x.dll exists! ← malicious
    │
    ├── Location 2
    └── Location 3
```

---

# 11. Safe DLL Search Mode

The source explains that Windows has:

```text
SafeDllSearchMode
```

and that the default behavior affects the ordering of locations searched for DLLs.

Registry location:

```text
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager
```

Value:

```text
SafeDllSearchMode
```

The source states:

```text
1 = enabled
0 = disabled
```

and a reboot is required for changes to take effect.

---

# 12. DLL Search Order

With Safe DLL Search Mode enabled, the source lists:

```text
1. Application directory
2. System directory
3. 16-bit system directory
4. Windows directory
5. Current directory
6. PATH directories
```

Without Safe DLL Search Mode:

```text
1. Application directory
2. Current directory
3. System directory
4. 16-bit system directory
5. Windows directory
6. PATH directories
```

### CPTS point

You don't need to blindly memorize the order yet.

The important principle is:

> **The application may search multiple locations for a DLL, and if an attacker controls an earlier searched location, DLL hijacking may be possible.**

---

# 13. Finding DLL Hijacking Opportunities

You first need to determine:

```text
Which DLL does the application attempt to load?
```

The source mentions two useful tools.

### Process Explorer

Microsoft Sysinternals tool that allows you to inspect running processes and their loaded DLLs.

### PE Explorer

Can examine PE files such as:

```text
.exe
.dll
```

and reveal imported DLLs.

---

# 14. Process Monitor — VERY IMPORTANT

For practical DLL hijacking enumeration, **Procmon** is extremely useful.

The source uses Process Monitor to watch:

```text
main.exe
```

and identify DLL loading activity.

The filter is configured around:

```text
Process Name = main.exe
Operation = Load Image
```

Procmon only captures activity while it is running, so if the process was already started, you may need to restart it while Procmon is capturing.

---

# 15. `Load Image` Events

Filtering on:

```text
Operation = Load Image
```

shows libraries loaded by the process.

Example:

```text
main.exe
    ↓
ntdll.dll
    ↓
wow64.dll
    ↓
kernel32.dll
    ↓
...
    ↓
library.dll
```

The source shows:

```text
C:\Users\PandaSt0rm\Desktop\Hijack\library.dll
```

being successfully loaded.

### CPTS methodology

When analyzing a suspicious application:

```text
Start Procmon
      ↓
Launch target application
      ↓
Filter Process Name
      ↓
Filter Load Image
      ↓
Identify DLLs
      ↓
Investigate search paths
```

---

# 16. DLL Proxying

**DLL Proxying** is another DLL hijacking technique.

Instead of completely replacing the original functionality, we create a DLL that:

1. Gets loaded instead of the original DLL.
    
2. Loads the original DLL.
    
3. Gets the original function.
    
4. Performs our modification.
    
5. Returns the modified result.
    

The source demonstrates this by modifying an `Add()` function.

---

# 17. DLL Proxying Example

Original application expects:

```text
library.dll
```

with:

```text
Add(a, b)
```

Normally:

```text
1 + 1 = 2
```

The proxy DLL instead does:

```text
main.exe
   │
   ▼
library.dll  ← attacker-controlled proxy
   │
   ▼
library.o.dll ← original library
   │
   ▼
Add(1,1)
   │
   ▼
2
   │
   ▼
+1
   │
   ▼
3
```

The source's proxy function loads:

```c
LoadLibraryA("library.o.dll");
```

then finds:

```c
GetProcAddress(originalLibrary, "Add");
```

calls the original function, modifies the result, and returns it.

The demonstration therefore changes:

```text
1 + 1 = 2
```

into:

```text
1 + 1 = 3
```

showing that the application is executing code from the hijacked DLL.

---

# 18. Why Proxying Is Useful

If you simply replace:

```text
library.dll
```

with a malicious DLL, the application may crash because it expects functions from the original library.

Proxying can preserve the expected functionality:

```text
Application
     │
     ▼
Proxy DLL
     │
     ├── malicious/modified behavior
     │
     ▼
Original DLL
     │
     ▼
Expected functionality
```

This can make the hijack less disruptive.

---

# 19. Invalid / Missing DLL Hijacking

Another situation is even simpler.

Suppose the application tries:

```text
LoadLibrary("x.dll")
```

but:

```text
x.dll
```

doesn't exist.

Procmon may show:

```text
NAME NOT FOUND
```

The source demonstrates finding this by filtering for DLL paths with:

```text
NAME NOT FOUND
```

and identifies:

```text
C:\Users\PandaSt0rm\Desktop\Hijack\x.dll
```

as a missing DLL.

If the application searches a location you can control, placing a DLL there may cause the application to load your DLL.

---

# 20. `DllMain`

The example malicious/test DLL contains:

```c
BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved
)
```

`DllMain` is the DLL entry point.

The source demonstrates:

```c
case DLL_PROCESS_ATTACH:
    printf("Hijacked... Oops...\n");
    break;
```

When Windows loads the DLL into the process, `DllMain` is invoked with:

```text
DLL_PROCESS_ATTACH
```

The demonstration simply prints:

```text
Hijacked... Oops...
```

to prove the DLL was loaded.

---

# 21. DLL Injection vs DLL Hijacking

🔥 **This comparison is CPTS-important.**

||DLL Injection|DLL Hijacking|
|---|---|---|
|Target|Running process|Application loading DLL|
|Main idea|Insert DLL into process|Trick application into loading DLL|
|Requires running target?|Usually yes|Application must execute/load DLL|
|Typical mechanism|Remote memory/thread|DLL search order|
|Important API|`LoadLibrary`|DLL loading/search|
|Common investigation|Process/memory|Procmon/search paths|
|Main primitive|Process manipulation|DLL resolution|

### Simple memory trick

```text
INJECTION
= PUT DLL INTO PROCESS

HIJACKING
= MAKE PROCESS PICK YOUR DLL
```

---

# 22. Three DLL Injection Techniques

Remember these three:

### 1. LoadLibrary

```text
OpenProcess
   ↓
VirtualAllocEx
   ↓
WriteProcessMemory
   ↓
CreateRemoteThread
   ↓
LoadLibraryA
```

### 2. Manual Mapping

```text
Raw DLL
  ↓
Map sections
  ↓
Resolve imports
  ↓
Relocations
  ↓
Execute
```

### 3. Reflective DLL Injection

```text
DLL contains ReflectiveLoader
          ↓
Find itself
          ↓
Resolve APIs
          ↓
Allocate
          ↓
Map
          ↓
Imports
          ↓
Relocations
          ↓
DllMain
```

---

# 23. DLL Hijacking Attack Chain

For CPTS, think:

```text
Application
     │
     ▼
Loads DLL without secure/full path
     │
     ▼
Windows searches locations
     │
     ▼
Attacker-controlled location
     │
     ▼
Malicious DLL found first
     │
     ▼
DLL loaded
     │
     ▼
Attacker code executes
```

---

# 24. CPTS Practical Enumeration Workflow

When you suspect DLL hijacking:

### Step 1 — Identify target executable

```text
main.exe
```

### Step 2 — Start Procmon

Filter:

```text
Process Name = main.exe
```

### Step 3 — Look at DLL activity

Filter:

```text
Operation = Load Image
```

### Step 4 — Look for failures

Search/filter for:

```text
NAME NOT FOUND
```

particularly paths ending in:

```text
.dll
```

### Step 5 — Determine search location

Example:

```text
C:\Users\PandaSt0rm\Desktop\Hijack\x.dll
```

### Step 6 — Determine whether you can write to that location

This is critical.

A missing DLL alone does **not** automatically mean exploitation is possible.

You need:

```text
DLL missing
+
Attacker-controlled searched location
+
Application loads DLL
=
Potential DLL hijacking
```

---

# 25. The Most Important CPTS Distinction

Don't confuse these:

### DLL Injection

```text
I already have a running process.

I want my DLL/code inside it.
```

### DLL Hijacking

```text
The application needs a DLL.

I want the application to load MY DLL.
```

### DLL Proxying

```text
I hijack the DLL,
but preserve/forward the original functionality.
```

### Missing DLL Hijacking

```text
Application wants x.dll.
x.dll doesn't exist.
I can place my DLL where the application searches.
```

---

# 🔥 Final CPTS Cheat Sheet

```text
==============================
DLL INJECTION
==============================

LoadLibrary injection:
OpenProcess()
VirtualAllocEx()
WriteProcessMemory()
GetProcAddress()
CreateRemoteThread()
LoadLibraryA()

==============================
MANUAL MAPPING
==============================

Raw DLL
 ↓
Map sections
 ↓
Resolve imports
 ↓
Relocations
 ↓
TLS callbacks
 ↓
DllMain

==============================
REFLECTIVE DLL INJECTION
==============================

ReflectiveLoader
 ↓
Locate own image
 ↓
Find kernel32 exports
 ↓
VirtualAlloc
 ↓
Map headers/sections
 ↓
Resolve imports
 ↓
Relocations
 ↓
DllMain

==============================
DLL HIJACKING
==============================

Application
 ↓
Requests DLL
 ↓
Windows DLL search
 ↓
Attacker-controlled DLL
 ↓
DLL loaded
 ↓
Code executes

==============================
ENUMERATION
==============================

Process Explorer
PE Explorer
Process Monitor

Procmon:
Process Name = target.exe
Operation = Load Image

Look for:
SUCCESS
NAME NOT FOUND

==============================
DLL PROXYING
==============================

Proxy DLL
 ↓
Load original DLL
 ↓
GetProcAddress()
 ↓
Call original function
 ↓
Modify/forward result
```

## 🧠 CPTS mental model

```text
                 DLL TECHNIQUES
                       │
          ┌────────────┴────────────┐
          │                         │
      INJECTION                 HIJACKING
          │                         │
          ▼                         ▼
   Existing process          Application DLL
          │                    resolution
          ▼                         │
   Put code inside             Control what
      process                   gets loaded
          │                         │
     ┌────┴────┐               ┌────┴─────┐
     │         │               │          │
LoadLibrary Manual        Proxying    Missing DLL
           Mapping
              │
        Reflective
```

**The key exam/viva answer:**  
**DLL injection manipulates a running process to load/execute injected code, whereas DLL hijacking abuses the DLL resolution/search mechanism to cause an application to load an attacker-controlled library.**