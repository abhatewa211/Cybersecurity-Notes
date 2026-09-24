This section continues **Credential Hunting** and teaches an important CPTS habit:

> **Don't only search for files named `password`. Search for file types and locations that commonly contain credentials, secrets, or useful system information.**

A credential found in a local file or network share can lead to:

```text
Credential
    ↓
Local Administrator
    ↓
Initial Access / Lateral Movement
    ↓
Domain Account
    ↓
Domain Privilege Escalation
```

The section specifically highlights network shares, configuration files, virtual disks, SSH keys, Office documents, OneNote files, Sticky Notes databases, and several Windows system files.

---

# 1. Network Shares — Very Important

In an Active Directory environment, network shares can contain a huge amount of sensitive information.

The source specifically mentions using **Snaffler** to crawl network shares for interesting files such as:

```text
.kdbx
.vmdk
.vdhx
.ppk
```

### Why these extensions matter

|Extension|Potential value|
|---|---|
|`.kdbx`|KeePass database|
|`.vmdk`|VMware virtual disk|
|`.vhdx` / `.vdhx`|Hyper-V virtual disk|
|`.ppk`|PuTTY/SSH private key|
|`.config`|Application configuration|
|`.docx` / `.xlsx`|Potentially stored credentials|
|`.one`|OneNote data|
|`.txt`|Could contain plaintext credentials|

The source emphasizes that virtual disks may contain local administrator password hashes, while SSH private keys can provide access to other systems.

---

# 2. Why Network Shares Are So Valuable

Consider an organization with:

```text
FILE01
  │
  └── users
       │
       ├── bjones
       ├── administrator
       ├── jsmith
       └── ...
```

If permissions are incorrectly configured so that:

```text
Domain Users → Read
```

on everybody's folders, users may unintentionally expose their sensitive files to the entire domain.

The source gives exactly this type of situation: an employee folder such as:

```text
users\bjones
```

may be readable by all Domain Users.

### Mental model

```text
Employee
   │
   ▼
"My personal network folder"
   │
   ▼
Actually readable by:
   │
   ├── Employee
   ├── Domain Users
   └── potentially attacker
```

This is why **share enumeration is also credential hunting**.

---

# 3. Snaffler

The source mentions:

**Snaffler**

as a tool for crawling network shares and looking for interesting files/extensions.

Its GitHub repository is linked in the source.

For CPTS, don't just remember the tool name.

Remember the purpose:

```text
Snaffler
   ↓
Crawl network shares
   ↓
Identify interesting files
   ↓
Investigate credentials/secrets
   ↓
Potential access escalation
```

---

# 4. Manual Credential Hunting

🔥 **This is one of the most important parts of the section.**

Enumeration tools are useful, but you should be comfortable doing the same thing manually.

Why?

Because:

- Scripts may miss unusual files.
    
- You may discover a file type the script doesn't search.
    
- You may want to customize your searches.
    
- Understanding the manual process helps you interpret tool output.
    

The source explicitly emphasizes that we should understand manual searching rather than relying exclusively on enumeration scripts.

---

# 5. Searching File Contents — Example 1

```cmd
cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt
```

Output:

```text
stuff.txt
```

This tells us:

```text
A file matching the searched extensions
contains the string "password".
```

### Important switches

The command uses:

```text
/S
```

Search subdirectories.

```text
/I
```

Case-insensitive search.

```text
/M
```

Print only filenames containing a match.

So:

```text
/SI /M
```

is useful when you want to quickly identify **which files** contain the keyword.

---

# 6. Searching File Contents — Example 2

```cmd
findstr /si password *.xml *.ini *.txt *.config
```

Output:

```text
stuff.txt:password: l#-x9r11_2_GL!
```

This time the output includes the actual matching line.

### Difference

Example 1:

```text
stuff.txt
```

Example 2:

```text
stuff.txt:password: l#-x9r11_2_GL!
```

So:

```text
/M → filename
without /M → matching content
```

🔥 Very useful distinction for the exam.

---

# 7. Searching Everything — Example 3

```cmd
findstr /spin "password" *.*
```

This is a broader search.

Conceptually:

```text
Current directory
      ↓
All files
      ↓
Recursive search
      ↓
Search for "password"
```

Output:

```text
stuff.txt:1:password: l#-x9r11_2_GL!
```

This gives:

```text
filename
   ↓
line number
   ↓
matching text
```

---

# 8. PowerShell Alternative

You can perform similar searches using:

```powershell
Select-String
```

Example:

```powershell
Select-String -Path C:\Users\htb-student\Documents\*.txt -Pattern password
```

Output:

```text
stuff.txt:1:password: l#-x9r11_2_GL!
```

### Mental mapping

```text
findstr
   ≈
Select-String
```

Both can be useful for searching file contents.

---

# 9. Searching for Interesting Filenames

Sometimes you don't want to search the **contents** first.

Instead, search for filenames that look interesting.

The source gives:

```cmd
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
```

Example result:

```text
c:\inetpub\wwwroot\web.config
```

This approach searches for filenames containing patterns such as:

```text
pass
cred
vnc
```

and interesting extensions such as:

```text
.config
```

---

# 10. `where /R`

Another simple technique:

```cmd
where /R C:\ *.config
```

This recursively searches:

```text
C:\
```

for:

```text
*.config
```

Example:

```text
c:\inetpub\wwwroot\web.config
```

### Mental model

```text
where /R <root> <pattern>
```

Example:

```cmd
where /R C:\ *.config
```

means:

```text
Search recursively from C:\
for .config files
```

---

# 11. PowerShell File Extension Search

PowerShell provides another useful method:

```powershell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

This searches recursively for:

```text
.rdp
.config
.vnc
.cred
```

### Why these are interesting

```text
.rdp
```

Remote Desktop configuration.

```text
.config
```

Application configuration.

```text
.vnc
```

VNC-related configuration.

```text
.cred
```

Potential credential-related data.

The important concept is:

> **Search by file extension based on what type of information you're hunting for.**

---

# 12. Content Search vs Filename Search

🔥 Remember this distinction.

### Content search

```text
"Does this file contain password?"
```

Example:

```cmd
findstr /si password *.xml *.ini *.txt *.config
```

### Filename search

```text
"Does this file look interesting based on its name/extension?"
```

Example:

```cmd
where /R C:\ *.config
```

### Combined methodology

```text
Filename search
      ↓
Find interesting files
      ↓
Content search
      ↓
Find interesting strings
      ↓
Inspect credentials
```

---

# 13. Sticky Notes — A Great Credential-Hunting Technique

🔥 This is a particularly interesting real-world technique.

Users sometimes put:

```text
passwords
server names
credentials
notes
reminders
```

into Windows Sticky Notes.

The problem?

Sticky Notes stores the notes in a **SQLite database**.

The source gives the database location:

```text
C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

---

# 14. Sticky Notes Database Files

The directory may contain:

```text
plum.sqlite
plum.sqlite-shm
plum.sqlite-wal
```

Example:

```text
15cbbc93e90a4d56bf8d9a29305b8981.storage.session
Ecs.dat
plum.sqlite
plum.sqlite-shm
plum.sqlite-wal
```

### Important

The source specifically tells us to copy the **three `plum.sqlite*` files** when analyzing the database externally.

That means:

```text
plum.sqlite
plum.sqlite-shm
plum.sqlite-wal
```

---

# 15. Why the `-wal` File Matters

The SQLite database can use:

```text
WAL
```

which stands for **Write-Ahead Logging**.

Therefore, don't automatically assume everything interesting is contained only in:

```text
plum.sqlite
```

The source demonstrates examining the related SQLite files as a set.

---

# 16. Querying Sticky Notes

The source uses:

**DB Browser for SQLite**

and the query:

```sql
SELECT Text FROM Note;
```

The relevant table is:

```text
Note
```

and the interesting field is:

```text
Text
```

Conceptually:

```text
plum.sqlite
     │
     ▼
Note table
     │
     ▼
Text column
     │
     ├── normal note
     ├── server name
     └── potentially credential
```

---

# 17. Sticky Notes Example

The source's PowerShell example retrieves:

```text
vCenter
root:Vc3nt3R_adm1n!
Thycotic demo tomorrow at 10am
```

The important discovery is:

```text
root:Vc3nt3R_adm1n!
```

This demonstrates why seemingly harmless user applications can become credential sources.

---

# 18. Querying Sticky Notes with PowerShell

The source uses the **PSSQLite** module.

First:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

Then:

```powershell
cd .\PSSQLite\
Import-Module .\PSSQLite.psd1
```

Set the database:

```powershell
$db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
```

Then query:

```powershell
Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
```

This returns the contents of the `Text` column.

---

# 19. Why SQLite Knowledge Matters

This section isn't only teaching:

> "Look at Sticky Notes."

It's also teaching a broader skill:

```text
Unknown application data
        ↓
Identify storage format
        ↓
SQLite?
        ↓
Find database
        ↓
Identify tables
        ↓
Query useful columns
```

You can apply the same methodology to other applications that store data in SQLite.

---

# 20. `strings` — Quick Database Inspection

The source also demonstrates:

```bash
strings plum.sqlite-wal
```

This extracts printable strings from the database/WAL file.

Example output includes:

```text
CREATE TABLE "Note"
```

and eventually:

```text
root:Vc3nt3R_adm1n!
```

### Why use `strings`?

It is:

```text
Fast
Simple
Available on Linux
```

But it can be less efficient/noisier for larger databases.

---

# 21. SQLite vs `strings`

### Proper database analysis

```text
DB Browser
     ↓
SQL query
     ↓
SELECT Text FROM Note;
```

More structured.

### Quick inspection

```bash
strings plum.sqlite-wal
```

More brute-force.

### CPTS mental model

```text
Need accuracy?
     ↓
SQLite query

Need quick triage?
     ↓
strings
```

---

# 22. Other Files of Interest

The source provides a long list of files worth knowing.

```text
%SYSTEMDRIVE%\pagefile.sys

%WINDIR%\debug\NetSetup.log

%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security

%WINDIR%\iis6.log

%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt

%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav

%WINDIR%\system32\CCM\logs\*.log

%USERPROFILE%\ntuser.dat

%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat

%WINDIR%\System32\drivers\etc\hosts

C:\ProgramData\Configs\*

C:\Program Files\Windows PowerShell\*
```

These are **enumeration targets**, not guarantees that credentials will be present.

---

# 23. Categorize the Files

Instead of memorizing one giant list, group them.

### Windows configuration / registry-related

```text
SAM
SYSTEM
SOFTWARE
SECURITY
ntuser.dat
```

### Logs

```text
NetSetup.log
iis6.log
CCM\logs\*.log
AppEvent.Evt
SecEvent.Evt
```

### System data

```text
pagefile.sys
```

### Network configuration

```text
hosts
```

### Application/configuration

```text
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

This makes the list much easier to remember.

---

# 24. Credential Hunting Workflow

Here's how I would structure this for your CPTS methodology:

```text
                  WINDOWS FOOTHOLD
                         │
                         ▼
                 Credential Hunting
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
      Local files    User data      Network shares
          │              │              │
          ▼              ▼              ▼
   Config files     Sticky Notes    Snaffler
   .config          PS history      .kdbx
   .xml             databases       .vmdk
   .ini                             .vhdx
   .cred                            .ppk
          │
          └──────────────┬──────────────┘
                         ▼
                  Interesting data
                         │
                         ▼
                    Credentials
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
       Local privilege          Other systems /
         escalation             domain access
```

---

# 25. Manual Hunting Cheat Sheet

## Search contents

```cmd
findstr /SI /M "password" *.xml *.ini *.txt
```

```cmd
findstr /si password *.xml *.ini *.txt *.config
```

```cmd
findstr /spin "password" *.*
```

---

## PowerShell content search

```powershell
Select-String -Path C:\Users\<user>\Documents\*.txt -Pattern password
```

---

## Search filenames

```cmd
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
```

```cmd
where /R C:\ *.config
```

---

## PowerShell extension search

```powershell
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

---

## Sticky Notes

Location:

```text
C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\
```

Important:

```text
plum.sqlite
plum.sqlite-shm
plum.sqlite-wal
```

SQLite query:

```sql
SELECT Text FROM Note;
```

Quick Linux inspection:

```bash
strings plum.sqlite-wal
```

---

# 26. CPTS Exam Questions

### Q1. Why are network shares important during credential hunting?

Because users may store credentials, private keys, virtual disks, documents, databases, and other sensitive information on shares that may have overly permissive access.

---

### Q2. What tool does the source mention for crawling AD network shares?

```text
Snaffler
```

---

### Q3. Give examples of interesting file extensions.

```text
.kdbx
.vmdk
.vhdx / .vdhx
.ppk
.config
.cred
.vnc
.rdp
```

---

### Q4. What is the difference between `findstr /M` and normal `findstr`?

`/M` outputs the **filename** of files containing a match, whereas normal searching can show the matching content.

---

### Q5. What does `/S` do in `findstr`?

Searches subdirectories.

---

### Q6. What does `/I` do?

Makes the search case-insensitive.

---

### Q7. What does `where /R` do?

Recursively searches from the specified root directory for a matching file pattern.

Example:

```cmd
where /R C:\ *.config
```

---

### Q8. Where is the Sticky Notes database?

```text
C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

---

### Q9. What table contains Sticky Notes text?

```text
Note
```

---

### Q10. What column contains the note contents?

```text
Text
```

---

### Q11. What SQL query does the source use?

```sql
SELECT Text FROM Note;
```

---

### Q12. What three SQLite files should be copied?

```text
plum.sqlite
plum.sqlite-shm
plum.sqlite-wal
```

---

### Q13. What can `strings` be used for?

Quickly extracting printable strings from files such as the SQLite WAL file to look for potentially interesting information.

---

# 🔥 Final CPTS Mental Model

Don't approach credential hunting like:

```text
"Run one password-search command."
```

Approach it like an investigator:

```text
                 WHAT DOES THIS USER HAVE?
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
        Documents       Applications    Shares
            │              │              │
            ▼              ▼              ▼
        .txt/.docx      Databases       .kdbx
        .xlsx           Sticky Notes    .vmdk
        .one            Browser data    .vhdx
        .config         PS history     .ppk
            │              │              │
            └──────────────┼──────────────┘
                           ▼
                    Sensitive data
                           │
                           ▼
                      Credentials
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
        Privilege Escalation       Lateral Movement
```

### 🔑 The most important takeaway

**Credential hunting is broader than password files.**

A professional Windows assessment should make you think:

```text
Files
+
File extensions
+
File contents
+
Application databases
+
User history
+
Network shares
+
Virtual disks
+
Private keys
+
Logs
=
Credential Hunting
```

And importantly, the HTB section's final lesson is that **manual enumeration remains necessary even when automated privilege-escalation scripts are available**, because scripts may miss unusual or environment-specific files.