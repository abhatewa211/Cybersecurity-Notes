This section follows the same methodology as Server 2008: **identify the legacy OS → determine patch state → identify applicable vulnerabilities → filter the results → validate a privilege-escalation path.**

Windows 7 reached **end of life on January 14, 2020**, but the source notes that it continued to exist widely in enterprise environments.

---

# 1. Windows 7 vs Windows 10

Microsoft introduced significant security improvements in Windows 10 that aren't present, or are only partially present, in Windows 7.

|Security feature|Windows 7|Windows 10|
|---|--:|--:|
|Microsoft Password / MFA|❌|✅|
|BitLocker|Partial|✅|
|Credential Guard|❌|✅|
|Remote Credential Guard|❌|✅|
|Device Guard / Code Integrity|❌|✅|
|AppLocker|Partial|✅|
|Windows Defender|Partial|✅|
|Control Flow Guard|❌|✅|

### CPTS takeaway

When you see Windows 7, don't approach it exactly like Windows 10.

```text
Windows 7
   │
   ├── Older security controls
   ├── Missing modern mitigations
   ├── EOL
   └── Potentially missing patches
             ↓
       Larger historical
       vulnerability set
```

The source specifically highlights the differences in Credential Guard, Remote Credential Guard, Device Guard, AppLocker, Defender, and Control Flow Guard.

---

# 2. Business Context Still Matters

Windows 7 can still be found in:

- Education
    
- Retail
    
- Transportation
    
- Healthcare
    
- Financial organizations
    
- Government
    
- Manufacturing
    

The source emphasizes that penetration testers need to understand the client's **business, risk appetite, and limitations** before recommending removal or replacement of EOL systems.

### Example: Retail POS

A company might have hundreds of Windows 7 embedded devices running point-of-sale systems.

Replacing everything immediately may not be financially practical.

Compare that with:

```text
Large retail chain
    ↓
Hundreds of Windows 7 POS systems
    ↓
Replacement expensive
    ↓
Mitigating controls needed
```

versus:

```text
Law firm
   ↓
One old Windows 7 machine
   ↓
Not business-critical
   ↓
Could potentially upgrade/remove quickly
```

The key lesson is:

> **Risk depends on context, not simply the operating system version.**

---

# 3. Windows 7 Enumeration Workflow

The source demonstrates two important approaches:

### Option 1

```text
Sherlock
```

### Option 2

```text
Windows-Exploit-Suggester
```

For this walkthrough, the focus is **Windows-Exploit-Suggester**.

---

# 4. Collect `systeminfo`

On the Windows 7 target:

```cmd
systeminfo
```

The lab returns:

```text
OS Name:       Microsoft Windows 7 Professional
OS Version:    6.1.7601 Service Pack 1 Build 7601
OS Configuration: Standalone Workstation
System Type:   x64-based PC
```

### ⭐ CPTS MUST KNOW

`systeminfo` gives you several critical pieces of information at once:

```text
OS
Version
Service Pack
Build
Architecture
System configuration
```

For vulnerability research, this information is extremely valuable.

---

# 5. Save `systeminfo` Output

The source says to capture the output and save it to a text file on the attacker machine.

Conceptually:

```text
Windows 7 target
      │
      ▼
systeminfo
      │
      ▼
systeminfo.txt
      │
      ▼
Attack VM
      │
      ▼
Windows-Exploit-Suggester
```

---

# 6. Update Windows-Exploit-Suggester Database

The source uses:

```bash
sudo python2 windows-exploit-suggester.py --update
```

This updates the local Microsoft vulnerability database.

The tool stores the database locally as an Excel file.

---

# 7. Run Windows-Exploit-Suggester

Then:

```bash
python2 windows-exploit-suggester.py \
--database 2021-05-13-mssb.xls \
--systeminfo win7lpe-systeminfo.txt
```

The tool compares:

```text
Target patch level
        ↓
Microsoft vulnerability database
        ↓
Known exploits
```

The example identifies:

```text
Windows 7 SP1 64-bit
```

and reports numerous potential vulnerabilities.

---

# 8. Understanding the Output

The output uses indicators such as:

```text
[E] = ExploitDB PoC
[M] = Metasploit module
[*] = Missing bulletin
```

The source explicitly explains these indicators.

For example:

```text
[E] MS16-135
[M] MS16-075
[E] MS16-032
```

---

# 9. Don't Trust the Entire List Blindly

This is **one of the most important lessons in the section.**

A vulnerability suggester can return a huge amount of information.

The source says the tester must:

- Filter through the noise.
    
- Remove Denial-of-Service exploits.
    
- Remove exploits that don't make sense for the target OS.
    
- Focus on useful privilege-escalation candidates.
    

Think:

```text
386 possible vulnerabilities
          │
          ▼
      FILTER
          │
    ┌─────┼─────┐
    ▼     ▼     ▼
   DoS  Wrong   RCE/LPE
        OS      candidate
                │
                ▼
             Validate
```

### CPTS mindset

**Enumeration tools generate candidates, not guaranteed exploits.**

---

# 10. MS16-032

The source identifies **MS16-032** as particularly interesting.

It is associated with the **Secondary Logon Service** and can provide local privilege escalation.

The example identifies:

```text
MS16-032
CVE-2016-0099
```

and multiple proof-of-concept references.

---

# 11. Metasploit Local Exploit Suggester

If you already have a Meterpreter session, you don't necessarily need to manually run Windows-Exploit-Suggester.

Metasploit has:

```text
local_exploit_suggester
```

The source explains that it can quickly identify potential local privilege-escalation vectors and suggest Metasploit modules when available.

### Comparison

|Method|Input|Purpose|
|---|---|---|
|Windows-Exploit-Suggester|`systeminfo`|Offline vulnerability matching|
|Sherlock|Target Windows environment|Local vulnerability enumeration|
|Metasploit Local Exploit Suggester|Meterpreter session|Identify applicable Metasploit LPEs|

---

# 12. MS16-032 PowerShell PoC

The lab uses a PowerShell proof of concept.

First:

```powershell
Set-ExecutionPolicy bypass -scope process
```

Then:

```powershell
Import-Module .\Invoke-MS16-032.ps1
```

Then:

```powershell
Invoke-MS16-032
```

The PoC output shows the exploit working through token/handle manipulation:

```text
Duplicating CreateProcessWithLogonW handle
        ↓
Sniffing privileged impersonation token
        ↓
Thread belongs to svchost
        ↓
Building SYSTEM impersonation token
        ↓
Success, open SYSTEM token handle
        ↓
Duplicating SYSTEM token
        ↓
Starting token race
        ↓
Starting process race
        ↓
SYSTEM shell
```

---

# 13. Verify SYSTEM

The lab then verifies:

```cmd
whoami
```

Result:

```text
nt authority\system
```

### The important part

The actual CPTS concept isn't simply:

> “Run `Invoke-MS16-032`.”

It's understanding:

```text
Low privilege
     ↓
Identify OS + architecture
     ↓
Identify missing patches
     ↓
Find applicable LPE
     ↓
Validate exploit compatibility
     ↓
Execute authorized LPE
     ↓
SYSTEM
```

---

# 🔥 Complete Windows 7 Attack Chain

```text
                 WINDOWS 7
                     │
                     ▼
                systeminfo
                     │
                     ▼
          Windows 7 SP1 x64
                     │
                     ▼
      Windows-Exploit-Suggester
                     │
                     ▼
         Large vulnerability list
                     │
                     ▼
             FILTER RESULTS
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
       Remove DoS         Remove incompatible
                            vulnerabilities
          │                     │
          └──────────┬──────────┘
                     ▼
                 MS16-032
                     │
                     ▼
            Secondary Logon
                     │
                     ▼
             PowerShell PoC
                     │
                     ▼
          SYSTEM token/process
                     │
                     ▼
             NT AUTHORITY\SYSTEM
```

---

# 🧠 Windows 7 vs Server 2008

Now connect this section with the previous one.

|Concept|Server 2008|Windows 7|
|---|---|---|
|EOL|Yes|Yes|
|Patch enumeration|`wmic qfe`|`systeminfo` + suggester|
|Sherlock|Yes|Yes|
|Windows-Exploit-Suggester|Yes|Yes|
|Example LPE|MS10-092|MS16-032|
|Important consideration|Legacy server|Legacy workstation|
|Architecture awareness|Important|Important|
|Business context|Critical|Critical|

### Notice the pattern

The **specific exploit changes**, but the methodology remains almost identical.

---

# 🎯 CPTS Enumeration Formula

Memorize this instead of individual CVEs:

```text
IDENTIFY
   ↓
OS / VERSION / BUILD
   ↓
ARCHITECTURE
   ↓
PATCH LEVEL
   ↓
VULNERABILITY SUGGESTER
   ↓
FILTER RESULTS
   ↓
CHECK EXPLOIT COMPATIBILITY
   ↓
SELECT LPE
   ↓
EXPLOIT
   ↓
VERIFY
```

---

# ⚠️ Common Mistakes

### Mistake 1 — Assuming EOL = vulnerable

Wrong.

EOL tells you the support situation. You still need to identify the actual vulnerability.

---

### Mistake 2 — Running every exploit returned by a scanner

Bad methodology.

The source specifically says to remove:

- DoS exploits
    
- Incompatible OS exploits
    
- Irrelevant results
    

before choosing a useful candidate.

---

### Mistake 3 — Ignoring architecture

The target is:

```text
Windows 7 SP1
x64
```

so exploit compatibility matters.

---

### Mistake 4 — Ignoring business context

A Windows 7 POS system across hundreds of stores is very different from one forgotten Windows 7 workstation.

---

# 🔥 CPTS Must-Know Commands

### OS information

```cmd
systeminfo
```

### Installed hotfixes

```cmd
wmic qfe
```

### Windows 7 vulnerability database

```bash
sudo python2 windows-exploit-suggester.py --update
```

### Analyze target

```bash
python2 windows-exploit-suggester.py \
--database <database.xls> \
--systeminfo <systeminfo.txt>
```

### PowerShell execution-policy change for the lab

```powershell
Set-ExecutionPolicy bypass -scope process
```

### Load PoC

```powershell
Import-Module .\Invoke-MS16-032.ps1
```

### Execute PoC

```powershell
Invoke-MS16-032
```

### Verify privilege

```cmd
whoami
```

Expected successful lab result:

```text
nt authority\system
```

---

# 🎓 Viva Questions

### Q1. When did Windows 7 reach EOL?

**January 14, 2020.**

### Q2. What information does `systeminfo` provide that's useful for exploit research?

OS name, version, service pack, build, architecture, configuration and other system details.

### Q3. What does Windows-Exploit-Suggester do?

It compares `systeminfo` information against a local Microsoft vulnerability database to identify potential missing patches and associated exploits.

### Q4. What do `[E]` and `[M]` mean?

```text
[E] → ExploitDB PoC
[M] → Metasploit module
```

### Q5. Why must you filter Windows-Exploit-Suggester results?

Because the list can contain irrelevant, incompatible, or DoS-only vulnerabilities.

### Q6. What service is associated with MS16-032?

**Secondary Logon Service.**

### Q7. What privilege does the demonstrated MS16-032 PoC obtain?

```text
NT AUTHORITY\SYSTEM
```

### Q8. What's the biggest methodology lesson?

**Don't memorize exploits. Learn how to move from system enumeration → patch enumeration → vulnerability filtering → exploit validation → privilege verification.**

---

## 🧠 Final Mental Model

```text
           LEGACY WINDOWS 7
                  │
                  ▼
             systeminfo
                  │
          ┌───────┴───────┐
          ▼               ▼
       Version         Architecture
          │               │
          └───────┬───────┘
                  ▼
             Patch State
                  │
                  ▼
       Exploit Suggester
                  │
                  ▼
          FILTER THE NOISE
                  │
                  ▼
        Applicable LPE candidate
                  │
                  ▼
             Validate
                  │
                  ▼
              Exploit
                  │
                  ▼
        NT AUTHORITY\SYSTEM
```

**The big CPTS takeaway:** the OS-specific exploit is only one piece. The reusable skill is **enumerating the target accurately enough to discover which privilege-escalation techniques actually apply.**