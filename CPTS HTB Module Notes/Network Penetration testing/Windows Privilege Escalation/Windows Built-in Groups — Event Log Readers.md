This section focuses on the **Event Log Readers** group and how Windows event logs can expose sensitive information, especially **process command lines and credentials**.

---

## 1. What is the Event Log Readers group?

The **Event Log Readers** group allows members to read event logs from the local Windows machine without necessarily giving them full administrative privileges.

The important security idea is:

> **Event logs can contain sensitive information, not just harmless system events.**

For example, if process-creation auditing and command-line logging are enabled, **Security Event ID 4688** can contain the command line used to start a process.

![Image](https://images.openai.com/static-rsc-4/3kEuAjfgdtCX1qh5v7zSsg_3GqKsM0L2yZhsiJXd8uXkPpy-YmMcnx1tdBVr0KA02Mlj4T0KvcPE7nTDCsyEOCYNnXDUCyApDp80Q5mln4PrdLw1mB2RBmsC7jt_qVisj5O-T7D566ZKKb4inmY95CUrYG-JvDQrZXKPVQ1drbvHN0hm7rBBEjF2uI88g-aO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iysmVK5FC3K7Oo0uBqnDR-948RSbZGJ685yrLf_Qyg_kQkXG9O55YIrLA9TWjegXdbx-dier9ZvawndWjf0lFccwLOEEctdiUrcHLmKqIfYmO04D3BQwoQ00bo-osbjVXQD1hLzTRJAcBvFQr6-CemiCBVib2Z0KYBMwvJdFbbYGizjFtrgAnicz-txPdMzn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yKlkKaxRwo1osZIyK3VnsTcjT3YYgVza6TXGKt2IF-7iOTnd1MSrXh7yFPCoVECLbGcacZyp5edxZrbaIrDwR1zAK7xrnU-HbWEX6v2zXy4gRfy7gsXfYJsaqsmscYTUWlMmT-zVf4g2VNFw2SZYCuf4YhMjzR71ukLZNm6ILuA3x-BV-PVSDFXqGnlTBM0K?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_qXO0vQNPan-JxxbcXfOm4_SryTDHSLi0j1SbyRVKj0ESPwYXLcOcYtfuOLS6n05Ty5iKfk96ofRP-VwOa_8l8G_ZNfqD8vpv2sZElWZuknI_JXK-sAHB1-JW1F1mz1UMvr6ln489sWWDw2dEUU-8qxb_8DCbaSyQby1wuOwikZvfvzGCzwN_p0VCMWUSqjd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PIrxE5usglhSuV4o-b1by8-37YGPeik6uGC7MwKrZ3ut5NM8HtGaRTsesPv8uMfzyVZCGAwG_5zb9hUSHr1GkR017KDYOf-EyXmAnFtK0-7Ez6HqgcXVEPpaKG0fzo711CC29srD4M-Web9UNKVb91jlzwwhZvwqzK7pqwmufWD_FTMmsAjLjju6FrP4CnLo?purpose=fullsize)

---

# 2. Event ID 4688 — Process Creation

**Event ID 4688** = **A new process has been created**.

If an organization enables:

- Process creation auditing
    
- Command-line auditing
    

Windows can record information such as:

```text
Process Command Line:
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

This is extremely important from a security perspective.

The command itself might contain:

- usernames
    
- passwords
    
- network paths
    
- administrative commands
    
- scripts
    
- sensitive parameters
    

So **command-line logging can accidentally become a source of credential exposure**.

---

# 3. Why defenders monitor commands

Attackers frequently use legitimate Windows commands after gaining access.

Examples mentioned in the source:

### Initial enumeration

```text
tasklist
ver
ipconfig
systeminfo
```

### Reconnaissance

```text
dir
net view
ping
net use
type
```

### Potential malware propagation / lateral activity

```text
at
reg
wmic
wusa
```

The important concept for CPTS is:

> **Living-off-the-land:** attackers can use legitimate Windows utilities instead of dropping obvious malicious tools.

A command such as:

```cmd
tasklist
```

is completely legitimate.

But if it appears on a workstation where the user normally never performs administrative/IT activities, it can become a useful detection signal.

---

# 4. Real-world detection example

The source gives an important penetration-testing example.

A tester had obtained credentials using **Responder**, cracked them offline, and then used:

```cmd
tasklist
```

from a finance department workstation.

Because the organization had:

- process creation auditing
    
- command-line logging
    
- monitoring
    

the security team detected the command and contained the tester.

### CPTS lesson

This is a great reminder that:

```text
Command execution
       ↓
Process Creation Event 4688
       ↓
Command line recorded
       ↓
SIEM / detection platform
       ↓
Defender investigates
```

So **post-exploitation activity can generate detectable telemetry**.

---

# 5. AppLocker as another defensive control

Organizations can go beyond monitoring and potentially restrict execution of specific commands using carefully configured **AppLocker rules**.

Conceptually:

```text
Monitoring
   ↓
Detect suspicious command
   ↓
Investigate

AppLocker
   ↓
Restrict execution
   ↓
Prevent selected execution
```

The source emphasizes that built-in Microsoft capabilities can provide useful host-level visibility even when an organization does not have an expensive enterprise EDR deployment.

---

# 6. Confirming Event Log Readers membership

Use:

```cmd
net localgroup "Event Log Readers"
```

Example:

```text
Alias name     Event Log Readers
Comment        Members of this group can read event logs from local machine

Members
-------------------------------------------------------------------------------
logger
The command completed successfully.
```

### CPTS command

```cmd
net localgroup "Event Log Readers"
```

Remember this because you'll often enumerate built-in groups during Windows privilege escalation.

---

# 7. Important security issue — credentials in command lines

One of the biggest takeaways from this section is:

> **Never assume command-line logging only contains commands.**

Some Windows utilities allow credentials to be passed directly as command-line arguments.

Example from the source:

```cmd
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

If process command-line auditing is enabled, the password may appear in Event ID 4688.

Therefore:

```text
Sensitive command
       ↓
Command-line auditing
       ↓
Event 4688
       ↓
Credential potentially exposed
```

This is particularly interesting to a penetration tester because **logs themselves can become a source of credentials**.

---

# 8. Reading Windows events with `wevtutil`

Windows provides the built-in:

```cmd
wevtutil
```

utility for querying event logs.

Basic query:

```cmd
wevtutil qe Security
```

Useful options from the source:

```text
qe       Query events
/rd:true Reverse direction
/f:text  Text output
```

Example:

```powershell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

The source shows it finding:

```text
Process Command Line:   net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

### What is happening?

```text
wevtutil
   ↓
Security event log
   ↓
Search output
   ↓
Look for "/user"
   ↓
Potential credential-containing command
```

---

# 9. Querying a remote machine with `wevtutil`

`wevtutil` can also accept alternate credentials.

Source example:

```cmd
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

Important parameters:

|Parameter|Meaning|
|---|---|
|`/r:`|Remote computer|
|`/u:`|Username|
|`/p:`|Password|
|`qe`|Query events|
|`/f:text`|Text output|
|`/rd:true`|Reverse chronological direction|

### Security note

The source example itself demonstrates why passing passwords on command lines can be dangerous: **those credentials can potentially become visible through command-line auditing**.

---

# 10. PowerShell — `Get-WinEvent`

Another powerful Windows event-querying tool is:

```powershell
Get-WinEvent
```

Example from the source:

```powershell
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

Output:

```text
CommandLine
-----------
net use T: \\fs01\backups /user:tim MyStr0ngP@ssword
```

### What the command does

Break it down:

```powershell
Get-WinEvent -LogName security
```

Retrieves events from the Security log.

Then:

```powershell
where { $_.ID -eq 4688 }
```

Filters for:

```text
Event ID 4688
```

Then:

```powershell
$_.Properties[8].Value -like '*/user*'
```

Looks for `/user` in the process command-line property.

Finally:

```powershell
Select-Object
```

Displays the command line.

---

# 11. Important distinction: Event Log Readers vs Security log

This is a **CPTS must-know nuance** from the source.

The source specifically states that searching the **Security** event log with:

```powershell
Get-WinEvent
```

requires either:

- Administrator access, **or**
    
- appropriate permissions on:
    

```text
HKLM\System\CurrentControlSet\Services\Eventlog\Security
```

Therefore:

> **Membership in Event Log Readers alone is not sufficient for this particular `Get-WinEvent` Security-log operation.**

Don't make the mistake of assuming:

```text
Event Log Readers
       =
Full Security log access
```

The source explicitly distinguishes these.

---

# 12. Running `Get-WinEvent` with alternate credentials

PowerShell's:

```powershell
-Credential
```

parameter can be used to run the cmdlet with another user's credentials.

Conceptually:

```text
Current user
     ↓
Get-WinEvent
     ↓
-Credential
     ↓
Alternate security context
```

The exact credential handling depends on the environment and permissions.

---

# 13. PowerShell Operational logs

Security logs aren't the only interesting source.

The source also mentions:

```text
PowerShell Operational
```

These logs can contain potentially sensitive information when logging such as:

- Script Block Logging
    
- Module Logging
    

is enabled.

An important difference mentioned by the source:

> The PowerShell Operational log is accessible to **unprivileged users**.

This means that during enumeration, you shouldn't only think about:

```text
Security
System
Application
```

Also consider:

```text
PowerShell Operational
```

because it may contain useful information about PowerShell activity.

---

# 14. Pentester mental model

When you encounter **Event Log Readers**, think:

```text
             Event Log Readers
                    │
                    ▼
             Read event logs
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
     Security logs       PowerShell logs
          │                    │
          ▼                    ▼
      Event 4688          Script/module
          │                activity
          ▼
  Process command line
          │
          ▼
 ┌─────────────────────┐
 │ Credentials?        │
 │ Usernames?          │
 │ Network paths?      │
 │ Sensitive commands? │
 └─────────────────────┘
```

That is the core idea of this section.

---

# 🔥 CPTS Must-Know

### 1. Event Log Readers

```cmd
net localgroup "Event Log Readers"
```

Used to enumerate membership.

### 2. Event ID 4688

```text
A new process has been created
```

Can contain process command-line information when appropriate auditing is enabled.

### 3. `wevtutil`

```cmd
wevtutil qe Security
```

Query Windows event logs.

Example:

```powershell
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

### 4. `Get-WinEvent`

```powershell
Get-WinEvent -LogName security
```

PowerShell event-log querying.

### 5. Event 4688 filtering

```powershell
Get-WinEvent -LogName security |
where { $_.ID -eq 4688 }
```

### 6. Credential exposure

Be alert for commands such as:

```cmd
net use \\server\share /user:username password
```

because command-line auditing may record the entire command.

### 7. PowerShell Operational

Can contain sensitive information when:

```text
Script Block Logging
Module Logging
```

are enabled.

---

# 🧠 CPTS Exam Mental Model

If you see:

```text
Event Log Readers
```

don't immediately think:

> "Privilege escalation!"

Instead think:

> **"What information can I retrieve from the logs?"**

Then enumerate:

```text
1. Am I a member?
        ↓
2. Which logs can I read?
        ↓
3. Security / PowerShell / other logs
        ↓
4. Search for useful events
        ↓
5. Look for credentials, command lines,
   usernames, paths, scripts, and activity
```

And remember the important limitation:

```text
Event Log Readers
        ≠
automatic access to everything in Security
```

The source specifically notes that `Get-WinEvent` against the Security log requires additional privilege/permissions.

### One-line takeaway

> **Event Log Readers can turn Windows logs into an information source; Event ID 4688 is especially interesting because process command lines may expose reconnaissance commands and, in poorly designed command usage, credentials.**