## 1. Why Enumerate Security Controls?

After obtaining a foothold, your visibility into the environment usually improves.

At this point, you want to understand:

- What security products are installed?
    
- What security policies are enforced?
    
- Which tools can you execute?
    
- Which PowerShell features are available?
    
- Is PowerShell restricted?
    
- Is application whitelisting enabled?
    
- Is LAPS deployed?
    
- Which accounts can read LAPS passwords?
    

These controls directly affect your **AD enumeration, exploitation, and post-exploitation strategy**.

### Core idea

```text
Initial Foothold
       ↓
Enumerate Security Controls
       ↓
Understand Defensive Environment
       ↓
Adjust Enumeration / Tool Selection
       ↓
Continue Authorized Assessment
```

---

# 🛡️ 2. Security Controls Covered

This section focuses on four major areas:

```text
┌───────────────────────────────┐
│     SECURITY CONTROLS         │
├───────────────────────────────┤
│  1. Windows Defender          │
│  2. AppLocker                 │
│  3. PowerShell CLM             │
│  4. LAPS                      │
└───────────────────────────────┘
```

---

# 🦠 3. Windows Defender / Microsoft Defender

![Image](https://images.openai.com/static-rsc-4/nagxq6zizWj66Qlf7FZHP3Eq84VT2rFZSNagze_vAEpoxK4kDtHzbkG5dLJuI1CY-Y-z5vrSGTh0IB06qM_J2CdLTeibR9eCREpOwBlcw8c1BiJ89vi_aY6WhjNwwOuMSrzl-pQujWJ6WWe-aI_OuVvkFH0GBeWIadyM7RypQxXy5Ai6r0zGA5zims3Ramb4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VGpG9HlnfQ5Srlh2-DGe-7EE8RLYB_OybqRGQdyvJj0fZAjp-jSmeBlKI6rfNHIoe_XuQ5dzDc8czqb3mWRrQwqbDbjry_TR9MkyYZVMf2OTuUI-VHD_zMcCev_i6DmdSx7sVIW9yzeG3ztVCd8FjNX8dFxJYMo564pDgMXVNpEgKZug95e1lifC5C_e57N7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mpkYx6qGyY1RdiTDWeP-xGn9ogjVklp_TwwumSF1E5_Erg7iv8FoejYKo6eLrITrknJrMoaXxROrRHpWFCpbgw0WDAzQTL6LOdnBUbAfh132HJ2-HLLhRXdSNVABA4cW_Y9YhIHg2GhWpurk8qvS0gluOq2AbGd6wFMQGBUlclxxk9p82-FqwNSFuBzBamRM?purpose=fullsize)

The module explains that Windows Defender, now generally referred to as **Microsoft Defender**, has significantly improved over time.

By default, it can block tools such as:

```text
PowerView
```

The important lesson isn't simply whether Defender exists.

You need to determine **which protections are actually enabled** on the current host.

---

# 4. Checking Defender Status

The built-in PowerShell cmdlet is:

```powershell
Get-MpComputerStatus
```

This provides information about the current Defender configuration.

The module's example shows:

```text
AntispywareEnabled          : True
AntivirusEnabled            : True
RealTimeProtectionEnabled   : True
```

---

# 🔎 5. Important Defender Fields

You don't need to memorize every field in the output.

Focus on the important ones.

|Field|Meaning|
|---|---|
|`AntispywareEnabled`|Antispyware protection status|
|`AntivirusEnabled`|Antivirus protection status|
|`RealTimeProtectionEnabled`|Real-time protection status|
|`BehaviorMonitorEnabled`|Behavior monitoring status|
|`OnAccessProtectionEnabled`|On-access protection status|
|`QuickScanAge`|Age of last quick scan|
|`FullScanAge`|Age of last full scan|

Example:

```text
RealTimeProtectionEnabled : True
```

means real-time protection is enabled.

---

# 🧠 Mentor Tip — Don't Just Ask "Is Defender Installed?"

The better question is:

> **What protections are enabled and how do they affect my authorized assessment?**

Think:

```text
Defender
   ↓
Installed?
   ↓
Enabled?
   ↓
Real-time protection?
   ↓
Behavior monitoring?
   ↓
What does this mean for tool execution?
```

---

# 🔐 6. AppLocker

![Image](https://images.openai.com/static-rsc-4/f8C2SF3jhDnhHuxqBN-5k2MAn_kcDDyncjyMLp6kKR5c623xGZMODB0pxJff6ISNhQlDC9zD6Pe9gYo4LbR6JNpTwgqHKosYZxR_OIOaWt2dgWu-qLG-shlu-lN7z6VBJlmLCDGi5ooTGKndTQ7_LQ2wi1qld3RKvMcxSE4sSlJobmw5mLKDjt7U7G8rKixf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NLVTKa7GowE7fYKg_U35qeZDykL4oZSSWkdzpXrQxXzWu8bkVZ1woDc7rQ6wgk8Kc9qRA00gWKvaY4Rx_BNelswl5v0aNhlOmz4rB4CQ51rJm820fqJIn3WXld72u5VBcMNpNONHFxVvtzJC58e7zGEEhxS4XzIKUh0JCyjwAJ5bzQj_FCxkMI2897S1CvKP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hs8Y8Vg2O9to4kArEyESbB_1e9v-JDW8X82xcbziiQWG4wQgRjw2bxCBQmTT4nHSGhzJaR30L0uEoNpd2ZRLWs1sP3MGouo-nglGZYGcvXWTWw0wygAw6kT4ANCCW5eaWkEJGrCAn2zkleoEVgoV22Oaz1rmhEDLVbS7-hIkxSwtzVFtPfuhDIUitaaZQM1E?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Z0Kyr79McbMZr5LxDLL2EEzCb4-abUVUANVQlJl2c7ZsDy2pow49BcG3b7GLOadxYujvr1n6-2J_FDbmrkW2Kiwx4Jqs9Ol5JVRjT6UKfaKRU5PkXT42EGmkvg_pulyMbNYtn_yOmAHuCQTWc0O3BmDviim6585bjJq868iDuoJ6spbzTwcPFhbzNu7MsSGr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rCR2VFYZDfIwbPQxHVhRPemncQEXjslJmglEzlNbSw0qlFnvkYgi7lMhoqOhzEJsNnHufmvEGZ0SQmP_BKGK8sgMaAKTlumkRL_vdrv8lMOlnWoD1nQZg8ORjctPAB3tEkMIKJfCb-HsSQODLpW6Ke9MmDzlg7tV_E6s1xfd5HZbWmbKwFYIcP2eXXxJLMa1?purpose=fullsize)

**AppLocker** is Microsoft's application-control / application-whitelisting solution.

Its purpose is to control which applications and files users are allowed to run.

It can control:

- Executables
    
- Scripts
    
- Windows Installer files
    
- DLLs
    
- Packaged applications
    
- Packaged app installers
    

---

# 7. Application Whitelisting

The basic idea:

```text
User attempts to run application
              ↓
        AppLocker checks
              ↓
      ┌───────┴───────┐
      ↓               ↓
   Allowed          Denied
      ↓               ↓
   Execute          Blocked
```

Instead of asking:

> "Is this program malicious?"

application whitelisting can ask:

> "Is this application allowed to run?"

---

# 8. Common AppLocker Restrictions

The module notes that organizations commonly restrict:

```text
cmd.exe
PowerShell.exe
```

and may restrict execution from certain directories.

An important observation from the module is that organizations may block one PowerShell executable path while overlooking other PowerShell executable locations.

For example:

```text
%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe
```

may be specifically blocked.

### Mentor lesson

When enumerating a control, don't assume:

```text
"PowerShell blocked"
```

means:

```text
"All PowerShell functionality is unavailable."
```

You need to understand the **actual policy rules**.

---

# 9. Enumerating AppLocker

The module uses:

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

This retrieves the **effective AppLocker policy**.

"Effective" is important because you care about the policy that actually applies to the current system/user context.

---

# 10. Understanding AppLocker Output

Example:

```text
Name                : Block PowerShell
Description         : Blocks Domain Users from using PowerShell on workstations
Action              : Deny
```

The relevant fields are:

|Field|Meaning|
|---|---|
|`PathConditions`|Path affected by rule|
|`PathExceptions`|Paths excluded from rule|
|`PublisherExceptions`|Publisher-based exceptions|
|`HashExceptions`|File-hash exceptions|
|`Name`|Rule name|
|`Description`|Rule purpose|
|`UserOrGroupSid`|Account/group to which rule applies|
|`Action`|Allow or Deny|

---

# 11. Example AppLocker Rules

The module provides several rules.

### PowerShell rule

```text
Name        : Block PowerShell
Action      : Deny
```

### Program Files

```text
Name        : (Default Rule) All files located in the Program Files folder
Action      : Allow
```

### Windows folder

```text
Name        : (Default Rule) All files located in the Windows folder
Action      : Allow
```

### Local Administrators

```text
Name        : (Default Rule) All files
Action      : Allow
```

The last rule allows members of the local Administrators group to run applications.

---

# 🧠 12. AppLocker Mental Model

Think of AppLocker as:

```text
                Application
                     ↓
              AppLocker Rules
                     ↓
          ┌──────────┴──────────┐
          ↓                     ↓
       ALLOW                   DENY
          ↓                     ↓
       Execute                Block
```

When enumerating it, ask:

1. What is blocked?
    
2. Who is affected?
    
3. What paths are affected?
    
4. Are there exceptions?
    
5. What applications are allowed?
    
6. Are administrators treated differently?
    

---

# ⚙️ 13. PowerShell Constrained Language Mode

![Image](https://images.openai.com/static-rsc-4/ye0RCd_k5vBL7SH13IqyyiIzX7cpnA0nCCRFf-FsAmf5yFX9JDi0iB4FE6Ltxplpb1-rjr2j_GA0phsNvNHU56zOUuKkfZVz0UnIbuzQ4N5oQ0_6u7e8a-Xo2HsuOFpNr5a1X1m99Kzdp45XqSbKkB0vwW2pYFrDan-poG8DbGQd_qua-JwLDqHt_h02PgwY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TsC3GnnDPTN38wW62GFsd6UjAEm-ijpTi-nrQuV_5Vs6oMSSV1FlE2VxZ3fxpm5zxc9EnRrKUBrfZVWlTxAJbU1MuZiZVRxnrhBq82Ls9l6xiVvFKKdXqYAhLh7jJ28xBBz2IWJ2_zJ1FUYUYXCRZCUU_Rnkx6IonEogOxLz1r239qnuXPc_TJQWE24J9XeO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nnoMY6nGq2jm39N6c38Vzo9E9vNojohzRDDzZKxmbVpoUQ8Fz50D7RonTHe7g8dvLrsBpwN9XCql8KL3R0sa3HqNML6lhKSWT_Y_eg0aFiiqL43F8XT7XdHpPZQKNMUVYvlP0gAQltKAhfpgxh3BgauA2MXL6hXXnJcEsaJRVkwiI394fOZxnTrZux-CEsjV?purpose=fullsize)

PowerShell has different language modes.

One important security control is:

```text
ConstrainedLanguage
```

The module explains that Constrained Language Mode restricts many PowerShell features, including:

- COM objects
    
- Certain .NET types
    
- XAML-based workflows
    
- PowerShell classes
    
- Other functionality useful for advanced scripting
    

---

# 14. Checking PowerShell Language Mode

Command:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

Example output:

```text
ConstrainedLanguage
```

This immediately tells us the current PowerShell session is operating in constrained mode.

---

# 15. Full vs Constrained Language

At a high level:

```text
FullLanguage
     ↓
Normal PowerShell functionality
```

versus:

```text
ConstrainedLanguage
     ↓
Restricted PowerShell functionality
```

Therefore, after gaining a PowerShell foothold, checking:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

is a useful situational-awareness step.

---

# 🧠 16. Why Language Mode Matters

Suppose your normal workflow requires:

```text
PowerShell
    ↓
.NET functionality
    ↓
COM
    ↓
Advanced scripting
```

Constrained Language Mode may restrict some of those capabilities.

So the control can influence:

- Enumeration
    
- Script execution
    
- Tool functionality
    
- Post-exploitation options
    

This is why the module places it alongside Defender and AppLocker.

---

# 🔑 17. LAPS

![Image](https://images.openai.com/static-rsc-4/FsNQl9VuuzylYb_K1tl3s0jPAL6i-GH0A35FNHifr07xqb0e6ipAGhVBrgTGHF0Ik61wqXlK2aEx7hUkYUazOw-twbwV1MOWo-g34T4KGQ2AaCcv6-B1kH4iCZlMl2fMAt3YmCwvoVuLBSbQWXS9WrCjDz3OJxD5TUUeIFcwgJCZyGbCjLADbGs82JGa_565?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/s2lFlYS9qM41sGtfyFL0-IRSS7LrcP1UMntDP40p1Zd8WrPlr9iqxpDKHhEPk2PSNoCIAnvvol1G6AuFxUkUKhxOWFn74ar1eNyAMxol5Pe9Dj0TxlrDTFgHsu6Lz0UA1WfdZIwUMFP0w0EUXNEGS4OK_ou70_10BUzegf7ICqh5gRxU_cnvndhmZT_BK099?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/d42f_vt5UlKe-BImX-0Pv8Xcdg0BVXHAmtZ_oEh8ILPqnyM-4ef6aht3dqYNhb6_IVVCgQM5e_F1l84NkUkqrHvw5fdzVHvx0uDdmbKch4KZIkYT-5TBzyizVP3e5ke200ywIxeEOnxPT7Q_6wAiFjCpuRDgc38YmdcB6PCRd6WBxOb3KTN77YJD8WdD7oQE?purpose=fullsize)

**LAPS** stands for:

> **Local Administrator Password Solution**

The purpose is to:

- Randomize local administrator passwords
    
- Rotate them
    
- Reduce password reuse
    
- Help prevent lateral movement
    

This directly connects to the previous password-spraying/password-reuse section.

---

# 18. Why LAPS Matters to an AD Assessment

Without LAPS:

```text
WS01 → Administrator → Password123
WS02 → Administrator → Password123
WS03 → Administrator → Password123
```

One compromised local admin credential may work across multiple hosts.

With LAPS:

```text
WS01 → Random password A
WS02 → Random password B
WS03 → Random password C
```

Passwords are managed individually.

Therefore, LAPS can significantly reduce the impact of local administrator password reuse.

---

# 19. LAPS Enumeration

The module introduces **LAPSToolkit** to help enumerate LAPS configuration.

One function is:

```powershell
Find-LAPSDelegatedGroups
```

This looks for groups that have delegated rights related to reading LAPS passwords.

---

# 20. Find-LAPSDelegatedGroups

Command:

```powershell
Find-LAPSDelegatedGroups
```

Example output includes:

```text
OU=Servers,...        INLANEFREIGHT\Domain Admins
OU=Servers,...        INLANEFREIGHT\LAPS Admins
```

and similar entries for:

- Workstations
    
- Web Servers
    
- SQL Servers
    
- File Servers
    
- Contractor Laptops
    
- Staff Workstations
    
- Executive Workstations
    
- Mail Servers
    

---

# 21. What Does "Delegated Group" Mean?

Think:

```text
Computer / OU
      ↓
LAPS permissions
      ↓
Delegated group
      ↓
Members may have permission
      ↓
Potential ability to read LAPS passwords
```

The important security question is:

> **Who has the ability to read the local administrator password for these machines?**

---

# ⚠️ 22. All Extended Rights

The module highlights another important concept:

```text
All Extended Rights
```

An account that joined a computer to the domain can receive **All Extended Rights** over that host.

The module explains that this can give the account the ability to read LAPS passwords.

This means you shouldn't only look for explicitly named groups such as:

```text
LAPS Admins
```

You should also consider **effective rights**.

---

# 23. Find-AdmPwdExtendedRights

The module provides:

```powershell
Find-AdmPwdExtendedRights
```

This checks computers with LAPS enabled for:

- Groups with read access
    
- Users with `All Extended Rights`
    

---

# 24. Example Output

The module shows:

```text
ComputerName                Identity                    Reason
------------                --------                    ------
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\Domain Admins Delegated
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\LAPS Admins   Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\Domain Admins Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\LAPS Admins   Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\Domain Admins Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\LAPS Admins   Delegated
```

This gives you a relationship:

```text
Computer
   ↓
Identity with rights
   ↓
Reason
```

---

# 🔐 25. Get-LAPSComputers

The module then introduces:

```powershell
Get-LAPSComputers
```

This can identify computers with LAPS enabled and provide information such as:

- Computer name
    
- Password
    
- Password expiration
    

---

# 26. Example Output

The module's example:

```text
ComputerName                Password       Expiration
------------                --------       ----------
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:30
SQL01.INLANEFREIGHT.LOCAL   9G#f;p41dcAe,s 09/26/2020 00:30:09
WS01.INLANEFREIGHT.LOCAL    TCaG-F)3No;l8C 09/26/2020 00:46:04
```

### ⚠️ Important

The passwords shown in the HTB example are **lab data**. Don't treat these example values as real credentials for another environment.

---

# 🧠 27. LAPS Enumeration Chain

This is the most important conceptual flow:

```text
                 LAPS
                  |
        +---------+---------+
        |                   |
        v                   v
 Is LAPS enabled?      Who can read it?
        |                   |
        v                   v
Get-LAPSComputers   Find-LAPSDelegatedGroups
                            |
                            v
                  Find-AdmPwdExtendedRights
                            |
                            v
                  Identify privileged access
```

---

# 🔥 28. Complete Security-Control Enumeration Workflow

After gaining a foothold:

```text
                  Foothold
                     |
                     v
          ┌─────────────────────┐
          │ Enumerate Controls  │
          └─────────────────────┘
                     |
       +-------------+-------------+
       |             |             |
       v             v             v
   Defender      AppLocker      PowerShell
       |             |          Language Mode
       |             |             |
       +-------------+-------------+
                     |
                     v
                    LAPS
                     |
                     v
            Understand AD defenses
```

---

# 🧪 29. Commands You Must Know

### Windows Defender

```powershell
Get-MpComputerStatus
```

### AppLocker

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### PowerShell Language Mode

```powershell
$ExecutionContext.SessionState.LanguageMode
```

### LAPS delegated groups

```powershell
Find-LAPSDelegatedGroups
```

### LAPS extended rights

```powershell
Find-AdmPwdExtendedRights
```

### LAPS computers

```powershell
Get-LAPSComputers
```

---

# 🎯 30. What Each Command Answers

|Command|Question it answers|
|---|---|
|`Get-MpComputerStatus`|Is Defender enabled and what protections are active?|
|`Get-AppLockerPolicy -Effective...`|What AppLocker rules actually apply?|
|`$ExecutionContext.SessionState.LanguageMode`|Is PowerShell FullLanguage or ConstrainedLanguage?|
|`Find-LAPSDelegatedGroups`|Which groups are delegated LAPS-related access?|
|`Find-AdmPwdExtendedRights`|Who has relevant extended/read rights?|
|`Get-LAPSComputers`|Which computers use LAPS and what information can my account read?|

---

# 🧠 31. Red Team + Blue Team Perspective

This section is especially useful because every technique has a defensive counterpart.

### Red-team question

> What security controls are affecting my current host?

### Blue-team question

> Can I detect someone enumerating or interacting with these controls?

---

## Defender

```text
Get-MpComputerStatus
        ↓
Understand endpoint protection
```

## AppLocker

```text
Get-AppLockerPolicy
        ↓
Understand application restrictions
```

## PowerShell

```text
LanguageMode
        ↓
Understand scripting restrictions
```

## LAPS

```text
LAPS rights
        ↓
Understand local admin credential protection
```

---

# 📌 32. Important Relationships

### Defender + PowerShell

```text
PowerShell
    ↓
Security tooling
    ↓
Defender
    ↓
Potential detection/blocking
```

### AppLocker + PowerShell

```text
PowerShell executable
       ↓
AppLocker rule
       ↓
Allow / Deny
```

### LAPS + Lateral Movement

```text
Local admin password
       ↓
Unique + rotating?
       ↓
LAPS
       ↓
Reduced password reuse
       ↓
Reduced lateral-movement risk
```

---

# 🔥 33. Must-Memorize Cheat Sheet

```text
WINDOWS DEFENDER
Get-MpComputerStatus
        ↓
RealTimeProtectionEnabled


APPLOCKER
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
        ↓
Effective application-control rules


POWERSHELL CLM
$ExecutionContext.SessionState.LanguageMode
        ↓
ConstrainedLanguage / FullLanguage


LAPS
Find-LAPSDelegatedGroups
        ↓
Delegated LAPS groups

Find-AdmPwdExtendedRights
        ↓
Extended/read rights

Get-LAPSComputers
        ↓
LAPS-enabled computers + accessible information
```

---

# 🧩 34. Final Mentor Takeaway

Don't memorize this section as six random PowerShell commands.

Understand it as **situational awareness after obtaining a foothold**:

```text
             "I have access."
                    ↓
       "What protections exist here?"
                    ↓
       ┌────────────┼────────────┐
       ↓            ↓            ↓
    Defender     AppLocker     PowerShell
       |            |          Language
       +────────────┼────────────+
                    ↓
                   LAPS
                    ↓
       "How are local admin credentials
              being protected?"
                    ↓
          Better understanding of
             the AD environment
```

The module's conclusion is that these techniques help determine what protections are in place and should become part of your assessment toolkit before continuing **credentialed enumeration of the `INLANEFREIGHT.LOCAL` domain**.

### 🧠 One-line memory trick

**D-A-P-L = Defender → AppLocker → PowerShell → LAPS**

That is the order I recommend remembering this section in.