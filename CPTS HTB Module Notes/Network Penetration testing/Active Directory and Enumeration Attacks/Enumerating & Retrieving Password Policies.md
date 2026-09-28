The module focuses on **enumerating Active Directory password policies** from both Linux and Windows, using authenticated and unauthenticated techniques. The main goal is to understand how password-policy information can affect security assessments, especially when evaluating password-spraying risk.

---

## 1. What Is a Password Policy?

A **password policy** is a set of rules configured by an organization that controls how user passwords and account lockouts behave.

Important password-policy settings include:

|Policy|Meaning|
|---|---|
|**Minimum Password Length**|Minimum number of characters required|
|**Password History**|Number of previous passwords remembered|
|**Maximum Password Age**|How long a password can remain valid|
|**Minimum Password Age**|How soon a user can change a password again|
|**Password Complexity**|Whether passwords must contain different character types|
|**Account Lockout Threshold**|Number of failed attempts before lockout|
|**Account Lockout Duration**|How long the account remains locked|
|**Reset Lockout Counter**|Time before failed-attempt counter resets|
|**Force Logoff Time**|Time after which users may be forced to log off|

For penetration testing, these values are important because they tell us how aggressively authentication testing can be performed without unnecessarily locking accounts.

---

# 2. Enumerating Password Policy From Linux — Credentialed

If we have **valid domain credentials**, we can remotely retrieve the domain password policy.

The module demonstrates tools such as:

- `CrackMapExec`
    
- `rpcclient`
    

The example uses:

```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

The output provides information such as:

```text
Minimum password length: 8
Password history length: 24
Maximum password age: Not Set
Password Complexity Flags: 000001
```

And:

```text
Minimum password age: 1 day 4 minutes
Reset Account Lockout Counter: 30 minutes
Locked Account Duration: 30 minutes
Account Lockout Threshold: 5
Forced Log off Time: Not Set
```

These values are directly shown in the module's credentialed enumeration example.

### 🔑 Important interpretation

The example domain has:

- Minimum password length → **8**
    
- Password history → **24**
    
- Maximum password age → **Not Set**
    
- Password complexity → **Enabled**
    
- Minimum password age → **1 day**
    
- Lockout threshold → **5**
    
- Lockout duration → **30 minutes**
    
- Reset counter → **30 minutes**
    

---

# 3. SMB NULL Sessions

One of the most important concepts in this module is the **SMB NULL session**.

### What is an SMB NULL session?

An SMB NULL session is an **unauthenticated SMB connection** where no username/password is supplied.

Historically, certain Windows configurations allowed anonymous users to retrieve information from a domain.

Depending on configuration, this information could include:

- Users
    
- Groups
    
- Computers
    
- User attributes
    
- Domain information
    
- Password policy
    

The module notes that these configurations are often associated with **legacy Domain Controllers that were upgraded in place**, retaining insecure configurations from older Windows Server versions.

---

# 4. Checking SMB NULL Sessions With rpcclient

The module uses:

```bash
rpcclient -U "" -N 172.16.5.5
```

Explanation:

|Option|Meaning|
|---|---|
|`-U ""`|Empty username|
|`-N`|Do not request a password|
|`172.16.5.5`|Target Domain Controller|

After connecting:

```text
rpcclient $> querydominfo
```

Example:

```text
Domain:     INLANEFREIGHT
Total Users:    3650
Total Groups:   0
Total Aliases:   37
Server Role:    ROLE_DOMAIN_PDC
```

This confirms that useful domain information can be retrieved through the session.

---

# 5. Retrieving Password Policy With rpcclient

Once inside `rpcclient`, use:

```text
getdompwinfo
```

Example:

```text
rpcclient $> getdompwinfo

min_password_length: 8
password_properties: 0x00000001
    DOMAIN_PASSWORD_COMPLEX
```

Important:

```text
DOMAIN_PASSWORD_COMPLEX
```

indicates that password complexity is enabled in this example.

### 🧠 Remember

For HTB questions, if you see:

```text
getdompwinfo
```

think:

> **Retrieve domain password information through rpcclient.**

---

# 6. enum4linux

`enum4linux` is another important enumeration tool.

The module describes it as a tool built around the Samba suite, including:

- `nmblookup`
    
- `net`
    
- `rpcclient`
    
- `smbclient`
    

It can enumerate Windows hosts and domains.

### Common ports

|Tool|Port|
|---|---|
|`nmblookup`|UDP 137|
|`nbtstat`|UDP 137|
|`net`|TCP 139, TCP 135, UDP/TCP 135 and 49152–65535|
|`rpcclient`|TCP 135|
|`smbclient`|TCP 445|

---

## 7. Using enum4linux to Retrieve Password Policy

Command:

```bash
enum4linux -P 172.16.5.5
```

The `-P` option is used for **password-policy enumeration**.

Example output:

```text
Minimum password length: 8
Password history length: 24
Maximum password age: Not Set
Password Complexity Flags: 000001
```

Then:

```text
Minimum password age: 1 day 4 minutes
Reset Account Lockout Counter: 30 minutes
Locked Account Duration: 30 minutes
Account Lockout Threshold: 5
Forced Log off Time: Not Set
```

### ⭐ HTB memory point

```bash
enum4linux -P <IP>
```

→ Password policy enumeration.

---

# 8. enum4linux-ng

`enum4linux-ng` is a Python rewrite of `enum4linux`.

It provides additional functionality, including:

- Colored output
    
- YAML output
    
- JSON output
    
- Easier processing of enumeration results
    

### Command

```bash
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

Here:

```text
-P
```

means password-policy enumeration.

```text
-oA ilfreight
```

causes the results to be saved for further processing, including JSON/YAML output.

---

# 9. Understanding enum4linux-ng Output

The module shows:

```text
[*] Check for null session
[+] Server allows session using username '', password ''
```

This is an important finding.

It means:

> The server permits an SMB/RPC session without credentials.

The tool also identifies domain information:

```text
Domain: INLANEFREIGHT
SID: S-1-5-21-3842939050-3880317879-2865463114
Host is part of a domain (not a workgroup)
```

And:

```text
NetBIOS computer name: ACADEMY-EA-DC01
NetBIOS domain name: INLANEFREIGHT
DNS domain: INLANEFREIGHT.LOCAL
FQDN: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

---

# 10. enum4linux-ng Password Policy Output

The useful section is:

```text
domain_password_information:
  pw_history_length: 24
  min_pw_length: 8
  min_pw_age: 1 day 4 minutes
  max_pw_age: not set
```

Password properties:

```text
DOMAIN_PASSWORD_COMPLEX: true
DOMAIN_PASSWORD_NO_ANON_CHANGE: false
DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
```

Lockout information:

```text
lockout_observation_window: 30 minutes
lockout_duration: 30 minutes
lockout_threshold: 5
```

---

# 11. JSON Output

The `-oA` option is particularly useful because enumeration results can be stored and processed later.

Example:

```bash
cat ilfreight.json
```

The JSON contains information such as:

```json
"credentials": {
    "user": "",
    "password": ""
}
```

and:

```json
"services": {
    "SMB": {
        "port": 445,
        "accessible": true
    }
}
```

It also records:

```json
"null_session_possible": true
```

### Why is this useful?

Instead of manually copying enumeration results, you can:

1. Save them.
    
2. Process them with scripts.
    
3. Feed the results into another tool.
    
4. Maintain structured assessment data.
    

---

# 12. Enumerating NULL Sessions From Windows

You can also test for NULL sessions directly from Windows.

The module uses:

```cmd
net use \\DC01\ipc$ "" /u:""
```

If successful:

```text
The command completed successfully.
```

This establishes a NULL session to the IPC$ share.

### Important syntax

```text
net use \\HOST\ipc$ "" /u:""
```

Think:

> **Windows equivalent for testing an anonymous IPC$ connection.**

---

# 13. Common Authentication Errors

The module demonstrates three useful Windows errors.

### A. Account Disabled

```cmd
net use \\DC01\ipc$ "" /u:guest
```

Result:

```text
System error 1331 has occurred.

This user can't sign in because this account is currently disabled.
```

---

### B. Incorrect Password

```cmd
net use \\DC01\ipc$ "password" /u:guest
```

Result:

```text
System error 1326 has occurred.

The user name or password is incorrect.
```

---

### C. Account Locked

```cmd
net use \\DC01\ipc$ "password" /u:guest
```

Result:

```text
System error 1909 has occurred.

The referenced account is currently locked out and may not be logged on to.
```

### 🧠 Memorize

|Error|Meaning|
|---|---|
|**1331**|Account disabled|
|**1326**|Username/password incorrect|
|**1909**|Account locked|

---

# 14. LDAP Anonymous Bind

Another unauthenticated technique is an **LDAP anonymous bind**.

![Image](https://images.openai.com/static-rsc-4/WADPXCYsf3kpJaOTpM3ZUZy6WP3QYcvnL37QSDFKLuaaEpYjIaRt9GYyJpgPKG4Chd2WWDVL1XwQgSrh_NWqEBuzQC1XHBtxUN9kbv9Gz86yO4T3TaJj2bNH39pWhiykqUnEanFBFUjQJL1y3KqYMXtnEIZh8zZTfGdCZpz6iatLMViLRbW47Dwvo9k97kwN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tP9twnqjL-i7csJ56hxIjPyYhxG5DdrzkMrhf2xb7PNH6Q5pIIpI9E1hRsw7EZQuBNtMEShzMAVcqoweqG2bQqnFS5pjuXHMa6Z3dWFl9Hp0lN2BtW-Y5mx4D5dia9B3sW8yH6z43bQbLMLNkVbC3M1XVxDmRJpkx6zieCpIP7LUMpEOeoXTON0VOnUCgdDH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_zxx9NYv1wv9XHND7PwmHm0PvJs8xZrng4q7h_aHqqAAMpqNlmma-rlsPgJ5Ia3_Qa-eYDuDqDYZypUoJqTLWokucJ4QcT9PwE9mIdu4XKnEAC27k2iaO7kRkQoEGV4CNHKXlYUzM4q4Xnsmkq2SdQA-hbiZVXgwitfdeQT4YRC7l2hYxSFmRts1Rqft68vI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/A-TU82QSe-gypLAqIeceK6ZsVij22d90tfUtyug9mGJhU4rA4nUlATnk62CG8D2Flmsz8d3x91aTRFw58B0OUPjFvHRU4vETROeWnwudSgqLvxT-UxcsrKOmlG_kCAergUNYUdO16WjiLaCRNID8HA5G224wRRS8VrIFOtNq-aPFkDfr4rhcQ59TBjA5V-7S?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cniUW1ueMTVO2nLTlD5fyvVtD41ZN94xwDu6A0LgXXiitc_obA0_A1F4zwOy44brYYlMmfZsbUtoSydGAjhF9h_FuWpdJJMsNhsaQE9dAAYhGtklTTda3Y4u36SIMrQIF-IIj3DZxB4XZzF1HK6qh_hVKo5rriNo6w5lSW5ILxdnsJiXe86zaB-64XeZX3M0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QlL72qLFpiItG3Py5k5ue02X0JG6sME3y2ljOtIAFvswM-1n4w2aJhLxp-nnuW0HFhwh9_t6xK9Kf-VbEsiTDQpvCgT8NV8xlKBx29dYYWAeUm_CpTfWQ9L34C3u9Ez9UWJzB05kWTrumMs9OP-GXvKBB_mxPSNGWan9oXoJyp9x_tLfHGm9CEe-lT_jjTeI?purpose=fullsize)

LDAP anonymous binds can potentially expose:

- Users
    
- Groups
    
- Computers
    
- User attributes
    
- Password policy
    

The module describes this as a **legacy configuration**. Modern Windows Server configurations generally require authenticated users for LDAP requests, although improperly configured environments can still expose anonymous access.

---

# 15. LDAP Enumeration Tools

The module mentions:

- `windapsearch.py`
    
- `ldapsearch`
    
- `ad-ldapdomaindump.py`
    

One example uses:

```bash
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

The resulting attributes include:

```text
lockoutThreshold: 5
maxPwdAge: ...
minPwdAge: ...
minPwdLength: 8
pwdProperties: 1
pwdHistoryLength: 24
```

### Important note

The module notes that newer versions of `ldapsearch` deprecated `-h` in favor of:

```bash
-H
```

---

# 16. Understanding LDAP Password Attributes

These are worth memorizing:

|LDAP Attribute|Meaning|
|---|---|
|`minPwdLength`|Minimum password length|
|`pwdHistoryLength`|Password history length|
|`maxPwdAge`|Maximum password age|
|`minPwdAge`|Minimum password age|
|`pwdProperties`|Password-property flags|
|`lockoutThreshold`|Failed attempts before lockout|
|`lockoutDuration`|Lockout duration|
|`lockOutObservationWindow`|Lockout counter observation/reset window|
|`forceLogoff`|Forced logoff setting|

For this example:

```text
minPwdLength: 8
lockoutThreshold: 5
pwdProperties: 1
pwdHistoryLength: 24
```

The module interprets `pwdProperties: 1` as password complexity being enabled.

---

# 17. Enumerating Password Policy From Windows

If we have access to a Windows system and can authenticate to the domain, we can use built-in Windows tools.

The module specifically introduces:

```cmd
net.exe
```

Other tools include:

- PowerView
    
- SharpView
    
- CrackMapExec
    
- SharpMapExec
    

Using built-in tools can be useful when transferring additional tools to the target is undesirable or impossible.

---

# 18. `net accounts`

The basic command is:

```cmd
net accounts
```

Example:

```text
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Unlimited
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
```

---

# 19. Interpreting `net accounts`

From the example:

### Maximum password age

```text
Unlimited
```

→ Passwords do not expire according to this policy.

### Minimum password length

```text
8
```

→ Relatively short passwords are permitted.

### Lockout threshold

```text
5
```

→ Five failed attempts trigger account lockout.

### Lockout duration

```text
30 minutes
```

→ Locked accounts remain locked for 30 minutes before automatic unlocking in this configuration.

These interpretations are explicitly discussed in the module.

---

# 20. Password Complexity

Password complexity does **not necessarily mean a password is strong**.

The module explains that complexity can require a password to contain **3 of 4** character categories:

1. Uppercase
    
2. Lowercase
    
3. Number
    
4. Special character
    

For example:

```text
Password1
```

or:

```text
Welcome1
```

can satisfy complexity requirements while still being weak/common passwords.

### 🔥 Important concept

> **Complexity ≠ Strong password**

A password can technically satisfy complexity requirements and still be predictable.

---

# 21. PowerView

PowerView can retrieve domain policy information.

First:

```powershell
import-module .\PowerView.ps1
```

Then:

```powershell
Get-DomainPolicy
```

Example output:

```text
SystemAccess :
@{
    MinimumPasswordAge=1;
    MaximumPasswordAge=-1;
    MinimumPasswordLength=8;
    PasswordComplexity=1;
    PasswordHistorySize=24;
    LockoutBadCount=5;
    ResetLockoutCount=30;
    LockoutDuration=30;
}
```

---

# 22. Important PowerView Values

|PowerView value|Meaning|
|---|---|
|`MinimumPasswordAge`|Minimum password age|
|`MaximumPasswordAge`|Maximum password age|
|`MinimumPasswordLength`|Minimum length|
|`PasswordComplexity`|Complexity requirement|
|`PasswordHistorySize`|Password history|
|`LockoutBadCount`|Lockout threshold|
|`ResetLockoutCount`|Reset observation period|
|`LockoutDuration`|Lockout duration|
|`ClearTextPassword`|Cleartext password storage setting|

The output also reveals the relevant GPO:

```text
GPODisplayName : Default Domain Policy
```

---

# 23. Password Policy Enumeration — Big Picture

Think of the entire module like this:

```text
                 Active Directory
                       |
             +---------+---------+
             |                   |
        Have credentials?    No credentials?
             |                   |
             v                   v
        Credentialed       Look for exposed
        enumeration        anonymous access
             |                   |
      +------+-------+      +----+----+
      |              |      |         |
 CrackMapExec    rpcclient  SMB NULL  LDAP
      |              |      session   anonymous
      |              |      |         |
      +------+-------+      +----+----+
             |                   |
             +---------+---------+
                       |
                       v
              Password Policy
                       |
       +---------------+---------------+
       |               |               |
   Password        Lockout         Complexity
   requirements    settings        requirements
       |               |               |
       +---------------+---------------+
                       |
                       v
             Security Assessment
```

---

# 24. Analyzing the Example Domain

The module analyzes the `INLANEFREIGHT.LOCAL` policy.

### Minimum password length

```text
8
```

Eight characters is relatively common, although organizations increasingly use longer minimums such as 10–14 characters.

### Lockout threshold

```text
5
```

Five failed attempts trigger lockout.

### Lockout duration

```text
30 minutes
```

The example automatically unlocks accounts after the duration.

### Password complexity

```text
Enabled
```

The policy requires complexity, but complexity alone doesn't guarantee strong passwords.

These points are explicitly discussed in the module's analysis section.

---

# 25. Default Domain Password Policy

The module gives the following default values when a new domain is created:

|Policy|Default Value|
|---|--:|
|Enforce password history|24 days|
|Maximum password age|42 days|
|Minimum password age|1 day|
|Minimum password length|7|
|Password complexity|Enabled|
|Reversible encryption|Disabled|
|Account lockout duration|Not set|
|Account lockout threshold|0|
|Reset account lockout counter|Not set|

### ⚠️ Important distinction

The module's **example environment** has:

```text
Minimum password length = 8
Lockout threshold = 5
Lockout duration = 30 minutes
```

while the **default newly created domain policy** shown later has:

```text
Minimum password length = 7
Lockout threshold = 0
```

Do not mix these two sets of values.

---

# 26. Why Password Policy Matters to a Pentester

Password-policy enumeration gives us information about the authentication security of an Active Directory environment.

For example:

```text
Minimum length       → How short passwords can be
Complexity            → Required character categories
History               → Password reuse restrictions
Lockout threshold     → Failed-attempt tolerance
Lockout duration      → How long accounts remain locked
Maximum age           → Password expiration behavior
```

This information helps determine the **risk associated with authentication attacks**.

---

# 27. Password Spraying — Critical Safety Concept

The module's next step is to create a user list and assess password-spraying risk.

However, **account lockout must be avoided**.

The module specifically states that if the password policy cannot be obtained, testers should exercise extreme caution. It recommends, in an authorized assessment, at most one or two spraying attempts and waiting over an hour between attempts if two attempts are made.

### 🚨 Mentor rule

Never think:

> "The threshold is 5, so I can simply try 5 passwords."

Instead, understand:

> **The password policy is a safety boundary.**

A penetration tester should avoid causing account lockouts or operational disruption.

The module summarizes this very clearly:

> **“We do not want to be the pentester that locks out every account in the organization!”**

---

# 28. Tool Cheat Sheet

## Linux — Credentials Available

```bash
crackmapexec smb <IP> -u <USER> -p <PASSWORD> --pass-pol
```

```bash
rpcclient -U "<USER>" -N <IP>
```

Then:

```text
getdompwinfo
```

---

## Linux — SMB NULL Session

```bash
rpcclient -U "" -N <IP>
```

Then:

```text
querydominfo
```

and:

```text
getdompwinfo
```

---

## enum4linux

```bash
enum4linux -P <IP>
```

---

## enum4linux-ng

```bash
enum4linux-ng -P <IP> -oA <OUTPUT_NAME>
```

---

## LDAP Anonymous Bind

```bash
ldapsearch -H ldap://<IP> -x -b "DC=DOMAIN,DC=LOCAL" -s sub "*"
```

The module's original example uses `-h`; newer versions use `-H`.

---

## Windows

```cmd
net use \\DC01\ipc$ "" /u:""
```

Password policy:

```cmd
net accounts
```

---

## PowerView

```powershell
Import-Module .\PowerView.ps1
```

```powershell
Get-DomainPolicy
```

---

# 🧠 29. Must-Memorize Commands

If you're preparing for an HTB module assessment, remember these first:

```bash
crackmapexec smb <IP> -u <USER> -p <PASS> --pass-pol
```

```bash
rpcclient -U "" -N <IP>
```

```text
querydominfo
```

```text
getdompwinfo
```

```bash
enum4linux -P <IP>
```

```bash
enum4linux-ng -P <IP> -oA <NAME>
```

```bash
ldapsearch -H ldap://<IP> -x -b "DC=DOMAIN,DC=LOCAL" -s sub "*"
```

```cmd
net use \\DC01\ipc$ "" /u:""
```

```cmd
net accounts
```

```powershell
Get-DomainPolicy
```

---

# 🎯 30. HTB Exam/Viva Questions

### Q1. What is an SMB NULL session?

An unauthenticated SMB session that may allow enumeration of domain information when the target is misconfigured.

### Q2. Which `rpcclient` command retrieves password information?

```text
getdompwinfo
```

### Q3. Which `rpcclient` command retrieves domain information?

```text
querydominfo
```

### Q4. Which enum4linux option retrieves password-policy information?

```bash
-P
```

### Q5. What does `-oA` do in enum4linux-ng?

It saves enumeration results in structured output formats such as JSON/YAML.

### Q6. What command retrieves password policy from Windows?

```cmd
net accounts
```

### Q7. Which PowerView command retrieves domain policy?

```powershell
Get-DomainPolicy
```

### Q8. What does `minPwdLength` represent?

Minimum password length.

### Q9. What does `pwdHistoryLength` represent?

Number of previous passwords maintained in password history.

### Q10. What does `lockoutThreshold` represent?

Number of failed authentication attempts before an account is locked.

### Q11. What does `PasswordComplexity=1` indicate?

Password complexity is enabled.

### Q12. What does `System error 1909` indicate?

The referenced account is currently locked out.

### Q13. What does `System error 1331` indicate?

The account is disabled.

### Q14. What does `System error 1326` indicate?

The username or password is incorrect.

---

# 🧩 31. The Methodology You Should Remember

When you encounter an Active Directory environment:

```text
          Identify Domain Controller
                    ↓
          Determine available access
                    ↓
       ┌────────────┴────────────┐
       ↓                         ↓
 Credentials available      No credentials
       ↓                         ↓
 Credentialed enumeration   Test permitted
       ↓                     anonymous access
       ↓                         ↓
 CrackMapExec/rpcclient     SMB NULL / LDAP
       ↓                         ↓
       └────────────┬────────────┘
                    ↓
            Retrieve policy
                    ↓
       Analyze password settings
                    ↓
          Check lockout controls
                    ↓
      Plan assessment carefully
```

The key mindset is:

> **Enumerate first → understand the policy → assess safely → avoid unnecessary account lockouts.**

---

# 🔥 Final Revision Sheet

If you only have **5 minutes before an HTB exercise**, remember:

### SMB

```text
445/TCP → SMB
139/TCP → SMB over NetBIOS
```

### NULL session

```bash
rpcclient -U "" -N <IP>
```

### Domain information

```text
querydominfo
```

### Password policy

```text
getdompwinfo
```

### enum4linux

```bash
enum4linux -P <IP>
```

### enum4linux-ng

```bash
enum4linux-ng -P <IP> -oA output
```

### LDAP

```bash
ldapsearch -H ldap://<IP> ...
```

### Windows

```cmd
net accounts
```

### PowerView

```powershell
Get-DomainPolicy
```

### Important policy fields

```text
Minimum password length
Password history
Maximum password age
Minimum password age
Password complexity
Lockout threshold
Lockout duration
Lockout observation/reset window
```

### Critical mindset

**Password complexity does not automatically mean strong passwords.**

**Never intentionally lock out accounts during an authorized assessment.**

**Always understand the lockout policy before authentication testing.**

---

## 🧑‍💻 Mentor Mode: Next Step

These notes cover the module content. **Don't jump straight to memorizing commands.** For the exercises, I'll make you reason through:

**Target → Access level → Enumeration method → Command → Output → Interpretation → Next action**

Send me **Exercise 1 / the first question from the module**, and we'll solve it together step-by-step rather than me simply giving you the answer.