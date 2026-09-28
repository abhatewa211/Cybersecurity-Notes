## 1. Module Objective

In the previous section, we performed password spraying from a **Linux host**.

This section covers performing the same type of activity from a **domain-joined Windows host**.

The primary tool introduced is:

```text
DomainPasswordSpray
```

It is a PowerShell-based tool designed for password spraying against Active Directory environments.

---

# 🪟 2. Why Spray From Windows?

Imagine we obtain a foothold on a Windows workstation that is already joined to the organization's domain.

Our position might look like:

![Image](https://images.openai.com/static-rsc-4/h87GFzEBLD9YWw-9CRpw3W8oJrp_Xkxntk-zKFe2XBmrE-qMYtU_Q9nYyyKhJjHfT3-dad5wwCvTkC-NxmAsqq-5w52YVtxqVXjf_T9gsA4KvrFrTCk0SnKZc6HoXw579ihzNyIS2lMde4zbCqXzOYFU1T8fBLJOF7aKUwvxRtI0hL2gCu4qfKnqhFIawnzz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mYHrtfxbA0kYWFik1SN36uyfv4hTWy-UaD2jyPd8Y4W615VOW4ErKcKCS2YhRAO_Pt7yHgcIuhdQqCUIX_mFJhSWKOadCydSMXc5ep-aLn2YzSFOC6M3OQA8sIH9GYhG88vsGYuuvTVhRS64LGkUxpsvnpgEste91UHaEtbkws_sEFGiBWR2MPHl8s4sDl6p?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EDVUJFmNGUW8asJpz32LGnOIHBllzr_QuZuz5m70c_h-Y17A0TbDK2jlrPhnGkPhDLUWICskF2YBeABohlTVwrrRQLPXMDlJPyukGwenlLTjGO9h4RnDgMFsuBxLl1RnBXTHPNwCM6UhbNWFdATgvWw5BN8wPGl3o6qsGf6KR9VMwJu0nauV0Wz1AAO0sUzL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/b8FMzP4HdLd0ldAolSOXTcWSbdVA_vIe0gsGW3M3lZoHTogpkHgEMg1FZ11ZFr5JMJ2oSjW2hpOq9pA8pzdeGRoVYZsUCYJSIREIRoU1vJRIQWLVNEwOtM9n9oaNjVroscT2phPAOQ1JExAPGOOGATy8BrFyXgilEvfnBHKGfV4NHEh-4YylFTPe9hUuviZu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_zxx9NYv1wv9XHND7PwmHm0PvJs8xZrng4q7h_aHqqAAMpqNlmma-rlsPgJ5Ia3_Qa-eYDuDqDYZypUoJqTLWokucJ4QcT9PwE9mIdu4XKnEAC27k2iaO7kRkQoEGV4CNHKXlYUzM4q4Xnsmkq2SdQA-hbiZVXgwitfdeQT4YRC7l2hYxSFmRts1Rqft68vI?purpose=fullsize)

```text
             Active Directory Domain
                     |
              Domain Controller
                     |
        +------------+------------+
        |            |            |
       PC01         PC02        Server
        |
   Our foothold
        |
        v
 DomainPasswordSpray
```

The module gives several possible situations:

- Testing from a managed Windows device
    
- Testing from a Windows VM inside the network
    
- Being physically on-site
    
- Obtaining an initial foothold on a domain host
    
- Attempting to obtain credentials for an account with greater domain rights
    

---

# 🔥 3. DomainPasswordSpray

The tool introduced by the module is:

```text
DomainPasswordSpray
```

The important advantage is that when you're **authenticated to the domain**, it can automatically:

```text
1. Generate a user list
2. Query the domain password policy
3. Exclude accounts close to lockout
4. Perform the password spray
5. Record successful credentials
```

This makes the tool particularly useful from a domain-joined Windows host.

---

# 4. Authenticated vs Unauthenticated Windows Host

There are two situations to understand.

### Situation 1 — Authenticated

If the Windows host is domain-joined and we are authenticated:

```text
DomainPasswordSpray
        ↓
Automatically obtain users
        ↓
Query password policy
        ↓
Remove risky accounts
        ↓
Spray
```

The module says we can therefore skip:

```text
-UserList
```

because the tool can generate the user list itself.

---

### Situation 2 — Not authenticated

If we are on a Windows host but don't have domain authentication, the module says we can supply our own user list.

Conceptually:

```text
Unauthenticated Windows host
          |
          v
   Existing user list
          |
          v
 DomainPasswordSpray
```

---

# 5. Importing DomainPasswordSpray

The module begins with:

```powershell
Import-Module .\DomainPasswordSpray.ps1
```

This loads the PowerShell module into the current PowerShell session.

Think of it as:

```text
PowerShell
    ↓
Import .ps1
    ↓
Functions become available
```

---

# 6. Running the Tool

The module's example:

```powershell
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

Let's break this down.

|Option|Purpose|
|---|---|
|`Invoke-DomainPasswordSpray`|Executes the password spray|
|`-Password Welcome1`|Specifies the single password|
|`-OutFile spray_success`|Saves successful results|
|`-ErrorAction SilentlyContinue`|Suppresses non-critical error messages|

The important point is that **one password** is being tested against many users.

---

# 🧠 7. Automatic Password Policy Detection

The tool reports:

```text
[*] Current domain is compatible with Fine-Grained Password Policy.
```

This tells us the domain supports **Fine-Grained Password Policy (FGPP)**.

FGPP allows password and lockout settings to be applied more granularly than a single domain-wide policy.

The tool takes this into consideration when preparing the spray.

---

# 8. Automatic User Enumeration

The tool says:

```text
[*] Now creating a list of users to spray...
```

It then reports:

```text
[*] There are 2923 total users found.
```

So the tool automatically retrieves the domain users instead of requiring us to provide a username file.

---

# 9. Removing Disabled Users

The tool reports:

```text
[*] Removing disabled users from list.
```

This is important because disabled accounts aren't useful authentication targets.

Conceptually:

```text
2923 users
    ↓
Remove disabled accounts
    ↓
Eligible accounts
```

---

# 🚨 10. Lockout Threshold

The example reports:

```text
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
```

This is **one of the most important lines in the output**.

The tool is determining how many failed authentication attempts could cause an account to lock.

The module then reports:

```text
[*] Removing users within 1 attempt of locking out from list.
```

Therefore:

```text
Lockout threshold
        ↓
Check account state
        ↓
Remove risky accounts
        ↓
Continue with safer target list
```

This is one of the major advantages of using a tool that understands the domain's password policy.

---

# 11. User List Creation

The tool finally reports:

```text
[*] Created a userlist containing 2923 users gathered from the current user's domain
```

So the workflow is:

```text
Domain
  ↓
Enumerate users
  ↓
Remove disabled accounts
  ↓
Check lockout risk
  ↓
Create target list
```

---

# ⏱️ 12. Observation Window and Spray Timing

The tool also checks the domain password policy's observation window:

```text
[*] The domain password policy observation window is set to [time] minutes.
```

Then it determines the waiting period:

```text
[*] Setting a [time] minute wait in between sprays.
```

The purpose is to account for the domain's password-policy timing rather than blindly sending authentication attempts.

### 🧠 Remember

Password spraying is not simply:

```text
Try → Try → Try → Try
```

It should consider:

```text
Policy
  ↓
Lockout threshold
  ↓
Observation window
  ↓
Wait interval
  ↓
Next spray
```

---

# 13. Confirmation Prompt

Before starting, the tool asks:

```text
Are you sure you want to perform a password spray against 2923 accounts?

[Y] Yes
[N] No
[?] Help
```

This is a useful safety mechanism.

It gives the operator one final opportunity to review the scope before authentication attempts begin.

---

# 14. Password Spray Begins

The module's output:

```text
[*] Password spraying has begun with 1 passwords
```

Notice:

```text
1 password
```

That's the defining characteristic of password spraying.

```text
ONE password
      ↓
MANY accounts
```

The tool then reports:

```text
[*] Now trying password Welcome1 against 2923 users.
```

---

# 15. Successful Accounts

The module's example finds:

```text
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1
```

These are the successful credential pairs.

The tool then writes the results to:

```text
spray_success
```

This is why the `-OutFile` option is useful.

---

# 16. Password Spray Completion

At the end:

```text
[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success
```

The overall workflow becomes:

```text
Import tool
    ↓
Determine domain
    ↓
Enumerate users
    ↓
Check password policy
    ↓
Remove risky accounts
    ↓
Confirm scope
    ↓
Password spray
    ↓
Save successes
```

---

# 17. Kerbrute on Windows

The module also states that **Kerbrute** can be used to perform the same username enumeration and spraying steps discussed previously.

The provided Windows host contains the tool in:

```text
C:\Tools
```

So you should connect the previous Linux section with this section:

```text
Linux
 ├── Kerbrute
 ├── rpcclient
 └── CrackMapExec

Windows
 ├── DomainPasswordSpray
 └── Kerbrute
```

---

# 🛡️ 18. Mitigations

The module emphasizes that there is **no single solution** that completely prevents password spraying.

Instead, organizations should use a:

> **Defense-in-depth approach**

The module gives four major mitigation areas.

---

# 19. Multi-Factor Authentication

### Technique

```text
Multi-factor Authentication
```

MFA can significantly reduce the risk of password spraying because knowing the username and password alone may not be sufficient.

Examples mentioned by the module include:

- Push notifications
    
- Rotating OTP
    
- Google Authenticator
    
- RSA key
    
- SMS confirmations
    

### ⚠️ Important limitation

MFA doesn't necessarily hide whether a username/password combination is valid.

An application may still reveal information that allows an attacker to determine whether the credentials themselves are valid.

Therefore, MFA should be implemented across relevant external portals.

---

# 20. Restricting Access

The module recommends restricting application access according to the user's role.

The principle is:

> **Least privilege**

For example:

```text
100 domain users
      ↓
Application
      ↓
Only 20 actually require access
```

Instead of allowing all 100 users to authenticate to the application, access should be limited to those who need it.

---

# 21. Reducing Impact of Successful Exploitation

The module recommends several approaches.

### Separate administrative accounts

Privileged users should have a separate account for administrative activities.

Conceptually:

```text
Normal account
    ↓
Daily activities

Admin account
    ↓
Administrative tasks
```

This reduces the exposure of highly privileged credentials.

---

### Application-specific permissions

Where possible, applications should implement permission levels appropriate to each user's role.

---

### Network segmentation

Network segmentation can limit lateral movement.

Example:

![Image](https://images.openai.com/static-rsc-4/JvrdQmASorwVdfzaiOxxk-LV3BPpZ8IwW0AivEH4407hIccwRUdukEuTiNB5AJ594fbtgL7gkHgl17ArQCpFVyb86N9YH37bHYSg6Yjl4v6P4R1otAx55WBaU2TtPMq9-B9vZQlETVwdIS5xnH9DZAkW1tAlMyDotRvP6bXqEc9Id9WA5rE2bQTuGZmq0U2C?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/m48cfOWmy7WfeMCjE_ohmaKu2fpMEZg_YAZuzcm6SpYf7N3czEIRn4VxHxRJ5FBS2_P55Xq17opjeE3NwdwfkvN4g2RKZMuaevUVmyMy_EHhW7ynyisYtzapZ9Eoi_IrrGMit4CBWsMRKCJ32G35SHPcJI4hUm6Ty14Ht22S0FG9LAGKsCNo4PXauIEenoAA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bSSctj8cQPxCRJY33MXqL2mM3TxLzshmSaE38nxgZp2AG0Z0EItD1f7UC4-ScSgcxNHqCZQS7dZlMTSwjIQWQIqAdz-HZYusVTfuYm_Zgq2MBuQ97PmOs8n3hXhxgBY4C7Gg4iafCQsWqfvgj9u1PkIAacRHVhXHGAdzD6ZN0uOMD3GBuLuBpPjHPkAv_cmP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ALOahyviIScZ5jNs0jI7iQPKf5WlZTZYmH0gm-m3u9EHCcm856uGY1y6PMa470xfHaTXqHXrU79OP9jr8bcdoyA2IzWKzqi1WaB2wb_lDj3EJnchPki2B39xgLO1dNi688AcKHKgloaX4qmb4PCoGON_-PzHFGV7QZXZQnWRM1he9JkgOuOd_fJknqnVAKhV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rO62Y2ylvWbaoahXQl90d7kLRfAgDhZF5qw-qfMh2R4jfalvami87IPhki1w4h7q4BkyGPccK-XlmK48za0itdqD7l98HV0lG2P5_hL7oZpPikLRFVgePA3lraiEaPfntB3EoIErk7B2wn2zXsFjDwfklBonTj7miiJ4iNTPNbVZbjKt9h8clu4O36AvljW-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/72FKFMQHDOF08EoEJEJeXwnrNv387RCoyNEcXPT8j71dSS2ndK5jZbUxuyajnRNocaUM_fvksHCFbRoIQs7Q1g-ghxHEEWYoCQGdkX19DH0ATUdT6Nv16Xz_GlR7p9_wAffnuoa2pb6W63kim2F7qHnSNhzRQ3T8IfejKGO-U5rj6EXUl7WeV3Hvd0mIvJyp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1f6gOoGEjtNsr50YHCR0b2bZQbA8gDqG6_SD4q6s13IG0cpuNi4UzQHIh0BZCrpmfbA7_Ko4Ww_ZTYO0J_tL7inUa6eYuf7XkIq7VxpzuVR41AAH-qeKHln1hra9LkYa2LiuXRWd4HLy7tZS_mxla7rKyn8C3CFrz9a2--fPbZCysn71ENHcZAfCeZSPvAYo?purpose=fullsize)

```text
Compromised workstation
        ↓
User subnet
        X
Server subnet
        X
Domain administration subnet
```

If an attacker becomes isolated to one subnet, segmentation can slow or prevent further compromise.

---

# 22. Password Hygiene

The module recommends educating users to select difficult-to-guess passwords, including **passphrases**.

It also recommends password filters that restrict common patterns such as:

- Dictionary words
    
- Names of months
    
- Names of seasons
    
- Variations of the company's name
    

### Why?

Password spraying often relies on the fact that organizations contain users who choose predictable passwords.

Conceptually:

```text
Weak/common password
        +
Large user population
        ↓
Higher probability of a match
```

Better password hygiene reduces this risk.

---

# ⚠️ 23. Other Considerations — Account Lockout

The module gives an important warning:

> The domain password lockout policy itself can increase the risk of denial-of-service attacks.

Imagine:

```text
Lockout threshold = restrictive
        ↓
Attacker sprays incorrect password
        ↓
Many accounts fail authentication
        ↓
Many accounts lock
        ↓
Users cannot log in
```

If administrators must manually unlock every account, the operational impact can be significant.

Therefore, organizations need to balance:

```text
Security
   ↕
Availability
```

when designing lockout policies.

---

# 🔎 24. Detection

Defenders should understand what password spraying looks like in logs.

The module identifies several indicators:

- Many account lockouts within a short period
    
- Many login attempts
    
- Attempts against valid users
    
- Attempts against nonexistent users
    
- Many requests to a particular application/URL
    

---

# 25. Windows Event ID 4625

A particularly important detection event is:

```text
4625
```

Meaning:

> **An account failed to log on**

The module explains that many Event ID **4625** events within a short period may indicate password spraying.

### Detection concept

```text
Many failed logons
       +
Short time period
       ↓
Potential spraying
       ↓
SIEM correlation rule
       ↓
Alert
```

Organizations should correlate multiple failures within a defined time window rather than relying on one isolated failed login.

---

# 26. Event ID 4771

Another important event:

```text
4771
```

This represents:

> **Kerberos pre-authentication failed**

The module recommends monitoring this event as part of password-spraying detection and notes that Kerberos logging needs to be enabled.

### 🧠 Memorize

```text
4625 → Account failed to log on
4771 → Kerberos pre-authentication failed
```

These are important Windows security events to know for both **red-team and blue-team work**.

---

# 🛡️ 27. Detection Workflow

![Image](https://images.openai.com/static-rsc-4/i6EyNmYm9-JNA2kDpfRzwtknrNhPmAJQPDyuZnGNkXMKZ_ml91Kx4om1dhpPx68RmhGvPTD13jHxDPxRrwE33sGJGNHsTGcYzwRWAepWrx2eJluP3pkJ8MC7Vkc2qeVvWY0Y-L9H9-t1cc5H-DDcleQ8CE41ov1JqL-xjOqVnndqpKKCveB0jEg9Vnp8HkZ7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VPB4DUkNka5ApzSxY5mAX3XTYHmdfZwurIILUqscNzqldx9W0PtezzuKFRVP6kJNn5QcL-HC74fRyiTLTuKQXIKrjAE919te_12YN2UCqimsw6CwDQ4erLZ_gJKt4EuoRzE3Y2-INm79Iq16i-9ZiZ_O616oEi8lADWHjngrTE7mOSEgjCLoemks7DkW5yp4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/heDMpUr02FPGgduHUN6Pl6QryHv-njkoe4RHeUbRTXyZ_eMR6VG7BnmHxJlMFzh7Co0LFUmeWQMx6nmz5shc58qQeRCeV7ujzeXX9d1XK9NCmf9lN-GxveUms8RKcOI5dDRyWbzhJssjf-R8dJdx5qaBDlwJG4Ot3oyBubQ-eK6vwAd6Bo37-w3tgx8yLxJp?purpose=fullsize)

A defender can think about the detection process like this:

```text
Authentication events
        ↓
Collect logs
        ↓
4625 / 4771
        ↓
Time-based correlation
        ↓
Identify unusual volume
        ↓
Alert / investigate
```

The module states that with tuned mitigations and logging, organizations can be better positioned to detect and defend against internal and external password spraying.

---

# 🌐 28. External Password Spraying

The module says external password spraying is **outside the scope of this module**, but introduces it as an important real-world concept.

External spraying targets internet-facing services that use Active Directory authentication.

Examples from the module include:

- Microsoft 365
    
- Outlook Web Exchange
    
- Exchange Web Access
    
- Skype for Business
    
- Lync Server
    
- Microsoft RDS portals
    
- Citrix portals
    
- VMware Horizon VDI
    
- VPN portals
    
- Custom web applications using AD authentication
    

---

# 29. Internal vs External Password Spraying

|Internal|External|
|---|---|
|Inside organization's network|From the Internet|
|Domain hosts|Internet-facing services|
|Domain Controller authentication|Web/VPN/cloud portals|
|Windows/Linux foothold may exist|No internal foothold required|
|SMB/Kerberos/LDAP may be targeted|Web/VPN/identity portals may be targeted|

### Simple visualization

```text
INTERNAL

Attacker
   ↓
Internal host
   ↓
Domain Controller
   ↓
Domain accounts
```

```text
EXTERNAL

Internet
   ↓
VPN / M365 / Web App
   ↓
AD authentication
   ↓
Domain account
```

---

# 🚪 30. Moving Deeper

The final section is important because it connects password spraying to the broader penetration-testing methodology.

After obtaining valid credentials:

```text
Valid Credentials
       ↓
Credentialed Enumeration
       ↓
Understand Domain
       ↓
Identify Hosts / Users / Groups
       ↓
Lateral Movement
       ↓
Vertical Movement
       ↓
Assessment Goal
```

The module says the next stage is to perform **credentialed enumeration** using various tools that complement each other to build a complete and accurate picture of the domain.

---

# 🧠 31. Complete Module Workflow

Put everything you've learned from the password-spraying sections together:

```text
                DOMAIN
                   |
                   v
          Enumerate Users
                   |
                   v
         Understand Policy
                   |
                   v
        Build Target List
                   |
          +--------+--------+
          |                 |
          v                 v
       Linux             Windows
          |                 |
    rpcclient          DomainPasswordSpray
    Kerbrute           Kerbrute
    CME
          |                 |
          +--------+--------+
                   |
                   v
          Valid Credentials
                   |
                   v
        Credentialed Enumeration
                   |
                   v
         Lateral / Vertical
             Movement
```

---

# 🔥 32. Must-Know PowerShell Command

The most important command from this section:

```powershell
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

Know what each part does:

```text
Invoke-DomainPasswordSpray
        ↓
Run spraying function

-Password
        ↓
Specify one password

-OutFile
        ↓
Save successful results

-ErrorAction SilentlyContinue
        ↓
Suppress errors
```

---

# 🔑 33. Must-Know Output

### Domain discovery

```text
Current domain is compatible with Fine-Grained Password Policy.
```

### User enumeration

```text
Now creating a list of users to spray...
```

### Lockout policy

```text
The smallest lockout threshold discovered in the domain is 5 login attempts.
```

### Risk reduction

```text
Removing users within 1 attempt of locking out from list.
```

### Successful credentials

```text
SUCCESS! User:sgage Password:Welcome1
SUCCESS! User:tjohnson Password:Welcome1
```

### Completion

```text
Password spraying is complete
```

---

# 📌 34. Critical Things to Memorize

|Concept|Remember|
|---|---|
|Windows spraying tool|`DomainPasswordSpray`|
|PowerShell import|`Import-Module`|
|Main function|`Invoke-DomainPasswordSpray`|
|Password argument|`-Password`|
|Output file|`-OutFile`|
|Fine-Grained Password Policy|`FGPP`|
|Lockout risk|Check threshold before spraying|
|Disabled accounts|Remove from target list|
|Successful result|`SUCCESS!`|
|Failed logon event|**4625**|
|Kerberos pre-auth failure|**4771**|
|Defense strategy|Defense-in-depth|
|Authentication defense|MFA|
|Access principle|Least privilege|
|Lateral movement defense|Network segmentation|
|Password defense|Strong password hygiene|

---

# 🎯 35. Mentor-Level Understanding

The biggest lesson of this section is that **professional password spraying isn't simply running a command against every account**.

A mature workflow looks like:

```text
                 Understand Environment
                         ↓
                 Understand Policy
                         ↓
                  Identify Users
                         ↓
              Remove risky accounts
                         ↓
                Confirm the scope
                         ↓
                 Perform spray
                         ↓
                Record successes
                         ↓
               Validate credentials
                         ↓
             Credentialed enumeration
```

The tool's ability to automatically discover the domain, query password policy, remove accounts close to lockout, and maintain output is what makes **DomainPasswordSpray** useful from a domain-joined Windows host.

---

## 🧠 Final Revision Card

```text
DomainPasswordSpray
        ↓
Windows / PowerShell
        ↓
Automatic user enumeration
        ↓
Password-policy awareness
        ↓
Remove accounts near lockout
        ↓
ONE password → MANY users
        ↓
Save successful credentials
        ↓
Credentialed enumeration
```

### Defensive side:

```text
MFA
+
Least privilege
+
Separate admin accounts
+
Network segmentation
+
Strong password hygiene
+
4625 monitoring
+
4771 monitoring
+
Good lockout-policy design
```

**Module section → Windows spraying → Mitigation → Lockout considerations → Detection → External spraying → Moving Deeper: completed.**