**Source:** Your uploaded HTB module content. I’ve preserved the module’s important terminology, examples, attack chains, and commands rather than replacing them with a generic AD tutorial.

---

# 1. Active Directory — What Is It?

**Active Directory (AD)** is a directory service used in Windows enterprise environments.

According to the module, AD was officially implemented with **Windows Server 2000** and has continued to evolve with later Windows Server releases.

AD is based on technologies/protocols including:

- **X.500**
    
- **LDAP (Lightweight Directory Access Protocol)**
    

It provides centralized management of many enterprise resources:

- 👤 Users
    
- 💻 Computers
    
- 👥 Groups
    
- 🌐 Network devices
    
- 📁 File shares
    
- ⚙️ Group Policies
    
- 🖥️ Devices
    
- 🔗 Trusts
    

Most importantly, AD provides:

> **Authentication + Accounting + Authorization**

### 🧠 Mentor Explanation

Think of Active Directory as the **central identity and access-control system of a Windows enterprise**.

Instead of every computer independently maintaining:

```text
Users
Passwords
Groups
Permissions
Policies
```

the organization can manage these centrally through AD.

---

## 🖼️ Active Directory Architecture

![Image](https://images.openai.com/static-rsc-4/WADPXCYsf3kpJaOTpM3ZUZy6WP3QYcvnL37QSDFKLuaaEpYjIaRt9GYyJpgPKG4Chd2WWDVL1XwQgSrh_NWqEBuzQC1XHBtxUN9kbv9Gz86yO4T3TaJj2bNH39pWhiykqUnEanFBFUjQJL1y3KqYMXtnEIZh8zZTfGdCZpz6iatLMViLRbW47Dwvo9k97kwN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/scZY0tsLCjdfaGci1fGLEGMt4X1e6oDwZxk7Q8-VxrVqYtVI0TRIyd-tKnJGpDwae-HLk0DeiroIavsvzvdXfR3gnjPBmgM56XXUVTDCUPXJY65g7zlPrAahqayjdSFMAMM4hqvsxL0kSayaymI8Dau9fI_Y76hnFSXY-Jp18hUc_NFhbwro_KKCC0YgyTj_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CRZOdzrpyyREnjSrh1qhnwtZ2vhnVEKvOBCDvpqAWToiZbC1Vff493ckvLA5KwWv_BmwblFiL8WTYtTxLdIEgKdkYiIPQFS5t1MhUL94YFggAgqXB_5TpE81IOH7CE2vpXDn0_hwQHafq7fS4x6qXV3zbYLfU2KOxwpXlfBVErHsjLkYN7vug_v78aBAbcym?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BTbVrM7LAHgreMtvChBBUoqA_sZUU9btRIkI2uWpAkVW1NAxC4QlRW4FmZaJQmJp7GnOmPuTbByl3yI1FsvUfzyo_f3m5kGy77xRptYadv1mYxNTIlE2ueGJpywu58tf3ykEPMhsrNQPAoY34QI4A3UzSnTH5cK7UUiDAvDw2pijxPMqPkSC7_22zDUH-yor?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_F4lZAJYOhEmhauhJSgYwIu_T0QZTzWOkMlyqngtrXk8ZrMWhnkSG2Km0BfnKUTaqzhep5jLYk3L_ySlOFYqPDR0q9AEPSYI1JbpdsmUO3yQJW-90xpjwglkN5GCLKsPB1d9pIA1pe5eK6VdV7sxruE5J6efIgLo7atwvotYtMsE3bs1SpYGRKc5ZEb_jELx?purpose=fullsize)

A simplified mental model:

```text
                         ACTIVE DIRECTORY
                                │
                    ┌───────────┴───────────┐
                    │     DOMAIN CONTROLLER │
                    │                       │
                    │   AD Database        │
                    │   Users               │
                    │   Groups              │
                    │   Computers           │
                    │   Policies            │
                    │   Trusts              │
                    │                       │
                    │  LDAP    Kerberos     │
                    │  DNS     SMB/RPC      │
                    └───────────┬───────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
           Workstations       Servers          Users
```

The important concept is that the **Domain Controller (DC)** is central to many AD operations.

Microsoft's Kerberos documentation similarly describes the KDC as running on domain controllers and using the AD DS database as its security-account database. ([Microsoft Learn](https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview?utm_source=chatgpt.com "Kerberos authentication overview in Windows Server | Microsoft Learn"))

---

# 2. Why Should We Care About Active Directory?

The module highlights the huge enterprise presence of Microsoft Active Directory and the large attack surface created by:

- Numerous services
    
- Large numbers of users
    
- Complex permissions
    
- Misconfigured services
    
- Misconfigured permissions
    
- Weak credentials
    
- Vulnerable operating systems
    
- Excessive privileges
    
- Trust relationships
    

The key security problem is:

> **AD makes enterprise information and resources easy to manage and access — but mistakes in configuration can also make them easier for attackers to enumerate and abuse.**

### 🔥 Important

An attacker does **not necessarily need a remote code execution vulnerability** to compromise an AD environment.

A relatively low-privileged foothold can potentially lead to:

```text
Initial Access
      ↓
Enumeration
      ↓
Credential Discovery
      ↓
Privilege Escalation
      ↓
Lateral Movement
      ↓
Domain Admin / High Privilege
      ↓
Domain Compromise
```

The module specifically emphasizes **misconfigurations + permissions + credentials + vulnerabilities** as an important combination.

---

# 3. The AD Attacker's Mindset

One of the most important lessons from this module is:

> **Do not simply run tools. Understand why the attack works.**

The module explicitly stresses understanding the **"why" behind flaws and misconfigurations**.

This is extremely important for your cybersecurity learning.

### ❌ Beginner mindset

```text
Run BloodHound
↓
Click shortest path
↓
Copy command
↓
Get flag
```

### ✅ Pentester mindset

```text
What do I know?
       ↓
What can I enumerate?
       ↓
What identities exist?
       ↓
What privileges exist?
       ↓
What relationships exist?
       ↓
What credentials/tickets might exist?
       ↓
What path can I validate?
       ↓
What is the security impact?
       ↓
How would I remediate it?
```

---

# 4. The Main Goal of AD Enumeration

When you obtain a foothold inside an AD environment, your goal is generally to **understand the environment and identify paths to your assessment objective**.

The module describes objectives that can include:

- Accessing a particular host
    
- Accessing a user's email
    
- Accessing a database
    
- Obtaining a specific privilege
    
- Achieving domain compromise
    
- Identifying paths toward **Domain Admin**
    

### Important distinction

**Domain Admin is not automatically the goal of every engagement.**

Your actual objective depends on the scope of the penetration test.

---

# 5. Enumeration Is the Foundation

The module repeatedly emphasizes **enumeration**.

We want to answer questions such as:

### Identity

```text
Who are the users?
Who are the administrators?
What groups exist?
```

### Infrastructure

```text
What computers exist?
Where are the Domain Controllers?
What services are exposed?
```

### Permissions

```text
Who has access to what?
Who can modify what?
Who has administrative rights?
```

### Authentication

```text
How does authentication work?
Are Kerberos tickets available?
Are SPNs present?
```

### Relationships

```text
Which users belong to which groups?
Which users have local admin rights?
Are there trusts?
What privilege relationships exist?
```

---

# 6. Windows AND Linux Enumeration

A major skill this module wants you to develop is the ability to attack/enumerate AD from **both Windows and Linux**.

Why?

Because during a real penetration test:

- Your preferred tools may fail.
    
- Security software may block tools.
    
- You may be working from a managed workstation.
    
- You may be given a VDI.
    
- You may not have your normal Kali environment.
    
- You may only have native Windows tools.
    

This is called:

## 🟢 Living Off The Land

**Living off the land** means using tools and capabilities that are already available on the compromised or managed system instead of depending entirely on custom tooling.

Example concept:

```text
Normal situation:

Kali
 ↓
Impacket
 ↓
BloodHound
 ↓
Custom tools


Restricted environment:

Windows workstation
 ↓
PowerShell
 ↓
WMI
 ↓
LDAP
 ↓
DNS
 ↓
Built-in Windows utilities
```

### 🧠 Mentor Rule

**Never become dependent on one tool.**

Learn the underlying protocol and concept.

For example:

```text
Don't only learn BloodHound.
Learn AD relationships.

Don't only learn Kerbrute.
Understand Kerberos authentication.

Don't only learn NetExec.
Understand SMB/LDAP authentication.

Don't only learn Responder.
Understand NTLM challenge-response.
```

---

# 7. Important Tools Mentioned in the Module

The module introduces/references several important tools.

|Tool|Main Concept|
|---|---|
|**Sysinternals**|Windows administrative/system utilities|
|**WMI**|Windows Management Instrumentation|
|**DNS**|Domain/service discovery and name resolution|
|**Responder**|Network authentication capture/poisoning techniques|
|**Kerbrute**|Kerberos-based username enumeration/password spraying|
|**BloodHound**|AD relationship and attack-path analysis|
|**Hashcat**|Password/hash cracking|
|**Rubeus**|Kerberos interaction and ticket operations|
|**enum4linux**|SMB/RPC-based enumeration|
|**DomainPasswordSpray**|Domain password spraying|
|**PowerShell**|Windows administration and AD enumeration|

---

# 8. Real-World Attack Chain #1 — "Waiting On An Admin"

This is one of the most important scenarios in the module.

The attacker initially compromised a domain-joined host and obtained:

```text
SYSTEM
```

level access.

Because the machine was domain joined, this access could be used to perform domain enumeration.

The attacker discovered:

```text
SPNs
 ↓
Kerberoasting
 ↓
TGS tickets
 ↓
Password cracking
 ↓
Valid user credentials
```

Initially, the recovered account did not provide significant privileges.

However, it had:

```text
Write access
      ↓
Certain file shares
```

The attacker then used the writable shares to place **SCF files** and waited while **Responder** was running.

Eventually:

```text
Responder
    ↓
NetNTLMv2 hash
    ↓
BloodHound
    ↓
Identify account
    ↓
Account = Domain Admin
```

### Attack-chain diagram

```text
Compromised Host
      │
      ▼
 SYSTEM Access
      │
      ▼
AD Enumeration
      │
      ▼
SPNs Found
      │
      ▼
Kerberoasting
      │
      ▼
TGS Tickets
      │
      ▼
Password Cracking
      │
      ▼
User Credentials
      │
      ▼
Writable File Shares
      │
      ▼
SCF Files + Responder
      │
      ▼
NetNTLMv2 Hash
      │
      ▼
BloodHound
      │
      ▼
Domain Admin
```

### 🧠 Lesson

The important part isn't any single technique.

It's the **chain**.

One low-impact permission can become valuable when combined with another weakness.

---

# 9. Scenario #2 — Password Spraying

Password spraying is another major AD attack technique covered by the module.

### Password spraying ≠ brute force

This distinction is **VERY IMPORTANT**.

### Brute force

Try many passwords against **one account**:

```text
administrator:
Password1
Password2
Password3
Password4
...
```

This can quickly trigger account lockout.

### Password spraying

Try **one password against many accounts**:

```text
Password123
    ↓
user1
user2
user3
user4
user5
```

Then try another password later.

The module emphasizes that password spraying must be performed carefully to avoid account lockouts.

---

# 10. Why Password Policy Matters

Before spraying, an attacker may want to understand:

- Minimum password length
    
- Complexity requirements
    
- Lockout threshold
    
- Lockout duration
    
- Password history
    
- Other domain password-policy settings
    

The module gives an example where an SMB NULL session exposed:

```text
Users
+
Password Policy
```

This information allowed the tester to stay within the lockout parameters.

### Example attack logic

```text
Enumerate users
       ↓
Identify password policy
       ↓
Determine lockout risk
       ↓
Choose candidate password
       ↓
Controlled spray
       ↓
Validate credentials
```

---

# 11. Scenario #2 — Continuing the Attack

The module's example eventually obtained a valid account using:

```text
Spring@18
```

The compromised account provided local administrative access to several hosts.

Then:

```text
BloodHound
    ↓
Find host
    ↓
Domain Admin active session
    ↓
Rubeus
    ↓
Kerberos TGT
    ↓
Pass-the-Ticket
    ↓
Domain Admin access
```

The example also demonstrates how **nested group membership** and **trust relationships** can extend compromise into another domain.

### Key lesson

A user's direct permissions are not the complete picture.

You must consider:

```text
User
 ↓
Groups
 ↓
Nested Groups
 ↓
Computer Rights
 ↓
Sessions
 ↓
Trusts
 ↓
Effective Privileges
```

---

# 12. Scenario #3 — Fighting In The Dark

This scenario demonstrates what happens when the tester has very little information.

The tester:

1. Used **Kerbrute**
    
2. Enumerated valid usernames
    
3. Performed targeted password spraying
    
4. Obtained an account
    
5. Used BloodHound
    
6. Found RDP access
    
7. Logged into a host
    
8. Used DomainPasswordSpray
    
9. Found additional credentials
    
10. Identified a privileged group relationship
    
11. Abused **GenericAll**
    
12. Used **Shadow Credentials**
    
13. Obtained the domain controller machine account NT hash
    
14. Performed **DCSync**
    
15. Retrieved NTLM password hashes
    

### Full chain

```text
Unknown Environment
        │
        ▼
    Kerbrute
        │
        ▼
Valid Users
        │
        ▼
Targeted Password Spray
        │
        ▼
Initial Account
        │
        ▼
    BloodHound
        │
        ▼
       RDP
        │
        ▼
Authenticated Host
        │
        ▼
DomainPasswordSpray
        │
        ▼
More Accounts
        │
        ▼
Help Desk Group
        │
        ▼
   GenericAll
        │
        ▼
Enterprise Key Admins
        │
        ▼
Domain Controller
        │
        ▼
Shadow Credentials
        │
        ▼
Machine Account NT Hash
        │
        ▼
     DCSync
        │
        ▼
Domain NTLM Hashes
```

### 🧠 Why this scenario matters

This demonstrates a central AD security principle:

> **Small permissions can combine into a major privilege escalation path.**

---

# 13. BloodHound — The Big Picture

BloodHound is used to visualize relationships inside Active Directory.

Think of AD as a giant graph:

```text
              ┌─────────┐
              │  User   │
              └────┬────┘
                   │
              MemberOf
                   │
                   ▼
              ┌─────────┐
              │  Group  │
              └────┬────┘
                   │
             GenericAll
                   │
                   ▼
              ┌─────────┐
              │ Computer│
              └────┬────┘
                   │
             AdminTo
                   │
                   ▼
              ┌─────────────┐
              │High Privilege│
              └─────────────┘
```

BloodHound helps identify relationships and possible attack paths.

![Image](https://images.openai.com/static-rsc-4/6H0tAcHWatXzMDK9jr644zXdF-8s7XTrE1YONjcWIu_kPifepXOaA8_4lrnRSIE1m93QhF4OPrMH8JT5eoZ57ssYqhn_pG3LNUS_9ecKN0njcaWFluBoDQb9G-OkoqNy3e-_JsT2bbJrtxWQdeNSroRfdMT70XFKv5E0bxlEiDWsYI-11faBgJ_nArlZUskd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wNLFZMl87N3y66wvf4rJ_s-aL6Aax7XCR4cKDxq4nI__qf7MG8bpyQ8DW-c-wl7trF5CVpAOZpfl_As4b8i4a8EM3hj0W0UmvwbKojzXzEPvPhopQdzqjcOlj2YCt3SxNYGEu25yQnMpbq3ZbG9xYcRSsjMWZ3piAS-uxludgtUTLSIhV4lG6nQWS6lqy6uj?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Krs7gGC6KWsVS4zBNL0FmvK-bWmtANwZFok0-RmGl26XnVIg-KD__kTFk3lrxPx-wzZYKUzzrwMLzd582LqnhdseMcN2VgdSkl8i9GkDMLsR1YlcQHQRD3Ng3ffBhL8R8th5JQKnoYoTTBxjq2jqmyi58OuaLcyMwfQ2XUxYC8t4mfcz4iBu1QI8fQnbTAFx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/m93MyWW37SwJGu14bpXY_aDFYnO35ZxpgeiaLsR5bWr_18yX3uL64Er7mE6cna9s2nzVt5eikFg0km2cCn5EwXPLb55ioz-o8Po0-U_T_Uc6093QrPWKQ6YDcGa5NJi1efyc5CUVTaWqwx2SLWVXXQsV2E9l3_X-OH-eeFD0_55lnF13PJ7d-8dcBaDXVsyV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6Wr5eZE4WZjJl3osNLhEOqlk-U1rJN6LhbXreHqWdDL8bHPZYannf9hVhr25iQDUSm1c_8Q11hR0K1H55gbNEvMxtKmeCrR2QP7ugeDsf4JcQZOQV2wvh64XyfxIJN-At_qqBySUy5wHD4tBYPETbMyFtSbePMbSk0MeLunlk45U0e0E7e4CCjXslkK2NxKu?purpose=fullsize)

The module uses BloodHound throughout its attack scenarios because **AD compromise is often about relationships rather than a single vulnerability**.

---

# 14. Kerberoasting

The module's first real-world scenario introduces:

## Kerberoasting

The basic concept:

```text
Find accounts with SPNs
        ↓
Request service tickets
        ↓
Obtain TGS material
        ↓
Offline password cracking
        ↓
Recover service-account password
```

### Important terminology

**SPN — Service Principal Name**

An SPN associates a service with an account in Active Directory.

Accounts associated with services can therefore become interesting targets for Kerberoasting.

### Why is offline cracking important?

Once ticket material has been obtained, password guessing can be performed offline rather than repeatedly authenticating against the domain.

The module's example specifically describes using **Hashcat** and wordlists/rules against retrieved tickets.

---

# 15. Responder & NetNTLMv2

Another important chain from the module:

```text
Writable Share
      ↓
SCF File
      ↓
User Interaction
      ↓
Responder
      ↓
NTLM Authentication
      ↓
NetNTLMv2 Hash
```

The module describes obtaining a **NetNTLMv2 hash** through this technique and then using BloodHound to determine the privilege associated with the captured account.

### 🧠 Important distinction

A:

```text
NetNTLMv2 hash
```

is not the same thing as having the user's plaintext password.

It is authentication material that may potentially be subjected to offline password cracking depending on the situation.

---

# 16. Pass-the-Ticket

The second scenario introduces:

## Pass-the-Ticket

Conceptually:

```text
Kerberos Ticket
      ↓
Obtained from memory/system
      ↓
Reuse ticket
      ↓
Authenticate as associated identity
```

The module's scenario describes extracting a domain administrator's **TGT** with Rubeus and then using a **pass-the-ticket** attack.

### Remember

```text
Pass-the-Hash
      ≠
Pass-the-Ticket
```

**Pass-the-Hash** deals with NTLM credential material.

**Pass-the-Ticket** deals with Kerberos tickets.

---

# 17. GenericAll

The third scenario introduces an important BloodHound relationship:

## GenericAll

At a high level, **GenericAll** represents broad control permissions over an AD object.

The module's scenario describes:

```text
Help Desk group
       │
   GenericAll
       ↓
Enterprise Key Admins
       │
   GenericAll
       ↓
Domain Controller
```

This relationship was used as part of the attack chain.

### 🧠 Mentor Rule

Whenever you see a BloodHound edge such as:

```text
GenericAll
GenericWrite
WriteDACL
WriteOwner
AddMember
AdminTo
ForceChangePassword
DCSync
```

**STOP and investigate what the relationship actually permits.**

Don't blindly memorize the name.

Understand the permission.

---

# 18. Shadow Credentials

The third scenario also introduces:

## Shadow Credentials

The module describes using Shadow Credentials after obtaining appropriate rights over an object and ultimately retrieving the NT hash of the domain controller machine account.

Conceptually:

```text
Abusable AD Permission
          ↓
Shadow Credentials
          ↓
Key-based authentication
          ↓
Machine account access
          ↓
NT hash
          ↓
Further AD attacks
```

This is an advanced AD concept that we'll study more deeply when we reach the relevant exercise.

---

# 19. DCSync

The scenario ends with:

## DCSync

The module explains that domain controllers perform directory replication and that this replication capability is central to the DCSync attack.

Conceptually:

```text
Replication Rights
       ↓
Impersonate replication behavior
       ↓
Request directory credential data
       ↓
NTLM hashes
```

The scenario describes obtaining NTLM password hashes for users through DCSync.

### 🔥 Extremely important concept

DCSync is fundamentally about **directory replication privileges**.

When you see permissions associated with:

```text
DS-Replication-Get-Changes
DS-Replication-Get-Changes-All
```

you should immediately recognize that these permissions can be highly security-sensitive.

---

# 20. The Most Important Lesson: Attack Chains

The module gives three different scenarios, but they teach the same fundamental lesson.

### Attack #1

```text
SYSTEM
 ↓
Enumeration
 ↓
SPN
 ↓
Kerberoasting
 ↓
Credentials
 ↓
Writable Share
 ↓
Responder
 ↓
Domain Admin
```

### Attack #2

```text
NULL Session
 ↓
Users + Password Policy
 ↓
Password Spray
 ↓
Valid Account
 ↓
BloodHound
 ↓
Admin Session
 ↓
TGT
 ↓
Pass-the-Ticket
 ↓
Domain Admin
```

### Attack #3

```text
Username Enumeration
 ↓
Password Spray
 ↓
Valid Account
 ↓
BloodHound
 ↓
More Credentials
 ↓
GenericAll
 ↓
Shadow Credentials
 ↓
Machine NT Hash
 ↓
DCSync
 ↓
Domain Hashes
```

### 🧠 The real skill

You are not learning:

> "How to run 20 hacking tools."

You're learning:

> **How to construct an attack path from the information available in an AD environment.**

---

# 21. Practical Lab Environment

The module provides two primary attack hosts:

### Windows

```text
MS01
```

Used for Windows-based enumeration and attack examples.

### Linux

```text
ATTACK01
```

A preconfigured **Parrot Linux** attack host.

---

# 22. Connecting to MS01 with FreeRDP

The module provides:

```bash
xfreerdp /v:<MS01 target IP> /u:htb-student /p:Academy_student_AD!
```

### Breakdown

```text
xfreerdp
│
├── /v:     Target IP
├── /u:     Username
└── /p:     Password
```

### General format

```bash
xfreerdp /v:<IP> /u:<USER> /p:<PASSWORD>
```

---

# 23. Connecting to ATTACK01 Using SSH

The module provides:

```bash
ssh htb-student@<ATTACK01 target IP>
```

This gives you a command-line session on the Parrot Linux attack host.

---

# 24. GUI Access to ATTACK01

The module also provides an XRDP server on ATTACK01.

This is useful for tools such as **BloodHound**, which has a GUI.

The module gives:

```bash
xfreerdp /v:<ATTACK01 target IP> /u:htb-student /p:HTB_@cademy_stdnt!
```

---

# 25. Lab Timing

The module warns that some mini AD labs can take:

> **3–5 minutes**

to fully spawn and become accessible via RDP.

The recommended approach is to spawn the lab and then continue reading the section while the environment starts.

---

# 26. Toolkit

### Windows attack host

Tools are located primarily in:

```text
C:\Tools
```

The Active Directory PowerShell module can also load when opening a PowerShell console.

### Linux attack host

Tools are either:

```text
PATH
```

or:

```text
/opt
```

---

# 27. Tooling Philosophy

The module encourages you to compile/upload your own tools when appropriate.

It also makes an important professional penetration-testing point:

> In an actual client network, inspect tools/code before introducing compiled executables.

Why?

Because you don't want to introduce:

```text
Unknown Tool
      ↓
Malicious Code
      ↓
Client Network
      ↓
Potential compromise
```

### 🧠 Professional Pentesting Principle

Never blindly execute an unknown binary inside a client's environment.

---

# 28. AD Enumeration Methodology — Your Mental Checklist

For this module, I want you to start thinking in this order:

```text
                    AD ENUMERATION
                          │
            ┌─────────────┴─────────────┐
            ▼                           ▼
       ENVIRONMENT                  IDENTITY
            │                           │
     ┌──────┼──────┐             ┌──────┼──────┐
     ▼      ▼      ▼             ▼      ▼      ▼
    DNS    SMB    LDAP          Users  Groups  Admins
     │      │      │
     └──────┼──────┘
            ▼
       PERMISSIONS
            │
      ┌─────┼─────┐
      ▼     ▼     ▼
   Local  Group  Object
   Admin  Rights Rights
      │
      ▼
    SESSIONS
      │
      ▼
 CREDENTIALS / TICKETS
      │
      ▼
  ATTACK PATH
      │
      ▼
PRIVILEGE ESCALATION
      │
      ▼
 LATERAL MOVEMENT
```

This is the mindset I want you to develop throughout the exercises.

---

# 29. ⭐ Things You MUST Remember

### Active Directory

> Centralized Windows enterprise directory and identity system.

### Domain Controller

> A server providing core AD domain services.

### LDAP

> Used to query/access directory information.

### Kerberos

> Major authentication protocol used within AD.

### SPN

> Service Principal Name associated with a service/account; important for Kerberoasting.

### Kerberoasting

> Obtain service tickets associated with SPNs and attempt offline password cracking.

### Password Spraying

> Try a small number of candidate passwords across many accounts while carefully considering lockout policy.

### BloodHound

> Graph-based AD relationship and attack-path analysis.

### Rubeus

> Kerberos-focused tool used in the module's ticket-related scenarios.

### Responder

> Used in network authentication capture/poisoning scenarios.

### NetNTLMv2

> NTLM challenge-response authentication material that can potentially be captured and cracked offline.

### Pass-the-Ticket

> Reuse a Kerberos ticket to authenticate as the associated identity.

### GenericAll

> Broad object-control permission that can create serious attack paths depending on the object.

### Shadow Credentials

> Technique involving key-based account mapping to abuse suitable AD permissions.

### DCSync

> Abuse replication-related privileges to obtain directory credential data.

---

# 30. 🧠 Mentor-Level Takeaways

If you remember only **10 things** from this introduction, remember these:

1. **AD is a centralized identity and resource-management system.**
    
2. **Enumeration is the foundation of AD penetration testing.**
    
3. **Don't depend exclusively on automated tools.**
    
4. **Understand the underlying protocols and permissions.**
    
5. **Users and groups are only part of the picture.**
    
6. **Sessions and relationships can be more valuable than direct permissions.**
    
7. **Password spraying must account for lockout policy.**
    
8. **BloodHound helps turn complicated AD relationships into attack paths.**
    
9. **Multiple low-severity weaknesses can combine into a critical attack chain.**
    
10. **Always ask: "What can I do with what I have?"**
    

---

# 📝 Quick Revision Sheet

```text
ACTIVE DIRECTORY
│
├── Users
├── Groups
├── Computers
├── Policies
├── File Shares
├── Trusts
└── Permissions
       │
       ▼
ENUMERATION
│
├── DNS
├── LDAP
├── SMB
├── WMI
├── PowerShell
└── Native Windows Tools
       │
       ▼
CREDENTIAL / ACCESS ATTACKS
│
├── Password Spraying
├── Kerberoasting
├── Responder
├── Pass-the-Ticket
└── Credential Discovery
       │
       ▼
RELATIONSHIP ANALYSIS
│
└── BloodHound
       │
       ▼
PRIVILEGE ESCALATION
│
├── GenericAll
├── Shadow Credentials
├── DCSync
└── Other AD permission abuse
       │
       ▼
LATERAL MOVEMENT
       │
       ▼
ASSESSMENT OBJECTIVE
```

## 🎯 What comes next

These notes cover the **Introduction** section you provided. The module itself explicitly says the concepts may initially seem overwhelming and that the following sections will teach many of these techniques through practical examples and labs.

**Next, we should NOT jump straight into the exercises.** We'll take the module section-by-section, build the required knowledge first, and then solve each exercise in **Cybersecurity Mentor Mode**—where I'll make you reason through the enumeration and explain _why_ each command is being used.