# 1. 🖥️ What is RDP?

**RDP — Remote Desktop Protocol** is a proprietary protocol developed by Microsoft.

It provides a **graphical interface** that allows a user to connect to another computer over a network.

Instead of physically sitting at the target machine, an administrator can remotely interact with its desktop as if they were sitting in front of it.

### Common legitimate uses

RDP is widely used by:

- System administrators
    
- IT support teams
    
- Managed Service Providers (MSPs)
    
- Organizations managing remote Windows systems
    

For example:

```text
Administrator
      │
      │ RDP
      ▼
┌──────────────────┐
│ Windows Server   │
│                  │
│ GUI Desktop      │
└──────────────────┘
```

---

# 2. ⚠️ Why Is RDP a Security Concern?

RDP makes remote administration convenient, but it also creates another **network-accessible gateway** into a Windows system.

Conceptually:

```text
Internet / Internal Network
          │
          ▼
       TCP/3389
          │
          ▼
       RDP Server
          │
          ▼
    Windows Login
          │
          ▼
     Remote Desktop
```

If authentication or configuration is weak, attackers may attempt to abuse the exposed service.

---

# 3. 🔌 Default RDP Port

RDP normally uses:

```text
TCP/3389
```

### ⭐ Memorize

```text
RDP → 3389/TCP
```

---

# 4. 🔎 RDP Enumeration with Nmap

The supplied material uses:

```bash
nmap -Pn -p3389 192.168.2.143
```

Example result:

```text
PORT     STATE    SERVICE
3389/tcp open     ms-wbt-server
```

### Command breakdown

|Option|Meaning|
|---|---|
|`-Pn`|Skip host discovery and treat target as online|
|`-p3389`|Scan TCP port 3389|

### Enumeration flow

```text
Nmap
 │
 └── TCP/3389
       │
       ├── Closed → RDP not directly exposed
       │
       └── Open
            ↓
       ms-wbt-server
            ↓
       Investigate RDP
```

---

# 5. 🔐 RDP Authentication

RDP normally requires **user credentials**.

Therefore, one common attack vector is:

# Password Guessing

The source also notes that, due to misconfiguration, an RDP service could potentially be found without a password, although this is uncommon.

---

# 6. ⚠️ Password Guessing vs Password Spraying

This distinction is **very important**.

## Password Guessing

Trying multiple passwords against a particular account.

```text
Administrator
     │
     ├── password1
     ├── password2
     ├── password3
     └── password4
```

This can trigger account lockout policies.

---

## Password Spraying

Instead of trying many passwords against one account, we try:

> **One password against many accounts**

Example:

```text
Password123
     │
     ├── administrator
     ├── guest
     ├── test
     ├── user
     └── admin
```

Then move to another password.

```text
Password123 → Many users
Winter2026  → Many users
Company123  → Many users
```

The goal is to reduce the chance of triggering account lockout.

The source specifically recommends considering password spraying when Windows password policies can lock accounts after repeated failed attempts.

---

# 7. 🧠 Password Spraying Concept

![Image](https://images.openai.com/static-rsc-4/EwzT7cvkKc4fnWj-3wTBzZy_mP1dzH39ZIdpXSp4XCUbPv0em6LJrX1yOZVfR9kMu1OD7yHBZ72tJOPddi5UFFHgCImCq-3iDPOgqSrhfYwJYCD0_GqPxEtc9RVSBo5YBINjfsqMK1QUgMEJtYeyVBQyum7ajZAc6WEwf21bOm0J1OcGSieU27IRlmaJW_n8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/UtoHIs-XBLSzSyWP99GVH66BQDQZ14kIRx7zM96_GbRjJfbYnmgvlLmkhIOjbj1KhWcv1rUB3_DD0Mdxz_R6wYZD8jXMjwIxfi0P4IwyQj4GseUbLCvrosUh_pB3mmhBnLbjpnp4sxyM9AiORVq9c6Lu0TV2f3V7Eu-xDC-LN6LJm50vHWCvy4Y6uwK5-CNf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XNoh9WJy-wvrMWBaTnlM-5qO66myy7EruS1GQVLgdFMx-NUo0E1O3U80hcJlsq-f2PsCqHAKA9RamD12RJ2nxYxbjv_IgfTZhSLVHK0SlmdgMLXV3MXoaYHX3Rx-2snzHiqepJBJkxZJZDYJYlgP-XphyD9jGoeutZ7FvF8a9n8obwSr3CA53GY_rCPvD8XG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7lqJ1B8OsX-1OqX1_o46JAcqQDl9lg5Dd0MQMqDhIVU9bheU2hVegxWghULVuGRrxzDvsxVARvFcsDpai8DtEjZeKqj1Q9cyEjCGC1MTjY0mzQajCUNMD1vt-9xbJiLuiqQSLolFpfZiMn5v30cFYgkFWXpoKNyvvVFZAr8xXMwAj5Qd5Wg7ur57d-Xw-MBq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EDVUJFmNGUW8asJpz32LGnOIHBllzr_QuZuz5m70c_h-Y17A0TbDK2jlrPhnGkPhDLUWICskF2YBeABohlTVwrrRQLPXMDlJPyukGwenlLTjGO9h4RnDgMFsuBxLl1RnBXTHPNwCM6UhbNWFdATgvWw5BN8wPGl3o6qsGf6KR9VMwJu0nauV0Wz1AAO0sUzL?purpose=fullsize)

```text
                 ONE PASSWORD
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Administrator      Guest          User1
        │              │              │
        ▼              ▼              ▼
      FAIL?          FAIL?          SUCCESS
                                      │
                                      ▼
                                  RDP Access
```

### Why it can be effective

A Windows environment may have:

```text
Many Users
+
One Weak/Common Password
```

instead of:

```text
One User
+
Many Password Attempts
```

---

# 8. 🧰 Crowbar — RDP Password Spraying

The source demonstrates **Crowbar** for RDP password spraying.

Example:

```bash
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
```

The supplied result identifies:

```text
administrator:password123
```

as valid credentials.

### Crowbar options

|Option|Meaning|
|---|---|
|`-b rdp`|Use RDP backend|
|`-s`|Target specification|
|`-U`|Username list|
|`-c`|Credential/password to test|

---

# 9. 📄 Username List

The source demonstrates a username file:

```text
root
test
user
guest
admin
administrator
```

The idea is:

```text
Username List
     │
     ▼
One Password
     │
     ▼
RDP Authentication Attempts
```

The important lesson is that the exact list of usernames depends on the target environment.

---

# 10. 🐍 Hydra — RDP Password Spraying

The material also demonstrates **Hydra**.

Example:

```bash
hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```

The example identifies:

```text
administrator : password123
```

as valid credentials.

### Important Hydra options

|Option|Meaning|
|---|---|
|`-L`|Username list|
|`-p`|Single password|
|`rdp`|RDP module|

---

# 11. ⚠️ RDP Connection Limitations With Hydra

The supplied output contains an important warning:

> RDP servers often don't like many connections.

Hydra therefore recommends reducing parallel connections.

The example shows Hydra reducing tasks to:

```text
4
```

and notes that the RDP module is experimental in that version.

### Practical lesson

Don't assume:

```text
More threads = Better
```

With RDP:

```text
Too many connections
        ↓
Server may reject / behave poorly
        ↓
Authentication testing becomes unreliable
```

---

# 12. 🖥️ Connecting to RDP

Once valid credentials are obtained, the material mentions two RDP clients:

```text
rdesktop
xfreerdp
```

---

# 13. 🧰 `rdesktop`

The supplied example:

```bash
rdesktop -u admin -p password123 192.168.2.143
```

The connection may display a certificate warning.

The example shows a self-signed/untrusted certificate and asks whether the user trusts it.

### Important security lesson

A certificate warning means you should understand **why** the certificate is untrusted before accepting it in a real environment.

In a controlled HTB/lab environment, self-signed certificates are common.

---

# 14. 🖼️ Basic RDP Attack Flow

```text
                   TARGET
                     │
                     ▼
                TCP/3389
                     │
                     ▼
               RDP Service
                     │
                     ▼
              Authentication
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
     Valid Credentials      Invalid
          │
          ▼
      RDP Session
          │
          ▼
     Remote Desktop
```

---

# 15. 🔥 RDP Attack Methodology

A useful workflow from this material:

```text
1. Identify RDP
       ↓
2. Confirm TCP/3389
       ↓
3. Identify authentication
       ↓
4. Understand password policy
       ↓
5. Test appropriate credentials
       ↓
6. Obtain valid credentials
       ↓
7. Connect using RDP
       ↓
8. Enumerate privileges
       ↓
9. Look for session / credential opportunities
```

---

# 16. 🧩 Protocol-Specific Attack — RDP Session Hijacking

This is one of the most important sections.

Imagine:

```text
You already compromise a Windows machine
                ↓
You have local administrator privileges
                ↓
Another user is connected through RDP
                ↓
You may be able to hijack their session
```

The source explains that this could allow an attacker to impersonate the logged-in user and potentially escalate privileges.

In an **Active Directory** environment, this could potentially lead to:

- Higher-privileged accounts
    
- Additional network access
    
- Domain Admin-level access
    

---

# 17. 👥 RDP Session Hijacking Scenario

The example contains:

```text
Current attacker:
juurena
User ID = 2
Administrator privileges

Target:
lewen
User ID = 4
Also logged in via RDP
```

The goal is to take over the `lewen` session.

Conceptually:

```text
Compromised Machine
       │
       ├── Attacker Session
       │
       └── Victim RDP Session
                │
                ▼
          Session Hijacking
                │
                ▼
          Victim's Context
```

---

# 18. 🔐 Requirements for RDP Session Hijacking

The source identifies two important requirements:

### 1. SYSTEM privileges

You need:

```text
SYSTEM
```

### 2. `tscon.exe`

Microsoft's:

```text
tscon.exe
```

binary allows users to connect to another desktop session.

---

# 19. 🧰 `tscon.exe`

The basic syntax shown is:

```cmd
tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

The important components are:

```text
TARGET_SESSION_ID
        +
OUR_SESSION_NAME
```

The target session ID identifies the session you want to connect to.

The destination identifies the current RDP session.

---

# 20. 🔎 Finding RDP Sessions — `query user`

The source uses:

```cmd
query user
```

Example:

```text
USERNAME       SESSIONNAME    ID   STATE
juurena        rdp-tcp#13     1    Active
lewen          rdp-tcp#14     2    Active
```

### What we're looking for

```text
Username
Session Name
Session ID
State
```

The **Session ID** is particularly important for session management.

---

# 21. ⚙️ Obtaining SYSTEM Privileges

The source notes that a local administrator can use several methods to obtain SYSTEM privileges, including:

- PsExec
    
- Mimikatz
    
- Windows services
    

The example uses the Windows service mechanism.

---

# 22. 🛠️ Using `sc.exe`

Windows services normally run under:

```text
Local System
```

Therefore, the material demonstrates creating a service that executes the `tscon` command.

Example:

```cmd
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
```

The result:

```text
[SC] CreateService SUCCESS
```

### Concept

```text
Local Administrator
       ↓
Create Windows Service
       ↓
Service runs as Local System
       ↓
Execute tscon
       ↓
Connect to target RDP session
```

---

# 23. ▶️ Starting the Service

After creating the service:

```cmd
net start sessionhijack
```

Conceptually:

```text
Service Created
      ↓
net start
      ↓
SYSTEM Process
      ↓
tscon
      ↓
Target Session
```

---

# 24. 🎯 Result of Session Hijacking

According to the supplied material, after the service starts, a new terminal appears with the target user's session.

The tester can then investigate what privileges the compromised user has elsewhere in the network.

For example:

```text
Hijacked User
      │
      ▼
Group Membership
      │
      ├── Help Desk
      ├── Local Admin rights
      └── Potentially higher privileges
```

The source specifically mentions that the account could potentially belong to a Help Desk group with administrative rights on many hosts, or even be a Domain Admin.

---

# 25. ⚠️ Important Caveat

The supplied material explicitly states:

> **This method no longer works on Server 2019.**

### ⭐ Memorize

Don't blindly assume the `tscon` session-hijacking technique works on every Windows Server version.

Always consider:

```text
Windows Version
+
Patch Level
+
Security Configuration
```

---

# 26. 🔥 RDP Session Hijacking Flow

```text
                  COMPROMISED HOST
                         │
                         ▼
              Local Administrator
                         │
                         ▼
                       SYSTEM
                         │
                         ▼
                  query user
                         │
                         ▼
              Identify Target Session
                         │
                         ▼
                     tscon.exe
                         │
                         ▼
                 Target RDP Session
                         │
                         ▼
                 User Impersonation
                         │
                         ▼
                Further Enumeration
```

---

# 27. 🧠 Why Session Hijacking Is Powerful

Notice that this technique can bypass the need to know the user's plaintext password.

Normally:

```text
Username + Password
       ↓
RDP Login
```

Session hijacking can instead work conceptually as:

```text
Existing Authenticated Session
             ↓
       Session Hijacking
             ↓
     Access as Existing User
```

That's why already-authenticated sessions can be valuable during a penetration test.

---

# 28. 🔑 RDP Pass-the-Hash (PtH)

The next major technique is:

# **RDP Pass-the-Hash**

Suppose you have:

```text
Username
+
NT Hash
```

but you **cannot recover the plaintext password**.

Normally, RDP authentication would appear to require:

```text
Username + Password
```

However, under certain Windows configurations, it may be possible to use the NT hash to authenticate through RDP.

The source specifically demonstrates this using:

```text
xfreerdp
```

---

# 29. 🧠 Pass-the-Hash Concept

![Image](https://images.openai.com/static-rsc-4/Nk0ZXSggvE5HFwy7iVpyqbrhhXa5mlpDJXIESXt2dpLI6dOevyw-FoX8wYFVf9b1Jw0EWaYOKiCdTKJqJhxwoJ37hZZ3zjMi92JfGxD66wrvB6-d87SPrqwzS5jyBr8XPlEjj50qFmLIAvYeMGu7FagZia844-sV-CO-8kYpa-gat76FDi7ni_GjwW8ZEqAy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mwhZrV6Pjuh5coH4u9_y8B9PhEF3BWO8RakQNVuDaeyFf8RQHI1B-wJaN_dpRR73P6RLjLdCNAp1_ZnGFeg2Ux6Ig9Q4Y2PujlfLtKLkSvbC7uLAyhA3lQZ43PWHimdyLRjGWNeaij4ctjLixVaDuI946ZPKzLneoQdl4e-8FAM3QhhX76o917ETbGJjD2C_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/swGvoNk7gZ95cXzSkTptpPy7_j1bvyr7F2X-4B4-HfvrmWHjl4kJjo7OAhtXHSSRRLnK3pB-N52c0E01F3vsN-l_GGVLSlOgybo-tjf8Zs1OB21CGVVQ2-JOaIavUlzRD_o_tNEhSas6MpGBFWDY1lmEBhN74X8_3MsJ-0MNd4Hw8cMDxwgQD7u3pd2zDKz4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mhJ_KiEtQNCrV40ZDse2mTL6uF7zrjc4rzyTD-0H9xxLZ6qB0VLH592oeAohsJ2PBBPMT4nZ88b_ywtAKbnZjKK6xM8eRYvwuRPReNSUrPAmCIJZehEQeIz14s_N8Qyu50zuQCHGoAHLfdCz1BDoh3bxutnDJWnDoz-A6ppB5G-2V7qW-pbX21fyj7c39xND?purpose=fullsize)

```text
Credential Dumping
       │
       ▼
   NT Hash
       │
       │
       ▼
   xfreerdp
       │
       ▼
    RDP Auth
       │
       ▼
  Target Desktop
```

### Key point

The attacker does not need to know:

```text
Plaintext Password
```

if the environment permits the hash-based authentication scenario.

---

# 30. ⚠️ RDP PtH Caveat — Restricted Admin Mode

The source identifies an important requirement:

> **Restricted Admin Mode must be enabled on the target host.**

It is disabled by default according to the material.

If the necessary configuration is absent, the PtH attempt will not work as demonstrated.

---

# 31. 🧩 `DisableRestrictedAdmin`

The supplied material explains that Restricted Admin can be enabled by adding:

```text
DisableRestrictedAdmin
```

as a:

```text
REG_DWORD
```

under:

```text
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
```

The example command is:

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Remember

```text
Registry:
HKLM
 └── System
      └── CurrentControlSet
           └── Control
                └── Lsa
                     └── DisableRestrictedAdmin
```

---

# 32. 🐉 `xfreerdp` Pass-the-Hash

The supplied example:

```bash
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9
```

The important option is:

```text
/pth
```

which supplies the NT hash for the authentication attempt.

---

# 33. 🧠 Breaking Down `xfreerdp`

```text
xfreerdp
   │
   ├── /v:<target>
   │       ↓
   │    Target RDP server
   │
   ├── /u:<user>
   │       ↓
   │    Username
   │
   └── /pth:<NT hash>
           ↓
        NT hash
```

---

# 34. 🎯 Successful RDP PtH

If the technique works:

```text
NT Hash
   │
   ▼
xfreerdp
   │
   ▼
RDP Authentication
   │
   ▼
Target User's Desktop
```

The source states that successful use allows the tester to log in through RDP as the target user **without knowing their cleartext password**.

---

# 35. ⚠️ RDP PtH Is Not Universal

This is extremely important.

The material explicitly says:

> **This will not work against every Windows system.**

However, it can be worth trying when all of these conditions are relevant:

```text
You have:
   │
   ├── NTLM hash
   │
   ├── Known user
   │
   ├── User has RDP rights
   │
   └── GUI access is useful
```

---

# 36. 🖼️ Complete RDP Attack Map

```text
                         RDP
                          │
                          ▼
                     TCP/3389
                          │
                          ▼
                    Enumeration
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
        Authentication          Existing Sessions
              │                       │
              ▼                       ▼
       Password Attacks        Session Hijacking
              │                       │
       ┌──────┴──────┐                ▼
       ▼             ▼             SYSTEM
    Guessing      Spraying            │
       │             │                ▼
       └──────┬──────┘             tscon
              │                       │
              ▼                       ▼
       Valid Credentials        Target Session
              │
              ▼
           RDP Login

              OR

          NT Hash
              │
              ▼
        Pass-the-Hash
              │
              ▼
          xfreerdp
              │
              ▼
          RDP Access
```

---

# 37. 🔥 Three Major RDP Attack Techniques

From this material, remember these three:

## 1️⃣ Password Spraying

```text
Many Users
     +
One Password
     ↓
RDP Authentication
```

Tools:

```text
Crowbar
Hydra
```

---

## 2️⃣ Session Hijacking

```text
Existing RDP Session
        ↓
SYSTEM privileges
        ↓
tscon.exe
        ↓
Target Session
```

---

## 3️⃣ Pass-the-Hash

```text
NT Hash
   ↓
Restricted Admin configuration
   ↓
xfreerdp /pth
   ↓
RDP Access
```

---

# 38. 🧰 Tool Cheat Sheet

|Tool|Purpose|
|---|---|
|`nmap`|Identify RDP service|
|`crowbar`|RDP password spraying|
|`hydra`|RDP password spraying|
|`rdesktop`|RDP client|
|`xfreerdp`|RDP client / PtH|
|`query user`|Enumerate logged-in sessions|
|`tscon.exe`|Connect to another Windows session|
|`sc.exe`|Create/manage Windows services|
|`net start`|Start a Windows service|
|`PsExec`|Obtain SYSTEM-level execution in appropriate contexts|
|`Mimikatz`|Credential/security testing tool|

---

# 39. 📌 Important Commands

### Identify RDP

```bash
nmap -Pn -p3389 <TARGET>
```

### Crowbar

```bash
crowbar -b rdp -s <TARGET>/32 -U users.txt -c '<PASSWORD>'
```

### Hydra

```bash
hydra -L usernames.txt -p '<PASSWORD>' <TARGET> rdp
```

### RDP with rdesktop

```bash
rdesktop -u <USER> -p '<PASSWORD>' <TARGET>
```

### RDP with xfreerdp

```bash
xfreerdp /v:<TARGET> /u:<USER> /pth:<NT_HASH>
```

### Enumerate sessions

```cmd
query user
```

### Session connection

```cmd
tscon <SESSION_ID> /dest:<OUR_SESSION>
```

### Create service

```cmd
sc.exe create sessionhijack binpath= "cmd.exe /k tscon <SESSION_ID> /dest:<OUR_SESSION>"
```

### Start service

```cmd
net start sessionhijack
```

### Restricted Admin registry configuration from the source

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

---

# 40. 🧠 Important RDP Enumeration Checklist

When you find:

```text
3389/tcp open
```

think:

```text
             RDP
              │
              ▼
      ┌───────────────┐
      │ Authentication│
      └───────┬───────┘
              │
       ┌──────┴──────┐
       ▼             ▼
   Credentials     NT Hash
       │             │
       ▼             ▼
 Password Spray      PtH
       │             │
       └──────┬──────┘
              ▼
          RDP Access
              │
              ▼
       Privilege Check
              │
              ▼
      Session Enumeration
              │
              ▼
    Potential Session Hijack
```

---

# 41. ⭐ Key Concepts to Memorize

|Concept|Remember|
|---|---|
|RDP|Microsoft's remote desktop protocol|
|Default port|`TCP/3389`|
|RDP service|`ms-wbt-server`|
|Password spraying|One password against many accounts|
|Crowbar|RDP password spraying|
|Hydra|RDP password spraying|
|`rdesktop`|RDP client|
|`xfreerdp`|RDP client|
|Session enumeration|`query user`|
|Session hijacking|Requires `SYSTEM` in the supplied method|
|Session tool|`tscon.exe`|
|Service creation|`sc.exe`|
|PtH|Authenticate using NT hash rather than plaintext password|
|PtH client|`xfreerdp`|
|PtH requirement|Restricted Admin Mode in the supplied scenario|
|Server 2019|Supplied `tscon` method no longer works|

---

# 42. 📝 Viva / Exam Questions

### Q1. What is RDP?

RDP, or Remote Desktop Protocol, is a Microsoft protocol that provides a graphical interface for remotely connecting to another computer.

### Q2. What port does RDP use?

```text
TCP/3389
```

### Q3. How can you identify RDP with Nmap?

```bash
nmap -Pn -p3389 <TARGET>
```

### Q4. What is password spraying?

Trying one password against multiple usernames before moving to another password.

### Q5. Why is password spraying useful against Windows?

Because repeated failed attempts against one account may trigger account lockout policies.

### Q6. Which tools are demonstrated for RDP password spraying?

```text
Crowbar
Hydra
```

### Q7. Which clients can be used to connect to RDP?

```text
rdesktop
xfreerdp
```

### Q8. What is RDP session hijacking?

Taking control of an already-established RDP session belonging to another user.

### Q9. What privileges are required for the supplied session-hijacking technique?

```text
SYSTEM
```

### Q10. Which Windows binary is used?

```text
tscon.exe
```

### Q11. Which command displays active user sessions?

```cmd
query user
```

### Q12. What can `sc.exe` be used for in the example?

To create a Windows service that runs the session-connection command under the service's SYSTEM context.

### Q13. What is Pass-the-Hash?

Using an NT hash for authentication instead of recovering and supplying the user's plaintext password.

### Q14. Which tool is used for RDP PtH in the material?

```text
xfreerdp
```

### Q15. Which option specifies the NT hash?

```text
/pth
```

### Q16. What is an important requirement for the supplied RDP PtH technique?

**Restricted Admin Mode** must be enabled on the target.

### Q17. Does RDP PtH work on every Windows system?

No. The source explicitly warns that it does not work against every Windows system.

### Q18. Does the supplied RDP session-hijacking technique work on Server 2019?

The material states:

**No — this method no longer works on Server 2019.**

---

# 🏆 43. One-Minute Revision

```text
                     RDP
                      │
                 TCP/3389
                      │
                      ▼
                 ENUMERATION
                      │
                      ▼
                AUTHENTICATION
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
      Password     Password      NT Hash
       Guessing    Spraying        │
          │           │            │
          │       Crowbar          │
          │       Hydra            │
          │           │            │
          └─────┬─────┘            │
                ▼                  ▼
             RDP Login          Pass-the-Hash
                                   │
                                xfreerdp
                                   │
                                   ▼
                               RDP Access

          Existing RDP Session
                  │
                  ▼
             SYSTEM Privileges
                  │
                  ▼
               tscon.exe
                  │
                  ▼
          Session Hijacking
                  │
                  ▼
          User Impersonation
```

## 🔥 Final Takeaway

The **three things you absolutely need to remember** from this RDP section are:

```text
1. RDP
   → TCP/3389
   → Enumerate with Nmap

2. Password Spraying
   → One password
   → Many usernames
   → Crowbar / Hydra

3. Advanced Access
   → Session Hijacking
   → SYSTEM + tscon.exe

   OR

   → Pass-the-Hash
   → NT Hash + Restricted Admin
   → xfreerdp /pth
```

The overall pentesting mindset is:

> **Find RDP → understand authentication → identify valid credentials or hashes → obtain RDP access → enumerate privileges and existing sessions → look for further access.**