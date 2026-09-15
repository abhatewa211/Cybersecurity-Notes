## 1. What is Windows Privilege Escalation?

After gaining a **foothold** on a Windows machine, our next objective may be to **increase our privileges**.

The general goal is to escalate our access to:

- `Local Administrators`
    
- `NT AUTHORITY\SYSTEM` (`LocalSystem`)
    

However, **SYSTEM is not always required**. Sometimes gaining access to another user account is enough to achieve the assessment objective.

### Why is privilege escalation important?

Higher privileges can provide access to:

- Sensitive files
    
- Credentials
    
- Local databases
    
- Protected system resources
    
- Other user information
    
- Domain resources
    
- Additional systems through lateral movement
    

Privilege escalation can therefore be an important step toward the **ultimate objective of a penetration test**.

---

# 🧠 High-Level Privilege Escalation Flow

![Image](https://images.openai.com/static-rsc-4/QYmi-rmqykLMREWqsQ2E11kqDBgJMq0CiWxQEtbpKMYKwV5R8AgsOCKY7OhtwLdQtAqSaxp-FYCyjZk6TqEZ1V1TzDIk7MOyGPGk_pULeScirNruz0p1P3OAAOwlYvlDGtCBwriMNZASN4r20XOjbGWy4-8TUhea3YdWIYuO0DEBhaQ7qRVEV9iH3QPtmG2Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QjbkN66FvmsSNa-9PyHp_68zTXKcj1wCvOK6pju3sMVf-vtexagU7j3wbqwp6_-TqMUY7hC0JFz5X264MCEWG0RjCYFGCx3Ox19ZUTHsxUB8PNw-FFRd3fJaYbWMEF1amnT4sXDATIbPZGm5T6ik-4nQWVqYdueNsEkKOcADnmbzqhfHpTKILfN9d4jf7Krv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cQ4Xzy9oac14LUZSxikcS3I5zVICU199Djx_J3PKrTplhhQAF_CkR6K83HVl7uSAEQqEeGYAxdLZeN0z8cexBpaQSf3VZKMu6FYng3t58aTkn-DMd_7FDpnCIlbGnXGSlnCg9PQ1914Rwpz9gqCRceyt2m89thG3DmWfYCMiz2ggPuXDop_I0ebCUlQJVT-S?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Wo-wohqNlT6poRWnyRtMNvKBKEGQ3rA4ZPDF-y-0zgoAAaVx7o7RQQStnRAv0-wvYlIRBRVEyaBh7A7cSgvF2eXinAxx9Ee25bDO7TB7vdxBBZSgSqz_jcsOEfG3hJAdzmdByYHV5DS08yt1lnJaAmn1Q8E4yHuArkvCNtR9_soLnEKVYoDRzV9r6Uwd6_7C?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ir5Bm6Bpl2z9HGiGWMQ5Suh1dt6D-jKzONEdfE-TcdjEtEjeGmFHAPt5_40T7p2bV6iP2bNqIKjuv5VK1TN066BNV0-X6U4vEtjWNXSBueS84-TrsQwKHx9YvVELcVLlLMLLCmO_7QIt_ISGMcv5_r99LXMsRDsugZt1_jxe_DzkoUM9PTWZ-eIKS8v-anym?purpose=fullsize)

```text
              Initial Foothold
                     │
                     ▼
          Low-Privileged User
                     │
                     ▼
              Enumeration
     ┌───────────────┼────────────────┐
     │               │                │
     ▼               ▼                ▼
   Users           Services         Files
   Groups          Permissions      Credentials
   Privileges      UAC              Shares
     │               │                │
     └───────────────┼────────────────┘
                     ▼
          Identify Weakness
                     │
                     ▼
          Privilege Escalation
                     │
              ┌──────┴──────┐
              ▼             ▼
      Local Administrator  SYSTEM
              │             │
              └──────┬──────┘
                     ▼
       Further Access / Lateral Movement
```

---

# ⭐ 2. Why Do We Need Privilege Escalation?

The source gives four major reasons.

|#|Reason|
|---|---|
|**1**|Testing a client's **gold image** Windows workstation/server build for flaws|
|**2**|Escalating locally to access a local resource such as a **database**|
|**3**|Gaining `NT AUTHORITY\SYSTEM` on a **domain-joined machine** to gain a foothold into Active Directory|
|**4**|Obtaining credentials for **lateral movement** or further privilege escalation|

### ⭐ Remember this for CPTS

> **Initial Access → Privilege Escalation → Credential Access → Lateral Movement**

Privilege escalation isn't necessarily the final objective.

It can simply be the step that gives you the access required for the **next stage of the engagement**.

---

# 🔎 3. Manual Enumeration is Extremely Important

There are many tools available for Windows privilege escalation.

However, the source emphasizes that you should understand how to perform the checks **manually**.

Why?

Imagine you are given a client workstation where:

- ❌ No Internet access
    
- ❌ USB ports disabled
    
- ❌ Heavy firewall restrictions
    
- ❌ You cannot upload enumeration scripts
    
- ❌ You cannot install your normal tools
    

In this situation, automated tools may not be available.

You therefore need a strong understanding of:

### PowerShell

and

### Windows Command Line

⭐ **CPTS mindset:**  
Don't just memorize a tool like WinPEAS. Understand **what WinPEAS is checking**.

---

# ⚔️ 4. Common Windows Privilege Escalation Paths

The source identifies several broad attack areas:

![Image](https://images.openai.com/static-rsc-4/Xe_1RB4sAw5nq_uvZ5FcAVXEjEfM0WHzDmJnU39oNM4no9WTnrxpB_RBNsqVJxPr78r7WkF_sGBcPp20PqDOO8Ysf2g_1cCx-Voj7nOaQkGzTtpoebIKVKiq0ojQSp_Nttn3w4o-Db25NxY6GIEWIaaO8x0txFPlo38aQMhOt-VcX01PSjwUW1GStt25tqsd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/57twM8ZhODVIl77zfGjuB8ibGKVcRWWfHLeNcBS29zNYnJwiVTeukv6Xa7Ih-dDum5JcVZUMoVrAfETgV7McpMZk8HbtSSgFxntbYLDRNkQltRTA8tGN3fFZy0usRrd-2W_4Aik8S_2MREP07AKIPzMD5semxD5K_i1ejyE095TFEKcX3GwRw9jRCODQretg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0rwHwDrSDj9Q5-xxsH9BgYGrpR4hFI6KZRgwKa4S3mtX_AbcGNWg7UcIvo6la8pcdLQIB3xOVVZ11jCcoAtZGykjPQ1SF20fJTttWq2En5WBJUZ3vOBM6O2td3fP0zV7ZRM6HjfmWUaEEsipNhAN0F54c1Dpf0Ibby6CQL_hdMQOk2PHRouDV6V_uHFgyv1_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ir5Bm6Bpl2z9HGiGWMQ5Suh1dt6D-jKzONEdfE-TcdjEtEjeGmFHAPt5_40T7p2bV6iP2bNqIKjuv5VK1TN066BNV0-X6U4vEtjWNXSBueS84-TrsQwKHx9YvVELcVLlLMLLCmO_7QIt_ISGMcv5_r99LXMsRDsugZt1_jxe_DzkoUM9PTWZ-eIKS8v-anym?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/auC8G_sGjnLuwhwdfp8u4m9ceRyXzOVDkfJ-vpfaUyG0eTP-KznogKq2YfpW92oSM_YV5eT1NTlN6novzjuAGxQL10oWw2gFbCGVuF7mM-l7reE5R7ucGxrm8S19lA6-0UYkmnmcHkTgqILBV_4vc-I0epz94MsC8owCnMHPkO1mxLhn7qUQa9Ug-yJnP_T8?purpose=fullsize)

### 1️⃣ Abusing Windows Group Privileges

A user's group membership may provide additional privileges or access.

---

### 2️⃣ Abusing Windows User Privileges

Individual Windows privileges assigned to an account can sometimes provide an escalation path.

---

### 3️⃣ Bypassing User Account Control (UAC)

UAC is designed to control elevation of privileges.

Misconfigurations or certain conditions can potentially allow elevation.

---

### 4️⃣ Weak Service/File Permissions

Poor permissions can allow a low-privileged user to modify:

- Services
    
- Executables
    
- Files
    
- Directories
    

This can potentially lead to execution with a higher-privileged account.

---

### 5️⃣ Unpatched Kernel Exploits

An outdated Windows system may contain a vulnerability that allows local privilege escalation.

---

### 6️⃣ Credential Theft

Credentials or authentication material may be found locally.

Those credentials could potentially provide:

- Administrative access
    
- Another user's access
    
- Domain access
    
- Lateral movement opportunities
    

---

### 7️⃣ Traffic Capture

Network traffic may sometimes expose authentication material.

---

# 🧩 5. Scenario 1 — Overcoming Network Restrictions

This is an excellent example of **thinking outside the box**.

The tester was placed on a system with:

- No Internet access
    
- Blocked USB ports
    
- Network restrictions
    

The tester couldn't simply connect their attack machine directly to the user's network.

### Attack chain

```text
Restricted Windows System
          │
          ▼
   Network Enumeration
          │
          ▼
Printer VLAN discovered
          │
          ▼
Ports 80 / 443 / 445 allowed outbound
          │
          ▼
Permissions-related flaw
          │
          ▼
Privilege Escalation
          │
          ▼
LSASS Memory Dump
          │
          ▼
SMB Share
          │
          ▼
Transfer LSASS DMP
          │
          ▼
Offline Analysis with Mimikatz
          │
          ▼
Domain Admin NTLM Hash
          │
          ▼
Offline Cracking
          │
          ▼
Domain Controller Access
```

### Important details

The tester discovered that the **printer VLAN** allowed outbound communication over:

- Port `80`
    
- Port `443`
    
- Port `445`
    

A permissions-related vulnerability was then identified.

This allowed:

1. Privilege escalation
    
2. Manual LSASS memory dumping
    
3. Transfer of the LSASS dump through SMB
    
4. Offline analysis
    
5. Recovery of a domain administrator's NTLM password hash
    

The hash could then be cracked offline and used to access a domain controller.

### ⭐ CPTS takeaway

**Don't assume network restrictions mean you're stuck.**

Look at:

- What traffic is allowed?
    
- Which VLAN are you on?
    
- Which ports are reachable?
    
- Can existing network paths be used?
    
- Can data be transferred through an allowed service?
    

---

# 🧠 6. LSASS

**LSASS = Local Security Authority Subsystem Service**

In the source scenario, a memory dump of the LSASS process was obtained.

The dump was then analyzed offline to recover credential material.

### Important concept

```text
LSASS
  ↓
Memory
  ↓
Credential Material
  ↓
Memory Dump
  ↓
Offline Analysis
```

The source specifically describes using **Mimikatz** offline to retrieve an NTLM password hash for a domain administrator.

---

# 📂 7. Scenario 2 — Pillaging Open Shares

This scenario demonstrates why **file shares and backups** should never be ignored.

The environment was:

- Locked down
    
- Well monitored
    
- Without obvious configuration flaws
    
- Without obvious vulnerable services
    

But the tester discovered an **open file share**.

All users could:

- List its contents
    
- Download files
    

### Attack chain

```text
Open File Share
      │
      ▼
VM Backups
      │
      ▼
VMDK / VHDX Files
      │
      ▼
Mount VHDX
      │
      ▼
Browse Windows Filesystem
      │
      ▼
SYSTEM / SAM / SECURITY
Registry Hives
      │
      ▼
Move to Linux
      │
      ▼
secretsdump.py
      │
      ▼
Local Administrator Hash
      │
      ▼
Pass-the-Hash
      │
      ▼
Administrative Access
```

---

# 💾 8. VMDK and VHDX

These are virtual hard-drive formats.

The source specifically focuses on:

- `.VMDK`
    
- `.VHDX`
    

A backup containing one of these files can potentially expose the filesystem of a virtual machine.

In the scenario, the tester:

1. Accessed the file share.
    
2. Downloaded a `.VHDX`.
    
3. Mounted it as a local drive.
    
4. Browsed the filesystem.
    
5. Retrieved registry hives.
    

---

# 🔑 9. SYSTEM, SAM and SECURITY Hives

The three important registry hives mentioned are:

```text
SYSTEM
SAM
SECURITY
```

The source describes retrieving these hives from the mounted virtual hard drive and moving them to a Linux attack machine.

Then:

```text
SYSTEM + SAM + SECURITY
             │
             ▼
       secretsdump.py
             │
             ▼
 Local Administrator Hash
```

The organization was using a **gold image**.

Therefore, the recovered local administrator hash could potentially be used against many Windows systems.

The source specifically describes using the hash for a **pass-the-hash attack**.

---

# ⭐ 10. Gold Image — Why It Matters

A **gold image** is a standardized Windows system image used to deploy multiple machines.

The danger is:

```text
Same Image
     ↓
Same Local Admin Configuration
     ↓
Potentially Same Password/Hash
     ↓
Compromise One Backup
     ↓
Potentially Affect Many Systems
```

### CPTS takeaway

Whenever you discover:

- Backups
    
- VM images
    
- System images
    
- Configuration backups
    
- File shares
    

**Don't immediately ignore them.**

They may contain extremely valuable information.

---

# 🎯 11. Scenario 3 — Hunting Credentials & Abusing Account Privileges

This scenario combines multiple techniques.

The tester started with a:

> Standard domain user account

The environment was restricted and the goal was to access critical database servers.

### Attack chain

```text
Standard Domain User
          │
          ▼
       Snaffler
          │
          ▼
       File Shares
          │
          ▼
     .SQL Files
          │
          ▼
Database Credentials
          │
          ▼
        MSSQL
          │
          ▼
     xp_cmdshell
          │
          ▼
Local Command Execution
          │
          ▼
     Service Account
          │
          ▼
SeImpersonatePrivilege
          │
          ▼
     Juicy Potato
          │
          ▼
   Local Administrator
          │
          ▼
Database Host Access
```

---

# 🔍 12. Snaffler

The source describes using **Snaffler** to hunt file shares for sensitive information.

It discovered `.sql` files containing credentials for a database.

### Key lesson

Credentials don't necessarily appear in:

```text
password.txt
credentials.txt
```

They may appear inside:

- `.sql`
    
- Configuration files
    
- Scripts
    
- Backups
    
- Documentation
    
- Deployment files
    
- Shared folders
    

---

# 🗄️ 13. MSSQL + xp_cmdshell

The tester found database credentials.

Those credentials were used with an MSSQL client.

Then:

```text
MSSQL
  ↓
xp_cmdshell
  ↓
Command Execution
```

The source specifically says that `xp_cmdshell` was enabled and used to gain local command execution.

### Important concept

`xp_cmdshell` is a SQL Server stored procedure capable of executing operating-system commands.

Therefore, database access can sometimes become **OS-level access**.

---

# 👤 14. Service Accounts

The command execution occurred as a **service account**.

The tester then checked the account's privileges.

One particularly important privilege was found:

```text
SeImpersonatePrivilege
```

The source states that this privilege can be leveraged for local privilege escalation.

---

# 🚨 15. SeImpersonatePrivilege

This is a **very important Windows privilege to recognize during enumeration**.

When you obtain a shell as a service account, don't stop at:

```text
whoami
```

You should also investigate the privileges associated with that account.

Conceptually:

```text
Service Account
      │
      ▼
Privilege Enumeration
      │
      ▼
SeImpersonatePrivilege
      │
      ▼
Potential Local Privilege Escalation
```

The source's scenario used **Juicy Potato** to assist with escalation.

---

# 🥔 16. Juicy Potato

The source describes transferring a custom-compiled version of **Juicy Potato** to the host.

The goal was to assist with local privilege escalation.

The tester eventually added a local administrator user because obtaining a beacon/reverse shell was unsuccessful.

### Important lesson

Your preferred technique may not always work.

A real penetration test requires:

> **Adaptability.**

If:

```text
Reverse Shell ❌
```

you may need to find another way to demonstrate impact within the rules of the engagement.

---

# 🧠 17. Why Does Privilege Escalation Happen?

There isn't one single reason.

The source highlights:

### 👥 Personnel

Organizations may not have enough staff to properly handle:

- Patching
    
- Vulnerability management
    
- Assessments
    
- Monitoring
    
- System upgrades
    
- File-share auditing
    

### 💰 Budget

Security improvements require resources.

Limited budgets can result in:

- Old systems
    
- Poor patching
    
- Weak monitoring
    
- Poorly maintained infrastructure
    
- Inadequately secured file shares
    

---

# ⚠️ 18. Common Root Causes

```text
                    Privilege Escalation
                           │
       ┌───────────────────┼───────────────────┐
       ▼                   ▼                   ▼
   Poor Patching      Weak Permissions    Credential Exposure
       │                   │                   │
       ▼                   ▼                   ▼
   Old Software       Services/Files       Passwords
       │                   │                   │
       └───────────────────┼───────────────────┘
                           ▼
                     Higher Access
```

Other causes include:

- Weak file-share security
    
- Sensitive scripts
    
- Configuration files containing credentials
    
- Insufficient monitoring
    
- Lack of periodic security assessments
    

---

# 🧪 19. Practical Lab Environment

The source explains that later sections contain:

- Command output
    
- Practical examples
    
- Target VMs
    
- RDP credentials
    
- Exercises
    
- Skills assessments
    

You can connect using:

- Pwnbox
    
- Your own VM
    
- RDP
    

The source mentions:

- FreeRDP
    
- Remmina
    
- Other RDP clients
    

---

# 💻 20. FreeRDP

The source provides this command:

```bash
xfreerdp /v:<target ip> /u:htb-student
```

Example:

```bash
xfreerdp /v:10.129.43.36 /u:htb-student
```

### What does it mean?

```text
xfreerdp
   │
   ├── /v:<target ip>
   │       └── RDP target
   │
   └── /u:htb-student
           └── Username
```

You'll then be prompted for the password.

---

# 🔐 21. Understanding the RDP Certificate Warning

The example shows a certificate warning.

It reports:

```text
self signed certificate
```

and:

```text
CERTIFICATE NAME MISMATCH!
```

The certificate's Common Name was:

```text
WINLPE-SKILLS1-SRV
```

while the connection was made using:

```text
10.129.43.36:3389
```

Therefore, the hostname/IP did not match the certificate name.

### ⭐ Important security concept

A certificate warning shouldn't automatically be ignored in a real environment.

In a controlled HTB lab, you may encounter these warnings because of the lab's certificate configuration.

---

# 🧰 22. Tools Mentioned

|Tool|Purpose in the source|
|---|---|
|**PowerShell**|Manual Windows enumeration|
|**Windows CLI**|Manual enumeration|
|**Mimikatz**|Offline analysis of LSASS dump|
|**SMB**|File transfer in Scenario 1|
|**Snaffler**|Hunting file shares|
|**MSSQL client**|Database connection|
|**xp_cmdshell**|Local command execution|
|**secretsdump.py**|Extracting password hashes from registry hives|
|**Juicy Potato**|Assisting local privilege escalation|
|**FreeRDP**|RDP access|

The source also notes that relevant tools, scripts, precompiled binaries, and exploit PoCs may be available in:

```text
C:\Tools
```

on the target host.

---

# 🧠 23. CPTS Mindset

This entire introduction is teaching you something more important than individual exploits.

## Don't think:

> "Which exploit should I run?"

Think:

> **"What access do I have, what can this account access, and what weakness can turn that access into something more powerful?"**

### Example

You obtain:

```text
Low Privileged User
```

Don't immediately launch an exploit.

First ask:

```text
Who am I?
        ↓
What groups am I in?
        ↓
What privileges do I have?
        ↓
What services exist?
        ↓
What can I modify?
        ↓
What files can I read?
        ↓
Are credentials exposed?
        ↓
Are there interesting shares?
        ↓
Is the system patched?
        ↓
Is there a path to Administrator/SYSTEM?
```

---

# ⭐ 24. MOST IMPORTANT POINTS TO MEMORIZE

### 🔥 Privilege Escalation

**Initial foothold → higher privileges**

Common goals:

```text
Local Administrator
        OR
NT AUTHORITY\SYSTEM
```

But another user can sometimes be sufficient.

### 🔥 Manual Enumeration

Learn:

```text
PowerShell
Windows CMD
```

Don't depend completely on automated tools.

### 🔥 Major Attack Areas

Remember:

```text
Groups
Users
UAC
Services
Files
Kernel
Credentials
Traffic
```

### 🔥 Scenario 1

```text
Printer VLAN
→ Permissions flaw
→ LSASS dump
→ SMB
→ Mimikatz
→ Domain Admin hash
→ Domain Controller
```

### 🔥 Scenario 2

```text
Open Share
→ VHDX
→ SYSTEM/SAM/SECURITY
→ secretsdump.py
→ Local Admin Hash
→ Pass-the-Hash
```

### 🔥 Scenario 3

```text
Snaffler
→ SQL credentials
→ MSSQL
→ xp_cmdshell
→ Service Account
→ SeImpersonatePrivilege
→ Juicy Potato
→ Local Admin
```

---

# 🎯 25. Quick Revision — 30 Seconds

> **Windows privilege escalation is the process of increasing access after obtaining a foothold.**

Main objectives:

**Local Administrator / SYSTEM**

Main areas:

**Users → Groups → Privileges → UAC → Services → Files → Credentials → Kernel → Network**

Three scenarios:

**LSASS → credentials**

**VHDX → registry hives → hash**

**SQL credentials → xp_cmdshell → SeImpersonatePrivilege**

And the biggest CPTS lesson:

> **Enumeration comes before exploitation.**

The source concludes by emphasizing that real-world engagements rarely involve attacking just one host and that a tester must be able to think creatively and find ways to use elevated access to progress toward the assessment objective.