## 1. What Is a Domain Trust?

A **domain trust** establishes a relationship between two Active Directory domains so that authentication can occur across them.

In simple terms:

```text
Domain A
   │
   │ Trust
   ▼
Domain B
```

A trust can allow users from one domain to:

- Authenticate to another domain
    
- Access resources in another domain
    
- Perform administrative tasks in another domain
    

The important concept is that a user's account does **not necessarily have to exist in the same domain as the resource they are accessing**.

---

# 2. Why Organizations Use Domain Trusts

Large organizations frequently acquire other companies.

Instead of migrating every:

- User
    
- Computer
    
- Group
    
- Application
    
- Resource
    
- Service
    

into a single domain, the organizations can establish a **trust relationship**.

This makes integration much faster.

### Example

Suppose:

```text
Company A
INLANEFREIGHT.LOCAL
```

acquires:

```text
Company B
LOGISTICS.INLANEFREIGHT.LOCAL
```

Rather than immediately migrating all objects:

```text
LOGISTICS
    ↓
Migration
    ↓
INLANEFREIGHT
```

they can establish:

```text
INLANEFREIGHT.LOCAL
        ↕
LOGISTICS.INLANEFREIGHT.LOCAL
```

Users can then authenticate across the trust.

---

# 3. Why Trusts Matter During a Penetration Test

A trust can create an **additional attack path**.

The key idea is:

> A trusted domain can become a path into another domain.

For example:

```text
Attacker
   ↓
Compromise trusted domain
   ↓
Obtain credentials / privileges
   ↓
Cross trust
   ↓
Target domain
```

A domain that appears less important may therefore become the easiest route toward a more sensitive domain.

### Important scenario

An organization may have:

```text
Main Domain
     ↕
Acquired Company
```

If the acquired company's security posture is weaker, an attacker could potentially compromise that environment first and then use the trust relationship to reach the main organization.

The module refers to this type of indirect route as an:

```text
"end-around" attack
```

This is why **trust enumeration should be performed early after obtaining a foothold**.

---

# 4. Types of Domain Trusts

The major trust types covered in the module are:

1. Parent-child
    
2. Cross-link
    
3. External
    
4. Tree-root
    
5. Forest
    
6. ESAE / Bastion Forest
    

---

# 5. Parent-Child Trust

A **parent-child trust** exists between domains inside the same forest.

Example:

```text
inlanefreight.local
        │
        │ Parent
        ▼
logistics.inlanefreight.local
        Child
```

The child domain has a:

```text
Two-way
Transitive
Trust
```

with the parent.

Therefore:

```text
Child → Parent
Parent → Child
```

authentication can occur.

The module's example states that users in:

```text
corp.inlanefreight.local
```

could authenticate into:

```text
inlanefreight.local
```

and vice versa.

### Important

```text
Parent-child
= Within same forest
= Two-way
= Transitive
```

---

# 6. Cross-Link Trust

A **cross-link** trust exists between child domains.

Example:

```text
                Forest Root
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
      Child A              Child B
          │                   │
          └──── Cross-link ───┘
```

Its purpose is to **speed up authentication** between child domains.

Without a shortcut, authentication may need to travel through the hierarchy.

A cross-link provides a more direct relationship.

---

# 7. External Trust

An **external trust** is generally:

```text
Non-transitive
```

and exists between separate domains in separate forests that are not already connected through a forest trust.

Example:

```text
Forest A                    Forest B

Domain A  <──────────────>  Domain B
              External
               Trust
```

External trusts use:

```text
SID Filtering
```

to help prevent inappropriate SID-based privilege claims from crossing the trust.

### Remember

```text
External Trust
    ↓
Separate forests
    ↓
Non-transitive
    ↓
SID Filtering
```

---

# 8. Tree-Root Trust

A **tree-root trust** exists between:

- The forest root domain
    
- A new tree-root domain
    

Example:

```text
                Forest
                  │
       ┌──────────┴──────────┐
       ▼                     ▼
inlanefreight.local      anotherroot.local
     Tree 1                   Tree 2
```

It is:

```text
Two-way
Transitive
```

and is created by design when a new tree root is established inside the forest.

---

# 9. Forest Trust

A **forest trust** is a transitive trust between two forest root domains.

Example:

```text
Forest A                         Forest B

RootA.local  <────────────────>  RootB.local
                 Forest Trust
```

The module's example:

```text
INLANEFREIGHT.LOCAL
        ↕
FREIGHTLOGISTICS.LOCAL
```

uses:

```text
FOREST_TRANSITIVE
```

in the trust attributes.

---

# 10. ESAE / Bastion Forest

**ESAE** refers to an administrative security architecture involving a dedicated forest used to manage Active Directory.

The module describes it as:

```text
A bastion forest used to manage Active Directory.
```

This is an advanced AD architecture concept and becomes particularly relevant when studying privileged administration and forest-level security.

---

# 11. Transitive vs Non-Transitive Trust

This is one of the most important concepts in the module.

## Transitive Trust

A transitive trust can extend beyond the directly trusted domain.

Example:

```text
Domain A
   ↕
Domain B
   ↕
Domain C
```

If:

```text
A trusts B
B trusts C
```

and the relationships are transitive, trust can extend:

```text
A → C
```

The module describes it as:

> Trust is extended to objects that the child domain trusts.

### Simple model

```text
A ─── Trust ─── B
                 │
                 │ Transitive
                 ▼
                 C

A can potentially trust C
```

---

# 12. Non-Transitive Trust

A non-transitive trust is limited to the directly trusted relationship.

Example:

```text
A ───── Trust ───── B
```

If B trusts C separately, that does **not automatically mean** A trusts C.

```text
A ─── B

B ─── C

A ───X─── C
```

### Easy way to remember

**Transitive:**

```text
A → B → C
A → C
```

**Non-transitive:**

```text
A → B
B → C
A ✗ C
```

---

# 13. Transitive vs Non-Transitive Table

|Transitive|Non-Transitive|
|---|---|
|Shared relationship|Direct trust|
|Can extend through the trust chain|Does not extend automatically|
|1-to-many concept|Direct relationship|
|Forest|Typical external/custom trust|
|Tree-root|—|
|Parent-child|—|
|Cross-link|—|

The module explicitly identifies forest, tree-root, parent-child and cross-link trusts as transitive.

---

# 14. One-Way vs Two-Way Trust

Trust direction is another critical concept.

There are two major configurations:

```text
One-way
Two-way / Bidirectional
```

---

# 15. One-Way Trust

In a one-way trust:

```text
Trusted Domain
       ↓
Trusting Domain
```

Users in the trusted domain can access resources in the trusting domain.

But the reverse is not automatically true.

### Remember

```text
Trusted → Trusting
```

does not mean:

```text
Trusting → Trusted
```

The module states:

> Users in a trusted domain can access resources in a trusting domain, not vice versa.

---

# 16. Bidirectional Trust

A bidirectional trust allows authentication in both directions.

Example:

```text
INLANEFREIGHT.LOCAL
        ↕
FREIGHTLOGISTICS.LOCAL
```

Users from either domain can authenticate across the relationship, subject to permissions and authentication conditions.

### Remember

```text
A ↔ B
```

means:

```text
A → B
B → A
```

---

# 17. Why Trust Direction Matters During Enumeration

Suppose you compromise:

```text
DOMAIN A
```

and discover:

```text
A ↔ B
```

This is immediately interesting because authentication can potentially occur across the trust.

But if you find:

```text
A → B
```

you need to understand exactly which side is trusted/trusting before attempting cross-domain access.

The module emphasizes that if you cannot authenticate across a trust, you cannot perform enumeration or attacks across it.

---

# 18. Trust Enumeration

After gaining a foothold in an AD environment, one of the first questions should be:

> **What trusts exist?**

Useful tools include:

```text
Get-ADTrust
Get-DomainTrust
Get-DomainTrustMapping
netdom
BloodHound
```

---

# 19. Get-ADTrust

`Get-ADTrust` is part of the built-in:

```text
ActiveDirectory
```

PowerShell module.

First:

```powershell
Import-Module activedirectory
```

Then:

```powershell
Get-ADTrust -Filter *
```

This can reveal:

- Trust direction
    
- Target domain
    
- Source domain
    
- Whether it is intra-forest
    
- Whether it is forest-transitive
    
- SID filtering settings
    
- Trust attributes
    
- TGT delegation
    
- Encryption information
    

---

# 20. Important Get-ADTrust Fields

Example:

```text
Direction               : BiDirectional
DisallowTransivity      : False
ForestTransitive        : False
IntraForest             : True
Name                    : LOGISTICS.INLANEFREIGHT.LOCAL
SelectiveAuthentication : False
SIDFilteringForestAware : False
SIDFilteringQuarantined : False
Source                  : DC=INLANEFREIGHT,DC=LOCAL
Target                  : LOGISTICS.INLANEFREIGHT.LOCAL
TGTDelegation           : False
TrustType               : Uplevel
```

These fields should be understood rather than simply memorized.

---

# 21. IntraForest

Example:

```text
IntraForest : True
```

This indicates that the trust is within the same forest.

In the module:

```text
INLANEFREIGHT.LOCAL
        ↕
LOGISTICS.INLANEFREIGHT.LOCAL
```

is identified as a child-domain relationship because:

```text
IntraForest : True
```

---

# 22. ForestTransitive

Example:

```text
ForestTransitive : True
```

This indicates a forest-transitive trust relationship.

The module uses:

```text
FREIGHTLOGISTICS.LOCAL
```

as an example.

Important values:

```text
ForestTransitive : True
IntraForest      : False
```

---

# 23. SID Filtering

SID filtering is particularly important for trusts between separate forests.

The basic purpose is to prevent a domain from presenting arbitrary SIDs from another security authority in a way that could result in unintended privilege.

Think:

```text
Authentication
      ↓
SID information
      ↓
SID Filtering
      ↓
Filter unauthorized SID claims
```

The module specifically associates SID filtering with external trusts.

---

# 24. Selective Authentication

The field:

```text
SelectiveAuthentication
```

can appear when enumerating trusts.

It is important because trust existence does not automatically mean unrestricted access to every resource.

Selective authentication can restrict where trusted users are allowed to authenticate.

Therefore, when assessing a trust, don't only record:

```text
Trust exists
```

Also examine:

```text
Direction
SelectiveAuthentication
SID Filtering
Transitivity
```

---

# 25. PowerView — Get-DomainTrust

PowerView provides:

```powershell
Get-DomainTrust
```

Example:

```powershell
Get-DomainTrust
```

The module's example returns:

```text
SourceName      : INLANEFREIGHT.LOCAL
TargetName      : LOGISTICS.INLANEFREIGHT.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
```

and:

```text
SourceName      : INLANEFREIGHT.LOCAL
TargetName      : FREIGHTLOGISTICS.LOCAL
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Bidirectional
```

---

# 26. Get-DomainTrust vs Get-ADTrust

### Built-in AD PowerShell

```powershell
Get-ADTrust -Filter *
```

### PowerView

```powershell
Get-DomainTrust
```

Both can provide useful information about domain trust relationships.

### Quick memory

```text
Get-ADTrust
     ↓
Microsoft ActiveDirectory module

Get-DomainTrust
     ↓
PowerView
```

---

# 27. Get-DomainTrustMapping

PowerView also provides:

```powershell
Get-DomainTrustMapping
```

This is useful for building a broader picture of the trust relationships.

Example:

```text
INLANEFREIGHT.LOCAL
        ↕
LOGISTICS.INLANEFREIGHT.LOCAL

INLANEFREIGHT.LOCAL
        ↕
FREIGHTLOGISTICS.LOCAL
```

The output can show relationships in both directions.

---

# 28. Why Trust Mapping Is Useful

Suppose you have compromised:

```text
INLANEFREIGHT.LOCAL
```

and discover:

```text
LOGISTICS.INLANEFREIGHT.LOCAL
```

The next step is not immediately to attack.

First understand:

```text
What type of trust?
What direction?
Same forest?
Different forest?
Can I authenticate?
What accounts exist there?
```

This gives you a map of the potential attack surface.

---

# 29. Enumerating Users Across a Trust

Once a trust exists and cross-domain authentication/enumeration is possible, PowerView can query the child domain.

Example:

```powershell
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL |
select SamAccountName
```

Example output:

```text
samaccountname
--------------
htb-student_adm
Administrator
Guest
lab_adm
krbtgt
```

### Important

This demonstrates that after discovering a trust, you may be able to perform **enumeration in the other domain**.

---

# 30. netdom

Windows includes another useful tool:

```text
netdom
```

It can query information about:

- Domain trusts
    
- Domain controllers
    
- Workstations
    
- Servers
    

---

# 31. Query Domain Trusts with netdom

Command:

```cmd
netdom query /domain:inlanefreight.local trust
```

Example:

```text
Direction Trusted\Trusting domain
========= =======================
<->       LOGISTICS.INLANEFREIGHT.LOCAL
<->       FREIGHTLOGISTICS.LOCAL
```

The `<->` indicates bidirectional relationships in the example.

---

# 32. Query Domain Controllers

Command:

```cmd
netdom query /domain:inlanefreight.local dc
```

Example:

```text
List of domain controllers with accounts in the domain:

ACADEMY-EA-DC01
```

---

# 33. Query Workstations

Command:

```cmd
netdom query /domain:inlanefreight.local workstation
```

Example output includes:

```text
ACADEMY-EA-MS01
ACADEMY-EA-MX01
SQL01
ILF-XRG
MAINLON
CISERVER
INDEX-DEV-LON
```

---

# 34. BloodHound Trust Visualization

BloodHound can visually represent trust relationships.

The module recommends the pre-built query:

```text
Map Domain Trusts
```

This allows you to quickly see relationships between domains.

Example conceptual graph:

```text
                    ┌─────────────────────┐
                    │ INLANEFREIGHT.LOCAL │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │                     │
             Bidirectional        Bidirectional
                    │                     │
                    ▼                     ▼
       ┌────────────────────┐   ┌─────────────────────┐
       │ LOGISTICS...LOCAL  │   │ FREIGHTLOGISTICS... │
       └────────────────────┘   └─────────────────────┘
```

The module's BloodHound visualization shows two bidirectional trusts.

---

# 35. Trust Enumeration Workflow

A good workflow is:

```text
1. Obtain foothold
        ↓
2. Identify current domain
        ↓
3. Enumerate trusts
        ↓
4. Determine trust type
        ↓
5. Determine trust direction
        ↓
6. Determine transitivity
        ↓
7. Identify target domain
        ↓
8. Determine whether cross-domain authentication works
        ↓
9. Enumerate users/groups/resources
        ↓
10. Assess potential attack paths
```

---

# 36. Tool Cheat Sheet

|Purpose|Command|
|---|---|
|Built-in trust enumeration|`Get-ADTrust -Filter *`|
|PowerView trust enumeration|`Get-DomainTrust`|
|PowerView trust mapping|`Get-DomainTrustMapping`|
|Cross-domain user enumeration|`Get-DomainUser -Domain <DOMAIN>`|
|Trust enumeration with Windows built-in tools|`netdom query /domain:<DOMAIN> trust`|
|Domain controller enumeration|`netdom query /domain:<DOMAIN> dc`|
|Workstation enumeration|`netdom query /domain:<DOMAIN> workstation`|
|Visual trust mapping|BloodHound → `Map Domain Trusts`|

---

# 37. Important Terminology

## Trust

Relationship allowing authentication between domains.

## Trusted Domain

The domain whose users are trusted to authenticate to resources in the trusting domain.

## Trusting Domain

The domain providing access to its resources.

## Transitive

Trust can extend through additional trusted relationships.

## Non-Transitive

Trust is limited to the directly established relationship.

## One-Way

Authentication/access flows in one direction.

## Bidirectional

Authentication/access can occur in both directions.

## IntraForest

The relationship exists within the same forest.

## ForestTransitive

The trust is transitive between forests.

## SID Filtering

Helps prevent inappropriate SID-based privilege claims across trust boundaries.

## Selective Authentication

Allows authentication across a trust to be restricted to specifically allowed resources.

---

# 38. Trust Type Revision Table

|Trust Type|Same Forest?|Transitive?|Typical Direction|
|---|--:|--:|--:|
|Parent-child|Yes|Yes|Two-way|
|Cross-link|Yes|Yes|Two-way|
|Tree-root|Yes|Yes|Two-way|
|Forest|No|Yes|Configurable|
|External|No|No|Configurable|
|ESAE/Bastion|Architecture|Depends|Depends|

---

# 39. The Most Important Attack-Path Concept

The biggest lesson from this primer is:

```text
Trust ≠ Automatically Safe
```

A trusted domain may contain:

- Weak passwords
    
- Vulnerable services
    
- Misconfigured accounts
    
- Excessive privileges
    
- Service accounts
    
- Administrative users
    

Those weaknesses may become relevant to the trusted domain.

### Example

```text
             MAIN DOMAIN
                  ▲
                  │
                  │ Trust
                  │
                  ▼
            CHILD DOMAIN
                  ▲
                  │
             Weak System
                  ▲
                  │
               Attacker
```

The attacker may not need to compromise the main domain directly.

Instead:

```text
Weak Domain
     ↓
Compromise
     ↓
Trusted Relationship
     ↓
Main Domain
```

The module specifically highlights cases where an attacker can compromise a trusted domain and potentially obtain an account with administrative access in the principal domain.

---

# 40. What to Record During an Assessment

Whenever you discover a trust, document:

```text
Source Domain:
Target Domain:
Trust Type:
Trust Direction:
Transitive:
IntraForest:
ForestTransitive:
SelectiveAuthentication:
SID Filtering:
TGT Delegation:
Authentication possible:
```

Example:

```text
Source:
INLANEFREIGHT.LOCAL

Target:
LOGISTICS.INLANEFREIGHT.LOCAL

Type:
WINDOWS_ACTIVE_DIRECTORY

Attributes:
WITHIN_FOREST

Direction:
Bidirectional
```

---

# 41. Exam / HTB Quick Revision

### Q: What command lists AD trusts?

```powershell
Get-ADTrust -Filter *
```

### Q: PowerView equivalent?

```powershell
Get-DomainTrust
```

### Q: PowerView trust mapping?

```powershell
Get-DomainTrustMapping
```

### Q: Windows built-in trust enumeration?

```cmd
netdom query /domain:inlanefreight.local trust
```

### Q: Query domain controllers?

```cmd
netdom query /domain:inlanefreight.local dc
```

### Q: Query workstations?

```cmd
netdom query /domain:inlanefreight.local workstation
```

### Q: BloodHound trust query?

```text
Map Domain Trusts
```

### Q: Child-domain user enumeration?

```powershell
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL |
select SamAccountName
```

---

# 42. Must-Memorize Concepts

```text
Parent-child
    ↓
Same forest
    ↓
Two-way
    ↓
Transitive
```

```text
External
    ↓
Separate forests
    ↓
Non-transitive
    ↓
SID Filtering
```

```text
Forest Trust
    ↓
Forest root ↔ Forest root
    ↓
Transitive
```

```text
One-way
    ↓
Trusted → Trusting
```

```text
Bidirectional
    ↓
A ↔ B
```

```text
IntraForest : True
    ↓
Within same forest
```

```text
ForestTransitive : True
    ↓
Forest-transitive relationship
```

---

# 43. Final Mental Model

When you compromise an Active Directory environment, **do not stop at the current domain**.

Think:

```text
Current Domain
      │
      ▼
Enumerate Trusts
      │
      ├───────────────┐
      ▼               ▼
Child Domain      External/Forest
      │               │
      ▼               ▼
Users/Groups      Users/Groups
      │               │
      └───────┬───────┘
              ▼
       Identify Attack Paths
              │
              ▼
      Continue Assessment
```

The primer ends by introducing the next stage:

```text
Child → Parent Domain Trust Attacks
```

and:

```text
Attacks Across Bidirectional Forest Trusts
```

These should only be assessed when they are explicitly within the engagement's **Rules of Engagement (RoE)**.

---

# 44. One-Page Memory Sheet

```text
DOMAIN TRUSTS
│
├── Types
│   ├── Parent-child
│   ├── Cross-link
│   ├── External
│   ├── Tree-root
│   ├── Forest
│   └── ESAE/Bastion
│
├── Properties
│   ├── Transitive / Non-transitive
│   ├── One-way / Bidirectional
│   ├── IntraForest
│   ├── ForestTransitive
│   ├── SID Filtering
│   └── Selective Authentication
│
├── Enumeration
│   ├── Get-ADTrust
│   ├── Get-DomainTrust
│   ├── Get-DomainTrustMapping
│   ├── netdom
│   └── BloodHound
│
└── Assessment Mindset
    ├── Find trusted domains
    ├── Determine direction
    ├── Determine trust type
    ├── Check authentication
    ├── Enumerate across trust
    └── Identify attack paths
```

**Core rule to remember:**

> **Always enumerate domain trusts after obtaining an AD foothold. A weaker trusted domain can potentially provide an indirect path toward a more privileged domain.**