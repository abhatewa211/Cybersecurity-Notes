## 1. Status Update

By completing the skills assessments, we demonstrated the ability to:

- Perform **Active Directory enumeration**
    
- Identify useful information from an AD environment
    
- Discover potential attack paths
    
- Provide access and enumeration results to senior penetration testers
    
- Support follow-on penetration-testing activities
    
- Work effectively as part of an AD penetration-testing team
    

### Key takeaway

> **AD enumeration is not an isolated task.**

During a real penetration test, information discovered by one tester may directly determine what another tester does next.

For example:

```text
Initial Access
      ↓
Enumeration
      ↓
Identify Users / Groups / Hosts
      ↓
Identify Relationships
      ↓
Find Attack Paths
      ↓
Privilege Escalation
      ↓
Lateral Movement
      ↓
Domain / Forest Expansion
```

---

# 2. Real-World Active Directory Penetration Testing

Active Directory knowledge is extremely important for penetration testers because AD remains a core identity and access-management technology in many enterprise environments.

A penetration tester may encounter tasks involving:

- Domain enumeration
    
- User and group enumeration
    
- Host discovery
    
- Trust enumeration
    
- Credential attacks
    
- Kerberoasting
    
- Password spraying
    
- Lateral movement
    
- Privilege escalation
    
- Persistence testing
    
- Command and Control
    
- Cross-domain attacks
    

---

# 3. Cross-Domain Trusts

One important advanced AD concept is **domain trust**.

A trust allows users or resources from one domain to interact with another domain according to the trust relationship and permissions configured between them.

### Simplified example

```text
Domain A
CORP.LOCAL
     │
     │ Trust
     ↓
Domain B
DEV.LOCAL
```

If a penetration tester compromises an account or system in one domain, the tester may investigate whether the trust relationship provides a path into another domain.

### Important questions during an assessment

- What domains exist?
    
- What trusts exist between them?
    
- Is the trust one-way or two-way?
    
- Which security principals can cross the trust?
    
- What permissions exist across the trust?
    
- Can an attack path cross the domain boundary?
    

### Key concept

**A domain boundary does not automatically mean an attack-path boundary.**

---

# 4. Persistence

Persistence refers to techniques that allow an attacker to **maintain access** to an environment after the initial compromise.

In an authorized penetration test, persistence may be evaluated to determine whether an attacker could retain access over a longer assessment window.

Examples of areas testers may investigate include:

- Account permissions
    
- Group memberships
    
- Scheduled tasks
    
- Services
    
- Delegation
    
- ACL/DACL abuse
    
- Authentication mechanisms
    
- Domain-level privileges
    

### Important distinction

```text
Initial Access
      ↓
Privilege Escalation
      ↓
Persistence
      ↓
Maintain Access
```

Persistence should always be performed carefully in real engagements because changes can affect production systems.

---

# 5. Command and Control (C2)

**Command and Control (C2)** refers to the mechanisms used by an attacker or penetration-testing team to communicate with compromised systems.

In longer penetration tests, C2 infrastructure may allow testers to:

- Maintain communication with compromised hosts
    
- Execute authorized commands
    
- Perform additional enumeration
    
- Move between systems
    
- Demonstrate realistic attacker behavior
    

### High-level model

```text
Penetration Tester
       │
       ↓
    C2 Server
       │
       ├────────→ Host A
       ├────────→ Host B
       └────────→ Host C
```

The objective in an authorized assessment is generally to demonstrate the risk while maintaining operational safety and minimizing disruption.

---

# 6. Active Directory + Hybrid/Cloud Environments

Modern enterprises increasingly use **hybrid environments**.

A simplified environment may look like:

```text
                    Enterprise
                       │
          ┌────────────┴────────────┐
          ↓                         ↓
   On-Prem Active Directory     Cloud Identity
          │                         │
          ↓                         ↓
   Windows Servers              Cloud Services
          │                         │
          └────────────┬────────────┘
                       ↓
                 Hybrid Environment
```

Understanding traditional AD helps because many modern identity environments are built around concepts originating from enterprise directory services.

### Important areas to learn

- Active Directory
    
- LDAP
    
- Kerberos
    
- NTLM
    
- DNS
    
- Domain trusts
    
- Group Policy
    
- Identity federation
    
- Cloud identity
    
- Hybrid identity
    

---

# 7. Recommended HTB Learning Modules

The module recommends continuing with several specialized areas.

## Active Directory BloodHound

**Purpose:** Understand attack-path analysis and relationship mapping.

BloodHound helps visualize relationships between:

- Users
    
- Groups
    
- Computers
    
- Domains
    
- Sessions
    
- ACLs
    
- Trusts
    
- Administrative privileges
    

### Conceptual example

```text
User
 │
 ├── MemberOf → Group
 │                 │
 │                 ↓
 │            Admin Rights
 │                 │
 │                 ↓
 └────────────→ Computer
                       │
                       ↓
                  Domain Admin
```

The major benefit is turning large amounts of AD relationship data into **attack paths that are easier to understand**.

---

# 8. Active Directory LDAP

LDAP is an important protocol for interacting with directory services.

Learn:

- LDAP terminology
    
- Directory structure
    
- Distinguished Names
    
- Attributes
    
- Objects
    
- Queries
    
- Authentication
    
- Enumeration
    

### Example directory structure

```text
DC=corp,DC=local
       │
       ├── OU=Users
       │      ├── Alice
       │      └── Bob
       │
       ├── OU=Computers
       │      ├── WS01
       │      └── WS02
       │
       └── OU=Servers
              ├── DC01
              └── SRV01
```

---

# 9. PowerView

PowerView is a PowerShell-based toolset commonly associated with Active Directory enumeration and security testing.

It can help testers investigate areas such as:

- Domains
    
- Users
    
- Groups
    
- Computers
    
- Sessions
    
- Trusts
    
- Permissions
    
- ACL relationships
    

### Conceptual workflow

```text
PowerShell
    ↓
PowerView
    ↓
AD Enumeration
    ↓
Users / Groups / Computers
    ↓
Relationships
    ↓
Potential Attack Paths
```

---

# 10. Kerberoasting

**Kerberoasting** is an AD attack technique involving service accounts associated with **Service Principal Names (SPNs)**.

The high-level concept is:

```text
AD Environment
      ↓
Identify accounts with SPNs
      ↓
Request Kerberos service ticket
      ↓
Obtain ticket material
      ↓
Offline password cracking
      ↓
Potentially recover service-account credentials
```

### Why it matters

Service accounts can sometimes have:

- Weak passwords
    
- Long-lived credentials
    
- Excessive privileges
    

If a highly privileged service account uses a weak password, compromise of that account can have significant consequences.

### Defensive considerations

Organizations should consider:

- Strong service-account passwords
    
- Managed service accounts where appropriate
    
- Least privilege
    
- Monitoring unusual Kerberos ticket activity
    
- Regular credential rotation
    

---

# 11. Password Spraying

Password spraying is different from traditional brute force.

### Traditional brute force

```text
One Account
   ↓
Many Passwords
```

### Password spraying

```text
Many Accounts
      ↓
One Common Password
```

Example concept:

```text
alice → Password1
bob   → Password1
carol → Password1
david → Password1
```

The objective is to avoid repeatedly attacking one account and potentially triggering account lockout policies.

### Important defensive controls

- MFA
    
- Strong password policies
    
- Password screening
    
- Account lockout / smart lockout controls
    
- Monitoring authentication failures
    
- Detection of distributed authentication attempts
    

---

# 12. Hashcat

The module recommends **Cracking Passwords with Hashcat** to strengthen understanding of password-cracking concepts.

Hashcat is commonly used for authorized password-security testing.

### Conceptual workflow

```text
Credential Material
       ↓
Hash / Ticket Material
       ↓
Hashcat
       ↓
Dictionary / Rule / Mask
       ↓
Candidate Passwords
       ↓
Recovered Credential
```

Understanding password cracking is particularly useful when studying:

- Kerberoasting
    
- Password auditing
    
- Credential security
    
- Weak password detection
    

---

# 13. Active Directory Attack-Path Thinking

A major skill to develop is thinking about AD as a **graph of relationships**, rather than a collection of individual machines.

Example:

```text
Low-Priv User
     │
     ↓
Group Membership
     │
     ↓
Write Permission
     │
     ↓
Computer
     │
     ↓
Local Administrator
     │
     ↓
Privileged Session
     │
     ↓
Domain Privilege
```

Every relationship can potentially become an important part of an attack path.

---

# 14. HTB Practice Opportunities

The module recommends practicing against intentionally vulnerable environments.

## Recommended Machines

### Forest

Focus areas can include:

- AD enumeration
    
- Domain users
    
- LDAP
    
- Kerberos
    
- Service accounts
    
- Privilege escalation
    

### Active

Useful for practicing:

- SMB
    
- Windows exploitation
    
- File shares
    
- Active Directory
    
- Credential discovery
    

### Reel

Useful for practicing:

- Windows environments
    
- Enumeration
    
- Credential-related attack paths
    
- Privilege escalation
    

### Mantis

Useful for:

- Windows enumeration
    
- Web services
    
- Database-related attack paths
    
- AD concepts
    

### Blackfield

Useful for:

- Active Directory
    
- Kerberos
    
- Credential attacks
    
- Privilege escalation
    
- Domain-level concepts
    

### Monteverde

Useful for:

- Windows
    
- AD enumeration
    
- Credential discovery
    
- Lateral movement concepts
    

---

# 15. IppSec

**IppSec** is particularly useful for learning how experienced testers approach HTB machines.

Instead of simply copying commands, pay attention to:

### Enumeration methodology

```text
What is exposed?
       ↓
What information can I gather?
       ↓
What relationships exist?
       ↓
What is unusual?
       ↓
What should I investigate next?
```

### What to observe in walkthroughs

- Why a particular port was investigated
    
- Why a particular enumeration tool was chosen
    
- How clues were connected
    
- How credentials were discovered
    
- How privilege escalation was identified
    
- How the tester changed direction after new information appeared
    

The goal should be to develop **methodology**, not command memorization.

---

# 16. Pro Labs

HTB Pro Labs simulate larger corporate environments.

They are useful because real penetration tests are rarely limited to one machine.

Instead, testers may have to navigate:

```text
Initial System
      ↓
Internal Network
      ↓
Multiple Hosts
      ↓
Multiple Credentials
      ↓
Multiple Domains
      ↓
Trust Relationships
      ↓
Critical Systems
```

---

# 17. Dante Pro Lab

**Dante** is recommended as an entry point to Pro Labs.

It provides exposure to:

- Network penetration testing
    
- Multiple machines
    
- Different attack vectors
    
- Some Active Directory concepts
    
- Pivoting
    
- Enumeration
    

The important skill is learning how multiple individual vulnerabilities can combine into a larger attack path.

---

# 18. Offshore Pro Lab

**Offshore** is described as a more advanced environment.

It provides opportunities to practice:

- Active Directory enumeration
    
- Network enumeration
    
- Lateral movement
    
- Credential attacks
    
- Trust relationships
    
- Complex attack paths
    

The major difference from individual HTB machines is **scale**.

---

# 19. Important AD Talks & Videos

The module recommends several talks.

### Six Degrees of Domain Admin

Useful for understanding:

- BloodHound
    
- Attack paths
    
- AD relationships
    
- Privilege escalation
    

### Designing AD DACL Backdoors

Useful for understanding:

- DACLs
    
- ACL abuse
    
- AD permissions
    
- Persistence concepts
    

### Kicking The Guard Dog of Hades

Important historical material related to **Kerberoasting**.

### Kerberoasting 101

Useful for understanding:

- SPNs
    
- Kerberos
    
- Service tickets
    
- Kerberoasting methodology
    
- Password cracking
    

---

# 20. Important AD Security Researchers & Blogs

## SpecterOps

Important topics:

- BloodHound
    
- Active Directory
    
- Command and Control
    
- Attack paths
    
- Identity security
    

## Harmj0y

Known for extensive work around:

- Active Directory
    
- PowerShell
    
- Kerberos
    
- Windows security
    
- Offensive security
    

## AD Security Blog — Sean Metcalf

Excellent resource for:

- AD security
    
- Kerberos
    
- Windows security
    
- Domain security
    
- Defensive recommendations
    

## Shenanigans Labs

Useful for:

- Security research
    
- Vulnerabilities
    
- Threat-actor techniques
    
- Offensive security research
    

## Dirk-jan Mollema

Useful topics include:

- Active Directory
    
- Azure
    
- Protocols
    
- Python
    
- Identity security
    
- Vulnerabilities
    

## The DFIR Report

Particularly useful from a **defensive perspective**.

It documents real-world intrusion incidents and explains:

- Initial access
    
- Attacker behavior
    
- AD abuse
    
- Lateral movement
    
- Persistence
    
- Detection opportunities
    
- Attack artifacts
    

---

# 21. MITRE ATT&CK

![Image](https://images.openai.com/static-rsc-4/_tE9R19qzslx3W6zxFODNbzHD5Uidru-2_EHJE4XqS2BZz1RvEbXeOT9n_bv8eulur4hjghUi0AF-MpJVzyy1MLTFnNuzukGzCgtg12F_jxybNemUVM5dTUF8Rqi0ZdTewTDjZ2LJusQtqx3QKxHuE63zhiK4gvXD8izDvDPlUcXWvvlwnboBd9ingfO26EA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BBcY9jwf7Fa4uj1KSXzEvMMHmGXEya6abuH3LynPK-pXPiFbXBnVe3l6oD1-91oJifXy7TAmuz_Hzr52iSSDYCuxp3pBCgc6hE6Z9AZV45bPTOeOM9U9vZ1s_G5Rd9kzUU_Rskqtx-Y-2qXXPZU1Z4rBJ3WJavSpMLJqp8mZGs2uJ4A1bIx2tA2Xcy2niOU_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/GoZoVuc72rOhoYM1PkkRlFPZkX3aIal6k93pCrA8EF4yXa0HDcIlqXNfJn0gKpsWfSJPK-2_h-ikhAhdoMVTTdEwVM3uLnTA-E15lWxQR24yKQjeqFnCz5TN92P_79aj-JAadUd-KaxdSA4E1HCQUjUndZJgPXqmyOi8ZUhDyTmpqykKviz145z8aTqLVwON?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3qvE7oT8Np9RLq31SKGxDM97_B3Tsiseivvi1p1AyySBZz7JfYLHPT04PQGCq6eeyoB9ASaV82Gjq9fI6R-lsvakLJP189arppuE-_FrINOGF3W5ankjObt0YCpfNp7FQ1F5Yb8Gu6Q8f7mPLmfkeBEaX6KCXuHhHi8wpqBgsdy9qvwRbh9vAyrMFhZdg3to?purpose=fullsize)

The **MITRE ATT&CK Enterprise Matrix** is an important resource for understanding adversary behavior.

It organizes attacker behavior into **tactics, techniques, and procedures (TTPs).**

### Simplified attack lifecycle

```text
Reconnaissance
      ↓
Initial Access
      ↓
Execution
      ↓
Persistence
      ↓
Privilege Escalation
      ↓
Defense Evasion
      ↓
Credential Access
      ↓
Discovery
      ↓
Lateral Movement
      ↓
Collection
      ↓
Command & Control
      ↓
Exfiltration
      ↓
Impact
```

For an AD penetration tester, particularly important areas include:

- Credential Access
    
- Discovery
    
- Privilege Escalation
    
- Lateral Movement
    
- Persistence
    
- Command and Control
    

---

# 22. The Bigger Picture

One of the most important lessons from this module is:

> **Active Directory is a huge topic and cannot be mastered by memorizing a few commands.**

You need to understand how the components interact.

### Core AD knowledge map

```text
                    ACTIVE DIRECTORY
                           │
        ┌──────────────────┼──────────────────┐
        ↓                  ↓                  ↓
      Users              Groups            Computers
        │                  │                  │
        └────────────┬─────┴────────────┬─────┘
                     ↓                  ↓
                 Permissions         Sessions
                     │                  │
                     ↓                  ↓
                   ACLs             Credentials
                     │                  │
                     └────────┬─────────┘
                              ↓
                       Attack Paths
                              ↓
                     Privilege Escalation
                              ↓
                       Lateral Movement
                              ↓
                       Domain Expansion
```

---

# 23. Essential AD Concepts to Master

For your pentesting progression, make sure you understand these thoroughly:

### Fundamentals

- Domain
    
- Forest
    
- Tree
    
- Domain Controller
    
- Organizational Unit
    
- Users
    
- Groups
    
- Computers
    
- Group Policy
    

### Authentication

- Kerberos
    
- NTLM
    
- LDAP
    
- SMB
    
- SPNs
    
- Tickets
    
- Service accounts
    

### Enumeration

- Users
    
- Groups
    
- Computers
    
- Shares
    
- Sessions
    
- Trusts
    
- ACLs
    
- Delegation
    
- SPNs
    

### Offensive Security

- Password spraying
    
- Kerberoasting
    
- Credential attacks
    
- Lateral movement
    
- Privilege escalation
    
- ACL abuse
    
- Trust abuse
    
- Persistence
    
- C2
    

### Tools

- Nmap
    
- BloodHound
    
- PowerView
    
- Impacket
    
- CrackMapExec/NetExec
    
- Hashcat
    
- LDAP tools
    
- Kerberos tooling
    

---

# 24. What You Should Focus on Next

Based on the progression of this module, a strong learning sequence is:

```text
AD Fundamentals
       ↓
LDAP
       ↓
PowerView
       ↓
BloodHound
       ↓
Kerberos
       ↓
Kerberoasting
       ↓
Password Spraying
       ↓
Credential Attacks
       ↓
ACL / DACL Abuse
       ↓
Lateral Movement
       ↓
Domain Trusts
       ↓
Privilege Escalation
       ↓
Persistence
       ↓
C2
       ↓
Hybrid / Cloud AD
```

---

# 25. Practical Methodology

When you receive an AD target during an authorized assessment, develop this mindset:

### Phase 1 — Identify

```text
What am I looking at?
```

Identify:

- IP addresses
    
- Hostnames
    
- Domains
    
- Domain controllers
    
- Services
    
- Network segments
    

### Phase 2 — Enumerate

```text
What information can I gather?
```

Look for:

- Users
    
- Groups
    
- Computers
    
- Shares
    
- SPNs
    
- Sessions
    
- Trusts
    
- Permissions
    

### Phase 3 — Correlate

```text
How are these objects connected?
```

This is where tools such as BloodHound become particularly useful.

### Phase 4 — Identify Attack Paths

```text
What relationships could allow privilege escalation
or lateral movement?
```

### Phase 5 — Validate

Perform controlled, authorized testing to determine whether the suspected attack path is actually exploitable.

### Phase 6 — Document

Record:

- Evidence
    
- Commands/tools used
    
- Findings
    
- Screenshots
    
- Credentials where permitted
    
- Affected hosts
    
- Attack path
    
- Business/security impact
    
- Remediation
    

---

# 26. Reporting Mindset

Since you're working toward **CPTS-style penetration-testing reporting**, don't only document _what command worked_.

Document the **story of the attack**.

### Weak reporting

> Ran BloodHound and found Domain Admin.

### Better reporting

```text
BloodHound enumeration identified an indirect privilege
escalation path involving the compromised user, group
membership, and excessive permissions on a domain-connected
host.

The relationship allowed the tester to progress from the
initial low-privileged account toward a higher-privileged
security context.
```

Then include:

- Screenshot
    
- Evidence
    
- Affected objects
    
- Reproduction steps
    
- Impact
    
- Remediation
    

---

# 27. Key Takeaways

### ⭐ 1. Enumeration is foundational

Good enumeration can reveal the majority of an AD attack path.

### ⭐ 2. Think in relationships

Don't look at users, computers, groups and ACLs individually.

Think:

```text
WHO → HAS WHAT → ACCESS TO WHAT → CAN CONTROL WHAT
```

### ⭐ 3. BloodHound helps visualize relationships

It converts complicated AD relationships into understandable graphs.

### ⭐ 4. Kerberos matters

Understanding Kerberos is essential for understanding:

- Authentication
    
- SPNs
    
- Service tickets
    
- Kerberoasting
    

### ⭐ 5. Credentials are extremely valuable

A single compromised credential can sometimes lead to:

```text
User
 ↓
Computer
 ↓
Admin
 ↓
Another Computer
 ↓
Privileged Account
 ↓
Domain
```

### ⭐ 6. Trusts can expand the attack surface

Cross-domain relationships should always be considered during authorized AD assessments.

### ⭐ 7. Real environments are larger than individual machines

Pro Labs are valuable because they force you to think about:

- Networks
    
- Hosts
    
- Domains
    
- Credentials
    
- Trusts
    
- Attack paths
    

### ⭐ 8. Keep learning

AD constantly evolves, and new vulnerabilities, techniques and defensive controls continue to appear.

---

# 28. Final Revision Cheat Sheet

|Topic|Remember|
|---|---|
|**AD**|Central enterprise identity/directory environment|
|**LDAP**|Directory access/query protocol|
|**Kerberos**|Major AD authentication protocol|
|**SPN**|Associates services with accounts|
|**Kerberoasting**|Service-ticket/password-cracking attack|
|**Password Spraying**|One/few passwords against many accounts|
|**BloodHound**|Visualizes AD relationships and attack paths|
|**PowerView**|PowerShell AD enumeration|
|**ACL/DACL**|Controls permissions/access|
|**Trust**|Relationship between domains|
|**Persistence**|Maintaining access|
|**C2**|Communication/control of compromised systems|
|**Lateral Movement**|Moving between systems|
|**Privilege Escalation**|Obtaining higher privileges|
|**Hashcat**|Password/hash auditing and cracking|
|**MITRE ATT&CK**|Adversary tactics and techniques|
|**Pro Labs**|Large simulated enterprise environments|

## The mindset to remember

> **Enumerate → Understand → Correlate → Identify Attack Path → Validate → Document → Remediate**

That is the transition from simply **running pentesting tools** to actually **thinking like an Active Directory penetration tester**.