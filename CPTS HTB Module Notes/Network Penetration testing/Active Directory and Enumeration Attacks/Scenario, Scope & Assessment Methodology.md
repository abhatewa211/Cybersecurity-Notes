Yes. I’ll treat the material you just sent as the **current module**, and these are the **master study notes for it**. I’ll keep the important terminology and requirements from the module intact and add explanations around them.

# 📘 Active Directory Penetration Testing

## Module Notes — 

---

# 1. Module Overview

This module places us in the role of a penetration tester working for:

**CAT-5 Security**

The target organization is:

**Inlanefreight**

The purpose of the module is to simulate a real-world **internal penetration test against an Active Directory environment**.

The assessment is designed to test our ability to:

- Perform reconnaissance
    
- Enumerate Active Directory
    
- Discover credentials
    
- Obtain an initial foothold
    
- Move laterally through the environment
    
- Escalate privileges
    
- Analyze AD relationships
    
- Work toward Domain Admin-level compromise
    
- Interpret enumeration results
    
- Choose the next appropriate attack path
    

The module emphasizes that successful penetration testing is not just about knowing tools and commands.

A good penetration tester must be able to:

> **Collect information → understand what it means → identify attack paths → decide what to investigate next.**

---

# 2. Assessment Objectives

The tasking email establishes several major objectives.

### Primary objectives

```text
Domain Enumeration
       ↓
Credential Discovery
       ↓
Initial Foothold
       ↓
Lateral Movement
       ↓
Privilege Escalation
       ↓
Domain Admin Credentials
```

These stages form the basic progression of the assessment.

---

# 3. Two Internal Penetration Tests

The final assessment consists of **two internal penetration tests**.

## Test 1 — Starting From an External Breach Position

The first assessment simulates an attacker who begins outside the internal network.

Conceptually:

```text
External Attacker
       │
       ▼
Passive Reconnaissance
       │
       ▼
Information Gathering
       │
       ▼
Internal Access
       │
       ▼
AD Enumeration
       │
       ▼
Credential Discovery
       │
       ▼
Lateral Movement
       │
       ▼
Privilege Escalation
       │
       ▼
Domain Compromise
```

The important lesson is that **external information can help an attacker understand and attack an internal environment**.

---

# 4. Test 2 — Starting From an Internal Attack Box

The second assessment starts with an attack box already positioned inside the network.

```text
Internal Network
       │
       ▼
Attack Box
       │
       ▼
Internal Enumeration
       │
       ▼
Domain Enumeration
       │
       ▼
Credential Discovery
       │
       ▼
Foothold
       │
       ▼
Lateral Movement
       │
       ▼
Privilege Escalation
       │
       ▼
Domain Compromise
```

This represents a different threat model.

An attacker who is already inside the network may have access to internal services that are not publicly exposed.

---

# 5. Why the Starting Position Matters

An external attacker might first need to discover:

- Company domains
    
- Public infrastructure
    
- Technologies
    
- Employees
    
- Publicly exposed information
    
- Potential attack paths
    

An internal attacker may already be able to interact with:

- Internal DNS
    
- SMB
    
- LDAP
    
- Kerberos
    
- Domain controllers
    
- Workstations
    
- Servers
    
- Internal applications
    

Therefore:

> **The attacker's initial position determines what information and attack surfaces are immediately available.**

---

# 6. Assessment Scope

Before performing any penetration test, we need to establish the:

> **Scope of the assessment**

Scope tells the penetration tester exactly what is authorized.

It prevents situations where a tester accidentally attacks:

- A third-party system
    
- A production system
    
- Another customer
    
- An unrelated subsidiary
    
- An out-of-scope domain
    
- A real-world website
    

### Golden rule

> **If something isn't explicitly authorized, don't assume it is authorized.**

---

# 7. 🟢 In-Scope Targets

The following targets are explicitly in scope.

|Target|Description|
|---|---|
|`INLANEFREIGHT.LOCAL`|Customer domain including AD and web services|
|`LOGISTICS.INLANEFREIGHT.LOCAL`|Customer subdomain|
|`FREIGHTLOGISTICS.LOCAL`|Subsidiary company with external forest trust|
|`172.16.5.0/23`|In-scope internal subnet|

---

# 8. `INLANEFREIGHT.LOCAL`

This is the primary customer domain.

It includes:

- Active Directory
    
- Web services
    

This domain is one of the primary targets of the assessment.

---

# 9. `LOGISTICS.INLANEFREIGHT.LOCAL`

This is an explicitly authorized subdomain.

Important:

```text
LOGISTICS.INLANEFREIGHT.LOCAL
```

is in scope.

However, this does **not** mean every other subdomain discovered beneath `INLANEFREIGHT.LOCAL` is automatically authorized.

---

# 10. `FREIGHTLOGISTICS.LOCAL`

This is the subsidiary company's domain.

The scope states that there is an:

> **External forest trust**

between:

```text
FREIGHTLOGISTICS.LOCAL
```

and:

```text
INLANEFREIGHT.LOCAL
```

This is important for the AD portion of the assessment because **trust relationships can affect authentication, authorization, and possible attack paths**.

We will study trusts technically later in the module.

---

# 11. `172.16.5.0/23`

This is the authorized internal network range.

The `/23` CIDR notation represents a subnet containing:

**512 total IPv4 addresses**

with:

- Network address: `172.16.5.0`
    
- Broadcast address: `172.16.6.255`
    

The usable host range is:

```text
172.16.5.1
       ↓
172.16.6.254
```

For this lab, the important point is:

> **`172.16.5.0/23` is explicitly authorized internal scope.**

---

# 12. 🌳 Domain / Forest Relationship

The environment can be visualized conceptually as:

![Image](https://images.openai.com/static-rsc-4/nEBVC2fKdZX-0KGysWiStqmPZQDIUfoPReDnCJHqAdEB-mV1RfAuu839MRqeToutpMXFx31e81mOkZOvWlLBkRZpcr61mdHwMnhHuEZ5T7OYAUmeRMSimkd5ipzJleav0rxrfQcOfIPFRDccDc7sCdKx9fr6tOc7bUXOKwBEg7sH54gYAMtchuXnWDtOhHlO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QrszOpDzmItgbIlYAWssadfMcTqCwEYT-k_tXohlrEY-1j5Swgbj85ybUAX6ry5hnbrdo3N9EexjQ0-P4Ybo5XdGmrWrgD6QhL3iRidNny8TfD19no-Sp8SuRW6uafDwaWjBNE5BtDDWI60mNL28J6lDWvdAOclZRu4QCZDULgr-CwwyCuRvO0CUzuoOSYDW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5p79M9-yMLUAptOPSKPA9Xgpqj77uIjhh38SG9QTdEH4vMpX0UTeO8tmrBXxsCj6E0IpHWwJtDGJgf_ccPT49j8I1d8zHi0WzgxSU79E0gwo6tRj8R2x4UUNBexYCR31YeZK3crtP9LjoxfQ5CRoo3rt9qlmVu-3R0zJCZ4rmcGAV-_dRe0Lrx8s2y7RlIKX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/81epOPjXHIOGqLdSlimjHYVcaaWVmxb4dQRuYoDy5J9lHSqnXoTkLBWeI8uz9UVEouYDDgOrqcDHtU3zYfJcOmnIH1ZbPRyKiNtjpnbaTrNnKdxV2LKvbKJeyKJ-8tnbwjInokgdJhYmy1J7L8fJp7ZJJGIbrtueE0IuFr9yk3MGanOqQQOHvSAFaO56shT3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Rf1TgiDJ_1WEuWv9LG_H_F5V9vXlPKKQs1JAlnmM8aVpGmlmbWcuC2O4_ue7XV2eLFh63Z5xymYbokGjRUtaYa8B43NVHuAQhFvQZgxNofaQc_YGhwiUp1bQBR55nCxmzQRCoRusaMtZXbCPGdbvlRcRO-7TFXvBVa4mCYN1Q-IKRKxQsqutqX7frG8L6zHQ?purpose=fullsize)

```text
              INLANEFREIGHT.LOCAL
                       │
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
        LOGISTICS          AD Environment
        Subdomain


       FREIGHTLOGISTICS.LOCAL
                 │
                 │
          External Forest
              Trust
                 │
                 ▼
       INLANEFREIGHT.LOCAL
```

### Important terminology

**Domain**  
A logical security and administrative boundary in Active Directory.

**Forest**  
A collection of one or more AD domains sharing common directory infrastructure such as the schema and configuration.

**Trust**  
A relationship that can allow authentication or resource-access relationships between domains or forests.

---

# 13. 🔴 Out-of-Scope Targets

The scope explicitly excludes:

### Other `INLANEFREIGHT.LOCAL` subdomains

Only:

```text
LOGISTICS.INLANEFREIGHT.LOCAL
```

is explicitly listed.

Other discovered subdomains are not automatically authorized.

---

### Subdomains of `FREIGHTLOGISTICS.LOCAL`

The parent domain is in scope:

```text
FREIGHTLOGISTICS.LOCAL
```

But:

```text
*.FREIGHTLOGISTICS.LOCAL
```

is explicitly out of scope.

---

### Phishing

Not authorized.

### Social engineering

Not authorized.

### Other IPs/domains/subdomains

Not explicitly listed = out of scope.

---

# 14. ⚠️ Discovery Does Not Expand Scope

This is one of the most important professional lessons in the module.

Suppose:

```text
INLANEFREIGHT.LOCAL
```

is authorized.

During enumeration you discover:

```text
SECRET.INLANEFREIGHT.LOCAL
```

You **cannot automatically attack it** simply because you found it.

Correct workflow:

```text
Discover
   │
   ▼
Check Scope
   │
   ▼
Explicitly Authorized?
   │
 ┌─┴─┐
YES  NO
 │    │
 ▼    ▼
Test STOP
```

### Remember:

> **Discovery ≠ authorization.**

---

# 15. External Information Gathering

The first technical phase of the module is:

> **External Information Gathering — Passive Checks**

The objective is to discover information about Inlanefreight that is publicly accessible.

The assessment is performed from an:

> **Anonymous perspective**

The testers aren't given unnecessary information beforehand.

---

# 16. Passive Reconnaissance

### Definition

Passive reconnaissance is the process of gathering information about a target without actively probing or attacking the target's infrastructure.

Potential information sources include:

- Search engines
    
- Public DNS information
    
- Public certificates
    
- Public documents
    
- Public repositories
    
- Publicly indexed websites
    
- Public technology information
    

Conceptually:

```text
Public Information
       │
       ▼
OSINT / Passive Recon
       │
       ▼
Domain Information
       │
       ▼
Infrastructure Clues
       │
       ▼
Potential Attack Information
```

---

# 17. Why Passive Reconnaissance Is Important

Passive reconnaissance can reveal information that becomes useful later.

For example:

```text
Public Information
       ↓
Company Structure
       ↓
Domains
       ↓
Technology
       ↓
Infrastructure
       ↓
Potential Internal Attack Paths
```

This is why professional penetration testers don't always begin with aggressive scanning.

First ask:

> **What can I learn without touching the target aggressively?**

---

# 18. Passive vs Active Enumeration

## Passive

The tester obtains information through publicly available sources.

Examples:

- Search engines
    
- Public documents
    
- Public certificates
    
- Public DNS information
    
- Public repositories
    

---

## Active

The tester directly interacts with the target.

Examples:

- Port scanning
    
- Service enumeration
    
- Vulnerability scanning
    
- Exploitation
    

### Comparison

|Passive|Active|
|---|---|
|Public information|Direct interaction|
|Low interaction|Direct probing|
|OSINT|Port scanning|
|Public records|Service enumeration|
|Public documents|Vulnerability scanning|

---

# 19. Real-World Website Restrictions

The scope specifically says that no:

- Active enumeration
    
- Port scans
    
- Attacks
    

will be performed against internet-facing real-world IP addresses or:

```text
https://www.inlanefreight.com
```

Therefore:

|Activity|Status|
|---|---|
|Passive enumeration|🟢 Authorized|
|Public information research|🟢 Authorized|
|Port scanning real website|🔴 Not authorized|
|Active enumeration|🔴 Not authorized|
|Attacking real website|🔴 Not authorized|

The practical offensive testing takes place against the controlled assessment environment.

---

# 20. Internal Testing

The second major component is:

> **Internal Testing**

The purpose is to demonstrate the security risks associated with vulnerabilities in:

- Internal hosts
    
- Internal services
    
- Active Directory
    

The module specifically focuses heavily on:

> **Active Directory**

---

# 21. Untrusted Insider Perspective

The assessment simulates an attacker who has obtained internal network access but does not have legitimate administrative privileges.

This is an:

> **Untrusted insider perspective**

The tester begins with limited knowledge and must discover the environment through enumeration.

---

# 22. Internal Testing Goals

The scope identifies the following progression:

```text
Anonymous Internal Position
          ↓
Domain User Credentials
          ↓
Internal Domain Enumeration
          ↓
Foothold
          ↓
Lateral Movement
          ↓
Vertical Movement
          ↓
Domain Compromise
```

Each stage builds upon information obtained in earlier stages.

---

# 23. Domain User Credentials

One major goal is obtaining:

> **Domain user credentials**

A domain credential can potentially allow access to:

- Domain resources
    
- SMB
    
- LDAP
    
- Kerberos
    
- Windows systems
    
- Internal applications
    
- Other network services
    

Credentials therefore significantly change the attacker's capabilities.

---

# 24. Active Directory Enumeration

Once access or credentials are obtained, the tester needs to understand the AD environment.

Important objects and information include:

```text
Users
Groups
Computers
Domains
Domain Controllers
Shares
Sessions
Permissions
Trusts
Services
Policies
```

The goal isn't merely to collect data.

The goal is to understand:

> **How the objects relate to each other and where those relationships may create attack paths.**

---

# 25. Foothold

A **foothold** is an initial position inside the target environment.

Example:

```text
No Access
   ↓
Valid Credential
   ↓
Authentication
   ↓
Initial System Access
   ↓
FOOTHOLD
```

A foothold may initially have very low privileges.

For example:

```text
Domain User
```

could be the starting point for further enumeration.

---

# 26. Lateral Movement

### Definition

Lateral movement means moving:

> **From one system to another within the environment.**

Example:

```text
Workstation A
      ↓
Server A
      ↓
Server B
      ↓
Database Server
```

Potential technologies encountered in AD environments include:

- SMB
    
- RDP
    
- WinRM
    
- WMI
    
- MSSQL
    

The exact technique used depends on the credentials, permissions, services, and environment discovered.

---

# 27. Vertical Movement

Vertical movement means:

> **Increasing privileges.**

Example:

```text
Standard User
      ↓
Local Administrator
      ↓
Server Administrator
      ↓
Domain-Level Administrator
```

### Memorize this:

> **Lateral = Across**

> **Vertical = Up**

---

# 28. Privilege Escalation

Privilege escalation is the process of obtaining permissions beyond those originally available.

Two broad categories are:

### Vertical privilege escalation

Increasing privilege level:

```text
User → Administrator
```

### Horizontal privilege escalation

Accessing another account/system with similar privilege.

In this module, the major focus is on progressing toward high-level AD privileges.

---

# 29. Domain Admin Objective

The tasking specifically mentions acquiring:

> **Domain Admin credentials**

This represents a high-impact level of compromise within a traditional Active Directory environment.

Conceptually:

```text
Low-Privilege User
       ↓
Enumeration
       ↓
Credentials
       ↓
Access
       ↓
Lateral Movement
       ↓
Privilege Escalation
       ↓
Domain Admin
```

A key lesson:

> **Domain compromise is often achieved by chaining multiple weaknesses rather than exploiting one vulnerability.**

---

# 30. Operational Safety

The assessment explicitly states:

> **Computer systems and network operations will not be intentionally interrupted during the test.**

A professional penetration tester must therefore consider the potential impact of every action.

Before performing a potentially dangerous action:

```text
Is it authorized?
       ↓
Could it crash something?
       ↓
Could it lock an account?
       ↓
Could it affect production?
       ↓
Could it modify/delete data?
       ↓
Is there a safer alternative?
```

This is an important distinction between:

**Responsible penetration testing**

and

**uncontrolled exploitation.**

---

# 31. Password Testing

The scope permits password files captured from Inlanefreight devices—or supplied by the organization—to be loaded onto:

> **Offline workstations for decryption**

The recovered passwords can then be used to accomplish authorized assessment objectives.

---

# 32. Online vs Offline Password Testing

### Online

```text
Attacker
   ↓
Authentication Service
   ↓
Password Attempt
   ↓
Password Attempt
   ↓
Password Attempt
```

Potential consequences:

- Account lockout
    
- Detection
    
- Authentication logs
    
- Service disruption
    

### Offline

```text
Captured Password Material
          ↓
Offline Workstation
          ↓
Password Analysis
          ↓
Recovered Credential
          ↓
Authorized Validation
```

The module specifically permits this activity within the engagement.

---

# 33. Credential Handling

Credentials discovered during a penetration test are highly sensitive.

The scope requires that captured password files and decrypted passwords:

- Not be revealed to unauthorized people
    
- Be stored securely
    
- Be kept on CAT-5-owned and approved systems
    
- Be retained according to the official contract
    

### Professional principle

> **Finding sensitive information creates an obligation to protect it.**

---

# 34. Scoping Documents

This module deliberately introduces us to realistic penetration-testing documentation.

A professional engagement may include:

### Scope Document

Defines:

> **What is included and excluded.**

### Rules of Engagement

Defines:

> **How testing can be performed.**

### Tasking Email

Defines:

> **What the assessment team needs to accomplish.**

---

# 35. Scope vs Objective vs Method

This distinction is extremely important.

|Concept|Question|
|---|---|
|**Scope**|What can I test?|
|**Objective**|What am I trying to accomplish?|
|**Method**|How am I allowed to test?|

### This module

**Scope:**

```text
INLANEFREIGHT.LOCAL
LOGISTICS.INLANEFREIGHT.LOCAL
FREIGHTLOGISTICS.LOCAL
172.16.5.0/23
```

**Objectives:**

```text
Domain Enumeration
Credential Discovery
Foothold
Lateral Movement
Privilege Escalation
Domain Admin Credentials
```

**Methods:**

```text
Passive External Enumeration
Internal Testing
Authorized Password Testing
AD Enumeration
Authorized Attack Techniques
```

---

# 36. Rules of Engagement — RoE

Rules of Engagement establish the conditions under which the assessment is performed.

They may define:

- Testing windows
    
- Authorized targets
    
- Authorized techniques
    
- Prohibited techniques
    
- Emergency contacts
    
- Operational restrictions
    
- Data handling
    
- Safety requirements
    

For this module, some explicit restrictions are:

```text
No phishing
No social engineering
No unauthorized targets
No active attacks against the real-world website
No intentional disruption
```

---

# 37. 🧠 Active Directory Assessment Mindset

This module is preparing us for a very important concept:

## Enumeration drives the attack.

You don't simply execute a predefined sequence of commands.

Instead:

```text
Information
    ↓
Interpretation
    ↓
Hypothesis
    ↓
Enumeration
    ↓
New Information
    ↓
New Hypothesis
    ↓
New Attack Path
```

For example:

```text
Discover Domain
      ↓
Identify Domain Controller
      ↓
Identify Users
      ↓
Identify Groups
      ↓
Identify Permissions
      ↓
Identify Credentials
      ↓
Identify Accessible Systems
      ↓
Identify Attack Path
```

---

# 38. The Penetration Tester Decision Cycle

For every exercise, use this methodology:

### Step 1 — What do I know?

Example:

> I discovered a domain controller.

### Step 2 — What does that tell me?

> The environment likely contains an Active Directory domain.

### Step 3 — What don't I know?

Potentially:

- Domain name
    
- Users
    
- Groups
    
- Services
    
- Shares
    
- Trusts
    
- Permissions
    

### Step 4 — What should I enumerate?

Choose the appropriate protocol/tool.

### Step 5 — What did I discover?

Record the result.

### Step 6 — What does that result mean?

Interpret it.

### Step 7 — What should I investigate next?

Continue based on evidence.

---

# 39. 🔥 Complete Attack-Path Model

Keep this diagram in your notes:

```text
                 AUTHORIZATION
                       │
                       ▼
                      SCOPE
                       │
                       ▼
              RECONNAISSANCE
                       │
                       ▼
             INFORMATION GATHERING
                       │
                       ▼
                  ENUMERATION
                       │
                       ▼
              CREDENTIAL DISCOVERY
                       │
                       ▼
                    FOOTHOLD
                       │
                       ▼
               LATERAL MOVEMENT
                       │
                       ▼
              PRIVILEGE ESCALATION
                       │
                       ▼
               DOMAIN COMPROMISE
                       │
                       ▼
                DOCUMENT FINDINGS
```

But remember: this isn't always linear.

Real AD testing often looks like:

```text
             ┌───────────────┐
             │  Enumeration  │
             └───────┬───────┘
                     ↓
                 Discovery
                     ↓
               New Access
                     ↓
               More Enumeration
                     ↓
              New Information
                     ↓
              New Attack Path
                     │
                     └───────────┐
                                 ↓
                            Enumeration
```

---

# 40. ⭐ Important Things to Memorize

### Scope

```text
INLANEFREIGHT.LOCAL             ✅
LOGISTICS.INLANEFREIGHT.LOCAL   ✅
FREIGHTLOGISTICS.LOCAL           ✅
172.16.5.0/23                    ✅
```

### Out of scope

```text
Other INLANEFREIGHT subdomains    ❌
FREIGHTLOGISTICS subdomains       ❌
Phishing                          ❌
Social engineering                ❌
Unlisted IPs/domains              ❌
Active attacks on real website   ❌
```

### Main objectives

```text
Enumeration
     ↓
Credentials
     ↓
Foothold
     ↓
Lateral Movement
     ↓
Privilege Escalation
     ↓
Domain Admin
```

### Core definitions

```text
Passive Recon      = Gather information without active probing
Active Enumeration = Direct interaction/probing
Foothold           = Initial access
Lateral Movement   = Move across systems
Vertical Movement  = Increase privilege
Privilege Escalation = Obtain higher privileges
Scope              = Authorized targets
RoE                = Authorized testing conditions
```

---

# 41. 🧪 How We Will Work Through the Exercises

From the **next section onward**, I'll keep two separate parts for every exercise.

### 📚 PART A — Notes

I'll explain:

- The concept
    
- Protocol
    
- Tool
    
- Commands
    
- Syntax
    
- Options
    
- Expected output
    
- Interpretation
    
- Security significance
    
- Common mistakes
    

### 🧑‍💻 PART B — Mentor Exercise

I'll give you:

```text
OBJECTIVE
   ↓
WHAT WE KNOW
   ↓
WHAT WE NEED
   ↓
YOUR HYPOTHESIS
   ↓
COMMAND
   ↓
OUTPUT
   ↓
INTERPRETATION
   ↓
NEXT STEP
```

I won't turn the module into a **command-copying exercise**. The goal is for you to understand **why** we're running a particular enumeration technique and what the output tells us.

**This section is now your foundation. The next module content/exercise should begin with the passive external enumeration portion.**