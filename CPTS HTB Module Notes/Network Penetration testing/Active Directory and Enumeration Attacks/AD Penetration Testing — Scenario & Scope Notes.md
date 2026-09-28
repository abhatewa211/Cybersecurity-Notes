## 1. Scenario Overview

We are acting as penetration testers for:

> **CAT-5 Security**

The senior team members want us to conduct an assessment independently after successfully shadowing previous engagements.

The engagement is against:

> **Inlanefreight**

The tasking from the Red Team Lead requires us to demonstrate our ability to perform:

- Domain enumeration
    
- Credential discovery
    
- Initial access / foothold
    
- Lateral movement
    
- Privilege escalation
    
- Domain compromise
    
- Obtaining **Domain Admin credentials**
    

The module states that completing the assessment demonstrates our ability to:

- Perform automated and manual AD enumeration
    
- Use multiple penetration-testing tools
    
- Interpret AD data
    
- Make decisions based on gathered information
    
- Perform common AD attacks
    
- Understand more advanced AD concepts
    

---

# 2. 🎯 The Two Internal Penetration Tests

This module contains **two internal penetration tests**.

### Assessment 1 — External Breach Simulation

The scenario begins from an:

> **External breach position**

The goal is to simulate an attacker who starts outside the organization's internal network and works toward internal compromise.

Conceptually:

```text
Internet / External Position
          │
          ▼
Passive Information Gathering
          │
          ▼
Identify Useful Information
          │
          ▼
Internal Foothold
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

### Assessment 2 — Internal Attack Box

The second assessment begins with:

> **An attack box already inside the internal network**

This simulates a situation where an attacker has already obtained some form of internal network access.

The starting point is therefore different:

```text
Internal Network
      │
      ▼
Attack Box
      │
      ▼
Anonymous/Internal Enumeration
      │
      ▼
Domain Credentials
      │
      ▼
AD Enumeration
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

### 🧠 Mentor Point

These two scenarios teach an important distinction:

**Where you start determines what information and attack paths are available to you.**

An external attacker may need to perform reconnaissance first.

An internal attacker may immediately have access to:

- Internal DNS
    
- SMB
    
- LDAP
    
- Kerberos
    
- Internal hosts
    
- Domain infrastructure
    

---

# 3. 📋 Assessment Scope

Before performing **any penetration test**, you need to know:

> **What am I allowed to attack?**

The scope defines the authorized:

- Domains
    
- Subdomains
    
- IP ranges
    
- Hosts
    
- Services
    
- Attack methods
    

This is one of the most important professional habits in penetration testing.

---

# 4. 🟢 In-Scope Targets

The following are explicitly authorized.

|Scope|Description|
|---|---|
|`INLANEFREIGHT.LOCAL`|Customer domain including AD and web services|
|`LOGISTICS.INLANEFREIGHT.LOCAL`|Customer subdomain|
|`FREIGHTLOGISTICS.LOCAL`|Subsidiary company; external forest trust with `INLANEFREIGHT.LOCAL`|
|`172.16.5.0/23`|In-scope internal subnet|

### ⭐ Important

The scope isn't simply:

> "Attack Inlanefreight."

It is specifically limited to the resources listed above.

---

# 5. 🌳 Understanding the Domain Structure

The scope contains:

```text
                    INLANEFREIGHT.LOCAL
                            │
                            │
                    ┌───────┴────────┐
                    │                │
                    ▼                ▼
              AD Services      LOGISTICS
                               .INLANEFREIGHT.LOCAL


           FREIGHTLOGISTICS.LOCAL
                    │
                    │ External Forest Trust
                    │
                    ▼
             INLANEFREIGHT.LOCAL
```

The important concept here is:

## Forest Trust

`FREIGHTLOGISTICS.LOCAL` is described as a **subsidiary company** with an:

> **External forest trust**

with `INLANEFREIGHT.LOCAL`.

That means the relationship between the two environments may become relevant during AD enumeration and later attack-path analysis.

### 🧠 Mentor Rule

When you encounter:

```text
Domain
Forest
Trust
Child Domain
Parent Domain
External Trust
```

don't immediately assume compromise.

Instead ask:

```text
What trust exists?
What direction does it operate?
What authentication is possible?
What resources are exposed?
What permissions exist across the trust?
```

---

# 6. 🔴 Out of Scope

These are **NOT authorized**.

### Subdomains

```text
Any other subdomains of INLANEFREIGHT.LOCAL
```

Only:

```text
LOGISTICS.INLANEFREIGHT.LOCAL
```

is included.

---

### FREIGHTLOGISTICS.LOCAL subdomains

The parent domain is in scope:

```text
FREIGHTLOGISTICS.LOCAL
```

But:

```text
Any subdomains of FREIGHTLOGISTICS.LOCAL
```

are explicitly out of scope.

---

### Phishing / Social Engineering

```text
Any phishing or social engineering attacks
```

are prohibited.

That means we cannot attempt to obtain credentials by tricking employees.

---

### Other IPs / Domains

```text
Any other IPs/domains/subdomains
not explicitly mentioned
```

are out of scope.

This is extremely important.

If enumeration reveals another interesting domain:

```text
interesting-domain.com
```

you cannot automatically attack it just because you discovered it.

---

### Real-world Website

The real:

```text
https://www.inlanefreight.com
```

website is **not to be actively attacked**.

Only passive enumeration is permitted.

---

# 7. ⚠️ Scope Rule to Memorize

## Discovery ≠ Authorization

This is a critical professional penetration-testing concept.

Suppose you are authorized to test:

```text
INLANEFREIGHT.LOCAL
```

During enumeration you discover:

```text
SECRET.INLANEFREIGHT.LOCAL
```

Discovery does **not automatically make it in-scope**.

Always compare what you discover against the original scope.

```text
Discovered
    │
    ▼
Check Scope
    │
 ┌──┴───┐
 ▼      ▼
In     Out
scope  scope
 │      │
 ▼      ▼
Test   STOP
```

---

# 8. 🌐 External Information Gathering

The engagement permits:

> **External Information Gathering (Passive Checks)**

The purpose is to simulate a real-world attacker who has:

- No credentials
    
- No internal access
    
- No advance information
    
- Only publicly available information
    

The assessment team performs passive enumeration against information available on the internet.

---

# 9. 🕵️ Passive vs Active Reconnaissance

This distinction is **VERY IMPORTANT**.

## Passive Enumeration

Information is collected without directly interacting with the target infrastructure in an intrusive way.

Examples can include:

```text
Search engines
Public documents
Public DNS information
Certificate information
Publicly available websites
Public repositories
Publicly indexed information
```

The scope specifically permits this type of external information gathering.

---

## Active Enumeration

Active enumeration involves directly interacting with target infrastructure.

Examples include:

```text
Port scanning
Service enumeration
Vulnerability scanning
Direct requests
Exploitation
```

For the **real-world public infrastructure**, these are prohibited by the scope.

The document explicitly states:

> **No active enumeration, port scans, or attacks will be performed against internet-facing "real-world" IP addresses or the website located at `https://www.inlanefreight.com`.**

### 🔥 Remember This

```text
Real-world Internet Target
          │
          ├── Passive enumeration ✅
          │
          ├── Port scanning ❌
          │
          ├── Active enumeration ❌
          │
          └── Attacks ❌
```

---

# 10. 🧠 Why Passive Recon Matters

The purpose isn't simply to collect random information.

The objective is to find information that may help with the internal assessment.

For example:

```text
Public Information
       ↓
Organization Structure
       ↓
Potential Domains
       ↓
Employee / Technology Information
       ↓
Infrastructure Clues
       ↓
Useful Internal Testing Information
```

The module is demonstrating how an attacker can begin with **very little information** and gradually build an understanding of an organization.

---

# 11. 🏢 Internal Testing

The second major testing method is:

> **Internal Testing**

The purpose is to demonstrate the risks associated with vulnerabilities in:

- Internal hosts
    
- Internal services
    
- Active Directory
    

The assessment attempts to simulate an:

> **Untrusted insider**

---

# 12. Internal Testing Starting Position

The testers begin with:

> **An anonymous position on the internal network**

They don't receive extensive advance information.

Instead:

```text
Internal Network
      │
      ▼
Anonymous Position
      │
      ▼
Enumeration
      │
      ▼
Domain User Credentials
      │
      ▼
Internal Domain Enumeration
      │
      ▼
Foothold
      │
      ▼
Lateral Movement
      │
      ▼
Vertical Movement
      │
      ▼
Domain Compromise
```

---

# 13. 🎯 Internal Testing Goals

The scope explicitly identifies the following goals.

### 1. Obtain domain user credentials

```text
Anonymous
   ↓
Credential Discovery
   ↓
Domain User
```

### 2. Enumerate the internal domain

Once credentials or useful access are obtained:

```text
Users
Groups
Computers
Sessions
Shares
Permissions
Trusts
```

can become relevant.

### 3. Gain a foothold

Obtain an initial authenticated position on an internal system.

### 4. Move laterally

Move:

```text
Host A
  ↓
Host B
  ↓
Host C
```

### 5. Move vertically

Increase privilege:

```text
Low Privilege
     ↓
Higher Privilege
     ↓
Administrator
     ↓
Domain-Level Privilege
```

### 6. Compromise all in-scope internal domains

The final goal is to assess the impact of successfully compromising the in-scope environment.

---

# 14. Lateral vs Vertical Movement

### ↔️ Lateral Movement

Moving **across systems**.

```text
USER
 │
 ▼
WORKSTATION 1
 │
 ▼
SERVER 1
 │
 ▼
SERVER 2
```

The privilege level may remain similar, but the attacker gains access to additional systems.

---

### ⬆️ Vertical Movement

Increasing privilege.

```text
Standard User
      ↓
Local Administrator
      ↓
Server Administrator
      ↓
Domain Admin
```

### ⭐ Remember

```text
Lateral = Across
Vertical = Up
```

---

# 15. 🛡️ Avoiding Operational Disruption

The scope explicitly says:

> **Computer systems and network operations will not be intentionally interrupted during the test.**

This is a major penetration-testing principle.

A penetration test isn't:

> "Break everything."

It is:

> **Demonstrate realistic security impact while minimizing operational risk.**

Therefore, a professional tester considers:

```text
Can I safely test this?
        │
        ▼
Could this crash the service?
        │
        ▼
Could this lock accounts?
        │
        ▼
Could this affect production?
        │
        ▼
Is it explicitly authorized?
```

---

# 16. 🔑 Password Testing

The scope specifically permits password files captured from Inlanefreight devices—or provided by the organization—to be:

> **Loaded onto offline workstations for decryption**

and used to gain further access and accomplish assessment goals.

This means offline password analysis is authorized within the engagement.

---

# 17. 🔐 Why Offline Password Cracking Is Useful

Instead of repeatedly attacking a live authentication service:

```text
Live System
     ↓
Repeated Login Attempts
     ↓
Detection / Lockout / Disruption
```

the tester can potentially perform:

```text
Captured Password Material
          ↓
Offline Workstation
          ↓
Password Cracking
          ↓
Recovered Credential
          ↓
Authorized Validation
```

This can reduce the risk of account lockouts and unnecessary interaction with production systems.

---

# 18. 🔒 Credential Confidentiality

The scope contains an important confidentiality requirement:

Captured password files and decrypted passwords:

> **must not be revealed to people who are not officially participating in the assessment.**

The data must also be:

> **stored securely on Cat-5 owned and approved systems**

and retained according to the contract.

### 🧠 Professional Principle

Credentials obtained during a penetration test are **sensitive assessment data**.

They should be:

```text
Collected
   ↓
Protected
   ↓
Used only for authorized purposes
   ↓
Stored securely
   ↓
Handled according to contract
   ↓
Properly disposed/retained
```

---

# 19. 📜 Scoping Documents & Rules of Engagement

This section teaches something beyond technical exploitation.

As an offensive security professional, you will frequently receive documents such as:

### Scope of Work

Defines:

```text
What is being tested?
What isn't?
```

### Rules of Engagement (RoE)

Defines:

```text
How can testing be performed?
When?
From where?
With what restrictions?
```

### Tasking / Authorization

Defines:

```text
What objectives must be accomplished?
```

---

# 20. 🧠 Scope vs Objective vs Method

These three concepts should never be confused.

|Concept|Question|
|---|---|
|**Scope**|What can I test?|
|**Objective**|What am I trying to demonstrate?|
|**Method**|How am I allowed to test it?|

For this assessment:

### Scope

```text
INLANEFREIGHT.LOCAL
LOGISTICS.INLANEFREIGHT.LOCAL
FREIGHTLOGISTICS.LOCAL
172.16.5.0/23
```

### Objective

```text
Credential Discovery
Domain Enumeration
Foothold
Lateral Movement
Privilege Escalation
Domain Admin Credentials
```

### Methods

```text
Passive External Recon
Internal Enumeration
Authorized Password Testing
AD Attack Techniques
```

---

# 21. 🎯 The Complete Engagement Model

This entire scenario can be visualized as:

![Image](https://images.openai.com/static-rsc-4/fdKbY_syMrtC5TzB_gJ1K_5WiI3Ri-pfwvqCwWKM0CymS_9ud1qQRyPDKD5kp9q0zQnBOEFaXRadxQTBuWzmTwQaye3tSO-JeKY7l3lpNTsijRutEvmZ_AnjUDUNPLeSqnLfTjv3uErSDwWijNBdZ25BGXakDFLMc309CoxY3m2vy-LV-_HRDLOyXz3jhxBC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6jEuy_ZI3ULUz2Sd9VCe89yoGFmNWIviWI_x8GryLLZvcHzXh1s-8CzSKYC_E0fnVuit0gGI0XcwvAmc8FoEvai3H91ubEoTiJNhfZDYUeb5hItFIjwjwhSvr_8A7tnKNkCR82UNLRG2tJ8H3IfZTFYte81-ZUSp07HHzk8caOwsdB6cZE1lp0MckWQXWVqY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NgJ0JaUNmC922oXVdDJfaTzbjgjP-BfPxhKVZGKwVV4YhLWrNrrtiCDvRy7j-tseRPd3HxUrLMSSDyV5m-jo9TGsV_F5uptf7fsi3HsfgaR8wEuSA02Bq8Ez6hGoMOT3j6hRzWAkmbCPvPac_5Vg-Vwn9VUmTyO-1BhwE0CMkAX7HGNjp09S17wEt7smGNVa?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/y_YJI_-IXYP-4QrmyyybMCisgTYyV6kkVrHHznoQR-foDW-fQeq8OII-9kMRmvfnET8iHV3Vo0B4B9AbyRC628f4dMTz-VLvQjh9UM2Pp9U-W08sQsalB7ak-AhrhDGZnd_KJ9b6EobhoMAkCMq2gEWw66L85JvaA-Iyw_ylH2nKmN_hv7tffWr5Zsnv06DH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/h64QJRdXEgcGyL5pVwBV0w0PTfABU01B5l9XEUo8nfLpCDM16XWBvZxbBTp9edckdRPOdZ_aQ6P84IFPwcn4J9xxVDFTaVzMpjmV-QzFSqWoLXcq16U8WOkV2HS_lBKo5c1UhPpZb8IBpP8c2e3-CJEc01EUnBGJMAiYmXlZM2ZheaVyAKrHjYqOu-LyjMrF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jXYh00Rz7_H-7wMernAs7A_p-klyxtTdZDuJzeSIY3W_Ze_y3P_ul3wz9GQ-nJqT6C_OudhfTIn3xZVU7ZYdYkpEQMLdBLLkvXpO3ahZlfn_Tm8KjqcpH4KiX44MHaNeXsyQc4Cq5VWo_69zjbLQXJQdw13cdRdlP4_LDLk3xObjX9s3UW1vuuU_UpMvJXUP?purpose=fullsize)

```text
                    SCOPE
                      │
                      ▼
              AUTHORIZATION
                      │
                      ▼
             RECONNAISSANCE
                      │
             ┌────────┴────────┐
             ▼                 ▼
         External           Internal
         Passive            Position
             │                 │
             └────────┬────────┘
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
               REPORT / FINDINGS
```

---

# 22. ⭐ Critical Scope Checklist

Before executing any command against a target, ask:

### Scope

- Is the IP in scope?
    
- Is the hostname in scope?
    
- Is the domain in scope?
    
- Is the subdomain in scope?
    

### Method

- Is this attack technique authorized?
    
- Is active enumeration allowed?
    
- Is exploitation allowed?
    
- Is credential testing allowed?
    

### Impact

- Could this lock an account?
    
- Could this crash a service?
    
- Could this affect production?
    
- Could this interrupt operations?
    

### Data

- Am I handling credentials?
    
- Where are they stored?
    
- Who is authorized to see them?
    

---

# 23. 🧠 Mentor Exercise — Think Like a Pentester

Before we begin the actual technical exercises, you should be able to answer these **without looking back**:

### Q1.

Is `INLANEFREIGHT.LOCAL` in scope?

**Yes.**

### Q2.

Is `LOGISTICS.INLANEFREIGHT.LOCAL` in scope?

**Yes.**

### Q3.

Is every subdomain of `INLANEFREIGHT.LOCAL` automatically in scope?

**No.**

### Q4.

Is `FREIGHTLOGISTICS.LOCAL` in scope?

**Yes.**

### Q5.

Are subdomains of `FREIGHTLOGISTICS.LOCAL` in scope?

**No.**

### Q6.

Is `172.16.5.0/23` in scope?

**Yes.**

### Q7.

Can we actively scan `www.inlanefreight.com`?

**No.**

### Q8.

Can passive enumeration of the real-world website be performed?

**Yes, according to the scope.**

### Q9.

Is phishing authorized?

**No.**

### Q10.

Can captured password material be used for offline cracking?

**Yes, within the explicitly authorized assessment conditions.**

---

# 🔥 24. The Most Important Lessons From This Section

If you're preparing for the actual exercises, memorize these:

### **1. Scope comes first.**

```text
Scope → Authorization → Testing
```

Never reverse this.

### **2. Discovery does not expand scope.**

Finding something doesn't mean you're authorized to attack it.

### **3. Passive ≠ Active.**

Passive information gathering is authorized against the real-world external infrastructure, while active enumeration and attacks are not.

### **4. Internal testing starts from an untrusted position.**

The objective is to discover what an attacker with internal access could accomplish.

### **5. Lateral ≠ Vertical.**

```text
Lateral = across systems
Vertical = increase privilege
```

### **6. Credentials are sensitive data.**

Their handling is part of professional penetration testing.

### **7. AD testing is about chaining information.**

```text
Enumeration
      ↓
Credentials
      ↓
Access
      ↓
Relationships
      ↓
Lateral Movement
      ↓
Privilege Escalation
      ↓
Domain Compromise
```

### **8. The goal isn't "hack everything."**

The goal is to **demonstrate the security impact within the authorized scope without intentionally disrupting operations.**

---

## 🎯 Where We Are Now

We have now covered the **Scenario + Scope** section. The next section begins the actual technical work:

> **Passive external enumeration against Inlanefreight.**

That is where we'll start applying the tools and methodology we've already documented.

For the exercises, I'll switch into **Cybersecurity Mentor Mode**: I'll give you the objective, let you reason first, explain what evidence we're looking for, and then use the appropriate command/tool rather than simply dumping the answer.