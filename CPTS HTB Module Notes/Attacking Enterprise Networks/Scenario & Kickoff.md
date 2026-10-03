![Image](https://images.openai.com/static-rsc-4/9L3sFr4dvrQB5emTpngDkBttuYV-lJa-dZsPR3zC913wLchpnpTD-XW3Rcga1WLv_fEup-OYVMDHe-kyOLu8BHYy-PpDe6ADtVoTxyi3w7SbeOgC3ICqOi6WmHVtv9EJPBJ7cBU7tMVWKTsaDpnDYYryr0q5-uJ3VupreHzfHA-wa7UqpRgGq8WEBlKLbuwA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-WFaeKRhCbNIm7hxXRWk1lw20yoEkcDuixNplZdzjs5YPYmid4hrM-9RfIfyGmMCXmh7cQFlXCCRC-V_wQTZwPKbLHgRtOSxROPMKyVRXa8oXHAu9ymjWrF1j1NQ0Y9QcMFtOql0wAwEcIKNJ4mTApy6LHAXUjGta2HWFpUGMv-n0-fRWrQNfyp_5eZDsClx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7NPH7aON4dOXUe1iOenZ0UAwK08KEC5PwaXsu0q-aZicokc-vALe11JK8HGre8fhWW4ktVCLUcPHJ1SQViyT72KpqX0D4xna9IrYoJ71OZBZj094Xobv3xO0FE1CHaZ-qVWQwksy14LyO7gXydXr_GFU7KK8MWJqgD93kw4-p6gpvqQdbVWt4GsqL3edDsta?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0rIijQC-BshvMZHmhQMNL8jjaAlbPasYKqRUbnAmr06xSkwh2PLyVEkM87_wNfiFQA8oVql6sNCMRI1ccQxFCxrMKn9xtygpsYvEQWmu6lTbWOhuDHaEKCaKKFXl-1uCSSiWhI7SJvBMa7PLn3bYv9dUo9CICZ8QYF1E8jy9ugsIgnB4nwxkTvJwx38Dsxgo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/kuEKJjLelfaI43XYR3EnPBthy4IP_rqCU0TiBQ5CbOc_mtRe3-QOVOyJMOAOEoaPkjSGn4pF-bJg-u7uM79BEBJqQ1RKSW_mZ1WonYR4uwrykG1bvnbB7fH8JSULwsiNLLsPdNaqAFw0blD_A_eFNcHSjSuxAN2R-3yyWwLIqo21N90yKioV2QUsoEw7x5qL?purpose=fullsize)

These notes preserve the **important scope, authorization, Rules of Engagement (RoE), contacts, timelines, restrictions, and testing methodology** from the material you provided, while organizing it into a format suitable for **CPTS study, revision, and your penetration-testing report notes**.

---

# 1. 🎯 Scenario Overview

### Client

**Inlanefreight**

### Security Testing Company

**Acme Security, Ltd.**

### Assessment Type

> **Full-Scope External Penetration Test**

### Primary Objective

The purpose of the assessment is to evaluate **Inlanefreight's perimeter security** and determine:

- What vulnerabilities are exposed to an anonymous Internet user.
    
- What level of access can be obtained externally.
    
- Whether the DMZ can be breached.
    
- Whether access can be extended into the internal network.
    
- How far access can be taken once inside.
    
- Whether Active Directory can ultimately be compromised.
    

The customer specifically wants the testers to identify **as many vulnerabilities as possible**.

Therefore:

> **Evasive testing is NOT required.**

---

# 2. 🧠 Attacker Perspective

The assessment is designed to simulate an attacker who begins with:

```text
NO CREDENTIALS
       ↓
ANONYMOUS INTERNET USER
       ↓
EXTERNAL RECON
       ↓
VULNERABILITY DISCOVERY
       ↓
EXPLOITATION
       ↓
DMZ ACCESS
       ↓
INTERNAL NETWORK ACCESS
       ↓
ACTIVE DIRECTORY
       ↓
DOMAIN COMPROMISE
```

This is important because the tester is **not starting with privileged access**.

The objective is to determine how far an unauthenticated external attacker could potentially progress.

---

# 3. 🌐 External Testing Scope

The following external targets are explicitly in scope.

## External Network

```text
10.129.x.x
```

This represents the:

> **"external" facing target host**

---

## External Domain

```text
*.inlanefreight.local
```

This means:

> **All subdomains of inlanefreight.local are in scope.**

The client has provided the primary domain but **has not provided the exact subdomains**.

Therefore, part of the assessment involves discovering them.

---

# 4. 🏢 Internal Testing Scope

If a foothold into the internal network is achieved, the assessment expands to the following internal networks:

### Network 1

```text
172.16.8.0/23
```

### Network 2

```text
172.16.9.0/23
```

### Active Directory

```text
INLANEFREIGHT.LOCAL
```

Therefore, the internal scope is:

```text
172.16.8.0/23
        +
172.16.9.0/23
        +
INLANEFREIGHT.LOCAL
```

---

# 5. 🗺️ Scope Diagram

![Image](https://images.openai.com/static-rsc-4/3NV7kW_9npx_aCid7hbgO6VXa1OlXfpH6IG1a8zUt2Y9ybCKONA4wI7_2Ju5TLvArQQCC29q2HYBX2OLas93y_fnS_HNDl492z973D9_Iohy5gRnHb6XEWgtVVqhCgiz26oZVYJwbpuaFdDvPmgMnZsECoTIOuSPNt2IliIUe5ZWcDThrZuyuBLbOqtG0riZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/uzvAbmAwPgU25mhB6muPyTpjd2H4zRHN3alnThmBvE8o66xHI7o93vWu-UxZZ4qk_BY0hWTuePSeaBD7Smfs4RrkcP8sy7ij2UHIK9VSFuwvcr5NEwboRcKjy00PzyIEF1PeDmqAosGLhlpMKZZxi6oW03ZyTMLyJ63v6UxaDJ5Te70KJhkI3Sk5UD7aZeYD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/UNZz164DYiugbRp_M30BH54ZyRP2stM601rNwGPWGp3uxI7_8Jhl1iRN0nGuVwMvkHlgDpgFjzvTHyvuT0hy26IH6zBZTkN6BHfA72h3rlblDf2RABLxI8JN-eFJnJ66O3rmnCvcAnlq97brEMh8okJJzmxdHkvrhHfNI8Gbl9adpEb0l_tFxQK4lPcDqR7I?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iieUyIIU0YE28XaIUkKHbSUvAWN6AszNRHVhe7jNmYTrRJSgOMeKtI6W22wdk-YSZb3dZcrRKef30W0xqY_6VG9OAB6FsXoh-MKBO15-VnGqXvu5d5zCBqJw-H3R4R5umNnhnIvnlShBBJyBSbXifWkZfKkuMIu4cCwgCAw8HqhA8VnZ2pYzc7gcQkf70sJL?purpose=fullsize)

A simplified representation of the engagement:

```text
                    INTERNET
                       │
                       │
                Anonymous User
                       │
                       ↓
              ┌─────────────────┐
              │ External Target │
              │ 10.129.x.x      │
              └────────┬────────┘
                       │
                       ↓
                     DMZ
                       │
                       │ Foothold
                       ↓
             ┌─────────────────────┐
             │ Internal Network    │
             │ 172.16.8.0/23      │
             │ 172.16.9.0/23      │
             └──────────┬──────────┘
                        │
                        ↓
              Active Directory
             INLANEFREIGHT.LOCAL
                        │
                        ↓
                Domain Compromise
```

---

# 6. 🔐 Credentials Provided?

The client has **NOT provided**:

- Web application credentials
    
- VPN credentials
    
- Active Directory user credentials
    

Therefore, the external assessment begins from an **unauthenticated perspective**.

This is an important scope detail.

### Starting position:

```text
Credentials: NONE
```

The tester must discover whether access can be obtained without supplied credentials.

---

# 7. 🔎 Discovery Is Part of the Assessment

The client has provided:

- Primary domain
    
- External network range
    
- Internal network ranges
    

But they have **not provided**:

- Exact subdomains
    
- Exact live hosts
    
- Exact internal live systems
    

Therefore, the tester is expected to perform **discovery**.

The goal is to determine:

> **What visibility does an attacker have against the external network?**

And, if internal access is achieved:

> **What visibility does an attacker have against the internal network?**

---

# 8. 🤖 Automated Testing Is Allowed

The client explicitly permits automated testing techniques.

Examples include:

- Enumeration
    
- Vulnerability scanning
    
- Service discovery
    
- Automated vulnerability assessment
    

However, there is an important restriction:

> **Testing must be performed carefully to avoid service disruption.**

So:

```text
Automated Testing
        ↓
Allowed
        ↓
But
        ↓
Avoid Service Disruption
```

This distinction is extremely important in professional penetration testing.

---

# 9. 🚫 Out-of-Scope Activities

The following activities are **explicitly OUT OF SCOPE**.

## 1. Phishing / Social Engineering

Do not perform phishing or social-engineering attacks against:

- Inlanefreight employees
    
- Inlanefreight customers
    

---

## 2. Physical Attacks

Physical attacks against Inlanefreight facilities are prohibited.

For example:

- Physical intrusion
    
- Office access testing
    
- Badge attacks
    
- Physical device tampering
    

---

## 3. Destructive Actions / DoS

The assessment does **NOT** authorize:

- Destructive actions
    
- Denial-of-Service testing
    
- Activities intended to disrupt services
    

Even though the objective is to find as many vulnerabilities as possible, **availability must be protected**.

---

## 4. Unauthorized Environmental Modifications

The tester must not modify the environment without:

> **Written consent from authorized Inlanefreight IT staff.**

This is an important professional rule.

### Therefore:

```text
Finding a vulnerability
        ≠
Permission to modify the environment
```

---

# 10. 📜 Scope of Work — SoW

Before testing begins, a **Scope of Work (SoW)** has been signed.

The SoW is signed by:

- Acme Security management
    
- An authorized member of Inlanefreight IT
    

The SoW defines important engagement details.

### It includes:

- Testing specifics
    
- Testing methodology
    
- Timeline
    
- Meetings
    
- Deliverables
    

---

# 11. 📑 Rules of Engagement — RoE

A separate **Rules of Engagement (RoE)** document has also been signed.

It is commonly known as an:

> **Authorization to Test**

This document is extremely important.

It establishes what the penetration testers are **authorized to test**.

---

# 12. 🛡️ What the RoE Defines

The RoE lists the scope for different types of assessments.

Examples include:

### URLs

```text
https://example.target
```

### Individual IP addresses

```text
10.x.x.x
```

### CIDR ranges

```text
172.16.8.0/23
```

### Credentials

If applicable, credentials authorized for testing should be documented.

---

# 13. 👥 Emergency & Engagement Contacts

The RoE also contains key personnel from both organizations.

Minimum requirement:

```text
Acme Security
    ↓
At least 2 contacts

Inlanefreight
    ↓
At least 2 contacts
```

Contact information includes:

- Name
    
- Phone/cell number
    
- Email address
    

This is critical in case something unexpected happens during testing.

---

# 14. 📅 Testing Dates & Testing Window

The RoE also defines:

- Testing start date
    
- Testing stop date
    
- Authorized testing window
    

This prevents testers from performing unauthorized testing outside the agreed engagement period.

---

# 15. ⏱️ Engagement Timeline

The testing team has been given:

### Testing

**1 week**

### Reporting

**2 additional days**

Total planned engagement period:

```text
1 Week Testing
       +
2 Days Draft Report
       =
Engagement Timeline
```

However, an important professional practice is:

> **The report should be worked on throughout the engagement rather than waiting until the final two days.**

---

# 16. 🌙 Testing Hours

The client has authorized testing:

> **24/7**

However, there is a special requirement for heavy scans.

### Heavy vulnerability scans

Should be performed:

> **Outside regular business hours**

Specifically:

> **After 18:00 London time**

Therefore:

```text
Normal Testing
      ↓
24/7 Authorized

Heavy Vulnerability Scanning
      ↓
After 18:00 London Time
```

---

# 17. ✅ Administrative Readiness

Before beginning technical testing, the team verifies:

### Documentation

- SoW signed
    
- RoE signed
    
- Scope completed
    
- Testing dates established
    
- Testing window established
    
- Contacts established
    
- Authorization confirmed
    

### Result

> **The team is administratively cleared to begin testing.**

This is an extremely important professional penetration-testing concept:

## Never begin testing without proper authorization.

---

# 18. 🚀 Project Kickoff Checklist

Before touching the environment:

```text
┌───────────────────────────────────┐
│       PROJECT KICKOFF             │
├───────────────────────────────────┤
│ ✓ SoW signed                      │
│ ✓ RoE signed                      │
│ ✓ Authorization confirmed        │
│ ✓ Scope confirmed                 │
│ ✓ IP ranges confirmed             │
│ ✓ Domains confirmed               │
│ ✓ Internal networks confirmed     │
│ ✓ Testing window confirmed        │
│ ✓ Contacts confirmed              │
│ ✓ Emergency contacts available    │
│ ✓ Out-of-scope activities known   │
│ ✓ Deliverables understood         │
└───────────────────────────────────┘
```

Only after these items are confirmed should testing begin.

---

# 19. 💻 Testing Environment

It is now:

> **First thing Monday morning**

The testing team is ready.

The penetration-testing VM has been configured.

The tester also creates a:

> **Skeleton note-taking and directory structure**

before starting the assessment.

This is an excellent professional habit.

---

# 20. 📁 Note-Taking Structure

A penetration tester should maintain organized evidence from the beginning.

A practical structure could look like:

```text
Inlanefreight/
│
├── 01_Scope/
│
├── 02_Recon/
│
├── 03_Enumeration/
│
├── 04_Vulnerability_Assessment/
│
├── 05_Exploitation/
│
├── 06_Post_Exploitation/
│
├── 07_Lateral_Movement/
│
├── 08_Active_Directory/
│
├── 09_Pivoting/
│
├── 10_Evidence/
│
├── 11_Screenshots/
│
└── 12_Report/
```

The exact structure can vary, but the important thing is **consistency and traceability**.

---

# 21. 📝 Documentation While Scanning

A very important efficiency technique is described in this section.

While initial discovery scans are running, the testers begin filling out:

> **The report template**

Instead of waiting for scans to finish, they use the time productively.

### Workflow:

```text
Start Discovery Scan
        │
        ├──────────────→ Wait
        │
        ↓
Work on Report Template
        │
        ↓
Document Scope
        ↓
Document Methodology
        ↓
Document Engagement Details
        ↓
Review Initial Results
```

This saves time during the engagement.

---

# 22. 📊 Why Continuous Documentation Matters

If you wait until the end of the engagement to write the report, you may forget:

- Why you tested something
    
- What commands you used
    
- When you discovered something
    
- Which host was involved
    
- How you obtained access
    
- Which attack path was successful
    
- What evidence supports a finding
    

Therefore:

> **Documentation should happen throughout the penetration test.**

---

# 23. 📧 Start-of-Testing Communication

Before beginning external information gathering, the team sends an email notifying the relevant personnel that testing is beginning.

The email is from:

**Bryan Robinson**

To:

**Sarah McDonald**

The email communicates the start of the external penetration test for Inlanefreight.

---

# 24. 🖥️ Testing Source IP

The testing traffic originates from:

```text
10.10.14.15
```

This is an important engagement detail because the client can identify traffic generated by the penetration-testing team.

In a real engagement, the source IP may be allowlisted, monitored, or used to distinguish authorized security testing from malicious traffic.

---

# 25. 👤 Secondary Contact

The email identifies:

**John Lee**

as the:

> **Principal Security Consultant**

along with the relevant contact details.

Having secondary contacts is important because penetration tests can encounter unexpected situations requiring rapid communication.

---

# 26. 📧 Start-of-Testing Communication Flow

The overall kickoff process is:

```text
SoW Signed
     ↓
RoE Signed
     ↓
Scope Confirmed
     ↓
Testing Window Confirmed
     ↓
Contacts Confirmed
     ↓
Testing VM Prepared
     ↓
Notes Structure Created
     ↓
Report Template Prepared
     ↓
Start-of-Test Email Sent
     ↓
External Recon Begins
```

---

# 27. 🔎 External Information Gathering Begins

After sending the kickoff email:

> **External information gathering begins.**

The initial objective is to determine what an unauthenticated attacker can discover from the Internet.

Potential discovery areas include:

```text
Domain
  ↓
Subdomains
  ↓
DNS
  ↓
IP addresses
  ↓
Live hosts
  ↓
Open ports
  ↓
Services
  ↓
Technologies
  ↓
Potential vulnerabilities
```

Remember:

The exact subdomains and live hosts have **not** been provided.

Therefore, discovery is part of the engagement.

---

# 28. 🧠 Key Professional Lessons

## Lesson 1 — Authorization Comes First

Before testing:

> **Confirm written authorization.**

The RoE/Authorization to Test establishes the legal and technical boundaries.

---

## Lesson 2 — Scope Is Everything

Always know:

```text
WHAT can I test?
WHERE can I test?
WHEN can I test?
HOW can I test?
WHAT can I NOT do?
WHO do I contact if something goes wrong?
```

---

## Lesson 3 — In-Scope Does Not Mean "Anything Goes"

Even within the scope, restrictions apply.

For example:

```text
Automated Scanning
       ↓
Allowed

DoS
       ↓
Not Allowed
```

and:

```text
Finding a vulnerable system
       ↓
Does NOT automatically authorize
environment modification
```

---

## Lesson 4 — External Access Can Lead to Internal Testing

The engagement specifically allows escalation of testing scope after a successful foothold:

```text
External
   ↓
DMZ
   ↓
Internal Network
   ↓
Active Directory
   ↓
Domain Compromise
```

This is why the assessment is **full-scope**.

---

## Lesson 5 — Protect Availability

Even during aggressive vulnerability discovery:

> **Do not cause service disruptions.**

Heavy scans should be scheduled appropriately.

---

## Lesson 6 — Document as You Go

Don't wait until the end.

```text
Test
 ↓
Record
 ↓
Capture Evidence
 ↓
Continue Testing
```

This makes the final report much easier to produce.

---

# 29. 📌 CPTS Exam / Practical Takeaways

Memorize these points from this section:

### Scope

```text
External:
10.129.x.x
*.inlanefreight.local

Internal:
172.16.8.0/23
172.16.9.0/23
INLANEFREIGHT.LOCAL
```

### Starting Position

```text
Anonymous Internet User
No provided credentials
```

### Testing

```text
Full-Scope External Pentest
↓
DMZ Breach
↓
Internal Access
↓
Active Directory
↓
Potential Domain Compromise
```

### Authorized

- Automated enumeration
    
- Vulnerability scanning
    
- External testing
    
- Internal testing after foothold
    
- 24/7 testing
    

### Heavy scans

> **After 18:00 London time**

### Out of Scope

- ❌ Phishing/social engineering
    
- ❌ Physical attacks
    
- ❌ Destructive actions
    
- ❌ DoS testing
    
- ❌ Unauthorized environment modifications
    

### Documentation

- SoW
    
- RoE
    
- Authorization to Test
    
- Contacts
    
- Testing window
    
- Scope
    
- Evidence
    
- Reports
    

---

# 🔥 Final Mental Model

```text
                 INLANEFREIGHT
                       │
              ┌────────┴────────┐
              │   AUTHORIZED    │
              │   PENTEST       │
              └────────┬────────┘
                       │
                       ↓
              EXTERNAL RECON
                       │
                       ↓
             10.129.x.x / DOMAIN
                       │
                       ↓
              VULNERABILITY TEST
                       │
                       ↓
                 DMZ FOOTHOLD
                       │
                       ↓
              INTERNAL NETWORK
               /             \
              ↓               ↓
       172.16.8.0/23    172.16.9.0/23
              \               /
               └──────┬──────┘
                      ↓
          INLANEFREIGHT.LOCAL
                      │
                      ↓
             ACTIVE DIRECTORY
                      │
                      ↓
              DOMAIN COMPROMISE
```

## 🧠 The core principle

**Scope → Authorization → Recon → Enumeration → Exploitation → Internal Access → AD → Documentation**

The most important thing to understand from this section is that a professional penetration test isn't simply **"run Nmap and hack the target."** The tester must operate within a clearly documented **scope and authorization**, understand exactly what is permitted, protect availability, communicate with the client, document continuously, and then methodically determine how far an external attacker can progress.

![[Pasted image 20261002124440.png]]