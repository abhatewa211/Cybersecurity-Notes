![Image](https://images.openai.com/static-rsc-4/7bI211UfGJBNm_8WGBUmChi5sVl5J0nx4qYgpBTW-T8BUhuW_Q6QcSyPWUV6bxdJ-BTw5laZ--uBW1NqsjXgs47_a3iKYpTAA0PGsgW37b4YgI-_Nwo1RFiFJKnX0TGpHJbBae_R38WYSHHSnh8PEX6UJRNN-_2hxZ6azlxjViVjK_Rmu57nHGrZOk0BDdSK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iBCalZF0QgHG8HIBQECj9s9MO75WccCRlV5WBeUBtm5Wmzmen8FnB9JgPHDTP8PDIYczTFPY2FskprXpB5xQYvNkrhiQd1SDuV9R3GJusdj41CLG_GqFKCKhs2SXKKJUP30VM-PAtYz-OxpToYRjF4-E5_vzyl7pMRo8U-M0QQuun1i2kiiyal5P83aXhF7Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6p0atG-Er70EdP4W881E1mfYYlm-8MMz9Ny4Tj_1CCKDDD8kMgC2M4UxoS_G2j-g-suDZz1PXcpREsvqjp08dRuoH7utvzzAXDm5f_ZF-Pt63s6bNCxyQZ5HKdYYyoxa9QkeUdZYpLA9SAXV_q38J9fG2RCL-G8WZv0JkT5Qe-NXTqtzja604ZnRPo7uORkc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gpoqFSj9gPVHKmR66SH5P8J0UFa6rsjn9NVjvdSUxD2_kgYSGNtoaP5lXFk4VIu4dQ2L10mQ1y7btkjWT1qq7n0T_xzib5B_pvS0siCmUuI4YChVBb_PdEIQ79zWn5PRQjNE4RKWvmCYVG_v0eqKFJ_qjvZx0eDLbGwmgGwbvFkyfbAMXXoUSiCn46vKEPpF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dXIUFMVi0NNlc9Vr-CDm2Vdy62eLZl9Poz5xS_8MgfTgsfg4pZUKtQqY-9MS6Wwet4vgbeOK-tl0VuUbRC4hQMBaQ2EiXl7FNim8TbS5_Ve1CrjXgCSeXpGzAw_KXDL8vSzOYHLbGir_Pm-RGHR2gEzuUF6mYAyGbwQU8mPjQpMY1DbQXlFGmnAYu_qrz5m5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OZgJNOwOfsB3syndoLRuu-Tbo4MGl8_xvRcsPcvac9YCl-0bhDi0P_2ZAj-6ob_fM1LfpsSqU61qW8nJ8N9Ezc6M3jbVtGx0CdkHu-jmfgAi-3sdCqJ78vybyiK99S1StqhLXxXT8zuVUK53BqBQ0AnUAhaFSNxUF8B3JxgKD-8BBbZ6GAtU6S-LjiIlH9H7?purpose=fullsize)

# Introduction to Documentation and Reporting

## 1. Why Documentation & Reporting Matters

Strong **documentation and reporting skills** are extremely important in Information Technology and Information Security.

Technical skills such as:

- Enumeration
    
- Exploitation
    
- Privilege escalation
    
- Active Directory attacks
    
- Web application testing
    
- Network penetration testing
    

are essential, but technical ability alone is not enough.

A penetration tester must also be able to **clearly document what they did, what they discovered, and how they proved it**.

### Important Principle

> **Technical skills get you the finding; documentation proves the finding.**

A highly skilled penetration tester who cannot properly document their work may struggle to:

- Explain vulnerabilities to clients.
    
- Reproduce their findings.
    
- Defend their actions.
    
- Write professional reports.
    
- Communicate with non-technical management.
    
- Preserve evidence.
    
- Continue testing after a system failure.
    
- Demonstrate that testing stayed within scope.
    

---

# 2. Where Documentation Is Used

Documentation and reporting are useful in many areas of cybersecurity.

Examples include:

### Internal Policies

Documents explaining how an organization should:

- Handle passwords
    
- Manage access
    
- Respond to incidents
    
- Configure systems
    
- Protect sensitive information
    

### Technical Documentation

Documents describing:

- Network architecture
    
- Systems
    
- Applications
    
- Configurations
    
- Security controls
    
- Procedures
    

### Penetration Test Reports

Reports describing:

- What was tested
    
- When it was tested
    
- How it was tested
    
- What vulnerabilities were found
    
- How vulnerabilities were exploited
    
- What evidence proves the vulnerability
    
- What impact the vulnerability could have
    
- How the issue should be fixed
    

### Client Deliverables

The final documentation delivered to the customer after an engagement.

---

# 3. There Is No "One Size Fits All"

There is no single perfect method for taking notes or writing penetration test reports.

Different testers may use:

- Obsidian
    
- OneNote
    
- Markdown
    
- CherryTree
    
- Notepad
    
- Joplin
    
- Custom scripts
    
- Spreadsheets
    
- Screenshots
    
- Terminal logging
    

The important thing is not necessarily the tool.

The important thing is having a **consistent and reliable process**.

A good documentation process should make it easy to answer:

1. What did I do?
    
2. When did I do it?
    
3. Against which target?
    
4. From which source system?
    
5. Which command/tool did I use?
    
6. What was the result?
    
7. What evidence did I obtain?
    
8. What does the evidence prove?
    
9. What happened next?
    
10. Can another tester reproduce it?
    

---

# 4. Fundamental Documentation Principles

Good penetration testing documentation should be:

### Detailed

Record specific actions instead of vague statements.

Bad:

> Scanned the network.

Good:

> Performed TCP port enumeration against the identified target using Nmap and recorded the resulting open services and versions.

---

### Organized

Use a consistent directory and naming structure.

For example:

```text
Pentest/
├── 01-Overview/
├── 02-Scope/
├── 03-Enumeration/
├── 04-Exploitation/
├── 05-Privilege-Escalation/
├── 06-Active-Directory/
├── 07-Findings/
├── 08-Evidence/
├── 09-Attack-Chain/
├── 10-Reports/
└── 11-Retest/
```

---

### Reproducible

Another tester should be able to understand how you reached the result.

Record:

```text
Target
↓
Command
↓
Output
↓
Observation
↓
Exploit/validation
↓
Evidence
↓
Impact
```

---

### Evidence-Based

Do not rely only on memory.

Save:

- Screenshots
    
- Terminal output
    
- Tool output
    
- Logs
    
- Requests/responses
    
- Configuration files
    
- Relevant command history
    
- Proof of access
    
- Timestamps
    

---

# 5. Penetration Testing Is a Snapshot in Time

One of the **most important concepts** in penetration testing documentation is that a penetration test represents a **snapshot of the target environment during a specific period**.

The environment can change after testing.

For example:

```text
January 7
     ↓
Testing begins
     ↓
January 19
     ↓
Testing ends
     ↓
January 20+
     ↓
Client changes infrastructure
```

A vulnerability introduced after January 19 would not necessarily be covered by the original report.

Therefore, the report should clearly document the testing period.

### Example

> "All testing activities were performed between January 7, 2022 and January 19, 2022."

A disclaimer may also be included:

> "This report represents a snapshot in time during the aforementioned testing period, and Acme Consulting, LLC cannot attest to the state of any client-owned information assets outside of this testing window."

### Important Information to Record

The overview should include:

- Type of assessment
    
- Testing dates
    
- Testers
    
- Source IP addresses
    
- Testing location
    
- VPN usage
    
- Internal/external testing position
    
- Special testing considerations
    
- Scope
    
- Out-of-scope systems
    
- Limitations
    

---

# 6. Internal vs External Penetration Testing

Throughout penetration testing documentation, you may see:

### Internal

"An internal" generally refers to an:

> **Internal Penetration Test**

The tester is operating from inside the organization's network or from a position that simulates an internal attacker.

Examples:

```text
Internal workstation
       ↓
Corporate network
       ↓
Servers
       ↓
Active Directory
       ↓
Domain Controller
```

### External

"An external" refers to an:

> **External Penetration Test**

The tester operates from outside the organization's network.

Example:

```text
Internet
   ↓
Public IP
   ↓
Firewall
   ↓
VPN/Web Server
   ↓
Internal Infrastructure
```

---

# Documentation & Reporting in Practice

# 7. Scenario 1 — The Case of an Exploding VM

This scenario demonstrates why **backup and evidence preservation** are critical.

A tester was conducting a nearly month-long external penetration test.

One day, the testing VM failed completely.

The tester attempted filesystem recovery, but the filesystem was gone.

Fortunately, detailed project notes had been maintained on a separate workstation.

The testing team also used shared storage and automated synchronization.

The tester had been backing up project evidence at the end of every working day.

Therefore:

```text
Destroyed VM
     ↓
Build new VM
     ↓
Sync project data
     ↓
Restore evidence
     ↓
Continue testing
```

### Lesson

A testing VM should never be the **single source of truth**.

Important project data should be backed up.

### What Should Be Backed Up?

- Notes
    
- Screenshots
    
- Scan results
    
- Tool output
    
- Logs
    
- Evidence
    
- Findings
    
- Credentials obtained during authorized testing
    
- Attack paths
    
- Configuration information
    
- Report drafts
    

### Key Takeaway

> **If your evidence exists in only one place, you don't really have a backup.**

---

# 8. Scenario 2 — Ping of Death

This scenario demonstrates the importance of:

- Scope documentation
    
- Written authorization
    
- Scan logs
    
- Timestamps
    
- Raw evidence
    
- Exclusion lists
    

The tester was performing an internal penetration test.

A member of the client's IT team was hostile and highly protective of several critical servers.

During enumeration, the tester received an email and call requesting that testing stop because several critical servers had apparently been brought down.

The tester reviewed the evidence.

The affected IP addresses were included in the client's confirmed scope.

The tester had also retained:

- Scope files
    
- Log data
    
- Timestamped scan results
    
- Raw scanning data
    

Therefore, the tester could demonstrate exactly what had happened.

### Why Documentation Protected the Tester

The documentation demonstrated:

```text
Client-approved scope
        ↓
Target IP included
        ↓
Tester scanned target
        ↓
Raw scan evidence
        ↓
Timestamped records
```

The tester had not knowingly tested an unauthorized system.

### Lesson Learned

Even when documentation protects you, processes can still be improved.

The tester changed their process to explicitly ask clients for:

- IP addresses that must never be scanned
    
- Hostnames that must never be tested
    
- Critical systems
    
- Sensitive infrastructure
    
- Explicit exclusions
    

### Important Practice

Maintain a separate:

## EXCLUSION LIST

```text
DO NOT TEST

10.10.10.50 — Production DB
10.10.10.51 — Backup Server
10.10.10.60 — VoIP Infrastructure
server-critical.example.com
```

This reduces ambiguity.

---

# 9. Scenario 3 — Slow as Molasses

This scenario demonstrates how documentation can help determine the actual cause of a network problem.

The tester was conducting an internal penetration test onsite.

A network administrator was already skeptical because previous penetration tests had reportedly caused network slowdowns.

Less than 20 minutes after testing began, the administrator claimed that the scans had slowed the network significantly.

The tester's source IP addresses were blocked.

Instead of simply arguing, the testers produced their evidence.

They showed:

- Scan output
    
- Commands
    
- Configuration
    
- Testing activity
    
- Evidence of following normal scanning practices
    

Another administrator discovered that:

> **Debug mode had been enabled on every network device.**

The combination of debug mode and normal Nmap scanning was sufficient to overwhelm the devices.

After debug mode was disabled, testing continued normally.

### Lesson

Without documentation, the tester could easily have been blamed.

With documentation:

```text
Tester activity
      ↓
Scan evidence
      ↓
Configuration investigation
      ↓
Debug mode discovered
      ↓
Actual cause identified
```

### Key Takeaway

> **Documentation protects both the tester and the client.**

---

# 10. Why These Scenarios Matter

The three scenarios demonstrate three major principles.

|Scenario|Main Lesson|
|---|---|
|Exploding VM|Back up your evidence|
|Ping of Death|Document scope and exclusions|
|Slow as Molasses|Keep detailed technical evidence|

Strong documentation helps you:

- Justify your actions
    
- Reproduce findings
    
- Troubleshoot problems
    
- Protect yourself professionally
    
- Protect the client
    
- Preserve evidence
    
- Avoid repeating testing
    
- Maintain continuity
    
- Demonstrate compliance with scope
    
- Produce better reports
    

---

# 11. Never Rely on Memory

A common mistake is thinking:

> "I'll remember this and write it in the report later."

This is unreliable.

During a long penetration test you may perform hundreds or thousands of actions.

For example:

```text
Nmap
↓
SMB enumeration
↓
LDAP enumeration
↓
Web enumeration
↓
Credential discovery
↓
Password spraying
↓
Initial foothold
↓
Privilege escalation
↓
Lateral movement
↓
Domain compromise
```

Trying to reconstruct everything days or weeks later can result in:

- Missing evidence
    
- Incorrect commands
    
- Incorrect timestamps
    
- Missing screenshots
    
- Forgotten attack paths
    
- Incomplete findings
    

Therefore:

> **Document findings as they occur.**

---

# 12. Documentation Workflow

A useful workflow is:

```text
PLAN
  ↓
SCOPE
  ↓
ENUMERATION
  ↓
DISCOVERY
  ↓
VALIDATION
  ↓
EXPLOITATION
  ↓
POST-EXPLOITATION
  ↓
EVIDENCE COLLECTION
  ↓
FINDING DOCUMENTATION
  ↓
ATTACK CHAIN
  ↓
REPORT
  ↓
QA
  ↓
DELIVER
  ↓
RETEST
```

Each phase should produce documentation.

---

# 13. What to Record During Testing

For every important action, try to capture:

### 1. Timestamp

When did the activity occur?

Example:

```text
2026-10-01 03:15 IST
```

### 2. Target

What system was tested?

```text
10.10.10.25
```

### 3. Source

Which machine/IP performed the test?

```text
10.10.14.20
```

### 4. Tool

What tool was used?

```text
Nmap
Burp Suite
NetExec
Impacket
Metasploit
```

### 5. Command

Record the exact command where practical.

### 6. Result

What happened?

### 7. Evidence

Save screenshots, logs, or output.

### 8. Interpretation

Explain what the result means.

### 9. Next Step

Record what you did next.

---

# 14. Evidence Management

Evidence should be stored systematically.

Example:

```text
Evidence/
├── Screenshots/
│   ├── 001-web-login.png
│   ├── 002-sql-error.png
│   └── 003-shell.png
│
├── Nmap/
│   ├── initial-scan.txt
│   ├── full-tcp.txt
│   └── udp-scan.txt
│
├── SMB/
│   ├── shares.txt
│   └── users.txt
│
├── AD/
│   ├── domain-users.txt
│   ├── computers.txt
│   └── attack-path.txt
│
└── Findings/
    ├── F-001.md
    ├── F-002.md
    └── F-003.md
```

### Good Evidence Naming

Avoid:

```text
screenshot1.png
final.png
new.png
test.png
```

Prefer:

```text
F-001-SQLi-login-bypass.png
F-002-SMB-anonymous-access.png
F-003-AD-privilege-escalation.png
```

This makes evidence much easier to locate.

---

# 15. Screenshots

Screenshots are useful when they demonstrate:

- Successful exploitation
    
- Sensitive information exposure
    
- Authentication bypass
    
- Privilege escalation
    
- Command execution
    
- Web vulnerabilities
    
- Configuration weaknesses
    
- Access to sensitive resources
    

A screenshot should have enough context to explain what happened.

### Bad Screenshot

A cropped terminal showing only:

```text
root@kali:~#
```

### Better Screenshot

Shows:

```text
Target
Command
Relevant output
Evidence of successful exploitation
```

---

# 16. Executive Summary

The **Executive Summary** is designed primarily for non-technical audiences.

Typical readers may include:

- Management
    
- Executives
    
- CISOs
    
- Security managers
    
- Risk teams
    
- Business owners
    

They may not understand:

```text
Kerberoasting
NTLM relay
LDAP enumeration
SMB signing
SQL injection
SSRF
RCE
```

Therefore, the executive summary should focus on:

- What was tested
    
- Why it was tested
    
- Important findings
    
- Business impact
    
- Overall security observations
    
- High-level remediation direction
    

### Technical Detail vs Executive Detail

Technical:

> The tester obtained a domain user's NTLM credential material through an exposed administrative share and subsequently leveraged the credential to authenticate to additional systems.

Executive:

> An attacker who gained access to the internal network could obtain credentials and use them to access additional corporate systems, increasing the potential impact of a single compromised account.

---

# 17. Executive Summary Rule

Think:

> **What does management need to know?**

Not:

> **What commands did I run?**

The detailed commands belong in the technical findings.

---

# 18. Technical Findings

Technical findings are written for:

- Security engineers
    
- System administrators
    
- Developers
    
- Network administrators
    
- Security operations teams
    

A finding should normally explain:

1. Finding title
    
2. Severity
    
3. Affected system
    
4. Description
    
5. Technical details
    
6. Impact
    
7. Evidence
    
8. Reproduction steps
    
9. Attack path
    
10. Remediation
    
11. References, if applicable
    

---

# 19. Example Finding Structure

```text
Finding ID: F-001

Title:
Weak Password Policy

Severity:
High

Affected Asset:
10.10.10.25

Description:
The system permits weak passwords that can be
successfully guessed using common password lists.

Impact:
An attacker may compromise user accounts and
potentially access internal resources.

Evidence:
[Evidence screenshot]

Steps to Reproduce:
1. Enumerate valid usernames.
2. Identify password policy weaknesses.
3. Attempt authorized password testing.
4. Confirm successful authentication.

Remediation:
Enforce strong password requirements and
implement additional authentication controls.
```

---

# 20. Attack Chains

A major part of penetration testing documentation is showing how individual weaknesses combine into a larger attack.

Instead of documenting findings as completely isolated issues, show the relationship.

Example:

```text
Internet-Facing Service
        ↓
Information Disclosure
        ↓
Valid Username Discovered
        ↓
Weak Password
        ↓
Initial Access
        ↓
Local Enumeration
        ↓
Credential Discovery
        ↓
Privilege Escalation
        ↓
Domain Account
        ↓
Lateral Movement
        ↓
Domain Administrator
```

This demonstrates the **real-world impact** of multiple weaknesses working together.

---

# 21. Attack Path Documentation

For each attack path, record:

### Initial Access

How did the attacker get in?

### Discovery

What did the attacker discover?

### Credential Access

Were credentials or hashes obtained?

### Privilege Escalation

How was additional privilege obtained?

### Lateral Movement

Did access move to another system?

### Objective

What could the attacker ultimately access or control?

---

# 22. Example Attack Path Note

```text
## Attack Path 01

### Initial Access
Target: 10.10.10.20

A vulnerable service exposed externally allowed
the tester to obtain initial access.

### Enumeration
After obtaining access, local enumeration identified
additional services and configuration information.

### Credential Discovery
Credentials were discovered in an exposed configuration file.

### Lateral Movement
The recovered credentials were successfully validated
against another authorized host.

### Privilege Escalation
A local privilege escalation weakness was identified.

### Final Impact
The attack chain resulted in privileged access to
a critical system.
```

---

# 23. Documentation During a CPTS-Style Assessment

For a CPTS-style assessment, documentation should be particularly systematic.

For every target:

```text
Target IP:
Hostname:
OS:
Domain:
Open Ports:
Services:
Versions:
Users:
Credentials:
Shares:
Web Applications:
Vulnerabilities:
Initial Access:
Privilege Escalation:
Lateral Movement:
Evidence:
Final Access:
```

### Example

```text
Host: 10.10.10.50

Hostname:
DC01

OS:
Windows Server

Domain:
CORP.LOCAL

Ports:
53
88
135
139
389
445
464
636
3268

Services:
DNS
Kerberos
LDAP
SMB
RPC

Notes:
- Domain Controller identified
- LDAP available
- SMB available
- Domain enumeration performed

Credentials:
[Store securely]

Findings:
F-001
F-002

Evidence:
Evidence/AD/DC01/
```

---

# 24. Obsidian for Penetration Testing

Obsidian can be useful because penetration testing involves many interconnected pieces of information.

A structured notebook can contain:

```text
Pentest
│
├── Overview
│
├── Scope
│
├── Rules of Engagement
│
├── Targets
│
├── Enumeration
│
├── Credentials
│
├── Findings
│
├── Attack Paths
│
├── Evidence
│
├── Research
│
├── Reporting
│
└── Retest
```

![Image](https://images.openai.com/static-rsc-4/iBCalZF0QgHG8HIBQECj9s9MO75WccCRlV5WBeUBtm5Wmzmen8FnB9JgPHDTP8PDIYczTFPY2FskprXpB5xQYvNkrhiQd1SDuV9R3GJusdj41CLG_GqFKCKhs2SXKKJUP30VM-PAtYz-OxpToYRjF4-E5_vzyl7pMRo8U-M0QQuun1i2kiiyal5P83aXhF7Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yohxRO0dIgGpUVtOqtSUmqqKniXod61bl_Z7SDaduCR2kRyULppL-TAOJ6T8zBWRlLee6uEUcPQfXV3Li9JHIHnrHIW9RqslzyKaDYZHT99lMl5xy6akkO_1Gu8kSqFiQEfg-uODeLsfkBV7FZxTS8CfnDz4rx3CqV11cwDaJKpvIVM9yUANyk9iUTyRDocu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/U6rHbnrtT1reL-5OiiLNyshDgw9jKlFj1YMqGip3hY6wmIl_NzVVBuqgYtne2bCGGK_LLkjmA-oElEjVivmW-6KmvnyTQwOpLTMFDbqTY-vVyouVY696Qx3n32u1ppBFXHXVJ4VOlqe9ECAi46p5mJCbwr_H9phpwlpuX9cl0zfIWdKmik1o-A-3KF3MqMlF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PtTny97JNZo5TllGmPeX6ogdks8OmQLF4FKRHF_wMfqlIOZcSrsbohaF2KL-xbZDDjgmRaj4a9tcj3y5KwFaFQyeo_Sbq7xMfGb8UGyv4g0a07O6TrM8Sgl1fRdpxAGV60DIV89tePPKAV5rKwEE6ClQgsNMyLtgRYAOj2C3da361xG1KCJc-zyqOonc90-S?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/93rn-_p65V1XFH_tpyqWxxNtDsKzOlxZJGkrinbe5qZgvNiABWYJOYES2ENKltMzzXJ_OU05BzLCczs1ZfI-9CfJMpIN3T7w9Z5rIlmT_8C0GUjGpeGG-LpCa43sU9KspPYMODrOW47Ft8PLnBVu5trN8aVB4UtsOosfWUhvu8tUw404Qjiq563yNJea9RzU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dgXsh1vOub0ekby0s2StdM-EICq3FDAa37LsKNF_OKNxl4a737ZNg6NTYvikklFy8L2MT8PglkP8p1yQkix2s3xEtaZMknJGJYpbuiT4nhWZv0ERoMqqLrW3sQEPYCsXYUc0WA7xpRDxE-8_NScsHB0pqGLsWhDpmEc_AWfuGWYJ8trIeJ6fhpCva62jLQ0f?purpose=fullsize)

The goal is not to make the notebook look fancy.

The goal is:

> **Fast documentation + easy retrieval + reproducibility.**

---

# 25. Useful Note Categories

## Overview

Contains:

- Engagement name
    
- Client
    
- Dates
    
- Testers
    
- Scope
    
- Source IPs
    
- Testing methodology
    
- Special considerations
    

## Scope

Contains:

- In-scope IPs
    
- Domains
    
- Applications
    
- Networks
    
- Excluded systems
    
- Excluded techniques
    

## Enumeration

Contains:

- Nmap
    
- DNS
    
- SMB
    
- LDAP
    
- HTTP
    
- FTP
    
- SSH
    
- SMTP
    
- Other services
    

## Credentials

Contains:

- Usernames
    
- Passwords
    
- Hashes
    
- Tokens
    
- Keys
    

**Important:** Credentials must be handled according to the engagement's security requirements and stored securely.

## Findings

Each finding gets its own entry.

## Attack Paths

Documents how separate findings combine.

## Evidence

Stores screenshots, logs and output.

## Retest

Records whether vulnerabilities were successfully fixed.

---

# 26. Reporting Structure

A typical penetration test report can contain:

```text
1. Cover Page
2. Confidentiality Statement
3. Executive Summary
4. Assessment Overview
5. Scope
6. Rules of Engagement
7. Methodology
8. Testing Timeline
9. Findings Summary
10. Detailed Findings
11. Attack Chains
12. Remediation Recommendations
13. Conclusion
14. Retest Results
15. Appendices
```

A strong report generally serves **two audiences**:

### Management

Needs:

- Risk
    
- Business impact
    
- Important findings
    
- High-level recommendations
    

### Technical Team

Needs:

- Technical details
    
- Evidence
    
- Reproduction steps
    
- Affected assets
    
- Remediation instructions
    

---

# 27. Report Finding Severity

Findings are commonly categorized by severity.

Example:

```text
Critical
High
Medium
Low
Informational
```

Severity should be based on the methodology used by the engagement.

For example, a report may use CVSS or another documented risk model.

Do not assign severity randomly.

Consider:

- Exploitability
    
- Impact
    
- Required privileges
    
- Required user interaction
    
- Exposure
    
- Business context
    
- Existing mitigating controls
    

---

# 28. Remediation

A good finding should not simply say:

> "Fix this vulnerability."

It should provide useful remediation guidance.

### Weak Recommendation

> Update the server.

### Better Recommendation

> Upgrade the affected service to a supported version, disable the vulnerable configuration, restrict unnecessary network exposure, and validate the change through a follow-up security assessment.

The recommendation should be:

- Specific
    
- Actionable
    
- Relevant
    
- Technically realistic
    

---

# 29. Documentation Quality Checklist

Before completing an engagement, ask:

### Scope

-  Did I document all in-scope assets?
    
-  Did I document exclusions?
    
-  Did I record testing dates?
    
-  Did I record source IP addresses?
    
-  Did I document special access such as VPN?
    

### Testing

-  Did I document important commands?
    
-  Did I save relevant output?
    
-  Did I record timestamps?
    
-  Did I capture screenshots?
    
-  Did I document attack paths?
    
-  Did I record credentials securely?
    

### Findings

-  Does every finding have evidence?
    
-  Can the finding be reproduced?
    
-  Is the affected asset identified?
    
-  Is the impact explained?
    
-  Is remediation provided?
    
-  Is severity justified?
    

### Reporting

-  Is the executive summary understandable?
    
-  Are technical findings detailed?
    
-  Are screenshots readable?
    
-  Are findings consistently formatted?
    
-  Did I remove unnecessary sensitive information?
    
-  Did someone perform QA/review?
    

---

# 30. Important Lessons From the Module

## Lesson 1 — Document Everything Important

Don't depend on memory.

---

## Lesson 2 — Preserve Evidence

Logs, screenshots and raw outputs can protect the tester and help the client troubleshoot problems.

---

## Lesson 3 — Back Up Your Work

A destroyed VM should not mean a destroyed engagement.

---

## Lesson 4 — Clearly Define Scope

Always know:

```text
IN SCOPE
---------
10.10.10.0/24

OUT OF SCOPE
------------
10.10.20.0/24
Production DB
VoIP infrastructure
```

---

## Lesson 5 — Ask for Explicit Exclusions

Even if a system technically falls inside a provided range, ask whether there are individual hosts or systems that must not be touched.

---

## Lesson 6 — Record Testing Windows

A penetration test is a **snapshot in time**.

---

## Lesson 7 — Separate Technical and Business Communication

Management needs:

> Risk + Impact + Recommendation

Technical teams need:

> Evidence + Reproduction + Technical Details + Remediation

---

## Lesson 8 — Document Findings During Testing

Do not wait until the end of the engagement.

---

## Lesson 9 — Attack Chains Matter

A collection of medium-severity weaknesses can sometimes create a much more meaningful attack path when combined.

Document the chain.

---

## Lesson 10 — Reporting Is Part of the Technical Work

Reporting is not just administrative work.

A penetration test without good documentation can lose much of its practical value.

---

# 31. CPTS Exam / Practical Assessment Mindset

When performing a practical assessment, think like this:

```text
ENUMERATE
    ↓
OBSERVE
    ↓
VALIDATE
    ↓
EXPLOIT
    ↓
DOCUMENT
    ↓
COLLECT EVIDENCE
    ↓
UNDERSTAND IMPACT
    ↓
CONTINUE ATTACK PATH
    ↓
DOCUMENT AGAIN
```

Do not wait until the end to remember what happened.

### Golden Rule

> **If you found it, document it.**
> 
> **If you exploited it, prove it.**
> 
> **If it matters, screenshot it.**
> 
> **If you changed something, record it.**
> 
> **If you accessed something sensitive, document exactly how and why.**

---

# 32. Quick Revision Sheet

### Documentation

**Purpose:** Preserve an accurate record of testing.

### Reporting

**Purpose:** Communicate findings and risk to technical and non-technical audiences.

### Evidence

**Purpose:** Prove what happened.

### Scope

**Purpose:** Define what can and cannot be tested.

### Testing Window

**Purpose:** Establish the period represented by the report.

### Executive Summary

**Audience:** Management / non-technical stakeholders.

### Technical Findings

**Audience:** Engineers / security professionals.

### Attack Chain

**Purpose:** Demonstrate how individual weaknesses can combine into a larger compromise.

### Backup

**Purpose:** Prevent loss of testing evidence.

### Retest

**Purpose:** Validate whether remediation actually addressed the finding.

---

# 33. One-Page Mental Model

```text
                 PENETRATION TEST
                        │
          ┌─────────────┴─────────────┐
          │                           │
       TESTING                  DOCUMENTATION
          │                           │
     Enumeration                  Notes
          │                       Logs
     Exploitation               Screenshots
          │                       Evidence
    Priv Esc / AD                  Scope
          │                       Timeline
    Lateral Movement             Commands
          │                           │
          └─────────────┬─────────────┘
                        │
                  FINDINGS
                        │
                  ATTACK CHAINS
                        │
                EXECUTIVE SUMMARY
                        │
                TECHNICAL REPORT
                        │
                  REMEDIATION
                        │
                     RETEST
```

# Final Takeaway

The core lesson of this module is simple:

> **A penetration tester's job is not only to compromise systems. It is to create an accurate, reproducible, evidence-backed record of what was tested, what was discovered, what was exploited, what impact it had, and how the client can fix it.**

Strong documentation protects the **tester**, helps the **client**, improves the **quality of the final report**, and makes the entire penetration testing process more professional and repeatable.

The visual examples above are illustrative; the notes themselves are based on the module text you provided. The report structure is also consistent with common pentest-report guidance emphasizing scope, methodology, evidence, findings, remediation, and retesting. ([trailhead.salesforce.com](https://trailhead.salesforce.com/content/learn/modules/responsibilities-of-a-penetration-tester/report-penetration-test-findings?utm_source=chatgpt.com "Comprehensive Guide to Penetration Test Reporting"))