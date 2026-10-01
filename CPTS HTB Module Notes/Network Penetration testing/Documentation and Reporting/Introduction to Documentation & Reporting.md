
![Image](https://images.openai.com/static-rsc-4/SFDqeBUR2oHkMD4Fbu0mpF_Cjq_x03DhgBNjN5VEbyz6vQsejGB8NkL685mmOn2EnxwZjjwDJsvJWRmkpKX9rS5dbycFeXTyHPGNT4Je2ShxLIr6BfrD1E1d3kFb7hZgheQrebO1NlVH-mrcndF21f9Dvpd7u1z5hF7vGCGCCMDqAQoTrpJO5bKoN6ahaCsT?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/G_FUampzUyIJ3OZ7yqROfsYyPyNZ6EdGhPEHCyjIlEDELgPITRFo-tiGwx3TehqjBNuZ4qkaIlZl4-ia2JbbUqRdN1zz2b1lFKukXZUXMfXQQttbJ5YEjyhocK9INmiOtoRRDeFTgSY4tQNKfiCEMLEGw8SPIRA_EIibDR0t2db5IA_0CWefYnOd3njYKC-F?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iBCalZF0QgHG8HIBQECj9s9MO75WccCRlV5WBeUBtm5Wmzmen8FnB9JgPHDTP8PDIYczTFPY2FskprXpB5xQYvNkrhiQd1SDuV9R3GJusdj41CLG_GqFKCKhs2SXKKJUP30VM-PAtYz-OxpToYRjF4-E5_vzyl7pMRo8U-M0QQuun1i2kiiyal5P83aXhF7Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_JFTzQ3uf4ab0sOPwjwmnHZIxTSJ6uVzFpo6xPQEqRw39ijmKXW4AhEOBngfALakCKphqpPmofn8pOGDUhUw5fDr-QSByrd6dRALTnVOiNZnejQAEMZnRjLHEg7IfrxSUXwCJlW43_o2WZRvd_MH3URk1fWMFwWcDHT0YQK0cKrRnfkT4j_K9iAi1luQDJFb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dXIUFMVi0NNlc9Vr-CDm2Vdy62eLZl9Poz5xS_8MgfTgsfg4pZUKtQqY-9MS6Wwet4vgbeOK-tl0VuUbRC4hQMBaQ2EiXl7FNim8TbS5_Ve1CrjXgCSeXpGzAw_KXDL8vSzOYHLbGir_Pm-RGHR2gEzuUF6mYAyGbwQU8mPjQpMY1DbQXlFGmnAYu_qrz5m5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yohxRO0dIgGpUVtOqtSUmqqKniXod61bl_Z7SDaduCR2kRyULppL-TAOJ6T8zBWRlLee6uEUcPQfXV3Li9JHIHnrHIW9RqslzyKaDYZHT99lMl5xy6akkO_1Gu8kSqFiQEfg-uODeLsfkBV7FZxTS8CfnDz4rx3CqV11cwDaJKpvIVM9yUANyk9iUTyRDocu?purpose=fullsize)

# 

## 1. Introduction

Strong **documentation and reporting skills** are incredibly beneficial in any area of Information Technology or Information Security.

Being highly technical is essential, but technical skills alone are not enough. A penetration tester must also be able to clearly communicate:

- What was tested
    
- What was discovered
    
- What was exploited
    
- How it was exploited
    
- What evidence was obtained
    
- What impact the vulnerability has
    
- How the client can remediate it
    

Without good documentation, even technically impressive work can become difficult to communicate, reproduce, or defend.

### Core Concept

> **Technical skills get you the result; documentation allows you to prove, explain, reproduce, and report that result.**

---

# 2. Why Documentation Is Important

The **Notetaking & Organization** module establishes that thorough notes are critical during an assessment because notes, tool output, and logs become the raw inputs for the draft report.

Documentation is important because:

- It saves time during report writing.
    
- It preserves evidence.
    
- It allows findings to be reproduced.
    
- It helps answer client questions.
    
- It helps correlate security events.
    
- It allows another tester to understand what was performed.
    
- It protects the tester when questions arise about testing activity.
    
- It prevents having to repeat work.
    
- It provides continuity if the original tester becomes unavailable.
    

### Important

> **Being overly verbose in your notetaking never hurts.**

Detailed notes are especially useful when someone asks:

> "Did you scan X host on Y day?"

Your notes should allow you to answer that accurately.

---

# 3. Documentation Is a Process, Not Just a Report

Documentation should begin **before testing starts** and continue throughout the entire engagement.

A useful mental model is:

```text
SCOPE
  ↓
PLAN
  ↓
TEST
  ↓
DOCUMENT
  ↓
COLLECT EVIDENCE
  ↓
IDENTIFY FINDINGS
  ↓
BUILD ATTACK CHAINS
  ↓
WRITE REPORT
  ↓
QA
  ↓
DELIVER
  ↓
RETEST
```

The report is therefore the final product of a much larger documentation process.

---

# 4. There Is No "One Size Fits All"

There is no universal note-taking structure.

The structure should be adapted according to:

- Tester preference
    
- Assessment type
    
- Project requirements
    
- Client requirements
    
- Team workflow
    
- Type of testing
    
- Available tools
    

For example, an application-focused assessment may require additional web application categories while having less emphasis on Active Directory.

An internal penetration test may require extensive:

- AD Enumeration
    
- Service Enumeration
    
- Credentials
    
- Attack Path documentation
    

An external penetration test may place more emphasis on:

- OSINT
    
- External services
    
- Web applications
    
- Attack paths from Internet-facing systems
    

The important thing is:

> **Have a consistent structure that you can reproduce from engagement to engagement.**

---

# 5. Recommended Documentation Structure

The Notetaking & Organization module provides a useful baseline structure.

```text
Notes/
│
├── 1. Administrative Information
├── 2. Scoping Information
├── 3. Activity Log
├── 4. Payload Log
├── 5. OSINT Data
├── 6. Credentials
├── 7. Web Application Research
├── 8. Vulnerability Scan Research
├── 9. Service Enumeration Research
├── 10. AD Enumeration Research
├── 11. Attack Path
└── 12. Findings
```

This structure is extremely useful because each section has a specific purpose.

---

# 6. Administrative Information

The Administrative Information section can contain:

- Project stakeholders
    
- Project Manager
    
- Client Points of Contact (POCs)
    
- Rules of Engagement information
    
- Unique project objectives
    
- Flags/objectives
    
- Project-specific information
    
- Running to-do list
    

Example:

```text
## Administrative Information

Project:
ACME Internal Penetration Test

PM:
[Name]

Client POC:
[Name]

Testing Dates:
[Start Date] - [End Date]

Tester:
[Name]

Objectives:
- Identify exploitable vulnerabilities
- Assess internal attack paths
- Determine potential impact

To-Do:
- [ ] Enumerate remaining web services
- [ ] Review AD attack paths
- [ ] Validate Finding H3
```

---

# 7. Scoping Information

This is one of the most important sections.

It should contain:

- In-scope IP addresses
    
- CIDR ranges
    
- Web application URLs
    
- VPN information
    
- AD information
    
- Client-provided credentials
    
- Explicit exclusions
    
- Other scope-specific information
    

Example:

```text
## In Scope

10.10.10.0/24
10.10.20.15
https://portal.example.com

## Out of Scope

10.10.50.0/24
Production Database
VoIP Infrastructure

## Provided Credentials

Username:
[REDACTED]

Password:
[REDACTED]
```

### Why This Matters

Scope documentation prevents accidental testing of systems that should not be touched.

It also provides evidence of what the client authorized.

---

# 8. Activity Log

The **Activity Log** provides high-level tracking of everything performed during the assessment.

Example:

```text
| Time | Activity | Target | Result |
|------|----------|--------|--------|
| 09:10 | Nmap scan | 10.10.10.20 | 22,80,443 |
| 09:35 | SMB enumeration | 10.10.10.20 | Shares found |
| 10:20 | Web enumeration | 10.10.10.20 | Login portal |
| 11:15 | Credential testing | Web Portal | Valid login |
```

This becomes particularly valuable when:

- A client asks what happened.
    
- A network issue occurs.
    
- Security logs need correlation.
    
- A finding needs a timestamp.
    
- Another tester needs to continue the engagement.
    

---

# 9. Payload Log

A payload log records payloads used during testing.

Track:

- Payload
    
- Target host
    
- Upload location
    
- Timestamp
    
- File hash
    
- Whether the payload was removed
    

The Notetaking module specifically recommends tracking when a payload was used, what host it was used against, where it was placed, and whether it was cleaned up. A file hash is also recommended.

Example:

```text
## Payload Log

Payload:
payload.exe

Target:
10.10.10.25

Path:
/tmp/payload.exe

SHA256:
[HASH]

Uploaded:
2026-10-01 02:15

Cleanup:
Removed
```

---

# 10. Credentials

Maintain a centralized location for compromised credentials and secrets.

The Notetaking module explicitly recommends a dedicated **Credentials** section.

Example:

```text
## Credentials

Username:
administrator

Password:
[REDACTED]

Source:
SMB share

Host:
10.10.10.25

Status:
Validated

Notes:
Credential successfully authenticated to authorized host.
```

### Security Rule

Credentials should be stored securely and redacted appropriately in reports.

Never unnecessarily expose:

- Passwords
    
- Password hashes
    
- API keys
    
- Tokens
    
- Private keys
    
- Sensitive secrets
    

---

# 11. Findings

Each finding should have its own dedicated location.

The Notetaking module recommends creating a **subfolder for each finding** and storing the narrative and evidence together.

Example:

```text
Evidence/
└── Findings/
    ├── H1 - Kerberoasting/
    │   ├── Finding.md
    │   ├── screenshot.png
    │   └── output.txt
    │
    ├── H2 - ASREPRoasting/
    │   ├── Finding.md
    │   └── evidence.txt
    │
    └── H3 - LLMNR-NBT-NS/
        ├── Finding.md
        └── screenshot.png
```

This makes report creation significantly easier.

---

# 12. Vulnerability Scan Research

Keep notes about:

- Vulnerabilities discovered
    
- Vulnerability scanner results
    
- Research performed
    
- Validation attempts
    
- Exploitation attempts
    
- False positives
    
- Failed exploitation
    

The purpose is to avoid repeating work.

Example:

```text
## Vulnerability Research

Target:
10.10.10.25

Finding:
CVE-XXXX-XXXX

Scanner:
[Scanner]

Initial Result:
Potential vulnerability detected.

Validation:
Attempted manual validation.

Result:
Confirmed / False Positive

Notes:
[Technical notes]
```

---

# 13. Service Enumeration Research

Maintain a dedicated section for services investigated.

Record:

- Service
    
- Port
    
- Version
    
- Enumeration performed
    
- Vulnerabilities
    
- Misconfigurations
    
- Exploitation attempts
    
- Failed attempts
    
- Interesting observations
    

Example:

```text
## Service Enumeration

Host:
10.10.10.25

Port:
445

Service:
SMB

Version:
[Version]

Enumeration:
- Shares
- Users
- SMB signing
- Authentication

Interesting:
Anonymous access detected.

Next Step:
Enumerate accessible shares.
```

The module specifically recommends recording both **promising vulnerabilities and failed exploitation attempts**.

---

# 14. Web Application Research

Keep track of interesting web applications discovered during testing.

Useful information includes:

- URLs
    
- Subdomains
    
- Ports
    
- Technologies
    
- Login portals
    
- Interesting endpoints
    
- Authentication mechanisms
    
- Default credentials attempted
    
- Vulnerabilities
    
- Screenshots
    

Tools mentioned in the source include:

- Aquatone
    
- EyeWitness
    

The module recommends using tools such as these to screenshot applications and then reviewing the results for applications of interest.

Example:

```text
## Web Application

URL:
https://portal.example.com

Technology:
Apache
PHP

Interesting:
Login portal

Authentication:
Username/password

Testing:
- Default credentials
- Authentication bypass
- Directory enumeration
- Input validation

Evidence:
Evidence/Web/portal/
```

---

# 15. Active Directory Enumeration Research

For an internal assessment, maintain a dedicated AD research section.

Document:

- Domain
    
- Domain controllers
    
- Users
    
- Groups
    
- Computers
    
- Shares
    
- Trust relationships
    
- SPNs
    
- Delegation
    
- ACLs
    
- Interesting accounts
    
- Attack paths
    

The module recommends documenting AD enumeration **step-by-step** and noting areas of interest that need further investigation.

Example:

```text
## AD Enumeration

Domain:
INLANEFREIGHT.LOCAL

DC:
DC01

Users:
- Administrator
- User01
- Service01

Interesting:
Service account has SPN.

Next:
Investigate Kerberos attack opportunities.
```

---

# 16. OSINT

The OSINT section contains interesting information collected through open-source intelligence.

Possible information:

- Domains
    
- Subdomains
    
- Public email addresses
    
- Publicly exposed information
    
- Technology information
    
- Organizational information
    
- Public documents
    

The module recommends maintaining an OSINT section when applicable.

---

# 17. Attack Path

The **Attack Path** is one of the most important documentation sections.

It should show the complete path taken after obtaining an initial foothold.

For an external penetration test:

```text
Internet
   ↓
Public Service
   ↓
Initial Foothold
   ↓
Credential Discovery
   ↓
Privilege Escalation
   ↓
Lateral Movement
   ↓
Critical System
```

For an internal penetration test:

```text
Internal Network
      ↓
Initial Host
      ↓
Credential Discovery
      ↓
Lateral Movement
      ↓
Domain User
      ↓
Privilege Escalation
      ↓
Domain Admin
```

The module recommends outlining the entire path and using screenshots and command output as closely as possible because this makes it easier to transfer the information into the final report.

---

# 18. Introduction to Reporting

Good notes are the foundation of a good report.

The reporting process can be viewed as:

```text
Testing
   ↓
Notes
   +
Tool Output
   +
Logs
   +
Screenshots
   ↓
Evidence
   ↓
Findings
   ↓
Attack Chains
   ↓
Report
```

If documentation is poor, report writing becomes much harder.

---

# 19. A Penetration Test Is a Snapshot in Time

A penetration test represents the security state of the target environment during a specific testing period.

For example:

> **"All testing activities were performed between January 7, 2022 and January 19, 2022."**

Changes made outside this period may not be represented in the report.

A report may therefore include a disclaimer such as:

> **"This report represents a snapshot in time during the aforementioned testing period, and Acme Consulting, LLC cannot attest to the state of any client-owned information assets outside of this testing window."**

### Important Information to Document

- Testing dates
    
- Tester(s)
    
- Type of assessment
    
- Source IP addresses
    
- Testing location
    
- VPN usage
    
- Internal/external position
    
- Scope
    
- Special considerations
    
- Limitations
    

---

# 20. Why Testing Evidence Matters

The client ultimately needs a report that clearly communicates:

- What vulnerabilities were discovered
    
- Where they exist
    
- How they were validated
    
- What evidence proves them
    
- How they can be reproduced
    
- How they should be fixed
    

The Notetaking module emphasizes that clients generally need clear issues and evidence that internal security teams, administrators, and developers can use for validation and reproduction.

---

# 21. Evidence

Every important finding should have evidence.

Evidence can include:

- Terminal output
    
- Screenshots
    
- Logs
    
- Tool output
    
- HTTP requests/responses
    
- Configuration information
    
- File listings
    
- Authentication results
    
- Proof of access
    

### Important

> **Evidence should prove the finding without unnecessarily exposing sensitive information.**

---

# 22. What to Capture

The source recommends collecting evidence not only for successful findings but potentially for unsuccessful tests as well.

Why?

If the client asks:

> "What testing did you perform?"

You can demonstrate the testing that was conducted.

Terminal logs may provide evidence, but they may not always be formatted cleanly for reports.

Therefore:

- Use logs for raw evidence.
    
- Capture significant terminal output separately.
    
- Use screenshots where appropriate.
    
- Keep evidence organized alongside findings.
    

---

# 23. Evidence Storage

A recommended baseline structure is:

```text
ACME-IPT/
│
├── Admin/
│
├── Deliverables/
│
├── Evidence/
│   ├── Findings/
│   ├── Scans/
│   │   ├── Vuln/
│   │   ├── Service/
│   │   ├── Web/
│   │   └── AD Enumeration/
│   │
│   ├── Notes/
│   ├── OSINT/
│   ├── Wireless/
│   ├── Logging output/
│   └── Misc Files/
│
└── Retest/
```

This structure is directly based on the module's suggested assessment storage organization.

---

# 24. Meaning of Each Folder

### Admin

Contains:

- Scope of Work
    
- Kickoff notes
    
- Status reports
    
- Vulnerability notifications
    

### Deliverables

Contains:

- Draft reports
    
- Final reports
    
- Supplemental spreadsheets
    
- Slide decks
    

### Evidence/Findings

One folder per finding.

### Evidence/Scans/Vuln

Vulnerability scanner exports.

### Evidence/Scans/Service

Service enumeration output such as Nmap or Masscan.

### Evidence/Scans/Web

Web testing output such as:

- Burp
    
- ZAP
    
- EyeWitness
    
- Aquatone
    

### Evidence/Scans/AD Enumeration

Examples:

- BloodHound JSON
    
- PowerView CSV
    
- ADRecon output
    
- PingCastle data
    
- Snaffler logs
    
- Impacket output
    

### Evidence/Notes

Your assessment notes.

### Evidence/OSINT

OSINT tool output.

### Evidence/Wireless

Wireless testing evidence, if applicable.

### Evidence/Logging output

- Tmux logs
    
- Metasploit logs
    
- Other raw logs
    

### Evidence/Misc Files

Contains relevant:

- Payloads
    
- Web shells
    
- Scripts
    
- Generated files
    

### Retest

Separate location for evidence collected during remediation/retesting.

---

# 25. Logging

Logging is essential.

The module states that all scanning and attack attempts should be logged and raw tool output should be preserved wherever possible.

Logging provides:

- Historical records
    
- Evidence
    
- Event correlation
    
- Reproduction information
    
- Report material
    

---

# 26. Tmux Logging

**Tmux logging** can automatically record terminal activity.

The module recommends Tmux with the `tmux-logging` plugin because it can save commands typed into a Tmux pane to a log file.

### Basic Setup From the Module

Clone TPM:

```bash
git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

Create configuration:

```bash
touch .tmux.conf
```

Configuration:

```bash
# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Initialize TMUX plugin manager
run '~/.tmux/plugins/tpm/tpm'
```

Reload:

```bash
tmux source ~/.tmux.conf
```

---

# 27. Tmux Logging Shortcuts

### Start/Stop Logging

```text
Ctrl+B
Shift+P
```

### Install Plugins

```text
Ctrl+B
Shift+I
```

### Retroactive Logging

If logging was not enabled:

```text
Ctrl+B
Alt+Shift+P
```

This can save the existing pane history.

However, the amount saved depends on the Tmux `history-limit`.

---

# 28. Increase Tmux History

The module recommends increasing the history limit:

```bash
set -g history-limit 50000
```

This helps preserve more terminal history if retroactive logging becomes necessary.

---

# 29. Tmux Pane Capture

When using multiple Tmux panes, copying output can become messy because output from multiple panes may be captured.

A pane capture can solve this.

Shortcut:

```text
Ctrl+B
Alt+P
```

This captures the relevant pane cleanly.

---

# 30. Tmux Pane Management

Create a session:

```bash
tmux new -s sessionname
```

Vertical split:

```text
Ctrl+B
Shift+%
```

Horizontal split:

```text
Ctrl+B
"
```

Move between panes:

```text
Ctrl+B
O
```

Clear pane history:

```text
Ctrl+B
Alt+C
```

---

# 31. Other Useful Tmux Plugins

The module mentions:

### tmux-sessionist

Helps manage Tmux sessions.

### tmux-pain-control

Provides improved pane controls.

### tmux-resurrect

Can restore:

- Sessions
    
- Windows
    
- Panes
    
- Pane order
    
- Running programs
    
- Vim sessions
    

---

# 32. Artifacts Left Behind

During penetration testing, testers may leave artifacts on client systems.

Examples:

- Payloads
    
- Web shells
    
- Tools
    
- Scripts
    
- Created accounts
    
- Configuration changes
    

These must be tracked.

At minimum record:

```text
When?
Where?
What?
Path?
Hash?
Cleaned?
```

Example:

```text
Payload:
shell.exe

Host:
10.10.10.25

Path:
/tmp/shell.exe

Hash:
SHA256: [HASH]

Timestamp:
2026-10-01 02:15

Cleanup:
Deleted
```

---

# 33. Account Creation & System Modifications

If you create accounts or modify systems, record:

- IP address
    
- Hostname
    
- Timestamp
    
- Description
    
- Location of change
    
- Application/service modified
    
- Account created
    
- Password, if required by the engagement process
    

The module emphasizes obtaining **written approval** before making these types of system modifications or performing testing that could affect stability or availability.

### Golden Rule

> **Never make potentially disruptive changes without appropriate authorization.**

---

# 34. Formatting and Redaction

Sensitive information must be properly redacted.

Especially:

- Credentials
    
- Passwords
    
- Password hashes
    
- PII
    
- Sensitive information
    

The module specifically recommends redacting credentials and PII from screenshots.

---

# 35. Screenshot Best Practices

Good screenshots should:

- Show only relevant information.
    
- Be cropped where appropriate.
    
- Clearly show the target/URL when useful.
    
- Highlight important information.
    
- Avoid unnecessary clutter.
    
- Remove sensitive information.
    

Possible enhancements include:

- Arrows
    
- Boxes
    
- Borders
    
- Cropping
    

However, annotations should preserve the authenticity of the evidence.

---

# 36. Terminal Output vs Screenshots

Whenever possible:

> **Prefer terminal output over screenshots of terminal sessions.**

Why?

Text-based evidence is:

- Easier to redact.
    
- Easier to highlight.
    
- Easier to format.
    
- Easier for clients to copy/paste.
    
- Smaller than screenshots.
    
- Easier to reproduce.
    

The module recommends preserving the exact command and output while allowing irrelevant output to be shortened with `<SNIP>`.

Example:

```text
$ nmap -sV 10.10.10.25

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.x
80/tcp  open  http    Apache

<SNIP>
```

### Important Rule

Never modify the actual command or output.

You may remove irrelevant portions and mark them:

```text
<SNIP>
```

But do not fabricate or alter evidence.

---

# 37. Redacting Passwords

Do **not** rely on simple blur/pixelation for sensitive information.

The module specifically warns that blurred or pixelated information can potentially be recovered.

Prefer:

```text
<PASSWORD REDACTED>
```

or a solid black bar directly applied to the image.

For hashes, an appropriate representation can retain a small portion to demonstrate that a hash existed while removing sensitive material.

Example:

```text
aad3b435...<REDACTED>...35b51404
```

---

# 38. Terminal Evidence Presentation

A good evidence block should preserve:

1. The original command.
    
2. The relevant output.
    
3. The important result.
    
4. Appropriate redaction.
    

You can highlight:

```text
COMMAND
   ↓
$ crackmapexec smb 10.10.10.25 -u user -p '<REDACTED>'

OUTPUT
   ↓
SMB 10.10.10.25 445 DC01
[+] INLANEFREIGHT\user:<REDACTED>
```

The module recommends highlighting the command and important output so readers can quickly understand what occurred.

---

# 39. What NOT to Archive

A penetration tester is trusted to:

> **"do no harm" wherever possible.**

Avoid unnecessarily:

- Bringing down hosts
    
- Affecting application availability
    
- Changing passwords without authorization
    
- Making difficult-to-reverse configuration changes
    
- Extracting sensitive information unnecessarily
    
- Collecting unnecessary PII
    
- Opening sensitive files when directory-level evidence is sufficient
    

The module specifically warns about handling potentially sensitive or legally discoverable information.

---

# 40. Example: Sensitive Network Share

Suppose you discover:

```text
\\server\share\

Financial/
Employees/
Payroll/
Credentials/
```

Do not automatically open every file.

A safer evidence approach may be:

```text
Screenshot:
Directory listing showing sensitive filenames
```

rather than:

```text
Opening and copying the contents of every sensitive document.
```

### Principle

> **Collect only what is necessary to prove the finding.**

---

# 41. Reporting Structure

A professional penetration test report may contain:

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
12. Recommendations
13. Conclusion
14. Retest Results
15. Appendices
```

---

# 42. Executive Summary

The Executive Summary is written primarily for non-technical readers.

Possible audience:

- Executives
    
- Management
    
- Business owners
    
- CISOs
    
- Risk teams
    

Do not overload it with commands.

Instead explain:

- What was tested
    
- Major security issues
    
- Overall impact
    
- Important risks
    
- High-level remediation direction
    

### Example

Technical:

> The tester obtained an NTLM hash through an SMB-based attack path and leveraged the resulting credential material for authenticated access.

Executive:

> The assessment demonstrated that an attacker with internal network access could obtain credentials and use them to access additional systems.

---

# 43. Technical Findings

Technical findings are written for:

- Security engineers
    
- System administrators
    
- Developers
    
- Network administrators
    

A finding should contain enough information to understand and reproduce the issue.

Suggested structure:

```text
Finding ID:
F-001

Title:
[Finding]

Severity:
[Severity]

Affected Asset:
[Host/IP]

Description:
[What is wrong]

Technical Details:
[How it works]

Evidence:
[Proof]

Impact:
[What could happen]

Reproduction:
[Steps]

Remediation:
[How to fix]

References:
[If applicable]
```

---

# 44. Finding vs Attack Chain

These are not exactly the same thing.

### Finding

A specific vulnerability or security weakness.

Example:

```text
Weak Credentials
```

### Attack Chain

A sequence showing how multiple weaknesses can be combined.

Example:

```text
Weak Credentials
       ↓
Initial Access
       ↓
Local Enumeration
       ↓
Credential Discovery
       ↓
Lateral Movement
       ↓
Privilege Escalation
       ↓
Domain Compromise
```

Both should be documented.

---

# 45. Attack Chain Documentation

When you gain a foothold, document the path immediately.

Example:

```text
## Attack Path

Initial Access
      ↓
10.10.10.25
      ↓
Credential Discovery
      ↓
Valid Domain Credentials
      ↓
SMB Access
      ↓
Lateral Movement
      ↓
DC01
      ↓
Privilege Escalation
      ↓
Domain Administrator
```

Add:

- Commands
    
- Screenshots
    
- Timestamps
    
- Evidence
    
- Findings involved
    

This makes the final report much easier to create.

---

# 46. How Documentation Protects the Tester

Consider a client claiming:

> "Your scan caused our server to crash."

Your documentation should allow you to answer:

```text
What did you scan?
        ↓
Which IP?
        ↓
When?
        ↓
Which tool?
        ↓
Which options?
        ↓
What output?
        ↓
Was the host in scope?
        ↓
What happened afterward?
```

Without documentation, this becomes difficult.

With documentation, you have an evidence trail.

---

# 47. Three Important Scenarios

## Scenario 1 — The Case of an Exploding VM

### Problem

Testing VM becomes unusable and the filesystem is lost.

### Solution

Detailed notes and backed-up evidence were available.

### Result

A new VM could be created and project data restored.

### Lesson

> **Back up your testing evidence.**

---

## Scenario 2 — Ping of Death

### Problem

Critical servers appeared to be affected during testing.

### Investigation

The tester produced:

- Scope files
    
- Logs
    
- Timestamped scan data
    
- Raw scan output
    

The affected systems were within the confirmed scope.

### Lesson

> **Keep written scope confirmation and raw testing evidence.**

### Process Improvement

Ask clients for explicit exclusions such as:

- Individual IP addresses
    
- Hostnames
    
- Critical systems
    

---

## Scenario 3 — Slow as Molasses

### Problem

A network administrator claimed scans had caused severe network slowdown.

### Evidence

The tester showed their scanning activity.

Further investigation revealed:

> **Debug mode had been enabled on every network device.**

Normal Nmap scans combined with debug mode caused the issue.

### Lesson

> **Good documentation allows technical issues to be investigated objectively.**

---

# 48. Full CPTS-Style Documentation Workflow

Combine the Notetaking & Organization module with this Reporting module:

```text
                    ENGAGEMENT
                         │
                         ▼
                  ADMIN INFORMATION
                         │
                         ▼
                     SCOPING
                         │
                         ▼
                   ACTIVITY LOG
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
        OSINT         ENUMERATION      WEB
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                  VULNERABILITY
                    RESEARCH
                         │
                         ▼
                    CREDENTIALS
                         │
                         ▼
                    EXPLOITATION
                         │
                         ▼
                  PRIVILEGE ESC.
                         │
                         ▼
                  LATERAL MOVEMENT
                         │
                         ▼
                    ATTACK PATH
                         │
                         ▼
                     FINDINGS
                         │
                         ▼
                     EVIDENCE
                         │
                         ▼
                      REPORT
                         │
                         ▼
                       RETEST
```

---

# 49. Golden Rules

## Rule 1

> **Document as you go.**

Do not rely on memory.

## Rule 2

> **Keep raw logs.**

Logs can answer questions that your notes cannot.

## Rule 3

> **Preserve evidence.**

Every significant finding should have proof.

## Rule 4

> **Track your attack path.**

Do not try to reconstruct the entire chain at the end.

## Rule 5

> **Know your scope.**

Always know what is in scope and what is excluded.

## Rule 6

> **Track artifacts.**

Know what you uploaded, changed, created, and removed.

## Rule 7

> **Redact sensitive information.**

Especially credentials and PII.

## Rule 8

> **Do not unnecessarily collect sensitive data.**

Prove the finding with the minimum necessary evidence.

## Rule 9

> **Do not alter evidence.**

You may use `<SNIP>` for irrelevant output, but never change the actual command or result.

## Rule 10

> **Make your documentation reproducible.**

Another tester should be able to understand what you did.

---

# 50. CPTS Practical Checklist

Before finishing an assessment:

### Administrative

-  Project information documented
    
-  Client POCs documented
    
-  Testing dates recorded
    
-  Objectives documented
    

### Scope

-  IP ranges recorded
    
-  Hosts recorded
    
-  URLs recorded
    
-  Exclusions recorded
    
-  Client-provided credentials documented securely
    

### Testing

-  Activity Log maintained
    
-  Scans saved
    
-  Commands logged
    
-  Exploitation attempts documented
    
-  Failed attempts documented
    
-  Credentials documented
    
-  Payloads documented
    
-  System changes documented
    

### Evidence

-  Screenshots captured
    
-  Terminal output saved
    
-  Logs preserved
    
-  Finding-specific evidence organized
    
-  Sensitive data redacted
    

### Attack Path

-  Initial foothold documented
    
-  Credential discovery documented
    
-  Privilege escalation documented
    
-  Lateral movement documented
    
-  Final objective documented
    

### Reporting

-  Executive Summary
    
-  Assessment Overview
    
-  Scope
    
-  Methodology
    
-  Findings
    
-  Evidence
    
-  Attack Chains
    
-  Remediation
    
-  Conclusion
    
-  Retest
    

---

# 51. Final Mental Model

```text
             DON'T JUST "PWN"
                    │
                    ▼
              DOCUMENT IT
                    │
                    ▼
              SAVE THE PROOF
                    │
                    ▼
             EXPLAIN THE IMPACT
                    │
                    ▼
             SHOW THE ATTACK PATH
                    │
                    ▼
             WRITE THE FINDING
                    │
                    ▼
             RECOMMEND A FIX
                    │
                    ▼
                  RETEST
```

# Final Takeaway

The most important lesson from these modules is:

> **A penetration test is not complete when you compromise the target. It is complete when you can accurately explain and prove what you did, what you found, how you achieved it, what impact it has, and how the client can remediate it.**

Your **notes, logs, screenshots, tool output, evidence, attack paths, and findings** are all connected.

The **Notetaking & Organization** module provides the foundation for collecting and organizing this information, while **Documentation & Reporting** turns that information into a professional deliverable.

A strong tester should therefore work like this:

```text
TEST → NOTE → LOG → SAVE EVIDENCE → VALIDATE → DOCUMENT FINDING
→ BUILD ATTACK PATH → REPORT → RETEST
```

And the core rule to remember for CPTS is:

> **If you found it — document it.**  
> **If you exploited it — prove it.**  
> **If you changed it — record it.**  
> **If it is sensitive — protect/redact it.**  
> **If it is important — preserve the evidence.**

This version is deliberately aligned with the **Notetaking & Organization module you uploaded**, including its exact organizational concepts and evidence-handling philosophy rather than replacing them with a generic pentesting template.