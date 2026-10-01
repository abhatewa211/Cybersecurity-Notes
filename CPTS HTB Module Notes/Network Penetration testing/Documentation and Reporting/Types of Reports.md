Absolutely. Below are **detailed study notes based directly on the pasted HTB module**, with the module’s important terminology and distinctions preserved.

![Image](https://images.openai.com/static-rsc-4/97Rs6ZOcNj1iGleWlqERnf_zB5P8o_KMmevmwFD-7H0y0HLW9QjZIsXwCIBm1nnB-VtjRsimK-Sm8qLrM7K-8v8mVcMyfyivANVpxXeeFw28K02vDrWNkHNucOHXwNhMsusYneag-g4nA_bW2dvYDpfOpHfx_YHaNFOzs9X6W_SQfTfqGyjBZbSkkeuXXVAj?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iGXZHh-TMKxhPm4OVozV6QG_m73DGnOAed7_9Bfr063R9toeKHHIAabSfyxJI7JRtKkvH0Rrjl9WIbMwYiuOEJ5EGHOFvASdIIl_u_r2yWKv0FhhH5Nx7sGYIj_rN9B1zGsuQkl9vRJlStxDk1Ia8U6HK61hC-2SDZy-CcFP998gW9unTnUhMDSvlZVzF7h_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RIrch_kHWku__br4eSFZCgpQ9XsCNxYFKbg21M7mmrdsCzGCf1HapP9HmiZqYY39A2I_9C5CXera_6Kh0HvYWEbnfbNJ0h4nlZwtckw8AGToad3TKsnZ-Z5xBv2A0Yf3kQvvRsU9tyyRn6GYvPfWyISEBdc8Ujh4F8zobWBI_QUDnUGp3ScQwivhc3b4q9ke?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/u-YpOUSybVF0KUoQ9kv3WeFWVIU0l4YbW4W09-bSdDUPlFR4Q_JhtQ3ua_wEz8zhLrHqAsGOGZ8Ea7U3aC_wl5KfvVB48W5csyDgrnEOYeK78ALhWJ_7YqRK2dGCsFTE8PeoSd5fDjl2i6tx6ICjd3BbehO4GRODIoV4JqFOCblMZzNUMnclsTscBJIrhyCD?purpose=fullsize)

## 1. Overview

The structure of a penetration-testing report can differ depending on the type of assessment being performed.

This module primarily focuses on an **Internal Penetration Test report** where the tester achieved **Active Directory (AD) domain compromise**.

The report demonstrates the typical elements of an **Internal Penetration Test report**, while also discussing other report types and additional deliverables.

### Important point

An **External Penetration Test** can also result in internal compromise. In that situation, the report may contain:

- Attack chains
    
- Internal compromise details
    
- Internal network findings
    
- Active Directory findings
    
- Other elements normally associated with internal penetration testing
    

However, external testing may also include **OSINT/publicly available information**, such as:

- Email addresses
    
- Subdomains
    
- Credentials found in breach dumps
    
- Domain registration/ownership information
    

These OSINT elements are not included in the module's lab because the lab is not testing against an actual company with an internet presence.

---

# 2. Common OSINT Information Targeted During a Penetration Test

The module identifies several common categories of information that may be targeted:

### 1. Public DNS and domain ownership records

Information about:

- Public DNS
    
- Domain ownership
    
- Registered domains
    

### 2. Email Addresses

Email addresses can potentially be used to:

- Check whether accounts have appeared in breaches
    
- Perform Google Dorking
    
- Search public sites such as Pastebin
    

### 3. Subdomains

Subdomains may reveal additional externally exposed systems or applications.

### 4. Third-party vendors

Organizations may depend on external vendors whose infrastructure or information can provide additional attack-surface information.

### 5. Similar domains

Look for domains that are related to the organization.

### 6. Public cloud resources

Cloud-hosted resources may expose additional information or attack surface.

> **Important:** OSINT tools are fluid and change over time. Do not become dependent on one particular tool. Running multiple tools and comparing the results is recommended.

These information-gathering topics are covered in other HTB modules and are outside the scope of this module.

---

# 3. Differences Across Assessment Types

Before understanding report structures, we need to understand the major assessment types.

The most important distinction is between:

- Vulnerability Assessment
    
- Penetration Testing
    
- Internal vs External testing
    
- Different testing perspectives
    
- Inter-disciplinary assessments
    

---

# 🔎 4. Vulnerability Assessment

A **Vulnerability Assessment** primarily involves running an **automated scan** of an environment to enumerate vulnerabilities.

The scan can be:

- Authenticated
    
- Unauthenticated
    

### Key characteristic

> **No exploitation is attempted.**

However, testers may validate scanner results.

### Validation can include:

- Confirming that a vulnerable version is actually being used
    
- Confirming a vulnerable configuration
    
- Confirming a misconfiguration
    
- Determining whether a scanner result is a false positive
    

### Goal

The goal is **not** to:

- Gain a foothold
    
- Move laterally
    
- Move vertically
    
- Compromise the environment
    

Some customers may even request the raw scan results **without validation**.

---

# 🌐 5. Internal vs External Vulnerability Scanning

## External Scan

An external scan is performed from the perspective of an **anonymous user on the internet**.

The target is generally the organization's:

- Public systems
    
- Internet-facing infrastructure
    
- Publicly accessible hosts
    

## Internal Scan

An internal scan is performed from the perspective of a scanner located **inside the internal network**.

It investigates hosts from behind the firewall.

The internal perspective could represent:

- Anonymous corporate network user
    
- Compromised server
    
- Authenticated user
    
- Other defined internal scenarios
    

### Authenticated Internal Scan

A client may provide credentials for an internal scan.

This can produce:

- More scanner findings
    
- More accurate results
    
- Less generic results
    

But it can also result in a much larger amount of data that must be reviewed.

---

# 📊 6. Vulnerability Assessment Report Contents

Vulnerability assessment reports generally focus on:

- Themes observed in scan results
    
- Number of vulnerabilities
    
- Severity levels
    
- Patterns across the environment
    
- Procedural deficiencies
    

### Important problem

Automated scans can generate **a LOT of data**.

Therefore, the tester needs to identify patterns and connect them to procedural deficiencies so the report does not become overwhelming.

---

# 🛡️ 7. Penetration Testing

Penetration testing goes **beyond automated scanning**.

A penetration test can use vulnerability-scan results to guide exploitation.

Penetration tests can also be:

- Internal
    
- External
    

Depending on the assessment type, vulnerability scanning may not be performed at all.

For example, an **evasive test** may deliberately avoid traditional scanning techniques.

---

# 8. Penetration Testing Perspectives

There are three major information-access perspectives:

## 🖤 Black Box

The tester has very limited information.

For an external test:

> The tester may have no more information than the company name.

For an internal test:

> The tester may only have a network connection.

---

## 🩶 Grey Box

The tester receives some information.

Example:

- In-scope IP addresses
    
- CIDR network ranges
    

---

## 🤍 White Box

The tester receives significant information.

Possible information includes:

- Credentials
    
- Source code
    
- Configurations
    
- Other internal information
    

### Easy memory

```text
BLACK BOX
↓
Almost no information

GREY BOX
↓
Some information

WHITE BOX
↓
Extensive information
```

---

# 9. Evasion Levels

Penetration testing can also differ based on how much the tester attempts to avoid detection.

## Zero Evasion

The goal is to uncover as many vulnerabilities as possible.

The tester is not primarily concerned with remaining hidden.

---

## Hybrid Evasive

The tester begins with evasive techniques and gradually becomes **"noisier"**.

The purpose is to determine:

- At what point monitoring detects the tester
    
- At what point security teams identify the activity
    
- At what point defensive tools block the activity
    

Once detected, the client may ask the tester to switch to **non-evasive testing** for the remainder of the assessment.

This type of assessment can help identify gaps in:

- Detection
    
- Prevention
    
- Monitoring
    
- Security procedures
    

---

# 🥷 10. Evasive Testing

In **evasive testing**, the tester attempts to remain undetected for as long as possible.

The goal is to determine:

- What access can be obtained
    
- How far the tester can progress
    
- How long the tester can remain undetected
    

This attempts to simulate a more advanced attacker.

### Limitation

Real attackers may have months or years.

A penetration test is usually limited by time.

Therefore, some organizations may conduct longer-term **adversary simulation** assessments lasting multiple months.

Only a small number of employees may know about the assessment.

Some employees may not even know the exact start date/time.

---

# 🌍 11. Internal vs External Penetration Testing

## External Penetration Test

Usually performed from the perspective of an:

> **Anonymous attacker on the internet**

It may use:

- OSINT
    
- Publicly available information
    
- Internet-facing applications
    
- Internet-facing hosts
    

The objective may be to gain access to:

- Sensitive information
    
- Internal systems
    
- Internal networks
    

---

## Internal Penetration Test

May be performed from the perspective of:

- Anonymous internal user
    
- Authenticated internal user
    

Typical objectives include:

```text
Find vulnerabilities
       ↓
Obtain foothold
       ↓
Horizontal privilege escalation
       ↓
Vertical privilege escalation
       ↓
Lateral movement
       ↓
Compromise internal network
       ↓
Active Directory compromise
```

---

# 🤝 12. Inter-Disciplinary Assessments

Some assessments require people with different skill sets.

This can make the assessment:

- More logistically complex
    
- More collaborative
    
- More valuable
    
- More closely integrated with the client's team
    

Examples include:

- Purple Team Style Assessments
    
- Cloud Focused Penetration Testing
    
- Comprehensive IoT Testing
    
- Web Application Penetration Testing
    
- Hardware Penetration Testing
    

---

# 🟣 13. Purple Team Style Assessments

A Purple Team assessment combines:

- **Red Team**
    
- **Blue Team**
    

A common example involves:

- Penetration tester
    
- Incident responder
    

### Basic process

```text
Penetration Tester
       ↓
Simulates Threat
       ↓
Incident Responder / Blue Team
       ↓
Reviews Detection
       ↓
Adjust Alerts / Monitoring
```

The purpose is to determine whether:

- Alerts are configured correctly
    
- Threat activity is detected
    
- Identification works correctly
    
- Security tooling needs adjustment
    

---

# ☁️ 14. Cloud Focused Penetration Testing

Cloud-focused penetration testing overlaps significantly with conventional penetration testing.

However, cloud assessments benefit from someone with knowledge of:

- Cloud architecture
    
- Cloud administration
    
- Cloud security
    

For example, a tester may discover:

- Secrets
    
- Keys
    
- Credentials
    

A cloud specialist can help determine what those discovered items could potentially be abused to access.

### Specialized infrastructure

Cloud assessments can involve:

- Containers
    
- Serverless applications
    
- Cloud infrastructure
    

These may require:

- Different methodologies
    
- Specialized knowledge
    
- Different toolkits
    

The technical details of testing these resources are outside the scope of this module.

---

# 📡 15. Comprehensive IoT Testing

IoT platforms typically contain three major components:

```text
Network
   +
Cloud
   +
Application
```

A thorough IoT assessment may therefore require specialists in each area.

There may also be a:

```text
Hardware Layer
```

### Important point

A team containing specialists can provide a more thorough assessment than one tester with only basic knowledge across every area.

The standard penetration-testing report structure can still be useful for presenting IoT findings.

---

# 🌐 16. Web Application Penetration Testing

Web application testing can sometimes be considered an **inter-disciplinary assessment**.

There are different scopes.

## Application-only assessment

The assessment may focus only on:

- Application vulnerabilities
    
- Validation
    
- Authenticated testing
    
- Role-based testing
    

The underlying server may not be evaluated.

---

## Application + Infrastructure Assessment

The objective may be to:

1. Compromise the application
    
2. Move beyond the application
    
3. Discover other hosts
    
4. Discover internal systems
    
5. Compromise additional systems
    
6. Perform privilege escalation
    
7. Move through Active Directory
    

This type of assessment can benefit from multiple skill sets.

For example:

```text
Application Developer /
Application Security Tester
             ↓
Initial Web Compromise
             ↓
Network-focused Tester
             ↓
Live off the land
             ↓
Privilege Escalation
             ↓
Active Directory
             ↓
Lateral Movement
```

---

# 🔧 17. Hardware Penetration Testing

Hardware testing is commonly associated with:

- IoT devices
    
- Laptops
    
- Onsite kiosks
    
- ATMs
    

The exact depth of testing depends on the client's requirements.

### ⚠️ Rules of Engagement are critical

Before testing, establish what is permitted, particularly for:

> **Destructive testing**

For example, if the client expects a device to be returned in working condition, destructive attacks such as physically removing/desoldering motherboard components would generally be inappropriate.

---

# 📝 18. Draft Report

A **Draft Report** is increasingly common.

Clients may want to:

- Review findings
    
- Add management responses
    
- Explain planned remediation
    
- Change wording
    
- Request organizational changes
    
- Adjust presentation
    
- Prepare information for management/board members
    

### Recommended process

```text
Assessment Complete
       ↓
Draft Report
       ↓
Client Reviews
       ↓
Review Meeting
       ↓
Questions / Clarification
       ↓
Client Feedback
       ↓
Final Report
```

The client is paying for the report deliverable, so the report should be as:

- Thorough
    
- Useful
    
- Valuable
    
- Relevant
    

as possible.

---

# 📄 19. Final Report

After reviewing the report with the client and confirming that they are satisfied, the tester can issue the:

> **Final Report**

The final report incorporates necessary modifications from the draft.

### Why this matters

Some auditing firms may not accept a draft report for compliance purposes.

Therefore, issuing the final report can be important for the client's compliance obligations.

---

# 🔄 20. Post-Remediation Report

A client may ask for vulnerabilities from the original assessment to be tested again after remediation.

This is known as remediation testing/retesting.

It is particularly important for organizations subject to compliance requirements such as **PCI**.

## ⭐ Critical Rule

> **You should not be redoing the entire assessment for this phase.**

Instead:

- Retest only the original findings
    
- Retest only the hosts affected by those findings
    

---

# ⏱️ 21. Why Retesting Needs a Time Limit

A time limit should be established between the original assessment and remediation testing.

If remediation testing occurs too late:

### Problem 1 — Environment changes

The environment may change so much that an accurate **"apples to apples"** comparison becomes impossible.

### Problem 2 — New hosts

If you scan the entire environment again, you may discover additional affected hosts.

This can create an endless remediation-testing loop.

### Problem 3 — New vulnerabilities

Running new large-scale vulnerability scans can identify vulnerabilities that did not exist during the original assessment.

The scope can quickly become uncontrolled.

### Alternative

If the client wants continuous validation, a **Breach and Attack Simulation (BAS)** tool may be recommended to periodically test whether the scenarios continue to occur.

---

# ⚖️ 22. Handling Pressure Around Findings

Sometimes clients may face pressure from:

- Auditors
    
- Compliance deadlines
    
- Management
    
- Remediation timelines
    

This can result in requests to change severity or modify findings.

The tester should:

- Maintain ethical boundaries
    
- Clearly explain what can and cannot be changed
    
- Understand the client's situation
    
- Offer practical alternatives
    

For example, an auditor may accept a:

> **Thoroughly documented remediation plan with a reasonable deadline**

instead of requiring complete remediation immediately.

This allows the tester to maintain professional integrity while helping the client move forward.

---

# 🔄 23. Retest vs New Assessment

If significant time has passed, one possible approach is to treat the work as a **new assessment**.

If the client does not agree, the tester may retest only the original findings.

The report should clearly state:

- How much time has passed
    
- That this is a point-in-time check
    
- Only previously reported vulnerabilities were tested
    
- Only originally reported hosts were assessed
    
- The environment may have changed significantly
    
- A complete new assessment was not performed
    

---

# 📊 24. How to Present Retest Results

Two approaches can be used.

### Approach 1 — Update original report

Add status to affected hosts/findings:

- Resolved
    
- Unresolved
    
- Partial
    

### Approach 2 — Create a new report

Include:

- Comparison information
    
- Updated executive summary
    
- Retest results
    

---

# 📜 25. Attestation Report

Some clients need an:

> **Attestation Letter / Attestation Report**

This is often provided to:

- Vendors
    
- Customers
    
- Third parties
    

who need evidence that a penetration test was conducted.

### Important difference

The client generally does **not** want to provide third parties with:

- Detailed technical findings
    
- Credentials
    
- Secrets
    
- Sensitive technical information
    

Instead, the attestation report should focus on:

- Number of findings
    
- Testing approach
    
- General comments about the environment
    

### Typical length

> **One or two pages**

---

# 📽️ 26. Other Deliverables — Slide Deck

A client may request a presentation.

The audience could be:

- Technical
    
- Executive
    
- Management
    
- Board-level
    

The language and focus should change depending on the audience.

### Executive presentation

Should not simply contain:

- Graphs
    
- Numbers
    
- Technical details
    

The module recommends making risks relatable using appropriate examples or relevant events.

The purpose is **not fear-mongering**.

The purpose is to help the audience understand the risk and increase the likelihood that appropriate action is taken.

---

# 📊 27. Spreadsheet of Findings

A findings spreadsheet contains the report's findings in a **tabular format**.

This allows the client to:

- Sort findings
    
- Manipulate data
    
- Track remediation
    
- Potentially import findings into a ticketing system
    

### Important

The spreadsheet should **not** include:

- Executive summary
    
- Finding narratives
    

Instead, it should contain the structured finding fields.

### Useful capability

Learn to use:

> **Pivot tables**

They can help create analytics and sort findings by:

- Severity
    
- Category
    

This helps clients prioritize remediation.

---

# 🚨 28. Vulnerability Notifications

Sometimes a tester discovers a critical vulnerability during an assessment.

The tester may need to:

1. Stop testing
    
2. Inform the client
    
3. Allow the client to decide whether to fix it immediately
    
4. Continue the assessment if appropriate
    

This is commonly handled through a **Vulnerability Notification**.

---

# 🚨 29. When Should a Vulnerability Notification Be Drafted?

At minimum, the module recommends this for a finding that is:

- **Directly exploitable**
    
- **Exposed to the internet**
    
- Results in **unauthenticated remote code execution**
    
- Results in **sensitive data exposure**
    
- Or leverages **weak/default credentials** for the same impact
    

However, expectations should be established during the:

> **Project kickoff**

Some clients may want:

- All Critical findings
    
- All High and Critical findings
    
- Internal High/Critical findings
    
- Medium findings as well
    

Therefore, establish a baseline and confirm the client's expectations.

---

# ⚡ 30. Contents of a Vulnerability Notification

A vulnerability notification should be concise.

Avoid unnecessary **fluff**.

Technical teams need to quickly understand:

- What the vulnerability is
    
- Why it matters
    
- How to reproduce it
    
- What evidence proves it
    

The module recommends using content similar to the **technical details of the finding**, along with tool-based evidence that the client can quickly reproduce.

---

# 🧠 31. Key Comparison Table

|Assessment / Report|Main Purpose|
|---|---|
|**Vulnerability Assessment**|Identify vulnerabilities through automated scanning|
|**Penetration Test**|Go beyond scanning and attempt exploitation|
|**Internal Test**|Assess from inside the network|
|**External Test**|Assess from the internet|
|**Black Box**|Minimal information|
|**Grey Box**|Limited information such as IP/CIDR|
|**White Box**|Extensive information such as credentials/source code|
|**Zero Evasion**|Find as many vulnerabilities as possible|
|**Hybrid Evasive**|Gradually increase noise to test detection|
|**Evasive Testing**|Remain undetected as long as possible|
|**Purple Team**|Red + Blue team collaboration|
|**Cloud Testing**|Focus on cloud architecture/resources|
|**IoT Testing**|Network + Cloud + Application + potentially Hardware|
|**Web App Testing**|Test application and potentially underlying infrastructure|
|**Hardware Testing**|Test physical devices/hardware|
|**Draft Report**|Client review and feedback|
|**Final Report**|Finalized assessment deliverable|
|**Post-Remediation Report**|Retest original findings|
|**Attestation Report**|Limited proof that testing occurred|
|**Slide Deck**|Present results to technical/executive audiences|
|**Findings Spreadsheet**|Structured findings for sorting/tracking|
|**Vulnerability Notification**|Quickly communicate critical exploitable issues|

---

# 🔥 32. CPTS Important Points to Memorize

## Vulnerability Assessment

```text
Automated Scan
      ↓
Enumerate Vulnerabilities
      ↓
Optional Validation
      ↓
NO Exploitation
```

**Key phrase:**

> **No exploitation is attempted.**

---

## Penetration Testing

```text
Enumeration
      ↓
Identify Vulnerabilities
      ↓
Exploit
      ↓
Foothold
      ↓
Privilege Escalation
      ↓
Lateral Movement
      ↓
Compromise
```

---

## Internal vs External

```text
EXTERNAL
Internet
   ↓
Public / Internet-facing systems

INTERNAL
Internal Network
   ↓
Hosts behind firewall
```

---

## Black / Grey / White Box

```text
BLACK
Minimal information

GREY
Some information

WHITE
Extensive information
```

---

## Evasion

```text
ZERO EVASION
↓
Maximum discovery

HYBRID EVASIVE
↓
Start stealthy → become noisier

EVASIVE
↓
Remain undetected as long as possible
```

---

# 🎯 33. Report Lifecycle

The overall reporting workflow can be remembered as:

```text
Assessment
    ↓
Findings
    ↓
Draft Report
    ↓
Client Review
    ↓
Feedback / Clarification
    ↓
Final Report
    ↓
Remediation
    ↓
Retest
    ↓
Post-Remediation Report
```

Additional deliverables can include:

```text
Attestation Letter
       +
Slide Deck
       +
Findings Spreadsheet
       +
Vulnerability Notifications
```

---

# 🧩 34. Quick Exam Revision

### Q: What is a Vulnerability Assessment?

An automated scan used to enumerate vulnerabilities, with possible validation but **no exploitation**.

### Q: What is the difference between internal and external scanning?

External scanning views the environment from the **internet**, while internal scanning views hosts from **inside the network**.

### Q: What is Black Box?

Testing with minimal information.

### Q: What is Grey Box?

Testing with limited information such as IP addresses/CIDR ranges.

### Q: What is White Box?

Testing with extensive information such as credentials, source code, and configurations.

### Q: What is Zero Evasion?

Testing designed to uncover as many vulnerabilities as possible without focusing on stealth.

### Q: What is Hybrid Evasive testing?

Beginning evasively and gradually becoming noisier to determine when defenses detect/block the tester.

### Q: What is Evasive Testing?

Attempting to remain undetected for as long as possible.

### Q: What is a Purple Team assessment?

A collaborative assessment involving **Red Team and Blue Team** activities.

### Q: What is a Post-Remediation Report?

A report documenting the results of retesting previously identified findings after remediation.

### Q: Should the entire assessment be repeated during remediation testing?

**No.** Retest only the original findings and affected hosts.

### Q: What is an Attestation Report?

A short document demonstrating that a penetration test occurred without exposing detailed technical findings or secrets.

### Q: What should a findings spreadsheet contain?

The structured finding fields in a tabular format; it should **not** contain the executive summary or narratives.

### Q: When should a vulnerability notification be created?

At minimum, for directly exploitable internet-exposed findings resulting in unauthenticated RCE or sensitive data exposure, including cases involving weak/default credentials.

---

# 🏆 Final Takeaway

The biggest lesson from this module is that **different assessments require different reporting approaches**.

You need to understand:

```text
WHAT was tested
      ↓
FROM WHICH perspective
      ↓
WITH WHAT level of information
      ↓
WHAT was discovered
      ↓
WHAT was exploited
      ↓
WHAT was reported
      ↓
WHAT was remediated
      ↓
WHAT was retested
```

For CPTS-style work, remember these distinctions especially:

**Vulnerability Assessment ≠ Penetration Test**

**Internal ≠ External**

**Black Box ≠ Grey Box ≠ White Box**

**Zero Evasion ≠ Hybrid Evasive ≠ Evasive**

**Draft Report ≠ Final Report**

**Initial Assessment ≠ Post-Remediation Retest**

**Full Technical Report ≠ Attestation Report**

**Findings Spreadsheet ≠ Executive Summary**

**Vulnerability Notification = Fast communication of serious issues**

These distinctions form the foundation for understanding the report types discussed throughout the module.