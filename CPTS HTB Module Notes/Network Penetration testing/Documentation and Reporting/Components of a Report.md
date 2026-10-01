![Image](https://images.openai.com/static-rsc-4/G_FUampzUyIJ3OZ7yqROfsYyPyNZ6EdGhPEHCyjIlEDELgPITRFo-tiGwx3TehqjBNuZ4qkaIlZl4-ia2JbbUqRdN1zz2b1lFKukXZUXMfXQQttbJ5YEjyhocK9INmiOtoRRDeFTgSY4tQNKfiCEMLEGw8SPIRA_EIibDR0t2db5IA_0CWefYnOd3njYKC-F?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/x3LP9iPIf_G_Cf1z-RTwqR02vaEzkhw-6OahAuldVbFiBnEVFZzAXNqgr11LFIK6UXsGsUWIT1cdZfFpwV5QNRyYbK4NEkuLZXemKaFRrxIu_D7XoLacR-zxHTO8HMHdJScVEzcdJuRJMsQLQzWttqNP9g1AsFsIMjdhzMFcegihsEFQgJEkon4lvmyjBGhA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EiOGVD91DaxfKkg3-irp9S7V3bfxNvh5ZVF3A1igMM1bx_LDyyRYG5Ahxk24JU0VImxjSapmZIHyUrzR5Xdizx6B5ilCJ9qYRWnnlFCpubozZI9p6efxeNfW2cWPEUyJcc9AdC0c-WY8FR6YPCrHLG1_cKZuJLw6U8XkQLrGEecl8l2whAd4zM9aSiUheQD6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hG4ymYuSoz1_0jPiHAlbyw8gCesauUEEpfEoSIv92wR4KRZEl2yHn5KwdG2xEaYd1UWnhuUlBiYIpvT77k6oO-mmdI2xQZF08hBOIISAhj7qt-NRgA2utUPKExf3CRpwKjUJHtCjbh1ee0SZ6Zf3-DVJQcUQTXLKOOColKltVr04iOLZ9P59g2x9Om26g_Fu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Yz5W3gquBy_-Ur8UCcXmBg7jczgFgyiEFVVK8Y-ji-gKAeN6TCAeOXWBjfkOXuW7W0i9G08T1YgchIeSUjhBmX7nqAZePnIqyW4nOGSa2lcvMVSlhWmrgr0-b9SP5mpTeTZwwj4O2ow7o7XIdD2RAPrAcCXN7F2wwiRrG0lRMFaY_hxmxsOkmi_da1WIe7lP?purpose=fullsize)

# 📘 

## 1. The Report Is the Main Deliverable

The **report is the main deliverable** that a client is paying for when they contract a penetration-testing firm.

The report should:

- Demonstrate the work performed during the assessment.
    
- Provide as much value to the client as possible.
    
- Explain the client's overall security posture.
    
- Clearly communicate important findings.
    
- Help the client prioritize remediation.
    

### Golden Rule

> **Everything in the report should have a reason for being there.**

Avoid unnecessary information that clutters the report or distracts the reader.

For example:

> **Do not paste 50+ pages of console output into the report.**

The goal is to communicate the assessment clearly rather than overwhelm the reader.

---

# 2. Prioritizing Our Efforts

During large assessments, testers encounter a lot of **"noise."**

This can come from:

- Vulnerability scanners
    
- Enumeration
    
- Automated tools
    
- False positives
    
- Informational findings
    
- Multiple versions of similar issues
    
- Exploitation attempts
    

The tester must filter this information and focus on meaningful security issues.

### Important

As testers, we are still required to **disclose everything we find**.

However, we shouldn't spend most of our assessment time validating minor, non-exploitable issues while potentially missing high-impact vulnerabilities.

---

## 2.1 High-Impact Findings

Examples of findings that deserve significant attention include:

- **Remote Code Execution (RCE)**
    
- Sensitive data disclosure
    
- Issues that enable privilege escalation
    
- Issues that enable lateral movement
    
- Vulnerabilities that can contribute to domain compromise
    

A repeatable process is important for:

1. Processing tool output.
    
2. Removing false positives.
    
3. Identifying informational issues.
    
4. Grouping similar issues.
    
5. Prioritizing high-impact vulnerabilities.
    

---

# 2.2 Don't Fall Down Rabbit Holes

A beginner can easily spend hours:

- Trying to exploit a vulnerability that isn't actually exploitable.
    
- Trying to make a broken Proof of Concept work.
    
- Investigating a false positive.
    
- Spending too much time on low-impact issues.
    

Experience helps with prioritization.

The module recommends using:

- Senior team members
    
- Mentors
    
- Experienced testers
    

when you're unsure whether something is worth pursuing.

### CPTS Mindset

Ask:

> **"Is this likely to lead somewhere valuable?"**

before spending hours on an exploitation path.

---

# 3. Writing an Attack Chain

The **Attack Chain** demonstrates the exploitation path used during an assessment.

It can show how the tester:

```text
Initial Access
      ↓
Foothold
      ↓
Privilege Escalation
      ↓
Lateral Movement
      ↓
Domain Compromise
```

The attack chain is particularly useful when **multiple findings work together**.

A finding that is only `medium-risk` on its own could become significantly more serious when combined with other weaknesses.

---

# 3.1 Why Attack Chains Matter

An attack chain helps the client understand:

- How vulnerabilities connect.
    
- How an attacker can move through the environment.
    
- Why individual findings have their assigned severity.
    
- The overall business/security impact.
    
- Which vulnerabilities could break the attack chain if remediated.
    

For example:

```text
Weak Authentication
       ↓
Credential Capture
       ↓
Password Cracking
       ↓
Domain User
       ↓
Privilege Escalation
       ↓
Lateral Movement
       ↓
Domain Compromise
```

The module specifically explains that multiple seemingly minor issues can combine to produce a major compromise.

---

# 3.2 How to Present an Attack Chain

A good structure is:

### Step 1 — Attack Chain Summary

Provide a high-level overview.

### Step 2 — Walk Through Each Step

Explain each stage.

### Step 3 — Provide Evidence

Use:

- Command output
    
- Screenshots
    
- Tool output
    
- Relevant diagrams
    

### Step 4 — Connect Findings

Show which findings contributed to the chain.

### Step 5 — Reuse Evidence

Evidence from the attack chain can often be reused in individual findings.

This avoids formatting the same evidence multiple times.

---

# 4. Sample Attack Chain — INLANEFREIGHT.LOCAL

The module provides an example of an **Internal Penetration Test** against:

```text
INLANEFREIGHT
```

Domain:

```text
INLANEFREIGHT.LOCAL
```

Testing approach:

```text
Non-Evasive
+
Grey Box
```

The client provided:

- In-scope network ranges
    
- No additional information
    

The tester ultimately compromised the Active Directory domain.

---

# 5. Sample Attack Chain — High-Level

The attack chain went approximately:

```text
Anonymous Internal User
        ↓
Responder
        ↓
NTLMv2 Hash
        ↓
Hashcat
        ↓
bsmith Domain User
        ↓
BloodHound Enumeration
        ↓
Kerberoasting
        ↓
mssqlsvc
        ↓
SQL01
        ↓
srvadmin
        ↓
MS01
        ↓
pramirez
        ↓
Pass-the-Ticket
        ↓
DCSync
        ↓
Domain Compromise
```

The purpose of the attack chain was to demonstrate how the vulnerabilities fit together and help the client prioritize remediation.

---

# 6. Attack Chain Steps

## Step 1 — Responder

The tester used **Responder** to obtain an NTLMv2 password hash for:

```text
bsmith
```

The attack involved spoofing:

- NBT-NS
    
- LLMNR
    

traffic on the local network.

---

## Step 2 — Crack the Hash

The captured password hash was cracked offline using:

```bash
hashcat
```

This revealed the user's cleartext password.

The credentials provided a foothold into:

```text
INLANEFREIGHT.LOCAL
```

The account initially had standard domain-user privileges.

---

## Step 3 — BloodHound Enumeration

The tester used:

```text
BloodHound.py
```

to enumerate the Active Directory environment.

It collected information about:

- Users
    
- Groups
    
- Computers
    
- ACLs
    
- Group membership
    
- User properties
    
- Computer properties
    
- User sessions
    
- Local administrator access
    

The collected information can be visualized to identify **attack paths**.

---

## Step 4 — Identify SPNs

The tester identified privileged users configured with:

> **Service Principal Names (SPNs)**

SPNs can potentially be targeted using:

> **Kerberoasting**

A Kerberoasting attack can allow a tester to obtain Kerberos service tickets and attempt offline password cracking if weak passwords are used.

---

## Step 5 — Target `mssqlsvc`

The tester found:

```text
mssqlsvc
```

had local administrator privileges over:

```text
SQL01.INLANEFREIGHT.LOCAL
```

SQL servers can be valuable targets because they may contain:

- Sensitive data
    
- Privileged credentials
    
- Logged-in privileged users
    

---

## Step 6 — Kerberoasting

The tester requested a TGS ticket for:

```text
mssqlsvc
```

The ticket was then cracked offline.

This revealed the cleartext password for the service account.

---

## Step 7 — Access SQL01

Using the recovered credentials, the tester accessed:

```text
SQL01
```

and retrieved credentials from the registry/LSA secrets.

The important account discovered was:

```text
srvadmin
```

---

## Step 8 — Discover `pramirez`

The tester used the `srvadmin` account to access:

```text
MS01
```

The tester discovered that:

```text
pramirez
```

was also logged in.

---

## Step 9 — Identify DCSync Rights

BloodHound showed that:

```text
pramirez
```

had permissions enabling a:

> **DCSync attack**

DCSync can abuse Active Directory replication functionality to retrieve NTLM password hashes for domain users.

---

## Step 10 — Kerberos Ticket

The tester used:

```text
Rubeus
```

to identify Kerberos tickets associated with:

```text
pramirez
```

The tester then extracted the TGT.

---

## Step 11 — Pass-the-Ticket

The extracted TGT was imported and used to authenticate as:

```text
pramirez
```

The authentication was confirmed using:

```cmd
klist
```

---

## Step 12 — DCSync

The tester then performed a:

> **DCSync attack**

using Mimikatz.

This retrieved the NTLM password hash for the built-in:

```text
Administrator
```

account.

This resulted in domain-level compromise.

---

# 🔥 7. Attack Chain — Exam Memory

Memorize the logical sequence:

```text
Responder
   ↓
NTLMv2 Hash
   ↓
Hashcat
   ↓
bsmith
   ↓
BloodHound
   ↓
Kerberoasting
   ↓
mssqlsvc
   ↓
SQL01
   ↓
srvadmin
   ↓
MS01
   ↓
pramirez
   ↓
Pass-the-Ticket
   ↓
DCSync
   ↓
Domain Compromise
```

---

# 8. Executive Summary

The:

> **Executive Summary**

is one of the most important parts of the report.

The report may be read by:

- Internal Audit
    
- IT
    
- IT Security
    
- Management
    
- C-level executives
    
- Board of Directors
    

Some readers may have little or no technical knowledge.

Therefore, the Executive Summary must communicate the important security risks in language that non-technical readers can understand.

---

# 8.1 Intended Audience

The Executive Summary is generally aimed at people responsible for:

> **Allocating budget to fix security issues.**

Therefore, it needs to communicate:

- What happened
    
- Why it matters
    
- What could happen
    
- What needs improvement
    
- General remediation priorities
    

without requiring the reader to understand technical security terminology.

---

# 8.2 Executive Summary — Do

## ✅ Be Specific With Metrics

Avoid vague terms like:

```text
Several
Multiple
Few
Many
```

Instead, provide actual numbers where possible.

Example:

❌

> Multiple systems were affected.

✅

> 25 systems were observed to be affected during the assessment.

If there may be additional instances, qualify the statement appropriately.

---

## ✅ Keep It a Summary

The module recommends approximately:

> **1.5–2 pages**

If your Executive Summary is significantly longer, consider reducing the detail.

---

## ✅ Describe What Was Accessed

Instead of saying:

> "Domain Admin access was obtained."

Explain what that means in practical terms.

For example:

> Access enabled exposure of HR documents, banking systems, or other critical assets.

This makes the risk understandable to non-technical readers.

---

## ✅ Explain General Improvements

Don't simply write:

> "Install three patches."

Instead identify the underlying process problem.

Example:

```text
Short-term:
Fix the vulnerable systems.

Long-term:
Improve patch and vulnerability-management processes.
```

---

## ✅ Discuss Expected Effort When Appropriate

An experienced tester may provide a general expectation such as:

- Low effort
    
- Moderate effort
    
- Significant effort
    

This can help management understand the practical implications of remediation.

---

# 8.3 Executive Summary — Do NOT

## ❌ Recommend Specific Vendors

The report is a:

> **Technical document, not a sales document.**

You can recommend categories such as:

- EDR
    
- Log aggregation
    
- Security monitoring
    

but avoid recommending specific vendors.

---

## ❌ Don't Overuse Acronyms

Avoid unexplained technical abbreviations.

For example:

❌

> "The attacker used MitM and SNMP weaknesses."

Better:

> Explain the attack in terms the intended audience understands.

---

## ❌ Don't Focus on Minor Findings

Spend more attention on significant findings.

Don't allow low-impact issues to distract from major risks.

---

## ❌ Don't Use Unnecessarily Complex Vocabulary

Technical vocabulary should never become a distraction.

The reader should understand the point without having to search for definitions.

---

## ❌ Don't Reference Technical Sections

The Executive Summary should stand on its own.

Don't force an executive reader to jump through the report to understand the point.

---

# 9. Technical → Non-Technical Vocabulary

The module provides examples of how technical terminology can be rewritten.

|Technical Term|More Understandable Description|
|---|---|
|VPN / SSH|A protocol used for secure remote administration|
|SSL/TLS|Technology used to facilitate secure web browsing|
|Hash|Output from an algorithm commonly used to validate file integrity|
|Password Spraying|An attack where one easily guessable password is attempted against many accounts|
|Password Cracking|An offline password attack used to recover the human-readable form of a password|
|Buffer Overflow / Deserialization|An attack that resulted in remote command execution|
|OSINT|Open Source Intelligence Gathering using public information|
|SQL Injection / XSS|A vulnerability where user input is accepted without proper sanitization, allowing manipulation of application logic|

---

# 10. Be Careful With Language

The report should not make assumptions sound like absolute facts.

For example:

❌

> "The client does not have security monitoring."

Better:

> "Testing activity appeared to go largely unnoticed."

This distinction matters because the tester may not know everything happening inside the client's environment.

The module specifically emphasizes careful wording such as:

- **"seems like"**
    
- **"indicated that"**
    
- **"may"**
    
- **"could"**
    

when the evidence doesn't establish certainty.

---

# 11. Summary of Recommendations / Remediation Summary

Before the detailed technical findings, it is useful to provide:

> **Summary of Recommendations**

or:

> **Remediation Summary**

This section provides:

- Short-term recommendations
    
- Medium-term recommendations
    
- Long-term recommendations
    

The recommendations should be based on:

- Findings
    
- Current environment
    
- Business needs
    
- Security budget
    
- Staffing
    
- Practical constraints
    

---

# 11.1 Recommendations Must Be Actionable

Every short- and medium-term recommendation should map back to a specific finding.

Think:

```text
Finding
   ↓
Recommendation
   ↓
Remediation Action
```

Don't create generic recommendations that don't correspond to the reported findings.

---

# 11.2 Short-Term vs Long-Term

Example:

### Missing Patch

**Short-term:**

> Deploy the missing patches.

**Long-term:**

> Review patch and vulnerability-management processes to prevent similar issues from recurring.

---

# 12. Findings

After the Executive Summary, the:

> **Findings**

section is one of the most important parts of the report.

It should:

- Demonstrate the tester's work.
    
- Explain risk.
    
- Provide evidence.
    
- Allow technical teams to validate/reproduce issues.
    
- Provide remediation advice.
    

---

# 13. Appendices

Appendices provide additional information without cluttering the main report.

There are two major categories:

```text
Appendices
├── Static Appendices
└── Dynamic Appendices
```

If an appendix makes the report unnecessarily large, consider using a:

> **Supplemental Spreadsheet**

This can make large datasets easier to:

- Sort
    
- Filter
    
- Analyze
    

---

# 14. Static Appendices

## 14.1 Scope

Shows the scope of the assessment.

Examples:

- URLs
    
- Network ranges
    
- Facilities
    
- Other defined targets
    

Auditors may need to see this information.

---

## 14.2 Methodology

Explains the:

> **Repeatable process**

used to ensure assessments are:

- Thorough
    
- Consistent
    
- Repeatable
    

---

## 14.3 Severity Ratings

If your severity ratings don't directly map to something like:

> **CVSS**

you need to explain the criteria used to assign severity.

Your severity definitions should be:

- Logical
    
- Defensible
    
- Consistent
    

---

## 14.4 Biographies

For assessments performed specifically for **PCI compliance**, the report should include information about the personnel performing the assessment.

The goal is to demonstrate that the consultant is adequately qualified.

Even outside compliance requirements, biographies can give the client confidence in the assessment team.

---

# 15. Dynamic Appendices

Dynamic appendices depend on what happened during the assessment.

---

## 15.1 Exploitation Attempts and Payloads

Track:

- Exploitation attempts
    
- Payloads
    
- Custom payloads
    
- Files dropped to disk
    
- Locations
    
- Other artifacts
    

This is important because the client's forensic team needs to distinguish:

```text
Pentester Activity
        vs.
Actual Attacker Activity
```

If payloads cannot be cleaned up, the client needs to know:

- What was created
    
- Where it exists
    
- What needs to be removed
    

---

# 15.2 Compromised Credentials

If many accounts were compromised, list them in the appendix.

If the entire domain was compromised, listing every individual account may be unnecessary.

Instead, it may be enough to state:

> **All domain accounts**

The purpose is to help the client take appropriate action.

---

# 15.3 Configuration Changes

Any configuration changes made during testing should be documented.

Examples could include:

- Security-tool changes
    
- EDR changes
    
- System configuration changes
    
- Other modifications
    

Ideally:

1. Obtain approval first.
    
2. Document the change.
    
3. Restore the original configuration.
    
4. Obtain written approval when appropriate.
    

This protects the client from unintended consequences.

---

# 15.4 Additional Affected Scope

Sometimes a finding affects a large number of hosts.

Instead of placing a huge list inside the finding, put the complete list in an appendix.

Example:

```text
Finding:
Insecure Configuration

Affected Hosts:
See Appendix A — Additional Affected Scope
```

This keeps the report clean.

---

# 15.5 Information Gathering

For an **External Penetration Test**, an appendix may contain information about the client's external footprint.

Possible information:

- WHOIS data
    
- Domain ownership
    
- Subdomains
    
- Discovered email addresses
    
- Public breach data
    
- SSL/TLS configuration
    
- Externally accessible ports/services
    

For large external scopes, a supplemental spreadsheet may be more appropriate.

---

# 15.6 Domain Password Analysis

If Domain Admin access is obtained and the NTDS database is dumped, password analysis can provide useful statistics.

Potential statistics include:

- Number of hashes obtained
    
- Number cracked
    
- Percentage cracked
    
- Privileged accounts cracked
    
- Top passwords
    
- Number of passwords cracked by password length
    

This information can reinforce themes around weak passwords in:

- Executive Summary
    
- Findings
    

The complete password-analysis report can also be provided as supplementary data.

---

# 16. Report Type Differences

Not every penetration-testing report needs the same components.

## Internal Penetration Test

May include:

- Executive Summary
    
- Attack Chain
    
- Findings
    
- Remediation Summary
    
- Compromised Credentials
    
- Configuration Changes
    
- Domain Password Analysis
    
- Other internal-environment appendices
    

---

## External Penetration Test — No Internal Compromise

May focus more heavily on:

- Information Gathering
    
- OSINT
    
- External footprint
    
- Internet-facing services
    

It may not include:

- Attack Chain for internal compromise
    
- Compromised credentials
    
- Configuration changes
    
- Domain password analysis
    

---

## Web Application Security Assessment (WASA)

A WASA report will generally focus heavily on:

- Executive Summary
    
- Findings
    

and may emphasize:

> **OWASP Top 10**

---

## Physical Security Assessment

Likely to use a more:

> **Narrative format**

---

## Red Team Assessment

Likely to use a more:

> **Narrative format**

---

## Social Engineering Engagement

Likely to use a more:

> **Narrative format**

### Professional Tip

Create reusable templates for different assessment types so you're prepared when a particular engagement begins.

---

# 🧠 17. Complete Report Structure

For an Internal Penetration Test, a useful high-level structure is:

```text
PENETRATION TEST REPORT
│
├── Executive Summary
│
├── Attack Chain
│
├── Summary of Recommendations
│
├── Findings
│   ├── Finding 1
│   ├── Finding 2
│   ├── Finding 3
│   └── ...
│
└── Appendices
    │
    ├── Static Appendices
    │   ├── Scope
    │   ├── Methodology
    │   ├── Severity Ratings
    │   └── Biographies
    │
    └── Dynamic Appendices
        ├── Exploitation Attempts & Payloads
        ├── Compromised Credentials
        ├── Configuration Changes
        ├── Additional Affected Scope
        ├── Information Gathering
        └── Domain Password Analysis
```

---

# 🔥 18. CPTS Exam Memory Map

Memorize:

```text
REPORT
  │
  ├── Executive Summary
  │       ↓
  │   Management / Non-Technical
  │
  ├── Attack Chain
  │       ↓
  │   How vulnerabilities connect
  │
  ├── Remediation Summary
  │       ↓
  │   Short / Medium / Long Term
  │
  ├── Findings
  │       ↓
  │   Technical Details + Evidence + Remediation
  │
  └── Appendices
          ↓
      Supporting Information
```

---

# ⚡ 19. Most Important Things to Remember

### ⭐ 1. Report = Main Deliverable

The report is what the client is paying for.

---

### ⭐ 2. Everything Needs a Purpose

Don't add unnecessary information.

---

### ⭐ 3. Don't Overwhelm the Reader

Avoid massive blocks of raw console output.

---

### ⭐ 4. Filter the Noise

Understand scanner output and eliminate:

- False positives
    
- Low-value noise
    
- Informational distractions
    

while still properly disclosing findings.

---

### ⭐ 5. Prioritize High-Impact Issues

Examples:

- RCE
    
- Sensitive data disclosure
    
- Privilege escalation
    
- Domain compromise
    

---

### ⭐ 6. Attack Chain Shows the Bigger Picture

Individual findings may become much more serious when chained together.

---

### ⭐ 7. Executive Summary Is for Non-Technical Readers

Think:

> **"Can someone with no cybersecurity background understand the risk?"**

---

### ⭐ 8. Be Specific

Avoid:

> "Several systems"

Prefer:

> "25 systems"

when the number is known.

---

### ⭐ 9. Executive Summary ≈ 1.5–2 Pages

Keep it concise.

---

### ⭐ 10. Don't Recommend Specific Vendors

The report is a:

> **Technical document, not a sales document.**

---

### ⭐ 11. Findings Are Extremely Important

They need to provide:

- Risk
    
- Evidence
    
- Reproduction
    
- Remediation
    

---

### ⭐ 12. Recommendations Must Map to Findings

```text
Finding → Recommendation
```

---

### ⭐ 13. Short-Term + Long-Term

Short-term:

> Fix the immediate issue.

Long-term:

> Fix the underlying process that allowed it to happen.

---

### ⭐ 14. Static Appendices

Remember:

```text
Scope
Methodology
Severity Ratings
Biographies
```

---

### ⭐ 15. Dynamic Appendices

Remember:

```text
Exploitation Attempts & Payloads
Compromised Credentials
Configuration Changes
Additional Affected Scope
Information Gathering
Domain Password Analysis
```

---

# 🎯 20. One-Minute Revision

If you need to revise this module quickly before a CPTS assessment:

```text
REPORT
↓
Main client deliverable
↓
Remove unnecessary clutter
↓
Prioritize high-impact issues
↓
Write Attack Chain
↓
Write Executive Summary
↓
Write Remediation Summary
↓
Write Findings
↓
Add Appendices
```

### Executive Summary

```text
Non-technical
Specific metrics
~1.5–2 pages
Explain impact
General remediation
No vendor recommendations
No excessive acronyms
No unnecessary technical details
```

### Attack Chain

```text
Foothold
↓
Privilege Escalation
↓
Lateral Movement
↓
Domain Compromise
```

### Remediation

```text
Short-term
+
Medium-term
+
Long-term
```

### Appendices

```text
Static:
Scope
Methodology
Severity Ratings
Biographies

Dynamic:
Payloads
Credentials
Configuration Changes
Affected Scope
Information Gathering
Password Analysis
```

---

# 🏆 Final CPTS Takeaway

The central lesson of **Components of a Report** is:

> **A penetration-testing report should not simply document everything the tester did. It should communicate the security risk clearly, demonstrate how the vulnerabilities can affect the environment, provide evidence that technical teams can reproduce, and give the client an actionable path toward remediation.**

The most important mental model is:

```text
WHAT DID WE FIND?
        ↓
WHY DOES IT MATTER?
        ↓
HOW DID THE ISSUES CONNECT?
        ↓
WHAT EVIDENCE PROVES IT?
        ↓
HOW CAN THE CLIENT FIX IT?
        ↓
HOW CAN THEY PREVENT IT FROM HAPPENING AGAIN?
```

That is the difference between simply recording penetration-testing activity and producing a **professional penetration-testing report**.