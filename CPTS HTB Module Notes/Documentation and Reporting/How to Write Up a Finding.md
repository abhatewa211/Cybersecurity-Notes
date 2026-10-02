![Image](https://images.openai.com/static-rsc-4/dXIUFMVi0NNlc9Vr-CDm2Vdy62eLZl9Poz5xS_8MgfTgsfg4pZUKtQqY-9MS6Wwet4vgbeOK-tl0VuUbRC4hQMBaQ2EiXl7FNim8TbS5_Ve1CrjXgCSeXpGzAw_KXDL8vSzOYHLbGir_Pm-RGHR2gEzuUF6mYAyGbwQU8mPjQpMY1DbQXlFGmnAYu_qrz5m5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fgsUzXFpIbPndZDjOF0XSvUbEvl1YrLvseD7Swo4lpdLxNtTbTpfOVlEGE9Qqlr0Jnj1j-Ml5tw1ScTwG3ELmjvycJnZ_9VEg4yf4Ya50JMF_89WlyIGkQEs3tiKY9WwqeAIQdsxsB5uwdETpti9BR-JoOK2aj6BrpdmtvY8WZ3n_H3ovIWGgOx3wEm5JEQH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/whoapQ91Gxa3sF_K5cBbIKn8g43E7YZTQMEDNKCPMRMAMkPRRGbExaOEHWSZ-JO1jMicV4y22nSU_onIbcVVBDkarCP4jcWEVaQsgbOwZburT31W7wZl-ew44BGG9TUHH1bkTk2L-vBhYcd-oJUZzWRTYEGPQ0Uw-eoWEU0PqH3kk6haMEAXNE5sHSIEPIg_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PE4QPECshbyus-4_j4ZLVH99-BAdCe1f0hJVCreThyV1EFHILAUN5g_8R9lZH9Ak8uZpiPAplZEIrUCWYld-f7VdDdJApk9jv7TcMMXSkeRnV0MQlZKtd7FUmEO2dAh6nSDagXuFNjcxoUKIoYJyIgDy28up6iUyN4daWJQkWuco7j0AnOUP4wlwdSMQfJbw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wxZHsFxIyYr4IcW9h0a5ZV7QZr8teIc6ZBI1v2AYAx0KveXyLgNKJtENyu3cwVQwcz4DianR-uGY_trsEiskd3Ns9PEHjSiPynLJKx1kQRp8KSy7hjOHHef1Hg6w769Bkgordresw98z2Wepd4Xycn1bYJbW_Wz7EmWYJ-wCnp1G7YKloa1o-9m-IFJrgK1J?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hG4ymYuSoz1_0jPiHAlbyw8gCesauUEEpfEoSIv92wR4KRZEl2yHn5KwdG2xEaYd1UWnhuUlBiYIpvT77k6oO-mmdI2xQZF08hBOIISAhj7qt-NRgA2utUPKExf3CRpwKjUJHtCjbh1ee0SZ6Zf3-DVJQcUQTXLKOOColKltVr04iOLZ9P59g2x9Om26g_Fu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MUptweQUpigwlyykeGheaQqav3gIwNYiexBMIjzGktnQX_O0pNIn029rMtUCxLJ4Sz67TzMwKd1qWZhdCZjLRn0HKgG4AvMxZe0_1ebMKhN4-Rj-UNTjT7mQfMGFgjt4AWRTfWP_wh-XE2q4nz3Qu0jgP0TK_-li6f3GlaJAzVx_qBOMhvQ5YBZZ7B7XBSFF?purpose=fullsize)

## 1. What Is the Findings Section?

The **Findings** section is the **"meat"** of a penetration-testing report.

This is where we:

- Show what we discovered.
    
- Explain how we exploited it.
    
- Explain the security impact.
    
- Identify affected systems.
    
- Provide evidence.
    
- Give the client guidance on remediation.
    

The more detail we provide in each finding, the better.

A well-written finding allows the client's technical teams to:

1. Understand the vulnerability.
    
2. Reproduce the finding.
    
3. Validate the vulnerability themselves.
    
4. Test whether their remediation actually worked.
    
5. Perform future post-remediation testing.
    

---

# 🔥 2. Most Important Principle

> **Every finding should be customized to the client's environment.**

Many penetration-testing firms maintain a database of **"stock" findings**.

These are useful as a starting point, but they should **never simply be copied unchanged** into the final report.

### Why?

The same vulnerability can have very different risk depending on where it exists.

For example:

```text
Default Credentials
        │
        ├── Printer
        │      ↓
        │   Lower impact
        │
        ├── HVAC Control
        │      ↓
        │   Potential physical impact
        │
        └── Critical Web Application
               ↓
           Potentially severe impact
```

Therefore, the finding must describe the **specific circumstances discovered during the assessment**.

---

# 3. Breakdown of a Finding

At minimum, **every finding** should contain the following information.

## ⭐ 1. Description

Explain:

- What the vulnerability is.
    
- What caused it.
    
- How it works.
    
- Which platform(s) are affected.
    

---

## ⭐ 2. Impact

Explain:

> **What happens if the finding is left unresolved?**

Don't simply say:

> "This is a critical vulnerability."

Explain what an attacker could actually accomplish.

Examples:

- Unauthorized access
    
- Credential theft
    
- Remote code execution
    
- Privilege escalation
    
- Lateral movement
    
- Sensitive data exposure
    
- Domain compromise
    

---

## ⭐ 3. Affected Systems

Identify exactly what is affected.

This could be:

- Host
    
- IP address
    
- Network
    
- Domain
    
- Application
    
- Server
    
- Cloud environment
    
- Specific account
    
- Entire environment
    

---

## ⭐ 4. Recommendation

Explain:

> **How should the client fix the problem?**

The recommendation should be:

- Specific
    
- Actionable
    
- Realistic
    
- Appropriate for the environment
    

---

## ⭐ 5. Reference Links

Provide useful external references for:

- Understanding the vulnerability.
    
- Understanding the root cause.
    
- Remediation.
    
- Workarounds.
    
- Mitigation.
    

---

## ⭐ 6. Reproduction Steps + Evidence

Show:

- How the vulnerability was discovered.
    
- How it was reproduced.
    
- What commands/tools were used.
    
- What evidence proves the issue.
    

---

# 🧠 4. Basic Finding Structure

A good finding can be remembered as:

```text
┌──────────────────────────────┐
│          FINDING             │
├──────────────────────────────┤
│ Description                  │
│ Impact                       │
│ Affected Systems             │
│ Recommendation              │
│ References                  │
│ Reproduction Steps           │
│ Evidence                     │
└──────────────────────────────┘
```

### Easy memory:

> **D-I-A-R-R-E**

**D**escription  
**I**mpact  
**A**ffected Systems  
**R**ecommendation  
**R**eferences  
**E**vidence/Reproduction

---

# 5. Optional Finding Fields

Additional information can be included when appropriate.

### Optional fields include:

- **CVE**
    
- **OWASP ID**
    
- **MITRE ID**
    
- **CVSS or similar score**
    
- Ease of exploitation
    
- Probability of attack
    
- Other information useful for understanding or mitigating the attack
    

---

# 📊 6. Example Finding Template

A professional finding could look like:

```text
Finding Title:
Weak Kerberos Authentication

Severity:
High

CVSS:
9.5

Affected Systems:
INLANEFREIGHT.LOCAL

Description:
[Explain exactly what was discovered and why it exists.]

Impact:
[Explain what an attacker could accomplish.]

Evidence:
[Commands / screenshots / output]

Reproduction:
[Step-by-step reproduction procedure]

Recommendation:
[Specific remediation steps]

References:
[Relevant authoritative resources]
```

The exact formatting can vary. What matters most is that the information is easy for the reader to understand and act upon.

---

# 7. Showing Reproduction Steps Adequately

This is one of the most important sections.

Never assume that the reader:

- Knows the tool you used.
    
- Understands the tool's output.
    
- Knows penetration-testing methodology.
    
- Understands what is important in a screenshot.
    
- Can fill in missing steps themselves.
    

Even a technically knowledgeable point-of-contact may have never used the specific tool involved in the attack.

---

# 7.1 Break Each Step Into Its Own Figure

If an attack has several steps:

❌ Don't put everything into one huge screenshot.

Instead:

```text
Figure 1
↓
Initial configuration

Figure 2
↓
Exploit execution

Figure 3
↓
Successful exploitation

Figure 4
↓
Impact / proof
```

This makes the process much easier to reproduce.

---

# 7.2 Capture Full Configuration

If setup is required, show the complete configuration.

For example, with a Metasploit module:

### Figure 1

Show:

- Module
    
- Target
    
- Options
    
- Payload
    
- Configuration
    

### Figure 2

Show:

- Exploit execution
    
- Result
    
- Evidence of success
    

This lets the reader understand exactly how the test was performed.

---

# 7.3 Explain Between Figures

Don't create:

```text
Screenshot
Screenshot
Screenshot
Screenshot
```

with no explanation.

Instead:

```text
Explanation
↓
Figure
↓
Explanation
↓
Figure
↓
Explanation
↓
Figure
```

The narrative should explain:

- What is happening.
    
- Why the tester performed that step.
    
- What the result means.
    
- What the next step is.
    

The module specifically recommends using narrative **between figures**, rather than trying to explain everything inside captions.

---

# 8. Alternative Tools

After demonstrating the vulnerability with your preferred toolkit, you can mention alternative tools that can validate the finding.

### Important:

You don't need to perform the same exploit twice.

Instead:

```text
Primary Tool
     ↓
Demonstrate Finding
     ↓
Alternative Tool
     ↓
Reference Link
```

This is useful because the client's team may use different tooling.

---

# 9. Evidence Must Be Understandable and Actionable

The primary objective is:

> **Present evidence in a way that is understandable and actionable to the client.**

Always think:

> **How will the client use this evidence?**

For example, if demonstrating a web vulnerability using a custom HTTP request, a screenshot of Burp Suite may not be the best evidence.

The client may need to:

- Copy the request.
    
- Copy the payload.
    
- Reproduce the vulnerability.
    
- Validate the fix.
    

A screenshot alone may prevent them from easily doing this.

---

# 🔎 10. Evidence Must Be Defensible

This is extremely important.

Your evidence should leave little room for argument about whether the vulnerability actually exists.

### Example — Cleartext Credentials

Suppose you want to demonstrate that credentials are transmitted in cleartext.

A screenshot of the login popup is **not sufficient**.

It only proves that:

> Basic Authentication exists.

It doesn't prove that the credentials are transmitted in cleartext.

### Better evidence:

```text
Fake Credentials
       ↓
Authentication Request
       ↓
Wireshark Capture
       ↓
Human-readable credentials
```

This provides much stronger evidence.

---

# 11. Prove That the Evidence Belongs to the Client

If demonstrating a vulnerability through:

- Web application
    
- RDP
    
- GUI
    
- Browser
    

make sure the evidence identifies the actual client environment.

### Useful evidence:

For a web application:

- URL in the address bar.
    

For a system:

```bash
ifconfig
```

or:

```cmd
ipconfig
```

This helps prove that the screenshot is from the client's environment rather than an unrelated system or image.

---

# 12. Keep Screenshots Professional

When taking browser screenshots:

### Recommended:

- Hide the bookmarks bar.
    
- Disable unnecessary browser extensions.
    
- Use a dedicated testing browser when possible.
    
- Ensure the relevant URL is visible.
    
- Make sure important information is readable.
    

Your evidence should look like professional assessment evidence, not a random desktop screenshot.

---

# 🔐 13. Redact Sensitive Information

Reports may be distributed to many audiences.

Therefore, credentials should generally be **redacted wherever possible**.

The module's example involving:

- Responder
    
- NTLMv2 hash
    
- Hashcat
    

shows hashes and cleartext passwords being redacted.

### Remember:

```text
Evidence
   ↓
Useful to prove vulnerability
   ↓
But avoid unnecessary secrets
```

---

# 14. Effective Remediation Recommendations

A recommendation should not be vague.

### ❌ Bad

> Reconfigure your registry settings to harden against X.

This forces the client to figure out:

- Which registry key?
    
- Which value?
    
- What should it be changed to?
    
- What systems are affected?
    
- What risks exist when making the change?
    

### ✅ Good

Provide:

- Full registry path.
    
- Current setting.
    
- Required setting.
    
- Relevant values.
    
- Warning/caution where appropriate.
    
- Testing recommendation.
    

The module emphasizes being **as specific as reasonably possible**.

---

# ⚠️ 15. Remediation Should Include Appropriate Warnings

Some remediation actions can introduce their own risks.

For example:

> Registry modifications should be approached with caution and tested on a small group before large-scale deployment.

This demonstrates that the tester understands:

- Operational risk.
    
- Change-management concerns.
    
- Potential unintended consequences.
    

---

# 16. Don't Force an Expensive Solution

A remediation recommendation should not simply say:

> "Buy this expensive commercial tool."

### Why?

The client may:

- Not have the budget.
    
- Have existing controls.
    
- Need an interim solution.
    
- Prefer configuration changes.
    
- Need a temporary workaround.
    

The module recommends giving the client **multiple approaches where possible**.

### Better structure:

```text
Option 1
↓
Vendor-supported workaround

Option 2
↓
Configuration change

Option 3
↓
Commercial solution
```

This gives the client choices.

---

# ⭐ 17. Generic Remediation vs Vendor-Specific Tools

The example findings should generally provide:

> **Generic remediation advice**

rather than recommending a specific vendor tool.

For example:

❌

> Purchase Vendor X's expensive security product.

Better:

> Restrict access to the vulnerable functionality and change the affected credentials.

If an affected software vendor provides an official workaround, that can be referenced as one possible remediation path.

---

# 📚 18. Selecting Quality References

Each finding should contain one or more external references.

The references should help the reader:

- Understand the vulnerability.
    
- Understand the attack.
    
- Understand remediation.
    
- Learn about mitigation/workarounds.
    

---

# 18.1 Vendor-Agnostic References

A **vendor-agnostic source** is often useful.

For example:

If the vulnerability is specific to Cisco ASA, a Cisco reference may be appropriate.

But for a general security concept, relying entirely on a vendor's marketing material isn't ideal.

The client generally wants:

> **How to understand and fix the problem**

rather than:

> **Why they should buy a particular product.**

---

# 18.2 Good References Should Be:

### ✅ Thorough

Explain:

- The vulnerability.
    
- The impact.
    
- Mitigation.
    
- Workarounds.
    

### ✅ Accessible

Avoid:

- Paywalls.
    
- Sources where only part of the information is available.
    

### ✅ Concise

The reader should be able to quickly reach useful information.

### ✅ Professional

Avoid websites overloaded with:

- Advertisements.
    
- Suspicious scripts.
    
- Poor formatting.
    

### ✅ Stable

Prefer reputable sources that are likely to remain available.

---

# 19. Writing Your Own Reference Material

The module also suggests that security professionals can create their own:

- Technical articles.
    
- Blog posts.
    
- Explanations.
    
- Remediation guides.
    

Researching the topic yourself can help you:

- Better understand the vulnerability.
    
- Explain the impact to the client.
    
- Answer questions during report review.
    
- Improve future assessments.
    

---

# 20. Example Finding — Weak Kerberos Authentication

One example in the module is:

> **Weak Kerberos Authentication ("Kerberoasting")**

The example finding demonstrates the important components:

- Finding title.
    
- Severity.
    
- CVSS.
    
- Affected environment.
    
- Detailed description.
    
- Impact.
    
- Remediation.
    
- References.
    

The example uses:

```text
INLANEFREIGHT.LOCAL
```

as the affected environment.

The example also demonstrates remediation such as:

- Addressing vulnerable SPN accounts.
    
- Using stronger service-account approaches such as gMSA where appropriate.
    

---

# 21. Example Finding — Tomcat Manager Weak/Default Credentials

Another example is:

> **Tomcat Manager Weak/Default Credentials**

The example demonstrates:

- High-risk severity.
    
- CVSS score.
    
- Affected host.
    
- Description.
    
- Impact.
    
- Remediation.
    

The remediation includes approaches such as:

- Restricting access.
    
- Changing default/weak credentials.
    

---

# ❌ 22. Poorly Written Finding

The module provides an example of a poorly written finding.

Common problems include:

### 1. Sloppy formatting

For example, poorly formatted reference/CWE information.

### 2. Missing CVSS

If the report template includes a CVSS field, leaving it blank is poor practice.

> CVSS is not necessarily mandatory, but if your template uses it, fill it in.

### 3. Weak Description

The description doesn't clearly explain:

- What the issue is.
    
- What caused it.
    
- Why it exists.
    

### 4. Vague Impact

Statements like:

> "This could be dangerous."

are not useful.

### 5. Poor Remediation

The remediation doesn't provide clear, actionable steps.

---

# 🧠 23. The Reader's Perspective

Imagine a client reading your finding.

They see:

```text
Severity: 🔴 HIGH
```

Their next questions are:

> **Why do I care?**

and:

> **What do I do about it?**

A good finding answers both.

The finding should educate the reader about the issue even if they have never heard of the attack technique.

For example, they may never have heard of:

> **Kerberoasting**

Therefore, don't simply write the word and expect them to understand it.

Explain:

- What it is.
    
- Why it matters.
    
- What happened in their environment.
    
- How it can be abused.
    
- How to fix it.
    

---

# 📐 24. Finding Formatting

There isn't only one correct formatting style.

The module's examples use a:

> **Tabular format**

But another valid approach is:

```text
Finding Title
     ↓
Description
     ↓
Impact
     ↓
Affected Systems
     ↓
Evidence
     ↓
Recommendation
     ↓
References
```

using different heading levels.

### The important principle:

> **Readability is paramount.**

The exact:

- Colors
    
- Layout
    
- Order
    
- Section names
    

can be adjusted as long as the reader can easily understand where one finding ends and another begins.

---

# 🎯 25. Finding Writing Formula

Use this formula when writing your own CPTS reports:

```text
WHAT?
↓
Describe the vulnerability.

WHERE?
↓
Identify affected systems.

WHY?
↓
Explain why the vulnerability exists.

IMPACT?
↓
Explain what an attacker can accomplish.

PROOF?
↓
Provide reproducible evidence.

HOW TO FIX?
↓
Provide actionable remediation.

LEARN MORE?
↓
Provide quality references.
```

---

# 🔥 26. What Makes a Finding "Good"?

A good finding is:

### Specific

It describes the actual client environment.

### Reproducible

Another technical person can follow your steps.

### Defensible

The evidence clearly proves the claim.

### Actionable

The client knows what to do next.

### Educational

The client understands why the issue matters.

### Professional

The formatting and language are clear.

### Practical

The recommendation considers realistic remediation options.

---

# 🚨 27. Common Finding-Writing Mistakes

Avoid these:

|Mistake|Problem|
|---|---|
|Copying stock findings unchanged|May misrepresent the client's environment|
|Huge screenshots|Difficult to understand|
|No explanation between figures|Reader doesn't know what happened|
|Screenshot-only HTTP evidence|Payload can't easily be copied|
|Vague impact|Client doesn't understand risk|
|Vague remediation|Client doesn't know how to fix it|
|Expensive vendor-only solution|May be unaffordable|
|Poor references|Doesn't help remediation|
|Exposing credentials|Unnecessary sensitive-data exposure|
|Unclear affected hosts|Client can't determine scope|
|Assuming technical knowledge|Reader may not understand the attack|
|Overly complex formatting|Reduces readability|

---

# 🛡️ 28. Evidence Checklist

Before finalizing evidence, ask:

### Does it prove the vulnerability?

```text
YES / NO
```

### Does it prove that it occurred on the client's system?

```text
YES / NO
```

### Can the client reproduce it?

```text
YES / NO
```

### Can the client understand it?

```text
YES / NO
```

### Is sensitive information redacted?

```text
YES / NO
```

### Is the evidence professional?

```text
YES / NO
```

### Is the evidence defensible?

```text
YES / NO
```

---

# 🧩 29. Professional Evidence Workflow

```text
Discover Vulnerability
        ↓
Validate Vulnerability
        ↓
Capture Evidence
        ↓
Redact Sensitive Information
        ↓
Explain Evidence
        ↓
Provide Reproduction Steps
        ↓
Provide Remediation
        ↓
Provide References
```

---

# 📝 30. Practical CPTS Finding Template

Use this structure when writing your own penetration-testing findings:

```text
==================================================
FINDING #01 — [VULNERABILITY NAME]
==================================================

Severity:
[Critical / High / Medium / Low / Informational]

CVSS:
[Score, if applicable]

CVE:
[CVE-ID, if applicable]

Affected Systems:
[IP / Host / Domain / Application]

Description:
[Explain what was discovered, the root cause,
and how the vulnerability works.]

Impact:
[Explain what an attacker could accomplish
if the vulnerability remains unresolved.]

Evidence:
[Commands, screenshots, output, requests,
responses, logs, etc.]

Reproduction Steps:
1. [Step]
2. [Step]
3. [Step]
4. [Result]

Recommendation:
[Specific, actionable remediation.]

Alternative Mitigation:
[Temporary workaround, if applicable.]

References:
1. [Reference]
2. [Reference]
```

---

# 🧠 31. CPTS Exam Memory — Finding Components

### Mandatory core information:

```text
DESCRIPTION
+
IMPACT
+
AFFECTED SYSTEMS
+
RECOMMENDATION
+
REFERENCES
+
REPRODUCTION / EVIDENCE
```

### Optional:

```text
CVE
OWASP ID
MITRE ID
CVSS
Ease of Exploitation
Probability of Attack
Additional Mitigation Information
```

---

# ⚡ 32. Quick Revision — Evidence

Remember:

> **One step = One figure**

> **Configuration = Show it**

> **Exploit = Show it**

> **Explain between figures**

> **Don't rely on captions to explain everything**

> **Make evidence reproducible**

> **Make evidence defensible**

> **Redact credentials**

> **Prove the evidence belongs to the client**

> **Offer alternative tools where useful**

---

# ⚡ 33. Quick Revision — Remediation

Remember:

### ❌ Don't say:

> "Harden the system."

### ✅ Explain:

- What needs to change.
    
- Where it needs to change.
    
- What value/configuration should be used.
    
- Any relevant warnings.
    
- How to safely test the change.
    

The module's key principle is:

> **Do your homework and be as specific as reasonably possible.**

---

# ⚡ 34. Quick Revision — References

Good references should be:

```text
Relevant
   ↓
Accurate
   ↓
Accessible
   ↓
Concise
   ↓
Professional
   ↓
Stable
```

Avoid:

- Paywalled resources.
    
- Excessively long documents when a concise explanation exists.
    
- Poor-quality websites.
    
- References that primarily exist to sell a vendor product.
    

---

# 🛠️ 35. WriteHat

The module provides hands-on practice using:

> **WriteHat**

WriteHat is a report-writing tool developed by **Black Lantern Security**.

It can be used for:

- Building a findings database.
    
- Adding findings.
    
- Generating reports.
    
- Customizing reports.
    
- Practicing report-writing workflows.
    

The module recommends experimenting with the tool to understand how reporting tools work.

### Important

Anything entered into the practice instance is not saved after the target expires.

Therefore, save your practice findings locally if you want to keep them.

---

# 🏆 36. Final CPTS Takeaway

The purpose of a finding isn't simply to say:

> **"I found a vulnerability."**

A professional finding tells the client:

```text
WHAT
↓
What is wrong?

WHERE
↓
Where does it exist?

WHY
↓
Why does it exist?

IMPACT
↓
What can an attacker do?

PROOF
↓
How do we know?

REPRODUCTION
↓
How can the technical team validate it?

REMEDIATION
↓
How can we fix it?

REFERENCES
↓
Where can we learn more?
```

The strongest finding is therefore:

> **Detailed enough to reproduce, clear enough to understand, defensible enough to prove, and actionable enough to remediate.**

That is the core skill this module is teaching.