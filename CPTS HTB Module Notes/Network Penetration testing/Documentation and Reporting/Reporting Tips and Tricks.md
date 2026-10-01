![Image](https://images.openai.com/static-rsc-4/gpoqFSj9gPVHKmR66SH5P8J0UFa6rsjn9NVjvdSUxD2_kgYSGNtoaP5lXFk4VIu4dQ2L10mQ1y7btkjWT1qq7n0T_xzib5B_pvS0siCmUuI4YChVBb_PdEIQ79zWn5PRQjNE4RKWvmCYVG_v0eqKFJ_qjvZx0eDLbGwmgGwbvFkyfbAMXXoUSiCn46vKEPpF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VwaaOOul2ONdogFl6azfnziZ_5q-ebOERxm2Sz1dw1PLs84tGwDBjNmTrpxQxAsIevSxXZFDt_GriS93iTuh9u8674EitArKpVIX-jWc051SkuuP3i01Ro6bXEGrGmCeqJdES2NO2fJ17d9o6w3YkbHEKy0-4214el5K7gjuFcVqg1LJnD6hALf_RONJa1-d?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/x3LP9iPIf_G_Cf1z-RTwqR02vaEzkhw-6OahAuldVbFiBnEVFZzAXNqgr11LFIK6UXsGsUWIT1cdZfFpwV5QNRyYbK4NEkuLZXemKaFRrxIu_D7XoLacR-zxHTO8HMHdJScVEzcdJuRJMsQLQzWttqNP9g1AsFsIMjdhzMFcegihsEFQgJEkon4lvmyjBGhA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/N6L5IgMp-kor1TXO2Y9I0EWuXE8Ef02cdTY1n5d_IYPevpziQxYUL0JopdyeNSSUXwxYD_WiQEE9I7ZoxjvO-FdjfPjSzvWoC56wFAqxZxaj9CrcYXv0_CLYZzEVO9gper-mNevEKkP8QKfo0uLAuq1ZE9UZXcdSkFfAlzqHIYVaNH1SGETGzzxgDOfTjAY8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/783AaqfjYVsPgqWtT61WZEfpy0kd9Uw6Em_Z6Lo-KoHQu8quhXBiPFXET1PrAOcNDUI1LLxljTR3IZM5u1XdCjuYn62UaOXe1GF0Ju7SwJwLLko60qUTnwylJRc4wwbGWgR8L-hSduYz0MffHdeIKzoIRcJTojiPQ1IW1kW_IwS3musYC4feYHCmXm-03UzK?purpose=fullsize)
## 1. Why Reporting Matters

**Reporting is an essential part of the penetration testing process.**

If reporting is poorly managed, it can become:

- Tedious
    
- Time-consuming
    
- Prone to mistakes
    
- Difficult to QA
    
- Difficult to reproduce or defend later
    

### ⭐ Golden Rule

> **Start building the report from the onset of the assessment.**

Do **not** wait until the last day.

While testing, you should already be:

- Taking organized notes.
    
- Recording evidence.
    
- Building the Attack Chain.
    
- Writing findings.
    
- Capturing screenshots.
    
- Recording commands/output.
    
- Filling in report information.
    

For example, while a long discovery scan is running, you can work on:

- Client name
    
- Contact information
    
- Scope
    
- Assessment dates
    
- Report template
    
- Other administrative information
    

This prevents you from having to scramble to recapture evidence after the assessment is finished.

---

# 🔥 2. Write as You Go

This is one of the **most important lessons in the entire module**.

```text
START ASSESSMENT
      ↓
Take Notes
      ↓
Capture Evidence
      ↓
Document Findings
      ↓
Build Attack Chain
      ↓
Draft Report
      ↓
QA
      ↓
FINAL REPORT
```

### ❌ Bad workflow

```text
Pentest
   ↓
Pentest
   ↓
Pentest
   ↓
Pentest
   ↓
"Now I'll write the report."
   ↓
😨 Missing evidence
😨 Missing commands
😨 Missing screenshots
😨 Forgotten details
```

### ✅ Good workflow

```text
Pentest
  ↘
   Notes
    ↘
     Evidence
      ↘
       Finding
        ↘
         Report
```

Working continuously ensures the report isn't rushed and reduces the amount of QA corrections later.

---

# 3. Templates

Don't recreate the report from scratch every time.

Maintain a:

> **Blank report template for every assessment type.**

Examples:

- Internal Penetration Test
    
- External Penetration Test
    
- Web Application Assessment
    
- Vulnerability Assessment
    
- Red Team Assessment
    
- Other specialized assessments
    

Even uncommon assessment types should have templates where practical.

---

# ⚠️ 4. NEVER Reuse an Old Client's Report Directly

This is extremely important.

### ❌ Bad practice

```text
Client A Report
      ↓
Copy
      ↓
Client B Report
```

Why?

You could accidentally leave:

- Previous client's name
    
- Previous client's IP addresses
    
- Previous client's findings
    
- Previous scope
    
- Previous environment information
    
- Other confidential data
    

This is:

- Unprofessional
    
- Potentially a security/privacy issue
    
- Easily avoidable
    

### ✅ Better

```text
Blank Template
      ↓
New Client Information
      ↓
New Assessment
```

---

# 📝 5. Microsoft Word Tips & Tricks

The module focuses heavily on Microsoft Word because it remains widely used for professional reporting.

The tips are primarily for:

> **Microsoft Word for Windows**

The module specifically notes that Word for Mac lacks some features useful for professional reporting and PDF generation.

---

# 6. Font Styles

Avoid excessive:

> **Direct Formatting**

Direct formatting means manually selecting text and repeatedly applying:

- Bold
    
- Italics
    
- Underline
    
- Color
    
- Highlighting
    
- Font changes
    

Instead, use:

> **Font Styles**

### Why?

Suppose you have 45 headings.

If you manually formatted each one and later decide the heading style should change:

❌ You have to edit all 45.

With styles:

```text
Modify Heading Style
       ↓
Every Heading Updates
```

This greatly improves consistency and efficiency.

---

# 7. Table Styles

Use:

> **Table Styles**

for the same reason you use font styles.

Benefits:

- Consistency
    
- Easy global changes
    
- Professional appearance
    
- Easier QA
    
- Easier maintenance
    

---

# 8. Captions

Use Word's built-in:

> **Insert Caption**

feature for:

- Images
    
- Tables
    
- Figures
    

### Why?

If you manually number:

```text
Figure 1
Figure 2
Figure 3
Figure 4
```

and later insert a new figure at the beginning, everything may need to be renumbered manually.

With Word captions:

```text
Insert Figure
      ↓
Automatic Numbering
      ↓
Add/Delete Figure
      ↓
Numbers Update
```

This is a **huge time saver**.

---

# 9. Page Numbers

Page numbers are important in professional reports.

They make communication easier.

For example:

> "Please look at the second paragraph on page 12."

This is much easier than:

> "Go somewhere near the middle of the report and look for the section about..."

Page numbers also help clients internally reference findings.

---

# 10. Table of Contents

A:

> **Table of Contents (ToC)**

is a standard component of a professional report.

It helps readers quickly navigate:

- Executive Summary
    
- Attack Chain
    
- Findings
    
- Recommendations
    
- Appendices
    

---

# 11. List of Figures / Tables

A:

> **List of Figures**

or:

> **List of Tables**

can be useful in larger reports.

These depend on properly configured captions.

For example:

```text
List of Figures

Figure 1 — Attack Chain
Figure 2 — Network Enumeration
Figure 3 — Kerberoasting Evidence
Figure 4 — Domain Compromise
```

---

# 12. Bookmarks

Word:

> **Bookmarks**

can be used to designate locations inside a document.

They are useful for:

- Hyperlinks
    
- Appendices
    
- Internal navigation
    
- Automated report generation
    

They can also be useful with macros to identify sections that can be automatically removed depending on assessment type.

---

# 13. Custom Dictionary

A custom dictionary can help prevent recurring spelling mistakes.

For example, if you repeatedly mistype a technical term, you can add it to your dictionary.

This can also help prevent embarrassing typos.

---

# 14. Language Settings

Language settings are particularly useful for:

> **Code / terminal evidence**

You can configure the relevant style so Word doesn't constantly flag command output as spelling errors.

This becomes extremely useful when a report contains many screenshots or terminal outputs.

---

# 15. Custom Bullet / Numbering

Custom numbering can automatically number:

- Findings
    
- Appendices
    
- Sections
    
- Other report elements
    

Example:

```text
Finding 1
Finding 2
Finding 3
...
```

Instead of manually changing every number when findings are added or removed.

---

# ⌨️ 16. Useful Microsoft Word Hotkeys

These are worth remembering.

|Shortcut|Function|
|---|---|
|`F4`|Repeat the last action|
|`Ctrl + A`|Select all|
|`F9`|Update fields / ToC / lists|
|`Ctrl + S`|Save|
|`Ctrl + Alt + S`|Split document window|
|`Shift + F5`|Return to the last editing location|

### ⭐ Important

`Ctrl + A` followed by `F9` can update:

- Table of Contents
    
- List of Figures
    
- List of Tables
    
- Other document fields
    

Use with care because updating all fields can sometimes have unexpected effects.

---

# 🤖 17. Automation

When report templates become mature, you can automate repetitive work.

Microsoft Word supports:

> **Macros**

For macro-enabled templates, use:

```text
.dotm
```

files.

The module notes that Windows provides the most useful environment for this workflow.

---

# 18. What Can Be Automated?

A macro can ask for:

```text
Client Name
     ↓
Assessment Dates
     ↓
Scope
     ↓
Testing Type
     ↓
Environment/Application
```

and automatically insert those values into designated placeholders.

---

# 19. One Template → Multiple Report Types

Macros can also combine multiple report templates into a single master template.

Bookmarks can identify sections that should be removed.

For example:

```text
MASTER TEMPLATE
│
├── Internal PT
├── External PT
├── Web Assessment
├── Red Team
└── Vulnerability Assessment
```

The macro can remove irrelevant sections depending on the engagement.

### Benefit

You only need to maintain one master template instead of constantly maintaining multiple versions.

---

# 20. Automated QA

Macros can also help automate repetitive:

> **Quality Assurance tasks**

For example:

- Detect recurring formatting mistakes.
    
- Correct common issues.
    
- Standardize information.
    

The module notes that advanced Word macro development is essentially programming in its own right.

---

# 🗃️ 21. Reporting Tools / Findings Database

After completing multiple assessments, you'll notice that many clients have similar problems.

Examples:

- Weak passwords
    
- Default credentials
    
- Missing patches
    
- Insecure configurations
    
- Excessive privileges
    
- Weak Kerberos configurations
    

If you rewrite every finding from scratch:

```text
Assessment 1 → Write Finding
Assessment 2 → Rewrite Finding
Assessment 3 → Rewrite Finding
Assessment 4 → Rewrite Finding
```

you waste time and increase inconsistency.

---

# 22. Findings Database

Maintain a database containing:

> **Sanitized versions of findings**

These can serve as starting points.

### Important:

The finding should still be:

> **Customized to the client's environment.**

So:

```text
Finding Template
       ↓
Customize
       ↓
Client Environment
       ↓
Final Finding
```

Never blindly copy a stock finding.

---

# 23. Why Findings Databases Matter

Without one:

- More time is wasted.
    
- Recommendations become inconsistent.
    
- Finding descriptions vary.
    
- Different consultants produce different-quality reports.
    

A findings database promotes:

- Efficiency
    
- Consistency
    
- Quality
    
- Standardization
    

---

# 24. Reporting Tools Mentioned

The module lists several tools.

### Free

- **Ghostwriter**
    
- **Dradis**
    
- **Security Risk Advisors VECTR**
    
- **WriteHat**
    

### Paid

- **AttackForge**
    
- **PlexTrac**
    
- **Rootshell Prism**
    

These tools can help with:

- Findings databases
    
- Report generation
    
- Workflow management
    
- Consistency
    
- Collaboration
    

---

# 📖 25. Miscellaneous Reporting Tips

This section contains many of the most practical lessons.

---

## ⭐ Tip 1 — Tell a Story

Your report should tell the story of the assessment.

Don't simply say:

> "Kerberoasting was possible."

Explain:

```text
Initial Access
      ↓
Credential Discovery
      ↓
Kerberoasting
      ↓
Password Cracking
      ↓
Privilege Escalation
      ↓
Domain Compromise
```

Explain:

> **Why does this matter?**

and:

> **What was the impact?**

---

# ⭐ 26. Write as You Go

Again:

> **Don't leave reporting until the end.**

Your report doesn't have to be perfect while you're testing.

But document:

- What happened
    
- When it happened
    
- Commands
    
- Evidence
    
- Findings
    
- Failed attempts
    
- Important observations
    

This prevents missing important details when you're rushing at the end.

---

# ⭐ 27. Stay Organized

Keep notes:

> **Chronological**

and:

> **Easy to navigate.**

A good note-taking system should make reporting easier, not create more work.

---

# ⭐ 28. Evidence — Enough, But Not Too Much

You need enough evidence to:

- Demonstrate the vulnerability.
    
- Explain what happened.
    
- Reproduce the issue.
    

But don't include:

- Hundreds of unnecessary screenshots.
    
- Entire command histories.
    
- Irrelevant output.
    

### Golden balance:

```text
Too Little
   ↓
Cannot Prove Finding

Too Much
   ↓
Report Becomes Cluttered

Correct Amount
   ↓
Clear + Reproducible + Professional
```

---

# 🖼️ 29. Clearly Mark Important Screenshot Information

A screenshot should immediately communicate:

> **"Look here."**

Use tools such as:

> **Greenshot**

to add:

- Arrows
    
- Boxes
    
- Highlights
    
- Explanations
    

### Bad

A screenshot containing 50 lines where the reader must guess what matters.

### Good

```text
┌───────────────────────────────┐
│ Command                       │
│                               │
│      ┌───────────────┐        │
│      │ IMPORTANT     │ ←      │
│      │ OUTPUT        │        │
│      └───────────────┘        │
└───────────────────────────────┘
```

---

# 🔐 30. Redact Sensitive Data

Always consider redacting:

- Cleartext passwords
    
- Password hashes
    
- API keys
    
- Tokens
    
- Secrets
    
- Other sensitive client data
    

Reports may be:

- Shared internally.
    
- Sent to management.
    
- Sent to auditors.
    
- Shared with third parties.
    

Therefore, don't unnecessarily expose secrets.

---

# ⚠️ 31. Solid Shapes vs Blurring

The module specifically recommends using:

> **Solid shapes**

rather than simple blur when obscuring sensitive information in screenshots.

For example:

```text
PASSWORD: █████████████
```

rather than:

```text
PASSWORD: [blurred text]
```

This helps prevent sensitive information from potentially being recovered from the image.

---

# 32. Clean Up Unprofessional Tool Output

Some tools produce output that isn't appropriate for a professional client report.

For example:

```text
(Pwn3d!)
```

The module suggests customizing tool output where possible so the report remains professional.

### Important distinction

You should **not falsify evidence**.

The idea is to remove unnecessary offensive/unprofessional presentation elements while preserving the actual representation of the finding.

---

# 33. Hashcat Output

Be careful with:

> **Hashcat output**

Some wordlists contain offensive or crude words.

If those appear in candidate-password output, they may be inappropriate for the final report.

The module says it can be acceptable to replace offensive/unprofessional content when the underlying evidence remains accurately represented.

When uncertain:

> **Ask a manager or team lead.**

---

# ✍️ 34. Grammar, Spelling & Formatting

Always check:

- Grammar
    
- Spelling
    
- Formatting
    
- Font consistency
    
- Font sizes
    
- Acronyms
    

### Acronym rule

Spell out an acronym the first time it appears.

Example:

> **Remote Desktop Protocol (RDP)**

Then:

> RDP

later in the report.

---

# 🖥️ 35. Screenshot Quality

Screenshots should be:

- Clear
    
- Focused
    
- Relevant
    
- Properly cropped
    
- Easy to read
    

Avoid capturing:

- Entire desktops unnecessarily.
    
- Unrelated applications.
    
- Huge empty spaces.
    
- Background clutter.
    

Poor screenshots increase report size and reduce readability.

---

# 💻 36. Terminal Evidence

Prefer:

> **Raw command output**

where possible.

If you must use a screenshot:

### Avoid:

- Transparent terminals
    
- Desktop backgrounds
    
- Other applications visible
    
- Crazy themes
    
- Unprofessional colors
    

### Prefer:

```text
Solid background
+
Readable text
+
Highlighted important output
```

The module also notes that reports may be printed, so a light background with dark text may sometimes be more printer-friendly.

---

# 👤 37. Keep Hostname & Username Professional

Avoid screenshots containing prompts like:

```text
azzkicker@clientsmasher
```

Use professional hostnames/usernames in assessment environments wherever appropriate.

The report is a professional deliverable.

---

# 🧪 38. QA — Quality Assurance

A report should go through:

> **At least one round of QA**

and preferably:

> **Two rounds of QA**

by reviewers other than the author.

Why?

Because authors become blind to their own mistakes after repeatedly reading the same document.

---

# 39. If You're Working Alone

If you're an independent tester and don't have another reviewer:

```text
Finish Report
     ↓
Step Away
     ↓
Sleep / Wait
     ↓
Return Later
     ↓
Review Again
```

A break gives you a fresh perspective.

---

# 📋 40. Style Guide

Teams should establish a:

> **Style Guide**

The style guide should define things such as:

- Fonts
    
- Headings
    
- Finding format
    
- Severity presentation
    
- Screenshots
    
- Captions
    
- Acronyms
    
- Tables
    
- Terminology
    
- Formatting
    

### Goal

Every consultant should produce reports that look and feel consistent.

---

# 💾 41. Autosave & Backups

Enable:

> **Autosave**

for:

- Note-taking tools
    
- Microsoft Word
    

Also:

> **Back up notes and evidence while working.**

Don't store everything on a single VM.

Why?

```text
VM Failure
   ↓
Lost Notes
   ↓
Lost Evidence
   ↓
Report Problems
```

Instead:

```text
Primary Location
      +
Secondary Backup
```

The module recommends automating this wherever possible.

---

# 🤖 42. Script and Automate Wherever Possible

Automate repetitive work.

Examples:

- Report generation
    
- Data insertion
    
- Formatting
    
- QA checks
    
- Evidence organization
    
- Backups
    
- Finding population
    

Benefits:

- Consistency
    
- Less manual work
    
- Fewer errors
    
- Faster assessments
    

---

# 📧 43. Client Communication

Strong:

> **Written and verbal communication skills**

are extremely important for penetration testers.

A pentester isn't only a technical person.

You are also acting as a:

> **Trusted Advisor**

The client is paying you to:

- Identify security issues.
    
- Explain the issues.
    
- Provide remediation guidance.
    
- Educate their staff.
    

---

# 📩 44. Start Notification

At the beginning of every engagement, send a:

> **Start Notification**

It should include:

- Tester name
    
- Engagement type
    
- Scope
    
- Testing source IP
    
- Expected testing dates
    
- Primary contact
    
- Secondary contact
    

---

# 🛑 45. Stop Notification

At the end of each day, send a:

> **Stop Notification**

This indicates that testing has ended for the day.

It can also provide:

- High-level findings summary
    
- Important observations
    
- Expected report timeline
    

This is especially useful when many high-risk findings were identified so the client isn't surprised by the final report.

---

# 46. Why Start & Stop Notifications Matter

They provide the client with a time window for:

- Scans
    
- Exploitation
    
- Testing activities
    

This helps the client's security team correlate:

```text
Pentester Activity
       ↕
SIEM Alerts
       ↕
EDR Alerts
       ↕
Network Logs
```

---

# 🚨 47. Immediately Communicate Critical Findings

If you discover something extremely serious, don't wait until the final report.

Examples:

- SQL Injection
    
- Remote Code Execution
    
- Domain compromise
    
- Other high-risk issues
    

The module advises formally notifying the client and discussing how they want you to proceed.

---

# 🌐 48. Scope Changes

Suppose you discover:

> An additional external subnet.

Don't simply start attacking it.

Discuss it with the client and determine whether they want it added to scope.

This should be:

- Reasonable
    
- Within the testing timeframe
    
- Approved appropriately
    

---

# 👑 49. Domain Admin / Enterprise Admin

If you achieve:

```text
Domain Admin
       or
Enterprise Admin
```

you should inform the client.

Why?

They may:

- See security alerts.
    
- Become concerned about an apparent compromise.
    
- Need to prepare management.
    
- Want certain systems/databases to remain untouched.
    

You can continue testing, but ask whether there are areas they want you to avoid even after obtaining privileged access.

---

# 📝 50. Detailed Notes Protect You

Suppose the client asks:

> "Did you scan 10.10.10.25 on September 30?"

You should be able to answer with evidence.

Detailed notes can help establish:

- What you did.
    
- When you did it.
    
- Which host you touched.
    
- Which commands were used.
    
- What happened.
    

This is particularly important if an outage occurs and the pentester is blamed.

Without logs:

> You may have no concrete evidence to defend yourself.

---

# 🏆 51. The Report Is Your Highlight Reel

One of the most important statements from the module:

> **"The report is your highlight reel and is honestly what the client is paying for!"**

You might perform an extremely sophisticated attack chain.

But if you can't communicate it clearly in the report:

> **It may as well have never happened.**

The client doesn't see most of your assessment activity.

The report is what communicates your work.

---

# 🔍 52. QA Process

A professional QA process should review:

### Technical accuracy

- Are findings correct?
    
- Are commands accurate?
    
- Is evidence valid?
    
- Are affected systems correct?
    
- Is severity appropriate?
    

### Presentation

- Grammar
    
- Spelling
    
- Formatting
    
- Tables
    
- Screenshots
    
- Captions
    
- Page numbers
    
- ToC
    

---

# 📋 53. QA Checklist

Include a QA checklist inside the report template.

Remove it before the final report is delivered.

Example:

```text
QA CHECKLIST
─────────────────────────────
☐ Client name correct
☐ Scope correct
☐ Dates correct
☐ Findings complete
☐ Evidence complete
☐ Screenshots readable
☐ Sensitive information redacted
☐ Severity consistent
☐ Recommendations actionable
☐ Grammar checked
☐ Spelling checked
☐ Acronyms expanded
☐ Formatting consistent
☐ ToC updated
☐ Figure numbers correct
☐ Page numbers correct
☐ Hyperlinks tested
☐ Final PDF checked
```

The checklist should evolve as the team discovers recurring mistakes.

---

# ⚠️ 54. Be Careful With Online Grammar Tools

Tools such as:

- Grammarly
    
- LanguageTool
    

can be useful.

However, some online services may send submitted text to their servers.

If your report contains:

- Confidential client information
    
- Vulnerabilities
    
- Credentials
    
- Internal IP addresses
    
- Sensitive findings
    

this could create a security or contractual issue.

### Before using cloud-based tools:

> **Check how they process and store your data and obtain appropriate approval.**

---

# 55. QA Tracking

As teams grow, QA becomes harder to track.

A small team might use:

> **Google Sheets or equivalent**

Larger teams may use:

> **Jira**

or another centralized workflow system.

You may also need a central location where reports can be stored for reviewers.

---

# 56. QA Reviewer vs Author

Ideally:

> **The QA reviewer should NOT make major changes to the report.**

Minor changes such as:

- Typos
    
- Small formatting issues
    
- Minor phrasing
    

may be corrected by the reviewer.

But the author should fix major problems such as:

- Missing findings
    
- Missing evidence
    
- Poor evidence
    
- Bad Executive Summary
    
- Incorrect technical details
    

---

# 🔄 57. Learn From QA

Use:

> **Track Changes**

when reviewing changes.

Why?

Because QA feedback shows you:

- What mistakes you're making.
    
- What needs improvement.
    
- What should be added to the checklist.
    
- What should be standardized.
    

Don't repeat the same mistakes across future reports.

---

# 📄 58. Draft vs Final Report

A common workflow is:

```text
Assessment
    ↓
Report Draft
    ↓
Internal QA
    ↓
DRAFT Report
    ↓
Client Review
    ↓
Client Feedback
    ↓
Changes
    ↓
FINAL Report
```

The client can review the draft and request:

- Clarifications
    
- Changes
    
- Questions
    
- Discussion
    

After that:

> **DRAFT → FINAL**

---

# 🗣️ 59. Report Review Meeting

After delivery, it is common to give the client approximately:

> **A week or so**

to review the report.

Then offer a:

> **Report Review Meeting**

During the meeting, discuss:

- Technical findings.
    
- How findings were discovered.
    
- Impact.
    
- Remediation.
    
- Client questions.
    

---

# 💡 60. Use Client Questions to Improve Your Reports

If clients repeatedly ask:

> "What does this mean?"

or:

> "How did you find this?"

that may indicate your report isn't explaining something clearly enough.

Use repeated questions as feedback to improve:

- Finding descriptions
    
- Evidence
    
- Recommendations
    
- Executive Summary
    
- Report structure
    

---

# 📦 61. Archive Assessment Data

Once the report is accepted:

```text
FINAL REPORT
      +
Testing Data
      +
Evidence
      +
Notes
      +
Logs
```

should be archived according to:

> **Company retention policies**

The module recommends retaining testing data at least until a retest of remediated findings has been performed, subject to applicable policies and agreements.

---

# 🧠 62. CPTS — High-Value Memory Points

## 🔥 Reporting Workflow

```text
PLAN
 ↓
TEMPLATE
 ↓
TAKE NOTES
 ↓
LOG EVERYTHING
 ↓
WRITE AS YOU GO
 ↓
CAPTURE EVIDENCE
 ↓
BUILD FINDINGS
 ↓
BUILD ATTACK CHAIN
 ↓
SELF-QA
 ↓
INTERNAL QA
 ↓
DRAFT
 ↓
CLIENT REVIEW
 ↓
FINAL
 ↓
ARCHIVE
```

---

# ⭐ 63. Top 15 Things to Remember

### 1.

> **Write as you go.**

### 2.

Use a **blank template** for each assessment type.

### 3.

Never blindly reuse another client's report.

### 4.

Use **Word Styles**, not excessive direct formatting.

### 5.

Use built-in **Captions**.

### 6.

Use a **Table of Contents**.

### 7.

Use **page numbers**.

### 8.

Maintain a **findings database**.

### 9.

Show enough evidence without cluttering the report.

### 10.

Clearly highlight what matters in screenshots.

### 11.

Redact sensitive information.

### 12.

Maintain professional tool output and screenshots.

### 13.

Perform at least one independent **QA review**.

### 14.

Communicate critical findings to the client during the engagement.

### 15.

Remember:

> **The report is your highlight reel.**

---

# 🎯 64. CPTS Quick Revision Sheet

## REPORTING

```text
Start Early
     ↓
Write as You Go
     ↓
Stay Organized
     ↓
Capture Evidence
     ↓
Tell a Story
```

## WORD

```text
Styles
Tables
Captions
Page Numbers
ToC
Bookmarks
Custom Numbering
Hotkeys
```

## EVIDENCE

```text
Enough Evidence
      +
Clear Screenshots
      +
Redaction
      +
Professional Presentation
```

## AUTOMATION

```text
Templates
   +
Macros
   +
Findings Database
   +
Reporting Tools
```

## CLIENT

```text
Start Notification
       ↓
Testing
       ↓
Stop Notification
       ↓
Critical Finding Communication
       ↓
Draft
       ↓
Review Meeting
       ↓
Final
```

## QA

```text
Technical Accuracy
+
Evidence
+
Grammar
+
Spelling
+
Formatting
+
Consistency
```

---

# 🏆 65. Final Takeaway

The central lesson of **Reporting Tips and Tricks** is:

> **Don't treat reporting as something you do after the penetration test. Reporting is part of the penetration test.**

A strong penetration tester should be able to:

```text
Find the vulnerability
        ↓
Understand the impact
        ↓
Capture defensible evidence
        ↓
Document it clearly
        ↓
Explain it to the client
        ↓
Recommend remediation
        ↓
Deliver a professional report
```

Your technical skills get you the finding.

Your documentation proves it.

Your communication makes the client understand it.

And your report is the final product that represents the quality of your entire assessment.