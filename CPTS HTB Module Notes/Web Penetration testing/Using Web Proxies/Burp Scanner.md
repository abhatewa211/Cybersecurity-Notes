![Image](https://images.openai.com/static-rsc-4/7HB6svzihQk1HdPfTiIWZDWiRvkoYSh5jipFkT4RC_0xn9IPKdrNzkMYSEDlQJLME0LZUxvyMRNHjo4RV0HdSnLrQc_-wt3upujdfRLwUEqZB2QXtPzdJXzCIbKEKu3OV0auctYmFq9ZpM7z5Ms4yG4csugVVx0e596un8t0RwkYUwKBZhEh7Iiw6kobbWpt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/z9FmGYm8taT697RYvEikyP62OMjhJx-yqljNR5YIT8W8kwNA9Je9gN7Msc_v-86j4OKcZ5UZq9s4JTHU70upJ1D2OicaEOG-zpcgSzDMX1DWa__UytKqrz10Wo4wkx3W65MDH7-gj85Vg6qiHpwIpF4xbST2fqaAQ5R2aypwz_3iiJ0ATirfQUjfSCY9qgRb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CA4aMojelsvKSPS4niG2t-5YwMTnSlDW0NBXGOiyluL_kaKpr9xGZn8O4MPdL-tkf44zJ2HEBqnBQcJEO-lSs1d4Gtq57iomxyG9ePm1xrYuwr0jQR5dJOhezo5QrlSaKIXTQTxvTpC9sJ5lA6KZXS60yEXLCMMadeYY-ZytHQOtJ7aDkja16VJU2jiqN8qR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vk5NSNSapJpQ9t-isWOkvNjBURHnfbC7r6wVlX82rXncjvZOcD03f1Lkvw15IsC91PSKEXUNe7p5Rm5IM-LMp-DyIT9Bq88EaxlZ80xZnpZMR8kjB81_st5ZI6xNHOS44mUlw_Nd_roHxj9OQdiotKeVbwgen4nTfDaugy-TNRNHH0qEkSWACx6OKtHhjv57?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bOeSF0-6P4dwPQrQWDJ7wovvy_uMMoPxyrSLsXYcfdDDKDYr6spNctarmKY4T6Yyk5idcJJUFW9BxYC6PcNC-_yHH7zwPkEDEjZMyEMxRkTCnjgHuxz6zYLhFGS-89FRJFAVdIYhXKCFFr5v5bJTEXNSpeb1DR8GDA_GyQzNwlIwTohLTy3jxM_hI1xqJiyu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iLbOnzxA2zonU2cAM-8aHd0W40W0XBLutfNPTLstKB8hHuvfoLCPCaSC-mGIGbWyZkA4RSuiP7TMeMSC3a8TzPNcxbs_m_ZKba33ISum06wx7N5cZFtNo1iHkCFoU9TfZrUI1s0guT3qYVNx1LKPI7jAiHDeRfZ95QOR-oWUKCBgcgDB_LIBH_reDziKAhWJ?purpose=fullsize)

## 1. What Is Burp Scanner?

**Burp Scanner** is Burp Suite's automated web vulnerability scanning feature.

It combines:

- **Crawler** → builds a map/structure of the web application
    
- **Passive Scanner** → analyzes requests/responses already observed
    
- **Active Scanner** → actively sends requests to test for vulnerabilities
    

### ⚠️ Important

Burp Scanner is a **Pro-only feature** and isn't available in Burp Community Edition.

The module describes it as an enterprise-level capability because of its broad coverage and advanced scanning functionality.

---

# 🗺️ 2. Big Picture

Think of Burp Scanner as a pipeline:

```text
                TARGET
                   │
                   ▼
                CRAWLER
                   │
                   ▼
             SITE STRUCTURE
                   │
          ┌────────┴────────┐
          │                 │
          ▼                 ▼
      PASSIVE             ACTIVE
       SCAN                SCAN
          │                 │
          │          Crawl + Fuzz
          │                 │
          │          Passive Scan
          │                 │
          │       Vulnerability Testing
          │                 │
          └────────┬────────┘
                   ▼
              FINDINGS
                   │
                   ▼
                REPORT
```

---

# 🎯 3. Starting a Scan

Burp provides three main ways to start scanning:

1. Scan a **specific request** from Proxy History
    
2. Start a **new scan** against a set of targets
    
3. Scan items that are already **in scope**
    

---

# 4. Scan a Specific Request

If an interesting request already exists in:

```text
Proxy → HTTP History
```

you can right-click it.

You can choose:

```text
Scan
```

to configure the scan before starting it.

Or:

```text
Passive/Active Scan
```

to quickly start scanning using the default configuration.

---

# 5. New Scan

Another option is:

```text
Dashboard → New Scan
```

This opens the scan configuration window.

You can then specify the targets and configure how Burp should scan them.

---

# 🎯 6. Target Scope

**Target Scope** determines which targets Burp should process.

This is extremely important during a real penetration test.

You don't want an automated scanner accidentally testing:

```text
Out-of-scope domain
Third-party service
Production system
Logout endpoint
Destructive functionality
```

when you're only authorized to test a specific application.

Burp's scope can be used across its features and can also allow Burp to ignore out-of-scope URLs, saving resources.

---

# 🗺️ 7. Site Map

Navigate to:

```text
Target → Site map
```

The Site Map contains directories and files Burp has discovered from traffic that passed through the proxy.

Conceptually:

```text
Target
│
├── /
├── login
├── dashboard
├── admin
├── api
│   ├── users
│   └── products
└── static
    ├── css
    └── js
```

The exact contents depend on what Burp has discovered.

---

# ➕ 8. Adding Targets to Scope

From the Site Map:

```text
Right-click target
       ↓
Add to scope
```

When the first item is added, Burp may ask whether its features should be restricted to in-scope items.

This is useful for preventing accidental interaction with targets outside your authorized scope.

---

# 🚫 9. Removing Targets From Scope

If something shouldn't be scanned:

```text
Right-click
    ↓
Remove from scope
```

You can then review the scope through:

```text
Target → Scope
```

Burp also provides advanced scope controls where regex patterns can be used to include or exclude targets.

---

# ⚠️ 10. Why Scope Is Important

Some endpoints can have side effects.

For example:

```text
/logout
/delete-account
/delete-user
/reset
/disable
```

The module specifically mentions that some items may be dangerous to scan because they could end a session, such as a logout function.

### ⭐ Pentesting principle

> **Define scope before automated scanning.**

Especially with active scanners.

---

# 🕷️ 11. Burp Crawler

Once the scope is configured:

```text
Dashboard
   ↓
New Scan
```

Burp provides two main options:

```text
Crawl
Crawl and Audit
```

---

# 12. What Does a Web Crawler Do?

A crawler navigates through a web application and discovers its structure.

It can:

- Follow links
    
- Access pages
    
- Find forms
    
- Examine requests
    
- Build an application map
    

Conceptually:

```text
             HOME
            /    \
         Login   Products
          │       /    \
       Profile  Item1  Item2
```

The goal is to create a comprehensive map of publicly accessible application content.

---

# 13. Crawl vs Crawl and Audit

This distinction is **very important**.

### Crawl

Only discovers/maps the application.

```text
Crawl
  ↓
Discover pages
  ↓
Build site map
```

### Crawl and Audit

Crawls the application and then performs vulnerability scanning.

```text
Crawl
  ↓
Build map
  ↓
Audit / Scanner
  ↓
Find vulnerabilities
```

---

# ⚠️ 14. Crawl Is NOT Directory Fuzzing

A crawler follows references it finds.

For example:

```html
<a href="/login">Login</a>
```

The crawler can discover:

```text
/login
```

But if:

```text
/admin
```

isn't referenced anywhere, a normal crawl won't necessarily discover it.

The module explicitly says Crawl does **not** perform fuzzing to find pages that aren't referenced, unlike tools such as `dirbuster` or `ffuf`.

Those resources can instead be discovered using:

- Burp Intruder
    
- Content Discovery
    

and then added to scope if needed.

### ⭐ Remember

> **Crawler follows what it discovers. Fuzzing searches for what isn't necessarily referenced.**

---

# ⚙️ 15. Crawl Configuration

When selecting:

```text
Crawl
```

you can configure the scan.

Burp allows custom configurations for things such as:

- Crawling speed
    
- Crawling limits
    
- Login behavior
    
- Other crawling parameters
    

---

# 📚 16. Configuration Library

Instead of manually configuring everything, Burp provides:

```text
Select from library
```

The module selects:

> **Crawl strategy - fastest**

This is a preset configuration.

---

# 🔐 17. Application Login

Burp can also be configured to access authenticated portions of an application.

You can provide:

```text
Username
Password
```

for login forms/fields that Burp discovers.

You can also manually record a login sequence using the pre-configured browser.

This lets Burp understand how to establish an authenticated session.

---

# 🔑 18. Why Authenticated Crawling Matters

Without authentication:

```text
Burp
 ↓
Public Pages
```

With an authenticated session:

```text
Burp
 ↓
Login
 ↓
Authenticated Session
 ↓
Private Pages
```

This can significantly increase application coverage because some functionality may only be accessible to logged-in users.

---

# 📊 19. Monitoring a Crawl

Once the crawl starts:

```text
Dashboard
   ↓
Tasks
```

You can monitor its progress.

You can also:

```text
View details
```

to inspect the running task.

The gear icon can be used to further customize scan configuration.

Once completed, the task displays:

```text
Crawl Finished
```

Then you can return to:

```text
Target → Site map
```

to see the updated application map.

---

# 👁️ 20. Passive Scanner

Once Burp has built a site map, we can analyze the discovered application for potential vulnerabilities.

A **Passive Scan** is fundamentally different from an Active Scan.

### Passive Scan:

> **Does not send new requests.**

Instead, it analyzes pages and traffic Burp has already observed.

---

# 21. Passive Scan Workflow

```text
Existing Request
      ↓
Burp observes it
      ↓
Analyze request/response
      ↓
Potential Issue
```

No new attack request is required.

---

# 22. What Can Passive Scanning Find?

The module gives examples such as:

- Missing HTML tags
    
- Potential DOM-based XSS
    

However, passive scanning generally produces **potential vulnerabilities** rather than actively verifying exploitability.

---

# ⭐ 23. Passive Scan Confidence

Burp provides a **Confidence** level for findings.

This helps prioritize results.

For example:

```text
Severity: High
Confidence: Certain
```

is generally more interesting than:

```text
Severity: Low
Confidence: Tentative
```

The module recommends focusing on:

```text
High severity
+
Certain confidence
```

while noting that sensitive applications may warrant reviewing all severity/confidence levels.

---

# 24. Starting Passive Scanning

From:

```text
Target → Site map
```

or:

```text
Proxy → HTTP History
```

right-click the target/request and choose:

```text
Do passive scan
```

or:

```text
Passively scan this target
```

The task can then be monitored from:

```text
Dashboard
```

---

# 🔥 25. Active Scanner

The **Active Vulnerability Scanner** is the more powerful and intrusive part of Burp Scanner.

Unlike passive scanning, it sends requests designed to test whether suspected vulnerabilities actually exist.

The module describes the active scan as performing a comprehensive sequence of discovery and vulnerability-testing operations.

---

# 26. Active Scanner Workflow

According to the module, the Active Scanner:

### 1️⃣ Crawls

It maps the application.

### 2️⃣ Fuzzes

It uses web fuzzing to identify possible pages.

### 3️⃣ Performs Passive Scanning

It analyzes discovered pages.

### 4️⃣ Verifies Potential Vulnerabilities

It sends requests to test suspected issues.

### 5️⃣ Performs JavaScript Analysis

It analyzes JavaScript for additional potential vulnerabilities.

### 6️⃣ Fuzzes Insertion Points

It tests parameters and other identified locations for common vulnerabilities.

---

# 🧠 27. Active vs Passive Scanner

|Feature|Passive|Active|
|---|---|---|
|Sends new requests|❌|✅|
|Analyzes existing traffic|✅|✅|
|Tests vulnerabilities|Limited|✅|
|Verification|Limited|✅|
|Intrusive|Lower|Higher|
|Speed|Generally faster|Generally slower|
|Potential target impact|Lower|Higher|

### ⭐ Easy memory trick

> **Passive = Observe**

> **Active = Test**

---

# ⚠️ 28. Why Active Scanning Needs More Care

Active scanning deliberately sends additional requests.

Therefore it can:

- Increase traffic
    
- Take longer
    
- Trigger application behavior
    
- Interact with sensitive functionality
    
- Potentially modify application state depending on the test
    

This is why scope and scan configuration are especially important.

---

# 🧪 29. Vulnerabilities Active Scanner Tests

The module mentions common vulnerability classes including:

```text
XSS
Command Injection
SQL Injection
```

along with other common web vulnerabilities.

The scanner also fuzzes identified insertion points and parameters.

---

# ⚙️ 30. Active Scan Configuration

Active scanning allows configuration of:

### Crawl configuration

Controls how Burp discovers application content.

### Audit configuration

Controls:

- Which vulnerability types to scan
    
- Where scanner payloads should be inserted
    
- Other audit behavior
    

---

# 📚 31. Audit Configuration Presets

Burp provides:

```text
Select from library
```

The module chooses:

> **Audit checks - critical issues only**

This limits the audit to the selected critical/high-impact category used in the exercise.

---

# 🔐 32. Login Credentials in Active Scanning

Just like crawling, active scanning can use login information.

This allows Burp to scan authenticated functionality.

Conceptually:

```text
Unauthenticated scan
        ↓
Public attack surface

Authenticated scan
        ↓
Public attack surface
+
Authenticated attack surface
```

This can significantly increase coverage.

---

# 📋 33. Monitoring Active Scan

Once configured:

```text
New Scan
   ↓
Crawl and Audit
   ↓
OK
```

The task appears under:

```text
Dashboard → Tasks
```

Because active scanning performs many operations, it can take significantly longer than simpler scans.

---

# 📝 34. Logger

While a scan is running, you can inspect the requests Burp is generating.

The module mentions:

```text
View details → Logger
```

or the general:

```text
Logger
```

tab.

The Logger shows requests that:

- Passed through Burp
    
- Were generated by Burp
    

This is useful for understanding what the scanner is actually doing.

---

# 🚨 35. Issue Activity

Once scanning finishes, findings can be viewed in:

```text
Dashboard → Issue activity
```

The results can be filtered by:

- Severity
    
- Confidence
    

The module demonstrates filtering for:

```text
High
+
Certain
```

---

# 💥 36. Example Finding — OS Command Injection

In the module's exercise, Burp identifies:

> **OS command injection**

with:

```text
Severity: High
Confidence: Firm
```

Because the scanner has high confidence that the issue exists, you can select the issue to examine:

- Advisory
    
- Request
    
- Response
    
- Potential exploitation details
    
- Threat information
    

---

# 🔎 37. Don't Blindly Trust Scanner Results

Even a strong scanner finding should be understood.

A scanner can help identify and prioritize vulnerabilities, but as a penetration tester you should understand:

```text
What request triggered it?
        ↓
What parameter was tested?
        ↓
What response confirmed it?
        ↓
What is the actual impact?
        ↓
Can it be reproduced?
```

The scanner output should support your manual analysis rather than replace it.

---

# 📄 38. Reporting

After scanning is complete, Burp allows you to generate a report.

From:

```text
Target → Site map
```

right-click the target:

```text
Issue
 ↓
Report issues for this host
```

---

# 39. Report Configuration

Burp asks you to select:

- Export format
    
- Information to include
    
- Issues to include
    

Reports can therefore be customized.

For example, you might choose to focus on:

```text
High severity
Certain/Firm confidence
```

depending on the reporting requirement.

---

# 40. What Does the Burp Report Contain?

The module states that Burp reports can include:

- Vulnerability information
    
- Proof-of-concept details
    
- Exploitation information
    
- Remediation information
    

They can therefore be useful as supplementary material for penetration-testing reports.

---

# ⚠️ 41. Critical Reporting Principle

This is an **important point from the module**:

> **Never simply export a scanner report and submit it to a client as the final penetration-testing deliverable.**

Tool-generated reports should instead be treated as supplementary/raw scan data.

A professional penetration-testing report should contain your own:

- Validation
    
- Risk analysis
    
- Business impact
    
- Evidence
    
- Reproduction information
    
- Remediation guidance
    
- Context
    

The module specifically describes tool reports as useful appendix/supporting data rather than a complete client deliverable.

---

# 🔥 42. Complete Burp Scanner Workflow

```text
                    TARGET
                       │
                       ▼
                 DEFINE SCOPE
                       │
                       ▼
                  SITE MAP
                       │
                       ▼
                    CRAWL
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
           PASSIVE            ACTIVE
            SCAN               SCAN
              │                 │
              │          ┌──────┴──────┐
              │          │             │
              │       Crawl         Fuzz
              │          │             │
              │          └──────┬──────┘
              │                 │
              │          Passive Scan
              │                 │
              │          Vulnerability
              │          Verification
              │                 │
              └────────┬────────┘
                       ▼
                ISSUE ACTIVITY
                       │
                       ▼
              VALIDATE FINDINGS
                       │
                       ▼
                    REPORT
```

---

# 🆚 43. Crawler vs Passive vs Active

|Feature|Crawler|Passive Scanner|Active Scanner|
|---|--:|--:|--:|
|Maps application|✅|❌|✅|
|Follows links|✅|❌|✅|
|Sends attack-style requests|❌|❌|✅|
|Analyzes existing traffic|❌|✅|✅|
|Finds potential vulnerabilities|❌|✅|✅|
|Verifies vulnerabilities|❌|Limited|✅|
|Fuzzes|❌|❌|✅|

---

# 🧠 44. Exam / Viva Questions

### Q1. What is Burp Scanner?

Burp's automated web vulnerability scanning capability, combining crawling and passive/active vulnerability scanning.

### Q2. Is Burp Scanner available in Community Edition?

**No. It is Pro-only.**

### Q3. What is Target Scope?

A mechanism for defining which targets Burp should include or exclude when processing/scanning.

### Q4. Where can you view the discovered application structure?

```text
Target → Site map
```

### Q5. What does the Crawler do?

It follows links, accesses forms, examines requests, and builds a map of the web application.

### Q6. Does Crawl perform directory fuzzing?

**No.** Crawl follows referenced content and does not fuzz for unreferenced pages.

### Q7. What is the difference between Crawl and Crawl and Audit?

**Crawl** maps the application.

**Crawl and Audit** performs crawling followed by vulnerability scanning.

### Q8. Does Passive Scan send new requests?

**No.** It analyzes traffic/pages that have already been visited.

### Q9. What does Confidence mean?

It indicates how confident Burp is that an identified potential vulnerability actually exists.

### Q10. What does Active Scanner do?

It crawls/fuzzes the application, performs passive analysis, verifies suspected vulnerabilities, analyzes JavaScript, and tests insertion points for common vulnerabilities.

### Q11. Where can active-scan requests be viewed?

In the **Logger**.

### Q12. Where can discovered vulnerabilities be reviewed?

```text
Dashboard → Issue activity
```

### Q13. What is an important advantage of authenticated scanning?

It allows Burp to reach functionality that may only be accessible after authentication.

### Q14. What is the purpose of reporting?

To export scan findings and supporting information in a structured format.

### Q15. Should a raw Burp Scanner report be submitted as the final pentest report?

**No.** Tool-generated reports should be supplementary data; the final deliverable should contain the tester's own analysis and context.

---

# ⭐ 45. Final Revision Sheet

### Burp Scanner

**Pro-only**

```text
Crawler
+
Passive Scanner
+
Active Scanner
```

### Scope

```text
Target → Scope
```

Controls what Burp should and shouldn't scan.

### Site Map

```text
Target → Site map
```

Shows discovered application structure.

### Crawl

**Maps the application.**

### Passive

**Analyzes existing traffic without sending new requests.**

### Active

**Actively tests vulnerabilities by sending requests.**

### Issue Activity

**Review and filter findings.**

### Logger

**Inspect requests generated/passed through Burp.**

### Reporting

```text
Target → Site map
→ Right-click target
→ Issue
→ Report issues for this host
```

### 🧠 One-line memory trick

> **Scope → Crawl → Map → Passive Analyze → Active Test → Validate → Report**

And the most important distinction:

> **A crawler discovers the application's structure; a passive scanner analyzes what Burp has already seen; an active scanner actively tests the application for vulnerabilities.**