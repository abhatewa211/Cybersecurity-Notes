![Image](https://images.openai.com/static-rsc-4/x96xewZHo4iI5PBO9y2wpqNnErh0nGnbvdHX65VyNwuLxnJiRpmCZe45neyuL-1BgFW4klpHkLcjj9YqLkGv8oibpHg5gLX28STy4ysigcnKwdUlS9GlMGhFIJHdhv2Sf_AmS4QuQw5yhCLM0_FwcGCOzTijnY5Q_HRROLtCcIxu0IRGTJMSeacRdatibkcv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lfs4ni7RBp5ioMfCldloPuPiVgavyN1oJ0bZiBx0L1h5mWPDCENiO0K2QSfVOwEac4BeJPBlm-sIrNGh2w5pnEdRX81QTm7IRnXQ-2iYv7sXLpFPzPaWt_lG3v2TS02kT4fIBLp5iU_sPUUPoTq8T_dqM0s7LX-owDK1FWAHQEDQbX_EltkG8Pq-TchQt4Rv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/izl-PshpN3EuZrVWw0sAtHfdIjF8ZI5cCrubIx9xgb6ffIB3-CwgBg2s5r_N60Ii5A5kAHa1PpYvy-KY7EZGlEkCC1FXHzFVI_MHQkUESv5Cg0wC8smvo0giDEIBiErkYRjSSrhi0RagaIdaePtvAw5T0ef5hx4U2bCwtyA-YSfa6tPwVPDCPUPxv782LABi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lM3nyvVo0vixLS1VlWTxlTV2-TYIX4B4uPAE_UDr_p2BsvqykX6vRX0TQlDYQS3lG1jXxjA39bDzRcCn3eAb_hElKjOdFqPiiLrJ-3AxUukEplGLk0GvWa2Rm4wWOKsqF7T8GrHSFXrMTmupQwvHtVyZv0KxL5HGxfezyEQTND3WLcqxHXbVVNlwxISEEvDs?purpose=fullsize)

## 1. What Is ZAP Scanner?

**ZAP Scanner** is ZAP's built-in web vulnerability scanner, similar to **Burp Scanner**.

It provides:

- **ZAP Spider** → builds the website/application map
    
- **Passive Scanner** → analyzes responses for potential issues
    
- **Active Scanner** → actively tests identified pages and parameters
    

### Mental model

```text
                  ZAP SCANNER
                      │
                      ▼
                   SPIDER
                      │
                      ▼
                  SITES TREE
                      │
             ┌────────┴────────┐
             ▼                 ▼
        PASSIVE SCAN       ACTIVE SCAN
             │                 │
             ▼                 ▼
          ALERTS            MORE ALERTS
             │                 │
             └────────┬────────┘
                      ▼
                   REPORT
```

---

# 🕷️ 2. ZAP Spider

**ZAP Spider** is similar to Burp's **Crawler**.

Its purpose is to discover the structure of a web application by finding and validating links.

You can start Spider in two main ways:

### From History

Locate a request in ZAP's History and:

```text
Right-click
   ↓
Attack
   ↓
Spider
```

### From ZAP HUD

After visiting the target in the pre-configured browser, use:

```text
Spider Start
```

from the HUD.

---

# 🎯 3. ZAP Scope

When starting Spider, ZAP may warn that the current website isn't in scope.

You can allow ZAP to automatically add it to scope.

### What is Scope?

Scope defines the URLs that ZAP is allowed to test when performing a generic scan.

Conceptually:

```text
Scope
 ├── target1.com
 ├── target2.com
 └── target3.com
```

This can be customized to include multiple websites/URLs.

### ⭐ Important

> **Always understand your scope before running automated scanning.**

---

# 🚀 4. Starting the Spider

After clicking:

```text
Spider Start
```

ZAP prompts you to start the scan.

Once started, Spider:

1. Visits the target
    
2. Looks for links
    
3. Validates discovered links
    
4. Requests discovered resources
    
5. Builds the application's site structure
    

This is similar to how Burp Crawler operates.

---

# 📊 5. Monitoring Spider

Spider progress can be viewed in:

### ZAP HUD

The Spider button shows progress.

### Main ZAP UI

ZAP automatically switches to the current Spider tab, where you can see:

- Progress
    
- Requests
    
- Spider activity
    

---

# 🌳 6. Sites Tree

After Spider finishes, the discovered structure can be viewed through:

```text
Sites
```

or:

```text
Sites Tree
```

The Sites Tree provides an expandable tree representation of discovered websites and directories.

Example:

```text
Target
│
├── index.php
├── robots.txt
├── sitemap.xml
├── devtools
│
└── wordpress
    └── wp-comments-post.php
```

This becomes the foundation for later scanning.

---

# 🕸️ 7. Normal Spider vs Ajax Spider

ZAP also provides:

> **Ajax Spider**

It is different from the normal Spider because it attempts to identify links requested through **JavaScript AJAX requests**.

This is important because modern applications can dynamically request content after the initial page load.

### Normal Spider

```text
HTML
 ↓
Links
 ↓
Pages
```

### Ajax Spider

```text
HTML
 ↓
JavaScript
 ↓
AJAX Requests
 ↓
Additional Resources
```

The module recommends running Ajax Spider **after the normal Spider** because it may discover links the normal Spider missed.

The trade-off is that Ajax Spider can take longer.

---

# 👁️ 8. Passive Scanner

One particularly useful aspect of ZAP is that its **Passive Scanner runs automatically while Spider is making requests**.

As ZAP receives responses, it can inspect them for potential security issues.

Examples mentioned in the module include:

- Missing security headers
    
- DOM-based XSS
    

Therefore, you may start seeing alerts **before running Active Scan**.

---

# 🚨 9. ZAP Alerts

ZAP provides an **Alerts** system for identified issues.

There are two useful perspectives:

### Current page

The alerts shown on the left pane relate to the page currently being visited.

### Entire application

The right pane can show alerts found across the web application.

You can also open:

```text
Alerts
```

in the main ZAP UI to see the overall findings.

---

# 🔍 10. Examining an Alert

When you click an alert, ZAP can provide:

- Alert details
    
- Affected URLs/pages
    
- Security information
    
- Evidence
    

Conceptually:

```text
Alert
 │
 ├── Risk
 ├── Confidence
 ├── URL
 ├── Evidence
 └── Description
```

This makes it possible to investigate the finding rather than simply seeing an alert name.

---

# 🔥 11. Active Scanner

Once the Sites Tree has been populated, we can start:

> **Active Scan**

The Active Scanner tests identified pages and HTTP parameters for vulnerabilities.

You can start it using:

```text
Active Scan
```

from the HUD/right pane.

---

# ⚠️ 12. If Spider Hasn't Been Run

An important convenience:

If you haven't already run Spider, ZAP can automatically run it before Active Scan so that it has a site tree to scan.

Therefore:

```text
No Spider
   ↓
Active Scan
   ↓
ZAP automatically builds site tree
   ↓
Active scanning begins
```

---

# 💥 13. What Does Active Scanner Do?

The Active Scanner sends different attack/test requests against:

- Identified pages
    
- HTTP parameters
    
- Other discovered attack surfaces
    

The goal is to identify as many vulnerabilities as possible.

Because it actively sends testing requests, it takes longer than passive scanning.

---

# 📈 14. Monitoring Active Scan

During Active Scan, ZAP displays progress.

For example:

```text
Active Scan: 4%
```

and later:

```text
Active Scan: 42%
```

You can also inspect the requests generated by ZAP.

This is useful for understanding what the scanner is actually testing.

---

# 📝 15. Active Scan Requests

The main ZAP interface can show information about requests being sent during the scan, such as:

- HTTP method
    
- URL
    
- Status code
    
- Response time
    

Conceptually:

```text
GET /login
200 OK
120 ms
```

This provides visibility into the scanner's activity.

---

# 🚨 16. Alerts After Active Scanning

As Active Scan discovers additional issues, the **Alerts** count/population increases.

Once the scan finishes:

```text
Alerts
   ↓
Review findings
   ↓
Prioritize
   ↓
Investigate
```

The module emphasizes that **all alerts should be considered**, while **High** alerts generally deserve particular attention because they can potentially lead to direct compromise of the web application or backend server.

---

# 🔴 17. High Alert Example

The example in the module identifies:

> **Remote OS Command Injection**

with:

```text
Risk: High
Confidence: Medium
```

This is an important example of why scanner findings need further investigation.

---

# 🔍 18. Alert Details

Clicking the High Alert provides additional information, including:

- Vulnerability description
    
- Risk level
    
- Confidence
    
- Attack example
    
- Evidence
    
- Affected URL
    
- Remediation/patching information
    

The module's example shows evidence associated with command execution on the target.

---

# 🧪 19. Request and Response Evidence

Within the alert details, you can click the URL to inspect the request and response that ZAP used to identify the vulnerability.

This is extremely useful because you can understand:

```text
What was sent?
      ↓
What did the server return?
      ↓
Why did ZAP consider this vulnerable?
```

The request can also be replayed using:

```text
ZAP HUD
```

or:

```text
ZAP Request Editor
```

This lets you manually investigate the finding.

---

# 🧠 20. Scanner Finding → Manual Investigation

A useful workflow is:

```text
Scanner finds issue
        ↓
Read alert
        ↓
Inspect URL
        ↓
Inspect request
        ↓
Inspect response
        ↓
Understand evidence
        ↓
Reproduce/validate
        ↓
Determine impact
        ↓
Document
```

This is much better than blindly accepting every scanner result.

---

# 📄 21. Reporting

After completing the scans, ZAP can generate reports containing the identified findings.

Navigate to:

```text
Report
   ↓
Generate HTML Report
```

ZAP will ask where to save the report.

---

# 📑 22. ZAP Report Formats

The module specifically mentions:

```text
HTML
XML
Markdown
```

So you can choose a format appropriate for your workflow.

---

# 📊 23. What Does the Report Show?

The example report provides a summary of alerts by severity.

For example:

```text
High
Medium
Low
Informational
```

The module's example contains:

```text
1 High
3 Medium
8 Low
6 Informational
```

and includes findings such as:

- Remote OS Command Injection
    
- Cross-Domain Misconfiguration
    
- Directory Browsing
    
- Other alerts
    

---

# 🆚 24. ZAP Scanner vs Burp Scanner

|Feature|ZAP Scanner|Burp Scanner|
|---|---|---|
|Web crawler|**ZAP Spider**|**Burp Crawler**|
|AJAX discovery|**Ajax Spider**|Different mechanisms|
|Passive scanning|✅|✅|
|Active scanning|✅|✅|
|Site map|**Sites Tree**|**Target → Site map**|
|Alerts/findings|**Alerts**|**Issue activity**|
|Request inspection|✅|✅|
|Reporting|HTML/XML/Markdown etc.|Burp reporting|
|Cost|Open-source/free|Scanner is Pro-only|

---

# 🧠 25. ZAP Scanner vs ZAP Fuzzer

Don't confuse these two.

### ZAP Fuzzer

Used for **controlled fuzzing of selected request locations**.

```text
Request
   ↓
Fuzz Location
   ↓
Payloads
   ↓
Processors
   ↓
Results
```

### ZAP Scanner

Used for **automated web application discovery and vulnerability scanning**.

```text
Target
   ↓
Spider
   ↓
Passive Scan
   ↓
Active Scan
   ↓
Alerts
   ↓
Report
```

---

# 🔥 26. Complete ZAP Scanner Workflow

```text
                 TARGET
                    │
                    ▼
                  SCOPE
                    │
                    ▼
                 SPIDER
                    │
          ┌─────────┴─────────┐
          │                   │
          ▼                   ▼
     Normal Spider       Ajax Spider
          │                   │
          └─────────┬─────────┘
                    ▼
                SITES TREE
                    │
                    ▼
             PASSIVE SCANNER
                    │
                    ▼
                 ALERTS
                    │
                    ▼
              ACTIVE SCANNER
                    │
                    ▼
          More Requests/Tests
                    │
                    ▼
                 ALERTS
                    │
                    ▼
          Manual Investigation
                    │
                    ▼
                 REPORT
```

---

# 📋 27. Quick Revision Table

|Component|Purpose|
|---|---|
|**Scope**|Defines URLs/targets to test|
|**Spider**|Discovers application structure|
|**Ajax Spider**|Finds JavaScript/AJAX-based links|
|**Sites Tree**|Displays discovered application structure|
|**Passive Scanner**|Analyzes responses without actively attacking|
|**Alerts**|Displays identified security issues|
|**Active Scanner**|Actively tests pages and parameters|
|**Request/Response**|Provides evidence for findings|
|**Report**|Exports scan findings|

---

# 🎓 28. Exam / Viva Questions

### Q1. What is ZAP Scanner?

ZAP's web vulnerability scanning functionality that combines Spider, passive scanning, and active scanning.

### Q2. What is ZAP Spider?

A crawler that discovers and maps websites by finding and validating links.

### Q3. What is Ajax Spider?

A Spider designed to identify links/resources requested through JavaScript AJAX activity.

### Q4. Why run Ajax Spider after normal Spider?

It may discover links that the normal Spider missed, although it may take longer.

### Q5. When does ZAP Passive Scanner run?

It automatically analyzes responses as ZAP makes requests, including during Spider activity.

### Q6. Give two examples of issues Passive Scanner may identify.

The module gives:

- Missing security headers
    
- DOM-based XSS
    

### Q7. What does Active Scanner do?

It actively sends testing requests against discovered pages and HTTP parameters to identify vulnerabilities.

### Q8. Why does Active Scan take longer?

Because it performs numerous active tests/attacks against the identified attack surface.

### Q9. Where can ZAP findings be viewed?

In the **Alerts** interface/tab.

### Q10. What information can an alert provide?

Risk, confidence, affected URL, evidence, details about the vulnerability, and information useful for replication/patching.

### Q11. Can you replay a request associated with an alert?

Yes. The module states that the request can be repeated through **ZAP HUD** or **ZAP Request Editor**.

### Q12. What report formats are mentioned?

**HTML, XML, and Markdown.**

---

# ⭐ 29. Most Important Things to Remember

> 🕷️ **Spider = Discover**

> 👁️ **Passive Scanner = Analyze**

> 💥 **Active Scanner = Test**

> 🚨 **Alerts = Findings**

> 🌳 **Sites Tree = Application Map**

> 📄 **Report = Document Findings**

And the complete chain:

**`Scope → Spider → Sites Tree → Passive Scan → Active Scan → Alerts → Validate → Report`**

That is the core ZAP Scanner workflow from this section.