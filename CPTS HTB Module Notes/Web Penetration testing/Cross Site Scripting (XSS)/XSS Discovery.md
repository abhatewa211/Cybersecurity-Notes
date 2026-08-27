## 1. What is XSS Discovery?

Now that we understand:

- What XSS is
    
- Stored XSS
    
- Reflected XSS
    
- DOM-based XSS
    
- Source & Sink
    

the next step is learning **how to discover XSS vulnerabilities**.

> **XSS Discovery = finding places where attacker-controlled input can reach a browser in an unsafe way and potentially execute as HTML/JavaScript.**

The difficulty of discovery depends heavily on how well the application validates, sanitizes, encodes, and processes user input.

---

# 2. Three Main Ways to Discover XSS

There are three major approaches discussed in this section:

```text
             XSS DISCOVERY
                  │
       ┌──────────┼──────────┐
       ↓          ↓          ↓
  Automated     Manual    Code Review
  Discovery    Testing
```

### 🔵 1. Automated Discovery

Use vulnerability scanners and specialized XSS tools.

### 🟠 2. Manual Discovery

Test input locations yourself using appropriate test payloads.

### 🟣 3. Code Review

Trace input through the application's front-end and back-end code.

---

# 3. 🖼️ XSS Discovery Workflow

![Image](https://images.openai.com/static-rsc-4/47wogSmXXSTrOvdup8woB1HK_Ifpfu_JFhPxfidq242FjOjyjaeP8LjmwqBhYJ6vSB08d1Yjv2Vgeb7tdtdyWQObCXMII0lFgABzpztsj7--MMxoYnQfyBN0stS6vy0yfJ8sTBfTdytY7ghLFbdp8YAA-7r-DDlrQY0ybAp4fzYdx_krKOMmAhdGbdpCE-2q?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6StR_O-bcXpTZRVheQQMR7a-8Leyl51loP2UICqCWAeDSydY3cY8ydEK2ARUt1BFP_zClCliYkkmrAcfy318EksBfvGzWfLtb7ohjwKB82TRnjdfK3nfcvDl02Z6AWQEnhwkpo4uEtMA5kNNiuW3B76FoHXgVps0gjy7xftprt3lCVFhYCrZ0atu-jYrekSW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dlVJouCZlbwiJpsSnUwlGVBw9xXR9sgigIu9p348pfZTe-ciiKtpfJ9992LUIZZYSd5EK91pjQprVYPbKeWbA2N-4LBw7PYjexjrU25qr3iZ_9E03CTfwkmJ1KKxLCGQPc5hV0H0pNz2yE7bidP-NTpNVyPU5RsmbLEiP_kz0Gnf3R0wVhKOcmRiobwU-0gY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JHCpkR05ajrLpt-LaqLhWMu6tRodGBXGhHPDLKWzL0ar1SEDtx-IBiYv6g2HsCsPZShxmcq5XQKACRU14wgbDdfmahGiLkfnGc9b71s45PTbPNaY9noogjbSEjfp3kBR48agI4XO-mTr5E9dQahUMIcWtTDVvImFncGN5vi_c-U6_J-unaeMI_dNrua_mwv5?purpose=fullsize)

A useful mental model is:

```text
Find Input
    ↓
Send Test Input
    ↓
Observe Reflection/DOM Changes
    ↓
Identify Context
    ↓
Test Appropriate Payload
    ↓
Verify Execution
    ↓
Determine XSS Type
```

---

# 4. Automated Discovery

Many web application vulnerability scanners can detect XSS.

Examples mentioned in the module include:

- **Nessus**
    
- **Burp Suite Professional**
    
- **OWASP ZAP**
    

These tools can help identify different types of XSS, including:

- Stored XSS
    
- Reflected XSS
    
- DOM-based XSS
    

---

# 5. Passive vs Active Scanning

This distinction is **very important**.

## 🟢 Passive Scan

A passive scanner generally analyzes what it can observe **without actively injecting attack payloads**.

For XSS, it may inspect:

- Client-side JavaScript
    
- DOM interactions
    
- Potential sources
    
- Potential sinks
    
- Application behavior
    

This is particularly useful for identifying potential **DOM-based XSS**.

### Conceptually:

```text
Application
     ↓
Observe
     ↓
Analyze code/traffic
     ↓
Identify suspicious behavior
```

---

# 6. 🔴 Active Scan

An active scanner actually sends test inputs/payloads to the application.

Conceptually:

```text
Scanner
   ↓
Test Payload
   ↓
Application
   ↓
Response
   ↓
Analyze Response
   ↓
Determine whether injection occurred
```

It may test many different payload variations because the application could have:

- Input filtering
    
- Encoding
    
- Sanitization
    
- WAF protection
    
- Different injection contexts
    

---

# 7. Paid vs Open-Source Tools

The module points out that paid tools generally provide stronger detection capabilities, particularly when more complicated security controls or bypasses are involved.

However:

> **Open-source tools can still be extremely useful for identifying potential XSS.**

Examples mentioned:

### 🛠️ XSStrike

A specialized XSS discovery tool.

### 🛠️ BruteXSS

An open-source XSS testing tool.

### 🛠️ XSSer

Another tool designed for automated XSS testing.

---

# 8. How Automated XSS Tools Generally Work

A simplified model:

```text
             Web Application
                    │
                    ▼
             Find parameters
                    │
                    ▼
             Find input points
                    │
                    ▼
          Send test payloads
                    │
                    ▼
          Receive application
              response
                    │
                    ▼
          Look for reflections
                    │
                    ▼
          Analyze the context
                    │
                    ▼
        Determine likely XSS
```

The important word here is **likely**.

Automated detection doesn't always prove that XSS actually executes.

---

# 9. Why Reflection Doesn't Automatically Mean XSS

Suppose you send:

```text
test
```

and the application returns:

```html
Task 'test' could not be added.
```

Your input was reflected.

But that alone doesn't prove XSS.

Now imagine the application returns:

```html
Task '&lt;script&gt;...&lt;/script&gt;'
```

The characters have been encoded.

The browser will treat them as text rather than executable HTML.

Therefore:

```text
Input reflected
      ≠
XSS confirmed
```

### ⭐ Important

> **Reflection is an indicator that deserves investigation, not automatically proof of XSS.**

---

# 10. Why Automated Tools Can Produce False Positives

A scanner might discover that its payload appears somewhere in the response.

But that doesn't necessarily mean:

```text
Payload
   ↓
Executed
```

It could simply mean:

```text
Payload
   ↓
Reflected as text
   ↓
Not executed
```

Other possibilities include:

- HTML encoding
    
- JavaScript encoding
    
- Context restrictions
    
- Browser behavior
    
- Sanitization
    
- CSP
    
- WAF filtering
    
- Incorrect injection context
    

Therefore:

> **Always manually verify an automated finding when possible.**

---

# 11. XSStrike Example

The module demonstrates **XSStrike** against the previous Reflected XSS application.

First, the repository is cloned:

```bash
git clone https://github.com/s0md3v/XSStrike.git
```

Then:

```bash
cd XSStrike
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Then run:

```bash
python xsstrike.py
```

---

# 12. Testing a URL

The `-u` option allows a URL to be supplied.

The example from the module is:

```bash
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"
```

The URL contains:

```text
?task=test
```

So the tool knows there is a parameter named:

```text
task
```

that can be investigated.

---

# 13. Understanding the XSStrike Output

The example output contains:

```text
[~] Checking for DOM vulnerabilities
[+] WAF Status: Offline
[!] Testing parameter: task
[!] Reflections found: 1
[~] Analysing reflections
[~] Generating payloads
[!] Payloads generated: 3072
```

Let's break that down.

---

## `Checking for DOM vulnerabilities`

The tool is checking for possible client-side DOM vulnerabilities.

---

## `WAF Status: Offline`

The tool reports that it did not detect an active Web Application Firewall in the example.

### Remember:

A tool's WAF detection is not necessarily definitive.

---

## `Testing parameter: task`

The tool identified:

```text
task
```

as the parameter it wants to test.

---

## `Reflections found: 1`

The tool detected that the supplied input appeared in the response.

This is important because reflected input can potentially create a Reflected XSS vulnerability.

But again:

> **Reflection ≠ confirmed XSS.**

---

## `Analysing reflections`

The tool determines **where and how** the input appears.

This matters because the same payload behaves differently depending on its context.

For example:

```html
<div>INPUT</div>
```

is different from:

```html
<input value="INPUT">
```

which is different from:

```javascript
var x = "INPUT";
```

---

## `Generating payloads`

The tool generates payload variations designed for the identified context.

The example reports:

```text
3072
```

generated payloads.

---

# 14. Why So Many Payloads?

This is an important concept.

There isn't one universal XSS payload that works everywhere.

An application might place your input inside:

### HTML body

```html
<div>INPUT</div>
```

### Attribute

```html
<input value="INPUT">
```

### JavaScript

```javascript
var task = "INPUT";
```

### URL

```html
<a href="INPUT">
```

### CSS

```html
<div style="...INPUT...">
```

Each context has different rules.

Therefore:

> **XSS payloads are context-dependent.**

---

# 15. Manual Discovery

Automated tools are useful, but manual testing remains extremely important.

The module describes the difficulty like this:

```text
Basic application
      ↓
Basic testing
      ↓
Potential XSS
```

Whereas:

```text
Complex application
      ↓
Filtering
Encoding
Sanitization
WAF
Complex JavaScript
      ↓
Advanced analysis
      ↓
Potential XSS
```

---

# 16. Manual XSS Testing

The simplest approach is to identify input locations and test them.

Potential locations include:

- Search boxes
    
- Comments
    
- Contact forms
    
- Usernames
    
- Profile fields
    
- URL parameters
    
- Error messages
    
- HTTP headers
    
- Other user-controlled values
    

### Important:

XSS isn't limited to visible HTML form fields.

---

# 17. XSS Can Exist Beyond Input Fields

The module specifically points out that XSS may occur through values such as:

```text
Cookie
User-Agent
```

**if the application later displays those values unsafely in an HTML context.**

For example, conceptually:

```text
HTTP Header
     ↓
Server/application
     ↓
Value displayed on webpage
     ↓
Unsafe HTML context
     ↓
Potential XSS
```

### ⭐ Key lesson

> **Test where data enters the application, not just where you see a textbox.**

---

# 18. XSS Payload Lists

There are many publicly available XSS payload collections.

The module mentions resources such as:

- PayloadsAllTheThings
    
- Payload-Box XSS payload list
    

These collections contain many different payload patterns.

However, don't fall into the trap of thinking:

> "I'll paste every payload until one works."

That isn't an efficient methodology.

---

# 19. Why Most Payloads Don't Work Everywhere

Suppose the application is vulnerable, but you try a payload designed for a different context.

It may fail.

For example, a payload designed for:

```html
<input value="USER_INPUT">
```

may not work when your input appears in:

```html
<div>USER_INPUT</div>
```

Similarly, a payload designed to bypass a particular filter may be unnecessary if no such filter exists.

---

# 20. Injection Context

This is one of the most important concepts in XSS discovery.

Imagine the application produces:

```html
<div>YOUR_INPUT</div>
```

Your input is inside the HTML body.

But imagine:

```html
<input value="YOUR_INPUT">
```

Now your input is inside an HTML attribute.

Or:

```javascript
var name = "YOUR_INPUT";
```

Now you're inside JavaScript.

### Therefore:

```text
               USER INPUT
                   │
          Where does it land?
                   │
       ┌───────────┼───────────┐
       ↓           ↓           ↓
      HTML      Attribute    JavaScript
       │           │           │
       ▼           ▼           ▼
  Different    Different    Different
  context      context      context
```

---

# 21. XSS Has Multiple Injection Vectors

The module mentions several vectors.

### `<script>` elements

One traditional approach.

### HTML attributes

For example, event-handler attributes.

### CSS-related contexts

Certain CSS contexts can also become relevant depending on the browser and application.

The key point isn't memorizing hundreds of payloads.

It's understanding:

> **Where exactly does my input land?**

---

# 22. Better Manual Methodology

Instead of blindly trying payloads:

### Step 1 — Find input

Identify user-controlled parameters.

```text
task=
search=
name=
comment=
```

### Step 2 — Send harmless test input

For example:

```text
XSS_TEST_123
```

### Step 3 — Find reflection

Search the response/DOM for:

```text
XSS_TEST_123
```

### Step 4 — Identify context

Determine whether it appears inside:

```text
HTML
Attribute
JavaScript
URL
DOM
```

### Step 5 — Understand filtering/encoding

Determine how special characters are handled.

### Step 6 — Test in an authorized environment

Use an appropriate proof-of-concept to determine whether the input can actually execute.

### Step 7 — Verify manually

Don't rely solely on the scanner.

---

# 23. Why Blind Payload Copy/Paste Is Inefficient

Imagine an application has:

```text
50 input parameters
```

and you have:

```text
1,000 payloads
```

Blindly testing everything could mean thousands of unnecessary requests.

Instead:

```text
Identify input
      ↓
Identify context
      ↓
Understand filtering
      ↓
Select appropriate test
```

is much more efficient.

---

# 24. Automating Your Own Testing

The module briefly discusses writing a custom Python script.

The basic concept would be:

```text
Python Script
      │
      ▼
Read input locations
      │
      ▼
Send test values
      │
      ▼
Receive response
      │
      ▼
Compare response
      │
      ▼
Identify reflections
```

This can be useful when existing tools don't handle a particular application correctly.

---

# 25. Why Custom Automation Can Be Useful

A custom script allows you to adapt the testing process to the application.

For example, you might customize:

- Input locations
    
- Request format
    
- Authentication
    
- Payload selection
    
- Response comparison
    
- Encoding
    
- Application-specific behavior
    

### But:

> The module considers this an advanced approach and doesn't cover it in detail.

---

# 26. 🟣 Code Review

According to the module, **manual code review is the most reliable discovery method** when you have access to the application's code.

Why?

Because instead of guessing what happens to your input, you can **trace it directly**.

---

# 27. Code Review Data Flow

The objective is:

```text
User Input
    ↓
Application
    ↓
Processing
    ↓
Sanitization / Encoding
    ↓
HTML / DOM
    ↓
Browser
```

You want to understand the entire path.

---

# 28. Front-End Code Review

For DOM XSS, examine JavaScript for:

### Sources

Where user-controlled data enters.

Examples include URL-derived values and browser-controlled input.

### Sinks

Where that data gets written or used.

Examples from the previous section:

```javascript
document.write()
```

```javascript
innerHTML
```

```javascript
outerHTML
```

and relevant jQuery DOM-manipulation functions.

---

# 29. Example Source → Sink Analysis

From the previous DOM XSS example:

### Source

```javascript
document.URL
```

↓

### Processing

```javascript
substring(...)
```

↓

### Decoding

```javascript
decodeURIComponent(...)
```

↓

### Sink

```javascript
innerHTML
```

↓

### DOM

```text
#todo
```

This is much stronger evidence than simply throwing random payloads at the application.

---

# 30. Back-End Code Review

Code review shouldn't stop at JavaScript.

You should also understand what happens on the server.

Conceptually:

```text
HTTP Request
     ↓
Server-side code
     ↓
Input processing
     ↓
Validation
     ↓
Sanitization/encoding
     ↓
Template
     ↓
HTML Response
```

This is especially important for:

- Stored XSS
    
- Reflected XSS
    
- Template rendering
    
- Server-side input handling
    

---

# 31. Why Code Review Can Beat Automated Tools

Modern applications may already have been scanned before release.

Developers may have fixed obvious XSS vulnerabilities.

Therefore:

```text
Simple payload
      ↓
Tool
      ↓
No finding
```

doesn't necessarily mean:

```text
No XSS exists
```

There may still be complex data flows that automated scanners don't understand.

Manual code review can reveal those flows.

---

# 32. Automated vs Manual vs Code Review

|Method|Advantages|Limitations|
|---|---|---|
|🤖 Automated|Fast, scalable, many payloads|False positives/negatives|
|🧑 Manual|Understands real application behavior|Time-consuming|
|🧑‍💻 Code Review|Deep understanding of data flow|Requires source/code access|

### Best approach

In a mature security assessment, these approaches complement each other.

```text
Automated
    +
Manual
    +
Code Review
    ↓
Better XSS Detection
```

---

# 33. 🖼️ XSS Discovery Comparison

![Image](https://images.openai.com/static-rsc-4/AZFKsxoGLjF-8ggNtfQwqOgUhYAZtfsxUIQRyhfVJJTf3xtwfEH2i9_7ulBnlE6Wao4SaPNyHyLDLNrnwQReXm85p_B2CJVe71zIR_nresUlVBSEpzWQHZBiWBgA8eCwpGdd7a45bKQf5OLlSnX-OXbStQbYT-0WnxQS7sKuRKHWNvba7zvGGclYa0ZaPsoI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/47wogSmXXSTrOvdup8woB1HK_Ifpfu_JFhPxfidq242FjOjyjaeP8LjmwqBhYJ6vSB08d1Yjv2Vgeb7tdtdyWQObCXMII0lFgABzpztsj7--MMxoYnQfyBN0stS6vy0yfJ8sTBfTdytY7ghLFbdp8YAA-7r-DDlrQY0ybAp4fzYdx_krKOMmAhdGbdpCE-2q?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QX6Nn3qX1AcUWTTIWKiJuhDnAE_Pb4pHNxrlAlHtW3zPbOryoz3MdXI_jzTXmOnsiqhMiYiVraQXgyaVAE__j-MfLyXBKf-1pczQNAhqlAcf2Bcgth1_TpmtOJ8zsPVAw_P_uBWZE_WZhypTp9om8tESFJ20Zu6EZFfelPKkCOoQ_xzFNpq69T_cb2Ldv-xx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KqTgFyICPDPa04yWLxnjxjBnO6ukMqmg-xncVf8q02bE2boySc0vXAbt9beJDymNJ3sVVvEnLboiGBZUgUBXdT_tyQl_lPbyZJ1mja9cSbKBOSldoqWYEOqxbMpY9slN39zbKkkj6qFaH8sVyyKm1dAdj6-2vi4EpSEL8SwdO4BekFHsZp53lX0HfpxCK8Z_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/YDMQ4Na3SD2wqGW8JtJ51oWSMqyzI10U-AW2qpNb40rjkU05BeEGjLmr4EGmxJZU7mTIxvZjFw3suM96mnQ5hWbO1Cr8rQwJLfvjGrB1iqg_TFgUoyUErw3ie7bTR2QDiDoiGFQ6Fzr3PIMIDXuFaY3zf5fXpBqaQ2hZhWAXCl4_NRPegO7h2pxoOydJAdku?purpose=fullsize)

Think of the three methods like this:

```text
🤖 AUTOMATED
"Let the tool search quickly."

        ↓

🧑 MANUAL
"Let me understand what the application does."

        ↓

🧑‍💻 CODE REVIEW
"Let me trace exactly where the input goes."
```

---

# 34. 🔥 Important Concept: Detection ≠ Exploitation

This distinction is worth keeping clear.

### Discovery

Finding evidence that a vulnerability may exist.

```text
Input
 ↓
Reflection / unsafe data flow
 ↓
Potential XSS
```

### Verification

Confirming that the browser actually interprets the input in a dangerous way.

```text
Potential XSS
      ↓
Controlled proof-of-concept
      ↓
Confirmed XSS
```

### Exploitation

Using the confirmed vulnerability to achieve a specific impact.

```text
Confirmed XSS
      ↓
Specific security impact
```

For learning and testing, keep exploitation confined to systems you're authorized to assess.

---

# 35. 🧠 Why Context Matters More Than Payload Count

A common beginner mistake is:

> **"I need a huge XSS payload list."**

A better mindset is:

> **"I need to understand where my input is being placed."**

For example:

```text
INPUT
  ↓
Where?
  ├── HTML
  ├── Attribute
  ├── JavaScript
  ├── URL
  └── DOM
```

Once you know the context, you can choose an appropriate test.

---

# 36. XSS Discovery Checklist

Use this checklist during an authorized assessment:

### 🔎 Reconnaissance

-  Identify application functionality
    
-  Identify user-controlled inputs
    
-  Identify URL parameters
    
-  Identify forms
    
-  Identify interesting HTTP headers
    
-  Identify client-side JavaScript
    

### 🧪 Initial Testing

-  Insert a unique harmless marker
    
-  Check whether it is reflected
    
-  Check the response
    
-  Check the rendered DOM
    
-  Identify the injection context
    

### 🔬 Analysis

-  Determine Stored vs Reflected vs DOM
    
-  Check encoding
    
-  Check sanitization
    
-  Identify potential Source
    
-  Identify potential Sink
    
-  Determine whether execution is possible
    

### 🤖 Automation

-  Run an appropriate scanner
    
-  Review findings
    
-  Look for false positives
    
-  Manually verify important findings
    

### 🧑‍💻 Code Review

-  Trace input from source to output
    
-  Inspect server-side processing
    
-  Inspect client-side JavaScript
    
-  Identify unsafe DOM sinks
    
-  Check security controls
    

---

# 37. ⚡ Quick Revision

### Automated Discovery

> Tools automatically identify inputs, send test cases, analyze reflections and look for potential XSS.

Examples from the module:

```text
Nessus
Burp Suite Professional
OWASP ZAP
XSStrike
BruteXSS
XSSer
```

---

### Manual Discovery

> Manually test user-controlled inputs and determine where the input appears and how it is processed.

Remember:

```text
Input → Reflection → Context → Appropriate test → Verification
```

---

### Code Review

> Trace the input through the application until it reaches the browser.

Especially for DOM XSS:

```text
SOURCE → PROCESSING → SINK → DOM
```

---

# 38. ⭐ Most Important Things to Remember

> **1. Automated tools are useful, but their results require verification.**

> **2. Reflection alone does not prove XSS.**

> **3. XSS can occur through more than visible HTML input fields.**

> **4. The injection context determines what kind of testing is appropriate.**

> **5. There is no single universal XSS payload.**

> **6. Payload lists contain many context-specific and filter-bypass payloads.**

> **7. Blindly trying thousands of payloads is inefficient.**

> **8. Understanding the data flow is more valuable than memorizing payloads.**

> **9. Code review can reveal vulnerabilities missed by automated scanners.**

> **10. For DOM XSS, think: `SOURCE → SINK`.**

---

# 🧠 Final XSS Discovery Mental Map

```text
                         XSS DISCOVERY
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
        AUTOMATED          MANUAL          CODE REVIEW
             │                │                │
             ▼                ▼                ▼
        Find inputs      Find inputs      Trace data
             │                │                │
             ▼                ▼                ▼
       Send payloads     Test input       Find Source
             │                │                │
             ▼                ▼                ▼
       Analyze response  Find context      Find Sink
             │                │                │
             ▼                ▼                ▼
       Potential XSS     Test behavior    Trace flow
             │                │                │
             └────────────────┼────────────────┘
                              ▼
                     MANUAL VERIFICATION
                              │
                              ▼
                       CONFIRMED XSS
```

### 🏆 The one formula to remember:

**Find the input → Find where it lands → Understand the context → Trace the data flow → Verify the behavior.**