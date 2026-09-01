![Image](https://images.openai.com/static-rsc-4/j-H1ekNQ4tDpwvBMoksG9MiSzD_njm-gwBykjQNBc249Z-INmqkB1YcvxGejvrr01P5OXjyzbkCPkIH1a9WvVgG0cwf1k3FjJi8Erp1dTp02c4lKbCOnh0jvA-sLGMBkuMhyYVJ-Qv-MnOvD3aa708_0nBNtO5ABI4lBNT1Jxi5GqLTaat5uFscU3gUOpxHR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eBZ-8uFdrdkkaam4SMSfVFN3PQ6XeZkq1gI4qrNGAczKkUMNdwf1i-zTbJdxOI0_C569iikXSVo3AaxQUsOxB2WubSg7lZ5TCWJiNsAkkdaNKMiVR_Y-SjsYVMtuIC_NGrnBIRwa9KFVSsCoEmWYKRPYSKz8kYWtq7uRflEraxCyRZgMpUdejAMdAHj0RGOm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ibXt1f_44_IDLQCUvVDpPUFk1oTYlau8W7EKuVvkmkvvEPOgGejM8fJaXAhXwi-bBdayLApCGnUZfAqa8cXO3ZlJnALKyT74abv0zCOFbC1hAM4lBbwA1zN23Q7dUKl6AHo02U5e2W3Kieezm4b21dXVXfIXiqkKPP42DzPHflKmFjScq4xfpDx1vVkF3Szo?purpose=fullsize)

## 1. Overview

The **second and more common type of HTTP Verb Tampering** is caused by **Insecure Coding**.

Unlike the previous example, where the vulnerability came from the web server's authentication configuration, this type is caused by mistakes in the **web application's code**.

The basic problem is:

> **The application applies a security filter to one HTTP method but fails to apply the same filter to another method.**

This can allow an attacker to change the HTTP method and **bypass the security filter completely**.

---

# 2. The Core Concept

Imagine an application has a filter designed to detect malicious input.

The developer writes the filter to inspect only:

```php
$_POST['parameter']
```

The application expects users to submit data using `POST`.

So the security flow is:

```text
POST Request
     │
     ▼
$_POST['parameter']
     │
     ▼
Security Filter
     │
     ├── Malicious → BLOCK ❌
     │
     └── Safe → Continue ✓
```

The problem occurs if the application also accepts `GET`.

An attacker can potentially change:

```text
POST → GET
```

and cause the malicious value to arrive through a different parameter source.

Conceptually:

```text
POST
 │
 ▼
$_POST
 │
 ▼
Security Filter ✓
 │
 ▼
Blocked


GET
 │
 ▼
$_GET
 │
 ▼
Security Filter not applied ❌
 │
 ▼
Malicious input reaches application
```

### ⭐ Main Lesson

> **A security filter is only effective if it checks every input path that can reach the vulnerable functionality.**

---

# 3. Why This Is More Common

The previous vulnerability type involved:

**Insecure Web Server Configuration**

This one involves:

**Insecure Application Coding**

Developers may accidentally create inconsistencies between:

- HTTP methods
    
- Parameter sources
    
- Validation
    
- Sanitization
    
- Application logic
    

For example:

```text
Developer thinks:

POST → input → filter → application


Actual application:

POST → filter
GET  → no filter
PUT  → no filter
...
```

This creates an opportunity for **HTTP Verb Tampering**.

---

# 🔴 4. Identify the Vulnerability

The lab uses the **File Manager** web application.

Normally, users can enter a filename:

```text
New File Name: test
```

and create the file.

However, if we enter special characters:

```text
test;
```

the application responds:

```text
Malicious Request Denied!
```

This tells us something important.

---

# 5. What Does "Malicious Request Denied!" Tell Us?

The response strongly suggests that there is a **backend security filter**.

Conceptually:

```text
User Input
    │
    ▼
Backend Application
    │
    ▼
Security Filter
    │
    ├── Safe → Create File ✓
    │
    └── Malicious → Deny ❌
```

The application is therefore attempting to protect itself against malicious input.

At first glance:

```text
Special characters
       ↓
Detected
       ↓
Request blocked
```

Everything appears secure.

But now we ask an important security-testing question:

> **Does the filter apply consistently to every HTTP method?**

---

# 6. Testing the HTTP Method

Intercept the file-creation request using **Burp Suite**.

The request can be examined to determine which HTTP method the application uses.

For example:

```http
GET /?filename=test%3B HTTP/1.1
```

The important part is:

```text
GET
```

Now we can investigate whether the security filter behaves differently when the HTTP method is changed.

---

# 7. Change the Request Method

In Burp Suite:

1. Intercept the request.
    
2. Right-click it.
    
3. Select **Change Request Method**.
    
4. Send the modified request.
    
5. Observe the response.
    

The important idea is:

```text
Original
GET
 │
 ▼
Security filter
 │
 ▼
Malicious Request Denied ❌
```

Then test another method, such as:

```text
POST
```

or, depending on the lab's intended request flow, compare the alternate method against the original.

---

# 8. What Happens in the Lab?

The altered request no longer receives:

```text
Malicious Request Denied!
```

Instead, the file is successfully created.

This is a major finding.

```text
Original request
      │
      ▼
Security filter
      │
      ▼
Blocked ❌


Tampered HTTP method
      │
      ▼
Filter bypass
      │
      ▼
File created ✓
```

### 🔥 Important

At this point, we know that **changing the HTTP verb changes the security behavior**.

But we still need to prove whether this is actually a security vulnerability.

---

# 9. Don't Stop at the Filter Bypass

This is an extremely important penetration-testing principle.

If we discover:

```text
Security filter bypassed
```

we should determine:

> **What vulnerability was that filter supposed to prevent?**

In this lab, the filter is protecting against:

# **Command Injection**

So the next step is to safely validate the impact within the authorized HTB lab.

---

# 10. Command Injection — Why It Matters Here

Command Injection occurs when attacker-controlled input is incorporated into an operating-system command in an unsafe manner.

Conceptually:

```text
User Input
    │
    ▼
Application
    │
    ▼
OS Command
    │
    ▼
Server executes attacker-controlled command
```

The File Manager is apparently using the supplied filename in a way that can reach command execution.

The security filter is intended to prevent this.

---

# 11. Proving the Filter Was Bypassed

The lab uses a filename containing two commands:

```text
file1; touch file2;
```

The conceptual structure is:

```text
file1
  ;
  ↓
touch file2
  ;
```

The semicolon is significant because, in a shell command context, it can separate commands.

The intended verification is:

```text
file1
file2
```

If **both files appear**, that demonstrates that the injected command was actually executed.

---

# 12. Verification Flow

The test works conceptually like this:

```text
Input:
file1; touch file2;
       │
       ▼
Application processes filename
       │
       ▼
Command execution
       │
       ├──► Create file1
       │
       └──► Execute "touch file2"
                     │
                     ▼
                 Create file2
```

Then check the File Manager.

If we see:

```text
file1
file2
```

we have strong evidence that command injection occurred.

---

# 13. Why This Proves the Filter Was Bypassed

Initially:

```text
test;
```

was blocked.

Therefore:

```text
Security filter
      │
      ▼
Detects suspicious input
      │
      ▼
Blocks request
```

After HTTP Verb Tampering:

```text
file1; touch file2;
        │
        ▼
Filter bypassed
        │
        ▼
Command reaches vulnerable functionality
        │
        ▼
Both files created
```

Therefore:

> **The HTTP Verb Tampering vulnerability allowed us to bypass the security filter and reach the underlying Command Injection vulnerability.**

---

# 14. Complete Attack Chain

```text
                  File Manager
                       │
                       ▼
                 Enter filename
                       │
                       ▼
              Special characters
                       │
                       ▼
                Security Filter
                       │
                       ▼
                  BLOCKED ❌
                       │
                       │
                Test HTTP verbs
                       │
                       ▼
                Change HTTP Method
                       │
                       ▼
              Filter not triggered
                       │
                       ▼
               Malicious input
                       │
                       ▼
              Command Injection
                       │
                       ▼
             OS command execution
                       │
                       ▼
              file1 + file2 created
                       │
                       ▼
                  SUCCESS ✓
```

---

# 15. The Critical Coding Mistake

The vulnerability generally comes down to **inconsistent input handling**.

A simplified vulnerable design might look like:

```text
POST parameter
      │
      ▼
Security filter
      │
      ▼
Application


GET parameter
      │
      ▼
Application
      │
      ▼
No equivalent filter
```

This creates two different paths to the same functionality.

### Secure design

```text
GET ────┐
POST ───┤
PUT ────┤
PATCH ──┤
DELETE ─┤
         ▼
   Common validation
         │
         ▼
   Safe application logic
```

The exact methods allowed should depend on the application's requirements, but **every accepted input path must receive appropriate security controls**.

---

# 16. Filter Bypass vs Vulnerability

This distinction is worth remembering.

### Filter bypass

Means:

> We found a way around a particular security check.

### Underlying vulnerability

Means:

> The dangerous functionality can actually be abused after bypassing the check.

In this lab:

```text
HTTP Verb Tampering
        ↓
Security filter bypass
        ↓
Command Injection
```

The **HTTP Verb Tampering** is the enabling vulnerability, while **Command Injection** is the underlying vulnerability that the filter was intended to prevent.

---

# 17. Why This Can Be Missed by Automated Scanners

This is one of the most important concepts from the previous section.

A scanner may see:

```text
GET request
   ↓
Malicious input
   ↓
Blocked
```

and conclude:

```text
Protected ✓
```

But a manual tester can ask:

```text
What happens if I change GET → POST?
```

and discover:

```text
POST
 ↓
Filter bypass
 ↓
Malicious input accepted
```

Therefore, automated scanning may miss vulnerabilities that depend on **application-specific logic and inconsistent parameter handling**.

---

# 🧠 18. Key Concepts to Memorize

### HTTP Verb Tampering

Changing the HTTP method to exploit differences in how the application handles requests.

### Security Filter

A defensive mechanism intended to detect or block malicious input.

### Insecure Coding

When security checks are implemented inconsistently across different HTTP methods or input sources.

### Filter Bypass

Finding an alternate request path that reaches the vulnerable functionality without triggering the intended security control.

### Command Injection

A vulnerability where attacker-controlled input can influence operating-system command execution.

---

# ⚔️ Previous Section vs This Section

||**Basic Authentication Bypass**|**Security Filter Bypass**|
|---|---|---|
|Root cause|Insecure server configuration|Insecure application coding|
|Target|Authentication|Security filter|
|Technique|Change HTTP method|Change HTTP method|
|Example|`GET → HEAD`|Alternate method bypasses filtering|
|Result|Access protected functionality|Malicious input reaches vulnerable functionality|
|Underlying issue|Authentication configuration|Inconsistent input validation/filtering|

---

# 🎯 Lab Methodology

For an authorized lab, remember this workflow:

```text
1. Identify interesting functionality
            ↓
2. Submit suspicious input
            ↓
3. Observe security filter
            ↓
4. Intercept request in Burp
            ↓
5. Identify HTTP method
            ↓
6. Test alternate HTTP methods
            ↓
7. Compare responses
            ↓
8. Determine whether filter is bypassed
            ↓
9. Validate the underlying vulnerability
            ↓
10. Document impact
```

---

# 🔥 Quick Revision

```text
INSECURE CODING
       ↓
Security filter only covers certain request paths
       ↓
Attacker changes HTTP verb
       ↓
Alternate request path avoids filter
       ↓
Malicious input reaches application
       ↓
Underlying vulnerability becomes exploitable
```

### ⭐ Golden Rule

> **Never assume that a security filter is effective simply because it blocks malicious input through the application's normal HTTP method. Test whether alternate HTTP methods or input sources can reach the same functionality without passing through the filter.**

And the most important distinction:

> **The goal isn't merely to bypass the filter — the goal is to verify what security control was bypassed and what impact that bypass enables.**