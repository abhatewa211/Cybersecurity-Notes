## 🎯 What You'll Learn

This module focuses on:

- Understanding **Adobe ColdFusion**
    
- Identifying ColdFusion during enumeration
    
- Recognizing default ports
    
- Identifying ColdFusion through:
    
    - Port scanning
        
    - File extensions
        
    - HTTP headers
        
    - Error messages
        
    - Default files/directories
        
- Enumerating the **CFIDE** directory
    
- Identifying the exact ColdFusion version
    
- Understanding historical ColdFusion vulnerabilities
    

---

# 1. What Is ColdFusion?

**ColdFusion** is a programming language and web application development platform based on **Java**.

It was initially developed by **Allaire Corporation in 1995**, acquired by **Macromedia in 2001**, and later Macromedia was acquired by **Adobe Systems**, which currently owns and develops ColdFusion.

ColdFusion is designed to build:

- Dynamic web applications
    
- Interactive web applications
    
- Database-connected applications
    
- API-integrated applications
    

It can connect to databases such as:

```text
MySQL
Oracle
Microsoft SQL Server
```

### Mental model

```text
                 ColdFusion
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Web App    Database     APIs
          │          │          │
          └──────────┴──────────┘
                     │
                  Java Runtime
```

---

# 2. CFML — ColdFusion Markup Language

ColdFusion uses:

**ColdFusion Markup Language (CFML)**

CFML is the proprietary language used to develop dynamic ColdFusion applications.

Its syntax is similar to HTML and uses **tags and functions** for common application tasks.

For example, the `cfquery` tag can execute SQL statements:

```html
<cfquery name="myQuery" datasource="myDataSource">
  SELECT *
  FROM myTable
</cfquery>
```

Then `cfloop` can iterate through the returned records:

```html
<cfloop query="myQuery">
  <p>#myQuery.firstName# #myQuery.lastName#</p>
</cfloop>
```

### 🔑 CPTS takeaway

If you see:

```text
.cfm
.cfc
```

during web enumeration, **ColdFusion should immediately come to mind.**

---

# 3. What Can ColdFusion Do?

ColdFusion provides built-in functionality for:

- Database integration
    
- Web services
    
- Email
    
- PDF manipulation
    
- Graphing
    
- Session management
    
- Form handling
    
- Debugging
    
- File uploading
    
- URL rewriting
    
- AJAX
    

It can also work with:

```text
JavaScript
Java
```

---

# 4. ColdFusion Benefits

|Feature|Description|
|---|---|
|**Developing data-driven web applications**|Builds rich, responsive applications with session management, form handling, debugging, etc.|
|**Integrating with databases**|Supports Oracle, SQL Server, MySQL and other databases|
|**Simplifying web content management**|Dynamic HTML, forms, URL rewriting, file uploading, large forms, AJAX|
|**Performance**|Designed for low latency and high throughput|
|**Collaboration**|Supports code sharing, debugging and version control|

---

# 5. ColdFusion Versions

The module states that, **at the time it was written**, the latest stable version was:

```text
ColdFusion 2021
```

with ColdFusion 2023 about to enter Alpha.

Earlier versions included:

```text
ColdFusion 2018
ColdFusion 2016
ColdFusion 11
```

⚠️ **Important:** These version statements are historical to the module. For an actual current assessment, always verify the deployed version separately.

---

# 6. ColdFusion Security History

ColdFusion has historically been affected by vulnerabilities including:

```text
SQL Injection
XSS
Directory Traversal
Authentication Bypass
Arbitrary File Upload
```

### Important CVEs from the module

|CVE|Vulnerability|
|---|---|
|**CVE-2021-21087**|Arbitrary disallow of uploading JSP source code|
|**CVE-2020-24453**|Active Directory integration misconfiguration|
|**CVE-2020-24450**|Command injection vulnerability|
|**CVE-2020-24449**|Arbitrary file reading vulnerability|
|**CVE-2019-15909**|Cross-Site Scripting (XSS)|

### 🧠 CPTS Tip

Don't immediately exploit a CVE just because you see a matching technology.

First determine:

```text
Is the service actually ColdFusion?
        ↓
What version?
        ↓
Is the vulnerable component present?
        ↓
Is the vulnerability applicable?
        ↓
Can it be safely tested?
```

---

# 7. Default / Common ColdFusion Ports

ColdFusion can expose several ports.

|Port|Protocol|Purpose|
|--:|---|---|
|**80**|HTTP|Non-secure web communication|
|**443**|HTTPS|Secure web communication|
|**1935**|RPC|Client-server communication|
|**25**|SMTP|Sending email|
|**8500**|SSL|Server communication via SSL|
|**5500**|Server Monitor|Remote administration|

### 🚨 Important

Default ports can be changed during:

- Installation
    
- Configuration
    

So:

```text
8500 open
```

doesn't automatically mean ColdFusion.

But:

```text
8500 + CFIDE + .cfm
```

is a **very strong indicator**.

---

# 🔎 8. ColdFusion Enumeration

There are several ways to identify ColdFusion.

The module gives five major methods:

```text
1. Port Scanning
2. File Extensions
3. HTTP Headers
4. Error Messages
5. Default Files
```

Let's break each one down.

---

# 9. Method #1 — Port Scanning

ColdFusion commonly uses:

```text
80
443
8500
```

Nmap may also be able to identify ColdFusion during a service scan.

Example from the module:

```bash
nmap -p- -sC -Pn 10.129.247.30 --open
```

Output:

```text
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-13 11:45 GMT
Nmap scan report for 10.129.247.30
Host is up (0.028s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown
```

### Interesting result

```text
8500/tcp open fmtp
```

At first glance Nmap identifies it as:

```text
fmtp
```

But we know:

```text
8500 → common ColdFusion port
```

Therefore, investigate it manually.

---

# 10. Method #2 — File Extensions

ColdFusion applications commonly use:

```text
.cfm
.cfc
```

### Example

If you discover:

```text
/index.cfm
/login.cfm
/admin.cfm
/test.cfc
```

you should consider ColdFusion as a likely technology.

---

# 11. Method #3 — HTTP Headers

HTTP response headers may identify ColdFusion.

Possible indicators include:

```text
Server: ColdFusion
X-Powered-By: ColdFusion
```

### Pentesting mindset

Don't rely on one fingerprint.

Combine:

```text
Headers
+
Extensions
+
Ports
+
Directories
+
Errors
```

---

# 12. Method #4 — Error Messages

ColdFusion-specific errors can reveal the underlying technology.

For example, errors may reference:

```text
ColdFusion
CFML
CFIDE
Application.cfm
ColdFusion functions/tags
```

The module specifically notes that application errors can contain references to ColdFusion-specific tags or functions.

### 🚨 Why errors matter

A normal page may reveal nothing.

But:

```text
Malformed request
       ↓
Application error
       ↓
Framework-specific message
       ↓
Technology fingerprint
```

Error handling is therefore part of enumeration.

---

# 13. Method #5 — Default Files

ColdFusion installations can create default files/directories such as:

```text
admin.cfm
CFIDE/administrator/index.cfm
```

The **CFIDE** directory is particularly important.

---

# 🧠 ColdFusion Fingerprinting Cheat Table

|Indicator|Example|
|---|---|
|Port|`8500`|
|Extension|`.cfm`|
|Extension|`.cfc`|
|Header|`Server: ColdFusion`|
|Header|`X-Powered-By: ColdFusion`|
|Directory|`/CFIDE/`|
|Admin path|`/CFIDE/administrator/`|
|File|`admin.cfm`|
|Error|ColdFusion-specific error|

The more indicators you find, the higher your confidence.

---

# 🔥 14. Real Enumeration Scenario

The module's target:

```text
10.129.247.30
```

Nmap finds:

```text
135/tcp
8500/tcp
49154/tcp
```

The interesting port is:

```text
8500
```

because it is associated with ColdFusion.

The tester browses to:

```text
IP:8500
```

and finds:

```text
CFIDE
cfdocs
```

directories.

![Image](https://images.openai.com/static-rsc-4/xDVortBJ79dP3czIN8gyKfH7801r4IUt4ZnpJ4cwMrvxvwjo_2BYtwOKpRBkuOHQGn2ZsZxIiSrTqp-yJne58rKPqnI7pPJGg-1kp16GTY_OwpZki2j63lsFjIZGCtJllEK6nmc0FmlLD7qy-SaD9XeUfftCoWxIY3WPxvfsmFxZPKYEA5tVY9dWCSPEdsJ4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iFI63eOoXTnT_BGYWljmnVMKh6pXRxPm7R-i1akOZgFGgFgC5vwXlGQQUCE5yEiUG0OLe43Pdr_l8yvMcsasjGPBVDaVNeDBOGU0TvqIgswxnAFJdGXaHEaecW0PK9neFl6DCPoSSnb5gWsVdOTrivQHlMjYoxtM4PE9Nn-iTBuNxtzr2LirTtxygqoFhhLl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/UlxCfhwRZ969t1aZZ9oR1kzWGdETRB4shaC69xhFOs9IuvOK_8lKOMYRgDjdXnLRUbArtoNMEAKvl8who8l_VBxnbwgUV1Oluv48COH6sSYdHphu5QCbor9qNaqd4MWIUGEjAa_rnOgp-EdIPI4EwN531GGH9lUO3sgr0ukVgyMu697NUU76XYKmlUgOG0Qt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/F_IdPNykn2xgWg9TC-soXlB4RoNST3PSGgkdtYIycRpjrF52YIF__yNXpw8HgDJqyy3t5HxOIRUdC9QnD87zVVrgglyAAFSaQOzLqSmsMOEIB4s-VFXXzvFiR56JdFhC7sYbtYSIy5gSxS2TO54KLm1NOu-ohp2xVi9WkfIndnvE3bCNOeAPXmsLWrEHT1JO?purpose=fullsize)

---

# 15. `/CFIDE/` — Very Important

The `/CFIDE/` directory exposes ColdFusion-related files and functionality.

The module shows files/directories including:

```text
Application.cfm
adminapi/
install.cfm
```

This is a **strong fingerprint**.

If you encounter:

```text
/CFIDE/
```

during an assessment, investigate it carefully.

---

# 16. Information Leakage Through Errors

The module also encounters an error page:

```text
Invalid request of Application.cfm
```

along with debugging information and ColdFusion-related resources.

This is another example of why verbose errors are dangerous.

They can disclose:

```text
Technology
Framework
File names
Application structure
Debugging information
Potential paths
```

---

# 🚨 17. Exact Version Identification

The biggest discovery happens when the tester visits:

```text
/CFIDE/administrator
```

The page loads the:

```text
ColdFusion 8 Administrator
```

login page.

This confirms that the server is running:

# **ColdFusion 8**

![Image](https://images.openai.com/static-rsc-4/UlxCfhwRZ969t1aZZ9oR1kzWGdETRB4shaC69xhFOs9IuvOK_8lKOMYRgDjdXnLRUbArtoNMEAKvl8who8l_VBxnbwgUV1Oluv48COH6sSYdHphu5QCbor9qNaqd4MWIUGEjAa_rnOgp-EdIPI4EwN531GGH9lUO3sgr0ukVgyMu697NUU76XYKmlUgOG0Qt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/F_IdPNykn2xgWg9TC-soXlB4RoNST3PSGgkdtYIycRpjrF52YIF__yNXpw8HgDJqyy3t5HxOIRUdC9QnD87zVVrgglyAAFSaQOzLqSmsMOEIB4s-VFXXzvFiR56JdFhC7sYbtYSIy5gSxS2TO54KLm1NOu-ohp2xVi9WkfIndnvE3bCNOeAPXmsLWrEHT1JO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8uBzuqXAFqvXQgznAlv5Q96xoQCKPQdIXQY7Joym2HkOjv1PoSsTVqcMWl0CnJLiwqmR8Hf-7ye4wSXp35XqeT7v7rMc0UKYIQkaCYucAKbXT9piJCplK4-3Ni0tkpbIY0t1Ql-OIDQl1cPz1HtxJt6pRNJYED90b2faJ9Drq5-0WrQNjOXhH4oVfqvXsW6m?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/geloUA2n3ekJve4OEAJFs2_ZrDUVL6CSL9RoIsP4xh5pVK_FSYwOxUaxy7KOZGHvIsdwntLYLmjGVKMFfbqv6d53_ht_obDT73BH5Rj2Mwzqs5YEzO1KgNWxis8fz7bo_udH-L1DnNFMTEt71WkG3F8CC-jff6QLbblJ0h_niyhn_L3LY2MVVnWMGng3WZJv?purpose=fullsize)

### Why version identification is critical

Knowing:

```text
ColdFusion
```

is useful.

Knowing:

```text
ColdFusion 8
```

is **much more useful**.

Because now you can investigate vulnerabilities specifically applicable to that version.

---

# 🧭 Complete Enumeration Flow

```text
                  TARGET
                    │
                    ▼
              Port Scanning
                    │
                    ▼
              8500/tcp open
                    │
                    ▼
             Browse :8500
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
       CFIDE                cfdocs
          │
          ▼
      .cfm files
          │
          ▼
   ColdFusion fingerprint
          │
          ▼
 /CFIDE/administrator
          │
          ▼
 ColdFusion 8 identified
          │
          ▼
  Version-specific research
```

---

# 🧪 Practical Enumeration Methodology

When you encounter a potentially ColdFusion server:

### Step 1 — Full TCP scan

```bash
nmap -p- -sC -Pn TARGET --open
```

Look for:

```text
80
443
8500
```

and unusual HTTP services.

---

### Step 2 — Visit interesting ports

For example:

```text
http://TARGET:8500/
https://TARGET:8500/
```

Look for:

```text
CFIDE
cfdocs
.cfm
.cfc
```

---

### Step 3 — Inspect HTTP headers

Look for:

```text
Server: ColdFusion
X-Powered-By: ColdFusion
```

---

### Step 4 — Look for ColdFusion extensions

Search for:

```text
*.cfm
*.cfc
```

---

### Step 5 — Check common paths

Especially:

```text
/CFIDE/
/CFIDE/administrator/
/CFIDE/administrator/index.cfm
/admin.cfm
```

---

### Step 6 — Examine errors

Look for:

```text
ColdFusion
CFML
Application.cfm
CFIDE
```

---

### Step 7 — Determine exact version

Don't stop at:

```text
ColdFusion detected
```

Try to establish:

```text
ColdFusion 8
ColdFusion 11
ColdFusion 2016
ColdFusion 2018
ColdFusion 2021
```

or whatever exact version is exposed.

---

# 🧠 CPTS Exam Points

## ⭐ Point 1 — Technology fingerprinting

You should be able to identify ColdFusion using multiple indicators:

```text
8500
.cfm
.cfc
CFIDE
ColdFusion headers
ColdFusion errors
```

---

## ⭐ Point 2 — `CFIDE` is a strong indicator

Remember:

```text
/CFIDE/
```

is highly associated with ColdFusion installations.

---

## ⭐ Point 3 — Don't trust Nmap's service name blindly

The scan showed:

```text
8500/tcp open fmtp
```

That doesn't mean:

```text
8500 = FMTP
```

and stop.

Instead:

```text
Port
 ↓
Investigate service
 ↓
HTTP response
 ↓
Directories
 ↓
Application fingerprint
```

---

## ⭐ Point 4 — Default ports aren't guaranteed

The module explicitly states:

> Default ports can be changed during installation or configuration.

Therefore:

```text
No 8500
```

does **not** mean:

```text
No ColdFusion
```

---

## ⭐ Point 5 — Version > Product

For vulnerability research:

```text
ColdFusion
```

isn't enough.

You want:

```text
ColdFusion 8
```

or:

```text
ColdFusion 2018
```

etc.

Version information determines which vulnerabilities are potentially relevant.

---

# 📝 CPTS Notes — What I'd Memorize

```text
ColdFusion
    ↓
Java-based web application platform
    ↓
Uses CFML
    ↓
Common extensions:
.cfm
.cfc
    ↓
Important directory:
/CFIDE/
    ↓
Important admin path:
/CFIDE/administrator/
    ↓
Common port:
8500
    ↓
Other common web ports:
80 / 443
```

### Important historical CVEs from this module

```text
CVE-2021-21087 → Arbitrary disallow of uploading JSP source code
CVE-2020-24453 → Active Directory integration misconfiguration
CVE-2020-24450 → Command injection
CVE-2020-24449 → Arbitrary file reading
CVE-2019-15909 → XSS
```

---

# ⚡ 30-Second Cheat Sheet

|🔥 Remember|Value|
|---|---|
|Platform|**ColdFusion**|
|Based on|**Java**|
|Language|**CFML**|
|Extensions|`.cfm`, `.cfc`|
|Important directory|`/CFIDE/`|
|Admin path|`/CFIDE/administrator/`|
|Common port|`8500`|
|HTTP|`80`|
|HTTPS|`443`|
|Example discovered version|**ColdFusion 8**|
|Key enumeration methods|Ports, extensions, headers, errors, default files|

### 🔥 Golden Mental Model

```text
              FIND
               │
               ▼
          8500 / HTTP
               │
               ▼
        Check .cfm/.cfc
               │
               ▼
          Check headers
               │
               ▼
           Check CFIDE
               │
               ▼
      /CFIDE/administrator
               │
               ▼
       Identify VERSION
               │
               ▼
     Research applicable CVEs
```

**CPTS mindset:** don't jump from `8500` → exploit. Go **fingerprint → enumerate → identify version → validate attack surface → then test**.