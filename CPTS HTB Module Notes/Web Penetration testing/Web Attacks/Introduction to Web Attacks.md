![Image](https://images.openai.com/static-rsc-4/v6O6O2xfI461sTLBy2oeq8fj19dCSijLL4qkb30hefS1wl_z0hPhi7R9V24ojeF8tifb7Lt_DHLNrs5YfeXfGpEb4nv7kYhZd5v_LX90gKIr-g1BlEwxA0I6i0sA-JpfOgtlSoNTCOFx1IlreYX2U4Zrzv7RzpCa_9VnFCoSG74Cik1-40t6ZoaWVD2cT-YP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6dyqNne4wm170NTWu_X2KpucQrqOCyj33MPsKjPs-Ofy5imiOlwkBYDZBLi9Eo4GkBJhUpZtyzvEeb_pVjPXjYMyLbHduE-vKcUYwA8fxGG63xyc9_2Kn3sbaHfmuLOpa2tPTlisJpfd5_1kUdGp_O3mzvN3LDvCxGiOEvz48y9yCIAVhSXoMAC7qsKigSbI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FoPXRhjCjMYanDtdEW1NCqVskBppdwQSLatKyobh2nJGDZWdKEGuSIu-rVw7-_-noNOcZ3WzVV_FFgafKRIQa8Yo2_h9uvi6Xls-1Z0hbwPKYAqVMzMt7kEB9_UJUhW-vcQxiqAw2InZ899bfDMphjnNt4QVsu67JEWQyfE_jeYwcA7_IyX2qr6xZshtNGHn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_i17b4bxfQ2L6f1L3WLADB_tz6Rroj-XjqmPY-sjQ0SmyTXmmEfUzuBdSo282iKTimyHXQ74cY7SRKwO7crntmMrwLdbrsxMWbHNvUJSUIQIHydE4mpqX150cL7Txtt1r3uxMgJ29YSCXZpZqp3XGHyGBylk8ehfYjNq6bv3j0RX9X0uvrnNb_dPi3DTiXwI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TvP6MB-QsTByls9ygbFRp1FGJmPmeEI_PCIdYvwZdA2mAcZ44hLg9H7GZ_Lw--HrN6E2dG_tZ5s-clqspKPlEvenCzc1C0pwZpOTBN3GMbIKOpg-KoWuAeMymayrtXhbaQxW7aofDE39nuZI9eQ3drka9h7DdKM_zQgbUHZGQ6fCqORmbQzBIyc4c6DQMRvi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PWO2lhJ-m4iHiJdm-dqNxlK002d8jbKFwhhJjzaTdpPvsQdKFeGv7V2SIMiRkENvnoP1nogIlwDa94ufBuezEO8uloseQoS4-t_so3-Z3yS-Dt8bn-HsPfkdvN3j5HqzpUTeD9szqUGZA-8HSLHU8bpdf8Mk2OCPhz5tcDDiDzAXsoPe_WBpYZomMgHFqigb?purpose=fullsize)

## 1. Introduction

Web applications have become extremely common and are now used by almost every type of business. Because businesses increasingly depend on web applications, **protecting them against malicious attacks has become critical**.

Modern web applications are also becoming:

- More complex
    
- More feature-rich
    
- More interconnected
    
- More dependent on APIs and external services
    
- More exposed to the Internet
    

As applications become more advanced, the number and complexity of possible attacks also increase.

### 🔑 Key Point

> **The more functionality a web application exposes, the larger its attack surface can become.**

This is one reason **web attacks are among the most common attacks against companies today**.

Protecting web applications is therefore becoming one of the **top priorities for IT and security departments**.

---

# 2. Why Web Applications Are Important Targets

A web application is often the **public-facing entry point** into an organization's infrastructure.

A simplified attack path can look like:

```text
Attacker
   │
   ▼
Internet
   │
   ▼
Web Application
   │
   ├──► Database
   │
   ├──► Internal APIs
   │
   ├──► File Storage
   │
   └──► Internal Network
             │
             ├──► Servers
             ├──► Applications
             └──► Sensitive Data
```

If an attacker successfully compromises an external-facing web application, the compromise may potentially be used to reach the **internal network**.

This can eventually result in:

- Theft of sensitive information
    
- Theft of business assets
    
- Unauthorized access
    
- Service disruption
    
- Further system compromise
    
- Financial losses
    

### ⚠️ Important

A vulnerability in a web application does **not necessarily remain isolated to the application itself**.

Depending on the vulnerability and the application's privileges, it can become a stepping stone toward other systems.

---

# 3. Internal Web Applications and APIs

An organization does **not** need to have a publicly accessible web application to be vulnerable.

Companies may also have:

### Internal Web Applications

Applications accessible only from the company's internal network.

Examples:

```text
Employee Portal
Admin Dashboard
Internal HR System
Internal File Management
Monitoring Dashboard
```

### External APIs

Modern applications frequently communicate through APIs.

For example:

```text
Mobile App
     │
     ▼
   API
     │
     ├──► Database
     ├──► Authentication
     └──► Internal Services
```

These APIs can be vulnerable to many of the **same classes of attacks as web applications**.

### 🔑 Key Takeaway

> **Internal web applications and external-facing APIs can be vulnerable to the same types of attacks and can potentially be leveraged toward the same goals.**

---

# 4. Attack Surface

The **attack surface** is essentially the collection of points through which an attacker may interact with or attempt to compromise an application or system.

For a modern web application, this could include:

```text
                    Web Application
                          │
       ┌──────────────────┼──────────────────┐
       ▼                  ▼                  ▼
     HTTP                APIs              Files
       │                  │                  │
       ▼                  ▼                  ▼
 HTTP Methods        API Parameters      File IDs
       │                  │                  │
       └──────────────────┼──────────────────┘
                          ▼
                     Backend
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
           Database     Server      Services
```

The larger and more complex the application, the more potential attack surfaces it may have.

---

# 5. Three Web Attacks Covered in This Module

This module focuses on three important web attacks:

|#|Attack|Main Security Issue|
|---|---|---|
|1|**HTTP Verb Tampering**|Improper handling of HTTP methods|
|2|**IDOR**|Broken access control / authorization|
|3|**XXE Injection**|Unsafe XML processing|

The module focuses on learning how to:

> **Detect → Exploit → Prevent**

each of these attacks.

---

# 🔴 6. HTTP Verb Tampering

![Image](https://images.openai.com/static-rsc-4/eNKxj_WgEgbhR9B_DwO0KhdiTSstJmFxRoDbLFoKNZBkuEGvj6MFzReXZMNaXv2H5dX8pxPSuVLMK2yO7UzzLPAIUWWCsTkeiL4gMP_VCupwTDjeArNXkdf3Xd9h_1TJ_sqz5z-p-Ag8KMhfnyK0ufvx4hU3xOGWpJ-LTw9Cyf8opMmet7OcPA4YqE9zmujS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ERdc3DeAGKTlXOCmXlHC72urKPfjdKsfkNxN2DX0yZKPrYdPVRQAVT_7pJ2OU_pKikoCb115wU0vo20foroYAoLs6oQh6XE6hKbYlZqFSiYFfhzcVis1x-nsTD4jBgMRGwM5Kd_M2v2KmpXCZVbL0uyfd-eR01PFsGnA1KshhYpSj4AqD1m1VTNL-GiIRpPF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MmAeJcFmiwbwxmXgvx4ofyQRI5giobemi6a7jreH913-0TszU7sbYe40XOyl-eaVhC4nmch6Dp4EaYeo_CCu0jPGtOROX7F-B1jzV5Ukr0IihQA01mHQBbjeN-_cSg5m9WfX3R7jCgEqlEr9pg43JVJUMaOSKYqI-d1RVq27K09ZC7UIsVsQIjbbPk-IAbMt?purpose=fullsize)

## What is HTTP Verb Tampering?

**HTTP Verb Tampering** is an attack that exploits web servers or applications that accept multiple HTTP verbs/methods.

Common HTTP methods include:

```text
GET
POST
PUT
DELETE
PATCH
HEAD
OPTIONS
```

Applications may normally expect a particular HTTP method for a particular operation.

For example:

```http
GET /admin
```

might be handled differently from:

```http
POST /admin
```

If the application's security controls are incorrectly configured, changing the HTTP method may cause the request to be processed differently.

---

## How the Attack Works

Suppose an application has an authorization mechanism that protects:

```http
POST /admin/delete.php
```

The application may correctly reject an unauthorized `POST` request.

However, if the backend or web server also accepts another method and applies different security rules, an attacker might try an unexpected HTTP method.

Conceptually:

```text
Expected Request
       │
       ▼
POST /admin
       │
       ▼
Authorization Check
       │
       ▼
     DENIED
```

An attacker tests:

```text
Unexpected HTTP Method
       │
       ▼
GET /admin
       │
       ▼
Different Processing
       │
       ▼
Potential Authorization Bypass
```

### 🔑 Important

> HTTP Verb Tampering can potentially bypass a web application's **authorization mechanism**.

It may also potentially bypass security controls designed to protect against **other web attacks**.

---

## Why HTTP Verb Tampering Happens

Possible causes include:

- Incorrect server configuration
    
- Different authorization rules for different HTTP methods
    
- Application logic that assumes only one method will be used
    
- Web server/application inconsistencies
    
- Security filters that inspect only specific HTTP methods
    
- Poorly implemented access controls
    

---

## Example Concept

Imagine an application expects:

```http
POST /upload
```

and applies authentication checks to `POST`.

But the server also processes:

```http
PUT /upload
```

If `PUT` does not receive the same security checks, the difference in behavior could create a security vulnerability.

### Security Principle

**Every HTTP method that can reach sensitive functionality should be subject to appropriate authorization and validation.**

---

# 🟠 7. Insecure Direct Object References (IDOR)

![Image](https://images.openai.com/static-rsc-4/9CyxjyFcBHnKzE4XctZywdO2IIQrRwZgWjJDyj6xfqHF_QnXqP4BCwW76tQ9gFDTbpFPQnyi9dQCA2rDXLoub7ExXZQ8luEbptrB_rC5PbbW_mknhbvaJ-9SiXJBNSJWrEXNLpuhOtlQskliSUepPGal8wffwPzM1RWoGVIAkmZ5zu3lUowm6asstHJK69pL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XmupKmPtwxGWl8unxG5BJHCD9u0cG0MhCfAcqGJkSw_1cMYNmnt5hekh8JQHmeyDKG0Xt5mADFg5RJmmnuISaPo95wq4FDBi10S3JZ8mqnjEm8EQBf0VJ5m2r2SU5x--Br8wFwTnlZI779sbLRJ26CwgLU5sy1_KE_ePiACKQC7fZ5nqa4yygNyYHM-FfSKB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/WPJlPm0HkYGpV-hAILBFoM0cD0tAEZ_dL0y2OKcFuI6dpEDGnstoL4FQSQhNcNQtA2jHRfWDqOSyyfY-57rSUE-l8Qy3RtGS8-YgwLeFTXPGizcG_ocqlQVEGkmLjDD53Q5luh7R0Bnjit2MvHf2dglhmVqj4pXTJ5x09oDY5mBCVhPRbQ18WtVNbKj4KEUl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vc5fEXArae92DIZiDW4QIxgjHrV5H0lasUTCDZBcJsjN1Ov4L5IIdJKYcL3ryqylFe7DXx8GCK6c2UKLTIUOwUGrXc0PewIT9Ia4KZ0uR9q6RxHMy-8H6eN6FX-m_jIpQuXMTtqvKq4QWvwp34MyyRmH4oqUyE9UmlL5uQVnVscIbJT2HuimSACotp-fc9ue?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_xHU_CQcPttsxV7mzmTivyX9uPpGusc627MckJ_SKWGfBXrARumfvHHlHIup46hJE8QGwjuhk87iya7lXOXXV_I6uuk5CJnIkFQaEtkbYGRdfeQfpg3g_C-jmNk43ZGMoNRgO4frAtq7sAaH7zjsy5r8ZMWTUlSd70WdWKQw0m5jrorD-EtZ-GL-9q3Kj22j?purpose=fullsize)

## What is IDOR?

**IDOR = Insecure Direct Object References**

IDOR is one of the most common web vulnerabilities.

It occurs when an application exposes a direct reference to an internal object—such as a file, account, document, or database record—without properly checking whether the requesting user is authorized to access that object.

---

# 8. Understanding "Direct Object Reference"

Suppose an application allows users to download files.

A request might look like:

```http
GET /download.php?id=1001
```

The number:

```text
1001
```

could represent a file ID.

The application should verify:

```text
Does the current user own file 1001?
```

If it simply retrieves the file because the ID exists, there may be an IDOR vulnerability.

---

## Vulnerable Logic

A vulnerable backend might effectively do:

```text
User requests object ID
          │
          ▼
Does object exist?
          │
          ▼
      YES → Return object
```

The missing step is:

```text
Is this user authorized to access the object?
```

---

## Secure Logic

A properly protected application should perform:

```text
User requests object ID
          │
          ▼
Does object exist?
          │
          ▼
Is the user authorized?
       /       \
     YES       NO
      │         │
      ▼         ▼
 Return       Deny
 object       access
```

### 🔑 Core Problem

> **IDOR is fundamentally an access-control problem.**

The application fails to properly enforce authorization on the backend.

---

# 9. Sequential IDs

One reason IDOR vulnerabilities can be easy to discover is that applications sometimes use predictable identifiers.

For example:

```text
/file?id=1001
/file?id=1002
/file?id=1003
/file?id=1004
```

If the application does not properly enforce authorization, changing the identifier could potentially expose another user's resource.

For example:

```text
User A
   │
   ▼
id=1001
   │
   ▼
User A's File


Attacker
   │
   ▼
id=1002
   │
   ▼
User B's File
```

The vulnerability isn't simply that IDs are sequential.

### ⚠️ Important

**Predictable IDs alone do NOT automatically create an IDOR vulnerability.**

The real problem is the **lack of proper server-side authorization**.

---

# 10. What Can IDOR Expose?

Depending on the application, IDOR may expose:

- User files
    
- Personal information
    
- Documents
    
- Account information
    
- Orders
    
- Messages
    
- Images
    
- Invoices
    
- Database records
    
- Other users' resources
    

The impact depends heavily on **what the referenced object contains** and how the application handles authorization.

---

# 11. Why IDOR Is Common

Modern web applications constantly store and reference objects.

For example:

```text
Users
 ├── User ID
 ├── Files
 ├── Messages
 ├── Orders
 ├── Invoices
 └── Documents
```

Applications need identifiers to distinguish these objects.

The security problem occurs when developers assume:

> "If the user knows the object ID, they can access it."

That assumption is unsafe.

### Correct Principle

> **Knowing an object's identifier should never automatically grant permission to access that object.**

---

# 🔵 12. XML External Entity (XXE) Injection

![Image](https://images.openai.com/static-rsc-4/vG77h0z1Udpzy4iW-vg03k9dVdMfCR9kf23REYo8_jG2PsxMbO9u4ggTPiS9bfGbz7Oi-oDP7RQVc9S9LpIHWF5ztdwCsKb_KLbLewy0payOk85NfX-kEviGJMbzDilbZ0IVIHjR90tfC5XL7AM1NtdKoRDm3Hythnw_2Oy0Kest7-BE2RzvEugBWl0VMk1e?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EQiPde7i8NK-ZvsncVO_0-qz63ezMygTrt3E7xF2-K8vAo1EAajizkp6bsMgo3etf52mAYaKn0Uf8NUiFVFZcYYMN-ZKkvmk2bQ-RFI6Z0oYHVXDWLNZiWqlbHVwCr53_cUG5PmMj2RbIVooKjGvNNZMArFEaCnAYFgXO_6aLK_i5T6EfRogva4dbQCjZZaQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sFVz8Z3Ca51OvOsnUjEwIpUao0AGf_QiKmD1E4CtWL9ZC57f0kJZf5632qdPds-MsT8Y5XTGgt08n0MYBPKlmfty14SfSLQ1SKrG7taoLzgHYrpKqvhQZGiFIULvoUtsS95mVRjHtelBs38LAgfBgl8g7eBWMQq0PplO03HRzsax6YYVtrb7d7Wyz08UvUtL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/O7KGS4KYPOuebQwauA1nFkHYxEM0d5HdhpDCCfD-xUxcOKe7I9_sVpwaZXe1HkqvsHiHDdpRUCdHAk3alX-7nBq5Kl7EfL2rYPGC4fnMVybzUEdYBnJePUZ53SZUQZSdOAkqwfmDcdOEDERsY2_0PLxhEVw52-PcyRHbIDNPOuoOMMLUaUi6S-HZONzzHDst?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/75kaWdndispNEgp6wUDL-ttHYWzPmczuRZ0d0cpmbj1MhPseuByKWQ28oUfRLPCHY1IIHUVARzz4IaCAwrYIvx-CWaDXogooOsQW8_PpkybI6KwD38YP5n-6x5-FUhkUk7GzXE2sMbKLnjiBNumqiEuPKuINXevWm4X3tHlCEMMV3ssq0f2LNMhHRsggokYD?purpose=fullsize)

## What is XXE?

**XXE = XML External Entity Injection**

XXE is a vulnerability that can occur when a web application processes **XML input** using an unsafe or outdated XML parser/library.

XML supports a feature called **external entities**.

If external entity processing is enabled when it shouldn't be, an attacker may be able to manipulate XML input in a way that causes the server to access resources that the attacker should not be able to access.

---

# 13. XML in Web Applications

XML can be used to exchange structured data.

For example:

```xml
<user>
    <name>Arjun</name>
    <role>student</role>
</user>
```

A web application may receive XML from:

- APIs
    
- File uploads
    
- SOAP services
    
- Integrations
    
- Legacy applications
    
- Data-import functionality
    

The application then passes the XML to an XML parser.

```text
Attacker
   │
   ▼
XML Request
   │
   ▼
Web Application
   │
   ▼
XML Parser
   │
   ▼
Application Logic
```

If the parser is improperly configured, this can create an XXE vulnerability.

---

# 14. Why XXE Happens

XXE commonly occurs when:

- XML external entities are enabled unnecessarily
    
- Outdated XML libraries are used
    
- XML parser security settings are incorrect
    
- User-controlled XML is processed without appropriate restrictions
    

The fundamental issue is:

```text
Untrusted XML
      │
      ▼
Unsafe XML Parser
      │
      ▼
External Entity Processing
      │
      ▼
Unauthorized Resource Access
```

---

# 15. Potential Impact of XXE

A successful XXE vulnerability can potentially allow an attacker to **disclose local files stored on the backend server**.

For example, sensitive files might contain:

- Configuration information
    
- Passwords
    
- Credentials
    
- Application settings
    
- Source code
    
- API keys
    
- Other sensitive information
    

This can provide valuable information for further attacks.

---

# 16. XXE and Source Code Disclosure

One particularly important impact is that an attacker may potentially obtain **source code** from the server.

This can enable a:

### Whitebox Penetration Test

A whitebox penetration test is performed with access to the application's internal implementation/source code.

Having source code can reveal:

```text
Application Logic
       │
       ├── Authentication
       ├── Authorization
       ├── Database Queries
       ├── File Handling
       ├── API Endpoints
       └── Hidden Functionality
```

This information can help identify additional vulnerabilities.

---

# 17. XXE and Server Credentials

XXE can potentially be used to access sensitive information available to the server.

In some situations, this may include **hosting server credentials** or other secrets.

If sufficiently privileged credentials are exposed, the consequences can become much more serious.

Conceptually:

```text
XXE
 │
 ▼
Sensitive File / Resource
 │
 ▼
Credentials
 │
 ▼
Server Access
 │
 ▼
Potential Further Compromise
```

The module notes that XXE can potentially lead to **remote code execution**, depending on the environment and available attack paths.

### ⚠️ Important

XXE does **not automatically mean remote code execution**.

The ultimate impact depends on:

- XML parser configuration
    
- Server permissions
    
- Available protocols/resources
    
- Application architecture
    
- Credentials exposed
    
- Other vulnerabilities present
    

---

# 18. Comparing the Three Attacks

|Attack|Main Weakness|What Is Being Abused?|Potential Impact|
|---|---|---|---|
|**HTTP Verb Tampering**|Incorrect handling of HTTP methods|HTTP verbs/methods|Authorization/security-control bypass|
|**IDOR**|Broken access control|Object identifiers/references|Unauthorized access to data/resources|
|**XXE**|Unsafe XML parsing|XML external entities|File/data disclosure and potentially further compromise|

---

# 19. Detection Mindset

When testing a web application, think about the three attacks differently.

### HTTP Verb Tampering

Ask:

> **"What happens if I change the HTTP method?"**

Example:

```text
GET
POST
PUT
DELETE
PATCH
```

Look for inconsistent authorization or security behavior.

---

### IDOR

Ask:

> **"Does the server verify that I am authorized to access this object?"**

Look for:

```text
?id=123
?user=123
?file=123
?document=123
/order/123
/profile/123
```

The important thing is **not merely changing IDs**, but determining whether the backend properly enforces authorization.

---

### XXE

Ask:

> **"Does this application parse XML, and is the parser safely configured?"**

Potential XML input locations include:

```text
API requests
SOAP
XML uploads
Import functionality
Legacy integrations
```

---

# 20. Detection → Exploitation → Prevention

The overall methodology of this module can be remembered as:

```text
             WEB APPLICATION
                    │
                    ▼
               DISCOVERY
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
        HTTP       IDOR      XXE
        Verbs      Access    XML
          │        Control   Parser
          │         │         │
          └─────────┼─────────┘
                    ▼
                DETECTION
                    │
                    ▼
                VALIDATION
                    │
                    ▼
                EXPLOITATION
                    │
                    ▼
                  IMPACT
                    │
                    ▼
                PREVENTION
```

---

# 🧠 High-Value Takeaways

### HTTP Verb Tampering

- HTTP has multiple methods/verbs.
    
- Applications may process different verbs differently.
    
- Incorrect configuration can create security weaknesses.
    
- Unexpected HTTP methods may potentially bypass authorization.
    
- It can also potentially bypass security controls against other attacks.
    

### IDOR

- IDOR stands for **Insecure Direct Object References**.
    
- It is primarily a **broken access-control vulnerability**.
    
- Applications often use IDs to reference resources.
    
- Sequential/predictable IDs can make testing easier.
    
- **Predictable IDs alone are not the vulnerability.**
    
- The critical issue is missing or incorrect **server-side authorization**.
    
- IDOR can expose other users' files, records, documents, or information.
    

### XXE

- XXE stands for **XML External Entity Injection**.
    
- It occurs when applications process XML unsafely.
    
- External entity processing is the key feature being abused.
    
- Outdated or insecurely configured XML parsers can be vulnerable.
    
- XXE can potentially disclose local files.
    
- Disclosed files may contain passwords, credentials, configuration data, or source code.
    
- XXE can potentially be chained with other weaknesses for more serious compromise.
    

---

# 🎯 Exam / Interview Quick Revision

```text
HTTP VERB TAMPERING
        ↓
Abuse unexpected HTTP methods
        ↓
Potential authorization/security-control bypass


IDOR
        ↓
Manipulate direct object references
        ↓
Missing backend authorization
        ↓
Unauthorized resource access


XXE
        ↓
Malicious XML + unsafe parser
        ↓
External entity processing
        ↓
Potential file/data disclosure
        ↓
Potential further compromise
```

## ⭐ One-Line Definitions

**HTTP Verb Tampering:**

> Exploiting differences in how an application/server handles HTTP methods to potentially bypass authorization or security controls.

**IDOR:**

> A broken access-control vulnerability where users can access objects/resources they are not authorized to access by manipulating direct references.

**XXE:**

> A vulnerability caused by unsafe XML external-entity processing that can potentially allow unauthorized access to server-side resources or files.

These three attacks all demonstrate an important security principle:

> **Never trust client-controlled input, and always enforce security controls on the server side.**