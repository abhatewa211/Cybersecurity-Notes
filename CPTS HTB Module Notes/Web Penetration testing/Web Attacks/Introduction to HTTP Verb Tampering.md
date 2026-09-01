![Image](https://images.openai.com/static-rsc-4/eNKxj_WgEgbhR9B_DwO0KhdiTSstJmFxRoDbLFoKNZBkuEGvj6MFzReXZMNaXv2H5dX8pxPSuVLMK2yO7UzzLPAIUWWCsTkeiL4gMP_VCupwTDjeArNXkdf3Xd9h_1TJ_sqz5z-p-Ag8KMhfnyK0ufvx4hU3xOGWpJ-LTw9Cyf8opMmet7OcPA4YqE9zmujS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AU1Jgs0RhjeNcZ4NAx0AH-lT-CFuQcarOJhfG98f6-iZV_gLOpAy1s-Qlv0g9xBB05HDWMNMNpDyCXLjaWj8x56QQFRlJeq8jqo1bxc4zrKf7GI7tl6s7H2dFyLRBJOqSL-yW_kwJDYZ8ziaF_Jqn_6ud6WBWobP0OI9wZaIxBKI_o1BvBXWmN0DWWe7TtEg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MmAeJcFmiwbwxmXgvx4ofyQRI5giobemi6a7jreH913-0TszU7sbYe40XOyl-eaVhC4nmch6Dp4EaYeo_CCu0jPGtOROX7F-B1jzV5Ukr0IihQA01mHQBbjeN-_cSg5m9WfX3R7jCgEqlEr9pg43JVJUMaOSKYqI-d1RVq27K09ZC7UIsVsQIjbbPk-IAbMt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ipS5-M_l8OLdQdwon3Z_haNG2fNl6o7VPTg8__NTvRqHqktlvqKQYmeWM-cA29gN19F0a0T-JHD265OOnl9QZV6DtdEFcRqcvti46pnWKw4-u9MIfvc3Kdty87CJrESstc1O6_HzZysK94-eatUfsnQIhDWnaPbpfwNUVkFcC9hWxnuFc4LmzI5AGQePV2BC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yq359QPbooibBbGI0MaoErj-Hc6EvbCiOrsLS7zZNBYLUnzirkqV7OmrXg8h2Bgrg0ZDoU0bnJjKDPrv3Ey2U-OvIvA72U89mpeuMf1STWdFfj1RqtDO9B6cvnKJrT2rZXKcWq473I3UHk-2D5IWHwHYsiaACJK0aujypfW9Yx2Vh5hhmCPeuux8e15PlMvV?purpose=fullsize)

---

## 1. What is HTTP?

**HTTP (Hypertext Transfer Protocol)** is the protocol used for communication between clients and web servers.

An HTTP request begins with an **HTTP method**, also called an **HTTP verb**.

For example:

```http
GET /index.php HTTP/1.1
Host: example.com
```

Here:

```text
GET → HTTP method / verb
/index.php → requested resource
HTTP/1.1 → HTTP version
```

The HTTP method tells the server **what kind of action the client wants to perform**.

---

# 2. HTTP Methods and Web Applications

Depending on the web server's configuration, a web application may be programmed to accept particular HTTP methods for different functionalities.

For example:

```text
GET
 ↓
Retrieve information

POST
 ↓
Submit information

PUT
 ↓
Write/replace a resource

DELETE
 ↓
Delete a resource
```

Most programmers primarily work with:

- `GET`
    
- `POST`
    

However, **any client can send other HTTP methods** and observe how the web server responds.

### Important Concept

> A client is not necessarily limited to the HTTP methods visible in the application's normal interface.

An attacker can manually construct HTTP requests using other methods and test how the server handles them.

---

# 3. What Happens When Unsupported Methods Are Used?

Suppose both the web application and backend server are configured to accept only:

```text
GET
POST
```

An attacker sends:

```http
PUT /index.php
```

If the server is correctly restricted, it may reject the request and return an error.

Conceptually:

```text
Attacker
   │
   │ PUT /index.php
   ▼
Web Server
   │
   ├── GET ✓
   ├── POST ✓
   └── PUT ✗
          │
          ▼
       Error
```

This is **not necessarily a serious vulnerability by itself**.

Possible consequences may include:

- Bad user experience
    
- Information disclosure through error messages
    
- Server/application behavior being revealed
    

But the situation becomes much more interesting when the server accepts methods that the application was **not designed to handle securely**.

---

# 4. Where HTTP Verb Tampering Becomes Dangerous

Consider this configuration:

```text
Web Server
     │
     ├── GET    ✓
     ├── POST   ✓
     ├── HEAD   ✓
     ├── PUT    ✓
     ├── DELETE ✓
     └── PATCH  ✓
```

But the actual application was only developed with:

```text
GET
POST
```

This creates a potential security problem.

Why?

Because the web server may accept methods that the application developers **didn't intend to expose**.

```text
Attacker
    │
    ▼
Unexpected HTTP Method
    │
    ▼
Web Server accepts it
    │
    ▼
Application handles it unexpectedly
    │
    ▼
Potential security bypass
```

This may potentially allow an attacker to:

- Access restricted functionality
    
- Bypass authentication
    
- Bypass authorization
    
- Bypass security filters
    
- Perform unintended operations
    

This is the basic idea behind **HTTP Verb Tampering**.

---

# 🔴 5. HTTP Verb Tampering — Definition

> **HTTP Verb Tampering is an attack that exploits insecure handling or configuration of HTTP methods to bypass authentication, authorization, or other security controls.**

The vulnerability can originate from either:

1. **Insecure web-server configuration**
    
2. **Insecure application coding**
    

This distinction is extremely important.

---

# 6. HTTP's Commonly Used Methods

HTTP defines several methods that web servers can accept.

The module highlights these important methods:

|HTTP Verb|Meaning|
|---|---|
|**GET**|Retrieves a resource|
|**POST**|Sends/submits data to the server|
|**HEAD**|Similar to GET, but response contains headers without the response body|
|**PUT**|Writes/replaces the request payload at a specified location|
|**DELETE**|Deletes the resource at the specified location|
|**OPTIONS**|Shows available options, such as supported HTTP methods|
|**PATCH**|Applies partial modifications to a resource|

---

# 7. Important HTTP Verbs

## 🔹 GET

Used primarily to **retrieve information**.

Example:

```http
GET /products
```

Conceptually:

```text
Client
  │
  │ GET /products
  ▼
Server
  │
  ▼
Product information
```

---

## 🔹 POST

Used primarily to **submit data** to the server.

Example:

```http
POST /login
```

Data might be included in the request body.

```http
POST /login HTTP/1.1

username=admin&password=example
```

---

## 🔹 HEAD

`HEAD` is similar to `GET`, but the server returns the **headers without the response body**.

Conceptually:

```text
GET
 ├── Headers
 └── Body

HEAD
 └── Headers
```

### Security relevance

This method becomes particularly interesting in **HTTP Verb Tampering** because a server may apply authentication restrictions differently to `HEAD` than to `GET` or `POST`.

---

## 🔹 PUT

`PUT` is used to **write or replace a resource** at a specified location.

For example:

```http
PUT /resource
```

Depending on server configuration, PUT can potentially have powerful consequences.

If an improperly configured web server allows writing files into a sensitive location such as the **webroot**, this can become extremely dangerous.

---

## 🔹 DELETE

`DELETE` requests a resource to be deleted.

Example:

```http
DELETE /resource
```

If improperly configured, DELETE functionality could potentially allow unauthorized deletion of resources.

---

## 🔹 OPTIONS

`OPTIONS` can be used to determine which HTTP methods/options are supported by a server.

For example, a server may respond with information indicating:

```text
Allow: GET, POST, HEAD, OPTIONS
```

This can help identify how the server is configured.

---

## 🔹 PATCH

`PATCH` is used to apply **partial modifications** to an existing resource.

Unlike PUT, which is commonly associated with replacing a resource, PATCH is intended for modifying only part of a resource.

---

# ⚠️ 8. Why PUT and DELETE Can Be Dangerous

Some HTTP methods can perform sensitive operations.

For example:

```text
PUT
 ↓
Write resource

DELETE
 ↓
Delete resource
```

If these methods are improperly exposed or configured, an attacker may potentially manipulate resources on the backend.

The module specifically highlights the possibility of:

> **Writing (`PUT`) or deleting (`DELETE`) files in the webroot directory.**

If a web server is insecurely configured to handle these methods, the consequences can potentially include **control over the backend server**.

---

# 9. Two Main Types of HTTP Verb Tampering

A very important concept:

```text
             HTTP VERB TAMPERING
                     │
          ┌──────────┴──────────┐
          ▼                     ▼
   Insecure Server          Insecure Coding
   Configuration             Practices
          │                     │
          ▼                     ▼
 Authentication            Security-filter
 bypass                    inconsistency
```

Let's understand both.

---

# 🔴 10. Type 1 — Insecure Web Server Configuration

![Image](https://images.openai.com/static-rsc-4/1Kw27fQN9q5dDKwFapOWzYpa-CDsDnaBserESJGdsgNyynlhV3uMuDKsNPD5SSVWvzV2f5Xo7hbT12m9Ts514Qm013-pI-zpFy-ymmE0ZrgHxbZYKrNxkm3V2Y-ZhvOq8ffiVo11euZ26v-y6z7hhrS0aVUvpjVZ_unDnECB3oRWNB1Hm1qA0j2Qs-Mefa6v?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pdlaCRNJylp022gKefkA-av-gxoL3Y5-CZ4bFSnJ1Q6qFO9WYIt9pDBxkqswssJ_y2At1nCxLjCmAmA328A0gWjr8LflzFcNFyvJwBs243_AjL8lAGYhId_ZfprfAt5OgKhnYwGX1vYCAr-PoM0lbjXXHxllE-b8A1CokEfkE9rQGrIgHFgYrwNhDOPDGVV1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/SItlggwXlidQAQqpE6j6yAXrW_JtiM5Yc7si3BrJdtVwMAhzHqQiA78Hl26FRLCr7fXqie4IAvCjd9dhytwWNSbhSvVTNBcE-mUPlzJJuUeMALBCOWHMWtCP72tL6Hamkgai5_JuIFogxZ-9o4hP1PED87HCsWmEmjJmywlLH5fN2HS_O0_JTj4Id5lzr2Sm?purpose=fullsize)

One type of HTTP Verb Tampering vulnerability occurs because the **web server's configuration does not properly restrict authentication to all relevant HTTP methods**.

---

## Example Configuration

The module gives this example:

```xml
<Limit GET POST>
    Require valid-user
</Limit>
```

Let's understand what this means.

The configuration says that authentication is required for:

```text
GET
POST
```

So:

```text
GET  → Authentication required
POST → Authentication required
```

But what about:

```text
HEAD
PUT
DELETE
```

If those methods aren't included in the authentication restriction, they may potentially be processed **without the same authentication requirement**.

---

# 11. Authentication Bypass Through HTTP Verb Tampering

Suppose:

```text
/admin
```

requires authentication.

Normal request:

```http
GET /admin
```

The server checks:

```text
Is the user authenticated?
       │
       ├── YES → Allow
       │
       └── NO → Deny
```

But the authentication configuration only protects:

```text
GET
POST
```

An attacker may try another method such as:

```http
HEAD /admin
```

If the server handles the method without applying the same authentication rule, the attacker may potentially bypass the authentication mechanism.

Conceptually:

```text
GET /admin
      │
      ▼
Authentication check
      │
      ▼
   DENIED ❌


HEAD /admin
      │
      ▼
Authentication rule not applied
      │
      ▼
Potential bypass ⚠️
```

### ⭐ Key Point

> **Security controls must consistently apply to every HTTP method that can reach protected functionality.**

---

# 12. Why This Configuration Is Dangerous

The problem is not simply that the server supports `HEAD`.

The real problem is:

```text
HTTP Method
     +
Different security rule
     =
Potential bypass
```

If authentication is applied only to certain methods, an attacker may look for a method that is:

- Accepted by the server
    
- Not covered by the authentication restriction
    
- Able to access the same protected resource
    

---

# 🟠 13. Type 2 — Insecure Coding

The second major category comes from **insecure application coding**.

This happens when developers create security filters that apply to one HTTP method or parameter source but later process input from a broader source.

This can produce an **inconsistency between the input being validated and the input actually being used**.

---

# 14. SQL Injection Example

The module provides this PHP example:

```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```

Let's break this down carefully.

---

## Step 1 — Security Filter

The application checks:

```php
$_GET["code"]
```

against this pattern:

```php
$pattern = "/^[A-Za-z\s]+$/";
```

The purpose is to allow only:

```text
A-Z
a-z
spaces
```

So conceptually:

```text
GET parameter
      │
      ▼
Input validation
      │
      ▼
Allowed characters?
      │
      ├── YES → Continue
      └── NO  → Reject
```

---

# 15. The Problem: `$_GET` vs `$_REQUEST`

Here's the critical part.

The application **validates**:

```php
$_GET["code"]
```

But later **uses**:

```php
$_REQUEST["code"]
```

These are not necessarily equivalent.

### `$_GET`

Contains parameters submitted through the URL/query string.

Example:

```http
GET /search.php?code=ABC
```

The value comes from:

```php
$_GET["code"]
```

---

### `$_POST`

Contains parameters submitted in the POST body.

Example:

```http
POST /search.php

code=ABC
```

The value can be accessed through:

```php
$_POST["code"]
```

---

### `$_REQUEST`

PHP's `$_REQUEST` can contain request data from multiple sources, including GET and POST data (depending on PHP configuration).

Therefore:

```text
$_GET["code"]
```

and:

```text
$_REQUEST["code"]
```

should **not automatically be treated as the same input source**.

---

# 16. The Security Filter Bypass

This creates an inconsistency:

```text
             GET parameter
                  │
                  ▼
             Sanitization
                  │
                  ▼
                Checked
                  │
                  │
                  ▼
             $_REQUEST["code"]
                  ▲
                  │
             POST parameter
                  │
                  ▼
              NOT checked
```

An attacker may potentially provide malicious input through a different request method/source while the application validates another parameter source.

---

# 17. Conceptual Attack Flow

The important concept is:

```text
GET parameter
     │
     ▼
Security filter
     │
     ▼
Contains no bad characters
     │
     ▼
Filter passes
     │
     ▼
Application uses $_REQUEST["code"]
     ▲
     │
POST parameter can influence value
     │
     ▼
Potentially malicious input
```

This creates an **HTTP Verb inconsistency**.

---

# 18. Why This Can Lead to SQL Injection

The intended logic is:

```text
Input
 ↓
Validate
 ↓
Safe input
 ↓
SQL Query
```

But the vulnerable logic becomes:

```text
GET input
   ↓
Validate GET
   ↓
Pass filter
   ↓
Use REQUEST
   ↑
POST input
   │
Potentially malicious
```

Therefore, the application may execute a query using data that **wasn't actually validated by the security filter**.

### ⭐ Critical Lesson

> **Always validate the exact input source that will ultimately be used.**

Do not validate one parameter source and then use another.

---

# 19. The Two Vulnerability Types Compared

|Feature|Insecure Server Configuration|Insecure Coding|
|---|---|---|
|Root cause|Web server configuration|Application code|
|Common issue|Authentication rules apply only to certain verbs|Security filter doesn't cover the actual input|
|Example|`<Limit GET POST>`|Validate `$_GET`, use `$_REQUEST`|
|Potential result|Authentication bypass|Security-filter bypass / SQL injection|
|Main lesson|Secure server configuration|Consistent input validation|

---

# 20. Why the Second Type Is More Common

The module makes an important observation:

> The second type is generally **more common** because it results from mistakes made during application development.

The first type is often avoided because secure web-server documentation typically warns administrators about restricting authentication and access controls appropriately.

So remember:

```text
Insecure Configuration
        ↓
Usually easier to avoid
        ↓
Documentation / secure defaults


Insecure Coding
        ↓
Developer implementation mistakes
        ↓
More common
```

---

# 🧠 21. The Most Important Concepts to Remember

### 1️⃣ HTTP methods are not limited to GET and POST

A client can send other methods such as:

```text
HEAD
PUT
DELETE
OPTIONS
PATCH
```

---

### 2️⃣ Supporting an HTTP method isn't automatically a vulnerability

For example:

```text
PUT supported
```

doesn't automatically mean:

```text
Vulnerable
```

The important questions are:

- What functionality does it expose?
    
- Is it authenticated?
    
- Is it authorized?
    
- Is it properly validated?
    
- Was it intentionally enabled?
    

---

### 3️⃣ Authentication must cover all relevant methods

Bad:

```text
GET  → Auth ✓
POST → Auth ✓
HEAD → Auth ✗
```

Better:

```text
All relevant methods
        ↓
Consistent authentication
        ↓
Consistent authorization
```

---

### 4️⃣ Validate the input you actually use

Bad:

```text
Validate → $_GET["code"]

Use → $_REQUEST["code"]
```

Better:

```text
Receive input
      ↓
Validate exact input
      ↓
Sanitize/encode appropriately
      ↓
Use validated value
```

And for SQL specifically, the preferred defense is **parameterized queries/prepared statements**, rather than relying on character filtering alone.

---

# 🎯 Quick Revision Sheet

```text
HTTP VERB TAMPERING
        │
        ├── Insecure Server Configuration
        │       │
        │       ├── Authentication limited to some verbs
        │       ├── Example: GET + POST
        │       └── HEAD may bypass controls
        │
        └── Insecure Coding
                │
                ├── Security filter covers wrong input source
                ├── Example: $_GET["code"]
                ├── Application uses $_REQUEST["code"]
                └── Potential security-filter bypass
```

### 🔥 One-Liners

**HTTP Verb Tampering:**

> Manipulating the HTTP method used in a request to exploit inconsistent server/application security controls.

**Insecure Server Configuration:**

> Authentication or authorization controls are applied only to certain HTTP methods, potentially allowing another method to bypass them.

**Insecure Coding:**

> Application security checks are inconsistently applied to HTTP parameters/methods, allowing unvalidated input to reach sensitive functionality.

**Golden Rule:**

> **Never assume that because an application normally uses GET/POST, an attacker cannot send other HTTP methods. Always enforce authentication, authorization, validation, and security controls consistently on the server side.**