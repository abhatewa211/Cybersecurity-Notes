![Image](https://images.openai.com/static-rsc-4/Cp9a3iOL0XI3SFcOd7Q1UrBndf59qCaLMVvGstMk1ckJkwcYTyVn8IHnUgv3Y7aAnr5DtdOZigyxMuDPVNUDH3_ykL1_0gWpoZq0j8762eqm0re7syG1AbJ-bT9ZZrsfAgdI0g7yu_ckh8eIFzAfhuVV_pSDORmaw877kCzrZoyjx27TrswTRvXpOAJBYmJI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eBZ-8uFdrdkkaam4SMSfVFN3PQ6XeZkq1gI4qrNGAczKkUMNdwf1i-zTbJdxOI0_C569iikXSVo3AaxQUsOxB2WubSg7lZ5TCWJiNsAkkdaNKMiVR_Y-SjsYVMtuIC_NGrnBIRwa9KFVSsCoEmWYKRPYSKz8kYWtq7uRflEraxCyRZgMpUdejAMdAHj0RGOm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hZBkkIaWW3EYl7Ms4WCEHnY_zVjJfOrjIZqbdG9fHFvbNU6FZdrh0tHfVz_UK6QKuR7Gl8TsGmik8Y6OG7AamNcBdotFNe9RyDJLJw7nlkDld2-itn3Dp1QhDZpe0H9In2vKS-AQyLhZf8FevF7Th-yiZWpd0CbYWqg7GD4cm3VtTFRSr11VEcz_SjjoOsSq?purpose=fullsize)

## 1. Overview

**HTTP Verb Tampering** exploitation is usually relatively straightforward:

> **Try alternate HTTP methods and observe how the web server and web application handle them.**

The key idea is that an application may properly protect a resource when accessed through `GET` or `POST`, while accidentally failing to apply the same authentication rules to another method such as `HEAD`.

### Two important types

|Type|Cause|Automated scanners|
|---|---|---|
|**Type 1**|Insecure web-server configuration|Often easier to detect|
|**Type 2**|Insecure application coding|Often missed; requires active testing|

The first type can often be identified when changing the HTTP method allows us to **bypass an authentication page**.

The second type generally requires testing whether different HTTP methods can bypass **application-level security filters**.

---

# 2. Basic Authentication

The exercise uses a simple **File Manager** web application.

Initially, the application allows users to add files.

Conceptually:

```text
File Manager
     │
     ├── Add file
     ├── View files
     └── Reset
```

The important functionality is the **Reset** button.

The Reset functionality deletes all files.

Because this is a sensitive operation, it is protected by **HTTP Basic Authentication**.

---

# 3. Identifying the Protected Resource

When the **Reset** button is clicked, the browser displays an HTTP Basic Authentication prompt.

The request eventually points to:

```text
/admin/reset.php
```

Trying to access it without valid credentials produces:

```text
HTTP/1.1 401 Unauthorized
```

### `401 Unauthorized`

A `401 Unauthorized` response indicates that authentication is required or the supplied authentication credentials are not accepted.

The basic flow is:

```text
Browser
   │
   ▼
/admin/reset.php
   │
   ▼
Authentication check
   │
   ▼
No valid credentials
   │
   ▼
401 Unauthorized
```

---

# 4. Determine the Authentication Scope

An important step is determining **what exactly is protected**.

Is authentication required only for:

```text
/admin/reset.php
```

or for the entire:

```text
/admin/
```

directory?

Testing:

```text
/admin/
```

also produces an authentication prompt.

Therefore:

```text
/admin/
   │
   ├── reset.php 🔒
   └── other resources 🔒
```

### ⭐ Important Finding

> **The entire `/admin` directory is restricted by authentication.**

This makes `/admin/reset.php` an interesting target for HTTP Verb Tampering.

---

# 5. Identify the HTTP Method

Before changing the HTTP method, determine what method the application normally uses.

Using **Burp Suite**, intercept the request.

The request looks conceptually like:

```http
GET /admin/reset.php HTTP/1.1
Host: SERVER_IP:PORT
```

The important part is:

```text
GET
```

So the normal application request uses the:

> **GET HTTP method**

---

# 6. First Test — Change GET → POST

Since the original request is:

```http
GET /admin/reset.php
```

we can test whether the authentication configuration also protects `POST`.

In Burp Suite:

1. Intercept the request.
    
2. Right-click the request.
    
3. Select **Change Request Method**.
    
4. Burp changes the request from `GET` to `POST`.
    
5. Forward the request.
    
6. Observe the response.
    

Conceptually:

```text
Original:

GET /admin/reset.php
        │
        ▼
Authentication
        │
        ▼
401 Unauthorized ❌
```

Then:

```text
Modified:

POST /admin/reset.php
        │
        ▼
Authentication
        │
        ▼
401 Unauthorized ❌
```

### Result

`POST` does **not** bypass the authentication.

This suggests that authentication covers both:

```text
GET ✓
POST ✓
```

---

# 7. Think Beyond GET and POST

This is where HTTP Verb Tampering becomes interesting.

Even though developers commonly focus on:

```text
GET
POST
```

HTTP supports other methods.

One particularly interesting method is:

```text
HEAD
```

### HEAD

`HEAD` is similar to `GET`, but the server returns the **response headers without the response body**.

Conceptually:

```text
GET
 │
 ├── Headers
 └── Body


HEAD
 │
 └── Headers
```

This creates an interesting possibility.

If `/admin/reset.php` performs an action when accessed, we don't necessarily need the response body.

We care about whether the **action executes**.

---

# 8. The Key Idea

Suppose:

```text
GET /admin/reset.php
```

requires authentication.

But:

```text
HEAD /admin/reset.php
```

doesn't receive the same authentication restriction.

Then:

```text
HEAD request
      │
      ▼
reset.php executes
      │
      ▼
No response body
      │
      ▼
Reset operation may still occur
```

This is the critical concept behind the exercise.

### ⭐ Remember

> **An empty response does not necessarily mean that the server did nothing.**

With `HEAD`, the absence of a response body is expected.

Therefore, when testing `HEAD`, we need to verify the **side effect** of the request.

---

# 9. Discovering Supported HTTP Methods

Before testing `HEAD`, we can use the `OPTIONS` method.

Example:

```bash
curl -i -X OPTIONS http://SERVER_IP:PORT/
```

The server responds:

```http
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Allow: POST,OPTIONS,HEAD,GET
Content-Length: 0
Content-Type: httpd/unix-directory
```

The most important header is:

```http
Allow: POST,OPTIONS,HEAD,GET
```

---

# 10. Understanding the `Allow` Header

The `Allow` header tells us which HTTP methods the resource/server indicates it supports.

Here:

```text
Allow:
POST
OPTIONS
HEAD
GET
```

Therefore:

```text
GET      ✓
POST     ✓
HEAD     ✓
OPTIONS  ✓
```

This tells us that **HEAD is accepted**.

### ⚠️ Important distinction

The fact that a method is accepted does **not automatically mean it is vulnerable**.

We still need to test how authentication and application functionality behave when that method is used.

---

# 11. Why HEAD Is Interesting Here

We already know:

```text
GET  → Authentication required
POST → Authentication required
```

But now we know:

```text
HEAD → Accepted
```

So the next test is:

```text
HEAD /admin/reset.php
```

The question becomes:

> **Does the authentication restriction also apply to HEAD?**

---

# 12. Exploiting the Authentication Misconfiguration

Modify the intercepted request:

```http
GET /admin/reset.php
```

to:

```http
HEAD /admin/reset.php
```

Then forward the request.

The expected vulnerable behavior is:

```text
GET /admin/reset.php
        │
        ▼
Authentication
        │
        ▼
401 ❌


HEAD /admin/reset.php
        │
        ▼
Authentication bypass
        │
        ▼
Empty response
        │
        ▼
Function executes
```

Instead of receiving:

```text
401 Unauthorized
```

the server returns an empty response.

This is expected because `HEAD` does not return the response body.

---

# 13. Verify the Side Effect

This is the most important part.

Don't stop at:

> "I received an empty response."

We need to determine whether the requested functionality actually executed.

Return to the File Manager.

Before the attack:

```text
File Manager
├── test
└── notes.txt
```

After sending the `HEAD` request:

```text
File Manager
└── No files
```

The files have been deleted.

Therefore:

```text
HEAD /admin/reset.php
          │
          ▼
Authentication bypass
          │
          ▼
reset.php executes
          │
          ▼
Files deleted
```

### 🎯 Conclusion

The authentication configuration protected:

```text
GET
POST
```

but failed to protect:

```text
HEAD
```

This allowed the Reset functionality to be triggered **without credentials**.

---

# 14. Full Attack Chain

```text
             File Manager
                   │
                   ▼
             Click Reset
                   │
                   ▼
          /admin/reset.php
                   │
                   ▼
             GET Request
                   │
                   ▼
         Basic Authentication
                   │
                   ▼
              401 ❌
                   │
                   │
          Test another verb
                   │
                   ▼
                 POST
                   │
                   ▼
              401 ❌
                   │
                   │
            Test HEAD
                   │
                   ▼
          HEAD /admin/reset.php
                   │
                   ▼
       Authentication not applied
                   │
                   ▼
             Function executes
                   │
                   ▼
            Files are deleted
                   │
                   ▼
             SUCCESS ✓
```

---

# 15. Why Automated Scanners May Miss This

This section highlights an important distinction between the two types of HTTP Verb Tampering.

### Insecure Server Configuration

Often easier for automated tools to identify because the scanner can:

```text
Request protected resource
        ↓
Try alternative methods
        ↓
Observe authentication behavior
        ↓
Detect bypass
```

### Insecure Coding

Much harder to automatically identify.

The scanner may need to understand:

```text
HTTP method
     ↓
Parameter source
     ↓
Security filter
     ↓
Application logic
     ↓
Final operation
```

For example:

```text
GET parameter → filtered
POST parameter → not filtered
$_REQUEST → used
```

An automated scanner may not understand this application-specific logic without actively testing it.

### ⭐ Key Point

> **HTTP Verb Tampering caused by insecure coding generally requires more active testing than simple server-configuration issues.**

---

# 16. Methodology for Testing HTTP Verb Tampering

When performing an authorized security assessment, use this workflow:

```text
1. Identify interesting functionality
          ↓
2. Identify protected endpoint
          ↓
3. Determine normal HTTP method
          ↓
4. Test authentication with alternate methods
          ↓
5. Identify accepted methods
          ↓
6. Test methods such as HEAD
          ↓
7. Compare responses
          ↓
8. Verify application side effects
          ↓
9. Document the vulnerability
```

---

# 17. Useful Testing Commands

### Check supported methods

```bash
curl -i -X OPTIONS http://SERVER_IP:PORT/
```

Look for:

```http
Allow: ...
```

---

### Send a HEAD request

```bash
curl -i -X HEAD http://SERVER_IP:PORT/admin/reset.php
```

For an authorized lab, compare its response with the normal request.

---

### Normal GET

```bash
curl -i http://SERVER_IP:PORT/admin/reset.php
```

Compare:

```text
GET → 401 Unauthorized
HEAD → potentially different behavior
```

The difference is what we're investigating.

---

# 🧠 18. Critical Concepts

### `401 Unauthorized`

Means authentication is required or credentials aren't accepted.

---

### `OPTIONS`

Can reveal which HTTP methods are supported.

Example:

```http
Allow: POST,OPTIONS,HEAD,GET
```

---

### `HEAD`

Similar to GET, but doesn't return the response body.

This makes it useful for testing whether a server performs an action **without giving us visible output**.

---

### `Allow`

The HTTP response header indicating methods the resource says it supports.

---

### HTTP Verb Tampering

Changing the HTTP method to exploit differences in how authentication, authorization, filtering, or application logic is applied.

---

# 🔥 Most Important Lesson

The vulnerability is **not simply**:

```text
HEAD is enabled
```

The actual vulnerability is:

```text
HEAD is accepted
       +
Authentication does not cover HEAD
       +
HEAD can trigger protected functionality
       =
Authentication bypass
```

That's the exact security issue to look for.

---

# 📌 Quick Revision Notes

```text
HTTP VERB TAMPERING — BASIC AUTH BYPASS

Target:
    /admin/reset.php

Normal method:
    GET

GET:
    Authentication required
    → 401 Unauthorized

POST:
    Authentication required
    → 401 Unauthorized

OPTIONS:
    Reveals:
    Allow: POST,OPTIONS,HEAD,GET

HEAD:
    Accepted by server
    Authentication not properly applied

Result:
    HEAD request reaches reset.php
    ↓
    No response body
    ↓
    Reset functionality executes
    ↓
    Files deleted
    ↓
    Authentication successfully bypassed
```

## 🎯 Remember This for the Lab

**Don't judge a `HEAD` request only by its response body.**

Because `HEAD` intentionally returns no body, the correct way to determine whether the request worked is to **check the application's state/side effect afterward**.

> **The core lesson: authentication and authorization controls must be applied consistently to every HTTP method capable of reaching protected functionality.**