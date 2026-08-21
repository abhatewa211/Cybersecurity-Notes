![Image](https://images.openai.com/static-rsc-4/yRaGmIqCbe6WZpFPu841h4od07g1BnARM3J5mjgJ_yT556kHCleQvhGJ5WX3ymwkdf61qL9aQ6EVzx-3Qwp_L71xT9HOfvO0QH6OoIMrdPBQaapS8mT-Vx6veQJaP3cMLWvDGgNwyGVs9QDPLQvOGB6biWPQwMSHNksj0TuE5cJgr8NRygQoSpicOCrI8aV2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Mh7sZ8I2H7Yq74TY1y2nqu8a9OA0RyJAd0ylZvMaS99-S7YqXMx8zPIGOBP3CD2hLvlI_GORn1iVta5i_0q2EY7DRIaEmFpiL6QJOipHs7hLop87cIntGwwg_97UvqiYs8IwztgEGIFEzxGAA7DeUUBs3IjhCEo-rz4DcYjCJMTf9dEa6F4ifTJzZ63cOBwt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4fVHyYpJRwm84SMHpL3vLuYBRPjOJsa9-6z3iolun4Huevg1R97M4RX1UTE10jEjPWwfpq-_gSyW8Dq-k_pPB7DeQgzMoY-pA8cTRw8t3_rEztbrAR2RDOoZ824a0t6lcGnQl7JYiUZQ4XfN2xGX_nA6KB8Y3g7cfAk5nkBEkCGOrc4Uiz1lQKteJxOIKxvI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TyYiwnQo-lV4YFtkI05_bP517Xd0EMUjEHfinDJNVF_650SmHdUUTrIt18liaDtycAL0paQm3Z3OSY9SquwelyRmdNNaW0mGUKYBvssW5mWTMftqKblqq8j60kTPeC4Bp9ncOHsgmZp4Tkl1iBf0on57uarmoBQXV3So8Tz5E4eBOtF9xoDg7jXjxvM8Po33?purpose=fullsize)

## 1. What Is Request Interception?

After configuring Burp Suite or ZAP as our web proxy, the next important skill is **intercepting HTTP requests**.

Normally:

```text
Browser
   │
   │ HTTP Request
   ▼
Web Server
   │
   │ HTTP Response
   ▼
Browser
```

With interception enabled:

```text
Browser
   │
   │ HTTP Request
   ▼
┌─────────────────┐
│   Burp / ZAP    │
│                 │
│   INTERCEPT     │
└────────┬────────┘
         │
         │ Forward
         ▼
    Web Server
```

The request is temporarily **held by the proxy**.

This gives us an opportunity to:

1. Inspect it
    
2. Modify it
    
3. Forward it
    
4. Drop it
    
5. Analyze the server's response
    

---

# 2. Why Intercept Requests?

The browser's front-end may restrict what the user can enter.

For example, a webpage might only allow:

```text
1
2
3
4
```

because JavaScript validates the input.

But the browser ultimately sends an **HTTP request**.

If we intercept that HTTP request, we can modify the actual request before it reaches the server.

This lets us determine whether the **server itself** performs proper validation.

### Important security principle ⭐

> **Client-side validation should never be considered a security boundary.**

A penetration tester should examine whether the **back-end server** independently validates user-controlled input.

---

# 3. Burp Suite — Intercepting Requests

In Burp, navigate to:

```text
Proxy
   ↓
Intercept
```

Burp normally provides an:

```text
Intercept is on
```

button.

This controls whether Burp pauses requests.

---

## 4. Burp — Intercept ON vs OFF

### Intercept ON

```text
Browser
   ↓
Burp
   ↓
⏸ REQUEST PAUSED
   ↓
Tester
   ↓
Forward / Drop
```

### Intercept OFF

```text
Browser
   ↓
Burp
   ↓
Server
```

Requests pass through without being manually paused in the interception view.

---

# 5. Burp Intercept Controls

When a request is intercepted, Burp provides important actions.

### `Forward`

Send the intercepted request to its intended destination.

```text
Intercept
   ↓
Forward
   ↓
Server
```

### `Drop`

Discard the request instead of sending it.

```text
Intercept
   ↓
Drop
   ↓
❌ Request discarded
```

### `Intercept is on/off`

Enable or disable interception.

### `Action`

Provides additional operations for the intercepted request.

---

# 6. Important Burp Workflow

A basic workflow looks like:

```text
1. Open Burp
       ↓
2. Proxy → Intercept
       ↓
3. Turn Intercept ON
       ↓
4. Open Burp Browser
       ↓
5. Visit target
       ↓
6. Request gets intercepted
       ↓
7. Inspect request
       ↓
8. Modify if required
       ↓
9. Forward
       ↓
10. Observe response
```

---

# 7. Multiple Requests May Be Intercepted

When browsing a website, the browser doesn't necessarily make only one request.

A single page may request:

```text
HTML
CSS
JavaScript
Images
Fonts
API endpoints
Favicon
Analytics
```

Therefore, when interception is enabled, you may see several requests.

For example:

```text
GET /
GET /style.css
GET /script.js
GET /favicon.ico
GET /api/data
```

If you're looking for a particular request, you may need to press **Forward** several times until you reach it.

### ⭐ Important HTB tip

If you see unrelated requests before the target request, simply **Forward** them until you reach the request you're interested in.

---

# 8. ZAP — Intercepting Requests

ZAP behaves slightly differently.

By default, request interception is **off**.

The ZAP toolbar contains a button controlling request interception/breaking.

### Green state

Generally indicates that requests can pass without being intercepted.

### Interception enabled

Requests are paused so they can be examined.

You can toggle request interception using:

```text
CTRL + B
```

---

# 9. ZAP Request Interception Workflow

Basic workflow:

```text
Start ZAP
    ↓
Enable Request Interception
    ↓
Open ZAP Browser
    ↓
Visit Target
    ↓
Request is intercepted
    ↓
Inspect Request
    ↓
Forward / Step
```

The intercepted request appears in ZAP's interface.

---

# 10. ZAP Heads Up Display (HUD)

![Image](https://images.openai.com/static-rsc-4/D5-a2aUiBt2Y8cztK6LAPf7gJ-Gsvtses4FjpAtVHGr4n0KIi5fxHW0Yelj31XkeffFc2-oSV2eqqaoEnI_zeBW0i7D-GmkBumoTpFUK_6qjLaWBOXhVkv-OF7RraME2RjG_vA0r1O3XeVovOK0awEBJpBcVWi3e4vy6mAvQ_V_4_up3-6Yy3BPbM9uVhFec?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4fVHyYpJRwm84SMHpL3vLuYBRPjOJsa9-6z3iolun4Huevg1R97M4RX1UTE10jEjPWwfpq-_gSyW8Dq-k_pPB7DeQgzMoY-pA8cTRw8t3_rEztbrAR2RDOoZ824a0t6lcGnQl7JYiUZQ4XfN2xGX_nA6KB8Y3g7cfAk5nkBEkCGOrc4Uiz1lQKteJxOIKxvI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TyYiwnQo-lV4YFtkI05_bP517Xd0EMUjEHfinDJNVF_650SmHdUUTrIt18liaDtycAL0paQm3Z3OSY9SquwelyRmdNNaW0mGUKYBvssW5mWTMftqKblqq8j60kTPeC4Bp9ncOHsgmZp4Tkl1iBf0on57uarmoBQXV3So8Tz5E4eBOtF9xoDg7jXjxvM8Po33?purpose=fullsize)

ZAP provides a powerful feature called:

> **Heads Up Display (HUD)**

The HUD allows many ZAP features to be controlled directly from within the browser.

Instead of constantly switching between:

```text
Firefox ↔ ZAP
```

you can interact with ZAP functionality directly inside the browser.

---

# 11. Enabling ZAP HUD

The HUD can be enabled using the HUD button in ZAP's top menu.

Once enabled, additional controls appear within the browser.

One of these controls can be used to enable request interception.

---

# 12. ZAP HUD — Step vs Continue vs Drop

When the HUD intercepts a request, you can choose different actions.

### `Step`

Send the current request and examine the response while continuing to break subsequent requests.

Conceptually:

```text
Request 1
   ↓
Step
   ↓
Response 1
   ↓
Request 2
   ↓
Step
```

This is useful when you want to understand **every step of an application's functionality**.

---

### `Continue`

Forward the request and allow the remaining requests to proceed.

Useful when you're interested in one particular request and don't want to manually handle every subsequent browser request.

```text
Target Request
      ↓
Continue
      ↓
Remaining requests proceed
```

---

### `Drop`

Discard the intercepted request.

```text
Request
   ↓
Drop
   ↓
❌ Not sent
```

---

# 13. Step vs Continue

This distinction is worth remembering.

|Action|Purpose|
|---|---|
|**Step**|Forward current request and continue examining subsequent requests|
|**Continue**|Allow requests to proceed without manually stopping each one|
|**Drop**|Discard the request|

### Easy memory trick:

```text
STEP     → Examine step-by-step
CONTINUE → Keep going
DROP     → Throw request away
```

---

# 14. Manipulating Intercepted Requests

This is where web proxies become extremely powerful.

Once a request is intercepted, it is **paused**.

You can inspect its contents and, during an authorized security test, modify values before forwarding it.

For example:

```http
POST /login HTTP/1.1
Host: example.com

username=arjun&password=test
```

You could examine:

```text
Method
URL
Headers
Cookies
Parameters
Body
```

and understand exactly what the application is sending.

---

# 15. Example Request

The HTB example uses a `/ping` endpoint.

The browser sends:

```http
POST /ping HTTP/1.1
Host: 94.237.62.138:32306
Content-Length: 4
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://94.237.62.138:32306
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9
Referer: http://94.237.62.138:32306/
Connection: keep-alive

ip=1
```

The important part for this exercise is:

```text
ip=1
```

---

# 16. Breaking Down the Request

Let's understand the important pieces.

### HTTP Method

```http
POST
```

The browser is submitting data to the server.

### Endpoint

```text
/ping
```

The request is being sent to the `/ping` endpoint.

### Host

```text
94.237.62.138:32306
```

This identifies the target server and port in the lab.

### Content-Type

```text
application/x-www-form-urlencoded
```

This indicates that the request body contains URL-encoded form data.

### Request Body

```text
ip=1
```

The application is sending an `ip` parameter with the value `1`.

---

# 17. Client-Side vs Server-Side Validation

This is one of the **most important concepts in this section**.

Imagine the webpage contains an IP input box.

The front-end JavaScript might enforce:

```text
Only numbers allowed
```

So the browser interface prevents you from entering:

```text
;ls;
```

However, the actual HTTP request might be:

```http
POST /ping HTTP/1.1

ip=1
```

With a proxy, the tester can manipulate the request before it reaches the server.

The key question becomes:

> **Does the server validate the input independently?**

---

# 18. HTB Example — Manipulating `ip`

The original request contains:

```text
ip=1
```

The exercise modifies it to:

```text
ip=;ls;
```

This is a deliberately vulnerable lab application demonstrating command injection.

The modified request is then forwarded to the server.

The application processes the maliciously altered parameter and returns output from the command.

The resulting response contains files such as:

```text
flag.txt
index.html
node_modules
package-lock.json
public
server.js
```

### What did this demonstrate?

It demonstrated that:

```text
Front-end validation
        ≠
Back-end security
```

The application relied on client-side restrictions rather than properly validating the input on the server.

---

# 19. Why This Is Important in Pentesting

This same general concept appears across many vulnerabilities.

The tester intercepts:

```text
Client Request
      ↓
Proxy
      ↓
Manipulate Input
      ↓
Server
      ↓
Observe Response
```

By doing this, we can determine how the server behaves when it receives unexpected input.

---

# 20. Applications of Request Manipulation

The module specifically mentions that request interception/manipulation can assist in testing for:

### 1. SQL Injection

Manipulating parameters to test whether database queries are safely constructed.

```text
?id=1
```

versus controlled test inputs.

---

### 2. Command Injection

Testing whether user-controlled input reaches operating-system command execution.

The HTB `/ping` example demonstrates this concept.

---

### 3. Upload Bypass

Manipulating upload requests to test whether server-side validation properly restricts uploaded files.

---

### 4. Authentication Bypass

Modifying authentication-related requests to determine whether authorization is correctly enforced.

---

### 5. XSS

Manipulating parameters and examining whether user-controlled data is safely handled when returned to the browser.

---

### 6. XXE

Manipulating XML requests to assess how the application processes XML input.

---

### 7. Error Handling

Sending unexpected values and analyzing:

```text
HTTP status codes
Error messages
Stack traces
Debug information
```

---

### 8. Deserialization

Manipulating serialized data to test whether the application safely handles untrusted serialized objects.

---

# 21. Important Security Principle ⭐

The proxy itself isn't the vulnerability.

The proxy provides the **visibility and control** needed to discover vulnerabilities.

Think of it as:

```text
Burp/ZAP
    ↓
Observe application behavior
    ↓
Modify request
    ↓
Send to server
    ↓
Analyze response
    ↓
Determine whether security control works
```

---

# 22. Burp vs ZAP Interception

|Feature|Burp|ZAP|
|---|---|---|
|Request interception|✅|✅|
|Default interception|Usually ON|Usually OFF|
|Forward request|✅|✅|
|Drop request|✅|✅|
|Request modification|✅|✅|
|Browser integration|Built-in browser|Pre-configured browser|
|HUD|❌|✅|
|Keyboard toggle|—|`CTRL+B`|

---

# 23. Common HTTP Components to Inspect

Whenever you intercept a request, don't just look at the parameter.

Train yourself to examine:

```text
┌─────────────────────────────┐
│ HTTP Request                │
├─────────────────────────────┤
│ Method                      │
│ URL                         │
│ Path                        │
│ Query Parameters            │
│ Headers                     │
│ Cookies                     │
│ Authentication              │
│ Content-Type                │
│ Request Body                │
└─────────────────────────────┘
```

For example:

```http
POST /api/user HTTP/1.1
Host: target.htb
Authorization: Bearer TOKEN
Content-Type: application/json
Cookie: session=abc123

{"id":10}
```

There are many potential points of interest:

```text
/api/user
Authorization
session
id
JSON body
HTTP method
```

---

# 24. Request → Modification → Response

This is the fundamental cycle you should remember.

```text
             ORIGINAL REQUEST
                    │
                    ▼
              ┌───────────┐
              │ Burp/ZAP  │
              └─────┬─────┘
                    │
                 Inspect
                    │
                    ▼
                Modify
                    │
                    ▼
             MODIFIED REQUEST
                    │
                    ▼
                Web Server
                    │
                    ▼
                RESPONSE
                    │
                    ▼
              Analyze Result
```

This cycle forms the foundation of manual web application testing.

---

# 25. 🔥 The Most Important Concept: Don't Trust the Client

Suppose the frontend says:

```text
Age must be a number.
```

That doesn't mean the server is secure.

Suppose the frontend says:

```text
Only normal users can access this button.
```

That doesn't mean the server properly enforces authorization.

Suppose the frontend says:

```text
Only JPG files are allowed.
```

That doesn't mean the server validates uploaded files correctly.

A penetration tester should ask:

> **What happens if I bypass the frontend and send the HTTP request directly?**

A web proxy makes this possible.

---

# 🧠 26. Exam / Viva Questions

### Q1. What is request interception?

Request interception is the process of temporarily stopping an HTTP request at a proxy so it can be inspected or modified before being forwarded.

### Q2. How do you enable interception in Burp?

Go to:

```text
Proxy → Intercept
```

and enable:

```text
Intercept is on
```

### Q3. Is ZAP interception enabled by default?

**No.** Request interception is off by default.

### Q4. What keyboard shortcut toggles ZAP interception?

```text
CTRL + B
```

### Q5. What does `Forward` do?

It sends the intercepted request to its intended destination.

### Q6. What does `Drop` do?

It discards the intercepted request without sending it.

### Q7. What is ZAP HUD?

**Heads Up Display** — a ZAP interface that allows many ZAP features to be controlled directly from within the browser.

### Q8. What is the difference between Step and Continue in ZAP HUD?

**Step** allows you to examine requests sequentially, while **Continue** lets remaining requests proceed without manually stopping each one.

### Q9. Why manipulate HTTP requests?

To understand how the server processes user-controlled data and test whether server-side security controls properly handle unexpected or malicious input.

### Q10. Why is client-side validation insufficient?

Because a user can potentially bypass the client interface and send a manually modified HTTP request directly to the server.

---

# ⭐ 27. Final Revision Sheet

```text
WEB REQUEST INTERCEPTION
│
├── Burp
│   ├── Proxy → Intercept
│   ├── Intercept ON/OFF
│   ├── Forward
│   ├── Drop
│   └── Modify request
│
├── ZAP
│   ├── Interception OFF by default
│   ├── CTRL+B
│   ├── Step
│   ├── Continue
│   ├── Drop
│   └── HUD
│
└── Purpose
    ├── Capture
    ├── Inspect
    ├── Modify
    ├── Forward
    ├── Replay
    └── Analyze response
```

### 🔥 One-line takeaway

> **Intercept → Inspect → Manipulate → Forward → Analyze**

That is the fundamental workflow behind manual web request testing with **Burp Suite and ZAP**.