## 1. What is Reflected XSS?

**Reflected XSS** is one of the two major types of **Non-Persistent XSS**.

The two non-persistent types are:

1. 🟠 **Reflected XSS** — processed by the **back-end server**
    
2. 🟡 **DOM-based XSS** — processed completely on the **client side**
    

### ⭐ Definition

> **Reflected XSS occurs when attacker-controlled input is sent to the back-end server and is returned in the server's response without being properly filtered, sanitized, or encoded, allowing the browser to interpret it as executable content.**

The key word is **reflected**:

```text
Attacker Input
      ↓
    Server
      ↓
Input reflected back
      ↓
   Browser
      ↓
Potential execution
```

---

# 2. Reflected XSS Is Non-Persistent

Unlike **Stored XSS**, reflected XSS isn't permanently stored by the application.

### Stored XSS

```text
Input
 ↓
Database
 ↓
Stored
 ↓
Retrieved later
 ↓
Victim
```

### Reflected XSS

```text
Input
 ↓
Request
 ↓
Server
 ↓
Response
 ↓
Browser
```

### ⭐ Main difference

> **Stored XSS persists. Reflected XSS normally exists only in the particular request/response flow.**

Therefore, if you simply leave the page and return normally, the payload generally won't execute again unless the malicious request is sent again.

---

# 3. Non-Persistent XSS

There are two types:

|Type|Processing|
|---|---|
|🟠 **Reflected XSS**|Back-end server processes the input|
|🟡 **DOM-based XSS**|Client-side/browser processes the input|

### Important

Both are called **Non-Persistent XSS** because the malicious input isn't permanently stored in the application in the way Stored XSS is.

---

# 4. Basic Reflected XSS Flow

```text
             ATTACKER
                 │
                 ▼
       ┌──────────────────┐
       │ Malicious Input  │
       └────────┬─────────┘
                │
                ▼
       ┌──────────────────┐
       │ HTTP Request     │
       └────────┬─────────┘
                │
                ▼
       ┌──────────────────┐
       │ Back-End Server  │
       └────────┬─────────┘
                │
          Input reflected
                │
                ▼
       ┌──────────────────┐
       │ HTTP Response    │
       └────────┬─────────┘
                │
                ▼
       ┌──────────────────┐
       │ Victim Browser   │
       └────────┬─────────┘
                │
                ▼
          Content executes
```

---

# 5. Where Can Reflected XSS Appear?

Reflected XSS commonly occurs where the server takes user input and includes it in its response.

Examples include:

- 🔍 Search results
    
- ❌ Error messages
    
- ✅ Confirmation messages
    
- URL parameters
    
- Query parameters
    
- Form submissions
    
- Other request-generated responses
    

The important thing is:

> **The server receives attacker-controlled input and reflects it into the response.**

---

# 6. Example — To-Do List

The lab uses another simple **To-Do List** application.

You enter:

```text
test
```

and click **Add**.

Instead of successfully adding the task, the application responds with:

```text
Task 'test' could not be added.
```

Notice something important:

```text
Your input:
test

Server response:
Task 'test' could not be added.
```

The application has **reflected your input back into the page**.

---

# 7. Why Is This Interesting?

Seeing your input reflected doesn't automatically mean XSS.

We need to ask:

> **How is the application handling the reflected input?**

If it safely encodes the input:

```text
<script>
```

may be displayed literally as text.

If it incorrectly inserts the input into an executable HTML context:

```text
<script>...</script>
```

the browser may interpret it as JavaScript.

### Therefore:

```text
Input reflected
      ↓
Is it safely encoded?
      ↓
 ┌────┴────┐
YES       NO
 ↓         ↓
Text     Potential
         XSS
```

---

# 8. Testing the Reflected Input

The same basic verification payload from the previous section can be used:

```html
<script>alert(window.origin)</script>
```

The important part is that the payload is sent as **input to the application**.

Conceptually:

```text
Input:
<script>alert(window.origin)</script>

        ↓

Server receives input

        ↓

Server creates response:

Task '<script>alert(window.origin)</script>' could not be added.
```

If the application doesn't safely handle the input, the browser may interpret the `<script>` element as executable code.

---

# 9. Alert Appears

If the payload executes successfully:

```javascript
alert(window.origin)
```

causes the browser to display the page's origin.

For example, conceptually:

```text
┌───────────────────────────────┐
│ https://example.com           │
│                               │
│             [ OK ]            │
└───────────────────────────────┘
```

### ⭐ What does this tell us?

It demonstrates that:

```text
Input
 ↓
Server
 ↓
Response
 ↓
Browser
 ↓
JavaScript execution
```

has occurred.

---

# 10. Why Does the Error Message Become Empty?

The application originally responds:

```text
Task 'test' could not be added.
```

After injecting:

```html
<script>alert(window.origin)</script>
```

the page may display:

```text
Task '' could not be added.
```

### Why?

Because the browser interprets:

```html
<script>alert(window.origin)</script>
```

as a **script element** rather than ordinary visible text.

The script executes, but the `<script>` element itself doesn't render like normal text.

Therefore:

```text
Task '
+
<script>...</script>
+
' could not be added.
```

becomes visually:

```text
Task '' could not be added.
```

### ⭐ Important

The payload hasn't necessarily disappeared.

It is still present in the HTML source.

---

# 11. Confirming With Page Source

You can inspect the source using:

```text
CTRL + U
```

or:

```text
Right-click
    ↓
View Page Source
```

You may see something similar to:

```html
<div></div>
<ul class="list-unstyled" id="todo">
    <div style="padding-left:25px">
        Task '<script>alert(window.origin)</script>' could not be added.
    </div>
</ul>
```

This demonstrates:

```text
Your input
     ↓
Server
     ↓
HTML response
     ↓
Your input appears in response
```

---

# 12. The Key Difference From Stored XSS

This is **not stored** in the database.

The payload is reflected as part of the current response.

### Reflected:

```text
Malicious Request
       ↓
Server
       ↓
Malicious Response
       ↓
Browser executes
```

After leaving the page:

```text
Return normally
     ↓
No malicious request
     ↓
No reflected payload
     ↓
No execution
```

### Stored:

```text
Malicious Input
       ↓
Database
       ↓
Payload remains
       ↓
Refresh
       ↓
Payload retrieved
       ↓
Execution again
```

---

# 13. How Do We Confirm It Is Non-Persistent?

The module demonstrates this by revisiting the reflected page.

Initially:

```text
Send malicious request
       ↓
Payload executes
```

Then leave/revisit the page normally:

```text
Open page normally
       ↓
No malicious request
       ↓
Payload isn't present
       ↓
No execution
```

### ⭐ Conclusion

The vulnerability is **Non-Persistent / Reflected XSS**.

---

# 14. The Big Question

## ❓ If Reflected XSS Isn't Stored, How Can We Target a Victim?

This is the most important concept in this section.

The answer depends on **how the application receives the input**.

If the input is sent through a URL using an HTTP **GET request**, the parameters are included in the URL.

Therefore, a specially crafted URL can contain the attacker-controlled input.

### Basic concept

```text
Attacker creates malicious URL
             ↓
       Sends URL to victim
             ↓
       Victim opens URL
             ↓
     Browser sends request
             ↓
          Server
             ↓
     Input reflected
             ↓
       Browser executes
```

---

# 15. HTTP GET Requests

A **GET request** commonly sends parameters as part of the URL.

For example:

```text
https://example.com/index.php?task=test
```

Here:

```text
?task=test
```

is the query portion of the URL.

### Structure

```text
https://example.com/index.php?task=test
│                       │       │
│                       │       └── Value
│                       └────────── Parameter
└───────────────────────────────── URL
```

If the application unsafely reflects the parameter, attacker-controlled input can potentially be placed into the URL.

---

# 16. Developer Tools — Network Tab

The module uses **Firefox Developer Tools** to determine how the application sends the input.

Open Developer Tools with:

```text
CTRL + SHIFT + I
```

Then select:

```text
Network
```

### Why?

The Network tab lets you inspect HTTP requests made by the browser.

You can see information such as:

- Request method
    
- URL
    
- Status code
    
- Request parameters
    
- Response
    
- Resources requested
    

---

# 17. Finding the Request

After entering:

```text
test
```

and clicking **Add**, look at the Network tab.

The first request in the lab is shown as a:

```text
GET
```

request.

Conceptually:

```text
Browser
   │
   │ GET /index.php?task=test
   ▼
Server
```

The important observation is:

> **The user's input is being transmitted as part of the URL.**

---

# 18. Why GET Makes Reflected XSS Easy to Deliver

Suppose the vulnerable parameter is:

```text
task
```

A normal request might look like:

```text
/index.php?task=test
```

Conceptually, if attacker-controlled markup is reflected unsafely, the request could contain:

```text
/index.php?task=<attacker-controlled-input>
```

Then:

```text
Attacker-controlled URL
          ↓
       Victim
          ↓
Browser sends GET request
          ↓
       Web server
          ↓
Input reflected
          ↓
Victim browser processes response
```

### ⭐ Key concept

> **A Reflected XSS payload can potentially be delivered through a malicious URL when the vulnerable input is supplied through a GET parameter.**

---

# 19. Copying the Request URL

The module describes two ways to obtain the URL.

### Method 1 — Address bar

After submitting the input, look at the browser's URL bar.

### Method 2 — Developer Tools

In the **Network** tab:

```text
Right-click GET request
        ↓
Copy
        ↓
Copy URL
```

This gives you the complete request URL.

---

# 20. Victim Request Flow

The complete concept is:

```text
             ATTACKER
                │
                │ Creates malicious URL
                ▼
       ┌─────────────────┐
       │ Malicious URL   │
       └────────┬────────┘
                │
                │ Sends URL
                ▼
             VICTIM
                │
                │ Opens URL
                ▼
       ┌─────────────────┐
       │ Victim Browser  │
       └────────┬────────┘
                │
                │ GET Request
                ▼
       ┌─────────────────┐
       │ Back-End Server │
       └────────┬────────┘
                │
          Reflects input
                │
                ▼
       ┌─────────────────┐
       │ HTTP Response   │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │ Victim Browser  │
       └────────┬────────┘
                │
                ▼
          Potential XSS
```

---

# 21. Why Doesn't Every User Get Attacked?

This is another important distinction.

With Stored XSS:

```text
One stored payload
       ↓
Page
       ↓
Everyone visiting page
```

With Reflected XSS:

```text
Malicious URL
       ↓
Specific victim
       ↓
Request
       ↓
Response
       ↓
Execution
```

The victim generally needs to **make the malicious request**.

Therefore, reflected XSS typically requires a delivery mechanism such as a malicious link.

---

# 22. Stored vs Reflected XSS

|Feature|Stored XSS|Reflected XSS|
|---|---|---|
|Persistence|✅ Persistent|❌ Non-persistent|
|Database storage|Usually|Usually not|
|Input source|Stored content|Current request|
|Server processing|Usually|✅ Yes|
|Payload returned|Later|Immediately|
|Refresh normally triggers payload?|✅ Potentially|❌ Normally no|
|Victim interaction required|Not necessarily|Usually|
|Common delivery|Affected webpage|Malicious request/link|
|Typical location|Comment/post|Search/error message|

---

# 23. Reflected XSS vs DOM XSS

These are both **Non-Persistent XSS**, but there is an important difference.

### Reflected

```text
Input
 ↓
Back-End Server
 ↓
HTTP Response
 ↓
Browser
```

### DOM-based

```text
Input
 ↓
Browser
 ↓
Client-side JavaScript
 ↓
DOM
```

### ⭐ Remember

> **Reflected = Server sees it.**

> **DOM = Server doesn't necessarily see it.**

---

# 24. Request → Reflection → Execution

The simplest mental model for Reflected XSS is:

```text
REQUEST
   ↓
REFLECTION
   ↓
RESPONSE
   ↓
BROWSER
   ↓
EXECUTION
```

Or:

> **Send → Reflect → Execute**

---

# 25. Important HTTP Concept

For this lab, the input is transmitted through a **GET request**.

Conceptually:

```text
GET /index.php?task=test
```

The server receives:

```text
task = test
```

and then creates:

```text
Task 'test' could not be added.
```

The vulnerability occurs if attacker-controlled input can instead become executable content in that response.

---

# 26. Status Codes in Network Tab

The lab screenshot also shows HTTP status codes such as:

```text
200
404
```

### `200 OK`

Generally means the request succeeded.

### `404 Not Found`

Generally means the requested resource could not be found.

For the XSS investigation, the important request is the one containing the application's user input.

### ⭐ Don't get distracted

The key information for this exercise is:

> **Which request contains the input, and what HTTP method is being used?**

---

# 27. Reflected XSS Testing Methodology

For this lab, the logical process is:

```text
1. Enter harmless input
        ↓
2. Observe where it appears
        ↓
3. Determine whether it is reflected
        ↓
4. Inspect the HTTP request
        ↓
5. Identify GET/POST/etc.
        ↓
6. Test whether the reflected input executes
        ↓
7. Leave/revisit the page
        ↓
8. Determine whether it is persistent
```

---

# 28. Important Difference: Reflection vs Persistence

These concepts should not be confused.

### Reflection

Means:

> **The server returns your input in the response.**

### Persistence

Means:

> **The input remains stored and can be retrieved later.**

Therefore:

```text
Reflected ≠ Stored
```

A reflected input can execute JavaScript without ever being stored.

---

# 29. Security Impact

Reflected XSS can potentially allow attackers to execute JavaScript in a victim's browser when the victim processes a malicious request.

Possible impacts include:

- Phishing
    
- Page manipulation
    
- Unauthorized actions
    
- Exposure of browser-accessible information
    
- Session abuse depending on cookie/security configuration
    
- Malicious redirects
    
- Social engineering
    

The actual impact depends heavily on:

- User privileges
    
- Application functionality
    
- Browser security controls
    
- Cookie configuration
    
- CSP
    
- Other application defenses
    

---

# 30. 🧠 Complete Mental Model

Remember Reflected XSS like this:

```text
                    REFLECTED XSS
                          │
                          ▼
                  Attacker Input
                          │
                          ▼
                    HTTP Request
                          │
                          ▼
                   Back-End Server
                          │
                          ▼
                  Input reflected
                          │
                          ▼
                   HTTP Response
                          │
                          ▼
                   Victim Browser
                          │
                          ▼
                   Browser interprets
                       content
                          │
                          ▼
                   Potential XSS
```

---

# 31. 🔥 Most Important Points

### ⭐ 1. Reflected XSS is Non-Persistent

The payload isn't permanently stored like Stored XSS.

### ⭐ 2. The server processes the input

This is the defining distinction from DOM-based XSS.

```text
Reflected XSS
Input → Server → Response → Browser
```

### ⭐ 3. Input is reflected

The server includes attacker-controlled input in its response.

### ⭐ 4. Error messages are common locations

For example:

```text
Task 'test' could not be added.
```

### ⭐ 5. JavaScript execution confirms the vulnerability

A browser-side effect such as the module's origin alert can demonstrate execution.

### ⭐ 6. Page source can help confirm reflection

You may see the input embedded inside the returned HTML.

### ⭐ 7. Refresh behavior helps distinguish persistence

If the malicious content disappears when you revisit the page normally, that supports the conclusion that it is non-persistent.

### ⭐ 8. GET requests can put parameters in the URL

For example:

```text
/index.php?task=test
```

### ⭐ 9. Malicious URLs can deliver Reflected XSS

Conceptually:

```text
Attacker
   ↓
Malicious URL
   ↓
Victim
   ↓
GET request
   ↓
Server reflects input
   ↓
Browser processes response
```

### ⭐ 10. Reflected XSS usually requires victim interaction

Unlike Stored XSS, the payload isn't simply sitting on a page waiting for everyone to visit it.

---

# 32. ⚡ Final Revision Table

|Concept|Remember|
|---|---|
|**Reflected XSS**|Input is reflected by server|
|**Persistent?**|❌ No|
|**Server involved?**|✅ Yes|
|**Database required?**|❌ No|
|**Common location**|Error/search/confirmation messages|
|**Typical delivery**|Malicious request/link|
|**GET parameters**|Can be contained in URL|
|**Execution**|Victim browser|
|**Refresh normally repeats it?**|❌ No|
|**Main memory trick**|**Send → Reflect → Execute**|

---

# 🧠 One-Line Definition

> **Reflected XSS is a non-persistent XSS vulnerability where attacker-controlled input is sent to the back-end server, reflected into the HTTP response without safe handling, and potentially interpreted as executable content by the victim's browser.**

### 🔴 Stored vs 🟠 Reflected — memorize this

```text
STORED XSS
Attacker
   ↓
Input
   ↓
Database
   ↓
Stored
   ↓
Victim visits page
   ↓
Execute


REFLECTED XSS
Attacker
   ↓
Malicious Request / URL
   ↓
Server
   ↓
Input reflected
   ↓
Victim receives response
   ↓
Execute
```

> **Stored = Store it first.**  
> **Reflected = Send it and get it reflected back.**