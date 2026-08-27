## 1. What is Stored XSS?

**Stored XSS**, also called **Persistent XSS**, is a type of Cross-Site Scripting where the attacker's injected content is **stored by the back-end application** and later retrieved and displayed to users.

### ⭐ Definition

> **Stored XSS occurs when an XSS payload is stored in the back-end database and is executed whenever a user visits the affected page.**

This is considered one of the **most critical types of XSS** because the attacker does not necessarily need to target each victim individually.

### Basic flow

```text
Attacker
   ↓
Submits malicious input
   ↓
Web Application
   ↓
Back-End Database
   ↓
Payload is stored
   ↓
Victim visits page
   ↓
Stored payload is retrieved
   ↓
Victim's browser renders it
   ↓
JavaScript executes
```

---

# 2. Why Is Stored XSS So Dangerous?

The major difference from other XSS types is **persistence**.

Once the malicious input has been stored:

```text
             ATTACKER
                │
                ▼
       Malicious Input
                │
                ▼
          Application
                │
                ▼
          ┌──────────┐
          │ Database │
          └────┬─────┘
               │
        Payload remains
               │
        ┌──────┼──────┐
        ▼      ▼      ▼
      User A  User B  User C
        │      │      │
        ▼      ▼      ▼
      Browser Browser Browser
        │      │      │
        └──────┼──────┘
               ▼
         Payload Executes
```

### Important consequence

**Any user who visits the affected page may become a victim.**

This gives Stored XSS potentially much wider reach than an attack that requires a victim to interact with a specially crafted request.

---

# 3. Why Is It Called "Persistent"?

It is called **Persistent XSS** because the malicious input **persists** after the attacker submits it.

For example:

```text
Attacker submits payload
        ↓
Application stores payload
        ↓
Attacker leaves
        ↓
Payload remains in database
        ↓
Users visit page later
        ↓
Payload executes
```

The attacker doesn't necessarily have to remain connected.

### 🧠 Memory Trick

> **Stored XSS = Store → Stay → Execute**

---

# 4. Typical Locations for Stored XSS

Stored XSS commonly occurs in areas where an application allows users to submit content that is later displayed.

Examples:

- 📝 Comments
    
- 📋 To-do items
    
- 💬 Forum posts
    
- ⭐ Product reviews
    
- 👤 User profiles
    
- 📢 Messages
    
- 📰 Posts
    
- 🏷️ Names or descriptions
    
- 📖 Guestbooks
    

The important characteristic isn't the specific feature.

It is:

> **User-controlled input is stored and later rendered to users.**

---

# 5. Example: Vulnerable To-Do List

The module uses a simple **To-Do List** application to demonstrate Stored XSS.

Imagine the page contains:

```text
┌─────────────────────────────────────┐
│             TO-DO LIST              │
├─────────────────────────────────────┤
│                                     │
│  [ Enter a task...              ]   │
│                                     │
│              [ Add ]                │
│                                     │
│  Tasks:                             │
│   • test                            │
│                                     │
│              [ Reset ]              │
└─────────────────────────────────────┘
```

You enter:

```text
test
```

and submit it.

The application displays:

```text
test
```

This tells us that our input is being placed back onto the webpage.

### But this alone does NOT prove XSS.

We need to determine whether the application safely handles the input.

---

# 6. Testing for XSS

A basic testing payload from the module is:

```html
<script>alert(window.origin)</script>
```

### What does this do?

The `<script>` element tells the browser that JavaScript code is present.

The JavaScript:

```javascript
alert(window.origin)
```

causes the browser to display the **origin of the page** in an alert dialog.

---

# 7. Why Use `window.origin`?

This is an important detail from the module.

Instead of simply using:

```javascript
alert(1)
```

the payload uses:

```javascript
alert(window.origin)
```

### Why?

Because the displayed origin helps determine **where the JavaScript actually executed**.

For example, conceptually:

```text
Main Website
      │
      ├── Form
      │
      └── Cross-domain iframe
               │
               └── User input
```

Modern applications may use **cross-domain iframes** to handle certain user interactions.

If the payload executes inside an iframe, the origin shown by `window.origin` can help determine the security context in which it executed.

### ⭐ Important

> `window.origin` helps identify the origin where the JavaScript is executing.

This can be more useful than a static value such as:

```javascript
alert(1)
```

because `1` tells you only that JavaScript executed—not **where** it executed.

---

# 8. Successful XSS Test

If the application is vulnerable and doesn't properly sanitize the input, the browser may execute the JavaScript.

Conceptually:

```text
Input:
<script>alert(window.origin)</script>
              ↓
Application stores it
              ↓
Page displays it
              ↓
Browser interprets <script>
              ↓
JavaScript executes
              ↓
Alert appears
```

The alert indicates that the browser interpreted the injected content as executable JavaScript.

---

# 9. Why Does the Alert Prove Something?

Suppose you submit:

```html
<script>alert(window.origin)</script>
```

and the browser displays an alert.

That means:

```text
Input
 ↓
Reached page
 ↓
Was interpreted as HTML/script
 ↓
JavaScript executed
```

Therefore, this provides strong evidence that the input is reaching an executable context without being safely handled.

### ⭐ Key point

> **Successful JavaScript execution is the important signal—not simply seeing your input on the page.**

---

# 10. Confirming Through Page Source

The module also demonstrates checking the page source.

You can open page source using:

```text
CTRL + U
```

or:

```text
Right-click
   ↓
View Page Source
```

You may find the injected content inside the HTML.

For example:

```html
<div></div>
<ul class="list-unstyled" id="todo">
    <ul>
        <script>alert(window.origin)</script>
    </ul>
</ul>
```

### What does this tell us?

The original user-controlled input has become part of the HTML response.

The browser therefore sees:

```html
<script>...</script>
```

rather than treating the entire value as ordinary text.

---

# 11. Important: Seeing the Payload in Source ≠ Automatically XSS

This is an important security-testing concept.

Simply finding:

```html
<script>...</script>
```

in source doesn't necessarily prove that a vulnerability exists in every situation.

You need to determine whether:

1. The input is actually controlled by the attacker.
    
2. It reaches an executable context.
    
3. The browser interprets it as code.
    
4. JavaScript actually executes.
    

### Strong confirmation

```text
Payload appears
      +
Browser executes it
      =
Strong evidence of XSS
```

---

# 12. Alternative XSS Verification Payloads

The module mentions two other simple ways to verify execution.

## `<plaintext>`

```html
<plaintext>
```

This changes how the browser renders the remainder of the HTML, causing subsequent markup to be displayed as plaintext.

### Why is it useful?

It creates a very obvious visual change.

Conceptually:

```text
Normal rendering:
HTML → interpreted as HTML

After <plaintext>:
HTML → displayed as text
```

---

# 13. `print()` Payload

Another basic payload mentioned is:

```html
<script>print()</script>
```

This invokes the browser's print dialog.

### Why is this useful?

It creates a very obvious browser-side effect.

```text
Payload
   ↓
JavaScript executes
   ↓
Browser print dialog appears
```

This can be useful in situations where `alert()` may not behave as expected.

---

# 14. Why Have Multiple Verification Methods?

Modern browsers may restrict or suppress `alert()` in certain circumstances.

Therefore, it can be useful to have alternative **non-destructive execution indicators**.

|Test|Observable Result|
|---|---|
|`alert(window.origin)`|Alert displaying the page origin|
|`<plaintext>`|Remaining markup rendered as text|
|`print()`|Browser print dialog|

### ⭐ Study point

These are primarily **verification techniques** for determining whether injected browser-side content executes.

---

# 15. The Most Important Part — Persistence

Now we need to determine whether the XSS is actually **Stored/Persistent XSS**.

The test is simple:

### Refresh the page.

```text
Submit payload
      ↓
Payload executes
      ↓
Refresh page
      ↓
Does payload execute again?
```

If the payload executes again after refreshing, this strongly indicates that the payload has been stored and retrieved again.

---

# 16. Persistence Test

### First visit

```text
Submit payload
      ↓
Payload executes
      ↓
Alert appears
```

### Refresh

```text
Refresh page
      ↓
Server retrieves stored content
      ↓
Browser receives it again
      ↓
Payload executes again
      ↓
Alert appears again
```

### ⭐ Conclusion

If the payload continues executing across page refreshes:

> **The application is demonstrating persistent/stored XSS behavior.**

---

# 17. Why Refreshing Matters

Imagine the payload was only temporarily reflected:

```text
Request
 ↓
Server
 ↓
Response containing input
 ↓
JavaScript executes
```

After refreshing without sending the malicious input again:

```text
Refresh
 ↓
No malicious input
 ↓
No payload
```

But with Stored XSS:

```text
Payload
 ↓
Database
 ↓
Refresh
 ↓
Database retrieves payload
 ↓
Payload executes again
```

This difference helps distinguish persistence.

---

# 18. Stored XSS Full Attack Flow

Here's the complete mental model:

```text
             ATTACKER
                │
                ▼
       ┌─────────────────┐
       │ Malicious Input │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │ Web Application  │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │    Database     │
       │                 │
       │ Payload stored  │
       └────────┬────────┘
                │
                │ Later
                ▼
       ┌─────────────────┐
       │ Victim requests │
       │     page        │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │ Stored payload  │
       │ returned        │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │ Victim Browser  │
       └────────┬────────┘
                │
                ▼
       JavaScript executes
```

---

# 19. Why Stored XSS Can Affect Many Users

Suppose an attacker stores malicious content in a publicly visible comment.

Then:

```text
              Database
                 │
        Stored malicious input
                 │
        ┌────────┼────────┐
        ▼        ▼        ▼
      User A   User B   User C
        │        │        │
        ▼        ▼        ▼
     Browser  Browser  Browser
```

Every user who loads the affected content may trigger the payload.

### ⭐ This is the key difference:

> **The payload is stored once but can potentially execute many times for many users.**

---

# 20. Why Removing Stored XSS Can Be Difficult

With Stored XSS, deleting the visible post/comment may not always be enough.

The malicious data may exist in the:

```text
Database
   ↓
Stored record
   ↓
Application output
```

Therefore, remediation may require:

1. Identifying the affected record
    
2. Removing or correcting malicious stored data
    
3. Fixing the vulnerable input/output handling
    
4. Checking whether other stored records are affected
    
5. Reviewing logs and affected users where appropriate
    

### ⭐ Important

> **The payload may need to be removed from the back-end database.**

This is one reason Stored XSS can be more difficult to remediate than a purely reflected issue.

---

# 21. Stored XSS vs Reflected XSS

|Feature|Stored XSS|Reflected XSS|
|---|---|---|
|Stored in database?|✅ Usually|❌ Usually not|
|Persistent?|✅ Yes|❌ No|
|Payload remains after refresh?|✅ Potentially|❌ Normally not without resubmitting|
|Victim must receive malicious request?|Not necessarily|Usually|
|Can affect multiple users?|✅ Potentially many|Depends on delivery|
|Common locations|Comments, posts, profiles|Search/error responses|

### 🧠 Easy memory

```text
STORED
Attacker → Database → Victim

REFLECTED
Attacker → Request → Server → Victim
```

---

# 22. Stored XSS vs DOM XSS

|Feature|Stored XSS|DOM XSS|
|---|---|---|
|Server storage|Usually|Not required|
|Database involved|Often|Not necessarily|
|Processing|Server/application + browser|Browser/client-side JS|
|Persistent|Yes|Usually no|
|Main issue|Stored malicious content|Unsafe DOM processing|

---

# 23. `window.origin` — Important Detail

Let's make this especially clear.

### Static test

```javascript
alert(1)
```

Result:

```text
1
```

You know:

> JavaScript executed.

But you don't learn much about the execution context.

### Origin-based test

```javascript
alert(window.origin)
```

Result might conceptually be:

```text
https://example.com
```

Now you know:

> JavaScript executed in the context of this origin.

This can help identify whether an input form is running inside a different origin or iframe.

---

# 24. iframe Consideration

Modern applications may use iframes:

```text
Main Website
│
├── Main Page
│
└── iframe
      │
      └── User Input Form
```

The iframe may have a different origin.

Therefore, testing:

```javascript
alert(window.origin)
```

can reveal the origin where the JavaScript actually executes.

### ⭐ Important

> A vulnerable form inside a separate security context may not have the same impact as XSS executing directly in the main application's origin.

---

# 25. Important Stored XSS Testing Logic

When working through a Stored XSS lab, think in this order:

```text
1. Find user-controlled input
          ↓
2. Submit harmless test input
          ↓
3. Observe where it appears
          ↓
4. Test whether executable content is interpreted
          ↓
5. Confirm browser-side execution
          ↓
6. Refresh the page
          ↓
7. Check whether execution happens again
          ↓
8. Determine whether the input is persistent
```

This gives you a structured methodology rather than blindly trying payloads.

---

# 26. Security Concept: Source → Storage → Sink

For Stored XSS, you can think of the vulnerability as:

```text
SOURCE
  ↓
User-controlled input
  ↓
STORAGE
  ↓
Database
  ↓
RETRIEVAL
  ↓
OUTPUT
  ↓
SINK
  ↓
Browser interprets content
  ↓
EXECUTION
```

### Example

```text
To-do input
     ↓
Application
     ↓
Database
     ↓
To-do page
     ↓
HTML rendering
     ↓
Browser
```

If the application doesn't safely handle the data before it reaches the output context, XSS can occur.

---

# 27. ⭐ Key Concepts to Memorize

### Stored XSS

> **Malicious input is stored on the back-end and later delivered to users.**

### Persistent

> **The malicious content remains stored and can execute repeatedly.**

### Main danger

> **Multiple users can potentially be affected by one stored payload.**

### Execution

> **The payload executes in the victim's browser.**

### Verification

> **A visible browser-side effect can confirm JavaScript execution.**

### Persistence check

> **Refresh the page and see whether the behavior occurs again.**

### `window.origin`

> **Shows the origin in which the JavaScript is executing.**

---

# 28. 🧠 Quick Revision

```text
             STORED XSS
                  │
                  ▼
        Attacker-controlled input
                  │
                  ▼
             Application
                  │
                  ▼
              Database
                  │
            Payload stored
                  │
                  ▼
            Victim visits
                  │
                  ▼
         Payload retrieved
                  │
                  ▼
          Victim's browser
                  │
                  ▼
         JavaScript executes
```

### Remember:

> 🔴 **Stored XSS = Store → Retrieve → Execute**

> 🔴 **Persistent = Payload survives the original request**

> 🔴 **Refresh test = Helps confirm persistence**

> 🔴 **Multiple visitors = Potentially multiple victims**

> 🔴 **Database cleanup may be required**

> 🔴 **XSS executes in the browser, not automatically on the server**

---

# 29. 🔥 Most Important Points From This Section

1. **Stored XSS = Persistent XSS.**
    
2. The attacker-controlled input is **stored by the back-end application**.
    
3. The stored content is later **retrieved and displayed**.
    
4. The victim's browser may execute the malicious content.
    
5. Stored XSS can potentially affect **any user who visits the affected page**.
    
6. This broad reach is why Stored XSS is often considered the **most critical XSS type**.
    
7. Stored payloads may be difficult to remove because the malicious data can remain in the **back-end database**.
    
8. `alert(window.origin)` is useful for confirming execution and identifying the execution origin.
    
9. `<plaintext>` and `print()` can provide alternative visible indicators of browser-side execution.
    
10. **Refreshing the page** helps determine whether the payload is persistent.
    
11. Finding the payload in page source can help understand how the input is being rendered, but **actual execution is the important confirmation**.
    
12. Cross-domain iframes can affect the security context in which input is processed.
    
13. The core Stored XSS model is:
    

```text
INPUT
  ↓
STORE
  ↓
RETRIEVE
  ↓
RENDER
  ↓
EXECUTE
```

### 🧠 One-line definition for your notes:

> **Stored XSS is a persistent XSS vulnerability where attacker-controlled input is stored by the application and later rendered in a user's browser, potentially causing the injected code to execute for every user who accesses the affected content.**