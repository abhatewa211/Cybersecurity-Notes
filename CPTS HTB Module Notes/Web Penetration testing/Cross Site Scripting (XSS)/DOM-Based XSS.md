## 1. What is DOM-Based XSS?

**DOM-based XSS** is the third and final major type of XSS.

It is another form of **Non-Persistent XSS**.

The biggest difference from Reflected XSS is **where the input is processed**.

### ⭐ Definition

> **DOM-based XSS occurs when client-side JavaScript takes attacker-controlled input and uses it to modify the page's DOM in an unsafe way, causing potentially malicious content to be interpreted by the browser.**

### The most important point:

**The input does NOT need to reach the back-end server.**

---

# 2. The Three Types of XSS

Before going further, keep this comparison in mind:

|Type|Where input is processed?|Persistent?|
|---|---|---|
|🔴 **Stored XSS**|Server + stored data|✅ Yes|
|🟠 **Reflected XSS**|Back-end server|❌ No|
|🟡 **DOM XSS**|Client-side JavaScript|❌ No|

### 🧠 Easy memory trick

```text
Stored   → Database
Reflected → Server
DOM       → Browser
```

---

# 3. DOM Means Document Object Model

**DOM = Document Object Model**

The DOM is the browser's representation of the webpage.

For example, this HTML:

```html
<body>
    <h1>Hello</h1>
    <p>Welcome</p>
</body>
```

is represented by the browser as a structure of objects.

Conceptually:

```text
                Document
                   │
                  html
                   │
          ┌────────┴────────┐
         head              body
                            │
                    ┌───────┴───────┐
                    h1              p
                    │               │
                 "Hello"        "Welcome"
```

JavaScript can interact with and modify these DOM objects.

---

# 4. How DOM XSS Happens

The basic process is:

```text
User-controlled input
        ↓
Client-side JavaScript
        ↓
DOM manipulation
        ↓
Unsafe HTML insertion
        ↓
Browser interprets content
        ↓
Potential XSS
```

### ⭐ Important

There may be **no HTTP request containing the malicious input**.

That's what makes DOM XSS fundamentally different from Reflected XSS.

---

# 5. Example: To-Do List

The lab uses another To-Do application.

You enter:

```text
test
```

The page displays:

```text
Next Task: test
```

At first glance, this looks similar to the previous XSS examples.

But now we inspect the browser's **Network** tab.

---

# 6. The Important Network Observation

Open Firefox Developer Tools:

```text
CTRL + SHIFT + I
```

Then select:

```text
Network
```

After adding `test`, the important observation is:

> **No HTTP request is made when the task is added.**

This is a major clue.

### Reflected XSS

```text
Input
 ↓
HTTP Request
 ↓
Server
 ↓
HTTP Response
 ↓
Browser
```

### DOM XSS

```text
Input
 ↓
Browser JavaScript
 ↓
DOM
 ↓
Page changes
```

### ⭐ Therefore:

> **If the input is processed entirely in the browser and never reaches the back-end, we're dealing with a DOM-based situation.**

---

# 7. The `#` in the URL

The lab shows that the URL contains a `#` parameter.

Conceptually:

```text
http://SERVER_IP:PORT/#task=test
```

The important part is:

```text
#task=test
```

This is a **fragment** of the URL.

---

# 8. Why Is `#` Important?

The fragment portion after `#` is normally handled by the browser and is **not sent to the server as part of the HTTP request**.

For example:

```text
http://example.com/index.php?task=test
                         ↑
                    query parameter
                    generally sent
                    to server
```

versus:

```text
http://example.com/index.php#task=test
                         ↑
                      fragment
                 handled client-side
```

### Conceptual flow

```text
                 URL
                  │
        ┌─────────┴─────────┐
        │                   │
     Server part        Fragment
        │                   │
        ▼                   ▼
   HTTP request       Browser/JS
                            │
                            ▼
                           DOM
```

### ⭐ Key takeaway

> **The fragment (`#...`) is a common source of client-side input because it can be processed by JavaScript without being sent to the server.**

---

# 9. Why Page Source Doesn't Show `test`

This is one of the most important concepts in DOM XSS.

You can press:

```text
CTRL + U
```

to view the original page source.

But the `test` value isn't there.

### Why?

Because the original HTML was loaded **before** the JavaScript modified the DOM.

Think of it as:

```text
SERVER
  ↓
Original HTML
  ↓
Browser receives page
  ↓
JavaScript runs
  ↓
JavaScript modifies DOM
  ↓
Rendered page changes
```

The `CTRL+U` page source represents the original HTML response, while the JavaScript-modified DOM is a later browser-side state.

---

# 10. Page Source vs Rendered DOM

This distinction is **extremely important**.

### `CTRL + U` — Page Source

Shows the original HTML received from the server.

```text
Server HTML
     ↓
View Source
```

### Web Inspector — Rendered DOM

Shows the DOM **after JavaScript has modified it**.

```text
Original HTML
     ↓
JavaScript
     ↓
Modified DOM
     ↓
Web Inspector
```

### 🧠 Remember:

> **View Source = original response**

> **Inspector = current DOM**

This is particularly useful when investigating DOM-based vulnerabilities.

---

# 11. Viewing the Rendered DOM

The module uses Firefox's Web Inspector.

Shortcut:

```text
CTRL + SHIFT + C
```

You can then inspect the actual DOM currently being rendered.

You may see something conceptually like:

```html
<ul id="todo">
    <b>Next Task:</b> test
</ul>
```

even though `test` wasn't present in the original page source.

---

# 12. Source and Sink

To understand DOM XSS properly, you need to understand two terms:

## 🔵 Source

The **Source** is where JavaScript obtains attacker-controlled input.

Examples:

- URL parameters
    
- URL fragments
    
- Input fields
    
- Browser-controlled data
    
- Other client-side input sources
    

## 🔴 Sink

The **Sink** is where that data is placed into the DOM or otherwise used in a potentially unsafe way.

### Basic model

```text
          SOURCE
             │
             ▼
      User-controlled
          input
             │
             ▼
       JavaScript
             │
             ▼
           SINK
             │
             ▼
            DOM
```

---

# 13. Source

The lab's source code contains:

```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

Let's understand what this does.

### First line

```javascript
document.URL.indexOf("task=")
```

The script searches the current URL for:

```text
task=
```

For example:

```text
http://SERVER_IP:PORT/#task=test
                         ↑
                       task=
```

The position of `task=` is located.

---

### Second line

```javascript
document.URL.substring(pos + 5, document.URL.length);
```

The script then extracts everything after:

```text
task=
```

So conceptually:

```text
URL:
#task=test

        ↓

JavaScript extracts:

test
```

Therefore:

> **The `task` parameter is the Source of the user-controlled input.**

---

# 14. Sink

Immediately afterward, the application uses:

```javascript
document.getElementById("todo").innerHTML =
    "<b>Next Task:</b> " + decodeURIComponent(task);
```

This is the crucial line.

The application takes:

```text
task
```

and inserts it into:

```text
todo
```

using:

```javascript
innerHTML
```

---

# 15. What Does `innerHTML` Do?

`innerHTML` allows JavaScript to read or replace the HTML contained inside a DOM element.

For example:

```javascript
document.getElementById("todo").innerHTML = "Hello";
```

changes the content of the element.

Or:

```javascript
document.getElementById("todo").innerHTML =
    "<b>Hello</b>";
```

inserts HTML.

The browser interprets:

```html
<b>Hello</b>
```

as markup.

---

# 16. Why `innerHTML` Can Become Dangerous

Suppose an application does:

```javascript
element.innerHTML = userInput;
```

without properly handling the input.

Then the browser may interpret attacker-controlled content as HTML.

Conceptually:

```text
User Input
    ↓
JavaScript
    ↓
innerHTML
    ↓
DOM
    ↓
Browser interprets HTML
```

This creates a potential **DOM XSS sink**.

### ⭐ Important

> `innerHTML` itself isn't automatically a vulnerability. The vulnerability depends on **untrusted data reaching an unsafe sink without appropriate handling**.

---

# 17. Source → Sink Model

The lab can be represented as:

```text
                 SOURCE
                    │
                    ▼
              URL fragment
              #task=test
                    │
                    ▼
             JavaScript
                    │
                    ▼
                 task
                    │
                    ▼
               innerHTML
                    │
                    ▼
                  SINK
                    │
                    ▼
               DOM element
                    │
                    ▼
             Browser renders
```

This is the central concept behind DOM XSS.

---

# 18. Common DOM XSS Sinks

The module identifies several JavaScript functions/properties that can write content to DOM objects.

### JavaScript

```javascript
document.write()
```

```javascript
DOM.innerHTML
```

```javascript
DOM.outerHTML
```

These can be dangerous when they receive **untrusted input** without appropriate sanitization/encoding.

---

# 19. jQuery Sinks

The module also identifies some commonly used jQuery functions:

```javascript
add()
```

```javascript
after()
```

```javascript
append()
```

Again, the important point isn't:

> "This function always causes XSS."

Instead:

> **An unsafe flow of attacker-controlled data into a DOM-manipulating sink can create DOM XSS.**

---

# 20. The Vulnerable Data Flow in This Lab

The lab's code essentially does:

```text
URL
 ↓
task=
 ↓
Extract task value
 ↓
decodeURIComponent()
 ↓
innerHTML
 ↓
#todo element
```

More visually:

```text
http://SERVER_IP:PORT/#task=test
                    │
                    ▼
              document.URL
                    │
                    ▼
                task=test
                    │
                    ▼
                 task
                    │
                    ▼
             decodeURIComponent
                    │
                    ▼
                innerHTML
                    │
                    ▼
                #todo DOM
```

This is why the lab is vulnerable to DOM XSS.

---

# 21. Why the Previous `<script>` Payload Doesn't Work

The previous sections used:

```html
<script>alert(window.origin)</script>
```

But in this DOM XSS lab, the module explains that this payload doesn't execute through the demonstrated `innerHTML` path.

Why?

Because browsers impose restrictions around `<script>` elements inserted through `innerHTML`; inserting a `<script>` this way does not make the script execute in the normal manner.

So:

```text
innerHTML
   +
<script>...</script>
```

doesn't necessarily result in script execution.

### ⭐ Important lesson

> **An unsafe HTML sink does not mean every possible XSS payload will execute.**

The payload must be compatible with the specific HTML/DOM context.

---

# 22. Alternative DOM XSS Payload

The module demonstrates a payload using an HTML event handler:

```html
<img src="" onerror=alert(window.origin)>
```

This doesn't rely on a `<script>` element.

Conceptually:

```text
<img>
   │
   ├── src=""
   │
   └── onerror
          │
          ▼
      JavaScript
```

Because the image source is invalid/empty in this example, the error handler can be triggered.

---

# 23. Understanding `onerror`

HTML elements can have event-handler attributes.

For example:

```html
<img onerror="...">
```

The browser can invoke the handler when the image loading encounters an error.

The module uses:

```html
onerror=alert(window.origin)
```

Therefore, conceptually:

```text
Create image
      ↓
Image fails to load
      ↓
onerror event
      ↓
JavaScript executes
      ↓
Alert appears
```

---

# 24. DOM XSS Attack Flow

The complete lab flow is:

```text
Attacker-controlled URL
          │
          ▼
#task=<input>
          │
          ▼
Browser loads page
          │
          ▼
Client-side JavaScript
          │
          ▼
Reads document.URL
          │
          ▼
Extracts task
          │
          ▼
innerHTML
          │
          ▼
DOM modified
          │
          ▼
Browser interprets injected HTML
          │
          ▼
Potential JavaScript execution
```

### ⭐ Notice:

There is **no server-side reflection step**.

---

# 25. Why This Is Non-Persistent

DOM XSS is generally **Non-Persistent**.

The application isn't storing the payload in its database.

The browser processes the input from the current client-side state.

For example:

```text
Open malicious URL
       ↓
JavaScript reads fragment
       ↓
DOM modified
       ↓
XSS occurs
```

Refresh or visit the normal URL:

```text
Normal URL
    ↓
No malicious fragment
    ↓
No malicious DOM modification
```

---

# 26. URL Fragment as a Source

This is particularly important for DOM XSS.

A URL might look like:

```text
http://SERVER_IP:PORT/#task=test
```

The browser handles the fragment locally.

The server doesn't need to receive:

```text
task=test
```

for JavaScript to access it.

Client-side code can inspect the URL and extract the fragment.

---

# 27. Reflected XSS vs DOM XSS

This is probably the **most important comparison** in this section.

### 🟠 Reflected XSS

```text
Attacker Input
     ↓
HTTP Request
     ↓
BACK-END SERVER
     ↓
HTTP Response
     ↓
Browser
     ↓
XSS
```

### 🟡 DOM XSS

```text
Attacker Input
     ↓
Browser
     ↓
Client-side JavaScript
     ↓
DOM Sink
     ↓
XSS
```

### 🧠 One-line memory:

> **Reflected XSS travels through the server. DOM XSS stays in the browser.**

---

# 28. Stored vs Reflected vs DOM

|Feature|🔴 Stored|🟠 Reflected|🟡 DOM|
|---|---|---|---|
|Persistent|✅|❌|❌|
|Server processes input|✅|✅|❌|
|Database storage|Usually|❌|❌|
|Client-side JS involved|May be|May be|✅|
|Input reaches server|Usually|✅|Not necessarily|
|DOM manipulation|May occur|May occur|✅|
|Common source|Stored content|Request parameter|URL fragment/input|
|Main concept|**Store**|**Reflect**|**Modify DOM**|

---

# 29. `CTRL + U` vs `CTRL + SHIFT + C`

This is worth memorizing for practical web security work.

### `CTRL + U`

```text
View Page Source
```

Shows:

> **Original HTML response**

### `CTRL + SHIFT + C`

```text
Web Inspector
```

Allows you to inspect:

> **Current rendered/modified DOM**

### Why this matters for DOM XSS

The malicious input may not exist in:

```text
Original source
```

but can appear after:

```text
JavaScript execution
        ↓
DOM modification
```

Therefore:

> **For DOM XSS, inspect both the original source and the live DOM.**

---

# 30. Source and Sink — Exam/Interview Version

### Source

> **A location from which JavaScript obtains attacker-controlled data.**

Examples:

```text
URL
URL fragment
Input field
Query parameters
```

### Sink

> **A function, property, or operation that uses the data in a potentially dangerous way, such as inserting it into the DOM.**

Examples from the module:

```text
document.write()
innerHTML
outerHTML
jQuery add()
jQuery after()
jQuery append()
```

---

# 31. Source → Sink Vulnerability

The most useful way to analyze DOM XSS is to follow the data.

Ask:

### 1️⃣ Where does the data come from?

```text
SOURCE
```

### 2️⃣ Where does it go?

```text
JavaScript processing
```

### 3️⃣ How is it inserted/used?

```text
SINK
```

### 4️⃣ Is there proper security handling?

```text
Sanitization / safe DOM APIs / appropriate encoding
```

If untrusted data reaches a dangerous sink without appropriate protection, there may be a DOM XSS vulnerability.

---

# 32. The Lab's Source

The source is:

```javascript
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
```

The important piece is:

```text
document.URL
```

The JavaScript reads user-controllable data from the URL.

---

# 33. The Lab's Sink

The sink is:

```javascript
document.getElementById("todo").innerHTML =
    "<b>Next Task:</b> " + decodeURIComponent(task);
```

The important part is:

```text
innerHTML
```

because it writes the extracted input into the DOM as HTML.

---

# 34. Complete Source → Sink Chain

```text
SOURCE
document.URL
     │
     ▼
Extract task parameter
     │
     ▼
task variable
     │
     ▼
decodeURIComponent(task)
     │
     ▼
SINK
innerHTML
     │
     ▼
#todo
     │
     ▼
DOM
     │
     ▼
Browser interprets content
```

### ⭐ This chain is the heart of the vulnerability.

---

# 35. Why `decodeURIComponent()` Matters

The application uses:

```javascript
decodeURIComponent(task)
```

This converts URL-encoded characters back into their decoded representation.

For example, URL encoding can represent special characters in an encoded form.

Conceptually:

```text
Encoded URL data
       ↓
decodeURIComponent()
       ↓
Original characters
       ↓
innerHTML
```

Therefore, when analyzing a DOM XSS vulnerability, it's important to follow **the data after decoding**, not just look at the raw URL.

---

# 36. Targeting a User

Because the malicious input is contained in the URL fragment, an attacker can potentially create a URL containing the malicious client-side input.

The conceptual flow is:

```text
Attacker
   ↓
Crafts URL
   ↓
Shares URL
   ↓
Victim opens URL
   ↓
Browser loads page
   ↓
JavaScript reads fragment
   ↓
JavaScript writes input into DOM
   ↓
Potential XSS
```

### Important distinction

The malicious fragment doesn't need to be sent to the server for this flow to occur.

---

# 37. 🧠 DOM XSS Mental Model

Memorize this:

```text
              DOM XSS
                 │
                 ▼
         User-controlled input
                 │
                 ▼
               SOURCE
                 │
                 ▼
        Client-side JavaScript
                 │
                 ▼
                SINK
                 │
                 ▼
                DOM
                 │
                 ▼
       Browser interprets input
                 │
                 ▼
          Potential XSS
```

---

# 38. 🔥 Most Important Points

### ⭐ 1. DOM XSS is Non-Persistent

It normally isn't stored permanently.

### ⭐ 2. It is processed client-side

The important processing happens in the browser.

### ⭐ 3. It doesn't require the server

The malicious input may never reach the back-end.

### ⭐ 4. `#` can be an important source

URL fragments are commonly processed client-side.

### ⭐ 5. `CTRL + U` may not show the injected input

Because JavaScript modifies the DOM **after** the original page source has been loaded.

### ⭐ 6. Web Inspector shows the modified DOM

This helps investigate client-side DOM changes.

### ⭐ 7. Source = where input comes from

Examples:

```text
URL
URL fragment
Input field
```

### ⭐ 8. Sink = where input is used

Examples:

```text
innerHTML
outerHTML
document.write()
```

### ⭐ 9. `innerHTML` doesn't automatically mean XSS

The vulnerability occurs when **untrusted data reaches an unsafe sink without adequate protection**.

### ⭐ 10. `<script>` isn't the only possible execution mechanism

Different HTML contexts and browser behaviors matter.

---

# 39. ⚡ Final Revision

```text
🔴 STORED XSS
Input → Database → Page → Browser
                ↑
           Persistent


🟠 REFLECTED XSS
Input → HTTP Request → Server → Response → Browser
                                      ↑
                                Non-Persistent


🟡 DOM XSS
Input → Browser → JavaScript → DOM Sink → Browser
                  ↑
             Client-side
             Non-Persistent
```

### The three-word memory trick:

> **Stored = STORE**

> **Reflected = SERVER**

> **DOM = BROWSER**

And for DOM XSS specifically:

> **SOURCE → JAVASCRIPT → SINK → DOM → EXECUTION**

That **Source → Sink** chain is the key concept to carry forward into the next XSS sections.