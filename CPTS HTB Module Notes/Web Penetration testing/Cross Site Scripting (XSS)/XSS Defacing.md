## 1. What is Website Defacing?

**Website defacing** means changing the visual appearance or content of a website so that visitors see a modified page.

In the context of XSS, JavaScript injected through a vulnerable application can manipulate the page's **DOM and styling**.

A common use of stored XSS for learning purposes is to demonstrate how an attacker could modify what every visitor sees.

> ⚠️ **Important:** Defacing a real website without authorization is illegal. The techniques below should be practiced only on HTB labs, CTFs, or systems you have explicit permission to test.

---

# 2. Why Stored XSS Is Important for Defacing

The type of XSS matters greatly.

```text
                    XSS
                     │
        ┌────────────┼────────────┐
        ↓            ↓            ↓
     Stored       Reflected      DOM
        │            │            │
        ↓            ↓            ↓
   Persistent    Temporary      Temporary
        │
        ↓
 Potentially affects
 every visitor
```

### Stored XSS

The payload is stored by the application and executed when users load the affected page.

Therefore, a stored XSS can potentially cause the modified appearance to be seen by **multiple visitors**.

### Reflected XSS

The payload generally needs to be delivered through a request/URL and affects the user who processes that request.

### DOM XSS

The manipulation happens client-side and is generally non-persistent.

### ⭐ Key point

> **Stored XSS is particularly significant for defacing because the injected payload can persist in the application's stored content.**

---

# 3. 🖼️ How XSS Defacing Works

![Image](https://images.openai.com/static-rsc-4/126OMRcnotoEa-Rs_koqJUG361XOshyUBalwtW-nKdRJnVjjkimthn9nxKzCZ78YNC7g_M_BilA1e5C3f_lRRg_DsuMYDFtxnxSm0tJj__IeQjCn1tLOKwa7RqcZuAae1P4jofmtwbNcxZk-jMZ3JdgoNW2b_erzA2AIkxrggDBq9KqNuGbFV8ZdpbCTx-6B?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KksNhz74wg3GHwRCxt3kSD85gTJhy7kVk9AOSu4jJB6cUWWLNlpFt2gJIh_xE8xZ3wLetCHAXxhRR01wibqk0o-f-vcgdxj4WfiYS5CgchsjjBs9iuRngjngqo15yVXiHsI3AU1dpWANsyTqJT2udUQYPFLekzO5kSnLPnFXIdDuzE7HKoVgwf9_8JWH4l-l?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/t-TfGdVtHT9OvIkDmCh5_Y66UQVO6hPvb_RykWzYn74m26_IL7xJo3CLWN3eM3Y3l9hKOftmLEzy8PsuxvloI0SluwG5I0sn_uoPrWRhc-wMeoCZsvc5YmeQZ46H5S526emG_8wMOBkWZMb7Eo7HzmU6YzyKPGrL7-WAgTPVTHU-wCD846-dMvLsXxCwUNzr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/viJLDZkUI33QDeJzahsV-6fD4BtMGOz9RMHA2nMPwPAMbf8IjeYnnE1GHP54Lvi9LsvyZxHdKKL5aIKXPAijtTxJTsP_0LooGBSN1MAaimMmPupHF7SkXz7SGjdErqbbeUhSRCPvp5KPvqXOnW4qqJbaLZANzXpUAgVnWV2fyO7oMUPgBPEwnJVKA-z9lV9j?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yrJ2QYDLEp-baVQ-Aoix_YKOeiWjTDTU3vgoqGRdV4lKDSKmDMgB1gU726RqnGhlGFnSTOjyfg3Ui7YByoW7_iSaNRAZm7H_tIts6HHpxGP_xuPwqQAgFYB2WIVtcfTStIkKR-6V0nNNWyGR-kStT0kztFkESHbBTKCVDN-wu4IMVFC2wIYIM5t4HXtlaTaC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_5WLSVWUIh0Q8qkgdODtnGGIrnFXBuJE3VuKHK_usGqZpTgejAXsRQU1NHpq4Qbvady0fyahrOD0r9jnkRnbJaUDzJ4VGQLyzxgG6zYIoHYyidumtWxvD2WQ-cCBgA75TYz3nTYsVK1NcPMklzTLJVNgzhbVyOr5QdzT5azZePB1H5tGUtuUNyRJ55NjfOMr?purpose=fullsize)

The basic flow is:

```text
Attacker-controlled input
          ↓
      Stored by app
          ↓
     Victim opens page
          ↓
      Browser receives
          ↓
    JavaScript executes
          ↓
       DOM changes
          ↓
    Modified webpage
```

The important distinction is that the **server-side stored content** and the **browser's rendered appearance** aren't necessarily the same thing.

The browser can receive the original HTML and then JavaScript can modify the DOM after the page loads.

---

# 4. Main Defacement Elements

The module identifies four useful HTML/DOM properties:

|Element|JavaScript property|Purpose|
|---|---|---|
|🎨 Background Color|`document.body.style.background`|Changes page background|
|🖼️ Background|`document.body.background`|Sets a background image|
|🏷️ Page Title|`document.title`|Changes browser tab title|
|📝 Page Text|`DOM.innerHTML`|Replaces HTML/content|

These allow an attacker to modify the appearance of a page.

---

# 5. 🎨 Changing the Background Color

The module demonstrates:

```html
<script>document.body.style.background = "#141d2b"</script>
```

The important JavaScript component is:

```javascript
document.body.style.background
```

### Breakdown

```text
document
   ↓
body
   ↓
style
   ↓
background
```

This means:

1. Access the document.
    
2. Select the `<body>`.
    
3. Access its CSS styling.
    
4. Change the background property.
    

---

## Example

```javascript
document.body.style.background = "black"
```

or using a hexadecimal color:

```javascript
document.body.style.background = "#141d2b"
```

### ⭐ Important

The actual color isn't important.

The important concept is:

> **JavaScript can manipulate CSS properties of DOM elements.**

---

# 6. Why It Becomes Persistent in the Lab

If the JavaScript payload is stored by the vulnerable application:

```text
Payload
   ↓
Database/storage
   ↓
Page loads
   ↓
Payload retrieved
   ↓
Browser executes it
   ↓
Background changes
```

Refreshing the page causes the stored payload to execute again.

This demonstrates the relationship between:

**Stored XSS + DOM manipulation = persistent visual modification**

---

# 7. 🖼️ Changing the Background Image

The module also demonstrates the `background` property:

```html
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```

Conceptually:

```text
document.body.background
          ↓
    Background image
```

Instead of changing the color, the page can display an image as its background.

---

# 8. 🏷️ Changing the Page Title

The browser tab title can be changed with:

```javascript
document.title = 'HackTheBox Academy'
```

The important property is:

```javascript
document.title
```

### Before

```text
┌──────────────────────────┐
│  2Do                     │
└──────────────────────────┘
```

### After

```text
┌──────────────────────────┐
│  HackTheBox Academy      │
└──────────────────────────┘
```

This demonstrates that XSS can manipulate more than the visible page body.

---

# 9. 📝 Changing Page Text with `innerHTML`

One of the most important concepts is:

```javascript
document.getElementById("todo").innerHTML = "New Text"
```

Here:

```text
document
   ↓
getElementById("todo")
   ↓
innerHTML
   ↓
"New Text"
```

The JavaScript finds the element whose ID is:

```text
todo
```

and replaces its HTML contents.

---

# 10. Understanding `innerHTML`

Suppose the page contains:

```html
<div id="todo">
    Old Text
</div>
```

Then:

```javascript
document.getElementById("todo").innerHTML = "New Text"
```

effectively changes the DOM to:

```html
<div id="todo">
    New Text
</div>
```

### ⭐ Key concept

`innerHTML` allows JavaScript to manipulate the HTML contained inside an element.

This is also why unsafe use of `innerHTML` is such an important concept in DOM-based XSS.

---

# 11. jQuery Alternative

If jQuery is loaded, the module demonstrates:

```javascript
$("#todo").html('New Text');
```

This performs a similar operation.

### Comparison

**JavaScript:**

```javascript
document.getElementById("todo").innerHTML = "New Text"
```

**jQuery:**

```javascript
$("#todo").html("New Text");
```

Both manipulate the contents of the selected element.

---

# 12. Replacing the Entire Page Body

Instead of changing one particular element, the module demonstrates selecting the `<body>`:

```javascript
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```

Let's break it down.

### `document.getElementsByTagName('body')`

Finds elements named:

```html
<body>
```

It returns a collection.

### `[0]`

Selects the first `<body>` element.

### `.innerHTML`

Controls the HTML contained inside it.

So:

```javascript
document.getElementsByTagName('body')[0].innerHTML = "New Text"
```

means:

> Replace the contents of the first `<body>` element with `"New Text"`.

---

# 13. 🧠 Why `[0]`?

`getElementsByTagName()` returns a collection.

Conceptually:

```text
getElementsByTagName('body')
            ↓
       HTMLCollection
            ↓
       ┌─────────┐
       │ body[0] │
       └─────────┘
```

Since a normal HTML document normally has one `<body>`, `[0]` selects that body.

---

# 14. Creating a Custom Defacement

The module creates HTML such as:

```html
<center>
    <h1 style="color: white">Cyber Security Training</h1>
    <p style="color: white">by 
        <img src="https://academy.hackthebox.com/images/logo-htb.svg" height="25px" alt="HTB Academy">
    </p>
</center>
```

The idea is:

```text
Original webpage
       ↓
JavaScript executes
       ↓
Body's innerHTML replaced
       ↓
Custom HTML appears
```

---

# 15. Why Test the HTML Separately?

The module gives an excellent practical tip:

> **Prepare and test your HTML separately before placing it into the final JavaScript payload.**

This makes troubleshooting much easier.

Instead of debugging:

```text
XSS
+
JavaScript
+
HTML
+
CSS
```

all at once, first make sure the HTML itself works.

Then incorporate it into the JavaScript.

---

# 16. Minifying the HTML

The module converts the multi-line HTML into a single line before placing it inside the JavaScript string.

Conceptually:

### Original

```html
<center>
    <h1>...</h1>
    <p>...</p>
</center>
```

### Minified

```html
<center><h1>...</h1><p>...</p></center>
```

This makes it easier to embed into a JavaScript string.

---

# 17. Complete Lab Payload Concept

The module combines the concepts into a stored-XSS demonstration containing:

```text
1. Background manipulation
2. Page title manipulation
3. Body/content manipulation
```

The three operations are conceptually:

```javascript
document.body.style.background = "...";
document.title = "...";
document.getElementsByTagName('body')[0].innerHTML = "...";
```

### Result

```text
        STORED XSS
            │
    ┌───────┼────────┐
    ↓       ↓        ↓
Background Title   Body HTML
    │       │        │
    └───────┼────────┘
            ↓
      Modified page
```

---

# 18. What Happens to the Original HTML?

This is an important point from the module.

When you inspect the source, the original HTML may still be present.

You could conceptually see:

```html
<div></div>
<ul>
    <ul>
        <script>...</script>
    </ul>

    <ul>
        <script>...</script>
    </ul>

    <ul>
        <script>...</script>
    </ul>
</ul>
```

The injected scripts are stored alongside the application's original content.

---

# 19. Source Code vs Rendered Page

This is **very important**.

The HTML source received by the browser can be different from what the user ultimately sees.

Think of it as:

```text
SERVER RESPONSE
      ↓
Original HTML
+
Injected JavaScript
      ↓
Browser parses HTML
      ↓
JavaScript executes
      ↓
DOM modified
      ↓
Rendered webpage
```

Therefore:

> **The browser's final appearance can be completely different from the original HTML response.**

---

# 20. Why Injection Position Matters

The module makes another important observation.

Suppose your injected script occurs:

```text
Near the beginning
        ↓
JavaScript executes
        ↓
Browser continues processing
        ↓
Other elements/scripts may appear
```

The final page could therefore be different from what you initially expected.

If the payload appears near the end:

```text
Original content
      ↓
Original scripts
      ↓
Injected JavaScript
      ↓
DOM modification
      ↓
Final appearance
```

the resulting page may be easier to control.

### ⭐ Key lesson

> **Where the payload is injected into the document can affect the final rendered result.**

---

# 21. Defacement Does Not Necessarily Mean Server Compromise

This is an important security distinction.

If XSS changes:

```text
document.body
document.title
DOM.innerHTML
```

the attacker has manipulated the **browser's representation of the page**.

That does **not automatically mean** they obtained:

- Server-level access
    
- Operating-system access
    
- Database administrator access
    
- Shell access
    

XSS is fundamentally a **client-side execution vulnerability**.

---

# 22. 🖼️ XSS Defacement Mental Model

![Image](https://images.openai.com/static-rsc-4/UILlhH_vG50CVU5xk7IJgTGVv63XSag-KbhwrSStC-opUVzSK1erXbcRJw6BPzRZmuyNJ4BDxpfQwcMVr4abiZU4JZwrU6fG1WIP-z7Y1eB4XDo9sUUYh26GSvwcwDNco2e2J4FNh1ATWQ3lT0kcPtnjlT0RlWVRDMB3d0PsxYdcGkYY5KXrpjkSAVxzTxUO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/t-TfGdVtHT9OvIkDmCh5_Y66UQVO6hPvb_RykWzYn74m26_IL7xJo3CLWN3eM3Y3l9hKOftmLEzy8PsuxvloI0SluwG5I0sn_uoPrWRhc-wMeoCZsvc5YmeQZ46H5S526emG_8wMOBkWZMb7Eo7HzmU6YzyKPGrL7-WAgTPVTHU-wCD846-dMvLsXxCwUNzr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7mYp563kcdh9CIt2qUR8tx5eTrSs2-yVMw2-fNQK4E1AH_RIitMDdijhRiCmZzwiQwO4IsuXr9jUdBQIIpsxPDq9lFMdTt2hzNg89ks1IoKuhqcEmLHYXey9CM0P-DevUAB7qX7Iw0ccLMNmuhON6HXrhTpsBPs6GcJPaMlYbFfvYu7JJdhYd5pztpACoOSX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NK5uumyqwt46ajo8iXFmQSIR4BW8zs6GDANDGJRk0rMo_yrQ_ORMo7yinsMopvdiMxuh6kKcKcNWG8PT5X_cM5TAWNOKVdZ3gwo9C1TmHJbqZ3-4Doa3SIb48cViXST-Prh-FD2_Qj4Li20mJk5NEAvPebylgiI0INIInhl5Ync4Ft44oxS6ARSXwtKRdb45?purpose=fullsize)

```text
                STORED XSS
                    │
                    ▼
             Payload stored
                    │
                    ▼
              Victim loads page
                    │
                    ▼
            Browser receives HTML
                    │
                    ▼
            JavaScript executes
                    │
       ┌────────────┼────────────┐
       ↓            ↓            ↓
  Background      Title       innerHTML
       │            │            │
       └────────────┼────────────┘
                    ↓
              DOM is modified
                    ↓
            User sees defaced page
```

---

# 23. Defacement Elements — Quick Reference

|Property|What it changes|
|---|---|
|`document.body.style.background`|Background styling|
|`document.body.background`|Background image|
|`document.title`|Browser tab/page title|
|`element.innerHTML`|HTML inside an element|
|`document.getElementsByTagName()`|Finds elements by HTML tag|
|`document.getElementById()`|Finds an element by ID|
|`$("#todo").html()`|jQuery HTML manipulation|

---

# 24. ⭐ Most Important Takeaways

### 1️⃣ Stored XSS is particularly dangerous for defacement

Because the payload can remain stored and affect visitors who load the affected content.

### 2️⃣ JavaScript can manipulate the DOM

For example:

```javascript
document.title
```

and:

```javascript
element.innerHTML
```

### 3️⃣ Defacement can be simple

An attacker doesn't necessarily need a sophisticated page. Changing:

- Background
    
- Title
    
- Main text
    

may be enough to demonstrate the impact.

### 4️⃣ `innerHTML` is extremely important

It can replace HTML content dynamically.

### 5️⃣ Original source and rendered DOM aren't necessarily identical

JavaScript can modify the DOM after the browser receives the original HTML.

### 6️⃣ Injection position matters

Where JavaScript executes can affect what ultimately appears on the page.

### 7️⃣ XSS ≠ server compromise

Defacing through XSS demonstrates control over the **victim's browser-rendered page**, not necessarily the underlying server.

---

# 🧠 Final Revision Card

```text
                    XSS DEFACING
                         │
                         ▼
                 Stored XSS Payload
                         │
                         ▼
                   Victim loads page
                         │
                         ▼
                   JS executes
                         │
          ┌──────────────┼──────────────┐
          ↓              ↓              ↓
     Background        Title       Page Content
          │              │              │
          ↓              ↓              ↓
   body.style...   document.title    innerHTML
          │              │              │
          └──────────────┼──────────────┘
                         ↓
                    DOM modified
                         ↓
                   Defaced webpage
```

### 🔥 One-line memory trick:

**Stored XSS → JavaScript executes → DOM/CSS changes → visitor sees modified webpage.**