## What is HTML Injection?

**HTML Injection** is a vulnerability that occurs when an application displays **unsanitized user input** as HTML content in a webpage.

When user input is inserted into a page without proper filtering, attackers can inject their own HTML code that the browser interprets and renders.

### Simple Definition

> HTML Injection occurs when an attacker can insert arbitrary HTML code into a webpage because user input is not properly validated or sanitized.

---

## Why is HTML Injection Dangerous?

When attackers control displayed HTML, they can:

- Modify the appearance of a website
    
- Insert fake login forms
    
- Display malicious advertisements
    
- Redirect users to malicious websites
    
- Deface web pages
    
- Prepare the page for more dangerous attacks like XSS
    

---

## How HTML Injection Works

### Normal Flow

```text
User Input
    ↓
Application
    ↓
Displayed as Text
```

Example:

```html
Input: John
Output: Your name is John
```

---

### Vulnerable Flow

```text
User Input
    ↓
No Sanitization
    ↓
Browser Interprets HTML
    ↓
HTML Executes
```

Example:

```html
Input:
<h1>Hacked!</h1>

Output:
Hacked!
```

The browser renders the HTML instead of displaying it as text.

---

# Visual Overview

## Safe Application

```text
User Input
   ↓
Validation/Sanitization
   ↓
Display as Text
   ↓
Safe
```

```mermaid
flowchart TD
A[User Input] --> B[Sanitize Input]
B --> C[Display as Text]
C --> D[Safe Website]
```

---

## Vulnerable Application

```text
User Input
   ↓
No Filtering
   ↓
HTML Rendered
   ↓
HTML Injection
```

```mermaid
flowchart TD
A[User Input] --> B[No Validation]
B --> C[Browser Renders HTML]
C --> D[HTML Injection]
```

---

# Example Vulnerable Application

## Source Code

```html
<!DOCTYPE html>
<html>

<body>
    <button onclick="inputFunction()">
        Click to enter your name
    </button>

    <p id="output"></p>

    <script>
        function inputFunction() {

            var input = prompt(
                "Please enter your name",
                ""
            );

            if (input != null) {

                document.getElementById("output")
                    .innerHTML =
                    "Your name is " + input;

            }
        }
    </script>

</body>
</html>
```

---

## Vulnerable Line

```javascript
document.getElementById("output").innerHTML =
"Your name is " + input;
```

### Why?

The code uses:

```javascript
innerHTML
```

`innerHTML` tells the browser:

> "Treat whatever is inside as HTML."

So if the user enters HTML tags, they are rendered instead of displayed as plain text.

---

# Testing for HTML Injection

## Step 1

Click:

```text
Click to enter your name
```

---

## Step 2

Instead of entering a name, enter:

```html
<h1>HTB Academy</h1>
```

---

## Result

Displayed page:

```text
Your name is

HTB Academy
```

The browser renders the heading.

---

# Page Defacement Example

One common use of HTML Injection is website defacement.

### Payload

```html
<style>
body {
    background-color: red;
}
</style>
```

---

### Result

```text
Entire webpage background becomes red.
```

The attacker has modified the page appearance.

---

# HTB Example Payload

The course uses:

```html
<style>
body {
    background-image:
    url('https://academy.hackthebox.com/images/logo.svg');
}
</style>
```

---

### What Happens?

The CSS gets injected into the page.

The browser processes:

```css
body {
    background-image:
    url(...);
}
```

Result:

```text
HTB logo becomes webpage background.
```

---

## Visualization

### Before Injection

![Image](https://images.openai.com/static-rsc-4/ZIBhWCbdwdvVU3ilPThQXg4Xj1vEgsm_Ja07eiBzCcBTOmfdU-y6q3tB8BLA7i1YYbXpcsJ8QxvaXltrgVEl5kOJ12g3FQ3e__rEIcU0TjNr7rcj3GjvBD6bAETEdUEOfyDe5dA-SO8JcdOHGunH-GeCHb842USbrh79gMMzdiPFrixa39NU7jNw_Auo36d8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qVlovuwsXZgg11cMxFLLkf9ndahQ6AE_UDoObqG-2iWn36TJ7TtcBUnWWgSj_eVNXxgKTRG1lj7le1cdvcF000-205cetQgiSNMsKCz_Kxoh-WcSbH8fNgfxaLskg0P46lWZL1CD9slPuImrTkl8rlrhgHZRX3aMeQ3F1DJrxrivE374uZmcl8_qpUOdmx_X?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HclMZi2xM39DyPP7WGPHYOP8EBWBz9mxlGTIiBk86jOI3CV9yCSZH2eO4kM43giEU25jMai-1-k998kxBuPKXe9T0ZI-JLSA-A-aOpUm0VFY934D9dot7Ea13wUvp2UVdaf-swChNoX1yCtlnRcXDf1T_16NSiZwk-gRiOmCJ2LAC__KV2XEdt0D4jfujYHR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8TzHREC7PAfiJNAH8zHSHAWFJSY2UViRg8A97Yf8b0iVcTeD2W146gwDXvUtKB8JxxSo7XjaAXVvWCLnay1-EgnqeA-IhET9Cc0SFmXlFhoI7nWjOHlsRyMjOlzxQQ6Zx1PK_-lCJ-6JQ63kDUg0mosz_mxwL5EljXkB48aZe8lxSbIh16cS-0IYJ6WQFxTM?purpose=fullsize)

---

### After HTML Injection / Defacement

![Image](https://images.openai.com/static-rsc-4/VwqU4u5GuwhO8NYu7WXBl-S7lbkBaa0ldg3FL13SPicMJotDbhsXFF8VH83T8f0wgb550F0qLmrlUBacWBdZXUd1xfKdkPEEW5oOEyCd-nUO80HmT4qUcbh9kCdlbSvGTov2cMxlog3KVHrQlRTKQUnj7mOVpXCLvkHfi7M_5dMtV-I4c-FXttdbBSJF6ZyR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/a8s6Y_hv2pNXTweDNa9-xoaHGsE0nTqByw7CUXoFg_Th9so7o0axABNO0bOYVaWMAMWX4YCQg4v6G9fBavDtz-DGfn6UXYpjIwo6ZFVntJ22_EWw-eeVQdyGvhzX1pnL_yRKwUUKjXk8stoSYcn6ZLKKFgHzuLahUpu6_uWX8hWLBpuvPa0_TaenZXh1w85A?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/N0hmeTJfYjB2T-D20z5pbKnUSMyvPnRis9BDXwPAjJanXYFdBTbdmaTrWEj0REkeiVk-IznZV1-jIsBczHSJJY8tLffGa5dtSqxZ0TOQwj6JdJsS1Jnu5GculqNrHAC4Bvj0pub7xOb5fJ-_iuIEWVEB7PAEUPtGfzKBAqS6bgENHKdwYOkSWn4H2fVmHq9G?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/YFTt5Op_KeJZhfcjxT_OEVpEHhPqQZHzGeuZg-lQH4WsOSpnEh0cxIdnEm_h2nnrkaFiwt4Xulh7Vno3flTyhAMLnn2UK4PFVl9SOPeTB3bratGqXRTxe3-sYOdiPkFs_p2brgGDOidQLlyOtvN8_R6pk7XMAedfagdiRJyhYzz0VMqTMqX2SwksTfYPdSd8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/21I2vGWFZMVvni-jYRD_gbKF3btLqRqnZWy0QI5Yg0NcwW3gXGC13xoLqwiGdvME-zTshafFKPJDVzRIZrhSS_1AMeMwE9Ghrn-n15wtnRGCJVSV24mKRpZvleEOZ8nlIwaWw8Y-LOF-aIZz3rmqKbMx8xqSgyKbVEk-yCj61aTZp6TNcMdACmqidfKBpbMv?purpose=fullsize)

---

# Common HTML Injection Payloads

## Change Text

```html
<h1>Website Hacked</h1>
```

Result:

```text
Large heading displayed
```

---

## Change Text Color

```html
<h1 style="color:red;">
Hacked
</h1>
```

---

## Add Image

```html
<img src="image.jpg">
```

---

## Add Fake Login Form

```html
<form>
Username:
<input type="text">

Password:
<input type="password">

<input type="submit">
</form>
```

Result:

```text
Fake login form appears
```

Attackers often use this for phishing.

---

## Add Hyperlink

```html
<a href="https://evil.com">
Click Here
</a>
```

---

## Change Background

```html
<style>
body {
    background:black;
}
</style>
```

---

# Difference Between HTML Injection and XSS

|HTML Injection|XSS|
|---|---|
|Injects HTML|Injects JavaScript|
|Changes page appearance|Executes scripts|
|Usually lower impact|Usually higher impact|
|Used for defacement|Used for account takeover, cookie theft|
|May lead to XSS|Directly executes code|

---

## HTML Injection Example

```html
<h1>Hello</h1>
```

Only HTML is rendered.

---

## XSS Example

```html
<script>
alert('XSS');
</script>
```

JavaScript executes.

---

# Root Cause

The vulnerability exists because:

```javascript
innerHTML
```

is used with untrusted input.

Example:

```javascript
element.innerHTML = userInput;
```

The browser interprets user input as HTML.

---

# Secure Alternative

Instead of:

```javascript
innerHTML
```

Use:

```javascript
textContent
```

Example:

```javascript
element.textContent =
"Your name is " + input;
```

---

### Difference

#### innerHTML

```javascript
element.innerHTML =
"<h1>Hello</h1>";
```

Output:

# Hello

(rendered heading)

---

#### textContent

```javascript
element.textContent =
"<h1>Hello</h1>";
```

Output:

```text
<h1>Hello</h1>
```

(displayed as text)

---

# Prevention

## 1. Validate User Input

Allow only expected characters.

Example:

```javascript
/^[a-zA-Z ]+$/
```

Only letters and spaces.

---

## 2. Sanitize Input

Remove dangerous tags:

```html
<script>
<style>
<iframe>
<object>
```

---

## 3. Use textContent

Preferred:

```javascript
element.textContent = input;
```

Avoid:

```javascript
element.innerHTML = input;
```

---

## 4. Server-Side Validation

Never trust client-side validation alone.

```text
Client Validation
      +
Server Validation
```

Both are required.

---

## 5. Encode Output

Convert:

```html
<
>
"
'
&
```

Into:

```html
&lt;
&gt;
&quot;
&#39;
&amp;
```

---

# Attack Chain

```text
User Input
    ↓
No Sanitization
    ↓
HTML Injection
    ↓
Page Defacement
    ↓
Fake Login Form
    ↓
Credential Theft
```

---

# Key Exam / HTB Points

### Remember

✅ HTML Injection = Unfiltered user input rendered as HTML

✅ Caused by improper input validation/sanitization

✅ Commonly occurs with:

```javascript
innerHTML
```

✅ Can lead to:

- Website defacement
    
- Fake forms
    
- Malicious links
    
- Social engineering attacks
    

✅ Testing Method:

```html
<h1>Test</h1>
```

If rendered as a heading → HTML Injection exists.

✅ Secure Alternative:

```javascript
textContent
```

instead of

```javascript
innerHTML
```

✅ Input should be validated and sanitized on:

- Front End
    
- Back End
    

---

# Quick Revision (1 Minute)

```text
HTML Injection
=
Displaying user input as HTML.

Cause:
innerHTML + No Sanitization

Impact:
• Defacement
• Fake Forms
• Malicious Links
• Reputation Damage

Test:
<h1>Test</h1>

Secure Fix:
textContent
+
Input Validation
+
Output Encoding
+
Server-side Sanitization
```

This covers all the important HTB concepts while preserving the key examples and payloads from the module.

