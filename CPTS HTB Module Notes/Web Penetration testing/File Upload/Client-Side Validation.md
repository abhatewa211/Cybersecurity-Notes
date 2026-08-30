![Image](https://images.openai.com/static-rsc-4/xi5Ts9_mDE8LwJjyG5HHHgqWvl-AlQI9-ePfakpAXA9zuquVJJd7BCqKWMq8mnqm14rwEc898WxdXepPFqDx1QxCfm7NX_dwBw3hLNO3ssjkViNGlKaPW7SAoaXiwMZSV-RPAyyCQKN7gcQlvPin9m2xKX35a2I3j71yjAxNLf6kRqlathNvFBxuzxPi8QsK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DyoUvFrJYd9wbiXoZBe4H4M-uj20YcOFIE289KcJ33ek83aXiJAQfgrKsMuvndr3jWG-Z5IWl5HlNHlMLyEFZZhuRKoGSkuqBUTRL5AbeBn6snDLNcIhE-yV0USiyw62bxR4m4Xs9_LFSbxaHtLExHybEXn1ac64Z5Qoed7NfKyYCbqmxdJlllIucxH6Mfor?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dxViUcZ-kSzPrfeoo-r33dU6WCdDEf2xk_PMZHqHEBA5SZYLT3yGr6SByP9pXzttaMv2Lp5YhWF3hHOXsZMuZC13IfiQ1CRgelyxiF8lVHyUSkGHp4cxwdhpI19YTK5D53UFBkY_e9NknqeOuGjbR9jeZ28ZEK9UU1Jpcv28aGdeQKA8AKR3YMKUOAnGDpVJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/r0Vrl2p__A_02i9TeyRMLEamGAvBSzvU3PG93BXY4XQTHHbLwIRkyKJYWhg2YOtAPBam8Fbvo4mnvdfeGkD1E6FiaWBnA7dJBpejBvvXgJxpDKujSJgBj35U5qpYNuJ2V6s8jIQIkBtwkuIs1KbPfkyrlukuySW7qSNuMAEg4WcBWN5rg_atX2GuU8AaMivn?purpose=fullsize)

---

## 1. What Is Client-Side Validation?

**Client-side validation** means that the browser checks the user's input **before sending it to the server**.

For file uploads, JavaScript may check:

```text
Is this file an image?
        ↓
YES → Allow Upload
NO  → Reject Upload
```

For example, an application might allow:

```text
.jpg
.jpeg
.png
```

and reject:

```text
.php
.jsp
.asp
.exe
```

### The security problem

The browser is controlled by the user.

Therefore:

> 🔴 **Client-side validation must never be considered a sufficient security control.**

If the backend doesn't perform its own validation, an attacker may be able to bypass the browser restrictions.

---

# 2. Client-Side vs Server-Side Validation

This is probably the **most important concept** in this section.

### Client-side validation

```text
User
 ↓
Browser
 ↓
JavaScript Validation
 ↓
Upload Request
 ↓
Server
```

### Server-side validation

```text
User
 ↓
Browser
 ↓
Upload Request
 ↓
Server
 ↓
Validation
 ↓
Accept / Reject
```

The difference is crucial.

The user can control:

- Browser behavior
    
- JavaScript execution
    
- HTML displayed in the browser
    
- HTTP requests sent to the server
    

But the user **cannot directly control the server's validation logic**.

Therefore:

> **Security-critical validation belongs on the backend.**

---

# 3. Recognizing Client-Side Validation

The exercise presents a **Profile Image** upload feature.

Normally, the application expects image files.

The file-selection dialog only displays:

```text
.jpg
.jpeg
.png
```

When a PHP file is selected, the application displays:

```text
Only images are allowed!
```

and disables the upload button.

At first glance, this looks secure.

But there is an important observation:

> **The page doesn't refresh or send an HTTP request when the invalid file is selected.**

That strongly suggests the rejection is happening locally in JavaScript.

---

# 4. The Important Question

When you encounter an upload restriction, don't immediately assume:

> "The server rejected my file."

Instead ask:

> **"Did the request ever reach the server?"**

If no request was sent, the restriction may exist entirely in the browser.

Conceptually:

```text
Select PHP
    ↓
JavaScript checks extension
    ↓
❌ Rejected
    ↓
No HTTP request
```

If the validation were server-side:

```text
Select PHP
    ↓
Browser sends request
    ↓
Server validates
    ↓
❌ Server rejects
```

This distinction is fundamental.

---

# 5. How Client-Side Validation Can Be Bypassed

The material presents **two approaches**:

### Method 1 — Modify the backend request

Use an intercepting proxy such as Burp Suite to capture the legitimate upload request and modify it before it reaches the server.

### Method 2 — Modify/disable frontend validation

Use browser developer tools to modify the HTML/JavaScript running locally.

```text
             Client-Side Validation
                     │
             ┌───────┴────────┐
             ▼                ▼
      Request Modification   JS/HTML Modification
             │                │
           Burp            Browser DevTools
```

---

# 🔬 6. Method 1 — Back-End Request Modification

The first approach is to capture a legitimate upload request.

The material uses **Burp** for this.

The normal workflow is:

```text
Select legitimate image
        ↓
Click Upload
        ↓
Burp captures request
        ↓
Inspect request
```

The application sends a standard HTTP upload request to:

```text
/upload.php
```

---

# 7. Understanding the Multipart Upload Request

An upload request commonly contains information describing the uploaded file.

One important part is:

```text
filename="HTB.png"
```

and another important part is the actual:

```text
file content
```

Conceptually:

```text
HTTP POST
   │
   ├── filename="HTB.png"
   ├── Content-Type: image/png
   │
   └── File Content
```

For the purposes of the authorized lab, the key question is whether changing these values causes the **backend** to accept something the frontend would reject.

---

# 8. Modifying the Request

The material demonstrates modifying:

```text
filename="HTB.png"
```

to:

```text
filename="shell.php"
```

and replacing the file content with the appropriate PHP test/web-shell content.

Conceptually:

```text
Original:

filename="HTB.png"
Content → PNG


Modified:

filename="shell.php"
Content → PHP
```

The frontend JavaScript is no longer involved because the request is being modified directly.

---

# 9. What About `Content-Type`?

The material specifically notes:

> **We may also modify the `Content-Type` of the uploaded file, though this should not play an important role at this stage, so we'll keep it unmodified.**

This is an important learning point.

An upload request can contain multiple pieces of metadata:

```text
Filename
Content-Type
File contents
```

But their security significance depends on what the backend actually validates.

If the server trusts only one of these values, that can create weaknesses.

---

# 10. Why Burp Works Here

The browser's JavaScript says:

```text
"PHP files aren't allowed."
```

But Burp operates on the HTTP request **after the browser has generated it**.

So the flow becomes:

```text
Browser
   ↓
Valid image request
   ↓
Burp
   ↓
Modify request
   ↓
Backend
```

The browser's original validation doesn't get another chance to inspect the modified request.

---

# 11. The Critical Backend Question

After modifying the request, the result tells us whether the backend has its own validation.

### If backend rejects it:

```text
Modified Request
      ↓
Backend Validation
      ↓
❌ Rejected
```

Then server-side validation exists.

### If backend accepts it:

```text
Modified Request
      ↓
Backend
      ↓
✅ File accepted
```

then the frontend restriction was not sufficient to prevent the upload.

This is the central lesson of the exercise.

---

# 🖥️ 12. Method 2 — Disabling Front-End Validation

The second method is to modify the JavaScript/HTML running inside the browser.

Because the frontend code executes locally:

> **The tester can manipulate the local copy of that code.**

This does **not** modify the actual server-side application.

It only changes what the current browser executes.

---

# 13. Opening the Page Inspector

The material uses Firefox.

The shortcut:

```text
CTRL + SHIFT + C
```

opens/toggles the **Page Inspector**.

You can then select the profile-image upload element.

---

# 14. The HTML File Input

The material identifies this HTML:

```html
<input type="file" name="uploadFile" id="uploadFile"
onchange="checkFile(this)" accept=".jpg,.jpeg,.png">
```

There are two particularly important attributes here:

### `accept`

```html
accept=".jpg,.jpeg,.png"
```

This influences which files the browser's file-selection dialog presents as acceptable.

### `onchange`

```html
onchange="checkFile(this)"
```

This causes JavaScript to execute when the selected file changes.

---

# 15. Understanding `accept`

The:

```html
accept=".jpg,.jpeg,.png"
```

attribute tells the browser which file types should be presented/selected through the file chooser.

But remember:

> **`accept` is a browser-side convenience/restriction, not a security boundary.**

It doesn't prove that the backend will reject other file types.

The material notes that `accept` can be removed/changed locally to make selecting another file easier.

---

# 16. Understanding `onchange`

The more interesting part is:

```html
onchange="checkFile(this)"
```

This means:

```text
File selected
     ↓
JavaScript executes
     ↓
checkFile()
     ↓
Validate extension
     ↓
Accept / Reject
```

So we need to inspect:

```text
checkFile()
```

---

# 🔎 17. Inspecting `checkFile()`

The material uses the browser console:

```text
CTRL + SHIFT + K
```

Then entering:

```text
checkFile
```

reveals the JavaScript function.

The relevant logic is:

```javascript
function checkFile(File) {
    ...
    if (extension !== 'jpg' &&
        extension !== 'jpeg' &&
        extension !== 'png') {

        $('#error_message').text("Only images are allowed!");
        File.form.reset();
        $("#submit").attr("disabled", true);

        ...
    }
}
```

---

# 18. Understanding the JavaScript

Let's break down what the function does.

### Extension check

```javascript
extension !== 'jpg'
```

checks whether the extension isn't JPG.

Likewise:

```javascript
extension !== 'jpeg'
extension !== 'png'
```

check the other allowed extensions.

So the application effectively says:

```text
Allowed:
jpg
jpeg
png

Everything else:
reject
```

---

# 19. Error Message

When the extension doesn't match:

```javascript
$('#error_message').text("Only images are allowed!");
```

the browser displays:

```text
Only images are allowed!
```

This explains the error observed earlier.

---

# 20. Resetting the Form

The function also executes:

```javascript
File.form.reset();
```

This resets the upload form.

So the selected invalid file is removed.

---

# 21. Disabling the Upload Button

The JavaScript also contains:

```javascript
$("#submit").attr("disabled", true);
```

This disables the upload button.

Therefore, the complete behavior is:

```text
PHP selected
    ↓
checkFile()
    ↓
Extension isn't jpg/jpeg/png
    ↓
"Only images are allowed!"
    ↓
Reset form
    ↓
Disable Upload
```

---

# 22. Why This Is Bypassable

The important realization is:

```text
checkFile()
```

is running **inside your browser**.

Therefore, modifying or removing the function changes what your browser does.

The server doesn't automatically know that the JavaScript was modified.

This leads to a core security principle:

> 🔴 **Never rely on client-side code to enforce security restrictions.**

---

# 23. Removing the JavaScript Validation

The material demonstrates removing:

```html
onchange="checkFile(this)"
```

from the HTML element.

The resulting element would conceptually become:

```html
<input type="file"
       name="uploadFile"
       id="uploadFile"
       accept=".jpg,.jpeg,.png">
```

Now selecting a file no longer triggers the `checkFile()` function.

---

# 24. Removing `accept`

The material also notes that:

```html
accept=".jpg,.jpeg,.png"
```

can be removed.

This is **not mandatory** for bypassing the validation because the file chooser can often be switched to `All Files`.

Removing `accept` simply makes selecting other files easier.

---

# 25. Important: Browser Modification Is Temporary

This is a very important concept.

When you modify the HTML through developer tools:

```text
Browser's local DOM
       ↓
Modified
```

you are **not modifying the server's source code**.

Refreshing the page normally restores the original HTML/JavaScript.

Therefore:

```text
Modify browser
      ↓
Validation disabled locally
      ↓
Upload
      ↓
Refresh
      ↓
Original page returns
```

This is completely expected.

---

# 26. Finding the Uploaded File

After the upload, the material shows the profile image element:

```html
<img src="/profile_images/shell.php"
     class="profile-image"
     id="profile-image">
```

The important part is:

```text
/profile_images/shell.php
```

This tells us where the uploaded file is being referenced.

Conceptually:

```text
Upload
  ↓
Server stores file
  ↓
Profile image points to it
  ↓
/profile_images/shell.php
```

---

# 27. Accessing the Uploaded File

The material then demonstrates accessing the uploaded PHP file through its URL.

The example uses:

```text
/profile_images/shell.php?cmd=id
```

If the server executes the PHP code, the response demonstrates command execution.

Again, the important distinction is:

```text
File uploaded
      ≠
Code executed
```

You need to determine what the server actually does with the uploaded file.

---

# 🧩 28. Complete Client-Side Validation Bypass Flow

### Method 1 — Request Modification

```text
Select valid image
       ↓
Browser creates request
       ↓
Burp intercepts
       ↓
Modify filename/content
       ↓
Send request
       ↓
Backend
       ↓
Does backend validate?
       ↓
If not → File accepted
```

### Method 2 — Frontend Modification

```text
Open Developer Tools
       ↓
Inspect upload input
       ↓
Find onchange="checkFile(this)"
       ↓
Inspect JavaScript
       ↓
Remove/modify client-side check
       ↓
Select file
       ↓
Upload normally
       ↓
Backend receives request
```

---

# ⚔️ 29. Client-Side vs Absent Validation

These two sections are closely related.

|Feature|Absent Validation|Client-Side Validation|
|---|---|---|
|Frontend restriction|None|Present|
|Backend restriction|None|Potentially none|
|File chooser|All files|May show only allowed types|
|JavaScript check|None|Present|
|Can browser-side check be bypassed?|Not applicable|Yes|
|Main test|Upload unexpected file|Determine whether backend validates independently|
|Risk|Potentially arbitrary upload|Potentially arbitrary upload if backend trusts frontend|

### Key difference

**Absent Validation:**

```text
No restriction anywhere
```

**Client-Side Validation:**

```text
Restriction exists
BUT
restriction may exist only in browser
```

---

# 🧠 30. Key Security Principle

This entire section demonstrates a very important rule:

> **Client-side validation is for usability; server-side validation is for security.**

For example:

```text
Browser:
"Only JPG/PNG allowed."

          ↓

Attacker:
"I can modify the browser."

          ↓

Server:
"Do I independently verify this?"

          ↓
      YES → Secure layer
      NO  → Vulnerability
```

---

# 🔥 31. Important Things to Memorize

> 🔴 **Client-side validation occurs in the user's browser.**

> 🔴 **Anything running in the browser should be considered controllable by the user.**

> 🔴 JavaScript-based file validation can be bypassed if the backend does not independently validate the upload.

> 🔴 The browser's `accept` attribute is **not a security boundary**.

> 🔴 `onchange="checkFile(this)"` means a JavaScript function is triggered when the file selection changes.

> 🔴 `checkFile()` in the example checks whether the extension is `jpg`, `jpeg`, or `png`.

> 🔴 The function displays **"Only images are allowed!"** when the extension doesn't match.

> 🔴 The function also resets the form and disables the upload button.

> 🔴 If selecting an invalid file causes **no HTTP request**, the validation may be entirely client-side.

> 🔴 Burp can be used to capture and modify the HTTP upload request in an authorized test.

> 🔴 Important multipart request components include the **filename** and **file content**.

> 🔴 `Content-Type` is another piece of upload metadata, but shouldn't automatically be trusted as proof of file type.

> 🔴 Developer Tools can modify the browser's local representation of HTML/JavaScript.

> 🔴 Browser-side modifications are **temporary** and normally disappear after refresh.

> 🔴 The ultimate security test is whether the **backend independently validates the uploaded file**.

---

# 🎯 32. Quick Revision Sheet

## Identify Client-Side Validation

Look for:

```text
File selected
     ↓
Error appears
     ↓
Upload button disabled
     ↓
No HTTP request
```

➡️ Strong indication that validation is happening client-side.

---

## Method 1 — Request Modification

```text
Valid upload
    ↓
Intercept request
    ↓
Modify request
    ↓
Send to backend
    ↓
Observe server response
```

**Question:** Does the backend independently reject the unexpected file?

---

## Method 2 — Frontend Modification

```text
CTRL + SHIFT + C
        ↓
Inspect upload element
        ↓
Find checkFile()
        ↓
CTRL + SHIFT + K
        ↓
Inspect JavaScript
        ↓
Modify/remove client-side validation
        ↓
Upload
```

---

# ⭐ 33. Final Takeaway

The biggest lesson from **Client-Side Validation** is:

> **Never trust security controls that exist only in the browser.**

A secure upload system should behave like:

```text
Browser Validation
       ↓
Helpful UX
       ↓
HTTP Request
       ↓
SERVER-SIDE VALIDATION
       ↓
File Type Verification
       ↓
Safe Storage
```

Even if an attacker:

- changes the HTML,
    
- disables JavaScript,
    
- changes the `accept` attribute,
    
- modifies the browser,
    
- or manually constructs the HTTP request,
    

the **backend should still reject an unauthorized file**.

### 🧠 One-line memory trick:

**“Frontend validation can stop a normal user; backend validation must stop an attacker.”**