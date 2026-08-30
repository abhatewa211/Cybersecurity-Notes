![Image](https://images.openai.com/static-rsc-4/dEg1uktJwSbSzX--a0h2pJuHmBdPg5mgfMyb_c9wsw5WUeUMDQJERuMYwgD4Djug9UuqxUoaD9s9t2zW-fhj65PG7VxXss-mArXe-4rgcFf-AMyAYoo0-4Q9P8zlq6TIID5mEzD1OVp3eaoh57KAuMa05L7aRMmp2XBzptJcX5ctTowXNVHFQShFPKRPUKog?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/b-AewgNaOaHSQNYrE9qGCORIyTmQHS9BlKhbJVXziKmi_wLE98fSb2VwG2cuaOnbCjQbhaOBti82-C_IH1KZFIWSN4L5lodQa7p30fqjSpw8iDWWqZk9JvkfCUr5DK5IQG1UZnRKTPg3BedBDbaoA9v0jbbjkh5E9exVddwVgAe_S5hlbZYyC4xqEyLDohWV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gtb2I96BJ2vcbKXSse8jSSouBgUkvR723oHQqixXr4SrklgkFcldz7w1UOmvV3wULhOy3z_3K0X1cffo2p3K-3xAK7B_TmTgk2lO4hxybob4t6ABMrCteOPabdVIkzTDP354NUn8HWoKkxWZbJiuiEAhf9CVnONVijqI7QMlPgfZav8zDSTFpP9wRPsxSpbg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qeOzxhRmZqucFjY-n8BtrED7AYKWbu7XAGtGKTK-8jXFN07AZhRI3fsFhvoNaeYm6njsPba0HZN1tfq24GBkx9szEvXXvYLi4O9CjQbSUEGeEvFcEwF1djXS4aLfzqhijpmHfUv3SbICOxU1yMbRlDi8ZRikDFtXROGLPtVL42lVpClz0iYoYVLHpjLjX9vR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sKoHNbVZg-0w_EOYejxt5gQsT7V7s-eICUE05WglVKj8Jxnzvb6raKMh_WOiWgGXPDu8sZFowygNR7UgudhmNEQ7P6H359b2ey5uGYL2564hiEGqsYwf6gr1C5yGyP9VDRn2oPdT9NRF7ki1YjGtb1bIlbv2ylRVtYPAICaaASXtjHiBb67wkO38qSypGATq?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/sSU-e5RMb21l10Y7SqdMoyjHsMRdEqTUDGwJn43WXqnXHwvJSi0CW2Z04gevL0UOXdNp5k3kQTW-ScpIEqduV8ZS25nJrl3EiE4s1IBuP7cM5R9RYMFgC9ttGrZtckNk6ZwRkXasyoJXpshP-gUoPRyOsc--YZUxh-9H_FNNt9kgs2zFYu99HCWb2BMHIkzi?purpose=fullsize)

---

## 1. What Is a Blacklist Filter?

A **blacklist** is a list of file types/extensions that the application explicitly refuses to accept.

For example:

```text
php
php7
phps
```

The logic is essentially:

```text
Uploaded File
     ↓
Extract Extension
     ↓
Is extension in BLACKLIST?
     ↓
 YES ──→ ❌ Reject
 NO  ──→ ✅ Continue
```

The problem is that a blacklist only knows about the things the developer remembered to block.

> ⚠️ **A blacklist is incomplete by design.**

If a server supports another executable extension that isn't present in the blacklist, that extension may potentially bypass the filter.

---

# 2. Why Backend Validation Matters

In the previous section, the application only had **client-side validation**, which could be bypassed by modifying the request.

Here, the situation is different.

When we modify the upload request and attempt to upload a PHP file, the server responds:

```text
Extension not allowed
```

This tells us something important:

> **The backend is performing its own validation.**

So simply bypassing the frontend is no longer enough.

The attack surface now becomes:

```text
Browser
   ↓
Client-side validation
   ↓
Burp/request modification
   ↓
Backend blacklist
   ↓
?????
```

The question becomes:

> **Can the backend blacklist itself be bypassed?**

---

# 3. Two Common Extension Validation Models

Backend applications generally use two major approaches.

### ① Blacklist

Block known-dangerous extensions:

```text
.php
.php7
.phps
```

Everything else is potentially allowed.

### ② Whitelist

Explicitly allow only known-safe extensions:

```text
.jpg
.jpeg
.png
```

Everything else is rejected.

### Comparison

|Blacklist|Whitelist|
|---|---|
|Blocks known bad types|Allows known good types|
|Everything not listed may pass|Everything not listed is rejected|
|Difficult to make comprehensive|Generally stronger|
|New executable extensions may be missed|Unknown extensions are rejected|

**Security takeaway:**

> A properly implemented whitelist is generally safer than relying on a blacklist alone.

---

# 4. The Example Blacklist Code

The module provides this PHP validation:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

Let's understand this line by line.

---

## 5. Extracting the Filename

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
```

The application obtains the uploaded filename.

For example:

```text
shell.php
```

becomes:

```text
$fileName = shell.php
```

`basename()` extracts the filename portion.

---

# 6. Extracting the Extension

```php
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
```

This extracts the extension.

For:

```text
shell.php
```

we get:

```text
$extension = php
```

For:

```text
shell.jpg
```

we get:

```text
$extension = jpg
```

---

# 7. Defining the Blacklist

```php
$blacklist = array('php', 'php7', 'phps');
```

The application explicitly blocks:

```text
php
php7
phps
```

So:

```text
shell.php   → ❌
shell.php7  → ❌
shell.phps  → ❌
```

But potentially:

```text
shell.phtml → ?
shell.phpX  → ?
other supported extension → ?
```

could behave differently depending on the server configuration.

---

# 8. Checking the Blacklist

```php
if (in_array($extension, $blacklist)) {
```

The application asks:

> "Is the uploaded extension present in my blacklist?"

If yes:

```php
echo "File type not allowed";
die();
```

The request is rejected.

---

# 🚨 9. The Fundamental Weakness

The key problem is:

> **The blacklist isn't comprehensive.**

The developer has blocked:

```text
php
php7
phps
```

but PHP-capable web server configurations can support additional extensions.

Therefore:

```text
Blocked extension
      ↓
❌ php

Unblocked extension
      ↓
? phtml
? other PHP-associated extensions
```

Whether an alternative extension actually executes PHP depends on the **specific web server/PHP configuration**.

---

# 10. Case-Sensitivity Issue

Another weakness in the example is that the comparison is case-sensitive.

The code checks:

```text
php
```

but not necessarily:

```text
PHP
pHp
PhP
```

because:

```php
in_array()
```

performs a case-sensitive string comparison by default.

Therefore, conceptually:

```text
php → blacklist match
pHp → potentially no match
PHP → potentially no match
```

### Important qualification

The effectiveness of a case variation depends on the operating system, web server, PHP configuration, and how the server maps extensions.

The module specifically highlights **Windows servers**, where filenames are generally case-insensitive.

---

# 11. Blacklist Bypass Concept

The overall concept is:

```text
Developer:
"Block PHP."

       ↓

Blacklist:
php
php7
phps

       ↓

Tester:
"Are there other extensions that the server treats as PHP?"

       ↓

Test alternatives

       ↓

Potentially find:
Extension accepted
+
PHP executed
```

This is why simply adding a few common dangerous extensions to a blacklist isn't a robust security design.

---

# 🔎 12. Fuzzing Extensions

Instead of manually trying hundreds of extensions, we can **fuzz** the upload functionality.

### What is fuzzing?

Fuzzing means automatically testing many possible inputs and observing how the application responds.

Here we're asking:

> **Which file extensions are rejected and which ones get through?**

Conceptually:

```text
.php
.php7
.phps
.phtml
.phpX
....
 ↓
Upload endpoint
 ↓
Compare responses
```

---

# 13. Useful Extension Wordlists

The module mentions two useful resources:

### PayloadsAllTheThings

Contains extension lists for:

- PHP
    
- ASP/.NET
    

### SecLists

Contains common web extensions.

These lists are useful because manually guessing extensions is inefficient.

---

# 14. Burp Intruder Workflow

The exercise uses **Burp Intruder** to automate extension testing.

Starting point:

```text
Burp History
     ↓
Find /upload.php request
     ↓
Right-click
     ↓
Send to Intruder
```

---

# 15. Configure the Attack Position

Inside **Intruder → Positions**:

### Step 1

Click:

```text
Clear
```

This removes automatically detected positions.

### Step 2

Find the filename:

```text
filename="HTB.php"
```

### Step 3

Select only:

```text
.php
```

### Step 4

Click:

```text
Add
```

Now the extension becomes the fuzzing position.

Conceptually:

```text
filename="HTB.$EXT$"
```

where `$EXT$` will be replaced by each payload.

---

# 16. Why Keep the File Content?

The module says to keep the file content unchanged.

That's because we're currently testing:

> **Which extensions pass the validation?**

We're not yet primarily testing the payload.

So:

```text
Filename → variable
File content → constant
```

This makes the experiment easier to interpret.

---

# 17. Loading the Extension Wordlist

Go to:

```text
Intruder → Payloads
```

Then load the PHP extension list.

Burp will send requests similar to:

```text
filename="HTB.php"
filename="HTB.php7"
filename="HTB.phtml"
filename="HTB.phar"
...
```

depending on the wordlist.

---

# 18. URL Encoding

The module specifically recommends disabling:

```text
URL Encoding
```

for this test.

Why?

Because we want the payload to remain an actual extension such as:

```text
.phtml
```

rather than having characters unnecessarily encoded.

---

# 19. Start the Attack

After loading the payload list:

```text
Start Attack
```

Burp sends multiple requests with different extensions.

The result table lets us compare:

```text
Extension
Status
Response length
Response content
```

---

# 📊 20. Analyzing Intruder Results

The exercise observes that successful requests had:

```text
Content-Length: 193
```

and returned:

```text
File successfully uploaded
```

while rejected requests returned:

```text
Extension not allowed
```

This creates a useful distinction:

```text
Response A:
File successfully uploaded
        ↓
Potentially allowed extension

Response B:
Extension not allowed
        ↓
Blacklisted extension
```

---

# 21. Why Response Length Is Useful

If you're testing hundreds of payloads, manually opening every response isn't practical.

Sorting by:

```text
Length
```

can quickly reveal groups of responses that behave differently.

For example:

```text
193 bytes → File successfully uploaded
different length → Extension not allowed
```

The exact lengths are specific to the exercise; **don't memorize 193 as a universal value**.

The important concept is:

> **Look for response differences that identify which payloads passed validation.**

---

# 🎯 22. Finding a Non-Blacklisted Extension

After fuzzing, we may discover extensions that weren't included in the blacklist.

One example from the module is:

```text
.phtml
```

The important distinction is:

> **Non-blacklisted does not automatically mean executable.**

An extension can be accepted for upload but still not be interpreted as PHP.

Therefore, two separate questions must be answered:

### Question 1

```text
Can I upload it?
```

### Question 2

```text
Will the web server execute it as PHP?
```

---

# 23. `.phtml` Example

The module uses:

```text
.phtml
```

because some PHP web-server configurations recognize it as a PHP-enabled extension.

So the testing flow is:

```text
.phtml
   ↓
Backend blacklist
   ↓
Not listed
   ↓
Upload succeeds?
   ↓
Web server configuration
   ↓
Does PHP execute?
```

### Important

`.phtml` **does not universally execute PHP**.

It depends on the server configuration.

---

# 24. Sending the Request to Repeater

Once a promising extension is identified, the module demonstrates:

```text
Intruder Results
      ↓
Right-click request
      ↓
Send to Repeater
```

Repeater allows us to manually modify and resend the request.

This is useful when we want precise control over:

- Filename
    
- Extension
    
- Content
    
- Headers
    
- Other request parameters
    

---

# 25. Testing the Uploaded File

The exercise changes the filename to use the discovered extension and uses the PHP shell content from the previous section.

For example:

```text
shell.phtml
```

If the upload succeeds, the next question is whether the web server executes the file as PHP.

The module then accesses the uploaded file through:

```text
/profile_images/shell.phtml
```

and tests command execution.

---

# 🔥 26. The Complete Blacklist Bypass Chain

Memorize this workflow:

```text
        Upload PHP
            ↓
      ❌ Blocked
            ↓
    Identify blacklist
            ↓
    Fuzz extensions
            ↓
  Find non-blacklisted type
            ↓
      Upload succeeds
            ↓
 Does server execute that type?
        ↙           ↘
      YES            NO
       ↓              ↓
 Potential RCE     Try another
```

This is the heart of the section.

---

# 🧠 27. Important Distinction: Upload ≠ Execution

This is **extremely important for exams/labs**.

Finding:

```text
Extension accepted
```

does **not** automatically mean:

```text
Remote Code Execution
```

There are separate stages:

```text
1. Extension accepted
        ↓
2. File successfully stored
        ↓
3. File is accessible
        ↓
4. Server interprets the file
        ↓
5. Code executes
```

You need to establish each stage.

---

# 🆚 28. Blacklist vs Whitelist

|Property|Blacklist|Whitelist|
|---|---|---|
|Strategy|Block known bad|Allow known good|
|Default behavior|Usually allow unknown|Reject unknown|
|New extension|May bypass|Rejected|
|Maintenance|Difficult|Easier|
|Security|Weaker when used alone|Generally stronger|
|Example|Block `.php`|Allow `.jpg/.png`|

### Memory trick:

**Blacklist = "Everything except these."**

**Whitelist = "Only these."**

---

# 🛡️ 29. Why Blacklists Fail

A blacklist can fail because:

### ① Missing extensions

Developer blocks:

```text
php
php7
phps
```

but misses another PHP-associated extension.

### ② Case sensitivity

The comparison may treat:

```text
php
pHp
PHP
```

differently.

### ③ Server-specific behavior

Different web servers/configurations may interpret different extensions.

### ④ Configuration changes

An extension that doesn't execute today might execute after a server configuration change.

### ⑤ Filename parsing differences

Different layers may interpret filenames differently.

---

# 🔬 30. What Should Secure Applications Do?

A secure application shouldn't rely solely on:

```text
Extension blacklist
```

Instead, it should use **defense in depth**.

A secure upload pipeline can look like:

```text
Upload
  ↓
Authentication/Authorization
  ↓
Allowlisted file type
  ↓
Validate actual file content
  ↓
Validate MIME/type information
  ↓
Safe filename generation
  ↓
Store outside executable web root
  ↓
Disable script execution
  ↓
Size/resource limits
  ↓
Optional malware scanning
```

The strongest design doesn't assume that a filename extension is trustworthy.

---

# 📌 31. Important Terms

### **Blacklist**

A list of explicitly prohibited values.

### **Whitelist**

A list of explicitly permitted values.

### **Extension**

The portion after the final `.` in a filename.

Example:

```text
shell.php
      ↑
  extension
```

### **Fuzzing**

Automatically testing many inputs to discover unexpected behavior.

### **Burp Intruder**

Burp functionality used to automate requests with different payloads.

### **Burp Repeater**

Burp functionality used to manually modify and resend individual requests.

### **Content-Length**

An HTTP header indicating the size of the request/response body, depending on context. In this exercise, response-length differences help distinguish successful and rejected uploads.

---

# ⭐ 32. Things You MUST Remember

> 🔴 **Backend validation is necessary because client-side controls can be manipulated.**

> 🔴 **A blacklist blocks known extensions rather than explicitly allowing safe ones.**

> 🔴 **Blacklist validation is weaker when it is incomplete.**

> 🔴 The example blacklist contains `php`, `php7`, and `phps`.

> 🔴 `pathinfo(..., PATHINFO_EXTENSION)` extracts the extension.

> 🔴 `in_array()` checks whether the extracted extension appears in the blacklist.

> 🔴 The example comparison is case-sensitive.

> 🔴 On systems such as Windows, filename case-insensitivity can make case-related blacklist mistakes particularly relevant.

> 🔴 **Fuzzing** can identify extensions that aren't rejected.

> 🔴 PayloadsAllTheThings and SecLists provide useful extension wordlists.

> 🔴 Burp **Intruder** can automate extension fuzzing.

> 🔴 Response differences such as **"File successfully uploaded"** vs **"Extension not allowed"** help identify promising extensions.

> 🔴 **An accepted extension doesn't automatically mean code execution.**

> 🔴 Whether an extension executes depends on the web-server/PHP configuration.

> 🔴 `.phtml` is one example of an extension that may be interpreted as PHP in some configurations.

> 🔴 A strong upload defense should prefer **allowlisting + content validation + safe storage + disabling execution** rather than relying on a blacklist alone.

---

# 📝 33. Exam/Interview Style Questions

### Q1. What is a blacklist?

A blacklist is a list of file types or extensions that the application explicitly blocks.

### Q2. Why is a blacklist weak?

Because it must comprehensively identify every dangerous extension. Any omitted executable extension may potentially bypass the filter.

### Q3. What is the difference between a blacklist and whitelist?

A blacklist says:

> **"These are forbidden."**

A whitelist says:

> **"Only these are permitted."**

### Q4. What does this do?

```php
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
```

It extracts the file extension.

### Q5. What does this do?

```php
in_array($extension, $blacklist)
```

It checks whether the extracted extension exists in the blacklist.

### Q6. Why use Intruder?

To automatically test a large number of possible file extensions rather than testing them manually.

### Q7. Why use Repeater?

To manually modify and resend a promising request.

### Q8. Does an upload succeeding prove RCE?

**No.**

The server must also interpret the uploaded file as executable code.

---

# 🧠 Ultra-Short Revision

```text
CLIENT-SIDE
     ↓
Bypass with request modification
     ↓
BACKEND BLACKLIST
     ↓
PHP blocked
     ↓
FUZZ EXTENSIONS
     ↓
Find non-blacklisted extension
     ↓
Test whether upload succeeds
     ↓
Test whether server interprets it
     ↓
Potential code execution
```

### The one sentence to remember:

> **A blacklist asks "Is this extension forbidden?", while a whitelist asks "Is this extension explicitly allowed?" — which is why blacklists can be bypassed when they are incomplete.**