Absolutely bro. I’ll keep the **important technical concepts, code, terminology, examples, and attack logic intact**, while organizing everything into clean study notes. I’ll also add visual references where they actually help.

# 📚 File Upload Attacks — Detailed Notes

> **Scope:** These notes are based on the material you provided and are structured for learning/authorized lab environments such as HTB.

---

# 1. What Is a File Upload Vulnerability?

Modern web applications frequently allow users to upload files:

- Profile pictures
    
- PDFs
    
- Documents
    
- Employee files
    
- Videos
    
- Attachments
    
- Other user-generated content
    

The danger occurs when the application **does not properly validate uploaded files**.

If an attacker can upload a file that the server interprets as executable code, they may potentially achieve:

> **File Upload → Code Execution → Remote Command Execution → Server Compromise**

The most dangerous scenario is:

### `Unauthenticated Arbitrary File Upload`

This means:

- No authentication is required.
    
- Any file type can be uploaded.
    
- The uploaded file is stored somewhere accessible.
    
- The server executes the uploaded file.
    

This can potentially lead to complete compromise of the backend server.

---

# 2. Types of File Upload Attacks

The major categories covered in this module are:

|Attack|Main weakness|
|---|---|
|**Absent Validation**|No upload validation|
|**Client-Side Validation**|Validation only happens in browser|
|**Blacklist Filters**|Blocks known bad extensions|
|**Whitelist Filters**|Allows specific extensions but implementation is weak|
|**Type Filters**|Validates Content-Type/MIME type|
|**Web Shell**|Uploaded script provides command execution|
|**Reverse Shell**|Server connects back to attacker|
|**Double Extensions**|Exploits weak extension matching|
|**Character Injection**|Exploits filename parsing inconsistencies|

A key principle:

> **Never assume that because an application blocks one extension, the upload functionality is secure.**

---

# 3. Absent Validation

## Definition

The simplest file upload vulnerability occurs when:

> **The web application does not have any form of validation filters on uploaded files.**

Therefore, the application may accept:

```text
.jpg
.png
.pdf
.php
.phtml
.aspx
.jsp
```

and potentially other executable file types.

If the uploaded file is stored in a web-accessible directory and the server executes that file, this can lead to **Remote Code Execution (RCE)**.

---

## Attack Flow

![Image](https://images.openai.com/static-rsc-4/r0gUmMUXpUmMcFxoK3QPZTEAqLzurTPh6fVETBJfTG0MAoF4589RyI8NpQzhSvCnm37MvkoEW-xhqBQxj0IuraflbJhz6ShyGawCqn-T0lALsPLdYmZ0GNJOHL81d4C6crbYdVmLFOVQPZM0xp4TGB56oflUYypQOwU0PJ-JTyeGl09KmjFZabMSYWCcyPC2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/v2VzHcZNwnAUbPK4WRJJraSv8Gec_zGOwFAYORIQNSUy1QPkk0NfwuSvjfCBHwBSm-c43k3p-MIVtXUzBWns8f-0EMYjQK15ipGjbDxYkJmZG-J01i0pESvZXAJ_B0Jds8gAwXRw55tfYsf0OyoQryrYuH3Z037bc8qMVutzOa768_2ODbN7Fr-ITsNxnCqB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dvN_xgSVXEUstAwKv6KAvmAdBnyOi6yqfsEtj7OmWn6uwb0SnIrdhVx1TyYze5p9RQbPu4AKE4M8Him1LANRHl1NPDqfPEHYhLvy69PVUxG9azUbRtSq75uKxBm1zbuuPEx3CSZCxjwXxpN1jTtrNutmK6D-LUS0I0Fp3in8fqKXSsWRnZaeJs7beYo9oAfZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/z0ozfc657ze3czEhkMmFpztIgdOXu04TzKegBnvbxEmErdp8wSpFw4QRBXeJX489IWZZGctsPH7x5Bc85D3DMIHtd1K7nTU1M4ScivlrGNrPX1zdT-GToMUPQLFS0IcrjHoZkdLSPVkh72OhMMkmHTV5hA25x6GEwVxf9gVGZulQDpx25Ls1FXYy0vZqWuLc?purpose=fullsize)

Conceptually:

```text
Attacker
   │
   │ Upload malicious file
   ▼
Web Application
   │
   │ No validation
   ▼
Backend Server
   │
   │ Stores executable file
   ▼
Uploaded File
   │
   │ Attacker visits file
   ▼
Code Execution
   │
   ▼
Server Access
```

---

# 4. Arbitrary File Upload

An application may have an upload interface such as:

```text
Employee File Manager

[ Drag & Drop File ]

[ Upload ]
```

If the application does not specify allowed extensions and accepts something like:

```text
shell.php
```

that is an important observation.

### Front-end clues

Things that may suggest missing restrictions:

- File selector says **All Files**
    
- `.php` files can be selected
    
- No client-side error occurs
    
- Upload succeeds
    
- No restrictions are mentioned
    

However:

> **Front-end behavior alone does NOT prove that the backend is vulnerable.**

The backend must also be tested.

---

# 5. Identifying the Web Framework

Before attempting to execute an uploaded script, we need to determine:

> **What programming language/framework is running the web application?**

This matters because a PHP web shell will not normally execute on an ASP.NET application.

For example:

|Application|Potential server-side language|
|---|---|
|`.php`|PHP|
|`.asp`|ASP|
|`.aspx`|ASP.NET|
|`.jsp`|Java/JSP|

---

## Method 1 — URL Extension Testing

Try common index extensions:

```text
/index.php
/index.asp
/index.aspx
/index.jsp
```

For example:

```text
http://SERVER_IP:PORT/index.php
```

If it displays the same page, that is evidence the application is using PHP.

### Important limitation

This method isn't always reliable because modern applications frequently use:

- Web routes
    
- MVC frameworks
    
- URL rewriting
    
- Extensionless URLs
    

Therefore:

```text
/
```

doesn't necessarily reveal the underlying language.

---

# 6. Technology Fingerprinting

Another approach is technology fingerprinting.

Tools such as **Wappalyzer** can identify technologies used by a website.

![Image](https://images.openai.com/static-rsc-4/PzdKb8W-giFKil_Yz2P-e1QK8Xhed_1T_JDVUrhZxcoMS6V2X_LCLje2FWfesGD9wCfxRXRfGpVa-C3E1y6n5dNIle6flyEUQO0mSsp-we5eGmz0Rr01QOO0QOMzNptpticuh_zPL7CJe8yRz2mEtpUHcaxp2HSY2FH6ibnrJhieMRa7UpuHpeOhrd5iKR3y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/h_gtX_c17o0ktr_n4q9lh733m30AtVBcJvZO3YQThsMvZNEYGCORDflcKIH0ermM_dQ2wVexNLyBZZgTLFdcvP6T88cFlCZ8fvwvYEcNaO3M18EnUtN-OCU3U4XQKqcA-4oUYjsCxjW1A9eJisRuF851iM2LPITTyIbum5S-NQjKTAkg22bDR62ybRVWqZi3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QFS4GVwo4Kkh_xE54n_1S32l1oAPsWul61BHWS8h4giRges_e9gmqLzUQb0AxtgUuf8aUB8P7gVuCZf9dtbQD416mlj-W9spEgiPpEL_cjuIYyGX2JpWmt0RZW-qzOcp3maorHhxrJ84VrYLE2jbX8QqFUSd8XOD6-6GoJpQHQjocQUOu8zJ7PyjiyPDeX1x?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZyJG-P02aXJlGnNG7JV8sOk4AiZ-VXun4no8RIu22_P2iQy2q9ryaVRMgw1Kp79EaUuzbm1XlGf9V8pMecK1iILBtk-9hxmsrzceszxHTuMUquaevbEzOflbCq7xeZ15O02DFoRHrZAExKBo-RHMHypuIbWu2bWmRETcxg-i9gkFEap4YaaSD4ejSot_1U6b?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PkoUcs48L6_5OaIFP12-cr0GXhqb4Z_9IPjOen46GJgRDQL-YgElCdpcch_Xq-jvejhz601T-Wt55eYbwKTsUZsK7tNjYmx834nALJ4PCuWBV3ckHogLVeHByLnHzj7tEm17fU58CR3iGDSLslBOQQ-bh3oG5wgW05eT41nybnuTniGYzzeWeajhSjV6rIju?purpose=fullsize)

It may reveal things such as:

```text
Apache
PHP
Ubuntu
jQuery
cdnjs
```

This can provide information about:

- Web server
    
- Programming language
    
- Operating system
    
- JavaScript libraries
    
- Frameworks
    
- Versions
    

### Other approaches

You can also use:

- Burp Scanner
    
- OWASP ZAP
    
- Web vulnerability scanners
    
- HTTP headers
    
- Error messages
    
- Source code
    
- Manual endpoint testing
    

---

# 7. Vulnerability Identification

Once we determine that the application uses PHP, we can perform a **safe execution test** in an authorized lab.

Instead of immediately uploading a full web shell, first use a simple test script.

Example:

```php
<?php echo "Hello HTB";?>
```

Save it as:

```text
test.php
```

Then upload it.

If the application reports:

```text
File successfully uploaded
```

and provides a link such as:

```text
/uploads/test.php
```

visit it.

If the browser displays:

```text
Hello HTB
```

then PHP code was executed.

---

## Why This Matters

If the server simply displayed the PHP source:

```php
<?php echo "Hello HTB";?>
```

then PHP execution did **not** occur.

But if it displays:

```text
Hello HTB
```

the PHP interpreter executed the code.

Therefore:

> **Successful upload + successful execution = highly significant vulnerability.**

---

# 8. Upload Exploitation

Once arbitrary executable files can be uploaded, the next step in a lab is generally to determine whether code execution can be obtained.

Two common concepts are:

### Web Shell

Provides command execution through HTTP.

### Reverse Shell

Causes the target server to establish a shell connection back to the tester.

---

# 9. Web Shells

A **web shell** is a server-side script that accepts commands through a web request and executes them.

Conceptually:

```text
Browser
   │
   │ HTTP request containing command
   ▼
Web Shell
   │
   │ Executes command
   ▼
Operating System
   │
   │ Command output
   ▼
Browser
```

![Image](https://images.openai.com/static-rsc-4/v2VzHcZNwnAUbPK4WRJJraSv8Gec_zGOwFAYORIQNSUy1QPkk0NfwuSvjfCBHwBSm-c43k3p-MIVtXUzBWns8f-0EMYjQK15ipGjbDxYkJmZG-J01i0pESvZXAJ_B0Jds8gAwXRw55tfYsf0OyoQryrYuH3Z037bc8qMVutzOa768_2ODbN7Fr-ITsNxnCqB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dvN_xgSVXEUstAwKv6KAvmAdBnyOi6yqfsEtj7OmWn6uwb0SnIrdhVx1TyYze5p9RQbPu4AKE4M8Him1LANRHl1NPDqfPEHYhLvy69PVUxG9azUbRtSq75uKxBm1zbuuPEx3CSZCxjwXxpN1jTtrNutmK6D-LUS0I0Fp3in8fqKXSsWRnZaeJs7beYo9oAfZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BZSDJfz3wUsq1rn8qMcjmGokdXYVqCeDoxnez9BAaIA_h0uwRwfFPwAXxx2Oz06n0Ffe_PwQIO5od6hnFA9EE_Z3L77G8k8L9QmAzo3JGFB0A85ZfzeO2E1CARaA1FlgzIqjHm5XrMiSI8PNksiJgyBCDZlfGOpVHObR42fwKgoH90jYVvk-FURDlugfPU-F?purpose=fullsize)

A PHP web shell must be written for a PHP environment because it relies on PHP functions.

---

# 10. phpBash

A commonly referenced PHP web shell is **phpbash**.

It provides a terminal-like interface and can make enumeration easier.

The important concept is:

```text
Upload web shell
       ↓
Visit uploaded file
       ↓
Web shell executes
       ↓
Interact with backend
```

The provided material also references **SecLists Web-Shells**, which contains shells for different languages/frameworks.

---

# 11. Custom PHP Web Shell

A very basic PHP command execution example is:

```php
<?php system($_REQUEST['cmd']); ?>
```

The idea is:

```text
shell.php?cmd=id
```

The application receives:

```text
cmd=id
```

and passes the value to:

```php
system()
```

The resulting output is displayed in the HTTP response.

For example, in a lab:

```text
?cmd=id
```

could return information such as:

```text
uid=33(www-data)
gid=33(www-data)
groups=33(www-data)
```

This demonstrates command execution under the privileges of the web-server account.

---

# 12. Important Web Shell Limitation

A web shell may fail even when the upload succeeds.

Possible reasons include:

- Server disables dangerous functions
    
- Web Application Firewall
    
- PHP configuration restrictions
    
- Permission restrictions
    
- Security modules
    
- Different server architecture
    

Therefore:

> **Successful file upload does not automatically mean successful command execution.**

---

# 13. Reverse Shell

A reverse shell differs from a web shell.

### Web Shell

```text
Attacker → HTTP → Target
                  ↓
              Command
                  ↓
               Output
```

### Reverse Shell

```text
Attacker ← Connection ← Target
     ↑
  Listener
```

The target initiates a connection back to the tester.

![Image](https://images.openai.com/static-rsc-4/zfL38ZAMHbofkLPppNt68tlSNnFLbBY6LtocjbCjNgjvd1d4hg0DrJVPrYXUyv3KNs2iujgIqZlkJXKOu0IrAkhSe8DEd-7l05gadA3c0W1MIVQ4E-V1JTcXJh_xd2RcfKKBkYBDsUoKdv0bprdAlTe3rjxccynsZiPnRrODT7nmp6wq9OzUVWJ4huSKe0OI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/YyTUbv_6Aux-ItpcfJJfqRK_boYOGj7FVVAzUj-3dSmveDyH9wKQi2lKHnH8yYnVXbOEktwfR66cWHJmz3Xa4RK5x--wWbtwnD8rozVtbD0BbYHTM7Igs5TGRAIo7L8sYkX5_t_gc4O9m7oEOYtTDjG7V4AlLNXPNPTpyw8OqPFSfobiqxpM5B8lCplac_Si?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/M3LPGM7Kg_JQEkeGqeiaJIeIfudyJvqn8rg01OiDPiimbH_5bTwwMA9veVWNmRgGbhpuzq540bgqFq41yZNPmftsyScS-Iy4cyP7Ow-_TNydLl0euxkMRO_pCfdb20BbqvN681KKf_YvK6N8ONvnwReu0asfPDmUkRKTmrSf1ZHhfvwQbx06o-zWyquHLTmd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hqqyEy8S5VMr6r6ggfpEq1-TLxcA-BaOirt5cZTSDVM8SOM5VIC8HROVErft1D0mi2IzUSjbZ8jjQSh1KtBvGgyF0g7vEh7HtJMQl_BoMl268DzA35rnmOXIemSfIR_u6XqV_o9v7POLNJ9rOE0IAn_Yjsgn2U-DJfGRQbpbQToRwHwzBEd3qIru2bqFcFa6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NQ3z_CE3eL80BJC5eO2nE_LuW_bK1iDQj1vq99T3-SpzlFMEULQBKg_Qgl8hsmVB9T3FNJ6MDhgRItbjN4PNF3NSqnljm6mRTS26KN7JSWpOyO9kaCUBGPodZri9_Q9vInLdzRra1aTIW9KDKcuAwFp_QDDboxfCUdFDE0kn4wCPwNtMbisGLOmFlP5r4qRg?purpose=fullsize)

This usually provides a more interactive shell.

---

# 14. Reverse Shell Requirements

In an authorized lab, conceptually you need:

1. A reverse-shell payload appropriate for the target language.
    
2. Your reachable listener address.
    
3. A listening port.
    
4. The uploaded script to execute.
    
5. Network connectivity from target → listener.
    

The supplied example uses a PHP reverse-shell script where the connection settings are configured as:

```php
$ip = 'OUR_IP';
$port = OUR_PORT;
```

Then a listener receives the connection.

---

# 15. Web Shell vs Reverse Shell

|Feature|Web Shell|Reverse Shell|
|---|---|---|
|Interaction|HTTP-based|Direct shell|
|Convenience|Easy|More setup|
|Interactivity|Limited|Usually better|
|Firewall dependency|HTTP access|Outbound connection required|
|Useful for enumeration|Yes|Yes|
|May fail because of|Disabled functions/WAF|Firewall/network restrictions|

### Key takeaway

> **Reverse shells are generally more interactive, but web shells can work when outbound connections are blocked.**

---

# 16. Generating Reverse Shells

Tools such as `msfvenom` can generate payloads for different languages.

The supplied example uses:

```text
-p php/reverse_php
```

and specifies:

```text
LHOST
LPORT
```

with:

```text
-f raw
```

to control the output format.

General concept:

```text
Payload
  ↓
Language-specific reverse shell
  ↓
Generated file
  ↓
Upload
  ↓
Execute
  ↓
Listener receives connection
```

---

# 17. Client-Side Validation

Now we move to a very important concept.

Some applications validate files **only inside the browser**.

For example:

```text
Allowed:
.jpg
.jpeg
.png
```

JavaScript may prevent the user from selecting or uploading:

```text
shell.php
```

But:

> **Client-side security controls cannot be trusted as the primary security boundary.**

Why?

Because the client is controlled by the user.

---

# 18. Client-Side vs Back-End Validation

|Client-side|Back-end|
|---|---|
|Runs in browser|Runs on server|
|User controls environment|Server controls environment|
|Can be modified|Cannot be directly modified|
|Easy to bypass|Stronger security boundary|
|Useful for UX|Essential for security|

Therefore:

> **All security-sensitive file validation must happen on the backend.**

---

# 19. Identifying Client-Side Validation

Suppose selecting:

```text
shell.php
```

immediately produces:

```text
Only images are allowed!
```

and:

```text
Upload
```

becomes disabled.

If **no HTTP request is generated**, this is a strong indication that validation is happening locally.

The browser is making the decision before communicating with the server.

---

# 20. HTML `accept` Attribute

A file input might contain:

```html
<input type="file"
       name="uploadFile"
       id="uploadFile"
       onchange="checkFile(this)"
       accept=".jpg,.jpeg,.png">
```

The:

```html
accept=".jpg,.jpeg,.png"
```

attribute influences what the browser's file picker presents.

But it is **not a security mechanism**.

The interesting part is:

```html
onchange="checkFile(this)"
```

This invokes JavaScript when the selected file changes.

---

# 21. JavaScript Validation

A validation function may look conceptually like:

```javascript
function checkFile(File) {
    ...
    if (extension !== 'jpg' &&
        extension !== 'jpeg' &&
        extension !== 'png') {

        $('#error_message').text("Only images are allowed!");
        File.form.reset();
        $("#submit").attr("disabled", true);
    }
}
```

The browser checks the extension and rejects the file.

Because this occurs client-side, the tester can inspect how the application performs the check.

---

# 22. Burp Request Modification

Another approach is to observe the legitimate upload request.

A normal upload might contain:

```http
POST /upload.php HTTP/1.1
...
Content-Type: multipart/form-data; boundary=...
```

Inside the multipart body:

```text
filename="HTB.png"
Content-Type: image/png
```

The important components include:

```text
filename
file contents
Content-Type
```

In an authorized lab, intercepting and modifying the request allows you to determine whether the backend independently validates the file.

### Key question

> **Does the server trust the browser's validation, or does it perform its own validation?**

If the server accepts a malicious file after client-side controls are bypassed, the backend validation is insufficient.

---

# 23. Disabling Front-End Validation

The browser's developer tools can also reveal the validation logic.

For example:

```text
CTRL + SHIFT + C
```

opens the element inspector in Firefox.

You may discover:

```html
onchange="checkFile(this)"
```

Then the console can be used to inspect the function.

In the provided example:

```text
CTRL + SHIFT + K
```

opens the Firefox console.

The function can then be inspected to understand how the validation works.

---

# 24. Temporary Nature of Client-Side Changes

An important point:

> **Changes made through browser developer tools are temporary.**

Refreshing the page generally restores the original source.

That doesn't matter for the test because the goal is to determine whether the server performs its own validation.

---

# 25. Blacklist Filters

A blacklist works by defining extensions that are **not allowed**.

Example:

```php
$blacklist = array('php', 'php7', 'phps');
```

The application extracts the extension:

```php
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
```

and checks:

```php
if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

---

# 26. Why Blacklists Are Weak

The fundamental problem:

> **A blacklist has to anticipate every dangerous extension.**

If the developer blocks:

```text
.php
.php7
.phps
```

there may still be other server-supported executable extensions.

Therefore:

```text
Blacklist
   ↓
Known bad extensions
   ↓
Unknown executable extension
   ↓
Potential bypass
```

---

# 27. Case Sensitivity

The supplied example also highlights an important weakness:

```php
in_array($extension, $blacklist)
```

may perform a case-sensitive comparison.

Therefore, depending on the operating system and server configuration, variations in capitalization can sometimes matter.

Example concept:

```text
php
pHp
PHP
PhP
```

### Important

Whether capitalization actually bypasses a filter depends on:

- Application implementation
    
- Operating system
    
- Web server
    
- PHP configuration
    

So it must be tested rather than assumed.

---

# 28. Extension Fuzzing

When dealing with an unknown blacklist, testing one extension at a time is inefficient.

Instead, use an extension wordlist.

Useful resources referenced in the material include:

- PayloadsAllTheThings
    
- SecLists Web Extensions
    

The goal is to determine:

```text
Which extensions → blocked?
Which extensions → accepted?
Which accepted extensions → executed?
```

---

# 29. Burp Intruder Concept

The request might contain:

```text
filename="HTB.php"
```

The extension can be selected as the fuzzing position:

```text
HTB.§php§
```

Then the wordlist supplies different extensions.

Conceptually:

```text
.php
.php5
.php7
.phtml
.phar
.phps
...
```

The responses can then be compared.

---

# 30. Response Analysis

Suppose blocked requests return:

```text
Extension not allowed
```

while successful ones return:

```text
File successfully uploaded
```

You can identify potentially interesting extensions by comparing:

- HTTP status
    
- Response length
    
- Response body
    
- Error messages
    
- Upload behavior
    

### Important

An extension being accepted **does not automatically mean it executes code**.

You need to verify execution separately.

---

# 31. Non-Blacklisted Extensions

One potentially interesting extension in PHP environments is:

```text
.phtml
```

Depending on server configuration, `.phtml` may be treated as executable PHP.

Therefore the testing process becomes:

```text
Find accepted extension
        ↓
Upload test file
        ↓
Visit uploaded file
        ↓
Determine whether PHP executes
```

This distinction is extremely important:

> **Uploadable ≠ executable**

---

# 32. Whitelist Filters

A whitelist is the opposite approach.

Instead of saying:

> "Block these extensions."

the application says:

> "Only allow these extensions."

For example:

```text
.jpg
.jpeg
.png
.gif
```

### Why whitelists are generally stronger

A whitelist doesn't need to know every malicious extension.

It only needs to allow the formats the application actually requires.

---

# 33. Blacklist vs Whitelist

|Blacklist|Whitelist|
|---|---|
|Blocks known bad|Allows known good|
|Must cover dangerous cases|Smaller allowed set|
|Easier to bypass if incomplete|Generally stronger|
|Useful for broad file managers|Good for restricted upload features|

### Best practice

For an application that only needs profile pictures:

```text
Allow:
JPEG
PNG
WebP
```

rather than attempting to block hundreds of dangerous extensions.

---

# 34. Weak Whitelist Regex

A vulnerable whitelist may use:

```php
if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

The problem is:

> **The regex checks whether the filename contains an allowed extension, rather than ensuring that the filename ends with the allowed extension.**

---

# 35. Double Extensions

This creates the classic:

```text
shell.jpg.php
```

scenario.

The filename contains:

```text
.jpg
```

so a weak whitelist may accept it.

But the filename ultimately ends with:

```text
.php
```

If the server executes PHP based on the final extension, this can potentially lead to code execution.

Conceptually:

```text
Weak whitelist
       ↓
Contains .jpg?
       ↓
YES
       ↓
Upload accepted
       ↓
Server sees .php
       ↓
Potential PHP execution
```

---

# 36. Strict Regex

A stronger regex would be:

```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    ...
}
```

Notice the:

```text
$
```

at the end.

`$` means the match must reach the **end of the string**.

Therefore:

```text
shell.jpg.php
```

would not satisfy the pattern.

### Key lesson

> **Regex anchoring matters enormously in security validation.**

---

# 37. Reverse Double Extension

There is another interesting scenario where the upload validation may be secure but the **web server configuration is insecure**.

For example, a server configuration may use:

```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

This tells Apache to execute files containing:

```text
.phar
.php
.phtml
```

But notice there is no:

```text
$
```

at the end.

Therefore, the matching logic can potentially apply to filenames containing the executable extension rather than only filenames ending with it.

---

# 38. Reverse Double Extension Example

Consider:

```text
shell.php.jpg
```

The application whitelist might see:

```text
.jpg
```

and accept it.

Meanwhile, an incorrectly configured Apache rule might see:

```text
.php
```

and execute the file as PHP.

Thus:

```text
Application
    ↓
Sees .jpg
    ↓
Accepts

Web Server
    ↓
Sees .php
    ↓
Executes
```

This is why:

> **Application security and server configuration must both be secure.**

---

# 39. Character Injection

Another class of bypass involves inserting special characters into filenames.

The provided material lists:

```text
%20
%0a
%00
%0d0a
/
.\
.
…
:
```

Different characters may behave differently depending on:

- PHP version
    
- Web server
    
- Operating system
    
- URL parsing
    
- Filename normalization
    
- Application implementation
    

---

# 40. Null Byte Injection

Historically, older PHP environments could be affected by:

```text
%00
```

For example:

```text
shell.php%00.jpg
```

could be interpreted differently by different components.

Historically, some systems could treat the filename as ending at the null byte:

```text
shell.php
```

while another validation layer saw:

```text
shell.php.jpg
```

This is mainly relevant to **legacy/outdated environments**.

Modern systems generally mitigate classic null-byte filename attacks.

---

# 41. Character-Injection Fuzzing

The material demonstrates generating filename permutations.

The idea is to test combinations around:

```text
.php
.phps
.jpg
```

with special characters inserted before or after extensions.

The important security-testing concept is:

> **Different components may parse the same filename differently.**

---

# 42. Type Filters

Extension validation alone isn't enough.

For example:

```text
shell.php.jpg
```

might pass an extension whitelist.

Additionally, some formats such as SVG can introduce other risks.

Therefore modern applications may inspect the **actual file type/content**.

Two major mechanisms are:

### 1. Content-Type Header

Based on the HTTP upload request.

### 2. MIME Type / File Signature

Based on the actual file bytes.

---

# 43. Content-Type Header

An upload request may contain:

```text
Content-Type: image/png
```

The application might use something similar to:

```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type,
    array(
        'image/jpg',
        'image/jpeg',
        'image/png',
        'image/gif'
    ))) {

    echo "Only images are allowed";
    die();
}
```

The application is trusting the declared Content-Type.

---

# 44. Why Content-Type Can Be Manipulated

The browser constructs the upload request.

Therefore, in an authorized security test, the request can be intercepted and inspected.

For example:

```text
filename="shell.php"
Content-Type: image/jpg

<file contents>
```

If the server trusts only the declared Content-Type, it may incorrectly treat the uploaded file as an image.

### Key lesson

> **HTTP Content-Type is metadata supplied by the client; it is not proof of the actual file contents.**

---

# 45. Two Content-Type Headers

Multipart uploads can contain different Content-Type information.

For example:

```text
Main HTTP request:
Content-Type: multipart/form-data
```

and inside the multipart section:

```text
Content-Type: image/png
```

The second one describes the uploaded file.

### Important distinction

```text
HTTP Content-Type
        ↓
Entire request

Multipart Content-Type
        ↓
Individual uploaded file
```

Which one matters depends on how the application processes the upload.

---

# 46. MIME Type

MIME detection is stronger because it can inspect the actual file.

A common concept is:

> **Magic bytes / File signature**

Many file formats have characteristic bytes at the beginning of the file.

Examples:

```text
GIF87a
GIF89a
```

identify GIF files.

---

# 47. Magic Bytes

![Image](https://images.openai.com/static-rsc-4/izjxtiGw3O1dYmUjAQ6OBwj-bR1QgjiKDR9_a_6DvI0zXDg5lgdedRnJkkj0ViLfGRyYJs5Q-DFJ511pwQaH_Lh2G0F_D0IPeMRl4J8AGdjSAJEHg6FKpe37Ayf49_3T_xExCcuaXi8lQg08PuUTvurpskwMP3AC4j7u_ex6EGCW8L12SjHpP8cjKy0NwkTW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hOPsKmtvqKsPS5tun9b5koKqkvx8q7gVcDUH0ugJNCOWZO-wZjhLO927YNbmWLqLnEjKnYzYiu4xlI_w1AE41Y2pOcrK2Bip6KbrNeDhAmV7Z2_iXFKSy6QtWotMJtr3EhpKOr2sindh8ukqOjbfV65HGwFiW-wYY0px2EaIuMFBtOy36GfC2BZIsL9MdXsK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ilVZ8G_9J03HRba-7BvkMew5lNgKrt2SGLNH9HpkQeMjfYCJreijILhShV8cd6P2PRyalTs2BsSvGpds0fgZPC6loNPNo8Oi_w9Ixs_mAaM-FbWsse33v1BY-69kuTD938en2gacBlVSbbspysTVfV0MKlHxQRiC5jimPTfyO2aw_mDXCuDZyHcN6Wqwbty8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/z_zbTO9P732dgPduGfED32lQJnq8NuwIw-2efYy5Ml4eVFOCkfGxXsWcFD60wHuiLLn6Un5YKpwL1-xb68ypEr-AmWRnmgAt0M_qd3MfcLdZlraOhWwAvNxg4Qct6EWiPbBc3r2nVNJDlO70jGSYk6Xv7wcpiMc9NQIyJGPN489zxyma50MDH0s6yKaXDHAb?purpose=fullsize)

A file's extension does not necessarily determine its real type.

For example:

```bash
echo "this is a text file" > text.jpg
```

The extension says:

```text
.jpg
```

but the contents are plain text.

A file-identification utility may therefore report:

```text
ASCII text
```

rather than JPEG.

---

# 48. MIME Detection in PHP

PHP can inspect a file's MIME type with:

```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);
```

The application could then check:

```php
if (!in_array($type,
    array(
        'image/jpg',
        'image/jpeg',
        'image/png',
        'image/gif'
    ))) {

    echo "Only images are allowed";
    die();
}
```

Here the server is determining the type from the file itself rather than trusting only the filename.

---

# 49. GIF Magic Bytes Concept

The provided material demonstrates that a file beginning with:

```text
GIF8
```

can be recognized by simple file-type detection as GIF-like content.

This illustrates an important security principle:

> **MIME detection based only on a small signature can still be weaker than actually decoding and validating the file.**

A robust application should not assume that matching a magic byte sequence proves that the entire file is a valid, safe image.

---

# 50. Content-Type vs MIME Type

|Property|Content-Type Header|MIME/File Detection|
|---|---|---|
|Source|Client request|File contents|
|Controlled by client|Yes|Much less directly|
|Based on|Declared type|Bytes/signature/content|
|Reliability|Lower|Generally higher|
|Can be manipulated|Easily|Requires content manipulation|
|Best used alone?|❌|❌|

Neither should be considered sufficient by itself for high-security upload validation.

---

# 51. Combining Filters

Real applications may use multiple checks:

```text
Filename extension
       +
Content-Type
       +
MIME type
       +
File structure
       +
Image decoding
```

An attacker may therefore encounter several independent validation layers.

Conceptually:

```text
                 Upload
                    │
          ┌─────────▼─────────┐
          │ Extension Check   │
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │ Content-Type      │
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │ MIME Detection    │
          └─────────┬─────────┘
                    │
          ┌─────────▼─────────┐
          │ File Validation   │
          └─────────┬─────────┘
                    │
                  Store
```

---

# 52. Complete Attack Methodology

The entire module can be remembered as a progression:

![Image](https://images.openai.com/static-rsc-4/qeOzxhRmZqucFjY-n8BtrED7AYKWbu7XAGtGKTK-8jXFN07AZhRI3fsFhvoNaeYm6njsPba0HZN1tfq24GBkx9szEvXXvYLi4O9CjQbSUEGeEvFcEwF1djXS4aLfzqhijpmHfUv3SbICOxU1yMbRlDi8ZRikDFtXROGLPtVL42lVpClz0iYoYVLHpjLjX9vR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VH0vazS5s-Bs78LDGKpre9fKd_JK-epVR0rAVgEhWCyBAKxnUz_0-hgYPwjjiMtF0MCngkoVe2GzOVZWxyt0mO2QZDS2wrFh61xa746SmXoCCFDqBZ0g4fe921Shk7felTuVJ6rNJd85GTXDNYouggPfgbVDJ-2D5jwUvgXy_kNhc3ia4nuL7BryYqhSkNkk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xi5Ts9_mDE8LwJjyG5HHHgqWvl-AlQI9-ePfakpAXA9zuquVJJd7BCqKWMq8mnqm14rwEc898WxdXepPFqDx1QxCfm7NX_dwBw3hLNO3ssjkViNGlKaPW7SAoaXiwMZSV-RPAyyCQKN7gcQlvPin9m2xKX35a2I3j71yjAxNLf6kRqlathNvFBxuzxPi8QsK?purpose=fullsize)

```text
1. Identify upload functionality
             ↓
2. Determine what validation exists
             ↓
3. Identify server-side technology
             ↓
4. Test allowed extensions
             ↓
5. Determine whether validation is:
      ├── Client-side
      ├── Blacklist
      ├── Whitelist
      ├── Content-Type
      └── MIME/content-based
             ↓
6. Test validation robustness
             ↓
7. Determine whether uploaded files
   are accessible/executable
             ↓
8. In an authorized lab, verify
   impact with a harmless execution test
```

---

# 53. The Most Important Concepts to Remember

### 🔴 1. Client-side validation is not security

Anything running inside the browser is potentially modifiable by the user.

---

### 🔴 2. Backend validation is mandatory

Security decisions must ultimately be enforced on the server.

---

### 🔴 3. Blacklists are inherently difficult

You must know every dangerous possibility.

---

### 🟢 4. Whitelists are generally better

Only permit the formats actually required.

---

### 🔴 5. Extension checking isn't enough

A file can have:

```text
.jpg
```

while containing something entirely different.

---

### 🔴 6. Content-Type is client-controlled

Never blindly trust:

```http
Content-Type: image/png
```

---

### 🟠 7. MIME detection is stronger but not perfect

Magic bytes alone don't prove that a file is a safe, valid image.

---

### 🔴 8. Regex mistakes can create vulnerabilities

Compare:

```regex
\.(jpg|jpeg|png|gif)
```

with:

```regex
\.(jpg|jpeg|png|gif)$
```

The `$` ensures the allowed extension occurs at the end.

---

### 🔴 9. Upload success ≠ code execution

Always distinguish:

```text
Uploaded
```

from:

```text
Uploaded + interpreted/executed
```

---

### 🔴 10. Server configuration matters

Even secure application validation can be undermined by an insecure web-server configuration.

---

# 🧠 Quick Revision Sheet

```text
FILE UPLOAD ATTACKS
│
├── Absent Validation
│   └── Any file accepted
│
├── Client-Side Validation
│   └── Browser-only → bypassable
│
├── Blacklist
│   └── Blocks known extensions
│       └── Incomplete blacklist → possible bypass
│
├── Whitelist
│   └── Allows known extensions
│       └── Weak regex → possible bypass
│
├── Double Extension
│   └── shell.jpg.php
│
├── Reverse Double Extension
│   └── App sees .jpg
│   └── Server config sees .php
│
├── Character Injection
│   └── Parser/normalization inconsistencies
│
├── Content-Type
│   └── Client-declared type
│
└── MIME Type
    └── File bytes / magic signatures
```

## ⭐ Golden Rule

> **Never trust the filename, extension, Content-Type, or client-side validation by itself.**

A properly secured upload feature should validate the file **server-side**, permit only necessary formats, verify actual file contents, safely rename/store files, prevent uploaded content from being executed, and isolate uploaded files from executable web directories.