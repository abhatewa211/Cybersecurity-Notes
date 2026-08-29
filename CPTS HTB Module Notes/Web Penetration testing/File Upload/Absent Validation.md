![Image](https://images.openai.com/static-rsc-4/r0gUmMUXpUmMcFxoK3QPZTEAqLzurTPh6fVETBJfTG0MAoF4589RyI8NpQzhSvCnm37MvkoEW-xhqBQxj0IuraflbJhz6ShyGawCqn-T0lALsPLdYmZ0GNJOHL81d4C6crbYdVmLFOVQPZM0xp4TGB56oflUYypQOwU0PJ-JTyeGl09KmjFZabMSYWCcyPC2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dvN_xgSVXEUstAwKv6KAvmAdBnyOi6yqfsEtj7OmWn6uwb0SnIrdhVx1TyYze5p9RQbPu4AKE4M8Him1LANRHl1NPDqfPEHYhLvy69PVUxG9azUbRtSq75uKxBm1zbuuPEx3CSZCxjwXxpN1jTtrNutmK6D-LUS0I0Fp3in8fqKXSsWRnZaeJs7beYo9oAfZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ad-_iSlWYGwxw73ivKkSmkD0R_61Qag7MglCBAKClJPsmYO1XzftN4assgn3QLAMPSBmMBfpsEbv1DPPgZaqKg-HSY2FZw6o0cLZA9I_hE1bVvMxMIFYQmEqr0uDa91TD18Ve5s80s6PFI4f_rLAQBETYKGtmZcVEIkf_pnQvYHqbpViWJMELC44OErfnrkJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/liOBmaa412l1hjFEildDVbYjO_WV5fT-1na-8rDntsQvc9y1Xz61sLI00cbJ40wEHrJf6iQi1OmlRwgb24tFoCWSMxjkDyRQPA1Bi341SV6xMwe0Ejw61QrgFUUg05yJviPC8U_xcOz8dw09bSG27QyuMEU53F8g3licSqZ28wIlEWea8zIcMqElcaa50mKE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yGeus3lPMW4bjkGbrxxESMQB1rtrMe8FjQDJG1MaNneGhWYRHkHJS4rWiHG1XfBaF70lL01T6lsGPigXI40fPZ72FMrGCgDQu1NiC6qdbVZEjZtw0heSrJozVHNsvdX490gdHQ4TePQNGiuLHZO3adqLpbWu9o0_gHcL4yoDg9py_u-L7PKax8WdyBWwwZiG?purpose=fullsize)

## 1. What Is Absent Validation?

**Absent Validation** is the most basic form of a file-upload vulnerability.

It occurs when a web application:

> **does not have any form of validation filters on the uploaded files**

As a result, the application may allow users to upload **any file type by default**.

### Basic flow

```text
User
  ↓
Upload File
  ↓
No Validation
  ↓
Any File Type Accepted
  ↓
File Stored on Server
```

If the server is capable of executing the uploaded file, this can potentially escalate into **Remote Code Execution (RCE)**.

---

# 2. Why Absent Validation Is Dangerous

Normally, an application should restrict uploads to files it actually needs.

For example:

```text
Allowed:
.jpg
.png
.pdf
```

But with absent validation:

```text
.jpg   → accepted
.png   → accepted
.pdf   → accepted
.php   → accepted
.exe   → potentially accepted
.jsp   → potentially accepted
.asp  → potentially accepted
```

The dangerous part is not simply that an attacker can upload an unusual file.

The critical issue is:

> **Can the server process or execute the uploaded file?**

If yes, an arbitrary file upload can potentially become a code-execution vulnerability.

---

# 3. Web Shell and Reverse Shell

The material identifies two common types of scripts used when testing arbitrary file upload:

### Web Shell

A **Web Shell** provides a way to interact with the backend server through web requests.

Conceptually:

```text
Browser
   ↓
Web Shell
   ↓
Server
   ↓
Command
   ↓
Command Output
   ↓
Browser
```

A web shell accepts commands and returns their output through the browser.

### Reverse Shell

A **Reverse Shell** works differently.

Instead of repeatedly interacting with a web page, the compromised server establishes a connection back to a listener controlled by the tester.

```text
Server
   │
   │ Outbound connection
   ▼
Tester / Listener
   │
   ▼
Interactive Shell
```

### Important distinction

|Web Shell|Reverse Shell|
|---|---|
|Accessed through web requests|Server connects back|
|Output displayed through web interface|Interactive shell can be obtained|
|Requires executable server-side script|Requires code execution and outbound connectivity|
|Often easier to test initially|Can provide more interactive access|

---

# 4. Identifying the Web Framework

Before attempting to execute an uploaded script, we need to determine:

> **What programming language/framework is running the web application?**

This matters because a web shell must generally be written in a language that the server is configured to execute.

For example:

```text
PHP application
      ↓
PHP server-side code

ASP application
      ↓
ASP code

ASP.NET application
      ↓
ASP.NET-compatible code
```

Therefore:

> **Identify the server-side technology before selecting a corresponding test file.**

---

# 5. Looking at URL Extensions

One of the simplest manual techniques is examining the URL.

For example:

```text
http://SERVER_IP:PORT/index.php
```

The `.php` extension strongly suggests PHP.

Similarly, you may encounter:

```text
index.asp
index.aspx
```

which can provide clues about the backend technology.

### Important limitation

This method isn't always reliable.

Modern web applications frequently use **web routes**.

For example:

```text
http://SERVER_IP:PORT/login
http://SERVER_IP:PORT/dashboard
http://SERVER_IP:PORT/profile
```

There may be no visible extension at all.

So:

> **Absence of a file extension does not mean the application isn't using a particular server-side language.**

---

# 6. Testing `/index.ext`

A basic manual technique is to test common extensions.

For example:

```text
http://SERVER_IP:PORT/index.php
```

If this returns the same application as:

```text
http://SERVER_IP:PORT/
```

then there is evidence that the application is using PHP.

Other extensions that may be tested include:

```text
.php
.asp
.aspx
```

### Concept

```text
/index.php
/index.asp
/index.aspx
      ↓
Compare responses
      ↓
Identify possible backend technology
```

### ⚠️ Important limitation

This isn't guaranteed to work because:

- The application may not use an `index` page.
    
- URLs may be handled through routes.
    
- Multiple technologies may be used.
    
- The extension may not be exposed publicly.
    

---

# 7. Using Burp Intruder for Technology Discovery

Instead of manually testing extensions one by one, the material mentions using **Burp Intruder** with a web-extension wordlist.

The referenced SecLists wordlist is:

**Web Extensions**

[SecLists Web Extensions wordlist](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt?utm_source=chatgpt.com)

The basic idea is:

```text
/index.FUZZ
     ↓
Burp Intruder
     ↓
Try common extensions
     ↓
Compare responses
     ↓
Identify potential technology
```

This is useful during authorized penetration testing and lab environments.

---

# 8. Wappalyzer

Another method mentioned in the material is **Wappalyzer**.

Wappalyzer is a browser extension that identifies technologies used by websites.

[Wappalyzer](https://www.wappalyzer.com?utm_source=chatgpt.com)

It can potentially identify things such as:

- Web server
    
- Programming language
    
- Framework
    
- Operating system indicators
    
- JavaScript libraries
    
- Other technologies
    

For the example in the material, Wappalyzer identifies:

```text
Apache
PHP
Ubuntu
cdnjs
jQuery
```

This provides considerably more information than simply discovering `.php`.

---

# 9. Web Vulnerability Scanners

Technology identification can also be performed using security tools.

Examples mentioned in the material include:

- Burp Scanner
    
- OWASP ZAP
    
- Other web vulnerability assessment tools
    

The general workflow is:

```text
Target
  ↓
Scanner
  ↓
Technology Detection
  ↓
Framework / Language Identification
  ↓
Security Testing
```

### Important pentesting principle

Don't depend on one identification technique.

Use:

```text
Manual observation
       +
URL/extension testing
       +
Technology fingerprinting
       +
Security scanners
```

to build confidence.

---

# 10. Identifying the Vulnerability

Once the server-side language is identified, the next step in the authorized lab is determining whether the upload functionality accepts files using that language's extension.

For a PHP application, the material uses a harmless test file:

```text
test.php
```

containing:

```php
<?php echo "Hello HTB";?>
```

### Why use `Hello World` first?

Because the objective at this stage is **not yet to obtain full control**.

The goal is simply to answer:

> **Does the server execute PHP code from an uploaded PHP file?**

This is a much cleaner initial test.

---

# 11. The `Hello HTB` Test

The test file contains:

```php
<?php echo "Hello HTB";?>
```

The file is uploaded through the application's upload functionality.

If the application reports:

```text
File successfully uploaded
```

that establishes that the upload itself succeeded.

But that **alone does not prove code execution**.

The next step is to access the uploaded file.

---

# 12. Accessing the Uploaded File

In the example, the uploaded file becomes accessible at:

```text
http://SERVER_IP:PORT/uploads/test.php
```

The important observation is what the server returns.

### Scenario A — Code executes

The browser displays:

```text
Hello HTB
```

This means the PHP code was interpreted and executed.

```text
<?php echo "Hello HTB";?>
              ↓
        PHP Interpreter
              ↓
          Hello HTB
```

### Scenario B — Code does NOT execute

The browser might display the source itself:

```text
<?php echo "Hello HTB";?>
```

This would suggest that the server is serving the file as ordinary content rather than executing it as PHP.

---

# 13. Why `Hello HTB` Is Important

The difference between these two results is crucial.

### Source displayed

```text
<?php echo "Hello HTB";?>
```

➡️ PHP was likely **not executed**.

### Output displayed

```text
Hello HTB
```

➡️ PHP code was **executed**.

Therefore, the test establishes both:

1. The application accepted the uploaded `.php` file.
    
2. The server executed PHP contained in that uploaded file.
    

That combination is much more serious.

---

# 14. Complete Attack Chain

The section can be summarized as:

```text
             FILE UPLOAD
                  │
                  ▼
          No File Validation
                  │
                  ▼
         PHP File Accepted
                  │
                  ▼
           File Stored
                  │
                  ▼
       Uploaded File Accessible
                  │
                  ▼
        PHP Code Interpreted
                  │
                  ▼
          Code Execution
                  │
                  ▼
       Potential Server Control
```

This is the fundamental concept you should remember.

---

# 15. Front-End vs Back-End Validation

An especially important observation from the exercise is the difference between **front-end behavior** and **back-end security**.

Suppose the upload form allows:

```text
All Files
```

This tells us that the browser isn't restricting the selection.

But that **doesn't automatically prove the backend has no restrictions**.

The backend could still reject the file.

Therefore:

> **Never conclude that a file upload is vulnerable solely because the frontend allows the file to be selected.**

You need to test the actual server-side behavior.

---

# 16. Evidence of Absent Validation

In the exercise, the strongest evidence comes from the combination:

```text
1. PHP file can be uploaded
       +
2. Upload succeeds
       +
3. Uploaded PHP file is accessible
       +
4. PHP code executes
```

Together, these indicate a serious unrestricted upload condition.

---

# 17. Why File Extension Matters Here

The application accepts:

```text
test.php
```

and places it under:

```text
/uploads/
```

The web server then interprets the file as PHP.

This is particularly dangerous because the upload directory is apparently within the web application's accessible path.

Conceptually:

```text
/uploads/
    │
    └── test.php
          │
          ▼
      Web Server
          │
          ▼
      PHP Engine
```

A secure architecture would generally avoid allowing arbitrary user-uploaded content to be interpreted as executable server-side code.

---

# 18. Key Lesson: Upload ≠ Execution

This is one of the most important concepts from this section.

There are **two separate questions**:

### Question 1

> Can I upload the file?

```text
Upload accepted?
YES / NO
```

### Question 2

> What happens when the uploaded file is requested?

```text
Downloaded as data?
OR
Rendered?
OR
Parsed?
OR
Executed?
```

An upload vulnerability becomes substantially more dangerous when uploaded content reaches a dangerous processing or execution path.

---

# 19. Attack Surface Analysis

When assessing a file-upload feature in an authorized environment, think about these stages:

```text
┌─────────────────┐
│ 1. Upload       │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 2. Validation   │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 3. Storage      │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 4. Accessibility│
└────────┬────────┘
         ↓
┌─────────────────┐
│ 5. Processing   │
└────────┬────────┘
         ↓
┌─────────────────┐
│ 6. Execution?   │
└─────────────────┘
```

Each stage is important.

---

# 20. Tools Mentioned in This Section

|Tool|Purpose|
|---|---|
|**Burp Intruder**|Fuzzing/testing extensions and parameters|
|**Wappalyzer**|Technology fingerprinting|
|**Burp Scanner**|Automated web security/technology analysis|
|**OWASP ZAP**|Web application security testing|
|**SecLists**|Useful wordlists for security testing|

For authorized testing, these tools help answer:

> **What technology is running?**

and

> **How does the upload functionality behave?**

---

# 🧠 21. Important Things to Memorize

> 🔴 **Absent Validation = no file validation filters on uploaded files.**

> 🔴 It can allow **arbitrary file types** to be uploaded.

> 🔴 An arbitrary file upload can potentially lead to **Remote Code Execution (RCE)**.

> 🔴 A **Web Shell** provides command interaction through web requests.

> 🔴 A **Reverse Shell** provides an interactive connection initiated back from the target.

> 🔴 A web shell generally needs to be written in a language supported by the target's server-side environment.

> 🔴 **Identify the web technology before selecting the corresponding server-side test.**

> 🔴 URL extensions such as `.php`, `.asp`, and `.aspx` can provide clues about the backend technology.

> 🔴 URL extension testing isn't always reliable because modern applications may use **Web Routes**.

> 🔴 **Wappalyzer** can help identify technologies running on a website.

> 🔴 Burp/ZAP scanners can also assist with technology identification.

> 🔴 Successfully uploading a file **does not by itself prove code execution**.

> 🔴 You need to determine what happens when the uploaded file is accessed.

> 🔴 If PHP source is displayed, PHP may not be executing.

> 🔴 If `Hello HTB` is displayed from the PHP `echo` statement, the server executed the PHP code.

---

# 🎯 22. Quick Revision Sheet

### Absent Validation

```text
No validation
     ↓
Any file accepted
     ↓
Malicious file uploaded
     ↓
File stored
     ↓
File accessible
     ↓
Server interprets file
     ↓
Potential code execution
```

### Technology Identification

```text
URL extensions
      +
Manual endpoint testing
      +
Burp Intruder
      +
Wappalyzer
      +
Burp/ZAP
      ↓
Identify backend technology
```

### Vulnerability Verification

```text
Identify PHP
    ↓
Create harmless PHP test
    ↓
Upload test.php
    ↓
Confirm successful upload
    ↓
Access uploaded file
    ↓
Observe response
```

### Result

```text
<?php echo "Hello HTB";?>
          ↓
Source displayed
          ↓
PHP not executing

OR

<?php echo "Hello HTB";?>
          ↓
"Hello HTB"
          ↓
PHP executed
```

---

## ⭐ Final Takeaway

The **core lesson of Absent Validation** is:

> **A file upload feature becomes dangerous when the application accepts files without proper server-side validation and then places those files somewhere they can be interpreted or processed dangerously.**

The critical progression to remember is:

**Upload accepted → file accessible → server interprets uploaded code → code execution.**

That is the foundation for the more advanced file-upload bypass techniques covered in the later sections.