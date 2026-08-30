![Image](https://images.openai.com/static-rsc-4/dEg1uktJwSbSzX--a0h2pJuHmBdPg5mgfMyb_c9wsw5WUeUMDQJERuMYwgD4Djug9UuqxUoaD9s9t2zW-fhj65PG7VxXss-mArXe-4rgcFf-AMyAYoo0-4Q9P8zlq6TIID5mEzD1OVp3eaoh57KAuMa05L7aRMmp2XBzptJcX5ctTowXNVHFQShFPKRPUKog?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Q0zrUTfkvVBZb3rSw505kaa1W3uebgYPgMSmQ23rW_icxu021m1eiRGSAyU9KNy7DC2uCaHlwfLHKXYQ29kFlhtz20n-7v3a7ZOFqxAwQlRV5dyzkV2JlfDVaDhFWTOjzz9ECol02J3WLldigPP06WZ73hXfv28IADzs9uwA6y9K_X5UGAVCUfNf2PMeLWWp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qeOzxhRmZqucFjY-n8BtrED7AYKWbu7XAGtGKTK-8jXFN07AZhRI3fsFhvoNaeYm6njsPba0HZN1tfq24GBkx9szEvXXvYLi4O9CjQbSUEGeEvFcEwF1djXS4aLfzqhijpmHfUv3SbICOxU1yMbRlDi8ZRikDFtXROGLPtVL42lVpClz0iYoYVLHpjLjX9vR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DCYwd2l7uLDNl31gzOmaKXkvBMwCz1kompkTuxsNLuCN7MqYu51J1H1cfpk2fmWrWyrrV47Nwso5UWi9-MLw5TYAqC5-Jk4-5MCi8ZCFynWXMS6L44UaYv7AEM1arlYJlrwlPbyeXsOFLxDStjCh9n_ZvaT80AhsuewG6DCnWp4tDg3LTRrwHGl4QKtowUaf?purpose=fullsize)

This section is especially important because it shows that **even a whitelist can be incorrectly implemented**. The weakness isn't necessarily the idea of allowlisting itself—it can be the **regex, filename parsing, or web-server configuration** used to enforce it.

---

# 1. What Is a Whitelist?

A **whitelist** contains the file extensions that the application explicitly allows.

For an image upload, for example:

```text
.jpg
.jpeg
.png
.gif
```

The basic logic is:

```text
Uploaded File
      ↓
Check extension
      ↓
Is it allowed?
   ↙         ↘
 YES         NO
  ↓           ↓
Accept      Reject
```

Compared with a blacklist:

```text
BLACKLIST
"Block these dangerous extensions."

WHITELIST
"Only allow these approved extensions."
```

### Key point

> **A whitelist is generally more secure than a blacklist**, because it doesn't need to know every possible dangerous extension.

---

# 2. When to Use Blacklist vs Whitelist

Neither approach is universally appropriate for every application.

### Blacklist

Can make sense when an application needs to support a **very wide variety of file types**.

Example:

```text
File Manager
```

A file manager might intentionally allow:

- Documents
    
- Images
    
- Archives
    
- Videos
    
- Audio
    
- Other files
    

Creating a complete whitelist could be impractical.

### Whitelist

Works particularly well when only a few file types are required.

Example:

```text
Profile Image

Allowed:
.jpg
.jpeg
.png
.gif
```

### Both can be used together

A defense-in-depth design can combine:

```text
Whitelist
   +
Blacklist
   +
Content validation
   +
Safe storage
```

---

# 3. Testing the Whitelist

The exercise starts by attempting to upload:

```text
.phtml
```

Unlike the previous blacklist exercise, the application responds:

```text
Only images are allowed
```

This is important because the message **doesn't necessarily tell us what validation mechanism is being used**.

An error such as:

```text
Only images are allowed
```

could come from:

- A whitelist
    
- A blacklist
    
- MIME validation
    
- Content inspection
    
- Regex validation
    
- Multiple validation mechanisms
    

Therefore:

> **Don't determine the validation mechanism from the error message alone. Test its behavior.**

---

# 4. Fuzzing the Upload Function

We can again fuzz the upload functionality with an extension wordlist.

The goal is now slightly different.

Previously:

```text
Find extensions NOT blacklisted
```

Here:

```text
Find extensions that ARE allowed
```

The results show that PHP-related extensions such as:

```text
php5
php7
phtml
```

are rejected.

However, some other unusual extensions from the wordlist are accepted.

This gives us an important clue:

> **The application may be using a whitelist, but its validation may contain a flaw.**

---

# 5. The Example Whitelist Code

The module gives this PHP example:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

At first glance, this looks like a whitelist.

It says:

```text
jpg
jpeg
png
gif
```

are allowed.

But there's a subtle regex problem.

---

# 6. Understanding the Regex

The important part is:

```text
^.*\.(jpg|jpeg|png|gif)
```

The developer intended to say:

> "The filename must end in `.jpg`, `.jpeg`, `.png`, or `.gif`."

But the pattern doesn't actually enforce that.

It checks whether the filename **contains** one of those extensions.

### That's the vulnerability.

For example:

```text
shell.jpg.php
```

contains:

```text
.jpg
```

So the weak regex can potentially consider it valid.

But the actual filename ends with:

```text
.php
```

---

# 7. The Missing `$`

This is one of the most important details in the entire section.

The vulnerable pattern is:

```regex
^.*\.(jpg|jpeg|png|gif)
```

Notice there is **no `$` at the end**.

`$` means:

> **End of the string.**

Without `$`, the regex can match an allowed extension somewhere in the filename rather than requiring it to be the final extension.

---

# 8. Weak vs Strict Regex

### ❌ Weak pattern

```regex
^.*\.(jpg|jpeg|png|gif)
```

Potentially matches:

```text
image.jpg
image.jpg.php
shell.png.something
```

because the allowed extension can occur before the end.

---

### ✅ Strict pattern

```regex
/^.*\.(jpg|jpeg|png|gif)$/
```

The `$` requires the match to reach the end.

Therefore:

```text
image.jpg       → ✅
image.png       → ✅
shell.jpg.php   → ❌
shell.png.php   → ❌
```

### Memorize:

```text
^ = beginning
$ = end
```

---

# 💥 9. Double Extensions

The first major technique discussed is the **double extension**.

Suppose:

```text
.jpg
```

is allowed.

We can construct a filename containing `.jpg` but ending in another extension.

Conceptually:

```text
shell.jpg.php
```

The weak whitelist sees:

```text
shell.jpg.php
     ↑
allowed extension detected
```

while the server may interpret:

```text
shell.jpg.php
          ↑
       .php
```

as PHP, depending on its configuration.

---

# 10. Double Extension Flow

```text
shell.jpg.php
      │
      ├── Application regex
      │        ↓
      │    Finds .jpg
      │        ↓
      │       ✅
      │
      └── Web server
               ↓
          Sees .php
               ↓
       Potential execution
```

This demonstrates an important security issue:

> **Different components can interpret the same filename differently.**

---

# 11. Why Double Extensions Don't Always Work

A strict application may use:

```regex
/^.*\.(jpg|jpeg|png|gif)$/
```

Now:

```text
shell.jpg.php
```

fails because `.php` is the final extension.

Therefore:

```text
Weak regex → double extension may work
Strict regex → double extension blocked
```

The module notes that bypasses against strict patterns often depend on:

- Misconfigurations
    
- Outdated software
    
- Differences in filename parsing
    

---

# 12. Reverse Double Extension

This is one of the most interesting concepts in the module.

Instead of:

```text
shell.jpg.php
```

we use:

```text
shell.php.jpg
```

At first, that appears useless.

Why?

Because:

```text
Final extension = .jpg
```

So a strict application whitelist should accept it as an image.

But what if the **web server itself** has an incorrect configuration?

That's where reverse double extension becomes relevant.

---

# 13. Application vs Web Server

This is the key idea:

```text
Filename
   ↓
Application
   ↓
"Ends in .jpg"
   ↓
✅ Accept
   ↓
Web Server
   ↓
"Contains .php"
   ↓
Potentially execute as PHP
```

So the upload application may actually be doing its job correctly.

The vulnerability can instead be caused by the **web-server configuration**.

---

# 14. Apache `FilesMatch` Example

The module gives this example configuration:

```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

This configuration tells Apache to use the PHP handler for files matching:

```text
.phar
.php
.phtml
```

---

# 15. The Configuration Regex Problem

Look carefully at:

```regex
.+\.ph(ar|p|tml)
```

Again:

> There is no `$` at the end.

Therefore, the pattern can match a PHP-associated extension **anywhere within the filename**, rather than requiring it to be the final extension.

For example:

```text
shell.php.jpg
```

contains:

```text
.php
```

So the misconfigured Apache rule may treat it as PHP.

---

# 16. Reverse Double Extension Attack Chain

This produces:

```text
shell.php.jpg
      │
      ├── Upload application
      │       ↓
      │   Ends with .jpg
      │       ↓
      │      ✅
      │
      └── Apache
              ↓
          Contains .php
              ↓
      PHP handler selected
              ↓
      Potential execution
```

This is why it's called:

> **Reverse Double Extension**

The executable-looking extension comes **before** the allowed extension.

---

# 17. Why This Is a Configuration Vulnerability

Notice something important:

The upload application may have a strict whitelist:

```regex
/^.*\.(jpg|jpeg|png|gif)$/
```

So:

```text
shell.php.jpg
```

passes.

That's not necessarily a flaw in the upload validation.

The second vulnerability is:

```text
Apache configuration
```

which incorrectly treats filenames containing `.php` as PHP files.

Therefore:

> **Secure application code can still be undermined by insecure server configuration.**

---

# 18. Blacklist + Whitelist Together

The module also mentions that the application may still have a blacklist.

So the tester can fuzz the PHP extension wordlist to determine which extensions are blocked.

This gives a more complete picture:

```text
                 Upload
                    ↓
          ┌─────────┴─────────┐
          ↓                   ↓
      Whitelist            Blacklist
          ↓                   ↓
       Allowed?            Blocked?
          ↓                   ↓
          └─────────┬─────────┘
                    ↓
              Web Server
                    ↓
             Interpretation
```

Security controls can exist at several layers, and weaknesses can arise from the interaction between them.

---

# 🧪 19. Character Injection

The final technique discussed is **character injection**.

The basic concept is:

> Inject special characters into filenames so that different components interpret the filename differently.

The module lists examples such as:

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

Different characters have different historical/platform-specific behaviors.

---

# 20. Why Character Injection Can Work

Consider:

```text
Application interpretation
        ↓
"Looks like an allowed image"
```

but:

```text
Server interpretation
        ↓
"Looks like an executable file"
```

The vulnerability occurs when the two components **parse the filename differently**.

---

# 21. Null Byte Example

The material gives the historical example:

```text
shell.php%00.jpg
```

On older PHP environments, a null byte could historically cause filename handling to terminate early.

Conceptually:

```text
Application sees:

shell.php%00.jpg
        ↓
Contains .jpg
        ↓
Potentially passes validation


Older vulnerable processing:

shell.php%00.jpg
        ↓
Terminates at %00
        ↓
shell.php
```

### ⚠️ Important

This is primarily a **historical technique** associated with old/vulnerable PHP versions. Modern systems generally handle null bytes differently and reject them in relevant filesystem APIs.

Don't treat `%00` as a reliable modern bypass.

---

# 22. Windows Colon Example

The material also describes a Windows-specific example involving:

```text
shell.aspx:.jpg
```

Historically, Windows filename semantics and alternate data stream/path parsing could create unexpected behavior.

Again, the key lesson isn't to memorize one magic filename.

It's:

> **Different operating systems and server components can parse filenames differently.**

---

# 23. Generating Character-Injection Permutations

Instead of manually testing every combination, the module demonstrates generating a wordlist.

The supplied Bash script is:

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

---

# 24. Understanding the Bash Script

The outer loop:

```bash
for char in ...
```

iterates through special characters.

The inner loop:

```bash
for ext in '.php' '.phps'
```

iterates through PHP-related extensions.

Then the script creates different filename arrangements.

### Pattern 1

```text
shell$char$ext.jpg
```

### Pattern 2

```text
shell$ext$char.jpg
```

### Pattern 3

```text
shell.jpg$char$ext
```

### Pattern 4

```text
shell.jpg$ext$char
```

This produces many combinations automatically.

---

# 25. Why Generate Permutations?

Because filename parsing can be complicated.

Rather than assuming:

```text
"This one format will work."
```

we can systematically test:

```text
character
+
extension
+
position
+
allowed extension
```

The goal is to identify **differences in application/server behavior**.

---

# 🔬 26. Fuzzing Workflow

The overall workflow becomes:

```text
Create candidate filenames
          ↓
Generate wordlist
          ↓
Burp Intruder
          ↓
Upload candidates
          ↓
Compare responses
          ↓
Identify accepted files
          ↓
Determine how server interprets them
```

Again:

> **Upload acceptance and code execution are separate tests.**

---

# 27. Three Layers You Should Think About

This section becomes much easier if you visualize three separate layers.

### Layer 1 — Browser

```text
JavaScript
accept=""
```

### Layer 2 — Application

```text
Blacklist
Whitelist
Regex
MIME/content validation
```

### Layer 3 — Web Server

```text
Apache/IIS/etc.
        ↓
Filename parsing
        ↓
Handler selection
        ↓
PHP execution
```

A weakness at any layer—or an inconsistency between layers—can create a vulnerability.

---

# 🧠 28. The Most Important Concept: Parser Discrepancy

A recurring theme throughout this section is **different components interpreting the same filename differently**.

For example:

```text
Application:

shell.php.jpg
       ↓
Final extension = jpg
       ↓
✅ Image


Apache:

shell.php.jpg
       ↓
Contains .php
       ↓
Potential PHP handler
```

This is a **parser/interpretation discrepancy**.

It is one of the biggest concepts to take away from file-upload vulnerabilities.

---

# 🆚 29. Blacklist vs Whitelist vs Weak Whitelist

|Technique|Example|Main weakness|
|---|---|---|
|Blacklist|Block `.php`|May miss executable extensions|
|Whitelist|Allow `.jpg` only|Stronger if correctly implemented|
|Weak whitelist|Regex merely contains `.jpg`|Double extensions may pass|
|Strict whitelist|Regex ends with `$`|Much harder to bypass|
|Misconfigured server|`.php` recognized anywhere|Application validation can be undermined|

---

# 🚨 30. Common Mistakes

### Mistake 1 — Assuming an error message reveals the validation method

```text
"Only images are allowed"
```

doesn't necessarily tell you whether the application uses:

- Whitelist
    
- Blacklist
    
- MIME checking
    
- Content checking
    
- Multiple checks
    

---

### Mistake 2 — Forgetting `$`

Weak:

```regex
^.*\.(jpg|jpeg|png|gif)
```

Strict:

```regex
/^.*\.(jpg|jpeg|png|gif)$/
```

That final `$` is critical.

---

### Mistake 3 — Assuming upload acceptance means execution

```text
Upload accepted
      ≠
PHP executed
```

---

### Mistake 4 — Ignoring server configuration

Even a secure-looking upload validator can be undermined by:

```text
Apache/IIS configuration
```

---

### Mistake 5 — Assuming old bypasses work on modern systems

Techniques involving things such as:

```text
%00
```

are heavily dependent on old software behavior and should be treated as **historical/legacy techniques**, not universal modern bypasses.

---

# ⭐ 31. Things You MUST Memorize

> 🔴 **A whitelist generally provides stronger security than a blacklist when only a small set of file types is required.**

> 🔴 A whitelist explicitly defines what is allowed.

> 🔴 A blacklist explicitly defines what is forbidden.

> 🔴 Error messages do not necessarily reveal whether an application uses a blacklist or whitelist.

> 🔴 The regex must validate the **final extension**, not merely find an allowed extension somewhere in the filename.

> 🔴 `^` represents the beginning of a string.

> 🔴 `$` represents the end of a string.

> 🔴 Missing `$` can make a regex accept filenames containing an allowed extension before the actual final extension.

> 🔴 **Double extension:** `shell.jpg.php`

> 🔴 **Reverse double extension:** `shell.php.jpg`

> 🔴 Double-extension attacks rely on differences between filename validation and server interpretation.

> 🔴 A strict whitelist can prevent the classic `shell.jpg.php` technique.

> 🔴 Server configuration can introduce vulnerabilities even when application-side validation is strict.

> 🔴 Apache `FilesMatch` rules determine which filenames receive particular handlers.

> 🔴 A missing `$` in a server-side handler regex can cause unintended filename matches.

> 🔴 **Character injection** attempts to exploit differences in filename parsing.

> 🔴 `%00` is primarily a historical technique associated with older vulnerable environments.

> 🔴 Different operating systems and web servers can process filenames differently.

> 🔴 **Upload success does not automatically equal code execution.**

---

# 🎯 32. Complete Attack-Analysis Flow

For a file-upload assessment, think in this order:

```text
             FILE UPLOAD
                  │
                  ▼
       ┌─────────────────────┐
       │ Client-side checks? │
       └──────────┬──────────┘
                  │
                  ▼
        Inspect HTTP request
                  │
                  ▼
       ┌─────────────────────┐
       │ Backend validation? │
       └──────────┬──────────┘
                  │
          ┌───────┴────────┐
          ▼                ▼
      Blacklist         Whitelist
          │                │
          ▼                ▼
   Test coverage       Test regex
                           │
                           ▼
                  Check final extension
                           │
                           ▼
                  Check server config
                           │
                           ▼
                   File interpretation
                           │
                           ▼
                    Execution?
```

---

# 🧩 33. Blacklist → Whitelist Progression

The last three sections form a very logical progression:

### Section 1 — Absent Validation

```text
No validation
     ↓
Unexpected file accepted
```

### Section 2 — Client-Side Validation

```text
Frontend validation
     ↓
Modify browser/request
     ↓
Backend may accept file
```

### Section 3 — Blacklist

```text
Backend blacklist
     ↓
Known extensions blocked
     ↓
Incomplete blacklist
     ↓
Potential alternative extension
```

### Section 4 — Whitelist

```text
Backend whitelist
     ↓
Only approved extensions
     ↓
Weak regex?
     ↓
Filename parsing discrepancy
     ↓
Potential bypass
```

This progression teaches an important lesson:

> **The presence of a security control doesn't automatically mean the control is correctly implemented.**

---

# 📝 34. Quick Revision Card

### Whitelist

**Only explicitly allowed extensions are accepted.**

### Weak regex

```regex
^.*\.(jpg|jpeg|png|gif)
```

❌ Doesn't require the allowed extension to be final.

### Strict regex

```regex
/^.*\.(jpg|jpeg|png|gif)$/
```

✅ Requires the allowed extension to reach the end.

### Double Extension

```text
shell.jpg.php
```

Allowed extension appears first.

### Reverse Double Extension

```text
shell.php.jpg
```

PHP-associated extension appears before the allowed extension.

### Character Injection

Special characters are inserted into filenames to investigate parsing discrepancies.

### Core principle

> **Always consider how every component—browser, application, filesystem, and web server—interprets the filename.**