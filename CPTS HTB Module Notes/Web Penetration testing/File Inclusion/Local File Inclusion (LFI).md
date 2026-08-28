# 1. What Are We Trying to Achieve?

The main goal of exploiting LFI in this section is:

```text
User-controlled parameter
          ↓
Manipulate file path
          ↓
Application includes/reads unintended file
          ↓
Read local file from server
```

The techniques discussed here are:

1. **Basic LFI**
    
2. **Path Traversal**
    
3. **Filename Prefix**
    
4. **Appended Extensions**
    
5. **Second-Order LFI**
    

---

# 2. Basic LFI

![Image](https://images.openai.com/static-rsc-4/u4QidWS7XGKpVVbybrvTXbvDR_pK2WQD2v7LFK-ca-F7fUA3xe1jDan6lgZeTKZGjciA4_cw_-R-uIfAX2opvuztUdPuNRyJUV1mnfoEF6G1bP3oZIQf-huVKxaFZ2MXuyX1_cSAIH8L29wzp0qn2i-TNrrvszGfsO0O6eJ8UbHf5q-qWsK4epxV9bWE2WZr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0v8WbQCeSn-en7_iHdI_tT1DvQBNyNESVeTUcZUhBvlUXIywUlIVOcbLEHPygbUv5UeOtdHYkzwnIxUQwC3TWlxc50qWDOyYLrtrZly7TRFDsBqJ88_LzG_ISp1if1LTehomLxCti0jx4-yfl9LvqfaugQYF_jL2X34ZVKqgDJwV8W3McGRRhoaWPEkC2a0q?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RsCjLlbzhGaJVcxytM_c1RXpUs2l6rp8nwaHF5BQrQ8rRFMyG4owL0QHwEwdaFJIyaDvjQgj96iA3bvrMoTJjy1XgpoDTAcazztsQgxGBuzSBiV7DVomFtTrbazwWQaBjfHQXMbFFv9ADfYjPY-VZerihAfhs6eaga-w8WrtzAOyc1CrlyMZI0gR6blrag5A?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2JdLMEIiJAkLeADXIgVXfL_IouBc5fSilggV_kOqqhtWtvDixc-IhT61wh0xCURq-FZaRt_CRo77900ZGQEaOKrjaZGYCvIo4N-YNgCir76Vr3y1NWV2ZUwrT_Fsgz4qQxptcFa33xVAGyL_hMFHFOC_RZeUPOGeDfqCNURhzxgAoSNzuf_lAALwpmdPS1gl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/o_WvFr_f4KLFEuptn79UH31rZCFf_qkDxw5wTxuVU_nk05Ju0pMW-nWQ5nMkJHajWROtUkk4D5cxw9tqUwoDBX6Xg8MNBeJpQvo5y8w8LvhGGagWY9iNp84RXJhXn8rHp58B0Q5dAmlkJEJOXPvQSpJmCoFqEglHqewoHmSEte6OzmBQ3NwSdQFINHgT0ZMd?purpose=fullsize)

Imagine a web application that allows users to choose their language.

For example:

```text
English
Spanish
```

When Spanish is selected, the URL becomes:

```text
http://<SERVER_IP>:<PORT>/index.php?language=es.php
```

Notice the important part:

```text
language=es.php
```

The application is using the `language` parameter to determine what content gets loaded.

---

## Why Is This Interesting?

There could be several ways for an application to change its language:

- Different database tables
    
- Different versions of the web application
    
- Different templates/files
    

However, using a template engine to load different files is one of the easiest and most common approaches.

If the application is actually pulling a file based on:

```text
language=es.php
```

then we may be able to change the value and make the application load a **different local file**.

---

# 3. Reading `/etc/passwd`

Two commonly readable files mentioned in the source are:

### Linux

```text
/etc/passwd
```

### Windows

```text
C:\Windows\boot.ini
```

The example changes:

```text
language=es.php
```

to:

```text
language=/etc/passwd
```

Result:

```text
http://<SERVER_IP>:<PORT>/index.php?language=/etc/passwd
```

If the application directly passes the parameter to a file-inclusion function, it may read `/etc/passwd`.

---

## 🧠 Important Concept

A vulnerable application might effectively be doing:

```php
include($_GET['language']);
```

So:

```text
GET parameter
     ↓
language=/etc/passwd
     ↓
$_GET['language']
     ↓
include()
     ↓
/etc/passwd
```

If successful, the attacker can see the contents of the local file.

---

# 4. Path Traversal

Sometimes simply specifying an absolute path does **not** work.

Why?

Because developers may add something before or after the user-controlled parameter.

For example:

```php
include("./languages/" . $_GET['language']);
```

---

## What Happens Here?

Suppose we send:

```text
language=/etc/passwd
```

The application doesn't necessarily request:

```text
/etc/passwd
```

Instead, it constructs:

```text
./languages//etc/passwd
```

That file probably doesn't exist.

Therefore, our direct absolute path fails.

---

# 5. `../` — Parent Directory

This is where **path traversal** becomes important.

The sequence:

```text
../
```

means:

> **Go to the parent directory.**

For example:

```text
/var/www/html/languages/
```

Using:

```text
../index.php
```

means:

```text
/var/www/html/index.php
```

because `../` moves one directory upward.

---

# 6. Traversing Multiple Directories

If we need to move several directories upward, we can chain them:

```text
../../../
```

Conceptually:

```text
/var/www/html/languages/
            ↓ ../
/var/www/html/
            ↓ ../
/var/www/
            ↓ ../
/var/
            ↓ ../
/
```

Then we can specify the desired absolute path.

For example:

```text
../../../../etc/passwd
```

The complete request in the source is:

```text
http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/passwd
```

---

# ⭐ 7. Why Path Traversal Is Useful

The source points out an important advantage.

Even if the application directly uses:

```php
include($_GET['language']);
```

the traversal technique can still work.

If we aren't sure exactly where the application is located, adding enough:

```text
../
```

can move toward the root.

Once the traversal reaches:

```text
/
```

additional `../` components don't move beyond the root.

So conceptually:

```text
/
../
```

still resolves to:

```text
/
```

This means extra traversal components may not necessarily break the path.

---

# 8. Efficient Path Traversal

Although adding a huge number of `../` sequences can sometimes work, the source recommends being efficient.

For example, if the application is located under:

```text
/var/www/html/
```

we are:

```text
3 directories
```

away from `/`.

Therefore:

```text
../../../
```

would be sufficient.

### Best practice for testing/reporting

Instead of unnecessarily using:

```text
../../../../../../../../../../
```

try to determine the minimum traversal required.

The source specifically recommends finding the **minimum number of `../` sequences that works**.

---

# 9. Filename Prefix

Another situation occurs when the application **prepends a string** to our input.

For example:

```php
include("lang_" . $_GET['language']);
```

Now the application constructs the filename like:

```text
lang_ + user input
```

---

## Why Normal Traversal Fails

Suppose we try:

```text
../../../etc/passwd
```

The resulting filename becomes:

```text
lang_../../../etc/passwd
```

This is not the same as:

```text
../../../etc/passwd
```

The `lang_` prefix is still attached to the beginning.

Therefore, the intended traversal may fail.

---

# 10. Prefix + Absolute Path Behavior

The source demonstrates a technique involving placing `/` before the traversal:

```text
/../../../etc/passwd
```

The idea is that the prefix can be treated as part of a directory-like path, allowing traversal to proceed.

Example:

```text
http://<SERVER_IP>:<PORT>/index.php?language=/../../../etc/passwd
```

### ⚠️ Important Limitation

The source explicitly warns:

> This may **not always work**.

For example, the application may effectively require a directory such as:

```text
lang_/
```

and if that directory does not exist, the relative path may not resolve correctly.

Also, an arbitrary prefix can interfere with other LFI techniques discussed later, including:

- PHP wrappers
    
- PHP filters
    
- RFI
    

---

# 11. Appended Extensions

Another very common situation is when the application automatically adds an extension.

For example:

```php
include($_GET['language'] . ".php");
```

---

## What Happens?

Suppose we submit:

```text
/etc/passwd
```

The application actually constructs:

```text
/etc/passwd.php
```

instead of:

```text
/etc/passwd
```

Since:

```text
/etc/passwd.php
```

doesn't normally exist, the attempt fails.

---

# ⭐ 12. Why Developers Append `.php`

The source explains that this is common because it means developers don't need to specify the extension every time.

For example, instead of:

```text
language=en.php
```

the application can accept:

```text
language=en
```

and automatically construct:

```text
en.php
```

This may also appear safer because it seems to restrict inclusion to PHP files.

However, it can create a different security challenge when the application's file path remains influenced by user input.

---

# 13. Important Exercise — PHP File Reading

The source asks you to investigate what happens when attempting to read a PHP file, such as:

```text
index.php
```

through LFI.

The important question is:

> **Do you receive the PHP source code, or does the server execute/render it as HTML?**

This distinction connects directly to the previous topic:

```text
READ
vs
EXECUTE
```

If the server processes the PHP file normally, you may see its rendered output rather than the underlying source.

---

# 14. Second-Order Attacks

A **Second-Order Attack** is a more advanced form of LFI.

The key difference is:

> The malicious value isn't necessarily used immediately.

Instead:

```text
Attacker-controlled input
        ↓
Stored somewhere
        ↓
Application retrieves stored value
        ↓
Another functionality uses it
        ↓
LFI occurs
```

---

# 15. Second-Order LFI Example

Imagine a web application that lets users download their avatar through a URL like:

```text
/profile/$username/avatar.png
```

Normally:

```text
/profile/alice/avatar.png
```

would retrieve Alice's avatar.

But imagine the attacker can influence their username.

A malicious value could conceptually contain a file path such as:

```text
../../../etc/passwd
```

If the application later uses the stored username when constructing the avatar path, the application may end up requesting an unintended local file instead.

---

# 16. Why Is It Called "Second-Order"?

Because there are **two stages**.

### Stage 1 — Poison the value

The attacker supplies a malicious value.

```text
Attacker
   ↓
Registration/profile
   ↓
Malicious username
   ↓
Database
```

### Stage 2 — Application uses it later

```text
Database
   ↓
Username retrieved
   ↓
Avatar functionality
   ↓
File path
   ↓
LFI
```

Therefore:

```text
FIRST ORDER
Input → Vulnerable function

SECOND ORDER
Input → Storage → Later retrieval → Vulnerable function
```

---

# 17. Why Developers Miss Second-Order LFI

This is a **very important security concept**.

Developers may protect direct parameters such as:

```text
?page=
```

For example, they might validate the direct request.

But they may trust values retrieved from the database.

Consider:

```text
Direct request
     ↓
Validation
     ↓
Safe
```

versus:

```text
Database value
     ↓
Trusted automatically
     ↓
Used as file path
     ↓
LFI
```

If an attacker can poison the database value during registration, the later functionality may become exploitable.

---

# 18. How to Identify Second-Order LFI

When reviewing an application, don't only search for:

```text
GET parameter → include()
```

Also look for:

```text
User input
     ↓
Stored value
     ↓
Database
     ↓
Retrieved later
     ↓
File path
     ↓
File-loading function
```

The source describes this as finding a function that pulls a file based on a value that we **indirectly control**.

---

# 🔥 19. Complete LFI Attack Flow

```text
                         LFI
                          │
          ┌───────────────┴───────────────┐
          │                               │
     Direct Input                    Indirect Input
          │                               │
          ▼                               ▼
   ?language=...                    Stored value
          │                               │
          ▼                               ▼
    File path                       Database
          │                               │
          ▼                               ▼
   File inclusion                 Later functionality
          │                               │
          └───────────────┬───────────────┘
                          ▼
                   Unintended file
                          │
                          ▼
                    File disclosure
```

---

# ⭐ 20. LFI Techniques Summary

|Technique|Problem|Core Idea|
|---|---|---|
|**Basic LFI**|User controls file path|Supply a local file path|
|**Path Traversal**|Directory is prepended|Use relative traversal with `../`|
|**Filename Prefix**|String is added before input|Prefix changes the resulting path|
|**Appended Extension**|`.php` or another extension is added|Requested path becomes `<input>.php`|
|**Second-Order LFI**|Input is stored and used later|Poison a value that another function later uses as a file path|

---

# 🧠 21. Most Important Concepts

## 🔴 1. Basic LFI

Look for:

```text
User input → File path
```

---

## 🔴 2. Absolute Path

Example:

```text
/etc/passwd
```

This works when the complete user input reaches the inclusion function without additional path manipulation.

---

## 🔴 3. Path Traversal

Remember:

```text
../
```

means:

> **Parent directory**

Multiple levels:

```text
../../
../../../
../../../../
```

---

## 🔴 4. Prefixes Matter

If the application does:

```php
include("lang_" . $_GET['language']);
```

then your input becomes:

```text
lang_<input>
```

Always understand the **final path constructed by the application**.

---

## 🔴 5. Extensions Matter

If the application does:

```php
include($_GET['language'] . ".php");
```

then:

```text
/etc/passwd
```

becomes:

```text
/etc/passwd.php
```

---

## 🔴 6. Second-Order LFI

The malicious value may not reach the vulnerable function immediately.

It may follow:

```text
Input
 ↓
Database
 ↓
Later functionality
 ↓
File path
 ↓
LFI
```

---

# 📝 22. Practical Code-Review Mindset

Whenever you see something like:

```php
include(...)
```

don't immediately assume the vulnerability.

Trace **where the argument comes from**.

For example:

```php
include($_GET['language']);
```

Ask:

```text
Where does language come from?
        ↓
Can the user control it?
        ↓
Is anything prepended?
        ↓
Is anything appended?
        ↓
Is it normalized?
        ↓
Does traversal work?
        ↓
Does the function read or execute?
```

---

# 🎯 23. Quick Revision

### What is the basic LFI objective?

To make the application read the contents of an unintended **local file** on the back-end server.

### What is `/etc/passwd`?

A commonly readable Linux file mentioned in the material.

### What does `../` mean?

Move to the **parent directory**.

### Why use path traversal?

To escape a directory that the application prepends to the user-controlled filename.

### Why can a filename prefix break traversal?

Because the resulting path becomes something like:

```text
lang_../../../etc/passwd
```

instead of:

```text
../../../etc/passwd
```

### Why can an appended `.php` break LFI?

Because:

```text
/etc/passwd
```

becomes:

```text
/etc/passwd.php
```

### What is a Second-Order LFI?

An LFI where the attacker-controlled value is **stored first and used later** by another application functionality.

---

# 🧠 24. FINAL CHEAT SHEET

```text
╔══════════════════════════════════════════════════════════════╗
║                     LFI CHEAT SHEET                         ║
╠══════════════════════════════════════════════════════════════╣
║ BASIC LFI                                                   ║
║ User-controlled parameter → local file                     ║
║                                                            ║
║ Example:                                                   ║
║ ?language=/etc/passwd                                      ║
╠══════════════════════════════════════════════════════════════╣
║ PATH TRAVERSAL                                              ║
║ ../ = parent directory                                    ║
║                                                            ║
║ Example:                                                   ║
║ ../../../../etc/passwd                                    ║
╠══════════════════════════════════════════════════════════════╣
║ PREFIX                                                      ║
║ include("lang_" . $_GET['language']);                      ║
║                                                            ║
║ Input becomes:                                             ║
║ lang_<input>                                               ║
╠══════════════════════════════════════════════════════════════╣
║ APPENDED EXTENSION                                         ║
║ include($_GET['language'] . ".php");                       ║
║                                                            ║
║ /etc/passwd → /etc/passwd.php                              ║
╠══════════════════════════════════════════════════════════════╣
║ SECOND-ORDER LFI                                            ║
║ Input → Database → Later function → File path → LFI        ║
╠══════════════════════════════════════════════════════════════╣
║ ALWAYS ASK                                                  ║
║                                                            ║
║ 1. Where does the input come from?                         ║
║ 2. How is the final path constructed?                      ║
║ 3. Is a prefix added?                                       ║
║ 4. Is an extension added?                                   ║
║ 5. Can ../ traversal affect the path?                      ║
║ 6. Is the value used directly or indirectly?                ║
║ 7. Does the function READ or EXECUTE the file?              ║
╚══════════════════════════════════════════════════════════════╝
```

## ⭐ The one thing to remember

> **Don't look only at the payload/input. Look at the FINAL FILE PATH constructed by the application.**

For example:

```text
Input:
../../../etc/passwd

Application:
include("lang_" . INPUT . ".php")

Final path:
lang_../../../etc/passwd.php
```

Understanding that transformation is the key to understanding **Basic LFI, Path Traversal, Prefixes, Extensions, and Second-Order LFI**.

And the material notes that the techniques discussed in this section apply regardless of the particular back-end language or framework.