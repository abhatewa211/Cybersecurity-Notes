![Image](https://images.openai.com/static-rsc-4/xt4-COzJMzMgQipFW0z08PAyrJ6NNdlkSBUhc1oS2sq5Xj4OXSjsFpaUTGnMAldwkfk-YgTYdxkpxUTi_7LOECMSX0cxAY-65vM01rLbTRPgJ9g3rAOrmuZCGqTm51S0rda3vTyXaEyWBsSfZmMyoQ-xfTvz2Bdv5Uy9Zv8glfwQRWpsiJTRJI02KI7_BqXi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/WJQFCU3yJTUXaelIzk3SarYhUbezS6OVHqYvsfCi1fYBK7DRi-OVLC0IBcV_QAVtYWrZQpa14RPivvMzEff1_ZuWbFvX8HSvm6aWVNr6RH6_R0_aipGNEZC-hiy5uIJXriLlu3NfQ4KUWQkTvl4BO8vfWIcI8y5WqLUGbflQRE_JvsrBxclXjXeQYMxZ0iPk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/baiUClTdo8lRArB6q4yjeLDnYdqujDrIfnh9SDdl1dbP13tMXVPvmopE_prP8obKMdcx_bqgnC4wOKeQ_S6t2lHJion4OA6fymTObIEIMDojI6r33HdPTjH1qzu5nei57AptXap806Kqfz37rsCWMRFkYkaYNdClxn1yhSXOrC6W-NNpqmpAsMNA-W346uh0?purpose=fullsize)

# 1. Introduction

We now understand the basic use of `ffuf` through the utilization of:

- Wordlists
    
- Keywords
    
- `FUZZ`
    
- Target URLs
    
- HTTP response codes
    

Next, we will learn how to use the same concepts to **locate pages/files** inside a discovered directory.

In the previous section, we discovered:

```text
/blog
```

When visiting:

```text
http://SERVER_IP:PORT/blog
```

we received an empty page.

There were:

- No visible links
    
- No obvious pages
    
- No useful navigation
    

Therefore, we need to perform **deeper enumeration**.

The process will be:

```text
Discovered /blog
       ↓
Find file extension
       ↓
Identify PHP
       ↓
Fuzz PHP filenames
       ↓
Discover hidden pages
       ↓
Manually investigate
```

---

# 2. Extension Fuzzing

Before searching for files, we need to determine what kind of files the website uses.

Common web extensions include:

```text
.html
.htm
.php
.asp
.aspx
.jsp
```

For example:

```text
/login.php
/login.aspx
/login.jsp
/login.html
```

We need to determine which extension is relevant to our target.

---

# 3. Why Does the Extension Matter?

Suppose we simply fuzz:

```text
http://TARGET/blog/FUZZ
```

and our wordlist contains:

```text
login
admin
dashboard
upload
```

We may miss:

```text
login.php
admin.php
dashboard.php
upload.php
```

if our wordlist only contains filenames without extensions.

Therefore, identifying the technology/extension first can make our next fuzzing stage much more efficient.

---

# 4. Identifying the Server Technology

One possible method is examining HTTP response headers.

For example:

```http
Server: Apache
```

or:

```http
Server: Microsoft-IIS
```

We may then make educated guesses.

For example:

```text
Apache
  ↓
Potential PHP application
```

or:

```text
IIS
  ↓
Potential ASP/ASPX application
```

However:

> **This is only a clue, not proof.**

Server software and application technology are not necessarily the same thing.

For example, Apache can serve:

```text
PHP
Python
Perl
Static HTML
Node.js
```

Therefore, relying solely on the server header isn't very practical.

---

# 5. Better Approach — Extension Fuzzing

Instead of guessing, we can use ffuf itself to determine which extensions appear valid.

This uses the same fuzzing concept we've already learned.

Previously:

```text
http://TARGET/FUZZ
```

was used to fuzz directory names.

Now we place:

```text
FUZZ
```

where the file extension should be.

Conceptually:

```text
indexFUZZ
```

If the wordlist contains:

```text
.php
.aspx
.jsp
.html
```

ffuf tests:

```text
index.php
index.aspx
index.jsp
index.html
```

---

# 6. Extension Wordlist

SecLists provides a useful wordlist for common web extensions:

```text
/opt/useful/seclists/Discovery/Web-Content/web-extensions.txt
```

We can use it with ffuf:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
-u http://SERVER_IP:PORT/blog/indexFUZZ
```

---

# 7. Why Use `index`?

We need some filename to attach the extension to.

For example:

```text
FUZZ.php
```

would fuzz the filename.

But at this stage, we're trying to discover the **extension**, not the filename.

Therefore, we need a filename we can reasonably expect to exist.

A common filename is:

```text
index
```

Many websites have:

```text
index.html
index.php
index.aspx
index.jsp
```

Therefore, we use:

```text
indexFUZZ
```

---

# 8. Important Detail — The Dot

The HTB wordlist already contains the dot.

For example:

```text
.php
.aspx
.jsp
.html
```

Therefore, we use:

```text
indexFUZZ
```

NOT:

```text
index.FUZZ
```

If the wordlist already contains:

```text
.php
```

then:

```text
indexFUZZ
```

becomes:

```text
index.php
```

---

# 9. Extension Fuzzing Command

The HTB command is:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
-u http://SERVER_IP:PORT/blog/indexFUZZ
```

### Breakdown

```text
-w
```

Specifies the extension wordlist.

```text
web-extensions.txt:FUZZ
```

Assigns the `FUZZ` keyword to the extension list.

```text
-u
```

Specifies the target.

```text
http://SERVER_IP:PORT/blog/indexFUZZ
```

Places the extension at the end of `index`.

---

# 10. What Requests Does Ffuf Generate?

Suppose the wordlist contains:

```text
.php
.phps
.aspx
.jsp
.html
```

ffuf effectively tests:

```text
/blog/index.php
/blog/index.phps
/blog/index.aspx
/blog/index.jsp
/blog/index.html
```

The server responds to each request.

---

# 11. Example Output

The HTB exercise produces results such as:

```text
.php       [Status: 200, Size: 0, Words: 1, Lines: 1]
.phps      [Status: 403, Size: 283, Words: 20, Lines: 10]
```

This tells us something important.

---

# 12. Interpreting `.php`

The result:

```text
.php [Status: 200]
```

means:

```text
/blog/index.php
```

returned a successful response.

Therefore, `.php` is a strong indication that PHP is being used.

---

# 13. Interpreting `.phps`

We also see:

```text
.phps [Status: 403]
```

This is interesting, but it isn't the same as the `.php` result.

The server is returning:

```text
403 Forbidden
```

which means access is forbidden.

It could indicate that the server recognizes or handles that extension, but we shouldn't automatically conclude that it represents an accessible application page.

The key result for this exercise is:

```text
.php → 200
```

---

# 14. Why `200` Matters Here

We want to find an extension that produces a meaningful successful response.

The result:

```text
.php → 200
```

suggests that:

```text
/blog/index.php
```

exists and is accessible.

This gives us a useful direction:

> **The application appears to use PHP.**

Now we can focus our page discovery on:

```text
*.php
```

---

# 15. Important Distinction

Don't think:

```text
.php → 200
```

means:

> "Every PHP file exists."

It only establishes that the target responds successfully to that particular tested path.

For example:

```text
/blog/index.php → 200
/blog/login.php → 404
/blog/admin.php → 404
```

Only the discovered resource is confirmed.

---

# 16. Page Fuzzing

Now that we have identified:

```text
.php
```

we can begin fuzzing for PHP pages.

The concept is similar to directory fuzzing.

Previously:

```text
http://TARGET/FUZZ
```

Now:

```text
http://TARGET/FUZZ.php
```

The `FUZZ` keyword represents the **filename**.

---

# 17. Page Fuzzing Command

The HTB command is:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/blog/FUZZ.php
```

Here we reuse the same directory wordlist:

```text
directory-list-2.3-small.txt
```

but now the words represent possible **filenames**.

---

# 18. What Does `FUZZ.php` Mean?

Suppose the wordlist contains:

```text
index
login
admin
config
dashboard
upload
```

ffuf effectively tests:

```text
/blog/index.php
/blog/login.php
/blog/admin.php
/blog/config.php
/blog/dashboard.php
/blog/upload.php
```

This is why the position of `FUZZ` is so important.

---

# 19. Extension Fuzzing vs Page Fuzzing

These two stages are easy to confuse.

## Extension fuzzing

We know the filename:

```text
index
```

and fuzz the extension:

```text
indexFUZZ
```

Example:

```text
index.php
index.aspx
index.jsp
```

---

## Page fuzzing

We know the extension:

```text
.php
```

and fuzz the filename:

```text
FUZZ.php
```

Example:

```text
login.php
admin.php
dashboard.php
```

### Mental model

```text
Extension discovery:

index + FUZZ
        ↓
index.php


Page discovery:

FUZZ + .php
        ↓
admin.php
```

---

# 20. Example Ffuf Output

The HTB scan returns:

```text
index       [Status: 200, Size: 0, Words: 1, Lines: 1]
REDACTED    [Status: 200, Size: 465, Words: 42, Lines: 15]
```

There are two important discoveries.

---

# 21. `index.php`

The result:

```text
index [Status: 200, Size: 0]
```

means:

```text
/blog/index.php
```

returned:

```text
HTTP 200
```

but the response size is:

```text
0 bytes
```

So the page appears to be empty.

This explains why visiting:

```text
/blog/
```

didn't visibly show anything useful.

The directory may be serving an empty `index.php`.

---

# 22. The Second PHP Page

The other discovery returns:

```text
Status: 200
Size: 465
Words: 42
Lines: 15
```

This is much more interesting.

Unlike:

```text
index.php → Size 0
```

the second file contains actual content.

Therefore, this page deserves manual investigation.

---

# 23. Why Response Size Matters

Consider:

```text
index.php       → 0 bytes
admin.php       → 465 bytes
```

Both return:

```text
200 OK
```

But the response sizes tell us they behave differently.

This is why ffuf displays:

```text
Status
Size
Words
Lines
```

A status code alone doesn't always tell the complete story.

---

# 24. Visiting the Discovered Page

Once ffuf finds:

```text
REDACTED.php
```

we manually visit:

```text
http://SERVER_IP:PORT/blog/REDACTED.php
```

The HTB exercise shows an **admin panel-related page**.

This demonstrates the purpose of page fuzzing:

```text
Hidden page
     ↓
Not linked from /blog
     ↓
Ffuf discovers it
     ↓
Manual browsing reveals functionality
```

---

# 25. The Importance of Manual Verification

Ffuf is an enumeration tool.

It does not replace manual analysis.

If ffuf reports:

```text
admin.php [Status: 200]
```

you need to inspect:

```text
/blog/admin.php
```

Questions to ask include:

```text
What does the page do?
Is authentication required?
Are there forms?
Are there parameters?
Does it expose information?
Does it link to additional resources?
What technologies does it use?
```

The discovery is the beginning of the investigation, not the end.

---

# 26. Two-Stage Fuzzing Workflow

This section demonstrates an important methodology:

```text
Stage 1
Directory Discovery
       ↓
/blog
       ↓
Stage 2
Extension Discovery
       ↓
.php
       ↓
Stage 3
Page Discovery
       ↓
FUZZ.php
       ↓
Hidden PHP page
       ↓
Manual Investigation
```

This is a very useful mental model for HTB labs.

---

# 27. Why Not Fuzz Everything at Once?

Technically, you could create more complex fuzzing combinations.

For example:

```text
FUZZ1.FUZZ2
```

where:

```text
FUZZ1 = filename
FUZZ2 = extension
```

However, this can create a massive number of requests.

For example:

```text
10,000 filenames
×
40 extensions
=
400,000 requests
```

Instead, we can reduce the search space intelligently:

```text
Discover extension
       ↓
PHP
       ↓
Only search *.php
```

This is much more efficient.

---

# 28. Multiple FUZZ Keywords

Ffuf supports multiple keywords.

For example:

```text
FUZZ_1.FUZZ_2
```

could represent:

```text
filename.extension
```

with separate wordlists.

Conceptually:

```text
FUZZ_1 = index
FUZZ_2 = .php
```

produces:

```text
index.php
```

However, the number of combinations can grow very quickly.

Therefore, use targeted fuzzing where possible.

---

# 29. Important Wordlists

### Directory/file names

```text
/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

### Web extensions

```text
/opt/useful/seclists/Discovery/Web-Content/web-extensions.txt
```

The first is used for:

```text
directories
filenames
```

The second is used for:

```text
extensions
```

---

# 30. Complete Command Sequence

## Step 1 — Find directories

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

Discover:

```text
/blog
```

---

## Step 2 — Find extension

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
-u http://SERVER_IP:PORT/blog/indexFUZZ
```

Discover:

```text
.php
```

---

## Step 3 — Find PHP pages

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/blog/FUZZ.php
```

Discover:

```text
index.php
REDACTED.php
```

---

## Step 4 — Manually investigate

Visit:

```text
http://SERVER_IP:PORT/blog/REDACTED.php
```

---

# 31. Why This Is More Efficient

Instead of testing:

```text
admin.html
admin.php
admin.aspx
admin.jsp
admin.asp
...
```

for every possible filename, we first establish that PHP appears relevant.

Then:

```text
FUZZ.php
```

reduces the search space.

This is an example of **enumeration based on evidence**.

---

# 32. Important Lesson: Don't Blindly Trust Server Headers

The module mentions using server headers as a way to make an extension guess.

For example:

```text
Apache → maybe PHP
IIS → maybe ASP/ASPX
```

But remember:

> **The web server software does not necessarily determine the application's programming language.**

Therefore, extension fuzzing is useful because it provides actual evidence from the target's responses rather than relying solely on assumptions.

---

# 33. Common Mistakes

## Mistake 1 — Using `index.FUZZ`

If the extension wordlist already contains the dot:

```text
.php
```

then:

```text
indexFUZZ
```

produces:

```text
index.php
```

Using:

```text
index.FUZZ
```

would produce:

```text
index..php
```

which is incorrect.

---

## Mistake 2 — Fuzzing `FUZZ` without the extension

After identifying PHP, don't go back to:

```text
/blog/FUZZ
```

if your goal is specifically PHP page discovery.

Use:

```text
/blog/FUZZ.php
```

---

## Mistake 3 — Assuming every 200 response contains useful content

Example:

```text
index.php → 200 → Size 0
```

The page exists but is empty.

Compare response characteristics, not just status codes.

---

## Mistake 4 — Ignoring 403

For extension fuzzing:

```text
.phps → 403
```

is still an observation worth noting.

But don't treat it as equivalent to an accessible `200`.

---

# 34. Exam / Viva Questions

### Q1. Why do we perform extension fuzzing?

To determine which file extensions are used by the target web application.

---

### Q2. What wordlist is used for extension fuzzing in this module?

```text
/opt/useful/seclists/Discovery/Web-Content/web-extensions.txt
```

---

### Q3. Why do we use `index` during extension fuzzing?

`index` is a commonly found filename on websites, making it a useful known filename for testing different extensions.

---

### Q4. Why is the command `indexFUZZ` rather than `index.FUZZ`?

Because the extension wordlist already contains the dot, such as:

```text
.php
```

---

### Q5. What does `.php → 200` tell us?

It indicates that the tested PHP resource returned a successful response and provides evidence that PHP is used by the application.

---

### Q6. What does `FUZZ.php` mean?

`FUZZ` represents the filename while `.php` is fixed as the extension.

---

### Q7. What wordlist is reused for PHP page fuzzing?

```text
directory-list-2.3-small.txt
```

---

### Q8. Why can we reuse a directory wordlist for page fuzzing?

Because the words in a directory wordlist can also represent common filenames such as:

```text
login
admin
index
dashboard
upload
```

---

### Q9. What is the difference between extension fuzzing and page fuzzing?

Extension fuzzing:

```text
indexFUZZ
```

finds the extension.

Page fuzzing:

```text
FUZZ.php
```

finds the filename.

---

### Q10. Why is a `200` response with size `0` less interesting than a `200` response with size `465`?

Both resources returned successfully, but the first appears to contain no meaningful response body, while the second contains actual content.

---

# 35. Quick Revision

```text
                PAGE FUZZING
                     │
                     ▼
                /blog found
                     │
                     ▼
             Directory is empty
                     │
                     ▼
            Extension Fuzzing
                     │
                     ▼
               indexFUZZ
                     │
                     ▼
                 .php → 200
                     │
                     ▼
               PHP identified
                     │
                     ▼
               Page Fuzzing
                     │
                     ▼
                 FUZZ.php
                     │
                     ▼
             Hidden PHP pages
                     │
                     ▼
             Manual investigation
```

---

# 36. Essential Commands

### Extension fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
-u http://SERVER_IP:PORT/blog/indexFUZZ
```

### PHP page fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/blog/FUZZ.php
```

### Multiple keyword concept

```text
FUZZ_1.FUZZ_2
```

---

# 37. The Three Commands to Remember

```text
1. Directory:

http://TARGET/FUZZ
```

```text
2. Extension:

http://TARGET/indexFUZZ
```

```text
3. Page:

http://TARGET/FUZZ.php
```

### Mental model

```text
Directory:
     FUZZ

Extension:
     index + FUZZ

Filename:
     FUZZ + .php
```

---

# 38. Golden Methodology

The important lesson from this section is **don't fuzz blindly**.

Instead:

```text
Find directory
      ↓
Understand response
      ↓
Determine extension
      ↓
Use known extension
      ↓
Fuzz filenames
      ↓
Compare response characteristics
      ↓
Manually verify
```

This approach dramatically reduces unnecessary requests and makes your enumeration more systematic.

---

# 39. Final Takeaways

> **Extension fuzzing helps determine which file extensions are supported or present on the target.**

> **The `web-extensions.txt` SecLists wordlist contains common web extensions.**

> **`indexFUZZ` is used when the extension is being fuzzed.**

> **If the wordlist already contains the dot, don't add another dot.**

> **Once `.php` is identified, use `FUZZ.php` to search for PHP pages.**

> **A directory wordlist can also be useful for filename discovery.**

> **A `200` response confirms a successful response, but response size and content must also be examined.**

> **An empty `index.php` doesn't mean the directory is empty.**

> **The interesting PHP page discovered through fuzzing should be manually investigated.**

The core workflow is:

```text
Directory
   ↓
Extension
   ↓
Filename
   ↓
Page
   ↓
Content
   ↓
Further Enumeration
```

This is the foundation for the next stages of web enumeration, where we can start looking beyond filenames and directories toward **parameters and parameter values**.