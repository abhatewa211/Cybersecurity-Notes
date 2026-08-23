![Image](https://images.openai.com/static-rsc-4/jCy_TsSiF8Wt-v-KSbjuK6EYUm0rvd0qTQ9eBSCYJKBrzFY6NB49UMezLj795dV_sF1uTmwB_Vq7uGaAcgwKbav1bl6Qi-ES1WpG3v5P7Tpr5kMqN48MQO9cERSZpvjheJDcEOOxMWMocrL0LlsxguZZUIagwdgOngS_mMDGINPYIFh1yRq_TcMVRwpLiOlh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ialz8rsKV_YtzMHtFFMeNQOPXjdjkH5z8snNfQPG63uMl3Q3xZJPFJuDrNZkgdKu7DgY8FER10YN_X4h0f3j3Xu0Ta2aO-AEvA2XFbVLJ2-jNgwNOCtgGAcYkzIB_wznOzAlmtZKk5xRcqG7Z0H9rlFPEIGUI3IWrRRHe1uAQKQCtIAtLuvD6Rl8hBXQOpGr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/30ptudjeXDGxlOkcFgmyfTS0TqToyK0vB1rZlbkPGSSgfxyFzI0SWiOWcgsAg3Y664Nx8_dzsy0t4h5mXX1ChsyShUbH6ZSNTufD3MHC8X7jwzCKCnrnRfK_nQrjn7xyevtYcK1wg4AQ18E3uTiGzgKGKg038S0uWx-b-Jomg9WtLSwIjDextEEB0AuU8UGf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gvy3J6MS1PaEKbW53cYYjn9w7aXnTnd27pJAPoLuRPt_VDRZ9NQ1kkLci21STEmjJMSfqQdwBgak0-doBpts24lJBNNuVa3BqpmebPlNKRl6qzsM7rmR2MQFmRDv4bb5MHgWawwJ_7UCHWEZTaUuCskdMQDOmf5kZRZiAEVZBFZUfHpVWCqNGr63xAWRJWHS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/r-s-YhvDjsxZADm-ANmvKxcU14-B9eO81H3QLQKeeLMp79gay5SAX_EHxsyD3X6XuEJUqb6BEmwwqUyhqXw6L_vXy5rZ_uASFejs1NZKNvtdKsGdtxRm11QQ_DIOnAiQ2Af2UV1PEFGmIfPXbmCZ1ciurgIhrKHgEN5eArwZ9EXKR8lS4x62iby0M6yJO0EO?purpose=fullsize)
# 1. Introduction

We will start by learning the basics of using **`ffuf`** to fuzz websites for directories.

The basic situation is:

```text
http://SERVER_IP:PORT
```

When visiting the target website, we may see a simple page such as:

```text
+--------------------------------------+
|                                      |
|       Welcome to HTB Academy         |
|                                      |
+--------------------------------------+
```

The website may have:

- No links
    
- No navigation
    
- No useful information
    
- No obvious directories
    
- No information that leads us to other pages
    

Therefore, it looks like our only option is to **fuzz the website**.

---

# 2. What is Fuzzing?

The term **fuzzing** refers to a testing technique that sends various types of user input to a certain interface to study how it reacts.

The type of input depends on what we are testing.

For example:

### SQL Injection Fuzzing

We could send special characters and SQL-related payloads:

```text
'
"
'
' OR 1=1--
```

and observe how the application responds.

---

### Buffer Overflow Fuzzing

We could send increasingly long strings:

```text
AAAA
AAAAAAAAAA
AAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
```

and observe whether and when the application crashes or behaves unexpectedly.

---

### Web Fuzzing

For web applications, we commonly use wordlists containing potentially interesting:

```text
Directories
Files
Endpoints
Parameters
Extensions
Virtual hosts
```

The goal is to determine which resources actually exist.

---

# 3. Why Do We Need Web Fuzzing?

Web servers normally don't provide us with a complete directory of every available:

- Page
    
- Directory
    
- File
    
- Endpoint
    
- Virtual host
    

For example, a website might contain:

```text
/
├── index.php
├── login.php
├── admin/
├── backup/
├── uploads/
├── api/
└── dev/
```

But the homepage may only contain:

```text
Home
About
Contact
```

We would have no obvious way of knowing that:

```text
/admin/
/backup/
/dev/
```

exist.

Therefore, we use **web fuzzing** to discover potentially hidden resources.

---

# 4. Basic Web Fuzzing Concept

Suppose we have:

```text
http://SERVER_IP:PORT/
```

We can take a wordlist:

```text
admin
login
backup
uploads
images
dashboard
test
dev
api
```

and insert each word into the URL.

For example:

```text
http://SERVER_IP:PORT/admin
http://SERVER_IP:PORT/login
http://SERVER_IP:PORT/backup
http://SERVER_IP:PORT/uploads
http://SERVER_IP:PORT/images
http://SERVER_IP:PORT/dashboard
```

The server responds to every request.

We then analyze the responses to determine which resources are likely to exist.

---

# 5. HTTP Status Codes

One of the most important concepts in web fuzzing is understanding HTTP response codes.

## `404 Not Found`

If we visit:

```text
https://www.hackthebox.eu/doesnotexist
```

we would receive:

```text
HTTP/1.1 404 Not Found
```

This generally indicates that the requested resource doesn't exist.

Conceptually:

```text
Client
  |
  | GET /doesnotexist
  |
  v
Web Server
  |
  | 404 Not Found
  v
Client
```

---

# 6. `200 OK`

If we visit an existing page such as:

```text
/login
```

the server may return:

```text
HTTP/1.1 200 OK
```

and provide the requested page.

Conceptually:

```text
Client
  |
  | GET /login
  |
  v
Web Server
  |
  | 200 OK
  | Login Page
  v
Client
```

This is the basic idea behind web fuzzing.

We send many possible paths and look at how the server responds.

---

# 7. Basic Fuzzing Logic

The process can be represented as:

```text
              WORDLIST
                  |
                  v
        +-------------------+
        |      ffuf         |
        +-------------------+
                  |
          Insert each word
             into FUZZ
                  |
                  v
        http://TARGET/FUZZ
                  |
                  v
             Web Server
                  |
        +---------+---------+
        |                   |
        v                   v
      200 OK              404
        |                   |
        v                   v
  Investigate            Ignore
```

For example:

```text
Wordlist:

admin
login
backup
test
uploads
```

ffuf generates:

```text
/admin
/login
/backup
/test
/uploads
```

---

# 8. Why Can't We Do This Manually?

Imagine a wordlist containing:

```text
10,000 words
```

Manually testing:

```text
http://TARGET/admin
http://TARGET/login
http://TARGET/backup
...
```

would be extremely slow.

Even if each request took only one second:

```text
10,000 requests × 1 second
= 10,000 seconds
```

which is approximately:

```text
166 minutes
≈ 2.8 hours
```

And real-world wordlists can contain far more entries.

Therefore, automated tools are much more efficient.

---

# 9. Ffuf

**ffuf** is a fast web fuzzing tool.

It automates the process of:

```text
Generate request
      ↓
Send request
      ↓
Receive response
      ↓
Analyze response
      ↓
Display interesting result
```

It can send many requests very quickly and allows us to filter results based on characteristics such as:

- HTTP status code
    
- Response size
    
- Word count
    
- Line count
    

---

# 10. The `FUZZ` Keyword

The most important concept to understand when using ffuf is:

```text
FUZZ
```

`FUZZ` represents the position where ffuf should insert each word from the wordlist.

Example:

```bash
ffuf -w wordlist.txt:FUZZ -u http://TARGET/FUZZ
```

If the wordlist contains:

```text
admin
login
backup
```

ffuf effectively tests:

```text
http://TARGET/admin
http://TARGET/login
http://TARGET/backup
```

### Remember

```text
-w = wordlist
FUZZ = insertion point
-u = target URL
```

---

# 11. Wordlists

To determine which pages exist, we need a **wordlist** containing commonly used words for web directories and pages.

This is similar to a:

> **Password Dictionary Attack**

In a password dictionary attack, we have:

```text
password
123456
admin
qwerty
...
```

For web fuzzing, the dictionary contains possible:

```text
admin
login
dashboard
backup
uploads
api
test
dev
...
```

---

# 12. Why Wordlists Are Important

A wordlist determines what ffuf will test.

For example:

```text
Small wordlist
       ↓
Fewer requests
       ↓
Faster scan
       ↓
Potentially fewer discoveries
```

Whereas:

```text
Large wordlist
       ↓
More requests
       ↓
Slower scan
       ↓
Potentially more discoveries
```

Therefore, wordlist selection is an important part of web enumeration.

---

# 13. Limitations of Wordlists

A wordlist cannot discover everything.

For example, suppose a website has:

```text
/company-secret-project-x9/
```

If that exact name isn't present in our wordlist, ffuf won't magically discover it through simple directory fuzzing.

Therefore:

> **Wordlist-based fuzzing is only as good as the words being tested.**

The HTB material notes that common wordlists can achieve very high coverage on some websites, but they won't guarantee discovery of every resource.

---

# 14. SecLists

We don't need to manually create our own wordlists.

The security community has already created large collections of useful wordlists.

One of the most important collections is:

**SecLists**

SecLists contains wordlists for many security testing purposes, including:

```text
Web Content Discovery
DNS Enumeration
Usernames
Passwords
Fuzzing
Payloads
File names
Directories
Parameters
```

The repository is available on GitHub:

[SecLists — GitHub repository](https://github.com/danielmiessler/SecLists?utm_source=chatgpt.com)

---

# 15. SecLists on PwnBox

Within the HTB PwnBox environment, the SecLists repository is available under:

```text
/opt/useful/SecLists
```

The specific web-content wordlists can be found under:

```text
/opt/useful/seclists/Discovery/Web-Content/
```

Notice that Linux paths are **case-sensitive**.

Depending on the environment, you may encounter:

```text
/opt/useful/SecLists/
```

or:

```text
/opt/useful/seclists/
```

Always verify the actual path on your machine.

---

# 16. Finding `directory-list-2.3-small.txt`

The HTB module uses the:

```text
directory-list-2.3-small.txt
```

wordlist.

We can locate it with:

```bash
locate directory-list-2.3-small.txt
```

Example output:

```text
/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

This is a commonly used wordlist for web content discovery.

---

# 17. Directory-List Variants

The `directory-list-2.3` wordlist comes in different forms and sizes.

The general idea is:

```text
Small
  ↓
Fast initial scan

Medium
  ↓
More comprehensive

Large
  ↓
Much more extensive
```

### Practical approach

Start with:

```text
directory-list-2.3-small.txt
```

If you don't find anything useful, consider a larger wordlist.

This prevents unnecessarily large scans at the beginning of enumeration.

---

# 18. Inspecting the Wordlist

We can examine the wordlist using:

```bash
head /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

or:

```bash
less /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

You may notice entries such as:

```text
# Copyright ...
# This work is licensed ...
admin
login
images
uploads
backup
```

The lines beginning with `#` are comments.

---

# 19. The `-ic` Option

This is an important point from the HTB module.

The wordlist contains **copyright comments at the beginning**.

These comments can be treated as entries and clutter the fuzzing results.

ffuf provides the:

```text
-ic
```

option.

`-ic` means:

> **Ignore comments**

So instead of processing comment lines as potential directory names, ffuf skips them.

---

# 20. Basic Ffuf Directory Fuzzing Command

The basic command is:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

With comment lines ignored:

```bash
ffuf -ic \
-w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

The structure is:

```text
ffuf
 │
 ├── -ic
 │     └── ignore comments
 │
 ├── -w
 │     └── wordlist
 │
 └── -u
       └── target URL
```

---

# 21. What Happens Internally?

Suppose our wordlist contains:

```text
admin
login
backup
uploads
```

and our command is:

```bash
ffuf -w wordlist.txt:FUZZ -u http://TARGET/FUZZ
```

ffuf sends requests equivalent to:

```http
GET /admin HTTP/1.1
Host: TARGET
```

```http
GET /login HTTP/1.1
Host: TARGET
```

```http
GET /backup HTTP/1.1
Host: TARGET
```

```http
GET /uploads HTTP/1.1
Host: TARGET
```

The server responds to each.

ffuf then displays interesting responses.

---

# 22. Example Ffuf Output

You might see:

```text
admin       [Status: 301, Size: 312, Words: 20, Lines: 10]
login       [Status: 200, Size: 5421, Words: 834, Lines: 120]
backup      [Status: 403, Size: 278, Words: 20, Lines: 10]
```

Interpretation:

### `admin`

```text
301
```

Likely indicates a redirect.

Investigate it.

### `login`

```text
200
```

The resource returned successfully.

Definitely investigate it.

### `backup`

```text
403
```

Access is forbidden.

But the result may still be valuable because the resource may exist.

---

# 23. Important — Don't Only Search for `200`

A common beginner mistake is:

> "I'll only look at 200 responses."

That's not always correct.

Interesting responses include:

```text
200 OK
301 Moved Permanently
302 Found
401 Unauthorized
403 Forbidden
405 Method Not Allowed
```

For example:

```text
/admin → 403
```

can be much more interesting than a random:

```text
/test → 200
```

depending on the application's behavior.

Always investigate unusual responses.

---

# 24. Understanding `404`

The most common baseline response is:

```text
404 Not Found
```

For example:

```text
http://TARGET/doesnotexist
```

might return:

```text
HTTP/1.1 404 Not Found
```

Therefore, during fuzzing:

```text
admin → 404
login → 404
backup → 404
test → 404
```

usually means those entries didn't produce a distinct resource.

However, **never blindly assume `404` means "not interesting"** without understanding the target's behavior.

Some applications use:

```text
200
```

for custom error pages.

---

# 25. False Positives

Web fuzzing can produce false positives.

For example, imagine every nonexistent page returns:

```text
HTTP/1.1 200 OK
```

with:

```text
Size: 5000
```

Then:

```text
/admin
/login
/backup
/xyz123
```

could all return:

```text
200
Size: 5000
```

This doesn't mean all of them exist.

They may simply be receiving the same custom error page.

Therefore:

> **Always understand the baseline response before trusting fuzzing results.**

---

# 26. Establishing a Baseline

Before a large fuzzing scan, request a random path:

```bash
curl -i http://SERVER_IP:PORT/thisshouldnotexist12345
```

Record:

```text
HTTP status
Response size
Words
Lines
Redirect behavior
```

Example:

```text
Status: 404
Size: 4210
Words: 500
Lines: 80
```

Now you know what the target does when it receives an invalid path.

This information helps you configure ffuf filters later.

---

# 27. The Complete Basic Workflow

A clean web fuzzing workflow looks like:

```text
               Target
                  │
                  ▼
          Visit Website
                  │
                  ▼
        No useful links?
                  │
                 YES
                  │
                  ▼
       Establish baseline
                  │
                  ▼
         Select wordlist
                  │
                  ▼
            Run ffuf
                  │
                  ▼
       Analyze responses
                  │
        ┌─────────┼─────────┐
        ▼         ▼         ▼
       200       301       403
        │         │         │
        └─────────┼─────────┘
                  ▼
       Manually investigate
                  │
                  ▼
        Continue enumeration
```

---

# 28. Example: Complete Command

For the HTB exercise:

```bash
ffuf -ic \
-w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

### Breakdown

```text
ffuf
```

Runs ffuf.

```text
-ic
```

Ignores comments in the wordlist.

```text
-w
```

Specifies the wordlist.

```text
...directory-list-2.3-small.txt:FUZZ
```

Maps the wordlist to the `FUZZ` keyword.

```text
-u
```

Specifies the target URL.

```text
http://SERVER_IP:PORT/FUZZ
```

Places each word from the wordlist into the URL.

---

# 29. Mental Model to Memorize

Remember this:

```text
                 WORDLIST
                     │
                     ▼
             +---------------+
             |     FFUF      |
             +---------------+
                     │
                     ▼
                  FUZZ
                     │
                     ▼
            http://TARGET/FUZZ
                     │
                     ▼
                WEB SERVER
                     │
           ┌─────────┴─────────┐
           ▼                   ▼
        Resource             Resource
         exists             doesn't exist
           │                   │
           ▼                   ▼
       200/301/403             404
           │                   │
           ▼                   ▼
      Investigate             Ignore
```

---

# 30. Important Commands

### Locate wordlist

```bash
locate directory-list-2.3-small.txt
```

### View beginning of wordlist

```bash
head directory-list-2.3-small.txt
```

### View entire wordlist interactively

```bash
less directory-list-2.3-small.txt
```

### Basic ffuf

```bash
ffuf -w wordlist.txt:FUZZ -u http://TARGET/FUZZ
```

### Ignore comments

```bash
ffuf -ic -w wordlist.txt:FUZZ -u http://TARGET/FUZZ
```

### Establish baseline

```bash
curl -i http://TARGET/random-nonexistent-page
```

---

# 31. Key Concepts for HTB

### Fuzzing

Sending many inputs to an interface and observing its responses.

### Web fuzzing

Using wordlists to discover web resources such as:

```text
Directories
Files
Pages
Endpoints
Parameters
Vhosts
```

### Wordlist

A collection of potential values that ffuf tests.

### `FUZZ`

The position where ffuf inserts wordlist entries.

### SecLists

A large collection of security-related wordlists.

### `directory-list-2.3-small.txt`

A commonly used web-content discovery wordlist.

### `-ic`

Tells ffuf to ignore comments in the wordlist.

### `200`

Usually indicates a successful HTTP response.

### `404`

Usually indicates that the requested resource was not found.

### `403`

Access is forbidden, but the resource may still exist.

---

# 32. Common Beginner Mistakes

## Mistake 1 — Forgetting `FUZZ`

Incorrect:

```bash
ffuf -w wordlist.txt -u http://TARGET/
```

Correct:

```bash
ffuf -w wordlist.txt:FUZZ -u http://TARGET/FUZZ
```

---

## Mistake 2 — Using the wrong wordlist

A password wordlist is not normally appropriate for directory discovery.

Use a web-content wordlist such as:

```text
directory-list-2.3-small.txt
```

---

## Mistake 3 — Ignoring false positives

Don't assume:

```text
200 = definitely exists
```

First understand the baseline.

---

## Mistake 4 — Ignoring `403`

A `403` response can indicate an interesting existing resource.

---

## Mistake 5 — Starting with enormous wordlists

Start small:

```text
small → medium → large
```

This makes enumeration faster and easier to analyze.

---

# 33. Exam / Viva Questions

### Q1. What is fuzzing?

Fuzzing is a testing technique that sends different inputs to an interface and observes how it reacts.

---

### Q2. Why is web fuzzing useful?

It can discover hidden directories, files, endpoints, parameters, and other web resources that aren't linked from the application's visible pages.

---

### Q3. What does `FUZZ` mean in ffuf?

`FUZZ` identifies the location where ffuf should insert values from the supplied wordlist.

---

### Q4. What does `-w` do?

It specifies the wordlist that ffuf should use.

---

### Q5. What does `-u` do?

It specifies the target URL.

---

### Q6. What does `-ic` do?

It tells ffuf to ignore comments in the wordlist.

---

### Q7. Why are wordlists important?

They provide the potential directory, file, parameter, or other values that ffuf will test.

---

### Q8. What is SecLists?

SecLists is a collection of security-related wordlists used for tasks such as web content discovery, DNS enumeration, username enumeration, password attacks, and fuzzing.

---

### Q9. What does HTTP `200` mean?

The request was successfully processed and a response was returned.

---

### Q10. What does HTTP `404` mean?

The requested resource was not found.

---

### Q11. Why shouldn't we ignore `403`?

Because a `403 Forbidden` response can indicate that a resource exists but access to it is restricted.

---

### Q12. Why establish a baseline?

To understand how the application responds to nonexistent resources and identify false positives during fuzzing.

---

# 34. Quick Revision Sheet

```text
WEB FUZZING
     │
     ├── Goal
     │    └── Discover hidden resources
     │
     ├── Tool
     │    └── ffuf
     │
     ├── Input
     │    └── Wordlist
     │
     ├── Placeholder
     │    └── FUZZ
     │
     ├── Wordlists
     │    └── SecLists
     │
     └── Important wordlist
          └── directory-list-2.3-small.txt
```

### Core command

```bash
ffuf -ic \
-w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

### Remember:

```text
-w  → Wordlist
-u  → URL
FUZZ → Injection point
-ic → Ignore comments
```

### Core methodology:

```text
Target
  ↓
Baseline
  ↓
Wordlist
  ↓
Ffuf
  ↓
HTTP responses
  ↓
Identify interesting results
  ↓
Manual verification
  ↓
Further enumeration
```

---

# 35. Golden Rule

> **Ffuf does not tell you that something is vulnerable. It helps you discover things that deserve investigation.**

The correct mindset is:

```text
Fuzz → Discover → Verify → Enumerate → Assess
```

not:

```text
Fuzz → See 200 → Assume vulnerability
```

This distinction becomes increasingly important as we move from basic directory fuzzing into **files, extensions, virtual hosts, parameters, and parameter values**.