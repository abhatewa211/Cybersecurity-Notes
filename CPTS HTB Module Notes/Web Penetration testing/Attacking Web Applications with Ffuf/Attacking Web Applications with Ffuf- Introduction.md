![Image](https://images.openai.com/static-rsc-4/VZE95xIA7HtamTbVn1Lnlz9Qfnp7d5QGTUOSUTlT-1R9uRXoqHtHn96JzWaPIaatpZe8AE3Tf-BQ2KBs7KztOuDtmDEmAp-EVgmWsW7gZIwy6UQ60EcFjphP7JAwcbwCgTj_xrJIKQBpa2LcVxBlPrVb1I_UFMyCrfzETIQpcwlBhAnqaDw-9Svvc9ewu-By?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ld5DPiB4VMaPe6COw1GEMZYW32cCn24H9QnuIdBsc17QRAkQ5aSaat0EcsEk1m9VG-S5xf5irGPhZuRl5xAgBfR6dsDKcsQrIoneBOeYp9jVVtS_7gMsMw-wF3iaJkowQMUgqMZuQ725S3EiypPidQ4QcUJJoeOENJgppWqSQqOIQkicQKE6a7m4r2wzuziI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zxqfkxV_rvNEM_Ezl_K3HPIqwZWxVgxcDr_E-GFrL7aH2UfqbyUQrmsLrbfGGVG1FmwGaDGKKN40c2ipPVP2tYPhwbrkDkILDGyjyfQm6C4Wm9nj0fxGO3mSF4XYOhWzawTfn6Ogop5qH3ohoalcyB4pSHG3bln3QuGg4t8cH5EtPDEZumYKV7HqObha9FGv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eymWqPGsX-2-z_br1CXCbv6K5RSZ6hbTk2B1Jo1mXIBVTzCY2VEf3XyOjizKCwGeAJEeZAy1ViYD-G1DMj9Pray_f3VbCXPSkesDOzymkb-62p0k1bd8HNzbUg_9Wpr0DMO5BjjdNMQCAtL9KP5dgopZhA2dIiFEFLeNlyB7z0X_DQWz3dpvqDr8APGjEyqx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ryq_mVqawdU13daH5PAAUDAWvJAMZyPhF835rJ5mYugD8oZiqoddFSyMfQAC0kiUTgRaBthlQj9FxIyixCoGVXzhHf_UDiki31_YoO_yGQPucbf7QElIYuJ2xTBgk6-sKhgG3evYL3-C2qBzZHgYnrIF5fTQMzqU6oxnt1m-SJaDIRXM_Fy1c7mEPJAKuHbt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EuL_KQbDDY49d6FFwwS_LpNQn2LtCMLrY9CcpW4cUyZUH8gSklqj6O_P_SBrv8MkroFd-w1YJNjUhwAEgrOMBIgzPlyHE3871ekHaON1VRMx4UAoQFe4N46mfg3_3UnYEwB2_VfzcTVJpSgQTpMI3URk1X5o-cRLl6gPMvBKn6oZJ6uQ6r2omCwhmX22KZxi?purpose=fullsize)

# 1. Introduction

Welcome to the **Attacking Web Applications with Ffuf** module!

There are many tools and methods to utilize for **directory and parameter fuzzing/brute-forcing**. In this module we will mainly focus on the **ffuf** tool for web fuzzing, as it is one of the most common and reliable tools available for web fuzzing.

The following topics will be discussed:

- Fuzzing for directories
    
- Fuzzing for files and extensions
    
- Identifying hidden vhosts
    
- Fuzzing for PHP parameters
    
- Fuzzing for parameter values
    

Tools such as `ffuf` provide us with a handy automated way to fuzz the web application's individual components or a web page.

This means, for example, that we use a list that is used to send requests to the webserver if the page with the name from our list exists on the webserver.

If we get a response code **200**, then we know that this page exists on the webserver, and we can look at it manually.

> **Important:** A `200` response is not the only useful result. `301`, `302`, `401`, `403`, `405`, and sometimes other responses can also reveal interesting resources.

---

# 2. What is Fuzzing?

**Fuzzing** is the process of automatically sending a large number of specially selected inputs to an application and observing how the application responds.

In web penetration testing, fuzzing can be used to discover:

- Hidden directories
    
- Hidden files
    
- Backup files
    
- Configuration files
    
- API endpoints
    
- Parameters
    
- Parameter values
    
- Virtual hosts
    
- Subdomains
    
- Different file extensions
    
- Hidden functionality
    

Instead of manually trying:

```text
/admin
/login
/backup
/config
/uploads
/dashboard
```

we can provide ffuf with a wordlist containing thousands of possible values.

ffuf then automatically tests them.

---

# 3. The Core Concept — `FUZZ`

The most important concept in ffuf is the keyword:

```text
FUZZ
```

`FUZZ` represents the location where ffuf should insert entries from the wordlist.

For example:

```bash
ffuf -w wordlist.txt:FUZZ -u http://TARGET/FUZZ
```

If the wordlist contains:

```text
admin
login
backup
uploads
images
```

ffuf effectively sends requests such as:

```text
http://TARGET/admin
http://TARGET/login
http://TARGET/backup
http://TARGET/uploads
http://TARGET/images
```

### Remember

> **Wordlist = possible inputs**

> **FUZZ = insertion point**

> **Target = application being tested**

---

# 4. Basic Ffuf Syntax

The basic structure is:

```bash
ffuf -w <WORDLIST> -u <URL>
```

Example:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
-u http://10.10.10.10/FUZZ
```

### Important options

|Option|Meaning|
|---|---|
|`-w`|Wordlist|
|`-u`|Target URL|
|`-X`|HTTP method|
|`-H`|HTTP header|
|`-d`|POST/request body data|
|`-e`|Extensions|
|`-mc`|Match status codes|
|`-fc`|Filter status codes|
|`-fs`|Filter response size|
|`-fw`|Filter response word count|
|`-fl`|Filter response line count|
|`-t`|Number of concurrent threads|
|`-rate`|Requests per second|
|`-o`|Output file|
|`-of`|Output format|
|`-r`|Follow redirects|
|`-recursion`|Enable recursive fuzzing|
|`-v`|Verbose output|

---

# 5. Wordlists

A good wordlist is extremely important.

On Kali Linux, SecLists is commonly used for web enumeration.

Common locations include:

```bash
/usr/share/seclists/Discovery/Web-Content/
```

Useful wordlists include:

```text
common.txt
directory-list-2.3-small.txt
directory-list-2.3-medium.txt
raft-medium-directories.txt
raft-medium-files.txt
raft-medium-words.txt
```

For parameter discovery:

```text
burp-parameter-names.txt
```

For usernames:

```text
/usr/share/seclists/Usernames/
```

### Choosing a wordlist

Start small.

For example:

```text
common.txt
```

or:

```text
directory-list-2.3-small.txt
```

If the small list doesn't produce useful results, move to larger lists.

### Why?

Large wordlists can generate:

- Huge amounts of traffic
    
- More false positives
    
- Longer scan times
    
- More server load
    
- Rate limiting
    

---

# 6. Directory Fuzzing

Directory fuzzing is usually one of the first fuzzing techniques we perform.

The objective is to discover directories that aren't linked from the main website.

For example:

```text
http://TARGET/
```

may contain hidden directories:

```text
/admin/
/login/
/uploads/
/backup/
/dev/
/test/
/api/
```

## Basic command

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://TARGET/FUZZ
```

### Example

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
-u http://10.10.10.10/FUZZ
```

Conceptually:

```text
Wordlist
   |
   +---- admin ------> http://TARGET/admin
   |
   +---- login ------> http://TARGET/login
   |
   +---- backup -----> http://TARGET/backup
   |
   +---- uploads ----> http://TARGET/uploads
```

---

# 7. Understanding HTTP Status Codes

When fuzzing, don't only look for `200`.

## Important responses

### `200 OK`

The request succeeded.

Example:

```text
admin [Status: 200]
```

This is usually an important discovery.

---

### `301 Moved Permanently`

Usually indicates a redirect.

For example:

```text
admin [Status: 301]
```

The server may redirect:

```text
/admin
```

to:

```text
/admin/
```

This can strongly indicate that the directory exists.

---

### `302 Found`

Temporary redirect.

It can indicate:

- Login redirects
    
- Authentication
    
- Application routing
    
- Existing resources
    

---

### `401 Unauthorized`

Authentication is required.

Example:

```text
admin [Status: 401]
```

This is interesting because the endpoint may exist even though you cannot access it without authentication.

---

### `403 Forbidden`

Access is forbidden.

Example:

```text
admin [Status: 403]
```

A `403` can still be valuable.

It may indicate that:

```text
/admin
```

actually exists, but the server doesn't allow access.

> **Important:** Don't automatically ignore `403`.

---

### `404 Not Found`

Usually means the requested resource does not exist.

However, applications can return custom responses, so we must verify the baseline response before blindly filtering.

---

### `405 Method Not Allowed`

The resource exists, but the HTTP method being used isn't allowed.

For example:

```text
GET /api/admin
```

may return:

```text
405 Method Not Allowed
```

while:

```text
POST /api/admin
```

may work.

---

# 8. Understanding Ffuf Output

A typical result can look like:

```text
admin      [Status: 403, Size: 289, Words: 21, Lines: 11]
login      [Status: 200, Size: 5421, Words: 834, Lines: 120]
uploads    [Status: 301, Size: 326, Words: 20, Lines: 10]
```

The fields mean:

|Field|Meaning|
|---|---|
|`admin`|Wordlist entry|
|`Status`|HTTP response code|
|`Size`|Response body size|
|`Words`|Number of words|
|`Lines`|Number of lines|
|`Duration`|Request duration|

### Why is response size important?

Suppose a nonexistent page always returns:

```text
Size: 1234
```

Then thousands of fuzzed entries may appear as:

```text
abc       1234
admin     1234
backup    1234
login     1234
```

These could all be false positives.

We can filter the common response size.

---

# 9. Filtering Results

Filtering is one of the most important ffuf skills.

## Filter by status code

```bash
-fc 404
```

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-fc 404
```

This hides responses with status `404`.

---

# 10. Filter by Response Size

Use:

```bash
-fs SIZE
```

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-fs 1234
```

This hides responses with a body size of `1234`.

This is extremely useful when the application returns the same custom page for nonexistent resources.

---

# 11. Filter by Word Count

Use:

```bash
-fw WORDS
```

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-fw 20
```

---

# 12. Filter by Line Count

Use:

```bash
-fl LINES
```

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-fl 10
```

---

# 13. Match Instead of Filter

Filtering removes results.

Matching specifies what you want to keep.

## Match status codes

```bash
-mc 200
```

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-mc 200
```

You can specify multiple status codes:

```bash
-mc 200,301,302,403
```

### Difference

```text
-mc = show these
-fc = hide these
```

This distinction is extremely important.

---

# 14. Baseline Before Fuzzing

Before starting a large fuzzing scan, understand what a nonexistent page looks like.

For example:

```bash
curl -i http://TARGET/random-nonexistent-page-12345
```

Look at:

```text
HTTP status
Content length
Response body
Redirect behavior
```

If every nonexistent page returns:

```text
200 OK
Size: 4210
```

then simply looking for `200` won't work.

You may need:

```bash
-fs 4210
```

This is one of the most important practical lessons in ffuf.

---

# 15. Fuzzing Files

Directory fuzzing looks for paths such as:

```text
/admin
/login
/uploads
```

File fuzzing searches for actual files:

```text
/index.php
/login.php
/config.php
/robots.txt
/backup.txt
```

Example:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
-u http://TARGET/FUZZ
```

---

# 16. Fuzzing File Extensions

Suppose we discover:

```text
/index
```

but don't know the extension.

Potential files could be:

```text
index.php
index.html
index.txt
index.asp
index.aspx
index.jsp
```

We can fuzz the extension.

Example:

```bash
ffuf -w extensions.txt:FUZZ \
-u http://TARGET/indexFUZZ
```

Where:

```text
extensions.txt
```

contains:

```text
.php
.html
.txt
.asp
.aspx
.jsp
```

The requests become:

```text
/index.php
/index.html
/index.txt
/index.asp
/index.aspx
/index.jsp
```

---

# 17. Using `-e` for Extensions

ffuf also supports the `-e` option.

Example:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt \
-u http://TARGET/FUZZ \
-e .php,.txt,.html
```

This tests words with the specified extensions.

For example:

```text
admin
admin.php
admin.txt
admin.html
login
login.php
login.txt
login.html
```

This can be very useful when you already have an idea about the server technology.

---

# 18. Fuzzing Pages Under a Known Directory

Suppose we discover:

```text
/blog/
```

We can fuzz inside it.

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/blog/FUZZ
```

Potential discoveries:

```text
/blog/index.php
/blog/login.php
/blog/admin.php
/blog/archive.php
```

---

# 19. Recursive Fuzzing

Recursive fuzzing allows ffuf to continue fuzzing directories it discovers.

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-recursion
```

You can limit recursion depth:

```bash
-recursion-depth 2
```

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-recursion \
-recursion-depth 2
```

Concept:

```text
TARGET/
│
├── admin/
│   ├── login
│   ├── users
│   └── config
│
├── blog/
│   ├── posts
│   └── archive
│
└── uploads/
    └── images
```

Instead of stopping at:

```text
/admin
```

recursive fuzzing can continue with:

```text
/admin/FUZZ
```

---

# 20. Virtual Hosts — Vhosts

A web server can host multiple websites on the same IP address.

For example:

```text
10.10.10.10
```

could host:

```text
www.example.com
admin.example.com
dev.example.com
internal.example.com
```

The server determines which website to return based on the HTTP `Host` header.

Example:

```http
Host: admin.example.com
```

---

# 21. Why Vhost Fuzzing Matters

DNS enumeration may not reveal every virtual host.

A web server can still respond differently when you send:

```http
Host: admin.example.com
```

even if:

```text
admin.example.com
```

doesn't have a publicly resolvable DNS record.

Therefore, we can fuzz the `Host` header.

---

# 22. Basic Vhost Fuzzing

Example:

```bash
ffuf -w subdomains.txt:FUZZ \
-u http://TARGET/ \
-H "Host: FUZZ.example.com"
```

Possible requests:

```text
Host: admin.example.com
Host: dev.example.com
Host: test.example.com
Host: staging.example.com
```

---

# 23. Vhost False Positives

This is extremely important.

Suppose every invalid vhost returns:

```text
Size: 4242
```

Then:

```text
admin.example.com     Size: 4242
dev.example.com       Size: 4242
test.example.com      Size: 4242
```

may all be false positives.

Filter the default response:

```bash
-fs 4242
```

Example:

```bash
ffuf -w subdomains.txt:FUZZ \
-u http://TARGET/ \
-H "Host: FUZZ.example.com" \
-fs 4242
```

The official ffuf examples use this exact concept: identify the default virtual-host response size and filter it while fuzzing the `Host` header. ([GitHub](https://github.com/ffuf/ffuf?utm_source=chatgpt.com "GitHub - ffuf/ffuf: Fast web fuzzer written in Go · GitHub"))

---

# 24. Subdomain Fuzzing vs Vhost Fuzzing

These are related but not identical.

### Subdomain fuzzing

You fuzz the hostname:

```text
FUZZ.example.com
```

Example:

```bash
ffuf -w subdomains.txt:FUZZ \
-u https://FUZZ.example.com
```

### Vhost fuzzing

You fuzz the `Host` header:

```bash
ffuf -w subdomains.txt:FUZZ \
-u http://TARGET/ \
-H "Host: FUZZ.example.com"
```

### Key idea

```text
Subdomain fuzzing
        ↓
FUZZ.example.com

Vhost fuzzing
        ↓
Host: FUZZ.example.com
```

Vhost fuzzing can be particularly useful in lab environments where DNS does not expose every virtual host.

---

# 25. PHP Parameter Fuzzing

Once we discover a PHP page, we may need to determine which parameters it accepts.

For example:

```text
http://TARGET/index.php
```

might accept:

```text
?id=123
?page=home
?file=test
?user=admin
```

But we don't necessarily know the parameter names.

This is where parameter fuzzing becomes useful.

---

# 26. GET Parameter Name Fuzzing

Suppose:

```text
http://TARGET/index.php?FUZZ=test
```

The `FUZZ` keyword represents the parameter name.

Command:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u "http://TARGET/index.php?FUZZ=test"
```

ffuf may test:

```text
?id=test
?page=test
?user=test
?file=test
?username=test
```

---

# 27. Filtering Parameter Fuzzing

Parameter fuzzing often produces many false positives.

Suppose invalid parameters return:

```text
Size: 1500
```

Use:

```bash
-fs 1500
```

Example:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u "http://TARGET/index.php?FUZZ=test" \
-fs 1500
```

The important result is the parameter that produces a response different from the baseline.

---

# 28. POST Parameter Fuzzing

Parameters don't always appear in the URL.

For example:

```http
POST /login.php

username=admin&password=test
```

We can fuzz POST parameters.

Example:

```bash
ffuf -w parameter-names.txt:FUZZ \
-u http://TARGET/login.php \
-X POST \
-d "FUZZ=test" \
-H "Content-Type: application/x-www-form-urlencoded"
```

The requests may become:

```text
username=test
password=test
user=test
admin=test
id=test
```

---

# 29. Parameter Value Fuzzing

Sometimes we already know the parameter name but don't know the correct value.

For example:

```text
http://TARGET/index.php?user=FUZZ
```

We can use a wordlist containing possible values.

```bash
ffuf -w values.txt:FUZZ \
-u "http://TARGET/index.php?user=FUZZ"
```

Potential requests:

```text
?user=admin
?user=administrator
?user=test
?user=guest
?user=student
```

---

# 30. POST Parameter Value Fuzzing

Example:

```bash
ffuf -w passwords.txt:FUZZ \
-u http://TARGET/login.php \
-X POST \
-d "username=admin&password=FUZZ" \
-H "Content-Type: application/x-www-form-urlencoded"
```

Here:

```text
username = fixed
password = FUZZ
```

Only the password value changes.

---

# 31. Fuzzing Different Parts of an HTTP Request

One of ffuf's biggest strengths is that `FUZZ` can be placed in different parts of the request.

### URL

```bash
-u http://TARGET/FUZZ
```

### GET parameter

```bash
-u "http://TARGET/index.php?FUZZ=test"
```

### Parameter value

```bash
-u "http://TARGET/index.php?id=FUZZ"
```

### POST body

```bash
-d "username=FUZZ&password=test"
```

### Header

```bash
-H "Host: FUZZ.example.com"
```

This is the central idea behind ffuf.

---

# 32. Useful Ffuf Command Examples

## Directory discovery

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ
```

## Directory discovery with extension

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-e .php,.html,.txt
```

## Filter 404

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-fc 404
```

## Filter response size

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-fs 1234
```

## Match only 200

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-mc 200
```

## Follow redirects

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-r
```

## More threads

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-t 100
```

## Rate limiting

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-rate 100
```

## Recursive fuzzing

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-recursion \
-recursion-depth 2
```

---

# 33. Saving Results

Results can be saved using:

```bash
-o results.json
```

and:

```bash
-of json
```

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-o results.json \
-of json
```

This is useful when:

- The scan takes a long time
    
- You need to review results later
    
- You are documenting an assessment
    
- You want machine-readable output
    

---

# 34. Threads and Speed

ffuf can run multiple requests concurrently.

The `-t` option controls threads.

Example:

```bash
-t 100
```

means ffuf can use up to 100 concurrent threads.

### More threads ≠ always better

Too many threads can cause:

- Server overload
    
- Rate limiting
    
- Connection failures
    
- Increased noise
    
- Missing results due to instability
    

For a stable lab:

```bash
-t 100
```

or higher may be reasonable.

For a fragile target:

```bash
-t 10
```

may be better.

Use only appropriate settings for systems you are authorized to test.

---

# 35. Rate Limiting

Instead of controlling concurrency, you can control requests per second.

Example:

```bash
-rate 100
```

This limits the scan to approximately 100 requests per second.

This can be useful when:

- The target is slow
    
- Rate limiting exists
    
- You want controlled traffic
    
- You want to avoid overwhelming the application
    

---

# 36. Common Fuzzing Workflow

A practical workflow is:

```text
1. Identify target
       ↓
2. Check website manually
       ↓
3. Determine technology
       ↓
4. Establish baseline response
       ↓
5. Directory fuzzing
       ↓
6. File fuzzing
       ↓
7. Extension fuzzing
       ↓
8. Recursive fuzzing
       ↓
9. Vhost/subdomain discovery
       ↓
10. Parameter name fuzzing
       ↓
11. Parameter value fuzzing
       ↓
12. Manually investigate discoveries
```

---

# 37. Example Investigation

Suppose you find:

```text
/blog
```

You then fuzz:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/blog/FUZZ
```

You discover:

```text
courses
```

Now fuzz:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/blog/courses/FUZZ
```

You discover:

```text
linux-security.php7
```

Now you investigate the page manually.

If it appears to behave differently depending on parameters, you can move to parameter fuzzing.

This demonstrates an important principle:

> **Fuzzing is iterative. One discovery becomes the starting point for the next fuzzing stage.**

---

# 38. Don't Immediately Trust Every Result

A fuzzing result is a **lead**, not automatically a vulnerability.

For example:

```text
admin [Status: 200]
```

doesn't necessarily mean:

```text
Admin panel vulnerable
```

It only tells you that something responded at:

```text
/admin
```

You must manually investigate it.

Similarly:

```text
backup [Status: 403]
```

doesn't mean you can access the backup.

It indicates that the server may recognize the resource but deny access.

---

# 39. False Positives

False positives are one of the biggest challenges in web fuzzing.

Common causes:

### Custom 404 pages

The server returns:

```text
200 OK
```

for nonexistent pages.

### Redirects

Everything redirects to:

```text
/login
```

### Generic error pages

Every invalid request returns the same body.

### Wildcard virtual hosts

Every Host header produces the same response.

---

# 40. How to Reduce False Positives

Use:

```bash
-fc
```

for status filtering.

Use:

```bash
-fs
```

for size filtering.

Use:

```bash
-fw
```

for word filtering.

Use:

```bash
-fl
```

for line filtering.

Also establish a baseline using a random nonexistent path before scanning.

---

# 41. Important SecLists Wordlists

### Web directories

```text
/usr/share/seclists/Discovery/Web-Content/
```

Examples:

```text
common.txt
directory-list-2.3-small.txt
directory-list-2.3-medium.txt
raft-medium-directories.txt
```

### Parameters

```text
burp-parameter-names.txt
```

### DNS/subdomains

```text
/usr/share/seclists/Discovery/DNS/
```

### Usernames

```text
/usr/share/seclists/Usernames/
```

---

# 42. Ffuf Cheat Sheet

|Goal|Example|
|---|---|
|Directory fuzzing|`ffuf -w wordlist:FUZZ -u http://TARGET/FUZZ`|
|Extensions|`-e .php,.txt,.html`|
|Filter status|`-fc 404`|
|Filter size|`-fs 1234`|
|Filter words|`-fw 20`|
|Filter lines|`-fl 10`|
|Match status|`-mc 200`|
|Follow redirects|`-r`|
|Threads|`-t 100`|
|Rate limit|`-rate 100`|
|Recursive|`-recursion`|
|Recursion depth|`-recursion-depth 2`|
|Verbose|`-v`|
|Save output|`-o results.json`|
|Output format|`-of json`|
|Custom header|`-H "Header: FUZZ"`|
|POST request|`-X POST`|
|POST data|`-d "param=FUZZ"`|

---

# 43. The Most Important Concepts to Memorize

## 1. `FUZZ`

The location where ffuf inserts wordlist entries.

```text
http://TARGET/FUZZ
```

---

## 2. `-w`

Specifies the wordlist.

```bash
-w wordlist.txt:FUZZ
```

---

## 3. `-u`

Specifies the target URL.

```bash
-u http://TARGET/FUZZ
```

---

## 4. `-fc`

Filters status codes.

```bash
-fc 404
```

---

## 5. `-fs`

Filters response sizes.

```bash
-fs 1234
```

---

## 6. `-mc`

Matches status codes.

```bash
-mc 200
```

---

## 7. `-H`

Adds/customizes HTTP headers.

```bash
-H "Host: FUZZ.example.com"
```

---

## 8. `-X`

Changes HTTP method.

```bash
-X POST
```

---

## 9. `-d`

Specifies request body data.

```bash
-d "username=FUZZ"
```

---

## 10. `-e`

Adds extensions.

```bash
-e .php,.html,.txt
```

---

# 44. Quick Mental Model

Whenever you see an unknown part of an HTTP request, ask:

> **Can I put `FUZZ` here?**

Examples:

```text
URL
 ↓
http://TARGET/FUZZ
```

```text
Directory
 ↓
/blog/FUZZ
```

```text
Extension
 ↓
indexFUZZ
```

```text
Vhost
 ↓
Host: FUZZ.example.com
```

```text
GET parameter
 ↓
?FUZZ=test
```

```text
Parameter value
 ↓
?id=FUZZ
```

```text
POST value
 ↓
username=FUZZ
```

This is the fundamental mindset behind ffuf.

---

# 45. Practical HTB Methodology

When approaching an HTB Academy target, a useful sequence is:

### Step 1 — Visit the website

```bash
curl -i http://TARGET/
```

or open it in your browser.

---

### Step 2 — Establish a false-positive baseline

```bash
curl -i http://TARGET/random-nonexistent-page-12345
```

Record:

```text
Status
Size
Words
Lines
```

---

### Step 3 — Fuzz directories

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
-u http://TARGET/FUZZ
```

---

### Step 4 — Investigate interesting results

Look closely at:

```text
200
301
302
401
403
405
```

---

### Step 5 — Fuzz files/extensions

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-e .php,.txt,.html
```

---

### Step 6 — Fuzz discovered directories

If:

```text
/admin/
```

is discovered:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/admin/FUZZ
```

---

### Step 7 — Look for virtual hosts

```bash
ffuf -w subdomains.txt:FUZZ \
-u http://TARGET/ \
-H "Host: FUZZ.example.com" \
-fs BASELINE_SIZE
```

---

### Step 8 — Fuzz parameters

```bash
ffuf -w burp-parameter-names.txt:FUZZ \
-u "http://TARGET/page.php?FUZZ=test" \
-fs BASELINE_SIZE
```

---

### Step 9 — Fuzz values

Once a parameter is identified:

```bash
ffuf -w values.txt:FUZZ \
-u "http://TARGET/page.php?parameter=FUZZ"
```

---

### Step 10 — Manually validate

Never stop at the ffuf result.

Open the discovered endpoint and determine:

```text
What is it?
Why does it exist?
What functionality does it provide?
Does it require authentication?
Does it expose sensitive information?
Can it lead to further enumeration?
```

---

# 46. Key Takeaways

> **Ffuf is a web fuzzing tool used to automate the discovery of hidden web resources and parameters.**

> **The `FUZZ` keyword tells ffuf where wordlist entries should be inserted.**

> **Directory fuzzing searches for hidden paths.**

> **File fuzzing searches for files.**

> **Extension fuzzing identifies supported file extensions.**

> **Vhost fuzzing can identify websites hosted on the same server.**

> **Parameter fuzzing identifies unknown GET/POST parameter names.**

> **Value fuzzing searches for valid or interesting parameter values.**

> **Filtering is critical for removing false positives.**

> **A `403` response can still be an important discovery.**

> **Always establish a baseline before filtering by response size.**

> **Fuzzing results must be manually investigated and validated.**

---

# 47. Final One-Page Revision

```text
                    FFUF
                     │
                     ▼
              Find FUZZ Location
                     │
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
     URL/path      Header       Parameter
        │            │             │
        ▼            ▼             ▼
 /FUZZ            Host: FUZZ    ?FUZZ=test
                                   │
                                   ▼
                              Value Fuzzing
                                   │
                                   ▼
                               id=FUZZ
```

### Core command

```bash
ffuf -w WORDLIST:FUZZ -u http://TARGET/FUZZ
```

### Directory

```bash
.../FUZZ
```

### Extension

```bash
.../indexFUZZ
```

### Vhost

```bash
-H "Host: FUZZ.example.com"
```

### GET parameter name

```bash
...?FUZZ=test
```

### GET parameter value

```bash
...?id=FUZZ
```

### POST parameter

```bash
-d "FUZZ=test"
```

### POST value

```bash
-d "username=admin&password=FUZZ"
```

### Most important filters

```text
-fc  → filter status code
-fs  → filter response size
-fw  → filter word count
-fl  → filter line count
```

### Most important matching option

```text
-mc  → match status codes
```

### Golden Rule

```text
Baseline → Fuzz → Filter → Investigate → Validate
```

---

# 48. Lab Safety Note

Use ffuf against systems you own or have explicit authorization to test, such as HTB Academy machines, CTF targets, your own lab, or an authorized penetration-testing scope.

Fuzzing can generate a large number of HTTP requests, so choose wordlists, concurrency, and rate limits appropriately.

For reference, the official ffuf documentation covers content discovery, virtual-host discovery, GET/POST parameter fuzzing, recursion, and execution limits; Kali also packages ffuf directly. ([GitHub](https://github.com/ffuf/ffuf?utm_source=chatgpt.com "GitHub - ffuf/ffuf: Fast web fuzzer written in Go · GitHub"))

![Image](https://images.openai.com/static-rsc-4/ialz8rsKV_YtzMHtFFMeNQOPXjdjkH5z8snNfQPG63uMl3Q3xZJPFJuDrNZkgdKu7DgY8FER10YN_X4h0f3j3Xu0Ta2aO-AEvA2XFbVLJ2-jNgwNOCtgGAcYkzIB_wznOzAlmtZKk5xRcqG7Z0H9rlFPEIGUI3IWrRRHe1uAQKQCtIAtLuvD6Rl8hBXQOpGr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EuL_KQbDDY49d6FFwwS_LpNQn2LtCMLrY9CcpW4cUyZUH8gSklqj6O_P_SBrv8MkroFd-w1YJNjUhwAEgrOMBIgzPlyHE3871ekHaON1VRMx4UAoQFe4N46mfg3_3UnYEwB2_VfzcTVJpSgQTpMI3URk1X5o-cRLl6gPMvBKn6oZJ6uQ6r2omCwhmX22KZxi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tNMPeYeiKLIRG-Ra2PJ6K5X_9nRaOb8Hn7bLsn30SRvw324-X_HBa5oXYDwxxr6mPe59hL1LSF8Rj_XIrSJ-hQq_RrtqPzsEIhD7Kks3vTWGtxe_-8s9exgMNY15KdyP7PFSg1304w6V0OJj4amRqqXdUqL_oWaK1SmDTDbJloSmLd7Rb6C26adHQAGLCdow?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RUZTxCynYxduXxdnUGf7Q8i48B2uYn1gBUfGrqdhSDRagnbLSgnUo-arYNRRsweAGM68KexBJ2dmEe87264L9_-I00B33T-o02avSnDBPpzBsEcpZvYjbZL38W9AxFDTSxQv3KVKEckIXodHTsTE1_ArVoz02yNDAJNF6yQopzgLtOZMUQEFF_hoGgvlwYjG?purpose=fullsize)