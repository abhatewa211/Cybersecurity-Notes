![Image](https://images.openai.com/static-rsc-4/VZE95xIA7HtamTbVn1Lnlz9Qfnp7d5QGTUOSUTlT-1R9uRXoqHtHn96JzWaPIaatpZe8AE3Tf-BQ2KBs7KztOuDtmDEmAp-EVgmWsW7gZIwy6UQ60EcFjphP7JAwcbwCgTj_xrJIKQBpa2LcVxBlPrVb1I_UFMyCrfzETIQpcwlBhAnqaDw-9Svvc9ewu-By?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0pmMq1g8ETLchBsWExjJOUND5w16sjWkt5ZR9-uiQq9WK5E1tkWFwPWYIdd53QlzP5XJcvqfvsvF69khVCrC4AoD0pe1IAIi0bXunHcqh_7W2CmLRxLgvN7ER9sxKAGIn3U2IoTqKbqNUC1m_tc17CLD-KMdF-lWsZrEPNKVRGG737iGj3e5ozNaJUB8Yi7T?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xpSsOUB9PmXQh6NZVQgxsmf5fdtoAoPctcJNkV50tV0p2HDcNeXbwFPNHNEUlBV901OWeLK58XH69UFUD4e6LNH_lrRnLj8-75EJuzO6il9dQGcqnwsKdzEHQsavq44zeClGDVhzAif239RzdCMok7nlO4lNgRrS-aQFouR04Q-wUJWFmZ6Q2tidCnSB6BV7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FuDkoLwuuDEi2sJw5q1Twm6rzA7L1agq_4oEhLIfJX6wpBZ1mU0Iu8ujLjo9RxEPX-gskQKtWNbK7XA1m0Tv52IFGZLBuJ-10fQorybjw6PQQKlw2plwUxExLWf6rIIlDInLqVmiCl_8ceZ_a6_r9AiOkh4e2-teqOgVxsA2AHzrZlde8HdAwBDIsBJvMtIH?purpose=fullsize)

# 1. Introduction

Now that we understand the concept of **Web Fuzzing** and know our wordlist, we should be ready to start using `ffuf` to find website directories.

The basic objective is:

```text
Target Website
      ↓
Ffuf
      ↓
Wordlist
      ↓
Test possible directories
      ↓
Analyze HTTP responses
      ↓
Discover hidden resources
```

For example, a website may visibly expose:

```text
http://SERVER_IP:PORT/
```

but may secretly contain:

```text
/blog
/admin
/uploads
/backup
/dev
```

Directory fuzzing helps us discover these resources.

---

# 2. Ffuf

`ffuf` is a fast web fuzzing tool.

It is commonly used for:

- Directory discovery
    
- File discovery
    
- Extension discovery
    
- Virtual host discovery
    
- Parameter discovery
    
- Parameter value fuzzing
    

The tool is pre-installed on the HTB PwnBox.

If you want to install it on your own Linux machine, you can use:

```bash
sudo apt install ffuf -y
```

Alternatively, it can be obtained from its official GitHub repository:

[ffuf — Official GitHub Repository](https://github.com/ffuf/ffuf?utm_source=chatgpt.com)

---

# 3. First Command — `ffuf -h`

Whenever you are learning a new command-line tool, one of the best first steps is:

```bash
ffuf -h
```

This displays the help menu.

The complete help output is quite large, so we focus on the options that are especially relevant to web fuzzing.

---

# 4. Important HTTP Options

From the help menu:

```text
HTTP OPTIONS:

-H
-X
-b
-d
-recursion
-recursion-depth
-u
```

Let's understand each.

---

# 5. `-u` — Target URL

The `-u` option specifies the URL that ffuf should attack.

Example:

```bash
-u http://SERVER_IP:PORT/FUZZ
```

Here:

```text
-u
 ↓
Target URL
```

The `FUZZ` keyword identifies the part that will be replaced with words from the wordlist.

---

# 6. `-w` — Wordlist

The `-w` option specifies the wordlist.

Example:

```bash
-w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

However, ffuf allows us to assign a keyword to the wordlist.

We do that by adding:

```text
:FUZZ
```

after the wordlist.

Example:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ
```

This tells ffuf:

> Use this wordlist and replace the keyword `FUZZ` with each word from the list.

---

# 7. Understanding `:FUZZ`

This syntax is extremely important:

```text
/path/to/wordlist:FUZZ
```

The part before the colon:

```text
/path/to/wordlist
```

is the wordlist.

The part after the colon:

```text
FUZZ
```

is the keyword assigned to that wordlist.

Therefore:

```bash
-w wordlist.txt:FUZZ
```

means:

```text
wordlist.txt
      ↓
 assigned keyword
      ↓
     FUZZ
```

---

# 8. Putting `FUZZ` in the URL

Now we need to tell ffuf **where** to insert the words.

Because we're looking for directories, the directory name belongs after the final `/`.

Therefore:

```bash
-u http://SERVER_IP:PORT/FUZZ
```

For example, if our wordlist contains:

```text
admin
login
blog
uploads
```

ffuf effectively tests:

```text
http://SERVER_IP:PORT/admin
http://SERVER_IP:PORT/login
http://SERVER_IP:PORT/blog
http://SERVER_IP:PORT/uploads
```

---

# 9. The Complete Directory Fuzzing Command

The final command becomes:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

This is one of the most important commands in this section.

### Command structure

```text
ffuf
 │
 ├── -w
 │    │
 │    └── Wordlist:FUZZ
 │
 └── -u
      │
      └── http://SERVER_IP:PORT/FUZZ
```

---

# 10. What Does Ffuf Actually Do?

Suppose the wordlist contains:

```text
admin
login
blog
uploads
backup
```

ffuf generates requests such as:

```http
GET /admin HTTP/1.1
```

```http
GET /login HTTP/1.1
```

```http
GET /blog HTTP/1.1
```

```http
GET /uploads HTTP/1.1
```

```http
GET /backup HTTP/1.1
```

It then analyzes the server's responses.

---

# 11. Ffuf Output

When ffuf starts, it displays information about the scan.

Example:

```text
:: Method           : GET
:: URL              : http://SERVER_IP:PORT/FUZZ
:: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200,204,301,302,307,401,403
```

Let's understand these.

---

# 12. Method

```text
:: Method : GET
```

ffuf is using the HTTP `GET` method.

So requests look like:

```http
GET /FUZZ HTTP/1.1
```

For directory discovery, `GET` is normally what we want.

---

# 13. URL

```text
:: URL : http://SERVER_IP:PORT/FUZZ
```

This tells us the target URL and the fuzzing location.

The important part is:

```text
FUZZ
```

This will be replaced with each word from the wordlist.

---

# 14. Wordlist

Example:

```text
:: Wordlist : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

This tells us:

```text
Keyword = FUZZ
Wordlist = directory-list-2.3-small.txt
```

---

# 15. Follow Redirects

```text
:: Follow redirects : false
```

This means ffuf isn't automatically following HTTP redirects.

For example, if:

```text
/blog
```

returns:

```text
301
```

the server may redirect the client to:

```text
/blog/
```

By default, ffuf can report the redirect without following it.

---

# 16. Timeout

```text
:: Timeout : 10
```

This represents the request timeout.

If the server doesn't respond within the configured time, ffuf can treat the request as an error.

---

# 17. Threads

Example:

```text
:: Threads : 40
```

This means ffuf is using 40 concurrent threads.

More threads generally mean:

```text
More concurrency
      ↓
More requests at once
      ↓
Potentially faster scan
```

But there is an important warning.

---

# 18. Increasing Threads

We can increase the number of threads.

For example:

```bash
-t 200
```

A command could look like:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ \
-t 200
```

This may make the scan faster.

### BUT:

Higher concurrency can cause:

- Server overload
    
- Rate limiting
    
- Connection failures
    
- Network instability
    
- Application instability
    
- Potential denial of service
    

Therefore:

> **Do not blindly increase the thread count.**

Especially when testing remote systems.

---

# 19. Why High Thread Counts Can Be Dangerous

Imagine a server can comfortably process:

```text
100 requests/second
```

If your scanner suddenly sends:

```text
5,000 requests/second
```

the server may struggle.

Possible consequences include:

```text
Server slowdown
      ↓
Connection failures
      ↓
Service disruption
      ↓
Potential DoS
```

This is particularly important during real-world penetration testing.

Only test authorized targets and respect the scope/rate limits.

---

# 20. Matcher Options

The output shows:

```text
Matcher:
Response status:
200,204,301,302,307,401,403
```

These are the default HTTP status codes ffuf considers interesting.

Important examples:

|Status|Meaning|
|---|---|
|`200`|OK|
|`204`|No Content|
|`301`|Permanent Redirect|
|`302`|Temporary Redirect|
|`307`|Temporary Redirect|
|`401`|Unauthorized|
|`403`|Forbidden|

---

# 21. Why Matchers Matter

Suppose ffuf tests:

```text
/admin
/login
/blog
/random
```

The server responds:

```text
/admin → 403
/login → 200
/blog → 301
/random → 404
```

The default matcher will highlight:

```text
/admin
/login
/blog
```

while the `404` response won't normally appear as an interesting result.

---

# 22. `-mc` — Match Status Codes

The `-mc` option allows us to specify which HTTP status codes we want to match.

Example:

```bash
-mc 200
```

This means:

> Only show responses with HTTP status `200`.

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-mc 200
```

---

# 23. Match Multiple Status Codes

We can specify multiple values.

Example:

```bash
-mc 200,301,302,403
```

This tells ffuf to show results with those status codes.

---

# 24. Match Everything

The ffuf help menu shows:

```text
-mc all
```

This can be used to match all HTTP responses.

For example:

```bash
ffuf -w wordlist.txt \
-u http://TARGET/FUZZ \
-mc all
```

This can be useful when you want to inspect all responses and then filter unwanted ones.

---

# 25. Filter Options

Ffuf also provides filtering options.

Important ones include:

```text
-fc
-fs
```

### `-fc`

Filter HTTP status codes.

### `-fs`

Filter HTTP response sizes.

These are extremely useful for removing false positives.

---

# 26. `-fc` — Filter Status Codes

Example:

```bash
-fc 404
```

This means:

> Don't display responses with status code `404`.

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-fc 404
```

---

# 27. `-fs` — Filter Response Size

Sometimes a website returns the same response body for nonexistent pages.

Suppose every invalid request produces:

```text
Size: 1234
```

We can filter it:

```bash
-fs 1234
```

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-fs 1234
```

This removes responses with that specific size.

---

# 28. Matcher vs Filter

This is extremely important to remember.

### Matcher

```text
-mc
```

means:

> **Show these.**

### Filter

```text
-fc
```

means:

> **Hide these.**

Similarly:

```text
-ms = match response size
-fs = filter response size
```

### Mental shortcut

```text
M = Match
F = Filter
```

---

# 29. Input Options

The important input option in this section is:

```text
-w
```

It specifies:

```text
Wordlist + optional keyword
```

Syntax:

```text
/path/to/wordlist:KEYWORD
```

Example:

```text
/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ
```

---

# 30. Output Options

Ffuf can save results to a file.

The relevant option is:

```text
-o
```

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-o results.txt
```

Saving results is useful for:

- Documentation
    
- Reviewing discoveries later
    
- Reporting
    
- Comparing scans
    
- Keeping an enumeration record
    

---

# 31. Example from the HTB Exercise

The target is:

```text
http://SERVER_IP:PORT
```

The final command is:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

Ffuf starts scanning.

The output might contain:

```text
blog [Status: 301, Size: 326, Words: 20, Lines: 10]
```

This is an interesting result.

---

# 32. Interpreting the `blog` Result

The result:

```text
blog [Status: 301, Size: 326, Words: 20, Lines: 10]
```

means:

### `blog`

The word from the wordlist.

Therefore, ffuf tested:

```text
http://SERVER_IP:PORT/blog
```

### `301`

The server returned:

```text
Moved Permanently
```

This commonly indicates a redirect.

### `Size: 326`

The response body was 326 bytes.

### `Words: 20`

The response contained 20 words according to ffuf's response parsing.

### `Lines: 10`

The response contained 10 lines.

---

# 33. Visiting the Discovered Directory

We can manually visit:

```text
http://SERVER_IP:PORT/blog
```

This is extremely important.

**Ffuf discovers resources; manual testing verifies them.**

The target may return an empty page.

This doesn't necessarily mean the directory is useless.

It can indicate:

```text
Directory exists
      ↓
Accessible
      ↓
No obvious index/content
      ↓
Need deeper enumeration
```

---

# 34. Why Does `/blog` Return `301`?

A common reason is that the web server wants the trailing slash.

For example:

```text
/blog
```

may redirect to:

```text
/blog/
```

The server may use the trailing slash to indicate that `blog` is a directory.

So after discovering:

```text
/blog
```

always try:

```text
/blog/
```

---

# 35. Empty Directory ≠ No Content

Suppose:

```text
/blog/
```

shows an empty page.

That doesn't prove the directory contains nothing.

It may contain:

```text
index.php
login.php
admin.php
config.php
posts/
uploads/
images/
```

The browser might simply not show directory contents.

Therefore, the next step is:

> **Fuzz inside `/blog/`.**

---

# 36. Recursive Enumeration Concept

We initially tested:

```text
http://TARGET/FUZZ
```

Now that we found:

```text
/blog/
```

we can test:

```text
http://TARGET/blog/FUZZ
```

This could discover:

```text
/blog/admin
/blog/login
/blog/posts
/blog/uploads
```

This is an example of **iterative enumeration**.

---

# 37. Ffuf Speed

In the HTB example, ffuf tests approximately:

```text
87,651 URLs
```

in less than:

```text
10 seconds
```

The output might show:

```text
:: Progress: [87651/87651]
:: Job [1/1]
:: 9739 req/sec
:: Duration: [0:00:09]
:: Errors: 0
```

This demonstrates how efficient automated fuzzing can be.

---

# 38. Understanding Progress Output

Example:

```text
:: Progress: [87651/87651]
```

Means:

```text
87,651 requests completed
87,651 total requests
```

Therefore:

```text
100% complete
```

---

# 39. Requests Per Second

Example:

```text
9739 req/sec
```

means ffuf processed approximately:

```text
9,739 requests per second
```

The exact speed can vary significantly depending on:

- Network latency
    
- Server response time
    
- CPU
    
- Network bandwidth
    
- Target performance
    
- Thread count
    
- Rate limiting
    

---

# 40. Threads vs Requests Per Second

These concepts are related but not identical.

### Threads

```text
-t 40
```

controls concurrency.

### Requests per second

The resulting speed depends on:

```text
Threads
+
Network
+
Server response time
+
Latency
+
Rate limits
```

So:

> Increasing threads doesn't guarantee a proportional increase in requests per second.

---

# 41. Why Not Always Use `-t 200`?

You technically can:

```bash
-t 200
```

but it isn't always a good idea.

Potential problems:

```text
200 threads
     ↓
Large number of concurrent requests
     ↓
Server/network pressure
     ↓
Rate limiting or instability
```

On a remote production website, excessive scanning can potentially cause:

- Denial of Service
    
- Service degradation
    
- IP blocking
    
- WAF alerts
    
- Network congestion
    

Therefore:

> **Use the lowest concurrency that gives you acceptable performance.**

---

# 42. Recommended Practical Approach

For a lab:

```text
Start
 ↓
Default threads
 ↓
Observe performance
 ↓
Increase moderately if necessary
```

For an authorized production assessment:

```text
Check scope/rules
 ↓
Use conservative rate
 ↓
Monitor errors
 ↓
Avoid unnecessary load
```

---

# 43. Important Ffuf Options from This Section

|Option|Purpose|
|---|---|
|`-h`|Display help|
|`-w`|Specify wordlist|
|`-u`|Specify target URL|
|`-H`|Add HTTP header|
|`-X`|Specify HTTP method|
|`-b`|Specify cookies|
|`-d`|Specify POST data|
|`-t`|Number of threads|
|`-recursion`|Enable recursive scanning|
|`-recursion-depth`|Set recursion depth|
|`-mc`|Match status codes|
|`-ms`|Match response size|
|`-fc`|Filter status codes|
|`-fs`|Filter response size|
|`-o`|Save output|
|`-ic`|Ignore comments in wordlist|

---

# 44. Most Important Command to Memorize

For basic directory fuzzing:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

With comments ignored:

```bash
ffuf -ic \
-w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

---

# 45. Command Breakdown

```bash
ffuf
```

Launch ffuf.

```text
-w
```

Select wordlist.

```text
/path/to/wordlist:FUZZ
```

Assign the keyword `FUZZ` to the wordlist.

```text
-u
```

Specify target URL.

```text
http://SERVER_IP:PORT/FUZZ
```

Insert each word into the URL.

---

# 46. Example

Suppose:

```text
wordlist:

admin
blog
login
uploads
```

Command:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://10.10.10.10:8080/FUZZ
```

Ffuf tests:

```text
http://10.10.10.10:8080/admin
http://10.10.10.10:8080/blog
http://10.10.10.10:8080/login
http://10.10.10.10:8080/uploads
```

Suppose the responses are:

```text
admin   → 403
blog    → 301
login   → 200
uploads → 404
```

Interesting resources:

```text
admin
blog
login
```

---

# 47. What Should We Do After Finding a Directory?

Don't stop.

If we discover:

```text
/blog
```

we should:

### 1. Visit it

```text
http://TARGET/blog
```

### 2. Check the trailing slash

```text
http://TARGET/blog/
```

### 3. Inspect the page

Look for:

```text
Links
Comments
Forms
JavaScript
Images
API endpoints
Technologies
```

### 4. Fuzz inside it

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/blog/FUZZ
```

This is the natural continuation of directory enumeration.

---

# 48. Practical Enumeration Chain

The process can look like:

```text
TARGET
  │
  ▼
/
  │
  ▼
ffuf
  │
  ▼
/blog
  │
  ▼
/blog/
  │
  ▼
ffuf again
  │
  ├── /blog/admin
  ├── /blog/login
  ├── /blog/posts
  └── /blog/uploads
          │
          ▼
      Investigate
```

This is why web enumeration is often **iterative**.

One discovery leads to another.

---

# 49. Important Lesson — 301 Is Interesting

In the HTB example:

```text
blog [Status: 301]
```

A beginner might think:

> "It's not 200, so I'll ignore it."

That would be a mistake.

A `301` can indicate:

```text
The resource exists
        ↓
Server redirects client
        ↓
Likely directory normalization
```

Therefore, investigate it.

---

# 50. Important Lesson — 403 Is Interesting

Similarly:

```text
admin [Status: 403]
```

doesn't necessarily mean:

> "Nothing there."

It may mean:

```text
Resource exists
      ↓
Access denied
      ↓
Potentially interesting
```

Further investigation could determine:

- Whether authentication is required
    
- Whether another HTTP method is allowed
    
- Whether the resource has alternative paths
    
- Whether access differs based on context
    

Always remain within the authorized scope of the lab or assessment.

---

# 51. Common Mistakes

## Mistake 1 — Forgetting `:FUZZ`

Incorrect:

```bash
ffuf -w wordlist.txt -u http://TARGET/FUZZ
```

Depending on ffuf version/configuration, you should explicitly map the wordlist keyword when following the HTB workflow:

Correct:

```bash
ffuf -w wordlist.txt:FUZZ -u http://TARGET/FUZZ
```

---

## Mistake 2 — Putting FUZZ in the wrong location

For directory fuzzing:

```text
http://TARGET/FUZZ
```

not:

```text
FUZZhttp://TARGET/
```

---

## Mistake 3 — Ignoring the HTTP status

Don't just record the path.

Record:

```text
Path
Status
Size
Words
Lines
```

These characteristics help distinguish real discoveries from false positives.

---

## Mistake 4 — Using too many threads

Avoid immediately doing:

```bash
-t 1000
```

More speed isn't always better.

---

## Mistake 5 — Not manually validating

Ffuf result:

```text
blog [Status: 301]
```

should lead to:

```text
http://TARGET/blog
```

and:

```text
http://TARGET/blog/
```

---

# 52. Exam / Viva Questions

### Q1. What is ffuf?

`ffuf` is a fast web fuzzing tool used to discover web resources and fuzz various parts of HTTP requests.

---

### Q2. What is the main option used to specify a wordlist?

```text
-w
```

---

### Q3. What is used to specify the target URL?

```text
-u
```

---

### Q4. What does `:FUZZ` do?

It assigns the keyword `FUZZ` to the specified wordlist so ffuf knows where to substitute wordlist entries.

---

### Q5. What is the directory fuzzing URL format?

```text
http://TARGET/FUZZ
```

---

### Q6. What does `-mc` do?

It specifies which HTTP status codes should be matched/displayed.

---

### Q7. What does `-fc` do?

It filters out specified HTTP status codes.

---

### Q8. What does `-fs` do?

It filters responses based on their HTTP response size.

---

### Q9. What does `-t` do?

It controls the number of concurrent threads.

---

### Q10. Why shouldn't we use extremely high thread counts?

Because excessive concurrency can overload the target, trigger rate limiting, cause network issues, or potentially cause service disruption.

---

### Q11. What does HTTP `301` commonly indicate during directory fuzzing?

It commonly indicates that the requested resource redirects, often from `/directory` to `/directory/`.

---

### Q12. Why is a `403` response interesting?

It can indicate that the resource exists but access is forbidden.

---

### Q13. Why should we manually visit ffuf discoveries?

Because ffuf only identifies interesting responses. Manual investigation is required to determine what the discovered resource actually contains or does.

---

# 53. Quick Revision

```text
                 DIRECTORY FUZZING
                         │
                         ▼
                     ffuf
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
        Wordlist                    URL
             │                       │
             ▼                       ▼
      wordlist:FUZZ         http://TARGET/FUZZ
             │                       │
             └───────────┬───────────┘
                         ▼
                    HTTP Requests
                         │
                         ▼
                    Web Server
                         │
                         ▼
                  Analyze Responses
                         │
             ┌───────────┼───────────┐
             ▼           ▼           ▼
            200         301         403
             │           │           │
             └───────────┼───────────┘
                         ▼
                   Investigate
                         │
                         ▼
                  Fuzz Deeper
```

---

# 54. Golden Command

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

### With comments ignored:

```bash
ffuf -ic \
-w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ
```

### With controlled threading:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ \
-t 40
```

---

# 55. Final Takeaways

> **`ffuf` automates web fuzzing and can test thousands of potential resources very quickly.**

> **`-w` specifies the wordlist.**

> **`:FUZZ` assigns a keyword to the wordlist.**

> **`-u` specifies the target URL.**

> **For directory fuzzing, use `http://TARGET/FUZZ`.**

> **`-mc` controls which HTTP status codes are matched.**

> **`-fc` filters unwanted status codes.**

> **`-fs` filters responses by size.**

> **`-t` controls concurrent threads.**

> **Increasing threads can improve speed but can also overload a target.**

> **A `301` can indicate an existing directory.**

> **A `403` can indicate an existing but restricted resource.**

> **Always manually verify interesting results.**

> **An empty directory is not necessarily useless — fuzz inside it for files and subdirectories.**

The key workflow to remember is:

```text
Wordlist
   ↓
FUZZ
   ↓
http://TARGET/FUZZ
   ↓
Ffuf
   ↓
HTTP Responses
   ↓
Identify Interesting Results
   ↓
Manually Verify
   ↓
Fuzz Discovered Directories
```

This sets us up for the next stage: **finding files and file extensions inside discovered directories.**
