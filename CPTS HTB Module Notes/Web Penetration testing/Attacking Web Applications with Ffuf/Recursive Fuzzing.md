![Image](https://images.openai.com/static-rsc-4/T_NGorvQ8DEquqv5O_t_yYbsCbU-xwcv7RKPMlkC6Ei-Sid3WN0TUJ3v-XdlhTs1e-9DV-Yrn4aaKbiDDilyjDrHNbVzk3oynohkfg6DBHhWjS2ftV7yQ_YDa7N4uWpKE9yoqa4dQHNp9oyL0nC8ntc1Hm6Nn0rJRpVgjpzr020Biimyieyvd74BWIGFlooa?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HY4MJaMaaG9-PSIfqnK9VJVeOORfxcph6WrVirdZr1S5OZjaAw1nJSUqHWZiKr_QmMhEbrnosBWrEwUvBbqO9aZd_o7p_cW1tMnp4igh6IdSoWciMPqGXs4ZvU5kHHRaCugC_oLhTtSvI2jFvEz1M-1sPGmDB2Mlt9L2FNayd_yN9BfOYNHXFIqXIJyGA0GC?purpose=fullsize)

# 1. Introduction

So far, we have been performing web enumeration manually in stages:

```text
Main Website
     ↓
Fuzz Directories
     ↓
Find /blog
     ↓
Enter /blog
     ↓
Fuzz for Files
     ↓
Find .php Pages
```

This works well when there are only a few directories.

However, imagine a website with:

```text
/
├── admin/
│   ├── users/
│   │   ├── uploads/
│   │   └── backups/
│   └── config/
│
├── blog/
│   ├── posts/
│   ├── images/
│   └── comments/
│
├── forum/
│   ├── users/
│   ├── threads/
│   └── attachments/
│
└── api/
    ├── v1/
    └── v2/
```

Manually fuzzing every directory would take a very long time.

This is where **recursive fuzzing** becomes useful.

---

# 2. What Is Recursive Fuzzing?

**Recursive fuzzing** automatically starts another fuzzing scan whenever a new directory is discovered.

Instead of manually doing:

```text
Fuzz /
  ↓
Find /blog
  ↓
Fuzz /blog/
  ↓
Find /blog/admin
  ↓
Fuzz /blog/admin/
  ↓
Find /blog/admin/users
  ↓
Fuzz /blog/admin/users/
```

ffuf can automate this process.

Conceptually:

```text
                 /
                 │
             Fuzzing
                 │
       ┌─────────┼─────────┐
       ▼         ▼         ▼
     /blog     /admin     /forum
       │         │           │
     Fuzz      Fuzz        Fuzz
       │         │           │
   ┌───┴───┐     ▼       ┌───┴───┐
   ▼       ▼   /users    ▼       ▼
 /posts  /img            /users /threads
   │
  Fuzz
```

This is the basic idea of recursive enumeration.

---

# 3. Why Is Recursive Fuzzing Useful?

Without recursion, if we discover:

```text
/blog
/admin
/forum
```

we would need to manually launch:

```bash
ffuf ... -u http://TARGET/blog/FUZZ
```

then:

```bash
ffuf ... -u http://TARGET/admin/FUZZ
```

then:

```bash
ffuf ... -u http://TARGET/forum/FUZZ
```

And if `/blog` contains:

```text
/posts
/images
/uploads
```

we would need even more scans.

Recursive fuzzing automates this.

---

# 4. The Directory Tree Problem

Some websites have extremely deep directory structures.

For example:

```text
/login/user/content/uploads/images/archive/files/backup/
```

If every directory generates another recursive scan, the number of requests can grow rapidly.

Conceptually:

```text
Depth 0
   /
   │
   ├── A
   ├── B
   └── C

Depth 1
   A/
   ├── A1
   ├── A2
   └── A3

Depth 2
   A1/
   ├── A1a
   ├── A1b
   └── A1c
```

The deeper we go, the larger the scanning tree becomes.

Therefore:

> **Always consider specifying a recursion depth.**

---

# 5. Recursion Depth

ffuf provides:

```text
-recursion-depth
```

to control how deep recursive scanning should go.

For example:

```bash
-recursion-depth 1
```

means we don't recursively continue indefinitely into deeper levels.

This gives us a controlled scan.

---

# 6. `-recursion`

The option:

```text
-recursion
```

enables recursive scanning.

Example:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-recursion
```

When ffuf discovers a directory, it can add a new fuzzing job for that directory.

---

# 7. `-recursion-depth`

The option:

```text
-recursion-depth
```

controls how deep ffuf is allowed to recursively scan.

Example:

```bash
-recursion-depth 1
```

This limits recursion.

### Why use it?

Because unlimited recursion can result in:

```text
More directories
       ↓
More recursive jobs
       ↓
More requests
       ↓
Longer scan
```

A controlled depth gives us a more manageable scan.

---

# 8. Understanding Depth `1`

Suppose the website is:

```text
/
├── login/
│   └── user/
│       └── content/
│           └── uploads/
│
└── blog/
    └── posts/
        └── archive/
```

With:

```bash
-recursion-depth 1
```

we can conceptually scan:

```text
/
│
├── login/
│   └── user/     ← discovered, but don't continue deeper
│
└── blog/
    └── posts/    ← discovered, but don't continue deeper
```

The exact behavior depends on ffuf's recursion semantics/version, but the important HTB concept is:

> **A depth limit prevents the scan from expanding indefinitely.**

---

# 9. Why We Don't Always Want Unlimited Recursion

Suppose each directory contains 100 potential entries.

Imagine:

```text
100 entries
   ↓
10 directories discovered
   ↓
10 × 100
   ↓
1,000 requests
```

Then those directories discover more directories:

```text
1,000
   ↓
100 more directories
   ↓
10,000
```

The number of requests can grow very quickly.

Therefore:

```text
Small depth
   ↓
Controlled scan
```

is usually preferable to:

```text
Unlimited recursion
   ↓
Potentially enormous scan
```

---

# 10. Using Extensions with Recursive Fuzzing

One particularly useful feature is that we can specify extensions using:

```text
-e
```

For example:

```bash
-e .php
```

This tells ffuf to also test the specified extension.

Therefore, our recursive scan can discover both:

```text
/blog
```

and:

```text
/blog/index.php
```

---

# 11. Why `.php` Can Be Used Site-Wide

Earlier, we discovered that the target uses PHP.

For example:

```text
/blog/index.php
```

returned:

```text
200 OK
```

Once we've established that PHP is being used, we can reasonably use:

```bash
-e .php
```

throughout the recursive scan.

This saves us from having to rediscover the extension in every directory.

> **Important:** This is an assumption based on evidence from the target, not a guarantee that every resource is PHP.

---

# 12. The `-v` Option

When scanning recursively, ffuf may discover files under many different directories.

For example:

```text
index.php
login.php
config.php
admin.php
```

Without full URLs, it can become difficult to tell where each file was discovered.

The:

```text
-v
```

option enables verbose output.

This makes ffuf show the **full URLs**.

---

# 13. Why `-v` Is Important

Without verbose output, we might see:

```text
index.php
login.php
admin.php
```

But we don't immediately know whether they are:

```text
/blog/index.php
/admin/index.php
/forum/index.php
```

With:

```bash
-v
```

we can see:

```text
http://TARGET/blog/index.php
http://TARGET/admin/index.php
http://TARGET/forum/index.php
```

This is especially useful for recursive scanning.

---

# 14. Complete Recursive Fuzzing Command

The HTB command is:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ \
-recursion \
-recursion-depth 1 \
-e .php \
-v
```

This combines everything we've learned so far.

---

# 15. Command Breakdown

### `ffuf`

Starts the fuzzing tool.

---

### `-w`

Specifies the wordlist:

```text
/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

---

### `:FUZZ`

Assigns the wordlist to the `FUZZ` keyword.

---

### `-u`

Specifies:

```text
http://SERVER_IP:PORT/FUZZ
```

---

### `-recursion`

Enables recursive scanning.

---

### `-recursion-depth 1`

Limits the recursion depth.

---

### `-e .php`

Adds `.php` to the fuzzing process.

---

### `-v`

Displays full URLs and more detailed output.

---

# 16. What Does `-e .php` Actually Do?

Suppose the wordlist contains:

```text
admin
login
blog
index
```

With:

```bash
-e .php
```

ffuf can test both the word itself and its PHP version.

Conceptually:

```text
admin
admin.php

login
login.php

blog
blog.php

index
index.php
```

Therefore, one scan can look for both:

```text
directories
```

and:

```text
PHP files
```

This is why the effective number of requests increases.

---

# 17. Request Count Increase

The HTB example notes that the recursive scan sends significantly more requests.

There are two main reasons:

### Reason 1 — Recursion

Every discovered directory can trigger another scan.

### Reason 2 — Extensions

The scan tests entries with:

```text
.php
```

in addition to the normal entries.

Therefore:

```text
Normal scan
   ↓
Wordlist entries

Recursive + extension scan
   ↓
Wordlist entries
   +
PHP variants
   +
New directory scans
```

---

# 18. Example Output

The scan begins with something similar to:

```text
:: Method           : GET
:: URL              : http://SERVER_IP:PORT/FUZZ
:: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
:: Extensions       : .php
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200,204,301,302,307,401,403
```

Notice:

```text
:: Extensions : .php
```

This confirms that `.php` has been added.

---

# 19. Recursive Job Creation

One of the most important lines in the output can look like:

```text
[INFO] Adding a new job to the queue:
http://SERVER_IP:PORT/forum/FUZZ
```

This tells us that ffuf discovered:

```text
/forum/
```

and automatically created another fuzzing job for:

```text
http://SERVER_IP:PORT/forum/FUZZ
```

This is **recursive fuzzing in action**.

---

# 20. Understanding the Job Queue

Think of ffuf as maintaining a queue:

```text
Main scan
   │
   ├── /blog discovered
   │
   ├── /forum discovered
   │
   └── /admin discovered
          │
          ▼
     New scan jobs
          │
     ┌────┼────┐
     ▼    ▼    ▼
   blog forum admin
```

Instead of you manually launching each scan, ffuf adds the discovered directories to its queue.

---

# 21. Example: Root-Level Discovery

The output might show:

```text
[Status: 200, Size: 986, Words: 423, Lines: 56]
URL: http://SERVER_IP:PORT/
```

This represents the root website.

It may also show:

```text
FUZZ:
```

because the root request isn't associated with a specific discovered word.

Don't confuse this with a directory discovery.

---

# 22. Example: `index.php`

The output may contain:

```text
[Status: 200, Size: 986, Words: 423, Lines: 56]
URL: http://SERVER_IP:PORT/index.php

* FUZZ: index.php
```

This means ffuf discovered:

```text
/index.php
```

and the response was:

```text
200 OK
```

with:

```text
Size: 986
Words: 423
Lines: 56
```

---

# 23. Example: `/blog`

The output may contain:

```text
[Status: 301, Size: 326, Words: 20, Lines: 10]
URL: http://SERVER_IP:PORT/blog
--> http://SERVER_IP:PORT/blog/

* FUZZ: blog
```

This indicates:

```text
/blog
```

was discovered and the server redirected it to:

```text
/blog/
```

Because this is a directory, ffuf adds a new recursive job.

---

# 24. Example: `/blog/index.php`

Later, the recursive scan may discover:

```text
[Status: 200, Size: 0, Words: 1, Lines: 1]
URL: http://SERVER_IP:PORT/blog/index.php

* FUZZ: index.php
```

This is exactly what we manually discovered in the previous section.

The important difference is:

> **The recursive scan found it automatically.**

---

# 25. Why `-v` Helps Here

Imagine the output only said:

```text
index.php
index.php
login.php
admin.php
```

That wouldn't tell us where they were found.

With verbose output:

```text
/blog/index.php
/forum/index.php
/admin/login.php
/admin/admin.php
```

we immediately know the complete path.

Therefore:

> **`-v` becomes particularly useful when recursive scans produce results from multiple directories.**

---

# 26. Comparing Manual vs Recursive Fuzzing

## Manual approach

```text
Fuzz /
 ↓
Find /blog
 ↓
Fuzz /blog
 ↓
Find index.php
 ↓
Find another directory
 ↓
Fuzz it
 ↓
Repeat...
```

### Problems

- Time-consuming
    
- Easy to forget directories
    
- Requires many commands
    
- Difficult to track large directory trees
    

---

## Recursive approach

```text
Fuzz /
 ↓
Discover directories
 ↓
Automatically queue new scans
 ↓
Fuzz discovered directories
 ↓
Continue according to depth
```

### Advantages

- Automated
    
- Faster workflow
    
- Less manual effort
    
- Better coverage
    
- Useful for large directory trees
    

---

# 27. Recursive Fuzzing Trade-Off

Recursive fuzzing isn't automatically better in every situation.

### Advantages

```text
Automation
Coverage
Convenience
Less manual work
```

### Disadvantages

```text
More requests
Longer scans
Higher server load
More output
Potentially huge scan tree
```

Therefore:

> **Use recursion strategically.**

---

# 28. Choosing a Recursion Depth

A useful approach is:

```text
Start shallow
     ↓
Review results
     ↓
Identify interesting directories
     ↓
Perform targeted deeper scans
```

For example:

```bash
-recursion-depth 1
```

first.

Then, if `/admin` looks particularly interesting, run a dedicated scan against:

```text
/admin/
```

This is often more efficient than blindly scanning the entire site to unlimited depth.

---

# 29. Targeted Deeper Scanning

Suppose recursive fuzzing discovers:

```text
/admin/
```

Instead of increasing global recursion indefinitely, we can manually focus on it:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/admin/FUZZ \
-e .php
```

If that reveals:

```text
/admin/users/
```

we can then investigate that specific branch.

This gives us:

```text
Broad scan
   ↓
Find interesting branch
   ↓
Deep targeted scan
```

This is an efficient enumeration strategy.

---

# 30. Recursive Fuzzing Workflow

A practical workflow is:

```text
                    Target
                       │
                       ▼
              Initial Enumeration
                       │
                       ▼
              Recursive Fuzzing
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
        /blog        /forum       /admin
          │            │            │
          ▼            ▼            ▼
       Scan          Scan         Scan
          │            │            │
       Files         Files        Files
          │            │            │
          ▼            ▼            ▼
      Interesting resources
                │
                ▼
         Manual Investigation
```

---

# 31. Important Difference: Recursion vs Extension Fuzzing

These are separate concepts.

### Recursion

Answers:

> "Where else should I scan?"

```text
/blog
/forum
/admin
```

### Extension fuzzing

Answers:

> "What file types might exist?"

```text
.php
.html
.aspx
```

The command combines both:

```bash
-recursion -e .php
```

Therefore, ffuf can:

1. Discover directories.
    
2. Enter those directories automatically.
    
3. Test PHP files inside them.
    

---

# 32. Understanding the Full Command

```bash
ffuf \
-w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ \
-recursion \
-recursion-depth 1 \
-e .php \
-v
```

Visualized:

```text
                         FFUF
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
      Wordlist             URL          Recursion
          │                │                │
          ▼                ▼                ▼
     directory-list   TARGET/FUZZ      depth = 1
          │
          ▼
       + .php
          │
          ▼
       Verbose
```

---

# 33. What We Gain From One Command

Previously, we needed several commands:

```text
Command 1
Directory fuzzing

Command 2
Extension fuzzing

Command 3
Page fuzzing

Command 4
Another directory fuzzing scan

Command 5
Another page scan
```

Now, recursive fuzzing can combine much of this into:

```bash
ffuf -w wordlist.txt:FUZZ \
-u http://TARGET/FUZZ \
-recursion \
-recursion-depth 1 \
-e .php \
-v
```

This is a major improvement in enumeration efficiency.

---

# 34. Common Mistakes

## Mistake 1 — Unlimited recursion

Avoid blindly using:

```bash
-recursion
```

without thinking about depth.

Large websites can produce huge scanning trees.

Prefer:

```bash
-recursion-depth 1
```

or another appropriate limit.

---

## Mistake 2 — Forgetting `-v`

Without:

```bash
-v
```

recursive output can become difficult to interpret.

Use it when you need full URLs.

---

## Mistake 3 — Assuming `.php` is universal

If you discovered PHP somewhere, it can be reasonable to use:

```bash
-e .php
```

but remember that a website may contain multiple technologies.

For example:

```text
.php
.html
.js
.json
```

could all exist.

---

## Mistake 4 — Assuming more recursion means better results

More depth means more coverage, but also:

```text
More requests
More time
More noise
More server load
```

The goal isn't necessarily maximum requests.

The goal is:

> **Efficiently discovering useful resources.**

---

# 35. Important Output Fields

When reading recursive ffuf output, pay attention to:

|Field|Meaning|
|---|---|
|`Status`|HTTP response status|
|`Size`|Response body size|
|`Words`|Number of words|
|`Lines`|Number of lines|
|`URL`|Full discovered URL|
|`FUZZ`|Word that produced the result|
|`INFO`|Information about recursive jobs|

---

# 36. Key Output Example

```text
[INFO] Adding a new job to the queue:
http://SERVER_IP:PORT/forum/FUZZ
```

### Meaning

```text
/forum
   ↓
Directory discovered
   ↓
Recursive scan triggered
   ↓
New job created
   ↓
http://SERVER_IP:PORT/forum/FUZZ
```

This is one of the most important lines to recognize.

---

# 37. Request Count

The HTB example explains that the recursive scan:

- Took considerably longer
    
- Sent almost six times as many requests
    
- Used the wordlist with `.php` variants
    
- Performed additional scans inside discovered directories
    

This illustrates an important principle:

> **Automation increases coverage, but increased coverage comes at the cost of more requests.**

---

# 38. Why the Wordlist Effectively Gets Larger

Suppose the wordlist contains:

```text
10,000 words
```

With:

```bash
-e .php
```

ffuf can test:

```text
word
word.php
```

Conceptually:

```text
10,000
   +
10,000 PHP variants
   =
~20,000 candidate requests
```

Then recursion adds additional scans for discovered directories.

Therefore, the total request count can increase dramatically.

---

# 39. Efficiency Strategy

A good enumeration strategy is:

### Phase 1 — Broad

```text
Small wordlist
+
Low recursion depth
```

### Phase 2 — Analyze

Identify:

```text
Interesting directories
Interesting files
Interesting technologies
```

### Phase 3 — Deep

Run targeted fuzzing against the interesting locations.

Example:

```text
/
 ↓
/admin
 ↓
/admin/users
```

rather than scanning every possible branch equally deeply.

---

# 40. Exam / Viva Questions

### Q1. What is recursive fuzzing?

Recursive fuzzing automatically starts new fuzzing scans inside directories discovered during an initial scan.

---

### Q2. Which ffuf flag enables recursion?

```text
-recursion
```

---

### Q3. Which flag controls recursion depth?

```text
-recursion-depth
```

---

### Q4. Why should we specify recursion depth?

Because deeply nested directory structures can cause the scan tree and number of requests to grow rapidly.

---

### Q5. What does `-recursion-depth 1` do?

It limits recursive scanning to a shallow level so that the scan doesn't continue indefinitely into deeper directory structures.

---

### Q6. What does `-e .php` do?

It adds `.php` as an extension to the fuzzing process.

---

### Q7. Why can `.php` be used during recursive scanning?

Because the previous enumeration established evidence that the target uses PHP, and PHP extensions are often used throughout the application.

---

### Q8. What does `-v` do?

It enables verbose output, including full URLs, making recursive results easier to understand.

---

### Q9. What does "Adding a new job to the queue" mean?

It means ffuf discovered a directory and has created another fuzzing job to enumerate that directory.

---

### Q10. Why does recursive fuzzing generate more requests?

Because discovered directories trigger additional scans, and extension fuzzing can also increase the number of candidate requests.

---

### Q11. Why isn't unlimited recursion always desirable?

It can dramatically increase scan duration, traffic, server load, and output.

---

# 41. Quick Revision Sheet

```text
RECURSIVE FUZZING
       │
       ▼
Initial Scan
       │
       ▼
Find Directory
       │
       ▼
Automatically Queue New Scan
       │
       ▼
Fuzz Directory
       │
       ▼
Find More Directories
       │
       ▼
Repeat Until Depth Limit
```

### Core flags

```text
-recursion
        ↓
Enable recursion

-recursion-depth 1
        ↓
Limit recursion depth

-e .php
        ↓
Test PHP extension

-v
        ↓
Show full URLs
```

---

# 42. Golden Command

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
-u http://SERVER_IP:PORT/FUZZ \
-recursion \
-recursion-depth 1 \
-e .php \
-v
```

### Remember the roles:

```text
-w                    → Wordlist
FUZZ                  → Fuzzing keyword
-u                    → Target
-recursion            → Scan discovered directories
-recursion-depth 1   → Limit depth
-e .php               → Test PHP files
-v                    → Show full URLs
```

---

# 43. Manual vs Recursive

```text
MANUAL
────────────────────────────

Fuzz /
 ↓
Find /blog
 ↓
Manually fuzz /blog
 ↓
Find /blog/admin
 ↓
Manually fuzz /blog/admin
 ↓
Repeat...


RECURSIVE
────────────────────────────

Fuzz /
 ↓
Find /blog
 ↓
FFUF queues /blog/FUZZ
 ↓
Find /blog/admin
 ↓
FFUF queues deeper scan
 ↓
Continue until depth limit
```

---

# 44. Golden Methodology

The most important lesson isn't simply memorizing:

```text
-recursion
```

It's understanding **when and why to use it**.

A strong workflow is:

```text
Start with broad enumeration
        ↓
Use limited recursion
        ↓
Review discoveries
        ↓
Identify valuable branches
        ↓
Run deeper targeted scans
```

This gives you the benefits of automation without unnecessarily scanning an enormous directory tree.

---

# 45. Final Takeaways

> **Recursive fuzzing automates the process of fuzzing newly discovered directories.**

> **`-recursion` enables recursive scanning.**

> **`-recursion-depth` limits how deeply ffuf follows the directory tree.**

> **A shallow recursion depth is usually preferable for an initial broad scan.**

> **`-e .php` allows PHP files to be tested alongside the normal wordlist entries.**

> **`-v` displays full URLs and makes recursive results much easier to interpret.**

> **When ffuf says "Adding a new job to the queue," it means a newly discovered directory will be scanned automatically.**

> **Recursive fuzzing can dramatically increase the number of requests.**

> **More recursion isn't necessarily better; targeted deeper enumeration is often more efficient.**

The complete mental model is:

```text
                 ROOT
                  │
             ┌────┴────┐
             ▼         ▼
           /blog     /forum
             │         │
          Recursive  Recursive
             │         │
        ┌────┴───┐     ▼
        ▼        ▼   /users
     index.php  admin
        │
        ▼
   Interesting Page
        │
        ▼
   Manual Analysis
```

### The core progression so far:

```text
Directory Fuzzing
       ↓
Find /blog
       ↓
Extension Fuzzing
       ↓
Find .php
       ↓
Page Fuzzing
       ↓
Find hidden PHP pages
       ↓
Recursive Fuzzing
       ↓
Automate the entire discovery process
```

This is the point where `ffuf` starts becoming much more powerful: instead of treating each directory as a separate manual task, we can let it systematically explore the application's directory tree while keeping the scan depth under control.