![Image](https://images.openai.com/static-rsc-4/9NGuWrjz0aIVWbQMlvxQHTfr-wHaBaMgbScdGRgtbHJw6DchE4Der3HS9HriU8rcHBUhegOgIE9ZL60uWWUfEbjIr7fxVs09xIfMsgT5QUPKkrGLCTMLvqqlc4CLjES-VUHTt0uPp1-Ufm_LE3e2nXLXltEt7EUfVTBr-tjeHNn7V1XF-Tvv8_z9-btdgMTL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/w0CI5N1JIIcFYOaaNuAcnrLGibHR400_CUhWOtIbpACYBx0D7lC9EU4vNpXSGpnHezely1F_L3DjioAqLSGNi5qer4XIPog0XstFkiPzFw1CF6DUmWshPDfv_j-CYFi_O6wY0OzGMSoqQLVWjRz-gZL2CSTldQamfIRQsn-nQ01F-kUolhPsrmXLFFnu9eZL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DOO-J0M-jd-n9Q8TEnx6EdTtrIMul_LGHk6YWnBA2mRt-r7VN7BVaZYke6ejzUlwA2FV6rOpsMt2h8ud6wxZ378ZkHUmWYj3LgDD60LzMQzEIewzhPp-L01avHv_SIbRg6aWbpQ7n0tsGNZRtwgUVa-eqOSjoC5cGn4qc4TTayMwzGJr1NVJwsbGBoNZDpOw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bk0P4HnZ6MtHFa5uV9qks8k3oFlP8w33PH0czwR0f7N1IsFhxbhFhgMJfpURf5m4QmxpOp6bywVjubxiUYCld4mX3eBNMubPIjNs79n57HfdEvwnVM7ZWeC4LN56-a4i_XPI4NIoKVvHsZU2EXKj8IzNucsGM_znp1x5eZ0KYroqg5A1-SC9Rs0s50inUzgp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pX4Zk3O-EaOCfggjWsaK1pwe_-MbR0antFd-Y9SgycgHAMpeB9x5Zo1l1Y1yL6_bQ0fphrjCoX1hFprgo_UQwz1Z_BBioOMfj50M4QX-WwYOuUMVcgz87cQRQJ7-PCxJt_jNBXeTmmizmsg3eZ4l9-i0dNhQ04j4ev0Av0LZU8mg5p89HQR69H752uI0jmVN?purpose=fullsize)
## 1. Introduction

When working with SQLMap, problems can occur while:

- Setting up the target
    
- Reproducing an HTTP request
    
- Supplying cookies
    
- Supplying POST data
    
- Handling headers
    
- Detecting SQL injection
    
- Parsing database responses
    
- Communicating with the target
    

A common mistake is to immediately start changing many SQLMap options.

A better troubleshooting workflow is:

```text
SQLMap Problem
      │
      ▼
Display DBMS errors
      │
      ▼
Inspect HTTP traffic
      │
      ▼
Increase verbosity
      │
      ▼
Use proxy if necessary
      │
      ▼
Identify the actual problem
      │
      ▼
Fix request/configuration
```

The four major troubleshooting tools discussed here are:

|Technique|Main option|Purpose|
|---|---|---|
|Display DB errors|`--parse-errors`|Show database errors|
|Store traffic|`-t`|Save HTTP traffic to a file|
|Verbose output|`-v`|Increase console detail|
|Proxy|`--proxy`|Route traffic through a proxy such as Burp|

---

# 2. First Troubleshooting Principle

Before changing SQLMap's injection settings, determine **where the problem actually occurs**.

The problem could be:

```text
SQLMap
  │
  ├── Request construction
  │
  ├── Network connection
  │
  ├── Authentication
  │
  ├── HTTP response
  │
  ├── DBMS behavior
  │
  └── SQLi detection
```

For example:

```text
Missing Cookie
     ↓
Unauthenticated response
     ↓
SQLMap cannot reach vulnerable functionality
```

This is very different from:

```text
Correct request
     ↓
Application reached
     ↓
SQLMap cannot identify SQLi
```

Therefore, troubleshooting starts by understanding the actual request/response behavior.

---

# 3. `--parse-errors`

One of the first useful options is:

```bash
--parse-errors
```

This tells SQLMap to parse DBMS error messages and display them during the scan.

---

# 4. Why `--parse-errors` Is Useful

Suppose SQLMap reports:

```text
[WARNING] parsed DBMS error message:
'SQLSTATE[42000]: Syntax error or access violation: 1064
You have an error in your SQL syntax...'
```

Now you have additional information about what the backend database is reporting.

Without parsing the error, you might only see:

```text
Testing parameter...
```

With:

```text
--parse-errors
```

you can see database-side errors as part of SQLMap's output.

---

# 5. Example

A command can look like:

```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" \
--parse-errors
```

The output may contain:

```text
[WARNING] parsed DBMS error message:
'SQLSTATE[42000]: Syntax error or access violation: 1064
You have an error in your SQL syntax...'
```

This can help identify:

- DBMS type
    
- SQL syntax problems
    
- Application/database interaction issues
    
- Whether malformed requests are reaching the database
    

---

# 6. Understanding a Parsed DBMS Error

Consider:

```text
SQLSTATE[42000]
```

This is an SQLSTATE-related error classification.

The error may also contain:

```text
1064
```

which is a MySQL-related error code.

The important point is not to memorize every error code.

Instead:

> **The database is telling us what went wrong, and SQLMap is exposing that information to help diagnose the request.**

---

# 7. `--parse-errors` Mental Model

```text
SQLMap
   │
   ▼
HTTP Request
   │
   ▼
Application
   │
   ▼
DBMS
   │
   ├── Normal response
   │
   └── DB error
         │
         ▼
   --parse-errors
         │
         ▼
Error displayed
```

---

# 8. Store HTTP Traffic with `-t`

Another extremely useful debugging option is:

```text
-t
```

It allows SQLMap to store the HTTP traffic in an output file.

Example:

```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" \
--batch \
-t /tmp/traffic.txt
```

---

# 9. What `-t` Stores

The resulting file contains HTTP requests and responses.

For example:

```text
HTTP request [#1]:
GET /?id=1 HTTP/1.1
Host: www.example.com
Cache-control: no-cache
Accept-encoding: gzip,deflate
Accept: */*
User-agent: sqlmap/1.4.9 (http://sqlmap.org)
Connection: close
```

followed by:

```text
HTTP response [#1] (200 OK):
Date: Thu, 24 Sep 2020 14:12:50 GMT
Server: Apache/2.4.41 (Ubuntu)
...
```

---

# 10. Why Traffic Logging Is Useful

Instead of guessing what SQLMap sent, you can inspect the exact traffic.

```text
SQLMap
  │
  ├── Request #1
  ├── Request #2
  ├── Request #3
  ├── Request #4
  └── ...
        │
        ▼
 /tmp/traffic.txt
```

You can then inspect the file manually:

```bash
cat /tmp/traffic.txt
```

---

# 11. What to Look For in Traffic Logs

When troubleshooting, inspect:

### Request

```text
GET /?id=1 HTTP/1.1
```

Ask:

> Is SQLMap actually requesting the expected URL?

### Host

```text
Host: www.example.com
```

Ask:

> Is the correct host being targeted?

### Cookie

```text
Cookie: PHPSESSID=...
```

Ask:

> Is authentication/session information present?

### User-Agent

```text
User-agent: ...
```

Ask:

> Is the expected User-Agent being sent?

### Body

For POST requests:

```text
id=1&name=test
```

Ask:

> Is the body formatted correctly?

### Response status

```text
HTTP/1.1 200 OK
```

or:

```text
HTTP/1.1 403 Forbidden
```

Ask:

> Is the application accepting or rejecting the request?

---

# 12. Request/Response Debugging

A useful debugging model is:

```text
             SQLMap
                │
                │ Request
                ▼
        ┌────────────────┐
        │ Web Application│
        └───────┬────────┘
                │
                │ Response
                ▼
             SQLMap
                │
                ▼
             Analysis
```

If something goes wrong, determine whether the problem is on:

```text
REQUEST
   OR
RESPONSE
   OR
SQLMap's interpretation
```

---

# 13. Verbose Output — `-v`

Another major troubleshooting option is:

```text
-v
```

It controls the verbosity level of SQLMap's console output.

Example:

```bash
sqlmap -u "http://www.target.com/vuln.php?id=1" \
-v 6 \
--batch
```

---

# 14. Verbosity Levels

SQLMap supports verbosity levels from:

```text
0
```

through:

```text
6
```

The higher the value, the more information SQLMap displays.

Conceptually:

```text
-v 0
 ↓
Minimal output

-v 1
 ↓
Normal/default information

-v 2
 ↓
More details

...

-v 6
 ↓
Very detailed debugging output
```

---

# 15. Why `-v 6` Is Important

At high verbosity, SQLMap can show:

- Debug messages
    
- HTTP requests
    
- HTTP responses
    
- Headers
    
- Internal processing information
    
- Connection details
    
- Timing-related information
    

For example:

```text
[DEBUG] resolving hostname 'www.example.com'
```

followed by:

```text
[INFO] testing connection to the target URL
```

and:

```text
[TRAFFIC OUT] HTTP request [#1]:
```

Then:

```text
[TRAFFIC IN] HTTP response [#1] (200 OK):
```

---

# 16. `[DEBUG]`

When you see:

```text
[DEBUG]
```

SQLMap is providing lower-level diagnostic information.

Examples:

```text
[DEBUG] cleaning up configuration parameters
[DEBUG] setting the HTTP timeout
[DEBUG] setting the HTTP User-Agent header
[DEBUG] creating HTTP requests opener object
[DEBUG] resolving hostname 'www.example.com'
```

These messages help identify where SQLMap's internal workflow is reaching a problem.

---

# 17. `[INFO]`

Messages marked:

```text
[INFO]
```

generally describe important normal progress.

Examples:

```text
[INFO] testing connection to the target URL
```

or:

```text
[INFO] testing if the target URL content is stable
```

---

# 18. `[WARNING]`

Messages marked:

```text
[WARNING]
```

indicate something worth paying attention to.

A warning does not necessarily mean SQLMap has failed.

For example:

```text
[WARNING] parsed DBMS error message
```

can actually be useful information.

Another example:

```text
[WARNING] reflective value(s) found and filtering out
```

means SQLMap detected something that could interfere with response comparison and is handling it.

---

# 19. `[TRAFFIC OUT]`

At high verbosity you may see:

```text
[TRAFFIC OUT] HTTP request [#1]:
```

This means:

> SQLMap is showing the request it sent.

Example:

```http
GET /?id=1 HTTP/1.1
Host: www.example.com
User-agent: sqlmap/1.4.9
Connection: close
```

This is extremely useful for checking whether SQLMap constructed the request correctly.

---

# 20. `[TRAFFIC IN]`

You may then see:

```text
[TRAFFIC IN] HTTP response [#1] (200 OK):
```

This means:

> SQLMap is showing the response it received.

You can inspect:

- HTTP status
    
- Headers
    
- Content type
    
- Server information
    
- Page body
    
- Cookies
    
- Other response data
    

---

# 21. `-v 6` vs `-t`

These two options are related but different.

|Option|Purpose|
|---|---|
|`-v 6`|Show detailed traffic/output in the terminal|
|`-t file`|Save HTTP traffic to a file|

### Think:

```text
-v 6
 ↓
Watch it live

-t
 ↓
Save it for later
```

You can also use both when troubleshooting.

---

# 22. Using a Proxy

The final major troubleshooting method is:

```text
--proxy
```

This allows SQLMap's traffic to be routed through a proxy such as:

**Burp Suite**

Conceptually:

```text
SQLMap
   │
   │ HTTP
   ▼
 Burp Suite
   │
   │ HTTP
   ▼
Target
```

Instead of:

```text
SQLMap ───────────→ Target
```

---

# 23. Why Use Burp as a Proxy?

Routing SQLMap through Burp allows you to:

- Inspect requests
    
- Inspect responses
    
- Review HTTP history
    
- Repeat requests
    
- Compare requests
    
- Modify requests during authorized testing
    
- Use Burp's analysis features
    

This is especially useful when SQLMap behaves unexpectedly.

---

# 24. Proxy Debugging Workflow

A common workflow is:

```text
             SQLMap
                │
                ▼
          Burp Proxy
                │
        ┌───────┴───────┐
        │               │
        ▼               ▼
     Request          Response
        │               │
        └───────┬───────┘
                ▼
             Target
```

Burp can therefore act as a visibility layer between SQLMap and the application.

---

# 25. Why a Proxy Is Powerful for Troubleshooting

Suppose SQLMap says:

```text
Parameter does not appear injectable
```

Instead of guessing, you can inspect the request in Burp.

Maybe you discover:

```text
Missing Cookie
```

or:

```text
Wrong HTTP method
```

or:

```text
Incorrect POST body
```

or:

```text
Unexpected redirect
```

The proxy helps you identify the actual problem.

---

# 26. Four Troubleshooting Tools Compared

|Tool/Option|What it shows|Best use|
|---|---|---|
|`--parse-errors`|DBMS errors|Database/application errors|
|`-t traffic.txt`|Saved HTTP traffic|Detailed offline analysis|
|`-v 6`|Detailed live output|Real-time debugging|
|`--proxy`|Traffic through proxy|Interactive HTTP analysis|

---

# 27. Recommended Troubleshooting Order

When SQLMap isn't behaving as expected, use this order:

### Step 1 — Check the request

Ask:

```text
Is the URL correct?
Is the parameter correct?
Is the HTTP method correct?
Is the POST body correct?
Are cookies present?
Are required headers present?
```

---

### Step 2 — Parse DB errors

Use:

```bash
--parse-errors
```

This can expose useful database-side information.

---

### Step 3 — Save traffic

Use:

```bash
-t /tmp/traffic.txt
```

Then inspect:

```bash
cat /tmp/traffic.txt
```

---

### Step 4 — Increase verbosity

Use:

```bash
-v 6
```

This lets you see detailed request/response behavior live.

---

### Step 5 — Use Burp

If the problem is still unclear:

```text
SQLMap
  ↓
Burp
  ↓
Target
```

Inspect the requests interactively.

---

# 28. Practical Debugging Example

Suppose you run:

```bash
sqlmap -u "http://target/vuln.php?id=1"
```

and SQLMap doesn't detect SQLi.

Don't immediately assume:

```text
"No SQLi exists."
```

Instead:

```text
1. Check request
       ↓
2. Check response
       ↓
3. Check cookies
       ↓
4. Check parameters
       ↓
5. Parse DB errors
       ↓
6. Inspect traffic
       ↓
7. Increase verbosity
       ↓
8. Use Burp if necessary
```

Only after troubleshooting should you conclude that the parameter may not be injectable.

---

# 29. Common Causes of SQLMap Problems

## Missing authentication

```text
Browser:
Cookie = present

SQLMap:
Cookie = missing
```

Result:

```text
SQLMap reaches login page
```

instead of the vulnerable endpoint.

---

## Incorrect POST body

Expected:

```text
uid=1&name=test
```

Actual:

```text
uid=1 name=test
```

The application may parse these completely differently.

---

## Wrong HTTP method

Application expects:

```text
PUT
```

but SQLMap sends:

```text
GET
```

The request may not reach the vulnerable code path.

---

## Missing headers

Some applications behave differently depending on:

```text
Content-Type
Authorization
Referer
User-Agent
Host
Cookie
```

---

## Dynamic application behavior

The target may generate different responses for reasons unrelated to SQLi.

This can cause problems with:

```text
Boolean-based detection
Time-based detection
```

---

# 30. Important Distinction: Error vs Detection Failure

A SQLMap problem does not necessarily mean:

```text
SQLi does not exist
```

It could mean:

```text
SQLMap cannot correctly reproduce the request
```

Therefore:

```text
Detection failure
       ≠
Vulnerability absence
```

This is one of the most important troubleshooting lessons.

---

# 31. HTTP Traffic as Ground Truth

When troubleshooting SQLMap, the actual HTTP traffic is often the best source of truth.

Think:

```text
SQLMap console
      ↓
"What SQLMap thinks it sent"

HTTP traffic
      ↓
"What SQLMap actually sent"
```

Therefore, if you are confused, inspect:

```text
Request
+
Response
```

rather than relying only on summary messages.

---

# 32. Important Output Prefixes

Memorize these:

```text
[INFO]
```

Normal progress/information.

```text
[WARNING]
```

Potential issue or notable condition.

```text
[DEBUG]
```

Detailed internal diagnostic information.

```text
[TRAFFIC OUT]
```

Request sent by SQLMap.

```text
[TRAFFIC IN]
```

Response received by SQLMap.

---

# 33. Quick Command Reference

### Display database errors

```bash
sqlmap -u "http://target/?id=1" --parse-errors
```

### Save traffic

```bash
sqlmap -u "http://target/?id=1" \
-t /tmp/traffic.txt
```

### High verbosity

```bash
sqlmap -u "http://target/?id=1" \
-v 6
```

### Combine useful debugging options

```bash
sqlmap -u "http://target/?id=1" \
--parse-errors \
-v 6 \
-t /tmp/traffic.txt
```

### Route through a proxy

Conceptually:

```bash
sqlmap -u "http://target/?id=1" \
--proxy="http://127.0.0.1:8080"
```

The exact proxy address/port should match your authorized testing setup.

---

# 34. Debugging Decision Tree

```text
              SQLMap problem
                    │
                    ▼
           Is the request correct?
               /          \
             NO            YES
             │              │
             ▼              ▼
        Fix request    Parse DB errors
                            │
                            ▼
                     Save HTTP traffic
                            │
                            ▼
                       -v 6 output
                            │
                            ▼
                     Still unclear?
                       /       \
                     YES       NO
                      │         │
                      ▼         ▼
                   Burp      Fix issue
                   Proxy
                      │
                      ▼
               Inspect request
               and response
```

---

# 35. The Four Commands to Memorize

```text
--parse-errors
        ↓
Show DB errors
```

```text
-t traffic.txt
        ↓
Save HTTP traffic
```

```text
-v 6
        ↓
Show detailed debugging output
```

```text
--proxy
        ↓
Route traffic through proxy
```

### Memory trick

> **Errors → Traffic → Verbosity → Proxy**

```text
ERRORS
  ↓
TRAFFIC
  ↓
VERBOSE
  ↓
PROXY
```

---

# 36. Final Practical Workflow

For an authorized lab, when SQLMap gives unexpected results:

```text
             SQLMap
                │
                ▼
        Something doesn't work
                │
                ▼
        ┌──────────────────┐
        │ Check target URL │
        └────────┬─────────┘
                 ▼
        Check parameter/body
                 │
                 ▼
          Check cookies
                 │
                 ▼
        Check HTTP method
                 │
                 ▼
        --parse-errors
                 │
                 ▼
        -t traffic.txt
                 │
                 ▼
              -v 6
                 │
                 ▼
        --proxy → Burp
                 │
                 ▼
          Inspect request
          + response
                 │
                 ▼
           Fix the issue
```

---

# 37. Final Takeaway

The most important lesson from **Handling SQLMap Errors** is:

> **Don't troubleshoot SQLMap by blindly changing options. First determine what SQLMap is actually sending, what the server is returning, and what the database is reporting.**

Use:

```text
--parse-errors
```

when you need database errors.

Use:

```text
-t
```

when you want to save the complete HTTP traffic.

Use:

```text
-v 6
```

when you want to watch detailed SQLMap behavior in real time.

Use:

```text
--proxy
```

when you want interactive inspection through Burp or another authorized proxy.

### Ultimate troubleshooting formula

```text
                SQLMap Issue
                     │
                     ▼
              "What was sent?"
                     │
                 -t / -v 6
                     │
                     ▼
             "What came back?"
                     │
              Traffic/response
                     │
                     ▼
             "What did DB say?"
                     │
              --parse-errors
                     │
                     ▼
            "Need live inspection?"
                     │
                  --proxy
                     │
                     ▼
               Find the cause
                     │
                     ▼
                 Fix it
```

**For HTB/lab work, the big skill here is not memorizing four switches—it is learning to read the HTTP request/response and use SQLMap's output to locate exactly where the failure is occurring.**