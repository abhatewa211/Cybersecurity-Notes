![Image](https://images.openai.com/static-rsc-4/8Sxu7-XG8N21IeWxureaIZmOo7RUzSAHqHKXiSNAPqHMbfJran99gLR0WGsRtYGOKV85fXfZ7UxKvpFE2K04vGQcAjZY_jkwXQvhz9U8J-0OaZ9PoHch4l7ws2Pf3fqzFTwkelkzNmN3DvLpBB2eEZNfCEyOdP4YZMo-ueZS0m9rirnosZ1xL0UBkylqYj_w?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pCfga3jg2776NCvoqxuYLpUS4gVeo6P-kPqlR6dmyJnStIGxJX73ry_F0RY_aJmz6oDdu9JTpp-MkfQb76TMLoPCyb3E5ZZ8Auvkh8Kj4rJXbiYSGi33BnCgFzmxcL6iMaHxQTgedAypkcR2_AtYTMiPMidqnsa90VN8J6qGYQ_r5ELfUQEHSpLPZRCiAk9a?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I1icbnleHNxjt3-zeHP2_hiAWI_kRRZIKZa5IE0jNX3Pq2FECCN2ScrS077P2Ncd6ZnffhjrInWG-QUv1BuhglBnreSPB0ZSJcdriQmS89YtEvx5Dj4GrJXkOR6NINq_-WklIpV-HuXAphZmmMHa1k19OIhWPz2JAPe2DAltZUHus1xjiu3y6zPTW3-aWMui?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tNMPeYeiKLIRG-Ra2PJ6K5X_9nRaOb8Hn7bLsn30SRvw324-X_HBa5oXYDwxxr6mPe59hL1LSF8Rj_XIrSJ-hQq_RrtqPzsEIhD7Kks3vTWGtxe_-8s9exgMNY15KdyP7PFSg1304w6V0OJj4amRqqXdUqL_oWaK1SmDTDbJloSmLd7Rb6C26adHQAGLCdow?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nEL0CBv55qBN8y0J9aXVjRh7NXVkwSHj5vplR0CPs3sXBdIPJWvxZmgKNiQJ4xPUmnxevZjxQAvBdw1qri2FiiH6ViBqb_gywbx_u9qWEgCkMJpNSsLtOsBVIjD-SVsnlRTbjgX47Si53MMcRARtW-pGQHvuihWORmHvmU_xTXbiL8g1Ymq3YBEJWYd491Zs?purpose=fullsize)

This section introduces another major stage of web enumeration: **finding hidden GET parameters**. The important idea is that a web page may expose functionality that isn't visible through links or forms, but can be activated by supplying a specific parameter.

---

# 1. Introduction

After discovering the VHost:

```text
admin.academy.htb
```

a recursive `ffuf` scan reveals:

```text
/admin/admin.php
```

When we visit:

```text
http://admin.academy.htb:PORT/admin/admin.php
```

we see a message indicating that we don't have permission to read the `flag`.

This raises an important question:

> **What does the application use to determine whether we are allowed to access the flag?**

---

# 2. What We Know

We haven't:

- Logged in
    
- Received an authentication cookie
    
- Supplied credentials
    
- Established a session
    

Yet the page is clearly performing some form of access check.

That suggests the application might accept some additional input.

One possibility is a **parameter**.

Conceptually:

```text
Request
   │
   ▼
/admin/admin.php
   │
   ▼
Application checks input
   │
   ├── No parameter → Access denied
   │
   └── Correct parameter → Potentially different behavior
```

---

# 3. What Is a Parameter?

A parameter is additional data supplied to a web application.

For example:

```text
http://example.com/page.php?id=10
```

Here:

```text
id=10
```

is a parameter.

It consists of:

```text
Parameter name = Value
```

So:

```text
id=10
```

means:

```text
name  → id
value → 10
```

---

# 4. GET Parameters

A **GET parameter** is commonly placed directly in the URL after a `?`.

Example:

```text
http://example.com/page.php?name=admin
```

The structure is:

```text
http://example.com/page.php?name=admin
                         │    │
                         │    └── Value
                         └─────── Parameter name
```

---

# 5. The `?` Character

The question mark separates the URL path from the query string.

Example:

```text
http://example.com/admin.php?key=value
```

Breakdown:

```text
http://example.com
        │
        └── /admin.php
                 │
                 └── ?key=value
```

Everything after `?` is part of the query string.

---

# 6. Parameter Name vs Parameter Value

This distinction is critical for parameter fuzzing.

Consider:

```text
/admin.php?key=secret
```

There are two components:

```text
key
│
└── Parameter name

secret
│
└── Parameter value
```

In this section, we are initially fuzzing the **parameter name**, not the value.

---

# 7. The Fuzzing Goal

We don't know which parameter the application expects.

It could be:

```text
key
id
user
admin
access
auth
token
debug
file
page
```

Instead of guessing manually, we use a wordlist.

Conceptually:

```text
/admin.php?FUZZ=key
```

Ffuf replaces:

```text
FUZZ
```

with words from the parameter wordlist.

---

# 8. Parameter Fuzzing

Suppose the wordlist contains:

```text
id
key
admin
token
debug
```

Ffuf effectively tests:

```text
/admin.php?id=key
/admin.php?key=key
/admin.php?admin=key
/admin.php?token=key
/admin.php?debug=key
```

The server's responses are then compared.

---

# 9. Why Do We Need a Parameter Wordlist?

Web applications frequently use predictable parameter names.

Examples include:

```text
id
page
file
user
name
search
query
token
key
debug
admin
action
```

A specialized wordlist saves us from manually testing thousands of possible names.

---

# 10. SecLists Parameter Wordlist

The module uses:

```text
/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

This is a wordlist containing commonly encountered web parameter names.

It is therefore appropriate for parameter discovery.

---

# 11. The Basic Ffuf Command

The module uses:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key \
-fs xxx
```

The important portion is:

```text
?FUZZ=key
```

---

# 12. Breaking Down the Command

### `-w`

Specifies the parameter wordlist:

```text
-w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ
```

---

### `-u`

Specifies the target:

```text
-u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key
```

---

### `FUZZ`

This is the parameter name we're discovering.

For example:

```text
FUZZ = id
```

becomes:

```text
/admin/admin.php?id=key
```

---

### `key`

This is the **value** we're supplying for every candidate parameter.

So:

```text
FUZZ=key
```

means:

> Try each possible parameter name using `key` as its value.

---

### `-fs xxx`

This filters the normal/default response size.

The module uses:

```text
xxx
```

as a placeholder because the exact size depends on the target instance.

You should determine the actual baseline response size for your running lab.

---

# 13. Why Do We Filter?

Just like VHost fuzzing, parameter fuzzing can produce many responses that look identical.

For example:

```text
id=key      → 200 / 500 bytes
admin=key   → 200 / 500 bytes
debug=key   → 200 / 500 bytes
token=key   → 200 / 500 bytes
```

If the normal response is:

```text
500 bytes
```

we can use:

```bash
-fs 500
```

to remove those results.

Then an unusual response might stand out:

```text
secret=key → 200 / 850 bytes
```

---

# 14. Baseline First

As always:

> **Identify the normal response before deciding what to filter.**

A good workflow is:

```text
Request without useful parameter
        ↓
Observe response
        ↓
Record size
        ↓
Fuzz parameters
        ↓
Filter baseline size
        ↓
Investigate anomalies
```

This is the same methodology we used for VHosts.

---

# 15. Why Use a Constant Value?

We don't yet know the correct parameter value.

Our first question is:

> **Does this parameter exist and affect the application?**

Therefore, we keep the value simple:

```text
key
```

and fuzz only the parameter name:

```text
FUZZ=key
```

This separates the problem into two stages:

```text
Stage 1:
Find the parameter name

Stage 2:
Determine the correct parameter value
```

---

# 16. Parameter Name Discovery

Suppose the real application expects:

```text
?access=secret
```

but we don't know `access`.

Our first scan tests:

```text
?access=key
```

along with thousands of alternatives.

If `access` produces a different response, we have discovered something important:

```text
access
  ↓
Application recognizes parameter
  ↓
Investigate its value
```

We don't necessarily know the correct value yet.

---

# 17. The Module's Result

The parameter fuzzing scan produces a single interesting hit.

However, when we visit it:

```text
http://admin.academy.htb:PORT/admin/admin.php?REDACTED=key
```

the application responds:

```text
This method is deprecated
```

This is an important result.

It tells us:

> **We discovered a real/recognized parameter, but the application no longer uses it for the functionality we're looking for.**

---

# 18. "Deprecated" Does NOT Mean "Fake"

This is an important distinction.

If the application says:

```text
This method is deprecated
```

the parameter was probably meaningful to the application at some point.

The parameter may still exist in the codebase or application logic, but its associated functionality has been retired.

Therefore:

```text
Parameter discovered
        ↓
Different response
        ↓
Parameter is recognized
        ↓
But functionality is deprecated
        ↓
Continue enumeration
```

---

# 19. Why This Is Still a Valuable Discovery

Even though the parameter doesn't give us the flag, we've learned something about the application.

We've discovered:

```text
A parameter name
        +
Application behavior
```

That can reveal:

- Legacy functionality
    
- Older application logic
    
- Unpublished parameters
    
- Developer assumptions
    
- Possible attack surface
    

This is why parameter fuzzing is valuable even when the first hit isn't immediately useful.

---

# 20. Hidden Parameters Are Important

The module gives an important tip:

> Fuzzing parameters may expose unpublished parameters that are publicly accessible.

This is significant because an application might have functionality that isn't linked from the interface.

For example, a normal page might only show:

```text
/admin/admin.php
```

but the backend might support:

```text
/admin/admin.php?debug=true
```

or:

```text
/admin/admin.php?mode=legacy
```

without exposing those options through the UI.

---

# 21. Why Unpublished Parameters Can Be Risky

Developers may spend most of their security effort testing the obvious application paths.

Hidden parameters may receive less testing.

For example:

```text
Normal interface
      ↓
Well tested
      ↓
/login
/admin
/dashboard

Hidden parameter
      ↓
Less obvious
      ↓
?debug=
?legacy=
?internal=
```

Therefore, discovered parameters should be assessed carefully for vulnerabilities.

---

# 22. Parameter Fuzzing and Web Vulnerabilities

Finding a parameter is only the beginning.

Once we discover:

```text
?parameter=value
```

we can investigate how the application processes the value.

Depending on the application, parameters may potentially be relevant to vulnerabilities such as:

```text
SQL Injection
Cross-Site Scripting
Local File Inclusion
Command Injection
Path Traversal
Authentication/authorization flaws
Server-Side Request Forgery
```

The exact testing depends on the application's behavior and the authorized lab scope.

---

# 23. GET vs POST

This section focuses on **GET parameters**.

### GET

Parameters appear in the URL:

```text
/admin.php?key=value
```

### POST

Parameters are generally sent in the request body:

```http
POST /admin.php HTTP/1.1

key=value
```

Conceptually:

```text
GET:
URL
 │
 └── ?parameter=value


POST:
Request
 │
 └── Body
       │
       └── parameter=value
```

The module covers POST parameter fuzzing separately.

---

# 24. Multiple GET Parameters

GET requests can contain multiple parameters.

Example:

```text
/admin.php?user=admin&key=secret
```

Here:

```text
user=admin
key=secret
```

are two separate parameters.

They are separated by:

```text
&
```

So:

```text
?param1=value1&param2=value2
```

is the general format.

---

# 25. Parameter Fuzzing vs Parameter-Value Fuzzing

These are different tasks.

### Parameter-name fuzzing

```text
/admin.php?FUZZ=key
```

Question:

> **Which parameter names are accepted?**

### Parameter-value fuzzing

```text
/admin.php?key=FUZZ
```

Question:

> **Which values are accepted for the `key` parameter?**

This distinction becomes very important later in the module.

---

# 26. Visualizing the Difference

```text
PARAMETER NAME FUZZING

/admin.php?FUZZ=key
             │
             └── What parameter name works?
```

versus:

```text
PARAMETER VALUE FUZZING

/admin.php?key=FUZZ
                  │
                  └── What value works?
```

Memorize this.

---

# 27. The Full GET Parameter Workflow

```text
/admin/admin.php
       │
       ▼
Access denied
       │
       ▼
Maybe hidden parameter?
       │
       ▼
Choose parameter wordlist
       │
       ▼
/admin.php?FUZZ=key
       │
       ▼
Ffuf tests thousands of names
       │
       ▼
Filter normal response
       │
       ▼
Interesting response
       │
       ▼
Manually verify
       │
       ▼
Deprecated parameter
       │
       ▼
Continue enumeration
```

---

# 28. Why the Value `key` Isn't Necessarily Correct

Don't misunderstand:

```text
?FUZZ=key
```

as:

> "The key is `key`."

It simply means we're giving every discovered parameter a test value.

For example:

```text
FUZZ=id
```

produces:

```text
?id=key
```

and:

```text
FUZZ=access
```

produces:

```text
?access=key
```

The value is merely a probe.

---

# 29. Example

Imagine the application expects:

```text
?auth=letmein
```

We don't know either piece initially.

First we fuzz names:

```text
?FUZZ=key
```

Eventually:

```text
?auth=key
```

produces a different response.

Now we know:

```text
auth
```

is probably interesting.

Next we can investigate:

```text
?auth=FUZZ
```

to discover possible values.

This is the natural progression.

---

# 30. Filtering Strategy

Suppose the normal response is:

```text
Status: 200
Size: 465
Words: 42
Lines: 15
```

Then:

```bash
-fs 465
```

can remove the default responses.

If the interesting parameter returns:

```text
Status: 200
Size: 900
Words: 80
Lines: 25
```

it remains visible.

---

# 31. Why Response Size Can Be More Useful Than Status

Consider:

```text
Parameter     Status     Size
--------------------------------
id            200        465
user          200        465
debug         200        465
auth          200        900
token         200        465
```

If we only look at status:

```text
200
200
200
200
200
```

everything appears identical.

But response size reveals:

```text
auth → 900
```

which makes it interesting.

---

# 32. Common Mistakes

## Mistake 1 — Fuzzing the value instead of the name

This:

```text
/admin.php?FUZZ=key
```

finds parameter names.

This:

```text
/admin.php?key=FUZZ
```

finds parameter values.

Don't mix them up.

---

## Mistake 2 — Forgetting the `?`

Incorrect:

```text
/admin.php/FUZZ=key
```

Correct:

```text
/admin.php?FUZZ=key
```

---

## Mistake 3 — Ignoring baseline responses

If every request returns the same response, identify its size/words/lines and filter it.

---

## Mistake 4 — Assuming every hit gives useful functionality

The discovered parameter in this section returns:

```text
This method is deprecated
```

It is still a legitimate discovery, but it isn't the desired solution.

---

## Mistake 5 — Stopping after the first hit

Parameter fuzzing should be treated as enumeration.

A hit may be:

```text
Interesting
        ↓
Deprecated
        ↓
Continue looking
```

---

# 33. Useful Ffuf Options for Parameter Fuzzing

|Option|Purpose|
|---|---|
|`-w`|Parameter wordlist|
|`-u`|Target URL|
|`-fs`|Filter response size|
|`-fw`|Filter word count|
|`-fl`|Filter line count|
|`-fc`|Filter status codes|
|`-mc`|Match status codes|
|`-ms`|Match response size|

The basic pattern is:

```text
Wordlist
   +
FUZZ
   +
GET parameter
   +
Baseline filtering
```

---

# 34. Golden Command

Parameter-name fuzzing:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key \
-fs BASELINE_SIZE
```

Where:

```text
BASELINE_SIZE
```

should be replaced with the actual default response size.

---

# 35. Golden Mental Model

```text
                 ADMIN PAGE
                     │
                     ▼
              Access denied
                     │
                     ▼
          Maybe hidden parameter
                     │
                     ▼
             Parameter wordlist
                     │
                     ▼
             ?FUZZ=key
                     │
                     ▼
              Ffuf enumeration
                     │
                     ▼
          Filter default response
                     │
                     ▼
             Interesting hit
                     │
                     ▼
              Manual testing
                     │
                     ▼
          "Method deprecated"
                     │
                     ▼
             Continue hunting
```

---

# 36. Parameter Fuzzing Cheat Sheet

### Find parameter names:

```bash
ffuf -w parameter-wordlist:FUZZ \
-u http://TARGET/page.php?FUZZ=value
```

### Find parameter values:

```bash
ffuf -w value-wordlist:FUZZ \
-u http://TARGET/page.php?parameter=FUZZ
```

### Filter response size:

```bash
-fs SIZE
```

### Filter status code:

```bash
-fc CODE
```

### Filter word count:

```bash
-fw WORDS
```

### Filter line count:

```bash
-fl LINES
```

---

# 37. Parameter Enumeration Logic

A useful way to think about this is:

```text
                 UNKNOWN
                    │
           ┌────────┴────────┐
           ▼                 ▼
     Parameter Name      Parameter Value
           │                 │
           ▼                 ▼
       ?FUZZ=value       ?name=FUZZ
           │                 │
           ▼                 ▼
      Discover name      Discover value
```

So if we eventually determine:

```text
name = access
```

we can move to:

```text
?access=FUZZ
```

---

# 38. Exam / Viva Questions

### Q1. What is a GET parameter?

A value supplied through the URL's query string after `?`.

Example:

```text
?page=1
```

---

### Q2. Where are GET parameters located?

After the `?` in the URL.

---

### Q3. What separates multiple GET parameters?

The:

```text
&
```

character.

Example:

```text
?id=1&user=admin
```

---

### Q4. What does `?FUZZ=key` do?

It fuzzes the **parameter name** while using `key` as the test value.

---

### Q5. Which wordlist is used in the module?

```text
/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

---

### Q6. Why do we use `-fs`?

To remove the common/default response based on its response size.

---

### Q7. What is the difference between parameter-name and parameter-value fuzzing?

```text
?FUZZ=value
```

finds parameter names.

```text
?parameter=FUZZ
```

finds parameter values.

---

### Q8. What did the discovered parameter return?

```text
This method is deprecated
```

---

### Q9. Does a deprecated parameter mean the scan failed?

No. It means the application recognized or processed the parameter differently, but the associated functionality is no longer in use.

---

### Q10. Why are hidden parameters worth investigating?

Because unpublished parameters can expose additional functionality and may have received less security testing.

---

# 39. Important Things to Memorize

```text
GET parameter:
?page=value
```

```text
Parameter-name fuzzing:
?FUZZ=value
```

```text
Parameter-value fuzzing:
?parameter=FUZZ
```

```text
Filter response size:
-fs SIZE
```

```text
Parameter wordlist:
/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

---

# 40. Final Takeaways

> **GET parameters are passed in the URL after `?`.**

> **Parameter-name fuzzing uses `?FUZZ=value`.**

> **Parameter-value fuzzing uses `?parameter=FUZZ`.**

> **SecLists provides specialized parameter-name wordlists.**

> **The module uses `burp-parameter-names.txt`.**

> **A response-size filter helps eliminate the normal/default response.**

> **A different response doesn't necessarily mean you've found the final solution; it means the parameter deserves investigation.**

> **The parameter discovered in this section was recognized but returned "This method is deprecated."**

> **Hidden/unpublished parameters are important attack-surface discoveries because they may expose functionality that isn't linked through the normal application interface.**

### The core progression:

```text
Admin page
    ↓
Access denied
    ↓
Suspect hidden parameter
    ↓
?FUZZ=key
    ↓
Ffuf parameter enumeration
    ↓
Filter baseline
    ↓
Parameter discovered
    ↓
Manual verification
    ↓
Deprecated
    ↓
Continue enumeration
```

### And the most important syntax:

```text
# Parameter NAME fuzzing
/admin.php?FUZZ=key

# Parameter VALUE fuzzing
/admin.php?parameter=FUZZ
```

**Memorize that distinction — it becomes the foundation for the next parameter-fuzzing techniques.**