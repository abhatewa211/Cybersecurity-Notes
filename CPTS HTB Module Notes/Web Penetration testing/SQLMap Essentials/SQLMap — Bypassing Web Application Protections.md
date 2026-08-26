# 1. Overview

In an ideal penetration-testing scenario, the target does not have additional protection mechanisms that interfere with automated testing.

In real applications, however, automated tools can encounter protections that make requests invalid, blocked, or difficult to analyze.

SQLMap incorporates several mechanisms intended to deal with these situations.

### Main protection categories covered

```text
                    WEB APPLICATION
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
       CSRF            Unique           Calculated
       Token           Values             Values
          │               │                │
          └───────────────┼────────────────┘
                          │
                          ▼
                    Request Validation
                          │
          ┌───────────────┼────────────────┐
          ▼               ▼                ▼
       WAF/IPS        User-Agent        IP Filtering
          │               │                │
          └───────────────┼────────────────┘
                          ▼
                    SQLMap Request
```

---

# 2. Anti-CSRF Token Bypass

## What is CSRF?

**CSRF = Cross-Site Request Forgery**

An anti-CSRF token is a value incorporated into HTTP requests to ensure that a request was generated from a legitimate interaction with the application.

The material explains that these tokens are particularly common in requests generated through web forms.

---

## Why CSRF tokens can affect SQLMap

A typical protected request might conceptually look like:

```text
POST /update HTTP/1.1

id=1&csrf-token=ABC123
```

The server expects the token to be valid.

If SQLMap repeatedly sends:

```text
csrf-token=ABC123
```

the application may reject subsequent requests because the token is no longer valid.

### Visual model

```text
Normal browser:

GET form
   ↓
Server generates token
   ↓
Browser receives token
   ↓
Browser submits token
   ↓
Server validates token ✓


Automated requests:

Request 1 → token A ✓
Request 2 → token A ✗
Request 3 → token A ✗
```

---

# 3. `--csrf-token`

SQLMap provides:

```text
--csrf-token
```

for this situation.

The option specifies the **token parameter name** that already exists within the supplied request data.

SQLMap can then parse the target response, search for a fresh token value, and use that value in subsequent requests.

### Example from the material

```bash
sqlmap -u "http://www.example.com/" \
--data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" \
--csrf-token="csrf-token"
```

SQLMap recognizes:

```text
POST parameter 'csrf-token' appears to hold anti-CSRF token.
```

and asks whether it should automatically update the value in future requests.

---

## Automatic CSRF recognition

Even without explicitly specifying `--csrf-token`, SQLMap can recognize common parameter-name infixes such as:

```text
csrf
xsrf
token
```

and may prompt the user about updating the value.

### Remember

```text
--csrf-token
      ↓
Identify CSRF parameter
      ↓
Parse response
      ↓
Find fresh token
      ↓
Update next request
```

---

# 4. Unique Value Bypass

Some applications require a parameter to contain a **unique value for every request**.

This is similar to CSRF protection, but the application may not need SQLMap to parse the page to obtain the value.

Instead:

```text
Request 1 → unique value
Request 2 → different value
Request 3 → different value
```

The material describes this as another mechanism that can prevent CSRF attempts while also interfering with some automation tools.

---

# 5. `--randomize`

SQLMap provides:

```text
--randomize
```

to randomize the value of a specified parameter before sending the request.

### Example

```bash
sqlmap -u "http://www.example.com/?id=1&rp=29125" \
--randomize=rp --batch -v 5
```

Here:

```text
rp=29125
```

is the parameter being randomized.

The material demonstrates different values being generated across requests:

```text
rp=99954
rp=87216
rp=36456
rp=16689
rp=40049
rp=95185
```

### Mental model

```text
--randomize=rp

rp=29125
   ↓
rp=99954
   ↓
rp=87216
   ↓
rp=36456
   ↓
...
```

---

# 6. Calculated Parameter Bypass

Another protection mechanism occurs when one parameter's value must be **calculated from another parameter**.

A common conceptual example is:

```text
id=1
h=MD5(id)
```

So:

```text
id = 1
h = MD5(1)
```

The application expects the relationship between the parameters to remain valid.

---

# 7. `--eval`

SQLMap provides:

```text
--eval
```

for evaluating Python code immediately before the request is sent.

The material's example is:

```bash
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b49" \
--eval="import hashlib; h=hashlib.md5(id).hexdigest()" \
--batch -v 5
```

The provided source shows the same mechanism with the calculated `h` value changing as SQLMap changes `id`.

### Conceptual flow

```text
SQLMap changes id
       ↓
--eval executes Python
       ↓
Calculate h from id
       ↓
Send:
id=<new value>
h=<calculated value>
       ↓
Application validates relationship
```

### Key difference

|Option|Purpose|
|---|---|
|`--csrf-token`|Refresh an anti-CSRF token|
|`--randomize`|Generate a different value for a parameter|
|`--eval`|Calculate a parameter based on other request values|

---

# 8. IP Address Concealing

The material also discusses situations where the tester wants to conceal the originating IP or where the application's protection mechanism blocks the current IP address. It describes using a proxy or Tor.

> In authorized testing, this can also be useful for testing whether IP-based controls behave as expected.

---

# 9. `--proxy`

SQLMap can route traffic through a proxy using:

```text
--proxy
```

Example from the source:

```bash
--proxy="socks4://177.39.187.70:33283"
```

Conceptually:

```text
SQLMap
   │
   ▼
 Proxy
   │
   ▼
Target
```

Instead of:

```text
SQLMap ───────────► Target
```

---

# 10. `--proxy-file`

If multiple proxies are available, SQLMap can use:

```text
--proxy-file
```

The material explains that SQLMap goes sequentially through the proxy list and can move to the next proxy if the current one encounters problems such as IP blacklisting.

Conceptually:

```text
Proxy 1
   ↓
fails/blocked
   ↓
Proxy 2
   ↓
fails/blocked
   ↓
Proxy 3
   ↓
Target
```

---

# 11. Tor

SQLMap also supports the Tor network using:

```text
--tor
```

The source explains that when Tor is properly installed, a SOCKS4 proxy service should normally be available locally on port:

```text
9050
```

or:

```text
9150
```

SQLMap can attempt to locate and use the local Tor service.

---

# 12. `--check-tor`

To verify whether SQLMap is actually using Tor:

```text
--check-tor
```

can be used.

The material says SQLMap checks the Tor Project's check service and looks for the expected result, including the presence of:

```text
Congratulations
```

### Mental model

```text
SQLMap
   ↓
Tor
   ↓
Tor exit node
   ↓
Target

--check-tor
   ↓
Verify Tor connectivity
```

---

# 13. WAF Bypass

## What is a WAF?

**WAF = Web Application Firewall**

A WAF can inspect HTTP requests and block traffic that appears malicious.

During its initial testing, SQLMap performs a heuristic check for the presence of a WAF. It sends a predefined malicious-looking payload using a non-existent parameter.

Conceptually:

```text
SQLMap
   │
   │ suspicious test request
   ▼
   WAF
   │
   ├── Allowed → normal response
   │
   └── Blocked → different response
```

---

# 14. Detecting a WAF

The material gives **ModSecurity** as an example.

If ModSecurity is present, a request may produce:

```text
406 - Not Acceptable
```

instead of the normal response.

This response difference can indicate protection between the tester and the target.

---

# 15. `identYwaf`

When SQLMap detects a possible WAF, it uses the third-party library:

```text
identYwaf
```

The material states that this library contains signatures for:

```text
80 different WAF solutions
```

---

# 16. `--skip-waf`

If you want SQLMap to skip its initial WAF heuristic test:

```bash
--skip-waf
```

can be used.

The material describes this as useful when you want to produce less noise from the heuristic test.

---

# 17. User-Agent Blacklisting

SQLMap normally has a recognizable default User-Agent, for example:

```text
User-agent: sqlmap/1.4.9 (http://sqlmap.org)
```

Some defenses can immediately identify and block requests containing this value.

A possible symptom is receiving an HTTP `5XX` response immediately when SQLMap starts.

---

# 18. `--random-agent`

SQLMap provides:

```text
--random-agent
```

which changes the default SQLMap User-Agent to a randomly selected value from a pool of browser User-Agent values.

### Concept

```text
Default:

User-Agent: sqlmap/...


        ↓ --random-agent


Browser-like User-Agent
```

---

# 19. Important Protection Reality

The material makes an important observation:

> Once some form of protection is detected, additional security mechanisms may also cause problems.

It explains that security protections continue to evolve, leaving less maneuvering space for automated exploitation tools.

So don't assume:

```text
WAF detected
   ↓
One bypass
   ↓
Everything works
```

Real applications can have **multiple layers of defense**.

---

# 20. Tamper Scripts

One of SQLMap's most well-known mechanisms for modifying requests is the use of **tamper scripts**.

A tamper script is a Python script that modifies a request immediately before it is sent to the target, commonly to change the representation of a payload so that certain protections do not recognize it.

### Visual model

```text
Original SQLMap payload
          │
          ▼
     Tamper script
          │
          ▼
Modified representation
          │
          ▼
        Target
```

---

# 21. Example: `between`

The source uses the `between` tamper script as an example.

It changes:

```text
>
```

into a `NOT BETWEEN` representation and changes:

```text
=
```

into a `BETWEEN` representation.

This can alter the textual appearance of a SQL expression while preserving its intended SQL behavior in appropriate contexts.

---

# 22. `--tamper`

Tamper scripts can be supplied using:

```text
--tamper
```

Multiple scripts can be chained.

Example from the material:

```bash
--tamper=between,randomcase
```

Conceptually:

```text
Payload
   ↓
between
   ↓
randomcase
   ↓
Modified payload
   ↓
Target
```

---

# 23. Tamper Script Priority

SQLMap assigns predefined priorities to tamper scripts.

This is important because some scripts modify SQL syntax while others modify the representation without depending heavily on the inner SQL structure.

For example, the material contrasts scripts that modify SQL syntax with scripts that operate more independently of the inner content.

### Key idea

```text
Tamper A
   ↓
Tamper B
   ↓
Tamper C
```

The order matters.

---

# 24. Important Tamper Scripts

The supplied material lists the following:

|Tamper|Description|
|---|---|
|`0eunion`|Replaces instances of `UNION` with `e0UNION`|
|`base64encode`|Base64-encodes characters in the payload|
|`between`|Replaces `>` and `=` with `BETWEEN`-style equivalents|
|`commalesslimit`|Changes MySQL `LIMIT M,N` to `LIMIT N OFFSET M`|
|`equaltolike`|Replaces `=` with `LIKE`|
|`halfversionedmorekeywords`|Adds MySQL versioned comments before keywords|
|`modsecurityversioned`|Wraps the complete query with a MySQL versioned comment|
|`modsecurityzeroversioned`|Wraps the query with a MySQL zero-versioned comment|
|`percentage`|Adds `%` before each character|
|`plus2concat`|Replaces `+` with an MsSQL `CONCAT()` counterpart|
|`randomcase`|Randomizes keyword character casing|
|`space2comment`|Replaces spaces with comments|
|`space2dash`|Replaces spaces with dash comments|
|`space2hash`|Replaces MySQL spaces with `#` comments|
|`space2mssqlblank`|Replaces spaces with alternative valid MsSQL blank characters|
|`space2plus`|Replaces spaces with `+`|
|`space2randomblank`|Replaces spaces with random valid blank characters|
|`symboliclogical`|Replaces `AND`/`OR` with symbolic equivalents|
|`versionedkeywords`|Encloses non-function keywords with MySQL versioned comments|
|`versionedmorekeywords`|Encloses keywords with MySQL versioned comments|

---

# 25. Listing Tamper Scripts

SQLMap provides:

```text
--list-tampers
```

to display the available tamper scripts along with their descriptions.

The source also notes that custom tamper scripts can be developed for specialized situations, including second-order SQLi scenarios.

---

# 26. Miscellaneous Bypasses

The final part of the material introduces two additional mechanisms:

1. **Chunked transfer encoding**
    
2. **HTTP Parameter Pollution (HPP)**
    

---

# 27. Chunked Transfer Encoding

SQLMap provides:

```text
--chunked
```

which causes the POST request body to be split into chunks.

Conceptually:

```text
Normal:

POST BODY
────────────────────────────


Chunked:

┌────────┐ ┌────────┐ ┌────────┐
│ chunk1 │ │ chunk2 │ │ chunk3 │
└────────┘ └────────┘ └────────┘
```

The source explains that blacklisted SQL keywords can be split between chunks in a way that may allow the request to pass unnoticed by certain simplistic filtering mechanisms.

---

# 28. HTTP Parameter Pollution — HPP

**HPP = HTTP Parameter Pollution**

The idea is to provide the same parameter name multiple times and split content across those occurrences.

The material gives the conceptual example:

```text
?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...
```

If the target platform supports this behavior, the application may concatenate or otherwise process the repeated parameter values. The source gives **ASP** as an example of a platform that can support this behavior.

### Visual concept

```text
?id=1
&id=UNION
&id=SELECT
&id=...
       │
       ▼
Target application
       │
       ▼
Processes repeated parameters
```

---

# 29. Complete Protection-BYPASS Map

![Image](https://images.openai.com/static-rsc-4/xsnxpu2zzXiQz9veRO1OQdnyClwHXd6tJv17DBrJlkm_WofaCje9COCKlue39cLweKj2WOymznV1DuLt7YNfjEY4A7CfPpeaRD40lL7BcvpCCOnLKYv3jBzE2P7SLK8kp_As7e9Rgx9K4xWxMlyLlMQcI2vV7ksyp_ntcRDu6ckk3Ai99LBM_WV_yQ0LAGSB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ngkr-dXVcXPQM5iQBFci0CfE6mJw7hL-egLsp4FbRmqCMdAuhQ4Le5Bn0l4nd0HoLeSYzvYGnQLLb-ERRPgdF3ndVFsmexDadKu7wh6nLhALopbBXvIfrOTT6HiQh2IDtMtH6k8QIRoX_eRO_OE_G8InSI3sZ36et5XBrjy3gPE3bc0iPX7bsZtzdPqXrVOW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/UsnTLWcEXcFd4qNcKBrZRmwycDIyIKgTG9YehzVqmYujizlrCJ5SjcDxFZK1U6Y4imkCSv9XdgY-Ou7qGCOFngI6c2flcFkxau9qAwKZhxWSUCLNstX2zzril9rqt5KcNk3BIvDORGiJZGInixbnkscldNqDRz9yA-VOjvTvBuWvhKRwMI3mRoJJbX1rjC1x?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gGZINi6LYJwZjlPjvUr8qhV3wN15KJm7HyV1v1jlI79MSAsdHyZvCMCl9fL3OxtIvRRD4-Pjy7RbkliejoCbLjXtmQe9MFTRg21HdhXq7mHViuhrictDw8Lv2PCjF64-JIdPVUMPuN539GK95cykUUKq8q53OyeuyThmxE-isKC5-Y-tkebn9AWJCV0ko1Cy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Qbxan8wwiy60q8PArwWSAkW7fKhTEBsdpe4xwcSIvCEhrekPhZCmsUYqmAVT-8DX7M8Usimc345Tutg2ohjekeq_LKIuk5fDcCA08dsL5aOUOIn1zc5vKZmg9sDG_pLiFWv7tEXBMgxcwYVm4QQk6Pkl_7jDdFpjswc5IrUNpv0fp9sQmcuZFFFi7fVtP2Ll?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/H2TOo3I63Q1JphovEHsWGxdARM8eoVq-yslVsRywHfTHOlOlDqSoR79HIAL7mVHAkl1YKtqYmaY_RjVkPDdbD4yrSHc7ycR_nWO8WymCZkzvu42VZ9pLkRHwUt8kTtO2OdeGIoqF0Jq1W_2STUH2BKjJ2XVdzwcpy8AUnplWTlF4y_Pns_SuTrerOVa82HiD?purpose=fullsize)

```text
                 SQLMap REQUEST
                       │
       ┌───────────────┼────────────────┐
       │               │                │
       ▼               ▼                ▼
     CSRF            Unique          Calculated
     Token           Value             Value
       │               │                │
       │          --randomize         --eval
       │
  --csrf-token
       │
       └───────────────┬────────────────┘
                       │
                       ▼
                 Request shaping
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
          Proxy/Tor             WAF
             │                   │
       --proxy / --tor     --skip-waf
             │                   │
             └─────────┬─────────┘
                       ▼
                 User-Agent
                       │
                 --random-agent
                       │
                       ▼
                 Tamper scripts
                       │
                    --tamper
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
          --chunked              HPP
             │                   │
             └─────────┬─────────┘
                       ▼
                    TARGET
```

---

# 30. ⭐ Important Command Cheat Sheet

|Goal|SQLMap option|
|---|---|
|Handle anti-CSRF token|`--csrf-token`|
|Randomize parameter|`--randomize`|
|Calculate parameter dynamically|`--eval`|
|Route through proxy|`--proxy`|
|Use proxy list|`--proxy-file`|
|Use Tor|`--tor`|
|Verify Tor|`--check-tor`|
|Skip WAF heuristic test|`--skip-waf`|
|Random browser User-Agent|`--random-agent`|
|Modify payload/request|`--tamper`|
|List tamper scripts|`--list-tampers`|
|Chunk POST body|`--chunked`|

---

# 31. 🧠 Easy Way to Remember Everything

### **C-R-E-P-W-R-T-C-H**

Think:

```text
C → CSRF
R → Randomize
E → Eval
P → Proxy
W → WAF
R → Random-Agent
T → Tamper
C → Chunked
H → HPP
```

Or simply remember the categories:

```text
REQUEST VALIDATION
│
├── --csrf-token
├── --randomize
└── --eval

NETWORK / IDENTITY
│
├── --proxy
├── --proxy-file
├── --tor
└── --check-tor

WAF / FILTERING
│
├── --skip-waf
├── --random-agent
└── --tamper

REQUEST FORMATTING
│
├── --chunked
└── HPP
```

---

# 32. 🔥 Most Important Takeaways

### 1. CSRF ≠ unique-value protection

Both can interfere with automation, but they work differently.

```text
CSRF
→ Fresh token obtained from application response

Unique value
→ Generate a different value for a parameter
```

---

### 2. `--eval` is for calculated relationships

If:

```text
h = function(id)
```

then:

```text
--eval
```

can calculate the dependent value before the request.

---

### 3. `--random-agent` deals with User-Agent filtering

If the application's defenses recognize SQLMap's default User-Agent, SQLMap can use a different browser-style User-Agent.

---

### 4. `--tamper` modifies representation

Tamper scripts don't fundamentally mean "find a different SQL injection." They modify the request/payload representation before transmission.

---

### 5. `--list-tampers` is your reference

Instead of memorizing every tamper script:

```bash
sqlmap --list-tampers
```

The material specifically recommends this switch for viewing the implemented scripts and descriptions.

---

### 6. Protection layers can stack

A target might have:

```text
CSRF
 +
WAF
 +
IP filtering
 +
User-Agent filtering
 +
request validation
```

Therefore, fixing one problem does **not** necessarily mean SQLMap will work immediately.

---

# 📌 One-Page Revision Sheet

```text
SQLMAP — BYPASSING WEB APPLICATION PROTECTIONS

CSRF
────────────────────────────────────────
--csrf-token
→ Automatically refresh anti-CSRF token


UNIQUE VALUES
────────────────────────────────────────
--randomize=<parameter>
→ Randomize parameter before requests


CALCULATED VALUES
────────────────────────────────────────
--eval="<Python code>"
→ Calculate dependent parameters before request


PROXY / TOR
────────────────────────────────────────
--proxy=<proxy>
→ Route traffic through proxy

--proxy-file=<file>
→ Sequential proxy list

--tor
→ Use local Tor service

--check-tor
→ Verify Tor usage


WAF
────────────────────────────────────────
--skip-waf
→ Skip SQLMap's WAF heuristic test


USER-AGENT
────────────────────────────────────────
--random-agent
→ Use random browser-style User-Agent


TAMPER
────────────────────────────────────────
--tamper=<scripts>
→ Modify requests before sending

--list-tampers
→ List available tamper scripts


MISC
────────────────────────────────────────
--chunked
→ Chunk POST body

HPP
→ Split request content across repeated
  parameter names
```

The supplied module's core message is that SQLMap has multiple mechanisms for handling application protections, but those protections are increasingly sophisticated, so there is no universal bypass.