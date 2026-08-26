![Image](https://images.openai.com/static-rsc-4/SUf7lxRpcYCOmEExxacnLL0wx2zJ4C9zRMpGSBf7YHLvQSetVviSg-hvpmvWUr8WFd8gQp3MBpW8LE5AG05MAvgs9MQMArRm2wzTodsT4Fj5BmT6Tg90jl3JMTaA-T2ZmTfP-NR_s50lPyVqntbYWNF5fNtooXfZkHPCnZYv0tsyRLbhmPbRkVzyhACJCTKW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6a43t612wWN7SOjNbnkv-MdCPOipX4jO7gqIYLdq6houfTNWOE6vGo8b_LPKOW-6zqsWTQFlcuNJfETKgjII_iIa4tzTBajNB8CwsA65A7CyBkaooaosiK8iWGp4z91evWVt4eaMLywp550rZaBqSwYtJP4-zqSsCwmrL_qWWMRFHvkUR_BcKTOrbOtq9n7s?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/j5OmilAZlSIsdPIB0crD96NhmAp6tuiPWQ7RffzfZuTXusmOdaGXCJqq9-iT3PWe4tPDHYnQ9TuEhSVR60UT-OzSE0h6lzfNkWWdgParHyDzts9H8_5rHazPi45gRQlVO73SAYua5cYcA_ulmiyurKMYz7oCzOoK-80Spu-f0Wm9D_lffbiNqb2KKq4WA2ca?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NHNlqleZ4shJ5H3z06__xu7c3AZHbfTigg6Pu20xycKxQ0kjUu_Ffa7RH_BGllkY9zzTpXf39dn5YKwwa18PwbrrNPuiP74ASeMwlJ0POvBOgrSMJRY3lLtB46As3IV7rzA8QHPGyAa30lixXVb8rr3N1uIuuLaMh9EZa3vCpmWdxWGKYkGQPKdFMgAxp8T7?purpose=fullsize)
## 1. Introduction

SQLMap has many options for constructing and modifying the HTTP request before testing it for SQL injection.

A large number of SQLMap failures are not caused by SQLMap itself.

They can happen because of:

- Missing cookies
    
- Incorrect headers
    
- Incorrect POST data
    
- Incorrect HTTP method
    
- Complicated command-line construction
    
- Testing the wrong parameter
    
- Missing authentication/session information
    
- Incorrectly formatted JSON/XML data
    

### Core idea

> **SQLMap needs an accurate representation of the request that reaches the vulnerable application.**

Think of the process as:

```text
Browser / Client
      │
      ▼
HTTP Request
      │
      ├── URL
      ├── Parameters
      ├── Headers
      ├── Cookies
      ├── Method
      └── Body
      │
      ▼
    SQLMap
      │
      ▼
SQLi Testing
```

---

# 2. The Three Main Ways to Give SQLMap a Request

There are three particularly important approaches:

```text
                    SQLMap Request
                         │
             ┌───────────┼───────────┐
             │           │           │
             ▼           ▼           ▼
           URL         --data        -r
             │           │           │
             ▼           ▼           ▼
            GET         POST     Full HTTP
                                  Request
```

### Simple GET

```bash
sqlmap -u "http://target/page.php?id=1"
```

### POST data

```bash
sqlmap "http://target/" --data "uid=1&name=test"
```

### Complete HTTP request

```bash
sqlmap -r req.txt
```

---

# 3. Why Request Setup Matters

Suppose the vulnerable endpoint requires:

```text
Cookie: PHPSESSID=abc123
```

but SQLMap sends:

```text
No Cookie
```

The server might respond:

```text
403 Forbidden
```

or:

```text
Please log in
```

SQLMap may then be unable to reach the vulnerable functionality.

Therefore:

```text
Correct request
      ↓
Correct application state
      ↓
Correct parameter
      ↓
Reliable SQLi testing
```

---

# 4. Using "Copy as cURL"

One of the easiest ways to reproduce a browser request is using the browser's Developer Tools.

Modern browsers such as:

- Chrome
    
- Edge
    
- Firefox
    

provide a Network panel where you can inspect HTTP requests.

---

## Basic workflow

```text
Open Browser
     ↓
Developer Tools
     ↓
Network
     ↓
Perform the action
     ↓
Find HTTP request
     ↓
Right-click
     ↓
Copy as cURL
     ↓
Paste into terminal
```

This gives you a command containing many details of the original request.

---

# 5. Why "Copy as cURL" Is Useful

A manually constructed SQLMap command might accidentally forget:

- User-Agent
    
- Accept header
    
- Cookies
    
- Referer
    
- Authentication headers
    
- POST body
    
- Other request details
    

But the browser-generated cURL command represents the actual request much more closely.

Conceptually:

```text
Browser request
       │
       ▼
Copy as cURL
       │
       ▼
Complete request representation
       │
       ▼
Adapt for SQLMap
```

---

# 6. Converting cURL to SQLMap

Suppose the browser gives:

```bash
curl 'http://www.example.com/?id=1' \
-H 'User-Agent: Mozilla/5.0 ...' \
-H 'Accept: image/webp,*/*' \
-H 'Accept-Language: en-US,en;q=0.5' \
--compressed \
-H 'Connection: keep-alive' \
-H 'DNT: 1'
```

The material demonstrates replacing the original `curl` command with `sqlmap`:

```bash
sqlmap 'http://www.example.com/?id=1' \
-H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' \
-H 'Accept: image/webp,*/*' \
-H 'Accept-Language: en-US,en;q=0.5' \
--compressed \
-H 'Connection: keep-alive' \
-H 'DNT: 1'
```

The important concept is:

> **Use the browser to capture the request, then adapt that request for SQLMap.**

---

# 7. SQLMap Needs Something to Test

SQLMap needs either:

1. A parameter it can test, or
    
2. An option that tells it how to find parameters.
    

For example:

```text
?id=1
```

contains:

```text
id
```

which SQLMap can test.

Alternatively, specialized functionality can help discover parameters, such as:

```text
--crawl
--forms
-g
```

---

# 8. GET Requests

GET parameters are normally placed directly inside the URL.

Example:

```text
http://www.example.com/?id=1
```

SQLMap can test this using:

```bash
sqlmap -u "http://www.example.com/?id=1"
```

or equivalently:

```bash
sqlmap "http://www.example.com/?id=1"
```

The parameter is:

```text
id=1
```

---

# 9. GET Request Diagram

```text
Browser
   │
   │ GET /?id=1
   ▼
Web Server
   │
   ▼
Application
   │
   ▼
Database
```

The `id` parameter is carried inside the URL.

---

# 10. POST Requests

POST parameters are generally sent in the HTTP request body.

Example:

```bash
sqlmap "http://www.example.com/" \
--data "uid=1&name=test"
```

The POST body is:

```text
uid=1&name=test
```

SQLMap can test the POST parameters for SQL injection.

---

# 11. POST Request Diagram

```text
POST / HTTP/1.1
Host: www.example.com

uid=1&name=test
       │
       ▼
    SQLMap
       │
       ▼
Application
       │
       ▼
   Database
```

Unlike GET:

```text
GET  → parameters commonly in URL
POST → parameters commonly in body
```

---

# 12. Testing a Specific POST Parameter

Suppose the POST data is:

```text
uid=1&name=test
```

and you already know that:

```text
uid
```

is the parameter of interest.

You can narrow testing with:

```bash
sqlmap "http://www.example.com/" \
--data "uid=1&name=test" \
-p uid
```

The `-p` option tells SQLMap which parameter to test.

---

# 13. Using `*` to Mark the Injection Point

Another useful method is placing an asterisk `*` where you want SQLMap to focus.

Example:

```bash
sqlmap "http://www.example.com/" \
--data "uid=1*&name=test"
```

The asterisk marks:

```text
uid=1*
     ↑
 injection point
```

This explicitly tells SQLMap:

> Test this particular location.

---

# 14. `-p` vs `*`

|Method|Purpose|
|---|---|
|`-p uid`|Tell SQLMap to test parameter `uid`|
|`uid=1*`|Mark the exact injection location|

### Memory trick

```text
-p
 ↓
Parameter name

*
 ↓
Exact injection marker
```

---

# 15. Full HTTP Requests

Sometimes the request is much more complicated.

For example:

```text
GET request
+
many headers
+
cookies
+
authentication
+
long parameters
```

Building all of that manually can be annoying and error-prone.

This is where:

```text
-r
```

becomes extremely useful.

---

# 16. `-r` — Request File

The `-r` option tells SQLMap to load a complete HTTP request from a file.

Example:

```bash
sqlmap -r req.txt
```

The file contains the complete HTTP request.

Conceptually:

```text
req.txt
  │
  ├── Method
  ├── URL/path
  ├── Host
  ├── Headers
  ├── Cookies
  └── Body
       │
       ▼
     SQLMap
```

---

# 17. Capturing Requests with Burp Suite

A common workflow is:

```text
Browser
   ↓
Burp Suite
   ↓
Intercept request
   ↓
Save/copy request
   ↓
req.txt
   ↓
SQLMap -r req.txt
```

The request can be copied manually or saved through Burp's request functionality.

---

# 18. Example HTTP Request File

The material provides:

```http
GET /?id=1 HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
If-Modified-Since: Thu, 17 Oct 2019 07:18:26 GMT
If-None-Match: "3147526947"
Cache-Control: max-age=0
```

This contains much more information than:

```text
?id=1
```

That's why request files are useful for complex applications.

---

# 19. Running the Request File

Once the request is stored in:

```text
req.txt
```

run:

```bash
sqlmap -r req.txt
```

SQLMap begins by parsing it:

```text
[INFO] parsing HTTP request from 'req.txt'
```

Then it proceeds with normal testing:

```text
[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
```

---

# 20. Marking a Parameter in a Request File

The same `*` marker can be used inside a saved request.

For example:

```text
/?id=*
```

This tells SQLMap exactly where the injection point should be tested.

Conceptually:

```text
GET /?id=* HTTP/1.1
          ↑
       Injection
        marker
```

---

# 21. Why `-r` Is Often the Best Practical Option

For simple URLs:

```bash
sqlmap -u "http://target/?id=1"
```

is perfectly fine.

But for complicated authenticated requests:

```text
-r request.txt
```

is often much easier.

### Comparison

|Situation|Preferred approach|
|---|---|
|Simple GET|`-u`|
|Simple POST|`--data`|
|Complex GET|`-r`|
|Complex POST|`-r`|
|Many headers|`-r`|
|Authentication cookies|`-r` or `--cookie`|
|JSON body|`--data` or `-r`|
|Long/complex request|`-r`|

---

# 22. Custom SQLMap Requests

SQLMap allows you to manually specify individual HTTP request components.

Important options include:

```text
--cookie
-H / --header
--host
--referer
-A / --user-agent
--random-agent
--mobile
--method
```

These let you reproduce the target's request more accurately.

---

# 23. Supplying Cookies

Suppose an authenticated application requires:

```text
PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c
```

You can provide it with:

```bash
sqlmap ... \
--cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

This is important when the vulnerable endpoint is accessible only to an authenticated session.

---

# 24. Cookies Through `-H`

The same effect can be achieved using an HTTP header:

```bash
sqlmap ... \
-H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'
```

Conceptually:

```http
Cookie: PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c
```

---

# 25. `--cookie` vs `-H`

Both can represent cookie information.

```text
--cookie
   ↓
Dedicated cookie option

-H "Cookie: ..."
   ↓
Generic HTTP header option
```

For straightforward cookie handling, `--cookie` is generally easier to read.

---

# 26. Other HTTP Headers

SQLMap can also customize headers such as:

```text
Host
Referer
User-Agent
Cookie
X-Forwarded-For
...
```

Using:

```bash
-H "Header: value"
```

is a flexible way of adding custom headers.

---

# 27. User-Agent

The User-Agent identifies the client software.

A typical browser User-Agent might look like:

```text
Mozilla/5.0 ...
```

SQLMap can specify a User-Agent with:

```text
-A
```

or:

```text
--user-agent
```

---

# 28. `--random-agent`

SQLMap also provides:

```text
--random-agent
```

This makes SQLMap select a User-Agent from its collection of browser-like values.

The purpose is to make the request resemble normal browser traffic rather than using SQLMap's recognizable default User-Agent.

---

## Why this can matter

Some security controls may identify obvious automated tools by User-Agent.

Conceptually:

```text
User-Agent: sqlmap/...
        ↓
Potentially recognizable
```

versus:

```text
User-Agent: browser-like value
        ↓
Looks more like ordinary browser traffic
```

### Important

Changing the User-Agent is **not a universal security-control bypass**.

It only changes one aspect of the request.

---

# 29. `--mobile`

SQLMap can also use:

```text
--mobile
```

to imitate a mobile browser through its User-Agent behavior.

Conceptually:

```text
Normal browser
      OR
Mobile browser
      ↓
Different User-Agent
```

---

# 30. Testing HTTP Headers for SQL Injection

By default, SQLMap primarily focuses on parameters.

However, a tester can explicitly mark another part of the request for testing.

For example:

```bash
--cookie="id=1*"
```

The `*` indicates the location to test.

Conceptually:

```text
Cookie: id=1*
             ↑
       Injection marker
```

The same principle can be applied to other supported request components.

---

# 31. Alternative HTTP Methods

The most common HTTP methods used in SQLMap examples are:

```text
GET
POST
```

But applications can use other methods.

For example:

```text
PUT
```

SQLMap can specify the method using:

```text
--method
```

Example:

```bash
sqlmap -u "http://www.target.com" \
--data='id=1' \
--method PUT
```

---

# 32. HTTP Method Diagram

```text
GET
 ↓
Parameters usually in URL

POST
 ↓
Parameters usually in body

PUT
 ↓
Data commonly sent in body

PATCH
 ↓
Partial resource modification
```

The exact behavior depends on the application.

---

# 33. JSON Requests

Modern APIs frequently use JSON rather than traditional form data.

Example:

```json
{"id":1}
```

SQLMap supports JSON-formatted request bodies.

Conceptually:

```text
POST /api/item
Content-Type: application/json

{"id":1}
```

SQLMap can analyze the JSON parameter structure.

---

# 34. XML Requests

SQLMap also supports XML-formatted request bodies.

Example:

```xml
<element>
    <id>1</id>
</element>
```

Conceptually:

```text
HTTP Request
     │
     ▼
XML Body
     │
     ▼
Application
     │
     ▼
Database
```

---

# 35. Relaxed JSON/XML Parsing

The material emphasizes that SQLMap's support for JSON and XML is implemented in a relatively **relaxed** manner.

This means SQLMap does not require every request to follow one extremely rigid structure.

It attempts to identify parameter values within these formats.

---

# 36. Simple JSON Body

If the body is short and simple:

```json
{"id":1}
```

the `--data` option can be sufficient.

Conceptually:

```bash
sqlmap "http://target/api" \
--data='{"id":1}'
```

---

# 37. Complex JSON Body

Suppose the request body is:

```json
{
  "data": [{
    "type": "articles",
    "id": "1",
    "attributes": {
      "title": "Example JSON",
      "body": "Just an example",
      "created": "2020-05-22T14:56:29.000Z",
      "updated": "2020-05-22T14:56:28.000Z"
    },
    "relationships": {
      "author": {
        "data": {
          "id": "42",
          "type": "user"
        }
      }
    }
  }]
}
```

Manually putting this into a command line can become difficult.

That's where:

```text
-r req.txt
```

becomes useful.

---

# 38. Complex JSON Through Request File

Save the complete HTTP request to:

```text
req.txt
```

Then:

```bash
sqlmap -r req.txt
```

SQLMap may recognize the JSON body:

```text
[INFO] parsing HTTP request from 'req.txt'
JSON data found in HTTP body.
Do you want to process it? [Y/n/q]
```

It then begins testing the parameters contained within the JSON structure.

---

# 39. Understanding the JSON Example Output

The example reports:

```text
[INFO] testing if HTTP parameter 'JSON type' is dynamic
```

followed by:

```text
[WARNING] HTTP parameter 'JSON type' does not appear to be dynamic
```

and:

```text
[WARNING] heuristic (basic) test shows that HTTP parameter
'JSON type' might not be injectable
```

The important lesson is:

> SQLMap can parse structured request bodies, but parsing them does not mean the parameter is automatically dynamic or injectable.

---

# 40. Request Construction Hierarchy

A useful way to think about request complexity is:

```text
Simple
  │
  ▼
GET URL
  │
  ▼
POST --data
  │
  ▼
Custom headers/cookies
  │
  ▼
JSON/XML body
  │
  ▼
Complete HTTP request
  │
  ▼
-r request.txt
```

As complexity increases, using a request file often becomes easier.

---

# 41. Choosing the Right SQLMap Method

## Scenario 1 — Simple GET

```text
http://target/page.php?id=1
```

Use:

```bash
sqlmap -u "http://target/page.php?id=1"
```

---

## Scenario 2 — Simple POST

```text
uid=1&name=test
```

Use:

```bash
sqlmap "http://target/" --data="uid=1&name=test"
```

---

## Scenario 3 — Specific parameter

Use:

```bash
-p uid
```

---

## Scenario 4 — Exact injection location

Use:

```text
uid=1*
```

---

## Scenario 5 — Authenticated request

Use:

```text
--cookie="PHPSESSID=..."
```

or a complete request file.

---

## Scenario 6 — Many headers

Use:

```text
-r req.txt
```

---

## Scenario 7 — Complex JSON/XML

Prefer:

```text
-r req.txt
```

---

# 42. Common Mistakes

## Mistake 1 — Forgetting the session cookie

```text
Correct URL
+
Missing session
=
Unauthenticated request
```

---

## Mistake 2 — Incorrect POST syntax

For example, accidentally supplying:

```text
uid=1 name=test
```

instead of:

```text
uid=1&name=test
```

can result in SQLMap not seeing the intended parameters.

---

## Mistake 3 — Testing the wrong parameter

If:

```text
uid
```

is vulnerable but:

```text
name
```

isn't, broad testing may waste requests.

Use:

```text
-p uid
```

when the target is known.

---

## Mistake 4 — Overly complicated command line

Trying to manually reproduce:

```text
URL
+
10 headers
+
cookies
+
POST body
+
JSON
+
custom method
```

can introduce errors.

A request file is often cleaner:

```bash
sqlmap -r req.txt
```

---

## Mistake 5 — Assuming JSON parsing means SQLi

This:

```text
JSON data found
```

only means SQLMap recognized JSON.

It does **not** mean:

```text
JSON = SQLi
```

The parameter still needs to be dynamic and injectable.

---

# 43. Most Important Options

|Option|Meaning|
|---|---|
|`-u`|Target URL|
|`--data`|POST/body data|
|`-p`|Select parameter|
|`*`|Mark injection point|
|`-r`|Load complete HTTP request|
|`--cookie`|Specify cookies|
|`-H`|Custom HTTP header|
|`--host`|Custom Host header|
|`--referer`|Custom Referer|
|`-A`|User-Agent|
|`--random-agent`|Random browser-like User-Agent|
|`--mobile`|Mobile User-Agent behavior|
|`--method`|Specify HTTP method|
|`--crawl`|Crawl for links|
|`--forms`|Test parameters in forms|
|`-g`|Process Google dork results|

---

# 44. `*` Marker — Extremely Important

The asterisk is one of the easiest concepts to remember.

It means:

> **Test this exact location for injection.**

Examples:

### GET

```text
/?id=*
```

### POST

```text
uid=1*&name=test
```

### Cookie

```text
Cookie: id=1*
```

Conceptually:

```text
                *
                │
                ▼
         Injection marker
```

---

# 45. Complete HTTP Request Model

A complete HTTP request can contain:

```text
┌──────────────────────────────┐
│ HTTP Method                  │
│ GET / POST / PUT / ...       │
├──────────────────────────────┤
│ URL / Path                   │
├──────────────────────────────┤
│ Host                         │
├──────────────────────────────┤
│ Headers                      │
│ - User-Agent                 │
│ - Cookie                     │
│ - Referer                    │
│ - Accept                     │
│ - Custom headers             │
├──────────────────────────────┤
│ Request Body                 │
│ - Form data                  │
│ - JSON                       │
│ - XML                        │
└──────────────────────────────┘
```

SQLMap can be configured to reproduce these components.

---

# 46. Best Practical Workflow

For an authorized lab, a very reliable workflow is:

```text
1. Open browser
        ↓
2. Open Developer Tools
        ↓
3. Open Network tab
        ↓
4. Perform the desired action
        ↓
5. Find the HTTP request
        ↓
6. Inspect URL, parameters, cookies and body
        ↓
7. Copy as cURL OR save full request
        ↓
8. Convert/use with SQLMap
        ↓
9. Mark specific parameter if needed
        ↓
10. Run SQLMap
```

---

# 47. Best Option for Each Situation

```text
Simple GET
    ↓
-u

Simple POST
    ↓
--data

Specific parameter
    ↓
-p

Exact location
    ↓
*

Cookies
    ↓
--cookie

Custom headers
    ↓
-H

Alternative method
    ↓
--method

Complex request
    ↓
-r req.txt

Complex JSON/XML
    ↓
-r req.txt
```

---

# 48. Final Cheat Sheet

```text
SQLMap Request Setup
│
├── GET
│   └── sqlmap -u "URL?id=1"
│
├── POST
│   └── sqlmap "URL" --data="id=1"
│
├── Specific parameter
│   └── -p id
│
├── Exact injection point
│   └── id=1*
│
├── Full request
│   └── -r req.txt
│
├── Cookie
│   └── --cookie="PHPSESSID=..."
│
├── Header
│   └── -H "Header: value"
│
├── User-Agent
│   └── -A "..."
│
├── Random User-Agent
│   └── --random-agent
│
├── Mobile User-Agent
│   └── --mobile
│
├── HTTP method
│   └── --method PUT
│
├── JSON
│   └── --data='{"id":1}'
│
└── Complex JSON/XML
    └── -r req.txt
```

---

# 49. Final Mental Model

The biggest lesson from this section is:

> **SQLMap is only as good as the HTTP request you give it.**

Think:

```text
             Correct Request
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
      URL        Headers       Body
       │            │            │
       ▼            ▼            ▼
   Parameters    Cookies      POST/JSON/XML
       │            │            │
       └────────────┼────────────┘
                    ▼
                  SQLMap
                    │
                    ▼
              SQLi Testing
```

If the request is wrong:

```text
Wrong request
     ↓
Wrong application state
     ↓
Wrong response
     ↓
Failed / inaccurate testing
```

If the request accurately represents the application's real request:

```text
Correct request
     ↓
Correct application state
     ↓
Correct parameter
     ↓
Reliable SQLMap testing
```

### The three commands to remember most

```bash
sqlmap -u "http://target/page.php?id=1"
```

```bash
sqlmap "http://target/" --data="uid=1&name=test"
```

```bash
sqlmap -r req.txt
```

And the three concepts to remember:

```text
-u
 ↓
Simple URL

--data
 ↓
POST/body data

-r
 ↓
Complete HTTP request
```

> **For real-world/HTB-style work, `-r req.txt` is especially valuable because it lets you preserve the complete request—method, URL, headers, cookies, and body—instead of trying to recreate a complicated request manually.**