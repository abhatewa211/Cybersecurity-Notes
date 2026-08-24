![Image](https://images.openai.com/static-rsc-4/84iIgrScY9DQGOuR8vWwu-EujQzmOUD6Q23CElQOafdPRAhyAjHFNychLlLW5vbLCt_3ix-ARu9rtDlRw8KxVNkmTWm271HXBPgJ8pCm1auu_9jEm0PVeiJprBhYbzzGVpmbpbEwnJmo98SW8FE7KMog-uAh81SOhosYsxKjWFFTWFyeUxuX0ICPuw77o_uS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eLYnl0xM86CWRtUwvXRERFfSCn3pivpDss8DdAD5mFacCh1vDDjVwz32fKzfrGTz_ALKY2BU432P7p0DImezxaj6OBbsJnEfzsokCFEUGa8VmkkFeagdRNKDhBvK4AWjII4v_wrJbRahMfWdSDcUgneZGmvt0dPW_kMaEz6pHv9XyFFpPoC1NL5Az2pbLcRw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RUZTxCynYxduXxdnUGf7Q8i48B2uYn1gBUfGrqdhSDRagnbLSgnUo-arYNRRsweAGM68KexBJ2dmEe87264L9_-I00B33T-o02avSnDBPpzBsEcpZvYjbZL38W9AxFDTSxQv3KVKEckIXodHTsTE1_ArVoz02yNDAJNF6yQopzgLtOZMUQEFF_hoGgvlwYjG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2SzO2oXs7W1U0aT_koXlNJDYtffl2_AjDITh07vRo1Vw7IjLMYLWDpcBqMMAWWbkbd8EZmboMMU7g3nQmhllCUo6P8ftu-KLTpOR1llt4ZoAJXNJdWq7B3xuZFhaHUTfbRtICgoFxDFM5941Ga4yVufMN5yEZC0gyqv7JHvd48xjfLmKY7e0gglWjh0quUrT?purpose=fullsize)

This section extends the previous **GET parameter fuzzing** technique to **POST parameters**.

The most important difference to remember is:

> **GET parameters are normally placed in the URL query string, while POST parameters are placed inside the HTTP request body.**

---

# 1. GET vs POST

### GET

A GET parameter appears after `?`:

```text
http://admin.academy.htb:PORT/admin/admin.php?param1=key
```

The parameter is part of the URL.

### POST

A POST parameter is sent in the request body:

```http
POST /admin/admin.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

param1=key
```

The parameter isn't appended to the URL.

---

# 2. Visual Comparison

```text
GET REQUEST
────────────────────────────

GET /admin/admin.php?key=value HTTP/1.1
Host: admin.academy.htb


             URL
              │
              ▼
       ?key=value
```

Versus:

```text
POST REQUEST
────────────────────────────

POST /admin/admin.php HTTP/1.1
Host: admin.academy.htb
Content-Type: application/x-www-form-urlencoded

key=value
       ▲
       │
   Request Body
```

The destination page can be the same:

```text
/admin/admin.php
```

but the input is delivered differently.

---

# 3. Why POST Fuzzing Is Necessary

Suppose the application doesn't recognize:

```text
/admin/admin.php?key=value
```

but internally expects:

```text
POST /admin/admin.php

key=value
```

GET fuzzing wouldn't discover the POST-only behavior.

Therefore, when testing a web application, we should consider both:

```text
GET parameters
```

and:

```text
POST parameters
```

---

# 4. The `-d` Option

Ffuf provides:

```text
-d
```

for specifying request data.

For example:

```bash
-d 'username=admin'
```

means the request body contains:

```text
username=admin
```

For fuzzing, we replace the parameter name with:

```text
FUZZ
```

so:

```bash
-d 'FUZZ=key'
```

---

# 5. The `-X POST` Option

By default, ffuf uses:

```text
GET
```

We need to explicitly tell it to use POST:

```text
-X POST
```

Therefore:

```bash
-X POST -d 'FUZZ=key'
```

means:

> Send a POST request and fuzz the parameter name inside the request body.

---

# 6. Content-Type

The module specifically points out that for this PHP application, POST data should use:

```text
application/x-www-form-urlencoded
```

We can specify this using:

```bash
-H 'Content-Type: application/x-www-form-urlencoded'
```

This tells the server how to interpret the request body.

---

# 7. What Is `application/x-www-form-urlencoded`?

It is a common encoding for HTML form data.

For example:

```text
username=admin&password=123456
```

The structure is:

```text
parameter=value
```

and multiple parameters are separated by:

```text
&
```

For example:

```text
username=admin&id=10
```

---

# 8. The Complete Ffuf Command

The module uses:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u http://admin.academy.htb:PORT/admin/admin.php \
-X POST \
-d 'FUZZ=key' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-fs xxx
```

This is the main command to remember from this section.

---

# 9. Command Breakdown

## Wordlist

```text
-w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ
```

Uses the parameter-name wordlist.

`FUZZ` is the replacement keyword.

---

## Target

```text
-u http://admin.academy.htb:PORT/admin/admin.php
```

Notice there is **no `?FUZZ=key`** here.

That's because this is a POST request.

---

## HTTP Method

```text
-X POST
```

Changes the HTTP method from GET to POST.

---

## Request Data

```text
-d 'FUZZ=key'
```

Places the fuzzing keyword inside the POST body.

---

## Content-Type

```text
-H 'Content-Type: application/x-www-form-urlencoded'
```

Specifies the format of the POST data.

---

## Filtering

```text
-fs xxx
```

Filters the normal/default response size.

As with the previous section, `xxx` represents the baseline size that you determine from the target.

---

# 10. What Does Ffuf Actually Send?

Suppose the wordlist contains:

```text
id
key
admin
user
token
```

Ffuf will effectively send requests like:

```http
POST /admin/admin.php HTTP/1.1
Host: admin.academy.htb
Content-Type: application/x-www-form-urlencoded

id=key
```

Then:

```http
POST /admin/admin.php HTTP/1.1
Host: admin.academy.htb
Content-Type: application/x-www-form-urlencoded

key=key
```

Then:

```http
POST /admin/admin.php HTTP/1.1
Host: admin.academy.htb
Content-Type: application/x-www-form-urlencoded

admin=key
```

and so on.

---

# 11. GET vs POST Parameter Fuzzing

This is one of the **most important things to memorize**.

### GET parameter fuzzing

```bash
ffuf -w wordlist:FUZZ \
-u 'http://TARGET/page.php?FUZZ=key'
```

Fuzzing happens in:

```text
URL query string
```

---

### POST parameter fuzzing

```bash
ffuf -w wordlist:FUZZ \
-u 'http://TARGET/page.php' \
-X POST \
-d 'FUZZ=key'
```

Fuzzing happens in:

```text
POST request body
```

---

# 12. Easy Memory Trick

Remember:

```text
GET
↓
?FUZZ=value
```

and:

```text
POST
↓
-d 'FUZZ=value'
```

So:

```text
GET  → URL
POST → DATA
```

---

# 13. What Did the Scan Find?

The scan identifies:

```text
id
```

as an interesting parameter.

The module notes that it also finds the parameter discovered during the earlier GET fuzzing.

The important new discovery is:

```text
id
```

Now we need to determine what the application does with it.

---

# 14. Manually Testing the `id` Parameter

The module uses `curl`:

```bash
curl http://admin.academy.htb:PORT/admin/admin.php \
-X POST \
-d 'id=key' \
-H 'Content-Type: application/x-www-form-urlencoded'
```

This sends:

```http
POST /admin/admin.php HTTP/1.1
Host: admin.academy.htb
Content-Type: application/x-www-form-urlencoded

id=key
```

---

# 15. The Response

The server responds with:

```html
<div class='center'><p>Invalid id!</p></div>
```

The important message is:

```text
Invalid id!
```

This is a significant discovery.

---

# 16. What Does "Invalid id!" Tell Us?

It strongly suggests that the application **recognized the `id` parameter** and attempted to process its value.

Compare this with a parameter that the application completely ignores.

For example:

```text
POST:
randomparameter=key

Response:
Access denied
```

versus:

```text
POST:
id=key

Response:
Invalid id!
```

The second response gives us more information.

It indicates that:

```text
id
 ↓
recognized by application
 ↓
value processed
 ↓
value is invalid
```

---

# 17. This Is Different From the Deprecated Parameter

Earlier, GET fuzzing discovered a parameter that produced:

```text
This method is deprecated
```

Now POST fuzzing discovers:

```text
id
```

which produces:

```text
Invalid id!
```

These are different application behaviors.

That difference is extremely useful during enumeration.

---

# 18. Think of Responses as Application Clues

Suppose we test:

```text
foo=key
```

and get:

```text
Access denied
```

Then:

```text
id=key
```

gives:

```text
Invalid id!
```

The second response tells us more about the backend logic.

We can think of it as:

```text
Unknown parameter
       ↓
Default behavior


Recognized parameter
       ↓
Specific error
       ↓
Backend logic revealed
```

---

# 19. Why "Invalid id!" Is Interesting

The application appears to expect:

```text
id=<something>
```

but:

```text
id=key
```

isn't a valid ID.

That gives us a new direction:

> **Instead of fuzzing the parameter name, investigate the parameter's value.**

This leads naturally into **parameter value fuzzing**.

---

# 20. Parameter Name vs Parameter Value

We've now reached the important distinction again.

### We already did:

```text
-d 'FUZZ=key'
```

This asks:

> Which parameter names are accepted?

Now we may want:

```text
-d 'id=FUZZ'
```

This asks:

> Which values are accepted for the `id` parameter?

---

# 21. Visualize the Transition

```text
STEP 1
──────────────────

FUZZ=key
│
└── Fuzz parameter NAME


STEP 2
──────────────────

id=FUZZ
   │
   └── Fuzz parameter VALUE
```

This is the logical progression of the module.

---

# 22. POST Parameter Fuzzing Workflow

```text
                Admin Page
                    │
                    ▼
             Access restricted
                    │
                    ▼
        Suspect hidden parameters
                    │
                    ▼
          POST parameter fuzzing
                    │
                    ▼
             -d 'FUZZ=key'
                    │
                    ▼
              Interesting hit
                    │
                    ▼
                    id
                    │
                    ▼
             Manual POST request
                    │
                    ▼
             id=key
                    │
                    ▼
             "Invalid id!"
                    │
                    ▼
       Parameter is recognized
                    │
                    ▼
         Investigate ID values
```

---

# 23. Why `curl` Is Useful

Ffuf is excellent for automated enumeration.

Once we have an interesting result, however, manually reproducing the request is useful.

For example:

```bash
curl http://admin.academy.htb:PORT/admin/admin.php \
-X POST \
-d 'id=key' \
-H 'Content-Type: application/x-www-form-urlencoded'
```

This allows us to clearly see the application's response.

A useful methodology is:

```text
Ffuf
 ↓
Discovery
 ↓
Curl/Burp
 ↓
Manual verification
 ↓
Further testing
```

---

# 24. Ffuf vs Curl

### Ffuf

Best for:

```text
Automated enumeration
Large wordlists
Finding unusual responses
Parameter discovery
```

### Curl

Best for:

```text
Reproducing requests
Quick manual testing
Inspecting responses
Changing parameters individually
```

Both are useful together.

---

# 25. Important Ffuf Options for POST

|Option|Purpose|
|---|---|
|`-w`|Wordlist|
|`-u`|Target URL|
|`-X POST`|Use POST method|
|`-d`|POST request body|
|`-H`|Add HTTP header|
|`-fs`|Filter response size|
|`-fw`|Filter word count|
|`-fl`|Filter line count|
|`-fc`|Filter status code|

The core combination is:

```text
-X POST
-d 'FUZZ=key'
```

---

# 26. Content-Type Is Important

For this lab, the request should use:

```text
Content-Type: application/x-www-form-urlencoded
```

Therefore:

```bash
-H 'Content-Type: application/x-www-form-urlencoded'
```

is included.

Without the appropriate content type, the application may not interpret the POST body as expected.

---

# 27. Multiple POST Parameters

POST bodies can contain multiple parameters.

Example:

```text
username=admin&password=test
```

If we wanted to fuzz one parameter:

```text
username=admin&FUZZ=test
```

or:

```text
FUZZ=admin&password=test
```

depending on which parameter we're investigating.

---

# 28. GET and POST Can Use Similar Parameter Names

An application may accept:

```text
GET:
?id=10
```

and also:

```text
POST:
id=10
```

But that shouldn't be assumed.

The backend can treat GET and POST differently.

Therefore:

> **Finding a parameter through GET does not automatically prove that the same parameter works through POST, and vice versa.**

Always verify.

---

# 29. Why Test Both?

A web application might have logic such as:

```text
GET:
?id=10
→ ignored

POST:
id=10
→ processed
```

or:

```text
GET:
?id=10
→ processed

POST:
id=10
→ ignored
```

Therefore, comprehensive web testing should consider the request method.

---

# 30. Common Mistakes

### Mistake 1 — Putting the POST parameter after `?`

Don't do:

```text
/admin.php?FUZZ=key
```

when you're testing POST parameters.

Use:

```text
/admin.php
```

with:

```text
-d 'FUZZ=key'
```

---

### Mistake 2 — Forgetting `-X POST`

Without:

```text
-X POST
```

ffuf will normally send GET requests.

---

### Mistake 3 — Forgetting `-d`

`-d` specifies the request body.

```bash
-d 'FUZZ=key'
```

---

### Mistake 4 — Forgetting Content-Type

For this PHP application:

```bash
-H 'Content-Type: application/x-www-form-urlencoded'
```

helps ensure the body is interpreted as form data.

---

### Mistake 5 — Assuming `id=key` is the correct value

The word:

```text
key
```

is only a test value.

The response:

```text
Invalid id!
```

indicates that the actual expected ID is something else.

---

# 31. Important Security Lesson

Parameter fuzzing isn't just about discovering "secret parameters."

It also helps us understand **backend application logic**.

For example:

```text
id=key
    ↓
Invalid id!
```

reveals that the backend has an `id` processing path.

That can lead to further authorized testing of:

- Input validation
    
- Access control
    
- Object references
    
- Authorization logic
    
- Error handling
    

---

# 32. GET vs POST Cheat Sheet

|Feature|GET|POST|
|---|---|---|
|Parameter location|URL|Request body|
|Separator|`?`|Body encoding|
|Ffuf method|Default GET|`-X POST`|
|Ffuf data|URL|`-d`|
|Example|`?id=10`|`id=10`|
|Header often useful|Depends|Content-Type|
|Name fuzzing|`?FUZZ=key`|`-d 'FUZZ=key'`|
|Value fuzzing|`?id=FUZZ`|`-d 'id=FUZZ'`|

---

# 33. The Two Commands to Memorize

### GET parameter-name fuzzing

```bash
ffuf -w parameter-wordlist:FUZZ \
-u 'http://TARGET/page.php?FUZZ=key'
```

### POST parameter-name fuzzing

```bash
ffuf -w parameter-wordlist:FUZZ \
-u 'http://TARGET/page.php' \
-X POST \
-d 'FUZZ=key' \
-H 'Content-Type: application/x-www-form-urlencoded'
```

The difference is essentially:

```text
GET:
?FUZZ=key

POST:
-d 'FUZZ=key'
```

---

# 34. The Key Discovery in This Section

The important result is:

```text
id
```

When tested with:

```text
id=key
```

the application returns:

```text
Invalid id!
```

This gives us a much stronger clue than a generic response.

It suggests:

```text
id parameter
      ↓
Recognized
      ↓
Value processed
      ↓
"key" isn't valid
```

---

# 35. Natural Next Step

We have now moved from:

```text
"What parameter exists?"
```

to:

```text
"What value does this parameter expect?"
```

That means the next logical phase is **parameter-value fuzzing**:

```text
id=FUZZ
```

rather than:

```text
FUZZ=key
```

---

# 36. Exam / Viva Questions

### Q1. What is the main difference between GET and POST?

GET parameters are normally included in the URL query string, while POST parameters are sent in the request body.

---

### Q2. Which ffuf option specifies POST data?

```text
-d
```

---

### Q3. Which option changes the HTTP method to POST?

```text
-X POST
```

---

### Q4. What Content-Type does this PHP lab use?

```text
application/x-www-form-urlencoded
```

---

### Q5. How do you fuzz POST parameter names?

```bash
-d 'FUZZ=key'
```

---

### Q6. What parameter was discovered?

```text
id
```

---

### Q7. What happened when we sent `id=key`?

The server responded:

```text
Invalid id!
```

---

### Q8. What does `Invalid id!` suggest?

It suggests that the application recognizes the `id` parameter and attempts to validate/process its value.

---

### Q9. What should we investigate next?

The **value** accepted by the `id` parameter.

Conceptually:

```text
id=FUZZ
```

---

### Q10. Why use curl after ffuf?

To manually reproduce and verify an interesting request and inspect the application's response.

---

# 37. Quick Revision

```text
GET
↓
URL
↓
/admin.php?FUZZ=key
```

```text
POST
↓
Request Body
↓
-d 'FUZZ=key'
```

For this PHP application:

```text
-H 'Content-Type: application/x-www-form-urlencoded'
```

Discovery:

```text
FUZZ=key
    ↓
id
    ↓
id=key
    ↓
Invalid id!
```

Therefore:

```text
Parameter name discovered
        ↓
Application recognizes it
        ↓
Value is invalid
        ↓
Fuzz the VALUE next
```

---

# 38. Final Takeaways

> **POST parameters are sent in the HTTP request body rather than appended to the URL.**

> **Use `-X POST` to tell ffuf to send POST requests.**

> **Use `-d` to specify POST data.**

> **For this PHP lab, use `Content-Type: application/x-www-form-urlencoded`.**

> **POST parameter-name fuzzing uses `-d 'FUZZ=key'`.**

> **The module discovers the `id` parameter.**

> **Testing `id=key` returns `Invalid id!`, indicating that the parameter is recognized but the supplied value is invalid.**

> **This is a clue to move from parameter-name fuzzing toward parameter-value fuzzing.**

### The core syntax to memorize:

```bash
ffuf -w /path/to/parameter-wordlist:FUZZ \
-u http://TARGET/page.php \
-X POST \
-d 'FUZZ=key' \
-H 'Content-Type: application/x-www-form-urlencoded'
```

And the conceptual progression:

```text
GET:
?FUZZ=key
    ↓
Find parameter


POST:
FUZZ=key
    ↓
Find parameter


Then:
id=FUZZ
    ↓
Find accepted value
```

**The biggest thing to remember: GET puts the parameter in the URL; POST puts it in the request body.**