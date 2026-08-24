![Image](https://images.openai.com/static-rsc-4/ytQKhjudLpkHNlyzmhqXq4v-NlfZOQKOYAU4JTOvKRi2Blb_PeM4yaEpou9G_w5vGSAMRgde62HpgbKh2nbYn3PTS_IHU1lWpW81lzM1R7_ansBrpc1SPPYD6wd79QX5GC2pQ29SDxR5bTravJ2eluhY-81vVnOAs38AXkUCBMfSuGvQpHpsVtlB5oDMnfnv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Rik7VKMQuXgTBUDQX5yELuI9nEzFL4TxZQyMuYbUaJJP5NUBOrO1yI1DrtEYUxDVhySqr7Fkh-GkRCdWSBwRnNgh-CSgHsnP2uxqULaVXx7GeQBFXvUo18AfxvX1rxDgZKqCqpIJ0Ak2FN35AAp-EMM4wlIyeRTTK79QdL1mS0kWLknhfVnaFWRKCKeDDPhf?purpose=fullsize)

This section is the **final step in the parameter-fuzzing chain**. Previously, we discovered that the application accepts an `id` parameter. Now we need to determine **which value for `id` is valid**.

The key transition is:

```text
FUZZ=key
   ↓
Find parameter name
   ↓
id=key
   ↓
"Invalid id!"
   ↓
id=FUZZ
   ↓
Find valid value
```

---

# 1. What Have We Discovered So Far?

Our investigation has progressed through several stages.

First, we discovered:

```text
admin.academy.htb
```

Then:

```text
/admin/admin.php
```

The page told us we didn't have permission to read the flag.

We then fuzzed GET parameters and POST parameters.

POST parameter fuzzing revealed:

```text
id
```

When we tested:

```text
id=key
```

the application responded:

```text
Invalid id!
```

This is an important clue.

It tells us that:

```text
id
```

is a recognized parameter, but:

```text
key
```

is not a valid value.

---

# 2. Parameter Name vs Parameter Value

This distinction is the **most important concept in this section**.

### Parameter-name fuzzing

We used:

```text
FUZZ=key
```

For example:

```text
id=key
user=key
admin=key
token=key
```

The question was:

> **Which parameter name does the application recognize?**

---

### Parameter-value fuzzing

Now we use:

```text
id=FUZZ
```

For example:

```text
id=1
id=2
id=3
id=4
...
```

The question becomes:

> **Which value does the application accept for the `id` parameter?**

---

# 3. The Key Difference

Memorize this:

```text
PARAMETER NAME FUZZING
──────────────────────

FUZZ=key
│
└── Fuzz NAME
```

versus:

```text
PARAMETER VALUE FUZZING
───────────────────────

id=FUZZ
   │
   └── Fuzz VALUE
```

This distinction appears repeatedly in web security testing.

---

# 4. Why Do We Need a Custom Wordlist?

For parameter **names**, we can use a generic wordlist such as:

```text
burp-parameter-names.txt
```

because common parameter names are relatively predictable:

```text
id
user
username
page
file
token
debug
action
```

Parameter **values** are different.

An application could expect:

```text
admin
john
123
1001
secret
production
enabled
```

There isn't one universal wordlist that works for every parameter.

Therefore:

> **The expected data type of the parameter should influence the value wordlist we use.**

---

# 5. Choosing a Value Wordlist

Before fuzzing values, ask:

> **What type of value does this parameter probably expect?**

For example:

|Parameter|Likely value|
|---|---|
|`username`|Usernames|
|`password`|Password candidates|
|`id`|Numbers/identifiers|
|`page`|Page numbers|
|`file`|Filenames|
|`role`|Role names|
|`token`|Token candidates|
|`action`|Action names|

For our case:

```text
id
```

strongly suggests an identifier.

So a numeric wordlist is a reasonable starting point.

---

# 6. Sequential IDs

Many applications use sequential identifiers.

For example:

```text
id=1
id=2
id=3
id=4
...
id=100
```

or:

```text
id=1000
id=1001
id=1002
```

If we don't know the format, we can begin with a reasonable range.

The module chooses:

```text
1 → 1000
```

---

# 7. Creating the Custom Wordlist

The module uses Bash:

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

This creates:

```text
ids.txt
```

containing:

```text
1
2
3
4
5
6
...
1000
```

---

# 8. Breaking Down the Bash Command

The command is:

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

Let's break it down.

### `seq 1 1000`

Generates:

```text
1
2
3
...
1000
```

---

### `for i in ...`

Loops through every number.

Conceptually:

```text
i=1
i=2
i=3
...
i=1000
```

---

### `echo $i`

Prints the current number.

---

### `>> ids.txt`

Appends the number to:

```text
ids.txt
```

So the final file contains all values.

---

# 9. Why `>>`?

The operator:

```text
>>
```

means:

> Append output to the file.

For example:

```bash
echo 1 >> ids.txt
```

adds:

```text
1
```

to the file.

Then:

```bash
echo 2 >> ids.txt
```

adds:

```text
2
```

and so forth.

---

# 10. `>` vs `>>`

This is a useful Linux concept.

### `>`

Overwrite/create:

```bash
echo hello > file.txt
```

### `>>`

Append:

```bash
echo hello >> file.txt
```

For our loop, we need:

```text
>>
```

because we want to keep adding IDs.

---

# 11. Verify the Wordlist

We can inspect it using:

```bash
cat ids.txt
```

We should see:

```text
1
2
3
4
5
...
```

At the end:

```text
996
997
998
999
1000
```

Now the wordlist is ready.

---

# 12. Why Not Just Guess Manually?

We could try:

```text
id=1
id=2
id=3
...
```

manually.

But that would be inefficient.

Ffuf can automate hundreds or thousands of requests.

Instead of:

```text
Human → Request → Read
Human → Request → Read
Human → Request → Read
...
```

we use:

```text
Wordlist
   ↓
Ffuf
   ↓
Hundreds of requests
   ↓
Filter normal responses
   ↓
Identify unusual result
```

---

# 13. Value Fuzzing Command

The module uses:

```bash
ffuf -w ids.txt:FUZZ \
-u http://admin.academy.htb:PORT/admin/admin.php \
-X POST \
-d 'id=FUZZ' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-fs xxx
```

This is the main command to remember.

---

# 14. Command Breakdown

### Wordlist

```text
-w ids.txt:FUZZ
```

Use:

```text
ids.txt
```

and assign the keyword:

```text
FUZZ
```

---

### Target

```text
-u http://admin.academy.htb:PORT/admin/admin.php
```

The URL does **not** contain the parameter.

---

### HTTP Method

```text
-X POST
```

Send a POST request.

---

### Data

```text
-d 'id=FUZZ'
```

This is the critical change from the previous section.

Previously:

```text
-d 'FUZZ=key'
```

Now:

```text
-d 'id=FUZZ'
```

We're keeping the parameter name fixed and fuzzing its value.

---

### Content-Type

```text
-H 'Content-Type: application/x-www-form-urlencoded'
```

This tells the PHP application how the POST body is encoded.

---

### Filter

```text
-fs xxx
```

Removes the normal response size.

Again, `xxx` is a placeholder in the module; use the baseline response size from your own target.

---

# 15. What Requests Does Ffuf Send?

Given:

```text
ids.txt
```

containing:

```text
1
2
3
4
5
```

ffuf effectively generates:

```http
POST /admin/admin.php HTTP/1.1
Host: admin.academy.htb
Content-Type: application/x-www-form-urlencoded

id=1
```

Then:

```http
id=2
```

Then:

```http
id=3
```

and so on.

---

# 16. The Fuzzing Process

The complete process looks like:

```text
ids.txt
   │
   ├── 1
   ├── 2
   ├── 3
   ├── 4
   ├── ...
   └── 1000
          │
          ▼
        ffuf
          │
          ▼
 POST id=FUZZ
          │
          ▼
    Web application
          │
          ▼
 Compare responses
          │
          ▼
 Filter baseline
          │
          ▼
 Interesting ID
```

---

# 17. Why Filtering Is Important

Suppose:

```text
id=1 → 200 / 465 bytes
id=2 → 200 / 465 bytes
id=3 → 200 / 465 bytes
...
```

Most IDs are invalid.

If the normal response is:

```text
465 bytes
```

we use:

```bash
-fs 465
```

Then ffuf hides those results.

Suppose:

```text
id=73 → 200 / 900 bytes
```

Now:

```text
900 ≠ 465
```

so the result remains visible.

---

# 18. The Important Signal

We're looking for an anomaly.

For example:

```text
ID      Status    Size
-----------------------
1       200       465
2       200       465
3       200       465
...
73      200       900   ← interesting
74      200       465
```

The status code isn't necessarily different.

The **response behavior** is.

---

# 19. Why This Is Similar to VHost Fuzzing

Remember our VHost methodology:

```text
Default VHost
     ↓
900 bytes
     ↓
-fs 900
     ↓
Different response
     ↓
Potential VHost
```

Value fuzzing follows the same principle:

```text
Invalid ID
     ↓
Normal response
     ↓
-fs baseline
     ↓
Different response
     ↓
Potential valid ID
```

The technique is the same.

Only the fuzzing location changes.

---

# 20. Parameter Fuzzing Evolution

This module has now built a very logical progression.

### Step 1 — Find the page

```text
/admin/admin.php
```

### Step 2 — Find the parameter

```text
FUZZ=key
```

### Step 3 — Discover:

```text
id
```

### Step 4 — Test it

```text
id=key
```

### Step 5 — Application says:

```text
Invalid id!
```

### Step 6 — Fuzz the value

```text
id=FUZZ
```

### Step 7 — Use IDs:

```text
1 → 1000
```

### Step 8 — Find the valid ID

### Step 9 — Manually verify

### Step 10 — Retrieve the intended lab flag

---

# 21. The Core Concept

Think of the application as:

```text
id = ?
```

We know:

```text
id
```

but not:

```text
?
```

So we systematically test:

```text
id=1
id=2
id=3
...
id=1000
```

until the application's response tells us we've found something different.

---

# 22. Why a Numeric Wordlist Makes Sense

The parameter name is:

```text
id
```

and the server responds:

```text
Invalid id!
```

That suggests the backend expects some identifier.

A numeric sequence is therefore a reasonable hypothesis.

But remember:

> **The name `id` doesn't guarantee that the value is numeric.**

It could be:

```text
user-001
abc123
admin01
UUID
```

Therefore, if `1–1000` doesn't work, we would reconsider the expected format rather than assuming the application is broken.

---

# 23. Custom Wordlists Are Powerful

The value wordlist should reflect what you're testing.

Examples:

### IDs

```text
1
2
3
...
1000
```

### Usernames

```text
admin
administrator
john
jason
guest
```

### File extensions

```text
php
html
txt
bak
old
```

### Common actions

```text
view
edit
delete
update
admin
debug
```

The correct wordlist depends on the parameter.

---

# 24. Wordlist Strategy

A good approach is:

```text
Identify parameter
       ↓
Infer expected data type
       ↓
Choose/create wordlist
       ↓
Start with small/common values
       ↓
Expand if necessary
```

This is much more efficient than blindly throwing enormous wordlists at every parameter.

---

# 25. Why Start With 1–1000?

The module chooses:

```text
1 → 1000
```

because it is:

- Easy to generate
    
- Small enough to scan quickly
    
- Reasonable for a sequential ID hypothesis
    
- Large enough to cover many simple applications
    

If necessary, the range could be expanded later.

---

# 26. Alternative Ways to Generate the Wordlist

The module uses:

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

A simpler equivalent in many shells is:

```bash
seq 1 1000 > ids.txt
```

This directly writes the sequence to the file.

You can verify:

```bash
head ids.txt
```

and:

```bash
tail ids.txt
```

---

# 27. Why `seq` Is Useful

`seq` generates sequences of numbers.

Examples:

```bash
seq 1 10
```

produces:

```text
1
2
3
4
5
6
7
8
9
10
```

And:

```bash
seq 100 200
```

produces:

```text
100
101
102
...
200
```

This is very useful for creating numeric fuzzing wordlists.

---

# 28. POST Value Fuzzing vs GET Value Fuzzing

The concept works for both HTTP methods.

### GET

```bash
ffuf -w values.txt:FUZZ \
-u 'http://TARGET/page.php?id=FUZZ'
```

### POST

```bash
ffuf -w values.txt:FUZZ \
-u http://TARGET/page.php \
-X POST \
-d 'id=FUZZ'
```

The principle is identical:

```text
parameter = FUZZ
```

Only the location changes.

---

# 29. GET vs POST — Full Comparison

|Stage|GET|POST|
|---|---|---|
|Parameter name|`?FUZZ=key`|`-d 'FUZZ=key'`|
|Parameter value|`?id=FUZZ`|`-d 'id=FUZZ'`|
|Method|GET|`-X POST`|
|Location|URL|Request body|
|Common content type|Depends|`application/x-www-form-urlencoded` in this lab|

---

# 30. Manual Verification With Curl

Once ffuf identifies an interesting ID, we should verify it manually.

The general format is:

```bash
curl http://admin.academy.htb:PORT/admin/admin.php \
-X POST \
-d 'id=FOUND_ID' \
-H 'Content-Type: application/x-www-form-urlencoded'
```

Replace:

```text
FOUND_ID
```

with the value discovered by ffuf.

---

# 31. Why Manual Verification Matters

Ffuf tells us:

```text
"This response was different."
```

It doesn't automatically prove:

```text
"This is definitely the correct application value."
```

So:

```text
Ffuf
 ↓
Interesting value
 ↓
Curl
 ↓
Inspect response
 ↓
Confirm
```

is a good workflow.

---

# 32. Potential Outcomes

Suppose ffuf finds:

```text
73 [Status: 200, Size: 900]
```

We test:

```bash
curl ... -d 'id=73'
```

Possible responses include:

### Valid ID

```text
Flag content
```

### Different application behavior

```text
Access granted
```

### Redirect

```text
Location: /admin/...
```

### Still invalid

```text
Invalid id!
```

Therefore, always manually verify.

---

# 33. Don't Assume the First Hit Is Always the Final Answer

A fuzzing result is a **lead**.

Even if ffuf reports:

```text
73
```

we still need to understand why the response differs.

Possible reasons include:

```text
Valid ID
Different error
Special application behavior
Dynamic content
Rate limiting
```

Verification is essential.

---

# 34. Common Mistakes

## Mistake 1 — Fuzzing the parameter name again

Don't use:

```text
-d 'FUZZ=key'
```

once we've already discovered `id`.

Use:

```text
-d 'id=FUZZ'
```

---

## Mistake 2 — Using the wrong wordlist

A parameter called:

probably doesn't need a username wordlist.

Start with a numeric list if the application behavior supports that hypothesis.

---

## Mistake 3 — Forgetting the POST method

Use:

```text
-X POST
```

---

## Mistake 4 — Forgetting the request body

Use:

```text
-d 'id=FUZZ'
```

---

## Mistake 5 — Forgetting Content-Type

For this PHP application:

```text
-H 'Content-Type: application/x-www-form-urlencoded'
```

---

## Mistake 6 — Not filtering the baseline

Without:

```text
-fs SIZE
```

you may receive hundreds of identical results.

---

# 35. Important Ffuf Options

|Option|Purpose|
|---|---|
|`-w`|Specify wordlist|
|`-u`|Specify URL|
|`-X POST`|Use POST|
|`-d`|POST body|
|`-H`|HTTP header|
|`-fs`|Filter response size|
|`-fw`|Filter word count|
|`-fl`|Filter line count|
|`-fc`|Filter status code|
|`-t`|Number of threads|

---

# 36. The Three Core Fuzzing Patterns

### 1. Directory

```text
/FUZZ
```

Question:

> What directories/files exist?

---

### 2. Parameter name

```text
?FUZZ=value
```

or:

```text
-d 'FUZZ=value'
```

Question:

> What parameter exists?

---

### 3. Parameter value

```text
?id=FUZZ
```

or:

```text
-d 'id=FUZZ'
```

Question:

> What value is accepted?

---

# 37. Complete Module Methodology

You can now visualize the entire process:

```text
                 TARGET
                    │
                    ▼
             Directory Fuzzing
                    │
                    ▼
                 /blog
                    │
                    ▼
            Extension Fuzzing
                    │
                    ▼
                  .php
                    │
                    ▼
              Page Fuzzing
                    │
                    ▼
            Hidden PHP page
                    │
                    ▼
            Recursive Fuzzing
                    │
                    ▼
           academy.htb discovery
                    │
                    ▼
             VHost Fuzzing
                    │
                    ▼
          admin.academy.htb
                    │
                    ▼
             Admin page
                    │
                    ▼
          Parameter fuzzing
                    │
                    ▼
              Discover id
                    │
                    ▼
             id=key
                    │
                    ▼
            "Invalid id!"
                    │
                    ▼
             Value fuzzing
                    │
                    ▼
               id=FUZZ
                    │
                    ▼
             Numeric wordlist
                    │
                    ▼
             Valid ID found
                    │
                    ▼
             Manual verify
                    │
                    ▼
              Flag content
```

---

# 38. Exam / Viva Questions

### Q1. What is value fuzzing?

Value fuzzing is the process of testing many possible values for a known parameter to identify a value that causes interesting or valid application behavior.

---

### Q2. What syntax is used for POST value fuzzing?

```bash
-d 'id=FUZZ'
```

---

### Q3. Why do we use a custom wordlist?

Because parameter values are application-specific and may not be covered by generic wordlists.

---

### Q4. What wordlist did the module create?

```text
ids.txt
```

containing:

```text
1–1000
```

---

### Q5. How was the wordlist created?

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

---

### Q6. What does `seq 1 1000` do?

Generates integers from `1` through `1000`.

---

### Q7. What changed from parameter-name fuzzing?

Previously:

```text
FUZZ=key
```

Now:

```text
id=FUZZ
```

---

### Q8. Why is `id` fixed?

Because we already discovered that `id` is a recognized parameter.

---

### Q9. Why use `-fs`?

To remove the normal response and make unusual responses easier to identify.

---

### Q10. What should we do after ffuf finds an interesting ID?

Manually send the request with `curl` and verify the application's response.

---

# 39. Quick Cheat Sheet

### Create numeric wordlist

```bash
seq 1 1000 > ids.txt
```

or the module's method:

```bash
for i in $(seq 1 1000); do echo $i >> ids.txt; done
```

### Fuzz POST parameter values

```bash
ffuf -w ids.txt:FUZZ \
-u http://admin.academy.htb:PORT/admin/admin.php \
-X POST \
-d 'id=FUZZ' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-fs BASELINE_SIZE
```

### Verify discovered value

```bash
curl http://admin.academy.htb:PORT/admin/admin.php \
-X POST \
-d 'id=FOUND_ID' \
-H 'Content-Type: application/x-www-form-urlencoded'
```

---

# 40. The Three Things to Memorize

### Parameter name:

```text
FUZZ=key
```

### Parameter value:

```text
id=FUZZ
```

### Numeric wordlist:

```bash
seq 1 1000 > ids.txt
```

---

# 41. Final Takeaways

> **Once a working parameter is discovered, the next step may be to fuzz its value.**

> **Parameter values are application-specific, so a custom wordlist may be necessary.**

> **The expected data type should guide your wordlist selection.**

> **Because the parameter is called `id`, a numeric sequence is a reasonable initial hypothesis.**

> **The module creates values from `1` through `1000`.**

> **For POST value fuzzing, use `-d 'id=FUZZ'`.**

> **Keep the known parameter name fixed and place `FUZZ` where the value belongs.**

> **Use `-fs` to filter the normal response and expose unusual responses.**

> **Always manually verify an interesting result with a tool such as `curl`.**

### The entire concept in one line:

```text
Find parameter → id
                  ↓
Test value → id=key
                  ↓
Invalid id!
                  ↓
Fuzz value → id=FUZZ
                  ↓
Find valid ID
                  ↓
Verify
```

**The key syntax to remember is:**

```bash
-d 'id=FUZZ'
```

That is the fundamental difference between **parameter-name fuzzing** and **parameter-value fuzzing**.