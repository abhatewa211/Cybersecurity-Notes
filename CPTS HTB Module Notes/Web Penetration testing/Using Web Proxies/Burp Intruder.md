![Image](https://images.openai.com/static-rsc-4/EwNRq_EOgh05Axznt3s05vgezkKi2mV_BJzIqOV5IcUBCM_iYzlPYLkxn8LilSurIMxr-a-zAwn4xgnOco8nhdyFDxoFFHx42qe36-LSMi5XHGAX3wjw3ynO8GCMLlSoXnz2abmRSQwMINYqLmI22NPwO1yzcxvpbXRLaxDsir0w6G70ORzikRKGC5G514DA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iTGolx8LlUnTG4OYbKha9xRS_BvJQbSSqaKuSGcGPOeGVV0iOf_KOzreu1gsBKfN65lgH2xmbjUy-eaERnmwiuyhUTcgUIm9Poaub0nE_WB5fdhLuAbJo3J_ohCtZ9Vv0_e-iYKNRlSjEpthN-eJbxjc6f0hsuA4_xzwJRLuBCvizvCbL4RSpANGNS-VyM2V?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FcDwrPbOtPtGgfrO0vnslMUGb46OGvUkK85R8dW8s00nJev-dABjUxGjn6J8slKHaElpz8Pt4_EdQgRWUMl4RL3VE_cRTaS81vRiTiOObgghfHuiDoNJ1nmqSUniU8zjt4luDd5xYonyKVALnDhC2DEDlWL7XPUeOnP2QkeO6tUkoDl-5W4VFZWb3IpPtsl6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qbhZ_TQCPDCuTZZ3gRlbQEoTL5bmlE-41uTTZ2YxcKzFUx29uj24eZk3Kej1dauRNTGbOie-0HHCpbqJUcU_2lI6OUNYnzFl87ZxCBpPI3tzVF496esGT7HyFi1oN9vqcjoj1JivDvuK7AW4B-qxaC3CV-uunEn9r4AUlbjRhdO-gJ2oukUt4897J0BLWAfN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZnuU9VcE6BD3Z6XQE61HED07sNzAx4EhEQgO8ZjAqt8dfJr4czQ96oe76WWknbvxNA2e0SDK0Ns8tNfPtkr7OVb0iF0dF3Sxp98csAlizlUUwgLOSoW1PWmbeEESNnIQ6iSJYO83ojaQc3Br77QTCjNfwDUgf3ESFu6KX4LpBPbGvoyBKdzsYx1g98YotzN9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ttq2L4bjscdTIJqix95L72Ll2D9kOKd2FgiuAtANyBhfU6wxFTr-h3BGEJi4557NgIaVV50dyN2hjOhWP_l0sAuotKYHGpr41BFDXxJCtZBQor0ZadqS4ajLdpQkJzzoz_DOkQiG4UGdZfGS8y9Y-KEc6Kue-3goxbTfhD0NUkjyilT46mZ5pqZdtUCkzRxA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/O7MPSMuW2tTzGgZHOk8RVTDqYMinLqSfpB3A12O60-Sz2v9rspd1_isG6ApmH2pWTj0E3ic-ctnIKuvYVviTgvXYIHK9E__9-XDo6t2zc5iosu45VXL-xUVlO2DS4ryvuhbywmqDXPexH0tYYny7hgBMMyxEUHVfNHuTPdN3lsneAxkrgDgyz0f6s8SqbN55?purpose=fullsize)

## 1. What Is Burp Intruder?

Burp Intruder is Burp Suite's built-in **web fuzzing and automated request-testing tool**.

Both Burp and ZAP provide additional features beyond their basic proxy functionality, particularly:

- **Web fuzzers**
    
- **Web scanners**
    

These tools can be used for tasks such as:

- Web fuzzing
    
- Enumeration
    
- Brute-forcing
    
- Testing directories
    
- Testing parameters
    
- Testing parameter values
    
- Other repetitive web-request testing
    

Burp Intruder can therefore serve as an alternative to CLI fuzzing tools such as `ffuf`, `dirbuster`, `gobuster`, and `wfuzz`.

---

# 2. Burp Intruder vs CLI Fuzzers

Burp Intruder is considerably more feature-rich than many CLI fuzzing tools, but there is an important limitation.

### Burp Community

The free Community version is throttled to approximately:

```text
1 request / second
```

This makes it extremely slow for large wordlists.

CLI fuzzers can commonly perform substantially more requests per second.

### Burp Professional

The Pro version removes this speed limitation and can be used for much larger/faster fuzzing operations.

### ⭐ Important

> **Burp Community Intruder is useful for short queries and learning, but it is generally unsuitable for large, high-speed fuzzing jobs.**

---

# 3. What Can Burp Intruder Fuzz?

Intruder can be used to fuzz:

```text
Pages
Directories
Sub-domains
Parameters
Parameter values
Other request locations
```

The fundamental idea is:

```text
Original Request
      ↓
Identify Payload Position
      ↓
Provide Wordlist
      ↓
Intruder substitutes each payload
      ↓
Send requests
      ↓
Compare responses
```

---

# 4. Intruder Workflow

The general workflow is:

```text
Proxy History
     ↓
Select interesting request
     ↓
Send to Intruder
     ↓
Target
     ↓
Positions
     ↓
Payloads
     ↓
Settings
     ↓
Start Attack
     ↓
Analyze Results
```

This four-stage configuration is the core of Intruder.

---

# 🎯 5. Target

Start by capturing the request through Burp's browser.

Then:

```text
Proxy
 ↓
HTTP History
 ↓
Select Request
 ↓
Right-click
 ↓
Send to Intruder
```

The shortcut is:

```text
CTRL + I
```

You can then open the Intruder tab.

The shortcut for directly going to Intruder is:

```text
CTRL + SHIFT + I
```

The **Target** section shows the target details obtained from the request that was sent to Intruder.

---

# 📍 6. Positions

**Positions** determine **where Intruder inserts payloads**.

Think of the payload position as a placeholder:

```text
GET /DIRECTORY/ HTTP/1.1
```

We want Intruder to replace:

```text
DIRECTORY
```

with values from our wordlist.

So we mark it:

```text
GET /§DIRECTORY§/ HTTP/1.1
```

The `§` symbols indicate the payload position.

---

# 7. Why Positions Matter

Suppose your wordlist contains:

```text
admin
login
dashboard
robots.txt
backup
```

Intruder effectively generates:

```text
GET /admin/ HTTP/1.1
GET /login/ HTTP/1.1
GET /dashboard/ HTTP/1.1
GET /robots.txt/ HTTP/1.1
GET /backup/ HTTP/1.1
```

The payload position determines **where those values go**.

---

# 8. Directory Fuzzing Example

For directory discovery, the request is structured as:

```http
GET /DIRECTORY/ HTTP/1.1
```

The goal is to identify directories that exist.

For example:

```text
/admin/
/login/
/dashboard/
/backup/
```

The server may return:

```text
200 OK
```

for an existing resource and:

```text
404 NOT FOUND
```

for a nonexistent one.

Therefore:

```text
200 OK  → Potentially interesting
404     → Usually nonexistent
```

The module uses this difference to identify the `/admin/` directory.

---

# ⚠️ Important Request Detail

When modifying the request for Intruder, the module notes:

> **Leave the extra two lines at the end of the request.**

Removing them can cause an error response.

So don't accidentally remove the blank lines separating the HTTP headers from the request body when preparing the request.

---

# 📦 9. Payloads

The **Payloads** section determines what values Intruder will insert into your payload positions.

A payload is essentially an item that Intruder substitutes into the request.

Example wordlist:

```text
admin
login
dashboard
backup
test
```

Intruder processes them one by one.

```text
§DIRECTORY§
     ↓
admin
     ↓
login
     ↓
dashboard
     ↓
backup
     ↓
test
```

The module identifies four major Payload configuration areas:

1. Payload Position & Payload Type
    
2. Payload Configuration
    
3. Payload Processing
    
4. Payload Encoding
    

---

# 10. Payload Position & Payload Type

The first thing to configure is:

```text
Payload Position
```

and:

```text
Payload Type
```

The payload set identifies which payload position we're configuring.

---

# 11. Attack Type Affects Payload Sets

For a simple example, suppose we have one payload position:

```text
GET /§DIRECTORY§/
```

With the **Sniper** attack type, we have one payload position.

Therefore:

```text
Payload Set: 1
Payload Position: DIRECTORY
```

If we use an attack type with multiple payload positions, more payload sets can become available.

---

# 12. Simple List

The module uses:

> **Simple List**

This is the most basic payload type.

You provide a wordlist:

```text
admin
login
dashboard
backup
```

Intruder iterates through each line.

Conceptually:

```text
Wordlist
   ↓
admin
   ↓
login
   ↓
dashboard
   ↓
backup
```

Each value is inserted into the selected payload position.

---

# 13. Runtime File

Another payload type is:

> **Runtime file**

Instead of loading the entire wordlist into memory beforehand, Intruder reads it line-by-line as the attack runs.

This can be useful when working with **very large wordlists**.

### Comparison

|Simple List|Runtime File|
|---|---|
|Loads wordlist|Reads during execution|
|Simple/common choice|Better for very large lists|
|Higher memory consideration|Reduces memory pressure|

The module specifically recommends Runtime File when using very large wordlists.

---

# 14. Character Substitution

Another payload type mentioned is:

> **Character Substitution**

It allows you to specify characters and replacements and have Intruder try potential permutations.

This can be useful when constructing variations of input.

The module notes that Intruder contains many additional payload types beyond these examples.

---

# 📂 15. Payload Configuration

After choosing the payload type, configure the actual payload data.

For a **Simple List**, you can:

### Manually add entries

Click:

```text
Add
```

and enter values individually.

### Load a wordlist

Click:

```text
Load
```

and select a wordlist file.

The module uses:

```text
/opt/useful/seclists/Discovery/Web-Content/common.txt
```

as its example wordlist.

---

# 16. Combining Wordlists

Intruder allows additional items to be added to the same payload list.

You can therefore:

```text
Wordlist A
     +
Wordlist B
     +
Manual entries
     ↓
Combined Payload List
```

This can be useful when building customized testing lists.

In Burp Pro, the module also notes that existing Burp wordlists can be selected through **Add from list**.

---

# 🧹 17. Payload Processing

**Payload Processing** allows you to apply rules to payloads before Intruder sends them.

Think of it as:

```text
Original Wordlist
       ↓
Payload Processing
       ↓
Modified/Filtered Payload
       ↓
Request
```

Examples include:

- Adding extensions
    
- Transforming payloads
    
- Filtering payloads
    
- Skipping unwanted entries
    

---

# 18. Example — Skip Dot Files

The module demonstrates skipping entries beginning with `.`.

The regex is:

```regex
^\..*$
```

Let's break it down.

### `^`

Beginning of the string.

### `\.`

Literal dot.

### `.*`

Any characters after the dot.

### `$`

End of the string.

Therefore:

```regex
^\..*$
```

matches strings such as:

```text
.git
.env
.htaccess
```

The processing rule can then:

> **Skip if matches regex**

This prevents those entries from being sent as payloads.

---

# 🔤 19. Payload Encoding

The fourth payload option is:

> **Payload Encoding**

This controls whether payloads are URL-encoded before being inserted into requests.

The module leaves:

```text
URL-encoding → Enabled
```

For HTTP requests, this can be important when payloads contain special characters.

---

# ⚙️ 20. Settings

The **Settings** tab contains additional attack configuration.

There are many available options, including:

```text
Network failure retries
Retry delays
Grep - Match
Grep - Extract
Resource Pool
```

You don't necessarily need to change every option.

The module demonstrates several particularly useful ones.

---

# 🔎 21. Grep — Match

**Grep - Match** allows Intruder to flag responses based on specific text.

In the directory fuzzing example, we're interested in:

```text
200 OK
```

So we configure Grep - Match to look for:

```text
200 OK
```

This gives us a quick way to identify potentially successful requests.

---

# 22. Why Grep-Match Helps

Imagine a wordlist generates:

```text
500 requests
```

Without filtering, you'd have to manually inspect many results.

With Grep-Match:

```text
500 Requests
      ↓
Grep Match: "200 OK"
      ↓
Potential matches highlighted
```

This makes result analysis much easier.

The module also recommends clearing the existing match list before adding `200 OK`.

---

# 23. Exclude HTTP Headers

The module specifically notes disabling:

> **Exclude HTTP Headers**

for this example because the relevant matching information is being searched for in the HTTP header/status information.

This is an important configuration detail for reproducing the exercise.

---

# ✂️ 24. Grep — Extract

**Grep - Extract** is useful when responses are very large but you're interested in only a particular section.

Conceptually:

```text
Large Response
      ↓
Grep - Extract
      ↓
Relevant Portion
```

This makes result analysis easier.

For this directory fuzzing example, the module doesn't use Grep-Extract because the goal is simply to identify responses associated with:

```text
200 OK
```

rather than extract a particular response body section.

---

# 🧵 25. Resource Pool

Intruder also provides:

> **Resource Pool**

This controls how much network resource the Intruder attack can use.

This becomes particularly relevant for very large attacks.

For the module's example:

```text
Resource Pool
→ Default settings
```

are retained.

---

# 🚀 26. Start Attack

Once everything is configured:

```text
Target
   ↓
Positions
   ↓
Payloads
   ↓
Settings
   ↓
Start Attack
```

Click:

> **Start Attack**

Intruder then iterates through the payload list and sends the generated requests.

---

# 27. Understanding the Results

After the attack begins, Intruder displays the requests and their responses.

In the example:

```text
200 OK
```

is highlighted because it was configured through **Grep - Match**.

You can sort the results by:

- Grep Match
    
- Status
    
- Length
    

This makes interesting responses easier to find.

---

# 28. Finding `/admin/`

The example ultimately identifies:

```text
/admin/
```

as an interesting result.

The next step described in the module is to manually visit:

```text
http://SERVER_IP:PORT/admin/
```

to verify that the resource actually exists.

### Important distinction

A `200 OK` result is an **indicator**, not automatically proof that you've discovered a valid/interesting directory.

Always validate interesting results.

---

# 29. Intruder Attack Types — Important Concept

The source mentions:

> **Sniper**

and:

> **Cluster Bomb**

### Sniper

The example has one payload position:

```text
GET /§DIRECTORY§/
```

so one payload set is used.

### Cluster Bomb

The module notes that if multiple payload positions are used with Cluster Bomb, additional payload sets become available.

This allows multiple payload locations to be tested with combinations of payload values.

The exact behavior of the different Intruder attack types is broader than this specific section, so don't infer additional details from this source alone.

---

# 30. Intruder vs Repeater

This is important given the previous section.

### Repeater

Used for **manual request repetition**:

```text
Modify
 ↓
Send
 ↓
Analyze
 ↓
Modify
 ↓
Send
```

### Intruder

Used when you want Burp to automatically iterate through a collection of payloads:

```text
Wordlist
   ↓
Payload 1
Payload 2
Payload 3
Payload 4
...
   ↓
Requests
   ↓
Analyze Results
```

### ⭐ Easy memory trick

> **Repeater = manually repeat**

> **Intruder = automatically iterate**

---

# 31. Intruder vs CLI Fuzzers

The module specifically compares Intruder with tools such as:

```text
ffuf
dirbuster
gobuster
wfuzz
```

### CLI fuzzers

Generally advantageous when:

- Speed is important
    
- Large wordlists are involved
    
- You want lightweight command-line workflows
    

### Burp Intruder

Particularly useful when:

- You're already working inside Burp
    
- You need detailed request control
    
- You want payload processing
    
- You want response matching/extraction
    
- You want to combine fuzzing with Burp's other functionality
    

The Community version's **1 request/second throttle** is the major limitation for large-scale fuzzing.

---

# 🧠 32. Complete Intruder Workflow

```text
                 HTTP REQUEST
                      │
                      ▼
                 Proxy History
                      │
                      ▼
                Send to Intruder
                      │
                      ▼
                    TARGET
                      │
                      ▼
                  POSITIONS
                      │
               Mark §PAYLOAD§
                      │
                      ▼
                   PAYLOADS
                      │
          ┌───────────┼───────────┐
          │           │           │
       Type       Processing    Encoding
          │           │           │
          └───────────┼───────────┘
                      ▼
                   SETTINGS
                      │
          ┌───────────┼───────────┐
          │           │           │
    Grep-Match   Grep-Extract  Resource
                      │
                      ▼
                START ATTACK
                      │
                      ▼
                RESULTS TABLE
                      │
                      ▼
               Analyze / Sort
                      │
                      ▼
               Verify Interesting
                   Results
```

---

# 📚 33. Quick Reference Table

|Component|Purpose|
|---|---|
|**Target**|Defines target request|
|**Positions**|Determines where payloads are inserted|
|**Payload Type**|Defines how payloads are generated|
|**Payload Configuration**|Provides the actual payload/wordlist|
|**Payload Processing**|Transforms or filters payloads|
|**Payload Encoding**|Controls URL encoding|
|**Settings**|Controls attack behavior/result processing|
|**Grep-Match**|Flags responses matching specific text|
|**Grep-Extract**|Extracts relevant response content|
|**Resource Pool**|Controls resource allocation|
|**Start Attack**|Begins payload iteration|

---

# 📝 34. Exam / Viva Questions

### Q1. What is Burp Intruder?

Burp's built-in web fuzzing and automated request-testing tool.

### Q2. What can Intruder be used for?

Web fuzzing, enumeration, brute-forcing, directory discovery, parameter testing, and similar repetitive request-testing tasks.

### Q3. What is a Payload Position?

The location in an HTTP request where Intruder inserts and iterates payload values.

### Q4. How do you mark a payload position?

Using the `§` markers or by selecting the value and using **Add §**.

Example:

```http
GET /§DIRECTORY§/ HTTP/1.1
```

### Q5. What is Simple List?

A payload type where Intruder iterates through each item in a supplied wordlist.

### Q6. What is Runtime File?

A payload type that loads the wordlist line-by-line during the attack, making it more suitable for very large wordlists.

### Q7. What is Payload Processing?

A feature that applies transformations or filtering rules to payloads before they are sent.

### Q8. What regex skips lines beginning with `.`?

```regex
^\..*$
```

### Q9. What is Grep-Match?

A feature that flags requests based on matching text in their responses.

### Q10. What is Grep-Extract?

A feature used to extract and display a specific portion of a response.

### Q11. What does Payload Encoding control?

Whether payloads are URL-encoded before being inserted into requests.

### Q12. What is the major limitation of Burp Community Intruder?

It is throttled to approximately **1 request per second**.

### Q13. What is the difference between Repeater and Intruder?

**Repeater** manually resends a request after modifications.

**Intruder** automatically iterates payloads through one or more positions.

### Q14. How do you send a request from Proxy History to Intruder?

Right-click the request → **Send to Intruder**, or use:

```text
CTRL + I
```

### Q15. What shortcut opens Intruder?

```text
CTRL + SHIFT + I
```

---

# 🔥 35. Final Revision Notes

### Remember the four Payload sections:

```text
1️⃣ Payload Position & Type
2️⃣ Payload Configuration
3️⃣ Payload Processing
4️⃣ Payload Encoding
```

### Remember the attack flow:

```text
Request
 ↓
Intruder
 ↓
Positions
 ↓
Payloads
 ↓
Processing
 ↓
Encoding
 ↓
Settings
 ↓
Start Attack
 ↓
Results
```

### Directory fuzzing example:

```http
GET /§DIRECTORY§/ HTTP/1.1
```

Wordlist:

```text
admin
login
dashboard
backup
```

Response analysis:

```text
200 OK → investigate
404    → usually not found
```

### ⭐ Core takeaway

**Burp Intruder takes an existing HTTP request, identifies one or more payload positions, iterates a configured set of payloads through those positions, and provides tools such as Payload Processing, Payload Encoding, Grep-Match, and Grep-Extract to make the resulting responses easier to analyze.**

And the most important practical distinction from the previous module is:

> **Repeater is for manually repeating and modifying requests; Intruder is for systematically iterating payloads through request positions.**