![Image](https://images.openai.com/static-rsc-4/SFZJ2SV8bwG2PkyBYRNoics1WmJwKVvN9L4ZA89K8Ors7Y7xZSw0bTUce2qKWbf8p-0bBxSYJNPB2elZ7o7ygGUXGOGxG0sdajUHTv2hSMmhqnz4Jhp8C_cS4wrE5kaBq4FjmvrmfCOIePALBMXQZhTIYJrS8fPEIkv2d6VLzxwOLiOkfe6H3u7U3GAPa8d_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/J4i3KWF2uhVPgZDrWVtrA2ZLAaG49OzPX-3M3h8slIsn7HuEl4DS3IGha2EbSBbabvpwC5KZyTq290vbzPBnRrvAnj9D1cMbbdfuQl34PZyt-NRhhr8tp9gxGxu283hjSD5c-kJa4SbxkqSCcEENuFuwRId40A3elT2IyIrlWO0Tidbuh9KE6tR5N4G9I17G?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VzVUGq9ZRvMztI4-4JV-iKRNl0gzH_LAYS9jYBatoSsuMuPWRWIEiav1PI0aec0bopO4D5XtGLgRFNdjOiZUhvd7p5SaG4TXhsA8nCZyGNmbIFcI1-hu43XIkFvTxsxxWinn-3dHFCPy3q6LCMbg7blyzMZQPKMphfOdKX084ZwKDkikGiyZ2yb81k_u-bU_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4bnl_SYXKzPm0fprTG06oD_Iw6JMwKGbFKhTQeKR5Ktn2MJRN17WxN9yIMxJhSWahclSGuYJMlXgUK_iBM_ilcJephK4ELkApNIEec3gZe1SywkKl4CAYQgAeaclSuDY5dha3_YOUq4gtmpTD-HcM1lknVlHAJbeNo7fd_pK8_DvZtS_fXG_WzjB703IjuJL?purpose=fullsize)

## 1. What Is ZAP Fuzzer?

**ZAP Fuzzer** is ZAP's built-in web fuzzing feature.

It can be used to fuzz different web endpoints and request locations. Its overall purpose is similar to **Burp Intruder**, although ZAP Fuzzer does not provide every feature available in Intruder.

The major advantage highlighted in this module is that **ZAP Fuzzer does not throttle fuzzing speed**, making it particularly useful compared with the free version of Burp Intruder.

### Quick comparison

|Feature|Burp Intruder Community|ZAP Fuzzer|
|---|---|---|
|Web fuzzing|✅|✅|
|Payload positions|✅|✅|
|Wordlists|✅|✅|
|Payload processing|✅|✅|
|Speed throttling|**~1 req/sec**|**No paid-tier throttle**|
|Built-in wordlists|Available depending on setup|✅ Built-in databases|
|Advanced features|More extensive|Somewhat fewer|

---

# 🎯 2. Main ZAP Fuzzer Configuration

The main areas we need to configure are:

```text
1. Fuzz Location
2. Payloads
3. Processors
4. Options
```

Then:

```text
Start Fuzzer
```

So the overall workflow is:

```text
Captured Request
      ↓
Fuzz Location
      ↓
Payloads
      ↓
Processors
      ↓
Options
      ↓
Start Fuzzer
      ↓
Analyze Results
```

---

# 🚀 3. Starting a Fuzzing Attack

First, capture a request through ZAP's proxy.

For the directory-fuzzing example, the module visits:

```text
http://SERVER_IP:PORT/test/
```

The purpose is simply to get a request containing:

```text
/test/
```

so that `test` can later be replaced with payloads.

After locating the request in ZAP's proxy history:

```text
Right-click request
       ↓
Attack
       ↓
Fuzz
```

This opens the **Fuzzer** window.

---

# 📍 4. Fuzz Location

The **Fuzz Location** is equivalent to a **Payload Position** in Burp Intruder.

It specifies:

> **Where should ZAP insert the payload?**

For example:

```http
GET /test/ HTTP/1.1
```

Select:

```text
test
```

and click:

```text
Add
```

ZAP places a **green marker** around the selected location.

Conceptually:

```text
GET /[PAYLOAD]/ HTTP/1.1
```

Every payload will be inserted at that location.

---

# 📦 5. Payloads

ZAP Fuzzer's payload functionality is conceptually similar to Burp Intruder.

Click:

```text
Add
```

to add a payload source.

ZAP provides **8 different payload types**, including:

- `File`
    
- `File Fuzzers`
    
- `Numberzz`
    

---

# 📄 6. File Payload

The **File** payload type allows you to select a wordlist from a file.

Conceptually:

```text
Wordlist File
      ↓
ZAP Fuzzer
      ↓
Payload 1
Payload 2
Payload 3
...
```

This is useful when you already have your own wordlist.

---

# 🗂️ 7. File Fuzzers

**File Fuzzers** allows you to use ZAP's built-in wordlist databases.

This is one of the useful advantages highlighted in the module because you don't necessarily need to provide your own wordlist.

For the directory fuzzing example, the module uses:

```text
File Fuzzers
      ↓
dirbuster
      ↓
directory-list-1.0.txt
```

The payload list contains directory names such as:

```text
cgi-bin
.git
.svn
...
```

Additional databases can also be installed through the **ZAP Marketplace**.

---

# 🔢 8. Numberzz

Another payload type is:

> **Numberzz**

It generates sequences of numbers with configurable increments.

Conceptually:

```text
1
2
3
4
5
...
```

This can be useful when testing parameters or endpoints that use numeric values.

---

# 🧩 9. Adding the Payload

After selecting the desired payload source:

```text
Add
```

adds it to the Fuzzer configuration.

You can then use:

```text
Modify
```

to examine or change the payload list.

---

# ⚙️ 10. Processors

**Processors** allow us to modify each payload before ZAP sends it.

The workflow becomes:

```text
Original Payload
      ↓
Processor
      ↓
Processed Payload
      ↓
HTTP Request
```

ZAP provides several processors.

---

# 🔐 11. Important Payload Processors

The module lists:

### Base64

```text
Base64 Encode
Base64 Decode
```

### Hashing

```text
MD5
SHA-1
SHA-256
SHA-512
```

### String modification

```text
Prefix String
Postfix String
```

### URL encoding

```text
URL Encode
URL Decode
```

### Script

Allows a custom script to process each payload.

---

# 12. Prefix and Postfix

### Prefix String

Adds a value **before** the payload.

Conceptually:

```text
Payload:
admin

Prefix:
test_

Result:
test_admin
```

### Postfix String

Adds a value **after** the payload.

```text
Payload:
admin

Postfix:
.txt

Result:
admin.txt
```

This can be useful when you need to systematically transform a wordlist.

---

# 🧠 13. Script Processor

The **Script** processor allows a custom script to process each payload before it is used.

Conceptually:

```text
Wordlist
   ↓
Custom Script
   ↓
Transformed Payload
   ↓
Request
```

This provides considerably more flexibility when standard processors aren't sufficient.

---

# 🔗 14. URL Encode Processor

For the module's directory fuzzing example, we select:

```text
URL Encode
```

The purpose is to ensure payloads containing special characters are correctly encoded before being sent.

For example, a payload containing special characters may need URL encoding to prevent unexpected parsing or server errors.

---

# 15. Generate Preview

ZAP provides:

> **Generate Preview**

This lets you see what the processed payload will look like before sending it.

Conceptually:

```text
Original:
payload

      ↓

URL Encode

      ↓

Processed:
encoded-payload
```

This is useful for confirming that your processor is doing what you expect.

---

# ⚙️ 16. Options

The **Options** section controls how the Fuzzer attack runs.

The module demonstrates:

```text
Concurrent Scanning Threads per Scan
```

and sets it to:

```text
20
```

This allows multiple requests to be processed concurrently.

---

# 17. Concurrent Threads

More threads generally mean more simultaneous work.

Conceptually:

```text
1 Thread
    ↓
Request
Request
Request
```

versus:

```text
20 Threads
    ↓
Request Request Request Request
Request Request Request Request
...
```

This can make fuzzing significantly faster.

However, the module specifically warns that the number of threads should take into account:

- Available computer processing power
    
- How many connections the target server allows
    

So don't blindly maximize the thread count.

---

# ⚠️ 18. Why Thread Count Matters

Too many concurrent requests can create unnecessary load.

```text
Low threads
   ↓
Slower scan
```

```text
Higher threads
   ↓
Faster scan
```

But:

```text
Excessive threads
   ↓
More local resource usage
   +
More connections
   +
Potential server-side impact
```

For authorized lab/pentest environments, choose a sensible value.

---

# 🔄 19. Depth First

ZAP provides different ways of iterating through payloads.

The first is:

> **Depth First**

Depth First means ZAP exhausts the payload list for one payload position before moving to another.

Conceptual example:

```text
User A
 ├── Password 1
 ├── Password 2
 ├── Password 3
 └── Password 4

User B
 ├── Password 1
 ├── Password 2
 ├── Password 3
 └── Password 4
```

The module summarizes it as trying all words for one position before moving to the next.

---

# 🌐 20. Breadth First

The other strategy is:

> **Breadth First**

This works differently.

It tries the same payload across all payload positions before moving to the next payload.

Conceptually:

```text
Password 1
 ├── User A
 ├── User B
 └── User C

Password 2
 ├── User A
 ├── User B
 └── User C
```

---

# 🆚 21. Depth First vs Breadth First

|Strategy|Behavior|
|---|---|
|**Depth First**|Exhaust payloads for one position before moving on|
|**Breadth First**|Apply one payload across positions before moving to the next|

### Easy memory trick:

> **Depth = finish one position deeply.**

> **Breadth = spread one payload across positions.**

The module's examples specifically use password/user combinations to illustrate this distinction.

---

# ▶️ 22. Starting the Fuzzer

Once everything has been configured:

```text
Fuzz Location
      ↓
Payload
      ↓
Processor
      ↓
Options
      ↓
Start Fuzzer
```

Click:

> **Start Fuzzer**

ZAP begins generating requests.

---

# 📊 23. Analyzing Results

The results table provides useful information such as:

- Task ID
    
- Message type
    
- HTTP response code
    
- Reason
    
- Round-trip time
    
- Response size
    
- State
    
- Payload
    

For the directory fuzzing example, the module recommends sorting by:

```text
Response code
```

because we're primarily interested in:

```text
200 OK
```

---

# 🎯 24. Finding `/skills/`

The example produces one interesting result:

```text
Payload:
skills
```

with:

```text
HTTP:
200 OK
```

Therefore the request becomes:

```http
GET /skills/ HTTP/1.1
```

and the server responds successfully.

This indicates that:

```text
/skills/
```

exists and is accessible in the exercise environment.

---

# 🔍 25. Verify Interesting Results

Finding a `200 OK` is useful, but the response should still be examined.

Click the result to inspect:

```text
Request
Response
Headers
Body
```

The example shows the `/skills/` response and confirms that the page is actually accessible.

---

# 📏 26. Response Size

HTTP status isn't the only useful indicator.

Another useful field is:

> **Size Resp. Body**

Suppose most responses are:

```text
246 bytes
```

but one response is:

```text
12,500 bytes
```

That difference may indicate that the server returned a substantially different page.

Conceptually:

```text
Normal response
246 bytes
246 bytes
246 bytes
246 bytes

Interesting:
12,500 bytes  ← investigate
```

This can be useful even when status codes are identical.

---

# ⏱️ 27. RTT — Round Trip Time

Another useful result field is:

> **RTT**

RTT measures the time associated with the request/response round trip.

A significant response-time difference can sometimes be important.

The module specifically mentions **time-based SQL injection** as an example where response timing can indicate behavior.

Conceptually:

```text
Normal:
~100 ms

Potentially interesting:
~5,000 ms
```

The timing difference would warrant investigation in an authorized test.

---

# 🧠 28. Important Result Indicators

Depending on the testing scenario, useful indicators can include:

```text
HTTP Status
     ↓
Response Size
     ↓
Response Time / RTT
     ↓
Response Content
     ↓
Headers
```

There is no universal "interesting" value.

For example:

|Test|Potentially useful indicator|
|---|---|
|Directory fuzzing|HTTP status|
|Hidden page discovery|Response size/content|
|Parameter testing|Response differences|
|Time-based testing|RTT|
|Authentication testing|Status/body differences|

---

# 🔥 29. ZAP Fuzzer vs Burp Intruder

This is one of the most important comparisons from this section.

### Burp Intruder

Strengths:

- More advanced payload functionality
    
- Extensive configuration
    
- Powerful request manipulation
    
- Advanced attack features
    

Major Community limitation:

```text
~1 request/second
```

### ZAP Fuzzer

Strengths:

- No paid-tier fuzzing throttle
    
- Built-in wordlists
    
- Payload processors
    
- Concurrent threads
    
- Depth/Breadth strategies
    
- Good integration with ZAP
    

Limitation:

> It is missing some of the features available in Burp Intruder.

---

# 📋 30. Side-by-Side Workflow

### Burp Intruder

```text
Proxy History
     ↓
Send to Intruder
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

### ZAP Fuzzer

```text
Proxy History
     ↓
Attack → Fuzz
     ↓
Fuzz Location
     ↓
Payloads
     ↓
Processors
     ↓
Options
     ↓
Start Fuzzer
     ↓
Results
```

Notice how closely the two workflows correspond.

---

# 📝 31. Quick Reference

|ZAP Fuzzer Component|Purpose|
|---|---|
|**Fuzz Location**|Where payloads are inserted|
|**Payloads**|Values to test|
|**File**|Load a wordlist from a file|
|**File Fuzzers**|Use built-in ZAP wordlists|
|**Numberzz**|Generate number sequences|
|**Processors**|Transform payloads|
|**URL Encode**|URL-encode payloads|
|**Base64**|Encode/decode Base64|
|**MD5/SHA**|Hash payloads|
|**Prefix**|Add text before payload|
|**Postfix**|Add text after payload|
|**Script**|Custom payload processing|
|**Threads**|Control concurrent scanning|
|**Depth First**|Exhaust one position before moving|
|**Breadth First**|Spread a payload across positions|
|**Response**|HTTP response code|
|**Size Resp. Body**|Response-size comparison|
|**RTT**|Response timing comparison|

---

# 🧠 32. Exam / Viva Questions

### Q1. What is ZAP Fuzzer?

ZAP's built-in tool for automatically fuzzing web requests and endpoints.

### Q2. What is the major advantage of ZAP Fuzzer over Burp Community Intruder?

ZAP Fuzzer does not impose the same paid-tier request-speed throttle as Burp Community Intruder.

### Q3. What are the four main ZAP Fuzzer configuration areas?

```text
Fuzz Location
Payloads
Processors
Options
```

### Q4. What is a Fuzz Location?

The location in the HTTP request where ZAP inserts the payload.

### Q5. What is File Fuzzers?

A payload type that allows ZAP to use its built-in wordlist databases.

### Q6. What is Numberzz?

A payload generator that creates number sequences with configurable increments.

### Q7. Name some ZAP payload processors.

```text
Base64 Encode/Decode
MD5
SHA-1/256/512
Prefix
Postfix
URL Encode/Decode
Script
```

### Q8. Why use URL Encode?

To ensure payloads containing special characters are correctly encoded before being sent.

### Q9. What is Depth First?

It exhausts the payload list for one payload position before moving to another.

### Q10. What is Breadth First?

It applies one payload across all payload positions before moving to the next payload.

### Q11. What does concurrent scanning threads control?

How many fuzzing operations can run concurrently.

### Q12. Why shouldn't you simply maximize thread count?

Because available system resources and the number of connections the target permits can limit practical concurrency.

### Q13. What can indicate an interesting fuzzing result?

Depending on the attack:

```text
HTTP response code
Response body size
RTT
Response content
```

### Q14. What did the example discover?

The `skills` payload produced a `200 OK`, indicating that `/skills/` existed and was accessible in the exercise environment.

---

# 🔥 33. Final Mental Model

```text
                 ZAP FUZZER
                     │
                     ▼
              Capture Request
                     │
                     ▼
              Fuzz Location
                     │
               [PAYLOAD]
                     │
                     ▼
                  Payload
                     │
                     ▼
                Processor
                     │
                     ▼
               URL Encoding
                     │
                     ▼
                 Options
                     │
              ┌──────┴──────┐
              │             │
         Depth First   Breadth First
              │             │
              └──────┬──────┘
                     ▼
              Concurrent Requests
                     │
                     ▼
                  Results
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Status       Size       RTT
          │          │          │
          └──────────┼──────────┘
                     ▼
              Investigate Hits
```

### ⭐ The biggest takeaway

> **ZAP Fuzzer performs the same fundamental job as Burp Intruder—placing payloads into selected request locations and automatically testing them—but ZAP's lack of Burp Community's severe speed throttle makes it particularly attractive for larger fuzzing tasks.**

And remember the four pillars:

**📍 Location → 📦 Payload → ⚙️ Processor → 🚀 Options → 📊 Results**