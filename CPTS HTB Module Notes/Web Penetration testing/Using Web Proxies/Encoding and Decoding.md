![Image](https://images.openai.com/static-rsc-4/bUJzc0dc881tmjqcH2KbhNBrWHFXm8Dn3emKdYJZVCmz-xLY_RFfJ4Sz2x1Uqv-KOuRwb83L8oRsWNnuDkDsr7-PQ3_jv2YQGop1wIvt-xdVyW_BL2in50IQ3LX0JCzqYQ6goN_EWXXF-u6ezE7Keur8UBrb3HaIS6q0c8MwStdwAZK1VMx6LaJ2yjeDseVd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-PMPi_NtUDMQChrqYE5KiNwJgK_AtAd2Gg3345BqLGKYjzWR35WukHOzfWRH1tvNBe_uLu2oWGq3LZT95uTeuQAd7-EGnFcEbXq5bMAtvzzMiuX85b9vjdRznfwzh8rVAef8e5yUeBK8Fnp3j1MTKtrc1tJ9locPoMvD9yAWSN-4KS3YUC9zYThswNjEydcz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/3jKXJtwghmjGH3HgwXkunXgo3BpBzTk_OeaGHWkRxIYE_fGoP_0bp2rS5pk-ls-2NnsmYb3UslnEcQrmM5TJQXNpLzaOj4LTo1FbaVJyOpML5tyDeA2wYcW86nmG6rLpSfewlUWru3visOBOMqqlO3JMaJW5T8iosZnQhqxoXOS2LMvN6hxbKwUfUP294Rsv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/9y4aPAziGjsDAHc6-sqgrtcj66FZdYMePguNnIfR2dcfvxZHfv4533zb3Wvva9uwMVSVJ6F4ksqCaXyLDbJTYy8nEGOdIS1lLot2Pri-Nh6DcXmS6JTMkPOjzpX5GyHCxLMeMcemidKvmfiu1UOvci3QL2Te22-4LNPoFcPcw8fNUCi1weXh55dZrRViTzt2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tWrnqI_n3Yj3-8V05hWI80-GZCnkwkiPGdXk_vDhpVbfLGaJxT_c2JIjtXDAwkaluZMoxjlpk6MldTtNEYDyE-N15o6m5nZ2992QA71Q_QAglnZOYAP0j3fJsz1AIRssFuYM0_dcWU5svMY2gRJbxtDDXhUgd6-LbkqnZeagdpBI0VS615HEKVqEyCIB0uBT?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gxeiN0nraCyibmtA3qcoqIXZ6vlYWd6B5UzjJDChsJ6Wllyg1sSqZMxNHC-P7Ss1GlIhwosKCeVWkyiGMxOVcRIx-IH2Jhs7GDfKULo3gDLV8o1a7bH_31hHSPYghbQ2DurokjlT9VALmIZ0y2EBQ4vEqX1y_-UFkYSsyVQKDNuEhwMiajZb_tREGf4ZyvFM?purpose=fullsize)

## 1. What Is Encoding and Decoding?

When creating and modifying custom HTTP requests, we frequently encounter data that has been **encoded**.

A web application may encode information before sending it, and the server may expect data in a particular encoding format.

Therefore, during web application testing, we often need to:

```text
Encoded Data
     ↓
   Decode
     ↓
Original Data
```

and sometimes:

```text
Modified Data
     ↓
   Encode
     ↓
Encoded Data
     ↓
Send to Server
```

Both **Burp Suite** and **ZAP** provide built-in tools for this.

---

# 2. Why Encoding Matters in HTTP Testing

When manually creating or modifying HTTP requests, characters can have special meanings.

For example:

```text
Space
&
#
```

may be interpreted specially by HTTP/web applications.

If data isn't encoded correctly, the server may:

- Parse it incorrectly
    
- Interpret it as multiple parameters
    
- Treat part of it as a fragment
    
- Return an error
    
- Process the input differently than intended
    

Therefore:

> **Understanding encoding is essential when modifying and repeating HTTP requests.**

---

# 3. URL Encoding

**URL encoding**, also called **percent encoding**, represents certain characters using `%` followed by hexadecimal values.

For example:

```text
space → %20
```

So:

```text
hello world
```

can become:

```text
hello%20world
```

---

# 4. Important Characters to Encode

The module specifically highlights:

### Space

A space can interfere with parsing if it isn't properly encoded.

```text
hello world
```

↓

```text
hello%20world
```

---

### `&`

The ampersand is commonly used as a **parameter separator**.

For example:

```text
user=arjun&role=user
```

Here:

```text
user=arjun
```

and:

```text
role=user
```

are separate parameters.

If you need a literal `&` inside a parameter value, it needs appropriate encoding.

---

### `#`

The `#` character has a special meaning in URLs because it introduces a **fragment identifier**.

For example:

```text
https://example.com/page#section
```

The fragment is:

```text
section
```

When sending literal special characters as data, correct encoding prevents unintended interpretation.

---

# 5. URL Encoding Example

Consider:

```text
name=hello world
```

The space should be encoded:

```text
name=hello%20world
```

Another example:

```text
value=a&b
```

If the ampersand is intended to be part of the value rather than a parameter separator, it needs encoding.

The important concept is:

> **Encoding makes special characters safe to transmit in their intended context.**

---

# 6. URL Encoding in Burp Repeater

In Burp Repeater, select the text you want to encode.

Then:

```text
Right-click
    ↓
Convert Selection
    ↓
URL
    ↓
URL-encode key characters
```

There is also a keyboard shortcut:

```text
CTRL + U
```

This can make encoding selected text very quick.

---

# 7. Burp — Encode While Typing

Burp can also provide URL encoding while you type.

You can enable the appropriate option through the context menu.

This can be useful when you're constructing requests containing many special characters.

Instead of:

```text
Write
 ↓
Select
 ↓
Encode
```

you can have Burp encode the data as you enter it.

---

# 8. ZAP URL Encoding

ZAP can handle URL encoding automatically when sending request data.

This means you may not always see the explicit encoding operation in the interface.

Conceptually:

```text
Your input
    ↓
ZAP
    ↓
URL encoding
    ↓
HTTP request
```

However, understanding the encoding is still important because you may need to inspect or manually construct encoded requests.

---

# 9. Different Types of URL Encoding

The module mentions other forms, including:

### URL Encoding

Standard percent encoding.

### Full URL Encoding

Encodes a broader set of characters.

### Unicode URL Encoding

Useful in situations where Unicode representations are relevant.

The correct choice depends on what the application expects.

---

# 🔓 10. Decoding

Encoding is only one side of the process.

During penetration testing, we will often encounter encoded values.

For example:

```text
eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=
```

At first glance, this doesn't tell us much.

We can recognize it as **Base64-like data**.

Decoding it gives:

```json
{"username":"guest", "is_admin":false}
```

Now the underlying data is understandable.

---

# 11. Why Decode Data?

Web applications commonly encode data in:

- Cookies
    
- Parameters
    
- Tokens
    
- API requests
    
- API responses
    
- Application state
    
- Configuration values
    

Decoding can reveal the actual underlying structure.

### Example

```text
Cookie
   ↓
Base64
   ↓
JSON
   ↓
Understand application data
```

---

# 12. Common Encodings You Should Know

Both Burp and ZAP support multiple encoding/decoding formats.

Important ones include:

|Encoding|Common Use|
|---|---|
|URL encoding|HTTP/URL data|
|HTML encoding|HTML content|
|Unicode|Text representation|
|Base64|Binary/text representation|
|ASCII Hex|Hexadecimal representation|

You should become comfortable recognizing these formats.

---

# 13. Burp Decoder

Burp provides a dedicated:

> **Decoder**

tab.

You can enter encoded data and select the appropriate decoding method.

For example:

```text
Encoded:
eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=
```

Then:

```text
Decode as
   ↓
Base64
```

Result:

```json
{"username":"guest", "is_admin":false}
```

---

# 14. Burp Inspector

Recent Burp versions also provide the **Inspector** feature.

Inspector can be accessed from areas such as:

- Burp Proxy
    
- Burp Repeater
    

It can help inspect and decode/encode data without always switching to the dedicated Decoder tab.

This can be especially convenient when examining a request.

---

# 15. ZAP Encoder/Decoder/Hash

ZAP provides:

> **Encoder/Decoder/Hash**

It can be accessed using:

```text
CTRL + E
```

It provides functionality for:

- Encoding
    
- Decoding
    
- Hashing
    

The **Decode** section can automatically decode data using supported formats.

---

# 16. Example — Base64 Cookie

The module gives this value:

```text
eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=
```

Decode it using Base64.

The result is:

```json
{"username":"guest", "is_admin":false}
```

We can now understand the structure:

```text
username → guest
is_admin → false
```

---

# 17. Understanding the Data Structure

The decoded value is JSON:

```json
{
    "username": "guest",
    "is_admin": false
}
```

It contains two properties:

```text
username
is_admin
```

and their values:

```text
guest
false
```

This is much easier to analyze than the Base64 representation.

---

# 18. Encoding After Modification

Decoding is often only half the process.

Suppose we decode:

```json
{
    "username": "guest",
    "is_admin": false
}
```

During an authorized security assessment, we might want to test whether the application improperly trusts client-controlled data.

We could construct:

```json
{
    "username": "admin",
    "is_admin": true
}
```

Then encode it using the **same original encoding**, Base64.

Conceptually:

```text
Base64
   ↑
Modified JSON
   ↑
Decoded Cookie
```

---

# 19. Why Re-Encode Using the Original Format?

Suppose the server expects:

```text
Base64(JSON)
```

If we send:

```json
{"username":"admin","is_admin":true}
```

directly when the server expects Base64, the server may not understand it.

Instead:

```text
Modified JSON
     ↓
Base64 encode
     ↓
Encoded value
     ↓
Place into request
     ↓
Send
```

This preserves the expected format.

---

# 20. Putting Encoded Data Back Into a Request

Once we have the new encoded value, we can insert it into the relevant request.

For example:

```http
GET /dashboard HTTP/1.1
Host: target.htb
Cookie: session=<encoded-value>
```

Then send it through:

- Burp Repeater
    
- ZAP Request Editor
    

and observe the application's response.

### Important security principle

The point of the test is to determine whether the server **cryptographically protects and/or validates security-sensitive client-side state**, not merely whether the value is encoded.

> **Encoding is not encryption.**

Base64 provides representation/encoding, not confidentiality or integrity.

---

# 21. Encoding vs Encryption

This distinction is extremely important.

### Encoding

Used to represent data in another format.

Example:

```text
guest
   ↓
Base64
   ↓
Z3Vlc3Q=
```

Anyone who knows the encoding can decode it.

### Encryption

Used to protect data using cryptographic algorithms and keys.

```text
Plaintext
   ↓
Encryption + Key
   ↓
Ciphertext
```

Without the appropriate key, recovering the plaintext should be computationally difficult.

### ⭐ Remember

> **Base64 is encoding, not encryption.**

---

# 22. Encoding vs Hashing

Hashing is another different concept.

```text
Encoding:
Data → Encoded Data → Decode → Original Data

Hashing:
Data → Hash
```

A cryptographic hash is designed to be one-way.

Examples include:

```text
SHA-256
SHA-512
```

ZAP's Encoder/Decoder/Hash tool provides hashing functionality alongside encoding and decoding.

---

# 23. ZAP Custom Tabs

ZAP allows you to create customized tabs in its Encoder/Decoder/Hash interface.

You can use:

> **Add New Tab**

and configure the encoders/decoders you frequently use.

This can make your workflow faster if you repeatedly work with certain formats.

For example, you might create a tab containing:

```text
URL Decode
Base64 Decode
URL Encode
Base64 Encode
```

---

# 24. Burp Decoder Chaining

Burp Decoder can also perform multiple encoding/decoding operations.

For example:

```text
Data
 ↓
Base64 Decode
 ↓
URL Decode
 ↓
Plaintext
```

or:

```text
Modified Data
 ↓
URL Encode
 ↓
Base64 Encode
 ↓
Final Request Value
```

This is useful when applications apply **multiple encoding layers**.

---

# 25. Multi-Layer Encoding

Sometimes data isn't encoded just once.

For example:

```text
Original
   ↓
JSON
   ↓
Base64
   ↓
URL Encoding
```

The final HTTP request contains the outermost representation.

You may need to reverse the process:

```text
URL Decode
   ↓
Base64 Decode
   ↓
JSON
   ↓
Original Data
```

### ⭐ Important

Always identify the **order of encoding**.

Decoding in the wrong order can produce confusing results.

---

# 26. Encoding in Penetration Testing

Encoding/decoding is useful for analyzing:

### Cookies

```text
Cookie → Decode → Understand
```

### Parameters

```text
Parameter → Decode → Modify → Encode
```

### API Data

```text
JSON / Base64 / URL encoding
```

### Tokens

Some tokens may contain encoded components that can be inspected.

### HTTP Requests

Special characters often need appropriate encoding.

---

# 27. Encoding Workflow With Repeater

A practical workflow looks like:

```text
Capture Request
      ↓
Send to Repeater
      ↓
Identify Encoded Value
      ↓
Copy Value
      ↓
Decode
      ↓
Understand Structure
      ↓
Modify
      ↓
Encode Using Original Format
      ↓
Insert Into Request
      ↓
Send
      ↓
Analyze Response
```

This combines several concepts we've already learned.

---

# 28. Example Workflow

Suppose a cookie contains:

```text
eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=
```

### Step 1 — Decode

```text
Base64 Decode
```

Result:

```json
{"username":"guest", "is_admin":false}
```

### Step 2 — Understand

```text
username = guest
is_admin = false
```

### Step 3 — During an authorized test, modify

```json
{"username":"admin", "is_admin":true}
```

### Step 4 — Encode

```text
Base64 Encode
```

### Step 5 — Put it back into the request

```http
Cookie: session=<new-value>
```

### Step 6 — Send

Use:

```text
Burp Repeater
```

or:

```text
ZAP Request Editor
```

### Step 7 — Analyze

Observe whether the server:

- Rejects the value
    
- Ignores the modification
    
- Returns an error
    
- Changes application behavior
    

---

# 29. Important Security Lesson ⭐

Finding something like:

```json
{"is_admin":false}
```

inside a Base64 cookie does **not automatically mean there is a vulnerability**.

The critical question is:

> **Does the server trust client-controlled data to make authorization decisions?**

If the server cryptographically signs or validates the session state, modifying the encoded value should not grant privileges.

If the server blindly trusts it, that may indicate a serious authorization/session-management weakness.

---

# 30. Common Encoding Formats — Quick Reference

|Format|Example|Main Purpose|
|---|---|---|
|URL|`%20`|URL/HTTP data|
|Base64|`SGVsbG8=`|Binary/text representation|
|HTML|`&lt;`|HTML content|
|Unicode|`\u0041`|Unicode representation|
|ASCII Hex|`48 65 6C 6C 6F`|Hex representation|

---

# 🧠 31. Exam / Viva Questions

### Q1. Why is URL encoding important?

It ensures special characters are represented correctly when transmitted as part of URLs or HTTP request data.

### Q2. Give examples of characters that may need URL encoding.

```text
Space
&
#
```

among others, depending on context.

### Q3. What shortcut can be used for URL encoding in Burp?

```text
CTRL + U
```

### Q4. Where is Burp's main encoding/decoding functionality?

**Decoder** tab.

### Q5. What is Burp Inspector?

A feature available in areas such as Proxy and Repeater that helps inspect and perform encoding/decoding operations.

### Q6. What is ZAP's equivalent tool?

**Encoder/Decoder/Hash**, accessible with:

```text
CTRL + E
```

### Q7. What is Base64?

A method of encoding binary/text data into a textual representation.

### Q8. Is Base64 encryption?

**No. Base64 is encoding, not encryption.**

### Q9. Why decode cookies?

To understand whether they contain structured or encoded application data that may be relevant during authorized testing.

### Q10. Why re-encode modified data?

Because the application may expect the data in its original encoding format.

### Q11. What is multi-layer encoding?

When data has been encoded more than once using different encoding mechanisms.

### Q12. What is the difference between encoding and hashing?

Encoding can generally be reversed with the appropriate decoder; cryptographic hashing is designed as a one-way transformation.

---

# 🔥 32. Final Mental Model

```text
                 ENCODED DATA
                      │
                      ▼
                  DECODE
                      │
                      ▼
               UNDERSTAND DATA
                      │
                      ▼
                 MODIFY DATA
                      │
                      ▼
                   ENCODE
                      │
                      ▼
              INSERT INTO REQUEST
                      │
                      ▼
                   REPEATER
                      │
                      ▼
                    SEND
                      │
                      ▼
                  RESPONSE
                      │
                      ▼
                   ANALYZE
```

### ⭐ The core workflow

**Identify → Decode → Understand → Modify → Re-encode → Insert → Send → Analyze**

And remember these three distinctions:

> **Encoding ≠ Encryption**

> **Encoding ≠ Hashing**

> **Client-side encoding/obfuscation does not automatically provide security.**

The real skill is being able to recognize **what format you're looking at, decode it correctly, understand the underlying data, modify it appropriately, and encode it back into the format the application expects.**