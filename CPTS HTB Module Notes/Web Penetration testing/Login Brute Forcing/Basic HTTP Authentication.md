![Image](https://images.openai.com/static-rsc-4/pdlaCRNJylp022gKefkA-av-gxoL3Y5-CZ4bFSnJ1Q6qFO9WYIt9pDBxkqswssJ_y2At1nCxLjCmAmA328A0gWjr8LflzFcNFyvJwBs243_AjL8lAGYhId_ZfprfAt5OgKhnYwGX1vYCAr-PoM0lbjXXHxllE-b8A1CokEfkE9rQGrIgHFgYrwNhDOPDGVV1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/M4IlbqCC2567MkOMA54YQsc_dYm-oU0WgGHrTiZ3XHpX68elM0pEQbDpHAGBhTxmiqWsbrIZD3UX3goiMEW3aGgx2V9Kj5iEAfHOrPd6IDd9EmO9Y3n8DX6ZhCtgDEa8M80veAUk1Fq9X9h_DDXwpigEvIAE_2RWfN_yEzYgIdcU_UTZya7I1ShKRV-8Sgyh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/54tsppobzU3rY6mOZ_HK1uo5sA2iZtvu45m2xbsXR55lJn94U-h2vf7w7z51HL6ohoexHV_C4ikchRM-3gQI2NMXaP1-sdjypGO63Pls-Fat3kfYrlAR2QOV0uiZ8NRkPthDBNx7F_AH3ZyIJcO4MOcxsm1rNCoTjzPCKUS1qOdXZvhAiamtRKpFxYrtfB0Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XzP6-AsAjuo_skWSYH246X3QzS4K_8foTg1PW-xY_KVMfsZtvFayPaLsHWZKD_1mrwVy5oY66iCURWV_ImT1CXMEWYwmtrllSSOgwSe3pB0Irc9v5lZ0VGuvp8-ltaUQmZp9ZwOwmWBqTZKMsX9cZeWSXS7riHL5LQ5bhiyhkXRKgONlkpmTyW47qq5QDUTV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vfLBGt_X7lHT9goew_tiDFRx26AudSFnfvWRP5zQY4JNac2LWqwPsYVECf0VuIUPOS06Zye4Mm8D36PP-CeFnZa0e3Gw6dwerBLFYpRubAwn4J4jVq9-i5V9Cch7L8jGwJ8umxuOLCoDLuIi0aWgv2yV5pFBeDwocLkhKgUZ5bTpnXi692RtuZAJU_Vn_jvm?purpose=fullsize)

## 1. What Is Basic HTTP Authentication?

**Basic HTTP Authentication**, commonly called **Basic Auth**, is a simple authentication mechanism used by web applications and web servers to restrict access to protected resources.

It is easy to implement, but it has important security limitations.

### Basic idea

```text
User requests protected resource
            ↓
       Server responds
       401 Unauthorized
            ↓
    Browser requests credentials
            ↓
    Username + Password
            ↓
       Base64 encoding
            ↓
 Authorization: Basic <credentials>
            ↓
        Server verifies
            ↓
       Access / Deny
```

---

# 2. How Basic Auth Works

Basic Auth follows a simple **challenge-response flow**.

Suppose a user requests:

```text
/protected_resource
```

The server determines that authentication is required.

It responds with:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic
```

The `401 Unauthorized` status tells the client that authentication is required.

The `WWW-Authenticate` header tells the browser which authentication scheme should be used.

---

# 3. The `401 Unauthorized` Response

The server might respond conceptually with:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic
```

### Important components

### `401 Unauthorized`

Means:

> The request does not contain valid authentication credentials for the protected resource.

### `WWW-Authenticate`

Indicates the authentication mechanism the server expects.

For Basic Auth, it can identify the **Basic** authentication scheme.

---

# 4. User Provides Credentials

The browser asks the user for:

```text
Username
Password
```

Suppose the user enters:

```text
Username: alice
Password: secret123
```

Basic Auth combines them using a colon:

```text
alice:secret123
```

### Important ⭐

The format is:

```text
username:password
```

The colon separates the username and password.

---

# 5. Base64 Encoding

The resulting string is then **Base64 encoded**.

For example:

```text
alice:secret123
```

becomes:

```text
YWxpY2U6c2VjcmV0MTIz
```

The browser then sends it in the `Authorization` header.

---

# 6. Authorization Header

The request looks like:

```http
GET /protected_resource HTTP/1.1
Host: www.example.com
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```

The important part is:

```text
Authorization: Basic <encoded_credentials>
```

So the general format is:

```text
Authorization: Basic BASE64(username:password)
```

---

# 7. ⚠️ Base64 Is NOT Encryption

This is one of the **most important things to remember**.

Base64 is an **encoding**, not encryption.

For example:

```text
alice:secret123
        ↓
     Base64
        ↓
YWxpY2U6c2VjcmV0MTIz
```

Anyone who can obtain the Base64 value can decode it.

### Therefore:

```text
Base64
   ≠
Encryption
```

Basic Auth should therefore generally be used over **HTTPS/TLS**, so the credentials are protected while traveling over the network.

---

# 8. How the Server Processes the Header

The complete process is:

```text
Authorization Header
        ↓
Basic YWxpY2U6c2VjcmV0MTIz
        ↓
Remove "Basic "
        ↓
Base64 decode
        ↓
alice:secret123
        ↓
Separate username/password
        ↓
Verify credentials
        ↓
      ┌───┴───┐
      ↓       ↓
   Correct  Incorrect
      ↓       ↓
   Access    401
```

---

# 9. Complete Basic Auth Flow

![Image](https://images.openai.com/static-rsc-4/nD0WLOEUq4E3ZIt04bukGxTZPuJ5v_CYbkkwJ7fm8C8m3XO-WrkCNzvJlyuarnAa4Rs5BZCfpcog9UfyCMTrf_2qXg4StIWCMgUPsOfe1C5Qs7H3XlhnG5d3RpB7mgui-NNvgCNVopHWsrOhfWxPLRqJ8yOW8g0OIfxBF1SecA5XHNSW6YDmHB5HKIzVRMes?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/54tsppobzU3rY6mOZ_HK1uo5sA2iZtvu45m2xbsXR55lJn94U-h2vf7w7z51HL6ohoexHV_C4ikchRM-3gQI2NMXaP1-sdjypGO63Pls-Fat3kfYrlAR2QOV0uiZ8NRkPthDBNx7F_AH3ZyIJcO4MOcxsm1rNCoTjzPCKUS1qOdXZvhAiamtRKpFxYrtfB0Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/M4IlbqCC2567MkOMA54YQsc_dYm-oU0WgGHrTiZ3XHpX68elM0pEQbDpHAGBhTxmiqWsbrIZD3UX3goiMEW3aGgx2V9Kj5iEAfHOrPd6IDd9EmO9Y3n8DX6ZhCtgDEa8M80veAUk1Fq9X9h_DDXwpigEvIAE_2RWfN_yEzYgIdcU_UTZya7I1ShKRV-8Sgyh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XzP6-AsAjuo_skWSYH246X3QzS4K_8foTg1PW-xY_KVMfsZtvFayPaLsHWZKD_1mrwVy5oY66iCURWV_ImT1CXMEWYwmtrllSSOgwSe3pB0Irc9v5lZ0VGuvp8-ltaUQmZp9ZwOwmWBqTZKMsX9cZeWSXS7riHL5LQ5bhiyhkXRKgONlkpmTyW47qq5QDUTV?purpose=fullsize)

### Step 1

Client requests a protected resource:

```http
GET /protected_resource HTTP/1.1
Host: www.example.com
```

### Step 2

Server responds:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic
```

### Step 3

Browser asks the user for credentials.

### Step 4

User provides:

```text
username: alice
password: secret123
```

### Step 5

Browser creates:

```text
alice:secret123
```

### Step 6

It Base64-encodes the value:

```text
YWxpY2U6c2VjcmV0MTIz
```

### Step 7

Browser sends:

```http
Authorization: Basic YWxpY2U6c2VjcmV0MTIz
```

### Step 8

Server decodes and verifies the credentials.

### Step 9

If correct:

```text
Access granted
```

If incorrect:

```text
401 Unauthorized
```

---

# 10. Why Basic Auth Can Be Targeted by Brute Force

Basic Auth has a relatively simple authentication mechanism.

A tester can repeatedly submit different credentials:

```text
username: basic-auth-user
password: password1
        ↓
Failure

username: basic-auth-user
password: password2
        ↓
Failure

username: basic-auth-user
password: password3
        ↓
Success
```

If there are no effective protections such as:

- Rate limiting
    
- Account lockout
    
- IP restrictions
    
- Strong passwords
    
- MFA
    

then repeated password attempts may be possible.

---

# 11. HTB Basic Auth Lab

The provided exercise is an **authorized Hack The Box lab**.

The target uses Basic HTTP Authentication.

The username is already known:

```text
basic-auth-user
```

Therefore, there is no need to guess the username.

The task becomes:

```text
Known username
      +
Password wordlist
      ↓
Find valid password
```

---

# 12. Why Knowing the Username Helps

Suppose both username and password are unknown.

You might have:

```text
Usernames × Passwords
```

But if the username is known:

```text
Username = basic-auth-user
Password = ?
```

The search space is smaller.

This connects directly to your earlier notes about **username enumeration** and **default usernames**.

---

# 13. Downloading the Password List

The lab uses:

```bash
curl -s -O https://raw.githubusercontent.com/danielmiessler/SecLists/56a39ab9a70a89b56d66dad8bdffb887fba1260e/Passwords/2023-200_most_used_passwords.txt
```

The file contains a collection of commonly used passwords.

### `curl`

`curl` is a command-line tool for transferring data over network protocols such as HTTP/HTTPS.

### Options

```text
-s
```

means **silent mode**.

```text
-O
```

tells `curl` to save the downloaded content using the remote filename.

So:

```text
curl
 ↓
Download wordlist
 ↓
Save locally
```

---

# 14. Hydra Command

The lab then uses:

```bash
hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 127.0.0.1 http-get / -s 81
```

Let's break this down carefully.

---

# 15. `-l basic-auth-user`

```text
-l basic-auth-user
```

Specifies the known username.

Therefore:

```text
Username = basic-auth-user
```

Because only one username is needed, the lowercase `-l` option is used instead of `-L`.

---

# 16. `-P 2023-200_most_used_passwords.txt`

```text
-P 2023-200_most_used_passwords.txt
```

Tells Hydra to use that file as the password wordlist.

Conceptually:

```text
2023-200_most_used_passwords.txt

password1
password2
password3
...
```

Hydra tests the candidates against the target.

---

# 17. `127.0.0.1`

This is the target IP address.

```text
127.0.0.1
```

is the **localhost/loopback address**.

In this lab, the target application is running on the local machine/environment.

---

# 18. `http-get`

This tells Hydra to use its **HTTP GET authentication module**.

The lab specifically uses Basic HTTP Authentication.

So conceptually:

```text
Hydra
 ↓
http-get module
 ↓
HTTP Basic Authentication
 ↓
Target
```

---

# 19. `/`

The `/` specifies the root path being tested.

```text
/ 
```

So the target resource is essentially:

```text
http://127.0.0.1:81/
```

---

# 20. `-s 81`

This specifies the target port:

```text
-s 81
```

Normally HTTP commonly uses port **80**, but this HTB instance uses:

```text
81
```

Therefore Hydra must be explicitly told to connect to port 81.

---

# 21. Complete Command Breakdown

```bash
hydra \
  -l basic-auth-user \
  -P 2023-200_most_used_passwords.txt \
  127.0.0.1 \
  http-get / \
  -s 81
```

Think of it as:

```text
Username
    ↓
basic-auth-user

Password list
    ↓
2023-200_most_used_passwords.txt

Target
    ↓
127.0.0.1

Authentication type
    ↓
http-get

Resource
    ↓
/

Port
    ↓
81
```

---

# 22. Understanding Hydra's Output

The output contains:

```text
[DATA] max 16 tasks per 1 server, overall 16 tasks, 200 login tries
```

This tells you Hydra has:

- 1 username
    
- 200 password candidates
    
- Up to 16 parallel tasks in the displayed configuration
    

---

# 23. The Attack Target

The output:

```text
[DATA] attacking http-get://127.0.0.1:81/
```

confirms:

```text
Protocol/module → HTTP GET
Host → 127.0.0.1
Port → 81
Path → /
```

---

# 24. Successful Result

The important line is:

```text
1 of 1 target successfully completed, 1 valid password found
```

This means Hydra found a credential combination that the target accepted.

The lab then allows you to use the discovered password to authenticate and retrieve the flag.

---

# 25. Why This Attack Is Efficient

The lab provides several pieces of useful information:

```text
Known username
       +
Only 200 password candidates
       +
Basic Auth
       +
No demonstrated lockout/rate limit
       ↓
Small testing space
```

This is much easier than a theoretical exhaustive brute-force attack.

It is essentially a **dictionary attack automated through Hydra**.

---

# 26. Connecting This to Previous Topics

You've now seen how the concepts fit together.

```text
Password Security
       ↓
Understand weak passwords
       ↓
Dictionary Attacks
       ↓
Use wordlists
       ↓
Hybrid Attacks
       ↓
Modify likely passwords
       ↓
Hydra
       ↓
Automate authentication attempts
       ↓
Basic HTTP Auth
       ↓
Use http-get module
```

This is the practical side of the theory you've been studying.

---

# 27. Basic Auth vs HTTP Form Authentication

Don't confuse these two.

## Basic Auth

Credentials are sent through:

```http
Authorization: Basic <Base64>
```

Hydra can use:

```text
http-get
```

for the lab's Basic Auth scenario.

---

## HTTP Form Authentication

A website might have:

```text
Username: [________]
Password: [________]
        [ Login ]
```

The browser sends form data, often through POST.

Hydra can use:

```text
http-post-form
```

with parameters describing the form.

### Remember

```text
Basic Auth
→ Authorization header

Web login form
→ Form parameters
```

---

# 28. Security Weaknesses of Basic Auth

Basic Auth itself isn't inherently broken, but **using it without proper transport security and additional controls can be risky**.

### Main concerns

#### Base64 isn't encryption

Credentials can be decoded.

#### HTTPS is important

TLS protects credentials while they're transmitted.

#### Password strength matters

Weak passwords can be guessed.

#### Rate limiting matters

Without throttling, automated attempts may be easier.

#### MFA can provide additional protection

Password compromise alone then isn't necessarily enough for access.

---

# 29. Defensive View 🛡️

A secure Basic Auth deployment should consider:

```text
HTTPS/TLS
    +
Strong unique passwords
    +
Rate limiting
    +
Monitoring
    +
MFA where appropriate
    +
Secure account management
```

A server should also avoid exposing unnecessary authentication endpoints and should monitor repeated failed authentication attempts.

---

# 30. ⭐ Important Terms

|Term|Meaning|
|---|---|
|**Basic Auth**|HTTP authentication mechanism using username/password credentials|
|**401**|Authentication is required/credentials aren't accepted|
|**WWW-Authenticate**|Server header describing the authentication scheme|
|**Authorization**|Request header carrying authentication credentials|
|**Base64**|Encoding used to represent `username:password`|
|**HTTPS**|Encrypts traffic using TLS|
|**Hydra**|Automated network login/password-testing tool|
|**`http-get`**|Hydra module for HTTP GET authentication|
|**`-l`**|Single username|
|**`-P`**|Password wordlist|
|**`-s`**|Custom port|

---

# 31. 🧠 Exam / HTB Revision Questions

### What is Basic HTTP Authentication?

A simple HTTP authentication mechanism where the client sends a Base64-encoded `username:password` value in the `Authorization` header.

### What does a `401 Unauthorized` response indicate?

The requested resource requires authentication or the supplied credentials aren't valid.

### What is the purpose of `WWW-Authenticate`?

It tells the client which authentication scheme the server expects.

### Is Base64 encryption?

**No. Base64 is encoding, not encryption.**

### What does the Authorization header look like?

```http
Authorization: Basic <encoded_credentials>
```

### What does `-l` mean in Hydra?

A single username.

### What does `-P` mean?

A password wordlist.

### What does `-s 81` do?

Specifies port 81 instead of the service's default port.

### Why use `http-get` here?

Because the HTB target is using HTTP Basic Authentication over the HTTP GET resource.

---

# 🎯 Final Mental Model

```text
                 BASIC HTTP AUTH
                       │
                       ↓
               Request resource
                       │
                       ↓
               401 Unauthorized
                       │
                       ↓
             WWW-Authenticate: Basic
                       │
                       ↓
                User credentials
                       │
                       ↓
             username:password
                       │
                       ↓
                   Base64
                       │
                       ↓
         Authorization: Basic <...>
                       │
                       ↓
                Server verifies
                       │
                ┌──────┴──────┐
                ↓             ↓
             Correct       Incorrect
                ↓             ↓
             Access          401
```

### 🔑 The one sentence to remember:

> **Basic HTTP Authentication sends a Base64-encoded `username:password` in the `Authorization` header, and in an authorized HTB lab, Hydra's `http-get` module can automate testing a password wordlist against that authentication mechanism.**

**HTB connection:** You now have the chain **password mathematics → dictionary attacks → hybrid attacks → Hydra → Basic HTTP Authentication**, which is exactly how the module is building your practical understanding.