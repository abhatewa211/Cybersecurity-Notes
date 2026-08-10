## 1. Overview

This section focuses on understanding a specific FTP vulnerability through a relatively simple attack example.

The vulnerability discussed is:

> **CoreFTP before build 727 — CVE-2022-22836**

The vulnerability involves improper processing of an HTTP `PUT` request and can result in:

- **Authenticated directory/path traversal**
    
- **Arbitrary file write**
    

The important consequence is that an authenticated user can potentially write files **outside the directory to which the service is supposed to have access**.

---

# 2. 🧠 Vulnerability at a Glance

```text
CoreFTP
   │
   ▼
Before build 727
   │
   ▼
CVE-2022-22836
   │
   ▼
Improper HTTP PUT processing
   │
   ▼
Directory / Path Traversal
   │
   ▼
Restricted directory bypass
   │
   ▼
Arbitrary File Write
```

### ⭐ Main idea

The application is supposed to restrict an authenticated user to a particular directory.

Conceptually:

```text
Allowed Directory
       │
       ├── file1
       ├── file2
       └── file3
```

But directory traversal can attempt to escape that location:

```text
Allowed Directory
       │
       ▼
../../../../
       │
       ▼
Outside Allowed Directory
```

The resulting arbitrary file write is the key impact described by the source.

---

# 3. 🔥 Important Terms

Before understanding the attack, memorize these terms:

|Term|Meaning|
|---|---|
|**CoreFTP**|FTP service/software discussed in the example|
|**CVE-2022-22836**|Identifier assigned to this vulnerability|
|**HTTP PUT**|HTTP request method used to write/replace content at a specified resource|
|**Path Traversal**|Manipulation of a path to access a location outside the intended directory|
|**Authenticated**|The attacker/user has valid authentication credentials|
|**Arbitrary File Write**|Ability to write chosen content to a file/location outside the intended restriction|
|**Directory Restriction**|Mechanism intended to keep a user inside an authorized directory|

---

# 4. 📁 Normal File Upload vs Vulnerable Behavior

The source explains that the FTP service normally uses an HTTP:

```text
POST
```

request to upload files.

However, CoreFTP also allows:

```text
PUT
```

which can be abused to write content to files.

### Normal concept

```text
Authenticated User
        │
        ▼
Allowed Directory
        │
        ▼
Upload File
```

### Vulnerable concept

```text
Authenticated User
        │
        ▼
HTTP PUT
        │
        ▼
Path Traversal
 ../../../../
        │
        ▼
Outside Allowed Directory
        │
        ▼
Write File
```

---

# 5. 🖼️ Attack Concept

```text
             AUTHENTICATED USER
                     │
                     ▼
              HTTP PUT Request
                     │
                     ▼
             User-Controlled Path
                     │
                     ▼
              ../../../../
                     │
                     ▼
          ┌────────────────────┐
          │ Directory Traversal│
          └─────────┬──────────┘
                    │
                    ▼
          Restricted Path Bypass
                    │
                    ▼
             Arbitrary File
                 Write
                    │
                    ▼
             Target System
```

The vulnerability is therefore a combination of:

```text
Path Traversal
      +
Improper File Write Controls
      =
Arbitrary File Write
```

---

# 6. 🧪 CoreFTP Exploitation Example

The source provides the following proof-of-concept command:

```bash
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

This is presented in the source as a straightforward `cURL`-based PoC.

### ⚠️ Important

This should only be used against a system you are **authorized to assess**, such as your own lab or an approved penetration-testing engagement.

---

# 7. 🔍 Breaking Down the Command

Let's understand each important component.

## `curl`

```text
curl
```

is the client used to send the HTTP request.

---

## `-k`

```text
-k
```

Tells `curl` to allow insecure TLS connections, including cases where certificate validation would otherwise fail.

---

## `-X PUT`

```text
-X PUT
```

Explicitly specifies the HTTP request method:

```text
PUT
```

The source identifies this as the important request type used to write content.

---

## `-H "Host: <IP>"`

```text
-H "Host: <IP>"
```

Specifies the HTTP `Host` header.

Conceptually:

```text
HTTP Request
     │
     ├── Method → PUT
     ├── Host → Target IP
     └── Path → Traversal Path
```

---

# 8. 🔐 `--basic -u`

The command contains:

```text
--basic
```

and:

```text
-u <username>:<password>
```

This supplies **Basic Authentication** credentials.

The source explicitly says that it will skip the explanation of the Basic Auth process and move directly to the first part of the exploit.

So the important point for this section is simply:

```text
Valid Credentials
       │
       ▼
Authenticated Request
```

This vulnerability is described as an **authenticated** directory/path traversal issue.

---

# 9. 📦 `--data-binary`

The command contains:

```text
--data-binary "PoC."
```

This specifies the content that will be sent in the request body.

In the example:

```text
Content = PoC.
```

Conceptually:

```text
PUT Request
     │
     ├── Path → whoops
     │
     └── Content → PoC.
```

---

# 10. 🛣️ `--path-as-is`

The command also contains:

```text
--path-as-is
```

This is important because the request contains traversal sequences such as:

```text
../../../../
```

The source uses this to ensure the path is sent as specified rather than being normalized by the client.

Conceptually:

```text
Specified Path
     │
     ▼
../../../../../../whoops
     │
     ▼
Sent as intended
```

---

# 11. 📍 The Path Traversal

The important portion of the URL is:

```text
../../../../../../whoops
```

The:

```text
../
```

sequence represents moving up one directory level in a filesystem path.

Repeated traversal:

```text
../
../
../
../
```

can move progressively higher in the directory hierarchy.

Conceptually:

```text
/authorized/
     │
     └── uploads/
          │
          └── user/
               │
               └── file
```

Traversal can conceptually move:

```text
user/
 ↑
uploads/
 ↑
authorized/
 ↑
parent/
 ↑
parent/
```

The vulnerability occurs because the application fails to properly prevent the path from escaping its intended directory.

---

# 12. 🧠 The Core Vulnerability

The source summarizes the vulnerability conceptually as:

> The actual process misinterprets the user's input of the path.

This causes:

```text
User Input
    │
    ▼
Path Processing
    │
    ▼
Incorrect Interpretation
    │
    ▼
Restricted Folder Bypass
```

The result is that the application's write permissions aren't properly constrained to the authorized folder.

---

# 13. 🔥 Two-Part Attack

One of the **most important things to understand** is that the source divides the attack into **two parts**.

### Part 1

# Directory Traversal

The restriction is bypassed.

### Part 2

# Arbitrary File Write

The attacker-controlled content is written to the selected file.

So:

```text
PART 1
Directory Traversal
        ↓
Escape restriction
        ↓
PART 2
Arbitrary File Write
        ↓
Write chosen content
```

---

# 14. 🧩 Part 1 — Directory Traversal

The source maps the first stage to the four categories from the **Concept of Attacks** model.

Remember:

```text
Source
  ↓
Process
  ↓
Privileges
  ↓
Destination
```

---

# 15. 📥 Step 1 — Source

The user specifies:

- HTTP request type
    
- File content
    
- Path
    
- Escape characters
    

The source category is:

# `Source`

Conceptually:

```text
User
 │
 ├── HTTP method
 ├── File content
 └── Path
        │
        └── ../../../../
```

The important idea is:

> **The attacker-controlled request becomes the Source of the information being processed.**

---

# 16. ⚙️ Step 2 — Process

The changed HTTP request, file contents, and path are passed to the application.

The application then processes the supplied information.

Category:

# `Process`

```text
HTTP Request
     │
     ├── Method
     ├── Path
     └── Content
          │
          ▼
      Application
          │
          ▼
        Process
```

---

# 17. 🔐 Step 3 — Privileges

The application checks whether the authenticated user is authorized to access the specified path.

Normally:

```text
User
 │
 ▼
Allowed Directory
 │
 ▼
Permission Check
```

But because of the directory traversal:

```text
Allowed Directory
       │
       ▼
../../../../
       │
       ▼
Outside Directory
```

The restriction is bypassed.

Category:

# `Privileges`

The important point is:

> The application believes it is enforcing directory restrictions, but the manipulated path escapes the restricted area.

---

# 18. 🎯 Step 4 — Destination

The destination is another process responsible for writing the supplied contents onto the local system.

Category:

# `Destination`

Conceptually:

```text
User Input
    ↓
Application
    ↓
Path Validation
    ↓
Traversal
    ↓
File-Writing Process
```

At this point, the directory restriction has effectively been bypassed.

---

# 19. 🖼️ Directory Traversal Attack Flow

```text
                 SOURCE
                   │
                   ▼
        User-Controlled HTTP Path
                   │
                   │ ../../../../
                   ▼
                PROCESS
                   │
                   ▼
          Path Processing Logic
                   │
                   ▼
              PRIVILEGES
                   │
                   ▼
        Directory Restriction
             is bypassed
                   │
                   ▼
              DESTINATION
                   │
                   ▼
          File-Writing Process
```

---

# 20. 🔄 Why Does the Cycle Start Again?

The source says:

> Up to this point, we have bypassed the constraints imposed by the application.

Now the attack moves to the second part.

The attacker has successfully reached a location outside the intended directory.

But the objective is to actually **write content** there.

Therefore, the process starts again using the **Source → Process → Privileges → Destination** model.

---

# 21. ✍️ Part 2 — Arbitrary File Write

Now we analyze the second stage.

# Arbitrary File Write

The attacker wants to create a file such as:

```text
whoops
```

containing:

```text
PoC.
```

---

# 22. 📥 Step 5 — Source

The same user-supplied information is used again.

The source includes:

```text
Filename:
whoops
```

and:

```text
Content:
PoC.
```

Category:

# `Source`

Conceptually:

```text
User
 │
 ├── Filename → whoops
 │
 └── Content  → PoC.
```

---

# 23. ⚙️ Step 6 — Process

The process receives:

```text
Filename
+
Content
```

and performs the file-writing operation.

Category:

# `Process`

Conceptually:

```text
whoops
  +
PoC.
  │
  ▼
File-Writing Process
```

---

# 24. 🔐 Step 7 — Privileges

Because the directory traversal has already bypassed the original restrictions, the service approves the write to the specified location.

Category:

# `Privileges`

The key relationship is:

```text
Directory Traversal
       ↓
Restriction Bypass
       ↓
Unauthorized Location
       ↓
File Write
```

---

# 25. 🎯 Step 8 — Destination

The destination is now the file on the local system.

The source uses:

```text
Filename = whoops
Content = PoC.
```

So:

```text
DESTINATION
     │
     ▼
C:\whoops
```

The result is a file containing:

```text
PoC.
```

---

# 26. 🖼️ Complete Two-Stage Attack

```text
             STAGE 1
        DIRECTORY TRAVERSAL
                 │
                 ▼
             SOURCE
                 │
                 ▼
       User-controlled path
          ../../../../
                 │
                 ▼
             PROCESS
                 │
                 ▼
        Path interpretation
                 │
                 ▼
           PRIVILEGES
                 │
                 ▼
       Directory restriction
             bypassed
                 │
                 ▼
           DESTINATION
                 │
                 ▼
        File-writing process
                 │
                 │
                 ▼
             STAGE 2
       ARBITRARY FILE WRITE
                 │
                 ▼
             SOURCE
                 │
           ┌─────┴─────┐
           ▼           ▼
       Filename      Content
       "whoops"       "PoC."
           │           │
           └─────┬─────┘
                 ▼
             PROCESS
                 │
                 ▼
          Write file
                 │
                 ▼
           PRIVILEGES
                 │
                 ▼
       Restrictions already
             bypassed
                 │
                 ▼
           DESTINATION
                 │
                 ▼
           C:\whoops
```

---

# 27. 🖥️ Target System Result

The source demonstrates the resulting file on the target:

```cmd
C:\> type C:\whoops

PoC.
```

This confirms that the content:

```text
PoC.
```

was written into:

```text
C:\whoops
```

---

# 28. 🔥 Complete Attack Chain

The whole concept can be remembered as:

```text
Authenticated User
        │
        ▼
HTTP PUT
        │
        ▼
User-Controlled Path
        │
        ▼
../../../../
        │
        ▼
Directory Traversal
        │
        ▼
Restricted Directory Bypass
        │
        ▼
Arbitrary File Write
        │
        ▼
Chosen Filename
        │
        ▼
Chosen Content
        │
        ▼
File Created Outside
Authorized Directory
```

---

# 29. 🧠 Mapping the Attack to the Concept of Attacks

This is probably the **most important exam/HTB concept** from this section.

## Stage 1 — Directory Traversal

|Step|Category|Concept|
|---|---|---|
|**1**|**Source**|User specifies HTTP request, content and traversal path|
|**2**|**Process**|Application receives and processes the input|
|**3**|**Privileges**|Directory restrictions are bypassed|
|**4**|**Destination**|File-writing process receives the request|

---

## Stage 2 — Arbitrary File Write

|Step|Category|Concept|
|---|---|---|
|**5**|**Source**|Filename and content supplied by user|
|**6**|**Process**|Process writes the supplied content|
|**7**|**Privileges**|Previously imposed restrictions have been bypassed|
|**8**|**Destination**|Selected local file is created/written|

---

# 30. ⭐ The Pattern You Should Memorize

```text
       DIRECTORY TRAVERSAL
              │
              ▼
          SOURCE
              ↓
          PROCESS
              ↓
         PRIVILEGES
              ↓
         DESTINATION
              │
              ▼
       RESTRICTION BYPASS
              │
              ▼
       ARBITRARY FILE WRITE
              │
              ▼
          SOURCE
              ↓
          PROCESS
              ↓
         PRIVILEGES
              ↓
         DESTINATION
```

This directly connects the vulnerability to the **Concept of Attacks** framework you studied earlier.

---

# 31. 🔍 What Actually Goes Wrong?

The important failure isn't simply:

> “CoreFTP supports HTTP PUT.”

The important issue is the combination of:

```text
HTTP PUT
+
User-controlled path
+
Improper path processing
+
Insufficient directory restriction
+
File-writing capability
```

which results in:

```text
Arbitrary File Write
```

---

# 32. 🛡️ Security Impact

The source specifically establishes that the vulnerability allows writing files outside the directory to which the service has access.

Potential impact depends on:

- What directories the service can access
    
- What privileges the service has
    
- What file types can be written
    
- Whether another service processes the created file
    
- Whether the written file can subsequently be executed or interpreted
    

The supplied material specifically demonstrates **arbitrary file creation/write** and does not itself establish every possible post-exploitation consequence.

---

# 33. 🔗 Connection With Your Previous “Concept of Attacks” Notes

This vulnerability is a perfect practical example of:

# `SOURCE → PROCESS → PRIVILEGES → DESTINATION`

Compare the generic model:

```text
Source
  ↓
Information enters
  ↓
Process
  ↓
Information is processed
  ↓
Privileges
  ↓
Permissions determine what can happen
  ↓
Destination
  ↓
Result goes somewhere
```

with CoreFTP:

```text
User-Controlled HTTP Request
          ↓
     CoreFTP Process
          ↓
Directory restriction bypass
          ↓
    File-writing process
          ↓
    Arbitrary file written
```

Then the cycle repeats for the actual file-writing operation.

---

# 34. 🧠 Important Learning Point

The source is trying to teach something bigger than just one CVE.

The goal is to recognize the **attack pattern**.

Instead of memorizing:

> “CVE-2022-22836 uses `../../../../`.”

understand:

```text
User Input
    ↓
Input Manipulation
    ↓
Application Misinterprets Input
    ↓
Security Restriction Bypassed
    ↓
Unauthorized Operation
```

That pattern can help you understand other vulnerabilities too.

---

# 35. 🎯 Exam / Viva Questions

### Q1. What is CVE-2022-22836?

It is a vulnerability affecting **CoreFTP before build 727**, involving improper processing of HTTP `PUT` requests and resulting in authenticated directory/path traversal and arbitrary file write.

---

### Q2. What type of vulnerability is CVE-2022-22836?

The source identifies:

```text
Authenticated Directory / Path Traversal
+
Arbitrary File Write
```

---

### Q3. What HTTP method is important in this vulnerability?

```text
PUT
```

---

### Q4. What does the vulnerability allow?

It can allow an authenticated user to write files **outside the directory to which the service is supposed to have access**.

---

### Q5. What is directory traversal?

A technique involving manipulation of a filesystem path to move outside the intended directory, commonly represented by:

```text
../
```

---

### Q6. What is arbitrary file write?

The ability to write attacker-controlled content to a chosen file/location beyond the intended restrictions.

---

### Q7. What tool is used in the supplied PoC?

```text
cURL
```

---

### Q8. What option specifies the HTTP method in the PoC?

```text
-X PUT
```

---

### Q9. What option supplies Basic Authentication?

```text
--basic -u <username>:<password>
```

---

### Q10. What option supplies the file contents?

```text
--data-binary
```

---

### Q11. Why is `--path-as-is` important in the supplied PoC?

It allows the specified path, including traversal sequences, to be sent as written rather than normalized by the client.

---

### Q12. What is the first stage of the attack?

```text
Directory Traversal
```

---

### Q13. What is the second stage?

```text
Arbitrary File Write
```

---

### Q14. What are the four Concept of Attacks categories?

```text
Source
Process
Privileges
Destination
```

---

### Q15. What was the destination in the final example?

The local file:

```text
C:\whoops
```

containing:

```text
PoC.
```

---

# 36. 📝 Quick Command Reference

### Supplied PoC

```bash
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

### Important options

```text
curl
    → HTTP client

-k
    → Allow insecure TLS/certificate validation

-X PUT
    → Use HTTP PUT

-H
    → Set HTTP header

--basic
    → Use Basic Authentication

-u
    → Supply username/password

--data-binary
    → Send specified content

--path-as-is
    → Preserve supplied path
```

---

# 🔥 37. One-Minute Revision

```text
                CoreFTP
                   │
        Before build 727
                   │
                   ▼
             CVE-2022-22836
                   │
                   ▼
         Improper HTTP PUT
              processing
                   │
                   ▼
        Directory Traversal
                   │
                   ▼
       Escape authorized folder
                   │
                   ▼
       Arbitrary File Write
                   │
                   ▼
          Chosen filename
                   +
          Chosen content
                   │
                   ▼
             Target File
```

### Attack model:

```text
STAGE 1

Source
  ↓
Process
  ↓
Privileges
  ↓
Destination

Directory restriction bypassed

STAGE 2

Source
  ↓
Process
  ↓
Privileges
  ↓
Destination

File written
```

### Final result from the source:

```cmd
C:\> type C:\whoops

PoC.
```

# ⭐ Final Takeaway

The key lesson from this vulnerability isn't just **“use directory traversal.”**

It's understanding how a seemingly simple input-processing flaw can break a security boundary:

> **User-controlled path → improper processing → directory restriction bypass → unauthorized file-writing operation.**

And this is exactly why the **Source → Process → Privileges → Destination** model is useful: it lets you break the vulnerability into understandable stages rather than treating the exploit as one complicated command.
