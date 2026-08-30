![Image](https://images.openai.com/static-rsc-4/VaDroImzYESw0dyt7ddr1HYep0P4blWDLSSv0tUpNbjKotYHo_Auf5CPsgyc-GIJq3GKsj_vka_twVTjrq-vvdrFTCZqufjcTU5CxuDIaVmlGdLEfUCXoFgQWDL_-egdrKTPo0GWjZTtujnIxixL-evt9O7WHB6Nl8n4R6IjxhmqNopOX4Hn85N_zqmObeAo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/o5U_tN2ip6NQpFG3vMcIh0aL-lfyc6HhLTip6RFtSeRO6GfqKOZcmeC-o3FFOfjSEw2o3inm1EEgRd25naejsS23pXzhmXnS0UjBJyTQzrKM7rtbA4lz7FMbLagQrKBsK-OUCNzEymxgcu0IpQpzYpKi5FLyRKacn8zdCUHFGn-o5AmIq0IJZJbL9MdLUceo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vkYg5xxWDw2LN2Ne6vRI_uqO2blE25kOjAtyTh8eSZRXlidatje6AoKD0kB3FFGcun-1KwvZtqg9Dkx1X9FOPiubx8dVCfzi-1RLxdDOffXFgUXPI5GwWckXadWoD8WvaYWxQd5Xx_cenfOxFKKXFfAna9Rh2ZxLczR9CwOqlRGUOcOu_wp1Id0OnrGg20La?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-xuTZnk6XaTrVHlaHAZKFbbVpiQSAnUkyZKbee1CFmfM52WWumEoAYMwkoiZ24pjlUitBtoooOAhhlD_K9M9u71unXV9dv5091tgF0L4Lb3DuU4xy398h_CWdoND8Equb7hLoLXTmHZjO_znSxFSs7rUJRA2ZI8g99UWI-Oac6JqpGwKDkP8gcQ5bvo7Zw7x?purpose=fullsize)

## 1. Overview

Not every file-upload vulnerability involves:

- Uploading a PHP shell
    
- Bypassing an extension filter
    
- Uploading malicious SVG/XML files
    

There are other attack techniques where the **upload process itself** becomes the attack surface.

### Main categories

|Attack|Main Target|Possible Impact|
|---|---|---|
|Filename Injection|Filename processing|Command Injection / XSS / SQLi|
|Upload Directory Disclosure|File storage|Information disclosure|
|Windows-specific attacks|Windows filesystem|Errors, disclosure, overwriting|
|8.3 Filename attacks|Windows filenames|File targeting/overwriting|
|File-processing attacks|Libraries/processors|XXE, RCE, DoS, etc.|

---

# 2. Filename Injection

One of the most important ideas in this section:

> **The filename itself is user-controlled input.**

Developers sometimes focus heavily on validating the **file content** while forgetting that the filename can also contain malicious input.

The attack depends on what the application does with the filename after upload.

---

## 2.1 Command Injection Through Filename

Imagine an application receives:

```text
file.jpg
```

and internally runs an operating-system command to move it:

```text
mv <filename> /tmp/
```

If the filename is inserted into the command unsafely, shell metacharacters may cause additional commands to execute.

Examples from the module include filenames conceptually like:

```text
file$(whoami).jpg
```

```text
file`whoami`.jpg
```

```text
file.jpg||whoami
```

The important concept isn't the specific payload — it's the **data flow**:

```text
User-controlled filename
        ↓
Application
        ↓
Filename inserted into OS command
        ↓
Shell interprets special characters
        ↓
Unexpected command execution
```

### ⭐ Key takeaway

> **A file-upload vulnerability can exist even when the uploaded file itself is completely harmless.**

The vulnerable component may be the **filename handling**.

---

# 3. XSS Through Filename

The filename can also be used as an XSS injection point.

For example, a malicious filename could contain HTML/JavaScript.

If the application later displays the filename without proper output encoding:

```text
Upload filename
      ↓
Server stores filename
      ↓
Filename displayed in webpage
      ↓
Browser interprets injected HTML
      ↓
XSS
```

### Important condition

The filename needs to reach an HTML context **without proper escaping/encoding**.

So simply having a malicious filename isn't enough.

---

# 4. SQL Injection Through Filename

The same principle applies to database queries.

Suppose the application stores uploaded filenames in a database and constructs SQL queries using string concatenation.

A malicious filename could potentially manipulate the query.

The module gives an example conceptually like:

```text
file';select+sleep(5);--.jpg
```

If the application handles the filename unsafely:

```text
Filename
   ↓
SQL query
   ↓
SQL syntax manipulated
   ↓
SQL Injection
```

### ⭐ General principle

Treat:

> **Filename = Untrusted User Input**

It should receive the same security treatment as any other user-controlled input.

---

# 5. Upload Directory Disclosure

Sometimes we successfully upload a file but **don't know where the server stored it**.

For example:

```text
Upload successful
       ↓
But where is the file?
       ↓
/uploads/?
/files/?
/images/?
/documents/?
```

Knowing the upload directory can be important because it tells us where the uploaded resource may be accessible.

---

## 5.1 Finding the Upload Directory

Possible approaches mentioned in the module include:

### A. Fuzzing

Search for common directories such as:

```text
/uploads/
/upload/
/files/
/images/
/documents/
/attachments/
```

The exact location depends on the application.

---

### B. Source-Code Disclosure

If another vulnerability such as:

- LFI
    
- XXE
    

allows access to application source code, the source may reveal:

```text
Upload directory
Allowed extensions
File naming scheme
Storage mechanism
```

This is why vulnerabilities can chain together:

```text
Limited Upload
      ↓
XXE / LFI
      ↓
Source Code
      ↓
Upload Directory
      ↓
Further Testing
```

---

# 6. Error Messages as an Information Source

A very useful pentesting concept:

> **Errors can leak information.**

If an application doesn't properly handle an upload error, its error message may reveal internal filesystem information.

For example, intentionally triggering an upload error may expose something resembling:

```text
Unable to write:
/var/www/html/uploads/file.jpg
```

Now we know the upload directory.

---

# 7. Causing Upload Errors

The module gives several examples of ways errors may occur.

### Existing filename

Upload a file with a name that already exists.

```text
existing-file.jpg
```

If the application doesn't handle the collision properly, an error may reveal the storage path.

---

### Simultaneous requests

Sending two identical upload requests simultaneously may create a race condition or file-writing conflict.

Conceptually:

```text
Request A ──┐
            ├──→ Same filename
Request B ──┘
                 ↓
             Write conflict
                 ↓
               Error
                 ↓
          Possible path disclosure
```

---

### Extremely long filename

The module suggests trying an excessively long filename, such as one containing around **5,000 characters**.

If the application fails to handle it correctly, the resulting error may disclose useful filesystem information.

### Important

The goal isn't simply:

> “Make the application crash.”

The goal is:

> **Observe what information the resulting error reveals.**

---

# 8. Windows-Specific Upload Attacks

![Image](https://images.openai.com/static-rsc-4/EhkAih3HPX_ZtoRUCdYRzWrGeuiOGZ1hIU7Y3q_fJ4hsokh6DFSYlra8DMZHMTqhYsn-u3nvGut26OVSkZir4cJQWdKVKlXjstjEN2OQh-kT5ctlRykHaMjds-5CcdvhVpZWNgQIqzfcYZ1QXPUs6O-H9ZMyoxaNANkGkp1s9EYrMUzsDXQzE8NvhpI60bIe?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vkYg5xxWDw2LN2Ne6vRI_uqO2blE25kOjAtyTh8eSZRXlidatje6AoKD0kB3FFGcun-1KwvZtqg9Dkx1X9FOPiubx8dVCfzi-1RLxdDOffXFgUXPI5GwWckXadWoD8WvaYWxQd5Xx_cenfOxFKKXFfAna9Rh2ZxLczR9CwOqlRGUOcOu_wp1Id0OnrGg20La?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/U9Ha0N7Yr03DTYp6wic0QOw-S3Oji88TdHb5lMESI_M8TFXVti1Gt_Dx12sUn7wjw89rAnG7rCPzacP7C1qTh1QxNeYZ_89fQ5gAGGtwcSY_0_9nBHuKd9QkKcOEaZxUwS8JSTm0hTaiEE2SpDKfRleSXggHBI6gsrWxHhFSbMCNHGfmu3A0e2CXEx-Sxewu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/INMWiQOo_8Uy0iHlfxyP0Sy2oJ78WqykjmIuNBqhpX_fo3gldzjfAr4blXQmyJv23mm5XwUkZfMEzNwL3GTwEw0_Zuowr9KFhpAYMyNxOPpmSx4LAkV3eeaqUV1T1EjbX3ADBf_2VRXYR-njXP1pu1tFv2TswAdESer_-AFTlDI6fKhnFVoaHeuShTmC0NTy?purpose=fullsize)

Some filename attacks behave differently on Windows because of Windows filesystem rules.

Important areas include:

1. Reserved characters
    
2. Reserved filenames
    
3. 8.3 filenames
    

---

# 9. Windows Reserved Characters

Windows has characters that have special meanings or restrictions in filenames.

The module mentions:

```text
|
<
>
*
?
```

If an application doesn't properly sanitize or quote filenames, these characters can potentially cause unexpected behavior.

Possible result:

```text
Malicious filename
      ↓
Windows filesystem / command processing
      ↓
Unexpected interpretation
      ↓
Error / information disclosure
```

---

# 10. Windows Reserved Filenames

Windows also has reserved device names.

Examples mentioned:

```text
CON
COM1
LPT1
NUL
```

These names cannot normally be used like ordinary filenames.

If an application attempts to create a file with one of these names, it may generate an error.

Again:

> **The error itself may reveal useful information.**

This can potentially disclose filesystem paths or other implementation details.

---

# 11. Windows 8.3 Filename Convention

This is an especially important Windows-specific concept.

Older Windows systems used a shortened filename format called:

> **8.3 Filename Convention**

The general structure is:

```text
8 characters . 3-character extension
```

Long filenames could have shortened aliases using `~`.

For example, a long filename might have an associated short form similar to:

```text
HAC~1.TXT
```

The number identifies the matching filename's order.

---

## Why is this relevant?

An application may validate one filename representation while Windows interprets another.

This can potentially create opportunities for:

- File targeting
    
- File overwriting
    
- Information disclosure
    
- DoS
    
- Access to unintended files
    

### Core idea

```text
Long filename
     ↓
Windows generates short alias
     ↓
Application handles filename incorrectly
     ↓
Different filename representation is referenced
     ↓
Unexpected file operation
```

---

# 12. Advanced File Upload Attacks

The upload process often performs more than simply:

```text
Receive → Save
```

Modern applications may automatically:

- Resize images
    
- Convert images
    
- Generate thumbnails
    
- Encode videos
    
- Extract archives
    
- Compress files
    
- Rename files
    
- Parse metadata
    
- Generate previews
    
- Convert document formats
    

Every additional processing step introduces another attack surface.

---

# 13. Automatic File Processing

Consider an image upload:

```text
User uploads image
       ↓
Server receives it
       ↓
Image processing library
       ↓
Resize
       ↓
Generate thumbnail
       ↓
Store processed image
```

Even if the upload validation itself is secure, a vulnerability may exist in the **image-processing library**.

Similarly:

```text
Video
 ↓
FFmpeg
 ↓
Transcoding
```

or:

```text
Document
 ↓
Document parser
 ↓
Preview generation
```

Each component needs to safely process attacker-controlled input.

---

# 14. Vulnerable Libraries

The module highlights an important real-world scenario:

> Sometimes the vulnerability isn't in the upload code itself — it's in a library that processes the uploaded file.

For example, the module mentions an **AVI upload vulnerability involving XXE in FFmpeg**.

The general attack chain is:

```text
Malicious file
      ↓
Secure upload filter
      ↓
File accepted
      ↓
Automatic processing
      ↓
Vulnerable library
      ↓
Library vulnerability triggered
      ↓
Potential compromise
```

### ⭐ Key lesson

**Validating the file extension alone doesn't secure the entire upload pipeline.**

---

# 15. Custom Processing Code

Custom-built processing functions can be even harder to assess.

For example:

```text
Upload
  ↓
Custom parser
  ↓
Custom conversion
  ↓
Custom renaming
  ↓
Custom storage
```

Each custom component may contain unexpected vulnerabilities.

Finding these generally requires deeper knowledge of:

- Application architecture
    
- File formats
    
- Parsing
    
- OS behavior
    
- Security boundaries
    
- Vulnerable libraries
    

---

# 🧠 Complete Attack Map

```text
                 FILE UPLOAD
                     │
       ┌─────────────┼─────────────┐
       │             │             │
    Filename       Storage       Processing
       │             │             │
       │             │             ├── Image parser
       │             │             ├── FFmpeg
       │             │             ├── Document parser
       │             │             └── Archive extractor
       │             │
       │             └── Directory disclosure
       │
       ├── Command Injection
       ├── XSS
       └── SQL Injection
                     │
              Windows-specific
                     │
              ├── Reserved chars
              ├── Reserved names
              └── 8.3 filenames
```

---

# 🔥 CTF / Pentest Revision Sheet

### Filename Injection

**Question:** Is the filename used anywhere dangerous?

Check whether it reaches:

```text
OS command → Command Injection
HTML output → XSS
SQL query → SQL Injection
Filesystem operation → File manipulation
```

---

### Upload Directory

If the uploaded file isn't directly accessible:

```text
Fuzz directories
       ↓
Trigger errors
       ↓
Check source code through other vulnerabilities
       ↓
Identify upload directory
       ↓
Identify naming scheme
```

---

### Windows

Remember:

```text
Reserved characters:
| < > * ?

Reserved names:
CON
COM1
LPT1
NUL

8.3:
LONGNAME.TXT
      ↓
LON~1.TXT
```

---

### Automatic Processing

Always ask:

> **What happens to the file AFTER it is uploaded?**

Potential processing:

```text
Resize
Convert
Compress
Extract
Parse
Rename
Preview
Transcode
```

Every one of these can introduce another vulnerability.

---

# ⭐ Final Takeaways

1. **The filename itself is attacker-controlled input.**
    
2. Filename injection can potentially lead to **Command Injection, XSS, or SQL Injection**.
    
3. Upload errors can disclose the **upload directory and filesystem paths**.
    
4. Windows has unique filename behavior that can create additional attack surfaces.
    
5. **8.3 filenames** can provide alternate representations of filenames.
    
6. Reserved Windows names such as `CON`, `COM1`, `LPT1`, and `NUL` can trigger useful errors.
    
7. A secure upload filter does **not** guarantee secure file processing.
    
8. Automatic processing libraries such as image, video, document, and archive processors must also be tested.
    
9. Vulnerabilities can be chained:
    

```text
Upload
  ↓
Error / XXE / LFI
  ↓
Information disclosure
  ↓
Discover storage/processing behavior
  ↓
Find secondary vulnerability
  ↓
Further exploitation
```

### 🧩 The mindset for this entire module

> **Don't only ask “Can I upload a malicious file?”**

Ask:

> **“What does the application do with my file, its filename, its contents, and its metadata after I upload it?”**

That question ties together **arbitrary uploads, limited uploads, filter bypasses, filename attacks, and advanced processing vulnerabilities**.