![Image](https://images.openai.com/static-rsc-4/I6SN5bpd9DWceSDCxNaAYKRTWNeTv0aRNaEGJzvi5YssoCW6cawb-sSmfec_VshMnsZLySkcQAyBpT2LN5DVxsLtjhBlgOrOA8jXHcywE5QhoRfm-RTsga6icoN26HB5mnf0DKinlRGx_xQFxEuO3V4tWjVZUzHlfA8bAav93TFVHqwp_q6RkCjf0fPBQ0RF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4N1rrnKv0Jiv96EUrxO4s5vrBcuZ3EHY2bMQ4hNHJY2FzNuCoYH3owwTzYh3XK49OvnwoMdQiqir9lnyUGV5K0-k16bJpbMeQvAUxcoVu3l8hcWfwtcbHsdyhctmFlanqDN53H3LkWN0DI38oKk3u_ffkLQqfpD8DOb96nPqciY4ZTuXb0JDD3hSgPX2L8Ty?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5dozrOogcOhWd6bolm_7jBbiyYMkMroP8uox08s0mMdb-NhSb39gzBZVHs9zocpZl99JDneWBfY_fk3OS9WYlBY01tlYImAUIRcH4xVHDT6FeJcqApIvTBRQH7icd069rEXxOPKiQxmGfjcM70y3IpghBrMtaSyKDZJq2W-HRvTHauhFArw7mGbGt3pCt0L0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/itibO0A5ZQgP4gOCPIMgQ5aYDpkRtjsTibmxqAwFOJmUXx4XxLatFr5tWBM3kMTX7m3fBzO--aEyxY9u8BXhV36dp_I7QwteJPhrysj-MYtpZSAxltAMFrolICRlljEjsgZDj65uBtZmJFMzQ_ckvxO4evMxLXSRMyY6_bb3PnA_jkmfG3X_FcFnP_cNsHiC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JhxY5YJ7_ntuS0SEE1SCcg6nGo7OJpmLlbFGBNQs6A1pJk5OxYzRXUDhqF4s9d8tqn-4OTFclkD8i4BDb6XPSeR-k1nK2q_Ur97WMi70NbNOMCTpDwH8f_IObGlnlhlV_UNv6SC3Xml09uaR-DY7-vHHensmBLFklad7MRTzSCaUQhAzPznM1jeoxyRwjBK9?purpose=fullsize)

---

## 1. What is IIS Tilde Enumeration?

When files/directories are created on Windows, the filesystem can generate an **8.3 short filename**:

```text
XXXXXXXX.XXX
```

Meaning:

- Maximum **8 characters** for the filename
    
- A `.`
    
- Maximum **3 characters** for the extension
    

For example:

```text
somefile.txt
```

may have a short name such as:

```text
SOMEFI~1.TXT
```

The `~1` identifies the first similarly named file. A second file could become:

```text
SOMEFI~2.TXT
```

The vulnerability arises because certain IIS versions can leak information about these short names through specially crafted HTTP requests.

### Why does this matter?

Even if the administrator believes a resource is hidden:

```text
/SecretDocuments/
```

the attacker may be able to discover its short name:

```text
/secret~1/
```

and then enumerate resources beneath it.

---

# 2. The `~` Character

The key character is:

```text
~
```

The attacker sends requests such as:

```text
http://example.com/~a
http://example.com/~b
http://example.com/~c
```

The responses can reveal whether a corresponding short filename exists.

### Example

Suppose the real directory is:

```text
SecretDocuments
```

The attacker starts with:

```text
/~s
```

If the response indicates a valid resource, continue:

```text
/~se
/~sec
/~secr
/~secre
/~secret
```

Eventually:

```text
secret~1
```

can be identified.

---

# 3. Directory → File Enumeration

Once we discover:

```text
/secret~1/
```

we can investigate files inside it.

For example:

```text
http://example.com/secret~1/somefile.txt
```

or potentially its 8.3 filename:

```text
http://example.com/secret~1/somefi~1.txt
```

The module specifically demonstrates that short names can also be identified for files, not just directories.

### Important concept

Think of it as:

```text
Normal filename
       ↓
Windows 8.3 filename
       ↓
IIS information disclosure
       ↓
Discover hidden resource
       ↓
Enumerate actual filename
       ↓
Access resource
```

---

# 4. Why `~1`?

Consider:

```text
somefile.txt
somefile1.txt
```

Possible short names:

```text
somefi~1.txt
somefi~2.txt
```

The number after `~` distinguishes similarly named files within the same directory.

So:

```text
~1
~2
~3
...
```

can be useful when multiple files share similar names.

---

# 5. Enumeration Methodology

The overall methodology is:

```text
        ┌─────────────────┐
        │   Target IIS    │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Port scanning   │
        │     Nmap        │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Identify IIS    │
        │ version         │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ IIS ShortName   │
        │ Scanner         │
        └────────┬────────┘
                 │
                 ▼
       ┌─────────────────────┐
       │ Short names found   │
       │ e.g. TRANSF~1.ASP   │
       └──────────┬──────────┘
                  │
                  ▼
        ┌─────────────────┐
        │ Brute-force full│
        │ filename        │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Gobuster / HTTP │
        │ enumeration     │
        └─────────────────┘
```

---

# 6. Step 1 — Nmap

First determine what services are exposed.

The module uses:

```bash
nmap -p- -sV -sC --open 10.129.224.91
```

Relevant result:

```text
80/tcp open  http    Microsoft IIS httpd 7.5
```

It also identifies:

```text
http-server-header: Microsoft-IIS/7.5
http-title: Bounty
Service Info: OS: Windows
```

### CPTS takeaway

If you see:

```text
Microsoft IIS
```

especially an older version, consider checking whether **IIS short-name enumeration** is applicable.

---

# 7. Step 2 — IIS ShortName Scanner

Manually testing:

```text
/~a
/~b
/~c
...
```

would obviously be tedious.

The module uses:

**IIS-ShortName-Scanner**

Command:

```bash
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/
```

The scanner reports:

```text
Result: Vulnerable!
Used HTTP method: OPTIONS
Suffix (magic part): /~1/
```

It identifies:

### Directories

```text
ASPNET~1
UPLOAD~1
```

### Files

```text
CSASPX~1.CS
CSASPX~1.CS??
TRANSF~1.ASP
```

---

# 8. Why Automating This Matters

The scanner sent:

```text
553 requests
```

and identified:

```text
2 directories
3 files
```

Instead of manually testing hundreds of possible combinations, the scanner automates the short-name discovery process.

### Tool to remember

```text
IIS-ShortName-Scanner
```

GitHub:

[IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner?utm_source=chatgpt.com)

---

# 9. Important Limitation

Finding a short name does **not necessarily mean we can directly GET the resource**.

The module discovers:

```text
TRANSF~1.ASP
```

but:

```text
http://10.129.204.231/TRANSF~1.ASP
```

doesn't allow direct GET access.

Therefore, the next step is to determine the **full filename**.

This is an important pentesting lesson:

> **Enumeration ≠ exploitation/access.**

A vulnerability may disclose metadata without immediately giving you the underlying resource.

---

# 10. Step 3 — Build a Custom Wordlist

The discovered short name is:

```text
TRANSF~1.ASP
```

So we can search our existing wordlists for words beginning with:

```text
transf
```

The module uses:

```bash
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
```

### Breaking the command down

#### `egrep -r`

```bash
egrep -r ^transf /usr/share/wordlists/*
```

Search recursively through wordlists.

```text
-r
```

means recursive.

```text
^transf
```

means:

> match lines beginning with `transf`

---

### Pipe

```bash
|
```

passes the output to the next command.

---

### `sed`

```bash
sed 's/^[^:]*://'
```

removes the filename/source information produced by `egrep`.

---

### Output

```bash
> /tmp/list.txt
```

saves the resulting custom wordlist.

---

# 11. Step 4 — Gobuster

Now use the custom wordlist to find the complete filename.

```bash
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp
```

The important result:

```text
/transf**.aspx        (Status: 200) [Size: 941]
```

This means the short name:

```text
TRANSF~1.ASP
```

corresponds to a full `.aspx` filename beginning with:

```text
transf
```

The module's output is redacted, but confirms that Gobuster successfully identifies the full filename.

---

# 12. The Full Attack Chain

Memorize this:

```text
             NMAP
               │
               ▼
        IIS 7.5 identified
               │
               ▼
      Short-name enumeration
               │
               ▼
       IIS-ShortName-Scanner
               │
               ▼
          TRANSF~1.ASP
               │
               ▼
      Direct GET unavailable
               │
               ▼
     Generate targeted wordlist
               │
               ▼
            Gobuster
               │
               ▼
      Full filename discovered
               │
               ▼
      Further enumeration/access
```

---

# 13. What Makes This Technique Interesting?

The vulnerability isn't necessarily:

> "IIS lets me download arbitrary files."

Instead, the initial problem is **information disclosure through short filename behavior**.

That information can then be chained into additional enumeration.

For example:

```text
Hidden resource
      ↓
8.3 filename
      ↓
Short-name disclosure
      ↓
Filename prefix
      ↓
Targeted brute force
      ↓
Full filename
      ↓
Interesting application/resource
      ↓
Potential further attack
```

This is classic **enumeration leading to attack-surface expansion**.

---

# 14. CPTS Exam Points 🧠

### ⭐ 1. What is 8.3?

Windows short filename format:

```text
XXXXXXXX.XXX
```

Maximum:

```text
8 characters + 3-character extension
```

---

### ⭐ 2. What character is associated with short names?

```text
~
```

Example:

```text
somefi~1.txt
```

---

### ⭐ 3. What should you consider when encountering older IIS?

Check for:

```text
IIS tilde / short-name enumeration
```

---

### ⭐ 4. Useful tool

```text
IIS-ShortName-Scanner
```

---

### ⭐ 5. HTTP method shown by the scanner

The module reports:

```text
OPTIONS
```

---

### ⭐ 6. If a discovered short name cannot be accessed directly?

Don't stop.

Use the short name to derive a **targeted wordlist**, then brute-force the full filename.

The module demonstrates:

```text
TRANSF~1.ASP
       ↓
transf*
       ↓
Gobuster
       ↓
full filename
```

---

# 15. Important Commands — Quick Revision

### Nmap

```bash
nmap -p- -sV -sC --open 10.129.224.91
```

### IIS ShortName Scanner

```bash
java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/
```

### Create targeted wordlist

```bash
egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
```

### Gobuster

```bash
gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp
```

---

# 16. Enumeration Checklist 📝

When you encounter an IIS target:

-  Scan all TCP ports
    
-  Identify IIS version
    
-  Check HTTP/HTTPS
    
-  Look for older IIS versions
    
-  Test IIS short-name enumeration
    
-  Run `IIS-ShortName-Scanner`
    
-  Record discovered `~1` resources
    
-  Separate discovered directories/files
    
-  Test direct access
    
-  If access fails, identify filename prefix
    
-  Generate a targeted wordlist
    
-  Use Gobuster/appropriate enumeration
    
-  Identify the full filename
    
-  Inspect the discovered resource
    
-  Look for additional attack paths
    

---

# 🔥 Final Cheat Sheet

|Concept|Remember|
|---|---|
|Technique|IIS Tilde Enumeration|
|Main issue|Information disclosure|
|Filesystem feature|Windows 8.3 filenames|
|Format|`XXXXXXXX.XXX`|
|Key character|`~`|
|Example|`SOMEFI~1.TXT`|
|Enumeration tool|IIS-ShortName-Scanner|
|Scanner HTTP method|`OPTIONS`|
|Follow-up tool|Gobuster|
|Key idea|Short name → filename prefix → brute force full name|
|Important distinction|Discovery doesn't guarantee GET access|

### 🧠 Golden mental model

> **Don't think "I found a hidden file." Think "I found information about a hidden file."**

The short-name vulnerability gives you a **foothold in enumeration**. From there, you use targeted wordlists and normal web enumeration to recover the actual resource name.