# HTB Skills Assessment – Web Fuzzing

## 1. Assessment Overview

### Objective

The objective of this assessment was to perform web enumeration and fuzzing against an online academy application when initially given only an IP address.

The assessment required:

1. Identifying domains/VHosts associated with the target.
2. Identifying useful file extensions.
3. Performing recursive content discovery against the discovered VHosts.
4. Identifying an interesting page containing the message:
   `You don't have access!`
5. Enumerating parameters accepted by that page.
6. Fuzzing parameter values.
7. Identifying a value that exposed a flag.

---

# 2. Initial VHost Enumeration

The first objective was to identify additional VHosts associated with the academy domain.

The general technique was HTTP Host-header fuzzing:

```text
Host: FUZZ.academy.htb
```

The `FUZZ` keyword was replaced with entries from a DNS/subdomain wordlist.

A baseline response size was identified and filtered using `-fs`.

Example:

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://TARGET:PORT/ \
-H 'Host: FUZZ.academy.htb' \
-fs 900
```

The scan returned an anomalous result for:

```text
admin
```

This established:

```text
admin.academy.htb
```

as a valid VHost.

During the Skills Assessment, the discovered academy VHosts relevant to the questions were:

```text
test.academy.htb
archive.academy.htb
faculty.academy.htb
```

### Question 1

**What other VHosts did you get?**

Answer:

```text
test, archive, faculty
```

---

# 3. File Extension Enumeration

The next stage involved identifying extensions that should be included during content discovery.

The relevant extensions identified during enumeration were:

```text
.php
.php7
.phps
```

These extensions were important because normal directory fuzzing could miss files using non-standard PHP extensions.

### Question 2

**What file extensions were found?**

Answer:

```text
.php, .php7, .phps
```

---

# 4. Recursive Web Content Enumeration

The assessment hint specifically stated:

> Run a recursive scan on all sub-domains you found, and use all of the extensions you found.

Therefore, each discovered VHost had to be scanned recursively.

The appropriate type of wordlist was a **Web-Content** wordlist rather than the DNS subdomain wordlist.

Example:

```bash
ffuf \
-w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt \
-u http://faculty.academy.htb:PORT/FUZZ \
-recursion \
-recursion-depth 1 \
-e .php,.phps,.php7 \
-fs BASELINE_SIZE
```

The same process was applied to:

```text
test.academy.htb
archive.academy.htb
faculty.academy.htb
```

---

# 5. Important Discovery: `/courses/`

During the recursive scan against the `faculty` VHost, the following directory was identified:

```text
/courses/
```

Because recursion was enabled, `ffuf` automatically queued another scan against:

```text
/courses/FUZZ
```

This is an important part of recursive enumeration.

Instead of stopping at:

```text
http://faculty.academy.htb:PORT/courses/
```

the scanner continued looking for files and directories inside `/courses/`.

---

# 6. Discovery of the Interesting Page

Inside the recursive `/courses/` scan, an anomalous result appeared:

```text
linux-security.php7
```

The response was:

```text
Status: 200
Size: 774
Words: 223
Lines: 53
```

The normal responses had been filtered based on their baseline response size.

The full discovered URL was:

```text
http://faculty.academy.htb:PORT/courses/linux-security.php7
```

During the actual instance used in the assessment, the port was:

```text
32495
```

Therefore:

```text
http://faculty.academy.htb:32495/courses/linux-security.php7
```

This was the page referenced by the next assessment question.

---

# 7. Parameter Enumeration

The next objective was to determine which parameters were accepted by:

```text
/courses/linux-security.php7
```

A parameter-name wordlist was used:

```text
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

The initial GET-based fuzzing approach was:

```bash
ffuf \
-w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
-u "http://faculty.academy.htb:PORT/courses/linux-security.php7?FUZZ=key" \
-fs 774
```

The baseline response size was:

```text
774
```

Therefore, responses with a different size were interesting.

The scan identified:

```text
user
```

with:

```text
Size: 780
```

This showed that `user` was accepted.

---

# 8. POST Parameter Fuzzing

The assessment material also demonstrated POST parameter fuzzing.

The POST request structure was:

```text
FUZZ=key
```

The appropriate command was:

```bash
ffuf \
-w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
-u "http://faculty.academy.htb:PORT/courses/linux-security.php7" \
-X POST \
-d "FUZZ=key" \
-H "Content-Type: application/x-www-form-urlencoded" \
-fs 774
```

The scan returned two interesting parameters:

```text
user
username
```

The responses were:

```text
user       → Size: 780
username   → Size: 781
```

The baseline response was:

```text
Size: 774
```

Therefore both parameters produced responses different from the baseline.

### Question 4

**What parameters are accepted by the page?**

Answer:

```text
user
username
```

---

# 9. Parameter Value Fuzzing

After identifying the accepted parameters, the next step was to determine which values were valid.

This changed the fuzzing target.

Instead of:

```text
FUZZ=key
```

the parameter name was kept fixed and the value became `FUZZ`.

For example:

```text
username=FUZZ
```

The objective was to find a value that caused a significant response change and ultimately exposed the flag.

---

# 10. Fuzzing the `username` Parameter

A username wordlist was used to fuzz the parameter value.

The important concept was to keep the parameter name fixed:

```text
username=FUZZ
```

The scan produced the following interesting result:

```text
harry    [Status: 200, Size: 773, Words: 218, Lines: 53]
```

This was anomalous because the response size differed from the normal response.

Therefore the discovered value was:

```text
harry
```

---

# 11. Manual Verification

After identifying `harry`, the result was manually verified using `curl`.

The POST request was:

```bash
curl -i -X POST \
"http://faculty.academy.htb:PORT/courses/linux-security.php7" \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "username=harry"
```

This request confirmed that the `username` parameter accepted:

```text
harry
```

and returned the flag.

---

# 12. Flag

The flag retrieved from the application was:

```text
HTB{w3b_fuzz1n6_m4573r}
```

---

# 13. Assessment Answers

| Question | Answer |
|---|---|
| Q1 – VHosts | `test, archive, faculty` |
| Q2 – Extensions | `.php, .php7, .phps` |
| Q3 – Interesting page | `http://faculty.academy.htb:32495/courses/linux-security.php7` |
| Q4 – Accepted parameters | `user, username` |
| Q5 – Flag | `HTB{w3b_fuzz1n6_m4573r}` |

---

# 14. Complete Attack/Enumeration Chain

```text
Target IP
   ↓
VHost Enumeration
   ↓
test.academy.htb
archive.academy.htb
faculty.academy.htb
   ↓
Extension Enumeration
   ↓
.php
.php7
.phps
   ↓
Recursive Web Content Fuzzing
   ↓
faculty.academy.htb
   ↓
/courses/
   ↓
/courses/linux-security.php7
   ↓
Parameter Fuzzing
   ↓
user
username
   ↓
Parameter Value Fuzzing
   ↓
username=harry
   ↓
Manual POST Verification
   ↓
HTB{w3b_fuzz1n6_m4573r}
```

---

# 15. Important Lessons Learned

## 15.1 VHost fuzzing is different from directory fuzzing

When fuzzing VHosts, the `Host` header is the important attack surface:

```text
Host: FUZZ.academy.htb
```

The URL itself does not necessarily change.

---

## 15.2 Response size is extremely useful

A large number of HTTP 200 responses does not mean that all results are valid.

The server may return the same default page for nonexistent resources.

`ffuf` can filter those responses using:

```text
-fs SIZE
```

This allows anomalous responses to stand out.

---

## 15.3 Choose the correct wordlist

Different fuzzing tasks require different wordlists.

### VHost/subdomain fuzzing

```text
Discovery/DNS/
```

### Directory/file fuzzing

```text
Discovery/Web-Content/
```

### Parameter-name fuzzing

```text
Discovery/Web-Content/burp-parameter-names.txt
```

### Username/value fuzzing

```text
Usernames/
```

Using the wrong wordlist can produce huge amounts of noise or completely miss the target.

---

# 16. Errors and Corrections During the Assessment

## Wrong wordlist for directory fuzzing

The DNS wordlist was initially used for web-content enumeration.

The correction was to switch to a Web-Content wordlist.

---

## Incorrect `-fs` usage

HTTP status codes were initially placed into `-fs`.

For example:

```text
-fs 200,204,301,302,...
```

This was incorrect.

`-fs` filters by **response size**.

The correct options are:

```text
-fs → response size
-fc → HTTP status code
-fw → word count
-fl → line count
-fr → regular expression
```

---

## Recursive path was initially overlooked

The important page was not directly:

```text
/linux-security.php7
```

It was inside the recursively discovered directory:

```text
/courses/linux-security.php7
```

This demonstrated why recursive enumeration matters.

---

## Filtering valid responses

When `user` produced a response size of `780`, filtering both:

```text
774,780
```

removed the valid result as well.

The correct approach is to preserve anomalous response sizes while filtering only the established baseline.

---

# 17. Final Conclusion

The assessment demonstrated a complete web-fuzzing workflow starting with very limited information.

The target was progressively enumerated through:

1. **VHost discovery**
2. **Extension identification**
3. **Recursive directory/file fuzzing**
4. **Parameter-name fuzzing**
5. **Parameter-value fuzzing**
6. **Manual verification**

The final successful request used:

```text
username=harry
```

which returned:

```text
HTB{w3b_fuzz1n6_m4573r}
```

The most important takeaway is that fuzzing is not simply about running `ffuf` with a large wordlist. The useful results came from repeatedly establishing a **baseline**, identifying **anomalous responses**, and then narrowing the attack surface step by step.
