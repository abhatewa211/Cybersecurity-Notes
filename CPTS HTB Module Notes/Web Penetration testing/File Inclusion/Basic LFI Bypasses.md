# 1. Basic Bypasses

Previously, we saw different techniques for exploiting LFI.

However, real applications may apply protections such as:

- String replacement
    
- Character filtering
    
- Regular expressions
    
- Approved-path restrictions
    
- Appended extensions
    

If these protections are implemented incorrectly, it may still be possible to bypass them.

### Core idea

```text
User input
    ↓
Security filter
    ↓
Does the filter actually remove the dangerous behavior?
    ↓
Application processes resulting path
```

> ⭐ **Important:** A blacklist/filter is not automatically a secure defense. You have to understand exactly how the input is transformed before it reaches the vulnerable function.

---

# 2. Non-Recursive Path Traversal Filters

One of the simplest LFI protections is a **search-and-replace filter**.

Example:

```php
$language = str_replace('../', '', $_GET['language']);
```

The intention is:

```text
../
 ↓
removed
```

So a payload such as:

```text
../../../../etc/passwd
```

would have its `../` portions removed.

The resulting path could become something like:

```text
./languages/etc/passwd
```

and therefore fail to access the intended file.

---

# 3. Why This Filter Is Weak

The problem is that the filter is **not recursive**.

It processes the original input once:

```text
Input
 ↓
Remove ../
 ↓
Output
```

It does **not** take the output and run the same filter again.

That distinction is critical.

---

# 4. Recursive vs Non-Recursive Filtering

### Non-recursive

```text
Input
 ↓
Filter once
 ↓
Output
```

### Recursive

```text
Input
 ↓
Filter
 ↓
New output
 ↓
Filter again
 ↓
New output
 ↓
Continue until safe
```

The source's example demonstrates why this matters.

Suppose the input contains:

```text
....//
```

The string contains:

```text
../
```

inside it.

After removing that occurrence, the remaining value can become:

```text
../
```

So the filter has unintentionally **created a traversal sequence** in its output.

---

# 5. `....//` Concept

The important transformation is:

```text
....//
```

↓

```text
../
```

after the filter removes one matching `../`.

Therefore, if the application only performs a single replacement, the resulting value can still contain:

```text
../
```

which can then be interpreted as directory traversal by the file-system/path handling.

The source demonstrates this concept using:

```text
....//....//....//....//etc/passwd
```

---

# ⭐ 6. Other Recursive-Style Variations

The source also mentions that `....//` isn't the only possible representation.

Examples include:

```text
..././
```

and:

```text
....\/
```

It also mentions techniques involving:

- Escaping the forward slash
    
- Adding extra forward slashes
    

For example:

```text
....////
```

The important lesson is **not to memorize one specific string**.

Instead:

> Understand how the application's filtering operation transforms the input.

---

# 🧠 7. Encoding

Another common protection is blocking characters associated with path traversal.

For example:

```text
.
/
```

may be filtered.

An application might reject input containing those characters.

However, HTTP supports **URL encoding**, where characters can be represented differently.

For example:

```text
../
```

can be URL-encoded as:

```text
%2e%2e%2f
```

The idea is:

```text
Encoded input
      ↓
Application/server decoding
      ↓
Original path representation
```

So a filter that checks the encoded representation incorrectly may fail to recognize what the application eventually processes.

---

# 8. URL Encoding Example

The source gives this encoded representation:

```text
%2e%2e%2f
```

which corresponds to:

```text
../
```

A longer encoded LFI path can similarly represent a traversal sequence followed by a local file path.

The source demonstrates using URL encoding to bypass the earlier `../` blacklist and successfully access `/etc/passwd`.

---

# ⭐ 9. Important Encoding Detail

The source gives an important warning:

> **All characters should be URL encoded, including the dots.**

Some URL encoders may leave `.` unchanged because they consider it part of the URL scheme.

So when testing encoding-based filtering, make sure you understand exactly what your encoder is producing.

---

# 10. Double Encoding

The source also discusses **double encoding**.

Conceptually:

```text
Original
   ↓
Encoded
   ↓
Encoded again
```

For example, the first encoded representation can itself be encoded.

The important concept is:

```text
Filter sees representation A
        ↓
Decoder transforms it
        ↓
Another representation appears
        ↓
Application eventually processes it
```

This can sometimes bypass filters that only expect a single encoding layer.

---

# 11. Approved Paths

Some applications use **Regular Expressions (Regex)** to restrict the files that can be included.

For example:

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}
```

This regex attempts to ensure that the supplied path begins with:

```text
./languages/
```

The intended rule is essentially:

```text
Only paths under ./languages/
```

---

# 12. Finding the Approved Path

Before attempting to understand or test such a restriction, you need to identify what path the application normally uses.

The source suggests:

### Method 1 — Examine normal requests

Look at requests generated by existing forms/features.

For example, selecting a language may reveal:

```text
./languages/en.php
```

### Method 2 — Discover directories

The source also mentions fuzzing web directories under the relevant path and trying different ones until you identify the expected location.

The goal is to determine:

```text
What path does the application consider valid?
```

---

# 13. Approved Path + Path Traversal

A key weakness can occur when the validation checks only the **beginning of the path**.

If the application expects:

```text
./languages/
```

we can conceptually construct a path that starts there and then traverses upward.

Example from the source:

```text
./languages/../../../../etc/passwd
```

The important idea is:

```text
Starts with approved path
             ↓
Passes initial validation
             ↓
Traversal moves outside approved directory
```

---

# ⭐ 14. Combining Bypasses

Real applications may have **multiple filters at the same time**.

For example:

```text
Approved path
      +
Blacklist
      +
Encoding filter
```

In that situation, techniques can be combined.

The source specifically mentions combining:

- Approved-path techniques
    
- URL encoding
    
- Recursive traversal representations
    

Conceptually:

```text
Approved prefix
      ↓
Traversal representation
      ↓
Encoding if required
      ↓
Application decodes/processes
```

---

# 15. Appended Extension

Another common defense is automatically adding an extension.

Example:

```php
include($_GET['language'] . ".php");
```

So:

```text
Input
 ↓
".php"
 ↓
Final path
```

For example:

```text
/etc/passwd
```

becomes conceptually:

```text
/etc/passwd.php
```

This prevents directly requesting files that don't have the expected extension.

---

# 16. Modern PHP vs Older PHP

This is an **important historical distinction**.

The source states that with modern PHP versions, bypassing an appended extension may not be possible using some older techniques.

You may therefore be restricted to reading files with the expected extension.

However, that can still be useful, particularly for **source-code-related scenarios**, which the next section discusses.

---

# 17. Older PHP Bypasses

The material covers two older techniques:

1. **Path Truncation**
    
2. **Null Bytes**
    

⚠️ These techniques are explicitly described as **obsolete with modern PHP** and primarily relevant to PHP versions before approximately **5.3/5.4**, depending on the technique.

They are still worth understanding because older servers may exist.

---

# 18. Path Truncation

Older PHP versions had a path/string length limitation of approximately:

```text
4096 characters
```

If a string exceeded this length, characters beyond the limit could be truncated.

The source also describes older PHP/path behavior involving:

- Trailing slashes
    
- Single dots
    
- Multiple slashes
    
- Current-directory shortcuts
    

For example:

```text
/etc/passwd/.
```

could effectively resolve as:

```text
/etc/passwd
```

Similarly:

```text
////etc/passwd
```

can represent:

```text
/etc/passwd
```

And:

```text
/etc/./passwd
```

can resolve as:

```text
/etc/passwd
```

---

# 19. Combining Path Truncation Behavior

The historical technique combines:

```text
Long input
+
Path normalization behavior
```

The goal was to cause an automatically appended extension such as:

```text
.php
```

to fall beyond the historical maximum length and therefore be truncated.

Conceptually:

```text
Requested path
       +
Huge amount of padding
       +
.php
       ↓
4096-character limit
       ↓
.php gets truncated
       ↓
Original target path remains
```

---

# 20. Important Requirement for Path Truncation

The source notes that the path should begin with a **non-existing directory** for this historical technique.

The example has the general structure:

```text
non_existing_directory/../../../etc/passwd/
+ many ./ sequences
```

The source describes repeating:

```text
./
```

approximately **2048 times** to reach the historical length limit.

---

# 21. Automating the Long String

Instead of manually writing thousands of characters, the source demonstrates generating the string with a shell loop.

The general idea is:

```bash
echo -n "non_existing_directory/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

This automatically creates the long sequence.

The important lesson is:

> When a payload requires a very large amount of repetitive data, automate its generation rather than manually constructing it.

---

# 22. Calculating the Length

There is an important warning with path truncation.

If you add too much data, you could accidentally truncate:

```text
/etc/passwd
```

instead of only truncating:

```text
.php
```

So the complete string length matters.

The source therefore says that you should calculate the full length to make sure the desired file path remains intact.

---

# 23. Null Bytes

Another historical technique involved **null byte injection**.

Older PHP versions before approximately **5.5** were vulnerable to this behavior.

The null byte is represented in URL-encoded form as:

```text
%00
```

Historically, adding a null byte could terminate the string so that anything after it was ignored.

---

# 24. How Null Byte Injection Worked Historically

Suppose the application automatically added:

```text
.php
```

to the supplied value.

Conceptually:

```text
Input:
target%00

Application appends:
.php

Result:
target%00.php
```

Historically, the null byte could terminate the string before `.php`.

So the system would effectively process:

```text
target
```

rather than:

```text
target.php
```

This allowed older applications to bypass certain appended-extension restrictions.

---

# ⭐ 25. Why Null Bytes Worked

The source explains that this behavior is related to how strings were historically represented at a low level.

Languages/environments such as:

- Assembly
    
- C
    
- C++
    

traditionally use a null byte to indicate the end of a string.

Therefore:

```text
STRING + \0 + MORE DATA
```

could historically be interpreted as:

```text
STRING
```

with everything after the null byte ignored by certain operations.

---

# 26. Modern Relevance

This distinction is **very important**:

### Modern PHP

Many of these historical bypasses no longer work.

### Older PHP

They may still be relevant when dealing with legacy systems.

So don't memorize them as universally working techniques.

Instead remember:

```text
Modern PHP
    ↓
Historical truncation/null-byte tricks
    ↓
Generally obsolete
```

The source explicitly describes these as techniques that may only work on older PHP versions.

---

# 🧠 27. Complete Bypass Map

```text
                    LFI FILTER
                        │
        ┌───────────────┼────────────────┐
        │               │                │
        ▼               ▼                ▼
   ../ blacklist     Encoding       Approved path
        │               │                │
        ▼               ▼                ▼
 Non-recursive       URL encode      Approved prefix
 filtering           characters          │
        │               │                 ▼
        ▼               ▼             Traversal
 Recursive-style      Decode             │
 representation      later              ▼
        │                               Target
        └───────────────┬────────────────┘
                        │
                        ▼
                  File Inclusion
```

---

# ⭐ 28. Important Filter Weaknesses

|Protection|Potential Weakness|
|---|---|
|`str_replace('../', '')`|Non-recursive transformation|
|Character blacklist|Alternate/encoded representations|
|URL filtering|Encoding/decoding differences|
|Approved prefix|Validation may not prevent traversal afterward|
|Appended `.php`|Historically bypassable on older PHP|
|Direct-input validation|May miss values stored and used later|

---

# 🔥 29. The Most Important Concept: Transformation

When dealing with an LFI filter, don't ask only:

> "Is `../` blocked?"

Ask:

> **"What does my input become after the filter processes it?"**

For example:

```text
INPUT
....//

      ↓ filter removes ../

OUTPUT
../
```

The output is now something the path parser may interpret as traversal.

That's the fundamental lesson behind **non-recursive filter bypasses**.

---

# 🎯 30. Code Audit Perspective

When you see:

```php
$language = str_replace('../', '', $_GET['language']);
```

ask:

```text
1. What exactly is being filtered?
2. Is filtering recursive?
3. Is decoding performed before or after filtering?
4. Is normalization performed?
5. Is the final path validated?
6. Is an approved directory checked?
7. Is a prefix added?
8. Is an extension appended?
9. Does the vulnerable sink read or execute?
```

---

# 📝 31. Exam / Interview Questions

### Q1. What is a non-recursive filter?

A filter that processes the input once but does not repeatedly process the resulting output.

### Q2. Why is a simple `str_replace('../', '')` filter weak?

Because specially constructed input can cause the filtering operation to remove part of the string while leaving another traversal sequence in the resulting output.

### Q3. What is URL encoding?

Representing characters using encoded representations such as:

```text
. → %2e
/ → %2f
```

so the application may later decode them back into their original representation.

### Q4. What is double encoding?

Encoding an already encoded representation again.

### Q5. What is an approved-path restriction?

A validation mechanism intended to ensure that the included file is located beneath a specific approved directory.

### Q6. Why can an approved-path regex still be problematic?

If it checks only the initial prefix and doesn't properly canonicalize/validate the final resolved path, traversal may potentially escape the intended directory.

### Q7. Are path truncation and null-byte techniques modern PHP techniques?

**No.** The source explicitly describes them as historical/obsolete techniques associated with older PHP versions.

---

# ⭐ 32. FINAL CHEAT SHEET

```text
╔══════════════════════════════════════════════════════════════╗
║                  BASIC LFI BYPASSES                         ║
╠══════════════════════════════════════════════════════════════╣
║ 1. NON-RECURSIVE FILTER                                     ║
║                                                            ║
║ Filter: str_replace('../', '', input)                      ║
║                                                            ║
║ Problem: filter runs once                                  ║
║                                                            ║
║ Key idea: understand the transformed output                ║
╠══════════════════════════════════════════════════════════════╣
║ 2. ENCODING                                                ║
║                                                            ║
║ ../ → encoded representation                               ║
║                                                            ║
║ Filter may see encoded data                                ║
║ Application may decode it later                            ║
║                                                            ║
║ Double encoding may also matter                            ║
╠══════════════════════════════════════════════════════════════╣
║ 3. APPROVED PATH                                           ║
║                                                            ║
║ Regex expects: ./languages/                                ║
║                                                            ║
║ Important question:                                       ║
║ Does validation check the FINAL resolved path?              ║
╠══════════════════════════════════════════════════════════════╣
║ 4. APPENDED EXTENSION                                      ║
║                                                            ║
║ include(input . ".php")                                    ║
║                                                            ║
║ Modern PHP → historical bypasses generally unavailable     ║
║ Older PHP → truncation/null-byte techniques existed        ║
╠══════════════════════════════════════════════════════════════╣
║ 5. PATH TRUNCATION                                         ║
║                                                            ║
║ Historical PHP limitation: ~4096 characters                ║
║                                                            ║
║ Goal: cause appended extension to fall beyond the limit    ║
╠══════════════════════════════════════════════════════════════╣
║ 6. NULL BYTE                                               ║
║                                                            ║
║ Historical representation: %00                             ║
║                                                            ║
║ Could terminate strings before appended extension          ║
║                                                            ║
║ Obsolete on modern PHP                                     ║
╠══════════════════════════════════════════════════════════════╣
║ GOLDEN RULE                                                ║
║                                                            ║
║ INPUT → FILTER → DECODE → NORMALIZE → FINAL PATH → SINK    ║
║                                                            ║
║ Understand every transformation.                           ║
╚══════════════════════════════════════════════════════════════╝
```

## 🧠 One-line takeaway

> **LFI bypasses are fundamentally about understanding how the application transforms your input before the file-loading function receives it.**

The source's techniques—non-recursive filtering, encoding, approved paths, appended extensions, historical path truncation, and null bytes—are different examples of that same underlying idea.