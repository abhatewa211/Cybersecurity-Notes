# 1. Introduction to Command Injection

## 🔥 What is Command Injection?

**OS Command Injection** is a vulnerability where **user-controlled input influences an operating-system command executed by the server**.

If an application takes user input and directly places it inside a system command without proper validation or safe command construction, an attacker may be able to alter the intended command and execute additional commands.

### Basic concept

```text
User Input
    ↓
Web Application
    ↓
OS Command
    ↓
Operating System
```

If the application expects:

```bash
ping -c 1 127.0.0.1
```

but the attacker can influence the command structure, the resulting command could become:

```bash
ping -c 1 127.0.0.1; whoami
```

The key problem is:

> **The application treats attacker-controlled data as part of the command syntax rather than purely as data.**

---

# 2. What Are Injection Vulnerabilities?

Injection vulnerabilities occur when **user-controlled input is interpreted as part of a query, command, or code** rather than remaining ordinary data.

OWASP categorizes injection as one of the major web application security risks.

![Image](https://images.openai.com/static-rsc-4/TUaUHZzXO6EvLf8adZUdv5FkuEfyW9FFgU4I4pQFprrYLk2Y6opnxrs46GKtM9ru5DPQ7UOHqluStSIKkqAGi1xhHq4eQorPnjEp7sHk5osAWNQqup9DtvCFZKMywzHMj4mC25lW6dGfqNovBum2c-3AgUKQ9Bh7VyhtBAe5kWD-n_fD5jfk7J6cgMXTBXmC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/t-ETEVKr-aG4JvLOUfWhj1hmCf7zfAzaQHEwvm-OiHJe8U0HPtLTe_pI6fMaSrNGFpe5DPZNrSGDzfN6uDUTpQDJwAgTBx51uWcE21qdNWRGP2afi7TVBzscVQFmPFTnfohrrzyY7K7RqqznGwAKa8liMaDP1rmy_QnyJvG5Sj6e2UFGmbSvxTF3TJDcchVY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AMn6kdvEJT1V5hYWBg_Ohj1SRgY0kqTDwW2B3dZuXKujRLcm0hJgci0RwZ_xQYUyINeiep15w-nDDkT1uRN5P6tKbB9JpHLNwphUA3NmjsgVybpHJ5jFUrqNCWWQ1ulOpgWfKeZYu0gC-QPHHAK4bHhSBdF2dK6m2DWG1J2SzZncTr0MQuq5XAc3ylSnge6T?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Jr4arF-p8MkfjA4-BnmrjK-hJ7pOt5w53dzGAibXiuFsjGHUH5Qrbio8oeoUSPGRDeav24PPlhT1F9DivFysuOR4IYBi2pwJY9LGbL9K5tDMkL7h7b_y_1d6yMDd6TxmqlOW5ZmsrkI_9DOftJ5UQN2tVt72qkEyaib2r-kxxTv9AD6z8qAHAEtVnzpqlSKh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fC_8kvwTzmuluIJ9BiDyuUzeEsEL8YHJ5_3rYTm_KxCsO5y_P9KpuRGhlElwQY6PBCtoF72SbhAhve5vNwx4b1zo8yW-tC_uqLNukpPImX9nc3ZxUcx__7iCyYCJlWRxSJZ7wjiM5dsV2f82o7Ecg0aoH0NLmW8ugvN4rDCa_XZmi1liHOOy84SoOmtGo3ak?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DVMMiuXd3hcsWe7FobDQiRsCaMifD2SEtUXSrXHySFyCMm7vX451MM91oB-YDQyO3wf21-Q12S48yuxSUc4vfCGwqSTAfdMW1c2gEJGQlJLT_HBmx_BYHqgULs8pMp1g8WQetue5vW55Q5XLntu0AQqAwx8D0TBKhH0UGar3Snb-a6-qhC2hPdbcI9BR27h0?purpose=fullsize)

## Common Injection Types

|Injection|Description|
|---|---|
|**OS Command Injection**|User input becomes part of an OS command|
|**Code Injection**|User input becomes part of evaluated code|
|**SQL Injection**|User input becomes part of an SQL query|
|**XSS / HTML Injection**|User-controlled input is interpreted/displayed as HTML or script|
|LDAP Injection|Input manipulates LDAP queries|
|NoSQL Injection|Input manipulates NoSQL queries|
|HTTP Header Injection|Input modifies HTTP headers|
|XPath Injection|Input manipulates XPath queries|
|IMAP Injection|Input manipulates IMAP commands|
|ORM Injection|Input manipulates ORM-generated queries|

### Core idea

```text
Unsanitized Input
       ↓
   Query / Code
       ↓
  Interpretation
       ↓
Unexpected Behavior
```

The attacker attempts to **escape the intended boundaries of the input** and influence the surrounding command/query.

---

# 3. OS Command Injection

For OS command injection to occur, attacker-controlled input must **directly or indirectly affect a system command**.

Almost every major programming language has mechanisms for executing OS commands.

Examples:

### PHP

Common functions include:

```text
exec()
system()
shell_exec()
passthru()
popen()
```

### Node.js

Common mechanisms include:

```text
child_process.exec()
child_process.spawn()
```

---

# 4. PHP Vulnerable Example

Consider:

```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

The intended command is:

```bash
touch /tmp/<filename>.pdf
```

The problem is that:

```text
$_GET['filename']
```

is directly inserted into the command.

### Secure design principle

User input should be treated as **data**, not command syntax.

---

# 5. Node.js Vulnerable Example

```javascript
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

Again:

```text
req.query.filename
        ↓
command string
        ↓
child_process.exec()
```

If the input can influence shell syntax, command injection may occur.

---

# 6. Important Observation

Command injection is **not specific to PHP**.

It can occur in:

- PHP
    
- Node.js
    
- Python
    
- Java
    
- .NET
    
- Ruby
    
- Go
    
- C/C++
    
- Shell scripts
    
- Thick-client applications
    
- Custom binaries
    

The underlying issue is the same:

> **Untrusted input reaches a command-execution mechanism in an unsafe way.**

---

# 7. Detection

Basic command injection detection and exploitation often involve determining whether additional command syntax changes the application's behavior.

A simplified process:

```text
Normal Input
     ↓
Observe Normal Behavior
     ↓
Test Command Syntax
     ↓
Observe Response
     ↓
Different Output?
     ↓
Potential Command Injection
```

Advanced cases may require:

- Fuzzing
    
- Code review
    
- Understanding application behavior
    
- Identifying filters
    
- Blind injection techniques
    
- Indirect injection analysis
    

The material here primarily focuses on **direct command injection**, where command output is returned to us.

---

# 8. Host Checker Example

Imagine a web application:

```text
+-----------------------------+
|       HOST CHECKER          |
|                             |
| Enter an IP Address:        |
| [ 127.0.0.1              ]  |
|                             |
|          [ Check ]          |
+-----------------------------+
```

![Image](https://images.openai.com/static-rsc-4/tCGEi45GDT7uRufOKEXJTRN1Up5GCLUagDtqkaNy9pnEza6sWXnyP7k5cm7iYxOUoFkLuDIzLc3RPwMcR17DFZqpf0QlcD-tLy2xTPekHMtmaRWi1ffXxQJefDtjzMGAvGhfWdI56N2HiqQT2XnmD1oa7WajdKEjpXwBksJZ0D78_HvCgoGNMApkg-K5gOop?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/65a2XYidROa9IYp74a1Kjy6UyIS5q7b0zWbjsgU1YT5gSosv65xntPi0wlSI4t4B0QI8PhjZOumgXj2dziuuNIUHSTgfi4-YC2sx9xL4YEfj483yll24iCMJCBptfL_oZJi50VdDfIELxeiZ16z1IusZAUiSedwx1P8qHNyk0Pa42JOVHoEvlQMHEdOkL3yY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ox_m6ei3FFRQC_fYZPFKyf7375uymtEYXBBmMTfJxDuBNU1KvgoWIbJrdmWp58CE2LUcmxe4ngr5ryaLP8nCyfPUOFdxvyjeTewCjCykjAasf8t2dSoQts5cL0nxn5byK6hAFlW8io2dcOZA9r4uqblHMPSWBrVvnG5X5VRRNtRkIKxlC0yWG2am0SGMbKMw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gOuwIMN3tZse5BgO5kfzS2Clj0U84qT6qiVgGPck0UsJ1vKbRjRAWV_KlrgqrA8rC-xsEX1eMha-PddfqSn2NJ1Cyc_Z7CFJ59eP4tYe74cxRkwJfnicthJjffQHd6lWeyWz2U5qDwTGOpl_r_p7TSUnqlx8GM20j-I3JMAHW7LoEYRnTZZ1_xTNH_moEbs5?purpose=fullsize)

Entering:

```text
127.0.0.1
```

produces ping output.

We can reasonably infer that the backend may be performing something similar to:

```bash
ping -c 1 OUR_INPUT
```

This is an important testing principle:

> **You don't always need source code to infer potentially dangerous backend behavior. Application behavior can provide clues.**

---

# 9. Command Injection Operators

Different shell operators can alter how commands execute.

|Operator|Character|URL Encoding|Behavior|
|---|--:|--:|---|
|Semicolon|`;`|`%3b`|Both commands|
|New line|`\n`|`%0a`|Both|
|Background|`&`|`%26`|Both; output behavior varies|
|Pipe|`\|`|`%7c`|Output generally from second command|
|AND|`&&`|`%26%26`|Second executes if first succeeds|
|OR|`\|`|`%7c%7c`|Second executes if first fails|
|Subshell|`` ` ` ``|`%60%60`|Both, Linux-oriented|
|Subshell|`$()`|`%24%28%29`|Both, Linux-oriented|

### 🧠 Memorize

```text
;    → unconditional separation
&&   → execute next if SUCCESS
||   → execute next if FAILURE
|    → pipe output
&    → background / command separation
\n   → command separation
```

---

# 10. Semicolon Operator

Suppose the application executes:

```bash
ping -c 1 127.0.0.1
```

Appending:

```text
; whoami
```

results conceptually in:

```bash
ping -c 1 127.0.0.1; whoami
```

The shell interprets this as **two commands**.

```text
Command 1
    ↓
ping

;

Command 2
    ↓
whoami
```

---

# 11. Front-End Validation

Sometimes the application refuses an input such as:

```text
127.0.0.1; whoami
```

and displays:

```text
Match the requested format
```

This does **not necessarily mean the backend is secure**.

A crucial distinction:

### Front-end validation

```text
Browser
   ↓
JavaScript validation
   ↓
Backend
```

### Backend validation

```text
Browser
   ↓
Backend validation
   ↓
Command execution
```

If validation exists only in JavaScript, a user can potentially bypass it by sending a request directly to the backend.

---

# 12. Detecting Client-Side Validation

Browser developer tools can help determine whether a request is actually being sent.

If:

```text
Invalid input
```

appears but **no HTTP request is generated**, validation likely happened on the client side.

This is a valuable diagnostic distinction:

> **No request = investigate client-side validation.**

---

# 13. Burp Suite / Proxy Concept

A web proxy can be used in an authorized lab to inspect and modify requests.

Typical workflow:

```text
Browser
   ↓
Proxy
   ↓
Web Server
```

Instead of:

```text
Browser ─────────→ Web Server
```

A proxy such as Burp Suite or ZAP allows you to inspect the request before it reaches the server.

![Image](https://images.openai.com/static-rsc-4/bywugeXox7kJtgNhxChPW_ZUq3syWooEHdyIfMC8cWxNr3jNwBG_7EXVP2HRakrwkQXYlkc1Wvekvj2PN42J-rHmxt7Ccj_pYHntE4_240nAuDn7UJ1Xtv1snvQWFIZBqJLA5NlXGE486Ofjl93bXXSuIw4if6lBx0PzyIM2WgDEtKkt7ibBN8LqIXn7fDpo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/igDhuXvMOaTEiUOkXRbUsiSSIzibMKfSHz4CJz65EKZUXVAgQBzPvgzFJgDOiAorQ1c6pAgD7TanuxPWJ2JiNaQK9s-WGwGo_bNN4hrQLQqIau1k1fhtZmZtvin3iefQtT6baayR18Y-3PTnCqkiNl9TK6nFUL7kVP2qsSPbh_iLHn3H8tfALumBpnNl_rZd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_a2QVIUhtxh4w-rewKQw36XFznlEojzWt9IpZ-5DCb59HeujyaDY-bpWMn7QKA4QzEN88SC7qzF6QbBXEDSE_lbL4GiEIOuN-aRAxdPRSR4FjncBMUZ-6ZtrWw0ThJceihyNhj6Dbs3b3doNPfrEzCaQnmplTwOuEjlw16IEzBYgV0BVQ-Tap4teHBwWMly-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CXG-rbmOITu8AmMPANKcNEkX3fOlhYtyl5cg_J4yQRmNpqFvToP_rVzStZ7z_sAhTyczsc4qdXBAfKJCfcFnQrpH9NCFT6fqsw6n7w1g3jDhOdTfqX63E-M_xjzMN9eqF4x_WhmhEZ0vGQ1TuZxW7wHa8A-9hQxPU9sIX9zEm_5bHmuXnP016L_ujTdOXpe6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8wYB767pCq-6Af2J6ls3xFbTUVSaWU5aBMhef9d7AGC5y_Loz0jbO_065anFu3qfnOCsk09ZLtu5xtJbcQxN8xURYOvmGoYnAVtSD7XghCObzFzN-ByggwKjukJVKbz_35TEp4L6N_RuS4KufINqUfJWRE_DFgpDWiiSsIQQ9G43aHnrnmxW8jS-6rWE3Qvu?purpose=fullsize)

### Important concept

Client-side validation can usually be bypassed by **constructing the HTTP request independently**, because JavaScript restrictions in the browser are not inherently security controls.

---

# 14. AND Operator — `&&`

Example:

```bash
ping -c 1 127.0.0.1 && whoami
```

Execution logic:

```text
ping succeeds?
      │
     YES
      ↓
 execute whoami
```

If the first command fails:

```text
ping fails
   ↓
whoami NOT executed
```

### Key rule

> `&&` → execute the second command **only when the first succeeds**.

---

# 15. OR Operator — `||`

Example:

```bash
ping -c 1 127.0.0.1 || whoami
```

Since the ping succeeds, the second command isn't executed.

```text
ping succeeds
     ↓
   STOP
```

But if the first command fails:

```text
ping fails
    ↓
whoami executes
```

### Key rule

> `||` → execute the second command **only when the first fails**.

This makes `||` useful for understanding command exit status and conditional execution.

---

# 16. Command Exit Codes

Shell commands generally return an exit status.

The important values here are:

```text
0       → success
non-zero → failure
```

Therefore:

```bash
command1 && command2
```

means:

```text
Run command2 if command1 == 0
```

while:

```bash
command1 || command2
```

means:

```text
Run command2 if command1 != 0
```

---

# 17. Injection Operator Comparison

### `;`

```text
command1 ; command2
```

→ Execute both independently.

### `&&`

```text
command1 && command2
```

→ Execute command2 only if command1 succeeds.

### `||`

```text
command1 || command2
```

→ Execute command2 only if command1 fails.

### `|`

```text
command1 | command2
```

→ Pipe output from command1 into command2.

---

# 18. Identifying Filters

Applications may implement defensive filtering.

One approach is a **blacklist**.

Example:

```php
$blacklist = ['&', '|', ';'];

foreach ($blacklist as $character) {
    if (strpos($_POST['ip'], $character) !== false) {
        echo "Invalid input";
    }
}
```

The application searches the input for forbidden characters.

---

# 19. Application Filter vs WAF

An important distinction:

### Application-level filtering

The application's own code detects the input.

```text
Request
 ↓
Application
 ↓
Filter
 ↓
"Invalid input"
```

### WAF filtering

A Web Application Firewall may intercept the request before it reaches the application.

```text
Request
 ↓
WAF
 ↓
Blocked
 ↓
Application never receives request
```

The response characteristics can sometimes provide clues about which layer blocked the request.

---

# 20. Methodology for Identifying Filters

Instead of testing a complex payload immediately, isolate components.

Suppose:

```text
127.0.0.1; whoami
```

is blocked.

Break it down:

```text
127.0.0.1
127.0.0.1;
127.0.0.1; 
127.0.0.1; whoami
```

This helps identify **which component triggers the filter**.

### General methodology

```text
Known-good input
       ↓
Add ONE element
       ↓
Observe response
       ↓
Blocked?
       ↓
Identify offending component
```

This is essentially controlled experimentation.

---

# 21. Blacklisted Characters

Commonly filtered characters can include:

```text
;
&
|
space
/
\
```

The exact blacklist depends entirely on the application.

---

# 22. Newline as an Alternative Separator

If common operators are blocked, a newline may behave as a command separator in relevant shells.

URL encoding:

```text
\n
```

becomes:

```text
%0a
```

Conceptually:

```text
command1
command2
```

can be interpreted as two commands.

**Important:** behavior depends on the shell, input handling, and application context.

---

# 23. Space Filtering

Suppose spaces are blocked.

Normal command:

```bash
whoami
```

doesn't require a space.

But:

```bash
command argument
```

does.

This creates a challenge because:

```text
command
   +
space
   +
argument
```

may be rejected.

---

# 24. Tabs — `%09`

A tab can act as whitespace in many command-line contexts.

URL encoding:

```text
Tab → %09
```

Conceptually:

```text
command<TAB>argument
```

instead of:

```text
command argument
```

### Key idea

> **Filtering one whitespace representation doesn't necessarily eliminate all whitespace.**

---

# 25. `$IFS` — Linux

Linux shells provide the `$IFS` variable.

`IFS` means:

> **Internal Field Separator**

It commonly contains whitespace characters.

For example:

```bash
${IFS}
```

can sometimes substitute for a literal space in shell syntax.

Conceptually:

```text
command${IFS}argument
```

instead of:

```text
command argument
```

---

# 26. Brace Expansion

Bash supports brace expansion.

Example:

```bash
{ls,-la}
```

The shell expands the expression in a way that allows the arguments to be formed without explicitly typing the conventional space.

This demonstrates a broader lesson:

> Shell parsing provides multiple syntactic representations of operations that may look different to a simple blacklist.

---

# 27. Bypassing Other Blacklisted Characters

A particularly interesting example is `/`.

Linux commands frequently need `/` for paths:

```text
/etc/passwd
/tmp/file
/usr/bin/...
```

If `/` is filtered, environment variables can sometimes contain that character.

---

# 28. Linux Environment Variables

Example:

```bash
echo ${PATH}
```

could produce:

```text
/usr/local/bin:/usr/bin:/bin:/usr/games
```

Since `/` appears in `$PATH`, substring expansion can retrieve it.

Example:

```bash
${PATH:0:1}
```

produces:

```text
/
```

### Syntax

```text
${VARIABLE:start:length}
```

For example:

```text
${PATH:0:1}
```

means approximately:

```text
Start at character 0
Take 1 character
```

---

# 29. Extracting Other Characters

Environment variables can contain other useful characters.

For example, a variable containing:

```text
...
;
...
```

could potentially be indexed to retrieve `;`.

The general technique is:

```text
Environment variable
        ↓
Find desired character
        ↓
Determine its position
        ↓
Extract one character
```

Useful discovery command:

```bash
printenv
```

This prints environment variables.

---

# 30. Windows Environment Variables

The same general idea can work on Windows.

Example:

```cmd
echo %HOMEPATH%
```

may produce something like:

```text
\Users\htb-student
```

Character/substring expansion can then be used to extract a desired character.

Example from the material:

```cmd
echo %HOMEPATH:~6,-11%
```

produces:

```text
\
```

---

# 31. PowerShell Character Indexing

PowerShell treats strings in a way that allows character indexing.

Example:

```powershell
$env:HOMEPATH[0]
```

can retrieve the first character.

Environment variables can be enumerated using:

```powershell
Get-ChildItem Env:
```

This provides a useful way of understanding what strings are available for character extraction.

---

# 32. Character Shifting

Another technique involves using character transformations.

The basic idea:

```text
Known character
      ↓
Transformation
      ↓
Desired character
```

For example, ASCII values can be used to identify a character immediately before another character.

The material demonstrates this using:

```bash
tr
```

and character ranges.

### Important concept

You don't necessarily need to type the target character literally if the shell can **derive it dynamically**.

---

# 33. Command Blacklists

Character filters aren't the only possible defense.

An application may also blacklist commands:

```text
whoami
cat
id
ls
...
```

For example:

```php
$blacklist = ['whoami', 'cat'];

foreach ($blacklist as $word) {
    if (strpos($_POST['ip'], $word) !== false) {
        echo "Invalid input";
    }
}
```

If the exact word appears, the request is rejected.

---

# 34. Command Obfuscation

**Command obfuscation** means representing a command differently while preserving its eventual meaning to the shell.

Example:

```text
whoami
```

may be represented using shell syntax that reconstructs the same command.

The goal, from an attacker's perspective, is to make the raw input differ from the blacklist entry.

From a defender's perspective, this demonstrates why:

> **Simple string blacklists are weak security controls.**

---

# 35. Quote-Based Obfuscation

The material demonstrates inserting quotes into command names:

```bash
w'h'o'am'i
```

and:

```bash
w"h"o"am"i
```

The shell can interpret these in a way that results in the intended command.

### Important rules from the material

- Don't mix quote types incorrectly.
    
- Quotes generally need to be properly balanced.
    
- Shell behavior varies by context.
    

---

# 36. Linux-Specific Obfuscation

Linux/Bash provides additional syntax.

Examples shown:

```bash
who$@ami
```

and:

```bash
w\ho\am\i
```

These demonstrate that shell parsing can produce the intended command even when the raw string doesn't literally contain the original command word.

---

# 37. Windows-Specific Obfuscation

Windows CMD provides the caret:

```text
^
```

Example:

```cmd
who^ami
```

The caret can act as an escape character in CMD contexts.

This is another reason defenses shouldn't rely solely on matching:

```text
whoami
```

literally.

---

# 38. Case Manipulation

Another obfuscation technique is changing capitalization.

For Windows:

```powershell
WhOaMi
```

can still work because CMD and PowerShell command handling is generally case-insensitive.

### Linux difference

Linux commands are generally **case-sensitive**.

Therefore:

```text
whoami
```

and:

```text
WHOAMI
```

are not necessarily equivalent.

---

# 39. Converting Case in Bash

The material demonstrates using:

```bash
tr
```

to transform uppercase characters to lowercase.

Conceptually:

```text
WhOaMi
   ↓
lowercase conversion
   ↓
whoami
```

This demonstrates a broader principle:

> The payload can dynamically transform itself before execution.

---

# 40. Reversed Commands

Another obfuscation technique is reversing the command.

Original:

```text
whoami
```

Reversed:

```text
imaohw
```

Linux can reverse strings using:

```bash
echo 'whoami' | rev
```

Then the reversed representation can be transformed back at runtime.

The important concept is:

```text
Original command
       ↓
Reverse
       ↓
Store/transmit reversed form
       ↓
Reverse at execution time
       ↓
Original command
```

---

# 41. PowerShell Reversed Strings

PowerShell can reverse strings through array indexing and joining.

Conceptually:

```text
whoami
 ↓
imaohw
 ↓
reverse again
 ↓
whoami
```

This demonstrates that the same obfuscation concept can be implemented differently across operating systems.

---

# 42. Encoded Commands

Encoding can hide command content from simplistic filters.

Common encoding approaches include:

```text
Base64
Hexadecimal
```

Tools commonly encountered:

```text
base64
xxd
```

The workflow is:

```text
Original command
       ↓
Encode
       ↓
Send encoded representation
       ↓
Decode
       ↓
Execute
```

---

# 43. Base64 Concept

For example, a command can be Base64 encoded.

The material demonstrates encoding:

```text
cat /etc/passwd | grep 33
```

into a Base64 representation.

The encoded string doesn't visibly resemble the original command.

Then:

```text
Base64
  ↓
Decode
  ↓
Command
  ↓
Shell execution
```

---

# 44. Why Encoding Helps Demonstrate Filter Weaknesses

A blacklist looking for:

```text
cat
/etc/passwd
|
```

may not find those literal strings inside a Base64 representation.

This illustrates an important defensive lesson:

> **Filtering encoded representations without understanding decoding and execution paths is difficult.**

A secure application should avoid creating a shell execution path in the first place.

---

# 45. PowerShell Encoding

PowerShell commonly represents command content using UTF-16LE before Base64 encoding.

The material demonstrates:

```text
UTF-16LE
    ↓
Base64
    ↓
PowerShell decoding
    ↓
Execution
```

This is an important distinction because PowerShell's common encoded-command conventions differ from ordinary UTF-8 Base64 encoding.

---

# 46. Other Obfuscation Techniques

The material also mentions:

- Wildcards
    
- Regular expressions
    
- Output redirection
    
- Integer expansion
    
- Variable expansion
    
- Character insertion
    
- Command transformation
    
- Encoding
    

These techniques demonstrate how complex shell syntax can make static blacklist detection unreliable.

---

# 47. Automated Obfuscation

When manual techniques become complicated, automated tools can generate obfuscated shell commands.

Two tools discussed are:

```text
Linux → Bashfuscator
Windows → DOSfuscation
```

---

# 48. Bashfuscator

Bashfuscator is designed to generate obfuscated Bash commands.

The basic workflow is:

```text
Original Bash command
        ↓
Bashfuscator
        ↓
Obfuscated command
        ↓
Shell
        ↓
Original behavior
```

The material shows installation via its GitHub repository and Python setup process.

---

# 49. Bashfuscator Help

The tool provides a help menu:

```bash
./bashfuscator -h
```

Important options shown include:

```text
-l
--list
```

List available obfuscators, compressors, and encoders.

And:

```text
-c COMMAND
--command COMMAND
```

Specify the command to obfuscate.

---

# 50. Basic Bashfuscator Usage

Conceptually:

```bash
./bashfuscator -c 'COMMAND'
```

generates an obfuscated version.

The important point is that the output can vary substantially.

The same input command can potentially produce very different representations.

---

# 51. Bashfuscator Complexity

One important observation from the material:

> Default/randomized obfuscation can produce extremely large payloads.

Payload length can range from relatively short strings to extremely large output.

Therefore, options can be used to constrain:

- Complexity
    
- Layers
    
- Mangling
    
- Size
    
- Transformation techniques
    

---

# 52. Testing Obfuscated Commands

The material demonstrates validating the generated output locally before using it in a lab.

Conceptually:

```text
Generate
   ↓
Test locally
   ↓
Does it execute?
   ↓
Understand failure
   ↓
Adjust configuration
```

This is a good general pentesting workflow:

> **Validate assumptions locally before troubleshooting application behavior.**

---

# 53. DOSfuscation

DOSfuscation is a Windows-oriented command obfuscation project.

Unlike Bashfuscator, the material describes it as an **interactive tool**.

Basic conceptual workflow:

```text
Start tool
   ↓
Set command
   ↓
Select transformation
   ↓
Generate obfuscated command
   ↓
Test in CMD/PowerShell
```

---

# 54. DOSfuscation Categories

The material's help menu includes areas such as:

```text
BINARY
ENCODING
PAYLOAD
```

These provide different ways of transforming Windows commands.

---

# 55. Environment Variable Encoding

DOSfuscation can generate commands using pieces of Windows environment variables.

Conceptually:

```text
Environment variables
        ↓
Extract characters
        ↓
Construct command
        ↓
CMD interprets it
```

This is essentially an automated version of the environment-variable techniques discussed earlier.

---

# 56. Running PowerShell on Linux

The material also notes that PowerShell Core (`pwsh`) can be used on Linux.

This can be useful for learning/testing PowerShell behavior without a dedicated Windows machine.

However, remember:

```text
PowerShell on Linux
```

is not identical to:

```text
Windows CMD
```

or necessarily identical to every Windows PowerShell environment.

---

# 57. Big Picture — Entire Attack Chain

The entire module can be understood as a progression:

```text
             USER INPUT
                  │
                  ▼
        ┌─────────────────┐
        │ Web Application │
        └────────┬────────┘
                 │
                 ▼
           OS Command
                 │
                 ▼
              Shell
                 │
                 ▼
           Operating System
```

If input is unsafely incorporated:

```text
Normal Input
     ↓
Command Construction
     ↓
Unexpected Syntax
     ↓
Additional Command
     ↓
Unexpected Execution
```

---

# 58. Filter-BYPASS Learning Tree

A useful way to remember the entire section:

```text
                FILTER
                   │
       ┌───────────┼────────────┐
       │           │            │
    Operator     Space        Command
       │           │            │
       ▼           ▼            ▼
    newline      tab/IFS      quotes
       │         braces        $@
       │                         │
       └──────────┬──────────────┘
                  ▼
             Obfuscation
                  │
        ┌─────────┼─────────┐
        │         │         │
      Case     Reverse    Encode
        │         │         │
        └─────────┼─────────┘
                  ▼
          Automated Tools
          /            \
 Bashfuscator      DOSfuscation
```

---

# 59. Injection Operators — Quick Revision

|Syntax|Remember It As|
|---|---|
|`;`|Run next command|
|`&&`|Next command if success|
|`||
|`&`|Background/separate execution|
|`|`|
|`\n`|New command line|
|`` `...` ``|Command substitution|
|`$()`|Command substitution|

---

# 60. Filter Identification — Quick Revision

When something is blocked:

### Don't immediately assume the entire payload is blocked.

Break it down:

```text
Known-good input
      ↓
Add operator
      ↓
Test
      ↓
Add whitespace
      ↓
Test
      ↓
Add command
      ↓
Test
```

This helps determine whether the filter targets:

```text
Character
   ↓
Whitespace
   ↓
Command
   ↓
Encoding
   ↓
Pattern
   ↓
Entire request
```

---

# 61. Linux vs Windows

|Feature|Linux/Bash|Windows CMD|PowerShell|
|---|---|---|---|
|Case-sensitive commands|Generally yes|Generally no|Generally no|
|`;`|Yes|Not generally as CMD command separator|Yes|
|`&&`|Yes|Yes|Yes|
|`||`|Yes|
|`$IFS`|Yes|No|No|
|`$()`|Yes|No|Yes, with different semantics|
|Backslash techniques|Yes|Different meaning|Different|
|`^`|No|Yes|Context-dependent|
|Environment variables|`$VAR`|`%VAR%`|`$env:VAR`|
|Character indexing|Bash syntax|Variable substring syntax|String indexing|

**Always identify the actual shell/environment before assuming syntax will behave the same way.**

---

# 62. Most Important Defensive Lesson

The most important lesson from the entire module is **not** how many bypasses exist.

It is this:

> **Blacklists are not a reliable primary defense against command injection.**

If an application constructs shell commands from untrusted input, attackers may find alternate representations through:

```text
Whitespace
Encoding
Variables
Quotes
Case changes
String transformations
Shell syntax
Environment variables
Character extraction
```

Therefore, continuously adding blacklist entries can become an arms race.

---

# 63. Defensive Prevention

The strongest mitigation is to **avoid invoking a shell with untrusted input whenever possible**.

Prefer:

```text
Structured API
       ↓
Fixed executable
       ↓
Explicit arguments
```

over:

```text
User Input
    ↓
String concatenation
    ↓
Shell command
```

### Example principle

Instead of dynamically constructing:

```text
"command " + user_input
```

use an API that accepts:

```text
executable
+
argument list
```

without invoking shell interpretation.

---

# 64. Defense-in-Depth

A secure implementation should combine:

### 1. Input validation

Use strict allowlists where practical.

For an IP address:

```text
Expected:
IPv4 / IPv6 address

Reject:
Everything else
```

### 2. Avoid shell execution

Prefer native libraries/APIs.

### 3. Parameterized arguments

Keep arguments separate from command syntax.

### 4. Least privilege

The web application should run with the minimum permissions required.

### 5. Monitoring

Log suspicious input and unusual process creation.

### 6. WAF

Useful as an additional layer, **not as the primary defense**.

---

# 65. Key Takeaways 🧠

If you're preparing for a pentesting certification/lab, remember these points:

**1. Command Injection**

```text
Untrusted input → OS command → unexpected execution
```

**2. Main operators**

```text
;
&&
||
&
|
\n
$()
```

**3. `&&`**

```text
Run second command if first succeeds.
```

**4. `||`**

```text
Run second command if first fails.
```

**5. Front-end validation ≠ backend security**

Client-side restrictions can be bypassed because they aren't inherently authoritative.

**6. Identify filters systematically**

Test one character/element at a time.

**7. Space filtering**

Conceptually understand alternatives such as:

```text
Tab
IFS
Brace expansion
```

**8. Character filtering**

Understand how shell/environment mechanisms can dynamically construct characters.

**9. Command filtering**

Understand:

```text
Quotes
Case transformation
String reversal
Encoding
Variable expansion
```

**10. Linux ≠ Windows**

Shell syntax and parsing behavior differ significantly.

**11. Automated obfuscation**

```text
Bash → Bashfuscator
Windows → DOSfuscation
```

**12. Best defense**

> **Don't build shell commands from untrusted input. Use safe APIs and structured arguments instead.**

---

## 🧩 One-Minute Revision Sheet

```text
COMMAND INJECTION
│
├── Cause
│   └── Untrusted input reaches OS command execution
│
├── Detection
│   ├── Establish normal behavior
│   ├── Test syntax
│   └── Compare output/errors
│
├── Operators
│   ├── ;    → both
│   ├── &&   → second if success
│   ├── ||   → second if failure
│   ├── |    → pipe
│   ├── &    → background/separation
│   └── \n   → new command
│
├── Filters
│   ├── Characters
│   ├── Spaces
│   ├── Commands
│   └── WAF/application filters
│
├── Obfuscation concepts
│   ├── Tabs
│   ├── IFS
│   ├── Variables
│   ├── Quotes
│   ├── Case manipulation
│   ├── Reversal
│   ├── Encoding
│   └── Character transformation
│
├── Tools
│   ├── Bashfuscator
│   └── DOSfuscation
│
└── Defense
    ├── Avoid shell
    ├── Validate input
    ├── Use structured arguments
    ├── Least privilege
    └── Defense in depth
```

### ⭐ Core mental model

**Think of command injection as a parsing problem:**

> **What the developer thinks is "data" may become "shell syntax" when it reaches the command interpreter.**

Once you understand **where parsing happens, which shell is involved, how input is transformed, and where validation occurs**, the entire module becomes much easier to reason about.