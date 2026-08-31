![Image](https://images.openai.com/static-rsc-4/apFdh-s35kM7fHlkUp2Cj_DX2vmhTZJuqx-41cd-FluGdA9V32ZrLP9PKXXqPKD2U7cEGQTPHVq1sXXXnZCPFYmGzg7ksWKhifw6XBvnKrgXP3VXclWH1QOPa9WpDOU0lVqsG-zBA2H3d2nZwMim4pfD_eWRDZD8oXYetErBUSZo3NwK9oJ5zzEDhCDPI0Py?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cWTDdjWzMbKdZ0Tm1o_T51am2iFbLcOXjP868YPq39wd3VVeRfPCY3LgS63zkJM_vJDYsqVOqfueFPf0GhNQOJi9Up6-1maPXtgQKzS2-RxprmdKOnPYXH9filockVge3wwmF1MffnLQaY6jM-MVLfFLefgavfD_RtWlbLTNi24eDIRltnp0TxT3vidaqcqE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/oOaZrbZtP6wrxuMzpXW1nShkCIeYvV3i3U8VEZwtTmu2yINYZzetfbe_dPuMkNXgustfYXtdOXH0yeA6X8tAjbH7n_SBYrfhL4P4g7_TGQu9rykdmRwqAh7u1EfrmZXONRC07GBxaVRaLjy_wWlD7Xr-WCkUrTQcAqHdkEbra5leVRKTlZig6HDRnXapF_Vd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/99V8QMR31ZlwC3nBNYJqyikwyjNmW8sMmYvdKYHf_hx6oPIJGJzYBFsZpiHvw-w7G3uuMlDJKruOt-UTzQ5ZeqkKXat8JKUjRVeTW6hj6-P7RQIlDoUxc9EsWG8aKdvS7Ms9iI1XoARUD5HgJj0iBYYfP1SGa4I3HnuPB2i44IXL7Dh65kliiMfLmS6qRscc?purpose=fullsize)

## 1. Introduction

In the previous section, we learned how to identify filters that block command-injection attempts.

We discovered that a web application may blacklist:

```text
;
&
|
```

and other potentially dangerous characters.

We also learned how to identify which individual character is causing a request to be rejected.

Now we move to another common filter:

> **The space character ( )**

Space filtering is particularly common when the application expects input such as an IP address, where spaces normally should not appear.

However, shells have multiple ways of separating command arguments.

---

# 2. The Main Concept

Suppose an application blocks:

```text
space
```

A naive assumption would be:

```text
No spaces
    ↓
No command arguments
    ↓
No command injection
```

But this isn't necessarily true.

The shell may recognize other whitespace or expansion mechanisms.

Conceptually:

```text
Literal space blocked
        ↓
Try another valid separator
        ↓
Shell parses arguments
        ↓
Command executes
```

Therefore:

> **A filter that blocks one representation of whitespace does not necessarily prevent the underlying shell syntax.**

---

# 3. First: Find a Working Injection Operator

Before dealing with spaces, we need an injection operator that isn't blocked.

The lab observes that many common operators are blacklisted.

However, the **newline character** may not be blacklisted.

The newline can be represented in a URL as:

```text
%0a
```

Therefore, we can test:

```text
127.0.0.1%0a
```

---

# 4. Why Use Newline?

A newline can separate commands in supported command interpreters.

Conceptually:

```text
COMMAND_A
COMMAND_B
```

is equivalent to placing the commands on separate command lines.

The important observation from the lab is:

```text
127.0.0.1%0a
```

is accepted by the application.

Therefore:

> **The newline character is not being blocked by this particular filter.**

This gives us a usable command-separation mechanism for the lab.

---

# 5. URL Encoding

The newline character:

```text
\n
```

can be URL-encoded as:

```text
%0a
```

So:

```text
127.0.0.1
```

followed by a newline can be represented in an HTTP parameter as:

```text
127.0.0.1%0a
```

### Important Encoding Reference

```text
Newline
\n
 ↓
%0a
```

---

# 6. Testing the Space Filter

Now that we have a working injection operator, we can test whether the space character is also filtered.

The attempted payload is:

```text
127.0.0.1%0a whoami
```

Conceptually, this represents:

```text
127.0.0.1
whoami
```

with a space before `whoami`.

The application responds:

```text
Invalid input
```

Therefore, another filter is active.

---

# 7. Isolating the Space Character

As before, we don't want to guess.

We know:

```text
127.0.0.1
```

works.

We also know:

```text
127.0.0.1%0a
```

is accepted.

Now we add the next character:

```text
space
```

The request is rejected.

Therefore, we have evidence that:

> **The space character is blacklisted.**

---

# 8. Why Are Spaces Commonly Blacklisted?

Spaces are often restricted when the expected input shouldn't contain them.

For example, an IP address normally looks like:

```text
127.0.0.1
```

rather than:

```text
127.0.0.1 something
```

A developer might therefore implement a filter such as:

```text
Reject input containing spaces
```

This can reduce some obvious command-injection attempts.

However, blocking only literal spaces does not necessarily address the underlying problem.

---

# 9. The Important Question

If:

```text
space
```

is blocked, how can command arguments be separated?

The answer is that command interpreters can recognize other forms of whitespace or perform expansions that result in argument separation.

The lab demonstrates three techniques:

1. **Tabs**
    
2. **`${IFS}`**
    
3. **Bash brace expansion**
    

---

# 10. Technique 1 — Tabs

A tab is another whitespace character.

Its URL-encoded representation is:

```text
%09
```

Therefore:

```text
Tab
 ↓
%09
```

Unlike a literal space, the tab character may not be included in the application's blacklist.

---

# 11. Using a Tab

The lab tests:

```text
127.0.0.1%0a%09
```

Here:

```text
%0a
```

represents the newline, while:

```text
%09
```

represents the tab.

The application accepts the request.

This demonstrates that the filter blocks the literal space but does not block the tab.

---

# 12. Why Does a Tab Work?

Shells can generally treat horizontal whitespace such as spaces and tabs as separators between command tokens.

Conceptually:

```text
command argument
```

and:

```text
command<TAB>argument
```

can be parsed into the same basic command/argument structure.

Therefore:

```text
Literal space
     ↓
Blocked

Tab
     ↓
Accepted
     ↓
Shell recognizes whitespace
```

### Key Lesson

> **Filtering only the space character is weaker than properly validating what the application actually needs.**

---

# 13. URL Encoding Reference — Tab

Remember:

```text
Tab
\t
 ↓
%09
```

So the two important encodings introduced here are:

|Character|URL Encoding|
|---|---|
|Newline|`%0a`|
|Tab|`%09`|

---

# 14. Technique 2 — `${IFS}`

Another Linux/Bash technique discussed in the lab involves:

```text
${IFS}
```

`IFS` stands for:

> **Internal Field Separator**

It is a shell environment variable involved in how the shell separates fields/words during parsing and expansion.

In common shell environments, its default value includes whitespace characters such as:

```text
space
tab
newline
```

Therefore, `${IFS}` can sometimes function as whitespace within shell syntax.

---

# 15. Basic Concept of `${IFS}`

Conceptually:

```text
${IFS}
   ↓
Shell expands variable
   ↓
Whitespace-related characters
   ↓
Arguments can be separated
```

The important point is that the input does not contain a literal space character.

---

# 16. Lab Test With `${IFS}`

The lab tests:

```text
127.0.0.1%0a${IFS}
```

The application does not reject the request.

Therefore:

```text
space
```

was successfully avoided while still supplying shell-recognized whitespace through variable expansion.

---

# 17. Important `${IFS}` Detail

It is useful to understand that `${IFS}` isn't literally a synonym for "one space."

Its exact value depends on the shell/environment.

Commonly, `IFS` contains whitespace characters used for field splitting.

Therefore:

```text
${IFS}
```

can behave as a separator in contexts where the shell performs the relevant expansion.

### Important Mental Model

```text
Literal space
     ↓
Filtered

${IFS}
     ↓
Variable expansion
     ↓
Whitespace
     ↓
Shell parsing
```

---

# 18. Technique 3 — Bash Brace Expansion

Another technique demonstrated by the lab is:

## Brace Expansion

Bash supports brace expansion using:

```text
{...}
```

For example:

```bash
{ls,-la}
```

The lab demonstrates:

```bash
{ls,-la}
```

producing the equivalent argument structure needed to execute:

```bash
ls -la
```

without explicitly writing a literal space between `ls` and `-la`.

---

# 19. Understanding the Example

Normally:

```bash
ls -la
```

contains a space.

With brace expansion:

```bash
{ls,-la}
```

Bash expands the comma-separated values into separate words in the appropriate command-expansion context.

The resulting command executes successfully in the demonstrated environment.

---

# 20. Why Brace Expansion Is Interesting

The important lesson is not simply:

```text
{ls,-la}
```

but rather:

> **Shell expansion features can transform an input representation before command execution.**

Therefore, a filter operating only on the raw input may not understand how the shell will ultimately interpret it.

Conceptually:

```text
Raw Input
   ↓
Shell Expansion
   ↓
Parsed Command
   ↓
Execution
```

This is one reason simplistic blacklist-based defenses can be fragile.

---

# 21. Applying Brace Expansion to the Lab

The lab demonstrates a command-injection form using:

```text
127.0.0.1%0a{ls,-la}
```

The important parts are:

```text
%0a
```

→ newline command separation

and:

```text
{ls,-la}
```

→ Bash brace expansion

The command can therefore be constructed without a literal space between:

```text
ls
```

and:

```text
-la
```

---

# 22. Comparing the Three Techniques

|Technique|Representation|Main Idea|
|---|---|---|
|**Tab**|`%09`|Use another whitespace character|
|**`${IFS}`**|`${IFS}`|Use shell variable expansion|
|**Brace Expansion**|`{ls,-la}`|Use Bash expansion to construct arguments|

---

# 23. Overall Filter-Bypass Concept

The application is effectively trying to prevent:

```text
space
```

But the shell supports multiple ways of representing or producing whitespace/separating arguments.

Conceptually:

```text
             SPACE FILTER
                  │
         ┌────────┼────────┐
         │        │        │
       SPACE      TAB     ${IFS}
         │        │        │
       BLOCK    MAY WORK  MAY WORK
```

And Bash features can introduce additional transformations, such as brace expansion.

---

# 24. Why Blacklist-Based Filtering Is Fragile

Imagine a filter:

```php
if (strpos($input, ' ') !== false) {
    reject();
}
```

This only answers:

> "Does the raw input contain the literal space character?"

It does **not** necessarily answer:

> "Will the eventual command contain argument separators after all parsing and expansion?"

That's a major distinction.

---

# 25. Raw Input vs Interpreted Input

This is a very important security concept.

### Raw input

What the application receives:

```text
127.0.0.1%0a%09
```

### Decoded input

After URL decoding:

```text
127.0.0.1
<TAB>
```

### Shell interpretation

The shell then parses the command according to its syntax and expansion rules.

Therefore:

```text
HTTP encoding
      ↓
URL decoding
      ↓
Application processing
      ↓
Shell parsing/expansion
      ↓
Command execution
```

Every layer can transform the data.

---

# 26. Why Encoding Matters

A tester must understand the difference between:

```text
representation
```

and:

```text
meaning
```

For example:

```text
%09
```

is an HTTP/URL representation of a tab character.

The server may decode it before passing the resulting character onward.

Similarly:

```text
%0a
```

represents a newline.

Therefore, filters must account for the transformations performed before the security-sensitive operation.

---

# 27. Filter Testing Methodology

The methodology used in this section is extremely important.

### Step 1 — Establish baseline

```text
127.0.0.1
```

Result:

```text
Accepted
```

### Step 2 — Identify a usable separator

```text
127.0.0.1%0a
```

Result:

```text
Accepted
```

### Step 3 — Add a literal space

```text
127.0.0.1%0a whoami
```

Result:

```text
Blocked
```

### Step 4 — Test alternative whitespace

Tab:

```text
%09
```

Result:

```text
Accepted
```

### Step 5 — Test shell expansion

`${IFS}`

Result:

```text
Accepted in the demonstrated environment
```

### Step 6 — Test Bash-specific expansion

```text
{ls,-la}
```

Result:

```text
Executed in the demonstrated Bash environment
```

---

# 28. Important Environment Dependency

These techniques are **not universal**.

Their behavior depends on things such as:

- Operating system
    
- Shell
    
- Shell configuration
    
- Command execution method
    
- Application framework
    
- Input decoding
    
- Filtering implementation
    

For example:

```text
Bash-specific feature
       ↓
May not behave the same
in another shell
```

Therefore:

> **Always determine what interpreter/environment is actually processing the input.**

---

# 29. Security Perspective

The important lesson isn't simply how to get around a space blacklist.

The deeper lesson is:

> **Security filters should protect the dangerous operation, not merely search for a few suspicious characters.**

A blacklist such as:

```text
;
&
|
space
```

may stop obvious payloads, but it can be difficult to enumerate every possible representation and parsing behavior.

---

# 30. Better Defensive Approach

From a defensive perspective, applications should avoid constructing shell commands from untrusted input whenever possible.

Instead of:

```text
User Input
    ↓
String concatenation
    ↓
Shell command
```

prefer:

```text
User Input
    ↓
Strict validation
    ↓
Safe API / argument handling
    ↓
Specific operation
```

For example, if the application only needs to check an IP address, it should validate that the value is actually a valid IP and use a command-execution mechanism that does not unnecessarily invoke a shell.

---

# 31. Important Security Principle

### ❌ Weak approach

```text
Block:
;
&
|
space
```

### ✅ Stronger approach

```text
Validate expected input
        +
Avoid shell interpretation
        +
Use safe APIs / argument separation
        +
Apply least privilege
```

The best defense is to prevent untrusted data from becoming shell syntax in the first place.

---

# 32. Quick Reference — Encodings

|Character / Syntax|Representation|
|---|---|
|Newline|`%0a`|
|Tab|`%09`|
|Space|`%20` or `+` in common URL-encoded form|
|Semicolon|`%3b`|
|`&`|`%26`|
|`\|`|`%7c`|

### Important

Encoding is not itself an attack or a defense.

It is a representation mechanism used when transmitting characters through HTTP.

---

# 33. Filter-Bypass Decision Tree

```text
SPACE FILTER DETECTED
          │
          ▼
Can another whitespace character
be accepted?
          │
       ┌──┴──┐
      YES    NO
       │      │
      TAB    Continue
       │      │
       ▼      ▼
   %09      Consider
             shell-specific
             parsing/expansion
```

For Bash environments, the lab demonstrates:

```text
Tab
 ↓
${IFS}
 ↓
Brace Expansion
```

---

# 34. Common Mistakes

### ❌ Mistake 1: Assuming space filtering prevents command injection

It doesn't necessarily.

---

### ❌ Mistake 2: Assuming `%09` is the same as `%20`

They represent different characters.

```text
%20 → space
%09 → tab
```

---

### ❌ Mistake 3: Assuming `${IFS}` is universally available

`IFS` is shell/environment dependent.

---

### ❌ Mistake 4: Assuming brace expansion works everywhere

Brace expansion is a Bash/shell feature and should not be assumed to work in every execution environment.

---

### ❌ Mistake 5: Ignoring decoding layers

A filter may inspect data before or after URL decoding.

You need to understand:

```text
Encoded input
     ↓
Decoded input
     ↓
Application
     ↓
Shell
```

---

# 35. Key Takeaways

### ⭐ 1. Newline can act as a command separator

In the demonstrated environment:

```text
%0a
```

was not blocked.

---

### ⭐ 2. Space was blacklisted

The payload containing a literal space produced:

```text
Invalid input
```

---

### ⭐ 3. Tabs can sometimes substitute for spaces

```text
%09
```

represents a tab.

The lab demonstrates that the tab bypassed the literal-space filter.

---

### ⭐ 4. `${IFS}` can provide shell-recognized whitespace

```text
${IFS}
```

uses the shell's Internal Field Separator variable.

---

### ⭐ 5. Bash brace expansion can construct arguments without literal spaces

Example:

```bash
{ls,-la}
```

---

### ⭐ 6. Filters are environment-dependent

What works in Bash may not work in another shell.

---

### ⭐ 7. Blacklists are fragile

Blocking a few characters does not guarantee that the underlying command-execution vulnerability has been eliminated.

---

# 36. Revision Cheat Sheet

```text
SPACE FILTER BYPASS
────────────────────────────────

Known good:
127.0.0.1

Newline:
%0a
↓
May act as command separator

Literal space:
" "
↓
BLOCKED

Tab:
%09
↓
Alternative whitespace
↓
May work

IFS:
${IFS}
↓
Shell variable
↓
Can provide whitespace
in relevant contexts

Brace Expansion:
{ls,-la}
↓
Bash expands arguments
without literal space


IMPORTANT
────────────────────────────────

Raw HTTP input
      ↓
URL decoding
      ↓
Application filtering
      ↓
Shell parsing
      ↓
Shell expansion
      ↓
Command execution
```

---

# 37. Final Mental Model

The central idea of this section is:

```text
             APPLICATION
                  │
          Blocks literal space
                  │
                  ▼
         But the shell may have
       other parsing mechanisms
                  │
       ┌──────────┼──────────┐
       │          │          │
      TAB        IFS      Brace Expansion
       │          │          │
       ▼          ▼          ▼
   whitespace  expansion   Bash expansion
       │          │          │
       └──────────┼──────────┘
                  ▼
             Shell Parsing
                  │
                  ▼
          Command Execution
```

### 🧠 One-Line Revision

> **A space blacklist only blocks the literal space representation; alternative whitespace characters and shell parsing/expansion mechanisms may still produce valid command arguments, which is why blacklist-only command-injection defenses are fragile.**

### 🔐 Defensive takeaway

The long-term solution is **not to build shell commands from untrusted input and then keep adding blacklist rules**. Validate input against what the application actually expects, use safe process/argument APIs that avoid shell interpretation where possible, and run the application with the minimum privileges required.