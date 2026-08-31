![Image](https://images.openai.com/static-rsc-4/gpxibUrIhWFIaufjtckD9ZAsP8LmF1WJ384ohnxgbhybGmYvIwheFCb9Z7-GB83c1JgSJjYyxfGrh6uzla5gZLRwrb8a_e4PsUVMUMTLmdM7HpdRDEmRzelvi7c1qqM9osA3D184_SS8wZjFSuNHw91C8YAqKmNIxJEmxbx_-n0KjN8N-B-76lk2bG7_rtqH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_X-iEL6Mbl53Z9PzRbFz6lB2d3rufKnXW5HiooMCursQvgXhVofqHdKet2paADaT8ehHM6dUQ6oaRMwVk1tG9VncaJw_QuZSNPBGRoE3J3r9TntXNwd-qpI2xz9wyOY3g-057sTzFlRKTMOUgAJZjHgX7uJa6qWTjsruIM6FAQLKaQ7KwQ5h3M89CHS4-1wZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bej2i0PDdecY-NAu9rlVjwatNYpdt6eesbv5RdubgJhrCM3i-1qAkvzshesXzp3jdu0lcRE3DBfleuYB7NSON9NFsb7Cjo_HHlfpFUc6a04krxrSf9qBw-Dg2v8nrwQ63nZw2PZQ9o4xnBMZ4VupkVfhrRguo09fWFVTEDDkwcChbedPpvKyOQAWdsu06HFc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/snvblhrHhu3Bmr4dIzmBx1Z_4VECTiM4bakPbGhK1ITUdfzE_8Omzptml5w_jshwZmfGk-5sm94Z02cr77c2qxN2I5NnGwh1Ddq_UN8Au6n_x-XLtvFsEYSDy-cQ-J2UCxt9RK96clrBTNqSKnd4D8uM4sLslrcp4mymPw_QLvWRRK4NEHgEQr4WMrQLl3HP?purpose=fullsize)

# 

## 1. Why Character Filters Matter

After bypassing:

- Injection operators
    
- Spaces
    

we may encounter another layer of filtering.

A common example is blocking:

```text
/
\
;
```

These characters can be important because:

- `/` is used for Linux paths.
    
- `\` is used for Windows paths.
    
- `;` can be used as a command separator in many shell contexts.
    

For example:

```bash
cat /etc/passwd
```

requires `/`.

If `/` is blacklisted, simply typing:

```text
/etc/passwd
```

may cause the request to be rejected.

The key idea in this section is:

> **Instead of directly typing a blocked character, we can sometimes generate that character through shell/environment features.**

---

# 2. Linux Environment Variables

Linux systems contain many environment variables.

You can view them with:

```bash
printenv
```

or inspect an individual variable:

```bash
echo "$PATH"
```

For example:

```bash
echo ${PATH}
```

might produce:

```text
/usr/local/bin:/usr/bin:/bin:/usr/games
```

Notice that the value contains multiple `/` characters.

This gives us an opportunity.

Instead of directly typing:

```text
/
```

we can extract `/` from an existing variable.

---

# 3. Bash Parameter Expansion

The important syntax is:

```bash
${VARIABLE:start:length}
```

For example:

```bash
${PATH:0:1}
```

means:

```text
Variable → PATH
Start   → 0
Length  → 1
```

So Bash extracts one character beginning at position `0`.

Given:

```text
/usr/local/bin:/usr/bin:/bin
^
0
```

the character at position `0` is:

```text
/
```

Therefore:

```bash
echo ${PATH:0:1}
```

produces:

```text
/
```

---

# 4. Important Point: `echo` Isn't Part of the Bypass

The lab uses:

```bash
echo ${PATH:0:1}
```

only so we can **see what character was extracted**.

When using the expansion as part of another command, the `echo` is not required.

The important component is:

```bash
${PATH:0:1}
```

which evaluates to:

```text
/
```

---

# 5. Visualizing `${PATH:0:1}`

Think of `$PATH` as a string:

```text
/usr/local/bin:/usr/bin:/bin
^
│
position 0
```

Then:

```text
${PATH:0:1}
```

means:

```text
Start at 0
Take 1 character
```

Result:

```text
/
```

So:

```text
${PATH:0:1}
        ↓
        /
```

---

# 6. Other Variables Can Also Work

The technique isn't limited to `$PATH`.

The lab mentions:

```text
$HOME
$PWD
```

For example, if `$HOME` begins with `/`, extracting its first character may also produce:

```text
/
```

The important principle is:

> **Find an environment variable containing the character you need, then extract only that character.**

---

# 7. Finding Useful Environment Variables

The command:

```bash
printenv
```

prints environment variables.

You can inspect the output and look for useful characters.

For example:

```bash
printenv
```

may show variables containing:

```text
/
:
;
_
-
```

etc.

You can then experiment with Bash substring extraction.

---

# 8. Extracting a Semicolon

The same concept can generate other characters.

The lab uses:

```bash
echo ${LS_COLORS:10:1}
```

which produces:

```text
;
```

Therefore:

```text
${LS_COLORS:10:1}
```

evaluates to a semicolon in the demonstrated environment.

This is especially interesting because `;` itself may be blacklisted.

---

# 9. Understanding the Semicolon Example

The important part is understanding that:

```bash
${LS_COLORS:10:1}
```

does **not inherently mean semicolon**.

It means:

```text
Take LS_COLORS
      ↓
Start at character 10
      ↓
Take 1 character
```

In the lab's environment, character 10 happens to be:

```text
;
```

Therefore:

```bash
echo ${LS_COLORS:10:1}
```

prints:

```text
;
```

### Important Environment Dependency

The exact contents of `LS_COLORS` can differ between systems.

Therefore, the same index may not necessarily produce `;` on another machine.

---

# 10. The General Formula

The technique can be summarized as:

```text
Find variable containing desired character
              ↓
Determine character position
              ↓
Extract one character
              ↓
Use expansion instead of literal character
```

For example:

```text
Variable:
PATH

Desired:
/

Position:
0

Extraction:
${PATH:0:1}
```

---

# 11. Combining Character and Space Bypasses

Now things become more interesting.

Previously we learned:

```text
${IFS}
```

can sometimes provide shell whitespace.

We now have:

```text
${PATH:0:1}
```

which produces:

```text
/
```

and:

```text
${LS_COLORS:10:1}
```

which produces:

```text
;
```

in the demonstrated environment.

These can be combined.

The lab demonstrates:

```text
127.0.0.1${LS_COLORS:10:1}${IFS}
```

The conceptual structure is:

```text
127.0.0.1
     │
     ├── ${LS_COLORS:10:1}
     │        ↓
     │        ;
     │
     └── ${IFS}
              ↓
           whitespace
```

So the shell receives the generated characters rather than those characters being directly present in the original input.

---

# 12. Why This Can Bypass a Character Filter

Imagine the application checks:

```php
if (strpos($input, ';') !== false) {
    echo "Invalid input";
}
```

A literal:

```text
;
```

would be detected.

But the raw input:

```text
${LS_COLORS:10:1}
```

doesn't contain a literal semicolon.

Later, shell expansion can transform it into:

```text
;
```

This illustrates a fundamental security issue:

```text
Raw Input
    ↓
Filter
    ↓
Shell Expansion
    ↓
Generated Character
```

If filtering occurs before expansion, the filter may never see the final character.

---

# 13. Windows — Same General Idea

The same general concept exists on Windows.

Windows has environment variables too.

For example:

```cmd
%HOMEPATH%
```

might contain:

```text
\Users\htb-student
```

Notice that the value begins with:

```text
\
```

We can extract that character rather than typing it directly.

---

# 14. Windows CMD Substring Syntax

Windows CMD provides variable substring expansion:

```cmd
%VARIABLE:~start,length%
```

The lab demonstrates:

```cmd
echo %HOMEPATH:~6,-11%
```

which produces:

```text
\
```

The basic structure is:

```text
%HOMEPATH
    :~
      6
      ,
      -11
%
```

The operation selects a portion of the environment-variable value.

---

# 15. Understanding the Windows Example

Suppose:

```text
%HOMEPATH%
```

contains:

```text
\Users\htb-student
```

The substring operation:

```cmd
%HOMEPATH:~6,-11%
```

selects the required portion according to CMD's substring rules.

In the demonstrated environment, the result is:

```text
\
```

### Important

Just like the Linux example, this depends on the actual variable contents.

A different username or environment can change the indexes.

---

# 16. Windows PowerShell

PowerShell handles environment variables differently.

Environment variables can be accessed using:

```powershell
$env:VARIABLE
```

For example:

```powershell
$env:HOMEPATH
```

The lab demonstrates:

```powershell
$env:HOMEPATH[0]
```

which returns:

```text
\
```

---

# 17. Why `[0]` Works in PowerShell

PowerShell allows strings to be accessed by character index.

Conceptually:

```text
\Users\htb-student
^
0
```

Therefore:

```powershell
$env:HOMEPATH[0]
```

returns the first character:

```text
\
```

This is somewhat different from the CMD substring syntax.

---

# 18. PowerShell Environment Variable Enumeration

PowerShell can display environment variables using:

```powershell
Get-ChildItem Env:
```

This is useful for discovering variables whose contents may contain useful characters.

Conceptually:

```text
Get-ChildItem Env:
        ↓
Environment variables
        ↓
Inspect values
        ↓
Find desired character
        ↓
Extract character
```

---

# 19. Important Difference: CMD vs PowerShell

|Feature|Windows CMD|PowerShell|
|---|---|---|
|Environment variable|`%HOMEPATH%`|`$env:HOMEPATH`|
|Substring|`%VAR:~start,length%`|Character indexing|
|Example|`%HOMEPATH:~6,-11%`|`$env:HOMEPATH[0]`|
|Variable listing|`set` / environment commands|`Get-ChildItem Env:`|

The underlying idea is the same:

> **Use an existing string containing the desired character and extract that character.**

---

# 20. Character Shifting

Environment-variable extraction isn't the only technique.

Another technique is:

# Character Shifting

The idea is to start with a character near the character you need and mathematically/algorithmically shift it.

For example:

```text
Desired character:
\
```

The ASCII value of:

```text
\
```

is:

```text
92
```

The character immediately before it is:

```text
[
```

with ASCII value:

```text
91
```

Therefore:

```text
[
 + 1
 ↓
\
```

---

# 21. Finding ASCII Values

Linux provides the ASCII manual page:

```bash
man ascii
```

The relevant relationship is:

```text
[ = 91
\ = 92
```

Therefore, if a tool can shift:

```text
[
```

by one character, the result becomes:

```text
\
```

---

# 22. The `tr` Example

The lab demonstrates:

```bash
echo $(tr '!-}' '"-~'<<<[)
```

which outputs:

```text
\
```

The important concept is the character translation performed by `tr`.

The command maps one character range to another shifted range.

---

# 23. Breaking Down the Command

The command:

```bash
tr '!-}' '"-~'
```

sets up a character translation.

The input:

```text
[
```

is provided through:

```bash
<<<[
```

Then:

```bash
$(...)
```

captures the command's output.

Finally:

```bash
echo
```

prints it.

So conceptually:

```text
[
 ↓
Character translation
 ↓
\
```

---

# 24. Why `[` Was Chosen

Because ASCII characters are sequential.

We know:

```text
[ = 91
\ = 92
```

Therefore:

```text
[ + 1 = \
```

The trick is simply finding the character immediately preceding the character we want.

---

# 25. Character-Shifting Methodology

For any target character:

```text
1. Identify the ASCII value.
2. Find the previous character.
3. Pass that character to the shifting mechanism.
4. Shift it into the desired character.
```

For example:

```text
Desired:
\

ASCII:
92

Previous:
[

ASCII:
91

Shift:
+1

Result:
\
```

---

# 26. Exercise — Generate `;`

The lab asks you to use the same technique to produce:

```text
;
```

The ASCII value of semicolon is:

```text
59
```

The character immediately before it is:

```text
:
```

because:

```text
: = 58
; = 59
```

Therefore:

```text
:
 + 1
 ↓
;
```

This is the exact reasoning you should use for the exercise.

---

# 27. Three Major Techniques

At this point, we have three important approaches.

## Technique 1 — Environment Variable Extraction

Linux:

```bash
${PATH:0:1}
```

can produce:

```text
/
```

in the demonstrated environment.

---

## Technique 2 — Windows Environment Variable Extraction

CMD:

```cmd
%HOMEPATH:~6,-11%
```

can produce:

```text
\
```

in the demonstrated environment.

PowerShell:

```powershell
$env:HOMEPATH[0]
```

can produce:

```text
\
```

---

## Technique 3 — Character Shifting

Using ASCII relationships:

```text
[ → \
: → ;
```

when shifted by one position using the demonstrated translation technique.

---

# 28. Comparison Table

|Technique|Platform|Example|Result|
|---|---|---|---|
|Environment substring|Linux|`${PATH:0:1}`|`/`|
|Environment substring|Linux|`${LS_COLORS:10:1}`|`;` in demonstrated environment|
|Environment substring|CMD|`%HOMEPATH:~6,-11%`|`\` in demonstrated environment|
|Character indexing|PowerShell|`$env:HOMEPATH[0]`|`\` in demonstrated environment|
|Character shifting|Linux|`tr ... <<<[`|`\`|

---

# 29. The Bigger Picture

We now have several layers of bypass techniques:

```text
                    COMMAND INJECTION
                           │
             ┌─────────────┴─────────────┐
             │                           │
       Injection Operators          Filter Bypass
             │                           │
      ;  &&  ||  |                 ┌─────┼─────┐
                                    │     │     │
                                  Space  Char  Encoding
                                    │     │
                                  ┌─┴─┐ ┌─┴──────┐
                                  │   │ │        │
                                 %09 IFS Variables
                                      │          │
                                      │       Substring
                                      │          │
                                      │      Character
                                      │      Extraction
                                      │
                                  Brace Expansion
```

The important progression is:

```text
Direct character
      ↓
Blocked
      ↓
Find another representation
      ↓
Shell interprets it
      ↓
Desired character appears
```

---

# 30. Raw Input vs Final Command

This is perhaps the **most important concept in the entire section**.

Suppose the filter blocks:

```text
;
```

The tester may send something conceptually equivalent to:

```text
${LS_COLORS:10:1}
```

The application sees:

```text
${LS_COLORS:10:1}
```

The shell later performs expansion:

```text
${LS_COLORS:10:1}
          ↓
          ;
```

Therefore:

```text
INPUT
  ↓
FILTER
  ↓
PARSER
  ↓
EXPANSION
  ↓
FINAL CHARACTER
```

Security controls must account for the transformations that occur before the dangerous operation.

---

# 31. Environment Matters

One of the most important caveats:

> **The exact indexes shown in the lab are environment-dependent.**

For example:

```bash
${PATH:0:1}
```

works for producing `/` because the demonstrated `$PATH` begins with `/`.

But:

```bash
${LS_COLORS:10:1}
```

depends on the exact contents of `$LS_COLORS`.

Similarly:

```cmd
%HOMEPATH:~6,-11%
```

depends on the structure of `%HOMEPATH%`.

Therefore, don't memorize the index blindly.

Instead:

```text
Inspect variable
      ↓
Find character
      ↓
Calculate index
      ↓
Extract it
```

---

# 32. Practical Enumeration Commands

### Linux

View one variable:

```bash
echo "$PATH"
```

View all environment variables:

```bash
printenv
```

Another useful command:

```bash
env
```

---

### Windows CMD

Display a variable:

```cmd
echo %HOMEPATH%
```

Environment-variable information can also be inspected with standard CMD environment commands.

---

### PowerShell

Display a variable:

```powershell
$env:HOMEPATH
```

List environment variables:

```powershell
Get-ChildItem Env:
```

---

# 33. Common Mistakes

### ❌ Mistake 1 — Assuming indexes are universal

They aren't.

```text
${LS_COLORS:10:1}
```

depends on the environment.

---

### ❌ Mistake 2 — Confusing encoding with generation

For example:

```text
%2f
```

is an encoded representation of `/`.

Whereas:

```bash
${PATH:0:1}
```

generates `/` through shell expansion.

These are different mechanisms.

---

### ❌ Mistake 3 — Forgetting the execution environment

Bash syntax:

```bash
${PATH:0:1}
```

shouldn't automatically be expected to work in:

```text
CMD
PowerShell
```

---

### ❌ Mistake 4 — Assuming every environment variable exists

Variables can differ between machines, users, shells, and configurations.

---

# 34. Defensive Perspective

The defensive lesson is extremely important.

A developer might think:

```text
"I blocked / and ;, so the input is safe."
```

But if the application eventually executes user-controlled data through a shell, the attacker may be able to construct those characters indirectly.

Therefore, continuously expanding a blacklist is generally fragile.

A stronger approach is:

```text
Don't pass untrusted input
        ↓
into shell syntax
```

Instead:

```text
Validate input
      ↓
Use safe APIs
      ↓
Pass arguments separately
      ↓
Avoid unnecessary shell interpretation
```

---

# 35. Important Takeaways

### ⭐ 1. Environment variables can contain useful characters

Example:

```bash
echo ${PATH:0:1}
```

→ `/`

---

### ⭐ 2. Bash substring expansion can extract characters

Syntax:

```bash
${VARIABLE:start:length}
```

---

### ⭐ 3. Environment variables can produce characters that are blacklisted

Example from the demonstrated environment:

```bash
${LS_COLORS:10:1}
```

→ `;`

---

### ⭐ 4. Windows provides similar mechanisms

CMD:

```cmd
%HOMEPATH:~6,-11%
```

→ `\`

PowerShell:

```powershell
$env:HOMEPATH[0]
```

→ `\`

---

### ⭐ 5. Character shifting can create desired characters

ASCII:

```text
[ = 91
\ = 92

: = 58
; = 59
```

Therefore:

```text
[ → \
: → ;
```

with a +1 character shift.

---

### ⭐ 6. Environment matters

Never assume the exact variable contents or indexes are universal.

---

# 36. Final Cheat Sheet

```text
╔══════════════════════════════════════════╗
║     BLACKLISTED CHARACTER BYPASSES       ║
╚══════════════════════════════════════════╝

LINUX
────────────────────────────────────────────

Environment variables:
printenv

PATH:
echo ${PATH}

Extract first character:
${PATH:0:1}

If PATH begins with /:
${PATH:0:1}
       ↓
       /

Example semicolon:
${LS_COLORS:10:1}
       ↓
       ;
(in demonstrated environment)


WINDOWS CMD
────────────────────────────────────────────

Environment variable:
%HOMEPATH%

Substring:
%HOMEPATH:~6,-11%

Demonstrated result:
\


POWERSHELL
────────────────────────────────────────────

Environment variable:
$env:HOMEPATH

First character:
$env:HOMEPATH[0]

Demonstrated result:
\

List environment variables:
Get-ChildItem Env:


CHARACTER SHIFTING
────────────────────────────────────────────

ASCII:

[ = 91
\ = 92

[ + 1 → \


: = 58
; = 59

: + 1 → ;


CORE IDEA
────────────────────────────────────────────

Blocked character
       ↓
Find it inside a string
       ↓
Extract it
OR
Find preceding ASCII character
       ↓
Shift it
       ↓
Generate required character
```

## 🧠 One-Line Revision

> **When a character is blacklisted, the shell may still be able to generate that character indirectly through environment-variable substring extraction, character indexing, or character shifting—making simple character blacklists unreliable as a security boundary.**