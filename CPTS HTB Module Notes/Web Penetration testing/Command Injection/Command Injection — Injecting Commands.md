![Image](https://images.openai.com/static-rsc-4/h5N-4dhFg3GmfLB2IfE40qBubapKSHUBgrYDQZzjjTU1JwAw3EvnDfmPo-1qnRqkftHLJwDfg2Ft1z2Am6FzS4Ls_ScfyyP-87xyxJ7EXSbHWTOcRxz_ldIeoN2a8KZ4J1sPIncGv_vf6mnzdv2iqy7PS3Y0oteGx8nG3X813cB8L7xnZi7zVSssjLgGdGDg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/J4d5KGUByISWjihsURkG83r6h5xb5iRVdhPIvvQ8WkdedwI6Nj3NPZQVcL5KrTJRJ9GzSECfQEankHHglPliqlct1gHLwp6hM51otJo7Av7445EKEQ3dgcCA4qzhypsN-wbq9e5WOjdc3HemHekVsVpNLIrknNqY9anNEaW01sOXvzR0IMO8ohE8q2lh9-xH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NKGGXEjDRiX4o4_0fLlYr4bWdO_SX2KyV2d8pWT3o7-oowiUnjM-ck8oj31KhgyjovTZ7Tu40FUD-iovt9rvwP-nJRQvyHFDpLtQo04plJKo7nO4BKjgISfo2eHF9gisYB8zmdfbTShQPpLqJXxAQgPVEo2w48pEgnzRp0VS8n61C8xaKPjgN8lxaBU_eL2U?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/douJ1PU3SL5V395CMB3k7nhtzBblAh8hsx4oFxBbKkKSNcaAgAMtwf0S7lXnVloMotA5CvAPSzKT1zpeLfvIvyeYWpE4vAlExGyfhfla8FhQQKSk2zjlKFVq7dgwq4gRQHLZxTbIPTceTuz9Zjs3BhATz2sJN46-O0sks4IEFB3Xsp81surOzhsohTh8jPBY?purpose=fullsize)

## 1. Where We Are

In the previous section, we identified the **Host Checker** application as potentially vulnerable to OS Command Injection.

We also learned about several command-injection operators.

Now we begin an actual injection attempt using the:

```text
;
```

**semicolon operator**

The goal is to determine whether our input can cause the server to execute an additional command.

---

# 2. Our First Payload

The application normally expects an IP address such as:

```text
127.0.0.1
```

We append a semicolon followed by another command:

```text
127.0.0.1; whoami
```

The suspected server-side command would therefore become:

```bash
ping -c 1 127.0.0.1; whoami
```

### What is happening?

The semicolon separates the two commands:

```text
ping -c 1 127.0.0.1
        ;
      whoami
```

The shell interprets them as two separate commands.

Conceptually:

```text
Command 1
   ↓
ping -c 1 127.0.0.1
   ↓
Command separator (;)
   ↓
Command 2
   ↓
whoami
```

---

# 3. Why Use `whoami`?

`whoami` is useful as a basic verification command because it reports the **identity of the user under which the command is executing**.

For example:

```bash
whoami
```

may return a username.

This makes it useful for confirming whether an additional command was actually executed.

### Important

For a controlled lab, `whoami` is a good demonstration command because it produces simple, recognizable output.

---

# 4. Testing the Command Locally

Before sending the payload to the web application, we can test the command locally on a Linux system:

```bash
ping -c 1 127.0.0.1; whoami
```

The command executes:

1. `ping -c 1 127.0.0.1`
    
2. `whoami`
    

The output therefore contains both:

```text
Ping output
```

and:

```text
whoami output
```

For example, the lab's system returns:

```text
21y4d
```

for the `whoami` command.

---

# 5. Why Local Testing Helps

Testing the command locally helps verify the shell behavior before testing the web application.

The reasoning is:

```text
Does the shell interpret
        ↓
;
as a command separator?
        ↓
YES
        ↓
Does our command execute?
        ↓
YES
        ↓
Now test whether the web application
allows the same syntax to reach the shell.
```

This separates two questions:

### Question 1

Does the command syntax work?

### Question 2

Does the target application allow our input to reach command execution?

---

# 6. Sending the Payload to Host Checker

We can now enter:

```text
127.0.0.1; whoami
```

into the Host Checker.

However, something unexpected happens.

The application rejects the input.

It displays an error indicating that the input must match the expected IP format.

At first, this might make us think:

> "The application isn't vulnerable."

But that conclusion would be premature.

---

# 7. Front-End Validation

The important clue is **where the error comes from**.

The application appears to be checking the input before sending the request to the server.

This is called:

## Front-End Validation

The browser validates the user's input before making the HTTP request.

Conceptually:

```text
User Input
    ↓
Browser Validation
    ↓
Valid?
 ┌──┴──┐
NO    YES
 ↓      ↓
Error   HTTP Request
         ↓
       Server
```

If the input fails the browser's validation, the request may never reach the back-end.

---

# 8. How Do We Confirm Front-End Validation?

We can use **Firefox Developer Tools**.

The material uses:

```text
CTRL + SHIFT + E
```

to open the Network tab.

Then we click the **Check** button again.

If the application displays an error but:

> **No network request is generated**

then the browser prevented the request from being sent.

This strongly indicates that the validation is occurring on the **front end**.

---

# 9. Network Tab Observation

The important observation is:

```text
Malicious Input
      ↓
Front-End Validation
      ↓
Rejected
      ↓
NO HTTP REQUEST
```

Compare this with valid input:

```text
127.0.0.1
      ↓
Front-End Validation
      ↓
Accepted
      ↓
HTTP Request
      ↓
Back-End
```

This distinction is extremely important.

---

# 10. Front-End Validation ≠ Security Boundary

A major security lesson from this section is:

> **Front-end validation should never be considered sufficient protection against malicious input.**

Why?

Because the user controls the client.

An attacker does not have to use the application's interface exactly as intended.

They can construct and send their own HTTP requests directly to the server.

### Remember

```text
Frontend validation
       ≠
Backend security
```

---

# 11. Why Developers Use Front-End Validation

Front-end validation is useful for legitimate reasons.

For example:

- Improving user experience
    
- Showing immediate errors
    
- Preventing accidental invalid input
    
- Reducing unnecessary requests
    
- Providing instant feedback
    

However, it should not be relied upon as the only security control.

---

# 12. Why Front-End Validation Can Fail as a Security Control

Consider:

```text
Browser
   ↓
Validation
   ↓
Server
```

The developer may assume:

> "The server only receives valid IP addresses."

But an attacker can instead do:

```text
Attacker
   ↓
Custom HTTP Request
   ↓
Server
```

The browser's validation is completely bypassed.

Therefore:

```text
Browser rules
     ↓
Can be bypassed
     ↓
Server must validate independently
```

---

# 13. The Correct Security Model

A secure application should validate input on the **back end**, even if it also validates it on the front end.

Ideally:

```text
             User Input
                 │
        ┌────────┴────────┐
        ▼                 ▼
 Front-End Validation  Back-End Validation
        │                 │
        └────────┬────────┘
                 ▼
          Safe Processing
```

The server must assume that incoming requests may have been manually constructed or modified.

---

# 14. Bypassing Front-End Validation

In a controlled security lab, one straightforward way to inspect and modify requests is to use an HTTP proxy.

Examples include:

- **Burp Suite**
    
- **OWASP ZAP**
    

The proxy sits between the browser and the web application.

Conceptually:

```text
Browser
   │
   ▼
Proxy
   │
   ▼
Web Server
```

This allows the tester to inspect and modify HTTP requests before they reach the server.

---

# 15. Burp Suite / ZAP Workflow

The material's workflow is:

```text
1. Start Burp Suite or ZAP
        ↓
2. Configure Firefox to use the proxy
        ↓
3. Enable interception
        ↓
4. Send a normal request from Host Checker
        ↓
5. Intercept the request
        ↓
6. Send it to Repeater
        ↓
7. Modify the request
        ↓
8. Send the customized request
        ↓
9. Analyze the response
```

This is a common web-security testing workflow.

---

# 16. Why Start With a Normal Request?

Instead of manually creating the entire HTTP request, first submit a legitimate value such as:

```text
127.0.0.1
```

This gives us a valid request generated by the application itself.

We can then inspect:

- HTTP method
    
- URL/path
    
- Parameters
    
- Headers
    
- Content type
    
- Request body
    
- Expected response
    

This reduces mistakes when modifying the request.

---

# 17. Sending the Request to Repeater

After intercepting the request in Burp Suite, the material sends it to:

## Repeater

Using:

```text
CTRL + R
```

Repeater allows us to repeatedly send a request after modifying it.

Conceptually:

```text
Original Request
      ↓
Burp Intercept
      ↓
Repeater
      ↓
Modify
      ↓
Send
      ↓
Observe Response
```

This is particularly useful for security testing because we can change individual parameters without repeatedly interacting with the browser UI.

---

# 18. The HTTP Request

The intercepted request contains the normal IP address:

```text
127.0.0.1
```

At this stage, the important goal is to identify **where the user-controlled IP value appears in the request**.

For example, it may appear in the request body as a parameter.

The exact parameter name depends on the application.

---

# 19. Modifying the Request

Once the request is inside Repeater, we can replace the normal IP value with our test input:

```text
127.0.0.1; whoami
```

The important difference is:

### Browser

The browser's validation may reject this.

### Repeater

Repeater is sending the HTTP request directly, allowing us to test how the **server** handles the input.

Conceptually:

```text
Browser UI
    ↓
Validation
    ↓
BLOCKED

Burp Repeater
    ↓
Custom HTTP request
    ↓
Server
```

---

# 20. URL Encoding

The material recommends URL-encoding the payload before sending it.

The semicolon:

```text
;
```

has the URL-encoded representation:

```text
%3b
```

Therefore, the payload can be represented in encoded form as:

```text
127.0.0.1%3b whoami
```

The purpose of URL encoding is to ensure that the special character is transmitted as intended within the HTTP request.

### Important

Always consider the exact request format and how the server/framework decodes parameters.

Encoding is about **transport representation**; it does not inherently make a payload safe.

---

# 21. Sending the Modified Request

After modifying the request:

```text
127.0.0.1; whoami
```

and appropriately encoding it, we send the request through Repeater.

Now the request bypasses the browser's front-end validation.

The important question becomes:

> **How does the back-end server process this input?**

---

# 22. The Critical Result

The response contains:

1. The output from the `ping` command.
    
2. The output from the `whoami` command.
    

This is significant.

The server effectively processed the input as though the command became:

```bash
ping -c 1 127.0.0.1; whoami
```

Therefore, the second command executed.

---

# 23. Confirming Command Injection

This gives us strong evidence of successful command injection.

The complete flow is:

```text
127.0.0.1; whoami
        │
        ▼
HTTP Request
        │
        ▼
Back-End Application
        │
        ▼
ping -c 1 127.0.0.1; whoami
        │
        ├───────────────┐
        ▼               ▼
      ping            whoami
        │               │
        ▼               ▼
   Ping output      User identity
```

The key observation is the **unexpected `whoami` output**.

---

# 24. What Did We Prove?

The test establishes several important facts.

### 1. The input reaches the back end

Our custom request was accepted by the server.

### 2. The back end does not enforce the same IP-only restriction

The front-end restriction was bypassed.

### 3. The input reaches command execution

Our injected syntax influenced the command.

### 4. The semicolon was interpreted as command syntax

The shell separated:

```text
ping
```

from:

```text
whoami
```

### 5. An additional command executed

The response contained the output of `whoami`.

Therefore, the application is vulnerable to **OS Command Injection**.

---

# 25. Front-End vs Back-End Validation

This is one of the most important concepts in this section.

|Front-End Validation|Back-End Validation|
|---|---|
|Runs in the browser/client|Runs on the server|
|Improves user experience|Provides server-side security|
|Can be bypassed|Must always be enforced|
|User can modify/bypass it|Server controls the final decision|
|Should not be trusted alone|Essential security control|

### Golden Rule

> **Never trust client-side validation as a security boundary.**

---

# 26. Complete Attack/Testing Flow

The entire lab scenario can be summarized as:

```text
                  HOST CHECKER
                       │
                       ▼
              Normal IP Input
                 127.0.0.1
                       │
                       ▼
                Ping Response
                       │
                       ▼
              Suspect OS Command
                       │
                       ▼
          Test: 127.0.0.1; whoami
                       │
                       ▼
             Front-End Validation
                       │
                       ▼
                    BLOCKED
                       │
                       ▼
          Inspect Network Behavior
                       │
                       ▼
             No HTTP Request
                       │
                       ▼
          Confirm Client-Side Check
                       │
                       ▼
             Use HTTP Proxy
              Burp Suite / ZAP
                       │
                       ▼
            Intercept Valid Request
                       │
                       ▼
                  Repeater
                       │
                       ▼
             Modify Request
                       │
                       ▼
             Send to Back End
                       │
                       ▼
             Server Processes Input
                       │
                       ▼
           Command Injection Works
                       │
                       ▼
        ping output + whoami output
```

---

# 27. Important Commands From This Section

### Original suspected command

```bash
ping -c 1 OUR_INPUT
```

### Injection payload

```text
127.0.0.1; whoami
```

### Resulting command

```bash
ping -c 1 127.0.0.1; whoami
```

### Verification command

```bash
whoami
```

### URL-encoded semicolon

```text
%3b
```

---

# 28. Key Concepts to Understand

## A. Input Validation

Applications often restrict what users can enter.

Example:

```text
Only accept IP addresses
```

This is useful, but it must be enforced on the server.

---

## B. Client-Side Validation

Validation performed by:

```text
HTML
JavaScript
Browser-side code
```

It can be bypassed because the attacker controls the client.

---

## C. Server-Side Validation

Validation performed by the back-end application.

This is much more important because requests can be manually constructed.

---

## D. HTTP Proxy

A proxy can sit between the client and server:

```text
Client → Proxy → Server
```

It allows security testers to inspect and modify requests in a controlled environment.

---

## E. Repeater

Burp Repeater allows a captured request to be:

- Modified
    
- Resent
    
- Repeated
    
- Compared
    

This makes it useful for testing how the server responds to different inputs.

---

# 29. Important Security Lesson

Suppose an application has:

```text
Front End:
"Only IP addresses are allowed."
```

But the server accepts:

```text
127.0.0.1; whoami
```

Then the front-end validation provides **no effective protection against an attacker who can send requests directly to the server**.

The secure architecture should instead be:

```text
             REQUEST
                │
                ▼
        ┌───────────────┐
        │ Backend Input │
        │   Validation  │
        └───────┬───────┘
                │
             Valid?
            /      \
          NO        YES
          │          │
       Reject      Process
```

---

# 30. Why This Vulnerability Exists

The complete vulnerability chain is:

```text
User-controlled input
        ↓
Front-end validation only
        ↓
Validation bypass
        ↓
Input reaches back end
        ↓
Input incorporated into OS command
        ↓
Shell interprets command syntax
        ↓
Additional command executes
```

The critical weakness is that the back end trusts input that should have been treated as untrusted.

---

# 31. Detection Evidence

For a security report, useful evidence would include:

### Input

```text
127.0.0.1; whoami
```

### Expected behavior

```text
Only ping output
```

### Actual behavior

```text
Ping output
+
whoami output
```

### Security conclusion

The application allows attacker-controlled input to influence OS command execution.

---

# 32. Common Misconceptions

### ❌ "The application rejected my payload, so it isn't vulnerable."

Not necessarily.

If the browser rejects the payload before sending an HTTP request, the back end hasn't actually been tested.

---

### ❌ "The IP validation protects the server."

Only if equivalent validation is enforced server-side.

---

### ❌ "Burp bypasses the server's security."

No.

Burp allows us to bypass **client-side restrictions** and determine how the server itself handles a custom request.

---

### ❌ "URL encoding prevents command injection."

No.

URL encoding changes how data is represented in an HTTP request. The server may decode it before processing.

---

### ❌ "Using PHP means the injection syntax is different."

Not necessarily.

The relevant behavior depends heavily on the command interpreter/environment receiving the constructed command.

---

# 33. Lab Methodology Cheat Sheet

```text
1. Identify suspicious functionality
        ↓
2. Establish normal behavior
        ↓
3. Infer the underlying command
        ↓
4. Create a controlled injection test
        ↓
5. Test through the normal interface
        ↓
6. If blocked, determine where it was blocked
        ↓
7. Check whether a request reached the server
        ↓
8. If blocked client-side, intercept a legitimate request
        ↓
9. Send the request to Repeater
        ↓
10. Modify the relevant parameter
        ↓
11. URL-encode where appropriate
        ↓
12. Send the request
        ↓
13. Compare the response with the baseline
        ↓
14. Confirm evidence of additional command execution
```

---

# 34. Most Important Takeaways

### ⭐ 1. Start with a known-good input

Use something like:

```text
127.0.0.1
```

to establish normal behavior.

### ⭐ 2. Test the shell behavior

The semicolon:

```text
;
```

can separate commands in the relevant shell environment.

### ⭐ 3. Use a recognizable verification command

In the lab:

```text
whoami
```

provides easily identifiable output.

### ⭐ 4. Don't confuse front-end validation with security

A browser restriction can be bypassed.

### ⭐ 5. Check the Network tab

If no HTTP request occurs, the validation likely happened before the request reached the server.

### ⭐ 6. Use an HTTP proxy in an authorized lab

Tools such as:

```text
Burp Suite
OWASP ZAP
```

allow inspection and modification of requests.

### ⭐ 7. Repeater is useful for controlled testing

It allows requests to be modified and resent without relying on the original web interface.

### ⭐ 8. URL encoding matters

For example:

```text
; → %3b
```

### ⭐ 9. The server-side response is the important evidence

If the response contains both:

```text
ping output
```

and:

```text
whoami output
```

then the additional command was executed.

---

# 35. Final Revision Summary

```text
HOST CHECKER
     │
     ▼
127.0.0.1
     │
     ▼
Normal ping response
     │
     ▼
Suspected command:
ping -c 1 OUR_INPUT
     │
     ▼
Test:
127.0.0.1; whoami
     │
     ▼
Browser rejects input
     │
     ▼
Network tab → No request
     │
     ▼
Front-end validation identified
     │
     ▼
Intercept legitimate request
with Burp Suite / ZAP
     │
     ▼
Send to Repeater
     │
     ▼
Modify input
     │
     ▼
127.0.0.1; whoami
     │
     ▼
Send custom HTTP request
     │
     ▼
Server processes input
     │
     ▼
Ping output + whoami output
     │
     ▼
OS COMMAND INJECTION CONFIRMED
```

## 🧠 Golden Rule

> **Client-side validation controls the user interface; server-side validation controls the security of the application.**

And for this lab specifically:

> **If a payload is blocked by the browser, first determine whether the request ever reached the server. If it didn't, you have tested the front end—not the back end.**