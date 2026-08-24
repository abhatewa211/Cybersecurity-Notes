![Image](https://images.openai.com/static-rsc-4/UbxPN-VdfvnxZtGDKKYoKARkow0f6VkEKQia9cVAJy3C-n_JfAMXXL9OZZQkl-ajXHOnRT8xj8hMPHBHzMrPNhq7BJwOcHfFmO_m-mvIiiN3Qvia5ETWnxoG6fZm0RtBInedf-JCoZ4ikUfgWRzMc5kCKJ0a3JO3DLWNU5MxNRgoNllOoQ-k_H4rvQuLd8eM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rTppiVjZ5db-xD3W_26e5oN-yj99VAxoOeUNDcFAItdVyeO4q6x656fTBDgekjJRlHM8IANiPb8wpN1LrIAFIlzSTGf3ZMzHk0x85WEKOUsMK9pWgG13lVc65TMon5PTLRDobKMVGV1iW0Xe6qIY57g7E25n6e4h6j2kMqqHIVv8CXx-KSyQpmheF6kYWOJK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/syHMYH6f_XeRBxnqb4700ymBO3uW0MYnQm3JqNd0QhisTnwbw4-8VBB-f0B6ROplDAj1Nx-R92j3o8sBskLR_OleuDjWBrDspCBJNm7JBxZ_PNHIWoHdH5nt9mZdrkeGztT5VVgmr1AZ1K9ZUM5tALwwtLDu0Z5kM86Q9CNb3XYwxZeuzq1ISKa7p9onzFPP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/f21jNCC5Qd-Sp5gSBv2aRMg3AmUol2noA5cJ7a8X5-vc8cGYR2IbavPQcqVZQFzsl0A8JpvpkTT2igOklhmQ8AjZqP-fSlXJ1YoqAC9cM0Gp1hZxE-KLClyOx1dGHUHWUd8NnBRAfZOGce43I4SWrby0ap5ZKa21jyABmpvLD_Q3_YLh_yNW5ndYR70p3Ln0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ah0yAzzU_UgtDpYP7WAJsrb_1D8eQP5mR20r5F4Vcrj7fUC4QZKMWxWyejN-kHneIhomD-3HMeqenTmCBwDrmpPxqW1x6C4QoQ5y7f_nm8U0RBChpRkE-M6jWe_DZDlP7OK9kidryOZxaFridmXmVx9BAKo5fE0k4Nz2PmJKAoMwO0u1D9JLXGpNwqRAJenh?purpose=fullsize)

## 1. What Is Hydra?

**Hydra** is a fast network login-cracking tool used in **authorized security testing**.

It supports numerous authentication protocols and services, including:

- SSH
    
- FTP
    
- HTTP
    
- SMTP
    
- POP3
    
- IMAP
    
- MySQL
    
- MSSQL
    
- VNC
    
- RDP
    

### Core idea

Hydra automates repeated authentication attempts.

```text
Username(s)
     +
Password(s)
     ↓
   Hydra
     ↓
Authentication attempts
     ↓
Success / Failure
```

It is especially useful in penetration-testing labs such as HTB because manually testing hundreds or thousands of credentials would be inefficient.

---

# 2. Why Hydra Is Popular

The material highlights three major advantages.

## ⚡ Speed and Efficiency

Hydra can use **parallel connections/tasks** to perform multiple authentication attempts.

Conceptually:

```text
             Hydra
               │
      ┌────────┼────────┐
      ↓        ↓        ↓
   Task 1   Task 2   Task 3
      │        │        │
      ↓        ↓        ↓
   Attempt  Attempt  Attempt
```

More parallel tasks can increase the number of attempts performed per unit of time, although the practical speed depends on the target and network.

---

## 🔄 Flexibility

Hydra supports many different protocols.

The same general tool can be used to test authentication on services such as:

```text
SSH
FTP
HTTP
SMTP
POP3
IMAP
MySQL
MSSQL
VNC
RDP
```

This makes Hydra useful across different types of infrastructure.

---

## 🧑‍💻 Ease of Use

Hydra has a command-line interface with a relatively straightforward structure.

The general syntax is:

```bash
hydra [login_options] [password_options] [attack_options] [service_options]
```

Once you understand the options, commands become relatively easy to construct.

---

# 3. Installation

Hydra is commonly available on penetration-testing distributions.

First, verify whether it is installed:

```bash
hydra -h
```

If Hydra is installed, this displays its help information.

If it isn't installed on a Debian/Ubuntu-based system, the provided material uses:

```bash
sudo apt-get -y update
sudo apt-get -y install hydra
```

### Verify installation

```bash
hydra -h
```

---

# 4. Hydra's Basic Syntax ⭐⭐⭐

The fundamental structure is:

```bash
hydra [login_options] [password_options] [attack_options] [service_options]
```

Think of a Hydra command as answering four questions:

```text
WHO?
 ↓
Username(s)

WHAT?
 ↓
Password(s)

HOW?
 ↓
Options / tasks / behavior

WHERE?
 ↓
Target + service
```

---

# 5. Important Hydra Options

|Option|Meaning|Example|
|---|---|---|
|`-l LOGIN`|Single username|`-l admin`|
|`-L FILE`|Username list|`-L usernames.txt`|
|`-p PASS`|Single password|`-p password123`|
|`-P FILE`|Password list|`-P passwords.txt`|
|`-t TASKS`|Number of parallel tasks|`-t 4`|
|`-f`|Stop after first successful login|`-f`|
|`-s PORT`|Non-standard service port|`-s 2222`|
|`-v` / `-V`|Verbose output|`-V`|
|`-M FILE`|Multiple targets from a file|`-M targets.txt`|
|`-x`|Generate passwords within specified parameters|`-x 6:8:abc...`|

---

# 6. `-l` vs `-L`

This distinction is **very important**.

## `-l`

Use `-l` when you know **one username**.

Example:

```bash
hydra -l admin ...
```

Meaning:

```text
Username = admin
```

---

## `-L`

Use `-L` when you have a **file containing usernames**.

Example:

```bash
hydra -L usernames.txt ...
```

Conceptually:

```text
usernames.txt

admin
root
user
administrator
guest
```

Hydra can test the usernames from the file.

### Memory trick

```text
-l → login
-L → Login LIST
```

---

# 7. `-p` vs `-P`

Exactly the same concept applies to passwords.

## `-p`

One password:

```bash
-p password123
```

## `-P`

Password list:

```bash
-P passwords.txt
```

Example:

```text
passwords.txt

password
123456
qwerty
welcome
admin123
```

### Memory trick

```text
-p → one Password
-P → Password list
```

---

# 8. `-t` — Parallel Tasks

The `-t` option controls the number of parallel tasks.

Example:

```bash
-t 4
```

Conceptually:

```text
           Hydra
             │
     ┌───────┼───────┐
     ↓       ↓       ↓
   Task 1  Task 2  Task 3  Task 4
```

Higher concurrency can improve speed, but **more is not always better**.

Too many requests can:

- Overload the target
    
- Trigger rate limiting
    
- Cause connection failures
    
- Generate obvious detection signals
    
- Reduce reliability
    

In a real engagement, concurrency should remain within the authorized testing limits.

---

# 9. `-f` — Stop After Success

The `-f` option tells Hydra to stop after finding a successful login.

Example:

```bash
hydra -f ...
```

Without this option, depending on the attack configuration, Hydra may continue searching after finding a valid credential.

### Why use `-f`?

If the objective is simply:

> Find one valid credential.

then continuing after success wastes time and creates unnecessary authentication attempts.

---

# 10. `-s` — Non-Standard Port

Services don't always run on their default ports.

The `-s` option specifies a custom port.

Example:

```bash
-s 2121
```

Conceptually:

```text
FTP
Default port → 21

Target FTP
Port → 2121
```

Hydra therefore needs to be told which port to use.

---

# 11. `-v` and `-V`

These options control output verbosity.

```bash
-v
```

provides verbose output.

```bash
-V
```

provides even more detailed information, including attempts.

This is particularly useful in a lab when you want to observe what Hydra is doing.

---

# 12. `-M` — Multiple Targets

The `-M` option allows Hydra to read multiple target hosts from a file.

For example:

```text
targets.txt

192.168.1.10
192.168.1.20
192.168.1.30
```

Then:

```bash
-M targets.txt
```

tells Hydra to use those targets.

⚠️ In real environments, this should only contain systems explicitly included in the authorized scope.

---

# 13. Hydra Services

Hydra uses service-specific modules to understand how to communicate with different authentication protocols.

### Common modules

|Hydra Module|Protocol / Service|Purpose|
|---|---|---|
|`ftp`|FTP|Test FTP authentication|
|`ssh`|SSH|Test SSH authentication|
|`http-get`|HTTP|Test HTTP GET authentication|
|`http-post-form`|HTTP|Test web forms using POST|
|`smtp`|SMTP|Test mail-server authentication|
|`pop3`|POP3|Test email retrieval authentication|
|`imap`|IMAP|Test remote email authentication|
|`mysql`|MySQL|Test MySQL authentication|
|`mssql`|Microsoft SQL Server|Test MSSQL authentication|
|`vnc`|VNC|Test VNC authentication|
|`rdp`|RDP|Test Remote Desktop authentication|

---

# 14. Why Hydra Needs Different Modules

Different protocols authenticate differently.

For example:

```text
SSH
 ↓
SSH authentication protocol

FTP
 ↓
FTP authentication protocol

HTTP form
 ↓
HTTP request + form parameters
```

Hydra's modules understand these differences.

Therefore, you can't simply use the exact same command structure for every service.

---

# 15. Hydra + HTTP Basic Authentication

The provided example uses:

```bash
hydra -L usernames.txt -P passwords.txt www.example.com http-get
```

This tells Hydra to:

1. Read usernames from `usernames.txt`
    
2. Read passwords from `passwords.txt`
    
3. Target `www.example.com`
    
4. Use the `http-get` module
    

Conceptually:

```text
usernames.txt
       +
passwords.txt
       ↓
     Hydra
       ↓
www.example.com
       ↓
HTTP authentication
```

---

# 16. Credential Combination Logic

If you have:

```text
3 usernames
+
5 passwords
```

then a typical username/password combination space can contain:

[  
3 \times 5 = 15  
]

candidate pairs.

Example:

```text
admin + password1
admin + password2
admin + password3
...

root + password1
root + password2
...
```

This is why combining username lists and password lists can grow quickly.

---

# 17. Targeting Multiple SSH Servers

The provided example:

```bash
hydra -l root -p toor -M targets.txt ssh
```

means:

```text
Username = root
Password = toor
Targets = targets.txt
Service = SSH
```

The file might contain:

```text
192.168.1.10
192.168.1.20
192.168.1.30
```

Hydra can test the specified credential against the authorized targets.

### Important concept

This isn't primarily about searching a large password space.

It's an example of testing a **known/default credential** across multiple systems.

---

# 18. Testing FTP on a Non-Standard Port

The provided command is:

```bash
hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp
```

Breaking it down:

```text
-L usernames.txt
      ↓
Username list

-P passwords.txt
      ↓
Password list

-s 2121
      ↓
Custom port

-V
      ↓
Verbose output

ftp.example.com
      ↓
Target

ftp
      ↓
FTP module
```

---

# 19. Web Login Forms

Web applications are slightly more complicated than protocols such as SSH or FTP because Hydra needs to understand:

- Login URL
    
- HTTP method
    
- Form parameters
    
- Username field
    
- Password field
    
- Success/failure condition
    

The provided example is:

```bash
hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
```

---

# 20. Understanding `http-post-form`

The important section is:

```text
/login:user=^USER^&pass=^PASS^:S=302
```

It contains several pieces of information.

### `/login`

The login endpoint.

### `user=^USER^`

Hydra inserts the username here.

### `pass=^PASS^`

Hydra inserts the password candidate here.

### `S=302`

The example tells Hydra to treat HTTP status `302` as the success condition.

---

# 21. `^USER^` and `^PASS^`

These are Hydra placeholders.

```text
^USER^
```

means:

> Insert the current username.

And:

```text
^PASS^
```

means:

> Insert the current password.

Conceptually:

```text
^USER^ → admin
^PASS^ → candidatePassword
```

The resulting request might conceptually contain:

```text
user=admin&pass=candidatePassword
```

---

# 22. Success Conditions

Hydra needs some way to determine whether a login succeeded.

The application might indicate success through:

- HTTP status code
    
- Response text
    
- Redirect
    
- Specific page content
    

The provided example uses:

```text
S=302
```

meaning the expected success condition is an HTTP **302 redirect**.

### Important

Not every website uses `302` for successful login.

The correct success/failure condition must be determined from the authorized application's actual behavior.

---

# 23. Advanced RDP Brute Force

The provided example uses Hydra's password-generation option:

```bash
-x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
```

The general structure is:

```text
-x MIN:MAX:CHARSET
```

So:

```text
6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
```

means:

```text
Minimum length = 6
Maximum length = 8
Character set = lowercase + uppercase + digits
```

---

# 24. Why `-x` Is Different From `-P`

This is another important distinction.

### `-P`

Uses an existing password file:

```bash
-P passwords.txt
```

### `-x`

Generates candidate passwords according to specified rules.

```bash
-x 6:8:CHARSET
```

So:

```text
-P
↓
Use supplied candidates

-x
↓
Generate candidates
```

---

# 25. Connecting Hydra to the Mathematics

This directly connects to your previous notes.

Suppose:

```text
Minimum length = 6
Maximum length = 8
Character set = 62
```

The total theoretical search space is:

[  
62^6 + 62^7 + 62^8  
]

That's already extremely large.

Let's calculate it:

[  
62^6 = 56,800,235,584  
]

[  
62^7 = 3,521,614,606,208  
]

[  
62^8 = 218,340,105,584,896  
]

Total:

[  
\boxed{221,918,520,426,688}  
]

So the attack would theoretically involve over **221 trillion combinations** if the entire space had to be exhausted.

### 🚨 Important lesson

Using a tool doesn't magically make a huge search space practical.

> **The mathematics still determines feasibility.**

---

# 26. Hydra's Role in the Brute-Force Ecosystem

Think of everything you've learned so far:

```text
                PASSWORD ATTACKS
                       │
       ┌───────────────┼────────────────┐
       ↓               ↓                ↓
  Brute Force      Dictionary         Hybrid
       │               │                │
  Generate all      Wordlist       Wordlist +
  combinations      candidates      modifications
       │               │                │
       └───────────────┼────────────────┘
                       ↓
                    Hydra
                       │
                       ↓
            Automates authentication
                 attempts against
              supported protocols
```

Hydra is therefore an **automation tool**, not a new password-guessing theory.

---

# 27. Hydra vs Python Scripts

You've already seen Python scripts for the HTB PIN and dictionary labs.

### Python approach

You manually write the logic:

```text
Generate candidate
      ↓
Send request
      ↓
Check response
      ↓
Success?
      ↓
Repeat
```

### Hydra

Hydra already implements much of this functionality for supported protocols.

```text
Username list
Password list
Target
Service
      ↓
    Hydra
      ↓
Automated authentication testing
```

### Key difference

> **Python gives you maximum customization; Hydra gives you ready-made protocol support and automation.**

---

# 28. When Hydra Is Useful

In an authorized penetration test or lab, Hydra can be useful when:

- A supported network service requires authentication
    
- You have an approved credential wordlist
    
- You need to test password strength
    
- You need to automate repeated authentication attempts
    
- You need to test multiple authorized targets
    
- You need protocol-specific handling
    

---

# 29. When Hydra Isn't the Right Tool

Hydra isn't automatically appropriate for every authentication scenario.

For example, a custom application may require:

- Complex JavaScript
    
- CSRF tokens
    
- Dynamic parameters
    
- CAPTCHA
    
- Multi-step authentication
    
- Browser-specific behavior
    
- API tokens
    

In such cases, a custom script or application-specific testing approach may be more appropriate.

---

# 30. Defensive Perspective 🛡️

Hydra also demonstrates what defenders need to protect against.

### Rate Limiting

Limit authentication attempts.

### Account Lockout

Temporarily lock accounts after repeated failures.

### MFA

Require another authentication factor.

### Strong Passwords

Make password guessing more difficult.

### Monitoring

Detect patterns such as:

```text
Many authentication attempts
          ↓
Same source / unusual pattern
          ↓
Potential automated attack
```

### Network Controls

Restrict access to sensitive services such as:

- SSH
    
- RDP
    
- Database services
    
- Administrative interfaces
    

---

# 31. ⭐ Hydra Cheat Sheet

## Help

```bash
hydra -h
```

## Single username + password list

```bash
hydra -l admin -P passwords.txt TARGET SERVICE
```

## Username list + password list

```bash
hydra -L usernames.txt -P passwords.txt TARGET SERVICE
```

## Parallel tasks

```bash
hydra -t 4 ...
```

## Stop after success

```bash
hydra -f ...
```

## Custom port

```bash
hydra -s 2222 ...
```

## Verbose

```bash
hydra -V ...
```

## Multiple targets

```bash
hydra -M targets.txt ...
```

## Generated password candidates

```bash
hydra -x MIN:MAX:CHARSET ...
```

---

# 32. 🧠 Most Important Options to Memorize

```text
-l  → Single username
-L  → Username file

-p  → Single password
-P  → Password file

-t  → Parallel tasks

-f  → Stop after success

-s  → Custom port

-v  → Verbose
-V  → More verbose

-M  → Multiple targets

-x  → Generate password combinations
```

### Easy memory trick

```text
LOWERCASE = ONE
-l → one login
-p → one password

UPPERCASE = LIST
-L → login list
-P → password list
```

---

# 33. 🔥 Final Mental Model

```text
                       HYDRA
                         │
               Network Login Cracker
                         │
        ┌────────────────┼────────────────┐
        ↓                ↓                ↓
     Username          Password         Target
        │                │                │
   -l / -L           -p / -P           Service
                         │
                         ↓
                 Candidate Attempts
                         │
                ┌────────┴────────┐
                ↓                 ↓
             Failure           Success
                │                 │
                ↓                 ↓
           Next candidate       Stop*
                              (*with -f)
```

### 🔑 Final takeaway

> **Hydra is a protocol-aware authentication-testing tool that automates large numbers of login attempts against supported services. Its effectiveness depends not just on Hydra's speed, but on the size and quality of the credential candidates, the target's authentication behavior, and defensive controls such as rate limiting and MFA.**

And for your HTB notes, remember the progression:

**Brute Force → Dictionary → Hybrid → Credential Stuffing → Hydra**

The first four describe **attack strategies**; **Hydra is a tool that can automate certain credential-testing strategies against network services.**