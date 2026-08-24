![Image](https://images.openai.com/static-rsc-4/er6ss7JxcYaOVkadBhNCzDicJv5ZWoo7lZ_AwK7lBcinrRpX8iKIwjV8-PlCc9QiAj4Lj_JJnYkxbJxiA2AB5AYDMV0p_aZ4L6j_Hpm8taxIl5Mod3Py2j4wUnOFTrBJML61pFh-Mn_2fyqbThWATBV1RXtZm6BposhIHvXzZGnLnsohEDLHY6nzaespaT91?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DjQo6GDnUdlR18TaN4E_hEiy7AhGa131AjAv--FyuCtPrmbIRRBFzWiDuF0QDqx6S7lrhi8GAZPW1f7YH4038CcsJXODl03vHgrxa8scZgN5lLjnoQ_LOokNuWWVroluCevsyQHVEVQqLo5hxodKNAK-WRGhQfRSCa6EVYNK59DJs4H6gmObsa0p49YkO586?purpose=fullsize)

# 1. What Is Medusa?

**Medusa** is a fast, massively parallel, modular login brute-forcing tool.

Its primary purpose is to help **penetration testers and security professionals assess the resilience of remote authentication systems**.

### Core idea

```text
Username(s)
     +
Password(s)
     ↓
   Medusa
     ↓
Authentication module
     ↓
Target service
     ↓
Success / Failure
```

Medusa is similar to Hydra in that it automates credential testing, but its architecture is heavily based around **modules**.

---

# 2. Why Medusa Is Useful

The source describes three important characteristics:

### ⚡ Fast

Medusa is designed to perform authentication attempts in parallel.

### 🔀 Massively Parallel

Multiple login attempts can be performed concurrently.

### 🧩 Modular

Different modules allow Medusa to interact with different services.

Think:

```text
                 MEDUSA
                    │
       ┌────────────┼────────────┐
       ↓            ↓            ↓
      SSH          FTP          HTTP
       │            │            │
       ↓            ↓            ↓
 Authentication-specific modules
```

---

# 3. Installation

Medusa is often available on penetration-testing distributions.

Check whether it is installed:

```bash
medusa -h
```

If it isn't installed on a Debian/Ubuntu-based Linux system:

```bash
sudo apt-get -y update
sudo apt-get -y install medusa
```

Then verify:

```bash
medusa -h
```

---

# 4. Basic Syntax ⭐⭐⭐

The source gives the general syntax as:

```bash
medusa [target_options] [credential_options] -M module [module_options]
```

A useful way to remember this is:

```text
TARGET
  ↓
Who are we testing?

CREDENTIALS
  ↓
Which usernames/passwords?

MODULE
  ↓
Which service?

MODULE OPTIONS
  ↓
How does that service authenticate?
```

---

# 5. Important Medusa Options

|Option|Meaning|
|---|---|
|`-h HOST`|Single target host|
|`-H FILE`|File containing multiple targets|
|`-u USERNAME`|Single username|
|`-U FILE`|Username list|
|`-p PASSWORD`|Single password|
|`-P FILE`|Password list|
|`-M MODULE`|Authentication module|
|`-m "MODULE_OPTION"`|Module-specific option|
|`-t TASKS`|Number of parallel tasks|
|`-f`|Stop after success on current host|
|`-F`|Stop after success across hosts|
|`-n PORT`|Non-default port|
|`-v LEVEL`|Verbosity level|

---

# 6. `-h` vs `-H`

This is important.

## `-h`

Single target:

```bash
-h 192.168.1.10
```

Meaning:

```text
Target = 192.168.1.10
```

## `-H`

Target list:

```bash
-H targets.txt
```

Example:

```text
targets.txt

192.168.1.10
192.168.1.20
192.168.1.30
```

### Memory trick

```text
-h → one Host
-H → Hosts file
```

---

# 7. `-u` vs `-U`

## Single username

```bash
-u admin
```

## Username list

```bash
-U usernames.txt
```

Example:

```text
usernames.txt

admin
root
user
administrator
guest
```

### Memory trick

```text
-u → one User
-U → Users list
```

---

# 8. `-p` vs `-P`

Same concept for passwords.

### Single password

```bash
-p password123
```

### Password list

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

# 9. `-M` — Module ⭐

The `-M` option selects the service/module Medusa should use.

Example:

```bash
-M ssh
```

means:

> Use the SSH authentication module.

Other examples from the source include:

```text
ftp
http
imap
mysql
pop3
rdp
ssh
svn
telnet
vnc
web-form
```

---

# 10. Medusa Modules

|Module|Service|Purpose|
|---|---|---|
|`ftp`|FTP|Test FTP authentication|
|`http`|HTTP|Test HTTP authentication|
|`imap`|IMAP|Test email authentication|
|`mysql`|MySQL|Test database authentication|
|`pop3`|POP3|Test email retrieval authentication|
|`rdp`|RDP|Test Windows remote login|
|`ssh`|SSHv2|Test SSH authentication|
|`svn`|Subversion|Test SVN authentication|
|`telnet`|Telnet|Test Telnet authentication|
|`vnc`|VNC|Test VNC authentication|
|`web-form`|Web Login Forms|Test HTTP POST login forms|

The key concept is:

> **The module tells Medusa how to communicate with the authentication service.**

---

# 11. `-m` — Module Options

Some services require additional information.

That's where:

```bash
-m "MODULE_OPTION"
```

comes in.

For example, the source gives an HTTP-related example involving:

```text
POST /login.php
```

and form parameters.

So conceptually:

```text
-M http
    +
-m "specific HTTP behavior"
```

tells Medusa both:

1. **Which protocol to use**
    
2. **How the particular authentication request should be constructed**
    

---

# 12. `-t` — Parallel Tasks

The `-t` option controls parallel authentication attempts.

Example:

```bash
-t 4
```

Conceptually:

```text
                 Medusa
                   │
       ┌───────────┼───────────┐
       ↓           ↓           ↓
     Task 1      Task 2      Task 3 ...
       │           │           │
       ↓           ↓           ↓
   Login test  Login test  Login test
```

More parallel tasks can improve speed, but excessive concurrency can:

- Overload a service
    
- Trigger rate limiting
    
- Cause connection failures
    
- Generate obvious attack traffic
    

In an authorized assessment, use the concurrency appropriate to the lab or engagement.

---

# 13. `-f` and `-F`

These are both **stop-after-success** options.

### `-f`

Stop after the first successful login on the **current host**.

### `-F`

Stop after a successful login across **any host**.

Memory:

```text
-f → current host
-F → any host
```

---

# 14. `-n` — Custom Port

Use:

```bash
-n PORT
```

when the target service isn't running on its standard port.

Example:

```bash
-n 2222
```

Conceptually:

```text
SSH
Default → 22

Target
→ 2222
```

---

# 15. `-v` — Verbosity

The source states that:

```bash
-v LEVEL
```

controls how much information Medusa displays.

The level can go up to:

```text
6
```

For example:

```bash
-v 4
```

provides more detailed output than a lower verbosity level.

---

# 16. Targeting an SSH Server

The source's example:

```bash
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh
```

means:

```text
Target
 ↓
192.168.0.100

Users
 ↓
usernames.txt

Passwords
 ↓
passwords.txt

Module
 ↓
SSH
```

### Workflow

```text
Username list
      +
Password list
      ↓
    Medusa
      ↓
   SSH module
      ↓
SSH authentication
```

This is an authorized penetration-testing/lab example.

---

# 17. Targeting Multiple Web Servers

The source gives:

```bash
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```

Here:

```text
-H web_servers.txt
```

means multiple targets.

```text
-U usernames.txt
```

means username list.

```text
-P passwords.txt
```

means password list.

```text
-M http
```

selects HTTP.

```text
-m GET
```

specifies the HTTP module behavior shown in the lab.

### Overall:

```text
              web_servers.txt
                     │
        ┌────────────┼────────────┐
        ↓            ↓            ↓
      Server 1     Server 2     Server 3
        │            │            │
        └────────────┼────────────┘
                     ↓
                  Medusa
                     ↓
              HTTP module
```

---

# 18. Empty and Default Password Checks

One particularly useful Medusa feature in the source is:

```bash
-e
```

The example:

```bash
medusa -h 10.0.0.5 -U usernames.txt -e ns -M service_name
```

uses:

```text
-e ns
```

The source explains:

```text
n → empty password
s → password matches username
```

So Medusa performs additional checks for:

### Empty password

```text
username:
password:
```

### Password equal to username

```text
username: admin
password: admin
```

---

# 19. Why Default Credentials Matter

This connects directly to your previous **Password Security** notes.

Organizations/devices may sometimes retain weak/default credentials.

Examples conceptually:

```text
admin : admin
user  : user
test  : test
```

Testing for these configurations can be useful during an authorized security assessment.

The key point is that the tester doesn't need to search an enormous password space if a weak/default configuration is suspected.

---

# 20. `-e ns` — Easy Memory

```text
-e n
```

→ **n = null/empty password**

```text
-e s
```

→ **s = same username as password**

Therefore:

```bash
-e ns
```

means:

```text
Try empty password
        +
Try username as password
```

---

# 21. Medusa vs Hydra ⭐⭐⭐

This is probably the most important comparison for your current module.

Both tools automate credential testing.

|Feature|Hydra|Medusa|
|---|---|---|
|Purpose|Network login/password testing|Network login/password testing|
|Parallel operation|✅|✅|
|Modular|✅|✅|
|Username list|`-L`|`-U`|
|Password list|`-P`|`-P`|
|Single username|`-l`|`-u`|
|Single password|`-p`|`-p`|
|Module selection|Service syntax/module|`-M`|
|Custom port|`-s`|`-n`|
|Stop after success|`-f`|`-f` / `-F`|
|Verbosity|`-v` / `-V`|`-v LEVEL`|

### ⭐ Biggest syntax difference

Hydra:

```text
-l / -L → login
```

Medusa:

```text
-u / -U → username
```

Don't mix these up.

---

# 22. Hydra vs Medusa — Memory Table

```text
HYDRA
────────────────
-l → one username
-L → username list
-p → one password
-P → password list
-s → port
-f → stop
```

```text
MEDUSA
────────────────
-u → one username
-U → username list
-p → one password
-P → password list
-n → port
-f/-F → stop
```

### Easy memory trick

> **Hydra uses L for Login; Medusa uses U for User.**

---

# 23. Medusa and Your Previous Topics

You've now covered several layers of password attacks:

```text
                    PASSWORD SECURITY
                           │
                           ↓
                  Weak passwords
                           │
          ┌────────────────┼────────────────┐
          ↓                ↓                ↓
     Brute Force       Dictionary         Hybrid
          │                │                │
          └────────────────┼────────────────┘
                           ↓
                    Credential Testing
                           │
                    ┌──────┴──────┐
                    ↓             ↓
                  Hydra          Medusa
                    │             │
                    └──────┬──────┘
                           ↓
                Automate authentication
                    against services
```

---

# 24. 🛡️ Defensive Perspective

Everything Medusa demonstrates also tells defenders what protections are needed.

### Rate Limiting

Limit repeated login attempts.

### Account Lockout

Temporarily restrict accounts after repeated failures.

### MFA

A password alone should ideally not be enough for sensitive systems.

### Strong Unique Passwords

Reduce dictionary and credential-based attacks.

### Disable Default Credentials

Change vendor defaults before deploying systems.

### Monitor Authentication

Look for:

```text
Many failed logins
       +
Many usernames
       +
Same source
       ↓
Potential automated attack
```

---

# 25. ⭐ Most Important Options to Memorize

```text
TARGETS
-h HOST       → one host
-H FILE       → host list

USERS
-u USER       → one username
-U FILE       → username list

PASSWORDS
-p PASS       → one password
-P FILE       → password list

MODULE
-M MODULE     → service/module
-m OPTION     → module-specific option

CONTROL
-t TASKS      → parallel tasks
-f            → stop on current host success
-F            → stop on any host success
-n PORT       → custom port
-v LEVEL      → verbosity

SPECIAL
-e ns         → empty password + username-as-password
```

---

# 26. 🧠 Final Mental Model

```text
                         MEDUSA
                           │
                 Fast + Parallel + Modular
                           │
            ┌──────────────┼──────────────┐
            ↓              ↓              ↓
         Targets         Users        Passwords
         -h / -H        -u / -U        -p / -P
            │              │              │
            └──────────────┼──────────────┘
                           ↓
                      -M MODULE
                           │
            ┌──────────────┼──────────────┐
            ↓              ↓              ↓
           SSH            FTP            HTTP
            │              │              │
            └──────────────┼──────────────┘
                           ↓
                    Authentication
                       attempts
                           │
                     ┌─────┴─────┐
                     ↓           ↓
                  Failure      Success
                     │           │
                     ↓           ↓
                Next pair      Stop*
                              *-f/-F
```

# 🎯 One-line takeaway

> **Medusa is a fast, parallel, modular login-testing tool that uses target lists, username/password lists, and service-specific modules to automate authentication testing.**

And the **big HTB takeaway** from this section:

> **Hydra and Medusa solve a similar problem, but their command-line syntax differs—especially `-l/-L` in Hydra versus `-u/-U` in Medusa, and `-s` versus `-n` for custom ports.**