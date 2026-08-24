![Image](https://images.openai.com/static-rsc-4/m8s2S5FsAzgJwgV5cbz5PiOh9jt9GT-hl0gbT3C9M_FUUq2GE_RLRRofbDHToFMBJgM-9SdnwiZ9ctAcxHebpMy8RS0NzxL7LHbkS7ty_wWemFoxoDkLV6SL92hlwM0NSrt2Wr2UjZSb_-24KOyfFqntsUb9ElFGLCJauXA_4zHvFJhxubSFJvgYsaeW1aGi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/udBxBTzSmcUGkCKZgfbPl8wJkFgmcr2PHiMXaeRqSn2plAPBtYbsOQkELB19OcITMidNbv4sLOda0nYPkhQGdd28u8pYZXt123F29ooinjRxrFdaTvx-MUOjMM6c5tXCGCnuiOmhBB6xJ2H_2j7BFoqe1L3XA6nxMa_SpkAERU37Q6HvipYBEhD_nPwewWG8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zxqfkxV_rvNEM_Ezl_K3HPIqwZWxVgxcDr_E-GFrL7aH2UfqbyUQrmsLrbfGGVG1FmwGaDGKKN40c2ipPVP2tYPhwbrkDkILDGyjyfQm6C4Wm9nj0fxGO3mSF4XYOhWzawTfn6Ogop5qH3ohoalcyB4pSHG3bln3QuGg4t8cH5EtPDEZumYKV7HqObha9FGv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/byy4hprgZ4Bpg6mNH4Ak0MHz3E6CVMEgWmWFqYyiv_LVqsjSnEPrEZbYX43Jxlo_l9cYiXrfY6HjpRWM8yiJ95yBVPn2WW3Jw9yj0dS8i8vB5F-XLJZv2_uZodFtS2UWYwWWNRkQBiRZvTuxY_Vgbt2N012_6ostNT92pj7kTyx9uSlYN1f3k1slAcpKLf7N?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/i_2sdOTCrwY5CaCUEY6DYuto-udSuVRG6DeDODqg0WU0uMCDDsbAvzMxQPU_xGPg726DIosWMf-EDx3Cc2Fqhpb4ab5wGZNzP7UkYqDoBAYJFLUY--Ui8IpUpfjadWIVYvpUJmErakCItMMnZ2FqJu7IdifBT3l5KObpsdrEzussihsCsEXYs5cce-UPvAoN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/oThn9iLoxmMavog0intABjkZh14mZGKzl2wVILlaPRKsgFRGiA8lshb6OAm3QVqUdTXHzmnT4BywnAk2M1JDLSn5ceE2Gsx6dL1I2ONzT7zai8JZ7bnTRjGhG1d8WYDbXFtEqCe9-Sf6B64FWyqn0qSxT6Uo1rLBGM1qeem9Op6_ilrPZqVQixTdE_fEhfbu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CEvYQr6Zdn8JRuIkUsKdYCmiBcUKUdpK8GryvYLkgSYQu3fBSET4cqzOWZdZivGVfYDrqTN-i0j_kv-UUVLs1CgI5WQ1RmPBnD4NwYczJARP20UBHmF5xh8yNtBYAexR2hE2LBAi-5AazocXthPbjWN41qz8OCC2ZG_lKy-YuLlAycZJy27e30_u6pSg5xTx?purpose=fullsize)

## 1. Introduction

In this section, we learn how to use `ffuf` to identify sub-domains:

```text
*.website.com
```

For example, if the main domain is:

```text
google.com
```

possible subdomains include:

```text
photos.google.com
mail.google.com
drive.google.com
```

The general structure is:

```text
SUBDOMAIN.DOMAIN.TLD
```

For example:

```text
photos.google.com
   │       │      │
   │       │      └── TLD
   │       └───────── Domain
   └───────────────── Subdomain
```

---

# 2. What Is a Subdomain?

A **subdomain** is a hostname underneath another domain.

For example:

```text
https://photos.google.com
```

Here:

```text
photos
```

is the subdomain of:

```text
google.com
```

Other examples:

```text
mail.google.com
drive.google.com
maps.google.com
```

Conceptually:

```text
                 google.com
                     │
       ┌─────────────┼─────────────┐
       ▼             ▼             ▼
   photos          mail           drive
       │             │             │
       ▼             ▼             ▼
photos.google   mail.google   drive.google
    .com           .com          .com
```

---

# 3. Why Do We Enumerate Subdomains?

A website may have different applications running under different subdomains.

For example:

```text
example.com
www.example.com
admin.example.com
dev.example.com
api.example.com
mail.example.com
```

The main website might look completely normal while another subdomain contains:

```text
Admin panel
Development application
API
Testing environment
Internal portal
Login system
```

Therefore:

> **Directory enumeration searches within a website, while subdomain enumeration searches for other websites/hostnames associated with the domain.**

---

# 4. Directory vs Subdomain Enumeration

This distinction is extremely important.

### Directory fuzzing

```text
https://example.com/FUZZ
```

might discover:

```text
/admin
/login
/blog
/uploads
```

### Subdomain fuzzing

```text
https://FUZZ.example.com/
```

might discover:

```text
admin.example.com
blog.example.com
dev.example.com
```

So:

```text
Directory:
example.com/FUZZ

Subdomain:
FUZZ.example.com
```

---

# 5. What Are We Actually Checking?

The module explains that we are checking different hostnames to determine whether they exist.

Conceptually:

```text
FUZZ.example.com
       ↓
Does this hostname exist?
       ↓
DNS resolution
       ↓
IP address?
       ↓
Try connecting
       ↓
Analyze response
```

If a hostname resolves and returns an interesting response, we have potentially discovered a valid subdomain.

---

# 6. Wordlists

As with directory fuzzing, we need a wordlist.

SecLists contains dedicated DNS/subdomain wordlists under:

```text
/opt/useful/seclists/Discovery/DNS/
```

A commonly used list in this module is:

```text
subdomains-top1million-5000.txt
```

Full path:

```text
/opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

# 7. Why Use a Subdomain Wordlist?

Subdomains often use predictable names.

Common examples include:

```text
www
mail
admin
dev
test
api
blog
support
portal
vpn
```

Instead of manually testing every possible hostname, we use a wordlist containing common subdomain names.

For example:

```text
admin
dev
test
api
blog
mail
support
```

becomes:

```text
admin.example.com
dev.example.com
test.example.com
api.example.com
blog.example.com
mail.example.com
support.example.com
```

---

# 8. `subdomains-top1million-5000.txt`

The wordlist:

```text
subdomains-top1million-5000.txt
```

is a relatively small list containing common subdomain names.

The module uses it because it provides a good balance between:

```text
Coverage
   +
Speed
```

Larger lists can be used if more extensive enumeration is required.

---

# 9. Fuzzing the Subdomain Position

This is the most important syntax change.

For directory fuzzing, we used:

```text
https://example.com/FUZZ
```

For subdomain fuzzing, we use:

```text
https://FUZZ.example.com/
```

The `FUZZ` keyword is placed **before the main domain**.

---

# 10. Example

Suppose our wordlist contains:

```text
www
blog
admin
support
```

Command:

```bash
ffuf -w subdomains.txt:FUZZ \
-u https://FUZZ.example.com/
```

Ffuf effectively tests:

```text
https://www.example.com/
https://blog.example.com/
https://admin.example.com/
https://support.example.com/
```

---

# 11. The HTB Example — `inlanefreight.com`

The module uses:

```text
inlanefreight.com
```

as the example target.

The command is:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u https://FUZZ.inlanefreight.com/
```

---

# 12. Command Breakdown

### `ffuf`

Starts ffuf.

```text
ffuf
```

### `-w`

Specifies the wordlist:

```text
-w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ
```

### `:FUZZ`

Assigns the wordlist to the `FUZZ` keyword.

### `-u`

Specifies the target URL:

```text
-u https://FUZZ.inlanefreight.com/
```

The key part is:

```text
FUZZ.inlanefreight.com
```

---

# 13. What Does Ffuf Test?

If the wordlist contains:

```text
support
ns3
blog
my
www
```

ffuf tests:

```text
https://support.inlanefreight.com/
https://ns3.inlanefreight.com/
https://blog.inlanefreight.com/
https://my.inlanefreight.com/
https://www.inlanefreight.com/
```

---

# 14. Example Results

The module receives results such as:

```text
[Status: 301, Size: 0, Words: 1, Lines: 1]
    * FUZZ: support

[Status: 301, Size: 0, Words: 1, Lines: 1]
    * FUZZ: ns3

[Status: 301, Size: 0, Words: 1, Lines: 1]
    * FUZZ: blog

[Status: 301, Size: 0, Words: 1, Lines: 1]
    * FUZZ: my

[Status: 200, Size: 22266, Words: 2903, Lines: 316]
    * FUZZ: www
```

This indicates that several candidate subdomains produced interesting responses.

For example:

```text
support.inlanefreight.com
blog.inlanefreight.com
www.inlanefreight.com
```

---

# 15. Understanding `FUZZ: www`

When ffuf reports:

```text
* FUZZ: www
```

it means the word:

```text
www
```

from the wordlist produced the response.

Therefore the tested hostname was:

```text
www.inlanefreight.com
```

---

# 16. Status Codes Matter

Just like directory fuzzing, HTTP status codes help us determine which results deserve investigation.

Important responses include:

|Status|Meaning|
|---|---|
|`200`|OK|
|`301`|Permanent redirect|
|`302`|Temporary redirect|
|`401`|Unauthorized|
|`403`|Forbidden|
|`405`|Method Not Allowed|
|`500`|Internal Server Error|

A `200` is obviously interesting, but don't automatically ignore:

```text
301
302
401
403
```

These can also indicate valid resources.

---

# 17. Why `301` Can Be Interesting

Suppose ffuf finds:

```text
FUZZ: blog
Status: 301
```

This could mean:

```text
blog.inlanefreight.com
       ↓
valid hostname
       ↓
server redirects somewhere
```

The redirect destination may reveal useful information.

Therefore, manually investigate interesting responses.

---

# 18. Now Apply the Technique to `academy.htb`

Previously we discovered:

```text
academy.htb
```

and added it to:

```text
/etc/hosts
```

using:

```bash
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

We might therefore try:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://FUZZ.academy.htb/
```

---

# 19. The Result

The scan produces:

```text
:: Progress: [4997/4997]
:: Job [1/1]
:: 131 req/sec
:: Duration: [0:00:38]
:: Errors: 4997
```

And importantly:

```text
No hits
```

At first glance, it might seem that:

> There are no subdomains under `academy.htb`.

But **that conclusion is incorrect**.

---

# 20. Why Didn't We Find Anything?

The key issue is:

```text
academy.htb
```

is a **private HTB hostname**.

It isn't a normal public domain with publicly accessible DNS records.

We added only:

```text
academy.htb → SERVER_IP
```

to `/etc/hosts`.

We did **not** add:

```text
admin.academy.htb → SERVER_IP
blog.academy.htb → SERVER_IP
dev.academy.htb → SERVER_IP
```

etc.

---

# 21. What Happens When Ffuf Tests `FUZZ.academy.htb`?

Suppose ffuf tries:

```text
admin.academy.htb
```

The operating system asks:

```text
"Where is admin.academy.htb?"
```

It checks the local hostname resolution configuration.

Our `/etc/hosts` contains:

```text
SERVER_IP academy.htb
```

but **not**:

```text
SERVER_IP admin.academy.htb
```

Therefore, the exact hostname isn't found there.

---

# 22. Then Public DNS Is Asked

The system may then try DNS.

Conceptually:

```text
admin.academy.htb
       ↓
/etc/hosts
       ↓
Not found
       ↓
Public DNS
       ↓
Not found
```

Why?

Because:

```text
academy.htb
```

is part of the private HTB environment.

Public DNS doesn't know the lab's internal hostnames.

---

# 23. This Produces Errors

That's why the scan shows:

```text
Errors: 4997
```

The important clue is:

```text
4997 errors
```

which corresponds closely to the number of attempted entries.

This isn't the same situation as:

```text
All 4997 hosts responded with 404
```

Instead, the requests are failing because the hostnames cannot be resolved/reached in the way the scan expects.

---

# 24. Very Important Distinction

There are two different situations.

### Situation A — Public domain

```text
example.com
```

Subdomains may have public DNS records:

```text
admin.example.com
blog.example.com
dev.example.com
```

A normal DNS-based subdomain scan can discover them.

---

### Situation B — Private HTB domain

```text
academy.htb
```

We manually add:

```text
academy.htb → SERVER_IP
```

But that doesn't automatically create:

```text
admin.academy.htb → SERVER_IP
blog.academy.htb → SERVER_IP
dev.academy.htb → SERVER_IP
```

Therefore, normal public DNS-based subdomain enumeration won't work.

---

# 25. `/etc/hosts` Is Exact

This is a very important concept.

If `/etc/hosts` contains:

```text
10.10.10.10 academy.htb
```

that means:

```text
academy.htb → 10.10.10.10
```

It does **not** mean:

```text
*.academy.htb → 10.10.10.10
```

In other words:

> **A hosts-file entry for a parent domain does not automatically create entries for its subdomains.**

---

# 26. Visualizing the Problem

Our hosts file:

```text
/etc/hosts

SERVER_IP    academy.htb
```

What we want to test:

```text
admin.academy.htb
blog.academy.htb
dev.academy.htb
test.academy.htb
```

But the system only knows:

```text
academy.htb
     │
     └── SERVER_IP
```

It doesn't automatically know:

```text
admin.academy.htb
blog.academy.htb
dev.academy.htb
```

---

# 27. DNS Enumeration vs Virtual Host Enumeration

This leads to a very important distinction.

### DNS-based subdomain enumeration

We ask:

> Does this hostname have a DNS record?

Example:

```text
admin.example.com
       ↓
DNS
       ↓
IP?
```

### Virtual host enumeration

We ask:

> Does the web server respond differently when I request this hostname?

For example:

```http
GET / HTTP/1.1
Host: admin.academy.htb
```

The IP can remain the same:

```text
SERVER_IP
```

while the `Host` header changes.

This is especially important in private HTB environments.

---

# 28. Same IP, Different Hostnames

Imagine:

```text
SERVER_IP
    │
    ├── academy.htb
    │
    ├── admin.academy.htb
    │
    └── dev.academy.htb
```

All three may point to the same IP.

The web server uses the hostname to determine which application/site should respond.

For example:

```http
Host: academy.htb
```

might return:

```text
Main Academy website
```

while:

```http
Host: admin.academy.htb
```

might return:

```text
Admin panel
```

---

# 29. Why the Module's Next Step Matters

At this point:

```text
Directory fuzzing
        ↓
Recursive fuzzing
        ↓
No admin panel
        ↓
Application says "Admin panel moved"
        ↓
academy.htb
        ↓
Same website
        ↓
Public DNS subdomain fuzzing
        ↓
No results
```

We now know that simply asking public DNS about:

```text
*.academy.htb
```

doesn't work.

The next logical technique is to test the **web server's handling of different hostnames**.

This is commonly called:

> **Virtual Host (vhost) fuzzing.**

---

# 30. Subdomain Fuzzing Command

For a public domain:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u https://FUZZ.inlanefreight.com/
```

The key structure is:

```text
https://FUZZ.DOMAIN/
```

---

# 31. What We Are Replacing

If:

```text
FUZZ = admin
```

then:

```text
https://FUZZ.inlanefreight.com/
```

becomes:

```text
https://admin.inlanefreight.com/
```

If:

```text
FUZZ = blog
```

then:

```text
https://blog.inlanefreight.com/
```

This is the same keyword substitution technique used throughout the module.

---

# 32. Comparison With Directory Fuzzing

### Directory

```text
https://example.com/FUZZ
```

tests:

```text
/admin
/blog
/login
```

### Subdomain

```text
https://FUZZ.example.com/
```

tests:

```text
admin.example.com
blog.example.com
login.example.com
```

### File

```text
https://example.com/FUZZ.php
```

tests:

```text
/admin.php
/login.php
/index.php
```

This gives us three useful patterns:

```text
Directory → example.com/FUZZ
File      → example.com/FUZZ.php
Subdomain → FUZZ.example.com
```

---

# 33. Common Subdomain Wordlist Entries

Typical entries include:

```text
www
mail
admin
api
dev
test
staging
portal
support
blog
vpn
remote
```

The exact list varies depending on the wordlist.

---

# 34. Why Larger Wordlists Exist

The module uses:

```text
subdomains-top1million-5000.txt
```

because it is relatively fast.

However, a small list can miss unusual subdomains.

For example:

```text
internal-api
legacy
uat
qa
customer
dashboard
```

might not be included near the top of a small list.

Therefore:

```text
Small list
   ↓
Fast initial enumeration
```

then:

```text
Larger list
   ↓
Broader enumeration
```

is a sensible approach.

---

# 35. Important Lesson — No Results Doesn't Always Mean No Subdomains

This is probably the most important lesson from the section.

If you receive:

```text
No hits
```

don't immediately conclude:

```text
There are no subdomains.
```

First ask:

> **Was my enumeration method capable of seeing the subdomains?**

In this case:

```text
Public DNS enumeration
       ↓
Private HTB domain
       ↓
Public DNS doesn't know the hosts
       ↓
No results
```

Therefore, the methodology—not necessarily the target—is the problem.

---

# 36. Error Interpretation

Compare these two outcomes.

### Outcome A

```text
4997 requests
4997 errors
```

This suggests a connectivity/resolution problem.

### Outcome B

```text
4997 requests
0 errors
0 interesting results
```

This would be a very different situation.

It could indicate that the requests completed successfully but none matched the configured criteria.

Therefore:

> **Always read the error count, not just the number of hits.**

---

# 37. Common Mistakes

## Mistake 1 — Thinking `/etc/hosts` supports wildcards automatically

Adding:

```text
SERVER_IP academy.htb
```

doesn't automatically make:

```text
anything.academy.htb
```

resolve.

---

## Mistake 2 — Assuming no hits means no subdomains

The scan may simply be using the wrong discovery mechanism.

---

## Mistake 3 — Confusing subdomains with directories

These are completely different:

```text
academy.htb/admin
```

vs:

```text
admin.academy.htb
```

The first is a directory.

The second is a hostname/subdomain.

---

## Mistake 4 — Ignoring errors

If ffuf reports:

```text
Errors: 4997
```

don't interpret that as:

> "The wordlist found nothing."

Investigate why the requests failed.

---

# 38. Useful Commands

### Check the hosts file

```bash
cat /etc/hosts
```

### Test the parent domain

```bash
getent hosts academy.htb
```

### Test a potential subdomain

```bash
getent hosts admin.academy.htb
```

If the second one doesn't resolve, that is evidence that the hostname isn't present in local/public DNS resolution.

---

# 39. Manual `/etc/hosts` Example

If we already knew a subdomain:

```text
admin.academy.htb
```

and knew it should point to the same server, we could explicitly map it:

```bash
sudo sh -c 'echo "SERVER_IP  admin.academy.htb" >> /etc/hosts'
```

Then:

```text
admin.academy.htb
        ↓
SERVER_IP
```

would resolve locally.

But during enumeration we **don't know the correct subdomain yet**, which is why manually adding entries isn't practical for discovering unknown hosts.

---

# 40. The Key Transition

This section sets up the transition from:

```text
DNS-based subdomain fuzzing
```

to:

```text
Virtual-host fuzzing
```

The difference is:

### DNS approach

```text
FUZZ.academy.htb
       ↓
Ask DNS
       ↓
Does hostname resolve?
```

### VHost approach

```text
SERVER_IP
   +
Host: FUZZ.academy.htb
       ↓
Ask web server
       ↓
Does it respond differently?
```

This distinction is **extremely important in penetration testing**.

---

# 41. Full Enumeration Methodology So Far

```text
                    TARGET
                       │
                       ▼
               Directory Fuzzing
                       │
                       ▼
                    /blog
                       │
                       ▼
               Extension Fuzzing
                       │
                       ▼
                     .php
                       │
                       ▼
                 Page Fuzzing
                       │
                       ▼
              Hidden PHP Pages
                       │
                       ▼
             Recursive Fuzzing
                       │
                       ▼
              Deeper Enumeration
                       │
                       ▼
             "Admin panel moved"
                       │
                       ▼
                  academy.htb
                       │
                       ▼
                /etc/hosts
                       │
                       ▼
               Same Application
                       │
                       ▼
           Public Subdomain Fuzzing
                       │
                       ▼
                No DNS results
                       │
                       ▼
             Private DNS Problem
                       │
                       ▼
              VHost Enumeration
```

---

# 42. Exam / Viva Questions

### Q1. What is a subdomain?

A hostname underneath a parent domain.

Example:

```text
admin.example.com
```

where `admin` is the subdomain.

---

### Q2. Where are SecLists DNS wordlists stored?

```text
/opt/useful/seclists/Discovery/DNS/
```

---

### Q3. Which wordlist does the module use?

```text
subdomains-top1million-5000.txt
```

---

### Q4. What URL format is used for subdomain fuzzing?

```text
https://FUZZ.example.com/
```

---

### Q5. What does `FUZZ` represent?

A candidate subdomain from the wordlist.

---

### Q6. Why did subdomain fuzzing against `academy.htb` return no hits?

Because `academy.htb` is a private HTB domain and its subdomains do not have publicly resolvable DNS records.

---

### Q7. Why didn't `/etc/hosts` solve the problem?

Because only:

```text
academy.htb
```

was added to `/etc/hosts`.

The file does not automatically create mappings for:

```text
*.academy.htb
```

---

### Q8. What does `Errors: 4997` indicate?

The requests encountered errors, consistent with the candidate hostnames not being resolvable/reachable through the public DNS-based approach.

---

### Q9. What is the difference between:

```text
academy.htb/admin
```

and:

```text
admin.academy.htb
```

The first is a path/directory on the main host. The second is a separate hostname/subdomain.

---

### Q10. What technique is useful when private subdomains don't have public DNS records?

**Virtual host (vhost) enumeration/fuzzing**, where candidate hostnames are sent to the web server rather than relying on public DNS to resolve each hostname.

---

# 43. Quick Revision

```text
SUBDOMAIN FUZZING
       │
       ▼
Wordlist
       │
       ▼
FUZZ.example.com
       │
       ▼
DNS Resolution
       │
       ▼
Does hostname exist?
       │
       ▼
Analyze response
```

### Public domain:

```text
FUZZ.inlanefreight.com
        ↓
Public DNS
        ↓
IP
        ↓
Web Server
```

### Private HTB domain:

```text
FUZZ.academy.htb
        ↓
/etc/hosts?
        ↓
Not found
        ↓
Public DNS?
        ↓
Not found
        ↓
Errors
```

---

# 44. Most Important Commands

### Public subdomain enumeration

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u https://FUZZ.inlanefreight.com/
```

### Check local hostname resolution

```bash
getent hosts academy.htb
```

### Check whether a candidate subdomain resolves

```bash
getent hosts admin.academy.htb
```

### View hosts mappings

```bash
cat /etc/hosts
```

---

# 45. Golden Mental Model

Remember these three:

```text
Directory:
https://example.com/FUZZ
```

```text
File:
https://example.com/FUZZ.php
```

```text
Subdomain:
https://FUZZ.example.com/
```

And remember:

```text
academy.htb → /etc/hosts
```

does **not** mean:

```text
*.academy.htb → /etc/hosts
```

---

# 46. Final Takeaways

> **Subdomain fuzzing searches for hostnames such as `admin.example.com` rather than directories such as `/admin`.**

> **The `FUZZ` keyword goes before the main domain: `FUZZ.example.com`.**

> **SecLists provides dedicated DNS/subdomain wordlists.**

> **`subdomains-top1million-5000.txt` is used in this module for initial enumeration.**

> **A successful `200`, `301`, `302`, `401`, or `403` response can be worth investigating.**

> **No results do not necessarily mean no subdomains exist.**

> **For private HTB domains, public DNS cannot resolve internal subdomains.**

> **Adding `academy.htb` to `/etc/hosts` only maps that exact hostname; it does not automatically map `*.academy.htb`.**

> **The large error count is an important clue that the DNS-based approach isn't working against the private domain.**

> **When DNS-based enumeration fails against a private lab domain, the next logical technique is virtual-host enumeration.**

### The big picture:

```text
Public Domain
     │
     ▼
FUZZ.example.com
     │
     ▼
Public DNS
     │
     ▼
Subdomain discovered
```

versus:

```text
Private HTB Domain
     │
     ▼
FUZZ.academy.htb
     │
     ▼
Public DNS
     │
     ✕
     │
     ▼
No resolution
     │
     ▼
VHost Fuzzing
```

**Key lesson:** Don't confuse **DNS discovery** with **web-server hostname discovery**. A hostname can be meaningful to a web server even when it has no public DNS record. That distinction is exactly what the next stage of the module builds upon.

:::