Absolutely bro — this section introduces a **very important real-world web enumeration concept: DNS resolution, `/etc/hosts`, domains, and the transition from directory fuzzing to subdomain/vhost discovery**.

![Image](https://images.openai.com/static-rsc-4/Eei_FoAj6ey2QUSoyRvjzgmWAAgX12kmvBc0tvnjIpsL3RMLR3lEIChBjVrdVa5dJD76ub1S-TVZW1pvbYZTgwZzOGqI1rLfRPoiVmLYdASgeKJEYZcDB9LR_S4zviVbLRFQMdaMK3ln2XTaPmd13YE4nIT9qnWLk0qKyBv0FT6Iakn_MrhKTSR5k_ChULaD?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/__MlgwW5RvTFNvf7aSihVu8HJaTXLfLsRyRl223zcQoi3BOAbuue-8EQx3AN8IXC0S6i6ojfKAiX2Ia5Lv7mDoasZI-8Q_VkImw6NcOcy6WxJwZF1BsgN8qpnDBqDPCev1S1fE9naoXyLnt2OR3YPFWsPcDuWvX-dKiOCrftdwml4WmzkAGunyz7wIRQDWHc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4ZvuRA0x-zam6tJYVsXTZ7tbTXLAcDhB6phIdUNaYt_TwoDiHr1hYIr94dc4mk91Jh75WVvGPjIGujMhP30lBz_m8KT2y0UxkodoEi6teIEf6BlO47qQL--AdZGfkcgxbVp92UVzIe59avob920jFReqNvVLfzjkdMLFb8-nKEz7m_0LgXHp7VOoqhla52dm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/keju1GCrPxSgvA3JVZ_ZRDEHBOAQmtfeEE7OnJYOjmP9-WvBgKJaavj5Kh1gYXhNBN4t4JIyUvHcb4rfi_hrQI6JCqskbaj_Eu-GkxJk6q7M6qIHG-awpgzydp0czzy20cJ_a_BUZEZpSkQZ4cI6GUifAt81q3khDzby39rP8gE4NxNc9ZmJlcD3jW-qL91E?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OSIddkSfA7aIFN_wJ4nFFjvH2TwWtOaTLrLSG0I1gGxrnS9PrEqMfOUV5S3qlRiz0L9QXptepdk3tKNQETdafmrR0xhP-3YHtIkJdmeYYq1sthwj2iK36ed74sNh8rkeQwfRDqv9oF1Ie6Yc5d77e1WQoKJZVmP7iONWPP3d36_Df6yRrqnEXRm3Nyedaeli?purpose=fullsize)

# 1. Introduction

During our previous enumeration, we accessed:

```text
/blog
```

and discovered a message:

```text
Admin panel moved to academy.htb
```

This is an important discovery.

It tells us that the application is referring us to another hostname:

```text
academy.htb
```

Naturally, we try to access:

```text
http://academy.htb:PORT
```

However, the browser reports that it cannot connect.

---

# 2. Why Can't We Access `academy.htb`?

The important thing to understand is that HTB Academy targets are usually **private lab environments**, not publicly accessible websites.

The domain:

```text
academy.htb
```

is not necessarily registered in public DNS.

Therefore, our computer doesn't automatically know which IP address it should connect to.

The browser needs to resolve:

```text
academy.htb
     ↓
SERVER_IP
```

before it can connect.

---

# 3. Domain Names vs IP Addresses

A computer ultimately communicates with an IP address.

For example:

```text
10.10.10.10
```

is an IP address.

A human-friendly domain name might be:

```text
academy.htb
```

DNS provides the mapping:

```text
academy.htb
       ↓
10.10.10.10
```

So instead of remembering:

```text
10.10.10.10
```

we can use:

```text
academy.htb
```

---

# 4. What Is DNS?

**DNS** stands for:

> **Domain Name System**

Its primary purpose is to translate domain names into IP addresses.

For example:

```text
www.example.com
       ↓
IP address
```

Conceptually:

```text
Browser
   │
   │ "Where is academy.htb?"
   ▼
DNS
   │
   │ "It is at SERVER_IP"
   ▼
Browser
   │
   ▼
SERVER_IP
```

---

# 5. Why Does `academy.htb` Fail?

When we enter:

```text
http://academy.htb:PORT
```

the browser needs to determine:

```text
academy.htb → ?
```

It checks available name-resolution sources.

In the HTB lab environment, the domain isn't publicly registered, so public DNS won't provide the required mapping.

If the domain isn't found locally either, resolution fails.

---

# 6. `/etc/hosts`

Linux provides a local file that can manually map hostnames to IP addresses:

```text
/etc/hosts
```

This file allows us to tell our computer:

```text
academy.htb
      ↓
SERVER_IP
```

without requiring a public DNS record.

---

# 7. Example `/etc/hosts`

A typical hosts file might contain:

```text
127.0.0.1       localhost
127.0.1.1       kali
```

We can add:

```text
10.10.10.10     academy.htb
```

Now the operating system can resolve:

```text
academy.htb
```

to:

```text
10.10.10.10
```

---

# 8. The HTB Command

The module uses:

```bash
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

Replace:

```text
SERVER_IP
```

with the IP address of the HTB target.

For example:

```bash
sudo sh -c 'echo "10.10.10.10  academy.htb" >> /etc/hosts'
```

---

# 9. Breaking Down the Command

Let's understand it piece by piece.

### `sudo`

```text
sudo
```

Runs the command with elevated privileges.

This is required because `/etc/hosts` is normally writable only by root.

---

### `sh -c`

```text
sh -c '...'
```

Runs the quoted command through a shell with the required privileges.

---

### `echo`

```text
echo "SERVER_IP academy.htb"
```

Produces the desired hosts-file entry.

---

### `>>`

```text
>>
```

Appends the output to the file instead of overwriting the existing contents.

This is important.

```text
>
```

would overwrite.

Whereas:

```text
>>
```

appends.

---

### `/etc/hosts`

The destination file:

```text
/etc/hosts
```

---

# 10. Result

After running:

```bash
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

our system now knows:

```text
academy.htb → SERVER_IP
```

Therefore, when we visit:

```text
http://academy.htb:PORT
```

the browser can connect to the target.

---

# 11. Verifying the Mapping

We can inspect the hosts file:

```bash
cat /etc/hosts
```

We should see something similar to:

```text
SERVER_IP    academy.htb
```

We can also test resolution:

```bash
getent hosts academy.htb
```

Expected conceptually:

```text
SERVER_IP    academy.htb
```

---

# 12. Another Useful Test

We can also use:

```bash
ping -c 1 academy.htb
```

However, don't rely on ping as proof that the web service is working.

ICMP may be disabled.

A successful web connection is better tested with:

```bash
curl -I http://academy.htb:PORT/
```

or by opening it in a browser.

---

# 13. Important — The Port Still Matters

Adding an entry to `/etc/hosts` only solves **hostname resolution**.

It doesn't automatically specify the HTTP port.

If the target is running on:

```text
PORT
```

you still need:

```text
http://academy.htb:PORT
```

For example:

```text
http://academy.htb:8080
```

not necessarily:

```text
http://academy.htb
```

---

# 14. Why Does the Domain Show the Same Website?

After adding:

```text
academy.htb → SERVER_IP
```

we visit:

```text
http://academy.htb:PORT
```

and see the same website that we saw when accessing:

```text
http://SERVER_IP:PORT
```

This tells us that:

```text
academy.htb
      ↓
same server/application
```

At least for the request being made, the hostname doesn't lead to a different application.

---

# 15. Verifying with `/blog/index.php`

We can verify this further by visiting:

```text
http://academy.htb:PORT/blog/index.php
```

If we can access the same page, then we know:

```text
academy.htb
      ↓
SERVER_IP
      ↓
same application
```

This is useful because it confirms that simply adding the hostname hasn't magically exposed the admin panel.

---

# 16. Important Clue: "Admin Panel Moved"

The message:

```text
Admin panel moved to academy.htb
```

is still extremely important.

Why?

Because it suggests that the application may have **multiple hostnames**.

For example:

```text
academy.htb
admin.academy.htb
dev.academy.htb
staging.academy.htb
```

could potentially point to different applications.

---

# 17. What Is a Subdomain?

A subdomain is a hostname that exists under a parent domain.

Parent domain:

```text
academy.htb
```

Possible subdomains:

```text
www.academy.htb
admin.academy.htb
dev.academy.htb
test.academy.htb
staging.academy.htb
```

The structure is:

```text
             academy.htb
                  │
       ┌──────────┼───────────┐
       ▼          ▼           ▼
     admin       dev         www
       │          │           │
       ▼          ▼           ▼
admin.academy  dev.academy  www.academy
     .htb         .htb         .htb
```

---

# 18. Why Search for Subdomains?

The main website may not contain the functionality we're looking for.

We already performed extensive enumeration and didn't discover:

```text
admin
admin.php
/admin/
/panel/
```

Yet the application explicitly told us:

```text
Admin panel moved to academy.htb
```

This suggests the panel may be accessible through another hostname.

Therefore, we should investigate:

```text
*.academy.htb
```

---

# 19. Subdomain Enumeration

Subdomain enumeration is the process of discovering hostnames under a domain.

For example:

```text
academy.htb
```

could have:

```text
admin.academy.htb
dev.academy.htb
test.academy.htb
portal.academy.htb
```

The goal is to determine which of these actually exist.

---

# 20. DNS Records vs Subdomains

These concepts are related but not identical.

### DNS records

DNS stores information about domains and hostnames.

Examples include:

```text
A
AAAA
CNAME
MX
TXT
NS
```

### Subdomain enumeration

We are specifically trying to discover:

```text
admin.academy.htb
dev.academy.htb
```

that may point to services or applications.

---

# 21. Why Public DNS Doesn't Help Here

The target is an HTB lab system.

Therefore:

```text
academy.htb
```

isn't necessarily publicly registered.

Similarly:

```text
admin.academy.htb
```

may only exist inside the lab environment.

So public DNS servers may not know anything about them.

This is why local testing and techniques such as virtual-host fuzzing are important.

---

# 22. `/etc/hosts` and Subdomains

If we discover:

```text
admin.academy.htb
```

we may need to add it to `/etc/hosts` too.

For example:

```bash
sudo sh -c 'echo "SERVER_IP  admin.academy.htb" >> /etc/hosts'
```

Then:

```text
http://admin.academy.htb:PORT
```

can resolve to the target.

---

# 23. One IP Can Host Multiple Websites

This is a very important web concept.

One IP address:

```text
10.10.10.10
```

can host multiple websites:

```text
academy.htb
admin.academy.htb
dev.academy.htb
```

The web server can determine which site the client wants based on the hostname in the HTTP request.

For example:

```http
GET / HTTP/1.1
Host: academy.htb
```

versus:

```http
GET / HTTP/1.1
Host: admin.academy.htb
```

The same IP can respond differently to these requests.

---

# 24. Why This Matters for HTB

This explains why a complete directory scan against:

```text
http://SERVER_IP:PORT/
```

may still miss an admin panel.

The panel may not be located at:

```text
/admin
```

Instead, it could be hosted at:

```text
admin.academy.htb
```

Therefore:

```text
Directory enumeration
        +
Subdomain/vhost enumeration
```

gives us broader coverage.

---

# 25. The Enumeration Decision

At this point, we have:

```text
Main IP
  ↓
Directory fuzzing
  ↓
Recursive fuzzing
  ↓
PHP page fuzzing
  ↓
No admin panel
  ↓
Application says:
"Admin panel moved to academy.htb"
  ↓
academy.htb resolves to same application
  ↓
Search *.academy.htb
```

This is the key reasoning step in the section.

---

# 26. Why We Move to Subdomain Enumeration

We already searched the application's:

```text
Directories
Files
PHP pages
Subdirectories
```

and didn't find the admin panel.

But the application explicitly mentions:

```text
academy.htb
```

This is a clue that another hostname may exist.

Therefore, our next logical step is:

```text
*.academy.htb
```

---

# 27. Practical Workflow

```text
Discover message
       ↓
"Admin panel moved to academy.htb"
       ↓
Try academy.htb
       ↓
DNS resolution fails
       ↓
Add academy.htb to /etc/hosts
       ↓
Visit academy.htb
       ↓
Same website
       ↓
Verify /blog/index.php
       ↓
No admin panel
       ↓
Enumerate subdomains
       ↓
*.academy.htb
```

---

# 28. Common Mistakes

## Mistake 1 — Thinking `/etc/hosts` is DNS

It isn't exactly the same thing.

`/etc/hosts` is a local static hostname-to-IP mapping.

It can override/precede normal DNS resolution depending on the system's resolver configuration.

---

## Mistake 2 — Forgetting the port

Adding:

```text
academy.htb → SERVER_IP
```

doesn't mean the service is automatically available on port 80.

Use:

```text
http://academy.htb:PORT
```

when the lab specifies a custom port.

---

## Mistake 3 — Assuming the parent domain is the admin panel

The message mentioning:

```text
academy.htb
```

doesn't necessarily mean:

```text
http://academy.htb:PORT
```

is itself the admin panel.

It could be pointing us toward a domain under which another hostname exists.

---

## Mistake 4 — Stopping after adding the hosts entry

Resolving the hostname is only one step.

After resolving it, we still need to enumerate the application.

---

## Mistake 5 — Assuming one IP means one website

Modern web servers commonly host multiple applications/sites on the same IP.

Always consider:

```text
Virtual hosts
Subdomains
Host headers
```

when appropriate.

---

# 29. Useful Commands

### View hosts file

```bash
cat /etc/hosts
```

### Resolve using local configuration

```bash
getent hosts academy.htb
```

### Test HTTP

```bash
curl -I http://academy.htb:PORT/
```

### Add hostname

```bash
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

### Test the discovered page

```bash
curl -i http://academy.htb:PORT/blog/index.php
```

---

# 30. Important Concepts to Memorize

### DNS

```text
Domain name → IP address
```

### `/etc/hosts`

```text
Local hostname → IP mapping
```

### Domain

```text
academy.htb
```

### Subdomain

```text
admin.academy.htb
```

### Multiple websites on one IP

```text
SERVER_IP
   ├── academy.htb
   ├── admin.academy.htb
   └── dev.academy.htb
```

---

# 31. Exam / Viva Questions

### Q1. Why couldn't the browser initially access `academy.htb`?

Because the hostname wasn't resolvable through the local hosts configuration or public DNS in the HTB lab environment.

---

### Q2. What file can be used to manually map a hostname to an IP?

```text
/etc/hosts
```

---

### Q3. What command can add `academy.htb` to `/etc/hosts`?

```bash
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

---

### Q4. Why do we still specify the port?

Because hostname resolution only maps the hostname to an IP; it doesn't determine which service port the HTB target is using.

---

### Q5. What is DNS?

The Domain Name System translates domain names/hostnames into network addresses such as IP addresses.

---

### Q6. What is a subdomain?

A hostname under a parent domain.

Example:

```text
admin.academy.htb
```

where:

```text
academy.htb
```

is the parent domain.

---

### Q7. Why do we start looking for `*.academy.htb`?

Because the application explicitly indicates that the admin panel was moved to `academy.htb`, yet the parent hostname shows the same application and our directory enumeration didn't find the admin panel. This suggests another hostname/subdomain may host it.

---

### Q8. Can multiple domains point to the same IP?

Yes.

A single IP can host multiple websites or virtual hosts.

---

# 32. Quick Revision

```text
                DISCOVERY
                    │
                    ▼
       "Admin panel moved to academy.htb"
                    │
                    ▼
             Try academy.htb
                    │
                    ▼
             DNS Resolution?
                    │
                  NO
                    │
                    ▼
             Edit /etc/hosts
                    │
                    ▼
       academy.htb → SERVER_IP
                    │
                    ▼
            Visit the domain
                    │
                    ▼
           Same application
                    │
                    ▼
       Verify /blog/index.php
                    │
                    ▼
       Admin panel still missing
                    │
                    ▼
       Enumerate *.academy.htb
```

---

# 33. Golden Command

```bash
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

Then:

```text
http://academy.htb:PORT
```

---

# 34. Golden Mental Model

```text
Browser
   │
   │ academy.htb
   ▼
/etc/hosts
   │
   │ Found?
   ├── YES ──→ SERVER_IP
   │
   └── NO
        │
        ▼
     DNS lookup
        │
        ├── Found → IP
        │
        └── Not found → Resolution failure
```

For an HTB private hostname, we can manually establish:

```text
academy.htb → SERVER_IP
```

using `/etc/hosts`.

---

# 35. Final Takeaways

> **DNS maps hostnames/domains to IP addresses.**

> **Private HTB hostnames may not exist in public DNS.**

> **`/etc/hosts` allows us to create local hostname-to-IP mappings.**

> **Adding an entry to `/etc/hosts` solves hostname resolution; it does not change the service port.**

> **One IP address can host multiple websites through different hostnames/virtual hosts.**

> **If the main domain shows the same application but a message points toward an admin panel, don't stop at the parent domain.**

> **The absence of an admin panel during recursive directory enumeration is a reason to investigate hostnames and subdomains.**

> **`academy.htb` becomes the parent domain for our next enumeration stage: `*.academy.htb`.**

The progression is:

```text
IP Enumeration
      ↓
Directory Enumeration
      ↓
Recursive Enumeration
      ↓
PHP/Page Enumeration
      ↓
Application Clue
      ↓
academy.htb
      ↓
/etc/hosts
      ↓
Same Application
      ↓
Subdomain Enumeration
      ↓
*.academy.htb
```

**Key lesson:** when web enumeration stops producing useful results, don't just keep throwing bigger wordlists at the same URL. **Change the attack surface you're enumerating.** Here, the clue tells us the next surface is the hostname/subdomain layer.