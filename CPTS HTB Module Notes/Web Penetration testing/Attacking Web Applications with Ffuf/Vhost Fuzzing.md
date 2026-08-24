![Image](https://images.openai.com/static-rsc-4/CvFKIS_IA0Ry_kSzndaPdlrQTp5FVRzgqXMcQvedxJf7YBipfJEExZHceUhYJMgWV8HIS66qsAJnC-J2ATd-5F4EnCb1KUNP3dcEk9hM4BPZMA0ItqFWSX7rGYKVZR07IF2thglafj5HxvKODzxF0pLhkkWuevOyTTVbTtufG2qShhianWQFy_5JXISv-x2n?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zxqfkxV_rvNEM_Ezl_K3HPIqwZWxVgxcDr_E-GFrL7aH2UfqbyUQrmsLrbfGGVG1FmwGaDGKKN40c2ipPVP2tYPhwbrkDkILDGyjyfQm6C4Wm9nj0fxGO3mSF4XYOhWzawTfn6Ogop5qH3ohoalcyB4pSHG3bln3QuGg4t8cH5EtPDEZumYKV7HqObha9FGv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/30XVH5VECy8IIEoetNcmRcmaLrmj1yx-Uk6hcVmWv5pY45iCEZ6JmOuhF4ZL5uM3YT6s1Yt4lN1FxgjAbIDyasXD8Ss11w6Eyz7MF3MDHCBMWHO_ym5xZNoic7q8b7x4NWu70QSiRg8UfeSf5zZhCrft5X2V3AA1KFPL87hNiTlargLaOBw4DbwEtcYW10ll?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/9MDhnv9XfZtokfmGUO6q7qLtEQBlyCia5cc-nNd4FBA3hc6zEPFWR7kSA7FnYPtOjJKDWXv19ZX40QdtAgllCsdQU1VNxONyoGVdch8ZzcdR1wwWl-D5kCQEPmYymli5QklRq_NFwE9E16rgEE3zuWs9gVy-Iyr2e4PVmyqx8Rrl0XmlnxBIjLLbb6A9ese8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mo4iTTRSupX8swaML9dUcRhBljf6szGnb3Mbb5PDEyO3K6AaB0RRpC1CG1BbIWPVnFrjUdbeIlalb28JNWpR1qS-wJWVOD2JiqRSLktOhCjadfCF62PLcxDgjGLEfMKUehUp-Wn365BDkvCvRJs0sOyD2nIgSm1Kz170S9xav1ghGbcGl5Gz59PejcJEfMD7?purpose=fullsize)

This section is **very important** because it explains how to discover hidden hostnames when **DNS enumeration doesn't work**. The central idea is:

> **Instead of asking DNS whether `FUZZ.academy.htb` exists, send `Host: FUZZ.academy.htb` directly to the server's IP and see whether the web server responds differently.**

---

# 1. Introduction

In the previous section, we tried subdomain fuzzing:

```text
FUZZ.academy.htb
```

The problem was that `academy.htb` is part of the private HTB environment.

Public DNS doesn't know about its internal subdomains.

Therefore:

```text
FUZZ.academy.htb
       ↓
Public DNS
       ↓
No public DNS record
       ↓
Resolution fails
```

But we already know the target's IP address.

So instead of asking DNS to resolve every possible hostname, we can directly contact the web server and tell it:

```http
Host: FUZZ.academy.htb
```

This is called **VHost fuzzing**.

---

# 2. What Is a VHost?

**VHost** means **Virtual Host**.

A web server can host multiple websites using the same IP address.

For example:

```text
SERVER_IP
    │
    ├── academy.htb
    ├── admin.academy.htb
    ├── dev.academy.htb
    └── test.academy.htb
```

All of these could potentially use:

```text
SERVER_IP
```

but the web server can return different websites depending on the hostname requested.

---

# 3. Why Use Virtual Hosts?

Imagine a server has:

```text
10.10.10.10
```

and hosts:

```text
academy.htb
admin.academy.htb
```

When we request:

```http
GET / HTTP/1.1
Host: academy.htb
```

the server may return:

```text
Main Academy Website
```

But:

```http
GET / HTTP/1.1
Host: admin.academy.htb
```

could return:

```text
Admin Panel
```

Same IP.

Same port.

Different hostname.

Different website.

---

# 4. VHost vs Subdomain

These terms are related but shouldn't be treated as identical.

### Subdomain

A hostname under a parent domain:

```text
admin.academy.htb
```

### VHost

A website/application selected by the web server based on the requested hostname.

A VHost might correspond to:

```text
admin.academy.htb
```

but the important characteristic is how the web server handles the request.

A VHost may or may not have a public DNS record.

---

# 5. The Critical Difference

### Public subdomain enumeration

```text
FUZZ.academy.htb
       ↓
DNS
       ↓
IP?
```

This requires DNS resolution.

### VHost enumeration

```text
SERVER_IP
    +
Host: FUZZ.academy.htb
       ↓
Web Server
       ↓
Different response?
```

DNS isn't required for the candidate hostname to resolve first.

That's the major advantage in private lab environments.

---

# 6. Same IP, Different Websites

Think of the server as a building:

```text
                 SERVER IP
                     │
              ┌──────┴──────┐
              │ Web Server  │
              └──────┬──────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   academy.htb   admin.htb     dev.htb
        │            │            │
        ▼            ▼            ▼
      Main         Admin        Dev
      Site         Panel       Website
```

The IP gets the traffic.

The `Host` header tells the web server **which virtual website we want**.

---

# 7. HTTP `Host` Header

The HTTP request contains a `Host` header.

For example:

```http
GET / HTTP/1.1
Host: academy.htb
```

The server can use:

```text
Host: academy.htb
```

to determine which virtual host should handle the request.

If we change it:

```http
Host: admin.academy.htb
```

the server may route us to a completely different application.

---

# 8. Why This Works Without Public DNS

Suppose we send:

```http
Host: admin.academy.htb
```

directly to:

```text
SERVER_IP
```

The computer doesn't necessarily need to resolve:

```text
admin.academy.htb → SERVER_IP
```

because we've already specified the server we're connecting to.

Conceptually:

```text
Normal request:

admin.academy.htb
        ↓
DNS resolution
        ↓
SERVER_IP
        ↓
HTTP request


VHost fuzzing:

SERVER_IP
    ↓
HTTP request
Host: admin.academy.htb
    ↓
Web server decides which VHost
```

---

# 9. Ffuf's `-H` Option

The important ffuf option here is:

```text
-H
```

It allows us to specify an HTTP header.

Syntax:

```bash
-H 'Header: Value'
```

For example:

```bash
-H 'Host: academy.htb'
```

---

# 10. Putting `FUZZ` in the Host Header

Instead of:

```text
-H 'Host: academy.htb'
```

we use:

```text
-H 'Host: FUZZ.academy.htb'
```

Now ffuf replaces:

```text
FUZZ
```

with every word from the wordlist.

For example:

```text
FUZZ = admin
```

becomes:

```http
Host: admin.academy.htb
```

Then:

```text
FUZZ = dev
```

becomes:

```http
Host: dev.academy.htb
```

And so on.

---

# 11. The HTB Command

The module uses:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://academy.htb:PORT/ \
-H 'Host: FUZZ.academy.htb'
```

This is the key command for this section.

---

# 12. Command Breakdown

### Wordlist

```text
-w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ
```

Uses the subdomain wordlist and assigns:

```text
FUZZ
```

as the keyword.

---

### Target

```text
-u http://academy.htb:PORT/
```

This is the actual server we're connecting to.

Notice something important:

> **`FUZZ` is NOT in the URL.**

The URL stays:

```text
http://academy.htb:PORT/
```

---

### Host Header

```text
-H 'Host: FUZZ.academy.htb'
```

This is where fuzzing happens.

---

# 13. Where Is FUZZ Now?

Previously:

### Directory fuzzing

```text
http://TARGET/FUZZ
```

### Subdomain fuzzing

```text
http://FUZZ.example.com
```

### VHost fuzzing

```text
http://TARGET/
Host: FUZZ.example.com
```

So the fuzzing position is now inside the HTTP header.

---

# 14. What Requests Does Ffuf Generate?

Suppose our wordlist contains:

```text
admin
dev
mail
blog
support
```

Ffuf sends requests conceptually like:

```http
GET / HTTP/1.1
Host: admin.academy.htb
```

Then:

```http
GET / HTTP/1.1
Host: dev.academy.htb
```

Then:

```http
GET / HTTP/1.1
Host: mail.academy.htb
```

Then:

```http
GET / HTTP/1.1
Host: blog.academy.htb
```

And so on.

---

# 15. The Problem With the Initial Scan

The HTB output shows results such as:

```text
mail2     [Status: 200, Size: 900]
dns2      [Status: 200, Size: 900]
ns3       [Status: 200, Size: 900]
dns1      [Status: 200, Size: 900]
lists     [Status: 200, Size: 900]
webmail   [Status: 200, Size: 900]
static    [Status: 200, Size: 900]
web       [Status: 200, Size: 900]
www1      [Status: 200, Size: 900]
```

At first this looks like:

> "We discovered hundreds of VHosts!"

But that's not correct.

---

# 16. Why Everything Returns `200`

The reason is that the target server is responding to the request regardless of the hostname we place in the `Host` header.

For example:

```http
Host: random123.academy.htb
```

may still return:

```text
200 OK
```

with:

```text
Size: 900
```

The same happens with:

```http
Host: admin.academy.htb
```

or:

```http
Host: xyz.academy.htb
```

if the server falls back to a default website.

Therefore:

```text
200 OK
```

alone isn't enough.

---

# 17. The Baseline Response

This is one of the most important concepts in VHost fuzzing.

Suppose a nonexistent VHost gives:

```text
Status: 200
Size: 900
Words: 423
Lines: 56
```

This is our **baseline**.

If every random hostname gives:

```text
200
900 bytes
423 words
56 lines
```

then these are likely all returning the same default website.

---

# 18. What Happens When a VHost Actually Exists?

Suppose:

```text
Host: admin.academy.htb
```

is a valid VHost.

The web server might return:

```text
Status: 200
Size: 2500
Words: 700
Lines: 120
```

Now we have:

```text
Normal response:
900 bytes

Interesting response:
2500 bytes
```

That difference is what we're looking for.

---

# 19. Response Size Becomes the Important Signal

The module specifically explains:

> If the VHost exists and we send the correct hostname, we should get a different response size.

Therefore, we shouldn't simply search for:

```text
200
```

We should look for:

```text
different response characteristics
```

Especially:

```text
Size
Words
Lines
```

---

# 20. Example

Suppose we test:

```text
Host: random.academy.htb
```

Response:

```text
200
Size: 900
```

Then:

```text
Host: test.academy.htb
```

Response:

```text
200
Size: 900
```

Then:

```text
Host: admin.academy.htb
```

Response:

```text
200
Size: 1875
```

The third result is interesting.

Why?

Because:

```text
admin.academy.htb
        ↓
Different response
        ↓
Potentially different VHost
```

---

# 21. Filtering the Baseline

Once we know the default response size, we can tell ffuf to ignore it.

Suppose the baseline is:

```text
Size: 900
```

We can use:

```bash
-fs 900
```

This means:

> Filter out responses with size 900.

Example:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://academy.htb:PORT/ \
-H 'Host: FUZZ.academy.htb' \
-fs 900
```

Now ffuf will hide the common/default response.

---

# 22. Why `-fs` Is Extremely Useful Here

Without filtering:

```text
admin    200 900
dev      200 900
test     200 900
blog     200 900
mail     200 900
...
```

There may be thousands of results.

After:

```text
-fs 900
```

we may get:

```text
admin    200 2500
```

This makes the interesting result much easier to identify.

---

# 23. Baseline First, Filter Second

A very important methodology:

```text
Step 1
Run VHost fuzzing
        ↓
Observe common response
        ↓
Identify baseline size
        ↓
Use -fs to filter baseline
        ↓
Run again
        ↓
Analyze anomalies
```

Don't blindly guess the filter value.

---

# 24. Why Response Size Is Better Than Status Code Here

Normally:

```text
200
```

is useful.

But in this situation:

```text
Every candidate → 200
```

so status code doesn't distinguish valid and invalid VHosts.

Instead:

```text
Response Size
```

becomes more useful.

This is a general fuzzing lesson:

> **The best detection signal depends on the application's behavior.**

---

# 25. Other Signals

Besides response size, we can compare:

```text
Status
Size
Words
Lines
Redirect location
Response body
```

For example:

```text
Default:
200 / 900 / 423 / 56

Potential VHost:
200 / 1800 / 650 / 100
```

The difference deserves investigation.

---

# 26. VHost Enumeration Workflow

A good workflow is:

```text
              Known IP
                 │
                 ▼
         Choose hostname
                 │
                 ▼
        Send Host: FUZZ.domain
                 │
                 ▼
            HTTP Server
                 │
                 ▼
        Get response for each
                 │
                 ▼
         Establish baseline
                 │
                 ▼
       Filter common response
                 │
                 ▼
        Identify anomalies
                 │
                 ▼
        Manually investigate
```

---

# 27. VHost vs DNS Fuzzing — Side by Side

|Feature|Subdomain/DNS Fuzzing|VHost Fuzzing|
|---|---|---|
|Target|`FUZZ.domain.com`|Known server IP/domain|
|Fuzz location|URL hostname|`Host` header|
|Requires public DNS?|Usually yes|No|
|Useful for private HTB hosts?|Limited|Yes|
|Uses `-H`?|Not necessarily|Yes|
|Can discover internal VHosts?|Not through public DNS|Yes|
|Main signal|DNS resolution + HTTP response|HTTP response differences|

---

# 28. The Most Important Difference

### Subdomain fuzzing:

```text
FUZZ.academy.htb
```

asks:

> **Can my system resolve this hostname?**

### VHost fuzzing:

```http
Host: FUZZ.academy.htb
```

asks:

> **Does the web server behave differently when I request this hostname?**

This is the heart of the section.

---

# 29. Why the IP Is Important

We already know:

```text
SERVER_IP
```

Therefore, we don't need to discover the server again.

We directly connect to:

```text
http://academy.htb:PORT/
```

and manipulate:

```http
Host:
```

The server receives the request.

---

# 30. HTTP Request Visualization

Normal request:

```http
GET / HTTP/1.1
Host: academy.htb
```

VHost fuzzing:

```http
GET / HTTP/1.1
Host: admin.academy.htb
```

Another fuzz attempt:

```http
GET / HTTP/1.1
Host: dev.academy.htb
```

Another:

```http
GET / HTTP/1.1
Host: test.academy.htb
```

The destination IP can remain exactly the same.

---

# 31. Why VHosts May Not Have DNS Records

A company may use internal hostnames such as:

```text
admin.internal.example.com
dev.internal.example.com
staging.internal.example.com
```

without publishing them publicly.

The web server can still be configured to recognize them.

Therefore:

```text
No public DNS record
        ≠
No VHost
```

This is an extremely important security-testing concept.

---

# 32. Real-World Example

Imagine:

```text
203.0.113.10
```

hosts:

```text
www.example.com
admin.example.com
dev.example.com
```

Only:

```text
www.example.com
```

is published in public DNS.

But the server configuration still contains:

```text
admin.example.com
dev.example.com
```

A DNS enumeration tool may find:

```text
www.example.com
```

but miss:

```text
admin.example.com
dev.example.com
```

VHost fuzzing may still identify them by sending:

```http
Host: admin.example.com
```

directly to the known server.

---

# 33. Why This Matters for Pentesting

Hidden VHosts can expose:

- Admin interfaces
    
- Development applications
    
- Staging environments
    
- Internal dashboards
    
- APIs
    
- Test applications
    
- Legacy applications
    

Therefore, VHost enumeration is an important part of web reconnaissance.

Only perform this against systems you're authorized to test.

---

# 34. Important Ffuf Options

|Option|Purpose|
|---|---|
|`-w`|Specify wordlist|
|`-u`|Target URL|
|`-H`|Add HTTP header|
|`-fs`|Filter response size|
|`-fc`|Filter response status code|
|`-mc`|Match response status code|
|`-v`|Verbose output|
|`-t`|Thread count|

For VHost fuzzing, the most important are:

```text
-w
-u
-H
-fs
```

---

# 35. The Golden VHost Command

Basic:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://academy.htb:PORT/ \
-H 'Host: FUZZ.academy.htb'
```

Once the baseline size is identified:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://academy.htb:PORT/ \
-H 'Host: FUZZ.academy.htb' \
-fs BASELINE_SIZE
```

For example, if the baseline is `900`:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://academy.htb:PORT/ \
-H 'Host: FUZZ.academy.htb' \
-fs 900
```

---

# 36. Important Note About the HTB Output

The module's output says:

```text
:: Header : Host: FUZZ
```

even though the command specifies:

```text
Host: FUZZ.academy.htb
```

The exact display formatting can vary with ffuf versions/configuration.

The important concept is:

```text
Host: FUZZ.academy.htb
```

is the header being fuzzed.

---

# 37. What Happens After Finding a Candidate?

Suppose filtering reveals:

```text
admin
```

with:

```text
Status: 200
Size: 2450
```

We should manually verify it.

One option is to add it to `/etc/hosts`:

```bash
sudo sh -c 'echo "SERVER_IP  admin.academy.htb" >> /etc/hosts'
```

Then visit:

```text
http://admin.academy.htb:PORT/
```

Alternatively, for testing without modifying `/etc/hosts`, tools such as `curl` can send a custom Host header directly:

```bash
curl -H 'Host: admin.academy.htb' http://SERVER_IP:PORT/
```

This is a useful way to verify the VHost behavior.

---

# 38. Why Manual Verification Is Important

A different response doesn't automatically mean:

```text
"VHost confirmed."
```

It could be caused by:

- Redirect behavior
    
- Application errors
    
- WAF behavior
    
- Different default responses
    
- Rate limiting
    
- Server configuration
    
- Random/dynamic content
    

Therefore:

```text
Interesting response
        ↓
Manual request
        ↓
Compare response
        ↓
Confirm behavior
```

---

# 39. False Positives

VHost fuzzing can produce false positives.

For example:

```text
random1 → 200 → 900
random2 → 200 → 900
random3 → 200 → 900
```

These are likely the default site.

But even a different response could be unrelated to a valid VHost.

That's why baseline analysis is critical.

---

# 40. Baseline Concept

A **baseline** is the normal response produced by a non-existent or default hostname.

Example:

```text
Random VHost
    ↓
200
900 bytes
423 words
56 lines
```

Therefore:

```text
Baseline = 900 bytes
```

We can filter it with:

```bash
-fs 900
```

---

# 41. Why `-fs` Instead of `-fc 200`?

You might wonder:

> Why not filter HTTP 200?

Because the real VHost could also return:

```text
200 OK
```

In fact, that's often exactly what we want.

The problem is that the **default VHost also returns 200**.

Therefore:

```text
-fc 200
```

would hide the legitimate VHost too.

Instead:

```text
-fs 900
```

hides only the common default response.

---

# 42. This Is a General Fuzzing Principle

The same principle applies beyond VHosts.

Suppose:

```text
Invalid request → 404 → Size 1234
```

Then:

```bash
-fs 1234
```

can remove the common false-positive response.

Or:

```text
Invalid request → 200 → Size 5000
```

then:

```bash
-fs 5000
```

can help isolate unusual responses.

The idea is:

```text
Find normal response
       ↓
Filter normal response
       ↓
Investigate anomalies
```

---

# 43. Common Mistakes

## Mistake 1 — Putting `FUZZ` in the URL

Incorrect for this technique:

```text
http://FUZZ.academy.htb/
```

That is DNS/subdomain fuzzing.

VHost fuzzing uses:

```text
http://academy.htb:PORT/
```

with:

```text
-H 'Host: FUZZ.academy.htb'
```

---

## Mistake 2 — Filtering `200`

Don't immediately use:

```bash
-fc 200
```

because valid VHosts may also return `200`.

---

## Mistake 3 — Ignoring response size

If everything returns:

```text
200
```

status code isn't useful enough.

Look at:

```text
Size
Words
Lines
```

---

## Mistake 4 — Not establishing a baseline

Before filtering:

```text
-fs
```

you need to know what the default response looks like.

---

## Mistake 5 — Assuming every different response is a VHost

Always manually verify interesting results.

---

# 44. Exam / Viva Questions

### Q1. What is a VHost?

A virtual host is a website/application configuration on a web server where multiple hostnames/websites can be served from the same server/IP.

---

### Q2. What is the major difference between VHost and subdomain enumeration?

Subdomain enumeration commonly relies on DNS resolution, while VHost enumeration sends different hostnames to a known server and analyzes how the web server responds.

---

### Q3. Which HTTP header is fuzzed?

```text
Host
```

---

### Q4. Which ffuf option allows us to specify the Host header?

```text
-H
```

---

### Q5. Where do we place `FUZZ`?

Inside the Host header:

```text
Host: FUZZ.academy.htb
```

---

### Q6. Why does every candidate initially return `200`?

Because the server is responding with its default website regardless of the hostname being supplied.

---

### Q7. Why is response size useful?

A valid VHost may return a different page and therefore a different response size compared with the default VHost.

---

### Q8. What ffuf option filters response sizes?

```text
-fs
```

---

### Q9. Why shouldn't we simply filter status `200`?

Because the legitimate VHost may also return `200 OK`.

---

### Q10. What is a baseline response?

The normal response returned for a nonexistent/default VHost, which can then be filtered to expose anomalous responses.

---

# 45. Quick Revision

```text
                 KNOWN SERVER IP
                       │
                       ▼
                 HTTP Request
                       │
                       ▼
             Host: FUZZ.academy.htb
                       │
                       ▼
                  Web Server
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
       Default VHost        Valid VHost
             │                   │
             ▼                   ▼
        200 / 900          200 / 2500
             │                   │
             ▼                   ▼
         Baseline             Interesting
             │
             ▼
        Filter with -fs
```

---

# 46. Subdomain vs VHost — Memorize This

### Subdomain fuzzing

```bash
ffuf -w wordlist:FUZZ \
-u http://FUZZ.academy.htb/
```

You're asking:

> **Can DNS resolve this hostname?**

---

### VHost fuzzing

```bash
ffuf -w wordlist:FUZZ \
-u http://academy.htb:PORT/ \
-H 'Host: FUZZ.academy.htb'
```

You're asking:

> **Does the web server recognize this hostname and respond differently?**

---

# 47. Full Methodology So Far

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
              Hidden PHP Page
                     │
                     ▼
            Recursive Fuzzing
                     │
                     ▼
             Deeper Enumeration
                     │
                     ▼
          "Admin panel moved..."
                     │
                     ▼
                 academy.htb
                     │
                     ▼
                /etc/hosts
                     │
                     ▼
            Same Main Website
                     │
                     ▼
          DNS Subdomain Fuzzing
                     │
                     ▼
          Public DNS unavailable
                     │
                     ▼
             VHost Fuzzing
                     │
                     ▼
            Host Header Fuzzing
                     │
                     ▼
            Baseline Filtering
                     │
                     ▼
           Hidden VHost Discovery
```

---

# 48. Final Takeaways

> **A VHost allows multiple websites/applications to be served from the same IP.**

> **VHosts may or may not have public DNS records.**

> **Public subdomain fuzzing depends on hostname resolution and therefore may miss private/internal hostnames.**

> **VHost fuzzing works against a known server by manipulating the HTTP `Host` header.**

> **Use `-H` to specify the Host header in ffuf.**

> **The basic pattern is `-H 'Host: FUZZ.academy.htb'`.**

> **The URL remains pointed at the known server rather than putting `FUZZ` into the URL hostname.**

> **A server may return `200 OK` for every hostname because it has a default VHost.**

> **Therefore, status code alone may not identify valid VHosts.**

> **Response size, words, lines, redirects, and other response characteristics become useful signals.**

> **Establish the baseline response first, then use `-fs` to filter it.**

> **A different response is a lead, not automatic proof — manually verify it.**

### The most important command:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://academy.htb:PORT/ \
-H 'Host: FUZZ.academy.htb'
```

Then, if the default response is:

```text
Size: 900
```

filter it:

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://academy.htb:PORT/ \
-H 'Host: FUZZ.academy.htb' \
-fs 900
```

### The one-line memory trick:

```text
DNS fuzzing  → FUZZ.domain → "Does DNS know it?"
VHost fuzzing → Host: FUZZ.domain → "Does the web server know it?"
```

**That distinction is the entire point of this section.**