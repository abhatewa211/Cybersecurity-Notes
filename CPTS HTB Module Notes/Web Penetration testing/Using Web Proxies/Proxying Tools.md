![Image](https://images.openai.com/static-rsc-4/j3BGecuKg7djuOwsGf2QhVfeVRM3oBDCSEghZiExO99nVP800oxdGpXsZ8pl5BotTSpsTF81TX-1brHzR3ysxHS87Fb216Tb-4j57bLpV8eRjAkKcgWLNdKYTKhxcC49jeq8HqbWLvdqxD2HZDn9YSFI3YaRmO4Rmhvx84jTlL29qjtRRT8vlh1yQBW6keH3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VeCsA5RF4o4HQimrOPjJfpD_iZiNnW6Mu1o2GXFitCMeqUMVOoznWW34ABSbXDaLZYJn9PtKTqevrMGPGuEpkzaPneyvTTJFEDmbK0n1v5WNhmbi8jTgORsvAxzpkrtNzkShWaLDaAYVilJflSp26c5hpD_zJR2x0xdhB-_T_sSxko-nw-cL-O-g5I4oM7cy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ge1UmLkDb2GrkpP8u3i5w9Pjly2nBuJqwSuktoFJxDuES2s2LXnN0mj3l2lWKKrve8T_WuUPUHcs0Bkbo1qWVp9EMJpXZTQyjMmvUw1J-NFMNyErlLoMpjQcJOkWLTgZDRDCdFigLwoLLIdDMQZX5QPdDJ3T3D8FIHDAEOoAyNMfsH74WY2akuKB2Ww4-Lhx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FL5_ONmD_knfBrENgGmtaQjkwX2RxGbO-Ls3XjocVEkJ5t0tQodPzfh-RbmAWZyEXOSBMeYhwt7IwQoeD2Wo8Th-vERBElxMOsINzO6G6b3hy-TAsmu0VMkXlyPb0ydW0pzQIQbTqUjFMTllKZyL724UxtfJ7BU4vmRktI7PRbMg8Fe0vHGxhWjWQFaf2yYe?purpose=fullsize)

## 1. What Is Proxying Tools?

So far, we've mainly used Burp/ZAP with a **web browser**.

However, web applications aren't only accessed through browsers.

Many other applications can communicate with web servers, including:

- Command-line tools
    
- Scripts
    
- API clients
    
- Thick-client applications
    
- Security tools
    
- Metasploit modules
    
- Custom applications
    

These applications may generate HTTP requests that we cannot easily see from the browser.

By configuring the application to use Burp/ZAP as its proxy, we can inspect those requests.

---

# 2. Basic Proxy Architecture

The normal communication looks like:

```text
Command-Line Tool
       │
       │ HTTP Request
       ▼
     Server
       │
       │ Response
       ▼
Command-Line Tool
```

With Burp/ZAP:

```text
Command-Line Tool
       │
       ▼
Burp / ZAP
       │
       ▼
     Server
       │
       ▼
Burp / ZAP
       │
       ▼
Command-Line Tool
```

The proxy becomes an intermediary.

---

# 3. Proxy Address

The local Burp/ZAP listener commonly uses:

```text
127.0.0.1:8080
```

For HTTP proxy configuration:

```text
http://127.0.0.1:8080
```

Here:

|Component|Meaning|
|---|---|
|`127.0.0.1`|Local machine|
|`8080`|Proxy listening port|
|`http://`|HTTP proxy protocol|

The exact port can be changed in Burp/ZAP, so the application must use the same port as the proxy listener.

---

# 4. Why Proxy Command-Line Tools?

Proxying command-line tools gives us visibility into their HTTP traffic.

For example:

```text
Tool
 ↓
HTTP Request
 ↓
Burp
 ↓
Inspect
 ↓
Modify / Repeat
 ↓
Server
```

This allows us to understand:

- What requests the tool sends
    
- Which headers it uses
    
- What parameters it sends
    
- Which endpoints it accesses
    
- How it handles responses
    
- What the server returns
    

---

# 5. Why Is This Useful During Pentesting?

A security tool might hide the underlying HTTP communication.

For example, you execute:

```text
some-tool --target example
```

but don't necessarily see every HTTP request it generates.

Proxying it through Burp/ZAP gives you the raw traffic.

```text
Security Tool
      ↓
   Burp/ZAP
      ↓
HTTP Request
      ↓
   Target
```

Now you can analyze the actual protocol communication.

---

# 6. Important Note ⚠️

Proxying tools generally makes them **slower**.

Why?

Instead of:

```text
Tool → Server
```

traffic now passes through:

```text
Tool → Proxy → Server
```

The proxy may also:

- Intercept requests
    
- Store history
    
- Inspect responses
    
- Apply modification rules
    
- Wait for user interaction
    

Therefore:

> **Only proxy tools when you need to investigate their requests.**

For normal usage, proxying may add unnecessary overhead.

---

# 🔗 7. ProxyChains

One of the easiest ways to proxy command-line applications on Linux is:

> **ProxyChains**

ProxyChains allows command-line applications to route traffic through a configured proxy.

This makes it useful when a command-line application doesn't provide an obvious proxy option.

---

# 8. How ProxyChains Works

Normally:

```text
curl
 ↓
Target
```

With ProxyChains:

```text
curl
 ↓
ProxyChains
 ↓
Burp/ZAP
 ↓
Target
```

The important advantage is that ProxyChains can be placed in front of many command-line applications.

---

# 9. ProxyChains Configuration

The configuration file is:

```text
/etc/proxychains.conf
```

The module's example changes the proxy configuration to:

```text
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```

The existing SOCKS proxy line is commented out:

```text
#socks4 127.0.0.1 9050
```

and the HTTP proxy is configured:

```text
http 127.0.0.1 8080
```

This tells ProxyChains to use the local HTTP proxy listener.

---

# 10. ProxyChains `-q`

ProxyChains supports:

```text
-q
```

which means:

> **Quiet mode**

It suppresses ProxyChains connection information.

Without quiet mode, the terminal can become cluttered with connection messages.

With:

```bash
proxychains -q ...
```

you can focus on the output produced by the actual application.

---

# 11. Example — cURL Through ProxyChains

The module demonstrates:

```bash
proxychains -q curl http://SERVER_IP:PORT
```

The traffic flow becomes:

```text
curl
 ↓
ProxyChains
 ↓
127.0.0.1:8080
 ↓
Burp / ZAP
 ↓
SERVER_IP:PORT
```

The terminal can still display the webpage returned by the server:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ping IP</title>
</head>
...
</html>
```

At the same time, Burp/ZAP records the HTTP request.

---

# 12. Verifying ProxyChains Traffic

After running:

```bash
proxychains -q curl http://SERVER_IP:PORT
```

go back to Burp/ZAP.

Look at:

```text
HTTP History
```

You should see the HTTP request generated by `curl`.

This confirms:

```text
curl
 ↓
ProxyChains
 ↓
Burp
 ↓
Target
```

---

# 13. Why cURL + Burp Is Useful

This combination gives you a very useful workflow.

You can generate requests from the command line:

```bash
curl ...
```

while simultaneously examining them in Burp.

This can help you understand:

- HTTP headers
    
- Request methods
    
- Parameters
    
- Response codes
    
- Response bodies
    
- Cookies
    
- Redirects
    

It also allows you to take interesting requests from the CLI tool and work with them inside Burp.

---

# 🔥 14. Metasploit Proxying

Metasploit modules can also generate HTTP traffic.

We can route that traffic through Burp/ZAP to inspect the requests.

Start Metasploit:

```bash
msfconsole
```

Then select an HTTP module.

The module uses:

```text
auxiliary/scanner/http/robots_txt
```

---

# 15. Setting a Proxy in Metasploit

Metasploit supports the:

```text
PROXIES
```

option.

The module example uses:

```text
set PROXIES HTTP:127.0.0.1:8080
```

This tells the Metasploit module to send its HTTP traffic through the local proxy.

---

# 16. Metasploit Example

The module's workflow is:

```text
msfconsole
      ↓
use auxiliary/scanner/http/robots_txt
      ↓
set PROXIES HTTP:127.0.0.1:8080
      ↓
set RHOST SERVER_IP
      ↓
set RPORT PORT
      ↓
run
```

Metasploit executes the scanner through Burp/ZAP.

---

# 17. What Is `robots_txt`?

The example uses:

```text
auxiliary/scanner/http/robots_txt
```

This module checks the target's:

```text
/robots.txt
```

file.

The request may look conceptually like:

```http
GET /robots.txt HTTP/1.1
Host: target
```

Because we configured the proxy, the request travels through Burp/ZAP.

---

# 18. Checking Burp History

After running the Metasploit module, go to:

```text
Burp
 ↓
Proxy
 ↓
HTTP History
```

You should see the request to:

```text
/robots.txt
```

along with the server's response.

For example, the server could return:

```text
404 Not Found
```

The important part for this exercise is that the HTTP request is visible inside the proxy.

---

# 19. Why Proxy Metasploit?

Proxying Metasploit modules can help with:

### Debugging

See exactly what the module sends.

### Understanding modules

Learn how automated scanners interact with web servers.

### Request analysis

Inspect:

```text
Headers
Parameters
Methods
Paths
Cookies
```

### Reproduction

An interesting request can potentially be reproduced manually in Burp Repeater/ZAP Request Editor during an authorized assessment.

---

# 20. Proxying Other Applications

The same general concept applies to many other tools.

For example:

```text
CLI tools
Scripts
API clients
Thick clients
Custom applications
Security tools
Automation scripts
```

The general requirement is:

> **Configure the application to use Burp/ZAP as its HTTP proxy.**

---

# 21. Tool-Specific Proxy Configuration

Not every application configures its proxy in the same way.

Some applications may provide:

```text
--proxy
```

or:

```text
--proxy-url
```

Others may use environment variables or configuration files.

Some applications have no native proxy configuration and may require another mechanism such as ProxyChains.

Therefore:

```text
Application
     ↓
How does it support proxies?
     ↓
Configure proxy
     ↓
127.0.0.1:8080
```

---

# 22. Native Proxy vs ProxyChains

There are two common approaches.

### Native proxy support

The application directly supports proxy configuration.

```text
Application
     ↓
HTTP Proxy Setting
     ↓
Burp/ZAP
```

### ProxyChains

ProxyChains sits between the command-line application and the network.

```text
Application
     ↓
ProxyChains
     ↓
Burp/ZAP
```

### ⭐ General rule

If the application has reliable native proxy support, that is often simpler.

If it doesn't, ProxyChains can be useful for command-line tools.

---

# 23. Proxying Thick Clients

A **thick client** is an application where significant functionality runs locally rather than entirely inside a browser.

Examples can include:

```text
Desktop applications
Custom enterprise software
API clients
Java applications
.NET applications
```

If such an application communicates with a web server, proxying it can expose its HTTP/HTTPS traffic.

```text
Thick Client
     ↓
Burp/ZAP
     ↓
Backend Server
```

This can reveal how the client communicates with the backend.

---

# 24. Important HTTPS Consideration

If an application communicates using HTTPS, merely configuring the proxy may not be enough.

The application may need to trust the proxy's CA certificate.

Conceptually:

```text
HTTPS Client
     ↓
Burp/ZAP
     ↓
HTTPS Server
```

For interception to work properly, the client generally needs to trust the proxy's certificate authority.

This is similar to what we configured earlier with Firefox.

---

# 25. Complete Workflow

A useful mental model is:

```text
             TOOL / APPLICATION
                     │
                     ▼
              Proxy Configuration
                     │
                     ▼
              127.0.0.1:8080
                     │
                     ▼
                 BURP/ZAP
                     │
          ┌──────────┴──────────┐
          │                     │
       Inspect               Modify
          │                     │
          └──────────┬──────────┘
                     ▼
                  SERVER
                     │
                     ▼
                  Response
                     │
                     ▼
                 BURP/ZAP
                     │
                     ▼
             TOOL / APPLICATION
```

---

# 26. Proxying Tools — Key Advantages

### 👁️ Visibility

See requests that would otherwise be hidden.

### 🔍 Analysis

Examine headers, parameters and responses.

### ✏️ Modification

Change requests before they're sent.

### 🔁 Repetition

Send interesting requests through Repeater/Request Editor.

### ⚙️ Automation

Apply Match & Replace rules.

### 🐛 Debugging

Understand why an application or module behaves unexpectedly.

---

# 27. Limitations

Proxying isn't always appropriate.

### Performance

```text
Tool → Proxy → Server
```

adds overhead.

### Compatibility

Some applications don't support HTTP proxies correctly.

### Certificate validation

Some HTTPS applications may reject proxy certificates.

### Non-HTTP traffic

A web proxy is primarily designed for web protocols; applications using unrelated protocols may not work through it.

---

# 🧠 28. Exam / Viva Questions

### Q1. Why proxy command-line tools?

To inspect and analyze HTTP requests generated by applications that aren't necessarily browser-based.

### Q2. What is a common local Burp/ZAP proxy address?

```text
127.0.0.1:8080
```

### Q3. What is ProxyChains?

A Linux utility that can route traffic from command-line applications through a configured proxy.

### Q4. What configuration file does the module use?

```text
/etc/proxychains.conf
```

### Q5. What does ProxyChains `-q` do?

Runs ProxyChains in quiet mode, reducing connection-related console output.

### Q6. How do you proxy cURL using ProxyChains?

The module demonstrates:

```bash
proxychains -q curl http://SERVER_IP:PORT
```

### Q7. How can Metasploit HTTP modules be proxied?

Using the Metasploit:

```text
PROXIES
```

option, for example:

```text
set PROXIES HTTP:127.0.0.1:8080
```

### Q8. Where can you verify proxied requests in Burp?

```text
Proxy → HTTP History
```

### Q9. Why shouldn't you always proxy tools?

Proxying generally slows network operations and adds unnecessary overhead when you aren't investigating the traffic.

### Q10. Can other applications besides browsers be proxied?

Yes. Command-line tools, scripts, API clients, thick clients, security tools and other applications can potentially be proxied if their traffic/proxy configuration supports it.

---

# 🔥 29. Final Revision Sheet

```text
             PROXYING TOOLS
                    │
        ┌───────────┴───────────┐
        │                       │
   Native Proxy             ProxyChains
        │                       │
        ▼                       ▼
 Application                CLI Tool
        │                       │
        └──────────┬────────────┘
                   ▼
              Burp / ZAP
                   │
                   ▼
                Target
```

### ProxyChains

```text
/etc/proxychains.conf

http 127.0.0.1 8080
```

Run:

```bash
proxychains -q curl http://SERVER_IP:PORT
```

### Metasploit

```text
msfconsole
 ↓
use auxiliary/scanner/http/robots_txt
 ↓
set PROXIES HTTP:127.0.0.1:8080
 ↓
set RHOST SERVER_IP
 ↓
set RPORT PORT
 ↓
run
```

### ⭐ Core takeaway

> **Web proxies aren't limited to browsers. Any application that communicates over HTTP/HTTPS can potentially be routed through Burp or ZAP, giving you visibility into exactly what the application sends and receives.**

The key workflow is:

**Configure Proxy → Generate Traffic → Inspect in Burp/ZAP → Modify/Repeat if necessary → Analyze Response.**