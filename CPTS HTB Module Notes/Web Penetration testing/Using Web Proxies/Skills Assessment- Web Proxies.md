# HTB Academy – Using Web Proxies
## Full Practical Report & Evidence Log

> **Environment:** Hack The Box Academy authorized lab environment  
> **Primary tools:** Burp Suite, OWASP ZAP  
> **Purpose:** Document the practical work, techniques, and assessment evidence from the **Using Web Proxies** module.

---

## 1. Executive Summary

This report documents the practical work completed for the HTB Academy **Using Web Proxies** module.

The work covered:

- Web proxy fundamentals
- Burp Suite and OWASP ZAP
- Proxy installation and configuration
- Browser proxying
- CA certificate installation
- HTTP request interception
- HTTP response interception
- Request and response manipulation
- Automatic request/response modification
- Request repetition
- Encoding and decoding
- Proxying command-line and security tools
- Proxychains
- Metasploit proxying
- ZAP Fuzzer
- ZAP Spider
- Passive and Active Scanning
- Reporting
- Burp extensions and ZAP add-ons
- Skills assessment exercises

The practical work was performed against authorized HTB Academy lab targets.

---

# 2. Web Proxy Fundamentals

Web proxies are specialized tools positioned between a client application and a back-end server.

They allow a penetration tester to:

- Capture HTTP/HTTPS requests.
- Inspect requests and responses.
- Modify requests before they reach the server.
- Modify responses before they reach the browser.
- Replay requests.
- Analyze application behavior.
- Automate repetitive request/response transformations.

Web proxies primarily work with web traffic such as:

- `HTTP/80`
- `HTTPS/443`

Unlike general network sniffing tools such as Wireshark, web proxies focus specifically on web application traffic and provide functionality for manipulating HTTP requests and responses.

### Common Uses

- Web application vulnerability scanning
- Web fuzzing
- Web crawling
- Web application mapping
- Web request analysis
- Web configuration testing
- Code reviews

---

# 3. Burp Suite vs OWASP ZAP

| Feature | Burp Suite | OWASP ZAP |
|---|---|---|
| Proxy | Yes | Yes |
| Request interception | Yes | Yes |
| Response interception | Yes | Yes |
| Request replay | Repeater | Request Editor / HUD |
| Fuzzing | Intruder | ZAP Fuzzer |
| Spider/Crawler | Crawler | Spider / Ajax Spider |
| Scanner | Burp Scanner | Passive + Active Scanner |
| Encoding/Decoding | Decoder / Inspector | Encoder/Decoder/Hash |
| Extensions | BApp Store | Marketplace / Add-ons |
| Built-in browser | Yes | Pre-configured browser |
| Open source | No | Yes |

---

# 4. Installation & Initial Setup

Both Burp Suite and ZAP are available for Windows, macOS, and Linux.

They are commonly available on penetration-testing distributions such as Kali Linux and Parrot OS.

## Burp Suite

Burp can be launched from the terminal:

```bash
burpsuite
```

It can also be launched from a JAR file:

```bash
java -jar </path/to/burpsuite.jar>
```

Burp Community Edition supports temporary projects. Professional/Enterprise editions provide persistent project options.

For initial configuration, **Use Burp Defaults** can be selected.

## ZAP

ZAP can be launched from the terminal:

```bash
zaproxy
```

ZAP supports temporary and persistent sessions.

---

# 5. Proxy Setup

A browser can be configured to send its traffic through Burp or ZAP.

The default listener used throughout the module is:

```text
127.0.0.1:8080
```

## Burp

Navigate to:

```text
Proxy → Proxy settings → Proxy listeners
```

## ZAP

Navigate to:

```text
Tools → Options → Network → Local Servers/Proxies
```

The browser must use the same host and port as the proxy listener.

## Pre-configured Browser

Burp:

```text
Proxy → Intercept → Open Browser
```

ZAP provides a pre-configured browser from its toolbar.

The pre-configured browser already has proxy settings and the necessary CA certificate configured, making it convenient for lab work.

---

# 6. Firefox + FoxyProxy

FoxyProxy can be used to quickly switch Firefox between different proxy configurations.

Example:

```text
Proxy IP:   127.0.0.1
Proxy Port: 8080
```

A proxy profile can be created for:

```text
Burp
```

or:

```text
ZAP
```

Then the profile can be selected from the FoxyProxy menu.

---

# 7. Installing CA Certificates

HTTPS interception requires the web proxy's CA certificate to be trusted by the browser.

## Burp

With Burp selected as the proxy, browse to:

```text
http://burp
```

Then select:

```text
CA Certificate
```

## ZAP

Navigate to:

```text
Tools → Options → Network → Server Certificates
```

Select:

```text
Save
```

## Firefox

Navigate to:

```text
about:preferences#privacy
```

Then:

```text
View Certificates
→ Authorities
→ Import
```

Import the Burp/ZAP CA certificate and trust it for identifying websites.

---

# 8. Intercepting Web Requests

## Burp

Navigate to:

```text
Proxy → Intercept
```

Toggle:

```text
Intercept is on
```

When a request is captured:

- **Forward** — send it to the destination.
- **Drop** — discard it.
- **Action** — access additional actions.

## ZAP

ZAP interception is off by default.

The interception control can be toggled from the toolbar or with:

```text
CTRL+B
```

ZAP also provides HUD functionality.

Important HUD controls include:

- Step
- Continue
- Drop

### Step

Sends the current request and allows further interception.

### Continue

Allows remaining requests to proceed.

---

# 9. Request Manipulation – Practical Evidence

The HTB lab demonstrated that client-side input restrictions should not be treated as a security boundary.

The original request was:

```http
POST /ping HTTP/1.1
Host: 94.237.62.138:32306
Content-Type: application/x-www-form-urlencoded

ip=1
```

The intercepted parameter was modified during the lab.

Example demonstrated:

```text
ip=;ls;
```

The resulting response showed directory contents including:

```text
flag.txt
index.html
node_modules
package-lock.json
public
server.js
```

### Lesson

A browser may restrict input using JavaScript or HTML attributes, but an attacker can construct the HTTP request independently.

Therefore:

> **Server-side validation is essential.**

---

# 10. Intercepting Responses

Response interception allows the tester to modify the response before it reaches the browser.

This is useful for testing:

- Disabled fields
- Hidden fields
- Client-side restrictions
- HTML behavior
- UI-based security controls

## Burp

Navigate to:

```text
Proxy → Proxy settings
```

Enable:

```text
Intercept Response
```

The lab modified:

```html
type="number"
```

to:

```html
type="text"
```

and:

```html
maxlength="3"
```

to:

```html
maxlength="100"
```

Example:

```html
<input type="text" id="ip" name="ip" min="1" max="255" maxlength="100"
    oninput="javascript: if (this.value.length > this.maxLength) this.value = this.value.slice(0, this.maxLength);"
    required>
```

This allowed arbitrary input to be entered through the browser.

## ZAP

ZAP can intercept the response after using:

```text
Step
```

The same HTML modifications can then be made.

### ZAP HUD

The HUD provides a **Show/Enable** feature that can:

- Enable disabled fields.
- Show hidden fields.
- Make certain hidden UI elements visible.

ZAP also provides a **Comments** feature that can reveal HTML comments.

---

# 11. Automatic Modification

Automatic modification allows rules to be applied to HTTP messages without manually editing every request.

## 11.1 Automatic Request Modification

### Burp

Navigate to:

```text
Proxy → Proxy settings → HTTP match and replace rules
```

Example:

```text
Type:
Request header
```

Match:

```regex
^User-Agent.*$
```

Replace:

```text
User-Agent: HackTheBox Agent 1.0
```

Enable:

```text
Regex match
```

The request's User-Agent can then be changed automatically.

### ZAP

ZAP provides:

```text
Replacer
```

Shortcut:

```text
CTRL+R
```

Example:

```text
Description: HTB User-Agent
Match Type: Request Header
Match String: User-Agent
Replacement String: HackTheBox Agent 1.0
Enable: True
```

The Initiators section can determine where the replacement is applied.

---

# 12. Automatic Response Modification

Burp can automatically modify response bodies.

Navigate to:

```text
Proxy → Options → Match and Replace
```

Example:

```text
Type:
Response body
```

Match:

```text
type="number"
```

Replace:

```text
type="text"
```

Another rule can change:

```text
maxlength="3"
```

to:

```text
maxlength="100"
```

These modifications persist across page refreshes while the proxy rules remain active.

---

# 13. Repeating Requests

Repeating requests is useful when the same request needs to be tested repeatedly with different values.

## Burp Repeater

From:

```text
Proxy → HTTP History
```

Select a request and send it to:

```text
Repeater
```

Shortcut:

```text
CTRL+R
```

Then use:

```text
Send
```

to resend the request.

Burp also allows changing the request method without rewriting the complete request.

## ZAP Request Editor

From ZAP History:

```text
Right-click request
→ Open/Resend with Request Editor
```

Then:

```text
Send
```

ZAP HUD can also:

- Replay in Console
- Replay in Browser

---

# 14. Encoding & Decoding

Encoding and decoding are essential when constructing custom HTTP requests.

Important URL-encoded characters include:

- Spaces
- `&`
- `#`

## Burp URL Encoding

In Repeater:

```text
Select text
→ Convert Selection
→ URL
→ URL-encode key characters
```

Shortcut:

```text
CTRL+U
```

## Burp Decoder

Burp Decoder can encode/decode:

- URL
- Base64
- HTML
- Unicode
- Hex
- Other supported formats

## ZAP

ZAP provides:

```text
Encoder/Decoder/Hash
```

Shortcut:

```text
CTRL+E
```

### Base64 Example

Supplied example:

```text
eyJ1c2VybmFtZSI6Imd1ZXN0IiwgImlzX2FkbWluIjpmYWxzZX0=
```

Decoded:

```json
{"username":"guest", "is_admin":false}
```

A tester could then modify it to:

```json
{"username":"admin", "is_admin":true}
```

and encode it back using Base64 for testing in an authorized environment.

---

# 15. Proxying Command-Line & Security Tools

Tools that make HTTP requests can also be routed through Burp or ZAP.

The basic proxy is:

```text
http://127.0.0.1:8080
```

Proxying tools can slow them down, so it is generally useful when traffic inspection is required.

---

# 16. Proxychains

Proxychains can route command-line traffic through a specified proxy.

Edit:

```text
/etc/proxychains.conf
```

Example:

```text
#socks4         127.0.0.1 9050
http 127.0.0.1 8080
```

Use quiet mode:

```bash
proxychains -q curl http://SERVER_IP:PORT
```

The resulting request should appear in Burp/ZAP HTTP history.

---

# 17. Metasploit Proxying – Practical Evidence

Metasploit can route HTTP module traffic through the web proxy.

Start Metasploit:

```bash
msfconsole
```

Use the HTTP scanner:

```text
use auxiliary/scanner/http/robots_txt
```

Set the proxy:

```text
set PROXIES HTTP:127.0.0.1:8080
```

Set the target:

```text
set RHOST SERVER_IP
set RPORT PORT
```

Run:

```text
run
```

The resulting HTTP request can then be inspected in Burp/ZAP history.

### Completed Assessment Result

The practical task produced:

```text
CFIDE
```

**Recorded answer:**

```text
CFIDE
```

---

# 18. ZAP Fuzzer

ZAP's Fuzzer can fuzz web requests.

Main configuration areas:

- Fuzz Location
- Payloads
- Processors
- Options

## Fuzz Location

Select the part of the request that should receive payloads.

## Payloads

Supported payload examples include:

- File
- File Fuzzers
- Numberzz

ZAP provides built-in wordlists.

## Processors

Examples:

- Base64 Encode/Decode
- MD5
- Prefix String
- Postfix String
- SHA-1
- SHA-256
- SHA-512
- URL Encode/Decode
- Script

## Options

Important options include:

- Concurrent scanning threads
- Retries
- Maximum errors
- Depth-first
- Breadth-first
- Redirect handling
- Delay

### Depth First

Tests all payloads at one position before moving to another.

### Breadth First

Tests each payload across all positions before moving to the next payload.

### Result Analysis

Useful response indicators include:

- HTTP status code
- Response body size
- RTT
- Response content

The supplied lab example identified:

```text
/skills/
```

as an accessible directory because it returned:

```text
HTTP 200
```

---

# 19. ZAP Scanner

ZAP provides:

- Spider
- Ajax Spider
- Passive Scanner
- Active Scanner
- Reporting

## 19.1 Spider

Spider discovers links and builds the Sites Tree.

It can be started through:

```text
Attack → Spider
```

or through the HUD.

The Sites Tree displays discovered URLs and directories.

## Ajax Spider

Ajax Spider can identify links generated through JavaScript/AJAX requests.

---

# 20. Passive Scanner

ZAP's passive scanner analyzes responses as they pass through the proxy.

Examples of issues it may identify include:

- Missing security headers
- Certain client-side vulnerabilities
- Other response/source-code issues

Passive scanning is generally less intrusive than active scanning because it analyzes observed traffic.

---

# 21. Active Scanner

The Active Scanner sends active testing requests against identified pages and parameters.

It can take longer because it actively tests application behavior.

The supplied lab demonstrated an alert for:

```text
Remote OS Command Injection
```

The alert was categorized as:

```text
High
```

The alert details included evidence from the server response.

The underlying request/response could then be opened and replayed through ZAP.

---

# 22. ZAP Reporting

Reports can be generated through:

```text
Report → Generate HTML Report
```

Other supported output formats include:

- HTML
- XML
- Markdown

Reports provide an organized record of identified alerts and are useful for penetration-testing documentation.

---

# 23. Extensions – Burp BApp Store

Burp supports extensions through:

```text
Extensions → BApp Store
```

Extensions can:

- Add scanners
- Add decoders
- Beautify code
- Add security checks
- Analyze requests
- Extend existing Burp functionality

The module demonstrated:

```text
Decoder Improved
```

Example functionality included additional encoding/decoding and hashing.

Other extensions discussed included:

- .NET Beautifier
- J2EEScan
- Active Scan++
- AWS Security Checks
- Backslash Powered Scanner
- Wsdler
- Java Deserialization Scanner
- CMS Scanner
- Headers Analyzer
- HTML5 Auditor
- JavaScript Security
- Retire.JS
- CSP Auditor
- Autorize
- CSRF Scanner
- JS Link Finder

---

# 24. ZAP Marketplace

ZAP supports community add-ons through:

```text
Manage Add-ons → Marketplace
```

Add-ons may be:

- Release
- Beta
- Alpha

The module demonstrated:

```text
FuzzDB Files
FuzzDB Offensive
```

These add-ons provide additional wordlists and payloads for fuzzing.

---

# 25. Skills Assessment – Recorded Evidence

Only answers explicitly obtained during the practical session are recorded below.

| Task | Result | Evidence |
|---|---|---|
| Q1 | `HTB{d154bl3d_bu770n5_w0n7_570p_m3}` | Obtained using ZAP's Show/Enable functionality for the disabled field. |
| Q2 | `3dac93b8cd250aa8c1a36fffc79a17a` | Obtained by decoding the supplied cookie through the identified encoding layers. |
| Q3 | **Not explicitly recorded** | Fuzzing workflow was worked through, but the final submitted Q3 value was not explicitly provided in the session. |
| Metasploit proxying task | `CFIDE` | Obtained after configuring Metasploit to use `HTTP:127.0.0.1:8080` and inspecting proxied traffic. |

---

# 26. Key Evidence Collected

## Evidence 1 — Disabled Button/Field

Recorded answer:

```text
HTB{d154bl3d_bu770n5_w0n7_570p_m3}
```

The result was obtained through ZAP's interface modification capability.

---

## Evidence 2 — Cookie Decoding

Original cookie was decoded through the identified encoding layers.

Final recorded decoded value:

```text
3dac93b8cd250aa8c1a36fffc79a17a
```

This is a 31-character MD5-looking value, matching the assessment description.

---

## Evidence 3 — Request Manipulation

The lab request:

```http
POST /ping HTTP/1.1
```

was manipulated from:

```text
ip=1
```

to an injection test value.

The resulting response exposed directory contents including:

```text
flag.txt
server.js
package.json-related files
public
```

This demonstrated the value of request interception and manipulation.

---

## Evidence 4 — Metasploit Proxying

Metasploit was configured with:

```text
set PROXIES HTTP:127.0.0.1:8080
```

The resulting traffic was visible through the web proxy.

Recorded result:

```text
CFIDE
```

---

# 27. Lessons Learned

### 1. Client-side validation is not security

HTML/JavaScript restrictions can be bypassed by directly modifying HTTP requests.

### 2. Proxies provide visibility

Burp and ZAP make it possible to see exactly what a web application sends and receives.

### 3. Response interception is useful

A tester can determine whether a security restriction exists only in the front-end.

### 4. Repeater saves time

Repeated requests can be modified and resent without repeatedly triggering browser actions.

### 5. Encoding matters

Correct encoding is essential when constructing custom requests.

### 6. Fuzzing requires meaningful comparison

Status codes alone are not always enough. Response length, content, and timing can reveal useful results.

### 7. Proxying tools expands visibility

Command-line tools and security frameworks can be routed through Burp/ZAP to inspect their HTTP behavior.

### 8. Scanners and manual testing complement each other

Automated scanners can identify potential issues, while manual proxy analysis helps verify and understand them.

### 9. Extensions improve capability

BApp Store extensions and ZAP Marketplace add-ons can significantly expand proxy functionality.

---

# 28. Conclusion

The **Using Web Proxies** module established a practical workflow for web application penetration testing using Burp Suite and OWASP ZAP.

The exercises demonstrated:

```text
Browser
   ↓
Burp/ZAP Proxy
   ↓
HTTP Request
   ↓
Back-end Server
   ↓
HTTP Response
   ↓
Burp/ZAP
   ↓
Browser
```

The practical skills developed include:

- Capturing traffic
- Intercepting requests
- Modifying requests
- Intercepting responses
- Modifying responses
- Automating modifications
- Replaying requests
- Encoding/decoding data
- Proxying command-line tools
- Proxying Metasploit
- Fuzzing parameters
- Spidering applications
- Passive scanning
- Active scanning
- Generating reports
- Extending Burp and ZAP

The recorded assessment evidence confirms successful completion of multiple practical tasks, including:

```text
Q1:
HTB{d154bl3d_bu770n5_w0n7_570p_m3}

Q2:
3dac93b8cd250aa8c1a36fffc79a17a

Metasploit proxying:
CFIDE
```

Q3's final answer is intentionally left unrecorded because it was not explicitly supplied during the session.

---

# 29. Evidence / Reproduction Notes

This report distinguishes observed results from assumptions.

The recorded evidence is based on:

- User-provided screenshots
- User-provided terminal output
- User-provided Intruder/Fuzzer results
- User-provided assessment answers
- The HTB Academy module material supplied during the session

No unobserved assessment result has been intentionally invented.

For a formal submission, retain the original screenshots alongside this Markdown report so that each result can be matched to its visual evidence.
