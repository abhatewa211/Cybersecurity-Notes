## 1. Avoid System Commands

- **Avoid system command execution functions** whenever possible, especially when user input is involved.
    
- Even indirect user influence over command arguments can potentially lead to command injection.
    
- Prefer **built-in language functions** that provide the required functionality securely.
    

**Example — PHP:**

- Instead of using a system `ping` command, use:
    
    - `fsockopen()`
        

If a system command is absolutely necessary:

1. Never pass raw user input directly to it.
    
2. **Validate** the input on the back-end.
    
3. **Sanitize** the input.
    
4. Minimize the use of system-command functions.
    

---

# 2. Input Validation

### Purpose

Input validation ensures that user input matches the **expected format**.

> Validation should be performed on **both front-end and back-end**.

Front-end validation alone is not sufficient because users can bypass it by sending requests directly to the server.

### PHP — Validate an IP

```php
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // call function
} else {
    // deny request
}
```

- `filter_var()` provides built-in validation for formats such as:
    
    - IP addresses
        
    - URLs
        
    - Emails
        
    - etc.
        

### Custom Formats

For non-standard formats, use **Regular Expressions (Regex)**.

PHP:

```php
preg_match()
```

JavaScript:

```javascript
/regex/.test(ip)
```

### NodeJS

Libraries can also be used for standard validation.

Example:

```text
is-ip
```

Function:

```javascript
isIp(ip)
```

---

# 3. Input Sanitization

**Sanitization is one of the most important protections against injection.**

It means removing characters that are **not necessary** for the expected input.

### Correct order

```text
Input → Validation → Sanitization → Processing
```

Sanitization should happen **after validation**.

Why sanitize even after validation?

- Validation can contain mistakes.
    
- Regex may be incorrectly written.
    
- Unexpected characters may still get through.
    

---

## PHP Sanitization

For an IP address, only alphanumeric characters and `.` are allowed:

```php
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

This removes everything except:

```text
A-Z
a-z
0-9
.
```

### JavaScript

```javascript
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

### NodeJS

The section also mentions:

```javascript
import DOMPurify from 'dompurify';

var ip = DOMPurify.sanitize(ip);
```

---

# 4. Escaping Special Characters

Sometimes applications legitimately need to allow special characters, such as in **user comments**.

In such cases, escaping can be used:

### PHP

```php
escapeshellcmd()
```

### NodeJS

```javascript
escape(ip)
```

⚠️ **Important:** Escaping alone should not be considered a strong security solution because escaping techniques can potentially be bypassed.

Prefer:

**Safe APIs / strict validation / sanitization → escaping as appropriate**

---

# 5. Server Configuration

Even if an application contains a vulnerability, secure server configuration can **reduce the impact**.

### Recommended protections

#### 1. Use WAFs

Use security layers such as:

- Apache `mod_security`
    
- External WAFs such as Cloudflare, Fortinet, or Imperva
    

#### 2. Principle of Least Privilege

Run the web server with the **lowest privileges necessary**.

Example:

```text
www-data
```

Avoid running web applications as highly privileged users such as `root`.

#### 3. Disable Dangerous Functions

PHP can restrict functions that should not be available to the web application.

Example:

```text
disable_functions=system,...
```

#### 4. Restrict Application File Access

PHP's:

```text
open_basedir
```

can restrict the directories accessible to the application.

Example:

```text
open_basedir = '/var/www/html'
```

#### 5. Reject Suspicious Requests

Consider rejecting:

- Double-encoded requests
    
- Non-ASCII characters in URLs
    

#### 6. Avoid Sensitive/Outdated Components

Avoid vulnerable or outdated libraries/modules where possible.

Example mentioned:

```text
PHP CGI
```

---

# 6. Defense-in-Depth

No single protection should be relied upon.

A stronger approach is:

```text
Avoid system commands
        ↓
Use safe built-in APIs
        ↓
Validate input
        ↓
Sanitize input
        ↓
Properly handle special characters
        ↓
Least-privileged web server
        ↓
WAF / server protections
        ↓
Penetration testing
```

### Key Takeaways

- **Best defense:** Don't use system commands when a safe built-in alternative exists.
    
- **Never trust front-end validation alone.**
    
- Validate input **on the server**.
    
- Sanitize input according to the required format.
    
- **Blacklists are not sufficient** as a primary defense.
    
- Escaping can be bypassed, so don't rely on it alone.
    
- Run web applications with **least privilege**.
    
- Restrict filesystem and dangerous-function access.
    
- Use WAFs as an additional security layer.
    
- Finally, perform **penetration testing** to verify that the defenses actually work.