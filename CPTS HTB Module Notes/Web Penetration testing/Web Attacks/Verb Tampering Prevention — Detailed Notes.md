![Image](https://images.openai.com/static-rsc-4/yq359QPbooibBbGI0MaoErj-Hc6EvbCiOrsLS7zZNBYLUnzirkqV7OmrXg8h2Bgrg0ZDoU0bnJjKDPrv3Ey2U-OvIvA72U89mpeuMf1STWdFfj1RqtDO9B6cvnKJrT2rZXKcWq473I3UHk-2D5IWHwHYsiaACJK0aujypfW9Yx2Vh5hhmCPeuux8e15PlMvV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KqTgFyICPDPa04yWLxnjxjBnO6ukMqmg-xncVf8q02bE2boySc0vXAbt9beJDymNJ3sVVvEnLboiGBZUgUBXdT_tyQl_lPbyZJ1mja9cSbKBOSldoqWYEOqxbMpY9slN39zbKkkj6qFaH8sVyyKm1dAdj6-2vi4EpSEL8SwdO4BekFHsZp53lX0HfpxCK8Z_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DzkC3oZBIKm12wPukC9rVLELKWQ0Cfx2A7fqK9H_PF2SdH2daCKfa7ALA23FsZ_Ruv5ZNXInGBjB-y_lBGw6QGiX_eqdFUHKk7XNIobl7P31coju748IQKp3ljNOcFIsHJLqpiYVrd3PiYht02IJr5AodL91eXW8Q8PiA1geKnkA6K1f5aeaOTVx6GkR8lky?purpose=fullsize)

## 1. Overview

HTTP Verb Tampering vulnerabilities are generally introduced by two things:

```text
HTTP Verb Tampering
        │
        ├── Insecure Configuration
        │
        └── Insecure Coding
```

Therefore, prevention also has two major areas:

1. **Secure web-server configuration**
    
2. **Consistent application coding**
    

The key principle is:

> **Security controls must apply consistently to every HTTP method and every request parameter that can reach the protected functionality.**

---

# 🔴 Part 1 — Insecure Configuration

## 2. Where Can This Vulnerability Occur?

HTTP Verb Tampering can occur in modern web servers such as:

- **Apache**
    
- **Tomcat**
    
- **ASP.NET**
    

The common mistake is limiting authorization to a **specific HTTP method**.

For example:

```text
GET → Protected 🔒

POST → Unprotected ❌
HEAD → Unprotected ❌
OPTIONS → Unprotected ❌
```

This creates an HTTP Verb Tampering opportunity.

---

# 3. Apache — Vulnerable Configuration

A vulnerable Apache configuration might look like:

```xml
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

Let's break this down.

### Directory

```xml
<Directory "/var/www/html/admin">
```

This configuration applies to the:

```text
/admin
```

directory.

### Basic Authentication

```xml
AuthType Basic
```

enables HTTP Basic Authentication.

### Authentication file

```xml
AuthUserFile /etc/apache2/.htpasswd
```

specifies where authentication credentials are stored.

### The Problem

The critical part is:

```xml
<Limit GET>
    Require valid-user
</Limit>
```

The authentication requirement is limited to:

```text
GET
```

Therefore:

```text
GET      → Authentication ✓
POST     → Potentially unprotected ❌
HEAD     → Potentially unprotected ❌
OPTIONS  → Potentially unprotected ❌
PUT      → Potentially unprotected ❌
DELETE   → Potentially unprotected ❌
```

---

# 4. Why `<Limit GET>` Is Dangerous

The administrator might think:

> "I protected the `/admin` directory with authentication."

But that's not exactly what the configuration says.

It says:

> **Require authentication when the request uses GET.**

That's a major difference.

### Vulnerable design

```text
             /admin
                │
       ┌────────┼────────┐
       ▼        ▼        ▼
      GET     POST     HEAD
       │        │        │
       ▼        ▼        ▼
      Auth     ???       ???
       │
       ▼
     Block
```

Only GET is explicitly protected.

---

# 5. Even GET + POST Can Be Vulnerable

Suppose the administrator changes:

```xml
<Limit GET>
```

to:

```xml
<Limit GET POST>
```

This is still potentially vulnerable.

Why?

Because other methods remain outside the restriction:

```text
GET      → Protected ✓
POST     → Protected ✓
HEAD     → Potentially unprotected ❌
OPTIONS  → Potentially unprotected ❌
PUT      → Potentially unprotected ❌
DELETE   → Potentially unprotected ❌
PATCH    → Potentially unprotected ❌
```

### ⭐ Important

> **Adding more methods to `<Limit>` does not necessarily solve the underlying problem.**

The safer approach is to avoid restricting authorization to only a selected list of methods.

---

# 6. Apache — Safer Approach

If authorization should apply generally, don't narrowly scope it to a few verbs.

If there is a specific reason to treat a method differently, Apache provides:

```text
LimitExcept
```

The idea is:

```text
LimitExcept <specific methods>
```

meaning the configuration applies to **all methods except the specified ones**.

### Security Principle

Instead of thinking:

```text
"Protect these 2 methods."
```

think:

```text
"Protect everything unless I have a specific reason not to."
```

---

# 🟠 7. Tomcat — Vulnerable Configuration

Tomcat can have similar issues through its `web.xml`.

Example:

```xml
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

The important line is:

```xml
<http-method>GET</http-method>
```

This restricts the authorization rule to:

```text
GET
```

Other HTTP methods may not receive the same authorization treatment.

---

# 8. Tomcat — The Security Problem

The configuration effectively becomes:

```text
/admin/*
    │
    ├── GET    → admin role required 🔒
    │
    ├── POST   → potentially outside rule
    ├── HEAD   → potentially outside rule
    ├── PUT    → potentially outside rule
    └── DELETE → potentially outside rule
```

Therefore, an attacker may try an alternate HTTP method.

### Safer Concept

Tomcat provides:

```text
http-method-omission
```

This allows the configuration to specify methods that should be **omitted**, rather than limiting authorization to only a small set of methods.

---

# 🔵 9. ASP.NET — Vulnerable Configuration

ASP.NET can have similar problems in `web.config`.

Example:

```xml
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
    </authorization>
</system.web>
```

The important part is:

```xml
verbs="GET"
```

The authorization scope is again limited to the `GET` method.

---

# 10. ASP.NET — The Problem

Conceptually:

```text
GET
 ↓
Authorization rules
 ↓
Admin required 🔒


POST
 ↓
Not covered by same rule ❌


HEAD
 ↓
Not covered by same rule ❌
```

Therefore, other HTTP methods could potentially access the functionality without the intended authorization control.

ASP.NET provides mechanisms such as:

```text
add
remove
```

to manage authorization more safely without narrowly restricting the entire policy to one HTTP verb.

---

# 11. Configuration Prevention — The Golden Rule

Across Apache, Tomcat, and ASP.NET, the central lesson is the same:

> **Do not limit authorization to a specific HTTP verb unless there is a very deliberate security reason for doing so.**

Instead, authorization should cover **all relevant HTTP methods**.

---

# 12. Why HEAD Deserves Special Attention

The module specifically recommends:

> **Generally consider disabling/denying all `HEAD` requests unless they are specifically required by the web application.**

Why?

Because `HEAD` can sometimes be overlooked when developers configure authentication rules.

For example:

```text
GET  → protected
POST → protected
HEAD → forgotten
```

An attacker may then test:

```http
HEAD /admin/
```

and potentially discover that a security control behaves differently.

### ⭐ Remember

`HEAD` isn't inherently malicious.

The security concern is:

```text
HEAD
 +
Different security handling
 +
Sensitive functionality
 =
Potential vulnerability
```

---

# 🛡️ Part 2 — Insecure Coding

## 13. Why Insecure Coding Is Harder to Find

Finding insecure server configuration is generally easier.

The configuration is often centralized:

```text
Apache config
Tomcat web.xml
ASP.NET web.config
```

Application-code vulnerabilities are harder because the relevant logic can be distributed across different parts of the application.

For example:

```text
Function A
   ↓
Input validation


Function B
   ↓
File creation


Function C
   ↓
Command execution
```

The inconsistency may exist between these separate functions.

---

# 14. Vulnerable PHP Example

The module provides:

```php
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

At first glance, this may appear secure against Command Injection.

Let's understand why it **looks** secure.

---

# 15. The Security Filter

The application uses:

```php
preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])
```

The regular expression looks for characters outside the allowed set.

Allowed characters include:

```text
A-Z
a-z
0-9
.
(space)
_
-
```

So a suspicious value containing special shell characters could be rejected.

Conceptually:

```text
$_POST['filename']
       │
       ▼
preg_match()
       │
       ├── Bad character → Reject ❌
       │
       └── Allowed → Continue ✓
```

If we looked **only at this line**, the filtering appears reasonable.

---

# 16. The Fatal Inconsistency

Now look at what happens afterward:

```php
system("touch " . $_REQUEST['filename']);
```

The application validates:

```php
$_POST['filename']
```

but uses:

```php
$_REQUEST['filename']
```

### 🚨 This is the vulnerability.

The two variables don't represent exactly the same input source.

```text
VALIDATION:

$_POST['filename']
        │
        ▼
     Filter ✓


EXECUTION:

$_REQUEST['filename']
        │
        ▼
     system()
```

---

# 17. Why `$_REQUEST` Is Dangerous Here

`$_REQUEST` can include request parameters from multiple sources, including GET and POST, depending on PHP configuration.

Therefore, conceptually:

```text
$_REQUEST['filename']
        │
        ├── GET
        │
        └── POST
```

But the security filter only checks:

```text
$_POST['filename']
```

This creates an inconsistent path.

---

# 18. How the Filter Gets Bypassed

Suppose an attacker sends malicious input through `GET`.

Conceptually:

```text
GET filename
      │
      ▼
$_GET['filename']
      │
      ▼
$_REQUEST['filename']
      │
      ▼
system()
```

But the filter checks:

```text
$_POST['filename']
```

If no POST parameter was supplied:

```text
$_POST['filename']
```

may be empty or otherwise not contain the malicious value.

Therefore:

```text
GET malicious input
       │
       ▼
POST filter sees nothing malicious
       │
       ▼
Filter passes ✓
       │
       ▼
$_REQUEST retrieves GET value
       │
       ▼
system()
       │
       ▼
Command Injection
```

---

# 19. The Critical Difference

The vulnerability can be summarized as:

```text
             INPUT
               │
        ┌──────┴──────┐
        ▼             ▼
      POST           GET
        │             │
        ▼             │
     FILTER            │
        │             │
        ▼             │
      Pass             │
        │             │
        └──────┬──────┘
               ▼
          $_REQUEST
               │
               ▼
            system()
```

The attacker-controlled GET value reaches `system()` without being subjected to the same filter.

---

# 20. Why This Is Called HTTP Verb Tampering

The attacker changes the request method/input source:

```text
Normal:
POST

Tampered:
GET
```

The application handles the two paths inconsistently.

Therefore:

```text
HTTP Method Change
        ↓
Different parameter source
        ↓
Security filter avoided
        ↓
Sensitive functionality reached
```

---

# 21. Why Real Applications Are Harder

The HTB example is intentionally simple.

In a real application, the vulnerable pieces may be separated:

```text
security.php
    ↓
validate_input()


file_manager.php
    ↓
create_file()


command.php
    ↓
execute_operation()
```

The developer may not immediately see that:

```text
Function A
checks POST
```

while:

```text
Function B
uses REQUEST
```

This makes these vulnerabilities difficult to identify during code review.

---

# 22. Preventing Insecure Coding

The module gives a critical rule:

> **We must be consistent with our use of HTTP methods.**

For a specific functionality, the application should consistently use the intended HTTP method.

For example:

```text
File Creation
     ↓
POST
     ↓
Validate POST input
     ↓
Use validated POST input
```

Avoid:

```text
File Creation
     ↓
Sometimes GET
Sometimes POST
     ↓
Different validation paths
     ↓
Potential bypass
```

---

# 23. Expand the Scope of Security Filters

Another important recommendation is:

> **Expand the scope of testing in security filters by testing all request parameters.**

The module provides these examples:

|Language|Function / Variable|
|---|---|
|**PHP**|`$_REQUEST['param']`|
|**Java**|`request.getParameter('param')`|
|**C#**|`Request['param']`|

The idea is that security-related functions should account for **all request parameter sources that the application may actually accept**.

---

# 24. Important Caveat: Filtering Is Not the Best Primary Defense

There's an important security-development lesson here.

Simply filtering special characters is generally **not a sufficient defense against Command Injection**.

For command execution, the preferred approach is to:

- Avoid invoking a shell where possible.
    
- Use safe APIs that don't interpret shell metacharacters.
    
- Use strict allowlists for filenames/identifiers.
    
- Separate data from commands.
    
- Apply least privilege to the application process.
    

So the deeper lesson is:

```text
Don't rely solely on:
"Block bad characters"

Prefer:
"Don't allow user input to become executable commands"
```

---

# 25. Secure vs Vulnerable Design

### ❌ Vulnerable

```php
if (!preg_match(..., $_POST['filename'])) {
    system("touch " . $_REQUEST['filename']);
}
```

Problem:

```text
Validate → POST
Use      → REQUEST
```

---

### ✅ Better Principle

```text
Receive input
      ↓
Use one consistent input source
      ↓
Validate that exact value
      ↓
Use safe file-handling APIs
      ↓
Avoid shell interpretation
```

The exact implementation depends on the application, but the important point is **consistency + safe APIs**.

---

# 26. Configuration vs Coding Prevention

|Area|Vulnerable Pattern|Prevention|
|---|---|---|
|Apache|`<Limit GET>`|Don't narrowly limit authorization to selected verbs; use `LimitExcept` where appropriate|
|Tomcat|`<http-method>GET</http-method>`|Use appropriate method-omission configuration|
|ASP.NET|`verbs="GET"`|Use `add`/`remove` appropriately|
|Application code|Validate `POST`, use `REQUEST`|Consistently handle the same input source|
|HTTP methods|Forgotten methods such as `HEAD`|Explicitly review/disable unnecessary methods|
|Command execution|User input reaches shell|Avoid shell execution; use safe APIs|

---

# 🧠 27. Most Important Takeaways

### 🔴 Configuration

> **Don't protect only GET or GET+POST.**

Because:

```text
GET + POST protected
        ≠
Everything protected
```

Other methods may remain accessible.

---

### 🟠 Coding

> **Don't validate one request source and use another.**

Bad:

```text
Validate → $_POST
Use      → $_REQUEST
```

Better:

```text
Validate → exact intended input
Use      → same validated input
```

---

### 🔵 HTTP Methods

Always consider:

```text
GET
POST
HEAD
PUT
DELETE
PATCH
OPTIONS
```

and any other methods your application/server accepts.

---

# 🎯 Final Revision Sheet

```text
              VERB TAMPERING PREVENTION
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
   CONFIGURATION                    CODING
          │                             │
          ▼                             ▼
 Don't limit auth               Be consistent
 to specific verbs              with HTTP methods
          │                             │
          ▼                             ▼
 Cover all relevant             Validate the same
 HTTP methods                   input you actually use
          │                             │
          ▼                             ▼
 Review HEAD                    Expand filter scope
 and unnecessary               to relevant parameters
 methods
          │                             │
          └──────────────┬──────────────┘
                         ▼
                 CONSISTENT SECURITY
```

## 🔥 Golden Rules

1. **Do not restrict authorization to only a few HTTP verbs unless there's a deliberate reason.**
    
2. **Remember that protecting GET and POST doesn't automatically protect HEAD, PUT, DELETE, OPTIONS, etc.**
    
3. **Consider denying unnecessary `HEAD` requests.**
    
4. **Use consistent HTTP methods for a given functionality.**
    
5. **Validate the exact input that will actually be used.**
    
6. **Don't let different request parameter sources create different security paths.**
    
7. **For Command Injection, don't rely solely on character filtering—avoid unsafe shell execution altogether.**
    
8. **Security controls should be enforced server-side and consistently across every path to sensitive functionality.**
    

### ⭐ The Core Concept

> **HTTP Verb Tampering prevention is ultimately about eliminating inconsistencies: the HTTP methods you accept, the authentication rules you apply, the parameters you validate, and the values you ultimately use must all line up.**