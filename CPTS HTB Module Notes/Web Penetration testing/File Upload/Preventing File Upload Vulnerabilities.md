## 1. Extension Validation

### Best Practice

Use **both a whitelist and blacklist** on the backend.

- **Whitelist** → allows only expected extensions.
    
- **Blacklist** → blocks dangerous extensions even if the whitelist is bypassed.
    
- Validation must happen **server-side**.
    
- Front-end validation can still be used for usability, but **must not be trusted for security**.
    

### Secure Regex

Whitelist should verify that the filename **ends with** the allowed extension:

```regex
^.*\.(jpg|jpeg|png|gif)$
```

The `$` is important because it ensures the extension is at the **end of the filename**.

### Example

```php
$fileName = basename($_FILES["uploadFile"]["name"]);

// Blacklist
if (preg_match('/^.*\.ph(p|ps|ar|tml)/', $fileName)) {
    die("Only images are allowed");
}

// Whitelist
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    die("Only images are allowed");
}
```

### Key Point

> **Use whitelist + blacklist + backend validation.**

---

# 2. Content Validation

Extension validation alone is **not enough**.

The server should validate:

1. **File extension**
    
2. **HTTP Content-Type**
    
3. **MIME type / file signature**
    

And they should all agree with the expected file type.

### Example

For a PNG upload:

```text
Filename → .png
Content-Type → image/png
MIME type → image/png
File signature → valid PNG
```

If any of these don't match, reject the file.

Example:

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!preg_match('/^.*\.png$/', $fileName)) {
    die("Only PNG images are allowed");
}

foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        die("Only PNG images are allowed");
    }
}
```

### Key Point

> **Never trust the filename or Content-Type alone. Verify the actual file content too.**

---

# 3. Upload Directory Protection

Do **not** give users direct access to the upload directory.

Instead:

```text
User
 ↓
download.php
 ↓
Authorization + validation
 ↓
Retrieve file
 ↓
Download
```

Direct access to the upload directory should ideally return:

```text
403 Forbidden
```

### Why?

If an attacker somehow uploads a malicious script, preventing direct access makes it much harder to execute it.

---

# 4. Secure Download Handling

A download script should enforce:

### Authorization

Verify that the authenticated user is allowed to access the requested file.

Prevents:

- Unauthorized file access
    
- IDOR
    

### Path Validation

Never directly use unsanitized user input as a filesystem path.

Prevents:

- Path traversal
    
- LFI-style issues
    

### Use an Allowlist

Only permit access to known, valid files/directories.

---

# 5. Security Headers

When serving uploaded files, use appropriate headers.

### `Content-Disposition`

Use:

```http
Content-Disposition: attachment
```

This tells the browser to **download** the file rather than render it inline.

### `Content-Type`

Set the correct MIME type so the browser knows how to handle the file.

### `X-Content-Type-Options`

```http
X-Content-Type-Options: nosniff
```

Prevents browsers from MIME-sniffing and interpreting content as another type.

---

# 6. Randomize Uploaded Filenames

Don't store files using the user's original filename.

Instead:

```text
Original:
profile.php

Stored:
8f31c92a7b4e.png
```

Store the sanitized original filename separately in a database.

### Benefits

- Hides the actual filename
    
- Makes file discovery harder
    
- Reduces filename injection risks
    
- Prevents predictable filenames
    
- Helps prevent direct access
    

---

# 7. Isolate Uploaded Files

Ideally, store uploaded files:

- On a **separate server**
    
- Or in a **separate container**
    
- Or in another isolated storage location
    

### Benefit

If an attacker somehow achieves RCE through an uploaded file:

```text
Compromised upload environment
        ↓
Limited impact
```

rather than:

```text
Compromised upload
        ↓
Entire application server compromised
```

### PHP `open_basedir`

PHP can restrict filesystem access using:

```text
open_basedir
```

This limits which directories PHP applications can access.

---

# 8. Disable Dangerous PHP Functions

Even if an upload vulnerability is exploited, disabling command-execution functions can reduce the impact.

In `php.ini`:

```text
disable_functions
```

Potentially dangerous functions include:

```text
exec
shell_exec
system
passthru
```

### Defense in Depth

This is **not a replacement for secure uploads**.

It is an additional security layer if other protections fail.

---

# 9. Error Handling

Do not expose detailed server errors to users.

Bad:

```text
Warning: failed to open
/var/www/html/uploads/user123/file.php
```

This reveals:

- Filesystem paths
    
- Filenames
    
- Upload directories
    
- Server information
    

Instead, return a generic message such as:

```text
Unable to upload file.
```

### Key Principle

> **Handle errors internally; expose only minimal information to users.**

---

# 10. Additional Security Measures

Also implement:

- **File-size limits** → prevent storage/memory exhaustion.
    
- **Keep libraries updated** → patch known vulnerabilities.
    
- **Malware scanning** → detect malicious uploaded files.
    
- **WAF** → provide an additional layer of protection.
    

---

# Final Prevention Checklist

```text
☑ Backend validation
☑ Extension whitelist
☑ Dangerous-extension blacklist
☑ Validate actual file content
☑ Verify MIME type
☑ Verify file signature
☑ Don't trust Content-Type
☑ Hide upload directory
☑ Block direct access
☑ Secure download endpoint
☑ Authorization checks
☑ Path validation
☑ Randomize stored filenames
☑ Store uploads separately/isolated
☑ Use open_basedir where appropriate
☑ Disable dangerous functions
☑ Hide detailed errors
☑ Limit file size
☑ Scan files for malware
☑ Keep libraries updated
☑ Use WAF as secondary protection
```

### One-line exam takeaway

> **Secure file uploads require strict backend extension + content validation, isolated storage, controlled file access, safe filenames, proper authorization, and defense-in-depth measures.**