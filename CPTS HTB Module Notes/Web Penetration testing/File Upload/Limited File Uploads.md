![Image](https://images.openai.com/static-rsc-4/U5T84hVFCMJ8pCj16USvbypbLxD28n2Ny-hP_0EkuNXVmeCYn7CvWCnbHfVLnKIEcXD1n8dsYPstuNzy5rk0E431ujzciAwRua84mB8TZZqe7PMrzIvBNxLWeUQk-XMHlaBZoyMuYfSv3ec1tDka5VVEYZOLzt5KXawKfLiBjvn073SnX2EEGTTKb3ek7qf5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1DDcMXc_cpLBHUloCaVpxjXlawhKWEXBqNxZkAEUO9oHpGktvgLEfU0EhnPeKa0AAIGlwoQHQ0TyEL1OQ5_A91XRnAd7NfvyMXYq5jatGDeyY3l8hnYg4dbcB3wxmNjmVq_x510AIwFFcqD9YZvyzczHSIVzJ52rfQYe2L0C1FgSM7cGOXrWlEK47NsiCapt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/WYPBm2-W3hhnWD5cbRVM9nPtKTEpIthOusTpRspVMtpB5qEBM7TY8KC15hkxWTB8zPLCJCIGE3BMhEtd0SVSlINjU5m9tBiieoIVx-StQYtaKUwfNYgM1BJVlgHGHgQm7r0eoNDBt4GDnqa0oBxXhRmhY23i3PFyhw6osMKb9Z18dYxdlcbYz8wotA_SjGrx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XzAm8Gg4ujvElLIK9YayvamUfsWxV7wGVN0Dg8iZHhNLJykYFTCiM8D_1QAvaV843EO9CYEjRuTr7yEbRGKlImXS2q0q7W8ZQ0YW4ousj4eD-eE8d-AroVFw0u965w9iKnQTvGIJs3hGtH4Ht2KUAM-OyGO6zXFaf4Iwk2mnN5Umiw9VHH-HPa_iG2CXcCnQ?purpose=fullsize)

## 1. Core Concept

So far, the main objective was to bypass upload filters and achieve **arbitrary file upload**, particularly uploading executable server-side scripts.

However, sometimes the upload functionality has **secure filters** that cannot be bypassed using the techniques discussed earlier.

In that situation, the upload is called a:

> **Limited / Non-Arbitrary File Upload**

This means:

- Only certain file types can be uploaded.
    
- Directly uploading a PHP/web shell may not be possible.
    
- But the **allowed file formats themselves may contain dangerous functionality**.
    
- A maliciously crafted allowed file can introduce another vulnerability.
    

### Important idea

**Limited upload ≠ Safe upload**

Even if PHP execution is impossible, files such as:

- `SVG`
    
- `HTML`
    
- `XML`
    
- Some images
    
- Some document formats
    

may still be abused.

The major attacks discussed here are:

|File/Feature|Potential Attack|
|---|---|
|HTML|Stored XSS / CSRF|
|Image metadata|Stored XSS|
|SVG|XSS|
|SVG/XML|XXE|
|XML-based documents|XXE / SSRF|
|ZIP|Decompression Bomb / DoS|
|JPG/PNG|Pixel Flood / DoS|
|Large uploads|Storage exhaustion / DoS|
|Filename handling|Directory Traversal|

---

# 2. Why Fuzz Allowed Extensions?

Even when arbitrary upload is impossible, determining **exactly which extensions are allowed** is still useful.

For example:

```text
PHP       ❌
PHTML     ❌
JPG       ✅
PNG       ✅
SVG       ✅
HTML      ❓
XML       ❓
```

If `SVG` is accepted, we immediately know that the upload functionality may deserve additional testing because SVG is **XML-based** and can contain active content.

### Key takeaway

> **Fuzzing isn't only about finding executable extensions.**

It can also reveal **dangerous non-executable formats** that can be used for XSS, XXE, SSRF, or DoS.

---

# 3. Stored XSS Through File Uploads

## What is Stored XSS?

**Stored Cross-Site Scripting (XSS)** occurs when malicious JavaScript is stored by the application and later executed when another user views the affected content.

With file uploads, the malicious content can be stored inside the uploaded file or its metadata.

---

## 3.1 HTML File Uploads

If an application allows users to upload `.html` files, the uploaded HTML can contain JavaScript.

For example:

```html
<script>
alert(window.origin);
</script>
```

Unlike PHP:

```text
HTML → executed by the browser
PHP  → executed by the server
```

Therefore, an HTML upload doesn't necessarily provide server-side code execution, but it can still attack users who visit the uploaded page.

### Possible scenario

```text
Attacker
   │
   │ uploads malicious HTML
   ▼
Web Application
   │
   │ stores file
   ▼
Victim visits trusted-looking URL
   │
   ▼
JavaScript executes
```

This can potentially lead to:

- Stored XSS
    
- CSRF-related attacks
    
- Attacks against the victim's browser/session context
    

### Important distinction

**No PHP execution does not mean no impact.**

---

# 4. XSS Through Image Metadata

Images can contain metadata such as:

- Comment
    
- Artist
    
- Author
    
- Description
    
- Software
    
- Copyright
    

If an application displays this metadata without properly escaping it, an attacker may inject HTML/JavaScript into the metadata.

### Example from the module

Using `exiftool`:

```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
```

Then:

```bash
exiftool HTB.jpg
```

The metadata contains:

```text
Comment : "><img src=1 onerror=alert(window.origin)>
```

If the application displays this value unsafely:

```text
Uploaded Image
      │
      ▼
Metadata extracted
      │
      ▼
Comment displayed
      │
      ▼
HTML interpreted
      │
      ▼
JavaScript executes
```

### Important condition

The attack depends on the application **rendering the metadata unsafely**.

Simply inserting JavaScript into an image's metadata does not automatically mean XSS will occur.

---

# 5. SVG — One of the Most Important Formats

![Image](https://images.openai.com/static-rsc-4/3nVMSToiu4jW8Tt92IHq4A6a0i-BWzwfrWW7Lk_siuAJEQFFx4tPf4R7jYWHNdhCaBRo4C-3OjT0J5LUPL7LoiR6mv6zA-RlcY948N9RSAyEo3HMJy24zBcPkmHIOt6M1Oc4VTbvomHx9hBpsgu25jDpoWekclCbNAipobAQsWYZ3zQFk-DX6eQYoTf7UWsc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1DDcMXc_cpLBHUloCaVpxjXlawhKWEXBqNxZkAEUO9oHpGktvgLEfU0EhnPeKa0AAIGlwoQHQ0TyEL1OQ5_A91XRnAd7NfvyMXYq5jatGDeyY3l8hnYg4dbcB3wxmNjmVq_x510AIwFFcqD9YZvyzczHSIVzJ52rfQYe2L0C1FgSM7cGOXrWlEK47NsiCapt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/hRgsamyd-5g_XvrS--Ggi7qpzLQVgME5GYoIG9r9kRb7-4NOWi_gJw1a9vwebxhijZgAD8lL5spjz_bI5jQniUeDc1HpN-WM-wHfifSZMh-8Lg3WAPJ9RidD-3l5LvnWOubg6PyD4MqirrwtCWQONXUAzZJ4BuFcBFiyh-D1Tw424bN6vwdjqWliDuE5xmea?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/tOlJA7CzLxbLRRMW-1f8v2abXW272scTT9CJxrqstr-XIslgeWVYgOgBipvQlyrRMJBt6_oCPn3YNsmVfSsOycsY86XcNepQ3GcfhoajIT-EV9qXUYNCW6dNAgcJzUZJG7GWRgyEBDeDskNWNdtlrkbDaZnaVVOXUtqqV1dStCmvmsz6EO9_--qK-Qqp9B1p?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/onRIXq1oxrs_ISYHWngenOuN1pMT2S7UuborG7QiQhWrX4a4CLdB2WLwIgXHgaTO-TpCUgHbjFZmXrR-SFR1MIFYeW1mRydIzO1DSl_v5MMV346_m1y1sCHOeHO3HHLsBGAShtG08KZrtaG04LujNH7rFWGmNz-b5ObMtFMBWWGUN-zlqBzUGOaOMn5HfcW6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TSaxgkDz5FyjPjeebp99XPmls58vXon2R0cT312K5Yv_4EN8WChKFYtL2wpv5KcnqQS4KSAPgUr495WMz19dnvyABCTAq3LNCUgyzASJdcDPLEoRu0X75phI-kzeG7GI9OQFno5HHnKc4cJUmayQgi68IEFPI-ogHh2yG3FweLWemHyn6TgGpVtU13I5dmcn?purpose=fullsize)

**SVG = Scalable Vector Graphics**

Unlike JPG/PNG, SVG is fundamentally **XML-based**.

This is important because XML can contain:

- Elements
    
- Attributes
    
- Scripts
    
- External entities
    
- Other XML functionality
    

Therefore, allowing SVG uploads can introduce several attack possibilities.

---

# 6. XSS Through SVG

A malicious SVG can contain JavaScript.

Example:

```xml
<?xml version="1.0" encoding="UTF-8"?>

<svg xmlns="http://www.w3.org/2000/svg"
     version="1.1"
     width="1"
     height="1">

    <rect x="1" y="1"
          width="1"
          height="1"
          fill="green"
          stroke="black" />

    <script type="text/javascript">
        alert(window.origin);
    </script>

</svg>
```

When the browser renders the SVG in a context where script execution is permitted, the JavaScript may execute.

### Attack flow

```text
Malicious SVG
     │
     ▼
Upload
     │
     ▼
Server stores SVG
     │
     ▼
Application displays SVG
     │
     ▼
Browser parses XML
     │
     ▼
JavaScript executes
```

### Important

SVG can therefore be:

> **An allowed image format that still introduces an XSS attack surface.**

---

# 7. XXE — XML External Entity

## What is XXE?

**XXE = XML External Entity**

It occurs when an application processes attacker-controlled XML and allows external entities to access resources.

SVG can sometimes be used as the XML container for such attacks.

The potential impact includes:

- Reading local files
    
- Reading application source code
    
- Accessing internal resources
    
- SSRF
    
- Information disclosure
    

---

# 8. SVG XXE — Reading Local Files

The module demonstrates an SVG containing an external entity:

```xml
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE svg [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>

<svg>&xxe;</svg>
```

Conceptually:

```text
SVG uploaded
     │
     ▼
XML parser processes SVG
     │
     ▼
External entity is resolved
     │
     ▼
/etc/passwd accessed
     │
     ▼
Contents reflected somewhere
```

### Why `/etc/passwd`?

It is a useful basic test because:

- It is commonly readable.
    
- It demonstrates local file disclosure.
    
- It confirms whether external entities are being processed.
    

---

# 9. Why XXE Is Particularly Valuable in File Upload Attacks

Reading `/etc/passwd` is useful for enumeration, but the bigger prize can be **application source code**.

Source code can reveal:

- Upload directories
    
- Allowed extensions
    
- File naming conventions
    
- Validation logic
    
- Internal endpoints
    
- Configuration mistakes
    
- Other vulnerabilities
    

This can turn:

```text
Limited upload
      ↓
XXE
      ↓
Source-code disclosure
      ↓
Understand application
      ↓
Discover another vulnerability
      ↓
Further exploitation
```

### ⭐ Important concept

> **A limited file upload vulnerability can become a stepping stone to a much larger attack.**

---

# 10. Reading PHP Source Code Through XXE

For PHP applications, the module demonstrates using PHP's filter mechanism:

```xml
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE svg [
    <!ENTITY xxe SYSTEM
    "php://filter/convert.base64-encode/resource=index.php">
]>

<svg>&xxe;</svg>
```

The purpose is to retrieve the PHP source in **Base64-encoded form**.

Why Base64?

Normally, PHP source code could be interpreted rather than returned as raw text.

Encoding it allows the content to be transported as data.

Conceptually:

```text
index.php
   │
   ▼
PHP filter
   │
   ▼
Base64 encode
   │
   ▼
XXE reads encoded data
   │
   ▼
Attacker decodes it
   │
   ▼
PHP source code
```

---

# 11. XXE Beyond SVG

XXE is **not exclusive to SVG**.

Many document formats use XML internally.

Examples include:

- XML
    
- Some PDF workflows
    
- Word documents
    
- PowerPoint documents
    
- Other XML-based formats
    

If a vulnerable document-processing component parses attacker-controlled XML, XXE may become possible.

### Potential impact

```text
XXE
├── Local file disclosure
├── Source-code disclosure
├── Internal service discovery
└── SSRF
```

---

# 12. XXE → SSRF

XXE can sometimes be used to make the vulnerable server access internal resources.

This can lead to:

**SSRF — Server-Side Request Forgery**

Conceptually:

```text
Attacker
   │
   ▼
Malicious XML/SVG
   │
   ▼
Vulnerable XML parser
   │
   ▼
Server makes request
   │
   ├── Internal service
   ├── Internal API
   └── Private network resource
```

This can potentially expose services that aren't directly accessible from the Internet.

---

# 13. Denial of Service Through File Uploads

Limited uploads can also lead to:

> **DoS — Denial of Service**

The goal isn't necessarily code execution.

Instead, the attacker abuses how the server processes the uploaded file.

The module discusses several approaches.

---

# 14. Decompression Bomb

![Image](https://images.openai.com/static-rsc-4/XzAm8Gg4ujvElLIK9YayvamUfsWxV7wGVN0Dg8iZHhNLJykYFTCiM8D_1QAvaV843EO9CYEjRuTr7yEbRGKlImXS2q0q7W8ZQ0YW4ousj4eD-eE8d-AroVFw0u965w9iKnQTvGIJs3hGtH4Ht2KUAM-OyGO6zXFaf4Iwk2mnN5Umiw9VHH-HPa_iG2CXcCnQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ydpiNeBlIAyUX6q_UnerhQb11WXNRB5oe0DbmPA5pCkUUqKh8v80OYjYs-SnEbl9w9qa72P8f9YR6ZTEU8_MucEmftlYqrsrnmQPFysszcvxIkhpTqYWd6_Q4XeRF-Oo63O3Glh50-w6FmAUOM5DAFopPg5IXJKrcQaWzFitqxoYW1gH85hxexo-BDdrc5t8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pQdIHQ30caIh0bulokEP50n6m-KVJdnLgZzVqX3kZp194LJjbRufiZsSISKXuiCx-wAGIxrfTFNDeF1cLvm2sW1RbXv5dRV5p-tjiWguJ0K_uFpM2KX7SjcNImK2FZtF3-iWs63qEV-In73SWtHtOtU2IAd9DfTrP-CW7ibuvJzj2GZjrLdt9r_rTc_HBzlt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-7370w6RkSqZ6AogWhPA9DrNCPtWSzKQdWYFFa5ql8TaHpRYd4skpubJR-dPsrBMQ5ZRiw3uhicHghATf_k1ktdKhq9DDytuEfzCck_pCvvHfsjM6ERuDlX-bgYeLiKScVtgrrpj7Sq5STyJt67H-UvnE1ANGDHkTxon68dbEJ_eyuJRlyux9zBAsKAfBLJN?purpose=fullsize)

A **Decompression Bomb** is a highly compressed archive that expands into an extremely large amount of data when extracted.

Example concept:

```text
Small ZIP
   │
   │ upload
   ▼
Web application
   │
   │ automatically extracts
   ▼
Huge amount of data
   │
   ▼
Disk / Memory exhaustion
   │
   ▼
Service degradation / crash
```

The module specifically mentions **nested ZIP archives**.

A relatively small uploaded archive can expand repeatedly and eventually consume enormous amounts of storage/resources.

### Important condition

The attack becomes relevant when the application **automatically extracts uploaded archives**.

---

# 15. Pixel Flood

Another image-related DoS technique is a **Pixel Flood**.

It targets image processing rather than archive extraction.

The general concept is:

```text
Small image file
      │
      ▼
Manipulated dimensions
      │
      ▼
Server believes image is enormous
      │
      ▼
Image processing allocates huge memory
      │
      ▼
Resource exhaustion
```

The module gives an example of an image claiming dimensions of:

```text
0xffff × 0xffff
```

which represents an enormous number of pixels.

If an application attempts to process such an image without appropriate limits, it may consume excessive memory/resources.

---

# 16. Oversized File Uploads

A simpler DoS possibility is uploading an extremely large file.

If the application doesn't properly enforce upload-size limits:

```text
Large file
   ↓
Server accepts upload
   ↓
Disk space decreases
   ↓
Repeated uploads
   ↓
Storage exhaustion
   ↓
Application/server problems
```

Potential consequences include:

- Disk exhaustion
    
- Application slowdown
    
- Failed writes
    
- Service instability
    
- Server crash
    

### Defensive lesson

Upload size limits should be enforced **server-side**, before excessive resources are consumed.

---

# 17. Directory Traversal Through Uploads

If the application is vulnerable to directory traversal while constructing the destination filename/path, an attacker may attempt to escape the intended upload directory.

Conceptually:

```text
Normal:

/uploads/image.jpg


Traversal:

/uploads/../../../some/path
```

The module gives:

```text
../../../etc/passwd
```

as an example of a path that could potentially target a different location.

### Potential impact

Depending on permissions and implementation, directory traversal could allow:

- Writing outside the intended upload directory
    
- Overwriting files
    
- Modifying application files
    
- Configuration manipulation
    
- Potential DoS
    

---

# 🧠 Attack-Surface Summary

This is the most important section to remember.

|Allowed Upload|Possible Abuse|
|---|---|
|HTML|Stored XSS / CSRF|
|Image + unsafe metadata display|Stored XSS|
|SVG|XSS|
|SVG/XML|XXE|
|XML-based documents|XXE|
|XXE|File disclosure / SSRF|
|ZIP|Decompression Bomb|
|JPG/PNG|Pixel Flood|
|Large files|Storage exhaustion|
|Vulnerable filename handling|Directory Traversal|

---

# ⭐ Most Important Takeaways

### 1. Limited upload doesn't mean safe upload

A file does **not** need to execute server-side code to be dangerous.

### 2. Think about the parser

Ask:

> **What will process this uploaded file after it reaches the server?**

For example:

```text
SVG → XML parser → possible XXE/XSS
ZIP → decompression library → possible DoS
Image → metadata parser → possible XSS
Document → document parser → possible XXE
```

### 3. Fuzz allowed extensions

Don't only search for:

```text
.php
.phtml
.php5
```

Also investigate potentially dangerous formats such as:

```text
.svg
.html
.xml
```

### 4. XSS isn't limited to HTML

It can potentially enter through:

- HTML files
    
- Image metadata
    
- SVG
    

### 5. SVG deserves special attention

SVG is simultaneously:

```text
Image format
      +
XML
      +
Potential scripting
```

That's why it can create multiple attack surfaces.

### 6. XXE can become a stepping stone

The chain can look like:

```text
Limited File Upload
        ↓
      SVG
        ↓
       XXE
        ↓
Source-code disclosure
        ↓
Discover upload implementation
        ↓
Find additional vulnerability
```

### 7. DoS can happen without code execution

```text
Upload
 ├── Decompression Bomb
 ├── Pixel Flood
 ├── Huge File
 └── Traversal
        ↓
Resource exhaustion / file corruption / service disruption
```

---

# 🔥 Exam / CTF Quick Revision

```text
LIMITED FILE UPLOAD
        │
        ├── HTML ─────────→ XSS / CSRF
        │
        ├── Image metadata → XSS
        │
        ├── SVG
        │    ├────────────→ XSS
        │    └────────────→ XXE
        │                       ├→ Local files
        │                       ├→ Source code
        │                       └→ SSRF
        │
        ├── ZIP ──────────→ Decompression Bomb → DoS
        │
        ├── JPG/PNG ──────→ Pixel Flood → DoS
        │
        ├── Huge file ────→ Storage exhaustion
        │
        └── Filename/path ─→ Directory Traversal
```

## 📝 One-line definition

> **Limited File Upload vulnerabilities occur when an application securely restricts uploaded file types but still allows an attacker to abuse the functionality or processing of permitted file formats to introduce attacks such as XSS, XXE, SSRF, DoS, or directory traversal.**