![Image](https://images.openai.com/static-rsc-4/dEg1uktJwSbSzX--a0h2pJuHmBdPg5mgfMyb_c9wsw5WUeUMDQJERuMYwgD4Djug9UuqxUoaD9s9t2zW-fhj65PG7VxXss-mArXe-4rgcFf-AMyAYoo0-4Q9P8zlq6TIID5mEzD1OVp3eaoh57KAuMa05L7aRMmp2XBzptJcX5ctTowXNVHFQShFPKRPUKog?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cqNHuTN3egs0bt2QvhatzMoxilc7Thl9-4SjxqPMczd_34yoY7MzvF7Z4r723tpOmumfU0FtY_Pg9hHfGbGI6QcztaKRH5-nLK7c74B3IOByD6Zseqz9CzpHwBdC5nZr3MMLOu4dzrcv3CE6RjwjHcqgyzIKkyk6kxisdwvAcVgTAusgfKmeZq00vko5Dm7j?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/izjxtiGw3O1dYmUjAQ6OBwj-bR1QgjiKDR9_a_6DvI0zXDg5lgdedRnJkkj0ViLfGRyYJs5Q-DFJ511pwQaH_Lh2G0F_D0IPeMRl4J8AGdjSAJEHg6FKpe37Ayf49_3T_xExCcuaXi8lQg08PuUTvurpskwMP3AC4j7u_ex6EGCW8L12SjHpP8cjKy0NwkTW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MbdA48co2PF-u59NtpetbVDCwHZzJLVSVslrq9rDoYJV1GS8ZsDoT9Doq1x0keHZRfhCFbEwl1DfaUva6jP0XOa3-C2XiG5Oo3CuD0NmHXLWFZ37coELmYCd7ZH-9yyHsNqpbNJGLcuRz4fRuQ7N6FXGfd5ry9r_qh_48HCkvJ-Ecw3zseHP6k4hYV_AWKLk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fx8ABVNTtIO8o9WYM7xYzkK3rLhTho8eDY0wBjt1RhscwxhRoCbW43aUiBQtqn1lsaQTtNuuyBF00I_fnG9LKdZPwqeqB9I7Yv-D96pVvzBbTsJpWNraMCNxjePm3qAqZa8T9xBS1eqwNmonUYfz5EAFk5XkMRH9maGJFl1UTf0fC32D0PrXP0a2kqlEOk0b?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pivydmeB2UzWphbuZlx8e96pu9M136iLQCN4P4mmidfK1wIABw5C1r-tFbcM8f_JmQpI8hHrep15adnjqT0vr6hJhwOGXPEe_I3getKdIeWq6YM-Kuq4Ducs9C6DKVVT1mwUWuvGwk6ZSIyQf_dJwyay0EWuXxIya21mWQbWqXM9udwnSbMyTxxjKy4PB4_x?purpose=fullsize)

## 1. Why Type Filters Exist

Previous sections focused primarily on the **filename and extension**.

For example:

```text
shell.php
shell.phtml
shell.jpg.php
```

However, checking only the extension is **not sufficient**.

An attacker may be able to:

- disguise a malicious script using an allowed extension
    
- exploit weak filename validation
    
- abuse allowed formats such as SVG
    
- exploit web-server misconfigurations
    

Therefore, modern applications may also inspect the **actual type/content of the uploaded file**.

### Core idea

> **Extension validation checks the filename.**  
> **Type validation checks information about the uploaded file itself.**

There are two important content/type validation methods:

1. **Content-Type Header**
    
2. **MIME-Type / File Content**
    

---

# 2. Content-Type Header

![Image](https://images.openai.com/static-rsc-4/yzarHlQkdYn4TCNzYwvOb8ErsyTQTODm3WUNGx2Nk9pLd6zACg0nCI8KsX5FGBFweexX0V1iEJ5ajMfnweGQNm5EEq01NUCLlNPx_mLeWB9PZjHLz6VLpk1036zaCOC0yJ2Tyt1jf3vOTa5DQ7niRIaWMQHIlbnuJpgwoLZ3Tvh5vxAKVMKJB-kP85I_9_Qz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ggx0UvXRSpjj3XP-FyLwDO4DXIJhb8KK8eeCJGUloCaGHUdaMaS-PS9H00Hb_TEOfjbvFnoK8zC0LfAQSgtU2HQZMXYTYDZlUr3SWD3JSt3RUhXXr1vVbr3Wk-7GcQe-KWIcKqXUpntZhoqll6KGN5fxUyzCpXjhZxC-mDdqJ534Gxa-yaB4lw-5Ozp4-SMh?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Q3i2htaUINR1-RUSOUBIUZjvaKKmL0ojZntjdjk3P82W3nh1X7TfCaS-D5ZUqCbGJBg3ZlgaaTIoOHToJaK_2VBYLCkqZcX7C8rdwLBzNN399GF06b7BNkIuo2aT8NNSq88at4Eg72o645jBhaTHUotkyxO6WscwNaHC6z8aFysqXFsHTTygXCoI-ViQO8P5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ILO_AW6AB_Zsgt9ntBNiP9WEete-B3Ma0l8blPPQt73HyXhiMaoFX7UhfcxdzI7mc7pUcO9BDWcUwC7tnn33CyJ3ymuYQAHrPm6QW7k8NNy1bk6iXW9W6oVRIj4IvCP-R3kyMFLGDMoBho9FHXyGAYg70pAYjG_FEIWjNMe2soY6K_x4lBPM-DMU4iZYDzA5?purpose=fullsize)

The HTTP upload request contains information about the uploaded file.

Example:

```http
Content-Disposition: form-data; name="uploadFile"; filename="HTB.png"
Content-Type: image/png
```

A PHP application might validate it like this:

```php
$type = $_FILES['uploadFile']['type'];

if (!in_array($type, array(
    'image/jpg',
    'image/jpeg',
    'image/png',
    'image/gif'
))) {
    echo "Only images are allowed";
    die();
}
```

### Important

The application is trusting:

```text
$_FILES['uploadFile']['type']
```

which is based on the uploaded file's **Content-Type information**.

The browser normally supplies this automatically.

However:

> **HTTP request data can be modified before it reaches the server.**

In an authorized lab, a proxy such as Burp can be used to examine and modify the upload request.

---

# 3. Identifying a Content-Type Filter

Suppose you try:

```text
shell.php
```

and receive:

```text
Only images are allowed
```

You then try filename tricks such as:

```text
shell.jpg.php
shell.php.jpg
```

and they still fail.

This can indicate that the application isn't relying solely on the filename extension.

The next thing to investigate is whether the application checks:

```text
Content-Type
        ↓
MIME-Type / File Content
```

---

# 4. Testing Allowed Content-Types

SecLists contains a large list of Content-Types.

Instead of testing hundreds of values, you can narrow the list to image types:

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/web-all-content-types.txt

cat web-all-content-types.txt | grep 'image/' > image-content-types.txt
```

This reduces the list substantially.

### Why fuzz?

The objective is to determine:

```text
Which Content-Type values does the server accept?
```

In an authorized test environment, Burp Intruder can be used to test the values systematically.

---

# 5. Bypassing a Content-Type-Only Filter

If the server trusts the uploaded file's Content-Type, the filename and actual contents may not necessarily match what the server is told.

Conceptually:

```text
Filename:
shell.php

Actual content:
PHP code

Declared Content-Type:
image/jpeg
```

If the backend validates **only the declared Content-Type**, this mismatch may allow the upload.

### Key lesson

> **Never trust the client-supplied Content-Type as proof of what a file actually is.**

---

# ⚠️ Important: Two Content-Type Headers

A multipart upload can contain **two different levels of Content-Type information**.

### 1. Entire HTTP request

```http
Content-Type: multipart/form-data; boundary=...
```

### 2. Individual uploaded file

```http
Content-Type: image/png
```

When investigating upload validation, pay attention to **which Content-Type the application is actually validating**.

---

# 6. MIME-Type

![Image](https://images.openai.com/static-rsc-4/izjxtiGw3O1dYmUjAQ6OBwj-bR1QgjiKDR9_a_6DvI0zXDg5lgdedRnJkkj0ViLfGRyYJs5Q-DFJ511pwQaH_Lh2G0F_D0IPeMRl4J8AGdjSAJEHg6FKpe37Ayf49_3T_xExCcuaXi8lQg08PuUTvurpskwMP3AC4j7u_ex6EGCW8L12SjHpP8cjKy0NwkTW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pivydmeB2UzWphbuZlx8e96pu9M136iLQCN4P4mmidfK1wIABw5C1r-tFbcM8f_JmQpI8hHrep15adnjqT0vr6hJhwOGXPEe_I3getKdIeWq6YM-Kuq4Ducs9C6DKVVT1mwUWuvGwk6ZSIyQf_dJwyay0EWuXxIya21mWQbWqXM9udwnSbMyTxxjKy4PB4_x?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ilVZ8G_9J03HRba-7BvkMew5lNgKrt2SGLNH9HpkQeMjfYCJreijILhShV8cd6P2PRyalTs2BsSvGpds0fgZPC6loNPNo8Oi_w9Ixs_mAaM-FbWsse33v1BY-69kuTD938en2gacBlVSbbspysTVfV0MKlHxQRiC5jimPTfyO2aw_mDXCuDZyHcN6Wqwbty8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NwP1O-3fA947dUDCKRh7WBgj8-M2E5zIWSdsKRAeVlc6X9TXv1m0nr6Y3e9YU2NyVXcrvxsXjH15Ly_URzYm6ceQwjKAzjV9kfHC_SzAzPMAEuPy0yVGhHLqkv6hq3ISm-o88snjKfMT7GNEKt9pbbDKpRlBrltoULqsO6C-TC4EctBh7qNkIkcu6kiKfhJL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/z_zbTO9P732dgPduGfED32lQJnq8NuwIw-2efYy5Ml4eVFOCkfGxXsWcFD60wHuiLLn6Un5YKpwL1-xb68ypEr-AmWRnmgAt0M_qd3MfcLdZlraOhWwAvNxg4Qct6EWiPbBc3r2nVNJDlO70jGSYk6Xv7wcpiMc9NQIyJGPN489zxyma50MDH0s6yKaXDHAb?purpose=fullsize)

The second major technique is **MIME-Type detection**.

**MIME** stands for:

> **Multipurpose Internet Mail Extensions**

Unlike simply trusting a filename or HTTP header, MIME detection can inspect the **actual bytes/content of a file**.

A file generally contains a recognizable signature near its beginning.

These are commonly called:

- **File Signatures**
    
- **Magic Bytes**
    

---

# 7. Magic Bytes / File Signatures

Different file formats have characteristic starting bytes.

For example, GIF files commonly begin with:

```text
GIF87a
```

or:

```text
GIF89a
```

Therefore, software can inspect the beginning of a file and use those bytes to help determine its type.

### Example

Create a file named `.jpg`:

```bash
echo "this is a text file" > text.jpg
```

Then:

```bash
file text.jpg
```

The result can identify it as:

```text
ASCII text
```

Even though the filename ends in:

```text
.jpg
```

### Important conclusion

The filename does **not** necessarily determine the file's actual detected type.

---

# 8. Example: Changing the Detected Type

If the beginning of the file contains:

```text
GIF8
```

the `file` utility may identify it as GIF data.

For example:

```bash
echo "GIF8" > text.jpg
file text.jpg
```

The important concept isn't the `.jpg` extension.

It's the **content/signature being examined**.

---

# 9. MIME-Type Validation in PHP

A PHP application can use:

```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array(
    'image/jpg',
    'image/jpeg',
    'image/png',
    'image/gif'
))) {
    echo "Only images are allowed";
    die();
}
```

Notice the difference from the previous example.

### Content-Type validation

```php
$_FILES['uploadFile']['type']
```

### MIME detection

```php
mime_content_type($_FILES['uploadFile']['tmp_name'])
```

The second approach attempts to determine the type from the **file itself**.

---

# 10. Content-Type vs MIME-Type

|Property|Content-Type|MIME-Type|
|---|---|---|
|Source|HTTP request|File content|
|Controlled by|Client/request|Server-side detection|
|Based primarily on|Declared type|File bytes/signature|
|Example|`image/png`|Detected image type|
|Can client modify it?|Yes|Not directly|
|Stronger validation?|❌ Alone is weak|✅ Generally stronger|

### Remember this

```text
Filename
   ↓
shell.php

Content-Type
   ↓
image/jpeg

MIME/File Content
   ↓
What the actual bytes indicate
```

These are **three different things**.

---

# 11. Magic Bytes + Executable Content

The interesting security problem occurs when a server checks the beginning of a file to determine its type but later processes the rest of the file differently.

Conceptually:

```text
┌─────────────────────────────┐
│ GIF signature / magic bytes │
├─────────────────────────────┤
│ Remaining file content      │
│                             │
│ Potentially interpreted by  │
│ another component           │
└─────────────────────────────┘
```

This demonstrates an important security principle:

> **Different components may interpret the same uploaded file differently.**

A file may appear to one component as an image while another component processes it according to its filename or server configuration.

---

# 12. Combining Filters

A web application may perform multiple checks:

```text
             Uploaded File
                   │
        ┌──────────┼──────────┐
        ↓          ↓          ↓
    Extension  Content-Type  MIME
        │          │          │
        └──────────┼──────────┘
                   ↓
              Allow / Reject
```

Examples of combinations that may be investigated during authorized testing include:

- Allowed MIME + disallowed Content-Type
    
- Allowed MIME + disallowed extension
    
- Disallowed MIME + allowed extension
    
- Different combinations of filename, declared type, and actual content
    

The security depends on whether the backend **consistently validates all relevant properties**.

---

# 🧠 Type Filters — What You Actually Need to Remember

### ⭐ 1. Extension ≠ Content-Type ≠ MIME-Type

This is probably the **most important concept** in this section.

### ⭐ 2. Content-Type is client-controlled

A browser sends it, so an attacker can potentially modify it in an intercepted request.

### ⭐ 3. MIME-Type examines file content

It can use **magic bytes/file signatures** to determine what a file appears to be.

### ⭐ 4. Magic Bytes

Examples:

```text
GIF87a
GIF89a
```

These identify GIF file signatures.

### ⭐ 5. Don't trust only one property

Secure upload validation should not rely solely on:

```text
filename
```

or:

```text
Content-Type
```

### ⭐ 6. Different components can interpret files differently

A validation component might identify something as an image while another component may process it differently.

---

# 🔥 Progression of the Entire Module

This is the mental map I'd use for your revision:

```text
FILE UPLOAD ATTACKS
        │
        ├── 1. Absent Validation
        │       └── No restrictions
        │
        ├── 2. Client-Side Validation
        │       └── Browser-side controls
        │
        ├── 3. Blacklist
        │       └── Block known bad extensions
        │
        ├── 4. Whitelist
        │       └── Allow known good extensions
        │
        └── 5. Type Filters
                │
                ├── Content-Type
                │
                └── MIME-Type
                        └── Magic Bytes
```

