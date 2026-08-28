This section moves from **LFI file disclosure** toward **Remote Code Execution (RCE)** by using PHP stream wrappers.

The main wrappers covered here are:

1. **`data://`**
    
2. **`php://input`**
    
3. **`expect://`**
    

The key idea is:

```text
LFI
 ↓
PHP Wrapper
 ↓
Execute PHP code / system commands
 ↓
Potential RCE
```

![Image](https://images.openai.com/static-rsc-4/zYcxaTldy38K1S_dmqnwZl4ffkRjabkm5yp4QiFAeiT5MDGrnSgN4baDGgh_hNgyCRTFlORaMfG7kgUzJFGnfJj6D_oZUCFDlZlPxo1RJ2EM1ViLEWm25i7mtWdzRIGeaOpx7HthfQmvPqoZQef6cxdLRcEJ1JxivzgaGvxQSeMA1gZRCtnXjJFnd0G_3qSr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FHAzkyyvaos_KvbbkyvzcJjVpgfGmEtvkPS9E0pNVpyBsUxPWtnBdtGzeYEMn1KoHuxaV82catO7R0wkWrG6FhqZ32_PDM7eWqt05vbIImW6EtLvVWnDDHoGa-JD4BiR0QyYjgt-7xthKhxBrBXbCsJ_oa26zXyW0ki-bjNcY90CnxN6aG0wgWO7LPPmTXT4?purpose=fullsize)

---

# 1. From LFI to RCE

So far, LFI has mainly been used to **read local files**.

For example:

```text
LFI
 ↓
/etc/passwd
 ↓
Read file
```

But PHP provides special **stream wrappers** that can change what happens when the vulnerable function processes our input.

This can potentially turn:

```text
File Inclusion
```

into:

```text
Remote Code Execution
```

The exact technique depends on:

- Backend language
    
- Framework
    
- Vulnerable function
    
- PHP configuration
    
- Available wrappers
    

---

# 2. Alternative Route: Credentials and SSH Keys

Before using wrappers, remember that LFI can sometimes provide an easier route to server access.

For example, source-code disclosure might reveal:

```text
config.php
     ↓
Database password
     ↓
Password reused by user
     ↓
SSH login
```

Another possibility is discovering improperly protected SSH private keys:

```text
/home/user/.ssh/id_rsa
```

If the private key is readable and usable, it may potentially provide SSH access.

So there are two broad approaches:

```text
                 LFI
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
  Data Enumeration       Wrappers
        │                   │
        ▼                   ▼
Credentials/keys           RCE
        │
        ▼
       SSH
```

> ⭐ **Important:** RCE through wrappers is not always necessary. Sometimes information obtained through LFI already provides a route to access.

---

# 3. PHP Wrappers Covered in This Section

|Wrapper|Main Purpose|Requirement|
|---|---|---|
|**`data://`**|Include data/PHP code|`allow_url_include`|
|**`php://input`**|Include POST input/PHP code|`allow_url_include` + POST-capable vulnerable parameter|
|**`expect://`**|Direct command execution|Expect extension installed/enabled|
|**`phar://`**|Covered later|Depends on application/file-upload conditions|
|**`zip://`**|Covered later|Depends on application/file-upload conditions|

The first three are the main wrappers for **direct command execution through LFI** in this section.

---

# ⭐ 4. `data://` Wrapper

The `data` wrapper can be used to include external data, including PHP code.

Basic concept:

```text
data://
   ↓
Data supplied through URL
   ↓
PHP includes the data
```

However, there is an important requirement.

### Required PHP configuration

```text
allow_url_include
```

must be enabled.

---

# 5. `allow_url_include`

This setting determines whether PHP allows URL-style resources to be included.

For the techniques in this section, we need:

```ini
allow_url_include = On
```

The material emphasizes that this option is **not enabled by default**.

Therefore, before attempting some wrapper-based attacks, we need to determine whether it is enabled.

---

# 6. Checking PHP Configuration

The PHP configuration file depends on the web server.

### Apache

The material gives the general location:

```text
/etc/php/X.Y/apache2/php.ini
```

### Nginx / PHP-FPM

The material gives:

```text
/etc/php/X.Y/fpm/php.ini
```

where:

```text
X.Y
```

represents the PHP version.

For example:

```text
/etc/php/7.4/apache2/php.ini
```

---

# 7. Why Use the Base64 Filter Again?

We learned about:

```text
php://filter/read=convert.base64-encode/resource=...
```

in the previous section.

The same technique is useful here because `php.ini` is a configuration file.

Instead of directly including it, we can:

```text
php.ini
   ↓
Base64 encode
   ↓
Return encoded content
   ↓
Decode locally
```

This avoids having the contents interpreted in an undesirable way and makes it easier to capture the entire configuration.

---

# 8. Why Use cURL or Burp?

The configuration file can be very large.

The material recommends using:

- **cURL**
    
- **Burp Suite**
    

instead of relying only on a normal browser.

Why?

Because the Base64-encoded response may be:

```text
VERY LONG
```

Using cURL/Burp makes it easier to:

- Capture the complete response
    
- Copy the Base64 data
    
- Decode it
    
- Search it
    

---

# 9. Finding `allow_url_include`

After retrieving the Base64-encoded `php.ini`, decode it and search for:

```text
allow_url_include
```

The material demonstrates:

```bash
echo 'BASE64_DATA' | base64 -d | grep allow_url_include
```

If the result is:

```text
allow_url_include = On
```

then the required configuration is enabled.

---

# ⭐ 10. Why This Check Is Important

Remember:

```text
allow_url_include = On
```

is **not enabled by default**.

But it can still be encountered in real applications.

The material mentions that some applications, including certain WordPress plugins/themes, may rely on this functionality.

This setting is important not only for:

```text
data://
```

but also for:

```text
php://input
```

and certain **RFI** scenarios.

---

# 11. `data://` → Remote Code Execution

Once:

```text
allow_url_include = On
```

has been confirmed, the `data://` wrapper can potentially be used to include PHP code.

The material's basic approach is:

```text
PHP code
   ↓
Base64 encode
   ↓
data://text/plain;base64,...
   ↓
LFI includes it
   ↓
PHP executes it
```

---

# 12. Creating the PHP Web Shell

The material uses a simple PHP web shell:

```php
<?php system($_GET["cmd"]); ?>
```

Its logic is:

```text
GET parameter: cmd
       ↓
system()
       ↓
Operating-system command
```

For example:

```text
?cmd=id
```

causes the shell to execute the `id` command.

> ⚠️ This is appropriate in the context of an authorized HTB/lab environment. Do not deploy a command-executing web shell on systems you do not own or have explicit permission to test.

---

# 13. Base64-Encoding the PHP Code

The source demonstrates encoding the PHP code:

```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
```

The resulting Base64 data represents the PHP code.

Conceptually:

```text
<?php system($_GET["cmd"]); ?>
             │
             ▼
        Base64 encode
             │
             ▼
PD9waHAg...
```

---

# 14. `data://text/plain;base64,`

The Base64 data is then placed after:

```text
data://text/plain;base64,
```

The structure is:

```text
data://
   │
   └── text/plain
          │
          └── ;base64,
                 │
                 └── encoded PHP
```

So the overall concept is:

```text
data://text/plain;base64,<ENCODED_PHP>
```

---

# 15. URL Encoding

The material then URL-encodes the Base64 string before placing it into the vulnerable parameter.

This is important because Base64 can contain characters that have special meanings in URLs.

Conceptually:

```text
PHP code
   ↓
Base64
   ↓
URL encode
   ↓
Place in URL
```

---

# 16. Executing a Command

Once the PHP code is included, the command can be supplied through:

```text
cmd
```

Conceptually:

```text
LFI parameter
      ↓
data://
      ↓
PHP web shell
      ↓
$_GET["cmd"]
      ↓
system()
      ↓
OS command
```

The material demonstrates this with:

```text
cmd=id
```

and obtains output identifying the web-server account:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

# ⭐ 17. Understanding the `www-data` Result

The command output tells us **which operating-system account is running the web application**.

In the example:

```text
uid=33(www-data)
gid=33(www-data)
```

So the PHP process is operating as:

```text
www-data
```

This is useful for understanding the permissions available to the executed process.

---

# 18. Using cURL

The same attack can be performed using cURL.

The source demonstrates piping the response into:

```bash
grep uid
```

This is simply a convenient way to extract the relevant command output from the HTML response.

The workflow is:

```text
Request
 ↓
LFI
 ↓
data:// wrapper
 ↓
PHP shell
 ↓
cmd=id
 ↓
HTML response
 ↓
grep uid
```

---

# 🔥 19. `php://input` Wrapper

The next wrapper is:

```text
php://input
```

It can also be used to provide PHP code to the vulnerable inclusion mechanism.

The major difference from `data://` is **where the PHP code comes from**.

### `data://`

Code is supplied inside the URL.

### `php://input`

Code is supplied through the **HTTP POST body**.

---

# 20. `data://` vs `php://input`

|Feature|`data://`|`php://input`|
|---|---|---|
|PHP code location|URL|POST body|
|Requires POST?|No|Yes|
|Requires `allow_url_include`|Yes|Yes|
|Can execute supplied PHP|Yes|Yes|
|Useful when URL becomes too large|Less convenient|More convenient|

The key distinction:

```text
data://
URL → PHP code

php://input
POST body → PHP code
```

---

# 21. Requirement for `php://input`

The vulnerable parameter/function must be capable of accepting **POST requests**.

The basic flow is:

```text
POST request
      │
      ▼
POST body contains PHP
      │
      ▼
php://input
      │
      ▼
PHP interprets included code
```

---

# 22. Example Concept

The source uses:

```text
POST body:
<?php system($_GET["cmd"]); ?>
```

while the vulnerable parameter points to:

```text
php://input
```

Then:

```text
GET:
?cmd=id
```

provides the command.

So two parts are being used:

```text
POST body
    ↓
PHP web shell

GET parameter
    ↓
Command
```

---

# ⭐ 23. Why GET Is Still Important

The material makes an important point.

If the web shell contains:

```php
$_GET["cmd"]
```

then the vulnerable function/application must also allow the GET parameter to reach the PHP code.

The source specifically mentions a situation where the application uses something like:

```php
$_REQUEST
```

which can accept data from multiple request methods.

---

# 24. If Only POST Is Accepted

If the application only accepts POST data and doesn't allow the command to be passed through GET, a dynamic web shell may not work in the same way.

Instead, the command can be directly embedded in the PHP code.

Conceptually:

```php
<?php system('id'); ?>
```

Then:

```text
POST body
    ↓
PHP code
    ↓
id executes
```

The key lesson:

> **The request method accepted by the vulnerable functionality determines how you can supply the PHP code and command.**

---

# 🔥 25. `expect://` Wrapper

The third wrapper is:

```text
expect://
```

Unlike `data://` and `php://input`, `expect://` is specifically designed for **command execution**.

Conceptually:

```text
expect://COMMAND
       ↓
Execute command
```

Therefore, you don't necessarily need to create a PHP web shell first.

---

# 26. Why `expect://` Is Different

Compare the three:

```text
data://
   ↓
PHP code
   ↓
system()
   ↓
command
```

```text
php://input
   ↓
POST PHP code
   ↓
system()
   ↓
command
```

```text
expect://
   ↓
command directly
```

So `expect://` is much more directly focused on command execution.

---

# 27. Expect Is an External Wrapper

There is an important limitation.

Unlike some standard PHP functionality, `expect` is an **external extension**.

It needs to be:

```text
Installed
+
Enabled
```

on the target server.

Therefore:

```text
expect://
```

will not necessarily work just because the server uses PHP.

---

# 28. Checking for the Expect Extension

The material shows searching the PHP configuration for:

```text
expect
```

For example:

```bash
echo 'BASE64_DATA' | base64 -d | grep expect
```

A configuration entry such as:

```text
extension=expect
```

indicates that PHP is configured to **attempt to load** the extension.

---

# ⚠️ 29. Configuration ≠ Functionality

This is a very important point from the source.

Seeing:

```text
extension=expect
```

does **not guarantee** that the extension is actually functional.

It could fail to load for many reasons.

Therefore:

```text
Configuration says enabled
        ≠
Extension definitely works
```

The material says the actual functionality needs to be confirmed by testing the wrapper itself.

---

# 30. Testing `expect://`

The material demonstrates using:

```text
expect://id
```

through the vulnerable LFI parameter.

If it works, the response contains:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirms that the Expect wrapper is actually functioning and that command execution is occurring.

---

# ⭐ 31. Expect Workflow

```text
LFI
 │
 ▼
expect://
 │
 ▼
Command
 │
 ▼
PHP Expect extension
 │
 ▼
Operating system
 │
 ▼
Command output
```

Unlike the `data://` approach, there is no need to first create a PHP web shell.

---

# 32. Three Main Direct-Execution Wrappers

This section's core comparison:

```text
                    LFI
                     │
          ┌──────────┼──────────┐
          │          │          │
          ▼          ▼          ▼
       data://   php://input  expect://
          │          │          │
          ▼          ▼          ▼
      PHP code    POST PHP     Command
          │          │          │
          ▼          ▼          │
       system()   system()      │
          │          │          │
          └──────────┼──────────┘
                     ▼
                OS command
```

---

# 🧠 33. Requirements Cheat Sheet

|Wrapper|What you need|
|---|---|
|`data://`|`allow_url_include=On`|
|`php://input`|`allow_url_include=On` + POST-capable vulnerable function|
|`expect://`|Expect extension installed and functioning|

---

# ⭐ 34. Troubleshooting Logic

If `data://` isn't working:

```text
Check:
allow_url_include
        ↓
Is it On?
        ↓
If No → data wrapper won't work
```

If `php://input` isn't working:

```text
Check:
allow_url_include
        +
Does vulnerable parameter accept POST?
```

If `expect://` isn't working:

```text
Check:
Is Expect installed?
        ↓
Is extension enabled?
        ↓
Does it actually load successfully?
```

---

# 35. Configuration Discovery Workflow

The source establishes a useful general methodology:

```text
LFI
 ↓
Read php.ini
 ↓
Base64 filter
 ↓
Decode
 ↓
grep relevant configuration
 ↓
Determine available functionality
 ↓
Choose wrapper
```

For example:

```text
php.ini
  │
  ├── allow_url_include = On
  │       ↓
  │    data://
  │    php://input
  │
  └── extension=expect
          ↓
       Test expect://
```

---

# 🔥 36. Important Difference: Check vs Test

Don't confuse configuration discovery with actual functionality.

### For `allow_url_include`

Configuration value:

```text
allow_url_include = On
```

is strong evidence that the relevant functionality is enabled.

### For Expect

Configuration:

```text
extension=expect
```

only means PHP is configured to attempt loading it.

You still need to determine whether it actually works.

---

# 37. `data://` Key Structure

Memorize:

```text
data://text/plain;base64,<BASE64_DATA>
```

Breakdown:

```text
data://
   ↓
MIME type
   ↓
text/plain
   ↓
Base64 indicator
   ↓
base64,
   ↓
Encoded content
```

---

# 38. `php://input` Key Structure

Memorize:

```text
php://input
```

The important difference is:

```text
data://
→ code is inside the URL

php://input
→ code is inside POST body
```

---

# 39. `expect://` Key Structure

Memorize:

```text
expect://COMMAND
```

It is intended for direct command execution through the Expect extension.

---

# 🎯 40. The Complete Attack Progression

This entire section can be visualized as:

```text
                    LFI
                     │
                     ▼
             Identify PHP backend
                     │
                     ▼
              Read php.ini
                     │
                     ▼
       Check PHP configuration
                     │
          ┌──────────┴───────────┐
          │                      │
          ▼                      ▼
allow_url_include            expect
     enabled?                available?
          │                      │
          ▼                      ▼
   ┌──────┴──────┐             Test
   │             │           expect://
   ▼             ▼                │
data://     php://input          ▼
   │             │             RCE
   ▼             ▼
 PHP code     POST PHP
   │             │
   └──────┬──────┘
          ▼
      system()
          │
          ▼
     OS command
          │
          ▼
         RCE
```

---

# ⭐ 41. Key Concepts to Memorize

### `data://`

> Include supplied data, including PHP code, when the required configuration permits it.

### `php://input`

> Use POST request data as the included input.

### `expect://`

> Execute commands directly through the Expect extension.

### `allow_url_include`

> Critical configuration setting for the `data://` and `php://input` techniques described here.

### `extension=expect`

> Indicates PHP is configured to load the Expect extension, but does **not** by itself guarantee that the extension successfully works.

---

# 📝 42. Interview / Exam Questions

### Q1. What is the main purpose of PHP wrappers in this section?

To extend LFI exploitation, potentially allowing PHP code execution and ultimately RCE.

### Q2. What configuration is required for `data://`?

```text
allow_url_include = On
```

### Q3. Is `allow_url_include` enabled by default?

**No.**

### Q4. What does `resource` mean in `php://filter`?

It identifies the stream/file that the filter operates on.

### Q5. Why use Base64 when reading `php.ini`?

To encode its contents so they can be safely captured and decoded without simply treating the configuration contents as normal included output.

### Q6. What is the difference between `data://` and `php://input`?

`data://` receives the supplied data through the URL, while `php://input` reads the HTTP request's POST body.

### Q7. What additional requirement does `php://input` have?

The vulnerable functionality must accept/process POST requests.

### Q8. What does `expect://` do?

It allows commands to be executed directly through the Expect wrapper.

### Q9. Does `extension=expect` guarantee Expect works?

**No.** The extension could fail to load.

### Q10. How do you confirm Expect functionality?

By actually testing the `expect://` wrapper and observing whether command execution succeeds.

---

# 🔴 43. Things You Should NOT Mix Up

### ❌ `data://` ≠ `php://input`

```text
data://
→ URL data

php://input
→ POST body
```

### ❌ `expect` configuration ≠ working Expect

```text
extension=expect
        ≠
expect:// definitely functional
```

### ❌ LFI ≠ automatically RCE

LFI provides file inclusion capabilities.

RCE depends on:

- Backend behavior
    
- Vulnerable function
    
- PHP configuration
    
- Available wrappers
    
- Server environment
    

---

# 🔥 44. FINAL CHEAT SHEET

```text
╔══════════════════════════════════════════════════════════════╗
║                    PHP WRAPPERS                             ║
╠══════════════════════════════════════════════════════════════╣
║ GOAL                                                        ║
║                                                            ║
║ LFI → PHP Wrapper → Code Execution → RCE                   ║
╠══════════════════════════════════════════════════════════════╣
║ 1. DATA://                                                  ║
║                                                            ║
║ Purpose: Include supplied data/PHP code                    ║
║                                                            ║
║ Requirement:                                               ║
║ allow_url_include = On                                    ║
║                                                            ║
║ Structure:                                                  ║
║ data://text/plain;base64,<DATA>                            ║
╠══════════════════════════════════════════════════════════════╣
║ 2. PHP://INPUT                                              ║
║                                                            ║
║ Purpose: Include POST request body                          ║
║                                                            ║
║ Requirements:                                              ║
║ • allow_url_include = On                                   ║
║ • Vulnerable function accepts POST                         ║
║                                                            ║
║ Code → POST body                                           ║
║ Command → GET parameter (if supported)                     ║
╠══════════════════════════════════════════════════════════════╣
║ 3. EXPECT://                                                ║
║                                                            ║
║ Purpose: Direct command execution                           ║
║                                                            ║
║ Requirement:                                               ║
║ Expect extension installed + functional                   ║
║                                                            ║
║ Structure:                                                  ║
║ expect://COMMAND                                           ║
╠══════════════════════════════════════════════════════════════╣
║ CONFIGURATION                                               ║
║                                                            ║
║ php.ini → Base64 filter → decode → grep                    ║
║                                                            ║
║ Check: allow_url_include                                   ║
║ Check: extension=expect                                    ║
╠══════════════════════════════════════════════════════════════╣
║ IMPORTANT                                                   ║
║                                                            ║
║ extension=expect ≠ guaranteed functionality                ║
║                                                            ║
║ Actually test expect://                                    ║
╠══════════════════════════════════════════════════════════════╣
║ ALTERNATIVE LFI ROUTE                                      ║
║                                                            ║
║ LFI → config.php → credentials → SSH                       ║
║                                                            ║
║ LFI → .ssh/id_rsa → SSH access                             ║
╠══════════════════════════════════════════════════════════════╣
║ UPCOMING                                                   ║
║                                                            ║
║ phar:// and zip://                                         ║
║                                                            ║
║ Particularly relevant to file-upload + LFI scenarios       ║
╚══════════════════════════════════════════════════════════════╝
```

## 🧠 The 7 things to remember

```text
1️⃣ LFI can sometimes be extended into RCE using PHP wrappers.

2️⃣ data:// can include supplied PHP code.

3️⃣ data:// requires allow_url_include to be enabled.

4️⃣ php://input gets its PHP code from the POST body.

5️⃣ php://input also depends on allow_url_include.

6️⃣ expect:// can execute commands directly, but requires
   a functioning Expect extension.

7️⃣ php.ini → configuration discovery is the key first step.
```

### 🔥 Master flow

> **LFI → read `php.ini` → check `allow_url_include` / Expect → select the appropriate wrapper → execute PHP/commands → verify the resulting execution context.**