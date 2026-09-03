![Image](https://images.openai.com/static-rsc-4/Q8j-Q_mNknkgZTV1umv_-g9TmuJwtesvN6r3Bn2kEvbvkXEOqJu5TB4vU5kfdxxSQSzpjUrdFvhtRmdeSa8Yj02uKRRJnNxuwJydVZWK7sDC_CyNd-uFITzrcLHTlK7t3p9JZMIx2cEfHBngce-jMxlWok7xuZwREndWOC0x24AqQwG9PKD-hMCbyLjHtHsj?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_pGxQld2OeMxe3ebsPiHb9nYW87Dle0nuoxCyGEUxGlww882WMn8QZR-U5UcC9556Naj9_2UWkhRe_-1I6_o0uIQoeFJ304_8xowBOdb4UNYoZJEx9JnX1XK7Vl3NzqBdBXhtUwBab1MWWH5zQ7A-Ywy-m3HsJYPcCiQnripNiZZoAeQkL_sEr3YOPkDr5VC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yArP4fVgT1kErxIWFRFA18XqaxwMxPvtUdkpUeU26rJsMYCv9s7tj-Cyz0-xpjqh88_zbsTgxCBxDdejL4rjhXFQwYB4ePv6JHaAc0RSjV-ZlLL_tWNbNXJxnAZ4bWvy8BdjblMoJoL9UklnIJDCGvN1oEirXg0sDP0da6jBd6xVVCEzwVx8TgbpKnpfggNV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1muZbAJbOuQfA7D5jfvVzAg-DI_iCfjfpJCLtNp2pjP9IVD0WdZIxosUhVWRh1LlZr-EpnKIAHKPKVy2yMtnH_GcgrNKwWonrjmLn8Sp1ytsnxUAmLnqVC3orFOhvNpuoCbjAVEZCxUTjrKuJ-9uZCabeOFP9hlP8s_XdtncUsmKu2kn-NENTbWWtlNHEXr5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PqSuwt0TiFk_eQ2BqANLEhs5ejYUCpVUfTmydEEmuRN9Imch5ILsKvxIsTEk7BeV8Y0_y8XnwIVEgu77xReJqz5ib-oTweiRGRNzeN8z-vee8xKtEmnJkpjx36l033tKv9U1OqP_nPpt_xtYehWHFefKnKWNc1-Yc6O0Iz_QRy9dVU_mKAHhc1SDdA97KfZl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ouep4SeL617r1HN9WuAyXOgBHzM3NYxlBUKEYlnvFZpE34yvjMH5p7cdsqdIUSEBadxOY7B56UU-poQHc01hDxaEfLjaj5_V4phHlc7dZG-vFbGG3orE6RFW_Q48eAhREZZ608THX6rM3psTMZlep5sfmn2C5PRo6W3-Rcbpd9CM5S__OqzxMrzX1lwoeJn5?purpose=fullsize)

---

## 1. What Is WordPress?

WordPress was launched in **2003** and is an open-source **Content Management System (CMS)**.

It can be used for:

- Blogs
    
- Forums
    
- Company websites
    
- General-purpose websites
    

WordPress is:

- Highly customizable
    
- SEO friendly
    
- Extensible through plugins and themes
    

However, this extensibility also increases the attack surface because **third-party themes and plugins can introduce vulnerabilities**.

### Technology Stack

```text
WordPress
   │
   ├── PHP
   │
   ├── Apache (usually)
   │
   └── MySQL (backend)
```

---

# 📊 2. WordPress — Important Statistics

At the time of the source material:

- WordPress accounted for around **32.5% of all sites on the Internet**
    
- It was the **most popular CMS by market share**
    
- Over **50,000 plugins**
    
- Over **4,100 GPL-licensed themes**
    
- **317 separate versions** released since launch
    
- Roughly **661 new WordPress websites** built every day
    
- WordPress blogs written in **120+ languages**
    

The source also cites research indicating:

- Roughly **8%** of WordPress hacks were due to weak passwords
    
- Around **60%** were due to an **outdated WordPress version**
    

According to WPScan's cited figures:

```text
Known vulnerabilities
       │
       ├── 54% → Plugins
       ├── 31.5% → WordPress Core
       └── 14.5% → Themes
```

### ⭐ Key lesson

The enormous number of plugins and themes creates a **large attack surface**.

Therefore, during a penetration test, don't focus only on the WordPress core version.

You should investigate:

```text
Core
Themes
Plugins
Users
Configuration
Exposed files
Directories
Login mechanisms
XML-RPC
```

---

# 🎯 3. Why WordPress Matters to a Penetration Tester

WordPress is extremely common on the Internet.

Therefore, during an external penetration test, you are very likely to encounter it.

You should understand:

- How WordPress works
    
- How to identify WordPress
    
- How to fingerprint its version
    
- How to enumerate themes
    
- How to enumerate plugins
    
- How to enumerate users
    
- How to identify vulnerable components
    
- How to identify security misconfigurations
    

The important mindset is:

> **Don't immediately attack the first vulnerability you find. First build a complete picture of the WordPress installation.**

---

# 🔎 4. WordPress Discovery / Footprinting

There are multiple ways to identify a WordPress installation.

One of the fastest is:

```text
/robots.txt
```

Try:

```text
http://target/robots.txt
```

A typical WordPress `robots.txt` may contain:

```text
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```

---

# 🚩 5. WordPress Fingerprints in `robots.txt`

The following directories are strong indicators:

```text
/wp-admin/
/wp-content/
```

### `/wp-admin/`

This is the WordPress administrative interface.

Attempting to access it will typically redirect to:

```text
/wp-login.php
```

Example:

```text
http://blog.inlanefreight.local/wp-login.php
```

### `/wp-content/`

This is especially interesting because it contains:

```text
wp-content/
│
├── plugins/
│
├── themes/
└── uploads/
```

These directories can reveal valuable information about the installation.

---

# 🧩 6. WordPress Plugin Directory

Plugins are normally stored at:

```text
/wp-content/plugins/
```

Example:

```text
http://target/wp-content/plugins/
```

This directory is important because plugins frequently contain vulnerabilities.

During enumeration, determine:

```text
Plugin name
Plugin version
Directory
Readme
Changelog
Known vulnerabilities
```

The source specifically emphasizes carefully enumerating plugins because vulnerable plugins can potentially lead to **RCE**.

---

# 🎨 7. WordPress Theme Directory

Themes are stored at:

```text
/wp-content/themes/
```

Example:

```text
http://target/wp-content/themes/
```

Themes can also contain vulnerabilities.

Therefore:

```text
Theme
  ↓
Identify version
  ↓
Search known vulnerabilities
  ↓
Determine exploitability
```

The source specifically warns that theme files should be carefully enumerated because they may lead to **Remote Code Execution**.

---

# 👤 8. WordPress User Roles

A standard WordPress installation has **five types of users**.

|Role|Capabilities|
|---|---|
|**Administrator**|Full administrative access, including managing users/posts and editing source code|
|**Editor**|Publish/manage posts, including other users' posts|
|**Author**|Publish/manage their own posts|
|**Contributor**|Write/manage own posts but cannot publish them|
|**Subscriber**|Browse posts and edit their own profile|

---

# 🔥 9. Why User Roles Matter

Not every valid account has the same security impact.

### Administrator

An Administrator generally has sufficient access to potentially obtain **code execution on the server**.

### Editor / Author

These accounts may have access to functionality or plugins that normal users cannot access.

Therefore:

```text
Account
   ↓
Determine Role
   ↓
Determine Permissions
   ↓
Identify Accessible Functionality
   ↓
Look for Abuse Paths
```

---

# 🔍 10. Source-Code Enumeration

Another quick way to identify WordPress is by looking at the HTML source.

Using:

```bash
curl -s http://blog.inlanefreight.local | grep WordPress
```

The example returns:

```html
<meta name="generator" content="WordPress 5.8" />
```

This immediately tells us:

```text
Application → WordPress
Version     → 5.8
```

---

# ⭐ 11. What to Look for in Page Source

When manually reviewing WordPress pages, look for:

```text
wp-content
themes
plugins
generator
author names
version parameters
JavaScript
CSS
```

For example:

```text
/wp-content/themes/...
```

reveals the active theme.

And:

```text
/wp-content/plugins/...
```

reveals installed plugins.

Author names in posts may also expose **valid usernames**.

---

# 🎨 12. Theme Enumeration

The example uses:

```bash
curl -s http://blog.inlanefreight.local/ | grep themes
```

Output:

```html
<link rel='stylesheet' id='bootstrap-css'
href='http://blog.inlanefreight.local/wp-content/themes/business-gravity/assets/vendors/bootstrap/css/bootstrap.min.css'
...
/>
```

This reveals:

```text
Theme → Business Gravity
```

### Next step

Once you identify the theme:

1. Determine its version.
    
2. Research the version.
    
3. Look for known vulnerabilities.
    
4. Determine whether they are relevant to the target.
    

---

# 🧩 13. Plugin Enumeration

Run:

```bash
curl -s http://blog.inlanefreight.local/ | grep plugins
```

The example reveals:

```text
contact-form-7
mail-masta
```

with references such as:

```text
/wp-content/plugins/contact-form-7/
/wp-content/plugins/mail-masta/
```

### Important

Finding a plugin isn't enough.

You need:

```text
Plugin
   ↓
Version
   ↓
Known vulnerability?
   ↓
Authentication required?
   ↓
Relevant to target?
```

---

# 🚨 14. Directory Listing — `mail-masta`

Browsing to:

```text
http://blog.inlanefreight.local/wp-content/plugins/mail-masta/
```

reveals that **directory listing is enabled**.

A:

```text
readme.txt
```

file is also present.

The source notes that readme files are often useful for fingerprinting versions.

The discovered version:

```text
mail-masta → 1.0.0
```

was associated with a **Local File Inclusion (LFI)** vulnerability published in August 2021.

### ⭐ Important methodology

Whenever you find:

```text
Directory listing
```

look for:

```text
readme.txt
README
CHANGELOG
version files
configuration files
backup files
```

They may reveal application/version information.

---

# 💬 15. wpDiscuz

Looking at another WordPress page:

```bash
curl -s http://blog.inlanefreight.local/?p=1 | grep plugins
```

reveals:

```html
<link rel='stylesheet'
id='wpdiscuz-frontend-css-css'
href='http://blog.inlanefreight.local/wp-content/plugins/wpdiscuz/themes/default/style.css?ver=7.0.4'
... />
```

This gives us:

```text
Plugin → wpDiscuz
Version → 7.0.4
```

The source identifies this version as having an:

> **Unauthenticated Remote Code Execution vulnerability**

from June 2021.

---

# ⚠️ 16. Don't Exploit Immediately

This is one of the **most important lessons** in the entire section.

Once you discover:

```text
wpDiscuz 7.0.4
        ↓
Unauthenticated RCE
```

it can be tempting to immediately exploit it.

But **don't rush**.

You may still have:

- Vulnerable themes
    
- Other vulnerable plugins
    
- Weak credentials
    
- User enumeration
    
- Exposed files
    
- Directory listing
    
- XML-RPC
    
- Other application weaknesses
    

Therefore:

```text
Finding a vulnerability
        ≠
Immediately exploiting it
```

First complete enough enumeration to understand the attack surface.

---

# 👤 17. WordPress Username Enumeration

The default login page is:

```text
/wp-login.php
```

WordPress can reveal whether a username exists based on the error message.

### Valid username + invalid password

Example:

```text
The password for username admin is incorrect.
```

This tells us:

```text
admin = valid username
```

### Invalid username

Example:

```text
The username someone is not registered on this site.
```

This tells us:

```text
someone = invalid username
```

---

# 🚨 18. Why Username Enumeration Matters

If the application behaves differently for:

```text
Valid username
```

versus:

```text
Invalid username
```

an attacker can build a list of valid users.

Conceptually:

```text
Candidate usernames
        ↓
Send authentication request
        ↓
Compare responses
        ↓
Different response?
        ↓
Potentially valid username
```

This creates a useful foundation for further authorized authentication testing.

The source explicitly identifies WordPress as vulnerable to **username enumeration**.

---

# 📋 19. Manual Enumeration — Current Findings

At this stage, the source had identified:

|Item|Finding|
|---|---|
|WordPress Core|**5.8**|
|Theme|**Business Gravity**|
|Plugin|**Contact Form 7**|
|Plugin|**mail-masta**|
|Plugin|**wpDiscuz**|
|wpDiscuz|**7.0.4**|
|wpDiscuz issue|**Unauthenticated RCE**|
|mail-masta|**1.0.0**|
|mail-masta issue|**LFI**|
|User enumeration|**Enabled**|
|Valid user|**admin**|

This is a good example of how your notes should evolve during an assessment.

---

# 🛠️ 20. WPScan

![Image](https://images.openai.com/static-rsc-4/fIwq2WoXSeIDdjtfqif2MSVjvlUFqqDPhYkG5MdKbeEgWjRl9chHzpgeNoTGx-FXpdQxkopKYZZlsBGc6ytMGi9wSq1Xrc83ARocwdb-TnYXeGjTcjDIdCZcGS5-k-lEyAVoOZXd2JunlTuDlvieTN1-wHNOe7p2c88OqOKR4X07MMgAqzsRVqMYTtvvgREM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I5_w4wQxr_mBWv6QVSHgja7spokEdTVsiLXkUbieK0WUJWe6jA5Oj63NTbMykPYm-omyTvYezfOQBMihlIHFOyja5SUbDjm1o0aeEQTf0I3UA8ZHgMxUo5AQyVt_L3ylaTRTQxbJBY0zuIfnjwP-hUFJE3LXghdE6vW7tLsF6gbwgN62b66ZGgJU4K7JOWBP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VG9RTrpzP1s7KMYyoquWsm8W9j94UZAnZQ0_qspnsktBRTxRZen-rKuyTQbIo-gPVzzNFQaoJEiMPRmu97W0YXLQ8lAqJUULKolmDG9tX39qdwLlOqNX_p-a-Is0zErSX8_LMneno90w2h4yD5e-fAfSNjSmrxNkIguc5_--PSXrsBctoHeAfF3qw8ZLMiXp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5-2GetP5ewqSJUUTI1hRjqDuMOqebRIBv000ApiHxYuimaCtWKPR7eRgH16I6xV2XKs-c0VI5Cks66SkJ460nhLlsaVjDIaQSVQSaBr4HMFKu6fdWW4xxPRlB7qjVLsKj2o-wMAf9P6wquKxxg6EXoiYkAYEYHNZI4mO8mR2T7b2VhjEBxKFkVfGv0HuNmSF?purpose=fullsize)

WPScan is an automated WordPress security scanner and enumeration tool.

It can identify:

- WordPress versions
    
- Plugins
    
- Themes
    
- Users
    
- Vulnerabilities
    
- Other interesting WordPress information
    

It can also determine whether themes and plugins are outdated or vulnerable.

---

# 📦 21. Installing WPScan

On systems where it isn't already installed:

```bash
sudo gem install wpscan
```

---

# 🔑 22. WPVulnDB API Token

WPScan can retrieve vulnerability information from external sources.

The source uses **WPVulnDB**.

A token can be supplied with:

```text
--api-token
```

The source states that the free plan allowed up to:

```text
25 requests per day
```

at the time of the material.

### General syntax

```bash
wpscan --url <URL> --api-token <TOKEN>
```

---

# 📖 23. WPScan Help

Run:

```bash
wpscan -h
```

Important options include:

|Option|Meaning|
|---|---|
|`--url URL`|URL of the WordPress site|
|`-h`, `--help`|Display help|
|`--hh`|Full help|
|`--version`|Display WPScan version|
|`-v`, `--verbose`|Verbose mode|
|`-o FILE`|Output to file|
|`-f FORMAT`|Output format|
|`--detection-mode MODE`|Detection mode|

Detection modes:

```text
mixed
passive
aggressive
```

---

# ⭐ 24. `--enumerate`

The:

```text
--enumerate
```

flag is extremely important.

It can enumerate components such as:

- Plugins
    
- Themes
    
- Users
    

By default, WPScan enumerates vulnerable:

- Plugins
    
- Themes
    
- Users
    
- Media
    
- Backups
    

---

# 🧩 25. Enumerating Specific Components

For example, the source gives:

```bash
wpscan --url <URL> --enumerate ap
```

where:

```text
ap → all plugins
```

This is useful when you specifically want to focus on plugins rather than performing every type of enumeration.

---

# 🔥 26. WPScan Full Enumeration Example

The source uses:

```bash
sudo wpscan --url http://blog.inlanefreight.local \
--enumerate \
--api-token dEOFB<SNIP>
```

The results provide a much more complete picture.

---

# 🖥️ 27. WPScan — Server Information

WPScan identifies:

```text
Server: Apache/2.4.41 (Ubuntu)
```

This was detected through:

```text
Headers
Passive Detection
Confidence: 100%
```

So our technology stack now looks like:

```text
Internet
   ↓
Apache/2.4.41
   ↓
Ubuntu
   ↓
WordPress
   ↓
PHP
   ↓
MySQL
```

---

# 🔗 28. XML-RPC

WPScan also discovered:

```text
XML-RPC seems to be enabled
```

at:

```text
/xmlrpc.php
```

Example:

```text
http://blog.inlanefreight.local/xmlrpc.php
```

### Why is this important?

WordPress XML-RPC functionality can expose additional attack surface.

The source specifically notes that it can be leveraged for **password brute-forcing** against the login page using tools such as:

- WPScan
    
- Metasploit
    

---

# 📄 29. WordPress `readme.html`

WPScan also discovered:

```text
/readme.html
```

Example:

```text
http://blog.inlanefreight.local/readme.html
```

This is another potential source of application/version information.

### Enumeration mindset

Don't assume small files are useless.

Potentially useful files include:

```text
robots.txt
readme.html
readme.txt
changelog
license
sitemap
```

---

# 📂 30. Upload Directory Listing

WPScan found:

```text
Upload directory has listing enabled
```

at:

```text
/wp-content/uploads/
```

This can lead to:

> **Sensitive data exposure**

depending on what files have been uploaded.

Potentially interesting information can include:

```text
Images
Documents
Backups
Exports
Uploaded configuration files
Other user-generated content
```

---

# 🚨 31. WordPress Core Version

WPScan identified:

```text
WordPress version 5.8
```

The source marks it as:

```text
Insecure
Released: 2021-07-20
```

WPScan identified three vulnerabilities affecting this version range.

### CVE-2021-39200

**WordPress 5.4 to 5.8 — Data Exposure via REST API**

Fixed in:

```text
5.8.1
```

### CVE-2021-39201

**WordPress 5.4 to 5.8 — Authenticated XSS in Block Editor**

Fixed in:

```text
5.8.1
```

The third finding concerned the **Lodash library update** and was also fixed in **5.8.1**.

### ⭐ Important

Don't just write:

```text
WordPress 5.8 = vulnerable
```

Record:

```text
Version
↓
Vulnerability
↓
CVE
↓
Authentication requirement
↓
Fixed version
↓
Practical relevance
```

---

# 🎨 32. WPScan Theme Discovery

Interestingly, automated enumeration corrected something from the manual enumeration.

WPScan identified:

```text
Theme → Transport Gravity
Version → 1.0.1
```

The important detail is:

> **Transport Gravity is a child theme of Business Gravity.**

So manual enumeration had identified the parent theme, while WPScan identified the actual theme in use.

### ⭐ Lesson

Automated tools can:

- Confirm manual findings
    
- Correct manual findings
    
- Add new information
    
- Still miss things
    

Never assume either method is perfect.

---

# 🧩 33. WPScan Plugin Enumeration

WPScan identifies:

```text
mail-masta
```

at:

```text
/wp-content/plugins/mail-masta/
```

Version:

```text
1.0
```

It identified two vulnerabilities:

```text
Mail Masta <= 1.0
    ↓
Unauthenticated Local File Inclusion (LFI)

Mail Masta 1.0
    ↓
Multiple SQL Injection vulnerabilities
```

---

# 👤 34. WPScan User Enumeration

WPScan identified:

```text
admin
john
```

### `admin`

Discovered through:

```text
Author Posts - Display Name
RSS Generator
Author ID Brute Forcing
Login Error Messages
```

### `john`

Discovered through:

```text
Author ID Brute Forcing
Login Error Messages
```

Therefore:

```text
Valid users:
├── admin
└── john
```

---

# 🧠 35. Passive vs Aggressive Detection

WPScan uses different techniques.

### Passive Detection

Attempts to gather information without actively probing heavily.

Examples from the output:

```text
Headers
CSS Style
URLs in Homepage
RSS Generator
```

### Aggressive Detection

Performs more active interaction.

Examples:

```text
Direct Access
Author ID Brute Forcing
Login Error Messages
Readme
Changelog
```

### Mental model

```text
Passive
  ↓
Observe what the application already reveals

Aggressive
  ↓
Actively interact with the application
```

---

# 🧵 36. WPScan Threads

The default number of WPScan threads is:

```text
5
```

This can be changed using:

```text
-t
```

Example:

```bash
wpscan --url http://target -t 10
```

When conducting authorized testing, choose concurrency carefully because aggressive scanning can create unnecessary load or trigger defensive systems.

---

# 🆚 37. Manual Enumeration vs WPScan

This is one of the **best lessons from the module**.

|Finding|Manual|WPScan|
|---|--:|--:|
|WordPress 5.8|✅|✅|
|Directory listing|✅|✅|
|Business Gravity|✅|❌/refined|
|Transport Gravity|❌|✅|
|Contact Form 7|✅|❌|
|mail-masta|✅|✅|
|wpDiscuz|✅|❌|
|`admin`|✅|✅|
|`john`|❌|✅|
|XML-RPC|❌|✅|
|Known vulnerabilities|Manual research|✅|

The source explicitly demonstrates that **WPScan missed wpDiscuz and Contact Form 7**, while it found additional information that manual enumeration missed.

---

# ⭐ 38. The Most Important Lesson

The correct approach is:

```text
MANUAL
   +
AUTOMATED
   ↓
MORE COMPLETE ENUMERATION
```

Not:

```text
WPScan
   ↓
Trust everything
```

And not:

```text
Manual
   ↓
Never use scanners
```

Instead:

```text
Human observation
       +
Automated enumeration
       ↓
Cross-validation
       ↓
Complete attack surface
```

The source explicitly states:

> **Scanners are great and are very useful but cannot replace the human touch and a curious mind.**

---

# 🗂️ 39. Final Enumeration Results

After combining manual enumeration and WPScan, the source reaches the following conclusions:

### WordPress

```text
WordPress Core → 5.8
```

It has some vulnerabilities, although they aren't considered the most interesting findings at this point.

### Theme

```text
Transport Gravity
```

### Plugins

```text
Contact Form 7
mail-masta
wpDiscuz
```

### wpDiscuz

```text
Version → 7.0.4
Issue → Unauthenticated RCE
```

### mail-masta

```text
Version → 1.0.0
Issues → LFI + SQL Injection
```

### Valid users

```text
admin
john
```

### Directory listing

Enabled throughout the site.

Potential impact:

```text
Sensitive data exposure
```

### XML-RPC

Enabled.

Potentially useful for:

```text
Password brute-forcing
```

---

# 🗺️ 40. Complete WordPress Enumeration Workflow

![Image](https://images.openai.com/static-rsc-4/IbM02yfJFaki2Rm7LjO8AQWH8XUOrygKPkXOuD0uwjEQFev_BzCSDEvY7PyrsF2d1ik25wQNg1fRuiFfh1jpC7T20m14iKlDZr8ABuNcJty--JBIIdiJVB1XBDEALPn3Hb86KTjbyIlTNUw9BBMCNbWOm-h4rfS_nc9TgUklvoqRpUA1fTtiGw2ZV3TWO18L?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qguoa3Z5hEXRer3zeIS2DWrgRKT44BnY7VtCH8lWqh8erb0DjYO50ZXm713UvNKi3Y8hdWNNvzdc2vyVx1hnpE_xbR3XKC956Bmjwv3EFwHLrta_r9ypJhWlFcNSLEB6UvELVl0mORYAx0PX_7pFtNvEHqjncmRmUJ8BwAyNVWIDFtpDLX0n905sVQ8tjrwn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/stWQqy3YZydiYUBCXR9XsEq-K2L6J3_qBOI3aMuTEvkfcXczlAEJowtvn3fG7OjB2umR_byVyD2onkYM_xi3YtEGIhdNdnP90me8a6sZsSnao-pXM_l21Qdz-Gkbk_gwuWHIQdK01jYeOHNrYC-GFlxfziZy8pn5CeAP7Y3nDMA_jvT58zHmSHtFZpj_dNC3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zN4G3Ijn8F2Hpk8zDcJkzh0Yrv-5WBj3ZsRttxiFuSLkbrz9OPejFpHM3jRlLL_hZpApcUt__viMmZwWSAlFUA2v7lZ6xHcOtOlrsf8i5mNgbSaMHDytMz4kPKAOiXLu08G2LnVkWURuULKMpziXhRcVsM4xSo-vZQr1eGsewBXO85M1NoKiu31QVmRQU_pv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/m4BwCsxKeAxUWtqqrCEoEr-ANyRABvqVfML1udc5IoVgjfoL4twx3P4d4kDVgjlJlVXN6071DQWOiu0GXSw7plpc4-VWUuPbFUTgijxp4i61v_trsD_Vwc1KeDDEqfVQ-KVjnQ51mM5s41yK6_IvIjVBedG84rT8YXqK_iQgqII4JbSJpKdQ62FFmFHSX-Qb?purpose=fullsize)

```text
                 TARGET
                   │
                   ▼
             Identify WordPress
                   │
          ┌────────┼────────┐
          ▼        ▼        ▼
       robots    Source   wp-login
        .txt      Code     .php
          │        │        │
          └────────┼────────┘
                   ▼
            Fingerprint Core
                   │
                   ▼
        Enumerate Themes/Plugins
                   │
          ┌────────┼─────────┐
          ▼        ▼         ▼
        Themes   Plugins   Uploads
          │        │         │
          ▼        ▼         ▼
       Version  Version   Directory
          │        │       Listing
          │        │
          └────┬───┘
               ▼
       Search Vulnerabilities
               │
               ▼
        Enumerate Users
               │
               ▼
        Check XML-RPC
               │
               ▼
        Check Exposed Files
               │
               ▼
        Run WPScan
               │
               ▼
       Compare Manual Results
               │
               ▼
        Build Attack Surface
               │
               ▼
        Prioritize Findings
               │
               ▼
             ATTACK
```

---

# 🧠 41. CPTS Notes — What You Should Actually Remember

## 🔥 WordPress fingerprints

Memorize:

```text
/wp-admin/
/wp-login.php
/wp-content/
/wp-content/plugins/
/wp-content/themes/
/wp-content/uploads/
/robots.txt
/wp-sitemap.xml
/xmlrpc.php
/readme.html
```

---

## 🔥 WordPress stack

```text
WordPress
   ↓
PHP
   ↓
Apache (usually)
   ↓
MySQL
```

---

## 🔥 User roles

```text
Administrator
Editor
Author
Contributor
Subscriber
```

---

## 🔥 Important enumeration commands

### Identify WordPress/version

```bash
curl -s http://blog.inlanefreight.local | grep WordPress
```

### Identify themes

```bash
curl -s http://blog.inlanefreight.local/ | grep themes
```

### Identify plugins

```bash
curl -s http://blog.inlanefreight.local/ | grep plugins
```

### Install WPScan

```bash
sudo gem install wpscan
```

### WPScan help

```bash
wpscan -h
```

### WPScan enumeration

```bash
sudo wpscan --url http://blog.inlanefreight.local \
--enumerate \
--api-token <TOKEN>
```

### Enumerate all plugins

```bash
wpscan --url <URL> --enumerate ap
```

---

# 🚨 42. High-Value Findings Checklist

When enumerating a WordPress target, check:

```text
[ ] WordPress version
[ ] Theme
[ ] Theme version
[ ] Plugins
[ ] Plugin versions
[ ] Vulnerable plugins
[ ] Vulnerable themes
[ ] Usernames
[ ] User roles
[ ] /wp-login.php
[ ] Username enumeration
[ ] /xmlrpc.php
[ ] XML-RPC enabled?
[ ] /robots.txt
[ ] /readme.html
[ ] Directory listing
[ ] /wp-content/uploads/
[ ] Backup files
[ ] Exposed configuration
[ ] Known CVEs
[ ] Authentication requirements
[ ] Interesting functionality
```

---

# 🎯 43. The Core Mental Model

The biggest lesson from this section can be represented as:

```text
          WORDPRESS
              │
              ▼
          DISCOVERY
              │
      ┌───────┼────────┐
      ▼       ▼        ▼
    Files   Source   Login
      │       │        │
      └───────┼────────┘
              ▼
         ENUMERATION
              │
    ┌─────────┼──────────┐
    ▼         ▼          ▼
   Core     Plugins     Themes
    │         │          │
    └─────────┼──────────┘
              ▼
         Usernames
              │
              ▼
      Misconfigurations
              │
      ┌───────┼────────┐
      ▼       ▼        ▼
    LFI       SQLi     RCE
              │
              ▼
       Prioritize & Validate
              │
              ▼
           ATTACK
```

---

# 🏆 44. Final CPTS Takeaway

**Do not treat WPScan as the answer.**

The correct penetration-testing mindset is:

> **Manual enumeration + automated enumeration + validation = a much more complete attack surface.**

The module demonstrates this perfectly:

- Manual enumeration discovered **wpDiscuz**
    
- WPScan missed **wpDiscuz**
    
- WPScan discovered **john**
    
- WPScan identified **Transport Gravity**
    
- Manual enumeration had initially identified **Business Gravity**
    
- WPScan discovered **XML-RPC**
    
- WPScan provided known vulnerability information
    

Therefore, the strongest workflow is:

```text
DISCOVER
   ↓
MANUALLY ENUMERATE
   ↓
AUTOMATE WITH WPSCAN
   ↓
COMPARE RESULTS
   ↓
VALIDATE
   ↓
PRIORITIZE
   ↓
ATTACK
```

And the final principle to remember is exactly the one emphasized by the material:

> **Scanners are useful, but they cannot replace the human touch and a curious mind.**

This is the point where the notes transition from **“What is running?”** to **“How can the identified WordPress attack surface be tested?”**