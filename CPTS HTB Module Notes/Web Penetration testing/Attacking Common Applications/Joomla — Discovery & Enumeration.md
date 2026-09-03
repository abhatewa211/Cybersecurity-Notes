![Image](https://images.openai.com/static-rsc-4/nrzBU8oYgeIEVkq6p9uXU8JoVMw8L978sUq2CosZTNgZj5zniLPqjd-FsQ_yV9ehHvb0TJgOND2odf9rWG4htBZR3Tml5TFsWa3S6u_eBhYhZpvxaJigp4I4H6Ax0ToE9hp3-cpJ3Nr9HniNeBwROGuITE1dxy3F9lxMSs9tU_fADyfu9cQIXd9gjsyULm9L?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/E6iZuwmNd-jEMylqraWa6S5pfNxImHC2eaHRqRcpp8hqQwAGHO1uJUSFqFsPmgj_wWfkaUZJHPlCgwv1ZmqhqiPUuahkBLDViJlctdKPfLZzlcqjdvqfsYX5Nfxj10i_cAS0w3x2A9YqcaZS65dRiEXkN6ihazm_vaut-FG6BrmwYm2fiTDB_cmdH7DhPQg6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pIkCyC3lZp14vHjNm5dyYSRNwIo2AoxOaFoNKiH1DO5a4IPfYe5dHlJsaWgz_pWhSuDpU5SkkLwbtlCP8LbJFsuLrR_VwovPg__t847lTxX86AnbVGB2fT3588F2vopVbv7EWz5bDfinB7mrhQhF6PHZcbV1yIQorQTzIu9m1vNYgPtpjaElfy2pARkGBJJV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7pHJCGl3NHh7IVYkwERFxS_2scH4ZIoiEi4HZhOZspiQTK0AHaLicir_yWP4Z_u7YhHF6t4Oe8Pel-UoTMAnAU9EzNFLUskXz3lRFe-zep0kupM26h-pSkJAUXTQRQlbooihEvBVg9IAm1tuHybk00SONkYC_1M63ZdOnspbVvD4WlTGsjhQtO7cbBrzsy2Q?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/j53zOyHst6pga4UFvAy5y-EAbImSHBGnXmvAa7Cu9iiSgw4QbkbgrIQjDspQHrvJFOo8aff-Y1bL8Te6Zwoy6axQRgoREjrWolaZOhymZ8XTiaIrnRwvhqhPf-9sMoGM6PfZS26EHOSOnK0Up9P1eGvik46T7hp6FSkesmcQcx2K-C8D2fWnzobaBCyMulSB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JY8F_sNgNuUa0v_t4VoSzB4oWLaa9fiklTdZnO9wxFVa1yidrLkzvBRry-0sCGuJl2RldFv9jEEVXZ9pg3gYwk29TEgnP6bQrKFhf7gsA8YxeVjH56poULV-qqLcjoyOC45BhkXuZjH_pD4pOBZyDae4gg5RhW3GCIj6IDRABNZj8X7HabBnwwP347ot1Wxd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6bmhbEjs8AfrFajzWG_p8QSOof-Vw4297gf4YFpUYfZsySGP55ZxP9O7D6xmREVR51ZTTwFE_qpBx_4Kvez-riGG6AH6W0zakCIctQXVnAribAozi4JQSrVkWh3AdOwCpK861Ve8zNh86UTfkG6L_I0Q9ZeFBOfPNihEIyQcHjhvTXWP5mcL4zs2UNA-RH4r?purpose=fullsize)

> **CPTS-style detailed notes:** I’ve preserved the important terminology, commands, URLs, version numbers, tool names, outputs, and attack methodology from the provided material. The statistics and tool capabilities below are **as stated in the source material**.

---

# 1. What Is Joomla?

Joomla is a **free and open-source Content Management System (CMS)** released in **August 2005**.

It can be used for:

- Discussion forums
    
- Photo galleries
    
- E-Commerce
    
- User-based communities
    
- General-purpose websites
    

Joomla is:

```text
Language → PHP
Database → MySQL
```

Like WordPress, Joomla can be extended using:

```text
7,000+ extensions
1,000+ templates
```

The source states that there can be up to **2.5 million Joomla sites on the Internet**.

---

# 2. Joomla — Important Statistics

According to the material:

|Statistic|Value|
|---|--:|
|CMS market share|**3.5%**|
|Websites powered by Joomla|**3% of all websites**|
|Top 1 million sites|Nearly **25,000**|
|Online forum community|~**700,000 users**|
|Developers who contributed|**770**|
|Extensions|**7,000+**|
|Templates|**1,000+**|

The source also mentions notable organizations using Joomla, including:

- eBay
    
- Yamaha
    
- Harvard University
    
- UK government
    

### ⭐ Remember

Joomla has a significant enough deployment footprint that **fingerprinting it should be part of normal web application enumeration**.

---

# 3. Joomla Usage Statistics API

Joomla collects anonymous usage statistics.

The collected information includes:

```text
Joomla versions
PHP versions
Database versions
Server operating systems
```

This information can be queried through Joomla's public API.

The source demonstrates querying:

```bash
curl -s https://developer.joomla.org/stats/cms_version | python3 -m json.tool
```

The returned data includes version distribution and:

```json
"total": 2776276
```

meaning the source's API query reported:

```text
2,776,276 Joomla installs
```

### ⚠️ Important distinction

This is **Joomla's public usage-statistics data**, not a technique for discovering the version of an individual target.

For a target, we need to perform **discovery/fingerprinting**.

---

# 🔎 4. Discovery / Footprinting

Imagine encountering an e-commerce website during an external penetration test.

At first:

```text
Unknown web application
        ↓
Doesn't appear fully custom
        ↓
Suspect Joomla
        ↓
Need to confirm
        ↓
Identify version
        ↓
Enumerate extensions/templates
```

The source specifically says that identifying the technology can help uncover:

- Vulnerabilities
    
- Misconfigurations
    
- Version-specific weaknesses
    
- Installed themes/plugins/extensions
    

---

# 🕵️ 5. Fingerprinting Joomla Through Page Source

One of the easiest techniques is inspecting the page source.

The source uses:

```bash
curl -s http://dev.inlanefreight.local/ | grep Joomla
```

The response contains:

```html
<meta name="generator" content="Joomla! - Open Source Content Management" />
```

### What does this tell us?

```text
Target
  ↓
HTML Source
  ↓
<meta name="generator">
  ↓
Joomla
```

This confirms that the application is running Joomla.

---

# ⭐ 6. First Joomla Fingerprint to Memorize

Look for:

```html
<meta name="generator" content="Joomla! - Open Source Content Management" />
```

Command:

```bash
curl -s http://target/ | grep Joomla
```

This is a **quick passive fingerprinting technique**.

---

# 🤖 7. `robots.txt`

Another extremely useful file is:

```text
/robots.txt
```

A Joomla `robots.txt` often contains references to Joomla-specific directories.

The source provides:

```text
User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

---

# 🚩 8. Interesting Joomla Directories

From `robots.txt`, several directories immediately stand out:

```text
/administrator/
/components/
/plugins/
/modules/
/libraries/
/installation/
/logs/
/tmp/
/cache/
```

### Most important:

```text
/administrator/
```

This is the Joomla administrative portal.

The presence of:

```text
/administrator/
```

is a strong Joomla fingerprint.

---

# 📂 9. What `robots.txt` Can Reveal

Even though `robots.txt` is intended to control search-engine crawling, it can inadvertently disclose interesting application paths.

Conceptually:

```text
robots.txt
    │
    ├── /administrator/
    ├── /components/
    ├── /plugins/
    ├── /modules/
    ├── /libraries/
    └── /installation/
             │
             ▼
       Application Structure
```

### ⭐ Pentesting lesson

**Do not treat `robots.txt` as a security control.**

If something appears in `robots.txt`, it does not mean the resource is actually protected.

---

# 🎨 10. Joomla Favicon

The source also notes that Joomla installations may have a **telltale Joomla favicon**.

However:

> **This is not always present.**

Therefore, favicon identification should be treated as an additional fingerprint rather than your only identification method.

---

# 📖 11. `README.txt`

Another useful file is:

```text
/README.txt
```

The source uses:

```bash
curl -s http://dev.inlanefreight.local/README.txt | head -n 5
```

The response contains:

```text
1- What is this?
    * This is a Joomla! installation/upgrade package to version 3.x
    * Joomla! Official site: https://www.joomla.org
    * Joomla! 3.9 version history - https://docs.joomla.org/Special:MyLanguage/Joomla_3.9_version_history
    * Detailed changes in the Changelog: https://github.com/joomla/joomla-cms/commits/staging
```

### Why is this useful?

It can reveal:

```text
Joomla major version
Version history
Changelog
Application identity
```

---

# 🔥 12. Joomla Version Fingerprinting

There are several ways to identify the Joomla version.

### Method 1

Page source:

```text
<meta name="generator" ...>
```

Primarily identifies Joomla.

### Method 2

```text
README.txt
```

Can reveal major-version information.

### Method 3

```text
administrator/manifests/files/joomla.xml
```

Can reveal the exact version.

### Method 4

```text
plugins/system/cache/cache.xml
```

Can provide an approximate version.

### Method 5

JavaScript files under:

```text
media/system/js/
```

may also help fingerprint the version.

---

# 🎯 13. `joomla.xml` — Exact Version

One of the most valuable files is:

```text
/administrator/manifests/files/joomla.xml
```

The source uses:

```bash
curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
```

The XML contains:

```xml
<extension version="3.6" type="file" method="upgrade">
```

and:

```xml
<version>3.9.4</version>
```

Therefore:

```text
Joomla Version
      ↓
3.9.4
```

### ⭐ CPTS takeaway

If an application exposes a manifest containing an exact version, **record it immediately**.

Then:

```text
Version
   ↓
Search vulnerability database
   ↓
Identify affected versions
   ↓
Determine exploitability
```

---

# 📦 14. `cache.xml`

The source also identifies:

```text
plugins/system/cache/cache.xml
```

as another potential source of version information.

It can help provide an **approximate Joomla version**.

---

# 🧰 15. Enumeration With Droopescan

The first automated enumeration tool introduced is:

```text
droopescan
```

It is a **plugin-based scanner** supporting:

- SilverStripe
    
- WordPress
    
- Drupal
    
- Limited Joomla functionality
    
- Limited Moodle functionality
    

---

# 📥 16. Installing Droopescan

Install using:

```bash
sudo pip3 install droopescan
```

After installation, verify it:

```bash
droopescan -h
```

---

# 🧠 17. Droopescan Commands

The help output shows two important commands:

```text
scan
stats
```

### `scan`

Used for:

```text
CMS scanning functionality
```

### `stats`

Shows:

```text
Scanner status & capabilities
```

---

# 📋 18. Droopescan Help

Basic syntax:

```text
droopescan (sub-commands ...) [options ...] {arguments ...}
```

Example:

```bash
droopescan scan drupal -u URL_HERE
```

and:

```bash
droopescan scan silverstripe -u URL_HERE
```

For more detailed scan options:

```bash
droopescan scan --help
```

---

# 🔍 19. Running Droopescan Against Joomla

The source uses:

```bash
droopescan scan joomla --url http://dev.inlanefreight.local/
```

The scanner returns several possible versions:

```text
3.8.10
3.8.11
3.8.11-rc
3.8.12
3.8.12-rc
3.8.13
3.8.7
3.8.7-rc
3.8.8
3.8.8-rc
3.8.9
3.8.9-rc
```

### ⚠️ Important

Droopescan does **not** necessarily identify the exact version.

Instead, it gives:

```text
Possible version(s)
```

This is why manual validation is important.

---

# 🌐 20. Interesting URLs Found by Droopescan

Droopescan identifies:

### Detailed version information

```text
http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml
```

### Login page

```text
http://dev.inlanefreight.local/administrator/
```

### License file

```text
http://dev.inlanefreight.local/LICENSE.txt
```

### Approximate version

```text
http://dev.inlanefreight.local/plugins/system/cache/cache.xml
```

This is a great example of automated enumeration pointing you toward **manual verification targets**.

---

# 🧩 21. Droopescan Result — What We Actually Know

After the scan:

```text
Possible Joomla versions
        ↓
Interesting URLs
        ↓
Manual verification
        ↓
Exact version
```

The source later confirms:

```text
Joomla → 3.9.4
```

Therefore:

```text
Scanner result
      +
Manual fingerprinting
      ↓
Exact version
```

---

# 🛠️ 22. JoomlaScan

Another tool introduced is:

```text
JoomlaScan
```

It is a Python tool inspired by the now-defunct:

```text
OWASP joomscan
```

The source notes that JoomlaScan is:

```text
A bit out-of-date
```

and:

```text
Requires Python 2.7
```

### ⭐ Important

An outdated tool isn't automatically useless.

It may still provide:

- Additional paths
    
- Accessible directories
    
- Extension fingerprints
    
- Useful clues
    

---

# 📦 23. Installing the `bs4` Dependency

The source uses:

```bash
python2 -m pip install bs4
```

Then JoomlaScan can be run.

---

# 🔎 24. Running JoomlaScan

The source uses:

```bash
python2 joomlascan.py -u http://dev.inlanefreight.local
```

The scanner reports:

```text
Robots file found:
http://dev.inlanefreight.local/robots.txt

No Error Log found
```

Then:

```text
Start scan...with 10 concurrent threads!
```

---

# 🧩 25. Joomla Components

JoomlaScan discovers components such as:

```text
com_actionlogs
com_admin
com_ajax
com_banners
```

For example:

```text
http://dev.inlanefreight.local/index.php?option=com_actionlogs
```

### What does `com_` mean?

Joomla components are application modules that provide functionality.

A URL such as:

```text
index.php?option=com_actionlogs
```

indicates the Joomla component:

```text
com_actionlogs
```

---

# 📂 26. JoomlaScan — Accessible Directories

The tool also identifies:

```text
Explorable Directory
```

Examples:

```text
/components/com_actionlogs/

/administrator/components/com_actionlogs/

/components/com_admin/

/administrator/components/com_admin/
```

This is useful because it gives us paths worth investigating manually.

---

# 📄 27. JoomlaScan — License Files

The scanner also discovers XML/license files such as:

```text
/administrator/components/com_actionlogs/actionlogs.xml
```

and:

```text
/administrator/components/com_admin/admin.xml
```

These files can potentially provide:

```text
Component information
Version information
Metadata
```

---

# 🧠 28. Why Use Multiple Enumeration Tools?

The source makes an important observation:

> JoomlaScan is not as valuable as droopescan, but it can help find accessible directories/files and fingerprint installed extensions.

This demonstrates a fundamental pentesting principle:

```text
Tool A
   +
Tool B
   +
Manual Enumeration
   ↓
More complete attack surface
```

Never assume one scanner sees everything.

---

# 🎯 29. Confirmed Joomla Version

After combining the enumeration results, we know:

```text
Joomla → 3.9.4
```

The administrator login portal is:

```text
http://dev.inlanefreight.local/administrator/index.php
```

---

# 🔐 30. Joomla Administrator Login

Unlike WordPress, Joomla's administrative portal is commonly located under:

```text
/administrator/
```

The source identifies:

```text
http://dev.inlanefreight.local/administrator/index.php
```

as the login portal.

### ⭐ Memorize

```text
WordPress → /wp-admin/
/wp-login.php

Joomla → /administrator/
```

---

# 👤 31. Joomla User Enumeration

Attempts at username enumeration produce a **generic error message**:

```text
Warning

Username and password do not match or you do not have an account yet.
```

### Why is this important?

The response does not distinguish between:

```text
Invalid username
```

and:

```text
Correct username + incorrect password
```

Therefore, the obvious login-error-based username enumeration technique used against some applications does not work here.

---

# 🧠 32. Login Enumeration — Important Lesson

Compare:

### Vulnerable behavior

```text
Username doesn't exist
→ "User doesn't exist"

Username exists
→ "Wrong password"
```

This allows enumeration.

### Joomla behavior shown in the source

```text
Invalid username
       ↓
Generic error

Invalid password
       ↓
Generic error
```

Therefore:

```text
No useful distinction
       ↓
No straightforward error-message enumeration
```

---

# 👑 33. Default Joomla Administrator Account

The source states:

```text
Default administrator account → admin
```

However, the password is:

> **Set at installation time.**

Therefore, knowing the username alone isn't enough.

The possible attack path becomes:

```text
Known username
      ↓
admin
      ↓
Weak/common password?
      ↓
Light brute-force / password guessing
      ↓
Potential admin access
```

---

# 🔐 34. Joomla Brute Force

The source uses a Joomla brute-force script:

```text
joomla-bruteforce
```

The script can be obtained from the referenced GitHub project in the material.

The example command is:

```bash
sudo python3 joomla-brute.py \
-u http://dev.inlanefreight.local \
-w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt \
-usr admin
```

> **Only perform password testing against systems where you have explicit authorization.**

---

# 💥 35. Successful Credentials

The source obtains:

```text
admin:admin
```

The result:

```text
admin:admin
```

means:

```text
Username → admin
Password → admin
```

The source comments that this is an example of poor password hygiene.

---

# 🔥 36. Complete Joomla Enumeration Workflow

![Image](https://images.openai.com/static-rsc-4/wd7aV-cL6zwvraQR2H4CgQKT11AbWDhDzoiJ8VoPUWC8v9QIT3t-fWjVv2BKqimNP3AyeYIeDcqtiJycpCG6LyTnTki88GBiOmcGFnhoV5zQ5L_pH-vCJiYGjAOEdUNpQNf7T6gdP-5ESmx2G79A9puB7ocfg8DWbvtAnpA3PIHxfstpYgFLIAlEeEllnGSH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vRYLs5iRilXOdP5OnfgM9dJRF93Q8RsfJkyuix3bxse1fBmDFfxB_vI3XIDTjgoZHhSZMzIaM64DqtM7CkpRCowcTKkWQNRPLhtq87SkTO9VM7igz4pQ3hyWQPs-j2ePbaDqBMSmiitwk7-4MjbwFKNH1dbBFvkCX9B3fuPnYLu8CWrMCwFDcq3LhvBPP5hG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VIzuSiBcuFy5sWIVFwey9mqvoPvX4OcU_HGikN4JjQXrKpNW-_mbTqEntvqNzJgTvfG2fgkyGrXDEtGGfXhSmpa04JMciAGTj-OLBkqsSV2GNj9Ayio7yH9jtBjMZJ0IutlWjrSO2-ffGhl-dnapRlW7n5q3pwJTulT556v5TTY1_4M4f0bruRIAWWbLdYcd?purpose=fullsize)

```text
                    TARGET
                       │
                       ▼
                Web Application
                       │
                       ▼
              Identify Joomla
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      Page Source   robots.txt   Favicon
          │            │            │
          └────────────┼────────────┘
                       ▼
                Version Discovery
                       │
       ┌───────────────┼────────────────┐
       ▼               ▼                ▼
   README.txt      joomla.xml       cache.xml
       │               │                │
       └───────────────┼────────────────┘
                       ▼
                  Joomla 3.9.4
                       │
                       ▼
               Automated Scanning
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
        Droopescan            JoomlaScan
             │                   │
             ▼                   ▼
       URLs / versions     Components / dirs
             │                   │
             └─────────┬─────────┘
                       ▼
              Administrator Portal
                       │
                       ▼
                 /administrator/
                       │
                       ▼
              Username Enumeration
                       │
                       ▼
              Generic Error Message
                       │
                       ▼
              Known Account: admin
                       │
                       ▼
            Weak Password Testing
                       │
                       ▼
                admin:admin
```

---

# 📋 37. Important Commands

## Fingerprint Joomla

```bash
curl -s http://dev.inlanefreight.local/ | grep Joomla
```

---

## Check `README.txt`

```bash
curl -s http://dev.inlanefreight.local/README.txt | head -n 5
```

---

## Retrieve Joomla manifest

```bash
curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
```

---

## Install Droopescan

```bash
sudo pip3 install droopescan
```

---

## Check Droopescan

```bash
droopescan -h
```

---

## Droopescan help

```bash
droopescan scan --help
```

---

## Scan Joomla

```bash
droopescan scan joomla --url http://dev.inlanefreight.local/
```

---

## Install JoomlaScan dependency

```bash
python2 -m pip install bs4
```

---

## Run JoomlaScan

```bash
python2 joomlascan.py -u http://dev.inlanefreight.local
```

---

## Joomla brute-force example from the source

```bash
sudo python3 joomla-brute.py \
-u http://dev.inlanefreight.local \
-w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt \
-usr admin
```

---

# 🗂️ 38. Joomla Paths to Memorize

|Path|Why It Matters|
|---|---|
|`/administrator/`|Administrator portal|
|`/administrator/index.php`|Administrator login|
|`/administrator/manifests/files/joomla.xml`|Exact Joomla version|
|`/README.txt`|Version/package information|
|`/robots.txt`|Joomla fingerprints and directories|
|`/plugins/system/cache/cache.xml`|Approximate version|
|`/components/`|Joomla components|
|`/administrator/components/`|Administrator components|
|`/plugins/`|Plugins|
|`/modules/`|Modules|
|`/libraries/`|Libraries|
|`/media/system/js/`|Possible version fingerprint|
|`/installation/`|Installation-related directory|
|`/logs/`|Potentially interesting logs|
|`/tmp/`|Temporary files|
|`/cache/`|Cached content|

The paths above are derived from the source's `robots.txt`, fingerprinting, and JoomlaScan examples.

---

# 🔎 39. Joomla Components vs Plugins vs Modules

This distinction is useful when enumerating Joomla.

```text
Joomla
 │
 ├── Components
 │      └── Major application functionality
 │
 ├── Plugins
 │      └── Extend/modify Joomla behavior
 │
 ├── Modules
 │      └── Additional page functionality
 │
 ├── Templates
 │      └── Presentation / appearance
 │
 └── Libraries
        └── Supporting code
```

The source specifically demonstrates component enumeration through identifiers such as:

```text
com_actionlogs
com_admin
com_ajax
com_banners
```

---

# ⚠️ 40. "Possible Version" ≠ Confirmed Version

This is a **very important penetration-testing lesson**.

Droopescan reports:

```text
Possible version(s):
3.8.10
3.8.11
3.8.12
...
```

That does **not** mean:

```text
Confirmed → one of these
```

Instead:

```text
Scanner
   ↓
Possible versions
   ↓
Manual fingerprint
   ↓
joomla.xml
   ↓
Confirmed version
```

The source ultimately establishes:

```text
Joomla 3.9.4
```

---

# 🧠 41. Manual + Automated Enumeration

The best approach is **not**:

```text
Run scanner
    ↓
Trust scanner
```

Instead:

```text
Manual Discovery
       +
Droopescan
       +
JoomlaScan
       +
Manual Validation
       ↓
Complete Attack Surface
```

### Manual techniques

```text
Page source
robots.txt
README.txt
joomla.xml
cache.xml
Favicon
```

### Automated techniques

```text
Droopescan
JoomlaScan
```

### Validation

```text
Confirm exact version
Confirm accessible directories
Confirm administrator portal
Confirm components
Confirm authentication behavior
```

---

# 🎯 42. Attack Surface Identified

By the end of this enumeration process, we have:

```text
Target
  │
  ├── Joomla
  │
  ├── Version → 3.9.4
  │
  ├── /administrator/
  │
  ├── /components/
  │
  ├── /plugins/
  │
  ├── /modules/
  │
  ├── Accessible component paths
  │
  ├── Joomla manifest
  │
  └── Known administrator username
          │
          ▼
       admin
          │
          ▼
   Weak password discovered
          │
          ▼
      admin:admin
```

The source confirms the Joomla version, administrator portal, generic login error, default administrator username, and successful credentials.

---

# ⭐ 43. CPTS High-Value Takeaways

### 🔥 Fingerprinting

```bash
curl -s http://target/ | grep Joomla
```

Look for:

```html
<meta name="generator" content="Joomla! - Open Source Content Management" />
```

---

### 🔥 Joomla administrator

Memorize:

```text
/administrator/
```

and:

```text
/administrator/index.php
```

---

### 🔥 Exact version

Memorize:

```text
/administrator/manifests/files/joomla.xml
```

The source's target:

```text
Joomla 3.9.4
```

---

### 🔥 Useful secondary version locations

```text
/README.txt
/plugins/system/cache/cache.xml
/media/system/js/
```

---

### 🔥 `robots.txt`

Look for:

```text
/administrator/
/components/
/plugins/
/modules/
/libraries/
/logs/
/tmp/
/cache/
```

---

### 🔥 Droopescan

Install:

```bash
sudo pip3 install droopescan
```

Scan:

```bash
droopescan scan joomla --url http://target/
```

---

### 🔥 JoomlaScan

Run:

```bash
python2 joomlascan.py -u http://target
```

Useful for discovering:

```text
Components
Directories
License files
Extension fingerprints
```

---

### 🔥 Username enumeration

The source shows Joomla returning:

```text
Username and password do not match or you do not have an account yet.
```

Therefore, straightforward login-error-based username enumeration is **not useful in this target scenario**.

---

### 🔥 Default administrator

```text
admin
```

The source demonstrates that weak credentials can lead to:

```text
admin:admin
```

---

# 📝 44. Enumeration Checklist

Use this during a Joomla assessment:

```text
[ ] Identify whether target is Joomla
[ ] Check page source
[ ] Check robots.txt
[ ] Check favicon
[ ] Check README.txt
[ ] Check joomla.xml
[ ] Check cache.xml
[ ] Check media/system/js/
[ ] Identify Joomla version
[ ] Locate /administrator/
[ ] Enumerate components
[ ] Enumerate plugins
[ ] Enumerate modules
[ ] Check accessible directories
[ ] Check XML/license files
[ ] Run droopescan
[ ] Run JoomlaScan
[ ] Compare scanner results
[ ] Manually validate findings
[ ] Check authentication behavior
[ ] Identify known/default usernames
[ ] Assess password strength where authorized
[ ] Document findings
```

---

# 🧠 45. The Complete Mental Model

```text
                  JOOMLA TARGET
                       │
                       ▼
                 FINGERPRINT
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Page Source     robots.txt      Favicon
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                 VERSION ENUM
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      README.txt    joomla.xml   cache.xml
          │            │            │
          └────────────┼────────────┘
                       ▼
                  Joomla 3.9.4
                       │
                       ▼
              AUTOMATED ENUMERATION
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
        Droopescan           JoomlaScan
             │                   │
             ▼                   ▼
     URLs / versions     Components / dirs
             │                   │
             └─────────┬─────────┘
                       ▼
               ADMIN PORTAL
                       │
                       ▼
                /administrator/
                       │
                       ▼
             AUTHENTICATION TEST
                       │
                       ▼
                Known User: admin
                       │
                       ▼
                Weak Password
                       │
                       ▼
                 admin:admin
```

---

# 🏆 46. Final CPTS Takeaway

The **most important concept** in this section is the methodology rather than any individual command.

A good Joomla enumeration process looks like:

```text
DISCOVER
   ↓
FINGERPRINT
   ↓
IDENTIFY VERSION
   ↓
ENUMERATE COMPONENTS
   ↓
ENUMERATE PLUGINS / MODULES
   ↓
FIND ADMIN PORTAL
   ↓
ENUMERATE AUTHENTICATION BEHAVIOR
   ↓
IDENTIFY VALID USERNAMES
   ↓
ASSESS CREDENTIAL SECURITY
   ↓
VALIDATE FINDINGS
   ↓
BUILD ATTACK SURFACE
```

For this particular source example, the important final findings are:

```text
CMS              → Joomla
Version          → 3.9.4
Admin portal     → /administrator/index.php
Known user       → admin
Credentials      → admin:admin
```

And the most important **technical fingerprints** to remember are:

```text
/administrator/
/administrator/manifests/files/joomla.xml
/README.txt
/plugins/system/cache/cache.xml
/components/
/plugins/
/modules/
```

The key CPTS mindset is:

> **Use multiple sources of evidence. A scanner gives you leads; manual enumeration confirms what is actually running.**