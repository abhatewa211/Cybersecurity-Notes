![Image](https://images.openai.com/static-rsc-4/HDN0TOCBB52RGF1noKCGXIrX8H22Dt7MqZeFkoYGukzxySaH4A8VsDgWa-fOpFGbLyTm-4itpVWpnP3Vd91nvLe7heL-34BCcR2-s2vFs0KdSkYrQFNzRrTYSCD4v6T1c4zsKT5LY2D0AwC4hrbZs9JvLrfJ_Z2W8QgGJiTjIuQezNL4lqU2Uiw66eF8e444?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yg1R58tMGXkhyTLzEV2EGVf4wOqMk-VJox-kfyZqSOdWFucewFhMqHiSO35psZKYu9dXYgT1_svMOrcqn0vD2AuhMNBZyOdZxlZmOoZVfGgRSBrvAENJpHQZTaWAmKF0mWaZIAql0uGaOBFluh2dhKqnZbNg6UcqvODPBdFxE0qzOrgSVTDo9j7RpvdkLbG5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Xhgh30KLBsCVOJCiq4qPadaToLyzIbOccv_-miyxqJA-Q4do7te_2sdGHH7g87wGO9jWmnGB7wU7y-8NdbVfwzQgZ4-TNe_4lW63uOmAVCgc-TD4_Jw5PUJs16V0k3F13BWvIyUIYXufJ03Im5utsuYGEgoePWJhysgKLXgPhQ-tI2r26VwYo3_Rdex8Eisk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ouChUwaLSFWkjGllNBsUT1vB5cIbpnjtGGsS873EhigJXyNC0A4DNeA482_zrO_VEkNxFalJnh3GM7Y0eefXhGjpWqvX1jUMT6FR1PP4RbeywZH8oWsyGzWMmQkrCAKmj2v-GGsuk2saYGkhbsMBJR1kM8dzLbgcZKpYF_cdd1V1OXYaoYPDgLWYexh82JgK?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ELW3k6Hz-P7gC6Moqva0yarp3mA2AFSTDuGZnE9mJPzPadx52pLjdb2u-mG2YonzeJQGrkh2uWCE9sqT-qDxDi1aDDlfiOdutiF3XcFUyK8ZiZmo11k3JntePv_jShUUbdq41OT6CYB8DT518WfQb0_UX0I2QmKYPM_NE15W3mbYSkZMgbVQrMmK8hH87sLB?purpose=fullsize)

---

# 1. What is Drupal?

Drupal is an open-source **Content Management System (CMS)** launched in **2001**.

It is the **third and final CMS** covered in this section alongside:

```text
WordPress
   ↓
Joomla
   ↓
Drupal
```

Drupal is popular with both:

- Companies
    
- Developers
    

### Technical stack

Drupal is primarily written in:

```text
PHP
```

It supports several database options:

```text
MySQL
PostgreSQL
SQLite
```

SQLite can be used when there is no separate DBMS installed.

---

# 2. Drupal Themes & Modules

Similar to WordPress, Drupal allows websites to be extended using:

```text
Drupal
 ├── Themes
 └── Modules
```

### Themes

Themes control the **appearance/presentation** of the website.

### Modules

Modules extend Drupal's functionality.

At the time of writing in the source:

```text
~43,000 modules
~2,900 themes
```

This large ecosystem is important from a security perspective because every additional component can potentially introduce another attack surface.

---

# 3. Drupal Statistics

The source provides the following historical statistics.

|Statistic|Value|
|---|--:|
|Internet sites running Drupal|~1.1 million|
|Share of all internet sites|~1.5%|
|Top 1 million websites|~5%|
|Top 10,000 websites|~7%|
|CMS market share|~2.4%|
|Supported languages|100|
|Community members|1.3+ million|
|Drupal 8 contributors|3,290|
|Companies involved in Drupal 8|1,288|
|Fortune 500 companies using Drupal|33|
|Government websites using Drupal|56%|
|Universities/colleges/schools|23.8%|

### Major brands mentioned

The source lists:

- Tesla
    
- Warner Bros Records
    

as examples of major organizations using Drupal.

> **Important:** These are statistics from the source's timeframe and should not be treated as current Drupal statistics.

---

# 4. Drupal Versions in Use

According to the Drupal website information cited by the source, there were approximately:

```text
950,000
```

Drupal instances in use at the time of writing.

The distribution ranged approximately from:

```text
Drupal 5.x → Drupal 9.3.x
```

as of:

```text
September 5, 2021
```

The source states Drupal usage remained between roughly:

```text
900,000 – 1.1 million instances
```

from:

```text
June 2013 → September 2021
```

---

# 5. Important: What These Statistics Actually Measure

A very important detail from the source:

These statistics do **not** represent every Drupal installation worldwide.

They primarily account for Drupal installations running the:

```text
Update Status
```

module.

The module checks in with:

```text
drupal.org
```

daily to look for:

- New Drupal versions
    
- Module updates
    

Therefore:

```text
Reported Drupal installations
        ≠
Every Drupal installation worldwide
```

---

# 🔎 6. Discovery / Footprinting

During an external penetration test, you may encounter a website that appears to be a CMS.

Suppose you've already determined:

```text
Not WordPress
Not Joomla
```

The next possibility is Drupal.

CMS platforms can be attractive targets because they commonly expose:

- Version information
    
- Themes
    
- Modules
    
- Administrative interfaces
    
- Content structures
    
- Other application-specific functionality
    

Therefore, the next step is:

```text
Discovery
   ↓
Fingerprinting
   ↓
Enumeration
   ↓
Version identification
   ↓
Module/theme discovery
   ↓
Vulnerability research
```

---

# 🕵️ 7. How to Identify a Drupal Website

The source provides several Drupal fingerprinting techniques.

Look for:

### 1. Header/footer

```text
Powered by Drupal
```

### 2. Standard Drupal logo

### 3. `CHANGELOG.txt`

### 4. `README.txt`

### 5. Page source

### 6. `robots.txt`

Particularly interesting references include:

```text
/node
```

---

# 🧪 8. Fingerprinting Using cURL

The source demonstrates using `curl` and `grep`:

```bash
curl -s http://drupal.inlanefreight.local | grep Drupal
```

Output:

```html
<meta name="Generator" content="Drupal 8 (https://www.drupal.org)" />
      <span>Powered by <a href="https://www.drupal.org">Drupal</a></span>
```

This gives us two strong indicators:

```text
Generator metadata
        +
"Powered by Drupal"
        ↓
Drupal identified
```

---

# 🧠 9. Why Multiple Fingerprints Matter

Never rely on only one indicator.

For example:

```text
"Powered by Drupal"
```

is useful, but an administrator could remove or customize it.

Likewise, a custom theme may hide the standard Drupal appearance.

Therefore, combine multiple indicators:

```text
HTML source
   +
Headers
   +
Footer
   +
robots.txt
   +
Known Drupal files
   +
URL structure
```

The more independent indicators you find, the stronger your fingerprint becomes.

---

# 🧩 10. Drupal Nodes

One particularly useful Drupal fingerprint is the concept of **nodes**.

Drupal indexes its content using:

```text
Nodes
```

A node can represent different types of content, such as:

- Blog posts
    
- Polls
    
- Articles
    
- Other Drupal content
    

The source explains that page URIs are usually structured as:

```text
/node/<nodeid>
```

For example:

```text
/node/1
```

---

# 🌐 11. Node Example

The example URL is:

```text
http://drupal.inlanefreight.local/node/1
```

![Image](https://images.openai.com/static-rsc-4/m5Nhh7mB-ZMznseE9aurjoJ-ldUgB-X-lhy3Eo2Ixv9iFSvwdtPJ3N__y0gYxa2kfDKewNL1cmgVlBPDK8Y7_bhuP0wzdew_hyGNKdMtlRkt-5c-A6v_4LBqqp1j-bz2k_7EAcTa9bzJ6XVvqI4jIHmToNNWmaMfg54hLli1HbygiK6Hx0k_-OapPTgtjiG-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/K7l5PEXzqSieMN8lNzyatJT7T1HVmrpQmvdt8IZI0NMkzAGSJR5zALlmbS7sbxBrPOmzUhFIRLOrXUiaFVyO_MoTvnnjc0sJ14yqDDBKQLhap50zBLqhgOHgv3DmjcljBF01kD6DkpfAFwSpJt_AxBBGKPI6vXKpWxINzBLcr7P_Ushag57YvutUhVUsmIIL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/eyM3n8DjnZmnhMCkHvxzf7ZoWI-s6wxDTmuiKSAQHG0IYKr47OVglpQfEYCQEoebNrdwEYQV5-mn_9K4LqKDUc7YcgWJhtwahNgypLmVYi162bK1tNqEb542Ji3bmM7NFSCVPWX-2daTpVolE-lM55AiyuhwksQikyTLRLXABOeyvZo7n2oG2x_PT3BeylbX?purpose=fullsize)

The page is identified as a Drupal blog page.

The important fingerprint here is:

```text
/node/1
```

### Why is this useful?

A website may use a completely custom theme.

So visually:

```text
Custom website appearance
        ↓
Drupal not immediately obvious
```

But:

```text
/node/1
```

may reveal the underlying CMS.

---

# ⚠️ 12. Login Page Is Not Guaranteed

The source gives an important warning:

> **Not every Drupal installation will look the same.**

A Drupal installation may:

- Use a custom theme
    
- Hide the standard login page
    
- Restrict access to the login page
    
- Prevent internet access to the login page
    

Therefore:

```text
No visible Drupal login
        ≠
Not Drupal
```

This is an important enumeration mindset.

---

# 👥 13. Drupal Default User Types

Drupal supports three default user categories.

## 1. Administrator

```text
Administrator
      ↓
Complete control over Drupal website
```

The administrator has complete control over the website.

---

## 2. Authenticated User

An authenticated user:

```text
Logs in
   ↓
Performs permitted operations
```

For example:

- Adding articles
    
- Editing articles
    

However, their actual capabilities depend on their assigned permissions.

---

## 3. Anonymous

Every visitor who isn't authenticated is considered:

```text
Anonymous
```

By default, anonymous users are allowed to:

```text
Read posts
```

---

# 🧠 14. User Model Summary

```text
                    Drupal Users
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
   Administrator   Authenticated    Anonymous
          │              │              │
          ▼              ▼              ▼
 Complete control   Login +          Website
                    permissions       visitors
```

---

# 🔍 15. Enumeration

Once Drupal has been identified, begin systematic enumeration.

The source recommends combining:

```text
Manual enumeration
        +
Automated enumeration
```

The goal is to identify:

- Drupal version
    
- Installed plugins/modules
    
- Other useful information
    

---

# 🎯 16. Version Enumeration

Version identification can be difficult because Drupal's behavior changes depending on:

- Drupal version
    
- Hardening measures
    
- Configuration
    

One important technique is checking:

```text
CHANGELOG.txt
```

However, newer Drupal installations may block access to:

```text
CHANGELOG.txt
README.txt
```

Therefore, version enumeration should use multiple techniques.

---

# 📄 17. `CHANGELOG.txt` Enumeration

The source demonstrates:

```bash
curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
```

Output:

```text
Drupal 7.57, 2018-02-21
```

This directly reveals:

```text
Drupal Version = 7.57
```

and the release date:

```text
2018-02-21
```

---

# 🚨 18. Why Version Information Is Valuable

Once you know:

```text
Drupal 7.57
```

you can begin researching:

```text
Drupal 7.57
      ↓
Known vulnerabilities
      ↓
Affected modules
      ↓
Public exploits / PoCs
      ↓
Potential attack paths
```

Version identification therefore becomes a bridge between:

```text
Enumeration
     ↓
Vulnerability Research
```

---

# ❌ 19. What Happens on Newer Drupal?

The source demonstrates the same request against:

```text
http://drupal.inlanefreight.local/CHANGELOG.txt
```

The response is:

```html
<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL "http://drupal.inlanefreight.local/CHANGELOG.txt" was not found on this server.</p></body></html>
```

Therefore:

```text
CHANGELOG.txt
       ↓
404 Not Found
```

does **not** necessarily mean:

```text
Not Drupal
```

It can simply mean the file isn't accessible.

---

# 🧠 20. Enumeration Mindset

This is an important CPTS lesson:

```text
Expected fingerprint missing
          ↓
Don't immediately stop
          ↓
Try another fingerprint
```

For example:

```text
CHANGELOG.txt blocked
        ↓
Page source
        ↓
robots.txt
        ↓
Node structure
        ↓
Automated enumeration
        ↓
Modules/themes
```

---

# 🛠️ 21. Droopescan

The source recommends:

```text
droopescan
```

for Drupal enumeration.

It was previously introduced during Joomla enumeration, but it provides significantly more functionality for Drupal.

The scan is performed against:

```text
http://drupal.inlanefreight.local
```

---

# 🔎 22. Running Droopescan

Command from the source:

```bash
droopescan scan drupal -u http://drupal.inlanefreight.local
```

The tool performs automated Drupal-specific enumeration.

---

# 📊 23. Droopescan Results

The source gives the following output:

```text
[+] Plugins found:                                                              
    php http://drupal.inlanefreight.local/modules/php/
        http://drupal.inlanefreight.local/modules/php/LICENSE.txt

[+] No themes found.

[+] Possible version(s):
    8.9.0
    8.9.1

[+] Possible interesting urls found:
    Default admin - http://drupal.inlanefreight.local/user/login

[+] Scan finished (0:03:19.199526 elapsed)
```

Let's break this down.

---

# 🧩 24. Plugin / Module Discovery

Droopescan identifies:

```text
php
```

at:

```text
/modules/php/
```

and:

```text
/modules/php/LICENSE.txt
```

This tells us that the site has a discoverable Drupal module named:

```text
php
```

### Why this matters

Modules expand the application's functionality.

Therefore:

```text
Drupal Core
     +
Installed Modules
     ↓
Total Attack Surface
```

The source later emphasizes that installed plugins/modules should be investigated.

---

# 🎨 25. Theme Discovery

The scan reports:

```text
[+] No themes found.
```

This demonstrates an important point:

```text
No result
   ≠
Nothing exists
```

Automated scanners can have limitations, particularly when applications use:

- Custom themes
    
- Obfuscation
    
- Hardening
    
- Unusual configurations
    

So manual enumeration remains important.

---

# 🔢 26. Possible Drupal Versions

Droopescan identifies:

```text
8.9.0
8.9.1
```

as possible versions.

The source concludes that the instance appears to be running:

```text
Drupal 8.9.1
```

### Important terminology

The scanner says:

```text
Possible version(s)
```

not:

```text
Confirmed version
```

This distinction matters.

A scanner may infer the version based on fingerprints.

You should validate important version information where possible.

---

# 📅 27. Drupal 8.9.1

The source states that:

```text
Drupal 8.9.1
```

was released in:

```text
June 2020
```

and wasn't the latest version at the time of the source.

Therefore:

```text
8.9.1
   ↓
Old version
   ↓
Research vulnerabilities
```

But again:

> **Old does not automatically mean exploitable.**

---

# 🔐 28. Interesting URL — Login

Droopescan identifies:

```text
Default admin
```

at:

```text
http://drupal.inlanefreight.local/user/login
```

This gives us another useful Drupal fingerprint.

The path:

```text
/user/login
```

can indicate a Drupal installation.

However, remember the earlier warning:

```text
Not every installation exposes the login page publicly.
```

---

# 🔬 29. Vulnerability Research

After identifying:

```text
Drupal 8.9.1
```

the next step is vulnerability research.

The source says a quick search for Drupal-related vulnerabilities did **not** reveal anything apparent affecting this core version.

Therefore, the assessment shouldn't stop.

Instead, investigate:

```text
Drupal Core
      ↓
Installed Modules
      ↓
Themes
      ↓
Built-in Functionality
```

---

# 🧠 30. Why Modules Are Important

The Drupal ecosystem contains a very large number of modules.

Therefore:

```text
Core version appears safe
          ↓
Don't stop
          ↓
Enumerate installed modules
          ↓
Identify module versions
          ↓
Research module vulnerabilities
```

This is one of the most important lessons from this section.

---

# 🗺️ 31. Complete Drupal Enumeration Workflow

```text
                    TARGET
                      │
                      ▼
              Identify CMS
                      │
                      ▼
                   Drupal
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
      Page Source   robots.txt   Nodes
          │           │           │
          └───────────┼───────────┘
                      ▼
              Version Discovery
                      │
             ┌────────┴────────┐
             ▼                 ▼
        CHANGELOG.txt      Droopescan
             │                 │
             ▼                 ▼
         Version          Version
                           Modules
                           Themes
                           URLs
             │                 │
             └────────┬────────┘
                      ▼
              Vulnerability
                Research
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
      Core Vulns             Module Vulns
          │                       │
          └───────────┬───────────┘
                      ▼
              Built-in Functionality
```

---

# 🧪 32. Commands — Quick Revision

### Identify Drupal from HTML

```bash
curl -s http://drupal.inlanefreight.local | grep Drupal
```

### Check `CHANGELOG.txt`

```bash
curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
```

### Scan Drupal using Droopescan

```bash
droopescan scan drupal -u http://drupal.inlanefreight.local
```

---

# 📌 33. Important URLs

### Node

```text
http://drupal.inlanefreight.local/node/1
```

### Login

```text
http://drupal.inlanefreight.local/user/login
```

### CHANGELOG

```text
http://drupal-acc.inlanefreight.local/CHANGELOG.txt
```

### Discovered module

```text
http://drupal.inlanefreight.local/modules/php/
```

---

# ⭐ 34. Things to Memorize for CPTS

## Drupal basics

```text
Language:
PHP
```

```text
Databases:
MySQL
PostgreSQL
SQLite
```

```text
Extensions:
Modules
Themes
```

---

## Drupal fingerprints

Remember:

```text
Powered by Drupal
        +
Drupal logo
        +
CHANGELOG.txt
        +
README.txt
        +
Page source
        +
robots.txt
        +
/node/<nodeid>
        +
/user/login
```

---

# 🔥 35. Most Important Enumeration Indicators

|Indicator|Why it matters|
|---|---|
|`Powered by Drupal`|Direct CMS fingerprint|
|`Drupal` generator meta tag|Version/CMS clue|
|`/node/1`|Drupal content structure|
|`/user/login`|Default Drupal login path|
|`CHANGELOG.txt`|Can reveal exact version|
|`README.txt`|Possible Drupal fingerprint|
|`/modules/`|Module discovery|
|`robots.txt`|Can expose Drupal paths|
|Droopescan|Automated Drupal enumeration|

---

# 🧠 36. Key Lessons

### Lesson 1 — Don't depend on appearance

A custom theme can hide Drupal visually.

```text
Custom appearance
       ≠
Not Drupal
```

---

### Lesson 2 — Missing files don't disprove the CMS

If:

```text
CHANGELOG.txt → 404
```

don't conclude:

```text
Drupal isn't installed
```

Try other techniques.

---

### Lesson 3 — Automate + verify manually

Best approach:

```text
Manual Enumeration
       +
Automated Enumeration
       ↓
Cross-check findings
```

---

### Lesson 4 — Version identification is critical

Once you know:

```text
Drupal 8.9.1
```

you can investigate:

```text
Core vulnerabilities
Module vulnerabilities
Theme vulnerabilities
```

---

### Lesson 5 — Modules can be the real attack surface

Even when:

```text
Drupal Core
       ↓
No obvious vulnerability
```

you should continue with:

```text
Installed Modules
       ↓
Module Versions
       ↓
Known Vulnerabilities
```

---

# 🏁 37. Final CPTS Cheat Sheet

```text
DRUPAL DISCOVERY & ENUMERATION
────────────────────────────────────

1. Identify Drupal
   ├── Powered by Drupal
   ├── Generator meta tag
   ├── Drupal logo
   ├── CHANGELOG.txt
   ├── README.txt
   ├── robots.txt
   └── /node/<id>

2. Identify users/roles
   ├── Administrator
   ├── Authenticated User
   └── Anonymous

3. Identify version
   ├── CHANGELOG.txt
   ├── README.txt
   ├── Page source
   └── Droopescan

4. Enumerate components
   ├── Modules
   ├── Themes
   └── Interesting URLs

5. Research vulnerabilities
   ├── Core
   ├── Modules
   └── Built-in functionality

6. Don't stop if core is clean
   ↓
   Investigate installed modules
```

## 🎯 One-line methodology to remember

> **Identify Drupal → fingerprint it → determine the version → enumerate modules/themes → identify interesting URLs → research core and module vulnerabilities → investigate built-in functionality.**

That is the **core workflow** this section is teaching.