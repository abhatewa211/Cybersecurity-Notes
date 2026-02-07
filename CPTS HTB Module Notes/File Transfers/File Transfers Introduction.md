## Overview

- **File transfers** are a critical part of penetration testing
    
- Required when:
    
    - Uploading tools, scripts, or exploits to a target
        
    - Exfiltrating data or logs from a target
        
    - Moving binaries for privilege escalation or lateral movement
        
- File transfers are often:
    
    - **Restricted**
        
    - **Monitored**
        
    - **Blocked** by host or network controls
        

Understanding **multiple file transfer techniques** is essential to succeed in real-world environments.

---

## Setting the Stage (Realistic Engagement Scenario)

### Initial Access

- Target: **IIS web server**
    
- Vulnerability: **Unrestricted file upload**
    
- Actions:
    
    - Upload a **web shell**
        
    - Use it to obtain a **reverse shell**
        
    - Begin system enumeration
        

---

### Enumeration Challenges

- Attempted to download `PowerUp.ps1` using **PowerShell**
    
- Blocked by:
    
    - **Application Control Policy**
        
- Manual enumeration revealed:
    
    - **SeImpersonatePrivilege**
        

---

### Privilege Escalation Requirement

- Goal:
    
    - Escalate privileges using **PrintSpoofer**
        
- Requirement:
    
    - Transfer a **compiled binary** to the target machine
        

---

## Failed File Transfer Attempts (and Why They Failed)

### PowerShell Download

- ❌ Blocked by Application Control Policy
    

---

### Certutil Download

- Attempted to download binary from **GitHub**
    
- ❌ Blocked due to:
    
    - Strong **web content filtering**
        
- Blocked services included:
    
    - GitHub
        
    - Dropbox
        
    - Google Drive
        

---

### FTP Transfer

- Set up FTP server
    
- Used Windows FTP client
    
- ❌ Blocked by firewall:
    
    - Outbound **TCP port 21** blocked
        

---

### SMB Transfer (Successful)

- Used **Impacket smbserver**
    
- Created a shared folder
    
- Outbound traffic allowed on:
    
    - **TCP port 445 (SMB)**
        
- Result:
    
    - Successfully transferred the binary
        
    - Escalated privileges to **administrator-level user**
        

---

## Key Lessons from the Scenario

- **Multiple controls** can block common transfer methods:
    
    - Application whitelisting
        
    - AV / EDR
        
    - Firewall rules
        
    - Web filtering
        
- Success often requires:
    
    - Trying **multiple approaches**
        
    - Understanding **network behavior**
        
    - Identifying **allowed ports**
        

---

## Importance of Understanding File Transfers

### Host-Based Controls

- Application whitelisting
    
- Antivirus (AV)
    
- Endpoint Detection and Response (EDR)
    
- Script execution policies
    

These controls may:

- Block tools
    
- Detect file downloads
    
- Prevent script execution
    

---

### Network-Based Controls

- Firewalls
    
- IDS (Intrusion Detection Systems)
    
- IPS (Intrusion Prevention Systems)
    

These may:

- Block specific ports
    
- Inspect traffic
    
- Flag uncommon protocols
    

---

## File Transfer as a Core OS Feature

- File transfer is:
    
    - Native to **all operating systems**
        
    - Supported by many built-in tools
        
- However:
    
    - Many tools are **monitored or restricted**
        
    - Default methods may fail in hardened environments
        

---

## Why Multiple Techniques Matter

- No single transfer method works everywhere
    
- Each environment is different
    
- A successful pentester must:
    
    - Adapt quickly
        
    - Know fallback techniques
        
    - Understand protocol behavior
        

---

## Scope of This Module

- Focuses on:
    
    - **Windows** and **Linux**
        
    - Tools commonly available by default
        
- Techniques covered:
    
    - Are **not exhaustive**
        
    - Are **practical and reusable**
        
- Serves as:
    
    - A **reference guide**
        
    - A foundation for other HTB Academy modules
        

---

## Hands-On Practice

- Module provides:
    
    - Target Windows machines
        
    - Target Linux machines
        
- Exercises involve:
    
    - Uploading files
        
    - Downloading files
        
    - Testing multiple techniques
        

---

## Recommended Practice Approach

- Experiment with:
    
    - As many transfer methods as possible
        
- Observe:
    
    - When a method works
        
    - When it fails
        
    - What controls block it
        
- Take notes on:
    
    - Port usage
        
    - Protocol behavior
        
    - Environmental restrictions
        

---

## Post-Module Practice

After completing this module:

- Apply techniques in:
    
    - Other HTB Academy modules
        
    - HTB machines
        
    - Pro Labs
        
- Build a **personal file transfer playbook**
    
- Document:
    
    - Which methods work best in different scenarios
        

---

## Key Takeaways (Must Remember)

- File transfers are **often the bottleneck**
    
- Expect:
    
    - Restrictions
        
    - Monitoring
        
    - Failures
        
- Always:
    
    - Have backup methods
        
    - Understand allowed ports
        
    - Leverage what the environment permits
        
- Flexibility and creativity are essential