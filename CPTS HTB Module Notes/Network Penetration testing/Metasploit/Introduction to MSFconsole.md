# 🖥️ What is MSFconsole?

![Image](https://www.offsec.com/_astro/msfconsolehelp-2_2mkfJx.webp)

![Image](https://help.rapid7.com/metasploit/Content/Resources/Images/msf/msf-console_389x214.png)

![Image](https://www.rapid7.com/cdn/assets/blt88ff2a32c2a3ce11/683dde575619a1291ac6e9e6/msf-banner-2015.png)

**MSFconsole (`msfconsole`)** is the **primary command-line interface** used to interact with the **Metasploit Framework**.

It provides a **centralized environment** where penetration testers can:

- Search exploits
    
- Configure payloads
    
- Launch attacks
    
- Manage sessions
    
- Perform post-exploitation
    

Most security distributions such as:

- **Parrot Security OS**
    
- **Kali Linux**
    

come with **Metasploit Framework preinstalled**, making it easy to start using `msfconsole`.

---

# 🚀 Launching MSFconsole

To start the Metasploit console, run the following command in the terminal:

```bash
msfconsole
```

Example output when launching:

```
=[ metasploit v6.x ]
+ -- --=[ exploits ]
+ -- --=[ auxiliary modules ]
+ -- --=[ payloads ]
+ -- --=[ encoders ]
+ -- --=[ nops ]
+ -- --=[ evasion modules ]

msf6 >
```

This interface provides the **interactive command prompt**:

```
msf6 >
```

where we can execute all Metasploit commands.

---

# 🎨 Splash Screen

When launching `msfconsole`, a **banner splash screen** appears that displays:

- Metasploit version
    
- Number of exploits
    
- Number of auxiliary modules
    
- Payload count
    
- Encoders
    
- NOP generators
    
- Evasion modules
    

Example:

```
=[ metasploit v6.1.9-dev ]
+ -- --=[ 2169 exploits ]
+ -- --=[ 1149 auxiliary ]
+ -- --=[ 398 post ]
+ -- --=[ 592 payloads ]
+ -- --=[ 45 encoders ]
+ -- --=[ 10 nops ]
+ -- --=[ 9 evasion ]
```

This information helps us understand **how many modules are currently available in the framework**.

---

# ⚡ Launching MSFconsole Without Banner

Sometimes we may want to start **msfconsole without the splash banner**.

We can do this using the **`-q` (quiet) option**.

```bash
msfconsole -q
```

Output:

```
msf6 >
```

This option is useful for:

- Scripts
    
- Automation
    
- Faster startup
    

---

# 📖 Viewing Available Commands

To view all available Metasploit commands, use:

```bash
help
```

This command displays **all msfconsole commands**, their syntax, and their descriptions.

Example:

```
Core Commands
=============
help
search
use
show
info
set
run
exploit
exit
```

Learning these commands is essential for efficient exploitation.

---

# 🔄 Updating Metasploit Framework

To ensure Metasploit contains the **latest exploits and modules**, it must be updated regularly.

### Old Method (Deprecated)

Previously, Metasploit updates were done using:

```bash
msfupdate
```

---

### Current Method (Recommended)

Today, updates are handled using the **APT package manager**.

Run the following command:

```bash
sudo apt update && sudo apt install metasploit-framework
```

Example installation output:

```
Preparing to unpack metasploit-framework
Unpacking metasploit-framework
Setting up metasploit-framework
Processing triggers for man-db
Scanning application launchers
Launchers are updated
```

This installs or updates:

- New exploits
    
- New payloads
    
- Framework improvements
    
- Security patches
    

---

# 🔍 Importance of Enumeration Before Exploitation

Before launching any exploit, we must **understand the target system**.

This process is called **Enumeration**.

Enumeration involves identifying:

- Running services
    
- Service versions
    
- Open ports
    
- System configurations
    

Example services we may find during enumeration:

|Service|Example|
|---|---|
|HTTP|Web servers|
|FTP|File transfer services|
|SQL|Databases|
|SSH|Remote administration|

---

### Why Versions Are Important

The **version of a service** determines whether a vulnerability exists.

Example:

|Service|Version|Status|
|---|---|---|
|Apache|2.4.49|Vulnerable|
|Apache|2.4.58|Patched|

Therefore, **outdated software versions are often the entry point into a system**.

---

# 🧩 MSF Engagement Structure

![Image](https://www.varonis.com/hubfs/Imported_Blog_Media/metasploit-guide-set-up.png?hsLang=en)

![Image](https://www.compassitc.com/hs-fs/hubfs/Penetration%20Test%20Phases.webp?height=604&name=Penetration+Test+Phases.webp&width=610)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/0%2AElVVdJ8FZWcrQbvZ.jpg)

![Image](https://cdn.prod.website-files.com/5efc3ccdb72aaa7480ec8179/673c4139f7c9e8a1b4d9468a_61ede195222006f6c54b1f20_Metasploit%2520Framework%2520Architecture.png)

The **Metasploit engagement structure** follows a structured penetration testing methodology.

It is divided into **five main phases**.

---

# 1️⃣ Enumeration

Goal: **Gather information about the target**

Activities include:

- Port scanning
    
- Service detection
    
- Version detection
    
- Network mapping
    

Example tools:

- Nmap
    
- Metasploit auxiliary scanners
    

Subcategories:

- **Service Validation**
    
- **Vulnerability Research**
    

---

# 2️⃣ Preparation

Goal: **Prepare the exploit strategy**

Activities include:

- Analyzing vulnerabilities
    
- Selecting correct exploit modules
    
- Payload configuration
    
- Code auditing
    

This stage ensures the attack is **accurate and efficient**.

---

# 3️⃣ Exploitation

Goal: **Gain access to the target system**

Activities include:

- Executing exploit modules
    
- Delivering payloads
    
- Establishing a session
    

Example payloads:

- Meterpreter
    
- Reverse shell
    
- Bind shell
    

---

# 4️⃣ Privilege Escalation

Goal: **Gain higher privileges on the compromised system**

Examples:

- User → Administrator
    
- User → Root
    

Techniques include:

- Exploiting kernel vulnerabilities
    
- Misconfigured services
    
- Weak permissions
    

---

# 5️⃣ Post-Exploitation

Goal: **Maintain access and extract information**

Activities include:

- Pivoting to other systems
    
- Data exfiltration
    
- Credential dumping
    
- Persistence
    
- Network discovery
    

---

# 🔑 Key Takeaways

✔ **MSFconsole is the primary interface for Metasploit**  
✔ It allows interaction with **exploits, payloads, modules, and sessions**  
✔ Metasploit should always be **kept updated using apt**  
✔ **Enumeration is the most critical step before exploitation**  
✔ The Metasploit workflow follows **five phases**:

1. Enumeration
    
2. Preparation
    
3. Exploitation
    
4. Privilege Escalation
    
5. Post-Exploitation
    

---

# 💡 Pro Tip for HTB / Bug Bounty / Pentesting

Always remember:

> **Enumeration is the key to exploitation.**

If you miss a service version or misidentify the target environment, the exploit will likely fail.

---

