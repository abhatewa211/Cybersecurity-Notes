![Image](https://images.openai.com/static-rsc-4/CxjYBMoqqQSV-kTBZAZPXafZvp20Gs1j8qkco5s1LC6xKnVMdhA1fzv1EfFGHwUEseM0yyuFStx_V2fWcBeE0tw0eFMdL9VVfwrICSQECQn5IyeJpSJRGEFiQQzO7u1Hw6QDadh8NsUCfqYpdOyGs81-E9CQwRULQYApwSvb-kJO3Rt0jmSyWHKTcNjlgf1I?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/_1-pw0x9BR_cRlI5uMkkl1pjmmNg_Uc_-YOPhYqk7DFSIzkSTjr4PQsTjrj1Sgcq_7YAF4tcy8uSPFa23ePwAOAy-amuchDZonQUHnnaoqhY3j-nGA68z3eCkm4-S0LTEj2y5GixoVs1iQGkyYa7i_xtmgXuT2Wa27gKXLKKCVzlVRs21Kx3YSP2G7s_-8MY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CiGapdso7fVddeIqnBhB-UjCRBFvLnd-9fnt7OwXhzs7jaIzKMyhtujc84sfEHIiQcys8l0g1u3XpUmx_ZuQ-eITEhAySRfTKwf2k74gCtH3GU4yHgrt3AopEQ5jr1cBJIdLuIqJImI41uWvncwazPpqg67MPpPMRglIrVCdzvwvaW6EnxrJOyji2vlVsU27?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xxkR6tXjUcw7aFosGJ_DDWP1jifDiUv7AqG5kSDzUo5ZytYL1j2dL378J4TV8DzGloJshCaud4Fb102c0deHNfGqOq_UOl1wouiYi5rjh6PWSbKKGcF2HLmvIqXxeIU5Twn05chJzRTTg27o0854JjZ3lyAr5I1EkydArx5aawXoJ_g-LuLQDjlILbbt6J4k?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/GBgeFfBy_p9cpqPdOMnX2EvWb6CnqixvqEBHpeG6lk75473nHCRgnt3k7-LTgVpQKDClduXGENa9BJaRGISvzTKacFZmtF_5PszFFtAoVHFbWxLMHePwRFjtqaB5ViqYXS8Y0dVn6csJEnV8puFaQ_ytabJcYu12B5Y4vALkrY96JcO48g43TS1wGIgzvxAC?purpose=fullsize)

## 1. Overview

Both **Burp Suite** and **OWASP ZAP** are available for:

- Windows
    
- macOS
    
- Linux
    

They are also commonly pre-installed on penetration-testing distributions such as:

- **Kali Linux**
    
- **Parrot OS**
    

HTB's **PwnBox** also comes with both tools pre-installed.

The general workflow is:

```text
Install
   ↓
Launch
   ↓
Create / Select Project
   ↓
Choose Configuration
   ↓
Start Proxy
   ↓
Configure Browser
   ↓
Begin Web Testing
```

---

# 2. Burp Suite Installation

If Burp isn't already installed, download it from the official PortSwigger download page:

[Burp Suite Download Page](https://portswigger.net/burp/releases/?utm_source=chatgpt.com)

Installers are available for:

```text
Windows
Linux
macOS
```

The installation process depends slightly on the operating system but is generally straightforward.

---

## 3. Launching Burp Suite

After installation, Burp can be started in several ways.

### From Linux terminal

```bash
burpsuite
```

### From the application menu

On Kali/Parrot:

```text
Applications
   ↓
Web Application Analysis
   ↓
Burp Suite
```

The exact menu location may vary depending on the desktop environment and distribution.

---

# 4. Running Burp Using the JAR File

Burp can also be distributed as a **JAR file**.

Because Java applications are cross-platform, the JAR can run on operating systems that have a compatible **Java Runtime Environment (JRE)**.

Example:

```bash
java -jar </path/to/burpsuite.jar>
```

For example:

```bash
java -jar ~/Downloads/burpsuite.jar
```

It may also be possible to launch the JAR by double-clicking it, depending on the operating system's Java configuration.

---

# 5. Java Runtime Environment

Both **Burp Suite and ZAP rely on Java**.

Normally, the required Java runtime is included or handled by the application's installer.

If Java isn't available or correctly configured, the application may fail to launch.

You can check Java from Linux with:

```bash
java -version
```

Example output could look similar to:

```text
openjdk version "21.x.x"
```

### ⭐ Important

You don't normally need to manually configure Java when using the standard Burp/ZAP installers, but understanding the dependency is useful when troubleshooting installation problems.

---

# 6. Burp Suite Project Setup

When Burp starts, it asks you to create or select a project.

The available options depend on the edition you're using.

### Community Edition

The Community Edition primarily works with:

> **Temporary projects**

This means the project is intended for the current Burp session rather than being saved as a persistent project on disk.

### Professional / Enterprise

Paid editions provide additional project-management capabilities, including persistent project options.

---

## 7. Temporary vs Persistent Projects

### Temporary Project

Useful when:

- Doing a small lab
    
- Practicing HTB Academy
    
- Testing a small application
    
- You don't need to preserve the session
    
- You want to quickly start Burp
    

Conceptually:

```text
Start Burp
   ↓
Temporary Project
   ↓
Do Testing
   ↓
Close Burp
```

---

### Persistent Project

Useful for larger engagements where you need to preserve testing data.

For example:

```text
Large Web Application
        ↓
Multiple Testing Sessions
        ↓
Large HTTP History
        ↓
Scanner Results
        ↓
Need to Continue Later
        ↓
Persistent Project
```

This becomes especially useful during lengthy penetration tests or when running an **Active Web Scan**.

---

# 8. Burp Configuration Setup

After selecting the project type, Burp asks which configuration to use.

The basic options include:

### Burp Default Configurations

Uses Burp's standard settings.

### Load a Configuration File

Allows you to load previously saved/custom configuration settings.

This can be useful once you've customized Burp for your workflow.

---

## ⭐ Recommended Configuration for Beginners

For normal learning and HTB labs:

```text
Temporary Project
        ↓
Burp Defaults
        ↓
Start Burp
```

This keeps the setup simple.

---

# 9. Burp Configuration Files

As you become more experienced, you may customize things such as:

- Proxy settings
    
- Scope
    
- Intruder settings
    
- Extensions
    
- UI preferences
    
- Scanner configuration
    
- Match/replace rules
    
- Project settings
    

You can then reuse appropriate configuration files instead of configuring everything from scratch.

Conceptually:

```text
Custom Burp Configuration
          ↓
     Save Config
          ↓
      New Session
          ↓
     Load Config
          ↓
    Same Environment
```

This becomes particularly useful for professional engagements.

---

# 10. Basic Burp Startup Flow

Remember this sequence:

```text
Launch Burp
    ↓
Select Project
    ↓
Select Configuration
    ↓
Start Burp
    ↓
Configure Browser
    ↓
Browse Target
    ↓
Capture HTTP Traffic
```

### For HTB/lab environments:

```text
Burp Suite
   ↓
Temporary Project
   ↓
Use Burp Defaults
   ↓
Start Burp
```

This is generally all you need to get started.

---

# 11. OWASP ZAP Installation

![Image](https://images.openai.com/static-rsc-4/4-NFqU9L0GY5-6EwXyql1I9gTbGLqzr88tdM62ra__GNutZ8bfmH7GI4wBq5uWgGTp-LxARgy4efGFZgs5RTJ-fyXRYKrMajq1INawwSPQcoF-d--odvM9oosqOfZJ0DYwHf41RlhyPMtRVHdhanoV10qzIvINzY0N3zLfo7jHEyLlaBfxLS5uJqLSKrIaet?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XWI_xuhIoTFub7V6yiAHEpmoXVcz3Y4694OOZNm-zvlg0hbFXszVUJ2WPeQldsllWaXRQ_eepkNcH-D8TTJIzGYDCi5GiRLf9kdjoJ6oBZm58DApR8RyRj7aZzOSePY4HXWYyQHJKfNDPhPvyiT3D-IaNmAUpDR3Rz-yJZFeVL-KNjVA837Osrfn4pqMfUgW?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/e0Ub661oi6Nbr2nPLATkQt-saBxK5oDSNJe9Re_5v4VdJfp4_A1dYYMVPxmNQZsXQh8br-y7AnYTNsVRITU6lWU98CH9U5owjmB-nSshNAkaFDM0r2CBvHU2Ne0y_0Nr1TMOG3d4wXda5OdKmfujVUSrBY3rC498a9b0drJC7eIw7W97KxWq3RwyIdjAW72d?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OOnpAYnStJtqh2K9UJNaW8AH706utltydQ-_NonX_qOjEsDR-w8AQ4WZkVlSwSeHS2FEu8rNnsUOL_YrWAUTEutB0gHYHkR00RKen6_6ol7V7HjbJ7WGI_pH2HcrnUCE3wvoPDY2l6YuGCTPKbgGsytMYcmLDxaUPY5bmoYl_toWRwPRv0f61IW3ZSLmbviY?purpose=fullsize)

ZAP can be downloaded from its official website:

[OWASP ZAP Download Page](https://www.zaproxy.org/download/?utm_source=chatgpt.com)

Installers are available for common operating systems.

The installation process is generally:

```text
Download
   ↓
Run Installer
   ↓
Follow Installation Steps
   ↓
Launch ZAP
```

---

# 12. Running ZAP

On Linux, ZAP can be launched from the terminal using:

```bash
zaproxy
```

Or through the graphical application menu.

Depending on the distribution, the menu location may differ.

---

# 13. Running ZAP Using Java

Like Burp, ZAP can also be distributed as a cross-platform JAR.

It can be launched with:

```bash
java -jar </path/to/zap.jar>
```

Or, depending on your desktop environment, by double-clicking the JAR.

---

# 14. ZAP Project / Session Setup

When ZAP starts, it asks how the session should be handled.

Unlike the free version of Burp, ZAP provides options for session persistence.

You can generally choose between:

### Persist the Session

Useful when you want to save your work.

### Temporary / Don't Persist

Useful for:

- HTB labs
    
- Small tests
    
- Short experiments
    
- Learning
    
- Temporary assessments
    

For this module's exercises, the recommended choice is:

> **Don't persist / temporary session**

because there is no requirement to preserve the project for several days.

---

# 15. ZAP Session Persistence

Think of the options like this:

```text
                 ZAP Session
                     │
          ┌──────────┴──────────┐
          │                     │
       Persist              Temporary
          │                     │
          ▼                     ▼
   Save session data       Don't save
   Continue later          Short testing
   Large projects          Labs
```

For a large engagement:

```text
Persist Session
      ↓
Save Project
      ↓
Return Later
```

For a quick lab:

```text
Temporary Session
      ↓
Perform Testing
      ↓
Finish
```

---

# 16. Burp vs ZAP Setup

|Setup Feature|Burp Suite|OWASP ZAP|
|---|---|---|
|Windows|✅|✅|
|macOS|✅|✅|
|Linux|✅|✅|
|Kali|Commonly available|Commonly available|
|Parrot|Commonly available|Commonly available|
|PwnBox|Pre-installed|Pre-installed|
|Java-based|✅|✅|
|Terminal launch|`burpsuite`|`zaproxy`|
|JAR available|✅|✅|
|Temporary sessions|✅|✅|
|Persistent sessions|Edition-dependent|✅|

---

# 17. Dark Mode / Theme Settings 🌙

Both applications allow you to customize their appearance.

## Burp Suite

Navigate to:

```text
Burp
  ↓
Settings
  ↓
User interface
  ↓
Display
  ↓
Theme
  ↓
Dark
```

---

## OWASP ZAP

Navigate to:

```text
Tools
  ↓
Options
  ↓
Display
  ↓
Look and Feel
  ↓
Flat Dark
```

This is purely a UI preference and doesn't affect the proxy's functionality.

---

# 18. Important Commands to Remember ⭐

### Burp

```bash
burpsuite
```

### ZAP

```bash
zaproxy
```

### Java version

```bash
java -version
```

### Burp JAR

```bash
java -jar /path/to/burpsuite.jar
```

### ZAP JAR

```bash
java -jar /path/to/zap.jar
```

---

# 19. Troubleshooting Basics

If Burp/ZAP doesn't start, check Java first:

```bash
java -version
```

If Java isn't installed, your Linux distribution may provide OpenJDK packages.

You can also check whether the application command exists:

```bash
which burpsuite
```

and:

```bash
which zaproxy
```

If the command returns a path, the executable is available in your `$PATH`.

---

# 🧠 20. Important Things to Remember

### Burp Suite

**Download:**

[PortSwigger Burp Releases](https://portswigger.net/burp/releases/?utm_source=chatgpt.com)

**Launch:**

```bash
burpsuite
```

**JAR:**

```bash
java -jar /path/to/burpsuite.jar
```

**Beginner setup:**

```text
Temporary Project
        ↓
Use Burp Defaults
        ↓
Start Burp
```

---

### OWASP ZAP

**Download:**

[ZAP Download](https://www.zaproxy.org/download/?utm_source=chatgpt.com)

**Launch:**

```bash
zaproxy
```

**JAR:**

```bash
java -jar /path/to/zap.jar
```

**Beginner setup:**

```text
Temporary / Don't Persist
        ↓
Start ZAP
```

---

# 🔥 Quick Revision

```text
┌─────────────────────────────────────────┐
│             BURP SUITE                  │
├─────────────────────────────────────────┤
│ Terminal: burpsuite                     │
│ JAR: java -jar burpsuite.jar            │
│ Community → Temporary projects          │
│ Pro → Persistent project options        │
│ Default config → easiest setup          │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│               OWASP ZAP                 │
├─────────────────────────────────────────┤
│ Terminal: zaproxy                       │
│ JAR: java -jar zap.jar                  │
│ Free & Open Source                      │
│ Temporary sessions available            │
│ Persistent sessions available           │
└─────────────────────────────────────────┘
```

## ⭐ Core takeaway

**Installation → Launch → Project/Session → Configuration → Start → Proxy setup**

For your HTB labs, the setup will usually be very simple:

**Burp:** `Temporary Project → Burp Defaults → Start Burp`

**ZAP:** `Temporary/Don't Persist → Start ZAP`

The **next critical part** is configuring the browser to send its HTTP/HTTPS traffic through the proxy.