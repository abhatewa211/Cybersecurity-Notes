## 1. What is Apache Tomcat?

![Image](https://images.openai.com/static-rsc-4/zaRzRho3WX1AZoYl49HVIYOG8jl5op8bt_FK7DXih0MjnGPp9oGjF3Kjo0CBkB8siJeuG0v0csFdgdfY-YDdrDktVwpiHyE9Wq01diGqe9uRJ6U9S9J_9Mr3UxyaA-yv6pzF9hcIFM_O9I0koY_zjCL7JrH6Ge_B6zbgixIMc3kjQozJFEuRAjKAU-f_dZqL?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/z8Gg-wS2kevYsIemCE-mWCTGNDDSedgQkyAUhXbZTpEbdBEp_JjEc5FX-nTO0FNM7bLdlz_2CAWN4mBqx0nR4-b9TFpToREWQUPY1y4KyZPwsBWGtos4-SEnpDe-oUnxOr_DsgTFgFNX59Jh4kmC5nlkWgaMoY9SAlvpnIr8x_5REJxv8Mn7rMQi6DzH7s_4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/IqDbxPGgQthQYWUi6AE8Hdbc0baFmXVBx1AkngPwjmX3-hfEUamJ1rGzs0hpTkziWgJkv0JJdEd_abcZOrZiKup7ojw6bJIinaPgHEhhMqNHHexj4MlfdUqt-G-lyl2V5wxPfAfhwj9M1AdVUcdYy1qmMLF1eyTqdBeoEDPT0k82-tgniK6iXgxeZnfiUxN6?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ElvGC3vIzCbTx4giEdt1ksjFRgq791p2qUFQqPuUjcBPFeAq0T_qD-7oDBVo_KmElpGCIyb073aBWvntHYb5GWVWSqtJBfk_l6vJJDbNffrU-VGnsPFLOnVKeWMVupXxZqClS1GDEDhJiIeNqAKXEIvGPBXMRUX28kSOZbiKLWWoXat60YzohP-InO-CWmkx?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/uGE9wY1_zJSIxNQhDlI-iREcGGapuezJo6ykb-0RIGw688xgnPyr_XwG-jrQdTjxit4gnbbSipiTZ11kpyMqka-Dr8ESRaA-Dg_dwmG0nDFMp0LO62kMATR5n9MDdMTd907CDYo5PgyG_o5_NHcr2SXyeYLH7KqoHEYK_H-9LHbd3YN2kDYRzQZf3X6kuY84?purpose=fullsize)

Apache Tomcat is an **open-source web server** designed to host applications written in **Java**.

It was initially designed to run:

- **Java Servlets**
    
- **JavaServer Pages (JSP)**
    

Its popularity expanded with Java-based frameworks and tools such as:

- Spring
    
- Gradle
    

The module notes that Tomcat is widely deployed and can be an important target during penetration tests.

### ⭐ Pentesting importance

Tomcat is often less exposed directly to the Internet than traditional web servers, but it is commonly encountered during **internal penetration tests**.

A particularly important observation from the module:

> Tomcat installations frequently use **weak or default credentials**.

This makes Tomcat a potentially valuable foothold into an internal network.

---

# 🎯 2. Tomcat Pentesting Mindset

Think of the assessment like this:

```text
                TOMCAT
                   │
                   ▼
          Fingerprint Server
                   │
                   ▼
            Identify Version
                   │
                   ▼
        Enumerate Web Directories
                   │
          ┌────────┴────────┐
          ▼                 ▼
      /manager         /host-manager
          │                 │
          └────────┬────────┘
                   ▼
          Test Credentials
                   │
             ┌─────┴─────┐
             ▼           ▼
          Failure      Success
             │           │
             ▼           ▼
        Brute Force    WAR Upload
                         │
                         ▼
                      JSP Shell
                         │
                         ▼
                         RCE
```

---

# 🔎 3. Discovery / Footprinting

During an external penetration test, tools such as **EyeWitness** may identify a Tomcat host as a high-value target.

However:

> **Tool identification is not enough. Always manually confirm the technology before planning exploitation.**

The module's example target is:

```text
http://app-dev.inlanefreight.local:8080/
```

Tomcat can often be identified through the **HTTP Server header**.

If a reverse proxy hides the header, requesting a deliberately invalid page may reveal the Tomcat version through the default error page.

---

# 🧪 4. Version Identification Through an Invalid URL

Example:

```text
http://app-dev.inlanefreight.local:8080/invalid
```

The resulting error page identifies:

```text
Apache Tomcat 9.0.30
```

![Image](https://images.openai.com/static-rsc-4/lN3CP-2edfPcWkTA-_zp8JFmrKFVrbg5lpD1Vb1rK14HSVUmOJG_cd8-w6Xt9w8fg_vnEJpgBSmb0VVnnfczCdz8vbLv2WadbmOzDqtxSIGrhYOpZvxc4IMqtdXWD6ebn0rjS-SnD9Fm_CAbFcode3udGcFdQNj83QeqGY8iFBs-FYyAvjck7uHyF6619vCG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/LBVDi2KXJB-XTIt-3e5g0_G_r_e7xNBJlSO7rxnOVzp-jGE4wHZrpmkkquSAbRRbKz8ZVWL2GLCEWJHHtv_aNvF_EWbf4YNvg1NMWMm2rowEHajZQf89qc12ECjtLUwLLmEqKhmCkQPzzDQAMN-eOb-_rr5IcIYOJ86ORVnholwqqyinKW9A4YD-Jy8VUvQV?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Yz11suRPFZQBPJkUBmWbm3bSPv11z7OzBA5z1JVhLf6NOPfS5bYLodqSs2xp8Yk0oxpirvkRGpe8bgCU4LhtDaOdJa-OjN8G8mO5JT18L8ROKNzxwPOah91CZg_-YaVObKIS4U5kZwYAe2ae2fMDcxI0YephEM-i0Qrf_3EotHhOLCEF4AB2MMPT-Rd_shGC?purpose=fullsize)

### Why does this work?

Even when a reverse proxy hides the normal HTTP `Server` header:

```text
Normal request
     ↓
Reverse proxy
     ↓
Header hidden
```

an error page may still expose:

```text
Tomcat 9.0.30
```

Therefore:

> **Error responses themselves are valuable enumeration sources.**

---

# 📚 5. `/docs` — Another Fingerprinting Method

Administrators may customize the default error page.

If the version isn't exposed there, check:

```text
/docs
```

Example:

```text
http://app-dev.inlanefreight.local:8080/docs/
```

The module demonstrates:

```bash
curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat
```

Output includes:

```html
<title>Apache Tomcat 9 (9.0.30) - Documentation Index</title>
```

### ⭐ Important

The `/docs` page may remain accessible because it is part of the default Tomcat installation.

So remember:

```text
Tomcat fingerprinting
        │
        ├── HTTP Server header
        ├── Invalid URL / error page
        └── /docs
```

---

# 🗂️ 6. Tomcat Directory Structure

Understanding the Tomcat filesystem is **extremely important** for enumeration.

```text
Tomcat
│
├── bin
│
├── conf
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── tomcat-users.xml
│   ├── tomcat-users.xsd
│   └── web.xml
│
├── lib
│
├── logs
│
├── temp
│
├── webapps
│   ├── manager
│   │   ├── images
│   │   ├── META-INF
│   │   └── WEB-INF
│   │       └── web.xml
│   │
│   └── ROOT
│       └── WEB-INF
│
└── work
    └── Catalina
        └── localhost
```

---

# 🧠 7. What Each Directory Does

|Directory|Purpose|
|---|---|
|`bin`|Scripts and binaries required to start/run Tomcat|
|`conf`|Tomcat configuration files|
|`lib`|JAR libraries needed by Tomcat|
|`logs`|Log files|
|`temp`|Temporary files|
|`webapps`|Default webroot; hosts applications|
|`work`|Runtime cache/data|

The most interesting areas from a pentesting perspective are generally:

```text
conf/
webapps/
WEB-INF/
```

because they can contain application configuration, routes, classes, libraries, and potentially sensitive information.

---

# 🔥 8. `tomcat-users.xml`

One of the most important files is:

```text
conf/tomcat-users.xml
```

This file stores:

- Users
    
- Passwords
    
- Assigned roles
    

It controls access to:

```text
/manager
/host-manager
```

### ⭐ Remember this

```text
tomcat-users.xml
       ↓
Users + Passwords + Roles
       ↓
Manager / Host Manager access
```

---

# 👑 9. Tomcat Manager Roles

The module lists four important built-in roles:

|Role|Access|
|---|---|
|`manager-gui`|HTML GUI + status pages|
|`manager-script`|HTTP API + status pages|
|`manager-jmx`|JMX proxy + status pages|
|`manager-status`|Status pages only|

### Easy way to memorize

```text
manager-gui
    ↓
Graphical interface

manager-script
    ↓
HTTP API

manager-jmx
    ↓
JMX

manager-status
    ↓
Status only
```

---

# 🔑 10. Weak Credentials Example

The module provides this example:

```xml
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />
```

And:

```xml
<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />
```

Therefore, example weak/default credentials are:

```text
tomcat : tomcat
admin  : admin
```

### 🚨 Pentesting takeaway

When you discover a Tomcat Manager interface, **check for authorized/default credentials before jumping immediately to brute force**.

The module specifically mentions trying credentials such as:

```text
tomcat:tomcat
admin:admin
```

---

# 🌐 11. `webapps` — The Web Application Directory

Tomcat's default webroot is:

```text
webapps/
```

Each application inside `webapps` generally has a structure similar to:

```text
webapps/customapp
├── images
├── index.jsp
├── META-INF
│   └── context.xml
├── status.xsd
└── WEB-INF
    ├── jsp
    │   └── admin.jsp
    ├── web.xml
    ├── lib
    │   └── jdbc_drivers.jar
    └── classes
        └── AdminServlet.class
```

---

# 🚨 12. `WEB-INF/web.xml` — VERY IMPORTANT

The most important file in the application structure is:

```text
WEB-INF/web.xml
```

This is called the:

> **Deployment Descriptor**

It contains information about:

- Application routes
    
- Servlets
    
- Classes responsible for processing those routes
    

---

# 🧩 13. Why `web.xml` Matters

Consider:

```xml
<servlet>
    <servlet-name>AdminServlet</servlet-name>
    <servlet-class>com.inlanefreight.api.AdminServlet</servlet-class>
</servlet>

<servlet-mapping>
    <servlet-name>AdminServlet</servlet-name>
    <url-pattern>/admin</url-pattern>
</servlet-mapping>
```

This tells us:

```text
/admin
   ↓
AdminServlet
   ↓
com.inlanefreight.api.AdminServlet
```

The corresponding compiled class would be located at:

```text
classes/com/inlanefreight/api/AdminServlet.class
```

---

# 🧠 14. Java Package → Filesystem Mapping

Java uses dot notation:

```text
com.inlanefreight.api.AdminServlet
```

This maps to:

```text
com/
└── inlanefreight/
    └── api/
        └── AdminServlet.class
```

So:

```text
com.inlanefreight.api.AdminServlet
```

becomes:

```text
classes/com/inlanefreight/api/AdminServlet.class
```

### ⭐ CPTS point

When analyzing Java applications, understanding package names can help you map application functionality to filesystem locations.

---

# 🔐 15. Why `WEB-INF` Is Interesting

The module highlights that compiled classes may contain:

- Business logic
    
- Sensitive information
    

and vulnerabilities in those classes can potentially lead to **total compromise of the website**.

The `WEB-INF` directory can contain:

```text
web.xml
JSP files
Libraries
Compiled Java classes
```

Therefore:

```text
WEB-INF
   ↓
Application internals
   ↓
Potentially sensitive information
```

---

# 📄 16. JSP vs PHP

Tomcat uses:

```text
JSP
```

or:

> **Jakarta Server Pages**

The module compares JSP to PHP files on an Apache server.

Conceptually:

```text
PHP application
     ↓
.php

Tomcat / Java application
     ↓
.jsp
```

---

# 🏠 17. Tomcat Manager & Host Manager

After fingerprinting Tomcat, one of the next steps is to look for:

```text
/manager
/host-manager
```

The module specifically recommends these as important enumeration targets.

---

# 🔎 18. Directory Enumeration With Gobuster

Example:

```bash
gobuster dir -u http://web01.inlanefreight.local:8180/ \
-w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```

The scan finds:

```text
/docs       (Status: 302)
/examples   (Status: 302)
/manager    (Status: 302)
```

### What did we discover?

```text
Target :8180
   │
   ├── /docs
   ├── /examples
   └── /manager
```

The `/manager` discovery is particularly important because it may provide access to Tomcat's management functionality.

---

# ⚔️ 19. Attack Path From Enumeration

The module's overall progression is:

```text
                Tomcat Discovered
                       │
                       ▼
                Fingerprint Version
                       │
                       ▼
               Find /manager
                       │
                       ▼
              Find /host-manager
                       │
                       ▼
              Test Weak Credentials
                       │
             ┌─────────┴─────────┐
             │                   │
          Failure              Success
             │                   │
             ▼                   ▼
       Brute Force          Manager Access
                                 │
                                 ▼
                            Upload WAR
                                 │
                                 ▼
                             JSP Shell
                                 │
                                 ▼
                                RCE
```

The source explicitly states that successful Manager access can allow uploading a **WAR (Web Application Resource / Web Application ARchive)** containing a JSP web shell, resulting in remote code execution.

---

# 📦 20. WAR Files

WAR stands for:

> **Web Application Resource / Web Application ARchive**

A WAR file packages a Java web application so it can be deployed by Tomcat.

In the context of this module:

```text
Tomcat Manager access
        ↓
WAR upload
        ↓
JSP web shell
        ↓
Remote Code Execution
```

This is one of the most important attack chains to understand.

---

# 🐚 21. JSP Web Shell Concept

The module does not yet walk through the full WAR exploitation process in this section, but establishes the concept:

```text
Valid Tomcat Manager credentials
             ↓
       Manager access
             ↓
         WAR upload
             ↓
       JSP web shell
             ↓
            RCE
```

So the key prerequisite is often:

> **Access to a sufficiently privileged Tomcat management interface.**

---

# 🧠 22. Enumeration Checklist

When you encounter Tomcat, run through this checklist:

### 🔍 Fingerprinting

-  HTTP `Server` header
    
-  Invalid URL
    
-  `/docs`
    
-  Error page
    
-  Identify version
    

### 📂 Application enumeration

-  `/manager`
    
-  `/host-manager`
    
-  `/examples`
    
-  Other applications under `webapps`
    

### 🔐 Authentication

-  Check whether authentication is enabled
    
-  Test authorized/default credentials
    
-  `tomcat:tomcat`
    
-  `admin:admin`
    
-  Identify available roles
    

### 🧩 Application analysis

-  `WEB-INF/web.xml`
    
-  JSP files
    
-  Java classes
    
-  JAR libraries
    
-  Configuration files
    

### ⚔️ Exploitation

-  Search version-specific vulnerabilities
    
-  Abuse Manager functionality if authorized
    
-  WAR deployment
    
-  JSP execution
    
-  RCE
    

---

# 🧭 23. Important Tomcat Paths

|Path|Why it's interesting|
|---|---|
|`/docs`|Fingerprinting / documentation|
|`/manager`|Tomcat management interface|
|`/host-manager`|Virtual host management|
|`/examples`|Default example applications|
|`/WEB-INF/web.xml`|Deployment descriptor|
|`/WEB-INF/classes/`|Compiled application classes|
|`/WEB-INF/lib/`|Application JAR libraries|
|`conf/tomcat-users.xml`|Users and roles|

---

# ⭐ 24. HIGH-VALUE CPTS NOTES

These are the things I'd **actually memorize**.

### 🥇 #1 — Tomcat is Java

```text
Tomcat
 ↓
Java
 ↓
Servlets + JSP
```

---

### 🥇 #2 — Fingerprinting

```text
Server header
     ↓
Invalid URL
     ↓
/docs
```

---

### 🥇 #3 — Important directories

```text
conf
webapps
WEB-INF
```

---

### 🥇 #4 — Important configuration

```text
tomcat-users.xml
```

Contains:

```text
Users
Passwords
Roles
```

---

### 🥇 #5 — Manager roles

```text
manager-gui
manager-script
manager-jmx
manager-status
```

---

### 🥇 #6 — Important endpoints

```text
/manager
/host-manager
/docs
/examples
```

---

### 🥇 #7 — Important application file

```text
WEB-INF/web.xml
```

Contains:

```text
Routes
Servlets
Classes
```

---

### 🥇 #8 — Potential attack chain

```text
Weak credentials
      ↓
/manager
      ↓
WAR upload
      ↓
JSP web shell
      ↓
RCE
```

---

# 🧪 25. COMMAND CHEAT SHEET

### Fingerprint Tomcat

```bash
curl -s http://TARGET:8080/docs/ | grep Tomcat
```

### Check an invalid page

```text
http://TARGET:8080/invalid
```

### Directory enumeration

```bash
gobuster dir -u http://TARGET:8180/ \
-w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
```

### Important directories to manually check

```text
/docs
/examples
/manager
/host-manager
```

---

# 🗺️ 26. COMPLETE TOMCAT METHODOLOGY

![Image](https://images.openai.com/static-rsc-4/LPkrNlMwz4tgY_a_gHIZ5ius2SB-DzS6AvhprDqDmsW0l5BYUsJnHv_nx-HHe4qwwutx6OkCmxC_clmaWpQo73jaFw9m8nYbE4UzpXFqoUJZs808UOXDL3DVwg8jFPAywtIZTghGT82_4Tx1jvWztu3aV2eqvng_zkxvBsOufLo1Ytrtf69RnKszGFG_06Zk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AEDBSb-zUL6BqS-TRqEa39Qu9RzVmkSMlD6OggvSyi_zUIpOT7Fj5n42k8sdJAafmFQBTnKpo25-VWxMqOojs2pR0SgfWlDBjTeuIS_SgBcXzqPiKsyWXAVAlC9Ip_o3XyJKAXAdyn7TqWSuJbl8JuJbxACq8rv4JXXqp610lpmPBU24DV_7RcVE0_kyKZ1q?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/k2ngOAijcWuHS3dSaqcDJmxZAe6M7jKqx0Eby-eoIiY0wxJ9VFV8wLDrozxzTkj8E7cEGvxIeuBDKfbBg-64DvJdtBxECnCV4hb48yVexedh9kqJCs2WZsK9FXlbe9J-r47K05OtoNEtV8epqLVMTzDqllnptXbk_sUrGZWafmR9Uik9Rpq06_s6FLaHyzQB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/i5NgU4ZH24yDzGBUNKWytmk2U8QJKrrGvMPsSQXTPvXE03CyNnwroKyEjX04lWUe1p5kVf8eYUHFoweApFf-d_PbRjS_umWdHcVBoAOHzQI3J2E5gZdOU4_gtX7YKM_YRS8DIH9nUHzVY8f0Y6h03N4tra4GytIHJ5eSCiPZsmRu3k386D4-FOQ9Y8_aDkKi?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cmua_NPDWqrogp9sODWhIkuBVPloJ-Fq8Xw_h_T-UxFfLOUpGBR3vCaqC08xajWywvsatc8jtayeXPEYvit8fN72MXhqkPjnTumN2WPpqMfdkf6oi9aPjr6Z9c0Cg04eb45yx4znaPrgUEcAZ-NHx0cjFPCJEBMtGMoDZnR9jyo83ksnih563uIOotSgWlHg?purpose=fullsize)

```text
                    ┌───────────────┐
                    │    TARGET     │
                    └───────┬───────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │ Identify Tomcat │
                   └────────┬────────┘
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
       Server Header    Invalid URL      /docs
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                      Version Found
                            │
                            ▼
                  Directory Enumeration
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
          /docs          /manager     /host-manager
                            │
                            ▼
                    Authentication
                            │
                   ┌────────┴────────┐
                   ▼                 ▼
                Failed            Success
                   │                 │
                   ▼                 ▼
              Brute Force       WAR Upload
                                     │
                                     ▼
                                  JSP Shell
                                     │
                                     ▼
                                    RCE
                                     │
                                     ▼
                            Internal Enumeration
```

---

# 📝 27. 30-SECOND REVISION

If you have **30 seconds before a CPTS question**, remember:

```text
TOMCAT
│
├── Java web server
├── JSP / Servlets
│
├── Fingerprint
│   ├── Server header
│   ├── Error page
│   └── /docs
│
├── Important paths
│   ├── /manager
│   ├── /host-manager
│   └── /examples
│
├── Important files
│   ├── tomcat-users.xml
│   └── WEB-INF/web.xml
│
├── Important roles
│   ├── manager-gui
│   ├── manager-script
│   ├── manager-jmx
│   └── manager-status
│
└── Attack path
    Weak creds
       ↓
    Manager
       ↓
    WAR
       ↓
    JSP
       ↓
    RCE
```

## 🔥 Final takeaway

The **core lesson of this module isn't simply "find Tomcat."**

It's:

> **Fingerprint → enumerate the application → identify management interfaces → understand authentication/roles → look for weak credentials → investigate Tomcat's built-in deployment functionality → determine whether authorized access can lead to code execution.**

And for CPTS, make sure you know these four things cold:

**`/manager` + `tomcat-users.xml` + `WEB-INF/web.xml` + WAR/JSP deployment.**