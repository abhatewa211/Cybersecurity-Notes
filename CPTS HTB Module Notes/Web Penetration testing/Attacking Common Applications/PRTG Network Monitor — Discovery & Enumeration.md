![Image](https://images.openai.com/static-rsc-4/5Ke_9KoXKgF3fGEDXL16dxIO0xqnAVVeHRR-0TuLYqIGATlx4-YndSMG-XaEr_IKar2D1r5EDhi0PD7sQZf9fna9yItD0ontdf23IaqoxxTbQYo38TmwxGjsW98qw-T6z_Z0h53LBLHTKmR08128Pkku3Z0rcO3J-N-h5nApGwvykoh6TnYagQPBUhWAM9BM?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8apoRF1PihQ4GRfxESgu_ee9OHaaP7raCbp_mDyA39pjJ_4h8fw9cM9raD7byVBqKCnP71VsCnf__mtQuJZYXo2wZTEVzHSMHeU1gYJqEQUqrP9zVJ2DIV7qY7LmPsxNm52pfEN1TFBaI233lk8_LO1rQmSrcj89araqE6-dxBmQ6eNKTJbTmFx0UAPf0l0Y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/W0_zDBJ9H45lzUCSnqMO-QjkQwqmo9IKRoeYZKDiXRxiVQyKbMW-AH8fagoht2FSaInvhd3L9ZFKCLPaZnaMkx3vnWUGXthWk32N4Jzi9fGpBA3eZiAP4dIidSZLGa2MlBsiFz8iR3ThYEpOcW9UpmG--ii-n1sR4C53yET6szqPjqHiPRwqN50306NeQqVE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HdcNOoCWrtxjrsTFbggPa_2UQy-6JDRe_a_PbRAS_zgj74F8QNNdRYED68OPxe6eHehBM-YD32PVFW6YeAVUa3I2VEwXNRW4w2psrmEcE1pvb527DIUm5BSvLDxZQMxk_-R7vseHqXV1iz3DHCNKgmue6BugfI-e7JVEhEWJP8MwOf1Dn7DYyv_05j_NkT5f?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/V9mdqGIVmMtLh1cbViN_ehHuXnL2f2y2Fm5n98qA_hCXhIzUIQnEJA9VkEyYg03wJZvJnrXwt84cJKor4bGCJuDUmwX4oA0HrFcUYKAX735Gw5BDYSLUBFE8Rf2xMiCdimtPZ30lpTw1hYYgntNOOge_OW5aCOrSO2IHvZogKDZmLABgsy0oafimXlek7d12?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Zupf7M2w4b4UkvCtnscbuTziRcC8rQ1-8ts9S7bEVXKexGQQ3mkpmvRXVeuYPLmWy7tbSqA--1HXctECGPtTJrUzBp0WhIEvvUF8TLD1vxHfezI5ekyj9Q2eR9vJREH5d9MbLf1qqnf7jE3tY1SP0CGcXXXtvttOS6710tvoFylCNDq5LgR2AJdn-oOTi7qz?purpose=fullsize)

## 1. What is PRTG?

PRTG Network Monitor is **agentless network-monitoring software**.

It can monitor:

- Bandwidth usage
    
- Uptime
    
- Routers
    
- Switches
    
- Servers
    
- Other network hosts
    

PRTG can automatically discover devices and gather information using protocols such as:

```text
ICMP
SNMP
WMI
NetFlow
REST API
```

The first version was released in **2003**. A free version released in 2015 was limited to **100 sensors** monitoring up to **20 hosts**.

---

# 2. Why PRTG Is Interesting to a Pentester

PRTG is commonly encountered during **internal penetration tests**, although external exposure is less common.

The module notes that PRTG has had **26 CVEs**, but only four had easily discoverable public PoCs at the time of writing:

- 2 × XSS
    
- 1 × DoS
    
- 1 × authenticated command injection
    

The important vulnerability for this module is the **authenticated command injection**.

So the general attack path is:

```text
PRTG discovered
      ↓
Fingerprint/version
      ↓
Find credentials
      ↓
Authenticated access
      ↓
CVE-2018-9276
      ↓
Command injection
      ↓
Windows command execution
```

---

# 3. Discovery with Nmap

PRTG commonly appears on web ports such as:

```text
80
443
8080
```

The web interface port can also be changed by an administrator.

The module performs a full TCP scan:

```bash
sudo nmap -sV -p- --open -T4 10.129.201.50
```

Relevant result:

```text
8080/tcp open  http  Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
```

This is a strong fingerprint:

```text
Indy httpd
+
Paessler PRTG bandwidth monitor
+
8080
```

The scan also identifies the host as Windows.

### CPTS point

Don't only look at port numbers.

The **service/version banner** can immediately tell you:

```text
Product → PRTG
Version → 17.3.33.2830
OS → Windows
```

---

# 4. EyeWitness / Visual Discovery

PRTG can also appear in tools such as **EyeWitness**.

The module's EyeWitness result exposes:

```text
prtgadmin:prtgadmin
```

as the default credentials displayed on the login page.

The module notes that these credentials are often left unchanged.

This gives us a useful enumeration workflow:

```text
Nmap
  ↓
Identify PRTG
  ↓
EyeWitness
  ↓
Inspect login page
  ↓
Check displayed/default credentials
```

---

# 5. PRTG Login

The module confirms the service by browsing to:

```text
http://10.129.201.50:8080/index.htm
```

The login page identifies the application as PRTG.

The credentials initially considered are:

```text
prtgadmin:prtgadmin
```

However, these don't work in the example.

After a few attempts, the module successfully authenticates with:

```text
prtgadmin:Password123
```

### Lesson

Don't stop after one default credential fails.

The authentication-testing methodology becomes:

```text
Known default
      ↓
Fails
      ↓
Try authorized common weak credentials
      ↓
Valid credentials
      ↓
Authenticated PRTG access
```

---

# 6. Version Enumeration ⭐

This is where the attack becomes much more interesting.

Nmap reports:

```text
17.3.33.2830
```

The module identifies this as likely vulnerable to:

```text
CVE-2018-9276
```

The vulnerability is an **authenticated command injection** affecting the PRTG System Administrator web console in versions before:

```text
18.2.39
```

The module then confirms the version using `curl`:

```bash
curl -s http://10.129.201.50:8080/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version
```

Relevant output:

```text
<link rel="stylesheet" type="text/css" href="/css/prtgmini.css?prtgversion=17.3.33.2830__" media="print,screen,projection" />

<span class="prtgversion">&nbsp;PRTG Network Monitor 17.3.33.2830 </span>
```

---

# 7. Version → CVE Mapping

This is the important reasoning step:

```text
Product:
PRTG Network Monitor

Version:
17.3.33.2830

Known vulnerability:
CVE-2018-9276

Affected:
Before 18.2.39

Result:
Version appears vulnerable
```

So instead of blindly launching an exploit:

```text
Scan
 ↓
Identify product
 ↓
Identify exact version
 ↓
Research vulnerability
 ↓
Compare affected version range
 ↓
Determine authentication requirement
 ↓
Exploit if applicable
```

That's the **CPTS methodology** you want to develop.

---

# 8. Why CVE-2018-9276 Matters

The vulnerability is an **authenticated command injection**.

The module explains that while creating a new notification, the:

```text
Parameter
```

field is passed directly into a **PowerShell script without input sanitization**.

That creates this conceptual chain:

```text
Authenticated PRTG user
          ↓
Create notification
          ↓
Execute Program
          ↓
Parameter
          ↓
PowerShell
          ↓
Unsanitized input
          ↓
Command injection
          ↓
OS command execution
```

🔥 **This is the key vulnerability mechanism.**

---

# 9. CPTS Attack Flow

```text
┌──────────────────────┐
│ Discover PRTG        │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Nmap / EyeWitness    │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Identify Version     │
│ 17.3.33.2830         │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Check CVE-2018-9276  │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Obtain Authentication│
│ prtgadmin:...        │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Notifications        │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Execute Program      │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Parameter Injection  │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ PowerShell           │
└──────────┬───────────┘
           ↓
        Command
        Execution
```

---

# 🎯 CPTS High-Value Facts

### PRTG

- Network monitoring software
    
- Agentless
    
- Developed by Paessler
    
- First version: **2003**
    
- Common web ports: **80, 443, 8080**
    

### Fingerprinting

```text
8080/tcp
Indy httpd
Paessler PRTG bandwidth monitor
```

### Credentials

Default example:

```text
prtgadmin:prtgadmin
```

Lab example:

```text
prtgadmin:Password123
```

### Vulnerability

```text
CVE-2018-9276
```

Type:

```text
Authenticated command injection
```

Affected:

```text
PRTG Network Monitor
before 18.2.39
```

Lab version:

```text
17.3.33.2830
```

### Vulnerable functionality

```text
Notifications
      ↓
Execute Program
      ↓
Parameter
      ↓
PowerShell
```

---

# 🧪 Enumeration Checklist

## Discovery

-  Run Nmap
    
-  Check ports `80`, `443`, `8080`
    
-  Inspect service banners
    
-  Identify PRTG
    
-  Determine OS
    
-  Use EyeWitness/browser for visual confirmation
    

## Authentication

-  Check default `prtgadmin:prtgadmin`
    
-  Test authorized weak credentials
    
-  Determine privilege level
    

## Version

-  Identify version through Nmap
    
-  Confirm version through HTTP content
    
-  Map version against CVEs
    
-  Determine whether authentication is required
    

## Exploitation Analysis

-  Examine Notifications functionality
    
-  Look for `EXECUTE PROGRAM`
    
-  Understand the `Parameter` field
    
-  Determine whether input reaches PowerShell
    
-  Validate command injection in the authorized lab
    

---

# ⚡ Quick Revision

```text
PRTG
│
├── Network monitoring software
│
├── Common ports
│   ├── 80
│   ├── 443
│   └── 8080
│
├── Fingerprint
│   └── Indy httpd / Paessler PRTG
│
├── Default credentials
│   └── prtgadmin:prtgadmin
│
├── Example weak credentials
│   └── prtgadmin:Password123
│
├── Version
│   └── 17.3.33.2830
│
├── CVE
│   └── CVE-2018-9276
│
├── Vulnerability
│   └── Authenticated command injection
│
└── Key functionality
    └── Notifications
         ↓
       Execute Program
         ↓
       Parameter
         ↓
       PowerShell
```

### 🔥 The exam memory hook

**`8080 → PRTG → credentials → version → CVE-2018-9276 → Notifications → Execute Program → Parameter → PowerShell → command injection.`**

The next part of your material is where this turns the authenticated command injection into actual host-level access.