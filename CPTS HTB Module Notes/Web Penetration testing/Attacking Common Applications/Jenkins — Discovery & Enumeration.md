![Image](https://images.openai.com/static-rsc-4/AwLlm5XCsucMjNM46lV6oojn3ZRmW20LtfJB1DKhePg3rvxP6V0FKgrnYPJyEU_JknndeB8hrz5AZJCycxLalIcXM28RbNM7SXAS9-XR2kiGiQSTHRos_83BU1QzGEj34gojmLG84ti65qeyvWxmDf0OMH8F6c4jQr1z_QG3CydfCiuDFz3ufYacbIUpeZ5V?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wWCfgSVnz9SesdpE9080AlVt9B6bJo90Ztuk4arHtKryqswKk5tgKGLYDK7FvIHmN1j-3SvsgLWx5JbBN-tWnzLTdFJD_8Z1otivYy8oqDts0YLeQq4a6B6KYdDZq-PmTnFI8ic4HXrmPRChlkjsQLiZxV0Ai0qnTvMWQStD27fRPVlkklTYW-ZMM0mgi9P1?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/h7i1Qf6BNAikh3WBzEwW2hFPfd_DrRAeAWn5_yWy2yZ3FwuzZyUH9qgp9paFHoJINBbYYzdkAha8L5-TG7ClTi6XMNSWyDT2ofUIH0VuFHd3RzGRtYW_-ykeu70i5dlFUrsM-gg8MjZ0yp5DMUjABAmaGmh58q7Xc0rM7wHseuDB8VQH_01TFTAx-6ELDqpI?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xZ_c15dijfUIh-GRmkBw5gtatqlandtMBhZWcPQCyOeseIpUfyfv0wI4Q6mp4KWJEo58uw7uQtmyG9iKWwjSpLQBoxj0rehvGWx1xekcQi0Xi2dXAj75zpydX5OcSZvG9s6tjqk8yMCW46o6sqZyOZ7W-8DE4sUpNDCg7kmaP_JRWCnPnk_vROjPj8FfzUck?purpose=fullsize)

## 1. What is Jenkins?

Jenkins is an **open-source automation server written in Java** that helps developers continuously build and test software projects.

It is a **server-based system** that runs in servlet containers such as **Tomcat**.

Jenkins is a **Continuous Integration (CI)** server.

### Important facts

|Fact|Details|
|---|---|
|Original name|**Hudson**|
|Originally released|**2005**|
|Renamed|**2011**|
|Reason|Dispute with Oracle|
|Language|Java|
|Server type|Automation / CI server|
|Plugins|**300+**|
|Example users|Facebook, Netflix, Udemy, Robinhood, LinkedIn|
|Reported adoption|86,000+ companies|

### Why Jenkins matters to a pentester

Jenkins can be extremely valuable during an internal penetration test because it may provide a route to **remote code execution (RCE)**.

The module specifically highlights an important scenario:

```text
Jenkins
   │
   ▼
Access Jenkins
   │
   ▼
Obtain RCE
   │
   ▼
Code execution as SYSTEM
   │
   ▼
Windows foothold
   │
   ▼
Active Directory enumeration
```

If Jenkins is running on a Windows server as the **SYSTEM** account, successful RCE could potentially provide a highly privileged foothold.

---

# 2. Discovery / Footprinting

The scenario presented is an **internal penetration test**.

Assume you've already completed your web discovery scans and identify a server that appears to be running Jenkins.

The interesting question becomes:

> **Can we access Jenkins, and if so, what level of access can we obtain?**

The module emphasizes that Jenkins is often installed on **Windows servers running as the all-powerful SYSTEM account**.

Therefore:

```text
Jenkins exposed
       ↓
Authentication weakness / vulnerability
       ↓
Jenkins access
       ↓
Remote Code Execution
       ↓
SYSTEM
       ↓
Active Directory foothold
```

This is why Jenkins should receive attention during internal enumeration.

---

# 3. Jenkins Ports

The module identifies two important ports:

### Port 8080 — Jenkins web interface

Jenkins runs on **Tomcat port 8080 by default**.

So during enumeration, you may encounter:

```text
http://target:8080/
```

However, don't assume 8080 automatically means Jenkins. Fingerprint the service.

### Port 5000 — Jenkins agent communication

Jenkins also utilizes **port 5000** to attach slave servers.

The port is used for communication between **masters and slaves**.

> CPTS terminology note: newer Jenkins terminology commonly uses **controller/agent**, but the module uses **master/slave**, so preserve the module's wording when taking exam notes.

---

# 4. Jenkins Authentication

One important enumeration step is determining **how Jenkins handles authentication**.

The module states that Jenkins can use several authentication mechanisms:

```text
                 Jenkins
                    │
        ┌───────────┼────────────┐
        ▼           ▼            ▼
     Local DB     LDAP      Unix user DB
        │
        ├── Servlet container
        │
        └── No authentication
```

Specifically, Jenkins can use:

- A local database
    
- LDAP
    
- Unix user database
    
- Servlet-container delegated security
    
- **No authentication**
    

Administrators can also configure whether users are allowed to create accounts.

### Why this matters

Don't immediately assume:

> "Jenkins = username + password."

Instead, determine the configured authentication model.

An unauthenticated Jenkins instance can potentially expose functionality without requiring credentials.

---

# 5. Jenkins Global Security

The module provides:

```text
http://jenkins.inlanefreight.local:8000/configureSecurity/
```

This is the **Configure Global Security** page.

![Image](https://images.openai.com/static-rsc-4/GQukiAC3_PJ2jt68xuc0t59XVEQjOHVUQFvR8Nfxyw0trVpnOu-eTGXX1RHYXAEZAWtCfr-k8TriVKHoj78S-h6t0p-LI8ExcVMhLxbv6KuM6jKHJLy1Pv2IKNbxw3KLOdfCZ0RGKsg8Xx5QQV38XIU0bKsJpHqNcyeKYS7XDBKt-wk4nQtFVxL1EoJiR79N?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/VkevGqkdpdaejSMuQA0shLgp6CV-B_zweu1YUTfW5rz4Dt_6VpN5UfhLTC-272wFWLeoXumebm8BuCuryhOInPBsmieOYfSxZv5-yADxBEkgnNLYQjizbTOaMzybnS27fK5kfOMjXm6Mid-yWzobJlv8NcSD_43F6PgAo29kU_pfCMB09fqwCMiQCwnj2dX7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/yMfjsle8e-Ymi9xgfzeOl6WWVPstmrEhwmKgBOJyD2BD_LzCbM2KyqbeJ6F2bvAV8QJMd9WzO42fphg7Tjp-xcX4wLci1OyRVXOUipQIRgdeUMBkY-L8DsFUSO3byBadvtIB-k2P98irsrS45uZqpv2_mBsT4w1xY1YvTpC0xxXjVyHv-Gw3ANU4CBZhFBcZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/h7i1Qf6BNAikh3WBzEwW2hFPfd_DrRAeAWn5_yWy2yZ3FwuzZyUH9qgp9paFHoJINBbYYzdkAha8L5-TG7ClTi6XMNSWyDT2ofUIH0VuFHd3RzGRtYW_-ykeu70i5dlFUrsM-gg8MjZ0yp5DMUjABAmaGmh58q7Xc0rM7wHseuDB8VQH_01TFTAx-6ELDqpI?purpose=fullsize)

The screenshot shows:

- Authentication configuration
    
- Security realm options
    
- **Jenkins' own user database**
    
- **Logged-in users can do anything**
    

### CPTS point

If you obtain access to the Jenkins security configuration, pay attention to:

1. **Security Realm**
    
2. Authentication source
    
3. Whether users can register
    
4. Authorization strategy
    
5. What authenticated users are allowed to do
    

These settings determine the attack surface.

---

# 6. Fingerprinting Jenkins

One of the quickest ways to identify Jenkins is through its **login page**.

The module provides:

```text
http://jenkins.inlanefreight.local:8000/login?from=%2F
```

![Image](https://images.openai.com/static-rsc-4/tIukyNQto-krBGc9tIhBzxEl8XhCmpkffc16htjwck1b1oBmMi1eikMtJLPXFVvr_8v74ZNaghv-4kJOX-kY9SyATf6cwTCEJhZQozVvyPlHskBAVOKNodPgXS7f8pGhgqq02tFDmX_EX9BHqPCLdIUBkuyMQvOuq6d4ViS9PG5ZdhXX3nd5E4frMEjFz5Y4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NzhrvjpAFvZWp_RlWUltgBd_89lxni-rumuY3Shge2_wDdoDupvL4ZX4bu5yMvB2LFj4zZrUoz0T-81FUVOb2uzjQOd3iy2S5bF5H9JYfF7v1NjLEHZDJ4LjtKwar03DBRma-WgzntCa8H_8OqJTOWJiv2oXMMa3rIepOs0yctcTFWHfXRnspuPlIbpNirLP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/4A4MSFkX68CNfpG5-TRaBIoFklpIF_ZwWBAKBL9wjbxkLoxlS_BOo1MVmolNED-JOWr3X_AS3tkg752_Oglz3RaMY_ryphm18uRL33KEUEBGzxd7SLq7Qr8yd_OZRYjAec6G5QfC3RNxgYyoQqi4onJDQgxkf-Kodo1KZKWi1T3je0oMkrxkq0C99aC9ZDtm?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZJMiOjebgrknghfOxBMAdDgF929VFnmIAMKleOdjW_Km78VEtL-kdfOAebcAvlKhwn6VhjEQy3cF0fs3iCeI93VYITdOEK7jcsyoqZkrX7t0GPhkcvvqCMqvW0z5hG8Ctzd1BHNn94lAl5-GwMEDgnZsf2c3yrtnqIZHz1P7Jtl-OHpT09iDGgAiWBrTzKfI?purpose=fullsize)

The login page contains recognizable Jenkins characteristics, including:

- Username field
    
- Password field
    
- **Keep me signed in** option
    

This can be used as a strong fingerprint that the web service is Jenkins.

---

# 7. Default / Weak Credentials

After fingerprinting Jenkins, one of the first things to consider is authentication.

The module specifically mentions:

```text
admin:admin
```

as an example of weak/default credentials.

Possible situations include:

```text
Jenkins
  │
  ├── Weak credentials
  │      └── admin:admin
  │
  ├── Default credentials
  │
  └── No authentication
```

The module notes that during **internal penetration tests**, it is not uncommon to encounter Jenkins instances that require **no authentication**.

It also notes that although rarer, Jenkins instances have been encountered during **external penetration tests** that were attackable.

---

# 8. Enumeration Methodology

For CPTS, think about Jenkins enumeration as a progression rather than immediately jumping to exploitation.

```text
┌──────────────────────┐
│ Web Discovery        │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Identify Jenkins     │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Identify Ports       │
│ 8080 / 5000          │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Fingerprint Login    │
│ Page                 │
└──────────┬───────────┘
           ↓
┌──────────────────────┐
│ Determine Auth       │
│ Mechanism            │
└──────────┬───────────┘
           ↓
      ┌────┴────┐
      ↓         ↓
 Weak/default  No auth
 credentials
      │         │
      └────┬────┘
           ↓
┌──────────────────────┐
│ Assess Jenkins       │
│ Functionality        │
└──────────┬───────────┘
           ↓
      Potential RCE
           ↓
   Privilege / AD impact
```

---

# 🎯 CPTS Exam Points

Memorize these:

### Jenkins basics

- Jenkins = **open-source automation server**
    
- Written in **Java**
    
- Used for **Continuous Integration**
    
- Originally called **Hudson**
    
- Hudson released in **2005**
    
- Renamed Jenkins in **2011**
    
- Runs in servlet containers such as **Tomcat**
    

### Ports

```text
8080 → Jenkins web interface (default)
5000 → Jenkins master/slave communication
```

### Authentication

Jenkins can use:

```text
Local database
LDAP
Unix user database
Servlet container
No authentication
```

Administrators can also control whether users can create accounts.

### Credentials

Always consider:

```text
admin:admin
```

and other weak/default credentials where authorized.

### High-value impact

A particularly valuable scenario is:

```text
Jenkins → RCE → SYSTEM → Active Directory foothold
```

---

# 🧠 Quick Revision Cheat Sheet

```text
JENKINS
│
├── Java
├── CI / automation server
├── Originally Hudson
├── 2005 → Hudson released
├── 2011 → renamed Jenkins
│
├── Ports
│   ├── 8080 → web interface
│   └── 5000 → master/slave communication
│
├── Authentication
│   ├── Jenkins DB
│   ├── LDAP
│   ├── Unix users
│   ├── Servlet container
│   └── None
│
├── Fingerprinting
│   └── /login?from=%2F
│
├── Weak credentials
│   └── admin:admin
│
└── Potential impact
    └── RCE → SYSTEM → AD foothold
```

**Most important mindset:** when you discover Jenkins during an internal assessment, don't treat it as "just another web login." Its authentication configuration, exposed functionality, and the account under which Jenkins runs can make it a potentially high-impact target.