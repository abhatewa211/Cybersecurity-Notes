# 1. What is LDAP?

**LDAP = Lightweight Directory Access Protocol**

LDAP is a **protocol used to access and manage directory information**.

A directory is a **hierarchical data store** containing information about resources such as:

- 👤 Users
    
- 👥 Groups
    
- 💻 Computers
    
- 🖨️ Printers
    
- 🌐 Network devices
    
- Other organisational resources
    

### Simple mental model

Think of LDAP as a **phonebook for an organisation**:

```text
                    LDAP Directory
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
        Users          Groups        Computers
          │              │              │
       jdoe           Admins          PC01
       alice          Developers       PC02
       bob            Finance          PC03
```

Applications can query this directory to retrieve information.

---

# 2. LDAP Functionality

The module highlights several advantages:

|Functionality|Meaning|
|---|---|
|**Efficient**|Fast directory queries and connections|
|**Global naming model**|Supports multiple independent directories|
|**Extensible & flexible**|Custom attributes and schemas|
|**Compatibility**|Platform-independent and works over TCP/IP|
|**Authentication**|Can provide central authentication / single sign-on|

---

# 3. LDAP Weaknesses

LDAP also has security concerns.

### 1. Compliance

Directory servers need to be LDAP compliant, which can limit vendor/product choices.

### 2. Complexity

LDAP can be difficult for administrators and developers to configure correctly.

### 3. Encryption

A particularly important point:

> **LDAP does not encrypt traffic by default.**

Traditional LDAP commonly uses:

```text
389/tcp
```

Encrypted LDAP can use:

```text
636/tcp
```

or LDAP can use **StartTLS** to establish encryption.

### 4. LDAP Injection

Applications that construct LDAP queries unsafely can be vulnerable to **LDAP injection**, allowing an attacker to manipulate queries and potentially bypass authentication or access data.

---

# 4. Common LDAP Use Cases

LDAP is commonly used as a **central directory** for organisational information.

### Authentication

One of the most common uses:

```text
User
 │
 ▼
Application
 │
 ▼
 LDAP
 │
 ▼
Validate credentials
 │
 ▼
Access granted
```

This allows central credentials to be used across multiple applications.

### Authorisation

LDAP can also help manage permissions and access control.

### Directory Services

Applications can:

- Search data
    
- Retrieve data
    
- Modify data
    

### Synchronisation

LDAP directories can replicate changes between systems.

---

# 5. LDAP vs Active Directory

🔥 **Very important CPTS distinction**

LDAP and Active Directory are **not the same thing**.

### LDAP

LDAP is a:

> **Protocol**

It specifies how clients and servers communicate with directory services.

### Active Directory

AD is a:

> **Directory service**

It stores and manages users, computers, groups, policies, etc.

Active Directory uses LDAP as **one of its protocols**.

### Easy way to remember

```text
LDAP = HOW you communicate
AD   = WHAT directory service you're communicating with
```

---

## LDAP vs AD table

|LDAP|Active Directory|
|---|---|
|Protocol|Directory service|
|Open/cross-platform|Microsoft Windows ecosystem|
|Defines directory communication|Provides directory management|
|Flexible schema|Windows-specific predefined/extended schema|
|Supports multiple authentication mechanisms|Primarily Kerberos, also NTLM/LDAP|
|Can communicate with AD|Uses LDAP among other protocols|

---

# 6. LDAP Architecture

LDAP uses a **client-server architecture**.

```text
┌─────────────┐
│ LDAP Client │
└──────┬──────┘
       │ LDAP request
       ▼
┌─────────────┐
│ LDAP Server │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ Directory Store │
│ Users           │
│ Groups          │
│ Computers       │
│ etc.            │
└─────────────────┘
```

The client sends LDAP messages, the server processes them, and returns responses.

LDAP messages are encoded using **ASN.1 (Abstract Syntax Notation One)** and transmitted over TCP/IP.

---

# 7. LDAP Operations

LDAP supports operations such as:

```text
bind
unbind
search
compare
add
delete
modify
```

### Important one: `bind`

`bind` is associated with authentication/establishing the LDAP session.

A simplified authentication flow:

```text
Client
  │
  │ bind(username,password)
  ▼
LDAP Server
  │
  │ Validate
  ▼
Success / Failure
```

---

# 8. Anatomy of an LDAP Request

An LDAP request contains several important components.

### 1. Session connection

Connect to an LDAP port, usually:

```text
389
```

or:

```text
636
```

### 2. Request type

For example:

```text
bind
search
modify
```

### 3. Request parameters

These may include:

- Distinguished Name (**DN**)
    
- Search scope
    
- Search filter
    
- Attributes
    
- Values
    

### 4. Request ID

Used to match a request with its corresponding response.

---

# 9. LDAP Response

The server response can contain:

```text
Response type
Result code
Matched DN
Referral
Response data
```

For example:

```text
result: 0 Success
```

means the operation succeeded.

---

# 10. `ldapsearch`

`ldapsearch` is a command-line utility used to query LDAP directories.

Example from the module:

```bash
ldapsearch -H ldap://ldap.example.com:389 \
-D "cn=admin,dc=example,dc=com" \
-w secret123 \
-b "ou=people,dc=example,dc=com" \
"(mail=john.doe@example.com)"
```

### Breakdown

```text
-H
```

LDAP server/URL:

```text
ldap://ldap.example.com:389
```

---

```text
-D
```

Bind DN:

```text
cn=admin,dc=example,dc=com
```

---

```text
-w
```

Password:

```text
secret123
```

---

```text
-b
```

Base DN:

```text
ou=people,dc=example,dc=com
```

---

```text
"(mail=john.doe@example.com)"
```

LDAP search filter.

The query searches for an entry whose `mail` attribute matches the specified address.

---

# 11. Understanding DN

The response can look like:

```text
dn: uid=jdoe,ou=people,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: John Doe
sn: Doe
uid: jdoe
mail: john.doe@example.com

result: 0 Success
```

The important thing here is:

```text
dn:
```

which identifies the **Distinguished Name** of the LDAP entry.

---

# 🔥 12. LDAP Injection

This is the main security topic of the module.

**LDAP injection** occurs when an application places untrusted user input directly into an LDAP query without properly escaping/validating it.

The attacker manipulates the LDAP query's logic.

### SQLi analogy

Think:

```text
SQL Injection
      ↓
Database query manipulation
```

versus:

```text
LDAP Injection
      ↓
LDAP query manipulation
```

The underlying concept is very similar.

---

# 13. LDAP Special Characters

The module highlights several characters/operators worth testing when assessing an LDAP-backed application:

|Input|Meaning|
|---|---|
|`*`|Wildcard / matches any number of characters|
|`(` `)`|Group expressions|
|`|`|
|`&`|Logical AND|
|`(cn=*)`|Condition matching any CN|
|`(objectClass=*)`|Condition matching objects of any class|

---

# 14. Vulnerable Authentication Query

The module gives this example:

```text
(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))
```

Imagine the application substitutes:

```text
$username
$password
```

with whatever the user submitted.

That's dangerous if the input isn't escaped correctly.

---

# 15. Wildcard Authentication Bypass

The module demonstrates the effect of supplying:

```text
$username = "*"
$password = "dummy"
```

which results in:

```text
(&(objectClass=user)(sAMAccountName=*)(userPassword=dummy))
```

The wildcard means the username condition can match **any username**.

Similarly:

```text
$username = "dummy"
$password = "*"
```

results in:

```text
(&(objectClass=user)(sAMAccountName=dummy)(userPassword=*))
```

The password condition becomes a wildcard match.

### Core lesson

The application intended:

```text
username == supplied username
password == supplied password
```

but unsafe LDAP construction can turn the query into:

```text
username matches anything
```

or:

```text
password matches anything
```

---

# 16. Realistic Attack Flow

```text
                Target
                   │
                   ▼
             Port scanning
                   │
                   ▼
              389 LDAP
                   │
                   ▼
        Identify LDAP-backed
          web application
                   │
                   ▼
          Inspect login form
                   │
                   ▼
       Test LDAP special chars
                   │
                   ▼
              Wildcard *
                   │
                   ▼
        LDAP query manipulation
                   │
                   ▼
         Authentication bypass
                   │
                   ▼
       Access protected resources
```

---

# 17. Enumeration

Before attempting injection, enumerate the target.

The module uses:

```bash
nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229
```

Relevant results:

```text
80/tcp  open  http  Apache httpd 2.4.41 ((Ubuntu))
389/tcp open  ldap  OpenLDAP 2.2.X - 2.3.X
```

This is an important observation:

```text
80  → Web application
389 → LDAP
```

That combination is a strong indication to investigate whether the web application's authentication is LDAP-backed.

---

# 18. The HTB Attack Scenario

The module makes an assumption:

> Because **OpenLDAP** is running, the web application on port 80 may use LDAP for authentication.

The login page can then be tested with wildcard characters.

According to the module, supplying:

```text
*
```

in the username/password fields results in authentication bypass.

This demonstrates a significant LDAP injection vulnerability because an unauthenticated attacker could potentially gain access to protected application functionality.

---

# 19. Pentesting Methodology 🧠

When you see LDAP during an assessment:

### Phase 1 — Discover

```bash
nmap -p- -sC -sV --open TARGET
```

Look for:

```text
389/tcp
636/tcp
```

---

### Phase 2 — Identify LDAP implementation

Possible result:

```text
OpenLDAP
```

or an environment involving:

```text
Active Directory
```

---

### Phase 3 — Identify applications

Look for:

```text
HTTP
HTTPS
VPN
SSO
Internal applications
```

---

### Phase 4 — Determine authentication backend

Ask:

```text
Does this application authenticate against LDAP?
```

Indicators include:

- LDAP server exposed
    
- LDAP-related errors
    
- Application documentation/configuration
    
- Username formats
    
- Authentication behavior
    

---

### Phase 5 — Test input handling

Where the application constructs LDAP filters from user input, assess special characters such as:

```text
*
(
)
|
&
```

The module specifically highlights these as useful LDAP query operators.

---

### Phase 6 — Validate impact

Determine whether manipulation results in:

```text
Authentication bypass
        ↓
Unauthorised application access
        ↓
Sensitive information
        ↓
Privilege escalation
        ↓
Potential server/application compromise
```

---

# 20. LDAP Injection vs SQL Injection

|SQL Injection|LDAP Injection|
|---|---|
|Targets SQL queries|Targets LDAP filters/queries|
|Database|Directory service|
|SQL syntax|LDAP filter syntax|
|`' OR 1=1`-style techniques|Wildcards/operators such as `*`, `|
|Can bypass authentication|Can bypass authentication|
|Can expose/modify database data|Can expose/modify directory data|

The module explicitly describes LDAP injection as similar to SQL injection, but targeting the LDAP directory service rather than a database.

---

# 21. Impact

LDAP injection can potentially result in:

- 🔓 Authentication bypass
    
- 📂 Unauthorised access to directory information
    
- 👤 Access to other user information
    
- ⬆️ Elevated privileges
    
- 💥 Application/server compromise
    
- ✏️ Modification of directory data
    
- 🗑️ Data deletion
    
- ⚠️ Service disruption
    

---

# 22. Prevention

The module recommends:

### Input validation

Validate user-supplied data before placing it into LDAP queries.

### LDAP escaping

Escape LDAP-specific special characters such as:

```text
*
(
)
\
NUL
```

as appropriate for the LDAP context.

### Parameterised/safe query construction

The goal is:

```text
User input
    ↓
Treated as DATA
    ↓
LDAP query
```

rather than:

```text
User input
    ↓
Interpreted as LDAP syntax
    ↓
LDAP query manipulation
```

The module specifically recommends removing/handling LDAP-specific special characters and using parameterised queries so input is treated solely as data.

---

# 🎯 CPTS Exam Points

### ⭐ LDAP

**Lightweight Directory Access Protocol**

A protocol for accessing/managing directory services.

### ⭐ LDAP ≠ Active Directory

```text
LDAP = protocol
AD   = directory service
```

### ⭐ Common ports

```text
389 → LDAP
636 → LDAP over SSL/TLS
```

### ⭐ `ldapsearch`

Command-line LDAP querying utility.

### ⭐ LDAP architecture

```text
Client → LDAP Server → Directory
```

### ⭐ Important LDAP operations

```text
bind
search
compare
add
delete
modify
unbind
```

### ⭐ LDAP injection

Occurs when attacker-controlled input is incorporated into LDAP queries without proper escaping/validation.

### ⭐ Characters to remember

```text
*
(
)
|
&
```

### ⭐ Wildcard

```text
*
```

can match multiple characters and, in a vulnerable authentication query, may contribute to authentication bypass.

### ⭐ Biggest methodology lesson

**Don't see port 389 and immediately attack LDAP.**

First determine:

```text
LDAP exposed
      ↓
What is using LDAP?
      ↓
Web application?
      ↓
Authentication?
      ↓
How is user input incorporated?
      ↓
Can LDAP syntax be injected?
```

---

# 🧪 Quick Revision Cheat Sheet

```text
LDAP
│
├── Lightweight Directory Access Protocol
├── Directory = users/groups/computers/etc.
├── Client-server architecture
│
├── Ports
│   ├── 389 → LDAP
│   └── 636 → LDAPS
│
├── Common operations
│   ├── bind
│   ├── search
│   ├── modify
│   ├── add
│   └── delete
│
├── Tool
│   └── ldapsearch
│
├── LDAP ≠ AD
│   ├── LDAP = protocol
│   └── AD = directory service
│
└── LDAP Injection
    ├── *
    ├── ()
    ├── |
    ├── &
    └── Can lead to authentication bypass
```

### 🔥 One-line memory trick

> **LDAP is the language/protocol used to talk to the directory; Active Directory is Microsoft's directory service, and LDAP injection happens when untrusted input is allowed to become part of that directory query.**