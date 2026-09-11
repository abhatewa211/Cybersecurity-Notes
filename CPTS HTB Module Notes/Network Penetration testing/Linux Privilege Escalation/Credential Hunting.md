## 1. 🧠 What is Credential Hunting?

While enumerating a system, **always note down any credentials** you encounter.

Credentials can be hidden in many different places:

```text
Configuration files
     │
     ├── .conf
     ├── .config
     ├── .xml
     │
Shell scripts
     │
Bash history
     │
Backup files
     ├── .bak
     │
Database files
     │
Text files
     │
Web application files
     │
SSH private keys
```

### Why are credentials valuable?

A discovered credential could allow you to:

```text
Credential found
      │
      ├──► Switch to another user
      │
      ├──► Escalate privileges
      │
      ├──► Access root
      │
      ├──► Access a database
      │
      └──► Access another system
              │
              └──► Lateral movement
```

⭐ **MENTOR TIP:**  
Don't only look for files literally named `password`. Look for **configuration files, scripts, backups, histories, database files, and keys**.

---

# 2. 🌐 Web Root — Very Important

The `/var` directory typically contains the **web root** for whatever web server is running on the host.

For example:

```text
/var
 │
 └── www
      │
      └── html
           │
           ├── index.php
           ├── wp-config.php
           └── ...
```

The web root is particularly interesting because web applications often need credentials to connect to databases.

### Common example

A WordPress installation may contain MySQL credentials inside:

```text
wp-config.php
```

The module demonstrates:

```bash
grep 'DB_USER\|DB_PASSWORD' wp-config.php
```

Example output:

```text
define( 'DB_USER', 'wordpressuser' );
define( 'DB_PASSWORD', 'WPadmin123!' );
```

### 🔥 What did we find?

```text
DB_USER       → wordpressuser
DB_PASSWORD   → WPadmin123!
```

These credentials could potentially be useful for accessing the database or, if reused, another account/system.

---

# 3. 📧 Spool & Mail Directories

The **spool or mail directories**, if accessible, may also contain valuable information or credentials.

Think:

```text
Mail / Spool
     │
     ├── Messages
     ├── Notifications
     ├── Automated output
     └── Potential credentials
```

Why?

Automated systems and users may accidentally leave sensitive information in messages, scripts, or generated files.

⭐ **Remember:** Don't ignore mail/spool directories during enumeration.

---

# 4. 🔎 Searching for Configuration Files

A very useful command from the module:

```bash
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

### Breaking it down

```text
find /
 │
 └── Search from the root filesystem

! -path "*/proc/*"
 │
 └── Exclude /proc

-iname "*config*"
 │
 └── Case-insensitive filename containing "config"

-type f
 │
 └── Files only

2>/dev/null
 │
 └── Hide permission/error messages
```

Example results:

```text
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/python3/debian_config
/etc/kbd/config
/etc/manpath.config
/boot/config-4.4.0-116-generic
...
```

### Why search for config files?

Configuration files can contain:

```text
Username
Password
API keys
Database credentials
Connection strings
Service configuration
Paths
Secrets
```

---

# 5. 🔑 SSH Keys

This is **VERY important for HTB**.

Search the system for accessible **SSH private keys**.

Why?

You may find a private key belonging to:

```text
another user
      │
      ▼
more privileges
      │
      ▼
potential privilege escalation
```

Or the key could allow access to **another host**.

```text
Private SSH Key
      │
      ├──► Current machine
      │
      └──► Another machine
              │
              └──► Lateral Movement
```

---

# 6. 📁 `.ssh` Directory

A user's SSH directory commonly contains files such as:

```text
~/.ssh/
 │
 ├── id_rsa
 ├── id_rsa.pub
 └── known_hosts
```

The module's example:

```bash
ls ~/.ssh
```

Output:

```text
id_rsa
id_rsa.pub
known_hosts
```

### What are these?

|File|Meaning|
|---|---|
|`id_rsa`|SSH **private key**|
|`id_rsa.pub`|SSH **public key**|
|`known_hosts`|Hosts the user has previously connected to|

🚨 **Most interesting:** `id_rsa`

A private key may potentially allow authentication as the associated user.

---

# 7. 🗺️ `known_hosts` — Don't Ignore It

Whenever you find SSH keys, **check `known_hosts`**.

The module specifically highlights this because it can reveal **targets**.

Conceptually:

```text
~/.ssh/known_hosts
       │
       ▼
Previously contacted hosts
       │
       ├──► Host A
       ├──► Host B
       └──► Host C
              │
              ▼
       Potential targets
```

The `known_hosts` file contains information about hosts the user has connected to in the past.

This can help with:

- **Lateral movement**
    
- Identifying other systems
    
- Finding potentially useful data on remote hosts
    
- Discovering information that may help with privilege escalation
    

---

# 🧠 Strict Mentor Checklist

When you're doing **Credential Hunting**, mentally run through this:

```text
                    CREDENTIAL HUNTING
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     CONFIG FILES       HISTORY          BACKUPS
     .conf              bash_history     .bak
     .config
     .xml
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                     WEB ROOT
                           │
                    DB credentials
                    WordPress config
                           │
                           ▼
                     SSH MATERIAL
                           │
                    ┌──────┴──────┐
                    ▼             ▼
                 id_rsa      known_hosts
                    │             │
                    ▼             ▼
               Authentication   Targets
```

### 🔥 Commands to memorize

**Search configuration files:**

```bash
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
```

**Search credentials in a known configuration file:**

```bash
grep 'DB_USER\|DB_PASSWORD' wp-config.php
```

**Inspect SSH directory:**

```bash
ls ~/.ssh
```

---

## 🚨 What I'd expect you to notice in an HTB box

If you get a shell and see:

```text
/var/www/
wp-config.php
```

👉 **Immediately think:**  
**"Database credentials may be here."**

If you see:

```text
~/.ssh/
id_rsa
```

👉 **Immediately think:**  
**"Private SSH key — whose key is this and where can it authenticate?"**

If you see:

```text
known_hosts
```

👉 **Immediately think:**  
**"What other hosts has this user interacted with?"**

And if you find:

```text
.conf
.config
.xml
.sh
.bak
.txt
```

👉 **Think:**  
**"Could this contain credentials or connection information?"**

### ⭐ Golden rule

> **Don't just find credentials — determine what they belong to and where they can be used.**

That distinction is what turns **enumeration** into an actual **attack path**.