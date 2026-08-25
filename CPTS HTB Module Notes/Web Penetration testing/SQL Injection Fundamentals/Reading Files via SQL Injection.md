![Image](https://images.openai.com/static-rsc-4/451_rKF6TO7F-wcX8LcDrt4gD9m5oql2z60qRIChdF8aRmx6F7Vi9-ayOpo_j17mG9I67wlwFYd7YdTK1b9CEO-DLDKY8fsASuCrIHWr1pbCNR9lpYdtqCKvhvtpdKyEQ-ZJWvlM7tK95rJsNgDMmagCoN8iMWjTo-PgeN43UC3GVuhoW5Un0BoEbEt81Luf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/KXMQSGx029kjirAJhQzS7tW2uiSbQjwcb9klLSckXE-GGcDCBhL_oiTnqzqZnNUaJl8Z8REnk57D1vpYu-aVT5UOWwwSG6YhxoqH1t2F9bdbypR0JCgg5_5rB7OHiH6SXkoYzxPKJ9bf9AIKk2Naw2xnhrk92qHhu6-EkVhDlfwB0QFG-MEtVThhmTW_d9nw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QfgIMddHhUL7tqjtC9d93ezFUGbnBMsXgeI7DsaMuQkDEmUvvGh0M9UdGtx399owOB6z9RmLgBTVvOsJylK3uNobKsE_bUkUg845V2C-MRQ7396fAhlHUMPcGPAxBBygq8fz_MnwPIJjRg9kunyqhgEU2uK5PnJs7Vl43BaRvxrfFvC6DxeqtUPHkKoA5bpv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7rFj3xlC2hL_bHasLPtjYc98RFpSVJn465VolWO25iyyM9fGYlS6aJE_fXze-tjxMBiHZhwcihEan21DBgDn6I5CA_IfxWbfMfIdt3ZAmCWD9f0hILeCm-FMnaWdBmn6-li8kiY3JcpmAFJAMXdirGxyXgjHDCXFdDB3WsubxTqj3V8FaOJnqRw7tDC3TsfG?purpose=fullsize)

---

# 1. What Makes This Section Different?

Until now, the target was primarily:

```text
Database
 ├── databases
 ├── tables
 ├── columns
 └── records
```

Now we're asking whether the database server can access files belonging to the **underlying operating system**.

Conceptually:

```text
                    Web Application
                          │
                          ▼
                    SQL Injection
                          │
                          ▼
                      Database
                          │
                    FILE privilege
                          │
                          ▼
                     LOAD_FILE()
                          │
                          ▼
                  Server filesystem
```

This is why excessive database privileges can dramatically increase the impact of SQL Injection.

---

# 2. Why Privileges Matter ⭐⭐⭐

Just because SQL Injection exists does **not** automatically mean the attacker can read arbitrary files.

The database account has permissions.

For file access, the module focuses on the MySQL/MariaDB:

```text
FILE
```

privilege.

So the important question becomes:

> **What privileges does the database user executing the query have?**

---

# 3. Database User vs Operating-System User

This distinction is extremely important.

There are potentially **two different identities** involved:

### Database user

For example:

```text
root@localhost
```

This is the MySQL/MariaDB account.

### Operating-system user

The MySQL server process may run under an OS account such as:

```text
mysql
```

or another service account.

These are **not necessarily the same user**.

So:

```text
Database root
      ≠
OS root
```

unless the environment has specifically configured it that way.

---

# 4. Why This Distinction Matters

`LOAD_FILE()` ultimately depends on the database server process being able to access the requested file.

Therefore:

```text
SQL privileges
       +
OS filesystem permissions
       ↓
Can LOAD_FILE() actually read it?
```

Both sides matter.

---

# 5. Step 1 — Find the Current DB User

MySQL/MariaDB provides several ways to identify the current database user.

The module gives:

```sql
SELECT USER();
```

```sql
SELECT CURRENT_USER();
```

and:

```sql
SELECT user FROM mysql.user;
```

For the current connection, the simplest conceptual option is:

```sql
SELECT USER();
```

---

# 6. `USER()` vs `CURRENT_USER()`

These can be confusing.

### `USER()`

Reports the client/account identity used for authentication, including host information.

Example:

```text
root@localhost
```

### `CURRENT_USER()`

Reports the MySQL account used by the server for authentication/privilege checking.

They can differ in some configurations.

For privilege analysis, understanding this distinction is useful.

---

# 7. UNION Version

Because our lab's reflected column is column 2, the user information can conceptually be placed there:

```text
Column 1 → filler
Column 2 → USER()
Column 3 → filler
Column 4 → filler
```

The module's example is:

```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

The result:

```text
root@localhost
```

tells us the database account involved in the query.

---

# 8. Why `root` Is Interesting

The lab reports:

```text
root@localhost
```

The name `root` is significant because MySQL's `root` account is commonly highly privileged.

But don't make this assumption:

> "`root` means I automatically have every privilege."

Instead, **verify the privileges**.

That's an important security-learning habit.

---

# 9. Step 2 — Check Superuser Privileges

The module checks:

```sql
SELECT super_priv FROM mysql.user;
```

The result can be:

```text
Y
```

or:

```text
N
```

where:

```text
Y = Yes
N = No
```

In the lab:

```text
super_priv = Y
```

Therefore the account has superuser privileges.

---

# 10. Filtering for a Specific User

If the server contains multiple users, querying all users may produce a lot of information.

You can conceptually filter:

```sql
WHERE user="root"
```

This changes:

```text
All users
```

into:

```text
Only root
```

The general enumeration principle is:

```text
Broad metadata
      ↓
Identify target
      ↓
Apply WHERE
      ↓
Focused result
```

---

# 11. INFORMATION_SCHEMA.USER_PRIVILEGES

You can also inspect privileges through:

```text
INFORMATION_SCHEMA.USER_PRIVILEGES
```

Important fields include:

```text
GRANTEE
PRIVILEGE_TYPE
```

Think:

```text
GRANTEE
   ↓
Who has the privilege?

PRIVILEGE_TYPE
   ↓
What privilege do they have?
```

---

# 12. Example Concept

The module uses a UNION query conceptually equivalent to:

```sql
SELECT grantee, privilege_type
FROM information_schema.user_privileges;
```

This can reveal privileges such as:

```text
SELECT
INSERT
UPDATE
...
FILE
```

The exact set depends on the account and DBMS configuration.

---

# 13. Why `FILE` Is the Important One ⭐

The key discovery is:

```text
FILE
```

This privilege is important because it is associated with filesystem operations available to MySQL/MariaDB.

In the context of this module:

```text
FILE privilege
       ↓
Potential file read/write capability
```

But remember:

> **Having `FILE` does not mean the database can read every file on the operating system.**

The underlying OS permissions and DBMS restrictions still matter.

---

# 14. Privilege Chain

Memorize this:

```text
Current DB user
       ↓
Check privileges
       ↓
FILE privilege?
       ↓
YES
       ↓
Attempt LOAD_FILE()
```

This is the reasoning behind the section.

---

# 15. `LOAD_FILE()` ⭐⭐⭐

MySQL/MariaDB provides:

```sql
LOAD_FILE()
```

which can read the contents of a file accessible to the database server.

Basic syntax:

```sql
SELECT LOAD_FILE('/path/to/file');
```

Conceptually:

```text
LOAD_FILE()
    │
    ▼
File path
    │
    ▼
Database server reads file
    │
    ▼
File contents returned
```

---

# 16. Example: `/etc/passwd`

The module demonstrates reading:

```text
/etc/passwd
```

using:

```sql
SELECT LOAD_FILE('/etc/passwd');
```

In the HTB lab, the resulting file contents become visible through the UNION injection.

---

# 17. What Is `/etc/passwd`?

On Linux systems, `/etc/passwd` is a standard account-information file.

A typical line looks like:

```text
root:x:0:0:root:/root:/bin/bash
```

The fields are colon-separated:

```text
username
password-placeholder
UID
GID
comment
home-directory
login-shell
```

Modern Linux systems generally store password hashes elsewhere, such as `/etc/shadow`, which has much more restrictive permissions.

So don't interpret `/etc/passwd` as simply:

> "the file containing everyone's passwords."

That's an outdated oversimplification.

---

# 18. UNION + `LOAD_FILE()`

We already know our UNION structure has four columns:

```text
1
2
3
4
```

And column 2 is reflected.

Therefore, conceptually:

```text
Column 1 → filler
Column 2 → LOAD_FILE()
Column 3 → filler
Column 4 → filler
```

The module demonstrates this with:

```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

The important thing to understand is the **placement**:

```text
LOAD_FILE()
     ↓
Reflected column
     ↓
File contents become observable
```

---

# 19. Why the Attack Works

The complete chain is:

```text
User input
    ↓
SQL Injection
    ↓
UNION SELECT
    ↓
LOAD_FILE()
    ↓
Database server
    ↓
Filesystem
    ↓
File contents
    ↓
SQL result
    ↓
Web application
    ↓
HTTP response
```

This is a major escalation from simply reading database records.

---

# 20. Conditions Required for `LOAD_FILE()`

Several conditions matter.

### 1. SQL Injection must exist

Without the ability to influence the SQL query, you cannot introduce the relevant expression.

### 2. UNION must work

In this lab, the output is obtained through UNION-based SQLi.

### 3. Appropriate database privileges

The module emphasizes the:

```text
FILE
```

privilege.

### 4. The DBMS process must be able to access the file

OS-level permissions matter.

### 5. The path must be correct

A nonexistent or inaccessible file won't produce the desired contents.

---

# 21. Important: Database Privileges ≠ Filesystem Permissions

This is worth repeating.

Suppose:

```text
FILE privilege = YES
```

That does **not** automatically mean:

```text
Every file = readable
```

Instead:

```text
FILE privilege
      +
OS access
      +
Correct path
      +
DBMS restrictions
      ↓
Actual result
```

This distinction is critical when troubleshooting.

---

# 22. Reading Application Source Code

The section then moves from a standard OS file to something much more interesting:

```text
/var/www/html/search.php
```

The reasoning is:

```text
We know the page is:
search.php

We know the common Apache webroot:
 /var/www/html

Therefore:
 /var/www/html/search.php
```

The goal is to see the **server-side PHP source code**.

---

# 23. Why Source Code Is Valuable

A web application's source code may contain information such as:

```text
Database connection details
SQL queries
Authentication logic
Input handling
API credentials
File paths
Hidden functionality
Security weaknesses
```

So source-code disclosure can turn one vulnerability into additional discoveries.

---

# 24. Source Code vs Rendered HTML

This is a very important web-development concept.

When you visit:

```text
/search.php
```

the server normally processes:

```text
PHP
 ↓
HTML response
```

The browser receives the generated HTML, **not the PHP source**.

But if you use `LOAD_FILE()` to read the actual `.php` file from disk:

```text
PHP source
 ↓
Database
 ↓
UNION result
 ↓
Browser
```

the browser can receive the PHP source as ordinary text/content.

---

# 25. Why the Browser May Render the Result

If the returned content contains HTML/PHP-like markup, the browser may interpret some of it as markup rather than displaying it as plain text.

That's why the module says the HTML source can be inspected with:

```text
Ctrl + U
```

The underlying principle is:

```text
Server-side source
       ↓
Read as file
       ↓
Returned through SQL result
       ↓
Browser receives it as response content
```

This is fundamentally different from normally requesting the PHP page.

---

# 26. Why PHP Source Code Is Normally Hidden

Normally:

```text
Browser
   │
   │ HTTP request
   ▼
Apache/PHP
   │
   │ Executes PHP
   ▼
Generated HTML
   │
   ▼
Browser
```

The browser should see:

```text
HTML
```

not:

```text
<?php
...
?>
```

But `LOAD_FILE()` bypasses the normal execution path by reading the file directly from disk.

---

# 27. What the Source Code Can Reveal

The lab's source code contains logic similar to:

```text
Check port_code
      ↓
Build SQL query
      ↓
Execute query
      ↓
Fetch results
      ↓
Display results
```

By inspecting the source, you can understand:

```text
Input → SQL query → Database → Output
```

This can explain **why the original SQL Injection existed**.

---

# 28. The Bigger Security Picture

This section demonstrates an important escalation chain:

```text
                SQL Injection
                     │
                     ▼
              Database Access
                     │
                     ▼
            Privilege Enumeration
                     │
                     ▼
               FILE privilege
                     │
                     ▼
                LOAD_FILE()
                     │
              ┌──────┴──────┐
              ▼             ▼
        OS files       Application
                           source
                              │
                              ▼
                       More information
```

The vulnerability isn't necessarily limited to:

> "I can read a database row."

Depending on configuration and privileges, the impact can extend beyond the DBMS.

---

# 29. ⭐ Important Distinction: SQL Data vs Files

Previously:

```text
SELECT username, password
FROM dev.credentials;
```

reads:

```text
Database data
```

Now:

```text
LOAD_FILE(...)
```

reads:

```text
Filesystem data
```

So:

```text
SELECT
 ↓
Database layer

LOAD_FILE()
 ↓
Filesystem layer
```

This is the major new concept.

---

# 30. Common Beginner Mistakes

### ❌ Mistake 1 — Assuming root automatically means OS root

```text
MySQL root
```

doesn't automatically mean:

```text
Linux root
```

Always distinguish the identities.

---

### ❌ Mistake 2 — Skipping privilege enumeration

Don't jump straight to file access.

Reason first:

```text
Who am I?
 ↓
What privileges do I have?
 ↓
Do I have FILE?
```

---

### ❌ Mistake 3 — Assuming FILE means unlimited filesystem access

It doesn't.

OS permissions still matter.

---

### ❌ Mistake 4 — Assuming `LOAD_FILE()` always works

It can fail because of:

```text
Insufficient privileges
File doesn't exist
OS permissions
DBMS configuration
Path restrictions
```

---

### ❌ Mistake 5 — Confusing PHP source with rendered HTML

Normally:

```text
PHP → executed → HTML
```

Reading the PHP file directly gives:

```text
PHP source → returned as data
```

That's why source-code disclosure is possible.

---

# 31. ⭐ Important Things to Memorize

> **The database account's privileges determine what SQL operations are possible.**

> **`FILE` is the important MySQL/MariaDB privilege discussed for filesystem access.**

> **`USER()` can identify the current database connection user.**

> **`CURRENT_USER()` represents the account used by the server for privilege checking and can differ from `USER()`.**

> **`super_priv = 'Y'` indicates superuser privileges for the relevant account.**

> **`INFORMATION_SCHEMA.USER_PRIVILEGES` can provide privilege information.**

> **`LOAD_FILE()` reads the contents of a file accessible to the database server.**

> **Database privileges and operating-system permissions are separate concepts.**

> **Reading application source code can reveal SQL queries, credentials, configuration, and vulnerabilities.**

---

# 32. One-Page Revision Sheet

```text
             READING FILES VIA SQLi

                    SQLi
                     │
                     ▼
              Find current DB user
                     │
               USER()/CURRENT_USER()
                     │
                     ▼
             Check privileges
                     │
              ┌──────┴──────┐
              │             │
             FILE          No FILE
              │             │
              ▼             ▼
        Potential file   File access
           access        restricted
              │
              ▼
          LOAD_FILE()
              │
       ┌──────┴───────┐
       ▼              ▼
  OS files       Web source
       │              │
       ▼              ▼
 /etc/passwd    search.php
```

---

# 33. The Golden Mental Model 🧠

Don't memorize the final file-reading query as a magic payload.

Understand the reasoning:

```text
1. SQLi exists
        ↓
2. UNION output is reflected
        ↓
3. Identify database user
        ↓
4. Enumerate privileges
        ↓
5. FILE privilege?
        ↓
6. Can database process access target file?
        ↓
7. LOAD_FILE() reads it
        ↓
8. Result is returned through the vulnerable application
```

The **security lesson** is the most important part:

> **SQL Injection impact depends heavily on the privileges of the database account and the configuration of the underlying server.**

A web application using an overly privileged database account can turn what initially looks like a database-only vulnerability into a much broader server-side information-disclosure problem.