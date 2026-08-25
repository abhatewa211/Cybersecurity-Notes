![Image](https://images.openai.com/static-rsc-4/DEiNVtXMDxzclqt3K96XnRP5VGxwV3LkrGVY1dPsr6AVCMMpYF3ZJZZ3Uq78XgyBEKAQ6oXXM46DXiwXRgAsRDtIfIh91IErfAewHVYHR-Andd41pp4Of97mI8D-CaVmO3SVmigRC5EoMrR700QPEYDc1qoDP7ojIjN7yn8cRk3Mu5P65OFi46E7W0toFyyf?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/7rFj3xlC2hL_bHasLPtjYc98RFpSVJn465VolWO25iyyM9fGYlS6aJE_fXze-tjxMBiHZhwcihEan21DBgDn6I5CA_IfxWbfMfIdt3ZAmCWD9f0hILeCm-FMnaWdBmn6-li8kiY3JcpmAFJAMXdirGxyXgjHDCXFdDB3WsubxTqj3V8FaOJnqRw7tDC3TsfG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/NooqnywIaJfvU8W06Y1aZwpUV26WiQpu21BntSvyevNkK4bbDMIeBiYMsSP64eN7ko3SRrZHgxHqVcUXwPf46QsBIbD9ROQkpkA0FjAU0CXouT9hG_CRkM_ZwVW9nBcQI0QHBWsighmSRtkE4cWe-0pjDTGnsJ3UBjx5uLsxY_-s8RcKWlM3q379Z0tjeVMZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/06OQ1CTvboD5-rVOaiuZZ9oe7h72kHMPz4ADYax5ILLHdGBxYMac4-l6pBfd3TI8atUW2k6hqiYa5HuVAwdPSPMywSPoezd1UNmT6hMmy44Fqpk1lGr23LBg2r3to8w4QQQ4k8o-ERjMlS9e6Xh7Tap-qq2C3p29IJqNjDAU6LaCOeupPWjndEj8QRCV4E1e?purpose=fullsize)

> **Lab context:** The commands and techniques below are for the authorized HTB environment described in your notes. The important skill is understanding the prerequisites and reasoning rather than blindly copying payloads.

---

# 1. Why File Writing Is More Dangerous ⭐⭐⭐

Reading a file can disclose sensitive information.

Writing a file can potentially **change the server's state**.

For example:

```text
Read file
   ↓
Information disclosure
```

versus:

```text
Write executable file
   ↓
Web server executes it
   ↓
Code execution
```

Therefore, file-writing capabilities are significantly more dangerous.

---

# 2. The Complete Attack Chain

Memorize the progression:

```text
                SQL Injection
                     │
                     ▼
              UNION Injection
                     │
                     ▼
             Identify DB user
                     │
                     ▼
              Check privileges
                     │
                     ▼
              FILE privilege?
                     │
                     ▼
          Check secure_file_priv
                     │
                     ▼
          Check filesystem access
                     │
                     ▼
        SELECT ... INTO OUTFILE
                     │
                     ▼
                File written
                     │
              ┌──────┴───────┐
              ▼              ▼
         Normal file    Executable file
              │              │
              ▼              ▼
        Data written     Potential RCE
```

This is the core concept of the entire section.

---

# 3. Requirements for Writing Files ⭐⭐⭐

The module gives **three requirements**:

### Requirement 1 — `FILE` privilege

The current MySQL/MariaDB user must have:

```text
FILE
```

---

### Requirement 2 — `secure_file_priv` must permit it

The DBMS configuration must allow the desired filesystem location.

---

### Requirement 3 — OS filesystem permissions

The MySQL process must actually have permission to write to the destination.

So:

```text
FILE privilege
      +
secure_file_priv configuration
      +
OS write permission
      ↓
Potential file writing
```

All three matter.

---

# 4. `secure_file_priv` ⭐⭐⭐

This variable is a major security control.

It determines where MySQL/MariaDB is permitted to perform certain file operations.

Conceptually:

```text
secure_file_priv
       │
       ├── Empty
       │     ↓
       │  Broad filesystem access
       │
       ├── Directory
       │     ↓
       │  File operations restricted to that directory
       │
       └── NULL
             ↓
          File operations disabled
```

---

# 5. Three Important Values

## A. Empty value

An empty value:

```text
""
```

means file operations aren't restricted to one specific directory by this variable.

However, **OS permissions and other DBMS restrictions still apply**.

---

## B. Specific directory

For example:

```text
/var/lib/mysql-files
```

means file operations are restricted to that directory.

Conceptually:

```text
/var/lib/mysql-files/
        ✓ allowed

/var/www/html/
        ✗ restricted by secure_file_priv
```

---

## C. `NULL`

A `NULL` value indicates that file operations are disabled through this mechanism.

So:

```text
NULL
 ↓
No permitted file read/write location
```

---

# 6. MariaDB vs MySQL Configuration ⚠️

Your module specifically highlights an important difference:

### MariaDB

The lab's MariaDB configuration has:

```text
secure_file_priv = ""
```

allowing broad file access subject to privileges and OS restrictions.

### MySQL

Modern MySQL installations may use:

```text
/var/lib/mysql-files
```

as the permitted directory.

Some configurations can use:

```text
NULL
```

to disable file operations.

### Lesson

Never assume:

> "`LOAD_FILE()` or `INTO OUTFILE` will work."

Always **check the configuration first**.

---

# 7. Checking `secure_file_priv`

The normal SQL statement is:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

This asks MySQL:

> "What restriction is currently configured for file operations?"

---

# 8. Why `INFORMATION_SCHEMA` Is Used

Because we're working through a UNION-based SQL injection, we want the value returned as part of a `SELECT`.

The module uses:

```text
INFORMATION_SCHEMA
        ↓
global_variables
        ↓
variable_name
variable_value
```

So the conceptual query becomes:

```sql
SELECT variable_name, variable_value
FROM information_schema.global_variables
WHERE variable_name = 'secure_file_priv';
```

The important fields are:

|Field|Meaning|
|---|---|
|`variable_name`|Configuration variable's name|
|`variable_value`|Its current value|

---

# 9. Applying the UNION Structure

Remember our lab has **four columns**.

Therefore:

```text
Column 1 → filler
Column 2 → variable_name
Column 3 → variable_value
Column 4 → filler
```

The module demonstrates:

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4
FROM information_schema.global_variables
WHERE variable_name="secure_file_priv"-- -
```

The important part isn't memorizing the payload.

Understand the construction:

```text
4 original columns
        ↓
Need 4 UNION columns
        ↓
Put interesting output
in reflected columns
```

---

# 10. Lab Result

The lab returns an empty value for:

```text
SECURE_FILE_PRIV
```

Meaning:

```text
secure_file_priv = ""
```

Therefore, the DBMS configuration does not restrict file operations to a particular directory.

**But this still doesn't prove we can write anywhere.**

We must also have OS-level write permission.

---

# 11. `SELECT ... INTO OUTFILE` ⭐⭐⭐

This is the primary file-writing mechanism discussed here.

Basic structure:

```sql
SELECT <data>
INTO OUTFILE '<file_path>';
```

Conceptually:

```text
SELECT
  ↓
Generate data
  ↓
INTO OUTFILE
  ↓
Write result to file
```

---

# 12. Exporting Existing Database Data

The module first demonstrates exporting table data:

```sql
SELECT * FROM users
INTO OUTFILE '/tmp/credentials';
```

This takes the result of:

```text
SELECT * FROM users
```

and writes it into:

```text
/tmp/credentials
```

So:

```text
Database table
      ↓
SELECT
      ↓
Result set
      ↓
INTO OUTFILE
      ↓
Filesystem
```

---

# 13. Writing Arbitrary Text

`INTO OUTFILE` isn't limited to existing table data.

You can also select a literal value:

```sql
SELECT 'this is a test'
INTO OUTFILE '/tmp/test.txt';
```

Conceptually:

```text
String
 ↓
SELECT
 ↓
OUTFILE
 ↓
/tmp/test.txt
```

The result is simply the text stored in that file.

---

# 14. File Ownership

The module demonstrates:

```text
-rw-rw-rw- 1 mysql mysql ...
```

This is important.

The created file is owned by:

```text
mysql
```

because the **MySQL server process** is performing the file operation.

This reinforces another important distinction:

```text
MySQL account
      +
MySQL server process
      ↓
Filesystem operation
```

---

# 15. Why File Ownership Matters

Suppose the database server runs as:

```text
mysql
```

Then the file created through the database may belong to:

```text
mysql:mysql
```

That affects what other processes/users can do with it.

This is why understanding:

```text
DB privileges
+
OS identity
+
filesystem permissions
```

is essential.

---

# 16. Writing Through UNION Injection

Now combine everything we've learned.

Suppose:

```text
Original query
      ↓
4 columns
```

and columns 2–4 are reflected.

We can conceptually construct:

```text
Column 1 → filler
Column 2 → desired text
Column 3 → filler
Column 4 → filler
        ↓
UNION SELECT
        ↓
INTO OUTFILE
```

The module's lab example writes:

```text
file written successfully!
```

to:

```text
/var/www/html/proof.txt
```

---

# 17. Why the Proof File Is Important

The proof file is **not about getting code execution yet**.

It's a validation step.

The reasoning is:

```text
Can I write a file?
        ↓
Write harmless text
        ↓
Can I access the file?
        ↓
YES
        ↓
File-writing capability confirmed
```

This is a much better methodology than immediately attempting something more destructive.

---

# 18. Why `/var/www/html/` Matters

Apache commonly uses:

```text
/var/www/html/
```

as a webroot on Linux installations.

The important concept is:

```text
Filesystem
   │
   └── Webroot
          │
          ├── index.php
          ├── search.php
          └── proof.txt
```

A file inside the webroot may be accessible through HTTP.

For example:

```text
Filesystem:
/var/www/html/proof.txt

HTTP:
/proof.txt
```

This creates the bridge:

```text
Database
 ↓
Filesystem
 ↓
Webroot
 ↓
HTTP
```

---

# 19. Why Finding the Webroot Matters

If you want a file to be accessible through the web application, you need to know where the web server serves files from.

Possible sources include:

```text
Apache configuration
Nginx configuration
IIS configuration
Application configuration
Known deployment conventions
```

The module mentions examples such as Apache's configuration and Nginx/IIS configuration.

### Key idea

Don't blindly assume:

```text
/var/www/html
```

is always the webroot.

It depends on the server configuration.

---

# 20. Source Code + Configuration = Powerful Combination

The previous section showed:

```text
LOAD_FILE()
      ↓
Read application source
```

This section shows:

```text
INTO OUTFILE
      ↓
Write to filesystem
```

Together:

```text
Read configuration
       ↓
Understand server layout
       ↓
Identify webroot
       ↓
Determine whether writing is possible
```

This demonstrates why SQL Injection can become much more serious when the database account is overprivileged.

---

# 21. Web Shell Concept ⚠️

The module then demonstrates writing a PHP web shell.

Conceptually, a web shell is:

```text
HTTP request
     ↓
PHP file
     ↓
PHP executes attacker-controlled input
     ↓
Operating-system command
     ↓
Command output
```

The lab uses a PHP construct that invokes:

```text
system()
```

with request-controlled input.

That turns:

```text
SQL Injection
```

into:

```text
Filesystem Write
       ↓
PHP File
       ↓
Web Server Executes PHP
       ↓
OS Command Execution
```

This is the critical escalation demonstrated by the lab.

---

# 22. Why This Is Called RCE

RCE =

```text
Remote Code Execution
```

The progression is:

```text
Remote HTTP request
       ↓
Server-side PHP execution
       ↓
Operating-system command
```

Therefore the attacker has moved from manipulating a database query to executing commands on the server.

---

# 23. Understanding the Final `id` Result

The lab accesses the PHP file and executes:

```text
id
```

The response identifies:

```text
www-data
```

This is extremely important.

It means the command is being executed under the identity of the web server process.

Conceptually:

```text
PHP
 ↓
Web server
 ↓
OS process
 ↓
www-data
```

It does **not** mean:

```text
www-data = root
```

The privileges of the resulting shell/command execution are limited by the account running the web server.

---

# 24. The Complete Escalation ⭐⭐⭐⭐⭐

This is probably the most important diagram from this entire part of the module:

```text
             SQL INJECTION
                   │
                   ▼
            UNION INJECTION
                   │
                   ▼
           DATABASE ENUMERATION
                   │
                   ▼
            CURRENT DB USER
                   │
                   ▼
            PRIVILEGE ENUMERATION
                   │
                   ▼
             FILE PRIVILEGE
                   │
                   ▼
           secure_file_priv
                   │
                   ▼
        Filesystem write permission
                   │
                   ▼
        SELECT ... INTO OUTFILE
                   │
                   ▼
             Write a file
                   │
                   ▼
              Webroot
                   │
                   ▼
              PHP file
                   │
                   ▼
           PHP code execution
                   │
                   ▼
                 RCE
```

---

# 25. Important Security Controls 🛡️

This section also teaches defenders what should be restricted.

### Least-privileged DB accounts

The application should **not** normally use a highly privileged database account.

Instead:

```text
Application DB account
        ↓
Only required permissions
```

rather than:

```text
Application DB account
        ↓
FILE + SUPER + everything else
```

---

### Restrict `secure_file_priv`

A restricted directory can significantly reduce where database file operations can occur.

---

### Filesystem permissions

The database process should not have unnecessary write access to sensitive directories.

---

### Webroot protection

The database process should ideally not be able to arbitrarily create executable server-side files inside the webroot.

---

### Parameterized queries

Most importantly, prevent the original SQL Injection.

Use:

```text
Parameterized queries
Prepared statements
```

rather than directly concatenating user input into SQL.

---

# 26. `secure_file_priv` Values — Revision Table

|Value|Meaning|
|---|---|
|Empty string `""`|No directory restriction from this variable|
|Specific directory|File operations restricted to that directory|
|`NULL`|File operations disabled|

⚠️ Always consider the **specific DBMS/version/configuration** rather than assuming one default applies everywhere.

---

# 27. Reading vs Writing

|Capability|Mechanism|Main Impact|
|---|---|---|
|Database read|`SELECT`|Data disclosure|
|File read|`LOAD_FILE()`|Server-file disclosure|
|File write|`INTO OUTFILE`|Filesystem modification|
|Executable file write|Web-accessible server-side file|Potential RCE|

This progression is worth remembering.

---

# 28. Common Beginner Mistakes

### ❌ Mistake 1 — Assuming `FILE` is enough

No.

You also need:

```text
secure_file_priv
+
OS permissions
+
valid destination
```

---

### ❌ Mistake 2 — Immediately trying to write executable code

A better lab methodology is:

```text
1. Confirm FILE privilege
2. Check secure_file_priv
3. Test harmless file write
4. Verify file exists
5. Understand execution context
```

This gives you evidence at every stage.

---

### ❌ Mistake 3 — Assuming every webroot is `/var/www/html`

It is common, but not universal.

Always verify the environment.

---

### ❌ Mistake 4 — Thinking database root = Linux root

Again:

```text
MySQL root
≠
Linux root
```

---

### ❌ Mistake 5 — Forgetting the web server's execution user

The lab ultimately shows:

```text
www-data
```

This tells you the privilege level of the resulting command execution.

---

# 29. ⭐ Must-Memorize Points

> **Writing files is generally more dangerous than simply reading them because it can potentially lead to code execution.**

> **MySQL file writing requires the `FILE` privilege.**

> **`secure_file_priv` controls where MySQL/MariaDB can perform certain file operations.**

> **An empty `secure_file_priv` value means there is no directory restriction from that variable.**

> **A specific `secure_file_priv` directory restricts file operations to that location.**

> **`NULL` disables file operations through this mechanism.**

> **Filesystem permissions still matter even when `FILE` is granted.**

> **`SELECT ... INTO OUTFILE` can write query results to files.**

> **A simple text file is a useful way to verify file-write capability in a lab.**

> **Writing a server-executable file into a webroot can potentially turn SQL Injection into RCE.**

> **The resulting OS command executes with the privileges of the relevant web-server process, not automatically as root.**

---

# 30. 🧠 Golden Mental Model

Don't memorize the web-shell payload.

Instead, remember the **decision tree**:

```text
SQLi found?
   │
   ├── NO → Stop
   │
   └── YES
         ↓
     UNION works?
         │
         └── YES
              ↓
       Identify DB user
              ↓
       Check FILE privilege
              │
              ├── NO → File write unavailable
              │
              └── YES
                    ↓
          Check secure_file_priv
                    ↓
          Check OS write access
                    ↓
             Test harmless file
                    ↓
               Write succeeds?
                    │
                    ├── NO → Diagnose restrictions
                    │
                    └── YES
                          ↓
                    File exists
                          ↓
              Is it web-accessible?
                          │
                          ├── NO → File write only
                          │
                          └── YES
                                ↓
                       Potential execution
```

**This reasoning chain is the real takeaway.** If you understand _why_ each prerequisite is checked, you can solve the HTB exercises instead of relying on memorized payloads.