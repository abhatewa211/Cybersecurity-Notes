![Image](https://images.openai.com/static-rsc-4/GQzut-ZhGhHpHJ-c8nekf7iR53qe3kEkkBxsgOUPZcAJ9zc46S2-1znhHO9iX1GncDkcb8A2XeMosXpin5nGP4P2CvOiDVRp0M7YeS_coqOvAdLwHjyVK-_iibL4rRYVIjBw66McMxGv6a2QrvY_wKrOXMkKX9nBLQSyLWmdK8nTbRJFfGxPJ1evr9hR2UZ7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Ft04dPiXQSmLqmesymFxqvzN5V3YkR79APenQt-_2RgRxzZUvw4PGxqcAr3ozrYUsU4p28YSMslWdcnsnOPjvB7IWZ_Ok_mCR-v8kqy_4ObHXIamimLr96ben5f8URnbUWoCiLLvpF02DSqQNlHmcZxiWgM3YyNGz1AprVRucptLI517Ql3pliUrixiOnlk9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/mSH-iiwU18wIRDCwkbdCgiLSCyZVTjL5GCElk6PSlblzhkkQcYCXqZXhr2T0zT78sX8AUqtBbAMRQh9o29wseeDkQHHJQMjcxHUALJFz4DJgNqHYG1EPIymajDE65Zt49qs1Cru1RVHyJwqc67wEQKX7IvAhYSq8u6U5y58q5Jl8UDr4BOtZBBcDE0AoY9hu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I0_irkZDx0VZWiNVE_6x3mrcumshloeUfZWg5MIr7FHi-AUv0t_Abdsc61eJ29-XVEm1r7ARbAYyQjtlAIXDhWfuOtJ4NX8at7H12vogThf7KAe6ZuJnHPHMY77_WCFIHvYGnCWIPP61M4n9X7Uik7vNP9Ziteh_nciV1a5fyNcy4sLMHqxCJ59jUmPfaiWN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZPb78de9H6Y2EJrZOepn-YsItRP6ecTnCYdTuikIdOOXULls4L6fNPQ3XMC4ea3AQng-EUurM4pFuhvu6l1zYZGML0tFIPIqQpsNEHX7l25XyYcnzWOnd0Tn7CQ5TJPNtlBVMKonoc6UnuOh04eR2JOyV9DuEHADMyMQWW7ue0aMSW9epLobVArA9GaXjCh3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qFWKMk9rxi_zKSzWT64LA5fliK8KrAmCu8I884nV1Ep5j_5F6QXafAgc_t3VYRk6fvdkWxViPnxH2zs2QNlQlAV7KfALfyqSZ9lb_aV_vmKYcZv_l5KOKQnbBa4j8ul82JGkqOHR-xQtyn6VMEwOzG3Wx7dGNiR8LrfkLj1GulqTJBc_poGTYzKwcatMRo2o?purpose=fullsize)
## 1. Introduction

This module introduces **SQL Injection through MySQL**.

To understand SQL Injection properly, we first need to understand:

- MySQL
    
- MariaDB
    
- SQL
    
- Databases
    
- Tables
    
- Columns
    
- Rows
    
- Data types
    
- Primary keys
    
- Constraints
    
- MySQL commands
    
- Database users and privileges
    

The concepts learned here form the foundation for later SQL Injection techniques.

---

# 2. What is MySQL?

**MySQL** is a relational database management system (**RDBMS**) that uses SQL to interact with databases.

Conceptually:

```text
                    MySQL
                      │
                      ▼
             Relational DBMS
                      │
             ┌────────┴────────┐
             ▼                 ▼
         Database            SQL
             │
             ▼
           Tables
             │
       ┌─────┴─────┐
       ▼           ▼
     Rows        Columns
```

MySQL is widely used in web applications to store and retrieve information.

Examples include:

- User accounts
    
- Login information
    
- Posts
    
- Comments
    
- Products
    
- Orders
    
- Application data
    

---

# 3. MySQL and MariaDB

The examples in this module use **MySQL/MariaDB syntax**.

MariaDB is a database system closely related to MySQL, and many basic commands and concepts are compatible.

For this module, the important point is:

```text
MySQL / MariaDB
       ↓
    RDBMS
       ↓
      SQL
       ↓
Relational Database
```

---

# 4. Structured Query Language (SQL)

**SQL** stands for:

> **Structured Query Language**

SQL is used to communicate with relational databases.

Although SQL syntax can differ slightly between different RDBMS products, they generally follow the **ISO standard for SQL** while implementing their own extensions and syntax.

This module follows **MySQL/MariaDB syntax**.

---

# 5. What Can SQL Do?

SQL can be used to perform many database operations.

Important operations include:

### Retrieve Data

```sql
SELECT * FROM users;
```

### Update Data

```sql
UPDATE users SET username = 'newuser';
```

### Delete Data

```sql
DELETE FROM users;
```

### Create Tables

```sql
CREATE TABLE users (...);
```

### Create Databases

```sql
CREATE DATABASE users;
```

### Add Users

Database administrators can create database accounts.

### Remove Users

Database accounts can also be removed.

### Assign Permissions

Users can be given specific database privileges.

---

# 6. MySQL Command-Line Utility

The `mysql` utility allows us to authenticate to and interact with a MySQL/MariaDB database from the command line.

Basic syntax:

```bash
mysql -u <username> -p
```

Where:

```text
-u → Username
-p → Password prompt
```

---

# 7. Logging into MySQL

Example:

```bash
mysql -u root -p
```

The terminal then asks:

```text
Enter password:
```

After successful authentication:

```text
mysql>
```

The `mysql>` prompt indicates that we are now interacting with the MySQL server.

### Flow

```text
Terminal
   │
   ▼
mysql -u root -p
   │
   ▼
Password Prompt
   │
   ▼
Authentication
   │
   ▼
mysql>
```

---

# 8. Why Should We Use `-p` Without the Password?

The recommended method is:

```bash
mysql -u root -p
```

rather than:

```bash
mysql -u root -ppassword
```

The reason is security.

If the password is entered directly into the command line, it may potentially be exposed through:

- Terminal history
    
- Shell history
    
- Logs
    
- Process information in some environments
    

For example, Bash may store commands in:

```text
~/.bash_history
```

Therefore:

```bash
mysql -u root -p
```

is preferred.

---

# 9. Passing the Password Directly

It is technically possible to specify the password directly:

```bash
mysql -u root -ppassword
```

### Important Syntax

There should be **no space** between:

```text
-p
```

and the password.

Correct:

```bash
mysql -u root -ppassword
```

Not:

```bash
mysql -u root -p password
```

However, directly specifying passwords on the command line should generally be avoided because it can expose credentials.

---

# 10. MySQL Users and Privileges

MySQL has its own user accounts and permission system.

Different users can have different privileges.

For example:

```text
root
 ↓
Highly privileged
```

while:

```text
app_user
 ↓
Limited privileges
```

A database user may be allowed to:

- Read data
    
- Insert data
    
- Update data
    
- Delete data
    
- Create tables
    
- Create databases
    
- Manage users
    
- Grant privileges
    

depending on their permissions.

---

# 11. The `root` User

In the examples, `root` represents the MySQL superuser.

A superuser has very extensive privileges and can execute a large range of database operations.

Conceptually:

```text
                 MySQL
                   │
             ┌─────┴─────┐
             ▼           ▼
           root       normal user
             │           │
       High privileges  Limited
                         privileges
```

### Security Connection

This is important for SQL Injection.

If a vulnerable web application connects to MySQL using a highly privileged account, a successful SQL injection could have a much larger impact.

This is why the **principle of least privilege** is important.

---

# 12. SHOW GRANTS

MySQL provides the:

```sql
SHOW GRANTS;
```

command to view the privileges assigned to the current user.

Conceptually:

```text
Current User
     ↓
SHOW GRANTS
     ↓
Database Permissions
```

This becomes particularly useful when assessing what a database account is capable of doing.

---

# 13. Connecting to a Remote MySQL Server

If no host is specified, MySQL normally attempts to connect to the local host.

You can specify a remote host using:

```text
-h
```

The port can be specified using:

```text
-P
```

### Example

```bash
mysql -u root -h docker.hackthebox.eu -P 3306 -p
```

Here:

```text
-u → Username
-h → Host
-P → Port
-p → Password prompt
```

---

# 14. Important Difference Between `-p` and `-P`

This is a common point of confusion.

### Lowercase `-p`

Used for the **password**.

```bash
-p
```

### Uppercase `-P`

Used for the **port**.

```bash
-P 3306
```

Remember:

```text
-p → password
-P → port
```

---

# 15. MySQL Default Port

The default MySQL/MariaDB port is:

```text
3306
```

For example:

```bash
mysql -u root -h 10.10.10.10 -P 3306 -p
```

However, administrators can configure MySQL to listen on a different port.

Therefore, during security assessments, do not assume that MySQL always uses `3306`.

---

# 16. Creating a Database

After logging into MySQL, SQL commands can be used to interact with the DBMS.

A database can be created with:

```sql
CREATE DATABASE users;
```

The database is named:

```text
users
```

A successful command may return:

```text
Query OK, 1 row affected
```

---

# 17. Semicolon in MySQL

MySQL expects SQL statements entered through the command-line client to be terminated with a semicolon:

```text
;
```

Example:

```sql
CREATE DATABASE users;
```

Without the terminating semicolon, the client may continue waiting for the rest of the statement.

### Remember

```text
SQL statement + ;
```

---

# 18. Viewing Databases

To list available databases:

```sql
SHOW DATABASES;
```

Example output:

```text
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| users              |
+--------------------+
```

This allows us to see the databases available to the current account.

---

# 19. Selecting a Database

The `USE` statement selects a database for subsequent operations.

Example:

```sql
USE users;
```

Response:

```text
Database changed
```

After this, commands such as:

```sql
SHOW TABLES;
```

will operate against the selected database.

---

# 20. SQL Keywords and Case

SQL keywords are generally **not case-sensitive**.

For example:

```sql
USE users;
```

and:

```sql
use users;
```

refer to the same SQL command.

It is good practice to write SQL keywords in uppercase because it makes queries easier to read.

Recommended:

```sql
SELECT * FROM users;
```

instead of:

```sql
select * from users;
```

### Important Distinction

SQL statement keywords are generally case-insensitive, but **database/table/identifier case sensitivity can depend on the MySQL configuration and operating system**.

Therefore, do not assume that every database identifier is always case-sensitive or always case-insensitive.

---

# 21. Creating Tables

A DBMS stores data in **tables**.

A table consists of:

- Rows
    
- Columns
    

Conceptually:

```text
                 TABLE
                   │
          ┌────────┴────────┐
          ▼                 ▼
       Columns             Rows
          │                 │
     Data structure      Records
```

---

# 22. Rows

A **row** represents an individual record.

For example:

```text
1 | alice | password123
```

could represent one user.

Another row:

```text
2 | bob | password456
```

represents another user.

---

# 23. Columns

A **column** represents a particular property/attribute of the data.

For example:

```text
id
username
password
date_of_joining
```

Each column has a specific data type.

---

# 24. Cells

The intersection of a row and column is called a **cell**.

Example:

```text
+----+----------+
| id | username |
+----+----------+
| 1  | alice    |
+----+----------+
```

The cell containing:

```text
alice
```

is where the `username` column and first row intersect.

---

# 25. Data Types

A data type specifies what kind of data a column can store.

Common types include:

- Numbers
    
- Strings
    
- Dates
    
- Times
    
- Binary data
    

Different DBMSs also provide database-specific data types.

Choosing appropriate data types is important for:

- Data integrity
    
- Storage
    
- Query performance
    
- Application behavior
    

---

# 26. Common MySQL Data Types

### INT

Used for integers.

Example:

```sql
id INT
```

Values might include:

```text
1
25
1000
```

---

### VARCHAR

Used for variable-length strings.

Example:

```sql
username VARCHAR(100)
```

This allows a string with a maximum length defined by the declaration.

---

### DATETIME

Used to store date and time information.

Example:

```sql
date_of_joining DATETIME
```

Example value:

```text
2026-08-25 13:30:00
```

---

# 27. Creating a Basic Table

Example:

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
);
```

This creates a table called:

```text
logins
```

with four columns:

```text
id
username
password
date_of_joining
```

---

# 28. Understanding the CREATE TABLE Statement

Let's break it down:

```sql
CREATE TABLE logins (
```

Creates a table called `logins`.

Then:

```sql
id INT,
```

creates an integer column named `id`.

Then:

```sql
username VARCHAR(100),
```

creates a string column called `username`.

Then:

```sql
password VARCHAR(100),
```

creates a string column called `password`.

Finally:

```sql
date_of_joining DATETIME
```

creates a date/time column.

The statement ends with:

```sql
);
```

---

# 29. Table Structure

The resulting table can be visualized as:

```text
logins

+----+----------+----------+----------------+
| id | username | password | date_of_joining|
+----+----------+----------+----------------+
|    |          |          |                |
+----+----------+----------+----------------+
```

The table initially contains **zero records**.

---

# 30. VARCHAR Length

Consider:

```sql
username VARCHAR(100)
```

This defines the maximum length for the column according to the specified `VARCHAR` definition.

The database enforces the applicable length constraints.

Therefore, applications should select appropriate lengths based on the data they expect to store.

---

# 31. SHOW TABLES

To list tables in the currently selected database:

```sql
SHOW TABLES;
```

Example:

```text
+-----------------+
| Tables_in_users |
+-----------------+
| logins          |
+-----------------+
```

This tells us that the `users` database contains a table called:

```text
logins
```

---

# 32. DESCRIBE

The `DESCRIBE` statement can be used to view the structure of a table.

Example:

```sql
DESCRIBE logins;
```

This displays information such as:

- Column names
    
- Data types
    
- Other table properties
    

Example:

```text
+-----------------+--------------+
| Field           | Type         |
+-----------------+--------------+
| id              | int          |
| username        | varchar(100) |
| password        | varchar(100) |
| date_of_joining | datetime     |
+-----------------+--------------+
```

### Remember

```text
SHOW TABLES
    ↓
List tables

DESCRIBE table
    ↓
Show table structure
```

---

# 33. Table Properties

When creating a table, we can specify additional properties and constraints.

Important properties include:

- `AUTO_INCREMENT`
    
- `NOT NULL`
    
- `UNIQUE`
    
- `DEFAULT`
    
- `PRIMARY KEY`
    

These properties help enforce rules on the data.

---

# 34. AUTO_INCREMENT

`AUTO_INCREMENT` automatically generates an increasing numeric value when a new record is inserted.

Example:

```sql
id INT NOT NULL AUTO_INCREMENT
```

Conceptually:

```text
First record  → ID 1
Second record → ID 2
Third record  → ID 3
Fourth record → ID 4
```

This is commonly used for ID columns.

---

# 35. NOT NULL

The `NOT NULL` constraint means that a column cannot contain the SQL `NULL` value.

Example:

```sql
username VARCHAR(100) NOT NULL
```

This means a username must be provided rather than being left as `NULL`.

### Concept

```text
NOT NULL
   ↓
Value is required
```

---

# 36. UNIQUE

The `UNIQUE` constraint ensures that values in a column are not duplicated in ways prohibited by that constraint.

Example:

```sql
username VARCHAR(100) UNIQUE NOT NULL
```

This can prevent two users from having the same username.

Example:

```text
alice  ✓
bob    ✓
alice  ✗
```

The duplicate `alice` would violate the uniqueness constraint.

---

# 37. DEFAULT

The `DEFAULT` keyword specifies a value that should be used when an appropriate value is not supplied during insertion.

For example:

```sql
date_of_joining DATETIME DEFAULT NOW()
```

`NOW()` returns the current date and time in MySQL.

Therefore, when a record is created without explicitly specifying `date_of_joining`, MySQL can use the current timestamp according to the column's default definition.

---

# 38. PRIMARY KEY

The `PRIMARY KEY` is one of the most important concepts in relational databases.

It uniquely identifies a record within a table.

For example:

```sql
PRIMARY KEY (id)
```

This makes the `id` column the table's primary key.

Conceptually:

```text
+----+----------+
| id | username |
+----+----------+
| 1  | alice    |
| 2  | bob      |
| 3  | charlie  |
+----+----------+
```

The `id` uniquely identifies each record.

---

# 39. Primary Key + AUTO_INCREMENT

A very common design is:

```sql
id INT NOT NULL AUTO_INCREMENT,
PRIMARY KEY (id)
```

This gives us:

```text
Unique ID
   +
Automatically Generated
   +
Cannot be NULL
```

This is a common pattern for relational database tables.

---

# 40. Complete `logins` Table

Combining the properties:

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);
```

This creates a `logins` table with:

|Column|Type|Properties|
|---|---|---|
|`id`|`INT`|`NOT NULL`, `AUTO_INCREMENT`, `PRIMARY KEY`|
|`username`|`VARCHAR(100)`|`UNIQUE`, `NOT NULL`|
|`password`|`VARCHAR(100)`|`NOT NULL`|
|`date_of_joining`|`DATETIME`|`DEFAULT NOW()`|

---

# 41. Complete MySQL Workflow

A typical basic workflow looks like:

```text
1. Connect to MySQL
        ↓
2. List databases
        ↓
3. Select database
        ↓
4. Create / inspect tables
        ↓
5. Insert data
        ↓
6. Retrieve data
        ↓
7. Update data
        ↓
8. Delete data
```

Commands:

```bash
mysql -u root -p
```

Then:

```sql
SHOW DATABASES;

USE users;

SHOW TABLES;

DESCRIBE logins;
```

---

# 42. MySQL Command Cheat Sheet

|Command|Purpose|
|---|---|
|`mysql -u root -p`|Connect to MySQL|
|`mysql -u root -h HOST -P PORT -p`|Connect to remote MySQL|
|`SHOW DATABASES;`|List databases|
|`CREATE DATABASE name;`|Create database|
|`USE database;`|Select database|
|`SHOW TABLES;`|List tables|
|`DESCRIBE table;`|Show table structure|
|`CREATE TABLE ...`|Create table|
|`SHOW GRANTS;`|Display current user's privileges|

---

# 43. MySQL Flags Cheat Sheet

|Flag|Purpose|Example|
|---|---|---|
|`-u`|Username|`-u root`|
|`-p`|Password prompt|`-p`|
|`-h`|Host|`-h 10.10.10.10`|
|`-P`|Port|`-P 3306`|

### Memorize This

```text
-u → user
-p → password
-h → host
-P → port
```

---

# 44. MySQL Security Considerations

When interacting with MySQL during security testing, several things are important.

### 1. Credentials

Avoid putting passwords directly into commands.

Prefer:

```bash
mysql -u root -p
```

over:

```bash
mysql -u root -ppassword
```

### 2. Privileges

Determine what the current database account is allowed to do.

```sql
SHOW GRANTS;
```

### 3. Network Exposure

MySQL commonly uses port:

```text
3306
```

but administrators can configure another port.

### 4. Least Privilege

Applications should not unnecessarily connect using highly privileged accounts.

---

# 45. Connection to SQL Injection

Everything in this section prepares us for SQL Injection.

A web application might perform a query such as:

```sql
SELECT * FROM logins
WHERE username = 'alice'
AND password = 'password';
```

The application sends the query to MySQL:

```text
User Input
    ↓
Web Application
    ↓
SQL Query
    ↓
MySQL
    ↓
Database
    ↓
Result
```

If user-controlled input is improperly incorporated into the SQL query, the query's structure may be manipulated.

That is the fundamental concept behind **SQL Injection**.

---

# 46. Important Concepts for SQLi

Before moving into SQL Injection techniques, make sure you understand:

### Database

```text
Container for organized data
```

### Table

```text
Collection of related records
```

### Column

```text
Property / field
```

### Row

```text
Individual record
```

### Primary Key

```text
Unique record identifier
```

### SQL Query

```text
Instruction sent to the database
```

### DBMS

```text
Software managing the database
```

### MySQL

```text
Relational DBMS
```

---

# 47. Full Architecture

Put everything together:

```text
                       USER
                         │
                         ▼
                ┌────────────────┐
                │ Web Application │
                └───────┬────────┘
                        │
                        │ SQL Query
                        ▼
                ┌────────────────┐
                │     MySQL      │
                │      DBMS      │
                └───────┬────────┘
                        │
                        ▼
                  ┌───────────┐
                  │ Database  │
                  │           │
                  │ ┌───────┐ │
                  │ │ Table │ │
                  │ └───────┘ │
                  └───────────┘
```

---

# 48. Key Terms

|Term|Definition|
|---|---|
|MySQL|Relational Database Management System|
|MariaDB|Relational database system closely related to MySQL|
|SQL|Structured Query Language|
|DBMS|Database Management System|
|Database|Organized collection of data|
|Table|Structure containing rows and columns|
|Row|Individual database record|
|Column|Attribute/field of a table|
|Cell|Intersection of a row and column|
|Data Type|Defines what kind of value a column stores|
|`INT`|Integer data type|
|`VARCHAR`|Variable-length string data type|
|`DATETIME`|Date and time data type|
|Primary Key|Uniquely identifies a record|
|Foreign Key|References a key in another table|
|`AUTO_INCREMENT`|Automatically generates increasing numeric values|
|`NOT NULL`|Prevents a column from containing `NULL`|
|`UNIQUE`|Enforces uniqueness|
|`DEFAULT`|Specifies a default value|
|`SHOW DATABASES`|Lists databases|
|`SHOW TABLES`|Lists tables|
|`DESCRIBE`|Displays table structure|
|`SHOW GRANTS`|Displays privileges|

---

# 49. Most Important Things to Memorize

> **MySQL is a relational database management system.**

> **SQL stands for Structured Query Language.**

> **SQL can retrieve, update, delete, and create database information and structures.**

> **The `mysql` command-line utility is used to authenticate and interact with MySQL/MariaDB.**

> **Use `-u` for the username and `-p` for the password prompt.**

> **Use `-h` for the host and uppercase `-P` for the port.**

> **The default MySQL/MariaDB port is 3306, although it can be changed.**

> **Avoid putting passwords directly into command-line arguments because they may be exposed through history or logs.**

> **SQL statements entered in the MySQL client are normally terminated with `;`.**

> **`SHOW DATABASES;` lists databases.**

> **`USE database;` selects a database.**

> **`SHOW TABLES;` lists tables in the selected database.**

> **`DESCRIBE table;` displays a table's structure.**

> **`INT` stores integer values.**

> **`VARCHAR` stores variable-length strings.**

> **`DATETIME` stores date and time values.**

> **`AUTO_INCREMENT` automatically generates increasing numeric IDs.**

> **`NOT NULL` prevents a column from containing `NULL`.**

> **`UNIQUE` prevents duplicate values where the constraint applies.**

> **`DEFAULT` provides a default value when one isn't supplied.**

> **`PRIMARY KEY` uniquely identifies records in a table.**

---

# 50. Quick Revision Sheet

## Connecting

```bash
mysql -u root -p
```

Remote:

```bash
mysql -u root -h <HOST> -P <PORT> -p
```

---

## Database Commands

```sql
SHOW DATABASES;

CREATE DATABASE users;

USE users;
```

---

## Table Commands

```sql
SHOW TABLES;

DESCRIBE logins;
```

---

## Create Basic Table

```sql
CREATE TABLE logins (
    id INT,
    username VARCHAR(100),
    password VARCHAR(100),
    date_of_joining DATETIME
);
```

---

## Create Improved Table

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);
```

---

# 51. Final Takeaway

The core MySQL structure to remember is:

```text
                  MySQL
                    │
                    ▼
                Database
                    │
                    ▼
                 Tables
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
       Columns              Rows
          │                   │
          ▼                   ▼
     Data Types            Records
```

And the basic workflow is:

```text
CONNECT
   ↓
SHOW DATABASES
   ↓
USE DATABASE
   ↓
SHOW TABLES
   ↓
DESCRIBE TABLE
   ↓
QUERY DATA
```

### Most Important SQLi Connection

The ultimate concept to carry forward is:

```text
              USER INPUT
                  │
                  ▼
           WEB APPLICATION
                  │
                  ▼
              SQL QUERY
                  │
                  ▼
                MySQL
                  │
                  ▼
              DATABASE
```

If the application incorrectly allows **untrusted input to alter the structure of the SQL query**, SQL Injection can occur.

So the learning path is:

```text
Databases
    ↓
Relational Databases
    ↓
RDBMS
    ↓
MySQL
    ↓
SQL
    ↓
Tables / Rows / Columns / Keys
    ↓
SQL Queries
    ↓
SQL Injection
```

This MySQL foundation is essential for understanding everything that follows in the SQL Injection module.