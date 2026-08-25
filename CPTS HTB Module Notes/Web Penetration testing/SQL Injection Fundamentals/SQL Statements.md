![Image](https://images.openai.com/static-rsc-4/F9y-yVRqPD_QF3gtasaaovezBO9pbCRtMXzumwj9g82elEmCEPQQD_nxMYxfCy-SkNAEbnlwnhoUV80To2SxiRcPnWiAjGlmujAoRdLRgfzV5MfYGhOYMBjZ9AlMmGQNLd2BLdR0WREg8XzCBIzMFtJTiCEQ_o-d_0r3q4c5XLCGyImZiSUbjwswvrlXseII?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/B9Z-b1kf5fCqmxN7rDTUfissxnlj8ZJTQwmyomxOUIOxCcU5pdm7R7IyyiJ_GRqP8fArCjLsNjyXf-N23kQVsYoRDCd46tVsIqD3jXRuYzsCIJl3c7B3ms1W2yttKimxQWpFDtRXhIsMl6uSKO5JX_tAeTeA6U6Znj964CsnkH2vlrfKjxeISInRnGLrd8v-?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/xn_W7v9FTYJJxGgShFz-IOil5YrayE3zlqxLEV-bnZdVTiu-E4OvFZ6Va4gJMmK1lC85wU7dmX_Av4oZs5AYccTO-1L_B9kGtfcUQPgUD7Fv2o4d-LCtQ-OixWPYXxaiu2l-dEbR0fmQnLSFX5v8N2z664rsJonZkVyk-OqBvtZNPQYbQCDjHq4mIhyaShcu?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/zWo3Bte57Gnt2TutyPfJjNOialvwGSrOyWuxFk0LojOy11PyUff1dIAapHCy9NfLjsTxhQQmreYi3pk7tyy-L239PRb9pXweP8G-MtCwY9Pu7IBgdgxUMCiUVm4rL46srVxWPQrRqXdk870NUY-TGQZMkFU-jlBle632jdhig_YUkYqp6atdENvkmA65trT3?purpose=fullsize)
## 1. Introduction

Now that we understand:

- MySQL
    
- Databases
    
- Tables
    
- Columns
    
- Rows
    
- Data types
    
- Primary keys
    
- Basic MySQL commands
    

we can start learning the essential **SQL statements**.

SQL statements are instructions sent to the database to perform specific operations.

The major statements covered in this section are:

```text
SQL STATEMENTS
│
├── INSERT  → Add records
├── SELECT  → Retrieve records
├── DROP    → Remove database objects
├── ALTER   → Change table structure
└── UPDATE  → Modify records
```

These statements are fundamental to understanding SQL and later understanding SQL Injection.

---

# 2. INSERT Statement

The `INSERT` statement is used to **add new records to a table**.

### Basic Syntax

```sql
INSERT INTO table_name
VALUES (column1_value, column2_value, column3_value, ...);
```

The values are supplied in the same order as the columns in the table.

---

# 3. INSERT — Complete Example

Suppose we have:

```text
logins

+----+----------+----------+----------------+
| id | username | password | date_of_joining|
+----+----------+----------+----------------+
```

We can insert a record:

```sql
INSERT INTO logins
VALUES (1, 'admin', 'p@ssw0rd', '2020-07-02');
```

This inserts one record.

Conceptually:

```text
INSERT
  ↓
logins table
  ↓
New Row
```

Result:

```text
+----+----------+----------+----------------+
| id | username | password | date_of_joining|
+----+----------+----------+----------------+
| 1  | admin    | p@ssw0rd | 2020-07-02     |
+----+----------+----------+----------------+
```

---

# 4. INSERT with Specific Columns

We don't always need to provide values for every column.

This is especially useful when some columns have:

- `AUTO_INCREMENT`
    
- `DEFAULT`
    
- Other automatically generated values
    

### Syntax

```sql
INSERT INTO table_name(column2, column3, ...)
VALUES (column2_value, column3_value, ...);
```

Example:

```sql
INSERT INTO logins(username, password)
VALUES ('administrator', 'adm1n_p@ss');
```

Here we don't specify:

```text
id
date_of_joining
```

because they can be generated automatically based on the table definition.

---

# 5. Why Can We Skip Columns?

Consider our table:

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);
```

When we execute:

```sql
INSERT INTO logins(username, password)
VALUES ('administrator', 'adm1n_p@ss');
```

MySQL can generate:

```text
id              → AUTO_INCREMENT
date_of_joining → DEFAULT NOW()
```

So the resulting record conceptually becomes:

```text
id              → Automatically generated
username        → administrator
password        → adm1n_p@ss
date_of_joining → Current date/time
```

---

# 6. NOT NULL and INSERT

There is an important restriction.

If a column has:

```sql
NOT NULL
```

and does not have an applicable default value, you generally need to provide a value for it.

For example:

```sql
username VARCHAR(100) NOT NULL
```

An INSERT that does not provide `username` can result in an error.

### Remember

```text
NOT NULL
   ↓
Required value
```

while:

```text
DEFAULT
   ↓
Database can provide a default value
```

---

# 7. Inserting Multiple Records

SQL allows multiple rows to be inserted in a single `INSERT` statement.

Example:

```sql
INSERT INTO logins(username, password)
VALUES
('john', 'john123!'),
('tom', 'tom123!');
```

This inserts two records.

Conceptually:

```text
INSERT
  │
  ├──► John
  │
  └──► Tom
```

Result:

```text
+----+---------------+------------+
| id | username      | password   |
+----+---------------+------------+
| 1  | admin         | p@ssw0rd   |
| 2  | administrator | adm1n_p@ss |
| 3  | john          | john123!   |
| 4  | tom           | tom123!    |
+----+---------------+------------+
```

---

# 8. Security Note — Password Storage

The examples in the module use passwords in cleartext for demonstration.

This is **not a secure way to store passwords**.

Real applications should not store users' passwords as plaintext.

Instead, passwords should be stored using a strong password hashing scheme designed for password storage.

### Important distinction

```text
Plaintext password
       ↓
      BAD
```

versus:

```text
Password
    ↓
Password Hashing Function
    ↓
Stored Password Hash
```

Also remember:

> Encryption and password hashing are not the same thing.

Password storage should normally use an appropriate password hashing algorithm rather than reversible encryption.

---

# 9. SELECT Statement

The `SELECT` statement is used primarily to **retrieve data** from a database.

### Basic Syntax

```sql
SELECT * FROM table_name;
```

The `*` is a wildcard representing **all columns** in this context.

The `FROM` keyword specifies which table the data should be retrieved from.

---

# 10. SELECT All Columns

Example:

```sql
SELECT * FROM logins;
```

This requests all columns and all matching rows from the `logins` table.

Example result:

```text
+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
| 1  | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
| 2  | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
| 3  | john          | john123!   | 2020-07-02 11:47:16 |
| 4  | tom           | tom123!    | 2020-07-02 11:47:16 |
+----+---------------+------------+---------------------+
```

---

# 11. SELECT Specific Columns

We don't always need every column.

We can specify exactly which columns we want.

### Syntax

```sql
SELECT column1, column2
FROM table_name;
```

Example:

```sql
SELECT username, password
FROM logins;
```

Result:

```text
+---------------+------------+
| username      | password   |
+---------------+------------+
| admin         | p@ssw0rd   |
| administrator | adm1n_p@ss |
| john          | john123!   |
| tom           | tom123!    |
+---------------+------------+
```

The database returns only:

```text
username
password
```

instead of:

```text
id
username
password
date_of_joining
```

---

# 12. `SELECT *` vs Specific Columns

### All columns

```sql
SELECT * FROM logins;
```

Means:

```text
Return all columns
```

### Specific columns

```sql
SELECT username, password
FROM logins;
```

Means:

```text
Return only username and password
```

### Security Perspective

Applications should generally retrieve only the data they actually need.

Returning unnecessary sensitive information can increase the impact of a vulnerability.

---

# 13. DROP Statement

The `DROP` statement is used to **completely remove database objects**.

For example:

```sql
DROP TABLE logins;
```

This removes the entire `logins` table.

Afterward:

```sql
SHOW TABLES;
```

may return:

```text
Empty set
```

---

# 14. DROP TABLE

Example:

```sql
DROP TABLE logins;
```

Conceptually:

```text
Before:

Database
   │
   └── logins table
          │
          ├── Row 1
          ├── Row 2
          └── Row 3


After:

Database
   │
   └── No logins table
```

### Important Warning

`DROP TABLE` is destructive.

It removes the table itself and its stored data.

Therefore:

> **Use `DROP` with extreme caution.**

---

# 15. DROP vs DELETE

This distinction is extremely important.

### DROP

```sql
DROP TABLE logins;
```

Removes the **table itself**.

### DELETE

```sql
DELETE FROM logins;
```

Removes **records from the table**, while leaving the table structure in place.

Conceptually:

```text
DROP
 ↓
Table + Data
 ↓
Removed
```

while:

```text
DELETE
 ↓
Rows
 ↓
Removed
Table remains
```

---

# 16. ALTER Statement

The `ALTER` statement is used to modify the **structure/properties of an existing table**.

It can be used to:

- Add columns
    
- Remove columns
    
- Rename columns
    
- Modify column definitions
    
- Make other structural changes
    

### Important distinction

```text
ALTER
 ↓
Changes table structure
```

while:

```text
UPDATE
 ↓
Changes data inside existing rows
```

---

# 17. ADD Column with ALTER

Suppose we have:

```text
logins
```

We can add a new column:

```sql
ALTER TABLE logins
ADD newColumn INT;
```

The table now has an additional column:

```text
id
username
password
date_of_joining
newColumn
```

---

# 18. RENAME COLUMN

We can rename an existing column.

Example:

```sql
ALTER TABLE logins
RENAME COLUMN newColumn TO newerColumn;
```

Now:

```text
newColumn
```

becomes:

```text
newerColumn
```

Conceptually:

```text
Before:
newColumn

       ↓ RENAME

After:
newerColumn
```

---

# 19. MODIFY Column

The `MODIFY` operation can change the definition of a column.

Example:

```sql
ALTER TABLE logins
MODIFY newerColumn DATE;
```

The column's type changes to:

```text
DATE
```

This is useful when the existing column definition needs to be changed.

---

# 20. DROP Column with ALTER

An individual column can also be removed:

```sql
ALTER TABLE logins
DROP newerColumn;
```

This removes that column from the table.

### Important

This is different from:

```sql
DROP TABLE logins;
```

because:

```text
ALTER TABLE ... DROP column
        ↓
Removes one column
```

while:

```text
DROP TABLE
        ↓
Removes entire table
```

---

# 21. ALTER Summary

|Operation|Example|
|---|---|
|Add column|`ALTER TABLE logins ADD newColumn INT;`|
|Rename column|`ALTER TABLE logins RENAME COLUMN newColumn TO newerColumn;`|
|Modify column|`ALTER TABLE logins MODIFY newerColumn DATE;`|
|Remove column|`ALTER TABLE logins DROP newerColumn;`|

---

# 22. UPDATE Statement

The `UPDATE` statement is used to **modify existing records** in a table.

This is different from `ALTER`.

### ALTER

Changes the **structure**.

### UPDATE

Changes the **data**.

---

# 23. UPDATE Syntax

General syntax:

```sql
UPDATE table_name
SET column1 = newvalue1,
    column2 = newvalue2
WHERE <condition>;
```

The important parts are:

```text
UPDATE
   ↓
Which table?

SET
   ↓
What should change?

WHERE
   ↓
Which records should change?
```

---

# 24. UPDATE Example

Consider:

```sql
UPDATE logins
SET password = 'change_password'
WHERE id > 1;
```

This means:

> Change the `password` column to `change_password` for every record whose `id` is greater than 1.

Before:

```text
+----+---------------+------------+
| id | username      | password   |
+----+---------------+------------+
| 1  | admin         | p@ssw0rd   |
| 2  | administrator | adm1n_p@ss |
| 3  | john          | john123!   |
| 4  | tom           | tom123!    |
+----+---------------+------------+
```

After:

```text
+----+---------------+-----------------+
| id | username      | password        |
+----+---------------+-----------------+
| 1  | admin         | p@ssw0rd        |
| 2  | administrator | change_password |
| 3  | john          | change_password |
| 4  | tom           | change_password |
+----+---------------+-----------------+
```

Three records were changed because:

```text
id > 1
```

matches:

```text
2
3
4
```

---

# 25. The Importance of WHERE

The `WHERE` clause determines which records are affected by an operation.

This is especially important with:

```sql
UPDATE
```

and:

```sql
DELETE
```

For example:

```sql
UPDATE logins
SET password = 'new_password'
WHERE id = 2;
```

Only the record with:

```text
id = 2
```

is targeted.

---

# 26. Dangerous UPDATE Without WHERE

Consider:

```sql
UPDATE logins
SET password = 'new_password';
```

There is no `WHERE` clause.

Therefore, the statement can update **all applicable rows** in the table.

Conceptually:

```text
UPDATE
   ↓
No WHERE
   ↓
All rows affected
```

This is why `WHERE` conditions should be carefully checked before running destructive or modifying queries.

---

# 27. Dangerous DELETE Without WHERE

The same principle applies to `DELETE`.

For example:

```sql
DELETE FROM logins
WHERE id = 2;
```

targets a specific record.

But:

```sql
DELETE FROM logins;
```

can remove all records from the table.

The table itself remains, but its rows can be removed.

---

# 28. SQL Statements — Big Picture

The statements covered in this section can be organized as:

```text
                    SQL
                     │
        ┌────────────┼─────────────┐
        ▼            ▼             ▼
      INSERT       SELECT        UPDATE
        │            │             │
     Add Data    Read Data     Modify Data

                     │
              ┌──────┴──────┐
              ▼             ▼
            ALTER          DROP
              │             │
        Change Structure   Remove
                          Object
```

---

# 29. INSERT vs UPDATE

This is another important distinction.

### INSERT

Creates a **new record**.

```sql
INSERT INTO logins(username, password)
VALUES ('john', 'john123!');
```

```text
Existing rows
     +
New row
```

### UPDATE

Changes an **existing record**.

```sql
UPDATE logins
SET password = 'newpass'
WHERE id = 3;
```

```text
Existing row
     ↓
Modified row
```

---

# 30. ALTER vs UPDATE

### ALTER

Changes table structure.

```sql
ALTER TABLE logins
ADD email VARCHAR(100);
```

The table structure changes:

```text
Before:
id | username | password

After:
id | username | password | email
```

### UPDATE

Changes the data:

```sql
UPDATE logins
SET email = 'user@example.com'
WHERE id = 1;
```

The structure stays the same; the record's data changes.

---

# 31. DROP vs ALTER DROP

These can be confusing.

### Drop Entire Table

```sql
DROP TABLE logins;
```

Result:

```text
Entire table removed
```

### Drop a Column

```sql
ALTER TABLE logins
DROP newerColumn;
```

Result:

```text
Only newerColumn removed
```

---

# 32. SQL Statement Comparison

|Statement|Purpose|Affects|
|---|---|---|
|`INSERT`|Add records|Data|
|`SELECT`|Retrieve records|Data retrieval|
|`UPDATE`|Modify records|Data|
|`ALTER`|Modify table structure|Schema|
|`DROP`|Remove database object|Table/database/object|

---

# 33. SQL Operations and CRUD

CRUD stands for:

```text
C → Create
R → Read
U → Update
D → Delete
```

Mapping the SQL statements:

|CRUD|SQL|
|---|---|
|Create|`INSERT`|
|Read|`SELECT`|
|Update|`UPDATE`|
|Delete|`DELETE`|

Note that `DROP` is not simply the same thing as CRUD `DELETE`: `DROP` removes a database object such as a table, not merely its records.

---

# 34. Practical Workflow

A basic database workflow might look like:

### Step 1 — Create Database

```sql
CREATE DATABASE users;
```

### Step 2 — Select Database

```sql
USE users;
```

### Step 3 — Create Table

```sql
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
);
```

### Step 4 — Insert Data

```sql
INSERT INTO logins(username, password)
VALUES ('admin', 'password');
```

### Step 5 — Retrieve Data

```sql
SELECT * FROM logins;
```

### Step 6 — Update Data

```sql
UPDATE logins
SET password = 'new_password'
WHERE id = 1;
```

### Step 7 — Modify Structure

```sql
ALTER TABLE logins
ADD email VARCHAR(100);
```

### Step 8 — Remove Table

```sql
DROP TABLE logins;
```

---

# 35. Connection to SQL Injection

These statements are important for SQL Injection because an attacker may attempt to manipulate the SQL query executed by a vulnerable application.

For example, a web application might internally execute:

```sql
SELECT * FROM logins
WHERE username = '<USER_INPUT>'
AND password = '<PASSWORD_INPUT>';
```

The application takes:

```text
User Input
    ↓
SQL Query
    ↓
MySQL
```

If the application incorrectly constructs the query, the attacker may attempt to alter the query's logic.

The key concept is:

```text
Normal:

Input → Data

Vulnerable:

Input → SQL Syntax + Data
```

This distinction is the foundation of SQL Injection.

---

# 36. Why SELECT Is Especially Important for SQLi

`SELECT` is particularly important because it retrieves information from the database.

A vulnerable application may execute:

```sql
SELECT username, password
FROM logins
WHERE username = '<INPUT>';
```

If an attacker can manipulate the query, they may potentially influence:

- Which records are returned
    
- Which columns are returned
    
- How conditions are evaluated
    
- Whether additional query results can be incorporated
    

This is why understanding `SELECT`, `FROM`, and eventually `WHERE`, `UNION`, and related SQL concepts is essential for the SQLi module.

---

# 37. Why UPDATE and DROP Matter

SQL Injection is not limited to reading data.

Depending on the DBMS, application, privileges, and injection context, SQL injection can potentially have effects beyond data retrieval.

For example, excessive privileges can increase the possible impact of database manipulation.

Conceptually:

```text
SQL Injection
      │
      ├──► SELECT → Read
      │
      ├──► UPDATE → Modify
      │
      ├──► INSERT → Add
      │
      └──► Destructive Operations
```

Whether a particular operation is possible depends on the application's query context, DBMS behavior, and database privileges.

---

# 38. Important SQL Keywords

|Keyword|Meaning|
|---|---|
|`INSERT INTO`|Insert records into a table|
|`VALUES`|Specifies values to insert|
|`SELECT`|Retrieve data|
|`FROM`|Specifies source table|
|`UPDATE`|Modify existing records|
|`SET`|Specifies new values|
|`WHERE`|Filters records affected by a query|
|`ALTER TABLE`|Modify table structure|
|`ADD`|Add a column|
|`RENAME COLUMN`|Rename a column|
|`MODIFY`|Change a column definition|
|`DROP`|Remove an object/column|
|`*`|Wildcard; in `SELECT`, represents all columns|

---

# 39. Important Things to Memorize

> **INSERT is used to add new records.**

> **SELECT is used to retrieve data.**

> **UPDATE is used to modify existing records.**

> **ALTER is used to modify the structure of an existing table.**

> **DROP can permanently remove database objects such as tables.**

> **The `WHERE` clause determines which records are affected by operations such as UPDATE and DELETE.**

> **An UPDATE without an appropriate WHERE clause can modify all applicable records.**

> **A DELETE without a WHERE clause can remove all rows from a table.**

> **INSERT can specify only selected columns when omitted columns can be automatically/defaulted appropriately.**

> **Multiple records can be inserted with a single INSERT statement by separating value sets with commas.**

> **Passwords should not be stored in plaintext in real applications.**

> **`SELECT *` retrieves all columns from the selected table in the query context.**

> **DROP TABLE removes the entire table, whereas ALTER TABLE ... DROP removes a specific column.**

---

# 40. Quick Revision Cheat Sheet

## INSERT

```sql
INSERT INTO table_name
VALUES (...);
```

Specific columns:

```sql
INSERT INTO table_name(column1, column2)
VALUES (value1, value2);
```

Multiple rows:

```sql
INSERT INTO table_name(column1, column2)
VALUES
(value1, value2),
(value3, value4);
```

**Purpose:** Add data.

---

## SELECT

All columns:

```sql
SELECT * FROM table_name;
```

Specific columns:

```sql
SELECT column1, column2
FROM table_name;
```

**Purpose:** Read/retrieve data.

---

## UPDATE

```sql
UPDATE table_name
SET column1 = new_value
WHERE condition;
```

**Purpose:** Modify existing data.

---

## ALTER

Add:

```sql
ALTER TABLE table_name
ADD column_name INT;
```

Rename:

```sql
ALTER TABLE table_name
RENAME COLUMN old_name TO new_name;
```

Modify:

```sql
ALTER TABLE table_name
MODIFY column_name DATE;
```

Remove column:

```sql
ALTER TABLE table_name
DROP column_name;
```

**Purpose:** Change table structure.

---

## DROP

```sql
DROP TABLE table_name;
```

**Purpose:** Remove the entire table.

---

# 41. Final Mental Model

Think of SQL statements like this:

```text
                 DATABASE
                    │
                    ▼
                  TABLE
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
      ADD          READ        MODIFY
       │            │            │
    INSERT        SELECT       UPDATE
                                  │
                                  │
                            ┌─────┴─────┐
                            ▼           ▼
                         ALTER        DROP
                       Structure     Object
```

### The five statements from this section:

```text
INSERT → Add
SELECT → Read
UPDATE → Modify data
ALTER  → Modify structure
DROP   → Remove object
```

### The most important distinction:

```text
ALTER  = Change the table
UPDATE = Change the data
DROP   = Remove the table/object
INSERT = Add data
SELECT = Read data
```

And the SQL Injection connection is:

```text
                 USER
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

Understanding exactly how these statements work is essential because **SQL Injection is fundamentally about manipulating SQL statements through improperly handled input**.