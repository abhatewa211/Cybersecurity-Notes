![Image](https://images.openai.com/static-rsc-4/mUdUgJuqryYdEOQpomO9YlLfqLpKpuQLhNhwHEbs9UTUcaWiV40dd80Pvn5aU-PLMq23mh1axmxGy2LcaKqA1tnwcfdg_xpV-BNIK4-T2Ou6KFHMk3sE3z9sH11mAXZ6ZfwgjMOj33sEZ1F-1YOouuv4mJHLLfofP9erUHG9Ustf8OnZZhg9NKlWgcnElfFR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/uZ0O0nrakhMrjK83XBs0RJkt8xN5hh8EOEIynrf2zEYApet7a3ObhDWF3sgIQfagnqVRmQGib2xfeH2BAiDEDhk3OMyxpMtax7IoUnzmdDtxYEPjXXVi36XOeGPOWyQpXdkTVOraVTV4aTz212TAoFcPYDU_ixyBpdEReZ7DxCjxfVGy5ZZuOjctLaXI7-Y5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/6Eu7SqjO8qLhHu726zGAUn0ufKhCzHRvn1dSCnPv1s3vIUBJRk1PvIrG16V-Rspbw87-gHKuNRhDvMrTfWfU50P6CJqoGn37ZbIlw79Zf-A3VjEu6McwHkU8RXGTqip20ewWheGZ7o74uLBZJwvdvc3qS7oU5hbf_-tr-S5P4NvVhjnHNuwyUigXlIxfvTTR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pwhmOk37i2FTVR2JOM83PRjAP0D5vA1Etxx1CtexF-gXjNLMPjSVWUcnapcxSvlWYgles5n3rSxgWj7rJ5_YkYc8Bozy_7c3_jEjZD9W5k5P-jUelb6IRKEt8RfaIlfIPs2GWAdR7bS63iD-zG9bolSdE3tTxHT52lZd2B_PEZ9R0k_7ZmodjhZJZyYfgSCX?purpose=fullsize)

---

# 1. What Is Database Enumeration?

**Enumeration** means systematically discovering information about the database structure.

Instead of immediately trying to retrieve unknown data, we first discover:

```text
What DBMS is this?
        ↓
What databases exist?
        ↓
Which tables exist?
        ↓
Which columns exist?
        ↓
Which data do those columns contain?
```

This is much more reliable than guessing table or column names.

---

# 2. The Database Enumeration Hierarchy ⭐

This is the most important mental model for this section:

```text
                    DBMS
                     │
                     ▼
                 Databases
                     │
                     ▼
                   Tables
                     │
                     ▼
                  Columns
                     │
                     ▼
                    Data
```

For example:

```text
MariaDB
   │
   ├── ilfreight
   │     └── ports
   │
   └── dev
         ├── credentials
         ├── framework
         ├── pages
         └── posts
                │
                └── columns
```

---

# 3. Why Fingerprinting Comes First

Different DBMS products have different:

- Syntax
    
- Functions
    
- Metadata structures
    
- System databases
    
- Version functions
    
- SQL behavior
    

For example:

```text
MySQL / MariaDB
MSSQL
PostgreSQL
Oracle
```

may implement similar SQL concepts but have different syntax and functions.

Therefore:

> **Knowing the DBMS helps determine which SQL syntax and enumeration methods are appropriate.**

---

# 4. MySQL Fingerprinting

The HTB module provides three useful tests.

|Query|Useful when|MySQL/MariaDB indication|
|---|---|---|
|`SELECT @@version`|Full query output is visible|Returns MySQL/MariaDB version|
|`SELECT POW(1,1)`|Only numeric output is visible|Returns `1`|
|`SELECT SLEEP(5)`|Blind/no output|Response is delayed|

These tests provide different levels of visibility.

---

# 5. `@@version`

The easiest case is when the application displays database output.

```sql
SELECT @@version;
```

For the lab, the output is:

```text
10.3.22-MariaDB-1ubuntu1
```

This immediately tells us:

```text
DBMS = MariaDB
```

MariaDB is closely related to MySQL and shares much of its SQL syntax.

---

# 6. Why Fingerprinting Matters

Suppose you don't know the database type.

You shouldn't blindly assume:

```text
"Apache = MySQL"
```

or:

```text
"Linux = MySQL"
```

Those are only guesses.

The module correctly points out that:

> Apache/Nginx or Linux can provide clues, but they are **not reliable proof** of the DBMS.

The actual database behavior is much stronger evidence.

---

# 7. `POW(1,1)`

If you only have numeric output, you may not be able to recognize a version string.

The module gives:

```sql
SELECT POW(1,1);
```

Mathematically:

```text
1¹ = 1
```

So MySQL/MariaDB returns:

```text
1
```

This can act as a DBMS fingerprint in situations where the application only exposes numeric results.

---

# 8. `SLEEP(5)`

In a blind situation, you may not see the query's output at all.

The module introduces:

```sql
SELECT SLEEP(5);
```

The important observation is:

```text
Request
  ↓
Database evaluates SLEEP(5)
  ↓
~5 second delay
  ↓
Response
```

If the response is delayed as expected, that provides evidence about the DBMS/function behavior.

This is an example of **time-based observation**.

---

# 9. Fingerprinting Summary ⭐

Remember:

```text
Full output
    ↓
@@version

Numeric output
    ↓
POW(1,1)

No output / blind
    ↓
SLEEP(5)
```

You don't necessarily need all three.

If `@@version` already gives a clear MariaDB/MySQL version, you've obtained much stronger information.

---

# 10. INFORMATION_SCHEMA ⭐⭐⭐

This is probably the **most important concept in this section**.

`INFORMATION_SCHEMA` is a special database containing **metadata about databases, tables, columns, and other database objects**.

Think of it as:

> **The database's map of its own structure.**

Instead of guessing:

```text
database?
table?
column?
```

we can query metadata.

---

# 11. The INFORMATION_SCHEMA Mental Model

Think:

```text
INFORMATION_SCHEMA
        │
        ├── SCHEMATA
        │      └── Database names
        │
        ├── TABLES
        │      └── Table names
        │
        └── COLUMNS
               └── Column names
```

This gives us the enumeration chain:

```text
SCHEMATA
   ↓
TABLES
   ↓
COLUMNS
   ↓
DATA
```

⭐ **Memorize this.**

---

# 12. Accessing Another Database

SQL uses the dot operator:

```text
database.table
```

For example:

```sql
SELECT * FROM my_database.users;
```

means:

```text
Database → my_database
Table    → users
```

This becomes important because our current application may be using one database while the interesting table exists in another.

---

# 13. SCHEMATA

The `SCHEMATA` table contains information about databases.

The important column here is:

```text
SCHEMA_NAME
```

We can query:

```sql
SELECT SCHEMA_NAME
FROM INFORMATION_SCHEMA.SCHEMATA;
```

Conceptually:

```text
INFORMATION_SCHEMA
       │
       ▼
    SCHEMATA
       │
       ▼
 SCHEMA_NAME
       │
       ▼
Database names
```

---

# 14. Example Result

The lab shows:

```text
mysql
information_schema
performance_schema
ilfreight
dev
```

The first few are normally default/system databases.

The interesting application databases are:

```text
ilfreight
dev
```

---

# 15. Default Databases

The module tells us that databases such as:

```text
mysql
information_schema
performance_schema
```

are default MySQL databases.

You may also encounter:

```text
sys
```

So during enumeration, don't automatically treat every database name as application-specific.

Conceptually:

```text
System databases
       ↓
Usually less interesting initially

Application databases
       ↓
Potentially interesting
```

---

# 16. UNION Enumeration of Databases

Because our UNION query has four columns and column 2 is reflected, we can place the metadata value there.

Conceptually:

```text
Column 1 → filler
Column 2 → schema name
Column 3 → filler
Column 4 → filler
```

The module uses:

```sql
cn' UNION SELECT 1, schema_name, 3, 4
FROM INFORMATION_SCHEMA.SCHEMATA-- -
```

The important part isn't memorizing the whole string.

Understand the structure:

```text
UNION SELECT
    filler,
    database-name,
    filler,
    filler
FROM metadata-table
```

---

# 17. Why `SCHEMA_NAME`?

Because:

```text
SCHEMATA
   ↓
SCHEMA_NAME
   ↓
Database names
```

So the query asks the metadata database:

> "Give me the names of the databases."

---

# 18. Finding the Current Database

Next we need to know which database the application is currently using.

MySQL provides:

```sql
SELECT database();
```

This returns the current database.

The lab's result is:

```text
ilfreight
```

So:

```text
Current database = ilfreight
```

---

# 19. Why Does the Current Database Matter?

Suppose:

```text
Current DB = ilfreight
```

but enumeration found:

```text
dev
```

Now we know:

```text
ilfreight → application currently connected here

dev → another database that may contain interesting data
```

This is exactly why database enumeration is useful.

---

# 20. TABLES

Once you've identified an interesting database, you need to discover its tables.

That's where:

```text
INFORMATION_SCHEMA.TABLES
```

comes in.

Two particularly important fields are:

```text
TABLE_SCHEMA
TABLE_NAME
```

Think:

```text
TABLE_SCHEMA
      ↓
Which database?

TABLE_NAME
      ↓
Which table?
```

---

# 21. Why Filter by Database?

If you simply ask for every table:

```text
TABLES
```

you may get tables from:

```text
mysql
information_schema
performance_schema
sys
ilfreight
dev
...
```

That could produce a huge amount of irrelevant information.

Instead, we narrow it:

```text
TABLE_SCHEMA = 'dev'
```

Conceptually:

```text
All tables
    ↓
Filter database
    ↓
Only dev tables
```

---

# 22. Finding Tables in `dev`

The module uses:

```sql
SELECT TABLE_NAME, TABLE_SCHEMA
FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_SCHEMA='dev';
```

The lab finds:

```text
credentials
framework
pages
posts
```

So our structure is now:

```text
dev
├── credentials
├── framework
├── pages
└── posts
```

---

# 23. Why `credentials` Looks Interesting

Among those tables:

```text
credentials
framework
pages
posts
```

the name:

```text
credentials
```

strongly suggests that it might contain authentication-related information.

But remember the cybersecurity lesson:

> **A table name is only a clue.**

You still need to inspect its columns before assuming what it contains.

---

# 24. COLUMNS

Now we know:

```text
Database = dev
Table    = credentials
```

But we still don't know:

```text
What columns exist?
```

That's where:

```text
INFORMATION_SCHEMA.COLUMNS
```

comes in.

Important fields include:

```text
COLUMN_NAME
TABLE_NAME
TABLE_SCHEMA
```

---

# 25. Finding Columns in `credentials`

Conceptually:

```text
INFORMATION_SCHEMA.COLUMNS
          │
          ▼
Filter TABLE_NAME
          │
          ▼
credentials
          │
          ▼
COLUMN_NAME
```

The module uses:

```sql
SELECT COLUMN_NAME, TABLE_NAME, TABLE_SCHEMA
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME='credentials';
```

The result shows:

```text
username
password
```

So now we know the structure:

```text
dev.credentials
├── username
└── password
```

---

# 26. Why We Need Column Names

You cannot reliably retrieve:

```text
unknown_column
```

if you don't know what the table actually contains.

Our enumeration has now given us:

```text
Database
   ↓
dev

Table
   ↓
credentials

Columns
   ↓
username
password
```

Now we have enough structural information to construct a `SELECT`.

---

# 27. Final Data Retrieval

The module then references the table using:

```text
dev.credentials
```

because the current database is:

```text
ilfreight
```

The dot notation tells MySQL:

```text
Database = dev
Table    = credentials
```

The conceptual query is:

```sql
SELECT username, password
FROM dev.credentials;
```

Within the four-column UNION structure, the useful values occupy the reflected positions.

---

# 28. Why the Dot Operator Matters ⭐

This is easy to forget.

If you're currently inside:

```text
ilfreight
```

and want:

```text
credentials
```

from:

```text
dev
```

you need to identify it as:

```text
dev.credentials
```

rather than simply:

```text
credentials
```

Think:

```text
database.table
```

---

# 29. Complete Enumeration Chain

This is the section's **most important diagram**:

```text
                  DBMS
                   │
                   ▼
          INFORMATION_SCHEMA
                   │
          ┌────────┼─────────┐
          │        │         │
          ▼        ▼         ▼
      SCHEMATA   TABLES    COLUMNS
          │        │         │
          ▼        ▼         ▼
      Databases   Tables    Columns
          │        │         │
          └────────┼─────────┘
                   ▼
                  DATA
```

Or practically:

```text
1. Identify DBMS
       ↓
2. Find databases
       ↓
3. Find current database
       ↓
4. Find tables in interesting database
       ↓
5. Find columns in interesting table
       ↓
6. Retrieve selected data
```

---

# 30. Example From the Lab

The complete chain is:

```text
DBMS
 ↓
MariaDB
 ↓
Databases
 ↓
ilfreight
dev
 ↓
Interesting DB
 ↓
dev
 ↓
Tables
 ↓
credentials
framework
pages
posts
 ↓
Interesting table
 ↓
credentials
 ↓
Columns
 ↓
username
password
 ↓
Data
 ↓
credential records
```

This is the exact logical progression you should understand.

---

# 31. Why `INFORMATION_SCHEMA` Is So Powerful

Without metadata, you might have to guess:

```text
users?
accounts?
credentials?
login?
auth?
```

and then:

```text
username?
user?
login?
email?
password?
hash?
```

That's inefficient.

With `INFORMATION_SCHEMA`:

```text
Database
   ↓
Tables
   ↓
Columns
```

you can systematically understand the database structure.

---

# 32. Enumeration ≠ Exploitation

This distinction is important.

### Enumeration

Learning:

```text
What exists?
What is its structure?
```

### Data retrieval

Learning:

```text
What information is stored there?
```

In this lab:

```text
SCHEMATA → enumeration
TABLES → enumeration
COLUMNS → enumeration
```

Then:

```text
SELECT username, password
```

is actual data retrieval.

---

# 33. Why `WHERE` Is Important During Enumeration

The metadata tables can contain information about **many databases and tables**.

Therefore, `WHERE` helps narrow the result.

For example:

```text
TABLE_SCHEMA='dev'
```

means:

```text
Only tables belonging to dev
```

Likewise, filtering for:

```text
TABLE_NAME='credentials'
```

means:

```text
Only information about credentials
```

This makes enumeration cleaner and easier to reason about.

---

# 34. ⭐ The Four Metadata Fields to Know

Memorize these:

### `SCHEMA_NAME`

```text
Database name
```

### `TABLE_SCHEMA`

```text
Database that owns the table
```

### `TABLE_NAME`

```text
Table name
```

### `COLUMN_NAME`

```text
Column name
```

These four fields are enough to understand the core enumeration process taught in this section.

---

# 35. Metadata Mapping

```text
SCHEMATA
   │
   └── SCHEMA_NAME
          ↓
       database

TABLES
   │
   ├── TABLE_SCHEMA
   │      ↓
   │   database
   │
   └── TABLE_NAME
          ↓
        table

COLUMNS
   │
   ├── TABLE_SCHEMA
   │      ↓
   │   database
   │
   ├── TABLE_NAME
   │      ↓
   │    table
   │
   └── COLUMN_NAME
          ↓
        column
```

---

# 36. Important Concept — Metadata vs Data

This distinction is very useful.

### Metadata

Information **about** the database:

```text
Database names
Table names
Column names
```

Stored/queryable through:

```text
INFORMATION_SCHEMA
```

### Data

The actual contents:

```text
username
password
posts
API keys
etc.
```

So:

```text
INFORMATION_SCHEMA
       ↓
"What exists?"

Application tables
       ↓
"What is stored?"
```

---

# 37. Common Beginner Mistakes

## ❌ Mistake 1 — Assuming the DBMS

Don't blindly assume:

```text
Apache → MySQL
```

Use evidence.

---

## ❌ Mistake 2 — Jumping directly to data

Don't immediately guess:

```text
SELECT username,password...
```

First establish:

```text
Database
Table
Columns
```

---

## ❌ Mistake 3 — Forgetting the current database

Knowing:

```text
dev
```

exists isn't the same as knowing:

```text
ilfreight
```

is the current database.

`database()` answers that question.

---

## ❌ Mistake 4 — Forgetting `TABLE_SCHEMA`

If you query all tables without filtering, you can get a massive result set.

Use the database name to narrow it.

---

## ❌ Mistake 5 — Forgetting `database.table`

If the target table is in another database, remember:

```text
database.table
```

For example:

```text
dev.credentials
```

---

## ❌ Mistake 6 — Assuming table names tell you everything

`credentials` sounds interesting, but you still need to inspect:

```text
COLUMNS
```

to understand its actual structure.

---

# 38. ⭐ The Golden Enumeration Workflow

Write this in your notes:

```text
              DATABASE ENUMERATION

                     START
                       │
                       ▼
                Identify DBMS
                       │
                       ▼
                Find databases
              INFORMATION_SCHEMA
                  .SCHEMATA
                       │
                       ▼
             Find current database
                  database()
                       │
                       ▼
                Find tables
              INFORMATION_SCHEMA
                  .TABLES
                       │
                       ▼
              Find interesting table
                       │
                       ▼
                Find columns
              INFORMATION_SCHEMA
                  .COLUMNS
                       │
                       ▼
                Build SELECT
                       │
                       ▼
                 Retrieve data
```

---

# 39. One-Page Revision Sheet

## Fingerprinting

```text
@@version
→ Version / DBMS information

POW(1,1)
→ Numeric fingerprint

SLEEP(5)
→ Time-based fingerprint
```

## Metadata

```text
INFORMATION_SCHEMA
        │
        ├── SCHEMATA
        │      └── SCHEMA_NAME
        │
        ├── TABLES
        │      ├── TABLE_SCHEMA
        │      └── TABLE_NAME
        │
        └── COLUMNS
               ├── TABLE_SCHEMA
               ├── TABLE_NAME
               └── COLUMN_NAME
```

## Enumeration

```text
DBMS
 ↓
Databases
 ↓
Current DB
 ↓
Tables
 ↓
Columns
 ↓
Data
```

## Cross-database reference

```text
database.table
```

Example:

```text
dev.credentials
```

---

# 40. ⭐ What You Should Be Able to Explain Without Looking

Before moving on, make sure you can explain these in your own words:

1. **Why do we fingerprint the DBMS first?**
    
2. **What is `INFORMATION_SCHEMA`?**
    
3. **What does `SCHEMATA` tell us?**
    
4. **What is the difference between `TABLE_SCHEMA` and `TABLE_NAME`?**
    
5. **What does `COLUMNS` tell us?**
    
6. **Why do we enumerate tables before columns?**
    
7. **Why do we need the current database name?**
    
8. **What does `database.table` mean?**
    
9. **Why is `WHERE TABLE_SCHEMA='dev'` useful?**
    
10. **What is the complete path from database enumeration to actual data?**
    

If you can answer those without copying from the notes, you genuinely understand this section.

---

## 🔥 Final Mental Model

Don't think of database enumeration as a collection of payloads.

Think of it as **walking down a hierarchy**:

```text
                 "What DBMS?"
                      ↓
                 "What DBs?"
                      ↓
                "What tables?"
                      ↓
               "What columns?"
                      ↓
                 "What data?"
```

And the MySQL metadata map is:

```text
SCHEMATA → databases
TABLES   → tables
COLUMNS  → columns
```

That is the core knowledge from this entire section.