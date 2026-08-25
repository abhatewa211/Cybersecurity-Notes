![Image](https://images.openai.com/static-rsc-4/xSLjlOG54yegwYstdSTe5GOcuRy0Af3i6LiupE6E1VxJ9Tx_KJuoqgfxAqXXz5mDT8RHevtchJzVF7Z-25Qhq5orzjr4rMHuGLlCKuCD6FIuz0Xtij_1gmIWyvdaUms3w9sS3LOOGTGGJPlNH32Yl6QcYmfQnYxSB521OrfD_o1fmwd4VOCMFi48GGUSwSpX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/k4XgpQW70Rwc-R5EXMcj12tQBxBR2Wy2HXEwkKHg158kA2N-1bmhrKTiqZi_LhIk4TFHMjJ4fgiH5O57IP_adrfumu_06M2p4baiGz3-rH1igYSicAxoKIX4yxzhfN_JUAD25zww9yxXf2fJ6Jdq0oP78Cn10N6EneKnxEpdWgN2HGfFm337gwx-XVTnkRc4?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BcW2sF7GOjaExoDDZjv-CWzHcFxsYKOgkL38YSLBME-tcbzMzkEzuqrZZGXXzlrd9NBjwOQOe4fjxoo9QLFS-iB4vhrtbeTHckLdel61m1tcRwQud5NCFefaQtLgOaEFZLwKzuXCa-n3UvwzIe6WuAjlSIB4bP16AW4EDmd0SXPZm-RAA_2Y-9rAUD_2TW28?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2ND8Y0oPYGmh5tUoqqv_0AKeGOpEmijf4olbHcFlbPXV3x2jBaBoVU0NzQVtYN99NnygOiwEEKt8s7ux9opMjm-jkCe6eCQQJa_an_Zf3CYYCsdtizKdIn9PcGb9412YJlW6r21W6psu-mL6WwYCIkKFF4lNOpX2JkWdVi3VFxuKRIfd21MFZmCoj9pniOxT?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZXyKmGn6ym3Emgzjn1IUQ4yQafE661knOdAfY2dfvzy6mPbCpPVK33rouXnbUU1UdRH7ok8MGfmHMn3OUgOHzQSzdDdZLuJKI9Ysm1zJqQTWMHKbNwz1EoeE99qMW0fjITE093W6NKl58bA3OyqYqJilbQVyPpXs_7MeQ2KGeWrHdXNr1W_UStGAkrl8-C3y?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/5_noXwsXotFxdhz0KGhHY0WfRHuMkp98rcyfFqYn34UGVmYyq6g-4rVqJ5XzMInn9xlltTZ1cXWt4zHqdYQ25Y98uA0kr3UXM3IkYWLmwoot3bCJVtFvn8PD6stVDxf2JqCNILtF65-afotZ6kI62t_VhSMo5kTDoN3AmxWigqJa7LOxOFfj5r_Q-eaJdESB?purpose=fullsize)
## 1. Introduction

So far, we have learned how to:

- Create databases
    
- Create tables
    
- Insert records
    
- Retrieve records
    
- Update records
    
- Modify table structures
    
- Delete database objects
    

Now we learn how to **control and filter query results**.

The most important clauses introduced here are:

```text
Query Result Control
│
├── ORDER BY → Sort results
├── LIMIT    → Restrict number of results
├── WHERE    → Filter results
└── LIKE     → Pattern matching
```

These clauses are particularly important when learning SQL Injection because applications frequently use them when constructing dynamic SQL queries.

---

# 2. ORDER BY

The `ORDER BY` clause is used to **sort query results** according to one or more columns.

### Basic Syntax

```sql
SELECT *
FROM table_name
ORDER BY column_name;
```

For example:

```sql
SELECT * FROM logins
ORDER BY password;
```

This sorts the returned records according to the `password` column.

---

# 3. Default Sorting — ASC

By default, `ORDER BY` sorts results in **ascending order**.

You can explicitly specify:

```sql
ASC
```

Example:

```sql
SELECT * FROM logins
ORDER BY password ASC;
```

`ASC` means:

> **Ascending**

The exact ordering behavior depends on the data type and collation.

Conceptually:

```text
ASCENDING

A → B → C
1 → 2 → 3
```

---

# 4. DESC

To sort in descending order, use:

```sql
DESC
```

Example:

```sql
SELECT * FROM logins
ORDER BY password DESC;
```

`DESC` means:

> **Descending**

Conceptually:

```text
DESCENDING

C → B → A
3 → 2 → 1
```

---

# 5. ORDER BY Example

Suppose the table contains:

```text
+----+---------------+-----------------+
| id | username      | password        |
+----+---------------+-----------------+
| 1  | admin         | p@ssw0rd        |
| 2  | administrator | adm1n_p@ss      |
| 3  | john          | john123!        |
| 4  | tom           | tom123!         |
+----+---------------+-----------------+
```

Running:

```sql
SELECT * FROM logins
ORDER BY password;
```

asks MySQL to sort the records based on `password`.

---

# 6. ORDER BY Multiple Columns

We can sort using more than one column.

Example:

```sql
SELECT * FROM logins
ORDER BY password DESC, id ASC;
```

Here:

```text
password → primary sort
id       → secondary sort
```

The second sort becomes useful when multiple rows have the same value for the first sort column.

---

# 7. Secondary Sorting

Suppose several records have:

```text
password = change_password
```

If we use:

```sql
ORDER BY password DESC;
```

the database has to determine the ordering among rows with equal password values.

Adding:

```sql
id ASC
```

provides a secondary ordering rule.

Conceptually:

```text
Primary sort:
password DESC

       ↓

Duplicate values?

       ↓ YES

Secondary sort:
id ASC
```

---

# 8. ORDER BY Syntax Cheat Sheet

### Ascending

```sql
SELECT * FROM logins
ORDER BY id ASC;
```

### Descending

```sql
SELECT * FROM logins
ORDER BY id DESC;
```

### Multiple columns

```sql
SELECT * FROM logins
ORDER BY username ASC, id DESC;
```

---

# 9. LIMIT

The `LIMIT` clause is used to **restrict the number of rows returned** by a query.

### Basic Syntax

```sql
SELECT *
FROM table_name
LIMIT number;
```

For example:

```sql
SELECT * FROM logins
LIMIT 2;
```

This returns at most two rows.

---

# 10. Why Use LIMIT?

Imagine a table containing:

```text
1,000,000 records
```

If we only need the first few records, returning the entire dataset is unnecessary.

Using:

```sql
LIMIT 10;
```

restricts the result to the requested number of rows.

Conceptually:

```text
1,000,000 records
       ↓
     LIMIT 10
       ↓
10 records
```

---

# 11. LIMIT Example

```sql
SELECT * FROM logins
LIMIT 2;
```

Possible output:

```text
+----+---------------+------------+
| id | username      | password   |
+----+---------------+------------+
| 1  | admin         | p@ssw0rd   |
| 2  | administrator | adm1n_p@ss |
+----+---------------+------------+
```

Only two rows are returned.

---

# 12. LIMIT with OFFSET

MySQL also allows an offset to be specified.

Syntax:

```sql
LIMIT offset, count;
```

For example:

```sql
SELECT * FROM logins
LIMIT 1, 2;
```

This means:

```text
offset = 1
count  = 2
```

The offset starts at **0**.

---

# 13. Understanding OFFSET

Suppose the rows are:

```text
Position

0 → admin
1 → administrator
2 → john
3 → tom
```

Query:

```sql
LIMIT 1, 2;
```

means:

```text
Start at offset 1
      ↓
administrator

Return 2 rows
      ↓
administrator
john
```

So:

```text
LIMIT offset, count
       │       │
       │       └── Number of rows
       └────────── Starting offset
```

---

# 14. LIMIT Syntax Variations

### First 5 rows

```sql
SELECT * FROM logins
LIMIT 5;
```

### Start at offset 5 and return 10 rows

```sql
SELECT * FROM logins
LIMIT 5, 10;
```

### Alternative syntax

MySQL also supports:

```sql
SELECT * FROM logins
LIMIT 10 OFFSET 5;
```

Both forms express the idea of starting at offset 5 and returning 10 rows.

---

# 15. WHERE Clause

The `WHERE` clause is used to **filter records according to a condition**.

### Basic Syntax

```sql
SELECT *
FROM table_name
WHERE <condition>;
```

Only records satisfying the condition are returned.

---

# 16. WHERE with Numbers

Example:

```sql
SELECT * FROM logins
WHERE id > 1;
```

This returns records where:

```text
id > 1
```

So:

```text
id = 1 → excluded
id = 2 → included
id = 3 → included
id = 4 → included
```

---

# 17. Common Comparison Operators

`WHERE` conditions can use comparison operators.

|Operator|Meaning|
|---|---|
|`=`|Equal|
|`!=`|Not equal|
|`<>`|Not equal|
|`>`|Greater than|
|`<`|Less than|
|`>=`|Greater than or equal|
|`<=`|Less than or equal|

Examples:

```sql
WHERE id = 1
```

```sql
WHERE id > 1
```

```sql
WHERE id <= 5
```

---

# 18. WHERE with Strings

String values should normally be quoted.

Example:

```sql
SELECT * FROM logins
WHERE username = 'admin';
```

This searches for a record where:

```text
username = admin
```

Possible result:

```text
+----+----------+----------+
| id | username | password |
+----+----------+----------+
| 1  | admin    | p@ssw0rd |
+----+----------+----------+
```

---

# 19. Numbers vs Strings

A key SQL syntax rule is that numeric values can generally be written directly:

```sql
WHERE id = 1
```

while string values are generally quoted:

```sql
WHERE username = 'admin'
```

Dates are also typically represented as quoted literals:

```sql
WHERE date_of_joining = '2020-07-02'
```

### Remember

```text
Number → 1

String → 'admin'

Date → '2020-07-02'
```

---

# 20. WHERE with UPDATE

`WHERE` isn't limited to `SELECT`.

It is also extremely important with `UPDATE`.

Example:

```sql
UPDATE logins
SET password = 'new_password'
WHERE id = 1;
```

Only the record satisfying:

```text
id = 1
```

is modified.

---

# 21. WHERE with DELETE

`WHERE` can also be used with `DELETE`.

Example:

```sql
DELETE FROM logins
WHERE id = 1;
```

This removes the matching record(s), while leaving the table itself.

---

# 22. LIKE Clause

The `LIKE` operator is used for **pattern matching**.

It is particularly useful when you don't know the exact value you're searching for.

### Basic Syntax

```sql
SELECT *
FROM table_name
WHERE column_name LIKE 'pattern';
```

---

# 23. `%` Wildcard

The `%` symbol is a wildcard that matches **zero or more characters**.

Example:

```sql
SELECT * FROM logins
WHERE username LIKE 'admin%';
```

This means:

```text
Starts with:
admin

Then:
zero or more characters
```

Therefore, it can match values such as:

```text
admin
administrator
admin123
admin_user
```

depending on the actual data and collation.

---

# 24. Understanding `admin%`

Break it down:

```text
admin%
│   │
│   └── zero or more characters
└────── exact beginning: admin
```

So:

```text
admin       ✓
administrator ✓
admin123    ✓
adm         ✗
useradmin   ✗
```

The pattern requires the string to begin with `admin`.

---

# 25. `_` Wildcard

The underscore:

```text
_
```

matches **exactly one character**.

For example:

```sql
SELECT * FROM logins
WHERE username LIKE '___';
```

There are three underscores.

Each underscore represents exactly one character.

Therefore, the pattern matches usernames with exactly three characters.

Example:

```text
tom → ✓
bob → ✓
john → ✗
admin → ✗
```

---

# 26. `%` vs `_`

This distinction is extremely important.

### `%`

Matches:

```text
ZERO or MORE characters
```

Example:

```sql
LIKE 'admin%'
```

Matches:

```text
admin
administrator
admin123
```

### `_`

Matches:

```text
EXACTLY ONE character
```

Example:

```sql
LIKE '___'
```

Matches:

```text
tom
bob
cat
```

but not:

```text
jo
john
admin
```

---

# 27. LIKE Pattern Examples

|Pattern|Meaning|
|---|---|
|`'admin%'`|Starts with `admin`|
|`'%admin'`|Ends with `admin`|
|`'%admin%'`|Contains `admin`|
|`'___'`|Exactly 3 characters|
|`'a__'`|Starts with `a`, followed by exactly 2 characters|
|`'__n'`|Exactly 3 characters ending in `n`|
|`'_admin%'`|One character, then `admin`, then zero or more characters|

---

# 28. Combining WHERE and LIKE

A common pattern is:

```sql
SELECT *
FROM logins
WHERE username LIKE 'admin%';
```

This can be thought of as:

```text
SELECT records
      ↓
FROM logins
      ↓
WHERE username
      ↓
matches pattern 'admin%'
```

---

# 29. Combining ORDER BY, WHERE, and LIMIT

These clauses can be combined.

For example:

```sql
SELECT *
FROM logins
WHERE username LIKE 'admin%'
ORDER BY id ASC
LIMIT 2;
```

The logical idea is:

```text
logins
  ↓
Filter
  ↓
username LIKE 'admin%'
  ↓
Sort
  ↓
id ASC
  ↓
Limit
  ↓
2 rows
```

This demonstrates how different clauses work together to control query results.

---

# 30. Clause Order

A basic `SELECT` query commonly follows this structure:

```sql
SELECT columns
FROM table
WHERE condition
ORDER BY column
LIMIT number;
```

Example:

```sql
SELECT username
FROM logins
WHERE id > 1
ORDER BY username ASC
LIMIT 2;
```

### Memorize the Basic Order

```text
SELECT
  ↓
FROM
  ↓
WHERE
  ↓
ORDER BY
  ↓
LIMIT
```

This order is extremely useful when reading and understanding SQL queries.

---

# 31. Logical Processing vs Written Order

It is useful to distinguish **SQL's written clause order** from the conceptual order in which the database processes a query.

A simplified conceptual processing order is:

```text
FROM
  ↓
WHERE
  ↓
SELECT
  ↓
ORDER BY
  ↓
LIMIT
```

You normally **write** the query as:

```text
SELECT
FROM
WHERE
ORDER BY
LIMIT
```

This distinction becomes increasingly useful when learning more advanced SQL.

---

# 32. Query Result Flow

A simplified model:

```text
             TABLE
               │
               ▼
             WHERE
               │
         Filter records
               │
               ▼
            SELECT
               │
         Choose columns
               │
               ▼
           ORDER BY
               │
           Sort rows
               │
               ▼
             LIMIT
               │
        Restrict output
               │
               ▼
             RESULT
```

This is a useful mental model for understanding how these clauses affect output.

---

# 33. Why These Clauses Matter for SQL Injection

These clauses are especially relevant to SQL Injection because web applications often construct queries dynamically.

For example:

```sql
SELECT *
FROM products
WHERE name LIKE '<USER_INPUT>'
ORDER BY <USER_INPUT>
LIMIT <USER_INPUT>;
```

If the application inserts untrusted user input directly into SQL syntax, the attacker may potentially influence how the query behaves.

This is why understanding:

```text
WHERE
LIKE
ORDER BY
LIMIT
```

is important when analyzing vulnerable SQL queries.

---

# 34. ORDER BY and SQLi

`ORDER BY` is particularly interesting because it specifies a **column/expression used for sorting** rather than simply being a quoted string value.

For example:

```sql
SELECT * FROM logins
ORDER BY id;
```

Understanding the distinction between:

```text
Data value
```

and:

```text
SQL expression / identifier
```

becomes important later when analyzing SQL injection contexts.

---

# 35. LIMIT and SQLi

`LIMIT` controls the number of rows returned.

For example:

```sql
SELECT * FROM logins
LIMIT 1;
```

The application may use user-controlled parameters to determine how many records are displayed.

Understanding:

```text
LIMIT count
LIMIT offset, count
```

is therefore useful when analyzing dynamic queries.

---

# 36. WHERE and SQLi

`WHERE` is one of the most important SQL clauses for understanding SQL Injection.

Example:

```sql
SELECT *
FROM logins
WHERE username = 'admin';
```

The application might instead construct:

```text
WHERE username = '<USER_INPUT>'
```

If user input is inserted unsafely, it may influence the logic of the `WHERE` condition.

That is the basic context in which SQL injection can occur.

---

# 37. LIKE and SQLi

Similarly, an application might construct:

```sql
SELECT *
FROM users
WHERE username LIKE '<USER_INPUT>';
```

The application's handling of the input determines whether it is treated purely as data or can influence SQL syntax.

Understanding wildcard behavior also helps distinguish:

```text
SQL pattern matching
```

from:

```text
SQL injection
```

These are different concepts.

---

# 38. Important Security Note

A wildcard is **not automatically an SQL injection**.

For example:

```sql
WHERE username LIKE 'admin%'
```

is normal SQL pattern matching.

SQL Injection occurs when **untrusted input can alter the SQL query's structure or logic**, not merely because SQL uses special characters.

---

# 39. Common Mistakes

### Mistake 1 — Confusing `%` and `_`

Remember:

```text
% → zero or more
_ → exactly one
```

---

### Mistake 2 — Forgetting WHERE

This:

```sql
UPDATE logins
SET password = 'new';
```

can modify all applicable rows.

Safer targeted form:

```sql
UPDATE logins
SET password = 'new'
WHERE id = 1;
```

---

### Mistake 3 — Confusing OFFSET with COUNT

In:

```sql
LIMIT 1, 2;
```

the values mean:

```text
1 → offset
2 → number of rows
```

Not the other way around.

---

### Mistake 4 — Assuming LIMIT Gives a Specific Order

Without `ORDER BY`, SQL does not guarantee a particular logical ordering of results.

If you need a predictable order, specify:

```sql
ORDER BY column;
```

before `LIMIT`.

---

# 40. Important Things to Memorize

> **`ORDER BY` sorts query results.**

> **The default ordering is ascending (`ASC`).**

> **`DESC` sorts in descending order.**

> **Multiple columns can be specified in `ORDER BY`.**

> **A secondary sort can resolve ordering between rows with equal primary sort values.**

> **`LIMIT` restricts the number of rows returned.**

> **`LIMIT offset, count` starts at the specified zero-based offset and returns the specified number of rows.**

> **`WHERE` filters records based on a condition.**

> **Numbers can generally be written directly in SQL conditions, while string and date literals are normally quoted.**

> **`LIKE` performs pattern matching.**

> **`%` matches zero or more characters.**

> **`_` matches exactly one character.**

> **`WHERE`, `ORDER BY`, and `LIMIT` can be combined in a single query.**

> **`WHERE` is particularly important when modifying or deleting data because it controls which records are affected.**

---

# 41. Quick Revision Cheat Sheet

## ORDER BY

Ascending:

```sql
SELECT * FROM logins
ORDER BY id ASC;
```

Descending:

```sql
SELECT * FROM logins
ORDER BY id DESC;
```

Multiple:

```sql
SELECT * FROM logins
ORDER BY username ASC, id DESC;
```

**Purpose:** Sort results.

---

## LIMIT

First 2 rows:

```sql
SELECT * FROM logins
LIMIT 2;
```

Offset + count:

```sql
SELECT * FROM logins
LIMIT 1, 2;
```

**Purpose:** Restrict output.

---

## WHERE

```sql
SELECT *
FROM logins
WHERE id > 1;
```

String:

```sql
SELECT *
FROM logins
WHERE username = 'admin';
```

**Purpose:** Filter records.

---

## LIKE

Starts with `admin`:

```sql
SELECT *
FROM logins
WHERE username LIKE 'admin%';
```

Exactly three characters:

```sql
SELECT *
FROM logins
WHERE username LIKE '___';
```

**Purpose:** Pattern matching.

---

# 42. Master Example

Putting everything together:

```sql
SELECT username
FROM logins
WHERE username LIKE 'admin%'
ORDER BY username ASC
LIMIT 2;
```

Breakdown:

```text
SELECT username
      │
      └── Return username

FROM logins
      │
      └── Search the logins table

WHERE username LIKE 'admin%'
      │
      └── Only usernames matching the pattern

ORDER BY username ASC
      │
      └── Sort alphabetically/according to collation

LIMIT 2
      │
      └── Return at most 2 rows
```

---

# 43. Final Mental Model

Remember the four main tools from this section:

```text
                 QUERY
                   │
                   ▼
                WHERE
                   │
              Filter rows
                   │
                   ▼
               SELECT
                   │
             Choose columns
                   │
                   ▼
              ORDER BY
                   │
               Sort rows
                   │
                   ▼
                LIMIT
                   │
             Limit output
                   │
                   ▼
                RESULT
```

### One-Line Memory Trick

```text
WHERE → WHICH ROWS?
SELECT → WHICH COLUMNS?
ORDER BY → WHAT ORDER?
LIMIT → HOW MANY?
LIKE → WHAT PATTERN?
```

That is the core of this section.

And for the SQL Injection module, the most important takeaway is:

> **Applications often build SQL queries using user-controlled values. Understanding exactly how `WHERE`, `LIKE`, `ORDER BY`, and `LIMIT` affect a query is essential for recognizing when user input can improperly influence SQL query logic.**