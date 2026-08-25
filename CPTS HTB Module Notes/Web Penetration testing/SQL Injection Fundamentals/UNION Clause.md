![Image](https://images.openai.com/static-rsc-4/EhfODzXevQZhFYFnLcivqqW2Q5ftm7bQuTUX2C6YizNg9GdL7Lss2O2Rhl6M45SmRHRWTd6Hjpwknv0z5XKeCYnRmYRVyj-6aL2va0SYLiE0wjgX8Rp8U28FdIVLDAiSaSD433nAIf8QzPuzqEgf3y3pxDpDJmxdokcNi4siL6pUnPGHTvsRoWUjhuqkiy_p?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/stneVNHnJrDMSGHOvHHW9pcM0cggjzmc9_pglx4ZumbiRluSlpp2Gi7gUYhhd6v0YioVQQmUg0k7-J1Qs4wgG5WnIs2Rqewnz0d_8FWkWJTEJybEQXmH_N2yR4zTlQTbdO2zUOHzcQAey_iP-S2VpH3q7lIClh8JAnbI74rZ8G60t_CjTU0DBFS-SsyTrZ0U?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/f3YB6wNyrMw7svAONjGPOs9g8_LErOvChqzof1ua0czBX1QSQdPEoRIiNR25Y9yl-eVEXwMqBFZOLqQPr5j9rO4dLBHbJDK1XZizQ0mUYVymQM722vlUbG5g1Mb1q72Z8PFUpvIda6azAaab0rJxPqVuKcrUK-Mhc4pp00rzX9dutBGRisSszN7ZnFOYhupE?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/W-8j0GZdocLz8hA1lH8ZGVuGbC8HcF8XitRtiZvBZ2HIDymkfSmGMPRCIE75m9PqHdf6DyamlPCJbvUOd2L8m6FgiCHWKq3Fb7b3PYtH61bhZ-HGstxsJDsLSNjSSgh9FjTq7IVWTXrd9Qx12xkU17sWnmetC88UQPZyOEGFQfVdDR77fGvGZLlgDWB69a84?purpose=fullsize)

---

# 1. What Is UNION?

The SQL `UNION` clause combines the results of multiple `SELECT` statements into a single result set.

Conceptually:

```text
SELECT A
     +
SELECT B
     ↓
   UNION
     ↓
Combined Results
```

For example:

```sql
SELECT * FROM ports
UNION
SELECT * FROM ships;
```

The database produces one combined result.

---

# 2. Normal SQL vs UNION Injection

So far, we have mainly manipulated an existing query:

```text
Original Query
      ↓
Change its logic
      ↓
Change TRUE/FALSE result
```

With UNION-based SQLi:

```text
Original Query
      ↓
Add another SELECT
      ↓
UNION
      ↓
Combined result
```

This is a fundamental difference.

### Logic manipulation

```text
OR / AND / comments
```

### Data extraction

```text
UNION SELECT
```

---

# 3. Basic UNION Example

Suppose we have:

### `ports`

|code|city|
|---|---|
|CN SHA|Shanghai|
|SG SIN|Singapore|
|ZZ-21|Shenzhen|

And:

### `ships`

|Ship|city|
|---|---|
|Morrison|New York|

We can run:

```sql
SELECT * FROM ports
UNION
SELECT * FROM ships;
```

The database combines the results:

|code|city|
|---|---|
|CN SHA|Shanghai|
|SG SIN|Singapore|
|Morrison|New York|
|ZZ-21|Shenzhen|

The important point is that the two result sets become **one result set**.

---

# 4. Visualizing UNION

Think of it as:

```text
┌─────────────────┐
│ SELECT ports    │
│                 │
│ CN SHA Shanghai │
│ SG SIN Singapore│
│ ZZ-21 Shenzhen  │
└────────┬────────┘
         │
       UNION
         │
┌────────▼────────┐
│ SELECT ships    │
│                 │
│ Morrison NY     │
└────────┬────────┘
         │
         ▼
┌────────────────────────┐
│ Combined Result        │
│                        │
│ CN SHA   Shanghai      │
│ SG SIN   Singapore     │
│ Morrison New York      │
│ ZZ-21    Shenzhen      │
└────────────────────────┘
```

---

# 5. The First Critical Rule — Same Number of Columns

This is probably the **single most important rule for UNION-based SQLi**:

> **The participating `SELECT` statements must return the same number of columns.**

For example:

```sql
SELECT city FROM ports
UNION
SELECT * FROM ships;
```

If:

```text
First SELECT  → 1 column
Second SELECT → 2 columns
```

the database rejects the query.

You get an error similar to:

```text
ERROR 1222:
The used SELECT statements have a different number of columns
```

---

# 6. Why Must Column Counts Match?

Imagine:

```text
SELECT A
```

returns:

```text
[A]
```

while:

```text
SELECT B, C
```

returns:

```text
[B] [C]
```

How would the database combine:

```text
[A]
```

with:

```text
[B] [C]
```

into the same result structure?

It can't.

The result sets need compatible structures:

```text
SELECT A, B
      UNION
SELECT C, D
```

Both produce:

```text
[column 1] [column 2]
```

Therefore they can be combined.

---

# 7. Second Critical Rule — Compatible Data Types

Matching the number of columns isn't always enough.

The corresponding columns should have compatible data types.

For example:

```text
SELECT integer_column, string_column
UNION
SELECT integer_value, string_value
```

is naturally compatible.

Think positionally:

```text
First SELECT       Second SELECT

Column 1  ──────── Column 1
Column 2  ──────── Column 2
Column 3  ──────── Column 3
```

The database compares the columns based on their **position**, not their names.

---

# 8. Column Names

Another useful detail:

The resulting column names generally come from the **first `SELECT`**.

For example:

```sql
SELECT code, city FROM ports
UNION
SELECT Ship, city FROM ships;
```

The output headings are based on the first query's columns:

```text
code | city
```

not necessarily:

```text
Ship | city
```

This becomes useful when interpreting UNION-based results.

---

# 9. UNION Injection Concept

Suppose an application normally executes:

```sql
SELECT *
FROM products
WHERE product_id = 'user_input';
```

The application expects:

```text
user_input → product ID
```

But if the input can alter the SQL query structure, the resulting query may contain another `SELECT` joined using `UNION`.

Conceptually:

```text
Original SELECT
      +
Attacker-controlled SELECT
      ↓
UNION
      ↓
Combined result
```

This is the foundation of **UNION-based SQL Injection**.

---

# 10. Why UNION Is Powerful

Imagine the application normally queries:

```text
products
```

but another table contains:

```text
users
passwords
```

If the application is vulnerable and the resulting query is compatible, a UNION can cause results from another table to appear in the application's response.

Conceptually:

```text
Application normally exposes:
       products

UNION-based SQLi:
       products
          +
       another table
          ↓
       application response
```

This is why UNION SQLi can become a data-extraction vulnerability.

---

# 11. The Key Challenge: Finding the Column Count

Suppose you don't know how many columns the original query returns.

You need to determine:

```text
Original SELECT
      ↓
How many columns?
```

For example, if the original query returns:

```text
4 columns
```

then your UNION `SELECT` must also return:

```text
4 columns
```

Conceptually:

```text
Original:
SELECT ?, ?, ?, ?

UNION:
SELECT ?, ?, ?, ?
```

---

# 12. Column Count Is Not the Same as Visible Columns

This distinction is important.

A query may return:

```text
4 columns
```

but the application might only visibly display:

```text
2 columns
```

For UNION SQLi, what matters initially is the **number of columns returned by the underlying SELECT**, not simply how many values you can see on the webpage.

Later, we care about which of those columns are reflected in the application's response.

---

# 13. Uneven Columns — The Problem

Suppose the original query returns four columns:

```text
Column 1
Column 2
Column 3
Column 4
```

But you only want to retrieve:

```text
username
```

You cannot simply create:

```sql
SELECT username FROM passwords
```

because that produces only one column.

The UNION requires:

```text
4 columns
```

So you need additional expressions to fill the remaining positions.

---

# 14. Junk Data

The HTB material introduces **junk values** for columns whose contents aren't important.

For example:

```sql
SELECT username, 2
FROM passwords;
```

This returns two columns:

```text
username | 2
```

The second column doesn't contain useful information; it exists to satisfy the required column count.

---

# 15. Four-Column Example

Suppose the original query has four columns:

```text
1
2
3
4
```

You want:

```text
username
```

Your UNION result must still contain four columns.

Conceptually:

```text
username | 2 | 3 | 4
```

So:

```sql
SELECT username, 2, 3, 4
FROM passwords;
```

produces:

```text
┌──────────┬───┬───┬───┐
│ username │ 2 │ 3 │ 4 │
└──────────┴───┴───┴───┘
```

---

# 16. Why Numbers Are Useful

The module specifically recommends numbers as filler values.

For example:

```text
1
2
3
4
```

This has two benefits:

### 1. They are easy to recognize

When the result appears:

```text
username | 2 | 3 | 4
```

you immediately know which position corresponds to which column.

### 2. They help track positions

You can conceptually label:

```text
Column 1 → username
Column 2 → 2
Column 3 → 3
Column 4 → 4
```

This becomes particularly useful when determining **which result column is reflected by the application**.

---

# 17. `NULL` as a Filler

For more advanced SQLi, `NULL` is often useful as a placeholder.

Conceptually:

```sql
SELECT username, NULL, NULL, NULL
FROM passwords;
```

Why?

Because `NULL` is compatible with many data types.

Instead of worrying whether a filler needs to be:

```text
integer
string
date
```

you can often use:

```text
NULL
```

where the DBMS permits it.

### Important distinction

For learning:

```text
Numbers → easy to identify
NULL    → broadly type-compatible
```

---

# 18. Data-Type Matching

Suppose the original query has:

```text
Column 1 → integer
Column 2 → string
```

Your UNION should provide compatible values:

```text
Column 1 → integer-compatible
Column 2 → string-compatible
```

Conceptually:

```text
Original                  UNION

integer   ─────────────── integer
string    ─────────────── string
```

If the types are incompatible in a way MySQL cannot reconcile, the query may produce an error.

---

# 19. Position Matters

UNION doesn't match columns by their names.

It matches:

```text
position 1 ↔ position 1
position 2 ↔ position 2
position 3 ↔ position 3
```

For example:

```sql
SELECT A, B, C
UNION
SELECT X, Y, Z;
```

means:

```text
A ↔ X
B ↔ Y
C ↔ Z
```

Not:

```text
A ↔ Z
```

just because the names or types might be preferable.

---

# 20. The Important UNION SQLi Formula

Keep this mental formula:

```text
Original SELECT column count
             =
UNION SELECT column count
```

Then:

```text
Each position
      ↓
Compatible data type
```

Then:

```text
Desired data
      ↓
Placed in an appropriate position
```

---

# 21. UNION Injection Workflow

For an authorized HTB lab, your conceptual workflow is:

```text
                 UNION SQLi
                     │
                     ▼
            Identify SQL context
                     │
                     ▼
          Determine column count
                     │
                     ▼
       Make UNION column count match
                     │
                     ▼
       Ensure compatible data types
                     │
                     ▼
        Identify reflected columns
                     │
                     ▼
       Place desired data there
                     │
                     ▼
          Interpret the output
```

This is the foundation of the upcoming practical sections.

---

# 22. Difference Between Normal UNION and UNION SQLi

### Normal SQL

The developer intentionally writes:

```sql
SELECT * FROM ports
UNION
SELECT * FROM ships;
```

The query is trusted and controlled.

### UNION SQL Injection

The application unintentionally allows user-controlled input to alter the query:

```text
User Input
    ↓
SQL Query
    ↓
UNION SELECT
    ↓
Unexpected result
```

The security problem is **untrusted input becoming SQL syntax**.

---

# 23. UNION vs Authentication Bypass

This distinction is extremely important.

### Authentication bypass

Goal:

```text
Change query logic
      ↓
Get TRUE
      ↓
Application accepts login
```

Common concepts:

```text
OR
comments
quotes
parentheses
```

### UNION SQLi

Goal:

```text
Combine original results
       +
Results from another SELECT
       ↓
Data appears in application response
```

Core concept:

```text
UNION SELECT
```

---

# 24. UNION Doesn't Mean "Run Any Query"

A common beginner misunderstanding is:

> "`UNION` lets me execute anything."

Not exactly.

`UNION` combines the **result sets of compatible SELECT statements**.

Therefore, the important constraints are:

```text
SELECT
  ↓
Same number of columns
  ↓
Compatible column types
  ↓
Combined result
```

It's fundamentally about **combining query results**.

---

# 25. Example — Two Columns

Suppose:

```sql
SELECT product_name, price
FROM products
WHERE product_id = '...';
```

The original result has:

```text
Column 1 → product_name
Column 2 → price
```

A compatible UNION needs:

```text
Column 1 → something
Column 2 → something
```

For example, conceptually:

```sql
UNION SELECT username, 2
```

Now both sides have:

```text
2 columns
```

---

# 26. Example — Four Columns

Original:

```text
SELECT ?, ?, ?, ?
```

Desired information:

```text
username
```

Need:

```text
username, filler, filler, filler
```

Conceptually:

```sql
SELECT username, 2, 3, 4
```

Result:

```text
┌──────────┬───┬───┬───┐
│ username │ 2 │ 3 │ 4 │
└──────────┴───┴───┴───┘
```

The useful value is in **column position 1**.

---

# 27. Why Reflected Columns Matter

Even if your UNION query succeeds, you may not immediately see the data.

For example, the database may return:

```text
Column 1
Column 2
Column 3
Column 4
```

but the webpage may only display:

```text
Column 2
```

Therefore:

```text
UNION succeeds
       ≠
Data is visible
```

You also need to determine which returned column positions are actually reflected in the application's response.

This becomes a key topic in practical UNION SQLi.

---

# 28. `UNION` vs `UNION ALL`

You should also know this distinction.

### `UNION`

Combines results and generally removes duplicate rows.

```sql
SELECT ...
UNION
SELECT ...
```

### `UNION ALL`

Combines results while retaining duplicates.

```sql
SELECT ...
UNION ALL
SELECT ...
```

For SQL Injection learning, you'll commonly encounter `UNION`, but knowing `UNION ALL` is useful.

---

# 29. Duplicate Removal

Suppose:

```text
Query A:
1
2

Query B:
2
3
```

With `UNION`:

```text
1
2
3
```

With `UNION ALL`:

```text
1
2
2
3
```

The distinction can matter when interpreting query results.

---

# 30. Important Terminology

### Result set

The rows returned by a query.

### Column count

Number of columns returned by a `SELECT`.

### Column position

The location of a column within the result:

```text
1st
2nd
3rd
4th
```

### Compatible type

A value that can be used in the corresponding column position without causing an incompatible-type error.

### Reflected column

A result column whose value is actually displayed or otherwise observable through the application's response.

---

# 31. Common Beginner Mistakes

### ❌ Mistake 1: Different column counts

```text
Original → 4 columns
UNION    → 2 columns
```

Won't work.

---

### ❌ Mistake 2: Forgetting column positions

The database maps:

```text
1 → 1
2 → 2
3 → 3
```

not by column names.

---

### ❌ Mistake 3: Ignoring data types

A filler value must be suitable for the corresponding position.

---

### ❌ Mistake 4: Assuming successful UNION means visible output

The query can execute successfully while the web application doesn't display the useful column.

---

### ❌ Mistake 5: Blindly using payloads

Don't memorize random UNION strings.

Instead understand:

```text
What is the original query?
How many columns?
Which positions accept my value?
Which positions are reflected?
```

That's the skill HTB is trying to teach.

---

# 32. ⭐ The Four Questions You Should Ask

When you encounter a UNION SQLi lab, stop and answer these four questions:

### 1. How many columns does the original query return?

```text
?
```

### 2. Can my UNION SELECT return the same number?

```text
Original = UNION
```

### 3. Which positions accept compatible data?

```text
1 → ?
2 → ?
3 → ?
4 → ?
```

### 4. Which positions are reflected in the application?

```text
Column 1 → visible?
Column 2 → visible?
Column 3 → visible?
Column 4 → visible?
```

Only after understanding these should you think about what information belongs in the UNION result.

---

# 33. ⭐ Most Important Things to Memorize

> **`UNION` combines the results of multiple `SELECT` statements.**

> **Every `SELECT` participating in a UNION must return the same number of columns.**

> **Corresponding columns should have compatible data types.**

> **Columns are matched by position, not by name.**

> **If the original query returns four columns, the UNION query must also return four columns.**

> **Junk values can fill positions where useful data isn't required.**

> **Numbers such as `1, 2, 3, 4` are useful as identifiable placeholders.**

> **`NULL` is often useful as a broadly compatible placeholder.**

> **A successful UNION doesn't guarantee that the desired data will be displayed by the web application.**

> **You must identify which result columns are reflected by the application.**

> **`UNION` generally removes duplicate rows; `UNION ALL` retains them.**

---

# 34. Final Mental Model

```text
             VULNERABLE APPLICATION
                      │
                      ▼
              ORIGINAL SELECT
                      │
              ┌───────┴────────┐
              │                │
              ▼                ▼
        Original Data     UNION SELECT
                              │
                              ▼
                       Desired Data
                              │
                              ▼
                    Compatible Columns
                              │
                              ▼
                      Combined Result
                              │
                              ▼
                    Application Response
                              │
                              ▼
                     Reflected Output
```

### The golden rule for UNION SQLi:

```text
             ORIGINAL QUERY
                    │
                    ▼
            Find column count
                    │
                    ▼
         UNION must match count
                    │
                    ▼
       Match compatible data types
                    │
                    ▼
       Identify reflected positions
                    │
                    ▼
          Understand the output
```

**The biggest mindset shift from the previous sections is this:** authentication-bypass SQLi mainly teaches you to **change the meaning of an existing query**; UNION SQLi teaches you to understand how a vulnerable query can **combine its result with another SELECT result**. That distinction will become crucial when you start extracting database metadata and data in the next parts.