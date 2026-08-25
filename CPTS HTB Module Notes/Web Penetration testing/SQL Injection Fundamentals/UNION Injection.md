![Image](https://images.openai.com/static-rsc-4/stneVNHnJrDMSGHOvHHW9pcM0cggjzmc9_pglx4ZumbiRluSlpp2Gi7gUYhhd6v0YioVQQmUg0k7-J1Qs4wgG5WnIs2Rqewnz0d_8FWkWJTEJybEQXmH_N2yR4zTlQTbdO2zUOHzcQAey_iP-S2VpH3q7lIClh8JAnbI74rZ8G60t_CjTU0DBFS-SsyTrZ0U?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/plVi3SXIA__x5D6UuSYKT90Z0dNsK5_LaskWwdtQJjHYcsTPT60BlzIKIgei6tY1n1tlDqmg_LwRcGaVgiQ9wV9_6KmYf5bi99DoDnba5O7fRaWv9mgJPtyWbRWK-jBkg1TMDA_4Ps2BDl9CURzrpg3Owv_xQHAEd2a_VZCKV6mAXLvFdMpuHuxm-I85O-hS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/W-8j0GZdocLz8hA1lH8ZGVuGbC8HcF8XitRtiZvBZ2HIDymkfSmGMPRCIE75m9PqHdf6DyamlPCJbvUOd2L8m6FgiCHWKq3Fb7b3PYtH61bhZ-HGstxsJDsLSNjSSgh9FjTq7IVWTXrd9Qx12xkU17sWnmetC88UQPZyOEGFQfVdDR77fGvGZLlgDWB69a84?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/pwhmOk37i2FTVR2JOM83PRjAP0D5vA1Etxx1CtexF-gXjNLMPjSVWUcnapcxSvlWYgles5n3rSxgWj7rJ5_YkYc8Bozy_7c3_jEjZD9W5k5P-jUelb6IRKEt8RfaIlfIPs2GWAdR7bS63iD-zG9bolSdE3tTxHT52lZd2B_PEZ9R0k_7ZmodjhZJZyYfgSCX?purpose=fullsize)

---

# 1. What Is UNION Injection?

A **UNION SQL Injection** occurs when an attacker can manipulate a vulnerable SQL query so that it combines the application's original `SELECT` statement with another `SELECT` statement.

Conceptually:

```text
Original SELECT
      +
Injected SELECT
      ↓
    UNION
      ↓
Combined Result
      ↓
Application displays result
```

This is different from the authentication-bypass techniques you learned earlier.

### Previous sections

You were changing:

```text
TRUE / FALSE
```

### UNION Injection

You are trying to make:

```text
Original result
      +
Additional result
```

appear in the application's response.

---

# 2. The Example Application

The HTB lab provides a search page similar to:

```text
┌─────────────────────────────────────────┐
│ Search: [ cn                       ]    │
│                              [Search]   │
└─────────────────────────────────────────┘

Port Code       Port City       Port Volume
------------------------------------------------
CN SHA          Shanghai        37.13
CN SHE          Shenzhen        23.97
```

The request contains:

```text
port_code=cn
```

The application probably uses that input in an SQL query.

We don't necessarily know the exact query initially.

That's important.

---

# 3. First Step — Detect SQL Injection

As with previous sections, start by testing whether special characters affect the SQL query.

A single quote:

```text
'
```

causes an SQL error.

Conceptually:

```text
Normal input
    ↓
Normal response

'
    ↓
SQL error
```

This suggests that the input may be reaching an SQL context without being safely parameterized.

### Important

An error is an **indicator**, not proof of exactly how the query is constructed.

You still need to determine the query's structure.

---

# 4. Why UNION Is Suitable Here

The lab gives us an important advantage:

> **We can see the results of our queries on the webpage.**

That makes this a good environment for **in-band UNION-based SQL Injection**.

Think:

```text
Injected SQL
     ↓
Database
     ↓
Query result
     ↓
Web page
     ↓
We can observe it
```

This is much easier than a blind SQL Injection scenario where the result isn't directly displayed.

---

# 5. The UNION SQLi Process

The overall workflow is:

```text
┌─────────────────────────┐
│ 1. Find SQLi            │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│ 2. Find column count    │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│ 3. Find reflected       │
│    columns               │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│ 4. Test data retrieval  │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│ 5. Enumerate database   │
└─────────────────────────┘
```

This section focuses primarily on **steps 2–4**.

---

# 6. Step 1 — Determine Number of Columns

Before using a UNION, we need to know:

```text
How many columns does the original SELECT return?
```

This is required because:

```text
Original SELECT columns
        =
UNION SELECT columns
```

If the counts don't match, the database rejects the query.

---

# 7. Two Methods

The module provides two methods:

### Method 1

```text
ORDER BY
```

### Method 2

```text
UNION
```

Both ultimately determine the same thing:

```text
Number of columns
```

---

# 8. Method 1 — ORDER BY

Recall:

```sql
SELECT *
FROM table
ORDER BY column;
```

We can specify the column position numerically.

Conceptually:

```text
ORDER BY 1
```

means:

```text
Sort according to column 1
```

Likewise:

```text
ORDER BY 2
ORDER BY 3
ORDER BY 4
```

refer to those column positions.

---

# 9. Why ORDER BY Can Find the Column Count

Suppose the original query has:

```text
4 columns
```

Then:

```text
ORDER BY 1 → valid
ORDER BY 2 → valid
ORDER BY 3 → valid
ORDER BY 4 → valid
ORDER BY 5 → invalid
```

Therefore:

```text
Largest valid column number = total column count
```

---

# 10. Example

The lab starts conceptually with:

```text
' order by 1-- -
```

The query still works.

Then:

```text
' order by 2-- -
```

also works.

Then:

```text
' order by 3-- -
```

works.

Then:

```text
' order by 4-- -
```

works.

But:

```text
' order by 5-- -
```

causes:

```text
Unknown column '5' in 'order clause'
```

Therefore:

```text
1 ✓
2 ✓
3 ✓
4 ✓
5 ✗
```

### Conclusion:

**The query returns 4 columns.**

---

# 11. Visual Representation

```text
ORDER BY 1   ✓
     ↓
ORDER BY 2   ✓
     ↓
ORDER BY 3   ✓
     ↓
ORDER BY 4   ✓
     ↓
ORDER BY 5   ✗
     ↓
Column count = 4
```

This is a very useful pattern to memorize.

---

# 12. Why the `-- -` Appears

You'll repeatedly see:

```text
-- -
```

in the HTB examples.

The extra dash is mainly being used by the module to make the whitespace after `--` visually obvious.

The important syntax is:

```text
-- [space]
```

The final `-` is not the essential part of the comment syntax.

So mentally read:

```text
-- -
```

as:

```text
-- [space] ...
```

---

# 13. Method 2 — UNION

The second technique is to try UNION queries with different numbers of columns.

For example:

```text
UNION SELECT 1,2,3
```

If the original query has four columns:

```text
Original → 4
UNION    → 3
```

the database returns a column-count mismatch.

---

# 14. Three-Column Attempt

The lab tries:

```text
cn' UNION SELECT 1,2,3-- -
```

The database reports that the SELECT statements have different numbers of columns.

This tells us:

```text
UNION columns ≠ original columns
```

At this stage:

```text
3 columns → incorrect
```

---

# 15. Four-Column Attempt

Next:

```text
cn' UNION SELECT 1,2,3,4-- -
```

This succeeds.

Therefore:

```text
Original query = 4 columns
UNION query    = 4 columns
```

The result displays:

```text
2
3
4
```

---

# 16. Comparing the Two Methods

|Method|Initial behavior|What tells you the count?|
|---|---|---|
|`ORDER BY`|Works until invalid number|First failing number|
|`UNION SELECT`|Errors until correct count|First successful count|

### ORDER BY:

```text
1 ✓
2 ✓
3 ✓
4 ✓
5 ✗
→ 4 columns
```

### UNION:

```text
1,2,3 ✗
1,2,3,4 ✓
→ 4 columns
```

---

# 17. Important Mindset

Don't memorize:

```text
"Try 4 because HTB's example has 4."
```

Instead ask:

> **What is the column count of the actual query I'm testing?**

It could be:

```text
2
3
4
5
8
10
```

The number depends entirely on the application's underlying query.

---

# 18. Step 2 — Find Reflected Columns

Knowing:

```text
4 columns
```

is only half the problem.

Why?

Because the web application may not display every column returned by the database.

For example:

```text
Database returns:

Column 1
Column 2
Column 3
Column 4
```

but the webpage might display only:

```text
Column 2
Column 3
Column 4
```

---

# 19. Why Would a Column Not Be Displayed?

A database table might contain fields such as:

```text
id
port_code
city
volume
```

The application might use:

```text
id
```

internally to identify the record but not display it.

So:

```text
Database:
id | code | city | volume

Website:
     code | city | volume
```

Therefore:

```text
Column 1 → not reflected
Column 2 → reflected
Column 3 → reflected
Column 4 → reflected
```

---

# 20. Why Numbers Are Perfect for Testing

The module uses:

```text
1, 2, 3, 4
```

because each number identifies its position.

The UNION result might be:

```text
1 | 2 | 3 | 4
```

But the webpage displays:

```text
2 | 3 | 4
```

Therefore you immediately know:

```text
Column 1 → hidden
Column 2 → visible
Column 3 → visible
Column 4 → visible
```

---

# 21. Visualizing Reflected Columns

```text
Database Result
┌─────┬─────┬─────┬─────┐
│  1  │  2  │  3  │  4  │
└─────┴─────┴─────┴─────┘
   │     │     │     │
   ✗     ✓     ✓     ✓
   │     │     │     │
   │     └─────┴─────┘
   │           │
   │           ▼
   │      Web Application
   │        displays:
   │
   └────── hidden
```

Therefore, useful data should be placed in a **reflected position**.

---

# 22. Very Important Distinction

Remember:

```text
Column count
```

and:

```text
Reflected columns
```

are **not the same thing**.

For example:

```text
Total columns = 4
Reflected columns = 3
```

That's completely possible.

---

# 23. Step 3 — Test Actual Database Data

Once we know:

```text
4 columns
```

and:

```text
2, 3, 4 → reflected
```

we can test whether actual database-generated information can appear in one of those positions.

The HTB example uses:

```text
@@version
```

---

# 24. What Is `@@version`?

In MySQL/MariaDB:

```sql
@@version
```

returns the database server's version information.

For example, the lab displays:

```text
10.3.22-MariaDB-1ubuntu1
```

This is useful as a **non-sensitive test value** because it confirms that the UNION result is actually being evaluated and reflected by the application.

---

# 25. Why Test With `@@version`?

Before trying to retrieve other database information, we want to prove:

```text
UNION works
       ↓
Desired column is reflected
       ↓
Database expression is evaluated
       ↓
Output reaches webpage
```

So:

```text
1, @@version, 3, 4
```

is conceptually:

```text
Column 1 → filler
Column 2 → database version
Column 3 → filler
Column 4 → filler
```

---

# 26. Result

The webpage shows something like:

```text
Port Code       Port City                     Port Volume
----------------------------------------------------------------
...             10.3.22-MariaDB-1ubuntu1      3 / 4
```

The important observation is:

```text
@@version
    ↓
Column 2
    ↓
Column 2 is reflected
    ↓
Database-generated value appears
```

Now we've confirmed the complete chain.

---

# 27. The Complete UNION SQLi Chain

This is the **core concept of the entire section**:

```text
                    INPUT
                      │
                      ▼
              Vulnerable SQL
                      │
                      ▼
             Find column count
                      │
                      ▼
                  4 columns
                      │
                      ▼
           Find reflected columns
                      │
              ┌───────┼───────┐
              ▼       ▼       ▼
              2       3       4
              │       │       │
              └───────┼───────┘
                      ▼
               Test @@version
                      │
                      ▼
              Database evaluates
                      │
                      ▼
             Web page displays it
```

---

# 28. The Four Main Questions

When approaching a UNION SQLi lab, train yourself to answer these **four questions in order**:

### ① Is the parameter injectable?

Look for behavior changes/errors when testing SQL syntax.

### ② How many columns does the original query return?

Use:

```text
ORDER BY
```

or controlled UNION column-count testing.

### ③ Which columns are reflected?

Use identifiable placeholder values and observe the response.

### ④ Can a database expression appear there?

Use a harmless test expression such as:

```text
@@version
```

This proves the UNION path.

---

# 29. Why `ORDER BY` Is Such a Good Learning Tool

`ORDER BY` teaches you an important concept:

```text
Column position
```

For example:

```text
ORDER BY 1
```

means:

```text
first result column
```

while:

```text
ORDER BY 4
```

means:

```text
fourth result column
```

This positional thinking becomes essential for UNION SQLi.

---

# 30. UNION Column Positions

If there are four columns:

```text
┌───────────┬───────────┬───────────┬───────────┐
│ Position 1│ Position 2│ Position 3│ Position 4│
└───────────┴───────────┴───────────┴───────────┘
```

Your UNION must produce the same structure:

```text
┌───────────┬───────────┬───────────┬───────────┐
│ Position 1│ Position 2│ Position 3│ Position 4│
└───────────┴───────────┴───────────┴───────────┘
```

Then determine:

```text
Which positions are visible?
```

---

# 31. Why Column 1 Can Be Invisible

The lab specifically emphasizes:

> **We cannot place our useful query at the beginning if column 1 is not printed.**

This is an important practical concept.

Suppose:

```text
Column 1 → hidden
Column 2 → visible
Column 3 → visible
Column 4 → visible
```

Then putting:

```text
@@version
```

in column 1 may successfully execute but produce **no visible output**.

That doesn't necessarily mean the UNION failed.

It may simply mean:

```text
Query succeeded
      ↓
Value placed in hidden column
      ↓
Web application didn't display it
```

---

# 32. This Is Why Blind Testing Can Mislead You

Imagine:

```text
UNION succeeds
```

but:

```text
No output appears
```

You shouldn't immediately conclude:

> "The injection doesn't work."

Instead ask:

```text
Did the UNION execute?
Was the column count correct?
Which columns are reflected?
Where did I place my expression?
```

This is much better troubleshooting.

---

# 33. Error-Based vs UNION-Based Discovery

Earlier you learned about different SQLi types.

Here, we're dealing with:

```text
In-band
   ↓
UNION-based
```

because:

```text
Database output
      ↓
HTTP response
      ↓
Same application page
```

We can directly see the result.

---

# 34. Why This Is Called "In-Band"

"In-band" essentially means the attack and the data retrieval happen through the same communication channel.

Conceptually:

```text
Request
  ↓
Web application
  ↓
Database
  ↓
Web application
  ↓
Response containing result
```

The same web interface provides the observable output.

---

# 35. Important Security Insight

The database isn't necessarily giving the attacker information directly.

The vulnerable application is acting as the bridge:

```text
Attacker
   ↓
HTTP Request
   ↓
Web Application
   ↓
Database
   ↓
Unexpected query
   ↓
Database Result
   ↓
Web Application
   ↓
HTTP Response
   ↓
Attacker
```

This is why **safe query construction** is so important.

---

# 36. Common Mistakes

## ❌ Mistake 1 — Guessing the column count

Don't assume:

```text
4 columns
```

just because one previous lab had four.

Determine it.

---

## ❌ Mistake 2 — Forgetting the UNION rule

```text
Original = 4
UNION = 3
```

will fail.

Remember:

```text
Original column count = UNION column count
```

---

## ❌ Mistake 3 — Assuming all columns are displayed

They aren't necessarily.

You must identify:

```text
reflected columns
```

---

## ❌ Mistake 4 — Thinking no output means failure

The expression could be in:

```text
hidden column
```

---

## ❌ Mistake 5 — Not using identifiable placeholders

Compare:

```text
?, ?, ?, ?
```

with:

```text
1, 2, 3, 4
```

The second is much easier to analyze.

---

## ❌ Mistake 6 — Skipping query reconstruction

Always understand:

```text
Original query
       +
Input
       =
Final query
```

---

# 37. ⭐ Things You MUST Remember

> **UNION-based SQLi combines the original query's results with another SELECT statement.**

> **Before using UNION, determine the original query's column count.**

> **`ORDER BY` can be used to determine column count by increasing the column number until it fails.**

> **The largest successful `ORDER BY` position indicates the number of columns.**

> **A UNION query must return the same number of columns as the original query.**

> **Use identifiable placeholder values such as `1,2,3,4` to track column positions.**

> **Not every database column is necessarily displayed by the web application.**

> **A successful UNION with no visible output may simply mean your useful value is in a non-reflected column.**

> **The useful data should be placed in a reflected column.**

> **`@@version` is a useful test expression because it demonstrates that database-generated information can be returned through the application.**

> **Finding the column count and finding reflected columns are two separate steps.**

---

# 38. One-Page Revision Sheet

```text
             UNION SQL INJECTION
                     │
                     ▼
          1. Detect SQL Injection
                     │
                     ▼
          2. Find column count
             ┌───────┴───────┐
             ▼               ▼
          ORDER BY          UNION
             │               │
             └───────┬───────┘
                     ▼
              Example = 4
                     │
                     ▼
          3. Find reflected columns
                     │
             1  2  3  4
             ✗  ✓  ✓  ✓
                     │
                     ▼
          4. Test database output
                     │
                 @@version
                     │
                     ▼
             Reflected result
                     │
                     ▼
           UNION SQLi confirmed
```

---

# 39. The Golden Mental Model 🧠

Don't think:

> **"Which UNION payload should I copy?"**

Think:

> **"What does the application query return, how many columns does it have, and which of those columns does the application actually reflect?"**

Your reasoning should look like:

```text
Input affects SQL
      ↓
SQLi indicated
      ↓
Column count?
      ↓
4
      ↓
Reflected positions?
      ↓
2, 3, 4
      ↓
Can database output appear?
      ↓
@@version appears
      ↓
UNION result is observable
```

Once you can independently reason through that chain, you've understood the **core mechanics of UNION-based SQL Injection**, rather than just memorizing payloads.