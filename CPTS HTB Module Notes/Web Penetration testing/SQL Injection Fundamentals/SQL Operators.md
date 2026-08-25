![Image](https://images.openai.com/static-rsc-4/89bgzo0ZGoXhB6mDQZWKuSe3_y9q_vBbJWszpdlhLd5Zqmk3nR6ZF5skapydnciIDnsNfU_EUjCyExJaEkLxWJXbTnLkhN3LUPBbDeGL1Xpv99jVHMyqljdTE4yUuuL-FJzIwQpC_6g14wpufA7iQmqk70MTNoak6U_qmLfzzhM9ISyDj-2SURoSLXo6gD5K?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/FWTzbFBVDfniBLht_zQT9O8GP0RzXyr8htiQVg6oaHkvfYoqEtCAxFdtI343iXbsUI_PtPqEAzF0zgrXMbK1HQwQ-9WlflHlvuHVmbDADkd_jCRyWROjN3tfoTuyo9aK-FceYC4kWNjgCQ_B4sL5V_lelAYl2EWd9F-r_UuDZh5Hund2OOd6vzYL9JwXAITz?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/JG30BmXvcotcLxXTqWD_rAWv-dH_BGXreG8Ku8D0KNdnh-Q3xFgKLYV842ZF17nmfD1XGW8cRXzNHR7u5H5F2Yu1UkiMHxCjtJL_2Xn3dPZ9nplB2J1I3h5V986L-NNR79LlOyEMXOg08chDJaTV6QAGMMG2A3fWZ9LGoSfMS2xd04Kdu1mJCxlGDkwMQ3aU?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/LZ-jb7uXkLz2LHi_CpYFJRNPAH9312KEuOc1fJwRzfbS0hYZ8PLXLKWYQeugADZdVgCUt7dOss35cmaENePfWOtWcMImT4km3QNM7ZgrvJmWxjkUNSPId7yIJEAqODK56b6XnDaa69pl12k-SC2mIZfnts2ZDWP3FPdW5LI2l8HXI5NqW25Q2T1ic--_wSsG?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qaBF_GCgOrOEVj174tA9ihEKQgonruq125EiyjA0qe_yZKv_Tyqx9QIyjIJiOsRFw2vTP4IwyApWoWaNwiC24iQkFbj48_S-zzipaHseDDqrMmVo2jwr2N1FdrwrCM3EkAhB6MCLFDlBjZXYrBU8XULJpg6yWI6_7k7A1VQnvWid0vWEq_D9_n4WxgHa6sbg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZXTNSo8LDK_VQBKWxNQU338fyxj3hU23JHanmG8-m5FT4w1rRc-3aVAGiQCUohhXbVYo_hbhG0EI34EJpHeQIKCcpLyxP_ovCR2agYfSXR96DgO4TuAbxct-cM6HRiOi1NEePOl9uYcmdMlvQUzysrln19jaWNEon0aUcjHd4LJgXl8lpX6C2tAXHKT2b625?purpose=fullsize)
## 1. Introduction

Sometimes a single condition isn't enough.

For example:

```sql
WHERE username = 'admin'
```

checks only one condition.

But we may need something like:

> Find users whose username is `admin` **AND** whose ID is greater than `1`.

SQL provides **logical operators** for combining and modifying conditions.

The three most important logical operators are:

```text
AND
OR
NOT
```

These are extremely important for SQL Injection because SQL queries frequently depend on boolean conditions.

---

# 2. Boolean Values in MySQL

Before learning the operators, understand how MySQL represents boolean results.

In MySQL:

```text
0       → FALSE
non-zero → TRUE
```

MySQL commonly returns:

```text
1 → TRUE
0 → FALSE
```

For example:

```sql
SELECT 1 = 1;
```

returns:

```text
1
```

because:

```text
1 = 1
```

is true.

Whereas:

```sql
SELECT 1 = 2;
```

returns:

```text
0
```

because:

```text
1 = 2
```

is false.

### Remember

```text
TRUE  → 1
FALSE → 0
```

---

# 3. AND Operator

The `AND` operator combines two conditions.

### Syntax

```sql
condition1 AND condition2
```

`AND` returns **TRUE only when both conditions are TRUE**.

### Truth Table

|Condition A|Condition B|A AND B|
|---|---|---|
|TRUE|TRUE|TRUE|
|TRUE|FALSE|FALSE|
|FALSE|TRUE|FALSE|
|FALSE|FALSE|FALSE|

The easiest way to remember:

> **AND = Everything must be TRUE.**

---

# 4. AND Example

```sql
SELECT 1 = 1 AND 'test' = 'test';
```

Evaluate each condition:

```text
1 = 1
 ↓
TRUE

'test' = 'test'
 ↓
TRUE
```

Therefore:

```text
TRUE AND TRUE
      ↓
    TRUE
```

MySQL returns:

```text
1
```

---

# 5. AND with a False Condition

Consider:

```sql
SELECT 1 = 1 AND 'test' = 'abc';
```

Evaluate:

```text
1 = 1
 ↓
TRUE
```

and:

```text
'test' = 'abc'
 ↓
FALSE
```

Therefore:

```text
TRUE AND FALSE
       ↓
     FALSE
```

Result:

```text
0
```

---

# 6. AND Mental Model

Think of `AND` as a security gate:

```text
Condition A ──┐
              ├── AND ──► Access only if BOTH are true
Condition B ──┘
```

For example:

```sql
WHERE username = 'admin'
AND id = 1
```

A row must satisfy:

```text
username = admin
        AND
id = 1
```

Both conditions must be true.

---

# 7. OR Operator

The `OR` operator also combines two conditions.

Unlike `AND`, `OR` returns TRUE when **at least one condition is TRUE**.

### Syntax

```sql
condition1 OR condition2
```

### Truth Table

|Condition A|Condition B|A OR B|
|---|---|---|
|TRUE|TRUE|TRUE|
|TRUE|FALSE|TRUE|
|FALSE|TRUE|TRUE|
|FALSE|FALSE|FALSE|

Easy memory trick:

> **OR = At least one must be TRUE.**

---

# 8. OR Example

```sql
SELECT 1 = 1 OR 'test' = 'abc';
```

Evaluate:

```text
1 = 1
 ↓
TRUE
```

and:

```text
'test' = 'abc'
 ↓
FALSE
```

Therefore:

```text
TRUE OR FALSE
      ↓
    TRUE
```

MySQL returns:

```text
1
```

---

# 9. OR with Two False Conditions

```sql
SELECT 1 = 2 OR 'test' = 'abc';
```

Both conditions are false:

```text
1 = 2       → FALSE
'test'='abc' → FALSE
```

Therefore:

```text
FALSE OR FALSE
      ↓
    FALSE
```

Result:

```text
0
```

---

# 10. OR Mental Model

Think of `OR` as multiple doors:

```text
Condition A ──┐
              ├── OR ──► TRUE if either door works
Condition B ──┘
```

For example:

```sql
WHERE username = 'admin'
OR username = 'administrator'
```

A row can match either username.

---

# 11. NOT Operator

`NOT` reverses a boolean result.

It converts:

```text
TRUE → FALSE
FALSE → TRUE
```

### Syntax

```sql
NOT condition
```

---

# 12. NOT Example

```sql
SELECT NOT 1 = 1;
```

First:

```text
1 = 1
 ↓
TRUE
```

Then:

```text
NOT TRUE
 ↓
FALSE
```

Result:

```text
0
```

---

# 13. NOT with False

```sql
SELECT NOT 1 = 2;
```

First:

```text
1 = 2
 ↓
FALSE
```

Then:

```text
NOT FALSE
 ↓
TRUE
```

Result:

```text
1
```

---

# 14. NOT Mental Model

Think of `NOT` as an inverter:

```text
TRUE
 ↓ NOT
FALSE
```

and:

```text
FALSE
 ↓ NOT
TRUE
```

---

# 15. AND vs OR vs NOT

|Operator|Meaning|TRUE when|
|---|---|---|
|`AND`|Both conditions|Both are TRUE|
|`OR`|Either condition|At least one is TRUE|
|`NOT`|Reverse condition|Original condition is FALSE|

### Memory Trick

```text
AND → ALL
OR  → ONE
NOT → REVERSE
```

---

# 16. Symbol Operators

MySQL also supports symbolic forms.

### AND

```text
AND
&&
```

These can represent logical AND.

Example:

```sql
SELECT 1 = 1 && 'test' = 'abc';
```

Result:

```text
0
```

because:

```text
TRUE AND FALSE
      ↓
    FALSE
```

---

# 17. OR Symbol

The symbolic form of `OR` is:

```text
||
```

Example:

```sql
SELECT 1 = 1 || 'test' = 'abc';
```

Conceptually:

```text
TRUE OR FALSE
     ↓
   TRUE
```

Result:

```text
1
```

### Important Modern MySQL Note

For portability and clarity, prefer writing:

```sql
AND
OR
NOT
```

rather than relying on symbolic forms.

In particular, MySQL's `||` behavior can depend on SQL mode; with `PIPES_AS_CONCAT`, it has a string-concatenation meaning rather than logical OR.

For security training, understanding the symbolic forms is useful, but using the explicit keywords is generally clearer.

---

# 18. NOT and `!`

The symbolic form of logical NOT is:

```text
!
```

For example:

```sql
SELECT NOT 1 = 1;
```

and:

```sql
SELECT !(1 = 1);
```

represent the same basic logical idea.

---

# 19. `!=` Operator

The `!=` operator means:

> **Not equal**

Example:

```sql
SELECT 1 != 1;
```

Since:

```text
1 = 1
```

is true, the condition:

```text
1 != 1
```

is false.

Therefore:

```text
0
```

is returned.

---

# 20. `<>` — Another Not-Equal Operator

SQL also commonly supports:

```sql
<>
```

as a not-equal comparison.

For example:

```sql
SELECT 1 <> 2;
```

returns true.

Conceptually:

```text
!= → Not equal
<> → Not equal
```

---

# 21. Operators in Queries

Logical operators become particularly useful inside `WHERE`.

For example:

```sql
SELECT *
FROM logins
WHERE username != 'john';
```

This returns records where:

```text
username is NOT john
```

---

# 22. Example — `!=`

Given:

```text
+----+---------------+
| id | username      |
+----+---------------+
| 1  | admin         |
| 2  | administrator |
| 3  | john          |
| 4  | tom           |
+----+---------------+
```

Query:

```sql
SELECT *
FROM logins
WHERE username != 'john';
```

Result:

```text
admin
administrator
tom
```

The `john` record is excluded.

---

# 23. Combining AND

We can combine multiple conditions.

Example:

```sql
SELECT *
FROM logins
WHERE username != 'john'
AND id > 1;
```

This requires:

```text
username != john
        AND
id > 1
```

Both conditions must be satisfied.

---

# 24. Evaluating the AND Example

Consider:

```text
id = 1, username = admin
```

Check:

```text
username != john → TRUE
id > 1            → FALSE
```

Therefore:

```text
TRUE AND FALSE
      ↓
    FALSE
```

Record excluded.

---

Consider:

```text
id = 2, username = administrator
```

Check:

```text
username != john → TRUE
id > 1            → TRUE
```

Therefore:

```text
TRUE AND TRUE
     ↓
   TRUE
```

Record included.

---

# 25. Result of the Combined Query

```sql
SELECT *
FROM logins
WHERE username != 'john'
AND id > 1;
```

Returns:

```text
+----+---------------+
| id | username      |
+----+---------------+
| 2  | administrator |
| 4  | tom           |
+----+---------------+
```

---

# 26. Multiple Conditions

We aren't limited to two conditions.

For example:

```sql
SELECT *
FROM logins
WHERE id > 1
AND username != 'john'
AND username != 'tom';
```

This means all three conditions must be true.

Conceptually:

```text
id > 1
  AND
username != john
  AND
username != tom
```

---

# 27. Operator Precedence

SQL can contain multiple operators in a single expression.

For example:

```sql
SELECT *
FROM logins
WHERE username != 'tom'
AND id > 3 - 2;
```

There are several operations here:

```text
!=
AND
>
-
```

The database needs to determine **which operation is evaluated first**.

This is controlled by **operator precedence**.

---

# 28. Why Operator Precedence Matters

Consider ordinary mathematics:

```text
3 + 2 * 4
```

Multiplication is performed before addition:

```text
2 * 4 = 8
3 + 8 = 11
```

It isn't:

```text
3 + 2 = 5
5 * 4 = 20
```

SQL also has precedence rules.

---

# 29. Simplified Operator Precedence

For the operators covered here, a useful simplified order is:

```text
HIGHER PRECEDENCE
        │
        ▼
Multiplication (*)
Division (/)
Modulus (%)
        ↓
Addition (+)
Subtraction (-)
        ↓
Comparison (=, >, <, <=, >=, !=, LIKE)
        ↓
NOT
        ↓
AND
        ↓
OR
        │
        ▼
LOWER PRECEDENCE
```

Operations higher in the list are evaluated before lower-precedence operations.

---

# 30. Operator Precedence Example

Consider:

```sql
SELECT *
FROM logins
WHERE username != 'tom'
AND id > 3 - 2;
```

First:

```text
3 - 2
```

is evaluated.

Result:

```text
1
```

So the query becomes conceptually:

```sql
SELECT *
FROM logins
WHERE username != 'tom'
AND id > 1;
```

---

# 31. Next Evaluation

Now we have:

```text
username != 'tom'
AND
id > 1
```

The comparison expressions are evaluated:

```text
username != 'tom'
```

and:

```text
id > 1
```

Then `AND` combines the boolean results.

Therefore, a row must satisfy:

```text
username ≠ tom
AND
id > 1
```

---

# 32. Result

The query:

```sql
SELECT *
FROM logins
WHERE username != 'tom'
AND id > 3 - 2;
```

is effectively equivalent to:

```sql
SELECT *
FROM logins
WHERE username != 'tom'
AND id > 1;
```

The resulting records are those where:

```text
id > 1
```

and:

```text
username != tom
```

For the example dataset:

```text
administrator
john
```

are returned.

---

# 33. Parentheses

When a query contains complicated conditions, parentheses can make the intended logic explicit.

For example:

```sql
WHERE (id > 1 AND username != 'john')
```

Parentheses help make grouping obvious.

This becomes particularly important when combining `AND` and `OR`.

---

# 34. AND + OR Example

Consider:

```sql
WHERE username = 'admin'
OR username = 'john'
AND id > 1;
```

Because `AND` has higher precedence than `OR`, the expression is conceptually interpreted as:

```text
username = 'admin'
OR
(
    username = 'john'
    AND
    id > 1
)
```

If you instead intend:

```text
(
    username = 'admin'
    OR
    username = 'john'
)
AND
id > 1
```

write the parentheses explicitly.

### Best Practice

When combining `AND` and `OR`, use parentheses when they improve clarity.

---

# 35. Truth Tables — Master Revision

## AND

```text
TRUE  AND TRUE  = TRUE
TRUE  AND FALSE = FALSE
FALSE AND TRUE  = FALSE
FALSE AND FALSE = FALSE
```

---

## OR

```text
TRUE  OR TRUE  = TRUE
TRUE  OR FALSE = TRUE
FALSE OR TRUE  = TRUE
FALSE OR FALSE = FALSE
```

---

## NOT

```text
NOT TRUE  = FALSE
NOT FALSE = TRUE
```

---

# 36. Visual Memory Trick

```text
              AND
               │
       ┌───────┴───────┐
       ▼               ▼
    TRUE             TRUE
       │               │
       └──────┬────────┘
              ▼
            TRUE
```

If either side becomes false:

```text
TRUE AND FALSE
      ↓
    FALSE
```

---

For OR:

```text
             OR
              │
       ┌──────┴──────┐
       ▼             ▼
    TRUE           FALSE
       │             │
       └─────┬───────┘
             ▼
           TRUE
```

---

For NOT:

```text
TRUE
 │
NOT
 │
 ▼
FALSE
```

---

# 37. SQL Operators — Categories

SQL has many types of operators.

### Arithmetic

```text
+
-
*
/
%
```

### Comparison

```text
=
!=
<>
>
<
>=
<=
LIKE
```

### Logical

```text
AND
OR
NOT
```

### Symbolic Logical Operators

```text
&&
||
!
```

The current section focuses primarily on logical operators and how they interact with comparisons and arithmetic.

---

# 38. SQL Injection Connection

This section is **extremely important for SQL Injection**.

Why?

Because SQL Injection often involves understanding how a database evaluates boolean conditions.

A normal query might contain:

```sql
WHERE username = 'admin'
AND password = 'something'
```

Conceptually:

```text
username correct?
       AND
password correct?
       ↓
    Access
```

The application's security logic can depend heavily on these conditions.

Understanding:

```text
AND
OR
NOT
=
!=
>
<
```

is therefore essential before studying SQL Injection techniques.

---

# 39. Boolean Logic and SQLi

At a high level, SQL Injection can involve attempting to influence a query's boolean expression.

For example, an application might construct:

```sql
SELECT *
FROM users
WHERE username = '<INPUT>'
AND password = '<INPUT>';
```

The database evaluates:

```text
Condition 1
    AND
Condition 2
```

Understanding how SQL evaluates these conditions allows a security learner to recognize when unsafe input handling could change the intended logic.

### Important

The vulnerability is **not** simply the presence of `AND` or `OR`.

The vulnerability arises when **untrusted input is incorporated into SQL syntax in an unsafe way**.

---

# 40. Why NOT Is Useful

`NOT` allows us to invert a condition.

For example:

```sql
WHERE NOT username = 'john'
```

is logically equivalent to:

```sql
WHERE username != 'john'
```

Conceptually:

```text
username = john
       ↓ NOT
username ≠ john
```

---

# 41. Important Precedence Reminder

For the operators discussed in this section, remember:

```text
Arithmetic
   ↓
Comparison
   ↓
NOT
   ↓
AND
   ↓
OR
```

Therefore:

```sql
A OR B AND C
```

is generally interpreted as:

```text
A OR (B AND C)
```

not:

```text
(A OR B) AND C
```

When in doubt:

> **Use parentheses.**

---

# 42. Common Mistakes

### Mistake 1 — Thinking AND means either condition

Wrong:

```text
A AND B
```

does **not** mean either A or B.

It means:

```text
A must be TRUE
AND
B must be TRUE
```

---

### Mistake 2 — Thinking OR requires both

Wrong.

`OR` needs:

```text
at least one TRUE condition
```

---

### Mistake 3 — Forgetting NOT reverses the result

```text
NOT TRUE → FALSE
NOT FALSE → TRUE
```

---

### Mistake 4 — Ignoring precedence

For example:

```sql
A OR B AND C
```

doesn't normally mean:

```text
(A OR B) AND C
```

because `AND` has higher precedence than `OR`.

---

### Mistake 5 — Confusing `!=` with `=`

```text
=  → Equal
!= → Not equal
```

---

# 43. Quick Revision Cheat Sheet

## AND

```sql
condition1 AND condition2
```

**TRUE only when both are TRUE.**

---

## OR

```sql
condition1 OR condition2
```

**TRUE when at least one is TRUE.**

---

## NOT

```sql
NOT condition
```

**Reverses the boolean result.**

---

## NOT EQUAL

```sql
username != 'john'
```

or:

```sql
username <> 'john'
```

---

## Symbol Forms

```text
AND → &&
OR  → ||
NOT → !
```

Use the keyword forms (`AND`, `OR`, `NOT`) for clarity and portability.

---

# 44. Example Queries

### AND

```sql
SELECT *
FROM logins
WHERE id > 1
AND username != 'john';
```

---

### OR

```sql
SELECT *
FROM logins
WHERE username = 'admin'
OR username = 'john';
```

---

### NOT

```sql
SELECT *
FROM logins
WHERE NOT username = 'john';
```

---

### Combined

```sql
SELECT *
FROM logins
WHERE id > 1
AND username != 'john'
AND username != 'tom';
```

---

### Arithmetic + Comparison + Logical

```sql
SELECT *
FROM logins
WHERE username != 'tom'
AND id > 3 - 2;
```

Simplifies conceptually to:

```sql
SELECT *
FROM logins
WHERE username != 'tom'
AND id > 1;
```

---

# 45. Master Mental Model

When reading a SQL condition, break it down:

```text
SQL CONDITION
     │
     ▼
Arithmetic?
     │
     ▼
Comparison?
     │
     ▼
NOT?
     │
     ▼
AND?
     │
     ▼
OR?
```

For example:

```sql
WHERE username != 'tom'
AND id > 3 - 2
```

Think:

```text
3 - 2
 ↓
1

id > 1
 ↓
TRUE / FALSE

username != 'tom'
 ↓
TRUE / FALSE

TRUE AND TRUE/FALSE
 ↓
Final result
```

---

# 46. Final Takeaway

The most important concepts from this section are:

```text
AND → Both conditions must be TRUE
OR  → At least one condition must be TRUE
NOT → Reverses TRUE/FALSE
```

MySQL commonly represents:

```text
TRUE  → 1
FALSE → 0
```

And remember the simplified precedence:

```text
HIGH
 │
 ├── *, /, %
 ├── +, -
 ├── Comparisons (=, !=, >, <, LIKE...)
 ├── NOT
 ├── AND
 └── OR
 │
LOW
```

### ⭐ SQLi Foundation

The most important connection to the upcoming SQL Injection material is:

```text
                    SQL QUERY
                       │
                       ▼
                  CONDITIONS
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
             AND      OR       NOT
              │        │        │
              └────────┼────────┘
                       ▼
                 TRUE / FALSE
                       │
                       ▼
                 Query Result
```

Once you understand **boolean conditions + operator precedence**, you'll have a much stronger foundation for understanding how SQL queries behave and how improperly handled user input can affect their logic.