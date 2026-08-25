![Image](https://images.openai.com/static-rsc-4/rsrzozWfolJwt9PoRQ00bZncXE4meZH8RgwyEzjfocb9inRTn1rvbS5hFjiqFk8OBhH3bX6F6WougE1zj19PKrnkej8XLaDVI5mkrwgYi1_itn1--DpCqEM6zQEJsA3dpiBS0fY-VtMaHiweWztgs_IPU5dDIynm7YVO5D3rn1S41pwPTHtRwM2s6z6lGga3?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/gDoEqM_LBSPwoyZ4o0F3QTfJE49RtUiRIcqr69CuOvqlz4Bi8i4Cn1VHwpKO9KrKh3yHiFS8lZwo7dhJ4djBqOAQRX92JsCjDK576wQQ4UosVetLGwV4vbqf6iyZr5JLAaSJBWTd1fXMdIs4HSbQP-FN4JvmS5EC6aR-3fk6N6VrBf2dTmPoh-tf5qkSjBAX?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qaBF_GCgOrOEVj174tA9ihEKQgonruq125EiyjA0qe_yZKv_Tyqx9QIyjIJiOsRFw2vTP4IwyApWoWaNwiC24iQkFbj48_S-zzipaHseDDqrMmVo2jwr2N1FdrwrCM3EkAhB6MCLFDlBjZXYrBU8XULJpg6yWI6_7k7A1VQnvWid0vWEq_D9_n4WxgHa6sbg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/OcNOWHVcNzeD2J2ji5WY0lZRrqPTDu0DLDVzSxYd3ZxKKUPy50k_rZG4EIpzyaWhR7KImaDJyzdGVZAlfZmlE6gJVI4NVAlEAFvfnAUfI7tRaHIkTT55g-fKq1vk4GgqwkI87LRW2cR2QNr7VQUcnpO2-Gze010_oz8hXdAuKzYybxF3q-aqRMwTey3fNoYc?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/f1iOgZjirsSvVW3OiJmZ9YblR3x67AJ9hmmX_53r6nrQTjojio2OA7rE4AGWehFkrMziGmiKZ0W7evFVSXx61A2smSf5GEMSZHrhn7ddJSd3oaABhHUDkbHjUobpkWvQ-cgZAk38x-L7wI86hA0M1xUXmXy0ubq6M3xV0uGC-BpReX8XeuAl4-izAnjXY_6O?purpose=fullsize)

---

# 1. Introduction

In the previous section, we learned how SQL Injection can modify query logic using operators such as:

```text
AND
OR
NOT
```

Now we introduce another important SQL feature:

```text
COMMENTS
```

Comments allow SQL developers to:

- Document queries
    
- Explain what a query does
    
- Ignore portions of a query
    

In SQL Injection analysis, comments are particularly important because they can affect how the **remaining portion of an application-generated query** is parsed.

---

# 2. MySQL Comment Types

MySQL supports several comment forms.

The important ones from this section are:

```text
-- 
#
/**/
```

There are two main **line-comment** styles discussed here:

```text
-- 
#
```

and an **inline/block comment**:

```text
/**/
```

---

# 3. `--` Comments

The MySQL double-dash comment syntax is:

```text
-- 
```

Notice the important whitespace after the two hyphens.

Example:

```sql
SELECT username FROM logins; -- Select usernames
```

Everything after the comment marker on that line is treated as a comment.

Conceptually:

```text
SELECT username FROM logins;
                          │
                          └── comment starts here
                              ↓
                         ignored text
```

---

# 4. Important: `--` Requires Whitespace

This is one of the **most important details to memorize**.

In MySQL, two dashes by themselves:

```text
--
```

are not sufficient for the standard `--` comment syntax.

The syntax requires whitespace after the second dash:

```text
-- 
```

So think:

```text
-- + whitespace
```

The whitespace can be represented in different ways depending on how the SQL is being transmitted.

---

# 5. URL Encoding `--`

When SQL input is sent through a URL, whitespace can be encoded.

For example, a space may be represented as:

```text
+
```

Therefore, a representation such as:

```text
--+
```

can be used when transmitting a `--` comment sequence through a URL.

The important concept is:

```text
SQL layer:
-- [space]

HTTP/URL representation:
--+
```

The exact encoding depends on how the request is constructed.

---

# 6. `#` Comments

MySQL also supports:

```text
#
```

as a single-line comment marker.

Example:

```sql
SELECT *
FROM logins
WHERE username = 'admin'; # comment
```

Everything after the `#` on that line is treated as a comment by MySQL.

---

# 7. Why `#` Is Important in Web Requests

There is an important distinction between:

```text
SQL
```

and:

```text
URL
```

In a browser URL, `#` normally introduces a **fragment identifier**.

For example:

```text
https://example.com/page#section
```

The browser treats:

```text
#section
```

as a URL fragment.

The fragment normally isn't sent to the web server as part of the HTTP request.

Therefore, when transmitting a literal `#` through a URL, it can need URL encoding:

```text
#
```

becomes:

```text
%23
```

---

# 8. URL Encoding vs SQL Comments

Don't confuse these two layers.

```text
Browser / HTTP
      │
      ▼
URL encoding
      │
      ▼
Web application
      │
      ▼
SQL query
      │
      ▼
MySQL parser
```

For example:

```text
%23
```

is a URL representation.

After decoding, the application receives:

```text
#
```

which can then have meaning to the MySQL parser.

---

# 9. Block / Inline Comments

MySQL also supports:

```text
/*
   comment
*/
```

For example:

```sql
SELECT username /* comment */
FROM logins;
```

The comment exists within the query rather than necessarily extending to the end of the line.

Conceptually:

```text
SQL
 │
 ├── code
 │
 ├── /* comment */
 │
 └── code
```

The HTB material notes that this style isn't typically used in basic SQL Injection examples, but you should recognize it.

---

# 10. Comment Types Cheat Sheet

|Syntax|Type|Important detail|
|---|---|---|
|`--`|Line comment|Requires whitespace after `--`|
|`#`|Line comment|MySQL-specific style|
|`/* ... */`|Block comment|Can occur within a query|

### Memorize:

```text
--  → line comment
#   → line comment
/**/ → block comment
```

---

# 11. Why Comments Matter in SQL Injection

Consider an application that creates:

```sql
SELECT *
FROM logins
WHERE username='<INPUT>'
AND password='<PASSWORD>';
```

The input is inserted into the middle:

```text
SQL before input
        │
        ▼
     INPUT
        │
        ▼
SQL after input
```

Conceptually:

```text
[username='<INPUT>'] [AND password='...']
```

If the input changes the SQL structure, the remaining SQL can potentially interfere with the intended modified query.

A comment can cause the remainder of that line to be treated as a comment.

---

# 12. Authentication Example

The normal query might be:

```sql
SELECT *
FROM logins
WHERE username='admin'
AND password='something';
```

The application intends:

```text
username correct
      AND
password correct
```

---

# 13. Comment-Based Query Modification

In the HTB lab, the username input is conceptually:

```text
admin'-- 
```

The resulting query is represented as:

```sql
SELECT *
FROM logins
WHERE username='admin'-- ' AND password='something';
```

The important structure is:

```text
username='admin'
        │
        └── comment begins
              ↓
        remainder ignored
```

Therefore, the password check is no longer part of the executable SQL expression.

---

# 14. Final Effective Query

Conceptually, the database evaluates only:

```sql
SELECT *
FROM logins
WHERE username='admin'
```

The application may then receive the admin record.

If the application interprets:

```text
record returned
```

as:

```text
authentication successful
```

the login logic can be bypassed.

---

# 15. The Important Lesson

The key idea isn't:

> "Comments magically bypass authentication."

The actual chain is:

```text
Unsafe query construction
        ↓
Input changes SQL structure
        ↓
Comment changes remaining SQL
        ↓
Password condition no longer participates
        ↓
Query checks only the username
        ↓
Application accepts returned record
```

This distinction is extremely important.

---

# 16. Query Before and After

### Original

```sql
SELECT *
FROM logins
WHERE username='admin'
AND password='something';
```

### Modified structure

```sql
SELECT *
FROM logins
WHERE username='admin'
-- remainder
```

### Effective logic

```text
username = admin
```

instead of:

```text
username = admin
AND
password = something
```

---

# 17. Why This Works in the Lab

The application appears to use this logic:

```text
Query returns a record
       ↓
Record exists?
       ↓
YES
       ↓
Login successful
```

Therefore, if the SQL query can be changed so that it returns an existing user's record without checking the intended password condition, the application's authentication logic can be defeated.

Again, this is an **application design/input-handling vulnerability**, not a MySQL malfunction.

---

# 18. The More Advanced Example

Now the query becomes more complicated.

The application uses parentheses:

```sql
SELECT *
FROM logins
WHERE (username='admin' AND id > 1)
AND password='HASH';
```

This changes the problem.

---

# 19. Understanding the Parentheses

The important section is:

```sql
(username='admin' AND id > 1)
```

The parentheses force this expression to be evaluated together.

Think:

```text
          username='admin'
                  AND
               id > 1
                  │
                  ▼
             Parentheses
                  │
                  ▼
             TRUE/FALSE
```

Then:

```text
(username='admin' AND id > 1)
                AND
          password='HASH'
```

---

# 20. Why Admin Cannot Log In

Suppose:

```text
admin ID = 1
```

The condition is:

```sql
id > 1
```

Therefore:

```text
1 > 1
```

is:

```text
FALSE
```

So:

```text
username='admin'
      AND
id > 1
```

becomes:

```text
TRUE AND FALSE
      ↓
    FALSE
```

Therefore the login fails even if the correct password is supplied.

---

# 21. Another User

Suppose `tom` has:

```text
id = 4
```

Then:

```text
id > 1
```

becomes:

```text
4 > 1
```

which is:

```text
TRUE
```

Therefore:

```text
username='tom'
      AND
id > 1
```

becomes:

```text
TRUE AND TRUE
      ↓
    TRUE
```

If the password is also correct:

```text
TRUE AND TRUE
      ↓
    TRUE
```

The login succeeds.

---

# 22. Password Hashing

The example also demonstrates that the application hashes the password before placing it into the SQL query.

For example, instead of:

```text
password='p@ssw0rd'
```

the application might use:

```text
password='0f359740bd1cda994f8b55330c86d845'
```

The important lesson is:

```text
User Password
      ↓
Hashing
      ↓
Hash value
      ↓
SQL query
```

---

# 23. Why This Changes the Injection Context

If the password input is transformed before reaching SQL:

```text
User input
    ↓
Hash function
    ↓
SQL query
```

then the original SQL Injection context is no longer directly receiving the raw password input.

This illustrates an important security concept:

> **Input processing can change the injection context.**

However, hashing passwords is **not a substitute for parameterized SQL queries**.

---

# 24. Why `admin'--` Alone Causes an Error Here

The query is:

```sql
SELECT *
FROM logins
WHERE (username='admin' AND id > 1)
AND password='HASH';
```

Suppose the username input changes the query to something conceptually like:

```sql
SELECT *
FROM logins
WHERE (username='admin'--' AND id > 1)
AND password='HASH';
```

The comment causes the remainder of the line to be ignored.

But now there is an important problem:

```text
(
```

was opened before:

```text
username='admin'
```

and the closing:

```text
)
```

appears **after the comment**.

Therefore the parser doesn't see the closing parenthesis.

---

# 25. Parenthesis Balance

Original:

```text
(
username='admin'
AND id > 1
)
```

Balanced:

```text
(  ...  )
```

After commenting:

```text
(
username='admin'
-- remainder
```

The `)` has effectively disappeared from the executable query.

So the parser sees:

```text
(
username='admin'
```

with no matching closing parenthesis.

That produces a syntax error.

---

# 26. Critical Lesson — Comments Don't Fix Everything

This is a **very important SQLi lesson**:

> Adding a comment doesn't automatically make an injection syntactically valid.

You must consider:

- Quotes
    
- Parentheses
    
- Operators
    
- SQL keywords
    
- Remaining query structure
    

The final SQL must still be syntactically valid.

---

# 27. Parentheses Must Balance

Think of parentheses like brackets:

```text
(
   expression
)
```

You need:

```text
Opening (
+
Closing )
```

For example:

```text
(TRUE AND TRUE)
```

is valid.

But:

```text
(TRUE AND TRUE
```

is incomplete.

Similarly:

```text
(TRUE AND TRUE))
```

contains an unmatched closing parenthesis.

---

# 28. Conceptual Solution in the Lab

The HTB material demonstrates adjusting the input so that the parenthesized expression is closed **before the remainder is commented**.

Conceptually:

```text
Original:
(username='admin' AND id > 1) AND password='HASH'
```

The desired effective structure becomes:

```text
(username='admin')
```

with the remaining SQL no longer participating.

The lesson is:

```text
Close required SQL structure
        ↓
Comment unwanted remainder
        ↓
Ensure final query is valid
```

---

# 29. Why the Parenthesis Matters

Compare:

### Incorrect structure

```text
(username='admin'
```

Missing:

```text
)
```

### Correct structure

```text
(username='admin')
```

This illustrates a general SQLi principle:

> **You must account for syntax that the application has already placed around your input.**

---

# 30. Query Reconstruction

This is one of the most useful skills to develop.

When you receive an SQLi lab, write:

```text
ORIGINAL QUERY:
[................................]
```

Then substitute the input:

```text
INPUT:
[................................]
```

Then reconstruct:

```text
FINAL QUERY:
[................................]
```

Then ask:

```text
Are quotes balanced?
Are parentheses balanced?
What gets commented?
What conditions remain?
How does operator precedence work?
```

---

# 31. SQLi Query Analysis Example

Original:

```sql
SELECT *
FROM logins
WHERE (username='<INPUT>' AND id > 1)
AND password='<HASH>';
```

Break it into:

```text
WHERE
    (
       username = INPUT
       AND
       id > 1
    )
    AND
    password = HASH
```

Now you understand exactly where the input sits.

This is much better than blindly trying payloads.

---

# 32. A Powerful Mental Model

Always think in layers:

```text
┌──────────────────────────┐
│ Application-generated SQL│
└────────────┬─────────────┘
             │
             ▼
       Insert user input
             │
             ▼
      Reconstruct query
             │
             ▼
       SQL parser sees:
             │
     ┌───────┼────────┐
     ▼       ▼        ▼
   Quotes Parentheses Comments
     │       │        │
     └───────┼────────┘
             ▼
       Final SQL logic
```

---

# 33. Comments Cheat Sheet

### MySQL `--`

```text
-- [whitespace]
```

Important:

> The whitespace after `--` matters.

---

### MySQL `#`

```text
#
```

Everything following it on that line can be treated as a comment.

---

### Block comment

```text
/*
comment
*/
```

---

### URL encoded `#`

```text
%23
```

---

### URL representation of a space

Often:

```text
+
```

So the `--` sequence may be represented in a URL as:

```text
--+
```

---

# 34. Comments vs Parentheses

These solve different problems.

### Comments

Control:

```text
"What happens to the remaining SQL?"
```

### Parentheses

Control:

```text
"How are expressions grouped?"
```

Therefore:

```text
Comments → Remaining query
Parentheses → Expression grouping
```

---

# 35. Comments vs Quotes

Another useful distinction:

### Quotes

Define string boundaries:

```text
'admin'
```

### Comments

Cause portions of SQL text to be ignored:

```text
-- comment
```

### Parentheses

Group expressions:

```text
(username='admin' AND id > 1)
```

These three pieces of syntax are extremely important when analyzing SQL Injection.

---

# 36. The Complete Advanced Example

Original query:

```sql
SELECT *
FROM logins
WHERE (username='admin' AND id > 1)
AND password='HASH';
```

Logical structure:

```text
              AND
             /   \
            /     \
           /       \
   username/id     password
      group
```

More precisely:

```text
       ┌───────────────────────┐
       │ username='admin'      │
       │        AND            │
       │      id > 1           │
       └──────────┬────────────┘
                  │
                 AND
                  │
             password=HASH
```

The lab demonstrates how altering the input and dealing with the surrounding parenthesis/comment structure can change which parts of the expression remain active.

---

# 37. Why This Section Is Important for HTB

This section teaches you to stop thinking:

> "Which payload should I type?"

and start thinking:

> **"What exact SQL query will the application generate after my input is inserted?"**

That is a much better penetration-testing mindset.

---

# 38. Recommended SQLi Workflow

For an authorized lab:

```text
1. Understand the normal request
        ↓
2. Observe the normal SQL behavior
        ↓
3. Identify the input location
        ↓
4. Test how special characters affect it
        ↓
5. Reconstruct the resulting SQL
        ↓
6. Identify quotes/parentheses
        ↓
7. Identify remaining SQL
        ↓
8. Understand operator precedence
        ↓
9. Determine whether comments affect the remainder
        ↓
10. Verify the final query's logic
```

---

# 39. Common Mistakes

## Mistake 1 — Forgetting whitespace after `--`

Remember:

```text
-- 
```

not merely:

```text
--
```

---

## Mistake 2 — Using `#` directly in a URL

A browser can treat:

```text
#
```

as a URL fragment.

Use URL encoding when necessary:

```text
%23
```

---

## Mistake 3 — Forgetting parentheses

If the original query has:

```sql
WHERE (condition)
```

and your modification causes the closing `)` to fall into a comment, the query may fail.

---

## Mistake 4 — Assuming comments automatically make SQL valid

They don't.

You still need:

```text
Balanced quotes
Balanced parentheses
Valid SQL syntax
```

---

## Mistake 5 — Ignoring the query context

This:

```sql
WHERE username='<INPUT>'
```

is different from:

```sql
WHERE (username='<INPUT>' AND id > 1)
```

Always reconstruct the **complete query**.

---

# 40. ⭐ Most Important Things to Memorize

> **MySQL supports `--` and `#` as single-line comments and `/* ... */` as a block comment.**

> **The `--` comment syntax requires whitespace after the two dashes.**

> **When using SQL through URLs, special characters may need URL encoding.**

> **`#` can be URL-encoded as `%23`.**

> **Comments can cause the remainder of a SQL statement to be ignored by the SQL parser, depending on context.**

> **Comments are useful in SQLi analysis because applications often append SQL syntax after user-controlled input.**

> **Comments do not automatically make an injection syntactically valid.**

> **Parentheses must remain balanced in the final SQL expression.**

> **Parentheses have higher precedence than surrounding operators because expressions inside them are evaluated first.**

> **Password hashing changes the input-processing path, but hashing alone does not prevent SQL Injection.**

> **Prepared/parameterized queries are the proper primary defense against SQL Injection.**

---

# 41. Quick Revision

```text
SQL COMMENTS
│
├── -- [space]  → Line comment
├── #            → MySQL line comment
└── /* ... */    → Block comment
```

### URL encoding:

```text
'  → %27
#  → %23
space → often +
```

### Query structure:

```text
Original SQL
     +
User Input
     ↓
Final SQL
     ↓
Check:
├── Quotes
├── Parentheses
├── Comments
├── Operators
└── Precedence
```

---

# 42. Final Mental Model

The entire section can be remembered as:

```text
                 USER INPUT
                     │
                     ▼
              SQL QUERY TEMPLATE
                     │
                     ▼
               INPUT INSERTED
                     │
                     ▼
              FINAL SQL QUERY
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
      QUOTES      PARENTHESES   COMMENTS
        │            │            │
        │            │            │
        ▼            ▼            ▼
     Strings      Grouping    Ignore remainder
        │            │            │
        └────────────┼────────────┘
                     ▼
                 SQL PARSER
                     │
                     ▼
                TRUE / FALSE
                     │
                     ▼
              APPLICATION LOGIC
```

### The golden rule:

> **Never analyze an SQLi input by itself. Analyze the complete query produced after the application inserts that input.**

That means looking at **what comes before the input, what comes after it, the quotes and parentheses around it, and what SQL the database will ultimately parse**.