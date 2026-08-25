![Image](https://images.openai.com/static-rsc-4/v7zPg6_OmOQLEOHfdqczIZic9QPTXqwUpDEZK6FxcjyNVOtAOy1PYnsBXDDVh8xJjvZEcIiCva22XV5vWStPX6CmqoE2J0zq0gu4UJpUL1MtYg-qLOZg0jiLqT4uySWIb_w2eXh8Ki4QLGUBjq8-hyegLl-kz0cd5dCnYlKbXt13Ghknm5Sg9jlLY6yIwy1b?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ntrFcRjzJjyLs2n7DWdL-M9-nNaKDyDbtDJg3O7L7qWLHGnBd_XIwr-hyr8UDsU6dUWMgy48vKjqfso5QdWuOAciovJ8InYTMyx2j7UoqJTFu8nuQiJFWt7pqP-cmFd4aVq0WUSt2Qc7gvtDYV4Kv5YfYkrXKg5l8B2FmHyZU3KY5-jTAfOOfTXuoKxlvCLC?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cyBwNw5xvUiwl8NrHDdKP_exAhPSmljI-90OocUZvEeeW3U11CX66h_8fkvTjDeIDffjRh2vI_fORRReTaOGd6EsNcQ7K3O6jT2zM8ND5_QBmiClNeE5LeeQIBMdPnpQ5p92oifaOa9GoEomJJNhLSyA3EAxqvk0effiTglpvQ9OBJ46o5tRrZvzZa2gfozl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wvvsVTXGxEHjY_j4KmbtNj2uJuuSHxMhwDXO0BaMIppRKKoYxBZzc28sfK_b8tCpS8fS2UNOvxDfsyfUj16LRd4obdFsEvxygPxKXWPQBGmia_tRswJthxjU4rmdBazdVeiZq72e47oBUl6Iume-7uZTWrVgMA9eW5OqdMkExORrhzYOrznFx2eEF2S0vls2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/golXfvWc8SA9hrDKvalKEvebtNq3_ZsoccaB2IaNDlNGsxg0M5xYPgT08VnaOt5QVngPuW2vECH4wQToAecOfmVcIrZnMeUFMYEPqEW8IUVc9OrG4OIxwykYV1k1Qqh-S_LBxwrnisZuLfyhIgao18uXdVVi8K4VC0QCsaL31cct3fkQm2aHimkdrLaQhOJM?purpose=fullsize)

> **Lab context:** The examples below are best understood as techniques for an authorized HTB/lab environment. Don't apply them to systems you don't have permission to test.

---

# 1. What Does "Subverting Query Logic" Mean?

**Subverting query logic** means changing the behavior of an existing SQL query by influencing its conditions.

The goal in this section is not yet to execute a completely separate SQL query.

Instead, we're learning to:

```text
Original SQL Query
       ↓
Understand its logic
       ↓
Influence its conditions
       ↓
Change TRUE/FALSE outcome
       ↓
Change application behavior
```

The example used here is **authentication bypass**.

---

# 2. Authentication Query

Imagine an administrator login page:

```text
┌──────────────────────────────┐
│       ADMIN LOGIN            │
│                              │
│ Username: [____________]     │
│ Password: [____________]     │
│                              │
│          [ LOGIN ]           │
└──────────────────────────────┘
```

The application might construct:

```sql
SELECT *
FROM logins
WHERE username='admin'
AND password='p@ssw0rd';
```

The important part is:

```sql
WHERE username='admin'
AND password='p@ssw0rd'
```

---

# 3. Understanding the Authentication Logic

The query essentially asks:

```text
Is username correct?
       AND
Is password correct?
```

Therefore:

```text
Username TRUE
      AND
Password TRUE
      ↓
Login succeeds
```

But:

```text
Username TRUE
      AND
Password FALSE
      ↓
Login fails
```

And:

```text
Username FALSE
      AND
Password TRUE
      ↓
Login fails
```

And:

```text
Username FALSE
      AND
Password FALSE
      ↓
Login fails
```

This follows the `AND` truth table you learned earlier.

---

# 4. Authentication as Boolean Logic

Think of the query as:

```text
             LOGIN
               │
        ┌──────┴──────┐
        ▼             ▼
 Username correct?  Password correct?
        │             │
        └──────┬──────┘
               │
              AND
               │
               ▼
          TRUE / FALSE
```

The application might then do something like:

```text
IF query returned a matching record
       ↓
   Login successful
ELSE
   Login failed
```

---

# 5. Correct Credentials

If we provide:

```text
Username: admin
Password: p@ssw0rd
```

the query becomes:

```sql
SELECT *
FROM logins
WHERE username='admin'
AND password='p@ssw0rd';
```

Assuming those credentials exist:

```text
username='admin'
       ↓
      TRUE

password='p@ssw0rd'
       ↓
      TRUE

TRUE AND TRUE
       ↓
      TRUE
```

Therefore:

```text
Login successful
```

---

# 6. Incorrect Credentials

Suppose we enter:

```text
Username: admin
Password: admin
```

The query becomes:

```sql
SELECT *
FROM logins
WHERE username='admin'
AND password='admin';
```

Assuming `admin` isn't the correct password:

```text
username='admin'
       ↓
      TRUE

password='admin'
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
Login failed
```

---

# 7. Where SQL Injection Enters

The application is potentially vulnerable if it constructs the SQL query directly from user input.

Conceptually:

```text
Username ──┐
           │
Password ──┼──► Application ──► SQL Query
           │
           └──────────────────────┘
```

For example:

```text
username = <USER INPUT>
password = <USER INPUT>
```

The application then inserts those values into the SQL query.

If the input can alter the query's logical structure, the attacker may be able to change the application's authentication decision.

---

# 8. SQLi Discovery

Before attempting to manipulate the authentication logic, the first step in a lab is determining whether the input appears to influence SQL syntax.

The HTB material lists characters such as:

|Character|URL-encoded|
|---|---|
|`'`|`%27`|
|`"`|`%22`|
|`#`|`%23`|
|`;`|`%3B`|
|`)`|`%29`|

These characters can have special meaning in SQL.

### Important

URL encoding is relevant when the payload is transmitted as part of a URL/HTTP request.

For example:

```text
'
```

may become:

```text
%27
```

in a URL-encoded request.

---

# 9. Why Test a Single Quote?

A single quote is particularly interesting when the application places user input inside a SQL string.

Suppose the application normally creates:

```sql
SELECT *
FROM logins
WHERE username='admin'
AND password='something';
```

The username value is surrounded by:

```text
'
```

If input changes the number/placement of quotes, the resulting SQL may become syntactically invalid.

That can reveal that the input is interacting with SQL syntax.

---

# 10. Quote Error

The HTB example demonstrates entering a single quote.

The resulting query can look conceptually like:

```sql
SELECT *
FROM logins
WHERE username='''
AND password='something';
```

Notice the unusual number of consecutive quotes.

The database may return a syntax error.

This is useful information during a **controlled security assessment**, because it can indicate that the application is constructing SQL in an unsafe way.

---

# 11. Why Does the Error Occur?

Remember SQL string syntax:

```sql
'admin'
```

There are:

```text
' → opening quote
admin → string
' → closing quote
```

If an additional quote is inserted:

```text
'''
```

the parser may not be able to construct the intended string.

Therefore:

```text
Unexpected quote
       ↓
Malformed SQL
       ↓
Syntax error
```

---

# 12. SQLi Discovery Mental Model

A useful workflow is:

```text
Normal Input
     ↓
Observe Normal Response
     ↓
Controlled Special Character
     ↓
Observe Response
     ↓
Does behavior change?
     │
   ┌─┴─┐
   ▼   ▼
  No   Yes
       │
       ▼
  Investigate SQL
  construction/context
```

A changed response or database error can be an indication worth investigating, but **one error alone does not prove every SQLi technique will work**.

---

# 13. Two General Problems After Injection

Once input affects the query, two major issues need to be considered:

### Problem 1 — Boolean logic

How can the query's condition be changed?

### Problem 2 — Syntax

How can the final SQL remain valid?

The material addresses both through:

```text
OR
```

and:

```text
SQL comments / quote balancing
```

---

# 14. OR Injection — Core Idea

The `OR` operator is important because:

```text
TRUE OR anything
       ↓
     TRUE
```

Truth table:

|A|B|A OR B|
|---|---|---|
|TRUE|TRUE|TRUE|
|TRUE|FALSE|TRUE|
|FALSE|TRUE|TRUE|
|FALSE|FALSE|FALSE|

Therefore, if you can introduce a condition that evaluates to `TRUE`, it can potentially change the outcome of a vulnerable query.

---

# 15. Always-True Conditions

A classic example is:

```sql
'1'='1'
```

because:

```text
1 = 1
```

is true.

Conceptually:

```text
'1'='1'
     ↓
   TRUE
```

Another way to think about it:

```sql
1 = 1
```

is an always-true comparison.

---

# 16. Why Operator Precedence Matters

This is where your previous section on operator precedence becomes **extremely important**.

The query may contain:

```text
AND
```

and your modified condition may contain:

```text
OR
```

In MySQL, `AND` has higher precedence than `OR`.

Therefore:

```text
A OR B AND C
```

is interpreted conceptually as:

```text
A OR (B AND C)
```

not:

```text
(A OR B) AND C
```

This difference can completely change the result.

---

# 17. HTB's OR Injection Example

The supplied material demonstrates an input conceptually resembling:

```text
admin' OR '1'='1
```

which can result in a query of the form:

```sql
SELECT *
FROM logins
WHERE username='admin'
OR '1'='1'
AND password='something';
```

The important learning objective is understanding how the inserted `OR` interacts with the existing `AND`.

---

# 18. Break the Query Apart

Look at:

```sql
username='admin'
OR
'1'='1'
AND
password='something'
```

Because:

```text
AND > OR
```

in precedence, evaluate the `AND` portion first:

```text
'1'='1'
      AND
password='something'
```

Suppose:

```text
'1'='1'
      ↓
TRUE
```

and:

```text
password='something'
      ↓
FALSE
```

Then:

```text
TRUE AND FALSE
      ↓
FALSE
```

Now the query becomes conceptually:

```text
username='admin'
OR
FALSE
```

Therefore:

```text
username='admin'
```

determines the final result.

---

# 19. Critical Lesson From This Example

This is one of the **most important details in this section**:

> An apparently "always true" condition does not necessarily make the entire query true.

Why?

Because **operator precedence matters**.

The expression:

```text
A OR TRUE AND B
```

is evaluated as:

```text
A OR (TRUE AND B)
```

not:

```text
(A OR TRUE) AND B
```

Therefore, you must always analyze the **complete Boolean expression**.

---

# 20. When the Username Exists

If:

```text
username='admin'
```

is true, then:

```text
TRUE OR FALSE
     ↓
   TRUE
```

The database can return the matching admin record.

The application then sees a successful query result and may treat the login as successful.

Conceptually:

```text
Admin exists
     ↓
username='admin' = TRUE
     ↓
TRUE OR FALSE
     ↓
TRUE
     ↓
Matching record
     ↓
Application accepts login
```

---

# 21. When the Username Does NOT Exist

Now suppose the username is:

```text
notAdmin
```

The query becomes conceptually:

```sql
SELECT *
FROM logins
WHERE username='notAdmin'
OR '1'='1'
AND password='something';
```

Evaluate:

```text
username='notAdmin'
        ↓
      FALSE
```

and:

```text
'1'='1'
AND
password='something'
```

becomes:

```text
TRUE AND FALSE
      ↓
    FALSE
```

Therefore:

```text
FALSE OR FALSE
      ↓
    FALSE
```

So the query does not return a matching row.

---

# 22. Why the Password Position Matters

The lesson here is that **where the input is injected matters**.

Compare:

```text
username input
```

with:

```text
password input
```

The surrounding SQL syntax is different.

For example, a vulnerable application might construct:

```sql
SELECT *
FROM logins
WHERE username='<USERNAME>'
AND password='<PASSWORD>';
```

An input inserted into `<USERNAME>` modifies one context.

An input inserted into `<PASSWORD>` modifies another.

This is why there is no universal SQLi payload that works in every application.

---

# 23. Password-Side Logic

The HTB example demonstrates changing the password-side condition as well.

The conceptual result is a query containing:

```text
username condition
OR
password condition
OR
additional condition
```

The purpose is to make the **overall `WHERE` expression return rows**, rather than merely relying on a particular known username.

The key concept to learn is:

```text
Change the Boolean expression
       ↓
WHERE returns a row
       ↓
Application interprets row as authentication success
```

---

# 24. Why the Application Is Vulnerable

Notice something important:

The database itself isn't "broken."

MySQL is correctly doing exactly what it was asked to do.

The problem is the **application's query construction**.

```text
Application intended:
"Check the supplied username and password."

Database received:
"A different Boolean expression."

Database:
"Okay, I'll evaluate that expression."
```

Therefore:

> **SQL Injection is primarily an application input-handling/query-construction vulnerability.**

---

# 25. SQL Comments

Another important concept in this section is **SQL comments**.

A comment tells the SQL parser that some portion of the query should be treated as commentary rather than executable SQL.

Conceptually:

```text
Original query
      │
      ▼
Injection point
      │
      ▼
Comment marker
      │
      ▼
Remaining SQL ignored
```

This can be useful when the application automatically appends SQL syntax after the user-controlled input.

---

# 26. Why Comments Matter in SQLi

Suppose the application generates:

```text
SQL before user input
+
USER INPUT
+
SQL after user input
```

The attacker may have to deal with the final portion.

Conceptually:

```text
[SQL before] [INPUT] [SQL after]
```

If the input changes the query structure, the automatically appended portion may cause a syntax error.

Comments can, depending on context and DBMS syntax, cause the remaining portion to be ignored:

```text
[SQL before] [modified INPUT] [COMMENT]
                              ↓
                         [SQL after ignored]
```

This is why comments are a major SQLi concept.

---

# 27. Comment Syntax

Different SQL dialects support different comment syntaxes.

Common examples include:

```text
-- 
#
/*
   comment
*/
```

However, the exact behavior and spacing requirements can depend on the DBMS and context.

For MySQL, `#` is a commonly recognized single-line comment syntax, while `--` has specific whitespace requirements after the two hyphens.

---

# 28. URL Encoding

If SQLi input is sent through an HTTP URL, characters may need URL encoding.

For example:

```text
' → %27
# → %23
```

Why?

Because characters such as `#` have special meaning in URLs.

For example:

```text
https://example.com/page?id=123#section
```

The portion after `#` is normally a URL fragment and isn't sent to the server as part of the HTTP request.

Therefore, when transmitting a `#` as data in a URL, it may need to be encoded as:

```text
%23
```

---

# 29. Important Distinction — URL Encoding vs SQL Syntax

Don't confuse these two layers.

```text
HTTP/URL Layer
       ↓
URL Encoding
       ↓
Application receives input
       ↓
SQL Layer
       ↓
SQL Parsing
```

For example:

```text
%27
```

is URL encoding.

After decoding:

```text
'
```

is the character that has meaning in the SQL context.

---

# 30. Authentication Bypass Flow

The entire lab concept can be represented as:

```text
                  LOGIN FORM
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
      Username                 Password
          │                       │
          └───────────┬───────────┘
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
                 TRUE / FALSE
                      │
                      ▼
              Login success/fail
```

With a vulnerable application:

```text
User Input
    ↓
SQL Query Construction
    ↓
Input alters SQL logic
    ↓
Different Boolean result
    ↓
Different authentication result
```

---

# 31. The Three Important Concepts

This section is really teaching three things:

### ① Find the SQL context

Understand how the application places your input into the query.

### ② Understand Boolean logic

Use your knowledge of:

```text
AND
OR
NOT
```

and operator precedence.

### ③ Keep the resulting SQL valid

Understand:

```text
quotes
comments
query structure
```

These three ideas form the foundation for practical SQL Injection.

---

# 32. Common Mistakes

### Mistake 1 — Assuming any `'` proves SQLi

A quote causing an error is an **indicator worth investigating**, but it doesn't automatically tell you the exact query structure or guarantee that exploitation is possible.

---

### Mistake 2 — Ignoring operator precedence

Remember:

```text
AND
```

has higher precedence than:

```text
OR
```

So:

```text
A OR B AND C
```

means:

```text
A OR (B AND C)
```

---

### Mistake 3 — Assuming an always-true condition always makes the query true

For example:

```text
A AND TRUE
```

is:

```text
A
```

not necessarily `TRUE`.

Similarly:

```text
A OR TRUE
```

is:

```text
TRUE
```

Context matters.

---

### Mistake 4 — Forgetting the surrounding query

An input doesn't exist in isolation.

Always reconstruct:

```text
Original SQL
+
Input
=
Final SQL
```

Then analyze the final expression.

---

# 33. Golden Rule for SQLi Analysis

Whenever you have an input, don't just look at the input itself.

Ask:

```text
What did the application originally write?
              +
What did my input add/change?
              ↓
What is the FINAL SQL query?
              ↓
How does MySQL parse it?
              ↓
What is the Boolean result?
```

This habit will save you a lot of confusion later.

---

# 34. SQLi Analysis Template

For future HTB SQLi exercises, you can use this template:

```text
1. Identify the input location
        ↓
2. Determine the surrounding SQL context
        ↓
3. Test how special characters affect behavior
        ↓
4. Reconstruct the resulting SQL
        ↓
5. Check quote/string boundaries
        ↓
6. Apply SQL operator precedence
        ↓
7. Determine TRUE/FALSE result
        ↓
8. Observe application behavior
```

---

# 35. ⭐ Things You MUST Remember

> **SQL Injection can modify the logic of an existing SQL query without necessarily executing a completely separate query.**

> **Authentication queries commonly use `AND` to require both username and password conditions to be true.**

> **`OR` can change Boolean logic because it evaluates to TRUE when at least one operand is TRUE.**

> **`AND` has higher precedence than `OR` in MySQL.**

> **Therefore, `A OR B AND C` is evaluated conceptually as `A OR (B AND C)`.**

> **An always-true expression does not automatically make every surrounding SQL expression true.**

> **The final SQL query must be syntactically valid.**

> **Quotes are important because they define SQL string boundaries.**

> **SQL comments can, depending on context, prevent the remainder of an application's query from affecting the modified query.**

> **URL encoding and SQL syntax are different layers. `%27` is URL encoding for `'`; `%23` is URL encoding for `#`.**

> **The injection context matters: username, password, search field, numeric parameter, `ORDER BY`, etc. can all produce different SQL contexts.**

> **A database returning a row isn't inherently a security issue; the vulnerability occurs because the application allowed untrusted input to alter the query's intended logic.**

---

# 36. Final Mental Model

```text
                 ORIGINAL QUERY
                       │
                       ▼
       username = X AND password = Y
                       │
                       ▼
                  SQL PARSER
                       │
                  TRUE / FALSE
                       │
                 Login Decision


                 SQL INJECTION
                       │
                       ▼
             User-controlled input
                       │
                       ▼
            Changes query structure
                       │
                       ▼
          Modified Boolean expression
                       │
                       ▼
                SQL PARSER
                       │
                  TRUE / FALSE
                       │
                       ▼
           Modified application behavior
```

### The key idea:

**SQL Injection is about changing what the database is asked to evaluate.**

And this section's central lesson is:

```text
SQL QUERY
   +
USER INPUT
   ↓
QUERY LOGIC
   ↓
AND / OR / NOT
   ↓
TRUE / FALSE
   ↓
APPLICATION BEHAVIOR
```

Once you fully understand **why `AND`/`OR` change the Boolean result and how quotes/comments affect the SQL syntax**, you're ready for the next major SQLi concept: **UNION-based SQL Injection**.