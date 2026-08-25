![Image](https://images.openai.com/static-rsc-4/jmIj956q13mp46mHxJYJsP-83PzV6wpFiA4qQbuyZJyrwiZVv7eWjp1Ouh_OuYtOaBNn0SFtfU2aj9lTnDzhsR21JZFRroyso7gbOOzIwsOSOQLmiazSe3Eocg7XaMj-DGc6-VzoBDo9kKopL6zsi0FIvIfXG_O0cDYPzD2XB4eGIZfJFEQ4h_IcCK1d65jJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/a8Ub1hguiCt4fRUFdqtKbL71krUqHtPsAiaFzGeuxljuLFau8HPttz9Aweq2dfcWy0FzAnUDfmzGJ7_4SZcxmXLsCC9GqTQ7cbc-SkgamoFLYNkurVSsLUS6nFcz80qJb5FIlBoDV5Hn3Pt-iYmdTLk5Nh2cbD_0JzwYpueCPwtbAN0pAMkRPAdGCjWVkrLp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/wvvsVTXGxEHjY_j4KmbtNj2uJuuSHxMhwDXO0BaMIppRKKoYxBZzc28sfK_b8tCpS8fS2UNOvxDfsyfUj16LRd4obdFsEvxygPxKXWPQBGmia_tRswJthxjU4rmdBazdVeiZq72e47oBUl6Iume-7uZTWrVgMA9eW5OqdMkExORrhzYOrznFx2eEF2S0vls2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fC_8kvwTzmuluIJ9BiDyuUzeEsEL8YHJ5_3rYTm_KxCsO5y_P9KpuRGhlElwQY6PBCtoF72SbhAhve5vNwx4b1zo8yW-tC_uqLNukpPImX9nc3ZxUcx__7iCyYCJlWRxSJZ7wjiM5dsV2f82o7Ecg0aoH0NLmW8ugvN4rDCa_XZmi1liHOOy84SoOmtGo3ak?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QfgIMddHhUL7tqjtC9d93ezFUGbnBMsXgeI7DsaMuQkDEmUvvGh0M9UdGtx399owOB6z9RmLgBTVvOsJylK3uNobKsE_bUkUg845V2C-MRQ7396fAhlHUMPcGPAxBBygq8fz_MnwPIJjRg9kunyqhgEU2uK5PnJs7Vl43BaRvxrfFvC6DxeqtUPHkKoA5bpv?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Y6Nv1YOYQETHTB30m-WWJjFlYdi9shVv3D311IIXj67uzj58a_rFBHeFQS6pzn3aTS4mgDU6pbwb5e61c-wSl82spyG0rnOVBj86H2IMNK4QwQpN-pLuiL3ENPMk9CY96uuxMMbOWrmsiIfv-YpSxdShium8MA0t4q92bI6GocTDDIkd5s_8FXt1xVE7mkmX?purpose=fullsize)

---

# 1. Introduction

We now understand:

- Databases
    
- MySQL
    
- SQL
    
- Tables
    
- Rows and columns
    
- `SELECT`
    
- `INSERT`
    
- `UPDATE`
    
- `WHERE`
    
- `LIKE`
    
- `AND`
    
- `OR`
    
- `NOT`
    
- SQL operator precedence
    

Now we can understand **SQL Injection (SQLi)**.

The fundamental idea is:

```text
User Input
    ↓
Web Application
    ↓
SQL Query
    ↓
MySQL Database
    ↓
Query Result
    ↓
Web Application
    ↓
User
```

If the application improperly incorporates user-controlled input into the SQL query, the input may be interpreted as **SQL syntax rather than merely data**.

That is the fundamental SQL Injection vulnerability.

---

# 2. How Web Applications Use SQL

Modern web applications frequently communicate with databases.

For example:

```text
                 WEB APPLICATION
                        │
                        │ SQL Queries
                        ▼
                    MySQL DB
                        │
                        ▼
                    Database
```

A web application can use SQL to:

- Retrieve users
    
- Search products
    
- Authenticate users
    
- Display posts
    
- Store comments
    
- Retrieve account information
    
- Update application data
    

---

# 3. PHP + MySQL Example

The HTB example uses PHP.

A connection can be created with:

```php
$conn = new mysqli("localhost", "root", "password", "users");
```

The parameters represent:

```text
localhost → Database host
root      → Database username
password  → Database password
users     → Database name
```

Then a query can be created:

```php
$query = "select * from logins";
```

And executed:

```php
$result = $conn->query($query);
```

Conceptually:

```text
PHP Application
      │
      │ SQL Query
      ▼
    MySQL
      │
      ▼
  Query Result
      │
      ▼
$result
```

---

# 4. Processing Query Results

The application can then process the returned rows.

Example:

```php
while($row = $result->fetch_assoc() ){
    echo $row["name"]."<br>";
}
```

This repeatedly retrieves rows from the result.

Conceptually:

```text
$result
   │
   ├── Row 1
   ├── Row 2
   ├── Row 3
   └── ...
```

The application can then display or otherwise use those values.

---

# 5. User Input in Web Applications

Web applications frequently use user input to perform searches.

For example, imagine a website with:

```text
Search User: [____________]
             [   Search   ]
```

The application receives the submitted value.

In PHP:

```php
$searchInput = $_POST['findUser'];
```

The application may then construct a query:

```php
$query = "select * from logins where username like '%$searchInput'";
```

This is where the security problem can begin.

---

# 6. Normal User Input

Suppose the user enters:

```text
admin
```

The application inserts that value into:

```sql
select * from logins where username like '%$searchInput'
```

Resulting query:

```sql
select * from logins where username like '%admin'
```

The database interprets `admin` as part of the search pattern.

This is normal behavior.

---

# 7. The Security Problem

The important problem is **how the application constructs the query**.

The example directly places user input inside the SQL string:

```php
$query = "select * from logins where username like '%$searchInput'";
```

Conceptually:

```text
User Input
    ↓
Inserted directly into SQL
    ↓
SQL Query
    ↓
Database
```

If the application doesn't properly separate **data** from **SQL syntax**, specially crafted input can potentially change the meaning of the query.

---

# 8. What Is Injection?

Injection is a general class of vulnerability.

It happens when an application incorrectly interprets user-controlled data as instructions/code.

The core distinction is:

```text
SAFE EXPECTATION:

User Input → DATA
```

versus:

```text
VULNERABLE:

User Input → DATA + CODE/SYNTAX
```

The attacker attempts to cross the boundary between:

```text
Data
```

and:

```text
Application/SQL instructions
```

---

# 9. What Is SQL Injection?

**SQL Injection (SQLi)** occurs when user-controlled input is incorporated into an SQL query in an unsafe manner, allowing the input to influence the query's structure or logic.

A simplified vulnerable pattern is:

```php
$searchInput = $_POST['findUser'];

$query = "select * from logins where username like '%$searchInput'";
```

The problem isn't simply that user input exists.

The problem is:

> **Untrusted input is being directly incorporated into SQL syntax without an appropriate safe query mechanism.**

---

# 10. Understanding the Quote Boundary

Consider:

```sql
select * from logins
where username like '%admin'
```

The string value is:

```text
'%admin'
```

The SQL parser understands the quote characters as defining a string.

Conceptually:

```text
SQL syntax:
username LIKE '

Data:
%admin

SQL syntax:
'
```

The quote characters define the boundary between SQL syntax and string data.

---

# 11. Why Quotes Matter

A single quote:

```text
'
```

has special meaning in SQL.

For example:

```sql
WHERE username = 'admin'
```

The quotes tell the database that:

```text
admin
```

is a string literal.

Therefore, when untrusted input is placed inside a quoted SQL string, quote handling becomes security-critical.

---

# 12. Conceptual Injection

Suppose an application constructs:

```sql
SELECT *
FROM logins
WHERE username = '<USER_INPUT>';
```

The intended structure is:

```text
WHERE username = 'DATA'
```

The security problem occurs if specially crafted input can cause the database to interpret part of that input as SQL syntax.

Conceptually:

```text
Expected:

' DATA '

Potentially dangerous:

' DATA ' SQL SYNTAX ...
```

The important idea is **breaking out of the intended string context**.

---

# 13. HTB Demonstration of Query Manipulation

The supplied example demonstrates the concept using an input resembling:

```text
1'; DROP TABLE users;
```

The application would construct something conceptually like:

```sql
select * from logins where username like '%1'; DROP TABLE users;'
```

The important lesson from this example is not the destructive action itself.

The lesson is:

```text
Original SQL
     +
Specially crafted input
     ↓
Different SQL structure
```

This demonstrates how changing the SQL syntax can potentially cause unintended database operations.

---

# 14. Important MySQL Limitation

The HTB example specifically notes an important limitation:

> The simple stacked-query example shown above is **not possible with the standard MySQL command/query interface in the same way**, whereas stacked queries are supported in some other database systems such as MSSQL and PostgreSQL under appropriate conditions.

Therefore, don't memorize:

```text
"semicolon = always successful SQL injection"
```

That is incorrect.

SQL Injection techniques depend on:

- DBMS
    
- Application
    
- Database driver
    
- Query context
    
- API behavior
    
- Permissions
    
- Whether multiple statements are supported
    

The module subsequently focuses on techniques appropriate to MySQL.

---

# 15. Syntax Errors

A successful SQL Injection needs to result in a **syntactically valid query**.

Suppose an application originally has:

```sql
SELECT *
FROM logins
WHERE username LIKE '%USER_INPUT';
```

If the injected input changes the quote structure incorrectly, the final SQL may contain an unmatched quote.

That can produce an error such as:

```text
syntax error
```

---

# 16. Why Syntax Errors Happen

SQL uses quotes to delimit strings.

For example:

```sql
'admin'
```

has:

```text
' → opening quote
admin → string
' → closing quote
```

If the final query contains an extra unmatched quote:

```text
'admin''
```

the SQL parser may not understand the intended structure.

Therefore:

```text
Injection
   ↓
Malformed SQL
   ↓
Syntax Error
```

---

# 17. Valid SQL Is Essential

A successful injection isn't simply:

```text
"Put SQL code into input."
```

The resulting query must also be valid SQL.

The goal of analyzing a vulnerable query is to understand:

```text
Original query structure
        +
User input
        ↓
Final query
        ↓
Valid SQL?
```

If the answer is no:

```text
Syntax Error
```

If the answer is yes:

```text
Database executes the resulting query
```

---

# 18. Why the Original Query Matters

In a real security assessment, you often won't see the application's source code.

You may only see:

```text
Web page
   ↓
Input field
   ↓
Response
```

You don't necessarily know the exact SQL query running in the background.

For example, you may not know whether the application uses:

```sql
WHERE username = '<input>'
```

or:

```sql
WHERE username LIKE '%<input>%'
```

or:

```sql
WHERE username = '<input>' AND active = 1
```

The surrounding query structure matters enormously.

---

# 19. Comments

One important technique for dealing with the **remainder of the original query** is SQL comments.

Conceptually:

```text
Original query
      │
      ▼
Injection point
      │
      ▼
Comment out unwanted remainder
```

This can prevent the application's remaining SQL syntax from interfering with the modified query.

The exact comment syntax depends on the DBMS and query context.

The HTB module covers SQL comments in a later section.

---

# 20. Another Way — Quote Balancing

Another general concept is ensuring that the resulting query has correctly balanced quotes.

For example, if an application's SQL string contributes a closing quote after the input, the injected input may need to account for that.

The core principle is:

```text
Final SQL
   ↓
Quotes must make syntactic sense
```

This is why understanding SQL string literals is so important before learning SQLi.

---

# 21. SQL Injection Types

SQL Injection can be classified according to **how the attacker obtains the result of the injected query**.

The major categories introduced here are:

```text
SQL Injection
│
├── In-Band
│   ├── Union-Based
│   └── Error-Based
│
├── Blind
│   ├── Boolean-Based
│   └── Time-Based
│
└── Out-of-Band
```

![Image](https://images.openai.com/static-rsc-4/ynnpmRHIOJ9uixo6kxFg2oPKdVw7caN-P8dRm5fIu_q80yfh649MeQbKp5ssxxNiwb25n7hpr-De-VDMoS6b7-s9fx9O4ynJN406oWBHTvChFrAwoUMwNGmAKdFH-sOMCIyQxoL3MR8eJlGuT8oq8I8YkZJQcOvQaCXo7_gA82Wik9aCH2RVXM4MjtSEZp3N?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/a8Ub1hguiCt4fRUFdqtKbL71krUqHtPsAiaFzGeuxljuLFau8HPttz9Aweq2dfcWy0FzAnUDfmzGJ7_4SZcxmXLsCC9GqTQ7cbc-SkgamoFLYNkurVSsLUS6nFcz80qJb5FIlBoDV5Hn3Pt-iYmdTLk5Nh2cbD_0JzwYpueCPwtbAN0pAMkRPAdGCjWVkrLp?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/BQk29wjvh4taAy8--T5UuGHx2EfljC-pIsiArF4NpF8ieM4ttraiOCkD4UeO-j4LyzFg0SRnsRxs4fSfn8HmNoolvscG0vzhNQ7YulMcmKrnxuTqCxZ3LTIRmX1nJSqDgPq3PapQUtyM9oRofONA4eRTux69uHHeE37RiXZ5mzBcDo-krXXk345hQCRkJuzy?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/I-IqoYQXdhhb5XZQ6qIrM4tzEXoQg_rC0hEEtRVzFJgZY7eCO7fGnPJUeKptvcpG1DAHrBD8CGc33uf57u7j0hbqhLexiECP06-o6xUYchZaPEicQhRR1sNaq8CsSSFbfJCLApONHMykspzZU8bvorRuRdQ4FhXMGNuY6rw_bEUR7IjPsuxktZVS8tX2Q3hH?purpose=fullsize)

---

# 22. In-Band SQL Injection

**In-band SQL Injection** occurs when the attacker can retrieve the results through the **same communication channel/application response** used to perform the injection.

Conceptually:

```text
Attacker
   │
   │ SQL Injection
   ▼
Web Application
   │
   ▼
Database
   │
   │ Result
   ▼
Web Application
   │
   ▼
Attacker
```

The output comes back through the normal application response.

---

# 23. Union-Based SQL Injection

One form of in-band SQLi is:

> **Union-Based SQL Injection**

The SQL `UNION` operator can combine compatible result sets from multiple `SELECT` statements.

Conceptually:

```text
Original SELECT
      +
Injected SELECT
      ↓
Combined result
      ↓
Application displays result
```

For example, a vulnerable application might display database results directly on the page.

Union-based techniques can potentially cause additional query results to appear in the application's normal output.

### Key idea

```text
UNION
  ↓
Combine result sets
  ↓
Retrieve additional data through normal output
```

The later sections of the module go into this technique in detail.

---

# 24. Error-Based SQL Injection

Another in-band technique is:

> **Error-Based SQL Injection**

This relies on situations where the application exposes useful database/PHP error information to the user.

Conceptually:

```text
Injected SQL
     ↓
Database Error
     ↓
Application displays error
     ↓
Information revealed
```

The attacker may intentionally cause an error that contains useful information.

### Important

Error messages should not expose sensitive internal database information in production applications.

---

# 25. Blind SQL Injection

Sometimes the application does **not directly display the result** of the injected query.

For example:

```text
Injection
   ↓
Database
   ↓
Result exists
   ↓
Application does NOT display result
```

This creates a **Blind SQL Injection** scenario.

Instead of directly reading the result, the attacker infers information from observable differences in the application's behavior.

---

# 26. Boolean-Based Blind SQL Injection

One type of blind SQLi is:

> **Boolean-Based SQL Injection**

The attacker uses conditions whose results are either:

```text
TRUE
```

or:

```text
FALSE
```

The application's response may differ depending on the result.

Conceptually:

```text
Condition
   │
   ├── TRUE  → Response A
   │
   └── FALSE → Response B
```

By observing these differences, information may be inferred.

---

# 27. Example Concept

Imagine an application normally responds:

```text
User found
```

for a true condition and:

```text
User not found
```

for a false condition.

Then:

```text
Condition → TRUE
     ↓
"User found"
```

versus:

```text
Condition → FALSE
     ↓
"User not found"
```

The attacker can potentially use this difference to infer information even though the database never directly displays the queried value.

---

# 28. Time-Based Blind SQL Injection

Another type is:

> **Time-Based SQL Injection**

Instead of relying on visible content, the attacker observes **response timing**.

Conceptually:

```text
Condition
   │
   ├── TRUE  → Delayed response
   │
   └── FALSE → Normal response
```

The module mentions MySQL's:

```text
SLEEP()
```

function as an example of a database operation that can deliberately delay execution.

The basic concept is:

```text
If condition is TRUE
       ↓
Database waits
       ↓
Application responds later
```

versus:

```text
If condition is FALSE
       ↓
No intentional delay
       ↓
Normal response
```

---

# 29. Out-of-Band SQL Injection

Sometimes the attacker cannot retrieve results through the application's normal response **at all**.

In that situation, information may potentially be sent through a separate communication channel.

This is known as:

> **Out-of-Band (OOB) SQL Injection**

Conceptually:

```text
                 Web Application
                       │
                       ▼
                    Database
                       │
                       │
                       ▼
                External Channel
                       │
                       ▼
                    Attacker
```

The separate channel might involve a network mechanism such as DNS, depending on the DBMS, server configuration, and available capabilities.

---

# 30. Comparing SQL Injection Types

|Type|How results are obtained|
|---|---|
|**In-Band**|Directly through normal application response|
|**Union-Based**|Additional result set is incorporated into normal output|
|**Error-Based**|Information is revealed through database/application errors|
|**Blind / Boolean-Based**|Infer information from TRUE/FALSE response differences|
|**Blind / Time-Based**|Infer information from response timing|
|**Out-of-Band**|Results are sent through a separate communication channel|

---

# 31. In-Band vs Blind vs Out-of-Band

The easiest way to remember the classification:

```text
                 SQL INJECTION
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
     IN-BAND        BLIND       OUT-OF-BAND
        │             │             │
        ▼             ▼             ▼
   Direct output   Indirect      Separate
   in response     inference     channel
```

---

# 32. In-Band

Think:

> **"I can see the result."**

```text
Injection
   ↓
Database
   ↓
Result
   ↓
Web page
```

---

# 33. Blind

Think:

> **"I can't see the result, but I can observe its effects."**

```text
Injection
   ↓
Database
   ↓
TRUE/FALSE or timing
   ↓
Different application behavior
```

---

# 34. Out-of-Band

Think:

> **"The result has to come back through another channel."**

```text
Injection
   ↓
Database
   ↓
External communication
   ↓
Attacker
```

---

# 35. Why SQL Injection Happens

The fundamental root cause is **unsafe handling of untrusted input**.

A vulnerable pattern looks like:

```php
$query = "SELECT *
          FROM logins
          WHERE username = '$userInput'";
```

The application is constructing SQL by concatenating user-controlled data into the SQL string.

The safer approach is to use **parameterized/prepared queries**, where the database driver treats supplied values as data rather than SQL syntax.

---

# 36. Sanitization vs Parameterization

The HTB text describes **sanitization** as removing special characters that could be used in injection attempts.

However, an important modern security lesson is:

> **Do not rely on ad-hoc character filtering as your primary SQL Injection defense.**

The preferred defense is:

```text
Prepared Statements
+
Parameterized Queries
```

Conceptually:

```text
SQL Structure
      +
Parameter
      ↓
Database
```

The parameter is treated as data rather than being interpreted as part of the SQL statement.

---

# 37. Safe vs Vulnerable Query Construction

### Vulnerable Concept

```text
User Input
    ↓
String Concatenation
    ↓
SQL Query
    ↓
Database
```

### Safer Concept

```text
SQL Template
    +
Parameter
    ↓
Prepared Statement
    ↓
Database
```

The critical difference is whether user input can become part of the SQL syntax.

---

# 38. Important SQLi Terminology

|Term|Meaning|
|---|---|
|**SQLi**|SQL Injection|
|**Injection**|Input interpreted as instructions/code|
|**Input Validation**|Checking whether input meets expected requirements|
|**Sanitization**|Transforming/removing unsafe input characters or patterns|
|**Prepared Statement**|SQL statement prepared separately from its parameter values|
|**Parameterized Query**|Query where user values are bound as parameters|
|**In-Band**|Results returned through the normal application channel|
|**Blind**|Results aren't directly returned; information is inferred|
|**Boolean-Based**|Infer information through TRUE/FALSE behavior|
|**Time-Based**|Infer information from response timing|
|**Union-Based**|Use compatible result sets to return additional data|
|**Error-Based**|Obtain information through database/application errors|
|**Out-of-Band**|Results returned through a separate channel|

---

# 39. Important SQL Injection Flow

Memorize this:

```text
             USER INPUT
                  │
                  ▼
          WEB APPLICATION
                  │
                  ▼
        SQL QUERY CONSTRUCTION
                  │
                  ▼
                MySQL
                  │
                  ▼
             SQL PARSER
                  │
          ┌───────┴───────┐
          ▼               ▼
       Normal          Modified
       Query           Query Logic
          │               │
          └───────┬───────┘
                  ▼
               RESULT
```

The vulnerability exists when the attacker can influence the **query structure**, not merely the data value.

---

# 40. Syntax Error Mental Model

Whenever analyzing an SQL injection, think:

```text
Original Query
      +
Attacker Input
      ↓
Final Query
      ↓
Is syntax valid?
      │
   ┌──┴──┐
   │     │
  NO    YES
   │     │
   ▼     ▼
Error  Execute
```

This is why quote handling and the surrounding SQL query are so important.

---

# 41. Important Concept — Query Context

The same input can behave differently depending on where it is inserted.

For example:

```sql
WHERE username = '<INPUT>'
```

is different from:

```sql
WHERE username LIKE '%<INPUT>%'
```

which is different from:

```sql
ORDER BY <INPUT>
```

which is different from:

```sql
LIMIT <INPUT>
```

Therefore:

> **There is no single universal SQL Injection payload that works everywhere.**

The injection context determines what syntax is possible.

---

# 42. SQL Injection Classification Diagram

```text
                         SQL INJECTION
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
       IN-BAND              BLIND           OUT-OF-BAND
          │                   │                   │
      ┌───┴───┐           ┌───┴────┐              │
      ▼       ▼           ▼        ▼              ▼
    UNION   ERROR       BOOLEAN   TIME        External
    BASED   BASED        BASED    BASED        Channel
```

---

# 43. Module Focus

According to the material you provided, this module focuses on introducing SQL Injection through:

> **Union-Based SQL Injection**

Therefore, the next concepts you should be particularly comfortable with are:

```text
SELECT
   ↓
WHERE
   ↓
UNION
   ↓
Column counts
   ↓
Compatible data types
   ↓
Identifying useful output columns
   ↓
Retrieving database information
```

Your previous SQL lessons are directly preparing you for this.

---

# 44. What You Should Know Before Union-Based SQLi

Before moving forward, make sure you understand:

### SQL basics

```sql
SELECT * FROM logins;
```

### Filtering

```sql
SELECT *
FROM logins
WHERE id > 1;
```

### Boolean logic

```sql
WHERE id > 1 AND username != 'john';
```

### Pattern matching

```sql
WHERE username LIKE 'admin%';
```

### Sorting

```sql
ORDER BY id;
```

### Limiting

```sql
LIMIT 2;
```

### SQL strings

```sql
'admin'
```

### SQL comments

Understand that comments can cause the remainder of a query to be ignored, depending on the syntax and DBMS.

---

# 45. ⭐ Most Important Things to Memorize

> **SQL Injection occurs when untrusted user input is incorporated into an SQL query in a way that allows the input to influence SQL syntax or logic.**

> **A quote can be significant when user input is placed inside an SQL string because it may change the boundary between data and SQL syntax.**

> **A successful SQL injection must result in syntactically valid SQL.**

> **The exact SQL query context determines what injection techniques are possible.**

> **The simple stacked-query example shown in the module is not generally how MySQL handles multiple statements through the relevant interface; support depends on the DBMS and driver configuration.**

> **In-Band SQLi returns information through the normal application response.**

> **Union-Based and Error-Based SQLi are types of In-Band SQLi.**

> **Blind SQLi does not directly return the desired data; information is inferred from application behavior.**

> **Boolean-Based SQLi relies on differences caused by TRUE/FALSE conditions.**

> **Time-Based SQLi relies on differences in response timing.**

> **Out-of-Band SQLi retrieves information through a separate communication channel.**

> **Prepared/parameterized queries are the preferred defense against SQL Injection.**

> **Ad-hoc character filtering/sanitization should not be treated as a substitute for parameterized queries.**

---

# 46. Quick Revision Sheet

```text
SQL INJECTION
│
├── Root Cause
│   └── Unsafe SQL construction using untrusted input
│
├── In-Band
│   ├── Union-Based
│   └── Error-Based
│
├── Blind
│   ├── Boolean-Based
│   └── Time-Based
│
└── Out-of-Band
    └── Separate communication channel
```

### Remember the three big categories:

```text
IN-BAND
→ I SEE THE RESULT

BLIND
→ I INFER THE RESULT

OUT-OF-BAND
→ RESULT COMES THROUGH ANOTHER CHANNEL
```

### Root Cause:

```text
Untrusted Input
      ↓
Unsafe SQL Construction
      ↓
Input Influences SQL Syntax
      ↓
SQL Injection
```

### Preferred Defense:

```text
Prepared Statements
        +
Parameterized Queries
        +
Least-Privilege Database Accounts
        +
Appropriate Input Validation
```

---

# 47. Final Mental Model

The entire SQL Injection concept can be reduced to:

```text
                    USER
                     │
                     │ Input
                     ▼
             WEB APPLICATION
                     │
                     │
             ┌───────┴────────┐
             │                │
          SAFE             UNSAFE
             │                │
             ▼                ▼
       Parameterized      SQL String
          Query           Concatenation
             │                │
             ▼                ▼
          MySQL          SQL Injection
             │                │
             ▼                ▼
          Database       Modified Query
```

The key question to ask whenever you see a web application interacting with SQL is:

> **“Is this user-controlled value being treated strictly as data, or can it become part of the SQL syntax?”**

That question is at the heart of SQL Injection.