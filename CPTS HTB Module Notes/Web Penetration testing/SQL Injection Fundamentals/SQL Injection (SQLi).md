![Image](https://images.openai.com/static-rsc-4/dHE02hjjD9O6h2xt20EOhYg-KVheRDNRwkaTvTEq8Mj5aPIC05S5iLqljkh8_odfOl5xutepOVMbPxUGmkyrkGihFoSRllLGj0MnMCY1dXXuPurnzFUh5bHJG5n5ogUZbA4907Z9Q7n5s4gcj4agQB0RouTFEt7_Cz4CtJ7KKubgPEr6XkJhT30-xGO9nSI9?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/fC_8kvwTzmuluIJ9BiDyuUzeEsEL8YHJ5_3rYTm_KxCsO5y_P9KpuRGhlElwQY6PBCtoF72SbhAhve5vNwx4b1zo8yW-tC_uqLNukpPImX9nc3ZxUcx__7iCyYCJlWRxSJZ7wjiM5dsV2f82o7Ecg0aoH0NLmW8ugvN4rDCa_XZmi1liHOOy84SoOmtGo3ak?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/stneVNHnJrDMSGHOvHHW9pcM0cggjzmc9_pglx4ZumbiRluSlpp2Gi7gUYhhd6v0YioVQQmUg0k7-J1Qs4wgG5WnIs2Rqewnz0d_8FWkWJTEJybEQXmH_N2yR4zTlQTbdO2zUOHzcQAey_iP-S2VpH3q7lIClh8JAnbI74rZ8G60t_CjTU0DBFS-SsyTrZ0U?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jmIj956q13mp46mHxJYJsP-83PzV6wpFiA4qQbuyZJyrwiZVv7eWjp1Ouh_OuYtOaBNn0SFtfU2aj9lTnDzhsR21JZFRroyso7gbOOzIwsOSOQLmiazSe3Eocg7XaMj-DGc6-VzoBDo9kKopL6zsi0FIvIfXG_O0cDYPzD2XB4eGIZfJFEQ4h_IcCK1d65jJ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/muMZxyZOGJTWseBJg486CqXA9uETTqjg5nP8Xezbib9cma-oPD7oS3RjBbSKYe-aVt1430NXR-HwgPqs41aQOJ_0gqlGkcKOCdomnXrES-L1z0B6bJl0ujBb6YAbjqfjrzsmRQQPQtV9fYdzq5_Ev5aptuC8DIjFkRePIM-8pYd0no8wFGl7Dh8QweS7HqXc?purpose=fullsize)
## 1. Introduction

Most modern web applications utilize a **database structure on the back-end**.

Databases are used to **store and retrieve data** related to the web application, including:

- Web application content
    
- User information
    
- User-generated content
    
- Login credentials
    
- Application configuration
    
- Other sensitive or operational data
    

To make web applications dynamic, the application needs to interact with the database **in real time**.

### Basic Request Flow

A simplified web application architecture consists of three major tiers:

```text
┌──────────────────────┐
│       Tier I         │
│   Client / Browser   │
└──────────┬───────────┘
           │
           │ HTTP / HTTPS
           ▼
┌──────────────────────┐
│       Tier II        │
│ Application Server   │
└──────────┬───────────┘
           │
           │ SQL Query
           ▼
┌──────────────────────┐
│       Tier III       │
│       DBMS           │
│  MySQL / PostgreSQL  │
└──────────────────────┘
```

When HTTP(S) requests arrive from a user, the **web application's back-end issues queries to the database** to build the response.

These queries can contain information obtained from the HTTP(S) request.

For example:

```text
User Input
    ↓
Web Application
    ↓
SQL Query
    ↓
Database
    ↓
Database Result
    ↓
Web Application Response
    ↓
User
```

### The Security Problem

If **user-supplied information is used directly to construct a database query**, a malicious user may be able to manipulate that input.

Instead of being treated as normal data, the input can become part of the SQL command.

This can allow the attacker to make the database perform actions that the original programmer **never intended**.

This type of attack is called:

> **SQL Injection (SQLi)**

---

# 2. What is SQL Injection?

**SQL injection refers to attacks against relational databases such as MySQL.**

SQLi occurs when a malicious user supplies input that changes the final SQL query sent by the web application to the database.

The goal is generally to cause the application or database to perform an **unintended SQL operation**.

### Important Definition

> **A SQL injection occurs when a malicious user attempts to pass input that changes the final SQL query sent by the web application to the database, enabling the user to perform other unintended SQL queries directly against the database.**

---

# 3. SQL Injection vs NoSQL Injection

SQL injection specifically targets **relational databases**.

Examples of relational database systems include:

- MySQL
    
- PostgreSQL
    
- Microsoft SQL Server
    
- Oracle Database
    
- SQLite
    

For example:

```text
Web Application
       ↓
     SQLi
       ↓
Relational Database
```

Non-relational databases use different query mechanisms.

For example:

```text
MongoDB
   ↓
NoSQL Injection
```

### Key Point

|Injection Type|Database Type|Example|
|---|---|---|
|SQL Injection|Relational|MySQL|
|NoSQL Injection|Non-relational|MongoDB|

This module focuses on **MySQL** to introduce SQL Injection concepts.

---

# 4. How SQL Injection Happens

A typical vulnerable application may construct a query using user input.

For example:

```sql
SELECT * FROM users
WHERE username = 'USER_INPUT'
AND password = 'PASSWORD_INPUT';
```

If the application directly inserts user-controlled input into this query without properly handling it, the attacker may be able to manipulate the query.

### Normal Input

Suppose the user enters:

```text
admin
```

The resulting query could be:

```sql
SELECT * FROM users
WHERE username = 'admin';
```

The application interprets `admin` as data.

### Malicious Input

An attacker may attempt to introduce SQL syntax into the input.

The important concept is that the attacker is trying to make the database interpret part of the supplied input as **SQL code instead of ordinary data**.

---

# 5. Escaping the Expected Input

To perform SQL injection, an attacker first needs to escape the boundaries of the application's expected input.

One of the most basic techniques is attempting to inject:

```text
'
```

or:

```text
"
```

These characters can sometimes terminate a string inside an SQL query.

For example, if an application creates:

```sql
SELECT * FROM users WHERE username = 'INPUT';
```

and the input contains a quote, the resulting SQL structure may become different from what the developer intended.

### Important Concept

The quote itself is not necessarily the complete attack.

It is often used as an initial test to determine whether:

1. User input reaches the SQL query.
    
2. The input is being interpreted as part of the SQL syntax.
    
3. The application is vulnerable to SQL injection.
    

---

# 6. The General SQLi Process

A simplified SQL injection process can be remembered as:

```text
        User Input
            │
            ▼
   ┌─────────────────┐
   │ Test Application│
   └────────┬────────┘
            │
            ▼
     Identify SQLi
            │
            ▼
   Escape Input Context
            │
            ▼
   Manipulate SQL Logic
            │
            ▼
   Execute Unintended Query
            │
            ▼
   Retrieve / Interpret Result
```

### Three Important Stages

## Stage 1 — Inject SQL Code

The attacker first attempts to introduce SQL syntax into the application's input.

Common characters used when testing include:

```text
'
"
```

The exact technique depends on how the application constructs its query.

---

## Stage 2 — Subvert the Original Query

Once injection is possible, the attacker attempts to change the logic of the original query.

This can involve techniques such as:

- Modifying query conditions
    
- Adding SQL expressions
    
- Using `UNION` queries
    
- Using stacked queries where supported
    

The objective is to make the database execute something different from the developer's intended query.

---

## Stage 3 — Retrieve the Result

After successfully manipulating the query, the attacker needs to obtain the resulting information.

The output may appear:

- Directly on the web page
    
- Inside an error message
    
- In a returned table
    
- Through application behavior
    
- Through another observable response
    

The attacker then interprets the result.

---

# 7. Stacked Queries

One method of SQL injection involves **stacked queries**.

Stacked queries attempt to execute multiple SQL statements through a single injection point.

Conceptually:

```sql
Original Query;
Injected Query;
```

For example:

```text
Application Query
       +
Injected SQL Statement
       ↓
Multiple SQL Statements
```

Whether stacked queries work depends on factors such as:

- Database system
    
- Database driver
    
- Application framework
    
- Configuration
    
- Query execution method
    

Therefore, stacked queries are **not universally supported**.

---

# 8. UNION-Based SQL Injection

Another important SQL injection technique is the use of **UNION queries**.

The SQL `UNION` operator can combine the results of multiple `SELECT` statements.

Conceptually:

```sql
SELECT column1 FROM table1
UNION
SELECT column1 FROM table2;
```

This can become useful during SQL injection when the attacker wants to make the application display results from another query.

### General Concept

```text
Original SELECT
      +
Injected SELECT
      ↓
    UNION
      ↓
Combined Result
```

The important idea is:

> **UNION queries can allow an attacker to combine the application's intended query results with results from another SELECT statement.**

For a UNION-based attack to work correctly, the injected query generally needs to be compatible with the structure of the original query.

---

# 9. SQL Injection Use Cases and Impact

SQL injection can have a **tremendous impact**, especially when privileges on the back-end server and database are poorly configured.

Potential consequences include:

```text
SQL Injection
     │
     ├──► Sensitive Data Exposure
     │
     ├──► Authentication Bypass
     │
     ├──► Unauthorized Data Access
     │
     ├──► Data Modification
     │
     ├──► File Read / Write
     │
     └──► Potential Server Compromise
```

---

# 10. Sensitive Information Disclosure

An attacker may be able to retrieve information that should not be publicly accessible.

Examples include:

- Usernames
    
- Passwords
    
- Personal information
    
- Application data
    
- Database records
    
- Credit card information
    
- Other sensitive information
    

### Why This Is Dangerous

Credentials obtained through SQL injection may potentially be reused against:

- The vulnerable application
    
- Other accounts
    
- Other services
    

This can turn a database vulnerability into a much larger security incident.

---

# 11. Authentication Bypass

SQL injection can sometimes be used to **subvert the intended authentication logic**.

The normal authentication process might be:

```text
Username + Password
        ↓
Database Query
        ↓
Credentials Checked
        ↓
Valid?
   /        \
 Yes         No
 ↓            ↓
Login       Reject
```

A vulnerable query may allow an attacker to manipulate the condition being checked.

This can potentially result in:

```text
Malicious Input
      ↓
Modified SQL Logic
      ↓
Authentication Logic Manipulated
      ↓
Unauthorized Access
```

### Important Point

Authentication bypass is one of the most well-known impacts of SQL injection.

---

# 12. Accessing Restricted Features

SQL injection may also allow an attacker to bypass application restrictions.

For example, an application may contain:

```text
Normal User
     ↓
Limited Access
```

while an administrator has:

```text
Administrator
     ↓
Admin Panel
     ↓
Privileged Functions
```

If SQL injection allows the attacker to manipulate the application's authorization logic, they may potentially access functionality intended only for specific users.

Examples:

- Admin panels
    
- User management
    
- Internal dashboards
    
- Restricted records
    
- Administrative functions
    

---

# 13. Reading and Writing Files

Depending on the database configuration, privileges, and DBMS capabilities, SQL injection can potentially allow attackers to interact with files on the back-end server.

Possible consequences can include:

```text
Database Access
      ↓
File Read
      ↓
Sensitive Files
```

or, in more permissive environments:

```text
Database Access
      ↓
File Write
      ↓
Malicious File
      ↓
Potential Server Compromise
```

This is highly dependent on:

- Database privileges
    
- Operating system permissions
    
- DBMS configuration
    
- Application configuration
    
- Security controls
    

Therefore, SQL injection does **not automatically mean full server compromise**, but excessive privileges can dramatically increase the impact.

---

# 14. Potential Server Compromise

In a poorly secured environment, SQL injection can become the starting point for a larger attack chain.

A simplified chain might look like:

```text
SQL Injection
     ↓
Database Access
     ↓
Sensitive Information
     ↓
Credentials / Configuration
     ↓
Additional Access
     ↓
Potential Server Compromise
```

This demonstrates why SQL injection should not be treated as merely a database problem.

---

# 15. Why Database Privileges Matter

The impact of SQL injection depends heavily on the privileges available to the database account used by the application.

### Poorly Configured Database Account

```text
Application
     ↓
Highly Privileged DB Account
     ↓
SQL Injection
     ↓
Large Attack Surface
```

### Properly Restricted Account

```text
Application
     ↓
Least-Privilege DB Account
     ↓
SQL Injection
     ↓
Reduced Potential Impact
```

### Security Principle

> **Least privilege** is extremely important.

The database account used by a web application should have only the permissions it actually needs.

---

# 16. SQL Injection Attack Surface

SQL injection can occur anywhere user-controlled input reaches an SQL query.

Potential input locations include:

- Login forms
    
- Search fields
    
- URL parameters
    
- POST parameters
    
- Cookies
    
- HTTP headers
    
- Form fields
    
- API parameters
    
- Application filters
    

Conceptually:

```text
             User-Controlled Input
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
      URL          Form         Cookie
        │            │            │
        └────────────┼────────────┘
                     ▼
              Web Application
                     │
                     ▼
                 SQL Query
                     │
                     ▼
                  Database
```

---

# 17. Signs That an Application May Be Vulnerable

During authorized security testing, indicators of SQL injection may include:

### 1. Database Errors

Unexpected database errors after specially crafted input may indicate that input is reaching the SQL layer.

### 2. Changed Application Behavior

The application's response changes significantly after modifying input.

### 3. Authentication Logic Changes

Unexpected login behavior may indicate that the underlying query is being manipulated.

### 4. Different Response Sizes

The application's response may change when query conditions are modified.

### 5. Unexpected Data

Information that should not normally appear may become visible.

> These signs are indicators, not proof by themselves. Proper testing is required to confirm SQL injection.

---

# 18. Common SQL Concepts to Know

Understanding SQL injection requires familiarity with basic SQL.

## SELECT

Retrieves data.

```sql
SELECT * FROM users;
```

## WHERE

Filters results.

```sql
SELECT * FROM users
WHERE username = 'admin';
```

## AND

Requires multiple conditions to be true.

```sql
condition1 AND condition2
```

## OR

Allows either condition to be true.

```sql
condition1 OR condition2
```

## UNION

Combines results from multiple compatible `SELECT` statements.

```sql
SELECT column FROM table1
UNION
SELECT column FROM table2;
```

## Comments

SQL comments can sometimes be relevant when testing query manipulation because they can cause the remainder of a query to be ignored.

The exact comment syntax depends on the SQL dialect and context.

---

# 19. Important SQL Injection Terminology

|Term|Meaning|
|---|---|
|SQL|Structured Query Language|
|SQLi|SQL Injection|
|DBMS|Database Management System|
|Relational Database|Database organized around tables and relationships|
|Input|Data supplied to the application|
|Query|SQL statement sent to the database|
|Injection Point|Location where attacker-controlled input reaches a query|
|UNION|SQL operator used to combine compatible query results|
|Stacked Queries|Multiple SQL statements executed together where supported|
|Authentication Bypass|Gaining access without valid credentials|
|Least Privilege|Giving an account only the permissions it requires|

---

# 20. Prevention of SQL Injection

SQL injection is usually caused by:

1. Poorly coded web applications
    
2. Unsafe handling of user input
    
3. Improper database privileges
    
4. Lack of secure development practices
    

There are several important defenses.

---

## 20.1 Prepared Statements / Parameterized Queries

One of the most important defenses is to use **prepared statements / parameterized queries**.

Instead of constructing SQL by directly concatenating user input:

```text
SQL + User Input
```

the application separates:

```text
SQL Structure
     +
User Data
```

Conceptually:

```text
SQL Query Template
       +
Parameter
       ↓
Database
```

This prevents user input from being interpreted as SQL syntax in the normal case.

---

# 21. Input Validation

Applications should validate incoming data.

Validation can check:

- Expected data type
    
- Expected length
    
- Allowed characters
    
- Expected format
    
- Acceptable ranges
    

For example, if an application expects an integer:

```text
Expected:
123
```

it should not blindly accept arbitrary text.

### Important

Input validation is useful as a **defense-in-depth measure**, but it should not replace parameterized queries.

---

# 22. Input Sanitization

Applications may also sanitize user input where appropriate.

However, relying solely on filtering characters such as:

```text
'
"
;
```

is not a reliable primary defense against SQL injection.

Attackers may use different encodings, syntax, or techniques depending on the application and database.

Therefore:

> **Use parameterized queries as the primary defense rather than attempting to build a blacklist of malicious characters.**

---

# 23. Database Privilege Management

Database accounts should follow the **principle of least privilege**.

For example, if an application only needs to read specific tables, its database account should not automatically have permission to:

- Modify unrelated tables
    
- Delete databases
    
- Access sensitive system resources
    
- Write arbitrary files
    
- Perform unnecessary administrative actions
    

### Secure Design

```text
Web Application
       ↓
Restricted DB Account
       ↓
Only Required Permissions
       ↓
Reduced SQLi Impact
```

---

# 24. Secure Development Approach

A secure application should follow several layers of protection:

```text
             Secure Application
                    │
       ┌────────────┼────────────┐
       ▼            ▼            ▼
Parameterized   Input         Least
  Queries      Validation    Privilege
       │            │            │
       └────────────┼────────────┘
                    ▼
             Reduced SQLi Risk
```

Additional protections can include:

- Secure coding practices
    
- Proper error handling
    
- Access control
    
- Database privilege restrictions
    
- Security testing
    
- Code review
    
- Web application firewalls where appropriate
    
- Monitoring and logging
    

---

# 25. SQL Injection — Complete Attack Concept

The complete concept can be summarized as:

```text
┌────────────────────────────┐
│      User-Controlled Input │
└──────────────┬─────────────┘
               │
               ▼
┌────────────────────────────┐
│     Vulnerable Application │
│                            │
│ Input inserted into query  │
└──────────────┬─────────────┘
               │
               ▼
┌────────────────────────────┐
│        SQL Query            │
│                            │
│ Intended logic + injection │
└──────────────┬─────────────┘
               │
               ▼
┌────────────────────────────┐
│          DBMS              │
└──────────────┬─────────────┘
               │
               ▼
┌────────────────────────────┐
│       Query Result         │
└──────────────┬─────────────┘
               │
               ▼
┌────────────────────────────┐
│      Web Application       │
└──────────────┬─────────────┘
               │
               ▼
             Attacker
```

---

# 26. SQL Injection Impact Summary

SQL injection can potentially result in:

### Confidentiality Impact

- Reading sensitive database information
    
- Exposing usernames and passwords
    
- Exposing personal information
    
- Exposing financial information
    

### Integrity Impact

- Modifying database records
    
- Manipulating application data
    
- Potentially writing files in certain configurations
    

### Availability Impact

- Potentially modifying or deleting important data
    
- Disrupting application functionality
    
- Causing database errors or failures
    

### Access Impact

- Authentication bypass
    
- Unauthorized access
    
- Privileged functionality access
    
- Potential progression toward server compromise
    

---

# 27. Important Things to Remember

> **SQL injection occurs when attacker-controlled input changes the SQL query executed by an application.**

> **SQL injection primarily targets relational databases such as MySQL.**

> **A quote (`'` or `"`) can sometimes be used to test whether input can escape its expected SQL context.**

> **The attacker must generally manipulate the original query logic after establishing an injection point.**

> **UNION queries can combine results from compatible SELECT statements.**

> **Stacked queries can execute multiple SQL statements where supported.**

> **SQL injection can expose sensitive information such as usernames, passwords, and financial data.**

> **SQL injection can sometimes bypass authentication and authorization controls.**

> **Excessive database privileges can greatly increase the impact of SQL injection.**

> **Least privilege reduces the potential damage caused by SQL injection.**

> **Prepared statements / parameterized queries are a primary defense against SQL injection.**

> **Input validation and sanitization are useful defense-in-depth measures but should not replace parameterized queries.**

---

# 28. Quick Revision Sheet

## SQL Injection in One Line

**SQL Injection = manipulating an application's SQL query through attacker-controlled input.**

### Attack Flow

```text
Input
 ↓
Injection Point
 ↓
Escape Query Context
 ↓
Manipulate SQL
 ↓
Execute Unintended Query
 ↓
Retrieve Result
```

### Major Techniques Introduced

```text
SQL Injection
├── Query Manipulation
├── Stacked Queries
└── UNION Queries
```

### Major Impacts

```text
SQLi
├── Sensitive Data Exposure
├── Authentication Bypass
├── Unauthorized Access
├── Data Modification
├── File Read / Write
└── Potential Server Compromise
```

### Major Defenses

```text
SQLi Prevention
├── Parameterized Queries
├── Prepared Statements
├── Input Validation
├── Secure Coding
├── Least-Privilege Database Accounts
├── Proper Access Control
└── Secure Error Handling
```

---

# 29. Exam / Interview Questions

### Q1. What is SQL Injection?

SQL injection is an attack in which malicious input changes the SQL query executed by a web application, allowing unintended database operations.

### Q2. Which type of database does SQL injection target?

Primarily **relational databases**, such as MySQL.

### Q3. What is the purpose of injecting a quote?

A quote can sometimes escape the application's expected string context and help determine whether user input is being interpreted as part of an SQL query.

### Q4. What is a UNION query?

A UNION query combines the results of compatible `SELECT` statements.

### Q5. What are stacked queries?

Stacked queries involve executing multiple SQL statements together where the database/application configuration supports them.

### Q6. What can SQL injection expose?

Potentially:

- Usernames
    
- Passwords
    
- Personal information
    
- Financial information
    
- Other sensitive database records
    

### Q7. Can SQL injection bypass authentication?

Yes. In vulnerable applications, manipulating the underlying authentication query may allow authentication bypass.

### Q8. What is the best primary defense against SQL injection?

**Prepared statements / parameterized queries.**

### Q9. Why is least privilege important?

If the application's database account has excessive permissions, a successful SQL injection can have a much greater impact.

### Q10. Does SQL injection always result in server compromise?

**No.** The final impact depends on the application's vulnerability, database permissions, DBMS capabilities, operating-system permissions, and overall environment.

---

# 30. Final Takeaway

SQL Injection is one of the most important web application vulnerabilities to understand because it sits at the boundary between **user-controlled input, application logic, and database operations**.

The fundamental problem is:

```text
Untrusted Input
      ↓
SQL Query Construction
      ↓
Database interprets input as SQL
```

A secure application instead maintains a separation between SQL code and user data:

```text
SQL Structure ───────────┐
                         ├──► Database
User Data ── Parameter ──┘
```

The most important defensive principles are:

1. **Use prepared statements / parameterized queries.**
    
2. **Validate input.**
    
3. **Do not rely solely on blacklists or character filtering.**
    
4. **Apply least privilege to database accounts.**
    
5. **Use secure coding and testing practices.**
    
6. **Handle database errors securely so sensitive information is not exposed.**
    

### Core Concept to Memorize

> **Never allow untrusted user input to become executable SQL syntax.**

That principle is at the heart of preventing SQL Injection.