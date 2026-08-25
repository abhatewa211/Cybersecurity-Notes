![Image](https://images.openai.com/static-rsc-4/WOIozpdgYjTzioKqhF-ToaBm4fegAHij_y5sY7Y9fWQis5DJj3OgxhESKxslW88-wUkIZ6D9CrzX0-lHmuPbe_2KfPfVIehOgzsRnWJTd4sy_jnhyRh41y-0Tvyoh-1VnBV76KvWkKD-OZIecjg8Dab95Y3_NHNCDaj3XOiCLkFE9-gGujb7k5hsVsIA6Ua_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/L-K4pYHLZPspOMFsYVuuOIrmYgoyycKxFQOuPsPzOjG6cbP9THO0ymKWqijShS0BptPxsiY30NGsyh63kHNknoBsAvvZGp645FTAgBqyIrQsmkkf1UeQpFDwq4O0mP8Ht_Wn0IRCRT0qsawolRya2_dHB9eNufG8r5T9DlvhLXsmEq8tB1fczmy5WqF7PaLa?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-k5DUC7nxSE3di0iTN6uGlTQ_qrSPFEqqcEejhoZUvMI9P8a4Xcl23BgspDOgsyhuqZrVyu9CxClFMsJpTEDJ5vxK38eW5xXM2nL5w7H2d4UuLJBTsVICQYGkeTVoQki_jDIgG9Dzx8NfBXjFoovvR_bd7e9Y5cIIt4P1WkAx0HWpLOgz-7tE5aoOkC1hGjZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2dVIoyDKb7MOrXo-NtswU_6hVOYgju81c6yNQph-cMfO8L8cZhbEjoJwKkVh1HVCtUgU020HHxtPauueLdTH6-03IuX1bLiXaGWWBmxdqYDnNnX6A7Lpygp9EhMZ0I8JzeU5J3-D7A_XR8W3uPLgpDbHJWu_S7AfwJL4Xn1rWJsQGuMHWSVKHwAPZWcx4UMd?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ebaGCQ7b26w2jKoWKCqx94JXa6Ev9Ba_kQk_cF65TKgX7L0C6O-VL9MfMEnXgNhx9R3yg_Hv3LxKsZQ8XxyztIaAPj6ZaxzHk6vWOpDfP9ygn4W_xXUuWNzwIOUAWs4VoWAHUrvvaDUKEmb-Y8QKC_9Dd3Fk8k0XDbUZr-gMlUdEe_tstKjIhimf5gBo9GVF?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/aNe1cbhQjdb26NuxG3CB76KaLVVdSvyiOkzHjdbmPx6tTPQIyBd0WnGCq4C0bZJqsMDPxdOZUMJr0xLUKBAztfWbOHdt2wzJ1BDMal1rT_f2xvW4tPZevlPvvozdjgR3Gevy5u4TNEW7v9GQK09JrhuCmJ_cPeZDWRJcBFKKLdSjG0bktsaY67-ViJFrPk4x?purpose=fullsize)
## 1. Introduction

Before learning about **SQL Injection (SQLi)**, it is important to understand:

- Databases
    
- Database Management Systems (DBMS)
    
- Relational databases
    
- Structured Query Language (SQL)
    
- How web applications communicate with databases
    
- How data is stored, retrieved, updated, and deleted
    

Modern web applications commonly use **back-end databases** to store information required by the application.

Examples of information stored in databases include:

- Images and files
    
- Posts and updates
    
- Usernames
    
- Passwords
    
- User profiles
    
- Application configuration
    
- Other application-related data
    

A simplified web application flow is:

```text
User
  │
  ▼
Web Application
  │
  ▼
Database
  │
  ▼
Stored Data
```

---

# 2. Why Do We Need Databases?

A web application needs a way to store information so that it can be retrieved later.

For example, consider a social media application.

When a user creates a post:

```text
User creates post
       ↓
Web Application
       ↓
Database
       ↓
Post stored
```

When another user opens the application:

```text
User requests posts
       ↓
Web Application
       ↓
Database query
       ↓
Posts retrieved
       ↓
Displayed to user
```

Therefore, databases allow applications to **persist and retrieve information**.

---

# 3. Traditional File-Based Databases

Historically, applications could store information using ordinary files.

For example:

```text
users.txt
posts.txt
passwords.txt
```

This approach can work for small amounts of data.

However, as the amount of data and number of users increases, file-based storage becomes increasingly difficult and inefficient.

### Problems with File-Based Storage

Large file-based systems can suffer from:

- Slow searches
    
- Difficult data organization
    
- Poor concurrency
    
- Difficult data relationships
    
- Difficult access control
    
- Data duplication
    
- Difficult backup and recovery
    
- Poor scalability
    

This led to the adoption of **Database Management Systems (DBMS)**.

---

# 4. Database Management System (DBMS)

A **Database Management System (DBMS)** is software that helps users and applications:

- Create databases
    
- Define databases
    
- Host databases
    
- Store data
    
- Retrieve data
    
- Modify data
    
- Delete data
    
- Manage access
    
- Control permissions
    
- Maintain consistency
    
- Perform backups and recovery
    

### Simple Definition

> **A DBMS is software used to create, manage, and interact with databases.**

Conceptually:

```text
             ┌──────────────────┐
             │      Users       │
             └────────┬─────────┘
                      │
                      ▼
             ┌──────────────────┐
             │      DBMS        │
             │                  │
             │ Manage Database  │
             └────────┬─────────┘
                      │
                      ▼
             ┌──────────────────┐
             │     Database     │
             │                  │
             │     Data         │
             └──────────────────┘
```

---

# 5. Types of Database Systems

Different types of DBMS have been developed for different use cases.

Important categories include:

### 1. File-Based

Data is primarily stored in files.

```text
Application
    ↓
Files
```

### 2. Relational DBMS (RDBMS)

Data is organized into **tables** containing rows and columns.

Examples include:

- MySQL
    
- PostgreSQL
    
- Microsoft SQL Server
    
- Oracle Database
    
- SQLite
    

```text
Users Table

+----+----------+----------+
| ID | Username | Password |
+----+----------+----------+
| 1  | alice    | ******   |
| 2  | bob      | ******   |
+----+----------+----------+
```

### 3. NoSQL Databases

NoSQL databases use data models other than the traditional relational table model.

They can be useful for certain applications requiring flexible schemas or particular scaling characteristics.

Example:

```text
MongoDB
```

### 4. Graph Databases

Graph databases represent information using:

- Nodes
    
- Relationships
    
- Properties
    

They are particularly useful for highly connected data.

### 5. Key/Value Stores

Data is stored as a key associated with a value.

Conceptually:

```text
Key              Value
------------------------
username         arjun
theme            dark
language         English
```

---

# 6. DBMS Interaction

There are several ways to interact with a DBMS.

## Command-Line Interface

Users can interact with a database through command-line tools.

Example:

```text
mysql
```

or another database-specific client.

---

## Graphical User Interface

A GUI can provide a visual way to:

- Browse tables
    
- Execute queries
    
- Manage users
    
- Modify database structures
    
- View data
    

---

## APIs

Applications can also communicate with databases through **Application Programming Interfaces (APIs)** and database libraries/drivers.

For example:

```text
Web Application
      ↓
Database Driver
      ↓
DBMS
```

---

# 7. Where Are DBMSs Used?

DBMSs are used across many industries.

Examples include:

### Banking

Storing:

- Customer information
    
- Transactions
    
- Account information
    
- Payment records
    

### Finance

Storing:

- Financial records
    
- Market information
    
- Customer accounts
    
- Transactions
    

### Education

Storing:

- Student information
    
- Grades
    
- Courses
    
- Attendance
    
- Examination records
    

### Web Applications

Storing:

- User accounts
    
- Posts
    
- Comments
    
- Product information
    
- Orders
    
- Application settings
    

---

# 8. Important DBMS Features

A DBMS provides several important features.

The major features introduced in this module are:

1. Concurrency
    
2. Consistency
    
3. Security
    
4. Reliability
    
5. Structured Query Language (SQL)
    

---

# 9. Concurrency

### Definition

**Concurrency** means multiple users or processes can interact with a database at the same time.

A real-world application may have thousands or millions of users simultaneously interacting with its database.

For example:

```text
User A ──┐
User B ──┤
User C ──┼──► DBMS ──► Database
User D ──┤
User E ──┘
```

The DBMS needs to ensure that these concurrent interactions do not:

- Corrupt data
    
- Overwrite valid information incorrectly
    
- Cause inconsistent results
    
- Lose data
    

### Example

Suppose two users try to purchase the last available product simultaneously.

Without proper concurrency handling:

```text
Stock = 1

User A → Buy
User B → Buy

Both see Stock = 1
        ↓
Potentially incorrect result
```

A DBMS uses mechanisms to manage such concurrent operations safely.

### Remember

> **Concurrency = multiple users interacting with the database simultaneously without corrupting or losing data.**

---

# 10. Consistency

### Definition

**Consistency** means the data remains valid and follows the database's defined rules.

A DBMS must ensure that operations do not leave the database in an invalid state.

For example, suppose a database has a rule that:

```text
Account balance ≥ 0
```

A properly managed transaction should not leave the database violating that rule.

### Concurrency + Consistency

Because many users can interact with the database simultaneously, maintaining consistency becomes particularly important.

```text
Multiple Users
      ↓
 Concurrent Operations
      ↓
      DBMS
      ↓
 Consistent Database
```

### Remember

> **Consistency = ensuring data remains valid and logically correct.**

---

# 11. Security

DBMSs provide security controls that regulate who can access data and what they can do with it.

Security can involve:

- User authentication
    
- Permissions
    
- Access control
    
- Database roles
    
- Privileges
    

For example:

```text
User
 ↓
Authentication
 ↓
Authorization
 ↓
Allowed Operations
```

A normal application user may have permission to:

```text
SELECT data
```

but not:

```text
DELETE database
```

An administrator may have significantly greater privileges.

### Why This Matters for SQL Injection

Database privileges are extremely important when discussing SQL injection.

If a vulnerable application uses a highly privileged database account:

```text
SQL Injection
      ↓
Highly Privileged DB Account
      ↓
Potentially Severe Impact
```

If the application uses a restricted account:

```text
SQL Injection
      ↓
Limited DB Account
      ↓
Reduced Impact
```

---

# 12. Reliability

A DBMS makes it easier to:

- Back up data
    
- Restore data
    
- Recover from failures
    
- Roll back operations
    
- Recover from data loss
    

For example:

```text
Database
   ↓
Backup
   ↓
Failure / Data Loss
   ↓
Recovery
   ↓
Restored Database
```

Reliability is especially important for organizations where database availability and integrity are critical.

---

# 13. Structured Query Language (SQL)

**SQL stands for Structured Query Language.**

SQL provides a standardized and intuitive way to interact with relational databases.

It can be used for operations such as:

- Retrieving data
    
- Inserting data
    
- Updating data
    
- Deleting data
    
- Creating database structures
    
- Managing database objects
    

A simplified example:

```sql
SELECT * FROM users;
```

This asks the database to retrieve records from the `users` table.

---

# 14. CRUD Operations

A useful way to understand basic database operations is **CRUD**.

|Operation|Meaning|SQL Example|
|---|---|---|
|Create|Add data|`INSERT`|
|Read|Retrieve data|`SELECT`|
|Update|Modify data|`UPDATE`|
|Delete|Remove data|`DELETE`|

### CRUD Flow

```text
          Database Operations

Create ──► INSERT
Read   ──► SELECT
Update ──► UPDATE
Delete ──► DELETE
```

These operations form a major part of how applications interact with databases.

---

# 15. Database Architecture

Web applications commonly use a layered architecture.

The architecture described in this module contains:

```text
Tier I
Client Application

       ↓

Tier II
Application Server / Middleware

       ↓

Tier III
DBMS / Database
```

![Image](https://images.openai.com/static-rsc-4/4OVwD8lYkpGrWwWei_ptOpXySb9Bk6kVJK5Mjtvm9WzJyiaBXi22-hQhsNJvDTyQFoJq4YtFmrxguKidWYR2igTURji23OvKVDd0T55guEGR9BBjyqq5xMOmql-lfkwbxsYveKaewL9Iq19g4rJkb3hHXe9Ogpl8NZcm2F0PHCv8cR-tEvuaEPr7QKO_IGee?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/r2qeKd22Etxm6wXEsHvFAbISTKAQ9fBwei3ZNNxl771NorD8k5ofwYweg7rjQzCU6KKVk6-g1ukrizen_VxeysOpvx4xnswgnI7kxf-l7uDkYiXaJucTECB1C4rfOBnQm4wh2ErkBs9r_GGCNxtua73vIW1yCssRWEqJ10ooBZcZMqnyLroXjYAqXktrHQJs?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/lYeikmblJtieDENMt2ZhQziqfx_gzW483m5WsscyPxQutLDKwHMUGdM__eQBISgSLwv8-gKZMFxZLX22yiRB8cvq2KCWS02PuIcX2bz5zd4F8WAFRVKdA9VRRwIzoaWOZkgn98TeXvaEZ1nAKbGxyywvCac_0-nXcQg5dRiDbwUhBO-K5tlruhYJZGufIzny?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/PLNypfIT2jW-zO8jPo8Ezo28T29zUwczGbYAsrzpBSbI-BH4szrrdZauKidHPb8epB_haW7Jhb6XWMSHpgNUXm_ZLm_fOK2pwEqxzC4sQOoxVh5egLdsxX_skNMyaOZ6mIDf-YkfJ24Jk_mH6ohM-Zspv1QU6Esq6iXcMC0r9C9tHRIh3C8A-jbcP1IOcTY2?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/DoDueZ0aMvrV4B0iGmsxyULqu-_X_fyOT_aQzCEhvVTll8xg-pwlAf7JhxDpZvgdGDBNJC8mUryuzaSRHuCp1IUr3DS_Hm1GQu9UJdiVXU9JVxfcMnKAkLWh5OO-WMXW8ZhcBeNFdP5aw_tFr31pkdjHWf0bqScvfgXr9oCP593XO4uOlqGoEY_wx_rL3IVf?purpose=fullsize)

---

# 16. Tier I — Client

**Tier I** usually consists of the client-side application.

Examples include:

- Websites
    
- Web browsers
    
- GUI applications
    
- Mobile applications
    

The client handles high-level interactions.

Examples:

- User login
    
- Comment submission
    
- Searching
    
- Creating a post
    
- Updating a profile
    

For example:

```text
User
 ↓
Website
 ↓
"Login"
```

The user's interaction is then passed to Tier II.

---

# 17. Tier II — Application Server / Middleware

The second tier is the **middleware/application layer**.

It receives requests from Tier I and interprets them.

The application server converts high-level user actions into a form that the DBMS can understand.

For example:

```text
User clicks "Login"
        ↓
Client sends request
        ↓
Application Server
        ↓
Processes request
        ↓
Constructs database operation
        ↓
DBMS
```

The application layer may use specific:

- Libraries
    
- Database drivers
    
- APIs
    

depending on the DBMS being used.

---

# 18. Tier III — DBMS

The third tier consists of the **Database Management System** and the underlying database.

The DBMS receives queries from Tier II.

It then performs the requested operation.

Common operations include:

### INSERT

Adding information.

```sql
INSERT INTO users (...);
```

### SELECT

Retrieving information.

```sql
SELECT * FROM users;
```

### UPDATE

Changing existing information.

```sql
UPDATE users SET ...;
```

### DELETE

Removing information.

```sql
DELETE FROM users WHERE ...;
```

---

# 19. Database Response

After processing a query, the DBMS sends a response back to the application server.

The response may contain:

### Requested Data

For example:

```text
Username: alice
Role: user
```

or:

### Error Code

If the query is invalid:

```text
Database Error
```

The overall process is:

```text
┌──────────────┐
│    Client    │
│   Tier I     │
└──────┬───────┘
       │ Request
       ▼
┌──────────────┐
│ Application  │
│   Tier II    │
└──────┬───────┘
       │ SQL Query
       ▼
┌──────────────┐
│    DBMS      │
│   Tier III   │
└──────┬───────┘
       │
       │ Data / Error
       ▼
┌──────────────┐
│ Application  │
└──────┬───────┘
       │
       ▼
     Client
```

---

# 20. Application Server and DBMS on the Same Host

It is possible to host both:

- Application server
    
- DBMS
    

on the **same host**.

For example:

```text
┌────────────────────────────┐
│          Server            │
│                            │
│  ┌──────────────────────┐  │
│  │ Application Server   │  │
│  └──────────┬───────────┘  │
│             │              │
│             ▼              │
│  ┌──────────────────────┐  │
│  │        DBMS          │  │
│  └──────────────────────┘  │
│                            │
└────────────────────────────┘
```

This setup can be appropriate for smaller applications.

---

# 21. Separating the Application Server and Database

For databases containing large amounts of data and supporting many users, the database is typically hosted separately.

Example:

```text
             Internet
                │
                ▼
       ┌─────────────────┐
       │ Application     │
       │ Server           │
       └────────┬────────┘
                │
                │ Database Connection
                ▼
       ┌─────────────────┐
       │ Database Server │
       │     DBMS        │
       └─────────────────┘
```

### Why Separate Them?

Separating the database can improve:

- Performance
    
- Scalability
    
- Resource management
    
- Infrastructure organization
    

It also allows database infrastructure to be scaled independently from the application layer.

---

# 22. Complete Web Application Database Flow

A typical interaction looks like this:

```text
                USER
                 │
                 ▼
        ┌────────────────┐
        │ Web Browser /  │
        │ Client App     │
        │    Tier I      │
        └───────┬────────┘
                │
                │ HTTP / HTTPS
                ▼
        ┌────────────────┐
        │ Application    │
        │ Server         │
        │    Tier II     │
        └───────┬────────┘
                │
                │ SQL Query
                ▼
        ┌────────────────┐
        │      DBMS      │
        │    Tier III    │
        └───────┬────────┘
                │
                ▼
           DATABASE
                │
                │ Result
                ▼
        ┌────────────────┐
        │ Application    │
        │ Server         │
        └───────┬────────┘
                │
                ▼
              USER
```

---

# 23. Example — User Login

Consider a normal login process.

### Step 1 — User

The user enters:

```text
Username: alice
Password: ********
```

### Step 2 — Client

The browser sends the login request to the application server.

```text
Browser
   ↓
HTTP Request
```

### Step 3 — Application Server

The application processes the request and communicates with the database.

```text
Application
      ↓
Database Query
```

### Step 4 — DBMS

The DBMS searches the relevant database records.

```text
DBMS
 ↓
Users Table
 ↓
Credential Check
```

### Step 5 — Result

The database returns information to the application.

```text
Database
   ↓
Result
   ↓
Application
   ↓
Login Success / Failure
   ↓
User
```

---

# 24. Why This Architecture Matters for SQL Injection

Understanding this architecture is extremely important before learning SQL injection.

The potential SQL injection path is:

```text
Attacker
   ↓
Client Input
   ↓
Application Server
   ↓
SQL Query
   ↓
DBMS
```

The vulnerability generally occurs when **untrusted input from Tier I reaches SQL query construction in Tier II without proper protection**.

Conceptually:

```text
Untrusted Input
      ↓
Application
      ↓
Unsafe SQL Construction
      ↓
DBMS
      ↓
Unintended Query
```

This is why understanding how the application, middleware, and database communicate is essential before studying SQLi.

---

# 25. Key Terms

|Term|Meaning|
|---|---|
|Database|Organized collection of stored information|
|DBMS|Software used to manage databases|
|RDBMS|Relational Database Management System|
|SQL|Structured Query Language|
|NoSQL|Database systems using non-relational data models|
|Middleware|Application layer between client and DBMS|
|Client|Application through which the user interacts with the system|
|Database Driver|Software/library that allows an application to communicate with a DBMS|
|Query|Instruction sent to the database|
|Concurrency|Multiple users/processes accessing the database simultaneously|
|Consistency|Maintaining valid and logically correct data|
|Security|Controlling access to database resources|
|Reliability|Ability to recover and preserve data|
|CRUD|Create, Read, Update, Delete|

---

# 26. Important SQL Commands to Remember

For SQLi learning, these basic commands are particularly important.

### SELECT

Used to retrieve data.

```sql
SELECT * FROM users;
```

### INSERT

Used to add data.

```sql
INSERT INTO users VALUES (...);
```

### UPDATE

Used to modify data.

```sql
UPDATE users
SET username = 'newname';
```

### DELETE

Used to remove data.

```sql
DELETE FROM users
WHERE id = 1;
```

### WHERE

Used to filter records.

```sql
SELECT * FROM users
WHERE id = 1;
```

---

# 27. Database Architecture — Quick Comparison

|Architecture|Description|
|---|---|
|File-Based|Data stored directly in files|
|Single Host|Application server and DBMS on same machine|
|Three-Tier|Client → Application Server → DBMS|
|Separate DB Server|Application and database hosted separately|

---

# 28. Important Things to Memorize

> **DBMS stands for Database Management System.**

> **A DBMS helps create, define, host, and manage databases.**

> **SQL stands for Structured Query Language.**

> **SQL provides a way to interact with relational databases.**

> **RDBMS stores data in relational structures such as tables.**

> **DBMSs can be accessed through command-line tools, graphical interfaces, and APIs.**

> **Concurrency ensures multiple users can interact with a database without corrupting or losing data.**

> **Consistency ensures that data remains valid and consistent.**

> **Security controls access through authentication and permissions.**

> **Reliability allows databases to be backed up and restored.**

> **Tier I usually contains the client application.**

> **Tier II contains the application server/middleware.**

> **Tier III contains the DBMS/database.**

> **The application server translates user actions into operations that the DBMS can perform.**

> **The DBMS can perform insertion, retrieval, deletion, and updating of data.**

> **The application server and DBMS can run on the same host, but large systems often separate them for performance and scalability.**

---

# 29. Quick Revision

## What is a Database?

An organized collection of information that applications can store and retrieve.

## What is a DBMS?

Software used to create, manage, and interact with databases.

## What is SQL?

A language used to communicate with relational databases.

## What are the Main DBMS Features?

```text
Concurrency
Consistency
Security
Reliability
SQL Support
```

## What are the Three Tiers?

```text
Tier I   → Client
Tier II  → Application Server / Middleware
Tier III → DBMS / Database
```

## What Can a DBMS Do?

```text
INSERT
SELECT
UPDATE
DELETE
```

## Why Separate the Database Server?

Primarily to improve:

```text
Performance
Scalability
Resource Management
```

---

# 30. Final Takeaway

Before learning SQL Injection, understand this fundamental relationship:

```text
             USER
               │
               ▼
        ┌─────────────┐
        │   CLIENT    │
        │   TIER I    │
        └──────┬──────┘
               │
               │ Request
               ▼
        ┌─────────────┐
        │ APPLICATION │
        │   TIER II   │
        └──────┬──────┘
               │
               │ SQL Query
               ▼
        ┌─────────────┐
        │    DBMS     │
        │   TIER III  │
        └──────┬──────┘
               │
               ▼
          DATABASE
```

The **client** generates user interactions.

The **application server** processes those interactions and communicates with the database.

The **DBMS** receives database queries and performs operations such as:

- Inserting data
    
- Retrieving data
    
- Updating data
    
- Deleting data
    

The database then returns the requested data or an error.

### The Connection to SQL Injection

The most important concept to carry into the next section is:

```text
User Input
    ↓
Application Server
    ↓
SQL Query
    ↓
DBMS
```

If an application incorrectly allows **untrusted user input to influence the structure of an SQL query**, SQL Injection can become possible.

That is why understanding **databases + DBMS + SQL + three-tier architecture** is the foundation for understanding SQL Injection.