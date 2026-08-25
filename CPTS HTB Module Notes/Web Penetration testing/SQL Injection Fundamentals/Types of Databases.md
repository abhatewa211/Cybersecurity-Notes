![Image](https://images.openai.com/static-rsc-4/Z7EiZiIaAPNHJqlobhTj3JfnlTV03RE5QgHpEoKdrRIbsdwmMPCEurFH5e9n4i7mbb3DEHxwXuKCpUinV37_0RhO_qFKNv5JoNhRF-dLEkGrUuYjNAEhvHSe1TWeqWP-UamQWYAV_1H64gQAK9JKVxfJDKsVEDs3iZqEf8Cq-ZIVhh3Y18JFi8IehBsZ7C66?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/L8g105y5Oeb7UvpHfAGgGRZk0z4W9sXlywXRHBSB9I2Rt6J6b4uuS-LOJubeRgiG9jdfAEt7wMbeZ9zTWj-0D3QaNCI3FNmfXkqSX173zf8Jb5XOOwc6v2x64_aqw0W1YTmO56ZtPp3gZ8szrOkzUGD0vr1IOPh0K3BaPt8RylM7IdNyhQESdGLQzKl3fFfj?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/buUe9t5LTd6CmmTCpWCuCKwNkq2PeDEuNR9vOB-Mhxtgvuzgvy6POZG9wRt3bitV2BIP-X_p6XxmOL6LnDkFUNx47Oa8NUXANVr3-61t8CV0SFKOZLeq2el1XZlOvASubmR7YKFFoSJ7qiiyDAlCt7K8q8IKiH8bfojcc8Ka1yJtZ41r7m_VvaLTAYAgkhTR?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/R_eIDvtS-irJIshdPTfJD-lCyCFWhnxjjnHukw2Lfj3G_h_cTytiucyxKb2juk2azMAaRqZ2tCT55zuHFaIWqyr8485fpaHyASzfPbaiLwI1xuuZpLKdM9F1Sc-vXCqMaX8u8wvpRl0DHpBsNVhN4HYFGRF4_oWfN3-d_l-LqTC9PvcNrX-z4NC-fHPc7-od?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/h8TXmcdPereSdd82yZU-VzvidqtRQRReqpv7ZjOscpWHYADtxmhLPJAzB2vzbS47El95hqt0aPndPaMlY2-_5cOu_rl5gNWy87hsUf_hze808d-YplKNbuSbvQ_--OtN3W0NTnE98RK803HxBFle8-7Ntqc2xuuztKz897ux-hg9wPgEQ82zFgMcbv1l_nJM?purpose=fullsize)
## 1. Introduction

Databases are generally divided into two major categories:

```text
                    DATABASES
                       │
              ┌────────┴────────┐
              ▼                 ▼
       RELATIONAL          NON-RELATIONAL
        DATABASES              DATABASES
          (SQL)                (NoSQL)
```

### Two Main Types

1. **Relational Databases**
    
2. **Non-Relational Databases (NoSQL)**
    

The major difference is how they **structure and store data** and how applications communicate with them.

> **Relational databases commonly use SQL, while non-relational databases use different data models and query/communication methods.**

---

# 2. Relational Databases

A **relational database** is the most common traditional type of database.

It organizes data into **tables**, with each table containing:

- Rows
    
- Columns
    
- Keys
    
- Relationships with other tables
    

Relational databases generally use a predefined **schema** to define how data is structured.

---

# 3. What is a Schema?

A **schema** is the structure or template that defines how data is organized in a relational database.

It describes things such as:

- Tables
    
- Columns
    
- Data types
    
- Keys
    
- Relationships between tables
    
- Constraints
    

Conceptually:

```text
                 DATABASE
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
      Users        Posts       Comments
        │            │            │
        └────────────┼────────────┘
                     │
               Relationships
```

### Important Definition

> **A schema defines the structure and relationships of the data within a database.**

---

# 4. Relational Database Tables

Relational databases store information in tables.

For example, a company selling products might have several tables.

### Customers

```text
+----+----------+-------------+--------------+
| ID | Name     | Address     | Contact      |
+----+----------+-------------+--------------+
| 1  | Alice    | Delhi       | 9999999999   |
| 2  | Bob      | Mumbai      | 8888888888   |
+----+----------+-------------+--------------+
```

### Products

```text
+----+------------+-------+
| ID | Product    | Price |
+----+------------+-------+
| 10 | Laptop     | 70000 |
| 11 | Keyboard   | 2000  |
+----+------------+-------+
```

### Orders

```text
+----------+------------+----------+----------+
| Order ID | Customer ID| Product ID| Quantity |
+----------+------------+----------+----------+
| 1001     | 1          | 10       | 1        |
| 1002     | 2          | 11       | 2        |
+----------+------------+----------+----------+
```

Instead of repeating all customer and product information inside every order, the order table can simply store the relevant IDs.

---

# 5. Rows and Columns

A relational table consists primarily of **rows and columns**.

### Column

A column represents a particular attribute.

Example:

```text
id
username
first_name
last_name
```

### Row

A row represents one record.

Example:

```text
1 | arjun | Arjun | Bhatewara
```

So:

```text
Table
 │
 ├── Columns → Properties / Attributes
 │
 └── Rows → Individual Records
```

---

# 6. Keys in Relational Databases

Keys are extremely important in relational databases.

They allow records to be uniquely identified and tables to be connected.

For example:

```text
users

+----+----------+------------+
| id | username | first_name |
+----+----------+------------+
| 1  | alice    | Alice      |
| 2  | bob      | Bob        |
+----+----------+------------+
```

The `id` column can uniquely identify a user.

---

# 7. Primary Key

A **primary key** is a column or combination of columns used to uniquely identify records within a table.

Example:

```text
users

+----+----------+
| id | username |
+----+----------+
| 1  | alice    |
| 2  | bob      |
| 3  | charlie  |
+----+----------+
```

Here:

```text
id = Primary Key
```

Each user can be identified using their unique ID.

### Important

A primary key should uniquely identify each record.

---

# 8. Foreign Keys

A **foreign key** is used to establish a relationship between tables.

Consider:

### Users

```text
+----+----------+
| id | username |
+----+----------+
| 1  | alice    |
| 2  | bob      |
+----+----------+
```

### Posts

```text
+----+---------+------------+
| id | user_id | content    |
+----+---------+------------+
| 10 | 1       | Hello!     |
| 11 | 2       | Hi there!  |
+----+---------+------------+
```

The `posts.user_id` value refers to `users.id`.

```text
users.id
   │
   │ relationship
   ▼
posts.user_id
```

This allows the database to determine which user created each post.

---

# 9. Relational Database Example

A common web application database might contain:

```text
┌─────────────────┐
│      users      │
├─────────────────┤
│ id              │
│ username        │
│ first_name      │
│ last_name       │
└────────┬────────┘
         │
         │ users.id
         │
         ▼
┌─────────────────┐
│      posts      │
├─────────────────┤
│ id              │
│ user_id         │
│ date            │
│ content         │
└─────────────────┘
```

The relationship can be represented as:

```text
users.id ─────────► posts.user_id
```

This means a post can reference the user who created it.

---

# 10. Why Use IDs Instead of Repeating Information?

Suppose Alice creates 100 posts.

A poorly designed database could store:

```text
Post 1 → Alice, Alice's address, Alice's phone, ...
Post 2 → Alice, Alice's address, Alice's phone, ...
Post 3 → Alice, Alice's address, Alice's phone, ...
...
Post 100 → Alice, Alice's address, Alice's phone, ...
```

This creates unnecessary duplication.

A relational design can instead store:

```text
users

id = 1
username = alice
```

and then:

```text
posts

id = 101
user_id = 1

id = 102
user_id = 1

id = 103
user_id = 1
```

The posts only need the user's ID.

### Benefits

- Less duplicated data
    
- Easier updates
    
- Better organization
    
- More efficient storage
    
- Easier relationships
    

---

# 11. Multiple Relationships

A table can participate in relationships with multiple other tables.

For example:

```text
             users
               │
               │ user_id
               ▼
             posts
               │
               │ post_id
               ▼
           comments
```

This allows the database to connect:

```text
User
 ↓
Posts
 ↓
Comments
```

For example, we could retrieve:

> All comments made on posts created by a particular user.

This is one of the major strengths of relational databases.

---

# 12. Relational Database Management System (RDBMS)

A **Relational Database Management System (RDBMS)** is a DBMS designed to manage relational databases.

It provides mechanisms for:

- Creating tables
    
- Storing data
    
- Retrieving data
    
- Updating data
    
- Deleting data
    
- Managing relationships
    
- Enforcing constraints
    
- Managing permissions
    

### Examples of RDBMS

Common examples include:

- MySQL
    
- Microsoft Access
    
- Microsoft SQL Server
    
- Oracle
    
- PostgreSQL
    
- SQLite
    

The module primarily focuses on **MySQL**.

---

# 13. How Relational Databases Connect Data

The key concept is:

```text
Table A
   │
   │ Key
   ▼
Table B
   │
   │ Key
   ▼
Table C
```

For example:

```text
users
  │
  │ id
  ▼
posts
  │
  │ id
  ▼
comments
```

This structure lets the database retrieve related information efficiently.

---

# 14. Relational Database Query Example

Suppose we have:

```text
users
+----+----------+
| id | username |
+----+----------+
| 1  | alice    |
| 2  | bob      |
+----+----------+
```

and:

```text
posts
+----+---------+-------------+
| id | user_id | content     |
+----+---------+-------------+
| 10 | 1       | Hello       |
| 11 | 2       | Welcome     |
+----+---------+-------------+
```

SQL can connect the two tables:

```sql
SELECT users.username, posts.content
FROM users
JOIN posts
ON users.id = posts.user_id;
```

Conceptually:

```text
users
  │
  │ JOIN
  ▼
posts
  │
  ▼
Combined Information
```

This demonstrates the power of relational databases.

---

# 15. Advantages of Relational Databases

Relational databases are particularly useful when data has a **clear and predictable structure**.

Advantages include:

### 1. Structured Data

Data follows a predefined schema.

### 2. Relationships

Tables can be linked through keys.

### 3. Efficient Queries

Related information can be retrieved through SQL queries.

### 4. Reduced Duplication

Data can be normalized and stored efficiently.

### 5. Consistency

Relationships and constraints help maintain valid data.

### 6. Mature Technology

Relational databases have been extensively used for many years.

---

# 16. When Relational Databases Are Useful

Relational databases work especially well when:

- Data is structured
    
- Relationships are important
    
- Data integrity is important
    
- Complex queries are required
    
- The schema is relatively well defined
    

Examples:

```text
Banking
E-commerce
Accounting
Inventory
Education
Customer Management
```

---

# 17. Non-Relational Databases

A **non-relational database**, commonly called a **NoSQL database**, does not use the traditional relational model.

Unlike relational databases, NoSQL databases may not organize data into:

- Tables
    
- Rows
    
- Columns
    
- Traditional primary-key/foreign-key relationships
    
- A fixed relational schema
    

Instead, NoSQL databases use different storage models depending on the type of data.

---

# 18. Why Use NoSQL?

NoSQL databases can provide:

- Flexibility
    
- Scalability
    
- Different data representations
    
- Support for less structured datasets
    

They can be particularly useful when the data structure is:

- Flexible
    
- Frequently changing
    
- Not clearly defined
    
- Large and distributed
    

Conceptually:

```text
Relational

Fixed / Defined Structure
          ↓
       Tables
          ↓
Relationships
```

versus:

```text
NoSQL

Flexible Structure
       ↓
Different Storage Models
       ↓
Documents / Key-Value / Graph / Wide-Column
```

---

# 19. Four Common NoSQL Storage Models

The four common storage models introduced here are:

```text
                 NoSQL
                   │
       ┌───────────┼───────────┐
       ▼           ▼           ▼
   Key-Value    Document    Wide-Column
                              
                   │
                   ▼
                 Graph
```

Specifically:

1. **Key-Value**
    
2. **Document-Based**
    
3. **Wide-Column**
    
4. **Graph**
    

Each model stores and organizes data differently.

---

# 20. Key-Value Databases

A **Key-Value** database stores data as pairs:

```text
KEY → VALUE
```

For example:

```text
username → arjun
theme    → dark
language → English
```

The key identifies the associated value.

The value can potentially contain more complex data.

---

# 21. Key-Value Example Using JSON

A key-value style structure can look like:

```json
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

Here:

```text
100001 → Value
100002 → Value
100003 → Value
```

The numeric-looking strings act as keys.

Each key points to a corresponding object containing the data.

---

# 22. Similarity to Programming Dictionaries

The key-value concept is similar to dictionaries or associative arrays in programming languages such as Python or PHP.

### Python Example

```python
{
    "username": "arjun",
    "role": "user"
}
```

The structure is:

```text
Key       → Value
username  → arjun
role      → user
```

The value does not necessarily have to be a simple string.

It can potentially be:

- String
    
- Number
    
- Dictionary/object
    
- Array
    
- Complex object
    

depending on the data model and serialization format.

---

# 23. Document-Based Databases

Document databases store data as **documents**.

A document can contain nested structures and different fields.

For example:

```json
{
  "username": "alice",
  "age": 20,
  "posts": [
    {
      "title": "Hello",
      "content": "My first post"
    }
  ]
}
```

The document can contain nested data.

This provides considerable flexibility compared with a rigid relational table structure.

---

# 24. Wide-Column Databases

Wide-column databases organize data around columns or column families rather than traditional relational tables.

They are designed for particular large-scale and distributed data workloads.

Conceptually:

```text
Column Family
       │
       ├── Column A
       ├── Column B
       ├── Column C
       └── Column D
```

The exact implementation varies between database systems.

---

# 25. Graph Databases

Graph databases represent data using:

- Nodes
    
- Relationships/Edges
    
- Properties
    

For example:

```text
       Alice
        │
      FRIEND
        │
        ▼
        Bob
        │
      WORKS_AT
        │
        ▼
      Company
```

Graph databases are useful when **relationships between entities** are the primary focus.

Examples of use cases include:

- Social networks
    
- Recommendation systems
    
- Network analysis
    
- Fraud detection
    
- Knowledge graphs
    

---

# 26. Relational vs Non-Relational

This is one of the most important comparisons in the topic.

|Feature|Relational|Non-Relational / NoSQL|
|---|---|---|
|Structure|Tables|Varies by model|
|Rows/Columns|Yes|Not necessarily|
|Fixed Schema|Generally yes|Often flexible|
|Relationships|Core feature|Depends on model|
|Primary/Foreign Keys|Common|Not traditional|
|Query Method|SQL commonly used|Varies|
|Flexibility|More structured|Generally more flexible|
|Typical Use|Structured relational data|Flexible/distributed data|
|Examples|MySQL, PostgreSQL, Oracle|MongoDB and others|

---

# 27. SQL vs NoSQL

The distinction is particularly important for security testing.

### SQL

Relational databases commonly use SQL.

```text
Application
     ↓
SQL
     ↓
RDBMS
     ↓
Relational Database
```

### NoSQL

NoSQL databases use different query and communication mechanisms depending on their model.

```text
Application
     ↓
NoSQL Query / API
     ↓
NoSQL Database
```

Therefore:

> **SQL injection and NoSQL injection are different vulnerabilities.**

---

# 28. SQL Injection vs NoSQL Injection

### SQL Injection

Targets relational database query languages.

```text
User Input
   ↓
SQL Query
   ↓
Relational DB
   ↓
SQL Injection
```

### NoSQL Injection

Targets applications using NoSQL databases.

```text
User Input
   ↓
NoSQL Query / Object
   ↓
NoSQL DB
   ↓
NoSQL Injection
```

The techniques are **not interchangeable**.

> **SQL injections are completely different from NoSQL injections.**

NoSQL injection is covered separately from SQL injection.

---

# 29. Example: Relational vs NoSQL Representation

Suppose we want to store a user and their posts.

### Relational Approach

We might use separate tables:

```text
users
+----+----------+
| id | username |
+----+----------+
| 1  | alice    |
+----+----------+

posts
+----+---------+-------------+
| id | user_id | content     |
+----+---------+-------------+
| 10 | 1       | Hello!      |
+----+---------+-------------+
```

Relationship:

```text
users.id
   │
   ▼
posts.user_id
```

### Document Approach

The same information could be represented as a document:

```json
{
  "id": 1,
  "username": "alice",
  "posts": [
    {
      "id": 10,
      "content": "Hello!"
    }
  ]
}
```

The structures are fundamentally different.

---

# 30. Schema Flexibility

One of the key differences between relational and NoSQL databases is how structure is handled.

### Relational

The structure is generally defined beforehand.

```text
users
 ├── id
 ├── username
 ├── first_name
 └── last_name
```

A new field may require a schema change.

### NoSQL

A document can potentially contain different fields from another document.

```json
{
  "username": "alice",
  "age": 20
}
```

Another document could contain:

```json
{
  "username": "bob",
  "country": "India",
  "interests": ["football", "gaming"]
}
```

This flexibility can be useful when data structures change frequently.

---

# 31. Scalability

NoSQL databases are often associated with highly scalable and distributed systems.

Their flexible models can make them useful for certain large-scale workloads.

However, it is important not to think:

> "NoSQL is always faster."

Database performance depends on:

- Data model
    
- Query patterns
    
- Hardware
    
- Indexing
    
- Architecture
    
- Workload
    
- Database implementation
    

The correct choice depends on the application's requirements.

---

# 32. Why Relational Databases Are Important for This Module

This module focuses on **MySQL**, which is a relational database system.

Understanding relational databases is therefore essential for understanding SQL injection.

The basic model is:

```text
Database
   │
   ├── users
   │     ├── id
   │     ├── username
   │     └── password
   │
   ├── posts
   │     ├── id
   │     ├── user_id
   │     └── content
   │
   └── comments
         ├── id
         ├── post_id
         └── content
```

Relationships allow these tables to work together.

---

# 33. Database Relationships — Big Picture

A more complete example:

```text
                   USERS
                     │
                     │ user_id
                     ▼
                   POSTS
                     │
                     │ post_id
                     ▼
                 COMMENTS
```

One user can have many posts.

One post can have many comments.

This can be represented conceptually as:

```text
User
 │
 ├── Post 1
 │    ├── Comment 1
 │    └── Comment 2
 │
 └── Post 2
      ├── Comment 3
      └── Comment 4
```

This is an example of how relational databases can represent complex relationships between entities.

---

# 34. Important Terminology

|Term|Meaning|
|---|---|
|Relational Database|Database that organizes data into related tables|
|RDBMS|Relational Database Management System|
|NoSQL|Non-relational database systems|
|Schema|Structure defining database organization|
|Table|Collection of related records|
|Row|Individual record|
|Column|Attribute/field|
|Primary Key|Uniquely identifies a record|
|Foreign Key|References a key in another table|
|Entity|A logical object represented within a database|
|Key-Value|Data stored as key → value pairs|
|Document|Self-contained structured data record|
|Wide-Column|Data organized around column families|
|Graph|Data represented as nodes and relationships|
|SQL Injection|Injection against SQL-based database queries|
|NoSQL Injection|Injection against NoSQL query mechanisms|

---

# 35. Most Important Concepts to Memorize

> **Databases are broadly categorized as relational and non-relational.**

> **Relational databases use structured tables, rows, columns, and relationships.**

> **Relational databases commonly use SQL.**

> **An RDBMS manages relational databases.**

> **A schema defines the structure and relationships of a relational database.**

> **Primary keys uniquely identify records.**

> **Foreign keys can connect records between tables.**

> **Relational databases are especially useful when data has a clear and structured design.**

> **NoSQL databases use different storage models rather than the traditional relational table model.**

> **The four common NoSQL models are Key-Value, Document-Based, Wide-Column, and Graph.**

> **Key-Value databases store data as key → value pairs.**

> **Document databases store information as documents, often allowing nested structures.**

> **Graph databases focus on nodes and relationships.**

> **NoSQL databases are often chosen for flexible or less-defined data structures.**

> **MongoDB is a common example of a NoSQL database.**

> **SQL Injection and NoSQL Injection are different vulnerabilities.**

---

# 36. Quick Revision Sheet

## Two Main Database Categories

```text
DATABASES
│
├── RELATIONAL
│   ├── Tables
│   ├── Rows
│   ├── Columns
│   ├── Keys
│   ├── Relationships
│   ├── Schema
│   └── SQL
│
└── NON-RELATIONAL / NoSQL
    ├── Key-Value
    ├── Document
    ├── Wide-Column
    └── Graph
```

---

## Relational Database

```text
Users
  │
  │ ID
  ▼
Posts
  │
  │ ID
  ▼
Comments
```

**Main idea:** structured data + relationships.

---

## NoSQL Database

```text
             NoSQL
               │
      ┌────────┼────────┐
      ▼        ▼        ▼
 Key-Value  Document  Graph
                  \
                   ▼
               Wide-Column
```

**Main idea:** flexible data models.

---

# 37. Final Takeaway

The most important distinction is:

```text
             DATABASES
                 │
        ┌────────┴────────┐
        ▼                 ▼
   RELATIONAL          NoSQL
        │                 │
     Tables          Flexible Models
        │                 │
     Schema          Less Rigid Structure
        │                 │
     SQL            Different Query Methods
        │                 │
     MySQL             MongoDB
```

### Relational Databases

Think:

**Tables → Rows → Columns → Keys → Relationships → Schema → SQL**

### NoSQL Databases

Think:

**Flexible Structure → Different Models → Key-Value / Document / Wide-Column / Graph**

And for the security side:

```text
Relational Database
        ↓
       SQL
        ↓
   SQL Injection


NoSQL Database
        ↓
 Different Query Model
        ↓
  NoSQL Injection
```

The two injection types should **not be treated as the same thing**.

For this module, the key database to remember is:

> **MySQL → Relational Database → RDBMS → SQL → SQL Injection**