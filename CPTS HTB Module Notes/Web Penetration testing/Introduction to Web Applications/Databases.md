# What is a Database?

A **Database** is a structured storage system used by web applications to store, manage, organize, and retrieve data efficiently.

Without databases, modern web applications would not be able to:

- Store user accounts
    
- Save passwords
    
- Store posts/comments
    
- Maintain sessions
    
- Save uploaded files
    
- Track orders and payments
    

### Simple Definition

> A database is a system that stores information so web applications can quickly retrieve and update it.

---

# Why Do Web Applications Need Databases?

Web applications constantly need to:

```text
Store Data
     ↓
Retrieve Data
     ↓
Modify Data
     ↓
Delete Data
```

Examples:

|Web Application|Stored Data|
|---|---|
|Facebook|Users, Posts, Comments|
|Amazon|Products, Orders, Payments|
|Instagram|Photos, Users, Followers|
|Banking App|Accounts, Transactions|

---

# Database Position in Web Architecture

```text
Client Browser
       ↓
Web Server
       ↓
Application
       ↓
Database
```

---

## Data Flow

```mermaid
flowchart TD
A[User] --> B[Web Server]
B --> C[Application]
C --> D[Database]
D --> C
C --> B
B --> A
```

---

# What Can Databases Store?

Databases store:

### User Data

```text
Username
Password Hashes
Emails
Phone Numbers
```

---

### Application Content

```text
Posts
Comments
Messages
Notifications
```

---

### Media Files

```text
Images
Videos
Documents
```

---

### Business Data

```text
Orders
Invoices
Transactions
Logs
```

---

# Types of Databases

The HTB module focuses on two major categories:

```text
Databases
│
├── Relational (SQL)
│
└── Non-Relational (NoSQL)
```

---

# Relational Databases (SQL)

## Definition

Relational databases store data in:

- Tables
    
- Rows
    
- Columns
    

Relationships are created between tables using keys.

---

# SQL Database Structure

Example:

### Users Table

|id|username|first_name|last_name|
|---|---|---|---|
|1|admin|John|Smith|
|2|user1|Jane|Doe|

---

### Posts Table

|id|user_id|date|content|
|---|---|---|---|
|1|1|01-01-2021|Hello World|
|2|2|02-01-2021|My First Post|

---

# Visualization

![Image](https://images.openai.com/static-rsc-4/hkLwfXzOCOusfyTq0Y3PzhZ7V8M1edypZ2t-KiBnFdnXYvQdpyIZbRIfk4uMbsntu5DnOSFlkJhWyLigorOaqE8Zqcey3YV4kN2MSlV86AYE_C43Rk54n6WA3O81R1TuQFMdc18azu4XUN2jOj4F-KOMtHlYG-7U3cqFo85NcEVo3X3ulmTXSe7E3zCxMcfk?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Tw-GiyhkBELKIrQQRYb7Hl9oBSp0AiNshZ-E7Xot3l8n_1RdYzs3PyliQzfDuCawgneS5fLTlbEDqmcdDxmVvTWngfFHRPDEdZ1BeN3YV38umkK2eP5gYpNI2QFB6CdNfxKyIxb04NRj5RKvJDNafbvTbYZ3ydmLtD0LuBCVyt1RbYYWzZADKEk8pc7AGA8h?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Dk8rr9p0-6CcvPvoCi5LP75TJG7wKafExFfyhSg8OzjGCVeSDxabkQX-iKkJDYv1I7xyeRNQUQXaqzp8ie7ruZt8bzV5nJunchelRq-TzWH0uIAE33DJFB-wkVL08qoB4_nN69RWiIu51LLAFVX6MtIrsPOVUtat2Vgtqiwgli4FCRFrhPDsGJGob3P7Gw4A?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/0Ph8ZtcfNcV2b0UOfXuEMlHyKlT3ueasyfvXAf9w4lGfakM21wP__FzBQbsL2qmkr7ngDo7UIcU2nJk9t2xf6NQLBIojUSYAOYZA6ay2Vj3_M8RYaj_uz2VfzMCo3oEPd1qyCeLe2GwAsbQV-g4MSJrKFQkX1xdEmf_Xm7yPdAOgkXU_GhEgTmIrs0rj273X?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/la157OrP4UYCk1kAgrnAyaFwnKoeD4OG2UJVeuLkWos380-conMnBHjq7gJaVYk-m3xX-IxZamIf0T5LmTXk0U511KnOwrjUhdc7zZuwpgifLUq3MEoRAeaGKDSj6zQFuTqwX5_qjV8f3zRzFhjoV3gyh90menwHc_HdO_wKl4t6Ywpe9O-KVtF4JG8rj2rT?purpose=fullsize)

---

# Primary Keys

A **Primary Key** uniquely identifies each row.

Example:

```text
users.id
```

|id|username|
|---|---|
|1|admin|
|2|user1|

No duplicate IDs allowed.

---

# Foreign Keys

A **Foreign Key** links tables together.

Example:

```text
posts.user_id
```

references:

```text
users.id
```

---

# Relationship Example

```text
users.id
      ↓
posts.user_id
```

---

## Diagram

```mermaid
flowchart LR
A[users.id] --> B[posts.user_id]
```

---

# What is a Schema?

### HTB Important Definition

> The relationship between tables inside a database is called a **Schema**.

---

# Example Schema

```text
Users
   ↓
Posts
   ↓
Comments
```

---

## Visualization

```mermaid
flowchart TD
A[Users]
B[Posts]
C[Comments]

A --> B
B --> C
```

---

# Advantages of SQL Databases

✅ Fast Queries

✅ Structured Data

✅ Data Integrity

✅ Relationships

✅ Reliable

✅ Mature Technology

---

# Popular SQL Databases

---

## 1. MySQL

### HTB Notes

- Most common database on the internet
    
- Open Source
    
- Free
    

Used by many PHP applications.

---

### Features

```text
Fast
Reliable
Easy to Learn
Large Community
```

---

## 2. Microsoft SQL Server (MSSQL)

### HTB Notes

Microsoft's relational database.

Commonly used with:

```text
Windows Server
IIS
ASP.NET
```

---

### Features

```text
Enterprise Ready
Active Directory Integration
Microsoft Ecosystem
```

---

## 3. Oracle Database

### HTB Notes

Designed for large enterprises.

---

### Features

```text
Very Reliable
Advanced Features
High Performance
```

---

### Drawback

```text
Expensive
```

---

## 4. PostgreSQL

### HTB Notes

Open-source relational database.

Designed to be:

```text
Extensible
Flexible
Feature Rich
```

---

### Features

```text
Advanced SQL
High Reliability
Strong Security
```

---

# Other SQL Databases

- SQLite
    
- MariaDB
    
- Amazon Aurora
    
- Azure SQL
    

---

# SQL Database Comparison

|Database|Cost|Popularity|
|---|---|---|
|MySQL|Free|Very High|
|MSSQL|Paid|High|
|Oracle|Expensive|Enterprise|
|PostgreSQL|Free|High|

---

# Non-Relational Databases (NoSQL)

## Definition

NoSQL databases do NOT use:

❌ Tables

❌ Rows

❌ Columns

❌ Relationships

❌ Schemas

---

Instead, they use flexible storage models.

---

# Why NoSQL?

Useful when data is:

```text
Large
Unstructured
Rapidly Changing
Highly Scalable
```

---

# SQL vs NoSQL

|Feature|SQL|NoSQL|
|---|---|---|
|Tables|Yes|No|
|Fixed Schema|Yes|No|
|Relationships|Yes|No|
|Scalability|Moderate|Excellent|
|Flexibility|Lower|High|

---

# NoSQL Storage Models

HTB identifies four models:

```text
1. Key-Value
2. Document-Based
3. Wide-Column
4. Graph
```

---

# 1. Key-Value Model

Stores data as:

```text
Key → Value
```

---

Example:

```json
{
  "100001":"Welcome",
  "100002":"First Post",
  "100003":"Reminder"
}
```

---

## Visualization

```text
100001 → Welcome
100002 → First Post
100003 → Reminder
```

---

# 2. Document-Based Model

Stores data as complex JSON objects.

---

Example

```json
{
  "id":100001,
  "date":"01-01-2021",
  "content":"Welcome"
}
```

---

# HTB Example JSON

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

---

# JSON Visualization

![Image](https://images.openai.com/static-rsc-4/dxdXkvgYYBGgaB2t8ZyyEqmJFhPJtqpd5OQcO2sYPIx9mJj6AM9DoNIC7ASOtgga3AGFcuWyLbxB_mPjcrCeC1ldYOoMnS30GrxbHRXu22tib5tJREBRqTicUI1f_A6YqeimE9DuaEMKIKq2OQsxpdXsWrqT5tUwJtuJyQHfNl-c03PGvtFjy4Z0zl_Lua5l?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Bjon9LIGipdvXdgTNjhsNH7O4GLnkF3XhgEYRByaaF34WgK99bzbrX0Ya5w88FILx9JnkyZMZIYMAFvfbXI_efKaMshlI9IcdCRkIDmTnaO3g4tD5GxA2r4w7b_Kw9-DqWTBc9agQNxHqMacjgMyg-zd1KzoGLu8_ac68CI5FTdA4C3T-jWyeK64PjYhqvrQ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/CwTHqvNKve3SfXjrJOljJYPF9y7-5DTuQVYBhklUSefABl_nMjrF2ZnxjYn5-q2itkI4f7uB0c2O1ezHYda0Sxbm4mgfbhrY0QRTNSMaBECsHTlO3RMVWphaN6bC9WZ8wYjOFA_tyilhlPudhDexYS8kG67_dWYfCIsOR_X7Speg_xt8twj0aWgX-T_3cQIg?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/cJumxSzxRPzVdyZe1t32ofLu357Hofc1pdZqn9mBJ44VtSB6ROl8PSuu_ypAicURIgMmf-L_sFnVu058SGqEtJL8eW3TM_L0ulwnFXsLrXgAalDdi8Kyzu2B3myjpJR8F3hUx9joWrwDNV8RQhm7ntMOgIe_-prC6tlHzjOWYaD9dUdG4M6h2ZF9Wp5vff95?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/X640L7lKvV55_0wiwuJgOCxYJ2jRWpQ_S6vaSPbW6L-gAhg1zw6ArAx1-Rtbv5bGWx9sUNuR949_35t1f9hMA6r6SLfvKbZtFPQcuXbBbP1SfNM3nX7jCbDGya0cKgzNxfZvxkO7NMSA37Gynn156nrEq-aAxhrtnfFujY1mmZ4yoiAtyvzV-0hTKNBidnPH?purpose=fullsize)

---

# 3. Wide-Column Model

Stores data in dynamic columns.

Useful for:

```text
Massive Datasets
Analytics
Big Data
```

---

# 4. Graph Model

Stores:

```text
Nodes
Edges
Relationships
```

---

Used for:

```text
Social Networks
Recommendations
Fraud Detection
```

---

# Popular NoSQL Databases

---

## MongoDB

### HTB Notes

Most popular NoSQL database.

Uses:

```text
Document-Based Model
```

Stores:

```text
JSON Documents
```

---

### Features

```text
Fast
Flexible
Highly Scalable
```

---

## ElasticSearch

### HTB Notes

Optimized for:

```text
Searching
Indexing
Analytics
```

---

### Features

```text
Very Fast Search
Large Dataset Handling
```

---

## Apache Cassandra

### HTB Notes

Designed for:

```text
Massive Scale
Fault Tolerance
```

---

### Features

```text
Distributed
Highly Available
Scalable
```

---

# Other NoSQL Databases

- Redis
    
- Neo4j
    
- CouchDB
    
- Amazon DynamoDB
    

---

# SQL vs NoSQL Architecture

```text
SQL
│
├── Tables
├── Rows
├── Columns
└── Relationships

NoSQL
│
├── Key-Value
├── Documents
├── Graphs
└── Wide Columns
```

---

# Using Databases in Web Applications

Before use:

```text
Install Database
       ↓
Configure Database
       ↓
Connect Application
       ↓
Store/Retrieve Data
```

---

# PHP Database Connection

HTB Example:

```php
$conn = new mysqli(
"localhost",
"user",
"pass"
);
```

---

# Creating Database

HTB Example:

```php
$sql =
"CREATE DATABASE database1";

$conn->query($sql);
```

---

# Connecting to Database

```php
$conn = new mysqli(
"localhost",
"user",
"pass",
"database1"
);
```

---

# Querying Data

```php
$query =
"select * from table_1";

$result =
$conn->query($query);
```

---

# Search Function Example

### User Input

```php
$searchInput =
$_POST['findUser'];
```

---

### Query

```php
$query =
"select * from users
where name like
'%$searchInput%'";
```

---

### Execute

```php
$result =
$conn->query($query);
```

---

### Output Results

```php
while(
$row =
$result->fetch_assoc()
){
    echo $row["name"];
}
```

---

# Database Security Risk

⚠️ Important HTB Point

The query:

```php
$query =
"select * from users
where name like
'%$searchInput%'";
```

directly inserts user input into SQL.

---

### Risk

```text
SQL Injection
```

---

# Attack Flow

```text
User Input
      ↓
SQL Query
      ↓
Database
      ↓
Result
```

If input is not validated:

```text
User Input
      ↓
Malicious SQL
      ↓
Database Manipulation
```

---

# Database Selection Guide

|Requirement|Best Choice|
|---|---|
|Structured Data|SQL|
|Relationships|SQL|
|Scalability|NoSQL|
|Unstructured Data|NoSQL|
|Analytics|ElasticSearch|
|Social Networks|Graph DB|
|Enterprise Apps|MSSQL / Oracle|
|PHP Websites|MySQL|

---

# Important HTB Exam Points

### Remember

✅ Databases store:

- Users
    
- Passwords
    
- Posts
    
- Files
    
- Application Data
    

---

✅ Main Types:

```text
SQL
NoSQL
```

---

✅ SQL Uses:

```text
Tables
Rows
Columns
Keys
Relationships
Schemas
```

---

✅ NoSQL Uses:

```text
Key-Value
Document
Wide Column
Graph
```

---

✅ Common SQL Databases:

- MySQL
    
- MSSQL
    
- Oracle
    
- PostgreSQL
    

---

✅ Common NoSQL Databases:

- MongoDB
    
- ElasticSearch
    
- Cassandra
    
- Redis
    
- Neo4j
    

---

✅ Important Definition:

```text
Relationship between tables
=
Schema
```

---

✅ Security Risk:

```text
Unsanitized User Input
      ↓
SQL Injection
```

---

# Quick Revision (1 Minute)

```text
DATABASES

Purpose:
Store and Retrieve Data

Stores:
• Users
• Passwords
• Posts
• Files
• Sessions

Types:

1. SQL
   • Tables
   • Rows
   • Columns
   • Relationships

Examples:
MySQL
MSSQL
Oracle
PostgreSQL

2. NoSQL
   • Key-Value
   • Document
   • Graph
   • Wide Column

Examples:
MongoDB
ElasticSearch
Cassandra
Redis

Important:
Relationship Between Tables
= Schema

Major Risk:
SQL Injection
```

These notes preserve all HTB concepts, examples, schema explanations, JSON examples, PHP database code, and exam-focused points while making them easier to revise and remember.