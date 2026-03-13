## CRUD API – Detailed Notes

---

### 1️⃣ What is an API?

![Image](https://substackcdn.com/image/fetch/%24s_%21g3db%21%2Cf_auto%2Cq_auto%3Agood%2Cfl_progressive%3Asteep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F4a38175b-11e8-40ae-879c-ab3ce2027089_2008x1252.png)

![Image](https://images.openai.com/static-rsc-3/Ej79Xe0LnuHsgCxhVSGMg1VWU8bqWEAWDJD4sZCpSGYxX7PIK2TsWoj--sHRFPyQEWkrPCqSAeFSNdTSuNUXV1k3_tmUSF4TSAlLlpL73Xo?purpose=fullsize&v=1)

![Image](https://media.licdn.com/dms/image/v2/C4D12AQEFrcvIlUTO1g/article-cover_image-shrink_600_2000/article-cover_image-shrink_600_2000/0/1617097642557?e=2147483647&t=IHGdhlSoNKrGI0TQ847yMzeQ1alLPpxpu9pjS_vFamk&v=beta)

![Image](https://substackcdn.com/image/fetch/%24s_%21wm3M%21%2Cf_auto%2Cq_auto%3Agood%2Cfl_progressive%3Asteep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Faa5b9234-47fd-4bd0-bf21-49b4e317dc38_2728x1222.png)

An **API (Application Programming Interface)** allows applications to communicate with each other.

Instead of directly accessing a database, a client (browser, script, mobile app) sends requests to an **API endpoint**, and the API interacts with the database and returns results.

Example API endpoint:

```
http://<SERVER_IP>:<PORT>/api.php
```

The API processes requests like:

- Reading data
    
- Creating new records
    
- Updating existing records
    
- Deleting records
    

These operations are performed using **HTTP methods**.

---

# CRUD Operations

CRUD represents the **four main database operations** used by APIs.

|Operation|HTTP Method|Description|
|---|---|---|
|Create|POST|Add new data to database|
|Read|GET|Retrieve data from database|
|Update|PUT|Modify existing data|
|Delete|DELETE|Remove data|

These operations are commonly used in:

- **REST APIs**
    
- **Web applications**
    
- **Mobile apps**
    
- **Microservices**
    

---

# Example API Structure

Example endpoint:

```
http://<SERVER_IP>:<PORT>/api.php/city/london
```

Structure:

```
api.php / table / row
```

Example:

```
/api.php/city/london
```

Meaning:

- **city** → database table
    
- **london** → specific record
    

---

# 1️⃣ READ Operation (GET)

### Purpose

Retrieve data from the database.

### Example Request

```bash
curl http://<SERVER_IP>:<PORT>/api.php/city/london
```

### Response

```json
[{"city_name":"London","country_name":"(UK)"}]
```

The API returns **JSON data**.

---

### Formatting JSON Output

Use `jq` to format the response:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/london | jq
```

Output:

```json
[
  {
    "city_name": "London",
    "country_name": "(UK)"
  }
]
```

Explanation:

|Command|Meaning|
|---|---|
|`-s`|silent mode|
|`jq`|JSON formatter|

---

### Searching for Multiple Results

Example:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/le | jq
```

Output:

```json
[
  {
    "city_name": "Leeds",
    "country_name": "(UK)"
  },
  {
    "city_name": "Leicester",
    "country_name": "(UK)"
  }
]
```

The API searches for **cities containing "le"**.

---

### Retrieve All Data

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq
```

This returns **all entries in the table**.

Example output:

```json
[
  {
    "city_name": "London",
    "country_name": "(UK)"
  },
  {
    "city_name": "Birmingham",
    "country_name": "(UK)"
  }
]
```

---

# 2️⃣ CREATE Operation (POST)

![Image](https://framerusercontent.com/images/BTPLEvCposHxde5H1WQJX8SQ.png)

![Image](https://www.altexsoft.com/media/2021/03/rest_api_works.png)

![Image](https://latenode.com/_next/image?q=75&url=https%3A%2F%2Fblog-static.latenode.com%2Flatenode-strapi-blog%2Fhttp_request_methods_featured_e68756c204.jpg&w=1200)

![Image](https://docs.trendmicro.com/all/ent/sc/v3.6/en-us/apiguide/images/api_begin_flow_revised.jpg)

### Purpose

Add new data to the database.

### Example Command

```bash
curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ \
-d '{"city_name":"HTB_City", "country_name":"HTB"}' \
-H 'Content-Type: application/json'
```

Explanation:

|Part|Meaning|
|---|---|
|`-X POST`|Use POST method|
|`-d`|Send data|
|`Content-Type`|Data format|

---

### Verify Creation

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/HTB_City | jq
```

Output:

```json
[
  {
    "city_name": "HTB_City",
    "country_name": "HTB"
  }
]
```

The new city **HTB_City** was successfully added.

---

# 3️⃣ UPDATE Operation (PUT)

![Image](https://media.licdn.com/dms/image/v2/D4D12AQHxG4Prn4ZrBQ/article-cover_image-shrink_600_2000/article-cover_image-shrink_600_2000/0/1718998421506?e=2147483647&t=-2LQBR1-lDFdKqTy66DNfGm4cTz7xy27k8-QYYsYaio&v=beta)

![Image](https://media2.dev.to/dynamic/image/width%3D1280%2Cheight%3D720%2Cfit%3Dcover%2Cgravity%3Dauto%2Cformat%3Dauto/https%3A%2F%2Fdev-to-uploads.s3.amazonaws.com%2Fuploads%2Farticles%2Ffdh5vv1jgt00qy4ovolm.png)

![Image](https://www.researchgate.net/publication/367197713/figure/fig2/AS%3A11431281252103722%401718531046369/System-Flow-chart-and-connect-to-database-via-API-Key-create-delete-update-regular.ppm)

![Image](https://voyager.postman.com/illustration/diagram-rest-postman-illustration.svg)

### Purpose

Modify existing database records.

### Example

```bash
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london \
-d '{"city_name":"New_HTB_City", "country_name":"HTB"}' \
-H 'Content-Type: application/json'
```

Explanation:

|Component|Meaning|
|---|---|
|`/city/london`|Target record|
|PUT|Update request|
|JSON data|New values|

---

### Verify Update

Check old entry:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/london | jq
```

Check new entry:

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City | jq
```

Output:

```json
[
  {
    "city_name": "New_HTB_City",
    "country_name": "HTB"
  }
]
```

This confirms the update.

---

### PATCH vs PUT

|Method|Purpose|
|---|---|
|PUT|Update entire record|
|PATCH|Update specific fields|

Example PATCH:

```
Update only city_name
```

Example PUT:

```
Replace entire entry
```

---

# 4️⃣ DELETE Operation

![Image](https://assets.apidog.com/blog/2024/01/apidog-workflow-3.png)

![Image](https://media.licdn.com/dms/image/v2/D4D12AQHxG4Prn4ZrBQ/article-cover_image-shrink_600_2000/article-cover_image-shrink_600_2000/0/1718998421506?e=2147483647&t=-2LQBR1-lDFdKqTy66DNfGm4cTz7xy27k8-QYYsYaio&v=beta)

![Image](https://techalmirah.com/images/uploads/postdelete-method-in-rest-api-DELETE-method-in-REST-API.png)

![Image](https://www.tutorialspoint.com/postman/images/delete_request.jpg)

### Purpose

Remove a record from the database.

### Example

```bash
curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City
```

---

### Verify Deletion

```bash
curl -s http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City | jq
```

Output:

```json
[]
```

An **empty array** means the record no longer exists.

---

# Authentication in APIs

In real applications, not all users can perform CRUD operations.

APIs usually require authentication.

Common authentication methods:

### 1️⃣ Cookies

```
Cookie: PHPSESSID=abc123
```

Used when the user is logged into a web session.

---

### 2️⃣ Authorization Header (JWT)

```
Authorization: Bearer <JWT_TOKEN>
```

Used in modern APIs.

---

# Security Considerations

If APIs allow unrestricted CRUD operations, it can lead to vulnerabilities such as:

- **Unauthorized data modification**
    
- **Data deletion**
    
- **Privilege escalation**
    

Proper security includes:

- Authentication
    
- Authorization
    
- Rate limiting
    
- Input validation
    

---

# Quick CRUD Summary

|Action|Method|Example|
|---|---|---|
|Read|GET|`/api.php/city/london`|
|Create|POST|Add new city|
|Update|PUT|Modify existing city|
|Delete|DELETE|Remove city|

---

✅ **Important Commands**

Read city:

```bash
curl http://<SERVER_IP>:<PORT>/api.php/city/london
```

Create city:

```bash
curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City","country_name":"HTB"}' -H 'Content-Type: application/json'
```

Update city:

```bash
curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City","country_name":"HTB"}' -H 'Content-Type: application/json'
```

Delete city:

```bash
curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City
```

---
