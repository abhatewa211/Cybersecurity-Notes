![Image](https://images.openai.com/static-rsc-3/Y5moKH0a-QZZC4wHYnKxld9WEDSxkfwe2aVpjSC_AD72Ra44a34y7U9rkmQqEYSw9v7GVQax_n1XuRk9tGXStekspDlOKr7_XVt2RL4Ljd0?purpose=fullsize&v=1)

![Image](https://developer.chrome.com/static/docs/devtools/network/reference/image/big-request-rows.png)

![Image](https://www.datocms-assets.com/22695/1751319055-1732101195-http-status-codes.webp)

![Image](https://media.licdn.com/dms/image/v2/D4D12AQFQDoCmd8YBrQ/article-cover_image-shrink_720_1280/article-cover_image-shrink_720_1280/0/1720390587225?e=2147483647&t=AK-l7JvhAnC4jqfECMdPBtZfk1Tlr-b4qYmVchGXsyc&v=beta)

---

# 1. Overview

HTTP supports **multiple request methods** for accessing and interacting with resources on a server.

These methods allow a **client (browser, cURL, application)** to communicate with a **web server** and specify **how the request should be processed**.

Each request made to a server includes:

- **HTTP Method**
    
- **Resource Path**
    
- **HTTP Version**
    

Example request:

```http
GET / HTTP/1.1
```

The **HTTP method** tells the server **what action should be performed**.

---

# 2. HTTP Request Methods

HTTP methods are also known as **HTTP verbs**.

They define the **operation the client wants to perform** on a resource.

---

## GET

**Purpose:**  
Requests a specific resource from the server.

Example:

```http
GET /index.html HTTP/1.1
Host: example.com
```

Key points:

- Retrieves data
    
- Does **not modify server data**
    
- Parameters are passed through **query strings**
    

Example:

```http
GET /search?name=admin
```

Characteristics:

|Feature|Description|
|---|---|
|Data location|URL|
|Request body|❌ No|
|Safe method|✔ Yes|

---

## POST

**Purpose:**  
Sends data to the server.

Example:

```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=123
```

Key points:

- Used for **forms**
    
- Used for **authentication**
    
- Used for **file uploads**
    

POST can send:

- text
    
- JSON
    
- images
    
- documents
    
- binary data
    

Characteristics:

|Feature|Description|
|---|---|
|Data location|Request body|
|Request body|✔ Yes|
|Safe method|❌ No|

---

## HEAD

**Purpose:**  
Requests only the **headers** of a resource.

Example:

```http
HEAD /file.zip HTTP/1.1
```

Key points:

- Same response as **GET**
    
- **No response body**
    
- Used to check:
    
    - file size
        
    - server headers
        
    - resource availability
        

Example use case:

Checking file size before download.

---

## PUT

**Purpose:**  
Creates or replaces a resource on the server.

Example:

```http
PUT /uploads/file.txt HTTP/1.1
Content-Type: text/plain
```

Security risk:

If **PUT is enabled without restrictions**, attackers may upload:

- malicious scripts
    
- web shells
    

Example attack:

```
PUT /shell.php
```

---

## DELETE

**Purpose:**  
Deletes an existing resource from the server.

Example:

```http
DELETE /uploads/file.txt HTTP/1.1
```

Security risk:

If not secured properly, attackers could:

- delete files
    
- cause **Denial of Service (DoS)**
    

---

## OPTIONS

**Purpose:**  
Returns information about supported methods on a server.

Example:

```http
OPTIONS / HTTP/1.1
```

Example response:

```http
Allow: GET, POST, OPTIONS
```

Used for:

- API discovery
    
- CORS preflight requests
    

---

## PATCH

**Purpose:**  
Applies **partial updates** to a resource.

Example:

```http
PATCH /user/123 HTTP/1.1
```

Difference from PUT:

|Method|Behavior|
|---|---|
|PUT|Replaces entire resource|
|PATCH|Updates part of resource|

---

# 3. Commonly Used HTTP Methods

|Method|Description|
|---|---|
|GET|Retrieve data|
|POST|Send data|
|HEAD|Retrieve headers|
|PUT|Create/replace resource|
|DELETE|Delete resource|
|OPTIONS|Show supported methods|
|PATCH|Partial update|

---

# 4. HTTP Methods in Web Applications

Most modern applications primarily use:

```
GET
POST
```

However **REST APIs** often use:

```
GET
POST
PUT
DELETE
PATCH
```

Example REST API:

```
GET    /users
POST   /users
PUT    /users/1
DELETE /users/1
```

---

# 5. HTTP Status Codes

HTTP status codes tell the client **the result of processing the request**.

They are included in the **HTTP response**.

Example:

```http
HTTP/1.1 200 OK
```

---

# 6. Status Code Classes

HTTP status codes are divided into **five classes**.

|Class|Description|
|---|---|
|1xx|Informational|
|2xx|Success|
|3xx|Redirection|
|4xx|Client Errors|
|5xx|Server Errors|

---

# 7. 1xx – Informational Responses

These responses provide **information about the request**.

Example:

|Code|Meaning|
|---|---|
|100|Continue|

They usually **do not affect request processing**.

---

# 8. 2xx – Successful Responses

Returned when a request is **successfully processed**.

|Code|Description|
|---|---|
|200 OK|Request successful|
|201 Created|Resource created|
|204 No Content|Request successful but no body|

---

### Example

```http
HTTP/1.1 200 OK
```

Meaning:

- Request succeeded
    
- Response body contains resource
    

---

# 9. 3xx – Redirection

Indicates the client must **perform another request**.

|Code|Description|
|---|---|
|301|Moved Permanently|
|302|Found|
|304|Not Modified|

---

### Example

```http
HTTP/1.1 302 Found
Location: /dashboard
```

Example use case:

After login:

```
login → redirect to dashboard
```

---

# 10. 4xx – Client Errors

Occurs when the **client sends an invalid request**.

|Code|Description|
|---|---|
|400|Bad Request|
|401|Unauthorized|
|403|Forbidden|
|404|Not Found|

---

### 400 Bad Request

Occurs when the request is **malformed**.

Example:

```
missing headers
invalid syntax
```

---

### 403 Forbidden

Example:

```http
HTTP/1.1 403 Forbidden
```

Meaning:

- Server understood the request
    
- Access is denied
    

---

### 404 Not Found

Occurs when the requested resource **does not exist**.

Example:

```
GET /admin
```

Response:

```
404 Not Found
```

---

# 11. 5xx – Server Errors

Occurs when the **server fails to process the request**.

|Code|Description|
|---|---|
|500|Internal Server Error|
|502|Bad Gateway|
|503|Service Unavailable|

---

### Example

```http
HTTP/1.1 500 Internal Server Error
```

Meaning:

- Something broke on the server.
    

Possible reasons:

- application crash
    
- database error
    
- server misconfiguration
    

---

# 12. Custom Status Codes

Some providers use **custom status codes**.

Examples:

|Provider|Example|
|---|---|
|Cloudflare|520|
|AWS|custom gateway codes|

These codes provide **additional infrastructure information**.

---

# 13. Viewing HTTP Methods and Status Codes

You can see them using:

### Browser DevTools

Steps:

```
F12 → Network tab
```

The Network panel shows:

|Field|Example|
|---|---|
|Method|GET|
|Status|200|
|Domain|example.com|
|Path|/login|

---

### Using cURL

View full request and response:

```bash
curl -v http://example.com
```

Example output:

```
> GET / HTTP/1.1
< HTTP/1.1 200 OK
```

---

# 14. Important for Web Security

Understanding HTTP methods helps detect vulnerabilities such as:

- **Unrestricted file upload (PUT)**
    
- **API misuse (PATCH)**
    
- **Dangerous DELETE requests**
    
- **Improper access control**
    

---

# Key Takeaways

### Common HTTP Methods

```
GET
POST
HEAD
PUT
DELETE
OPTIONS
PATCH
```

---

### Status Code Classes

```
1xx Informational
2xx Success
3xx Redirection
4xx Client Error
5xx Server Error
```

---

### Important Codes

```
200 OK
302 Found
400 Bad Request
403 Forbidden
404 Not Found
500 Internal Server Error
```

---
