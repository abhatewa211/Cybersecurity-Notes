![Image](https://miro.medium.com/1%2A13oqfKMwgrZ_5fX1HaFicg.png)

![Image](https://go-colly.org/http_header_struct.jpg)

![Image](https://www.tutorialspoint.com/http/images/http-message-response.jpg)

![Image](https://mdn.github.io/shared-assets/images/diagrams/http/messages/http-message-anatomy.svg)

---

# 1. Overview

HTTP communication mainly consists of **two components**:

1️⃣ **HTTP Request** – Sent by the **client**  
2️⃣ **HTTP Response** – Sent by the **server**

### Client Examples

- Web Browser (Chrome, Firefox)
    
- `cURL`
    
- Mobile applications
    
- Scripts or APIs
    

### Server Examples

- Apache
    
- Nginx
    
- IIS
    
- Web application servers
    

---

### Communication Flow

```
Client  ---- HTTP Request ---->  Server
Client  <--- HTTP Response ----  Server
```

The client requests a **resource**, and the server returns a **response**.

---

# 2. HTTP Request

An **HTTP request** is sent from the client to the server asking for a resource.

Example URL:

```
http://inlanefreight.com/users/login.html
```

Example HTTP request:

```
GET /users/login.html HTTP/1.1
Host: inlanefreight.com
User-Agent: Mozilla/5.0
Cookie: PHPSESSID=c4ggt4jull9obt7aupa55o8vbf
```

---

# 3. Structure of an HTTP Request

The HTTP request has **three main parts**:

1️⃣ Request Line  
2️⃣ Headers  
3️⃣ Request Body (optional)

---

## 3.1 Request Line

The **first line** of the HTTP request contains **three fields separated by spaces**.

|Field|Example|Description|
|---|---|---|
|Method|GET|The HTTP method or verb, which specifies the type of action to perform.|
|Path|/users/login.html|The path to the resource being accessed.|
|Version|HTTP/1.1|The HTTP protocol version.|

Example:

```
GET /users/login.html HTTP/1.1
```

---

## 3.2 HTTP Methods

Common HTTP methods:

|Method|Purpose|
|---|---|
|GET|Retrieve data|
|POST|Send data to server|
|PUT|Update existing data|
|DELETE|Remove data|
|HEAD|Retrieve headers only|
|OPTIONS|Show allowed methods|

Example:

```
GET /index.html HTTP/1.1
```

---

## 3.3 Request Path

The **path specifies the resource location** on the server.

Example:

```
/users/login.html
```

The path can also include **query parameters**.

Example:

```
/login.php?username=user
```

Query parameters pass data through the URL.

---

## 3.4 HTTP Headers

Headers provide **additional information about the request**.

Example request headers:

```
Host: inlanefreight.com
User-Agent: Mozilla/5.0
Cookie: PHPSESSID=c4ggt4jull9obt7aupa55o8vbf
Accept: */*
Connection: close
```

---

### Common Request Headers

|Header|Description|
|---|---|
|Host|Target domain|
|User-Agent|Client software info|
|Cookie|Session data|
|Accept|Supported response types|
|Authorization|Authentication credentials|
|Content-Type|Type of request body|

---

## 3.5 Request Body

The **request body** contains data sent to the server.

Usually used with:

- POST
    
- PUT
    
- PATCH
    

Example:

```
POST /login.php HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=password
```

---

# 4. HTTP Versions

### HTTP/1.x

Characteristics:

- Requests sent in **clear text**
    
- Uses **newline characters** to separate fields
    
- Human readable
    

Example:

```
GET / HTTP/1.1
Host: example.com
```

---

### HTTP/2

Characteristics:

- Uses **binary format**
    
- Faster communication
    
- Multiplexing support
    
- Reduced latency
    

Instead of text requests, HTTP/2 sends data as **binary frames**.

---

# 5. HTTP Response

After processing the request, the server sends an **HTTP response**.

Example response:

```
HTTP/1.1 200 OK
Date: Tue, 21 Jul 2020 05:20:15 GMT
Server: Apache/2.4.41
Set-Cookie: PHPSESSID=m4u64rqlpfthrvvb12ai9voqgf
Content-Type: text/html; charset=UTF-8
```

---

# 6. Structure of an HTTP Response

An HTTP response contains:

1️⃣ Status Line  
2️⃣ Response Headers  
3️⃣ Response Body

---

## 6.1 Status Line

The first line contains **two main components**:

|Field|Example|
|---|---|
|HTTP Version|HTTP/1.1|
|Status Code|200 OK|

Example:

```
HTTP/1.1 200 OK
```

---

## 6.2 Response Headers

Response headers provide **metadata about the response**.

Example:

```
Date: Tue, 21 Jul 2020 05:20:15 GMT
Server: Apache/2.4.41
Set-Cookie: PHPSESSID=m4u64rqlpfthrvvb12ai9voqgf
Content-Length: 464
Content-Type: text/html; charset=UTF-8
```

---

### Common Response Headers

|Header|Description|
|---|---|
|Server|Web server software|
|Set-Cookie|Sets cookies|
|Content-Type|Type of returned data|
|Content-Length|Size of response|
|Location|Redirect destination|

---

## 6.3 Response Body

The response body contains **the requested resource**.

Common formats include:

- HTML
    
- JSON
    
- Images
    
- CSS
    
- JavaScript
    
- PDFs
    
- Documents
    

Example HTML body:

```html
<!DOCTYPE HTML>
<html>
<head>
<title>Login Page</title>
</head>
<body>
<form>
...
</form>
</body>
</html>
```

---

# 7. Using cURL for HTTP Requests

`cURL` is a command-line tool used to interact with web servers.

Basic usage:

```bash
curl inlanefreight.com
```

This returns only the **response body**.

---

# 8. Viewing Full HTTP Request and Response

To see the full communication, use the **verbose flag**.

```
-v
```

Example:

```bash
curl inlanefreight.com -v
```

---

### Example Output

```
* Connected to inlanefreight.com (SERVER_IP) port 80

> GET / HTTP/1.1
> Host: inlanefreight.com
> User-Agent: curl/7.65.3
> Accept: */*

< HTTP/1.1 401 Unauthorized
< Date: Tue, 21 Jul 2020 05:20:15 GMT
< Server: Apache/X.Y.ZZ (Ubuntu)
< WWW-Authenticate: Basic realm="Restricted Content"
< Content-Length: 464
< Content-Type: text/html
```

---

### Request Section

Lines starting with `>` indicate the **request sent by the client**.

Example:

```
> GET / HTTP/1.1
> Host: inlanefreight.com
```

---

### Response Section

Lines starting with `<` indicate the **response from the server**.

Example:

```
< HTTP/1.1 401 Unauthorized
```

This means:

- The request was received
    
- Access is **not authorized**
    

---

# 9. HTTP Response Codes

Response codes indicate the **result of the request**.

Example:

```
401 Unauthorized
```

Meaning:

- The resource requires authentication.
    

More status codes will be covered later.

---

# 10. Extra Verbose Mode

The `-vvv` flag shows **even more debugging information**.

Example:

```bash
curl -vvv inlanefreight.com
```

This may include:

- TLS handshake details
    
- DNS resolution
    
- Connection debugging
    
- SSL certificate information
    

Very useful for **penetration testing and exploit development**.

---

# 11. Browser Developer Tools (DevTools)

Modern browsers include **built-in developer tools**.

Used by:

- Web developers
    
- Security testers
    
- Bug bounty hunters
    
- Penetration testers
    

---

## Opening DevTools

Keyboard shortcuts:

```
CTRL + SHIFT + I
```

or

```
F12
```

Works in:

- Chrome
    
- Firefox
    
- Edge
    

---

# 12. DevTools Tabs

Common DevTools tabs:

|Tab|Purpose|
|---|---|
|Elements|Inspect HTML|
|Console|Run JavaScript|
|Sources|View source files|
|Network|Monitor HTTP requests|
|Application|Storage and cookies|

For web security testing, the **Network tab is the most important**.

---

# 13. Network Tab

The **Network tab shows all HTTP requests made by the browser**.

Steps:

1. Open DevTools
    
2. Click **Network**
    
3. Refresh the page
    

You will see a list of requests.

Example:

```
GET /               304
GET /favicon.ico    404
```

---

### Example Data Displayed

The Network tab shows:

|Field|Description|
|---|---|
|Status|Response code|
|Method|HTTP method|
|Domain|Target domain|
|Path|Resource path|
|Size|Response size|
|Time|Request duration|

---

# 14. Filtering Requests

Large websites may send **hundreds of requests**.

Use the **Filter URLs** search box to locate specific requests.

Example filters:

```
login
api
users
```

This helps identify **important API calls or authentication requests**.

---

# 15. Why This is Important for Pentesters

Understanding HTTP requests is essential for:

- Web penetration testing
    
- Exploit development
    
- API testing
    
- Session manipulation
    
- Authentication bypass
    
- Request tampering
    

Tools that rely heavily on HTTP analysis:

- **Burp Suite**
    
- **OWASP ZAP**
    
- **Wireshark**
    
- **cURL**
    

---

# Key Takeaways

### HTTP Request

Contains:

- Method
    
- Path
    
- Version
    
- Headers
    
- Optional body
    

---

### HTTP Response

Contains:

- Version
    
- Status code
    
- Headers
    
- Response body
    

---

### Useful Commands

View request + response:

```
curl -v site.com
```

More debugging:

```
curl -vvv site.com
```

---

### Exercises

![[Pasted image 20260308124256.png]]

Step1. Strart the pwnbox as usual.

Step2. Run Command curl in terminal. (Highlighted)
![[Pasted image 20260308124523.png]]