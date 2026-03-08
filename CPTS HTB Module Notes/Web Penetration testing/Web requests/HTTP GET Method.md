
![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2A2UbC5pSRyjGmF1ezB9hvYg.png)

![Image](https://developer.chrome.com/static/docs/devtools/network/reference/image/search-requests.png)

![Image](https://i.sstatic.net/PNsXB.jpg)

![Image](https://wonderproxy.com/blog/content/images/2021/01/http-basic-auth-prompt-2.png)

---

# 1. Overview of the GET Method

Whenever we visit a URL in a browser, the browser **automatically sends a GET request** to retrieve the resource from the server.

Example:

```http
GET /index.html HTTP/1.1
Host: example.com
```

The GET method is primarily used to **retrieve data from a server**.

---

### Example URL Request

When visiting:

```
http://example.com/page
```

The browser sends:

```http
GET /page HTTP/1.1
Host: example.com
```

The server then returns:

```
HTTP/1.1 200 OK
```

along with the requested resource.

---

# 2. How Browsers Use GET Requests

When a webpage loads, the browser **does not send just one request**.

Instead it sends multiple requests for resources like:

- HTML
    
- CSS
    
- JavaScript
    
- Images
    
- Fonts
    
- APIs
    

This behavior can be observed using the **Network tab in Browser DevTools**.

---

### Viewing Requests in DevTools

Steps:

```
F12
```

or

```
CTRL + SHIFT + I
```

Then open:

```
Network Tab
```

After refreshing the page you will see:

|Method|Resource|
|---|---|
|GET|index.html|
|GET|style.css|
|GET|script.js|
|GET|logo.png|

This technique is **extremely important for web application analysis and bug bounty testing**.

---

# 3. HTTP Basic Authentication

Some websites protect pages using **HTTP Basic Authentication**.

Unlike traditional login forms that use **POST requests**, basic authentication is handled directly by the **web server**.

---

### Example Protected Page

```
http://<SERVER_IP>:<PORT>/
```

When visiting the page, the browser prompts:

```
Username: admin
Password: admin
```

⚠️ Warning shown in browser:

```
Your password will be sent unencrypted
```

This is because **Basic Auth only encodes credentials, it does not encrypt them** unless HTTPS is used.

---

# 4. Accessing Basic Auth Page with cURL

We can test the page using **cURL**.

Command:

```bash
curl -i http://<SERVER_IP>:<PORT>/
```

Example response:

```http
HTTP/1.1 401 Authorization Required
Date: Mon, 21 Feb 2022 13:11:46 GMT
Server: Apache/2.4.41 (Ubuntu)
WWW-Authenticate: Basic realm="Access denied"
Content-Type: text/html
```

Response body:

```
Access denied
```

---

### Explanation

|Header|Meaning|
|---|---|
|401 Authorization Required|Authentication required|
|WWW-Authenticate|Indicates authentication method|

Example:

```
WWW-Authenticate: Basic realm="Access denied"
```

This confirms that the page uses **HTTP Basic Authentication**.

---

# 5. Authenticating with cURL

To send credentials with cURL we use:

```
-u
```

Command:

```bash
curl -u admin:admin http://<SERVER_IP>:<PORT>/
```

Example response:

```html
<!DOCTYPE html>
<html lang="en">
<head>
...
```

This means authentication succeeded.

---

# 6. Authentication via URL

Another method is embedding credentials directly in the URL.

Format:

```
username:password@URL
```

Example:

```bash
curl http://admin:admin@<SERVER_IP>:<PORT>/
```

This also authenticates successfully.

The browser also supports this format.

---

# 7. Authorization Header

When authentication is used, the HTTP request includes an **Authorization header**.

Example request (verbose mode):

```bash
curl -v http://admin:admin@<SERVER_IP>:<PORT>/
```

Request output:

```http
GET / HTTP/1.1
Host: <SERVER_IP>
Authorization: Basic YWRtaW46YWRtaW4=
User-Agent: curl/7.77.0
Accept: */*
```

---

### Base64 Encoding

The value:

```
YWRtaW46YWRtaW4=
```

is **Base64 encoding of**

```
admin:admin
```

Basic authentication uses:

```
Authorization: Basic <base64(username:password)>
```

---

### Modern Authentication

Modern APIs usually use **Bearer tokens** instead.

Example:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

This is commonly used with:

- JWT authentication
    
- OAuth APIs
    

---

# 8. Manually Setting Authorization Header

Instead of using `-u`, we can manually set the Authorization header using:

```
-H
```

Command:

```bash
curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/
```

Response:

```html
<!DOCTYPE html>
<html lang="en">
<head>
...
```

Access is granted.

---

### Multiple Headers

You can add multiple headers:

```bash
curl -H "Header1: value" -H "Header2: value"
```

---

# 9. GET Parameters

GET requests can include **parameters inside the URL**.

Format:

```
?parameter=value
```

Example:

```
search.php?search=le
```

Example full URL:

```
http://<SERVER_IP>:<PORT>/search.php?search=le
```

---

### Example Search Feature

A webpage provides a **City Search function**.

When searching:

```
le
```

The browser sends:

```
GET /search.php?search=le
```

Results returned:

```
Leeds (UK)
Leicester (UK)
```

---

# 10. Monitoring GET Requests in DevTools

Steps:

1️⃣ Open DevTools

```
CTRL + SHIFT + I
```

2️⃣ Go to:

```
Network tab
```

3️⃣ Clear old requests using the **trash icon**

4️⃣ Perform search action

A request appears:

```
GET /search.php?search=le
```

---

### Request Example

```
GET http://127.0.0.1/search.php?search=le
```

This confirms that the **search function uses GET parameters**.

---

# 11. Replaying Requests with cURL

DevTools allows copying the request as a cURL command.

Steps:

```
Right Click Request
↓
Copy
↓
Copy as cURL
```

Example command:

```bash
curl 'http://<SERVER_IP>:<PORT>/search.php?search=le' \
-H 'Authorization: Basic YWRtaW46YWRtaW4='
```

Response:

```
Leeds (UK)
Leicester (UK)
```

---

### Removing Unnecessary Headers

Copied commands often include many headers.

You can simplify the request by keeping only:

- authentication headers
    
- essential headers
    

Example simplified command:

```bash
curl 'http://<SERVER_IP>:<PORT>/search.php?search=le' \
-H 'Authorization: Basic YWRtaW46YWRtaW4='
```

---

# 12. Copy as Fetch (JavaScript)

DevTools also allows copying requests as **JavaScript Fetch commands**.

Steps:

```
Right Click Request
↓
Copy
↓
Copy as Fetch
```

Then open console:

```
CTRL + SHIFT + K
```

Paste and run the command.

Example:

```javascript
fetch("http://127.0.0.1/search.php?search=lel", {
  headers: {
    "Authorization": "Basic YWRtaW46YWRtaW4="
  }
})
```

The browser sends the request and shows the response.

---

# 13. Why This Is Important for Web Security

Understanding GET requests helps with:

- analyzing application behavior
    
- identifying hidden endpoints
    
- parameter testing
    
- vulnerability discovery
    

Common attacks involve GET parameters such as:

```
SQL Injection
XSS
IDOR
Command Injection
```

Example vulnerable request:

```
GET /search.php?search=' OR 1=1--
```

---

# Key Takeaways

### GET Method

```
Used to retrieve data from a server
```

---

### Basic Authentication

Credentials format:

```
username:password
```

Encoded as:

```
Base64(username:password)
```

Example header:

```
Authorization: Basic YWRtaW46YWRtaW4=
```

---

### GET Parameters

Format:

```
?parameter=value
```

Example:

```
search.php?search=le
```

---

### Useful cURL Commands

Authenticate:

```bash
curl -u admin:admin http://target
```

Manual header:

```bash
curl -H "Authorization: Basic TOKEN" http://target
```

Verbose mode:

```bash
curl -v http://target
```

---

### Exercises
![[Pasted image 20260308154455.png]]

Step1.  Start the pwnbox as well and target machine too.

Step2.  Now open the browser in Pwnbox surf the target ip with port given and login with given credentials.
![[Pasted image 20260308155215.png]]

Step3. Now search any location there will be error in results, after that open the inspect element and go to network tab
![[Pasted image 20260308155327.png]]             ![[Pasted image 20260308155625.png]]

Step4. Now 