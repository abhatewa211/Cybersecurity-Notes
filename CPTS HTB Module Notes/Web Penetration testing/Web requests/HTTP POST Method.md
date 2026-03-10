![Image](https://mdn.github.io/shared-assets/images/diagrams/http/messages/http-2-connection.png)

![Image](https://user-images.githubusercontent.com/1152698/158563340-6f283de5-ce75-4a82-ab73-9314360242e1.png)

![Image](https://raw.githubusercontent.com/puikinsh/login-forms/main/assets/screenshots/minimal.png)

![Image](https://i.sstatic.net/DO6SZ.png)

---

# 1. Overview of the POST Method

In the previous section, we saw how **GET requests** are used to retrieve resources such as pages or search results.

However, when web applications need to:

- transfer **files**
    
- send **large amounts of data**
    
- hide parameters from the URL
    

they use the **POST request**.

---

### Key Difference

|Method|Data Location|
|---|---|
|GET|URL parameters|
|POST|Request body|

---

### Example GET Request

```http
GET /search.php?search=london HTTP/1.1
```

---

### Example POST Request

```http
POST /search.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

search=london
```

The parameters are placed **inside the request body**, not the URL.

---

# 2. Benefits of POST Requests

POST provides several advantages over GET.

---

## 1. Lack of Logging

POST data is **not included in the URL**.

Example GET:

```text
/search.php?username=admin&password=admin
```

This may appear in:

- browser history
    
- server logs
    
- proxies
    

POST avoids this because the data is sent in the **body**.

---

## 2. Less Encoding Requirements

URLs must contain **valid URL characters**.

Example encoded characters:

```text
space → %20
```

POST can send:

- binary data
    
- raw text
    
- files
    

Only parameter separators must be encoded.

---

## 3. More Data Can Be Sent

URLs have **length limits**.

Typical safe URL length:

```text
< 2000 characters
```

POST has **no strict length limit**, allowing:

- file uploads
    
- large JSON objects
    
- binary data
    

---

# 3. Login Forms and POST Requests

Most modern web applications use **POST requests for login forms**.

Example login page:

```
http://<SERVER_IP>:<PORT>/
```

The page contains fields:

```
Username
Password
Login button
```

---

### Example Credentials

```
username: admin
password: admin
```

After login, the user is redirected to:

```
Search page
```

---

# 4. Monitoring POST Requests with DevTools

Steps to observe login requests:

1️⃣ Open DevTools

```
F12
```

2️⃣ Go to

```
Network Tab
```

3️⃣ Clear previous requests

4️⃣ Submit login form

---

### Observed Request

```
POST / HTTP/1.1
```

Request body:

```bash
username=admin&password=admin
```

---

# 5. Recreating POST Requests with cURL

We can replicate the login request manually.

---

### Send POST Request

```bash
curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/
```

Explanation:

|Flag|Purpose|
|---|---|
|-X|Specify HTTP method|
|-d|Send POST data|

---

### Successful Response

The response HTML will show the **search page instead of login form**, indicating authentication succeeded.

Example response snippet:

```html
<em>Type a city name and hit <strong>Enter</strong></em>
```

---

### Following Redirects

Some login systems redirect users after authentication.

Example:

```
/login → /dashboard
```

To follow redirects in cURL:

```bash
curl -L http://target
```

---

# 6. Authentication Cookies

When login succeeds, the server returns a **session cookie**.

Example response header:

```http
Set-Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1
```

This cookie allows the browser to **stay authenticated**.

---

### Viewing Headers with cURL

```bash
curl -X POST -d 'username=admin&password=admin' http://target -i
```

Response:

```http
HTTP/1.1 200 OK
Set-Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1
```

---

# 7. Using Cookies with cURL

To reuse the authentication session, we include the cookie.

---

### Using -b Flag

```bash
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/
```

This allows access without logging in again.

---

### Cookie as Header

Cookies can also be added manually.

```bash
curl -H 'Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://target
```

---

# 8. Cookie Manipulation in Browser

We can manually modify cookies using **browser DevTools**.

Steps:

Open Storage tab:

```
SHIFT + F9
```

Then navigate:

```
Cookies → target website
```

You will see:

```
PHPSESSID
```

---

### Manually Setting Cookie

Steps:

1️⃣ Delete existing cookie  
2️⃣ Add new cookie

Example:

```
Name: PHPSESSID
Value: c1nsa6op7vtk7kdis7bcnbadf1
```

After refreshing the page, the user is **automatically authenticated**.

---

### Security Implication

If attackers obtain a valid session cookie, they may **hijack user sessions**.

Example attack:

```
Session Hijacking
```

This is common in **Cross-Site Scripting (XSS)** attacks.

---

# 9. JSON POST Requests

Modern applications often send POST data in **JSON format**.

Example request payload:

```json
{"search":"london"}
```

---

### Observed Request

In DevTools:

```
POST /search.php
```

Payload:

```json
{"search":"london"}
```

---

### Required Header

```http
Content-Type: application/json
```

This tells the server the request body is JSON.

---

### Example Request Headers

```http
POST /search.php HTTP/1.1
Host: server_ip
Content-Type: application/json
Content-Length: 19
Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1
```

---

# 10. Sending JSON POST Requests with cURL

To replicate the request:

```bash
curl -X POST \
-d '{"search":"london"}' \
-b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' \
-H 'Content-Type: application/json' \
http://<SERVER_IP>:<PORT>/search.php
```

Response:

```json
["London (UK)"]
```

This proves we can interact with the backend **without using the frontend interface**.

---

# 11. Copying Requests from DevTools

Browser DevTools allows exporting requests.

---

### Copy as cURL

Steps:

```
Right Click Request
→ Copy
→ Copy as cURL
```

This produces an exact command.

---

### Copy as Fetch

DevTools also supports copying as JavaScript Fetch.

Example:

```javascript
fetch("http://server_ip/search.php", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({"search":"London"})
});
```

Run it in the console:

```
CTRL + SHIFT + K
```

---

# 12. Why This Is Important for Web Security

Understanding POST requests allows security testers to:

- test login mechanisms
    
- manipulate API requests
    
- bypass frontend restrictions
    
- test input validation
    

Common attacks involve POST requests:

```
SQL Injection
Command Injection
Authentication Bypass
File Upload Attacks
```

Example attack:

```
username=admin' OR '1'='1
```

---

# Key Takeaways

### POST Request

Used for:

```
Login forms
File uploads
API requests
Large data transfers
```

---

### Important Headers

```
Content-Type
Cookie
Authorization
```

---

### Useful cURL Commands

Send POST request:

```bash
curl -X POST -d "username=admin&password=admin" http://target
```

Send JSON request:

```bash
curl -X POST -d '{"search":"london"}' -H "Content-Type: application/json" http://target
```

Send authenticated request:

```bash
curl -b "PHPSESSID=SESSIONID" http://target
```

---

### Exercises

![[Pasted image 20260310223316.png]]

Step1.  Start the pwnbox as well and target machine too.

Step2.  Now open the browser in Pwnbox surf the target ip with port given and login with given credentials.
![[Pasted image 20260310223650.png]]

Step3. Now search any location there will be error in results, after that open the inspect element and go to network tab refresh the page. 
![[Pasted image 20260310223823.png]]
![[Pasted image 20260310224046.png]]

Step4. Now copy the parameter and use it in curl by changing the search to flag and you will get the answer. (Highlighted answer)
![[Pasted image 20260310224145.png]]