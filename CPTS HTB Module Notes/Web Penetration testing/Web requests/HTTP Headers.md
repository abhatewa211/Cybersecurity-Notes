![Image](https://go-colly.org/http_header_struct.jpg)

![Image](https://s3-cdn.fastvue.co/img/blog-archive/tmgreporter/everything-you-need-to-know-about-user-agent-strings/images/1.png)

![Image](https://www.west-wind.com/Weblog/images/200901/Windows-Live-Writer/Response.Redirect-and-Cookies_EBED/CookieThere_2.png)

![Image](https://i.sstatic.net/vJ4JB.png)

---

# 1. Overview of HTTP Headers

In HTTP communication, **headers pass additional information between the client and the server**.

Headers are included in both:

- **HTTP Requests**
    
- **HTTP Responses**
    

They help define **how the communication should be handled**.

---

### Header Structure

Headers follow the format:

```id="n2m24n"
Header-Name: value
```

Example:

```id="3f4v3k"
Content-Type: text/html
```

A header can contain **one or multiple values**.

Example:

```id="v1e6qk"
Cookie: cookie1=value1; cookie2=value2
```

---

# 2. Categories of HTTP Headers

HTTP headers can be divided into **five categories**:

1️⃣ General Headers  
2️⃣ Entity Headers  
3️⃣ Request Headers  
4️⃣ Response Headers  
5️⃣ Security Headers

Each category serves a different purpose.

---

# 3. General Headers

General headers are used in **both HTTP requests and HTTP responses**.

They describe **the message itself**, not the content.

---

### Common General Headers

|Header|Example|Description|
|---|---|---|
|Date|Date: Wed, 16 Feb 2022 10:38:44 GMT|Holds the date and time at which the message originated.|
|Connection|Connection: close|Determines whether the network connection stays open after the request.|

---

### Connection Header

Example:

```id="afp5hx"
Connection: close
```

Meaning:

- The connection **will be terminated after the request completes**.
    

Another value:

```id="1v9dyl"
Connection: keep-alive
```

Meaning:

- The connection remains open for additional requests.
    

This improves **performance by reducing connection overhead**.

---

# 4. Entity Headers

Entity headers describe **the content (entity) being transferred**.

They can appear in:

- HTTP responses
    
- POST requests
    
- PUT requests
    

---

### Common Entity Headers

|Header|Example|Description|
|---|---|---|
|Content-Type|Content-Type: text/html|Defines the type of resource being transferred.|
|Media-Type|Media-Type: application/pdf|Describes the type of data transferred.|
|Boundary|boundary="b4e4fbd93540"|Separates different content parts.|
|Content-Length|Content-Length: 385|Indicates the size of the message body.|
|Content-Encoding|Content-Encoding: gzip|Specifies compression or encoding used.|

---

### Content-Type Header

Example:

```id="z6oqum"
Content-Type: text/html; charset=UTF-8
```

Meaning:

- The response contains **HTML**
    
- Encoding is **UTF-8**
    

Common Content Types:

|Type|Description|
|---|---|
|text/html|HTML webpage|
|application/json|JSON API response|
|application/xml|XML data|
|image/png|PNG image|
|application/pdf|PDF document|

---

### Content-Length Header

Example:

```id="o8sflf"
Content-Length: 385
```

Meaning:

- The message body size is **385 bytes**
    

This helps the server **know how much data to read**.

---

### Content-Encoding Header

Example:

```id="96w5ea"
Content-Encoding: gzip
```

Meaning:

- The response is **compressed using Gzip**
    

Compression reduces:

- bandwidth usage
    
- page load time
    

---

# 5. Request Headers

Request headers are **sent by the client** to the server.

They provide information about:

- the client
    
- the request
    
- supported content types
    

---

### Common Request Headers

|Header|Example|Description|
|---|---|---|
|Host|Host: [www.inlanefreight.com](http://www.inlanefreight.com)|Specifies the host being queried.|
|User-Agent|User-Agent: curl/7.77.0|Identifies the client software.|
|Referer|Referer: [http://www.inlanefreight.com/](http://www.inlanefreight.com/)|Shows where the request originated.|
|Accept|Accept: _/_|Specifies supported response types.|
|Cookie|Cookie: PHPSESSID=b4e4fbd93540|Sends stored client cookies.|
|Authorization|Authorization: BASIC cGFzc3dvcmQK|Sends authentication credentials.|

---

### Host Header

Example:

```id="uys7eq"
Host: www.inlanefreight.com
```

This header is **very important** because:

- Web servers host **multiple websites on the same server**
    
- The **Host header tells the server which website to load**
    

This is also useful for **enumeration during penetration testing**.

---

### User-Agent Header

Example:

```id="z8pyh8"
User-Agent: Mozilla/5.0
```

This identifies:

- Browser
    
- Browser version
    
- Operating system
    

Example information revealed:

```id="vugp29"
Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

---

### Referer Header

Example:

```id="9yxm0f"
Referer: http://www.inlanefreight.com/
```

This indicates **where the request came from**.

Example:

User clicked a link from Google:

```id="kz0t4k"
Referer: https://google.com
```

⚠️ Important:  
The Referer header **can be easily manipulated**, so trusting it may create security risks.

---

### Accept Header

Example:

```id="0ahqte"
Accept: */*
```

Meaning:

- The client accepts **any media type**
    

Example of specific types:

```id="qgkcd5"
Accept: text/html,application/json
```

---

### Cookie Header

Example:

```id="dyd72x"
Cookie: PHPSESSID=b4e4fbd93540
```

Cookies are used for:

- session tracking
    
- authentication
    
- user preferences
    

Multiple cookies:

```id="4q56sq"
Cookie: cookie1=value1; cookie2=value2
```

---

### Authorization Header

Example:

```id="r4zn1k"
Authorization: BASIC cGFzc3dvcmQK
```

This header sends **authentication credentials**.

Common authentication types:

|Type|Description|
|---|---|
|Basic|Base64 encoded username/password|
|Bearer|Token authentication|
|Digest|Encrypted challenge-response|

---

# 6. Response Headers

Response headers are **sent by the server**.

They provide **additional context about the response**.

---

### Common Response Headers

|Header|Example|Description|
|---|---|---|
|Server|Server: Apache/2.2.14|Identifies server software.|
|Set-Cookie|Set-Cookie: PHPSESSID=b4e4fbd93540|Sets cookies in the browser.|
|WWW-Authenticate|WWW-Authenticate: BASIC realm="localhost"|Specifies authentication method.|

---

### Server Header

Example:

```id="6mx8z1"
Server: Apache/2.2.14 (Win32)
```

This reveals:

- web server type
    
- version
    

This information can be useful for **server enumeration during penetration testing**.

---

### Set-Cookie Header

Example:

```id="oxwpib"
Set-Cookie: PHPSESSID=b4e4fbd93540
```

The browser stores the cookie and sends it in future requests.

Example stored cookie:

```id="njm1xo"
Cookie: PHPSESSID=b4e4fbd93540
```

---

### WWW-Authenticate Header

Example:

```id="h7j3gc"
WWW-Authenticate: BASIC realm="localhost"
```

Meaning:

- The server requires authentication
    
- Authentication type is **Basic**
    

---

# 7. Security Headers

Security headers improve **browser security policies**.

They help protect against attacks such as:

- Cross-Site Scripting (XSS)
    
- MITM attacks
    
- Data leakage
    

---

### Common Security Headers

|Header|Example|Description|
|---|---|---|
|Content-Security-Policy|script-src 'self'|Controls allowed resource sources.|
|Strict-Transport-Security|max-age=31536000|Forces HTTPS usage.|
|Referrer-Policy|origin|Controls referer information sharing.|

---

### Content-Security-Policy (CSP)

Example:

```id="yg98te"
Content-Security-Policy: script-src 'self'
```

Meaning:

- Scripts can only load from **the same domain**
    

This prevents:

- **Cross-Site Scripting (XSS)**
    

---

### Strict-Transport-Security (HSTS)

Example:

```id="5uw4fw"
Strict-Transport-Security: max-age=31536000
```

Meaning:

- The browser **must always use HTTPS**
    

This prevents **HTTP downgrade attacks**.

---

### Referrer-Policy

Example:

```id="sx8b04"
Referrer-Policy: origin
```

Controls how much **referer information is shared**.

Example protection:

- Prevent leaking sensitive URLs.
    

---

# 8. Viewing Headers with cURL

We can inspect HTTP headers using **cURL**.

---

## View Response Headers Only

Use the **-I flag**.

```bash
curl -I https://www.inlanefreight.com
```

This sends a **HEAD request** and returns **only headers**.

Example output:

```id="s19oyg"
Date: Sun, 06 Aug 2020 08:49:37 GMT
Connection: keep-alive
Content-Length: 26012
Content-Type: text/html
Server: Apache/2.2.14
Set-Cookie: name=value
Content-Security-Policy: script-src 'self'
Strict-Transport-Security: max-age=31536000
Referrer-Policy: origin
```

---

## Display Headers + Body

Use the **-i flag**.

```bash
curl -i https://www.inlanefreight.com
```

Difference:

|Flag|Behavior|
|---|---|
|-I|Headers only|
|-i|Headers + response body|

---

# 9. Modifying Headers with cURL

We can set custom headers using:

```id="ogk1vl"
-H
```

Example:

```bash
curl -H "User-Agent: Mozilla/5.0" https://example.com
```

---

### Setting User-Agent with -A

```bash
curl https://www.inlanefreight.com -A 'Mozilla/5.0'
```

This changes the **User-Agent header**.

Useful for:

- bypassing filters
    
- testing server behavior
    
- web scraping
    

---

# 10. Viewing Headers in Browser DevTools

Browser DevTools allow easy inspection of HTTP headers.

---

### Steps

1. Open DevTools
    

```id="07w3t3"
F12
```

or

```id="3o3p1o"
CTRL + SHIFT + I
```

---

2. Go to **Network tab**
    
3. Refresh the page
    
4. Click any request
    

---

### Information Displayed

DevTools shows:

- Request headers
    
- Response headers
    
- Cookies
    
- Request payload
    
- Response data
    

You can also view headers in **Raw format**.

---

# 11. Cookies Tab

DevTools also provides a **Cookies tab**.

This shows:

- stored cookies
    
- session IDs
    
- expiration times
    
- security attributes
    

---

# Key Takeaways

### HTTP Headers

Used to **exchange additional information** between client and server.

---

### Header Categories

1️⃣ General Headers  
2️⃣ Entity Headers  
3️⃣ Request Headers  
4️⃣ Response Headers  
5️⃣ Security Headers

---

### Important Pentesting Headers

- Host
    
- User-Agent
    
- Cookie
    
- Authorization
    
- Referer
    
- Server
    
- Set-Cookie
    

---

### Useful cURL Commands

View headers:

```id="4pjyz4"
curl -I site.com
```

View headers + body:

```id="yzqvdf"
curl -i site.com
```

Custom User-Agent:

```id="0lso0e"
curl -A "Mozilla/5.0" site.com
```

---

