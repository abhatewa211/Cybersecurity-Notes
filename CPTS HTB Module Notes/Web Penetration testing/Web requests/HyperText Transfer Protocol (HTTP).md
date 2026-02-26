## 1️⃣ What is HTTP?

**HyperText Transfer Protocol (HTTP)** is an **application-layer protocol** used to transfer data over the web.

- It enables communication between a **client** (browser, mobile app, cURL, etc.) and a **server** (web server).
    
- Most modern web and mobile applications communicate using HTTP.
    
- Default HTTP Port → **80**
    
- HTTPS (secure version) → **443**
    

> 🔎 _Hypertext_ refers to text containing links to other resources that users can interpret and navigate easily.

---

## 2️⃣ Client–Server Model

HTTP communication follows a **Request → Response** model:

- 🧑‍💻 **Client** sends a request.
    
- 🖥️ **Server** processes it.
    
- 📦 **Server** returns a response (resource + status code).
    

---

## 3️⃣ URL Structure (Uniform Resource Locator)

A URL defines how and where a resource is accessed.

## 📌 Example URL Structure

![Image](https://ittavern.com/images/blog/url-explained.png)

![Image](https://53.fs1.hubspotusercontent-na1.net/hub/53/hubfs/parts-url_0.webp?height=396&name=parts-url_0.webp&width=650)

![Image](https://media.licdn.com/dms/image/v2/C4D12AQFIhHOobhVDtA/article-cover_image-shrink_600_2000/article-cover_image-shrink_600_2000/0/1652351900740?e=2147483647&t=bWPh98q0zjM3OD0ObLkCbVU7qQttNHply9SZ9mHjxsI&v=beta)

![Image](https://hw-images.hostwinds.com/strapi-images/basic_url_structure_90bb9a9312.png)

### Example URL:

```
http://admin:password@inlanefreight.com:80/dashboard.php?login=true#status
```

---

### 🔎 URL Components Breakdown

|Component|Example|Description|
|---|---|---|
|**Scheme**|`http://` `https://`|Identifies the protocol. Ends with `://`|
|**User Info**|`admin:password@`|Optional credentials (`username:password@`)|
|**Host**|`inlanefreight.com`|Domain name or IP address|
|**Port**|`:80`|Default: HTTP → 80, HTTPS → 443|
|**Path**|`/dashboard.php`|Specific file or directory|
|**Query String**|`?login=true`|Parameters passed to server|
|**Fragment**|`#status`|Client-side reference to a section|

---

### ✅ Important Notes

- **Mandatory components:** Scheme + Host
    
- If no path is specified → Server returns default file (e.g., `index.html`)
    
- Multiple query parameters → separated by `&`
    
    ```
    ?user=admin&login=true
    ```
    

---

## 4️⃣ HTTP Flow (How a Website Loads)

## 🌍 HTTP Communication Flow

![Image](https://miro.medium.com/1%2AGHUcxtd9jlKBFccmd2ookw.png)

![Image](https://miro.medium.com/1%2AgoSb1oow5UBNF3KkzvOX8A.png)

![Image](https://substackcdn.com/image/fetch/%24s_%214Q7W%21%2Cf_auto%2Cq_auto%3Agood%2Cfl_progressive%3Asteep/https%3A%2F%2Fbucketeer-e05bbc84-baa3-437e-9518-adb32be77984.s3.amazonaws.com%2Fpublic%2Fimages%2F0e18db0d-f511-4f85-bb58-388fce70d42e_2631x2103.png)

![Image](https://www.ionos.com/digitalguide/fileadmin/DigitalGuide/Screenshots_2020/diagram-of-http-communication-process.png)

### Step-by-Step Process

### 1️⃣ User enters URL

Example:

```
inlanefreight.com
```

### 2️⃣ DNS Resolution

- Browser checks local `/etc/hosts`
    
- If not found → Queries DNS server
    
- DNS returns IP address (e.g., `152.153.81.14`)
    

> ⚠️ Servers communicate using **IP addresses**, not domain names.

---

### 3️⃣ HTTP Request Sent

Browser sends:

```
GET / HTTP/1.1
```

To:

```
IP: 152.153.81.14
Port: 80
```

---

### 4️⃣ Server Response

Server returns:

```
HTTP/1.1 200 OK
```

- HTML content (e.g., index.html)
    

---

### 5️⃣ Browser Renders Page

- Parses HTML
    
- Executes JavaScript
    
- Applies CSS
    
- Displays webpage
    

---

## 🔑 HTTP Status Codes (Important)

|Code|Meaning|
|---|---|
|200|OK|
|301|Moved Permanently|
|302|Found (Redirect)|
|400|Bad Request|
|401|Unauthorized|
|403|Forbidden|
|404|Not Found|
|500|Internal Server Error|

---

# 🛠 cURL (Client URL)

cURL is a **command-line tool** used to send HTTP requests.

It supports:

- HTTP
    
- HTTPS
    
- FTP
    
- SMTP
    
- Many more protocols
    

It is **essential for penetration testers** and automation scripts.

---

## 🔹 Basic cURL Request

```bash
curl inlanefreight.com
```

✔ Prints raw HTML  
❌ Does NOT render page like a browser

---

## 🔹 Download a File

### Use `-O` (Remote File Name)

```bash
curl -O inlanefreight.com/index.html
```

Saves file as:

```
index.html
```

---

### Use `-o` (Custom File Name)

```bash
curl -o homepage.html inlanefreight.com
```

---

## 🔹 Silent Mode

```bash
curl -s -O inlanefreight.com/index.html
```

✔ Suppresses progress/status output

---

## 🔹 Show Response Headers

```bash
curl -i inlanefreight.com
```

Includes HTTP response headers in output.

---

## 🔹 Verbose Mode

```bash
curl -v inlanefreight.com
```

Shows:

- Request headers
    
- Response headers
    
- Connection details
    

---

## 🔹 Send POST Data

```bash
curl -d "username=admin&password=1234" http://example.com/login
```

---

## 🔹 Authentication

```bash
curl -u admin:password http://example.com
```

---

## 🔹 Change User-Agent

```bash
curl -A "Mozilla/5.0" http://example.com
```

---

## 🔹 Help Menu

```bash
curl -h
curl --help all
man curl
```

---

# 🧠 Important Concepts to Remember

### 🔥 Key Points

- HTTP is **stateless**
    
- Uses **client-server model**
    
- Default HTTP port → **80**
    
- URL contains multiple structured components
    
- DNS resolves domain names to IP addresses
    
- Status codes indicate request results
    
- cURL is essential for:
    
    - Web testing
        
    - Automation
        
    - API interaction
        
    - Penetration testing
        

---

# 📌 Summary

- HTTP enables web communication.
    
- URL defines how a resource is accessed.
    
- DNS converts domain → IP.
    
- Server responds with status code + content.
    
- cURL allows sending raw HTTP requests from command line.
    

---
