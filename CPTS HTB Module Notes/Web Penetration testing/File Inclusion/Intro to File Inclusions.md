![Image](https://images.openai.com/static-rsc-4/BEiT1sZze4E6vJ0dMEQ8S5mSBegmOmRh7_Q8Hx1X4frFWF7ysmuLt1oZPs_4mCWNDhKcM3-xORQUwTqwQwfpDaC352xfDK3G0AtwhZLT7oVKEQDBtKS2c0LRMJtMP3axlnDFY3Xdp_gARYWWdMtRB0wzVi-bC6WA4HNm8e4js41U2qpyZH7Sag4JRLzb_mSP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/o0iAFxsIdmEgH1wOrlaW06lfnyLUOHJy2WU1K5-5Se146H1SLnb8zXwbKBw9FbSNZZwi-5y3RqwVil2JPPEHkDF0SvominBJZUZI021JD4rXcWhT2qBzuGy03iV_unRF2lpzq_BsmZFZeGwYy0Svk70UFLa0lKJove7qQSJrchlHEO6TXc373_XcMTy8R4ZS?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/u4QidWS7XGKpVVbybrvTXbvDR_pK2WQD2v7LFK-ca-F7fUA3xe1jDan6lgZeTKZGjciA4_cw_-R-uIfAX2opvuztUdPuNRyJUV1mnfoEF6G1bP3oZIQf-huVKxaFZ2MXuyX1_cSAIH8L29wzp0qn2i-TNrrvszGfsO0O6eJ8UbHf5q-qWsK4epxV9bWE2WZr?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/ztG5P5-z3vMFVO8La5sCM47kBIH5vCaIp7s-eCBVeb56lTUeY5XR5Qz84c-Wcwwtu7dnkliaaQxSuMKSmijjWiXmGSRn78hlXNLLQsokrqIK0dgpwtReRpV1RBxyCLgU2mhZI2wMYp22-YMwp2bGZg0LWrbkR2eoYu979iECdaZXNIU98P7sYGvAgigRwlkY?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/2JdLMEIiJAkLeADXIgVXfL_IouBc5fSilggV_kOqqhtWtvDixc-IhT61wh0xCURq-FZaRt_CRo77900ZGQEaOKrjaZGYCvIo4N-YNgCir76Vr3y1NWV2ZUwrT_Fsgz4qQxptcFa33xVAGyL_hMFHFOC_RZeUPOGeDfqCNURhzxgAoSNzuf_lAALwpmdPS1gl?purpose=fullsize)

## 1. What is File Inclusion?

Many modern back-end languages such as **PHP, JavaScript, and Java** use HTTP parameters to determine what content should be displayed on a web page.

This allows developers to:

- Build **dynamic web pages**
    
- Reduce the overall size of scripts
    
- Simplify application code
    
- Dynamically load different resources
    

For example:

```text
/index.php?page=about
```

Here, the `page` parameter determines what content the application loads.

The security problem occurs when this parameter is **not securely coded**.

If an attacker can manipulate the parameter, they may be able to make the application load the contents of an unintended file from the server.

This can result in a:

> **Local File Inclusion (LFI) vulnerability**

---

# 2. Local File Inclusion (LFI)

LFI is commonly encountered in **templating engines**.

A templating engine allows different pages of a website to share common components such as:

- Header
    
- Navigation bar
    
- Footer
    

Instead of duplicating these components across every page, the application loads the common elements once and dynamically loads the content that changes.

For example:

```text
/index.php?page=about
```

The application may work conceptually like this:

```text
                HTTP Request
                     │
                     ▼
          /index.php?page=about
                     │
                     ▼
              page parameter
                     │
                     ▼
                about.php
                     │
                     ▼
             Page is displayed
```

The vulnerability occurs when the attacker has control over the value of `page`.

Instead of:

```text
page=about
```

the attacker may attempt to manipulate the path so the application loads another local file.

---

# 3. Impact of LFI

LFI can have serious consequences.

The source identifies three major potential impacts:

### ① Source Code Disclosure

The attacker may be able to read application source code.

This can reveal:

- Application logic
    
- Hidden functionality
    
- Other vulnerabilities
    
- Credentials
    
- Database keys
    
- Other sensitive information
    

### ② Sensitive Data Exposure

Local files may contain sensitive information that could help an attacker understand or compromise the server.

### ③ Remote Code Execution

Under **specific conditions**, LFI may potentially lead to **Remote Code Execution (RCE)**.

This can result in compromise of:

- The back-end server
    
- Other connected systems
    

> ⚠️ **Important:** LFI does **not automatically mean RCE**. Code execution depends on additional conditions and on how the vulnerable application handles the included file.

---

# 4. Vulnerable Code — General Concept

File Inclusion vulnerabilities can occur in many technologies:

- **PHP**
    
- **NodeJS**
    
- **Java**
    
- **.NET**
    
- Other web frameworks
    

Although their syntax differs, the common concept is:

```text
User-controlled input
        ↓
File/resource path
        ↓
File-loading function
        ↓
File is read/rendered/executed
```

---

# 5. Language Parameter Example

A common application feature is language selection.

For example:

```text
?language=es
```

The application might use different directories:

```text
/en/
 /es/
```

So:

```text
?language=en
```

could cause the application to load content from:

```text
/en/
```

while:

```text
?language=es
```

could load:

```text
/es/
```

If the user has control over the path being loaded, this functionality may potentially be abused to access unintended files.

---

# 6. PHP

## `include()`

PHP provides the `include()` function for loading files.

A vulnerable example from the source:

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

The important issue here is:

```text
$_GET['language']
        ↓
include()
```

The HTTP parameter is directly passed to the file inclusion function.

### Why is this dangerous?

If user input controls the path passed to `include()`, the application may load files that the developer never intended to expose.

---

## Other PHP functions

The source also identifies several other functions that can be relevant:

```text
include()
include_once()
require()
require_once()
file_get_contents()
```

The important point is that vulnerability depends on **how user-controlled input reaches these functions**.

---

# 7. NodeJS

NodeJS applications can also load content based on HTTP parameters.

The source gives this example:

```javascript
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

Here:

```text
req.query.language
        ↓
path.join()
        ↓
fs.readFile()
        ↓
File contents
        ↓
HTTP response
```

The important point is that the parameter from the URL is being incorporated into the file path.

---

# 8. NodeJS — Express `render()`

Another example uses Express.js:

```javascript
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

Here the parameter is part of the **URL path**.

For example:

```text
/about/en
/about/es
```

The value is retrieved using:

```javascript
req.params.language
```

and then used by:

```javascript
res.render()
```

### Important distinction

Query parameter:

```text
/index.php?language=en
```

Path parameter:

```text
/about/en
```

Both can potentially become security issues when their values are directly used to determine which resource gets loaded.

---

# 9. Java

The same general concept exists in Java web applications.

## `include`

Source example:

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

The application takes the request parameter and uses it as the file to include.

---

## `import`

Another function is:

```jsp
<c:import url= "<%= request.getParameter('language') %>"/>
```

The source explains that `include` can take a file or page URL and render it into the front-end template.

`import` may also render a local file or URL.

---

# 10. .NET

## `Response.WriteFile()`

The `.NET` example uses:

```text
Response.WriteFile()
```

This function takes a file path and writes the file's content to the response.

The source demonstrates the concept using a `language` request parameter.

```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

Conceptually:

```text
HTTP parameter
      ↓
language
      ↓
Response.WriteFile()
      ↓
File content
      ↓
HTTP response
```

---

# 11. `.NET — @Html.Partial()`

Another relevant function is:

```cs
@Html.Partial(HttpContext.Request.Query['language'])
```

This can render the specified file as part of the front-end template.

---

# 12. `.NET — include`

The source also gives:

```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

According to the source, this `include` functionality may:

- Render local files
    
- Render remote URLs
    
- Execute specified files
    

---

# ⭐ 13. READ vs EXECUTE

This is one of the **most important concepts in the entire topic**.

Not every File Inclusion function behaves the same way.

Some functions:

> **Only read the content of a file**

Others:

> **Execute the specified file**

Some functions additionally support:

> **Remote URLs**

Others only work with:

> **Local files on the back-end server**

---

# 14. Function Capability Table

|Technology|Function|Read Content|Execute|Remote URL|
|---|---|--:|--:|--:|
|**PHP**|`include()` / `include_once()`|✅|✅|✅|
|**PHP**|`require()` / `require_once()`|✅|✅|❌|
|**PHP**|`file_get_contents()`|✅|❌|✅|
|**PHP**|`fopen()` / `file()`|✅|❌|❌|
|**NodeJS**|`fs.readFile()`|✅|❌|❌|
|**NodeJS**|`fs.sendFile()`|✅|❌|❌|
|**NodeJS**|`res.render()`|✅|✅|❌|
|**Java**|`include`|✅|❌|❌|
|**Java**|`import`|✅|✅|✅|
|**.NET**|`@Html.Partial()`|✅|❌|❌|
|**.NET**|`@Html.RemotePartial()`|✅|❌|✅|
|**.NET**|`Response.WriteFile()`|✅|❌|❌|
|**.NET**|`include`|✅|✅|✅|

---

# 15. Why Read vs Execute Matters

Suppose an application allows an attacker to make the application **read** a file.

The result may be:

```text
File
 ↓
Read
 ↓
Content disclosure
```

This can expose source code or sensitive data.

But if the vulnerable functionality **executes** the included file:

```text
File
 ↓
Include
 ↓
Execute
 ↓
Potential code execution
```

The impact can be significantly greater.

The source specifically states that executing files may allow functions to be executed and eventually lead to code execution, while simply reading the content would expose the source without executing it.

---

# 16. Remote URL Support

Another important property is whether a function accepts **remote URLs**.

Think of the difference as:

```text
LOCAL ONLY
     ↓
Files already present
on the back-end server
```

versus:

```text
REMOTE URL SUPPORT
     ↓
May retrieve/load
resources from elsewhere
```

Therefore, during a security review, don't just ask:

> "Can this function load a file?"

Also ask:

> **"Can it load a remote URL?"**

The source's capability table is specifically useful for making this distinction.

---

# 17. White-Box / Code Audit Perspective

If you're reviewing source code, look for this pattern:

```text
       USER INPUT
           │
           ▼
    HTTP parameter
           │
           ▼
       File path
           │
           ▼
    File-loading sink
           │
     ┌─────┼─────┐
     ▼     ▼     ▼
    READ EXECUTE REMOTE
```

Examples of user-controlled input:

```text
$_GET['language']
req.query.language
req.params.language
request.getParameter(...)
HttpContext.Request.Query[...]
```

Then identify the function receiving that value.

---

# 18. Code Audit Checklist

When looking for File Inclusion vulnerabilities:

### Step 1 — Find user input

Look for:

```text
GET parameters
POST parameters
URL path parameters
Request parameters
```

### Step 2 — Follow the data

Ask:

```text
Where does the parameter go?
```

### Step 3 — Look for file operations

Search for functions such as:

```text
include()
require()
file_get_contents()
fs.readFile()
res.render()
jsp:include
jsp:import
Response.WriteFile()
@Html.Partial()
```

### Step 4 — Determine the capability

Ask:

```text
Can it READ?
Can it EXECUTE?
Can it access REMOTE URLs?
```

### Step 5 — Determine the impact

Possible results include:

```text
Source-code disclosure
        ↓
Sensitive information
        ↓
Credential/key exposure
        ↓
Further compromise
```

And under specific conditions:

```text
LFI
 ↓
Code execution
 ↓
Server compromise
```

---

# 19. Critical Mental Model 🧠

Memorize this:

```text
┌──────────────────┐
│ User-controlled  │
│     input        │
└────────┬─────────┘
         ↓
┌──────────────────┐
│   File/resource  │
│      path        │
└────────┬─────────┘
         ↓
┌──────────────────┐
│ File-loading     │
│     function     │
└────────┬─────────┘
         ↓
    ┌────┼────┐
    ↓    ↓    ↓
   READ EXEC REMOTE
```

This is the pattern you should recognize during a **white-box review or source-code audit**.

---

# 20. Important Terminology

### LFI

**Local File Inclusion**

A vulnerability where application behavior allows unintended local files to be included/read/rendered.

### Source Code Disclosure

Exposure of the application's source code.

### Sensitive Data Exposure

Exposure of sensitive information stored on the server.

### RCE

**Remote Code Execution**

The ability to execute code on the remote system.

### File Inclusion Sink

The function or operation that consumes the attacker-influenced file path.

Examples:

```text
include()
fs.readFile()
res.render()
Response.WriteFile()
```

---

# ⭐ 21. Most Important Points to Memorize

### 🔴 Point 1

**User-controlled file paths are the main warning sign.**

---

### 🔴 Point 2

LFI is commonly associated with **templating engines** and dynamic content loading.

---

### 🔴 Point 3

Not every file-loading function executes files.

Always distinguish:

```text
READ ≠ EXECUTE
```

---

### 🔴 Point 4

Remote URL support is another important property.

```text
Local file support
        ≠
Remote URL support
```

---

### 🔴 Point 5

Even read-only access can be dangerous.

Source code can expose:

- Credentials
    
- Database keys
    
- Application logic
    
- Other vulnerabilities
    

---

### 🔴 Point 6

LFI can potentially lead to RCE **under specific conditions**.

Don't automatically equate:

```text
LFI = RCE
```

---

# 22. Quick Revision Table

|Question|Answer|
|---|---|
|What is LFI?|Local File Inclusion|
|Common location?|Templating engines|
|Main root cause?|User-controlled input influencing a file path|
|Can LFI expose source code?|✅ Yes|
|Can LFI expose sensitive data?|✅ Yes|
|Does every LFI lead to RCE?|❌ No|
|Can some inclusion functions execute files?|✅ Yes|
|Can some functions access remote URLs?|✅ Yes|
|What should you inspect in source code?|Input → path → file-loading sink|

---

# 🧠 23. Final Cheat Sheet

```text
                 LFI
                  │
                  ▼
       User controls a parameter
                  │
                  ▼
       Parameter influences path
                  │
                  ▼
        File-loading functionality
                  │
          ┌───────┼────────┐
          ▼       ▼        ▼
         READ   EXECUTE   REMOTE
          │       │        │
          ▼       ▼        ▼
       Source   Possible   Remote
       /data    code       resource
       leak     execution  access
```

### The golden rule:

> **Whenever user-controlled input reaches a file/resource-loading function, investigate how the path is constructed and determine whether the function can read, execute, or access remote resources.**

The source concludes that **File Inclusion vulnerabilities are critical** and can potentially result in compromise of the entire back-end server. Even when only source code can be read, that source may reveal credentials, database keys, or additional vulnerabilities.