## 1. XML External Entity (XXE)

- **XXE (XML External Entity) Injection** occurs when an application processes **user-controlled XML** using an unsafe XML parser.
    
- Attackers can abuse XML features, especially **external entities**, to perform unintended actions.
    
- Possible impacts include:
    
    - Reading sensitive files
        
    - Disclosing server-side information
        
    - Accessing internal resources
        
    - Causing denial of service
        
- XXE is recognized as a major web security risk by **OWASP**.
    

---

# 2. XML

**XML (Extensible Markup Language)** is designed mainly for **storing and transferring structured data**, rather than displaying it.

Example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <sender>john@inlanefreight.com</sender>
  <body>Hello</body>
</email>
```

### XML Structure

|Term|Meaning|Example|
|---|---|---|
|**Tag**|Defines keys/elements in XML|`<date>`|
|**Entity**|XML variable/reference|`&lt;`|
|**Element**|Root or child component containing data|`<date>01-01-2022</date>`|
|**Attribute**|Additional information inside a tag|`encoding="UTF-8"`|
|**Declaration**|Usually first line; defines XML version/encoding|`<?xml version="1.0"?>`|

### Special Characters

XML uses special characters for its structure:

```text
<  >  &  "
```

They can be represented using entity references:

```text
&lt;   <
&gt;   >
&amp;  &
&quot; "
```

### XML Comments

```xml
<!-- This is a comment -->
```

---

# 3. XML DTD

**DTD (Document Type Definition)** defines the permitted structure of an XML document.

It can define:

- Root elements
    
- Child elements
    
- Data types/content
    

Example:

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

### DTD Locations

A DTD can be:

**1. Defined internally:**

```xml
<!DOCTYPE email [
  ...
]>
```

**2. Loaded from a file:**

```xml
<!DOCTYPE email SYSTEM "email.dtd">
```

**3. Loaded from a URL:**

```xml
<!DOCTYPE email SYSTEM "http://example.com/email.dtd">
```

---

# 4. XML Entities

Entities are essentially **XML variables**.

They are defined using the `ENTITY` keyword:

```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

Then referenced as:

```xml
&company;
```

The XML parser replaces `&company;` with:

```text
Inlane Freight
```

---

# 5. External XML Entities

The important feature for XXE is the ability to define an entity that references an **external resource**.

Example:

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

`SYSTEM` specifies the external resource that should be loaded.

`PUBLIC` can also be used for externally declared/public entities.

---

# 6. Why External Entities Matter

When XML is processed **server-side**, an external entity may reference resources available to the backend server.

For example:

```xml
<!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
```

When referenced:

```xml
&signature;
```

the XML parser may load the referenced resource and substitute its contents.

This becomes dangerous when:

- XML input is controlled by the user.
    
- The server uses an unsafe XML parser.
    
- External entity processing is enabled.
    

This combination can lead to **XXE vulnerabilities**.

---

## Key Takeaways

- **XXE = abuse of external entities in unsafe XML parsing.**
    
- XML is used for **structured data storage/transfer**.
    
- **DTD** defines XML document structure.
    
- **ENTITY** creates XML variables.
    
- `SYSTEM` can reference external resources.
    
- External entities can reference resources such as:
    
    - `http://...`
        
    - `file://...`
        
- If user-controlled XML is parsed unsafely, external entities may cause **sensitive data disclosure or other server-side attacks**.
    
- The next step is understanding how external entities can be abused to **read local files and perform other malicious actions**.