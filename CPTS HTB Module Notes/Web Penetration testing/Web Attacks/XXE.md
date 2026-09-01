#  — Notes

## 1. XML External Entity (XXE) Injection

- **XXE (XML External Entity Injection)** occurs when an application processes **user-controlled XML** using an unsafe XML parser.
    
- Attackers can abuse XML features such as **external entities** to perform malicious actions.
    
- Possible impacts include:
    
    - Reading sensitive files from the server
        
    - Accessing internal resources
        
    - Causing denial of service
        
    - Potentially interacting with backend systems
        
- XXE is considered a major web security risk and is included in the **OWASP Top 10**.
    

---

## 2. XML

**XML (Extensible Markup Language)** is used mainly to **store and transfer structured data**.

Unlike HTML, XML is not primarily designed for displaying data.

### XML Structure

XML documents use a tree structure:

```xml
<email>
    <date>01-01-2022</date>
    <sender>john@example.com</sender>
    <body>Hello</body>
</email>
```

- **Root element:** The first/main element (`<email>`)
    
- **Child elements:** Elements contained inside the root element (`<date>`, `<sender>`, `<body>`)
    
- **Tags:** Define XML elements.
    
- **Attributes:** Additional information inside tags.
    
- **Entities:** XML variables/references.
    
- **Declaration:** Usually appears at the beginning and specifies XML version/encoding.
    

---

## 3. Important XML Components

|Component|Meaning|Example|
|---|---|---|
|**Tag**|Defines XML structure|`<date>`|
|**Entity**|XML variable/reference|`&company;`|
|**Element**|Tag + its contained value|`<date>01-01-2022</date>`|
|**Attribute**|Additional information for an element|`encoding="UTF-8"`|
|**Declaration**|Defines XML version/encoding|`<?xml version="1.0"?>`|

### XML Special Characters

Characters used by XML syntax must sometimes be represented using entities:

```text
<   → &lt;
>   → &gt;
&   → &amp;
"   → &quot;
```

XML comments:

```xml
<!-- This is a comment -->
```

---

# 4. XML DTD

**DTD (Document Type Definition)** defines the allowed structure of an XML document.

It can specify:

- The root element
    
- Child elements
    
- Which elements can contain other elements
    
- What type of data elements contain
    

Example:

```xml
<!DOCTYPE email [
  <!ELEMENT email (date, sender, body)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

### DTD Locations

A DTD can be:

**Internal:**

```xml
<!DOCTYPE email [
    ...
]>
```

**External file:**

```xml
<!DOCTYPE email SYSTEM "email.dtd">
```

**External URL:**

```xml
<!DOCTYPE email SYSTEM "http://example.com/email.dtd">
```

---

# 5. XML Entities

Entities are essentially **XML variables**.

They are defined using the `ENTITY` keyword.

Example:

```xml
<!DOCTYPE email [
    <!ENTITY company "Inlane Freight">
]>
```

The entity can then be referenced as:

```xml
&company;
```

The XML parser replaces `&company;` with:

```text
Inlane Freight
```

---

# 6. External XML Entities

The important XXE feature is the ability to define an entity that references an **external resource**.

Example:

```xml
<!DOCTYPE email [
    <!ENTITY company SYSTEM "http://localhost/company.txt">
    <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

### `SYSTEM`

`SYSTEM` tells the XML parser to load the entity from an external resource.

External resources can include:

```text
http://...
file://...
```

When the XML parser processes:

```xml
&signature;
```

it may replace it with the contents of the referenced resource.

---

# 7. Why External Entities Cause XXE

The dangerous situation occurs when:

1. An application accepts **XML from the user**.
    
2. The XML parser allows **DTD processing**.
    
3. The parser allows **external entities**.
    
4. An external entity references a resource on the server.
    
5. The application returns or otherwise processes the resulting data.
    

For example:

```text
User-controlled XML
        ↓
XML Parser
        ↓
External Entity
        ↓
Server-side resource
        ↓
Potential information disclosure
```

This is the fundamental concept behind **XXE injection**.

---

## Key Takeaways

- **XXE = abusing unsafe XML parsing through external entities.**
    
- XML is primarily used for **structured data storage and transfer**.
    
- **DTD** defines an XML document's structure.
    
- **ENTITY** creates XML variables.
    
- `SYSTEM` can reference an **external resource**.
    
- External entities become dangerous when they can reference resources on the backend server.
    
- The core issue is generally **unsafe XML parser configuration combined with user-controlled XML**.