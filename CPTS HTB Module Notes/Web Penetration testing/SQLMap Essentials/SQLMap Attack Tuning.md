![Image](https://images.openai.com/static-rsc-4/TzhHTV5jC1PeII5iQ3udBPU12_xi0Cr6zI_PgCXc5OopZTF3dbxM6qfbICVXV50EjRQ_VCP0w3HVR2BYlpdc7jdMCBvCyognGmLyYwMNwABQcZdDjNvRB01VMNnWLgUVqEw1vb9KzP3H8foTayuYTBQS5_g9k8MG9x4v44Vs2R-F_2Hla2yuR3tZjTZL5kq_?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/AoB2kLw8e-TrUxptQj-krTyXmdTH1b_oi6ffsAOnSCiBpgkQZeUizhZ7DHWU7EcKOPq1k830B_uDKLoZYZ0aZyAnm9lvzk_T4RyKrFwBR63D16_TtgaYKjplP12snXF00VxSlom6bEKuM4zP1L2p3VQFy9ZzyRmk6w9qDOzEJNwuH5mInAEDNYXMKFdguwwP?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/W-8j0GZdocLz8hA1lH8ZGVuGbC8HcF8XitRtiZvBZ2HIDymkfSmGMPRCIE75m9PqHdf6DyamlPCJbvUOd2L8m6FgiCHWKq3Fb7b3PYtH61bhZ-HGstxsJDsLSNjSSgh9FjTq7IVWTXrd9Qx12xkU17sWnmetC88UQPZyOEGFQfVdDR77fGvGZLlgDWB69a84?purpose=fullsize)

![Image](https://images.openai.com/static-rsc-4/jrdBfvaz-GnVlrc1opSnc4sG8ki7WKgVPZi4J0iRsDJ6ZZVmo9bTNQ4VUS1pM6tL7AVRopXt1rCrrh0EdfyoGytjdxxXJOAZn4YHcpYB0l6lb0Ic2GXU2jK1lUkv7qoXwKeKLD4_8UAok-a-sd0sAyq8qzKm8AmOC9HqwuSPcbqyiX7GaEicFJCl8APq8iOA?purpose=fullsize)

---

# 1. What Is Attack Tuning?

Normally, SQLMap works with its built-in collection of:

- SQL injection payloads
    
- Prefixes
    
- Suffixes
    
- Boundaries
    
- DBMS-specific techniques
    
- Detection methods
    

In most situations:

```text
Target
  ↓
SQLMap defaults
  ↓
Automatic detection
  ↓
Confirmed SQLi
```

But sometimes the vulnerable application has an unusual SQL query structure.

Then:

```text
Default SQLMap
      ↓
Detection fails / incomplete
      ↓
Fine-tuning
      ↓
More appropriate payloads
      ↓
Detection
```

---

# 2. Payload Structure

Every SQLMap payload can be understood as having two major parts:

```text
┌──────────────────────────────────────────┐
│              SQLi Payload                │
│                                          │
│  Boundary + Vector + Boundary            │
└──────────────────────────────────────────┘
```

The two important concepts are:

1. **Vector**
    
2. **Boundaries**
    

---

# 3. Vector

The **vector** is the central SQL code that performs the intended SQL operation.

Example from the material:

```sql
UNION ALL SELECT 1,2,VERSION()
```

Think of the vector as:

> **The useful SQL logic inside the payload.**

Conceptually:

```text
Prefix
   +
VECTOR
   +
Suffix
```

---

# 4. Boundaries

Boundaries are the prefix/suffix structures surrounding the vector.

Example:

```text
'<vector>-- -
```

Here:

```text
'
```

acts as a prefix, while:

```text
-- -
```

acts as a suffix/comment component.

Their purpose is to make the injected SQL fit correctly into the existing SQL statement.

---

# 5. Why Boundaries Matter

Imagine the application constructs:

```php
$query = "SELECT ... WHERE id LIKE (('" . $_GET["q"] . "'))";
```

The input isn't simply placed into:

```sql
WHERE id = INPUT
```

Instead, it is placed inside:

```sql
WHERE id LIKE (('INPUT'))
```

Therefore, SQLMap needs a payload that properly interacts with the existing:

```text
((' ... '))
```

structure.

This is where custom prefixes and suffixes can become useful.

---

# 6. `--prefix`

SQLMap provides:

```text
--prefix
```

to manually specify a payload prefix.

Example:

```bash
sqlmap -u "www.example.com/?q=test" \
--prefix="%'))"
```

This means SQLMap will place the vector after the specified prefix.

---

# 7. `--suffix`

Similarly:

```text
--suffix
```

specifies the ending/boundary after the vector.

Example:

```bash
--suffix="-- -"
```

So together:

```bash
sqlmap -u "www.example.com/?q=test" \
--prefix="%'))" \
--suffix="-- -"
```

the conceptual payload becomes:

```text
%')) + VECTOR + -- -
```

---

# 8. Prefix + Vector + Suffix

The easiest way to remember this is:

```text
┌────────┐ ┌────────────────────────┐ ┌─────────┐
│ Prefix │ │         Vector         │ │ Suffix  │
└────────┘ └────────────────────────┘ └─────────┘
     │                 │                    │
     ▼                 ▼                    ▼
   Close/          SQL logic             Finish/
   escape          to execute            comment
```

---

# 9. Example from the Material

Given:

```php
$query = "SELECT id,name,surname FROM users
WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
```

SQLMap uses:

```text
Prefix:
%'))

Vector:
UNION ALL SELECT 1,2,VERSION()

Suffix:
-- -
```

The resulting SQL becomes:

```sql
SELECT id,name,surname FROM users
WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

The important point is that the custom boundaries make the injected vector syntactically compatible with the surrounding query.

---

# 10. When Should You Use `--prefix` / `--suffix`?

Usually:

**Don't.**

SQLMap already contains many common boundaries.

Use them when:

```text
Default payloads
      ↓
Don't fit query structure
      ↓
You understand the query structure
      ↓
Custom boundary is required
```

This is an **advanced tuning technique**, not a first step.

---

# 11. Level and Risk

Two very important SQLMap options are:

```text
--level
--risk
```

They control how extensively SQLMap tests the target.

---

# 12. `--level`

The material defines:

```text
--level = 1–5
Default = 1
```

Increasing the level expands the set of:

- Vectors
    
- Boundaries
    

that SQLMap considers.

Conceptually:

```text
Level 1
   ↓
Most common/high-probability tests

Level 2
   ↓
More tests

Level 3
   ↓
More tests

Level 4
   ↓
More tests

Level 5
   ↓
Largest boundary/vector coverage
```

---

# 13. What Level Actually Controls

Think:

> **Level = How broadly should SQLMap search?**

Higher level means SQLMap considers payloads/boundaries with lower expected success probability.

Therefore:

```text
Higher level
     ↓
More payloads
     ↓
More requests
     ↓
Longer scan
```

---

# 14. `--risk`

The material defines:

```text
--risk = 1–3
Default = 1
```

Risk controls which additional vectors SQLMap is willing to use based on their potential impact.

Conceptually:

```text
Risk 1
   ↓
Lower-risk payload selection

Risk 2
   ↓
More potentially intrusive payloads

Risk 3
   ↓
Broadest/highest-risk testing
```

---

# 15. Level vs Risk

This distinction is extremely important.

|Option|Main question|
|---|---|
|`--level`|How many/which payloads and boundaries should be considered?|
|`--risk`|How potentially dangerous are the payloads SQLMap is allowed to use?|

Memory trick:

```text
LEVEL = Breadth
RISK  = Potential impact
```

---

# 16. Why High Level/Risk Can Be Slow

The material gives a very important comparison.

Default:

```text
--level=1 --risk=1
```

can use up to approximately:

```text
72 payloads
```

for a single parameter.

The most detailed combination:

```text
--level=5 --risk=3
```

can increase this to approximately:

```text
7,865 payloads
```

That's a **massive increase**.

Conceptually:

```text
Level 1 / Risk 1
       │
       ▼
~72 payloads
       │
       ▼
Fast-ish

Level 5 / Risk 3
       │
       ▼
~7,865 payloads
       │
       ▼
Much more testing
       │
       ▼
Much slower / potentially more intrusive
```

---

# 17. Why You Usually Shouldn't Increase Them Immediately

SQLMap's defaults are already designed around common SQL injection scenarios.

Therefore:

```text
Default
  ↓
Common payloads
  ↓
Common boundaries
  ↓
Efficient detection
```

Randomly using:

```bash
--level=5 --risk=3
```

can turn a relatively short scan into a very large scan.

So the recommended approach is:

> **Tune only when the default scan has a specific limitation you understand.**

---

# 18. Viewing Payloads with `-v`

To understand exactly what SQLMap is sending, increase verbosity.

For example:

```bash
sqlmap -u "www.example.com/?id=1" -v 3 --level=5
```

At verbosity level 3 or higher, SQLMap can display:

```text
[PAYLOAD]
```

entries.

For example:

```text
[PAYLOAD] 1) AND 5907=7031-- AuiO
```

and:

```text
[PAYLOAD] 1')) AND 1049=6686 AND (('OoWT' LIKE 'OoWT
```

---

# 19. Why `[PAYLOAD]` Is Useful

It lets you see:

```text
What is SQLMap actually testing?
```

instead of only seeing:

```text
Testing boolean-based blind...
```

You can therefore compare:

```text
Level 1
```

against:

```text
Level 5
```

and observe how the tested payload set expands.

---

# 20. Default Level Payloads

With default settings:

```bash
sqlmap -u www.example.com/?id=1 -v 3
```

you may see a relatively small collection:

```text
[PAYLOAD] 1) AND 2678=8644 AND (3836=3836
[PAYLOAD] 1 AND 7496=4313
[PAYLOAD] 1 AND 7036=6691-- DmQN
[PAYLOAD] 1') AND 9393=3783 AND ('SgYz'='SgYz
[PAYLOAD] 1' AND 6214=3411 AND 'BhwY'='BhwY
```

This is the normal efficient behavior.

---

# 21. Level 5 Payloads

With:

```bash
--level=5
```

SQLMap explores substantially more boundaries.

You may see combinations involving:

```text
1)
1'))
1%'
1"
1")))
...
```

The exact payloads are generated dynamically, but the key concept is:

```text
Higher level
    ↓
More boundary variations
    ↓
More possible injection contexts
```

---

# 22. Level/Risk and Vectors

The level/risk settings can also affect which SQLi techniques SQLMap tests.

With default settings you might see:

```text
AND boolean-based blind
OR boolean-based blind
MySQL error-based
...
```

With:

```bash
--level=5 --risk=3
```

you can see a much larger collection of DBMS-specific and technique-specific tests.

Examples from the material include:

```text
PostgreSQL AND boolean-based blind
PostgreSQL OR boolean-based blind
Oracle AND boolean-based blind
MySQL ORDER BY / GROUP BY techniques
Stacked-query variants
Additional error-based techniques
```

---

# 23. Why DBMS-Specific Payloads Matter

Different databases behave differently.

For example:

```text
MySQL
PostgreSQL
Oracle
Microsoft SQL Server
```

do not necessarily support identical syntax or functions.

Therefore SQLMap contains specialized payloads.

Conceptually:

```text
                 SQLi
                  │
       ┌──────────┼──────────┐
       ▼          ▼          ▼
     MySQL    PostgreSQL   Oracle
       │          │          │
       ▼          ▼          ▼
   Specialized payloads
```

Higher tuning levels can make SQLMap explore more of these possibilities.

---

# 24. Risk and `OR` Payloads

One particularly important point from the material is **OR-based payloads**.

Some `OR` payloads can be more dangerous because of the possibility that the underlying SQL statement modifies database content.

For example, imagine a vulnerable application performing:

```sql
UPDATE ...
```

or:

```sql
DELETE ...
```

A payload that changes the logical condition could potentially affect more records than intended.

Therefore:

```text
OR payload
   ↓
Potentially broader condition
   ↓
Potentially greater impact
```

This is why SQLMap's default risk setting is conservative.

---

# 25. Login Pages as a Special Case

The material notes that some SQLi scenarios may require `OR` payloads, particularly certain login-page query structures.

This can be a situation where increasing risk is considered during an authorized test.

The important lesson is:

> **Higher risk is not simply "better detection." It means accepting more potentially dangerous tests.**

---

# 26. Advanced Tuning

Beyond prefix/suffix and level/risk, SQLMap provides additional detection controls.

Important ones include:

```text
--code
--titles
--string
--text-only
--technique
--union-cols
--union-char
--union-from
```

These are generally used when SQLMap needs help understanding how the application's responses indicate TRUE/FALSE or how a UNION query must be structured.

---

# 27. `--code`

Sometimes the TRUE and FALSE responses have different HTTP status codes.

For example:

```text
TRUE  → HTTP 200
FALSE → HTTP 500
```

If the distinction is reliable, SQLMap can use:

```bash
--code=200
```

to treat a particular HTTP status as the TRUE condition.

---

# 28. HTTP Status Code Detection

Normally, SQLMap may compare page content.

But sometimes the application gives a clearer signal:

```text
Condition
   │
   ├── TRUE  → 200 OK
   │
   └── FALSE → 500 Error
```

Then:

```text
--code=200
```

tells SQLMap:

> Use HTTP status code 200 as the relevant TRUE-response indicator.

---

# 29. `--titles`

Sometimes TRUE and FALSE responses have different HTML titles.

Example:

```html
<title>Welcome</title>
```

versus:

```html
<title>Error</title>
```

SQLMap can be instructed to compare page titles using:

```text
--titles
```

Conceptually:

```text
Response
   │
   ▼
<title>...</title>
   │
   ▼
Compare titles
```

This can be useful when the full response contains lots of irrelevant dynamic content.

---

# 30. `--string`

Suppose:

```text
TRUE response:
"success" appears

FALSE response:
"success" absent
```

Then:

```bash
--string=success
```

can tell SQLMap to use that string as the response indicator.

---

# 31. `--string` Mental Model

```text
             Response
                │
                ▼
       Contains "success"?
           /           \
         YES            NO
          │              │
        TRUE           FALSE
```

This is similar to the `--string="luther"` concept from the previous SQLMap output section.

---

# 32. `--text-only`

Web pages often contain large amounts of HTML that don't necessarily matter to SQLMap's comparison.

For example:

```html
<script>
...
</script>

<style>
...
</style>

<meta ...>

<div>
Visible text
</div>
```

With:

```text
--text-only
```

SQLMap can focus on textual content rather than all HTML markup.

---

# 33. Why `--text-only` Helps

Imagine:

```text
TRUE response
  ↓
Huge HTML page
  ↓
Dynamic scripts/styles
  ↓
Visible text differs slightly
```

and:

```text
FALSE response
  ↓
Huge HTML page
  ↓
Dynamic scripts/styles
  ↓
Visible text differs
```

Removing HTML tags can reduce noise.

Conceptually:

```text
Full HTML
   ↓
Remove HTML tags
   ↓
Visible/text content
   ↓
Compare
```

---

# 34. `--technique`

SQLMap supports multiple SQLi techniques.

The technique letters are:

```text
B = Boolean-based blind
E = Error-based
U = UNION query-based
S = Stacked queries
T = Time-based blind
Q = Inline queries
```

So:

```text
BEUSTQ
```

represents the available technique categories.

---

# 35. Restricting Techniques

Suppose you want SQLMap to use only:

```text
B
E
U
```

you can specify:

```bash
--technique=BEU
```

This means:

```text
Boolean
+
Error
+
UNION
```

while excluding:

```text
S
T
Q
```

---

# 36. Why Restrict Techniques?

There can be practical reasons.

For example:

```text
Time-based blind
      ↓
Artificial delays
      ↓
Slow scan / timeouts
```

You might therefore exclude time-based testing when it is causing problems.

Conceptually:

```text
All techniques
      ↓
Choose relevant subset
      ↓
Faster/more controlled testing
```

---

# 37. Technique Selection Diagram

```text
              SQLMap Techniques
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
      B/E/U        S/T/Q       ...
        │
        ▼
--technique=BEU
        │
        ▼
Only selected techniques
```

---

# 38. UNION SQLi Tuning

UNION SQL injection sometimes requires additional information.

Important options include:

```text
--union-cols
--union-char
--union-from
```

These help SQLMap construct compatible UNION queries.

---

# 39. `--union-cols`

If you already know the exact number of columns in the vulnerable query, you can provide it.

Example:

```bash
--union-cols=17
```

This tells SQLMap:

> The vulnerable query has 17 columns.

Conceptually:

```text
Original query
      ↓
17 columns
      ↓
UNION query
      ↓
Must provide compatible column count
```

---

# 40. Why Column Count Matters

Suppose the original query returns:

```text
17 columns
```

A UNION query must match the column count.

Conceptually:

```text
SELECT ... 17 columns
UNION
SELECT ... 17 columns
```

rather than:

```text
SELECT ... 17 columns
UNION
SELECT ... 3 columns
```

The latter isn't compatible in the normal UNION case.

---

# 41. `--union-char`

SQLMap normally uses dummy values such as:

```text
NULL
```

or random integers while constructing UNION payloads.

Sometimes those values are incompatible with the expected data types.

You can provide an alternative character/value with:

```bash
--union-char='a'
```

Conceptually:

```text
Default:
NULL / random integer

Alternative:
'a'
```

This can help when the normal dummy values don't fit the target query.

---

# 42. `--union-from`

Some DBMS/query contexts require a `FROM` clause in the UNION query.

The material gives Oracle as an example.

You can specify the table with:

```bash
--union-from=users
```

Conceptually:

```text
UNION SELECT ...
FROM users
```

The option provides SQLMap with the needed `FROM` appendix.

---

# 43. Why `--union-from` Might Be Needed

SQLMap may sometimes be unable to identify the DBMS early enough to automatically construct the appropriate UNION syntax.

Therefore:

```text
DBMS not identified correctly
        ↓
Automatic UNION construction fails
        ↓
Provide required FROM information
```

---

# 44. Advanced Tuning Summary

|Option|Purpose|
|---|---|
|`--prefix`|Custom payload prefix|
|`--suffix`|Custom payload suffix|
|`--level`|Expand payload/boundary testing|
|`--risk`|Expand testing toward potentially more intrusive payloads|
|`--code`|Use HTTP status code for response comparison|
|`--titles`|Compare HTML page titles|
|`--string`|Use a specific string as response indicator|
|`--text-only`|Compare textual content rather than full HTML|
|`--technique`|Restrict SQLi techniques|
|`--union-cols`|Specify UNION column count|
|`--union-char`|Change UNION dummy value|
|`--union-from`|Specify UNION `FROM` appendix|

---

# 45. Attack-Tuning Decision Tree

```text
                 SQLMap detection problem
                         │
                         ▼
              Does default scan work?
                    /          \
                  YES           NO
                  │              │
                  ▼              ▼
               Finish      Understand query
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
               Odd syntax   Response     UNION issue
                    │        signal           │
                    ▼           │              ▼
            --prefix/        ┌──┼──┐      --union-cols
            --suffix         │  │  │      --union-char
                             ▼  ▼  ▼      --union-from
                           code title string
                             │
                             ▼
                        --text-only
                             │
                             ▼
                    Technique problem?
                             │
                             ▼
                       --technique
                             │
                             ▼
                     Need more coverage?
                             │
                             ▼
                       --level/--risk
```

---

# 46. Recommended Tuning Philosophy

The material's most important practical recommendation is:

> **Do not immediately increase everything.**

Avoid jumping straight to:

```bash
--level=5 --risk=3
```

unless you have a reason.

Instead:

```text
Default scan
    ↓
Observe failure
    ↓
Identify limitation
    ↓
Change ONE relevant setting
    ↓
Test again
```

This makes troubleshooting much easier.

---

# 47. Good vs Bad Tuning

### Bad approach

```text
SQLMap didn't find SQLi
        ↓
--level=5
--risk=3
--technique=BEUSTQ
--prefix=...
--suffix=...
Everything changed
        ↓
Huge scan
```

Now you don't know which change mattered.

### Better approach

```text
SQLMap didn't find SQLi
        ↓
Understand application/query
        ↓
Identify likely issue
        ↓
Apply targeted option
        ↓
Retest
```

---

# 48. Most Important Concepts to Memorize

### Payload structure

```text
PREFIX + VECTOR + SUFFIX
```

### Level

```text
LEVEL = more payload/boundary coverage
```

### Risk

```text
RISK = potentially more intrusive payloads
```

### Response comparison

```text
--code
--titles
--string
--text-only
```

### Technique selection

```text
--technique=BEU
```

### UNION tuning

```text
--union-cols
--union-char
--union-from
```

---

# 49. Quick Revision Table

|Concept|Remember|
|---|---|
|Vector|Main SQL logic|
|Prefix|Starts/bounds payload|
|Suffix|Ends/bounds payload|
|`--prefix`|Manually define prefix|
|`--suffix`|Manually define suffix|
|`--level`|More payload/boundary coverage|
|`--risk`|More potentially intrusive payloads|
|`-v 3`|Useful for seeing `[PAYLOAD]`|
|`--code`|Detect using HTTP status|
|`--titles`|Detect using page title|
|`--string`|Detect using specific string|
|`--text-only`|Compare visible/text content|
|`--technique`|Select SQLi techniques|
|`--union-cols`|Known UNION column count|
|`--union-char`|Alternative UNION filler|
|`--union-from`|Specify UNION `FROM`|

---

# 50. Final Mental Model

The whole section can be remembered as:

```text
                    SQLMap
                      │
                      ▼
                 Default Scan
                      │
              ┌───────┴───────┐
              │               │
           Works            Doesn't work
              │               │
              ▼               ▼
            Done       Understand problem
                              │
            ┌─────────────────┼──────────────────┐
            │                 │                  │
            ▼                 ▼                  ▼
       Query syntax      Response signal     UNION structure
            │                 │                  │
            ▼                 ▼                  ▼
    --prefix/suffix    --code/--titles    --union-cols
                       --string           --union-char
                       --text-only        --union-from
                              │
                              ▼
                       Technique choice
                              │
                              ▼
                        --technique
                              │
                              ▼
                       More coverage?
                              │
                              ▼
                       --level/--risk
```

## 🔥 The 5 things I'd memorize for HTB

```text
1. PREFIX + VECTOR + SUFFIX
```

```text
2. --level = more coverage
```

```text
3. --risk = potentially more dangerous payloads
```

```text
4. --technique=BEU = Boolean + Error + UNION
```

```text
5. UNION tuning:
   --union-cols
   --union-char
   --union-from
```

### One-line summary

> **Attack tuning is about giving SQLMap better information or narrowing/expanding its detection strategy when the default payload set doesn't fit the target—not about blindly turning every option to maximum.**

And especially remember the huge payload-count difference from the module:

```text
--level=1 --risk=1  → up to ~72 payloads
--level=5 --risk=3  → up to ~7,865 payloads
```

That single comparison explains **why tuning should be deliberate rather than automatic**.