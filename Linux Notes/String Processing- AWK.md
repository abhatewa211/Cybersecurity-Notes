  

## AWK

AWK is a powerful and versatile programming language designed for text processing. Developed by Alfred Aho, Peter Weinberger, and Brian Kernighan, AWK gets its name from the initials of its creators. It's a standard feature of most Unix-like operating systems.

AWK is primarily used for data extraction and reporting, but it can handle more complex tasks. It is often used in data transformation, producing formatted reports, and even as a simple but effective programming language for certain types of tasks.

The general structure of an AWK command is as follows:

```Shell
awk 'pattern { action }' file
```

In this structure:

- 'pattern' stands for the condition or pattern that you're searching for within the file.
- 'action' is the operation you want to perform when the pattern is found. This could be to print certain lines, modify the data, or perform more complex operations.
- 'file' is the specific file where the search is performed.

AWK command provides several options, including:

- `F` : This option is used to set the field separator. The field separator, which is either a string or a regular expression, defines how AWK divides lines into fields.
- `f` : This option allows you to specify a script file. This is useful when the operations are complex and cannot be comfortably written on the command line.
- `v` : This option is used to assign a value to a variable before the execution of the program. This can be used to pass external variables.

Understanding these basic elements of AWK programming provides a strong foundation for exploring more advanced features and functionalities of this versatile language.

## 🔹 Real-World Scenarios + Examples

---

### ✅ Scenario 1: Print the 1st and 3rd column of a file

**File:** `**students.txt**`

```Plain
John 85 Math
Sara 90 Physics
Mike 78 Chemistry
```

**Command:**

```Shell
awk '{ print $1, $3 }' students.txt
```

**Output:**

```Plain
John Math
Sara Physics
Mike Chemistry
```

---

### ✅ Scenario 2: Print lines where marks are more than 80

```Shell
awk '$2 > 80 { print $1, $2 }' students.txt
```

**Output:**

```Plain
Sara 90
```

---

### ✅ Scenario 3: Print line number along with content

```Shell
awk '{ print NR, $0 }' students.txt
```

**Output:**

```Plain
1 John 85 Math
2 Sara 90 Physics
3 Mike 78 Chemistry
```

---

### ✅ Scenario 4: Calculate sum and average of marks

```Shell
awk '{ sum += $2 } END { print "Total:", sum, "Average:", sum/NR }' students.txt
```

**Output:**

```Plain
Total: 253 Average: 84.3333
```

---

### ✅ Scenario 5: Use a delimiter (CSV file)

**File:** `**employees.csv**`

```Plain
Alice,Manager,5000
Bob,Engineer,4000
Cara,Analyst,3500
```

**Command:**

```Shell
awk -F',' '{ print $1, $3 }' employees.csv
```

**Output:**

```Plain
Alice 5000
Bob 4000
Cara 3500
```

---

### ✅ Scenario 6: Match pattern using regex

```Shell
awk '/Physics/ { print $0 }' students.txt
```

**Output:**

```Plain
Sara 90 Physics
```

---

## 🔹 Special Variables in `awk`

|   |   |
|---|---|
|Variable|Description|
|`$0`|Entire line|
|`$1`|First field|
|`NF`|Number of fields|
|`NR`|Current line number|
|`FS`|Field separator (input)|
|`OFS`|Output field separator|

---

## 🔹 Bonus: Inline text processing

```Shell
echo "apple banana cherry" | awk '{ print $2 }'
```

**Output:**

```Plain
banana
```

---