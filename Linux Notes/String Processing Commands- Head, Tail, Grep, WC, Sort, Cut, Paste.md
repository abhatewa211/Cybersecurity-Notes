## Head

The head command, as the name implies, print the top N number of data of the given input. By default, it prints the first 10 lines of the specified files. If more than one file name is provided then data from each file is preceded by its file name.

**Syntax:**

head [OPTION]... [FILE]...

**Options:**

![[Untitled 1.png]]

  

## Tail

The tail command, as the name implies, prints the last N number of data of the given input. By default, it prints the last 10 lines of the specified files. If more than one file name is provided then data from each file is preceded by its file name.

### **Syntax of Tail Command in Linux**

```Plain
tail [OPTION]... [FILE]...
```

**Options:**

![[Untitled 2.png]]

## Grep

The grep command, which stands for "global regular expression print," processes text line by line and prints any lines which match a specified pattern. It is a powerful tool for searching and filtering text.

**Syntax:**

```Plain
grep [OPTION]... PATTERN [FILE]...
```

**Options:**

- `i` : Ignore case distinctions in both the PATTERN and the input files
- `v` : Invert the sense of matching, to select non-matching lines
- `r` or `R` : Recursively search sub directories listed
- `l` : Suppress normal output; instead print the name of each input file from which output would normally have been printed
- `w` : Select only those lines containing matches that form whole words.

  

## WC

The `wc` command, which stands for "word, line, character, and byte count", as the name implies, prints newline, word, and byte counts for each file, and a total line if more than one file is specified. It can return the number of lines, words, and characters in the specified files.

**Syntax:**

```Plain
wc [OPTION]... [FILE]...
```

**Options:**

- `l` : Print the newline counts
- `w` : Print the word counts
- `c` : Print the byte counts
- `m` : Print the character counts
- `L` : Print the maximum display width

  

## Sort

The `sort` command, as the name implies, sorts the contents of a text file line by line. It can be used to sort a list in either numerical or lexicographical order and can also sort on specific fields, such as sorting a CSV file by the second column.

**Syntax:**

```Plain
sort [OPTION]... [FILE]...
```

**Options:**

- `n` : Compare according to string numerical value
- `r` : Reverse the result of comparisons
- `k` : Sort by a key at POSITION
- `t` : Use SEPARATOR as the field separator character
- `f` : Ignore case distinctions in both the PATTERN and the input files

  

## Cut

The `cut` command in UNIX is a command for cutting out the sections from each line of files and writing the result to standard output. It can be used to cut parts of a line by byte position, character and field. Basically the `cut` command slices a line and extracts the text.

**Syntax:**

```Plain
cut OPTION... [FILE]...
```

**Options:**

- `b` : The byte, characters positions to be cut are given by LIST
- `c` : Select only these characters
- `d` : Use DELIM instead of TAB for field delimiter
- `f` : Select only these fields; also print any line that contains no delimiter character, unless the -s option is specified
- `s` : Suppress lines with no field delimiter characters. Unless specified, lines with no delimiters are passed through unmodified.

  

## Paste

The `paste` command is a powerful utility present in UNIX and Linux systems. Its primary function is to concatenate or merge the contents of files and print the result on the standard output.

The name "paste" comes from its function of "pasting" the contents of files together, similar to how you would paste text together in a document. It can merge lines from different files in a sequence, which can be extremely useful when you're dealing with large data sets or log files.

This command can take multiple files as input and merge their contents on a line by line basis. For instance, if you have two files with a list of items, one item per line, `paste` can merge these files in such a way that each line contains an item from the first file and an item from the second file.

**Syntax:**

The basic syntax of the `paste` command is as follows:

```Plain
paste [OPTION]... [FILE]...
```

Here, `[OPTION]` represents optional flags that you can use to modify the output of the command, and `[FILE]` represents the files whose contents you want to concatenate.

**Options:**

- `d` : This option allows you to specify a LIST as the delimiter instead of the default TAB character. This can be useful if you want to separate the merged lines with a specific character or string.
- `s` : This option tells `paste` to merge all of the lines of each file in parallel instead of one from each file in turn. This is useful when you want to concatenate the contents of the files horizontally rather than vertically.

## 🔹 Real-World Scenarios + Examples

---

### ✅ Scenario 1: Replace text in a file

**File:** `**notes.txt**`

```Plain
I like cats.
Cats are cute.
```

**Command:**

```Shell
sed 's/cats/dogs/' notes.txt
```

**Output:**

```Plain
I like dogs.
Cats are cute.
```

> Note: Only replaces first match in each line (case-sensitive). To make it global, add g flag:

```Shell
sed 's/cats/dogs/g' notes.txt
```

---

### ✅ Scenario 2: Case-insensitive replace

```Shell
sed 's/cats/dogs/Ig' notes.txt
```

**Output:**

```Plain
I like dogs.
dogs are cute.
```

---

### ✅ Scenario 3: Replace on a specific line

```Shell
sed '2s/Cats/Dogs/' notes.txt
```

**Output:**

```Plain
I like cats.
Dogs are cute.
```

---

### ✅ Scenario 4: Delete lines that match a pattern

```Shell
sed '/cats/d' notes.txt
```

**Output:**

```Plain
Cats are cute.
```

(Deletes lines containing "cats")

---

### ✅ Scenario 5: Delete a specific line (e.g., line 3)

```Shell
sed '3d' file.txt
```

---

### ✅ Scenario 6: Insert a line before/after a match

**File:** `**log.txt**`

```Plain
Start
Error: Failed to load
End
```

**Insert before match:**

```Shell
sed '/Error/i\
WARNING: Check the system.
' log.txt
```

**Insert after match:**

```Shell
sed '/Error/a\
Attempting recovery...
' log.txt
```

---

### ✅ Scenario 7: Print only matched lines

```Shell
sed -n '/Error/p' log.txt
```

---

### ✅ Scenario 8: Substitute using a variable (e.g., in a script)

```Shell
name="John"
sed "s/USERNAME/$name/" file.txt
```

---

### ✅ Scenario 9: Multiple replacements

```Shell
sed -e 's/cats/dogs/' -e 's/like/love/' file.txt
```

---

## 🔹 Common Flags & Options

|   |   |
|---|---|
|Option|Description|
|`s`|Substitute|
|`g`|Global replacement in a line|
|`i`|Case-insensitive matching|
|`d`|Delete line|
|`p`|Print line (usually with `-n`)|
|`i\`|Insert line before match|
|`a\`|Append line after match|

---

## 🔹 Bonus: Edit file in-place (⚠️ destructive)

```Shell
sed -i 's/old/new/g' file.txt
```

> Backup first:

```Shell
sed -i.bak 's/old/new/g' file.txt
```

---

### ✅ Extra: Echo pipe for quick testing

```Shell
echo "apples are red" | sed 's/red/green/'
```

---