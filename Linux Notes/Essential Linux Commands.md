**Essential Linux Commands**

**Essential Linux Commands**

I. **Wildcard Commands.**

In Linux, the wildcard character is used in commands to represent one or more characters. The most commonly used wildcard characters are the asterisk (*) and the question mark (?). Here are some examples of how wildcards can be used in Linux commands:

1. **Asterisk (*)**: This represents zero or more characters.

• List all files in the current directory that end with ".txt":

bash

7/39

- ls *.txt
- Remove all files in the current directory with a ".bak" extension: bash
- ◇ rm *.bak
- **Question mark (?)**: This represents a single character.

◇ List all files in the current directory with names of three characters: bash

- ls ???
- Remove any file in the current directory named "file1.txt" or "file2.txt": bash
- ◇ rm file?.txt
- **Brackets ([ ])**: This represents a single character within the specified range or set.◇ List all files in the current directory that have a digit as the second character: bash
- ls [0-9]*
- List all files in the current directory that start with either "a", "b", or "c": bash
- ◇ ls [a-c]*
- **Curly braces ({ })**: This represents multiple possibilities separated by commas.◇ List all files that end with ".jpg" or ".png":

bash

- ls *.{jpg,png}
- Copy all files with names starting with "image" followed by either "1" or "2" to the "backup" directory: arduino

1. ◇ cp image{1,2}* backup/

ScreenShot

![[image5.png]]

II. **cd**- can be used to change the working directory of the working drive or another lettered drive.

8/39

Switches.

a. **cd ~**- jumps to main directory

b. **cd /**-root directory

c. **cd ..**- jumps single directory back

d. **cd directory name**- jumps to the directory

e. **cd dir/dir/dir**- jumps to the last directory typed

f. **cd ../../**- jumps two directories back

III. **Touch**- used to create a file without any content.

IV. **Mkdir**- used to make a new directory

Switches ScreenShot

9/39

![[image6.png]]

V. **cat**- reads files sequentially, displaying their content to the terminal. i. cat > file name- to write files.

Switches

![[Untitled.png]]