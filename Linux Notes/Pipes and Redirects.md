**Pipes And Redirects**

**Pipes and Redirects**

I. **Pipes**- A pipe is a form of redirection (transfer of standard output to some other destination) that is used in Linux and other Unix-like operating systems to send the output of one command/program/process to another command/ program/process for further processing. The Unix/Linux systems allow the stdout of a command to be connected to the stdin of another command. You can make it do so by using the pipe character **‘|’**.

**Syntax:**

command_1 | command_2 | command_3 | .... | command_N

34/39

![[image30.png]]

35/39

![[image31.png]]

![[image32.png]]

![[image33.png]]

II. **Redirects**- Redirection helps us redirect these input and output functionalities to the files or folders we want, and we can use special commands or characters to do so.

**Types of Redirection**

1. **Overwrite Redirection**:

Overwrite redirection is useful when you want to store/save the output of a command to a file and replace all the existing content of that file. for example, if you run a command that gives a report, and you want to save the report to

36/39

the existing file of the previous report you can use overwrite redirection to do this.

- “>” standard output

• “<” standard input

2. **Append Redirection**:

With the help of this Redirection, you can append the output to the file without compromising the existing data of the file.

- “>>” standard output

• “<<” standard input

3. **Merge Redirection**:

This allows you to redirect the output of a command or a program to a specific file descriptor instead of standard output. the syntax for using this is “>&” operator followed by the file descriptor number.

- “p >& q” Merges output from stream p with stream q

• “p <& q” Merges input from stream p with stream q

![[image34.png]]

37/39

![[image35.png]]

38/39

![[image36.png]]