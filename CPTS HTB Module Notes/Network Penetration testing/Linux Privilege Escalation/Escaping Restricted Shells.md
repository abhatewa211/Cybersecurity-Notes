# 1. 🧠 What is a Restricted Shell?

A **restricted shell** is a type of shell that limits the user's ability to execute commands.

A restricted shell may:

- Allow only a specific set of commands
    
- Restrict commands to specific directories
    
- Prevent changing directories
    
- Prevent modifying environment variables
    
- Prevent executing commands from other directories
    
- Restrict shell functions/scripts depending on the shell
    

### Normal shell vs restricted shell

```text
NORMAL SHELL
     │
     ├── Execute commands
     ├── Change directories
     ├── Modify environment
     ├── Execute programs
     └── Access filesystem
     
RESTRICTED SHELL
     │
     ├── Limited commands
     ├── Limited directories
     ├── Restricted environment
     └── Restricted shell functionality
```

Restricted shells are generally intended to provide a **safe and controlled environment**.

---

# 2. 🐚 Common Restricted Shells

The module discusses three:

```text
┌──────────────────────────────┐
│     Restricted Shells        │
├──────────────────────────────┤
│                              │
│ rbash → Restricted Bash      │
│ rksh  → Restricted Korn      │
│ rzsh  → Restricted Z shell   │
│                              │
└──────────────────────────────┘
```

---

# 3. 🔴 RBASH

`rbash` = **Restricted Bourne shell**

It is a restricted version of Bash.

The module describes restrictions including the ability to:

- Change directories
    
- Set or modify environment variables
    
- Execute commands in other directories
    

So instead of:

```text
User
 │
 ├── cd anywhere
 ├── modify PATH
 ├── execute arbitrary commands
 └── access programs anywhere
```

you may have:

```text
User
 │
 └── rbash
       │
       ├── ❌ cd
       ├── ❌ modify environment
       └── ❌ execute commands from other directories
```

---

# 4. 🟠 RKSH

`rksh` = **Restricted Korn shell**

It is the restricted version of the Korn shell.

According to the module, restrictions can include:

- Executing commands in other directories
    
- Creating/modifying shell functions
    
- Modifying the shell environment
    

---

# 5. 🟣 RZSH

`rzsh` = **Restricted Z shell**

It is the restricted version of Z shell.

The module mentions restrictions such as:

- Running shell scripts
    
- Defining aliases
    
- Modifying the shell environment
    

---

# 6. 🏢 Why Do Organizations Use Restricted Shells?

The module gives an enterprise example.

Imagine a company has:

```text
Employees
Contractors
External partners
        │
        ▼
 Linux servers
```

Instead of giving everyone a completely unrestricted shell, administrators can provide different restricted shells.

For example:

```text
External partners
       │
       ▼
     rbash
       │
       └── Limited network features


Contractors
       │
       ▼
     rksh
       │
       └── More flexibility


Employees
       │
       ▼
     rzsh
       │
       └── More flexibility but still restricted
```

The objective is to limit access to only the resources and functions necessary for the user's role.

---

# 7. 🚨 Important Security Concept

A restricted shell is **not automatically equivalent to a secure system**.

Why?

Because the restriction may apply to the shell itself, while some programs available to the user may provide other ways to execute commands or interact with the system.

Therefore:

```text
Restricted shell
       │
       ▼
What commands CAN I run?
       │
       ▼
What features do those commands provide?
       │
       ▼
Can one of those features execute something else?
       │
       ▼
Potential escape
```

This is the mindset you should develop for HTB.

---

# 8. 💥 Escaping a Restricted Shell

The module states that several methods may be used to escape a restricted shell.

Broadly:

```text
Restricted Shell
      │
      ├── Command injection
      ├── Command substitution
      ├── Command chaining
      ├── Environment variables
      └── Shell functions
```

These techniques attempt to take an **allowed functionality** and use it to execute something that wasn't intended to be allowed.

---

# 9. 💉 Command Injection

The module describes command injection as injecting additional commands into input accepted by the shell or a command.

The example uses:

```bash
ls -l `pwd`
```

Here:

```text
`pwd`
```

is evaluated and its output becomes part of the `ls` command's arguments.

### Conceptually

```text
ls -l `pwd`
       │
       ▼
    execute pwd
       │
       ▼
  current directory
       │
       ▼
ls -l <output-of-pwd>
```

The important lesson isn't just the specific command.

It's this:

> **If an allowed command accepts input that gets interpreted by a shell, that input may provide an opportunity to execute additional commands.**

---

# 10. 🔄 Command Substitution

Command substitution allows the shell to execute a command and substitute its output into another command.

The module specifically mentions:

```text
`command`
```

as one syntax.

For example, conceptually:

```bash
echo `pwd`
```

The shell executes:

```text
pwd
```

and substitutes its output.

### Visual

```text
Command substitution
       │
       ▼
`pwd`
       │
       ▼
Execute pwd
       │
       ▼
Output
       │
       ▼
Inserted into original command
```

### Key point

In a restricted environment, you should check whether **command substitution is available and whether it can invoke commands outside the intended restrictions**.

---

# 11. 🔗 Command Chaining

Another potential escape method is **command chaining**.

Commands can sometimes be separated using shell metacharacters such as:

```text
;
|
```

For example:

```text
command1 ; command2
```

means conceptually:

```text
command1
   │
   ▼
command2
```

And:

```text
command1 | command2
```

uses a pipe to pass output from one command to another.

### Security idea

If a restricted interface allows something like:

```text
allowed-command ; another-command
```

then the second command might bypass the intended restriction.

However, whether this works depends on **how the restricted shell parses and filters input**.

---

# 12. 🌱 Environment Variables

The module also identifies **environment variables** as a possible escape technique.

The idea is:

```text
Environment variable
       │
       ▼
Used by shell/program
       │
       ▼
Controls where/how commands execute
       │
       ▼
Modify its value
       │
       ▼
Potentially bypass restriction
```

For example, if a shell or program uses an environment variable to determine where commands are executed, changing that variable may alter the execution environment.

### Important connection to previous topic

Remember our **PATH Abuse** section?

`PATH` is an environment variable.

So when you see:

```bash
echo $PATH
```

you should recognize:

```text
Environment
    │
    └── PATH
         │
         └── Controls command lookup
```

That is why environment variables can be extremely important during enumeration.

---

# 13. 🧩 Shell Functions

The module also mentions **shell functions**.

A shell function can contain commands and then be called by its name.

Conceptually:

```text
Define function
      │
      ▼
Function contains commands
      │
      ▼
Call function
      │
      ▼
Commands execute
```

If a restricted shell allows users to define and execute functions, this may potentially provide a way around restrictions.

Again, whether this works depends on the shell's actual restrictions.

---

# 14. 🔥 The Enumeration Mindset

If you land in a restricted shell, **don't immediately start randomly trying escape commands**.

First understand your environment.

Think:

```text
                 RESTRICTED SHELL
                       │
                       ▼
              Identify the shell
                       │
              ┌────────┴────────┐
              ▼                 ▼
          rbash?              rksh?
              │                 │
              └────────┬────────┘
                       ▼
               What is allowed?
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
     Commands       Variables      Functions
        │              │              │
        ▼              ▼              ▼
     Arguments      PATH/etc.      Can define?
        │
        ▼
  Special parsing?
        │
        ▼
 Potential escape
```

---

# 🧪 15. What You Should Check

When you encounter a restricted shell, determine:

### ① What shell am I using?

The module identifies:

```text
rbash
rksh
rzsh
```

Knowing the shell matters because **each restricted shell has different restrictions**.

---

### ② What commands can I execute?

Create a mental inventory:

```text
Allowed commands
      │
      ├── ls
      ├── cat
      ├── ...
      └── ...
```

Then investigate what those programs can actually do.

---

### ③ Can I use command substitution?

Look for functionality involving:

```text
`command`
```

or equivalent shell substitution mechanisms.

---

### ④ Can I chain commands?

Check whether shell metacharacters such as:

```text
;
|
```

are interpreted.

---

### ⑤ Can I modify environment variables?

Especially pay attention to variables affecting command execution.

```text
PATH
SHELL
HOME
```

The module specifically discusses environment-variable manipulation as an escape category.

---

### ⑥ Can I define shell functions?

If functions are permitted, investigate whether they can execute functionality outside the restriction.

---

# 🧠 16. Restricted Shell Escape — Visual Summary

```text
                     RESTRICTED SHELL
                            │
                            ▼
                   Limited functionality
                            │
          ┌─────────────────┼──────────────────┐
          │                 │                  │
          ▼                 ▼                  ▼
     Command Input    Environment         Functions
          │             Variables              │
          │                 │                  │
          ▼                 ▼                  ▼
    Injection /        PATH or other       Function
    substitution       variables          execution
          │                 │                  │
          └─────────────────┼──────────────────┘
                            ▼
                    Bypass restriction
                            │
                            ▼
                     Potential shell
                          escape
```

---

# ⚔️ STRICT MENTOR MODE

Here's what I want you to remember for the CPTS/HTB perspective.

### ❌ Weak understanding

> "rbash is a restricted shell."

That's only identification.

### ✅ Strong understanding

> "A restricted shell limits certain shell capabilities. I need to identify the shell, determine what functionality remains available, and investigate whether allowed commands, parsing mechanisms, environment variables, or functions can be abused to execute functionality outside the intended restrictions."

That's the mindset you need.

---

# 🔑 MUST-MEMORIZE TABLE

|Concept|Remember|
|---|---|
|`rbash`|Restricted Bourne/Bash shell|
|`rksh`|Restricted Korn shell|
|`rzsh`|Restricted Z shell|
|Command injection|Inject additional commands through accepted input|
|Command substitution|Execute a command through substitution syntax|
|Command chaining|Use shell metacharacters such as `;` or `|
|Environment variables|May influence command execution/environment|
|Shell functions|May provide additional execution functionality|

---

# 🧠 CPTS Revision Card

```text
RESTRICTED SHELL
       │
       ▼
Limits commands / directories / shell features
       │
       ├── rbash
       ├── rksh
       └── rzsh
       │
       ▼
ESCAPE AREAS
       │
       ├── Command injection
       ├── Command substitution
       ├── Command chaining
       ├── Environment variables
       └── Shell functions
```

### ⭐ One sentence to burn into memory:

> **A restricted shell is only as strong as the restrictions placed around the functionality still available to the user.**

And one very important connection to your previous modules:

```text
Environment Enumeration
        ↓
PATH / shell / users
        ↓
Restricted Shell
        ↓
Identify allowed functionality
        ↓
Look for an escape
```

That's how these modules start connecting together instead of being isolated commands to memorize.