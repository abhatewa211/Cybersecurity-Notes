# 1️⃣ Every Operating System Has a Shell

Every operating system has a **shell**, and to interact with it, we must use an application known as a **terminal emulator**.

A shell allows us to send commands to the operating system.  
A terminal emulator is simply the interface window that lets us do that.

---

# 2️⃣ Terminal Emulators

Below are some of the most common terminal emulators:

|Terminal Emulator|Operating System|
|---|---|
|Windows Terminal|Windows|
|cmder|Windows|
|PuTTY|Windows|
|kitty|Windows, Linux and MacOS|
|Alacritty|Windows, Linux and MacOS|
|xterm|Linux|
|GNOME Terminal|Linux|
|MATE Terminal|Linux|
|Konsole|Linux|
|Terminal|MacOS|
|iTerm2|MacOS|

This list is by no means every terminal emulator available, but it does include some noteworthy ones.

Because many of these tools are open-source, we can install them on different operating systems in ways that may differ from the developers' original intentions. However, that is a project beyond the scope of this module.

Selecting the proper terminal emulator for the job is primarily a **personal and stylistic preference** based on workflows that develop as we get familiar with our OS of choice.

> Do not let anyone make you feel bad for selecting one option over the other.

The terminal emulator we interact with on targets will essentially be dependent on what exists on the system natively.

---

## 🖥 Linux Terminal Emulators

![Image](https://upload.wikimedia.org/wikipedia/commons/thumb/2/29/Linux_command-line._Bash._GNOME_Terminal._screenshot.png/960px-Linux_command-line._Bash._GNOME_Terminal._screenshot.png)

![Image](https://ubuntu-mate.community/uploads/default/original/2X/3/3a96c8c716a744c37100b32e1c855d7f905641b4.png)

![Image](https://upload.wikimedia.org/wikipedia/commons/3/38/Konsole_21.12.0_screenshot.png)

![Image](https://itsfoss.com/content/images/2024/08/konsole-with-image-other-applied.webp)

Examples include:

- GNOME Terminal
    
- MATE Terminal
    
- Konsole
    
- xterm
    

---

## 🖥 Windows Terminal Emulators

![Image](https://learn.microsoft.com/en-us/windows/terminal/images/search.png)

![Image](https://media2.dev.to/dynamic/image/width%3D1000%2Cheight%3D420%2Cfit%3Dcover%2Cgravity%3Dauto%2Cformat%3Dauto/https%3A%2F%2Fthepracticaldev.s3.amazonaws.com%2Fi%2Fa938phb64n1esvsrijgw.png)

![Image](https://support.cci.drexel.edu/media/images/putty_config_4a_-_display_taller_window_and_sc.width-800.png)

![Image](https://miro.medium.com/1%2AmT4NVX-K9Yx8VwGAYotoLg.jpeg)

Examples include:

- Windows Terminal
    
- cmder
    
- PuTTY
    
- kitty
    

---

## 🖥 macOS Terminal Emulators

![Image](https://images.macworld.co.uk/cmsdata/features/3448249/change_screenshot_to_jpg.jpg)

![Image](https://iterm2.com/img/screenshots/split_panes.png)

![Image](https://i.sstatic.net/LY1hs.png)

![Image](https://i.sstatic.net/VgrMX.png)

Examples include:

- Terminal
    
- iTerm2
    

---

# 3️⃣ Command Language Interpreters

Much like a human language interpreter translates spoken or sign language in real-time, a **command language interpreter** is a program that:

- Interprets instructions provided by the user
    
- Issues tasks to the operating system for processing
    

When we discuss **Command-Line Interfaces (CLI)**, we are referring to a combination of:

1. Operating System
    
2. Terminal Emulator Application
    
3. Command Language Interpreter
    

Many different command language interpreters can be used. Some are also called:

- Shell scripting languages
    
- Command and Scripting interpreters
    

(as defined in the Execution techniques of the MITRE ATT&CK Matrix)

We do not need to be software developers to understand these concepts, but:

> The more we know, the more success we can have when attempting to exploit vulnerable systems to gain a shell session.

Understanding the command language interpreter in use on any given system will also give us an idea of what commands and scripts we should use.

---

# 4️⃣ Hands-on with Terminal Emulators and Shells (Parrot OS Pwnbox)

Let’s use Parrot OS Pwnbox to further explore the anatomy of a shell.

Click the green square icon at the top of the screen to open the MATE terminal emulator and type something random:

```bash
wasdf
meep
```

You will see:

```bash
command not found
```

---

## 🔎 Terminal Example – Bash “command not found”

![Image](https://user-images.githubusercontent.com/4087461/85923328-5805e380-b88a-11ea-89e1-cc95d1e912ae.png)

![Image](https://i.sstatic.net/W6dtl.png)

![Image](https://i.stack.imgur.com/QaA7m.png)

![Image](https://mac.install.guide/assets/images/terminal/terminal-prompt.png)

As soon as we selected the icon:

- It opened the **MATE terminal emulator application**
    
- It was pre-configured to use a command language interpreter
    

We are “clued” to what interpreter is in use by seeing the:

```
$
```

The `$` sign is used in:

- Bash
    
- Ksh
    
- POSIX
    
- Many other shell languages
    

It marks the start of the shell prompt.

When we typed random text and hit enter:

Bash told us it did not recognize that command.

This shows that command language interpreters have their own set of commands they recognize.

---

# 5️⃣ Shell Validation Using `ps`

Another way to identify the interpreter is by viewing running processes.

In Linux:

```bash
ps
```

Example:

```bash
PID TTY          TIME CMD
4232 pts/1    00:00:00 bash
11435 pts/1   00:00:00 ps
```

This tells us:

- The running command interpreter is **bash**
    

---

# 6️⃣ Shell Validation Using `env`

We can also view environment variables:

```bash
env
```

Example output:

```bash
SHELL=/bin/bash
```

This confirms the shell language in use.

---

# 7️⃣ PowerShell vs Bash (Same Terminal, Different Interpreter)

Now select the blue square icon in Pwnbox.

It opens the same **MATE terminal application**, but this time it uses a different command language interpreter.

---

## 🔹 Bash Example

![Image](https://www.mikekasberg.com/images/posts/my-new-bash-prompt-full.jpg)

![Image](https://journaldev.nyc3.cdn.digitaloceanspaces.com/2018/12/ls-l.png)

![Image](https://upload.wikimedia.org/wikipedia/commons/3/30/Ps_command_screenshot.png)

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2AZMWydDPyy-JHzHj-IJmJdw.png)

Characteristics:

- Prompt: `$`
    
- Text-based processing
    
- Commands like:
    
    - `ls`
        
    - `cat`
        
    - `ps`
        
    - `grep`
        

---

## 🔹 PowerShell Example

![Image](https://i.sstatic.net/KT1ve.jpg)

![Image](https://images.hanselman.com/blog/Windows-Live-Writer/63963d6f2af3_12BCC/image_e2447ddd-416e-4036-9584-e728455e6d9d.png)

![Image](https://cdn.prod.website-files.com/6821b5175dd850cde4c319dc/68431bf8a1339e063d9d24b9_prozesse-02-1.jpeg)

![Image](https://redmondmag.com/articles/2016/11/17/~/media/ECG/redmondmag/Images/2016/11/GetProcess_Fig1.ashx)

Characteristics:

- Prompt: `PS>`
    
- Object-based processing
    
- Verb-Noun syntax
    
- Commands like:
    
    - `Get-Process`
        
    - `Get-ChildItem`
        

Example:

```powershell
Get-Process
```

---

# 8️⃣ Key Differences Between Bash and PowerShell

|Feature|Bash|PowerShell|
|---|---|---|
|Prompt|`$`|`PS>`|
|Data Type|Text streams|Objects|
|Default Platform|Linux/Unix|Windows|
|Command Style|Short Unix commands|Verb-Noun|
|Scripting|.sh|.ps1|

---

# 9️⃣ Important Takeaway

A terminal emulator is NOT tied to one specific language.

The shell language can be:

- Changed
    
- Customized
    
- Reconfigured
    

Based on:

- Sysadmin preference
    
- Developer workflow
    
- Pentester needs
    
- Technical requirements
    

---

# 🔟 Why This Matters in Penetration Testing

Understanding the interpreter helps us:

✔ Choose correct payloads  
✔ Craft proper reverse shells  
✔ Avoid syntax errors  
✔ Detect execution environments  
✔ Perform privilege escalation  
✔ Deliver compatible scripts

For example:

- A Bash reverse shell will fail inside PowerShell.
    
- A PowerShell payload will not execute inside a restricted POSIX shell.
    
- Object-based output in PowerShell behaves differently from text streams in Bash.
    

---

# 🧩 Shell Anatomy Summary

The full flow looks like this:

```
User → Terminal Emulator → Command Language Interpreter → Operating System
```

When gaining a shell during an engagement, always:

1. Identify the interpreter
    
2. Validate with `ps` or `env`
    
3. Adjust commands accordingly
    
4. Deliver compatible payloads
---

### Excercises

![[Pasted image 20260212115904.png]]
