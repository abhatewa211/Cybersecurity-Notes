There are various text editors available for Linux, each with their own unique features and functionalities. Popular text editors include Vim, Emacs, Nano, and Gedit. These editors are powerful tools that can be used for programming, writing scripts, or simply editing text files. They each offer different levels of complexity and customization, so users can choose the one that best fits their needs.

## Further Information on Text Editors

Vim, an improved version of the older Vi text editor, is known for its keyboard-centered operation. It is highly configurable and efficient, making it a favorite among programmers.

Emacs, another popular choice, offers a wide array of functions, including file management, email, and web browsing, all within the text editor itself. Its complex but powerful system can be a bit overwhelming for beginners, but is highly appreciated by experienced users.

Nano is a simple, user-friendly text editor that's great for beginners. It uses a simple interface and is less complex than Vim or Emacs, but still offers sufficient functionality for most text editing needs.

Gedit is the default text editor for the GNOME desktop environment. It's designed to be simple and easy to use, while still providing users with the power to handle all types of text editing tasks.

Each of these text editors can be installed and used on any Linux distribution. Depending on the user's needs and comfort level, one may be more suitable than the others.

## Writing to a File Using _cat_

To write to a file, we’ll make _cat_ command listen to the input stream and then **redirect the output of** _**cat**_ **command into a file using the Linux redirection operators “>”.**

Concretely, to write into a file using _cat_ command, we enter this command into our terminal:

```Shell
cat > readme.txt
```

We’ll see that once again the terminal is waiting for our input.

However, this time it won’t echo the texts we’ve entered. This is  
because we’ve instructed the command to redirect the output to the file _readme.txt_ instead of the standard output stream.

Let’s enter some texts into the terminal, followed by CTRL+D to terminate the command:

```Shell
cat > readme.txt
This is a readme file.
This is a new line.
```

The file _readme.txt_ will now contain the two lines we’ve entered.

To verify our result, we can use the _cat_ command once again:

```Shell
cat readme.txt
This is a readme file.
This is a new line.
```

Voila! We’ve written into a file using the _cat_ command.

### Appending Text to File Using _cat_

One thing we should note in the previous example is that it’ll always overwrite the file _readme.txt_.

**If we want to append to an existing file, we can use the “>>” operator**:

```Shell
cat >> readme.txt
This is an appended line.
```

To verify that the last command has appended the file, we check the content of the file:

```Shell
cat readme.txt
This is a readme file.
This is a new line.
This is an appended line.
```

There we have it. The line we enter is appended to the end of the file instead of replacing the entire document.

### Here Document

It is also worth noting that the [here document](https://tldp.org/LDP/abs/html/here-docs.html) syntax can be used with the _cat_ command:

```Shell
cat > readme.txt << EOF
This is an input stream literal
EOF
```

_EOF_ is a token that tells the _cat_ command to terminate when it sees such a token in the subsequent lines.

The token can be any other value as long as it is distinct enough  
that it won’t appear in the input stream literal. Do note that both the  
starting and ending _EOF_ tokens will not show up in the _readme.txt_ file.

  

## NANO

Nano is a command-line text editor that comes pre-installed with most Linux distributions. It’s designed to be user-friendly, with a simple interface that resembles popular graphical text editors. Nano provides essential editing features, making it ideal for quick edits, creating configuration files, or writing scripts directly in the terminal.

**Installing Nano Text Editor**

Nano is generally by default available in many Linux distributions but in case, it is not installed you may install the same using the following commands.

sudo apt update

In case of Debian/Ubuntu

sudo apt install nano

In case of Cent OS/Fedora

sudo yum install nano

**Shortcuts for Navigation**

When dealing with a large file, it is helpful to know how to navigate  
through the text quickly. Nano allows you to do this using the arrow  
keys or keyboard shortcuts.  

Useful keyboard shortcuts for navigating include:

- **Ctrl+F (^F)**. Move forward one character.
- **Ctrl+B (^B)**. Move back one character.
- **Ctrl+Space (^Space).** Go one word forward.
- **Alt+Space (M-Space)**. Go one word backward.
- **Ctrl+P (^P)**. Navigate to the previous line.
- **Ctrl+N (^N)**. Navigate to the next line.
- **Ctrl+V (^V).** Go to the next page.
- **Ctrl+Y (^Y)**. Move to the previous page.
- **Ctrl+A (^A)**. Go to the beginning of the line.
- **Ctrl+E (^E)**. Move to the end of the line.

  

## VIM

VIM, or Vi IMproved, is another command-line text editor that is included with most Linux distributions. It's an extended version of the original Vi editor, offering many additional features and improvements. VIM provides a powerful and efficient way to edit files directly from the terminal.

**Installing VIM Text Editor**

VIM is generally available by default in many Linux distributions. However, if it's not installed, you can install it using the following commands.

For Debian/Ubuntu:

```Shell
sudo apt update
sudo apt install vim
```

For Cent OS/Fedora:

```Shell
sudo yum install vim
```

**Shortcuts for Navigation**

When working with larger files or coding, being able to navigate quickly through your text is essential. VIM has powerful navigation shortcuts:

- **h** - Move left one character.
- **j** - Move down one line.
- **k** - Move up one line.
- **l** - Move right one character.
- **w** - Jump forwards to the start of a word.
- **W** - Jump forwards to the start of a word (words can contain punctuation).
- **e** - Jump forwards to the end of a word.
- **E** - Jump forwards to the end of a word (words can contain punctuation).
- **0** - Jump to the start of the line.
- **$** - Jump to the end of the line.
- **G** - Go to the last line of the document.
- **gg** - Go to the first line of the document.
- **:.** - Go to the line number specified instead of the period.

## Modes in VIM

VIM operates in different modes, each suited for a specific task. Understanding these modes is key to using VIM effectively.

- **Normal Mode**: This is the default mode when you open a file with VIM. It's used for navigation and manipulation of text. In this mode, keystrokes are interpreted as commands.
- **Insert Mode**: In this mode, you can insert and delete characters in the same way you do in other text editors. You can enter Insert Mode from Normal Mode by pressing `i`.
- **Visual Mode**: This mode is used for selecting blocks of text. You can enter Visual Mode from Normal Mode by pressing `v`.
- **Command-Line Mode**: This mode is used for entering editor commands. You can enter Command-Line Mode from Normal Mode by pressing `:`.
- **Ex Mode**: This mode is similar to Command-Line Mode, but optimized for batch processing. You can enter Ex Mode from Normal Mode by pressing `Q`.

To switch back to Normal Mode from any other mode, press `Esc`.