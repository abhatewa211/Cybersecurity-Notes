## 1. Why Evasion Tools?

When basic manual obfuscation techniques are insufficient against advanced filtering or WAFs, **automated command-obfuscation tools** can generate more complex variations of commands.

This section covers:

- **Linux → Bashfuscator**
    
- **Windows → DOSfuscation**
    

---

# 2. Linux — Bashfuscator

**Bashfuscator** is a tool for automatically obfuscating Bash commands.

### Installation

```bash
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
```

The tool is located under:

```text
./bashfuscator/bin/
```

### Help Menu

```bash
cd ./bashfuscator/bin/
./bashfuscator -h
```

Important options mentioned:

|Option|Purpose|
|---|---|
|`-h`|Display help|
|`-l`|List available obfuscators, compressors and encoders|
|`-c COMMAND`|Specify the command to obfuscate|

---

## Basic Usage

```bash
./bashfuscator -c 'cat /etc/passwd'
```

Bashfuscator automatically selects obfuscation techniques.

⚠️ The resulting payload can become **extremely large**, potentially ranging from hundreds to over a million characters.

---

## Producing Smaller Payloads

The section demonstrates:

```bash
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

These options can be used to make the generated payload **shorter and simpler**.

The resulting command can then be tested locally with:

```bash
bash -c 'OBFUSCATED_COMMAND'
```

### Important Concept

Bashfuscator:

```text
Original command
       ↓
Obfuscation techniques
       ↓
Obfuscated command
       ↓
Shell executes it
       ↓
Original functionality
```

The resulting command may look completely unrelated to the original command while still performing the same operation.

---

# 3. Windows — DOSfuscation

**DOSfuscation** is a Windows command-obfuscation tool.

Unlike Bashfuscator, it is primarily **interactive**.

### Installation / Setup

```powershell
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
```

Then:

```text
Invoke-DOSfuscation> help
```

---

## Important DOSfuscation Options

|Option|Purpose|
|---|---|
|`TUTORIAL`|Learn how the tool works|
|`BINARY`|Obfuscated binary syntax for CMD/PowerShell|
|`ENCODING`|Environment-variable-based encoding|
|`PAYLOAD`|Generate an obfuscated payload|

---

# 4. DOSfuscation Workflow

First specify the command:

```text
SET COMMAND <command>
```

Then select an obfuscation/encoding technique.

Example workflow from the section:

```text
SET COMMAND type C:\Users\htb-student\Desktop\flag.txt
encoding
1
```

The tool produces an obfuscated version using Windows environment variables.

The important idea is that the resulting command:

- Doesn't visibly contain the original command in its normal form.
    
- Uses environment-variable expansions.
    
- Is still interpreted by `CMD` to perform the original operation.
    

---

# 5. Running DOSfuscation on Linux

If you don't have a Windows VM, the section explains that you can use **PowerShell Core (`pwsh`)** on Linux.

Workflow:

```bash
pwsh
```

Then use the DOSfuscation commands inside PowerShell.

The section notes that `pwsh` is available by default in the Pwnbox environment.

---

# 6. Bashfuscator vs DOSfuscation

|Feature|Bashfuscator|DOSfuscation|
|---|---|---|
|Platform|Linux/Bash|Windows|
|Shell|Bash|CMD / PowerShell|
|Interaction|Command-line tool|Interactive|
|Main purpose|Bash command obfuscation|Windows command obfuscation|
|Techniques|Mutators, compressors, encoders, etc.|Binary, encoding, payload techniques|
|Output|Obfuscated Bash command|Obfuscated Windows command|

---

# Key Takeaways

- **Bashfuscator** automates Bash command obfuscation.
    
- **DOSfuscation** provides interactive Windows command obfuscation.
    
- Automated obfuscation can produce commands that look very different from the original.
    
- Bashfuscator's default output can become **very large**, so its options can be tuned for shorter payloads.
    
- Always **test generated commands locally** before using them in a lab.
    
- DOSfuscation can use **environment-variable encoding** to transform commands.
    
- `pwsh` allows PowerShell-based testing from Linux.
    
- These tools are particularly relevant when **basic manual obfuscation isn't sufficient**.