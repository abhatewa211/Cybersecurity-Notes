# HTB Academy — Attacking Common Applications
## Skills Assessment III — Full Penetration Testing / Skills Assessment Report

---

## 1. Executive Summary

This report documents the authorized Hack The Box Academy **Attacking Common Applications – Skills Assessment III**.

The assessment scenario provided access to a Windows host with Administrator credentials and required identification of the **hardcoded password for the Microsoft SQL Server (MSSQL) service**.

The successful path was:

> Windows access → Service enumeration → IIS application enumeration → `MultimasterAPI.dll` → dnSpy static analysis → `MultimasterAPI.Controllers` → `ColleagueController` → `GetColleagues()` → Hardcoded SQL connection string

The hardcoded MSSQL password was successfully recovered from the compiled application assembly.

**Final answer:**

```text
D3veL0pM3nT!
```

---

## 2. Assessment Scope and Objective

| Item | Value |
|---|---|
| Platform | Hack The Box Academy |
| Module | Attacking Common Applications |
| Assessment | Skills Assessment III |
| Target IP observed in RDP session | `10.129.145.109` |
| Hostname | `MULTIMASTER` |
| Operating System | Microsoft Windows `10.0.14393` |
| Authenticated account | `megacorp\administrator` |
| Primary service of interest | Microsoft SQL Server (`MSSQLSERVER`) |
| Application | MultiMasterAPI |
| Objective | Find the hardcoded MSSQL service password |

---

## 3. Assessment Scenario

The assessment states that the penetration-testing team found a Windows host on the network and obtained credentials for the **Administrator** account.

The required task was to:

> Connect to the host and find the `hardcoded password` for the MSSQL service.

The assessment was performed within the authorized HTB Academy laboratory environment.

---

# 4. Initial Access Verification

An existing RDP session was available to the Windows target.

The current Windows identity was verified using:

```cmd
whoami
```

### Output

```text
megacorp\administrator
```

This confirmed that the session had Administrator-level Windows access.

The hostname was then identified:

```cmd
hostname
```

### Output

```text
MULTIMASTER
```

Therefore:

- **User:** `megacorp\administrator`
- **Hostname:** `MULTIMASTER`

---

# 5. MSSQL Service Enumeration

Because the assessment specifically requested the hardcoded password for the MSSQL service, SQL-related Windows services were enumerated.

Command:

```cmd
sc query type= service state= all | findstr /I "SQL MSSQL"
```

### Relevant output

```text
SERVICE_NAME: MSSQLSERVER
DISPLAY_NAME: SQL Server (MSSQLSERVER)

SERVICE_NAME: SQLBrowser
DISPLAY_NAME: SQL Server Browser

SERVICE_NAME: SQLSERVERAGENT
DISPLAY_NAME: SQL Server Agent (MSSQLSERVER)

SERVICE_NAME: SQLTELEMETRY
DISPLAY_NAME: SQL Server CEIP service (MSSQLSERVER)

SERVICE_NAME: SQLWriter
DISPLAY_NAME: SQL Server VSS Writer
```

The primary SQL Server service was:

```text
MSSQLSERVER
```

---

# 6. MSSQLSERVER Service Configuration

The configuration of the MSSQLSERVER service was inspected with:

```cmd
sc qc MSSQLSERVER
```

### Output

```text
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: MSSQLSERVER
        TYPE               : 10   WIN32_OWN_PROCESS
        START_TYPE         : 2    AUTO_START
        ERROR_CONTROL      : 1    NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\sqlservr.exe" -sMSSQLSERVER
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : SQL Server (MSSQLSERVER)
        DEPENDENCIES       : KEYISO
        SERVICE_START_NAME : NT Service\MSSQLSERVER
```

The SQL Server installation directory was therefore identified as:

```text
C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\
```

The SQL Server executable was:

```text
C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\sqlservr.exe
```

---

# 7. SQL Server Configuration Enumeration

The SQL Server installation directory was searched for configuration files:

```cmd
dir /s /b "C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\*.config" 2>nul
```

### Files discovered

```text
C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\DatabaseMail.exe.config
C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\dcexec.exe.config
C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\SQLAGENT.exe.config
C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\sqlservr.exe.config
```

`SQLAGENT.exe.config` was inspected:

```cmd
type "C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\SQLAGENT.exe.config"
```

### Output

```xml
<?xml version ="1.0"?>
<configuration>
    <startup useLegacyV2RuntimeActivationPolicy="true">
        <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.0"/>
    </startup>
</configuration>
```

No database credentials were exposed in this configuration file.

---

# 8. Initial Password Search

A broader search was attempted for common credential-related strings:

```cmd
findstr /S /I /N /C:"password" /C:"pwd=" /C:"User ID" /C:"uid=" "C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\*.*" 2>nul
```

The search generated noisy output because binary SQL Server files were included.

This demonstrated that blindly searching the SQL Server installation directory was not an efficient approach.

The investigation was therefore redirected toward the web application hosted on the same Windows system.

---

# 9. IIS Application Enumeration

The IIS web application's binary directory was inspected:

```cmd
dir C:\inetpub\wwwroot\bin
```

### Relevant output

```text
Directory of C:\inetpub\wwwroot\bin

Antlr3.Runtime.dll
Antlr3.Runtime.pdb
Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll
Microsoft.Web.Infrastructure.dll
MultimasterAPI.dll
MultimasterAPI.pdb
Newtonsoft.Json.dll
roslyn
System.Net.Http.Formatting.dll
System.Web.Cors.dll
System.Web.Helpers.dll
System.Web.Http.Cors.dll
System.Web.Http.dll
System.Web.Http.WebHost.dll
System.Web.Mvc.dll
System.Web.Optimization.dll
System.Web.Razor.dll
System.Web.WebPages.Deployment.dll
System.Web.WebPages.dll
System.Web.WebPages.Razor.dll
WebGrease.dll
```

The most interesting file was:

```text
C:\inetpub\wwwroot\bin\MultimasterAPI.dll
```

This was a custom application assembly and was therefore selected for static analysis.

---

# 10. dnSpy Installation

The target already contained dnSpy.

The installation directory was:

```text
C:\TOOLS\dnSpy
```

The directory contained:

```text
dnSpy.exe
dnSpy.Console.exe
bin\
```

dnSpy was launched using:

```cmd
C:\TOOLS\dnSpy\dnSpy.exe
```

The following assembly was opened:

```text
C:\inetpub\wwwroot\bin\MultimasterAPI.dll
```

---

# 11. Static Analysis of MultimasterAPI.dll

After opening the DLL in dnSpy, the Assembly Explorer revealed the `MultimasterAPI` namespace.

The relevant namespace was:

```text
MultimasterAPI.Controllers
```

Within this namespace, the following controller was identified:

```text
ColleagueController
```

The controller contained methods including:

```text
ColleagueController()
Get()
GetColleagues()
```

The `GetColleagues()` method was selected for analysis.

---

# 12. ColleagueController — GetColleagues()

The decompiled `GetColleagues()` method contained a SQL Server connection string.

The important line was:

```csharp
string connString = "server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;";
```

This directly disclosed the MSSQL credentials.

### Connection string breakdown

| Field | Value |
|---|---|
| Server | `localhost` |
| Database | `Hub_DB` |
| Username | `finder` |
| Password | `D3veL0pM3nT!` |

---

# 13. Relevant Decompiled Code

The relevant portion of the method was:

```csharp
[HttpPost]
[Route("api/getColleagues")]
public List<Colleague> GetColleagues([FromBody] JObject data)
{
    List<Colleague> colleagues = new List<Colleague>();

    string connString =
        "server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;";

    SqlConnection con = new SqlConnection(connString);

    string name = data["name"].ToString();

    string query =
        string.Format(
            "Select * from Colleagues where name like '%{0}%'",
            name
        );

    SqlCommand cmd = new SqlCommand(query, con);

    ...
}
```

The important security finding is the cleartext credential contained directly inside the compiled application.

---

# 14. Application Logic

The `GetColleagues()` method performs the following operations:

1. Creates an empty list of `Colleague` objects.
2. Defines a SQL Server connection string.
3. Creates a `SqlConnection` using that connection string.
4. Reads the `name` value from the supplied JSON body.
5. Constructs a SQL query against the `Colleagues` table.
6. Opens the SQL connection.
7. Executes the query.
8. Reads the returned records.
9. Builds `Colleague` objects from the database results.
10. Returns the list of colleagues.

The database connection is therefore directly dependent on the embedded credentials.

---

# 15. Additional Security Observation — SQL Injection

The method also contains the following code:

```csharp
string name = data["name"].ToString();

string query =
    string.Format(
        "Select * from Colleagues where name like '%{0}%'",
        name
    );
```

The `name` value originates from request data and is inserted directly into the SQL statement.

The query is then passed to:

```csharp
SqlCommand cmd = new SqlCommand(query, con);
```

This is a potential **SQL injection vulnerability** because the application does not use a parameterized query for the user-controlled value.

This observation is separate from the hardcoded-password finding.

---

# 16. Attack Path Summary

The complete assessment path was:

1. Connect to the Windows target through the supplied Administrator access.
2. Verify the current identity using `whoami`.
3. Identify the hostname using `hostname`.
4. Enumerate Windows services.
5. Identify `MSSQLSERVER`.
6. Inspect the MSSQLSERVER service configuration.
7. Identify the SQL Server installation directory.
8. Search SQL Server configuration files.
9. Determine that the initial configuration search did not expose the credential.
10. Enumerate the IIS application's `bin` directory.
11. Discover `MultimasterAPI.dll`.
12. Launch dnSpy.
13. Open `MultimasterAPI.dll`.
14. Navigate to `MultimasterAPI.Controllers`.
15. Identify `ColleagueController`.
16. Open `GetColleagues()`.
17. Locate the hardcoded SQL Server connection string.
18. Extract the MSSQL username and password.
19. Submit the hardcoded password as the assessment answer.

---

# 17. Final Finding

The hardcoded MSSQL connection string was:

```text
server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;
```

Therefore:

### MSSQL Username

```text
finder
```

### MSSQL Password

```text
D3veL0pM3nT!
```

### Database

```text
Hub_DB
```

### Server

```text
localhost
```

### Source

```text
C:\inetpub\wwwroot\bin\MultimasterAPI.dll
```

### Class

```text
MultimasterAPI.Controllers.ColleagueController
```

### Method

```text
GetColleagues()
```

---

# 18. Security Impact

Embedding database credentials directly inside a compiled application creates a significant credential-disclosure risk.

An attacker who obtains the DLL can use a .NET decompiler such as dnSpy to inspect the application and recover the credentials.

The exposed information provides:

- Database server information
- Database name
- Database username
- Database password

Depending on network reachability and the privileges assigned to the `finder` database account, the credentials could allow unauthorized access to the associated SQL Server database.

The SQL query construction additionally creates a potential SQL injection risk.

---

# 19. Remediation Recommendations

## 19.1 Remove Hardcoded Credentials

Database passwords should never be stored directly in source code or compiled assemblies.

The following pattern should be avoided:

```csharp
string connString =
    "server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;";
```

---

## 19.2 Use Secure Secret Storage

Database credentials should be stored using an appropriate secure secret-management mechanism or protected configuration system.

The application should retrieve the credential at runtime without embedding the plaintext password in the deployed DLL.

---

## 19.3 Rotate the Exposed Credential

Because the password has been exposed in the application binary, it should be considered compromised.

The MSSQL password should be changed immediately.

---

## 19.4 Apply Least Privilege

The `finder` database account should have only the permissions required by the application.

Avoid granting unnecessary administrative or database-owner privileges.

---

## 19.5 Use Parameterized SQL

The current code:

```csharp
string query =
    string.Format(
        "Select * from Colleagues where name like '%{0}%'",
        name
    );
```

should be replaced with a parameterized query.

For example:

```csharp
string query =
    "SELECT * FROM Colleagues WHERE name LIKE @name";
```

and the parameter should be supplied separately.

This prevents user-controlled input from being interpreted as SQL syntax.

---

## 19.6 Protect Application Binaries

Access to IIS deployment directories and application binaries should be restricted.

Production users should not have unnecessary read access to deployment artifacts.

---

## 19.7 Scan for Secrets

Source repositories, build artifacts, deployment packages, and compiled assemblies should be scanned for:

- Passwords
- API keys
- Connection strings
- Access tokens
- Private keys
- Other credentials

Secret scanning should be integrated into the development and CI/CD process.

---

## 19.8 Implement Credential Rotation

Database credentials should be rotated periodically and whenever exposure is suspected.

---

# 20. Evidence Summary

| Evidence | Result |
|---|---|
| Windows identity | `megacorp\administrator` |
| Hostname | `MULTIMASTER` |
| MSSQL service | `MSSQLSERVER` |
| SQL Server executable | `C:\Program Files\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQL\Binn\sqlservr.exe` |
| IIS application directory | `C:\inetpub\wwwroot\bin` |
| Application binary | `MultimasterAPI.dll` |
| Namespace | `MultimasterAPI.Controllers` |
| Controller | `ColleagueController` |
| Method | `GetColleagues()` |
| Database server | `localhost` |
| Database | `Hub_DB` |
| Database user | `finder` |
| Hardcoded password | `D3veL0pM3nT!` |

---

# 21. Assessment Answer

The requested hardcoded password for the MSSQL service is:

```text
D3veL0pM3nT!
```

---

# 22. Conclusion

The Skills Assessment III objective was successfully completed.

The credential was not discovered in the standard SQL Server configuration files. Instead, enumeration of the IIS application revealed the custom `MultimasterAPI.dll` assembly.

Static analysis with dnSpy allowed the application structure to be inspected:

```text
MultimasterAPI
└── MultimasterAPI.Controllers
    └── ColleagueController
        └── GetColleagues()
```

The `GetColleagues()` method contained the cleartext SQL Server connection string:

```text
server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;
```

The assessment answer was therefore:

```text
D3veL0pM3nT!
```

---

## 23. Methodology Note

This report records the authorized HTB Academy laboratory activity, commands and outputs observed during the session, and the decompiled application code examined in dnSpy.

No additional exploitation steps or findings beyond the collected assessment evidence are presented as completed activities.
