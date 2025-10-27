# PHP Introduction and Installation in VS Code

## What is PHP?

PHP (Hypertext Preprocessor) is a popular open-source server-side scripting language designed for web development. It's embedded in HTML and executed on the server before the page is sent to the client's browser.

### Key Features:
- Server-side execution
- Cross-platform compatibility
- Supports various databases
- Large community and extensive documentation
- Object-oriented capabilities
- Easy integration with HTML, CSS, JavaScript

## Installing PHP for VS Code

### 1. Install PHP on Your System

#### For Windows:
1. Download PHP from [windows.php.net/download](https://windows.php.net/download)
2. Choose the Thread Safe version for use with a web server
3. Extract the ZIP file to a directory (e.g., `C:\php`)
4. Add PHP to your system PATH:
   - Open System Properties > Environment Variables
   - Edit the "Path" variable and add your PHP directory (e.g., `C:\php`)
5. Verify installation by running in Command Prompt:
   ```bash
   php -v
   ```

#### For macOS:
1. Use Homebrew (recommended):
   ```bash
   brew install php
   ```
2. Or download from [php.net/downloads](https://www.php.net/downloads)
3. Verify installation:
   ```bash
   php -v
   ```

#### For Linux (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install php
php -v
```

### 2. Setting Up VS Code for PHP Development

#### Essential Extensions:
1. **PHP Intelephense** (most important):
   - Provides code completion, navigation, and refactoring
   - Better performance than PHP IntelliSense
   - Install from VS Code Marketplace

2. **PHP Debug**:
   - Required for debugging PHP code
   - Install from VS Code Marketplace

3. **PHP Server** (optional):
   - Quickly launch a PHP development server
   - Install from VS Code Marketplace

4. **PHP Namespace Resolver** (optional but helpful):
   - Helps with importing and expanding namespaces
   - Install from VS Code Marketplace

#### Recommended Additional Extensions:
- **PHP DocBlocker** - for generating docblocks
- **PHP Getters & Setters** - for quickly generating getters/setters
- **PHPUnit** - if you're using PHPUnit for testing

### 3. Configuring PHP Debugging

1. Install Xdebug (recommended debugger):
   - For Windows: Edit `php.ini` and add:
 ```ini
     zend_extension=path_to_xdebug.dll
     xdebug.mode=debug
     xdebug.start_with_request=yes
``` 
- For Linux/macOS:
```bash
     pecl install xdebug
```
Then add to `php.ini`:
```ini
	zend_extension=xdebug.so
     xdebug.mode=debug
     xdebug.start_with_request=yes`
```

2. In VS Code:
   - Create a `.vscode/launch.json` file in your project
   - Add this configuration:
```json
     {
       "version": "0.2.0",
       "configurations": [
         {
           "name": "Listen for Xdebug",
           "type": "php",
           "request": "launch",
           "port": 9003
         },
         {
           "name": "Launch currently open script",
           "type": "php",
           "request": "launch",
           "program": "${file}",
           "cwd": "${fileDirname}",
           "port": 9003
         }
       ]
     }
```

### 4. Basic PHP Project Setup in VS Code

1. Create a new folder for your project
2. Open it in VS Code
3. Create an `index.php` file with basic content:
   ```php
   <?php
   echo "Hello, PHP World!";
   ?>
   ```
4. To run:
   - Use the PHP Server extension (right-click file > "PHP Server: Serve project")
   - Or run from terminal:
     ```bash
     php -S localhost:8000
     ```
   - Then open `http://localhost:8000` in your browser

### 5. PHP Settings in VS Code

Add these to your VS Code settings (`settings.json`) for better PHP development:

```json
{
  "php.validate.executablePath": "path_to_php_executable",
  "intelephense.environment.phpVersion": "8.1.0",
  "intelephense.files.maxSize": 2000000,
  "[php]": {
    "editor.defaultFormatter": "bmewburn.vscode-intelephense-client"
  },
  "intelephense.format.enable": true,
  "intelephense.completion.insertUseDeclaration": true,
  "intelephense.diagnostics.undefinedTypes": false
}
```

## Troubleshooting

1. **PHP not recognized in terminal**:
   - Verify PHP is in your system PATH
   - Restart VS Code after installation

2. **Extensions not working**:
   - Check PHP version compatibility
   - Ensure you have a `php.ini` file configured

3. **Debugging not working**:
   - Verify Xdebug is properly installed (`php -m` should list xdebug)
   - Check the port configuration matches in php.ini and launch.json

## 6. Testing PHP in VS Code

Now that you have PHP installed and configured in VS Code, let's test your setup to ensure everything works properly.

### 1. Basic PHP File Test

1. Create a new file named `test.php` in your project folder
2. Add the following code:

```php
<?php
// Basic PHP test
echo "<h1>PHP is working!</h1>";

// Show PHP information (remove this in production)
phpinfo();
?>
```

3. Save the file (`Ctrl+S` or `Cmd+S`)

### 2. Running the Test File

#### Method 1: Using Built-in PHP Server
1. Open the integrated terminal in VS Code (`Ctrl+` or `Cmd+`)
2. Run:
   ```bash
   php -S localhost:8000
   ```
3. Open your browser and visit:
   ```
   http://localhost:8000/test.php
   ```

#### Method 2: Using PHP Server Extension
1. Right-click on `test.php` in the Explorer
2. Select "PHP Server: Serve project"
3. VS Code will automatically open your browser

#### Method 3: Direct Execution
1. In the terminal, run:
   ```bash
   php test.php
   ```
   (This will output to the terminal instead of a browser)

### 3. Expected Results

You should see:
1. A heading saying "PHP is working!"
2. A detailed PHP information page showing:
   - Your PHP version
   - Loaded extensions (including Xdebug if installed)
   - Configuration settings

### 4. Debugging Test

1. Set a breakpoint by clicking to the left of line numbers in `test.php`
2. Press `F5` or click "Run and Debug" in the left sidebar
3. Select "Listen for Xdebug"
4. Open your browser and visit:
   ```
   http://localhost:8000/test.php
   ```
5. VS Code should pause execution at your breakpoint

### 5. Extension Functionality Test

Test these Intelephense features:
1. **Code Completion**:
   - Type `echo str` and check if string functions appear
2. **Go to Definition**:
   - Right-click on `phpinfo` and select "Go to Definition"
3. **Hover Information**:
   - Hover over `phpinfo` to see function documentation
4. **Error Checking**:
   - Add `echo undefinedFunction();` and look for squiggly lines

### 6. Troubleshooting Common Issues

If something isn't working:

1. **PHP not executing**:
   - Verify PHP is in your PATH (`php -v` in terminal)
   - Check the VS Code PHP executable path in settings

2. **Extensions not working**:
   - Reload VS Code (`Ctrl+Shift+P` > "Reload Window")
   - Check extension requirements (some need PHP 7.4+)

3. **Debugging not working**:
   - Verify Xdebug is installed (`php -m | grep xdebug`)
   - Check ports match in `php.ini` and `launch.json`

4. **No syntax highlighting**:
   - Ensure file has `.php` extension
   - Check PHP extensions are enabled

### 7. Final Verification

Create a more complex test file `functions.php`:

```php
<?php
function calculateSum(int $a, int $b): int {
    return $a + $b;
}

$result = calculateSum(5, '7'); // Intentional type mismatch
echo "The result is: " . $result;

// Test debugging
$x = 10;
$y = 20;
$z = $x * $y; // Set breakpoint here
echo "\nMultiplication result: " . $z;
?>
```

Check for:
1. Type warnings on the '7' argument
2. Proper function documentation on hover
3. Working breakpoints
4. Correct output (should show "The result is: 12" and "Multiplication result: 200")

If all these tests pass, your PHP environment in VS Code is properly set up and ready for development!