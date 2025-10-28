## **1. Understanding Variable Scope in PHP**
Variable scope defines where a variable can be accessed in a PHP script. PHP has three main types of variable scope:
1. **Local Scope** (inside a function)
2. **Global Scope** (outside a function)
3. **Static Scope** (persists between function calls)

---

## **2. Local Scope**
- Variables declared **inside a function** are **local**.
- They can only be accessed within that function.
- Destroyed when the function exits.

### **Example: Local Variable**
```php
function testFunction() {
    $localVar = "I'm local!";
    echo $localVar; // Works
}

testFunction();
echo $localVar; // Error: Undefined variable
```

---

## **3. Global Scope**
- Variables declared **outside a function** are **global**.
- They can be accessed anywhere **except inside functions** (unless explicitly declared global).

### **Example: Global Variable**
```php
$globalVar = "I'm global!";

function showGlobal() {
    echo $globalVar; // Error: Undefined variable
}

showGlobal();
echo $globalVar; // Works
```

---

## **4. Accessing Global Variables Inside Functions**
To use a global variable inside a function, you must:
1. Use the `global` keyword, **or**
2. Use the `$GLOBALS` superglobal array.

### **Method 1: `global` Keyword**
```php
$count = 10;

function incrementCount() {
    global $count;
    $count++;
}

incrementCount();
echo $count; // 11
```

### **Method 2: `$GLOBALS` Array**
```php
$name = "Alice";

function changeName() {
    $GLOBALS['name'] = "Bob";
}

changeName();
echo $name; // "Bob"
```

---

## **5. Static Variables**
- Normally, local variables are destroyed after a function call.
- `static` variables **persist** between function calls.

### **Example: Static Variable**
```php
function counter() {
    static $count = 0;
    $count++;
    echo "Count: $count <br>";
}

counter(); // Count: 1
counter(); // Count: 2
counter(); // Count: 3
```

---

## **6. Superglobals (Predefined Global Variables)**
PHP has several built-in global arrays accessible anywhere:
| **Variable**       | **Description** |
|--------------------|----------------|
| `$GLOBALS` | Stores all global variables |
| `$_SERVER` | Server and execution environment info |
| `$_GET` | HTTP GET request data |
| `$_POST` | HTTP POST request data |
| `$_REQUEST` | Combined GET, POST, and COOKIE data |
| `$_SESSION` | Session variables |
| `$_COOKIE` | HTTP Cookies |
| `$_FILES` | Uploaded file data |
| `$_ENV` | Environment variables |

### **Example: Using `$_GET`**
```php
// URL: example.com?name=John
echo "Hello, " . $_GET['name']; // Output: Hello, John
```

---

## **7. Variable Scope in Included Files**
- Variables declared in an included file **inherit the scope** of where they are included.
- If included inside a function, variables become **local** to that function.

### **Example: Included File Scope**
**config.php:**
```php
$dbHost = "localhost";
```

**index.php:**
```php
function connectDB() {
    include 'config.php';
    echo $dbHost; // Works (local to function)
}

connectDB();
echo $dbHost; // Error: Undefined (not global)
```

---

## **8. Best Practices**
1. **Avoid Excessive Global Variables**  
   - They can lead to **unpredictable code** and bugs.
   - Use **functions with parameters** instead.

2. **Use `static` for Persistent Local State**  
   - Better than global variables for counters/caches.

3. **Prefer `$_SESSION` Over Globals for User Data**  
   - More secure than storing user data in `$GLOBALS`.

4. **Sanitize Superglobals**  
   - Always validate `$_GET`, `$_POST`, etc., to prevent security risks.

---

## **9. Common Mistakes**
### **Mistake 1: Assuming Global Access Inside Functions**
```php
$var = 5;

function test() {
    echo $var; // Undefined (not global by default)
}
```

### **Mistake 2: Overusing `$GLOBALS`**
```php
function badPractice() {
    $GLOBALS['x'] = 10; // Hard to track changes
}
```

### **Mistake 3: Not Initializing Static Variables**
```php
function counter() {
    static $count; // Starts as NULL
    $count++; // Warning: Incrementing uninitialized value
}
```

---

## **10. Summary Table**
| **Scope Type** | **Accessibility** | **Keyword** | **Lifetime** |
|---------------|------------------|------------|-------------|
| **Local** | Inside function only | None | Function execution |
| **Global** | Everywhere (except functions by default) | `global` or `$GLOBALS` | Entire script |
| **Static** | Inside function, persists between calls | `static` | Multiple function calls |
| **Superglobals** | Everywhere | `$_GET`, `$_POST`, etc. | Entire script |

Understanding variable scope helps prevent bugs and write cleaner PHP code. Use **local variables** where possible and **limit global usage** to maintain code reliability. 🚀