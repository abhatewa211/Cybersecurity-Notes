## **Overview**
`$_SESSION` is a PHP superglobal array that persists data across multiple page requests for the same user, using server-side storage with a client-side session ID.

## **Session Basics**

### **How Sessions Work**
```
Client (Browser)              Server (PHP)
     |                             |
     |--- Request (no session) --->|
     |<-- Set-Cookie: PHPSESSID ---|
     |--- Request with Cookie ---->|
     |<-- Session Data ------------|
```

### **Initializing a Session**
```php
// Must be called before ANY output (including whitespace)
session_start();

// After session_start(), $_SESSION is available
$_SESSION['username'] = 'john_doe';
```

### **Session Configuration**
```php
// php.ini settings (or use ini_set())
session.save_handler = files      // Default: file storage
session.save_path = "/tmp"        // Where session files are stored
session.name = "PHPSESSID"        // Cookie name for session ID
session.cookie_lifetime = 0       // 0 = until browser closes
session.gc_maxlifetime = 1440     // 24 minutes default garbage collection
session.cookie_httponly = 1       // Prevent JavaScript access
session.cookie_secure = 1         // HTTPS only (if using SSL)
session.use_strict_mode = 1       // Prevents uninitialized session IDs
```

## **Working with $_SESSION**

### **Basic Operations**
```php
// Start session
session_start();

// Store data
$_SESSION['user_id'] = 123;
$_SESSION['user_data'] = [
    'name' => 'John Doe',
    'email' => 'john@example.com',
    'role' => 'admin'
];

// Access data
$userId = $_SESSION['user_id'];
echo "Welcome, " . $_SESSION['user_data']['name'];

// Check if session variable exists
if (isset($_SESSION['user_id'])) {
    // User is logged in
}

// Remove specific session variable
unset($_SESSION['user_data']);

// Check and use with null coalescing operator (PHP 7+)
$theme = $_SESSION['theme'] ?? 'light';

// Count session variables
$count = count($_SESSION);
```

### **Session Lifecycle Management**
```php
// Complete session destruction
session_destroy();

// But $_SESSION array still exists in current script
unset($_SESSION); // Remove from memory for current request

// To completely restart
session_start(); // New session ID generated
```

### **Regenerating Session ID**
```php
// Important for security (prevent session fixation)
session_regenerate_id(true); // true = delete old session file

// Use after privilege level change (login)
if ($login_successful) {
    session_regenerate_id(true);
    $_SESSION['logged_in'] = true;
}
```

## **Session Configuration & Options**

### **Custom Session Parameters**
```php
// Set session name (before session_start())
session_name('MYAPPSESSID');

// Configure cookie parameters (before session_start())
session_set_cookie_params([
    'lifetime' => 3600,           // 1 hour
    'path' => '/',
    'domain' => '.example.com',
    'secure' => true,             // HTTPS only
    'httponly' => true,           // No JS access
    'samesite' => 'Strict'        // CSRF protection
]);

// Set custom save path
ini_set('session.save_path', '/custom/path');
ini_set('session.save_handler', 'redis'); // Alternative handlers

// Start with options (PHP 7.1+)
session_start([
    'cookie_lifetime' => 86400,
    'read_and_close'  => true,    // For read-only sessions
    'use_strict_mode' => true
]);
```

## **Security Considerations**

### **Session Security Best Practices**
```php
// 1. Always use HTTPS for sessions
ini_set('session.cookie_secure', 1);

// 2. Prevent JavaScript access
ini_set('session.cookie_httponly', 1);

// 3. Use strict mode (PHP 5.5.2+)
ini_set('session.use_strict_mode', 1);

// 4. Regenerate ID on login
function login_user($user_id) {
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user_id;
    $_SESSION['login_time'] = time();
    $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
}

// 5. Validate session on each request
function validate_session() {
    if ($_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
        // Possible session hijacking
        session_regenerate_id(true);
    }
    
    if ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
        // Terminate suspicious session
        session_destroy();
        header('Location: /login.php');
        exit;
    }
    
    // Session timeout (30 minutes)
    if (isset($_SESSION['last_activity']) && 
        (time() - $_SESSION['last_activity'] > 1800)) {
        session_destroy();
        header('Location: /login.php?timeout=1');
        exit;
    }
    $_SESSION['last_activity'] = time();
}
```

### **Session Fixation Protection**
```php
// Always regenerate session ID after authentication
session_start();
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}

// Destroy old session completely
session_regenerate_id(true);
```

## **Advanced Session Management**

### **Custom Session Handlers**
```php
// Example: Database session handler
class DatabaseSessionHandler implements SessionHandlerInterface {
    private $db;
    
    public function open($savePath, $sessionName) {
        $this->db = new PDO('mysql:host=localhost;dbname=test', 'user', 'pass');
        return true;
    }
    
    public function close() {
        $this->db = null;
        return true;
    }
    
    public function read($sessionId) {
        $stmt = $this->db->prepare("SELECT data FROM sessions WHERE id = ?");
        $stmt->execute([$sessionId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['data'] : '';
    }
    
    public function write($sessionId, $data) {
        $stmt = $this->db->prepare("REPLACE INTO sessions (id, data, timestamp) VALUES (?, ?, ?)");
        return $stmt->execute([$sessionId, $data, time()]);
    }
    
    public function destroy($sessionId) {
        $stmt = $this->db->prepare("DELETE FROM sessions WHERE id = ?");
        return $stmt->execute([$sessionId]);
    }
    
    public function gc($maxLifetime) {
        $stmt = $this->db->prepare("DELETE FROM sessions WHERE timestamp < ?");
        return $stmt->execute([time() - $maxLifetime]);
    }
}

// Register custom handler
$handler = new DatabaseSessionHandler();
session_set_save_handler($handler, true);
session_start();
```

### **Session Serialization**
```php
// PHP automatically serializes/deserializes session data
$_SESSION['complex'] = [
    'object' => new MyClass(),
    'array' => [1, 2, 3],
    'resource' => fopen('file.txt', 'r') // Warning: Resources can't be serialized!
];

// Custom serialization (rarely needed)
ini_set('session.serialize_handler', 'php_serialize');
// or
ini_set('session.serialize_handler', 'wddx');
```

## **Common Patterns & Examples**

### **Login System**
```php
// login.php
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    if (authenticate($username, $password)) {
        session_regenerate_id(true);
        $_SESSION['user_id'] = get_user_id($username);
        $_SESSION['username'] = $username;
        $_SESSION['login_time'] = time();
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        
        // Redirect to prevent form resubmission
        header('Location: /dashboard.php');
        exit;
    }
}

// dashboard.php
session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: /login.php');
    exit;
}

// Validate session
validate_session(); // Custom function from earlier

echo "Welcome, " . htmlspecialchars($_SESSION['username']);

// logout.php
session_start();
$_SESSION = array(); // Clear all session variables

// Destroy session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

session_destroy();
header('Location: /login.php');
exit;
```

### **Flash Messages (One-time session messages)**
```php
// Helper functions
function set_flash_message($type, $message) {
    $_SESSION['flash'][$type] = $message;
}

function get_flash_message($type) {
    if (isset($_SESSION['flash'][$type])) {
        $message = $_SESSION['flash'][$type];
        unset($_SESSION['flash'][$type]);
        return $message;
    }
    return null;
}

// Usage
set_flash_message('success', 'Profile updated successfully!');
// Redirect...
// Then on next page:
$success = get_flash_message('success');
if ($success) {
    echo "<div class='alert alert-success'>$success</div>";
}
```

### **Shopping Cart**
```php
session_start();

// Initialize cart if not exists
if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

// Add item to cart
function add_to_cart($product_id, $quantity = 1) {
    if (isset($_SESSION['cart'][$product_id])) {
        $_SESSION['cart'][$product_id] += $quantity;
    } else {
        $_SESSION['cart'][$product_id] = $quantity;
    }
}

// Remove item from cart
function remove_from_cart($product_id) {
    unset($_SESSION['cart'][$product_id]);
}

// Get cart total
function get_cart_total() {
    $total = 0;
    foreach ($_SESSION['cart'] as $product_id => $quantity) {
        $price = get_product_price($product_id);
        $total += $price * $quantity;
    }
    return $total;
}
```

## **Performance Optimization**

### **Session Locking**
```php
// Problem: Session files are locked by default
// Solution: Close session early when possible

// Read-only sessions (PHP 7.0+)
session_start(['read_and_close' => true]);

// Or manually close when done writing
session_start();
$_SESSION['last_visit'] = time();
session_write_close(); // Release lock immediately

// Now do other processing without holding session lock
process_long_task();
```

### **Session Storage Optimization**
```php
// Store minimal data in session
$_SESSION['user_id'] = 123; // Good
$_SESSION['user'] = $large_user_object; // Bad

// Use database for large data
$_SESSION['cart_ids'] = [1, 2, 3]; // Store only IDs
// Fetch cart details from DB when needed

// Clean up old sessions regularly
ini_set('session.gc_probability', 1);
ini_set('session.gc_divisor', 100); // 1% chance on each request
ini_set('session.gc_maxlifetime', 1800); // 30 minutes
```

## **Troubleshooting & Debugging**

### **Common Issues & Solutions**
```php
// Issue: "Headers already sent" error
// Solution: Ensure no output before session_start()
ob_start(); // Enable output buffering at top of script

// Issue: Session not persisting
// Solution: Check cookie settings
session_set_cookie_params(3600, '/', '.example.com', true, true);
session_start();

// Issue: Session data lost
// Solution: Check save path permissions
ini_set('session.save_path', '/var/www/sessions');
// Ensure directory exists and is writable

// Issue: Concurrent writes
// Solution: Implement session locking or use read_and_close
session_start(['read_and_close' => true]);

// Debug session
echo '<pre>';
print_r($_SESSION);
echo 'Session ID: ' . session_id();
echo 'Session Name: ' . session_name();
echo '</pre>';
```

### **Session Debugging Functions**
```php
// Get session status
$status = session_status();
switch ($status) {
    case PHP_SESSION_DISABLED:
        echo "Sessions disabled";
        break;
    case PHP_SESSION_NONE:
        echo "No active session";
        break;
    case PHP_SESSION_ACTIVE:
        echo "Session active";
        break;
}

// Get session info
$info = session_get_cookie_params();
print_r($info);

// List all session variables
foreach ($_SESSION as $key => $value) {
    echo "$key: " . print_r($value, true) . "<br>";
}
```

## **Best Practices Summary**

### **Do's**
```php
// ✓ Always call session_start() before any output
// ✓ Regenerate session ID on login
// ✓ Use secure, HTTP-only cookies
// ✓ Validate session data on each request
// ✓ Set appropriate timeout
// ✓ Store minimal data in sessions
// ✓ Close session early when possible
// ✓ Use HTTPS for session cookies
```

### **Don'ts**
```php
// ✗ Don't store sensitive data (passwords, credit cards)
// ✗ Don't store large objects
// ✗ Don't trust session data without validation
// ✗ Don't use predictable session IDs
// ✗ Don't keep sessions alive indefinitely
// ✗ Don't output before session_start()
```

## **Quick Reference Card**

```php
// BASIC USAGE
session_start();                    // Start session
$_SESSION['key'] = 'value';         // Store data
$value = $_SESSION['key'];          // Retrieve data
unset($_SESSION['key']);            // Remove data
session_destroy();                  // Destroy session

// SECURITY
session_regenerate_id(true);        // Regenerate ID
ini_set('session.cookie_secure', 1);   // HTTPS only
ini_set('session.cookie_httponly', 1); // No JS access
ini_set('session.use_strict_mode', 1); // Strict mode

// CONFIGURATION
session_name('CUSTOMID');           // Before session_start()
session_set_cookie_params([         // Before session_start()
    'lifetime' => 3600,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict'
]);

// PERFORMANCE
session_write_close();              // Release lock early
session_start(['read_and_close' => true]); // Read-only
```

## **Alternative Session Solutions**

### **Using Redis/Memcached**
```php
// In php.ini or .htaccess
session.save_handler = redis
session.save_path = "tcp://127.0.0.1:6379?auth=password"

// Or programmatically
ini_set('session.save_handler', 'redis');
ini_set('session.save_path', 'tcp://127.0.0.1:6379');
```

### **JWT (JSON Web Tokens) Alternative**
```php
// For stateless authentication (API, SPAs)
$payload = [
    'user_id' => 123,
    'exp' => time() + 3600
];
$token = base64_encode(json_encode($payload));
// Send as Authorization header, not in session
```

### **Native PHP Sessions vs Custom**
```php
// Use native sessions when:
// - Simple web applications
// - Shared hosting environments
// - Quick development needed

// Consider custom handlers when:
// - Need horizontal scaling
// - Special storage requirements (DB, Redis)
// - Advanced session management needed
```

Remember: Sessions are powerful but require careful handling for security and performance. Always validate session data, use secure settings, and store only necessary information.