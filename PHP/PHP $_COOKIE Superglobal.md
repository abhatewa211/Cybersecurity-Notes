## **Overview**
`$_COOKIE` is a PHP superglobal (associative array) that contains variables passed to the current script via HTTP cookies.

## **Basic Characteristics**

### **Type & Structure**
```php
// $_COOKIE is an associative array
var_dump($_COOKIE); // array(0) { } or array with key-value pairs

// Keys are cookie names, values are cookie values
// Example: $_COOKIE['username'] = 'JohnDoe'
```

### **Scope**
- Available globally in all scopes without `global` keyword
- Automatically populated by PHP when script starts

## **Setting Cookies**

### **Basic Syntax**
```php
// setcookie(name, value, expire, path, domain, secure, httponly)
setcookie('username', 'JohnDoe', time() + 3600, '/');

// Alternative: setrawcookie() - doesn't URL-encode the value
setrawcookie('preference', 'raw_value', time() + 86400);
```

### **Parameters Explained**
```php
setcookie(
    $name,           // Cookie name (string)
    $value,          // Cookie value (string)
    $expire,         // Expiration timestamp (0 = session cookie)
    $path,           // Path where cookie is available ('/' = entire domain)
    $domain,         // Domain scope ('.example.com' = all subdomains)
    $secure,         // Only sent over HTTPS if true
    $httponly        // Accessible only via HTTP, not JavaScript
);
```

### **Common Patterns**
```php
// Session cookie (expires when browser closes)
setcookie('session_id', 'abc123', 0);

// Persistent cookie (30 days)
setcookie('user_pref', 'dark_mode', time() + (30 * 24 * 3600));

// Secure HTTPS-only cookie
setcookie('auth_token', 'xyz789', time() + 3600, '/', '', true, true);

// Cookie for entire domain and subdomains
setcookie('site_lang', 'en', time() + 86400, '/', '.example.com');
```

## **Accessing Cookies**

### **Reading Cookie Values**
```php
// Check if cookie exists
if (isset($_COOKIE['username'])) {
    echo "Welcome back, " . $_COOKIE['username'];
}

// Access with default value
$theme = $_COOKIE['theme'] ?? 'light'; // PHP 7+

// Old way (pre-PHP 7)
$theme = isset($_COOKIE['theme']) ? $_COOKIE['theme'] : 'light';

// Loop through all cookies
foreach ($_COOKIE as $name => $value) {
    echo "$name: $value<br>";
}
```

### **Important Notes on Timing**
```php
// THIS WON'T WORK as expected:
setcookie('test', 'value');
echo $_COOKIE['test']; // NULL - cookie not available until next request

// Correct approach:
setcookie('test', 'value');
// On NEXT page load, $_COOKIE['test'] will be available
```

## **Deleting/Modifying Cookies**

### **Deleting a Cookie**
```php
// Method 1: Set expiration in the past
setcookie('username', '', time() - 3600, '/');

// Method 2: Empty value and expired time
setcookie('username', '', 1);

// Also unset from $_COOKIE array for current script
unset($_COOKIE['username']);
```

### **Modifying Cookies**
```php
// Simply set a new value with same parameters
setcookie('counter', ($_COOKIE['counter'] ?? 0) + 1, time() + 3600, '/');
```

## **Security Considerations**

### **Security Best Practices**
```php
// 1. Always validate and sanitize cookie data
$username = filter_var($_COOKIE['username'] ?? '', FILTER_SANITIZE_STRING);

// 2. Use httponly flag for sensitive cookies
setcookie('session_id', $token, time() + 3600, '/', '', true, true);

// 3. Store minimal data in cookies
// Store session ID, not user data
setcookie('session_id', $encryptedSessionId, time() + 3600, '/', '', true, true);

// 4. Consider using session cookies for sensitive data
session_start(); // Use $_SESSION instead
```

### **Common Vulnerabilities**
```php
// UNSAFE - Direct output without sanitization
echo $_COOKIE['user_input']; // XSS risk!

// SAFE - Always sanitize
echo htmlspecialchars($_COOKIE['user_input'] ?? '', ENT_QUOTES, 'UTF-8');
```

## **Limitations & Constraints**

### **Size Limitations**
- 4KB per cookie (including name, value, attributes)
- 50 cookies per domain (varies by browser)
- 3000 total cookies across all domains (browser-dependent)

### **Browser Compliance Issues**
```php
// Different browsers handle cookies differently
// Always test in multiple browsers

// Some mobile browsers may reject cookies
if (!isset($_COOKIE['test_cookie'])) {
    // Handle non-cookie fallback
}
```

## **Practical Examples**

### **Example 1: Remember Me Functionality**
```php
// Setting remember me cookie
if (isset($_POST['remember_me'])) {
    $token = bin2hex(random_bytes(32));
    setcookie('remember_token', $token, time() + (30 * 24 * 3600), '/', '', true, true);
    // Store token in database associated with user
}

// Checking on login
if (isset($_COOKIE['remember_token'])) {
    $token = $_COOKIE['remember_token'];
    // Verify token in database and auto-login
}
```

### **Example 2: User Preferences**
```php
// Setting preferences
if (isset($_POST['theme'])) {
    setcookie('theme', $_POST['theme'], time() + (365 * 24 * 3600), '/');
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Applying preferences
$theme = $_COOKIE['theme'] ?? 'light';
echo "<body class='$theme-theme'>";
```

### **Example 3: Cookie Consent**
```php
// Check if consent given
if (isset($_POST['accept_cookies'])) {
    setcookie('cookies_accepted', '1', time() + (365 * 24 * 3600), '/');
}

// Show banner if not accepted
if (!isset($_COOKIE['cookies_accepted'])) {
    echo '<div class="cookie-banner">...</div>';
}
```

## **Debugging Cookies**

### **Debugging Techniques**
```php
// View all cookies
print_r($_COOKIE);

// Check headers
header('Content-Type: text/plain');
print_r(headers_list()); // See Set-Cookie headers

// Browser Developer Tools
// - Check Application/Storage tab
// - View network requests
```

### **Common Issues & Solutions**
```php
// Issue: Cookies not being set
// Solution: Check output before setcookie()
ob_start(); // Buffer output

// Issue: Cookies not persisting
// Solution: Verify expiration time
if (time() > ($_COOKIE['expiry'] ?? 0)) {
    // Cookie expired
}

// Issue: Path/domain problems
// Solution: Use consistent parameters
setcookie('name', 'value', time() + 3600, '/', '.yourdomain.com');
```

## **Alternatives & Best Practices**

### **When to Use Sessions Instead**
```php
// Use $_SESSION for:
// - Sensitive data
// - Large amounts of data
// - Data that changes frequently

session_start();
$_SESSION['user_id'] = 123; // Server-side storage
```

### **Modern Alternatives**
- **HTTP Only Cookies**: For authentication tokens
- **SameSite Attribute**: (PHP 7.3+)
  ```php
  setcookie('name', 'value', [
      'expires' => time() + 3600,
      'path' => '/',
      'domain' => 'example.com',
      'secure' => true,
      'httponly' => true,
      'samesite' => 'Strict' // or 'Lax', 'None'
  ]);
  ```
- **JavaScript Cookies**: Using `document.cookie` for client-only needs

## **Important Notes**

1. **Output Buffering**: Cookies must be set before any output (HTML, echo, whitespace)
2. **Character Encoding**: Values are URL-encoded automatically by `setcookie()`
3. **Array Cookies**: Can store arrays in cookies
   ```php
   setcookie('preferences[theme]', 'dark');
   setcookie('preferences[language]', 'en');
   // Access as $_COOKIE['preferences']['theme']
   ```
4. **Testing**: Always test in incognito/private browsing mode
5. **Legal Compliance**: Follow GDPR, CCPA, etc. (get user consent)

## **Quick Reference Card**

```php
// SET
setcookie($name, $value, $expire, $path, $domain, $secure, $httponly);

// GET
$value = $_COOKIE[$name] ?? $default;

// DELETE
setcookie($name, '', time() - 3600, $path, $domain);

// CHECK
if (isset($_COOKIE[$name])) { /* exists */ }

// SECURE SETTINGS (recommended for auth)
setcookie('auth', $token, time()+3600, '/', '.site.com', true, true);
```

Remember: Cookies are client-side storage - never trust them for sensitive operations without server-side validation.