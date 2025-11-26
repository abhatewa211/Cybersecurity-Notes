# **PHP `$_SERVER` Superglobal - Detailed Notes**

The `$_SERVER` superglobal is an associative array containing server and execution environment information. It provides details about:
- Server configurations
- Current request headers
- Script locations
- Client information

## **1. Key `$_SERVER` Elements**

### **Server Information**
| Variable | Description | Example |
|----------|-------------|---------|
| `$_SERVER['SERVER_NAME']` | Server hostname | `example.com` |
| `$_SERVER['SERVER_ADDR']` | Server IP address | `192.168.1.1` |
| `$_SERVER['SERVER_PORT']` | Server port | `80` or `443` |
| `$_SERVER['SERVER_SOFTWARE']` | Server software | `Apache/2.4.41` |
| `$_SERVER['SERVER_PROTOCOL']` | HTTP protocol | `HTTP/1.1` |

### **Request Information**
| Variable | Description | Example |
|----------|-------------|---------|
| `$_SERVER['REQUEST_METHOD']` | HTTP request method | `GET`, `POST` |
| `$_SERVER['REQUEST_URI']` | URI path | `/index.php?page=1` |
| `$_SERVER['QUERY_STRING']` | Query string | `page=1` |
| `$_SERVER['HTTP_HOST']` | Host header | `example.com` |
| `$_SERVER['HTTP_USER_AGENT']` | Client browser | `Mozilla/5.0` |
| `$_SERVER['HTTP_REFERER']` | Referring page | `https://google.com` |
| `$_SERVER['REMOTE_ADDR']` | Client IP address | `203.0.113.45` |
| `$_SERVER['REMOTE_PORT']` | Client port | `54321` |

### **Script Location**
| Variable | Description | Example |
|----------|-------------|---------|
| `$_SERVER['SCRIPT_FILENAME']` | Absolute script path | `/var/www/index.php` |
| `$_SERVER['SCRIPT_NAME']` | Script path | `/index.php` |
| `$_SERVER['PHP_SELF']` | Current script | `/index.php` |
| `$_SERVER['DOCUMENT_ROOT']` | Server root directory | `/var/www/html` |

## **2. Common Use Cases**

### **Detecting HTTPS**
```php
$is_https = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
// OR
$is_https = $_SERVER['REQUEST_SCHEME'] === 'https';
```

### **Getting Full URL**
```php
$url = "{$_SERVER['REQUEST_SCHEME']}://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
// https://example.com/index.php?page=1
```

### **Redirecting to Same Protocol**
```php
$protocol = $is_https ? 'https://' : 'http://';
header("Location: $protocol{$_SERVER['HTTP_HOST']}/newpage");
```

### **Browser Detection**
```php
$is_mobile = strpos($_SERVER['HTTP_USER_AGENT'], 'Mobile') !== false;
```

### **IP-Based Restrictions**
```php
$allowed_ips = ['192.168.1.1', '10.0.0.1'];
if (!in_array($_SERVER['REMOTE_ADDR'], $allowed_ips)) {
    die('Access denied');
}
```

## **3. Security Considerations**

### **Trust Issues**
- `HTTP_` headers can be spoofed
- `REMOTE_ADDR` can be affected by proxies
- Never trust `HTTP_REFERER`

### **Secure Usage**
```php
// Always sanitize before output
echo htmlspecialchars($_SERVER['HTTP_USER_AGENT']);

// Validate server variables before use
if (filter_var($_SERVER['SERVER_ADDR'], FILTER_VALIDATE_IP)) {
    // Valid IP
}
```

## **4. Full Example: Request Logger**
```php
$log_entry = [
    'timestamp' => date('Y-m-d H:i:s'),
    'ip' => $_SERVER['REMOTE_ADDR'],
    'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'],
    'agent' => $_SERVER['HTTP_USER_AGENT']
];

file_put_contents('access.log', json_encode($log_entry) . PHP_EOL, FILE_APPEND);
```

## **5. Important Notes**
1. Not all `$_SERVER` elements exist in all environments
2. Values are case-sensitive in some servers
3. Some headers require proper server configuration
4. IIS may use different variable names than Apache

The `$_SERVER` superglobal is invaluable for:
- Environment detection
- Request handling
- Security implementations
- Server-specific adaptations

Always validate and sanitize `$_SERVER` data before use, as some values can be manipulated by clients.