The `$_GET` superglobal in PHP is an associative array that collects data sent to the server via URL parameters (HTTP GET method). It's one of the most commonly used superglobals for retrieving user input from query strings.

## **1. Basics of `$_GET`**
- **Type**: Associative array (`array`)
- **Source**: Data appended to the URL after `?`
- **Format**: `key=value` pairs separated by `&`
- **Example URL**:  
  `http://example.com/?name=John&age=25`

### **Accessing `$_GET` Data**
```php
// URL: http://example.com/?username=alice&page=1
echo $_GET['username']; // Output: "alice"
echo $_GET['page'];    // Output: "1"
```

## **2. Key Characteristics**
| Feature | Description |
|---------|-------------|
| **HTTP Method** | Only works with GET requests |
| **Visibility** | Data appears in browser address bar |
| **Data Limits** | URLs have length restrictions (~2048 chars) |
| **Security** | Never trust `$_GET` data (always validate/sanitize) |
| **Content Type** | Always strings (numeric values need conversion) |

## **3. Handling Multiple Parameters**
```php
// URL: http://example.com/?category=books&sort=price&limit=10
$category = $_GET['category']; // "books"
$sortBy = $_GET['sort'];      // "price"
$limit = $_GET['limit'];      // "10"
```

## **4. Checking if GET Parameters Exist**
### **Method 1: `isset()`**
```php
if (isset($_GET['search'])) {
    $searchTerm = $_GET['search'];
    echo "Searching for: $searchTerm";
}
```

### **Method 2: `empty()` (Checks for empty strings too)**
```php
if (!empty($_GET['page'])) {
    $currentPage = (int)$_GET['page'];
}
```

### **Method 3: Null Coalescing Operator (PHP 7+)**
```php
$id = $_GET['id'] ?? 1; // Default to 1 if not set
```

## **5. Security Best Practices**
### **a) Always Validate Input**
```php
// Check if expected parameter exists
if (!isset($_GET['user_id'])) {
    die("User ID is required!");
}

// Validate numeric input
if (!is_numeric($_GET['user_id'])) {
    die("Invalid User ID!");
}
```

### **b) Sanitize Data**
```php
// For strings
$username = htmlspecialchars($_GET['username']);

// For numbers (prevent SQL injection)
$productId = (int)$_GET['product_id'];

// For database queries (use prepared statements)
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['user_id']]);
```

### **c) URL Encoding**
```php
// Properly encode URLs
$search = urlencode("coffee & tea");
$url = "search.php?q=$search"; // q=coffee+%26+tea
```

## **6. Common Use Cases**
### **a) Pagination**
```php
// URL: products.php?page=3
$currentPage = max(1, (int)($_GET['page'] ?? 1));
$itemsPerPage = 10;
$offset = ($currentPage - 1) * $itemsPerPage;
```

### **b) Search Filters**
```php
// URL: search.php?query=php&sort=date
$searchQuery = $_GET['query'] ?? '';
$sortMethod = in_array($_GET['sort'], ['date','price']) 
    ? $_GET['sort'] 
    : 'date';
```

### **c) API Endpoints**
```php
// URL: api/users.php?format=json
header('Content-Type: application/json');
echo json_encode(['data' => $users]);
```

## **7. Potential Risks**
| Risk | Prevention |
|------|------------|
| **XSS Attacks** | Use `htmlspecialchars()` for output |
| **SQL Injection** | Use prepared statements |
| **Parameter Tampering** | Validate all inputs |
| **Information Disclosure** | Don't expose sensitive data in URLs |

## **8. `$_GET` vs `$_POST`**
| Feature | `$_GET` | `$_POST` |
|---------|---------|----------|
| **Visibility** | URL-visible | Hidden in request body |
| **Bookmarking** | Can be bookmarked | Cannot be bookmarked |
| **Data Size** | Limited (~2KB) | Larger (depends on server) |
| **Caching** | Can be cached | Not cached |
| **Security** | Less secure (logged in servers) | More secure |

## **9. Practical Example: Search Form**
```html
<!-- HTML Form -->
<form action="search.php" method="get">
    <input type="text" name="query" placeholder="Search...">
    <button type="submit">Search</button>
</form>
```

```php
// search.php
$searchTerm = htmlspecialchars($_GET['query'] ?? '');
echo "You searched for: " . $searchTerm;
```

## **10. Advanced Techniques**
### **a) Building Query Strings**
```php
$params = [
    'page' => 2,
    'sort' => 'price',
    'available' => 1
];
$queryString = http_build_query($params);
// "page=2&sort=price&available=1"
```

### **b) Handling Arrays in GET**
```php
// URL: ?filters[size]=medium&filters[color]=blue
$filters = $_GET['filters'] ?? [];
// Array: ['size' => 'medium', 'color' => 'blue']
```

### **c) Logging GET Requests**
```php
file_put_contents('access.log', 
    date('Y-m-d H:i:s') . ' - ' . 
    $_SERVER['QUERY_STRING'] . "\n", 
    FILE_APPEND
);
```

## **Summary Cheat Sheet**
```php
// 1. Basic access
$value = $_GET['param_name'];

// 2. Safe access with defaults
$value = $_GET['param'] ?? 'default';

// 3. Type conversion
$id = (int)$_GET['id'];

// 4. Validation
if (!isset($_GET['required_param'])) {
    die("Parameter missing!");
}

// 5. Sanitization
$cleanInput = htmlspecialchars($_GET['user_input']);

// 6. Building URLs
$url = "page.php?" . http_build_query(['a' => 1, 'b' => 2]);
```

The `$_GET` superglobal is essential for web development but requires careful handling to ensure security and reliability. Always validate, sanitize, and escape data from URL parameters.