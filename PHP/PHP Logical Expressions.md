Logical expressions in PHP allow you to combine conditions, evaluate boolean logic, and control program flow. PHP supports standard logical operators (`&&`, `||`, `!`) and additional constructs for complex conditions.

---

## **1. Basic Logical Operators**
PHP supports the following logical operators:

| **Operator** | **Name**         | **Example**              | **Result** |
|-------------|-----------------|--------------------------|------------|
| `&&` (or `and`) | Logical AND | `$a && $b` | `true` if **both** `$a` and `$b` are `true` |
| `\|\|` (or `or`) | Logical OR | `$a \|\| $b` | `true` if **either** `$a` or `$b` is `true` |
| `!` | Logical NOT | `!$a` | `true` if `$a` is `false` |
| `xor` | Exclusive OR | `$a xor $b` | `true` if **only one** of `$a` or `$b` is `true` (not both) |

### **Examples**
```php
$a = true;
$b = false;

var_dump($a && $b);  // false (both must be true)
var_dump($a || $b);  // true (at least one is true)
var_dump(!$a);       // false (negation of true)
var_dump($a xor $b); // true (only one is true)
```

---

## **2. Short-Circuit Evaluation**
PHP uses **short-circuit evaluation**:
- For `&&` (`AND`), if the first condition is `false`, the second is **not evaluated**.
- For `||` (`OR`), if the first condition is `true`, the second is **not evaluated**.

### **Example**
```php
function isLoggedIn() {
    echo "Checking login...\n";
    return true;
}

function isAdmin() {
    echo "Checking admin...\n";
    return false;
}

// Short-circuit example
if (isLoggedIn() && isAdmin()) {
    // Only runs isLoggedIn(), isAdmin() is skipped if first is false
}
```

---

## **3. Operator Precedence**
Logical operators have different precedence levels (from highest to lowest):
1. `!` (NOT)
2. `&&` (AND)
3. `||` (OR)
4. `and`, `xor`, `or` (lowest precedence)

### **Example**
```php
$result = false || true;   // true (evaluated as (false || true))
$result = false or true;   // false (evaluated as ($result = false) or true)
```

**Best Practice:** Use parentheses `()` to clarify precedence:
```php
$result = (false or true); // true (explicit precedence)
```

---

## **4. Combining Logical Operators**
You can chain multiple conditions:
```php
$age = 25;
$isStudent = true;
$hasDiscount = false;

if ($age < 30 && $isStudent && !$hasDiscount) {
    echo "Eligible for student discount!";
}
```

---

## **5. Truthy and Falsy Values**
PHP evaluates non-boolean values in logical expressions:
- **Falsy values**: `false`, `0`, `""`, `"0"`, `NULL`, `[]`
- **Truthy values**: Everything else (`true`, `1`, `"hello"`, `[1, 2]`, etc.)

### **Example**
```php
$name = "John";

if ($name) {  // true (non-empty string is truthy)
    echo "Name is set!";
}
```

---

## **6. Ternary Operator (`?:`)**
A shorthand for `if-else`:
```php
$age = 20;
$status = ($age >= 18) ? "Adult" : "Minor";
echo $status; // "Adult"
```

---

## **7. Null Coalescing Operator (`??`)**
Checks if a variable exists and is not `NULL`:
```php
$username = $_GET['user'] ?? 'Guest'; // Fallback to 'Guest' if not set
```

---

## **8. Spaceship Operator (`<=>`)**
Compares two values:
- Returns `-1` if left is **less** than right.
- Returns `0` if equal.
- Returns `1` if left is **greater** than right.

```php
echo 5 <=> 3;  // 1 (5 > 3)
echo 2 <=> 2;  // 0 (equal)
echo 1 <=> 4;  // -1 (1 < 4)
```

---

## **9. Practical Use Cases**
### **Form Validation**
```php
$email = "test@example.com";
$password = "1234";

if (!empty($email) && !empty($password)) {
    // Proceed with login
}
```

### **Access Control**
```php
$isAdmin = true;
$isLoggedIn = true;

if ($isLoggedIn && $isAdmin) {
    echo "Welcome, Admin!";
}
```

### **Default Values**
```php
$config = $userConfig ?? $defaultConfig; // Fallback to default
```

---

## **10. Common Mistakes**
### **Mistake 1: Using `&` or `|` (Bitwise) Instead of Logical Operators**
```php
if ($a & $b) {  // Bitwise AND, not logical AND
    // Might not behave as expected!
}
```

### **Mistake 2: Assignment (`=`) Instead of Comparison (`==`)**
```php
if ($loggedIn = true) {  // Assigns true, always runs!
    // Should be ($loggedIn == true)
}
```

### **Mistake 3: Ignoring Operator Precedence**
```php
if ($a && $b || $c) {  // Ambiguous, use parentheses
    // Better: if (($a && $b) || $c)
}
```

---

## **Summary**
| **Concept** | **Usage** |
|------------|----------|
| `&&` (`AND`) | Both conditions must be `true` |
| `\|\|` (`OR`) | At least one condition must be `true` |
| `!` (`NOT`) | Inverts a boolean |
| `xor` | Only one condition is `true` (not both) |
| `?:` (Ternary) | Shorthand `if-else` |
| `??` (Null Coalescing) | Fallback if variable is `NULL` |
| `<=>` (Spaceship) | Three-way comparison |

Understanding logical expressions is crucial for writing clean, efficient PHP code. Always consider **short-circuiting**, **precedence**, and **truthy/falsy** behavior when working with conditions.