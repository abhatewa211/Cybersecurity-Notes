# File Upload in PHP - Detailed Notes

## **Overview**
File uploads allow users to submit files through HTML forms to a PHP server. PHP provides the `$_FILES` superglobal array to handle uploaded files.

## **HTML Form Setup**

### **Basic Upload Form**
```html
<!-- form.html -->
<form action="upload.php" method="POST" enctype="multipart/form-data">
    <input type="file" name="userfile">
    <input type="submit" value="Upload">
</form>
```

### **Essential Form Attributes**
```html
<!-- MUST include these attributes -->
<form method="POST" enctype="multipart/form-data">
    <!-- enctype="multipart/form-data" is REQUIRED for file uploads -->
</form>

<!-- Multiple file uploads -->
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="files[]" multiple>
    <!-- OR multiple single inputs -->
    <input type="file" name="file1">
    <input type="file" name="file2">
</form>
```

## **PHP Configuration (php.ini)**

### **Key Upload Directives**
```ini
; File upload settings
file_uploads = On                      ; Enable file uploads
upload_max_filesize = 2M               ; Max upload file size
post_max_size = 8M                     ; Max POST data size (must be > upload_max_filesize)
max_file_uploads = 20                  ; Max number of files per request
max_input_time = 60                    ; Max time to receive input
memory_limit = 128M                    ; Script memory limit

; Temporary storage
upload_tmp_dir = "/tmp"                ; Temporary directory for uploads
; If not set, uses system default (usually /tmp or C:\Windows\Temp)

; Error handling
max_execution_time = 30                ; Script timeout
```

### **Checking PHP Configuration**
```php
// Check upload settings at runtime
echo 'file_uploads: ' . ini_get('file_uploads') . "\n";
echo 'upload_max_filesize: ' . ini_get('upload_max_filesize') . "\n";
echo 'post_max_size: ' . ini_get('post_max_size') . "\n";
echo 'upload_tmp_dir: ' . ini_get('upload_tmp_dir') . "\n";
echo 'max_file_uploads: ' . ini_get('max_file_uploads') . "\n";

// Convert shorthand to bytes
function convert_to_bytes($value) {
    $value = trim($value);
    $last = strtolower($value[strlen($value)-1]);
    $value = intval($value);
    
    switch($last) {
        case 'g': $value *= 1024;
        case 'm': $value *= 1024;
        case 'k': $value *= 1024;
    }
    return $value;
}
```

## **$_FILES Superglobal Structure**

### **Single File Upload Structure**
```php
// After uploading single file named "userfile"
print_r($_FILES);
/*
Array
(
    [userfile] => Array
    (
        [name] => "example.jpg"          // Original filename
        [type] => "image/jpeg"           // MIME type
        [tmp_name] => "/tmp/php3h4j5h"   // Temporary location
        [error] => 0                     // Upload error code
        [size] => 123456                 // File size in bytes
    )
)
*/
```

### **Multiple Files Upload Structure**
```html
<input type="file" name="files[]" multiple>
```
```php
// Multiple files structure
print_r($_FILES);
/*
Array
(
    [files] => Array
    (
        [name] => Array
        (
            [0] => "file1.jpg"
            [1] => "file2.png"
            [2] => "file3.pdf"
        )
        [type] => Array
        (
            [0] => "image/jpeg"
            [1] => "image/png"
            [2] => "application/pdf"
        )
        [tmp_name] => Array
        (
            [0] => "/tmp/phpX1Y2Z3"
            [1] => "/tmp/phpA2B3C4"
            [2] => "/tmp/phpD5E6F7"
        )
        [error] => Array
        (
            [0] => 0
            [1] => 0
            [2] => 0
        )
        [size] => Array
        (
            [0] => 12345
            [1] => 23456
            [2] => 34567
        )
    )
)
*/
```

## **Upload Error Codes**

### **Error Code Constants**
```php
// UPLOAD_ERR_* constants
define('UPLOAD_ERR_OK', 0);         // No error, file uploaded successfully
define('UPLOAD_ERR_INI_SIZE', 1);   // File exceeds upload_max_filesize
define('UPLOAD_ERR_FORM_SIZE', 2);  // File exceeds MAX_FILE_SIZE in form
define('UPLOAD_ERR_PARTIAL', 3);    // File only partially uploaded
define('UPLOAD_ERR_NO_FILE', 4);    // No file was uploaded
define('UPLOAD_ERR_NO_TMP_DIR', 6); // Missing temporary folder
define('UPLOAD_ERR_CANT_WRITE', 7); // Failed to write file to disk
define('UPLOAD_ERR_EXTENSION', 8);  // PHP extension stopped the upload

// Error messages array
$upload_errors = array(
    UPLOAD_ERR_OK => "No errors.",
    UPLOAD_ERR_INI_SIZE => "File exceeds upload_max_filesize.",
    UPLOAD_ERR_FORM_SIZE => "File exceeds MAX_FILE_SIZE in form.",
    UPLOAD_ERR_PARTIAL => "File upload was incomplete.",
    UPLOAD_ERR_NO_FILE => "No file was uploaded.",
    UPLOAD_ERR_NO_TMP_DIR => "Missing temporary folder.",
    UPLOAD_ERR_CANT_WRITE => "Failed to write file to disk.",
    UPLOAD_ERR_EXTENSION => "File upload stopped by extension."
);
```

### **Checking Upload Status**
```php
if ($_FILES['userfile']['error'] === UPLOAD_ERR_OK) {
    echo "Upload successful!";
} else {
    echo "Error: " . $upload_errors[$_FILES['userfile']['error']];
}

// Check if file was uploaded (not just form submitted)
function is_file_uploaded($file_key) {
    return isset($_FILES[$file_key]) && 
           $_FILES[$file_key]['error'] !== UPLOAD_ERR_NO_FILE &&
           $_FILES[$file_key]['size'] > 0;
}
```

## **File Validation & Security**

### **Basic Security Checks**
```php
// Comprehensive validation function
function validate_uploaded_file($file) {
    $errors = [];
    
    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = "Upload error: " . $file['error'];
        return $errors;
    }
    
    // Check if file was actually uploaded (not spoofed)
    if (!is_uploaded_file($file['tmp_name'])) {
        $errors[] = "Possible file upload attack!";
        return $errors;
    }
    
    // Check file size (e.g., 5MB max)
    $max_size = 5 * 1024 * 1024; // 5MB in bytes
    if ($file['size'] > $max_size) {
        $errors[] = "File too large. Maximum size: 5MB";
    }
    
    // Check file size minimum (optional)
    if ($file['size'] < 10) { // 10 bytes minimum
        $errors[] = "File too small or empty";
    }
    
    // Get file extension and MIME type
    $filename = $file['name'];
    $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $file_mime = mime_content_type($file['tmp_name']);
    $file_info = finfo_open(FILEINFO_MIME_TYPE);
    $actual_mime = finfo_file($file_info, $file['tmp_name']);
    finfo_close($file_info);
    
    // Define allowed file types
    $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
    $allowed_mime_types = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf'
    ];
    
    // Validate extension
    if (!in_array($file_ext, $allowed_extensions)) {
        $errors[] = "Invalid file extension. Allowed: " . implode(', ', $allowed_extensions);
    }
    
    // Validate MIME type (server-side verification)
    if (!in_array($actual_mime, $allowed_mime_types)) {
        $errors[] = "Invalid file type detected.";
    }
    
    // Double-check MIME type vs extension
    $extension_mime_map = [
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
        'pdf' => 'application/pdf'
    ];
    
    if (isset($extension_mime_map[$file_ext]) && 
        $extension_mime_map[$file_ext] !== $actual_mime) {
        $errors[] = "File extension doesn't match actual file type!";
    }
    
    // Check for PHP files disguised as images
    if ($file_ext === 'php' || $file_ext === 'php3' || $file_ext === 'php4' || 
        $file_ext === 'php5' || $file_ext === 'php7' || $file_ext === 'phtml') {
        $errors[] = "Executable files not allowed!";
    }
    
    // Check image dimensions (for images only)
    if (strpos($actual_mime, 'image/') === 0) {
        $image_info = getimagesize($file['tmp_name']);
        if (!$image_info) {
            $errors[] = "Invalid image file";
        } else {
            list($width, $height) = $image_info;
            
            // Maximum dimensions
            if ($width > 5000 || $height > 5000) {
                $errors[] = "Image dimensions too large";
            }
            
            // Minimum dimensions
            if ($width < 10 || $height < 10) {
                $errors[] = "Image dimensions too small";
            }
            
            // Check aspect ratio (optional)
            $aspect_ratio = $width / $height;
            if ($aspect_ratio > 4 || $aspect_ratio < 0.25) {
                $errors[] = "Image aspect ratio not supported";
            }
        }
    }
    
    return $errors;
}
```

### **File Name Sanitization**
```php
function sanitize_filename($filename) {
    // Remove path information
    $filename = basename($filename);
    
    // Replace spaces with underscores
    $filename = str_replace(' ', '_', $filename);
    
    // Remove special characters (keep letters, numbers, dots, underscores, hyphens)
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);
    
    // Remove multiple dots (except the last one for extension)
    $filename = preg_replace('/\.(?=.*\.)/', '', $filename);
    
    // Convert to lowercase (optional)
    $filename = strtolower($filename);
    
    // Limit length
    if (strlen($filename) > 255) {
        $filename = substr($filename, 0, 255);
    }
    
    // Ensure filename is not empty
    if (empty($filename)) {
        $filename = 'upload_' . uniqid();
    }
    
    return $filename;
}

// Generate unique filename
function generate_unique_filename($original_name, $upload_dir) {
    $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
    $basename = sanitize_filename(pathinfo($original_name, PATHINFO_FILENAME));
    
    // Create unique filename
    $unique_name = $basename . '_' . uniqid() . '_' . time();
    
    // Add extension if it exists
    if ($extension) {
        $unique_name .= '.' . $extension;
    }
    
    // Ensure it's unique in the directory
    $counter = 1;
    $final_name = $unique_name;
    while (file_exists($upload_dir . '/' . $final_name)) {
        $final_name = $basename . '_' . uniqid() . '_' . time() . '_' . $counter++;
        if ($extension) {
            $final_name .= '.' . $extension;
        }
    }
    
    return $final_name;
}
```

## **Moving Uploaded Files**

### **Basic File Move**
```php
// upload.php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $upload_dir = 'uploads/';
    
    // Create upload directory if it doesn't exist
    if (!file_exists($upload_dir)) {
        mkdir($upload_dir, 0755, true);
    }
    
    // Validate and sanitize
    $errors = validate_uploaded_file($_FILES['userfile']);
    
    if (empty($errors)) {
        // Generate safe filename
        $original_name = $_FILES['userfile']['name'];
        $safe_filename = generate_unique_filename($original_name, $upload_dir);
        $destination = $upload_dir . $safe_filename;
        
        // Move uploaded file
        if (move_uploaded_file($_FILES['userfile']['tmp_name'], $destination)) {
            echo "File uploaded successfully!";
            
            // Set proper permissions
            chmod($destination, 0644); // Readable by all, writable by owner
            
            // Store file info in database (example)
            store_file_info($safe_filename, $original_name, $_FILES['userfile']['size']);
        } else {
            echo "Failed to move uploaded file.";
        }
    } else {
        foreach ($errors as $error) {
            echo "<p>Error: $error</p>";
        }
    }
}
```

### **Multiple File Upload Handling**
```php
// Handle multiple files
function handle_multiple_uploads($files_array) {
    $results = [];
    $upload_dir = 'uploads/';
    
    // Ensure upload directory exists
    if (!file_exists($upload_dir)) {
        mkdir($upload_dir, 0755, true);
    }
    
    // Loop through each file
    for ($i = 0; $i < count($files_array['name']); $i++) {
        // Skip empty files
        if ($files_array['error'][$i] === UPLOAD_ERR_NO_FILE) {
            continue;
        }
        
        // Create file structure for validation
        $file = [
            'name' => $files_array['name'][$i],
            'type' => $files_array['type'][$i],
            'tmp_name' => $files_array['tmp_name'][$i],
            'error' => $files_array['error'][$i],
            'size' => $files_array['size'][$i]
        ];
        
        // Validate
        $errors = validate_uploaded_file($file);
        
        if (empty($errors)) {
            // Generate safe filename
            $safe_filename = generate_unique_filename($file['name'], $upload_dir);
            $destination = $upload_dir . $safe_filename;
            
            // Move file
            if (move_uploaded_file($file['tmp_name'], $destination)) {
                $results[] = [
                    'original_name' => $file['name'],
                    'saved_name' => $safe_filename,
                    'size' => $file['size'],
                    'status' => 'success'
                ];
            } else {
                $results[] = [
                    'original_name' => $file['name'],
                    'error' => 'Failed to move file',
                    'status' => 'error'
                ];
            }
        } else {
            $results[] = [
                'original_name' => $file['name'],
                'errors' => $errors,
                'status' => 'error'
            ];
        }
    }
    
    return $results;
}

// Usage
if (isset($_FILES['files'])) {
    $results = handle_multiple_uploads($_FILES['files']);
    foreach ($results as $result) {
        if ($result['status'] === 'success') {
            echo "Uploaded: {$result['original_name']} as {$result['saved_name']}<br>";
        } else {
            echo "Failed: {$result['original_name']} - " . 
                 implode(', ', $result['errors'] ?? []) . "<br>";
        }
    }
}
```

## **Advanced Upload Features**

### **Progress Tracking (PHP 5.4+)**
```php
// Enable session upload progress
ini_set('session.upload_progress.enabled', 1);
ini_set('session.upload_progress.cleanup', 1);
ini_set('session.upload_progress.prefix', 'upload_progress_');

// HTML with hidden field
<form action="upload.php" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="<?php echo ini_get('session.upload_progress.name'); ?>" value="myupload">
    <input type="file" name="file1">
    <input type="submit" value="Upload">
</form>

// Check progress via AJAX
session_start();
if (isset($_SESSION['upload_progress_myupload'])) {
    $progress = $_SESSION['upload_progress_myupload'];
    $percentage = round(($progress['bytes_processed'] / $progress['content_length']) * 100);
    echo json_encode(['percentage' => $percentage]);
}
```

### **Chunked Uploads (Large Files)**
```php
// Using JavaScript libraries like Dropzone.js, Resumable.js
// Or implement custom chunking:

function handle_chunked_upload() {
    $chunk_number = $_POST['chunk'];
    $total_chunks = $_POST['chunks'];
    $identifier = $_POST['identifier'];
    $original_name = $_POST['filename'];
    
    $temp_dir = 'uploads/tmp/' . $identifier;
    $chunk_file = $temp_dir . '/' . $chunk_number;
    
    // Create temp directory
    if (!file_exists($temp_dir)) {
        mkdir($temp_dir, 0755, true);
    }
    
    // Save chunk
    move_uploaded_file($_FILES['file']['tmp_name'], $chunk_file);
    
    // Check if all chunks uploaded
    $uploaded_chunks = glob($temp_dir . '/*');
    if (count($uploaded_chunks) == $total_chunks) {
        // Reassemble file
        $final_file = 'uploads/' . generate_unique_filename($original_name, 'uploads');
        $fp = fopen($final_file, 'wb');
        
        for ($i = 0; $i < $total_chunks; $i++) {
            $chunk = $temp_dir . '/' . $i;
            $chunk_content = file_get_contents($chunk);
            fwrite($fp, $chunk_content);
            unlink($chunk);
        }
        
        fclose($fp);
        rmdir($temp_dir);
        
        return ['status' => 'complete', 'file' => $final_file];
    }
    
    return ['status' => 'chunk_uploaded', 'chunk' => $chunk_number];
}
```

### **Image Processing & Manipulation**
```php
function process_uploaded_image($source_path, $destination_path) {
    // Check if it's an image
    $image_info = getimagesize($source_path);
    if (!$image_info) {
        return false;
    }
    
    $mime_type = $image_info['mime'];
    
    // Create image resource based on type
    switch ($mime_type) {
        case 'image/jpeg':
            $image = imagecreatefromjpeg($source_path);
            break;
        case 'image/png':
            $image = imagecreatefrompng($source_path);
            break;
        case 'image/gif':
            $image = imagecreatefromgif($source_path);
            break;
        default:
            return false;
    }
    
    if (!$image) {
        return false;
    }
    
    // Get original dimensions
    $original_width = imagesx($image);
    $original_height = imagesy($image);
    
    // Calculate new dimensions (max 800px width)
    $max_width = 800;
    if ($original_width > $max_width) {
        $new_width = $max_width;
        $new_height = intval($original_height * ($max_width / $original_width));
    } else {
        $new_width = $original_width;
        $new_height = $original_height;
    }
    
    // Create new image
    $new_image = imagecreatetruecolor($new_width, $new_height);
    
    // Preserve transparency for PNG/GIF
    if ($mime_type === 'image/png' || $mime_type === 'image/gif') {
        imagealphablending($new_image, false);
        imagesavealpha($new_image, true);
        $transparent = imagecolorallocatealpha($new_image, 255, 255, 255, 127);
        imagefilledrectangle($new_image, 0, 0, $new_width, $new_height, $transparent);
    }
    
    // Resize image
    imagecopyresampled($new_image, $image, 0, 0, 0, 0, 
                      $new_width, $new_height, $original_width, $original_height);
    
    // Save processed image
    switch ($mime_type) {
        case 'image/jpeg':
            imagejpeg($new_image, $destination_path, 85); // 85% quality
            break;
        case 'image/png':
            imagepng($new_image, $destination_path, 8); // Compression level
            break;
        case 'image/gif':
            imagegif($new_image, $destination_path);
            break;
    }
    
    // Clean up
    imagedestroy($image);
    imagedestroy($new_image);
    
    return true;
}
```

## **Database Integration**

### **Storing File Information**
```php
class FileUploader {
    private $db;
    private $upload_dir = 'uploads/';
    
    public function __construct(PDO $db) {
        $this->db = $db;
    }
    
    public function saveFileInfo($file_data) {
        $sql = "INSERT INTO uploaded_files 
                (original_name, stored_name, file_size, mime_type, upload_date, user_id) 
                VALUES (:original_name, :stored_name, :file_size, :mime_type, NOW(), :user_id)";
        
        $stmt = $this->db->prepare($sql);
        return $stmt->execute([
            ':original_name' => $file_data['original_name'],
            ':stored_name' => $file_data['stored_name'],
            ':file_size' => $file_data['size'],
            ':mime_type' => $file_data['mime_type'],
            ':user_id' => $_SESSION['user_id'] ?? null
        ]);
    }
    
    public function getUserFiles($user_id) {
        $sql = "SELECT * FROM uploaded_files WHERE user_id = :user_id ORDER BY upload_date DESC";
        $stmt = $this->db->prepare($sql);
        $stmt->execute([':user_id' => $user_id]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    public function deleteFile($file_id, $user_id) {
        // Get file info first
        $sql = "SELECT stored_name FROM uploaded_files WHERE id = :id AND user_id = :user_id";
        $stmt = $this->db->prepare($sql);
        $stmt->execute([':id' => $file_id, ':user_id' => $user_id]);
        $file = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($file) {
            // Delete from filesystem
            $file_path = $this->upload_dir . $file['stored_name'];
            if (file_exists($file_path)) {
                unlink($file_path);
            }
            
            // Delete from database
            $sql = "DELETE FROM uploaded_files WHERE id = :id";
            $stmt = $this->db->prepare($sql);
            return $stmt->execute([':id' => $file_id]);
        }
        
        return false;
    }
}
```

### **Database Schema**
```sql
CREATE TABLE uploaded_files (
    id INT PRIMARY KEY AUTO_INCREMENT,
    original_name VARCHAR(255) NOT NULL,
    stored_name VARCHAR(255) NOT NULL UNIQUE,
    file_size INT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    upload_date DATETIME NOT NULL,
    user_id INT,
    description TEXT,
    downloads INT DEFAULT 0,
    is_public BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for faster queries
CREATE INDEX idx_user_id ON uploaded_files(user_id);
CREATE INDEX idx_upload_date ON uploaded_files(upload_date);
```

## **Security Best Practices**

### **Complete Security Checklist**
```php
class SecureFileUpload {
    private $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx'];
    private $allowed_mime_types = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    private $max_file_size = 10 * 1024 * 1024; // 10MB
    private $upload_dir;
    
    public function __construct($upload_dir) {
        $this->upload_dir = rtrim($upload_dir, '/') . '/';
        
        // Security: Ensure upload directory is outside web root
        $web_root = $_SERVER['DOCUMENT_ROOT'];
        if (strpos(realpath($this->upload_dir), realpath($web_root)) === 0) {
            throw new Exception('Upload directory should be outside web root!');
        }
        
        // Create directory with secure permissions
        if (!file_exists($this->upload_dir)) {
            mkdir($this->upload_dir, 0750, true);
        }
        
        // Add .htaccess to prevent execution
        $htaccess = $this->upload_dir . '.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, 
                "Order deny,allow\nDeny from all\n<FilesMatch \"\.(jpg|jpeg|png|gif|pdf)$\">\nOrder allow,deny\nAllow from all\n</FilesMatch>");
        }
    }
    
    public function upload($file_input_name) {
        // Check if file was uploaded
        if (!isset($_FILES[$file_input_name])) {
            throw new Exception('No file uploaded');
        }
        
        $file = $_FILES[$file_input_name];
        
        // Check upload errors
        if ($file['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('Upload error: ' . $file['error']);
        }
        
        // Verify upload was legitimate
        if (!is_uploaded_file($file['tmp_name'])) {
            throw new Exception('Possible file upload attack!');
        }
        
        // Validate file size
        if ($file['size'] > $this->max_file_size) {
            throw new Exception('File too large. Maximum: ' . 
                               ($this->max_file_size / 1024 / 1024) . 'MB');
        }
        
        // Get actual MIME type
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $actual_mime = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        // Get file extension
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        
        // Validate MIME type
        if (!in_array($actual_mime, $this->allowed_mime_types)) {
            throw new Exception('Invalid file type');
        }
        
        // Validate extension
        if (!in_array($extension, $this->allowed_extensions)) {
            throw new Exception('Invalid file extension');
        }
        
        // Verify extension matches MIME type
        $expected_mime = $this->get_mime_for_extension($extension);
        if ($expected_mime !== $actual_mime) {
            throw new Exception('File type mismatch detected!');
        }
        
        // Additional image validation
        if (strpos($actual_mime, 'image/') === 0) {
            $this->validate_image($file['tmp_name']);
        }
        
        // Generate secure filename
        $safe_filename = $this->generate_filename($file['name']);
        $destination = $this->upload_dir . $safe_filename;
        
        // Move file
        if (!move_uploaded_file($file['tmp_name'], $destination)) {
            throw new Exception('Failed to save uploaded file');
        }
        
        // Set secure permissions
        chmod($destination, 0644);
        
        return [
            'original_name' => $file['name'],
            'stored_name' => $safe_filename,
            'path' => $destination,
            'size' => $file['size'],
            'mime_type' => $actual_mime,
            'extension' => $extension
        ];
    }
    
    private function validate_image($file_path) {
        $image_info = getimagesize($file_path);
        
        if (!$image_info) {
            throw new Exception('Invalid image file');
        }
        
        // Check for embedded PHP/scripts in images
        $content = file_get_contents($file_path);
        if (preg_match('/<\?php|<\?=|eval\(|base64_decode/i', $content)) {
            throw new Exception('Suspicious content detected in image');
        }
        
        // Recreate image to strip metadata
        $this->strip_image_metadata($file_path, $image_info);
    }
    
    private function strip_image_metadata($file_path, $image_info) {
        // Create clean image without metadata
        $mime = $image_info['mime'];
        
        switch ($mime) {
            case 'image/jpeg':
                $image = imagecreatefromjpeg($file_path);
                imagejpeg($image, $file_path, 100);
                break;
            case 'image/png':
                $image = imagecreatefrompng($file_path);
                imagepng($image, $file_path, 9);
                break;
            case 'image/gif':
                $image = imagecreatefromgif($file_path);
                imagegif($image, $file_path);
                break;
        }
        
        if (isset($image)) {
            imagedestroy($image);
        }
    }
    
    private function get_mime_for_extension($extension) {
        $map = [
            'jpg' => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'png' => 'image/png',
            'gif' => 'image/gif',
            'pdf' => 'application/pdf',
            'doc' => 'application/msword',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ];
        
        return $map[$extension] ?? null;
    }
    
    private function generate_filename($original_name) {
        // Remove extension
        $name = pathinfo($original_name, PATHINFO_FILENAME);
        
        // Sanitize
        $name = preg_replace('/[^a-zA-Z0-9_-]/', '', $name);
        $name = substr($name, 0, 100);
        
        // Add randomness
        $random = bin2hex(random_bytes(8));
        $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
        
        return $name . '_' . $random . '.' . $extension;
    }
}
```

## **Error Handling & Debugging**

### **Comprehensive Error Handler**
```php
class UploadErrorHandler {
    public static function handle($file_error_code, $custom_message = '') {
        $messages = [
            UPLOAD_ERR_OK => 'The file uploaded successfully.',
            UPLOAD_ERR_INI_SIZE => 'The uploaded file exceeds the upload_max_filesize directive in php.ini.',
            UPLOAD_ERR_FORM_SIZE => 'The uploaded file exceeds the MAX_FILE_SIZE directive specified in the HTML form.',
            UPLOAD_ERR_PARTIAL => 'The uploaded file was only partially uploaded.',
            UPLOAD_ERR_NO_FILE => 'No file was uploaded.',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing a temporary folder.',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
            UPLOAD_ERR_EXTENSION => 'A PHP extension stopped the file upload.'
        ];
        
        $message = $messages[$file_error_code] ?? 'Unknown upload error.';
        
        if ($custom_message) {
            $message .= ' ' . $custom_message;
        }
        
        // Log error
        error_log("File upload error: $message (Code: $file_error_code)");
        
        // For development, show detailed error
        if (ini_get('display_errors')) {
            return $message;
        }
        
        // For production, generic error
        return 'File upload failed. Please try again.';
    }
    
    public static function log_upload_attempt($file_data, $success, $error = '') {
        $log_entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'filename' => $file_data['name'] ?? '',
            'file_size' => $file_data['size'] ?? 0,
            'file_type' => $file_data['type'] ?? '',
            'success' => $success,
            'error' => $error
        ];
        
        $log_file = 'uploads/upload_log.json';
        $logs = [];
        
        if (file_exists($log_file)) {
            $logs = json_decode(file_get_contents($log_file), true);
        }
        
        $logs[] = $log_entry;
        
        // Keep only last 1000 entries
        if (count($logs) > 1000) {
            $logs = array_slice($logs, -1000);
        }
        
        file_put_contents($log_file, json_encode($logs, JSON_PRETTY_PRINT));
    }
}
```

## **Complete Example: Production-Ready Upload Script**

```php
<?php
// config.php
define('UPLOAD_DIR', '/var/www/uploads/'); // Outside web root
define('MAX_FILE_SIZE', 10 * 1024 * 1024); // 10MB
define('ALLOWED_TYPES', [
    'image/jpeg' => 'jpg',
    'image/png' => 'png',
    'image/gif' => 'gif',
    'application/pdf' => 'pdf'
]);

// upload_handler.php
require_once 'config.php';
require_once 'SecureFileUpload.php';

session_start();

header('Content-Type: application/json');

try {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        throw new Exception('Invalid CSRF token');
    }
    
    // Check if file was uploaded
    if (!isset($_FILES['file'])) {
        throw new Exception('No file uploaded');
    }
    
    // Initialize uploader
    $uploader = new SecureFileUpload(UPLOAD_DIR);
    
    // Process upload
    $result = $uploader->upload('file');
    
    // Save to database
    $db = new PDO('mysql:host=localhost;dbname=app', 'user', 'pass');
    $stmt = $db->prepare("INSERT INTO files (user_id, filename, original_name, size, type) VALUES (?, ?, ?, ?, ?)");
    $stmt->execute([
        $_SESSION['user_id'],
        $result['stored_name'],
        $result['original_name'],
        $result['size'],
        $result['mime_type']
    ]);
    
    // Log success
    UploadErrorHandler::log_upload_attempt($_FILES['file'], true);
    
    // Return success response
    echo json_encode([
        'success' => true,
        'message' => 'File uploaded successfully',
        'file' => [
            'id' => $db->lastInsertId(),
            'name' => $result['original_name'],
            'url' => '/download.php?id=' . $db->lastInsertId()
        ]
    ]);
    
} catch (Exception $e) {
    // Log error
    if (isset($_FILES['file'])) {
        UploadErrorHandler::log_upload_attempt($_FILES['file'], false, $e->getMessage());
    }
    
    // Return error response
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
```

## **Quick Reference Cheatsheet**

```php
// HTML FORM
<form method="POST" enctype="multipart/form-data">

// CHECK UPLOAD
if ($_FILES['file']['error'] === UPLOAD_ERR_OK)

// SECURITY CHECK
is_uploaded_file($_FILES['file']['tmp_name'])

// MOVE FILE
move_uploaded_file($tmp_name, $destination)

// GET MIME TYPE
finfo_file(finfo_open(FILEINFO_MIME_TYPE), $file)

// VALIDATE IMAGE
getimagesize($file)

// SANITIZE FILENAME
basename($filename)

// PHP.INI SETTINGS
upload_max_filesize, post_max_size, max_file_uploads

// ERROR CODES
UPLOAD_ERR_OK, UPLOAD_ERR_NO_FILE, UPLOAD_ERR_INI_SIZE
```

## **Common Pitfalls & Solutions**

1. **"Undefined index: file"** - Check form field name matches $_FILES key
2. **Empty $_FILES array** - Ensure `enctype="multipart/form-data"` is set
3. **File uploads but size is 0** - Check `post_max_size` > `upload_max_filesize`
4. **Permission denied** - Check upload directory permissions (0755)
5. **File disappears after script ends** - Must move from temp directory
6. **Partial uploads on slow connections** - Increase `max_input_time`

Remember: Always validate, sanitise, and never trust user-uploaded files. Store uploads outside web root when possible, and implement proper access controls.