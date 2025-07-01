<?php
/**
 * Basic SQL Injection Vulnerable Code Examples
 * PHP examples demonstrating common SQL injection vulnerabilities
 * 
 * WARNING: This code is intentionally vulnerable and should ONLY be used for:
 * - Educational purposes
 * - Security research
 * - Testing security tools
 * - Academic studies
 * 
 * NEVER use this code in production environments!
 */

// ============================================================================
// BASIC STRING CONCATENATION VULNERABILITIES
// ============================================================================

function vulnerable_login_1($username, $password) {
    // VULNERABLE: Direct string concatenation
    $query = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    return $user !== null;
}

function vulnerable_login_2($username, $password) {
    // VULNERABLE: String interpolation
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    return $user !== null;
}

function vulnerable_login_3($username, $password) {
    // VULNERABLE: sprintf
    $query = sprintf("SELECT * FROM users WHERE username = '%s' AND password = '%s'", $username, $password);
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    return $user !== null;
}

// ============================================================================
// SEARCH FUNCTIONALITY VULNERABILITIES
// ============================================================================

function vulnerable_search_1($search_term) {
    // VULNERABLE: String concatenation in LIKE
    $query = "SELECT * FROM products WHERE name LIKE '%" . $search_term . "%'";
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $products = mysqli_fetch_all($result, MYSQLI_ASSOC);
    mysqli_close($conn);
    
    return $products;
}

function vulnerable_search_2($search_term) {
    // VULNERABLE: String interpolation in LIKE
    $query = "SELECT * FROM products WHERE name LIKE '%$search_term%'";
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $products = mysqli_fetch_all($result, MYSQLI_ASSOC);
    mysqli_close($conn);
    
    return $products;
}

// ============================================================================
// DATA MANIPULATION VULNERABILITIES
// ============================================================================

function vulnerable_insert($name, $email) {
    // VULNERABLE: String concatenation in INSERT
    $query = "INSERT INTO users (name, email) VALUES ('" . $name . "', '" . $email . "')";
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    mysqli_close($conn);
    
    return $result;
}

function vulnerable_update($user_id, $new_name) {
    // VULNERABLE: String concatenation in UPDATE
    $query = "UPDATE users SET name = '" . $new_name . "' WHERE id = " . $user_id;
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    mysqli_close($conn);
    
    return $result;
}

function vulnerable_delete($user_id) {
    // VULNERABLE: String concatenation in DELETE
    $query = "DELETE FROM users WHERE id = " . $user_id;
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    mysqli_close($conn);
    
    return $result;
}

// ============================================================================
// PDO VULNERABILITIES
// ============================================================================

function pdo_vulnerable_query($user_id) {
    // VULNERABLE: PDO with string concatenation
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    
    $pdo = new PDO("mysql:host=localhost;dbname=testdb", "root", "password");
    $stmt = $pdo->query($query);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    return $user;
}

function pdo_vulnerable_prepare($user_id) {
    // VULNERABLE: PDO prepare with string concatenation
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    
    $pdo = new PDO("mysql:host=localhost;dbname=testdb", "root", "password");
    $stmt = $pdo->prepare($query);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    return $user;
}

// ============================================================================
// MYSQLI VULNERABILITIES
// ============================================================================

function mysqli_vulnerable_query($user_id) {
    // VULNERABLE: mysqli with string concatenation
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    return $user;
}

function mysqli_vulnerable_prepare($user_id) {
    // VULNERABLE: mysqli prepare with string concatenation
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    return $user;
}

// ============================================================================
// INPUT VALIDATION BYPASSES
// ============================================================================

function bypass_simple_validation($user_input) {
    // VULNERABLE: Inadequate validation
    if (strpos($user_input, "'") !== false || strpos($user_input, ";") !== false) {
        return "Invalid input";
    }
    
    // Still vulnerable to other injection techniques
    $query = "SELECT * FROM users WHERE id = " . $user_input;
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    return $user;
}

function bypass_regex_validation($user_input) {
    // VULNERABLE: Regex can be bypassed
    if (!preg_match('/^[0-9]+$/', $user_input)) {
        return "Invalid input";
    }
    
    // Still vulnerable to numeric injection
    $query = "SELECT * FROM users WHERE id = " . $user_input . " OR 1=1";
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    return $user;
}

// ============================================================================
// WEB APPLICATION EXAMPLES
// ============================================================================

// VULNERABLE: GET parameter injection
if (isset($_GET['id'])) {
    $user_id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    echo json_encode($user);
}

// VULNERABLE: POST parameter injection
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    if ($user) {
        echo "Login successful";
    } else {
        echo "Login failed";
    }
}

// VULNERABLE: Cookie injection
if (isset($_COOKIE['user_id'])) {
    $user_id = $_COOKIE['user_id'];
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    echo json_encode($user);
}

// VULNERABLE: Session injection
session_start();
if (isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    $query = "SELECT * FROM users WHERE id = " . $user_id;
    
    $conn = mysqli_connect("localhost", "root", "password", "testdb");
    $result = mysqli_query($conn, $query);
    $user = mysqli_fetch_assoc($result);
    mysqli_close($conn);
    
    echo json_encode($user);
}

?> 