<?php
require_once('db_config.php');

// Input data
$username = trim($_POST['username']);
$email = trim($_POST['email']);
$password = $_POST['password'];
$confirm_password = $_POST['confirm_password'];

// Validate inputs
if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
    die('Please fill in all fields.');
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die('Invalid email format.');
}

if ($password !== $confirm_password) {
    die('Passwords do not match.');
}

if (strlen($password) < 8) {
    die('Password must be at least 8 characters long.');
}

// Hash the password
$hashed_password = password_hash($password, PASSWORD_DEFAULT);

// Check if username or email already exists
$stmt = $conn->prepare("SELECT id FROM registration WHERE LOWER(username) = LOWER(?) OR email = ?");
$stmt->bind_param("ss", $username, $email);
$stmt->execute();
$stmt->store_result();
if ($stmt->num_rows > 0) {
    $stmt->close();
    $conn->close();
    echo '<script>alert("Username or email already exists. Please choose a different username.");';
    echo 'window.location.href = "register.html";</script>';
    exit;
} else {
    $stmt->close();

    // Prepare SQL statement to insert new user
    $stmt = $conn->prepare("INSERT INTO registration (username, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $email, $hashed_password);

    // Execute SQL statement
    if ($stmt->execute()) {
        // Registration successful, redirect to login page
        echo '<script>alert("Registration successful. You will now be redirected to the login page.");';
        echo 'window.location.href = "login.html";</script>';
        // Alternatively, use PHP header redirection
        // header("Location: login.html");
        // exit();
    } else {
        echo "Error: " . $stmt->error;
    }
}

// Close statement and connection
$stmt->close();
$conn->close();
?>
