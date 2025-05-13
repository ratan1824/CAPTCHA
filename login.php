<?php
require_once('db_config.php');

session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Validate inputs
    if (empty($username) || empty($password)) {
        die('Please enter username and password.');
    }

    // Prepare SQL statement to fetch user data
    $stmt = $conn->prepare("SELECT id, username, password FROM registration WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows == 1) {
        $stmt->bind_result($id, $username, $hashed_password);
        $stmt->fetch();
        
        // Verify hashed password
        if (password_verify($password, $hashed_password)) {
            // Password is correct, start session
            $_SESSION['id'] = $id;
            $_SESSION['username'] = $username;

            // Redirect to dashboard or home page after login
            header("Location: dashboard.php");
            exit();
        } else {
            // Incorrect password
            echo "Incorrect username or password.";
        }
    } else {
        // User not found
        echo "Incorrect username or password.";
    }

    // Close statement
    $stmt->close();
}

// Close connection
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="register.html">Register here</a>.</p>
</body>
</html>
