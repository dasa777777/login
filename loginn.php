<?php

session_start();

include("connection.php");
include("functions.php");

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    // something was posted
    $user_name = $_POST['user_name'];
    $password = $_POST['password'];

    if (!empty($user_name) && !empty($password) && !is_numeric($user_name)) {
        // sanitize and validate user inputs
        $user_name = mysqli_real_escape_string($con, $user_name);
        $password = mysqli_real_escape_string($con, $password);

        // hash the password using bcrypt
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

        // prepare a select statement to find a matching user
        $stmt = mysqli_prepare($con, "SELECT * FROM users WHERE user_name = ?");
        mysqli_stmt_bind_param($stmt, "s", $user_name);
        mysqli_stmt_execute($stmt);

        $result = mysqli_stmt_get_result($stmt);

        if (mysqli_num_rows($result) == 1) {
            // retrieve the hashed password from the database
            $row = mysqli_fetch_assoc($result);
            $stored_hash = $row['password'];

            // verify the password using bcrypt
            if (password_verify($password, $stored_hash)) {
                // set the session variable and redirect to the index page
                $_SESSION['user_id'] = $row['user_id'];
                header("Location: index.php");
                die;
            } else {
                echo "Incorrect password.";
            }
        } else {
            // prepare an insert statement to add a new user to the database
            $stmt = mysqli_prepare($con, "INSERT INTO users (user_name, password) VALUES (?, ?)");
            mysqli_stmt_bind_param($stmt, "ss", $user_name, $hashed_password);
            mysqli_stmt_execute($stmt);

            if (mysqli_affected_rows($con) == 1) {
                // set the session variable and redirect to the index page
                $user_id = mysqli_insert_id($con);
                $_SESSION['user_id'] = $user_id;
                header("Location: index.php");
                die;
            } else {
                echo "Error creating user account.";
            }
        }
    } else {
        echo "Invalid username or password.";
    }
}

?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h3>Login</h3>
    <div>
        <form method="post">
            <input type="text" name="user_name" placeholder="Username"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <input type="submit" value="Login"><br>
        </form>
    </div>
</body>
</html>
