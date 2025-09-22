<?php

    if (empty($_POST["name"])) {
        die("Name is Required");
    }

    if( ! filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
        die("Valid Email is Required!");
    }

    if (strlen($_POST["password"]) < 8) {
        die("Password must be at least 8 characters");  
    }

    if ( ! preg_match("/[a-z]/i", $_POST["password"])) {
        die("Password must contain at least one letter");
    }

    if ( ! preg_match("/[0-9]/", $_POST["password"])) {
        die("Password must contain at least one number");
    }

    if ($_POST["password"] !== $_POST["password_confirmation"]) {
        die("Passwords must match");
    }

    $password_hash = password_hash($_POST["password"], PASSWORD_DEFAULT);

    $activation_token = bin2hex(random_bytes(16));

    $activation_token_hash = hash("sha256", $activation_token);

    $mysqli = require __DIR__ . "/database.php";

    $sql = "INSERT INTO user (name, email, password_hash, account_activation_hash)
            VALUES (?, ?, ?, ?)";

    $stmt = $mysqli->stmt_init();

    if ( ! $stmt->prepare($sql)) {
        die("SQL Error: " . $mysqli->error);
    }

    $stmt->bind_param("ssss",
                      $_POST["name"],
                      $_POST["email"],
                      $password_hash,
                      $activation_token_hash);

    mysqli_report(MYSQLI_REPORT_OFF);
                    
   if( $stmt->execute()){

    $mail = require __DIR__ . "/mailer.php";

    $mail->setFrom("noreply@example.com");
    $mail->addAddress($_POST["email"]);
    $mail->Subject = "Account Activation";
    $mail->Body = <<<END

    Click <a href="http://localhost/PHP-Account-Activation-by-Email/activate-account.php?token=$activation_token">here<a>
    to activate your account.

    END;

    try {

        $mail->send();
    
    } catch (Exception $e) {

        echo "Message could not be sent. Mailer error: {$mail->ErrorInfo}";
        exit;
    
    }

    header("Location: signup-success.html");
    exit;  

   }  else {
    if ($mysqli->errno === 1062) {
        die("Email already taken");
    } else {
        die($mysqli->error . " " . $mysqli->errno);
    }
   }
?>