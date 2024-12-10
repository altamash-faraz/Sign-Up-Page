<?php
// Database connection details
$host = "localhost";
$dbname = "recaptcha";
$username = "root";
$password = "altamash";

// reCAPTCHA secret key
$recaptcha_secret = "6LeP15cqAAAAAGn5npL6D2J_VM8Fj7kOB1AqVQkK";

// Function to validate reCAPTCHA
function validateRecaptcha($recaptcha_response, $recaptcha_secret) {
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $recaptcha_secret,
        'response' => $recaptcha_response
    ];
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    return json_decode($result)->success;
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $company_name = $_POST["company_name"];
    $email = $_POST["email"];
    $password = $_POST["password"];
    $confirm_password = $_POST["confirm_password"];
    $recaptcha_response = $_POST["g-recaptcha-response"];

    // Validate reCAPTCHA
    if (!validateRecaptcha($recaptcha_response, $recaptcha_secret)) {
        die("reCAPTCHA verification failed. Please try again.");
    }

    // Validate password match
    if ($password !== $confirm_password) {
        die("Passwords do not match. Please try again.");
    }

    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    try {
        $conn = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $stmt = $conn->prepare("INSERT INTO businesses (company_name, email, password) VALUES (:company_name, :email, :password)");
        $stmt->bindParam(':company_name', $company_name);
        $stmt->bindParam(':email', $email);
        $stmt->bindParam(':password', $hashed_password);
        $stmt->execute();

        echo "Sign-up successful! Welcome, " . htmlspecialchars($company_name) . "!";
    } catch(PDOException $e) {
        echo "Error: " . $e->getMessage();
    }
    $conn = null;
}
?>