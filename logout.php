<?php
/**
 * logout.php
 *
 * Ends the current user session and shows a logout confirmation.
 *
 * ResearchChatAI
 * Author: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

// =============================================================================
// SECURITY HEADERS
// =============================================================================

// Prevent clickjacking attacks
header("X-Frame-Options: DENY");

// Prevent MIME-type sniffing
header("X-Content-Type-Options: nosniff");

// Enable XSS protection in older browsers
header("X-XSS-Protection: 1; mode=block");

// Control referrer information leakage
header("Referrer-Policy: strict-origin-when-cross-origin");

// Restrict browser features and APIs
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// Content Security Policy - prevent XSS and injection attacks
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// Prevent caching of logout page
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: 0");

// Force HTTPS in production (uncomment when using HTTPS)
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

// =============================================================================
// SESSION TEARDOWN
// =============================================================================

// Start session to access session data
session_start();

// Clear all session variables
$_SESSION = [];

// Delete the session cookie to prevent session reuse
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => 'Strict'  // Additional CSRF protection
        ]
    );
}

// Destroy the session data on the server
session_destroy();

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Logged Out - ResearchChatAI</title>

    <!-- Stylesheets -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
    <link rel="stylesheet" href="src/CSS/login.css">

    <!-- FontAwesome -->
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/solid.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/light.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/regular.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/brands.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/fontawesome.min.css">
</head>

<body>
    <section class="section">
        <div class="container">
            <h1 class="title has-text-centered" style="margin-top:100px;">ResearchChatAI</h1>
            
            <!-- Logout Confirmation Card -->
            <div id="loginCard" class="card">
                <header class="card-header has-background-dark">
                    <p class="card-header-title has-text-white">
                        <span class="icon">
                            <i class="fas fa-check-circle"></i>
                        </span>
                        <span>Logout Successful</span>
                    </p>
                </header>
                
                <div class="card-content">
                    <div class="content has-text-centered">
                        <p class="mb-5">You have been successfully logged out of your account.</p>
                        <p class="mb-5">Your session has been securely terminated.</p>
                        <a href="login.php" class="button is-primary is-fullwidth">
                            <span class="icon">
                                <i class="fas fa-sign-in-alt"></i>
                            </span>
                            <span>Return to Login</span>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Clear client-side private key on logout -->
    <script>
        sessionStorage.removeItem('privateKey');
    </script>
</body>

</html>