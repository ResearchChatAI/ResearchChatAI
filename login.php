<?php
/**
 * login.php
 *
 * Handles user authentication with password migration (MD5 to Argon2id),
 * encryption key validation, and secure session management.
 *
 * ResearchChatAI
 * Author: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require 'Backend/MySQL/medoo-Credentials.php';

use Medoo\Medoo;

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
// Note: Adjusted to allow inline scripts for form validation
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://code.jquery.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// Force HTTPS in production (uncomment when using HTTPS)
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

// =============================================================================
// CONSTANTS
// =============================================================================

define('SESSION_KEY_LENGTH', 64);
define('MD5_HASH_LENGTH', 32);

// =============================================================================
// INITIALIZATION
// =============================================================================

$host = $_SERVER['HTTP_HOST'];
$errorCode = "";
$message = "";
$placeholderEmail = "";

// Initialize CSRF token for the form
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

// Check for success message from registration
if (isset($_GET['registered']) && $_GET['registered'] === '1') {
    $message = "ACCOUNTCREATED";
}

// =============================================================================
// AUTHENTICATION LOGIC
// =============================================================================

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Detect AJAX request (client-side key derivation flow)
    $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH'])
              && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';

    // CSRF token validation
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        if ($isAjax) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Invalid request']);
            exit;
        }
        $errorCode = "INVALID";
        error_log("CSRF token validation failed");
    } else {
        // Sanitize and validate input
        $email = isset($_POST['email']) ? trim(strtolower($_POST['email'])) : '';
        $password = isset($_POST['password']) ? $_POST['password'] : '';

        // Basic validation
        if (empty($email) || empty($password)) {
            if ($isAjax) {
                header('Content-Type: application/json');
                echo json_encode(['success' => false, 'error' => 'Invalid email or password']);
                exit;
            }
            $errorCode = "INVALID";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            if ($isAjax) {
                header('Content-Type: application/json');
                echo json_encode(['success' => false, 'error' => 'Invalid email or password']);
                exit;
            }
            $errorCode = "INVALID";
            $placeholderEmail = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');
        } else {
            $placeholderEmail = htmlspecialchars($email, ENT_QUOTES, 'UTF-8');

            // Attempt authentication
            $authResult = authenticateUser($database, $email, $password);

            if ($authResult['success']) {
                // Regenerate session ID to prevent session fixation
                session_regenerate_id(true);

                // Set session variables
                $_SESSION['pm_loggedin'] = true;
                $_SESSION['userID'] = $authResult['userID'];
                $_SESSION['userSession'] = generateSecureToken(SESSION_KEY_LENGTH);


                if ($isAjax) {
                    // Return encrypted key blob for client-side derivation
                    header('Content-Type: application/json');
                    echo json_encode([
                        'success' => true,
                        'privateKeyEnc' => $authResult['privateKeyEnc'],
                        'keySalt' => $authResult['keySalt']
                    ]);
                    exit;
                }

                // Fallback: standard redirect for non-JS clients
                $hostname = $_SERVER['HTTP_HOST'];
                $path = dirname($_SERVER['PHP_SELF']);

                $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
                           || $_SERVER['SERVER_PORT'] == 443
                           || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

                $protocol = $isHttps ? 'https://' : 'http://';
                $redirectUrl = $protocol . $hostname . ($path === '/' ? '' : $path) . '/index.php';

                if ($_SERVER['SERVER_PROTOCOL'] === 'HTTP/1.1') {
                    if (php_sapi_name() === 'cgi') {
                        header('Status: 303 See Other');
                    } else {
                        header('HTTP/1.1 303 See Other');
                    }
                }

                header('Location: ' . $redirectUrl);
                exit;
            } else {
                if ($isAjax) {
                    header('Content-Type: application/json');
                    echo json_encode(['success' => false, 'error' => 'Invalid email or password']);
                    exit;
                }
                // Generic error message to prevent user enumeration
                $errorCode = "INVALID";
            }
        }
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Authenticate user with email and password
 *
 * Supports legacy MD5 passwords (auto-upgrades to Argon2id) and validates
 * encryption keys for modern accounts.
 *
 * @param Medoo $database Database connection
 * @param string $email User email address
 * @param string $password User password
 * @return array Authentication result with 'success', 'userID', and 'privateKey'
 */
function authenticateUser($database, $email, $password)
{
    $result = [
        'success' => false,
        'userID' => null,
        'privateKeyEnc' => null,
        'keySalt' => null
    ];

    // Retrieve user from database
    $user = $database->get(
        "users",
        ["userID", "userPassword", "privateKeyEnc", "keySalt"],
        ["userEmail" => $email]
    );

    if (!$user) {
        // User not found - return generic failure
        return $result;
    }

    $storedPasswordHash = $user['userPassword'];
    $isValidPassword = false;
    $shouldUpgradePassword = false;

    // Verify password with current Argon2id hash
    if (password_verify($password, $storedPasswordHash)) {
        $isValidPassword = true;
    }
    // Check for legacy MD5 hash and upgrade if matched
    elseif (strlen($storedPasswordHash) === MD5_HASH_LENGTH &&
            ctype_xdigit($storedPasswordHash) &&
            hash_equals(md5($password), $storedPasswordHash)) {
        $isValidPassword = true;
        $shouldUpgradePassword = true;
    }

    if (!$isValidPassword) {
        return $result;
    }

    // Upgrade legacy password hash if needed
    if ($shouldUpgradePassword) {
        $newHash = password_hash($password, PASSWORD_ARGON2ID);
        $database->update(
            "users",
            ["userPassword" => $newHash],
            ["userID" => $user['userID']]
        );
    }

    // Private key derivation now happens client-side.
    // Return the encrypted blob + salt so the browser can decrypt.
    $result['success'] = true;
    $result['userID'] = $user['userID'];
    $result['privateKeyEnc'] = $user['privateKeyEnc'] ?? null;
    $result['keySalt'] = $user['keySalt'] ?? null;

    return $result;
}

/**
 * Validate and decrypt user's private encryption key
 *
 * @param array $user User record from database
 * @param string $password User's plaintext password
 * @return string|null|false Decrypted private key, null for legacy accounts, or false on failure
 */
function validateEncryptionKeys($user, $password)
{
    $keySaltEncoded = $user['keySalt'];
    $privateKeyEnc = $user['privateKeyEnc'];

    // Check for legacy account without encryption keys
    if (empty($keySaltEncoded) || empty($privateKeyEnc)) {
        return null; // Legacy account - no private key
    }

    // Decode and validate salt
    $keySalt = base64_decode($keySaltEncoded, true);
    if ($keySalt === false || strlen($keySalt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
        error_log("Invalid encryption key salt for user");
        return false;
    }

    // Derive encryption key from password
    $encryptionKey = sodium_crypto_pwhash(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
        $password,
        $keySalt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );

    // Decode encrypted private key
    $encryptedData = base64_decode($privateKeyEnc, true);
    if ($encryptedData === false) {
        error_log("Invalid base64 encoded private key");
        return false;
    }

    // Extract nonce and ciphertext
    $nonce = substr($encryptedData, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $ciphertext = substr($encryptedData, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

    // Decrypt private key
    $privateKey = sodium_crypto_secretbox_open($ciphertext, $nonce, $encryptionKey);

    // Clear sensitive data from memory
    sodium_memzero($encryptionKey);

    if ($privateKey === false) {
        error_log("Failed to decrypt private key - incorrect password or corrupted data");
        return false;
    }

    return $privateKey;
}

/**
 * Generate a cryptographically secure random token
 *
 * @param int $length Desired length of the token
 * @return string Hexadecimal token
 */
function generateSecureToken($length)
{
    // Generate token with length/2 random bytes (each byte = 2 hex chars)
    return bin2hex(random_bytes($length / 2));
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login - ResearchChatAI</title>
    
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
            
            <!-- Login Card -->
            <div id="loginCard" class="card">
                <header class="card-header has-background-dark">
                    <p class="card-header-title has-text-white">Login</p>
                </header>
                
                <form action="" method="post" id="loginForm">
                    <!-- CSRF Protection -->
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                    
                    <div class="card-content">
                        <div class="content">
                            <!-- Email Field -->
                            <div class="field">
                                <p class="control has-icons-left has-icons-right">
                                    <input 
                                        class="input" 
                                        type="email" 
                                        placeholder="Email" 
                                        name="email" 
                                        id="email"
                                        value="<?php echo htmlspecialchars($placeholderEmail, ENT_QUOTES, 'UTF-8'); ?>"
                                        autocomplete="email"
                                        required
                                    >
                                    <span class="icon is-small is-left">
                                        <i class="fas fa-envelope"></i>
                                    </span>
                                </p>
                            </div>
                            
                            <!-- Password Field -->
                            <div class="field">
                                <p class="control has-icons-left">
                                    <input 
                                        class="input" 
                                        type="password" 
                                        placeholder="Password" 
                                        name="password" 
                                        id="password"
                                        autocomplete="current-password"
                                        required
                                    >
                                    <span class="icon is-small is-left">
                                        <i class="fas fa-lock"></i>
                                    </span>
                                </p>
                            </div>
                            
                            <!-- Submit Button -->
                            <input type="submit" value="Log in" class="button is-primary is-fullwidth">
                        </div>
                    </div>
                    
                    <!-- Footer Links -->
                    <footer class="card-footer">
                        <a href="password-forgot.php" class="card-footer-item has-text-dark">Forgot password</a>
                        <a href="signup.php" class="card-footer-item has-text-dark">Sign up</a>
                    </footer>
                </form>
            </div>
            
            <!-- Error Message -->
            <?php if ($errorCode === "INVALID"): ?>
                <div class="notification is-danger mt-5" style="max-width: 350px; margin: 0 auto;">
                    <label class="label has-text-white">Error</label>
                    <div class="has-text-white">Invalid email or password. Please try again.</div>
                </div>
            <?php endif; ?>
            
            <!-- Success Message -->
            <?php if ($message === "ACCOUNTCREATED"): ?>
                <div class="notification is-success mt-5" style="max-width: 350px; margin: 0 auto;">
                    <label class="label">Success</label>
                    <div>Your account has been successfully created! You can log in now.</div>
                </div>
            <?php endif; ?>
        </div>
    </section>

    <!-- Scripts -->
    <script src="https://code.jquery.com/jquery-3.6.3.min.js"
        integrity="sha256-pvPw+upLPUjgMXY0G+8O0xUf+/Im1MZjXxxgOcBQBXU="
        crossorigin="anonymous"></script>
    <!-- libsodium-sumo for client-side key derivation (sumo needed for crypto_pwhash/Argon2id) -->
    <script src="https://cdn.jsdelivr.net/npm/libsodium-sumo@0.7.15/dist/modules-sumo/libsodium-sumo.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/libsodium-wrappers-sumo@0.7.15/dist/modules-sumo/libsodium-wrappers.js"></script>
    <script type="text/javascript">
        /**
         * AJAX login with client-side private key derivation.
         *
         * 1. POST credentials to server (validates password, returns encrypted key blob)
         * 2. Derive encryption key from password using Argon2id (identical params to PHP)
         * 3. Decrypt private key PEM using sodium secretbox
         * 4. Store decrypted private key in sessionStorage (cleared on tab close)
         * 5. Redirect to index.php
         */
        $('#loginForm').on('submit', function(event) {
            event.preventDefault();

            var email = $('#email').val().trim();
            var password = $('#password').val();

            if (!email || !password) {
                return false;
            }

            // Disable submit button and show loading state
            var submitBtn = $(this).find('input[type="submit"]');
            submitBtn.prop('disabled', true).val('Logging in...');

            $.ajax({
                type: 'POST',
                url: '',
                data: $(this).serialize(),
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
                dataType: 'json',
                success: async function(response) {
                    if (!response.success) {
                        showLoginError();
                        submitBtn.prop('disabled', false).val('Log in');
                        return;
                    }

                    // If user has encryption keys, derive private key client-side
                    if (response.privateKeyEnc && response.keySalt) {
                        try {
                            var _sodium = await sodium.ready;

                            // Debug: check what ready returns
                            console.log('sodium.ready resolved to:', typeof _sodium, _sodium ? Object.keys(_sodium).slice(0,10) : 'null');
                            // Use whichever has the crypto functions
                            var s = (_sodium && _sodium.crypto_secretbox_open) ? _sodium : sodium;

                            // Decode base64 salt
                            var keySalt = s.from_base64(response.keySalt, s.base64_variants.ORIGINAL);

                            // Derive encryption key (identical to PHP sodium_crypto_pwhash)
                            var derivedKey = s.crypto_pwhash(
                                32, // SODIUM_CRYPTO_SECRETBOX_KEYBYTES
                                password,
                                keySalt,
                                2,        // SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE
                                67108864, // SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE (64 MB)
                                s.crypto_pwhash_ALG_ARGON2ID13
                            );

                            // Decode encrypted private key (base64 → nonce + ciphertext)
                            var encryptedData = s.from_base64(response.privateKeyEnc, s.base64_variants.ORIGINAL);
                            var nonce = encryptedData.slice(0, s.crypto_secretbox_NONCEBYTES); // 24 bytes
                            var ciphertext = encryptedData.slice(s.crypto_secretbox_NONCEBYTES);

                            // Decrypt private key PEM
                            var privateKeyBytes = s.crypto_secretbox_open_easy(ciphertext, nonce, derivedKey);

                            if (!privateKeyBytes) {
                                console.error('Failed to decrypt private key');
                                showLoginError();
                                submitBtn.prop('disabled', false).val('Log in');
                                return;
                            }

                            // Store decrypted PEM in sessionStorage (cleared when tab closes)
                            var privateKeyPem = s.to_string(privateKeyBytes);
                            sessionStorage.setItem('privateKey', privateKeyPem);

                        } catch (e) {
                            console.error('Key derivation error:', e);
                            // Continue login even if key derivation fails
                            // (user can still use the app, just won't be able to decrypt messages)
                        }
                    }

                    // Redirect to homepage
                    window.location.href = 'index.php';
                },
                error: function() {
                    showLoginError();
                    submitBtn.prop('disabled', false).val('Log in');
                }
            });
        });

        function showLoginError() {
            // Remove existing error notification if any
            $('.notification.is-danger.mt-5').remove();
            // Add error message
            var errorHtml = '<div class="notification is-danger mt-5" style="max-width: 350px; margin: 0 auto;">'
                + '<label class="label has-text-white">Error</label>'
                + '<div class="has-text-white">Invalid email or password. Please try again.</div>'
                + '</div>';
            $('#loginCard').after(errorHtml);
        }
    </script>
</body>

</html>