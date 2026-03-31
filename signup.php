<?php

/**
 * signup.php
 *
 * Handles user registration with RSA key pair generation, password encryption,
 * and recovery key creation for end-to-end encrypted messaging.
 *
 * ResearchChatAI
 * Author: Marc Becker, David de Jong
 * License: MIT
 */

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

require 'Backend/MySQL/medoo-Credentials.php';
require_once 'Backend/Util/email.php';
require_once 'Backend/Util/crypto.php';

use Medoo\Medoo;

$turnstileSiteKey   = $env['TURNSTILE_SITE_KEY']  ?? '';
$turnstileSecretKey = $env['TURNSTILE_SECRET_KEY'] ?? '';

// =============================================================================
// SECURITY HEADERS
// =============================================================================

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self'; img-src 'self' data:; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// =============================================================================
// CONSTANTS
// =============================================================================

define('RSA_KEY_BITS', 2048);
define('RECOVERY_KEY_BYTES', 16);
define('MIN_PASSWORD_LENGTH', 8);
define('MAX_NAME_LENGTH', 100);

// =============================================================================
// INITIALIZATION
// =============================================================================

$errorCode   = "";
$message     = "";
$recoveryKey = "";
$showForm    = true;

session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

// =============================================================================
// REGISTRATION LOGIC
// =============================================================================

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $errorCode = "INVALID";
        error_log("CSRF token validation failed in signup");
    } else {
        $turnstileToken = isset($_POST['cf-turnstile-response']) ? trim($_POST['cf-turnstile-response']) : '';

        if (empty($turnstileToken)) {
            $errorCode = "CAPTCHA_MISSING";
        } elseif (!verifyTurnstileToken($turnstileToken, $turnstileSecretKey, $_SERVER['REMOTE_ADDR'] ?? '')) {
            $errorCode = "CAPTCHA_INVALID";
        }

        if (empty($errorCode) && (!isset($_POST['terms_accepted']) || $_POST['terms_accepted'] !== '1')) {
            $errorCode = "NOTACCEPTED";
        }

        if (empty($errorCode)) {
            $firstName = isset($_POST['firstName']) ? trim($_POST['firstName']) : '';
            $lastName  = isset($_POST['lastName'])  ? trim($_POST['lastName'])  : '';
            $email     = isset($_POST['email'])     ? trim(strtolower($_POST['email'])) : '';
            $password  = isset($_POST['password'])  ? $_POST['password'] : '';

            $validationResult = validateRegistrationInput($firstName, $lastName, $email, $password);

            if (!$validationResult['valid']) {
                $errorCode = $validationResult['errorCode'];
            } else {
                if ($database->has("users", ["userEmail" => $email])) {
                    $errorCode = "EXISTINGEMAIL";
                } else {
                    $registrationResult = createUserAccount($database, $firstName, $lastName, $email, $password);

                    if ($registrationResult['success']) {
                        $recoveryKey = $registrationResult['recoveryKey'];
                        sendWelcomeEmail($email, $firstName, $recoveryKey);
                        $message  = "SUCCESS";
                        $showForm = false;
                        session_regenerate_id(true);
                    } else {
                        $errorCode = "SERVERERROR";
                        error_log("Failed to create user account for: " . $email);
                    }
                }
            }
        }
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Verify a Cloudflare Turnstile token server-side.
 *
 * @param string $token    Token from the cf-turnstile-response POST field
 * @param string $secret   Turnstile secret key from .env
 * @param string $remoteIp Visitor's IP address
 * @return bool True if the token is valid
 */
function verifyTurnstileToken(string $token, string $secret, string $remoteIp): bool
{
    if (empty($token) || empty($secret)) {
        error_log("Turnstile: empty token or secret key");
        return false;
    }

    $payload = http_build_query([
        'secret'   => $secret,
        'response' => $token,
        'remoteip' => $remoteIp,
    ]);

    if (function_exists('curl_init')) {
        $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);
        $response = curl_exec($ch);
        if ($response === false) {
            error_log("Turnstile curl error: " . curl_error($ch));
            curl_close($ch);
            return false;
        }
        curl_close($ch);
    } else {
        $context = stream_context_create([
            'http' => [
                'method'  => 'POST',
                'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
                'content' => $payload,
                'timeout' => 5,
            ],
        ]);
        $response = @file_get_contents('https://challenges.cloudflare.com/turnstile/v0/siteverify', false, $context);
        if ($response === false) {
            error_log("Turnstile: file_get_contents failed (allow_url_fopen may be disabled)");
            return false;
        }
    }

    $data = json_decode($response, true);
    if (!isset($data['success'])) {
        error_log("Turnstile: unexpected response: " . $response);
        return false;
    }
    if (!$data['success']) {
        error_log("Turnstile: verification failed, error-codes: " . implode(', ', $data['error-codes'] ?? ['none']));
    }
    return $data['success'] === true;
}

/**
 * Validate user registration input for security and data integrity.
 *
 * @param string $firstName User's first name
 * @param string $lastName  User's last name
 * @param string $email     User's email address
 * @param string $password  User's chosen password
 * @return array{valid: bool, errorCode: string}
 */
function validateRegistrationInput(string $firstName, string $lastName, string $email, string $password): array
{
    $result = ['valid' => false, 'errorCode' => ''];

    if (empty($firstName) || empty($lastName)) {
        $result['errorCode'] = 'INVALIDNAME';
        return $result;
    }
    if (strlen($firstName) > MAX_NAME_LENGTH || strlen($lastName) > MAX_NAME_LENGTH) {
        $result['errorCode'] = 'INVALIDNAME';
        return $result;
    }
    if (preg_match('/[\x00-\x1F\x7F]/', $firstName) || preg_match('/[\x00-\x1F\x7F]/', $lastName)) {
        $result['errorCode'] = 'INVALIDNAME';
        return $result;
    }
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $result['errorCode'] = 'INVALIDEMAIL';
        return $result;
    }
    if (preg_match('/[\r\n]/', $email) || strpos($email, "\0") !== false) {
        $result['errorCode'] = 'INVALIDEMAIL';
        return $result;
    }
    if (empty($password)) {
        $result['errorCode'] = 'INVALIDPASSWORD';
        return $result;
    }
    if (strlen($password) < MIN_PASSWORD_LENGTH) {
        $result['errorCode'] = 'WEAKPASSWORD';
        return $result;
    }

    $result['valid'] = true;
    return $result;
}

/**
 * Create a new user account with an RSA key pair and encrypted private key.
 *
 * The private key is encrypted twice: once with a key derived from the user's
 * password (for normal login) and once with a key derived from a random recovery
 * key (for password recovery). Both use Argon2id key derivation and XSalsa20-Poly1305
 * authenticated encryption via libsodium.
 *
 * @param Medoo  $database  Active database connection
 * @param string $firstName User's first name
 * @param string $lastName  User's last name
 * @param string $email     User's email address
 * @param string $password  User's chosen password (plaintext, cleared after use)
 * @return array{success: bool, recoveryKey: string}
 */
function createUserAccount($database, string $firstName, string $lastName, string $email, string $password): array
{
    $result = ['success' => false, 'recoveryKey' => ''];

    try {
        $keyPair = openssl_pkey_new([
            'private_key_bits' => RSA_KEY_BITS,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($keyPair === false) {
            error_log("Failed to generate RSA key pair");
            return $result;
        }

        openssl_pkey_export($keyPair, $privateKey);
        $details   = openssl_pkey_get_details($keyPair);
        $publicKey = $details['key'];

        // Shared salt for both key derivations (password and recovery)
        $keySalt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

        // Encrypt private key with a key derived from the user's password
        $passwordKey   = sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            $password, $keySalt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
        $nonce         = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $privateKeyEnc = base64_encode($nonce . sodium_crypto_secretbox($privateKey, $nonce, $passwordKey));
        sodium_memzero($passwordKey);

        // Encrypt private key with a key derived from a random recovery key
        $recoveryKey        = bin2hex(random_bytes(RECOVERY_KEY_BYTES));
        $recoveryDerivedKey = sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            $recoveryKey, $keySalt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
        $recoveryNonce  = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $recoveryKeyEnc = base64_encode($recoveryNonce . sodium_crypto_secretbox($privateKey, $recoveryNonce, $recoveryDerivedKey));
        sodium_memzero($recoveryDerivedKey);
        sodium_memzero($privateKey);

        $hashedPassword = password_hash($password, PASSWORD_ARGON2ID);

        $insertResult = $database->insert("users", [
            "userName"             => encryptString($firstName),
            "userSurname"          => encryptString($lastName),
            "userEmail"            => $email,
            "userPassword"         => $hashedPassword,
            "publicKey"            => $publicKey,
            "privateKeyEnc"        => $privateKeyEnc,
            "keySalt"              => base64_encode($keySalt),
            "recoveryKeyEnc"       => $recoveryKeyEnc,
            "userRegistrationDate" => date('Y-m-d H:i:s'),
        ]);

        if ($insertResult === false) {
            error_log("Database insert failed for user: " . $email);
            return $result;
        }

        $result['success']     = true;
        $result['recoveryKey'] = $recoveryKey;
        return $result;

    } catch (Exception $e) {
        error_log("Exception during user creation: " . $e->getMessage());
        return $result;
    }
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - ResearchChatAI</title>

    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
    <link rel="stylesheet" href="src/CSS/login.css">

    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

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

            <div class="columns is-centered">
                <div class="column is-half">
                    <div class="card">
                        <header class="card-header has-background-dark">
                            <a href="login.php" class="card-header-icon" aria-label="Back to login">
                                <span class="icon has-text-white">
                                    <i class="fas fa-arrow-left" aria-hidden="true"></i>
                                </span>
                            </a>
                            <p class="card-header-title has-text-white">Sign Up</p>
                        </header>

                        <div class="card-content">
                            <?php if ($errorCode === "EXISTINGEMAIL"): ?>
                                <div class="notification is-danger">
                                    <p>This email address is already registered.</p>
                                    <p class="mt-2"><a href="login.php">Click here to log in</a></p>
                                </div>
                            <?php elseif ($errorCode === "INVALIDNAME"): ?>
                                <div class="notification is-danger">
                                    <p>Please enter a valid first and last name.</p>
                                </div>
                            <?php elseif ($errorCode === "INVALIDEMAIL"): ?>
                                <div class="notification is-danger">
                                    <p>Please enter a valid email address.</p>
                                </div>
                            <?php elseif ($errorCode === "INVALIDPASSWORD"): ?>
                                <div class="notification is-danger">
                                    <p>Please enter a password.</p>
                                </div>
                            <?php elseif ($errorCode === "WEAKPASSWORD"): ?>
                                <div class="notification is-danger">
                                    <p>Password must be at least <?php echo MIN_PASSWORD_LENGTH; ?> characters long.</p>
                                </div>
                            <?php elseif ($errorCode === "SERVERERROR"): ?>
                                <div class="notification is-danger">
                                    <p>An error occurred during registration. Please try again later.</p>
                                </div>
                            <?php elseif ($errorCode === "INVALID"): ?>
                                <div class="notification is-danger">
                                    <p>Invalid request. Please try again.</p>
                                </div>
                            <?php elseif ($errorCode === "CAPTCHA_MISSING"): ?>
                                <div class="notification is-danger">
                                    <p>Please complete the security check before submitting.</p>
                                </div>
                            <?php elseif ($errorCode === "CAPTCHA_INVALID"): ?>
                                <div class="notification is-danger">
                                    <p>Security check could not be verified. Please try again.</p>
                                </div>
                            <?php elseif ($errorCode === "NOTACCEPTED"): ?>
                                <div class="notification is-danger">
                                    <p>You must accept the Terms of Use and Privacy Policy to create an account.</p>
                                </div>
                            <?php endif; ?>

                            <?php if ($message === "SUCCESS"): ?>
                                <div class="notification is-success">
                                    <p class="mb-4"><strong>Account created successfully!</strong></p>

                                    <div class="box has-background-warning-light">
                                        <p class="has-text-weight-bold mb-3">
                                            <span class="icon-text">
                                                <span class="icon has-text-danger">
                                                    <i class="fas fa-exclamation-triangle"></i>
                                                </span>
                                                <span>IMPORTANT: Save Your Recovery Key</span>
                                            </span>
                                        </p>

                                        <div class="notification is-danger is-light mb-4">
                                            <p class="has-text-weight-bold">
                                                Without this key, all your encrypted data will be permanently lost if you forget your password!
                                            </p>
                                        </div>

                                        <div class="field">
                                            <label class="label">Recovery Key</label>
                                            <div class="control">
                                                <input class="input is-family-monospace" type="text"
                                                    value="<?php echo htmlspecialchars($recoveryKey, ENT_QUOTES, 'UTF-8'); ?>"
                                                    readonly id="recoveryKeyField">
                                            </div>
                                        </div>

                                        <button type="button" class="button is-small is-light" id="copyButton">
                                            <span class="icon"><i class="fas fa-copy"></i></span>
                                            <span>Copy to Clipboard</span>
                                        </button>

                                        <button type="button" class="button is-small is-light ml-2" id="downloadButton">
                                            <span class="icon"><i class="fas fa-download"></i></span>
                                            <span>Download as File</span>
                                        </button>

                                        <div class="content mt-4">
                                            <p class="has-text-weight-semibold">Why is this important?</p>
                                            <ul style="margin-left: 1.5rem;">
                                                <li>This is the <strong>only way</strong> to recover your encrypted messages if you forget your password</li>
                                                <li>We <strong>cannot</strong> recover this key for you</li>
                                                <li>Without it, all your data will be <strong>permanently lost</strong></li>
                                            </ul>

                                            <p class="has-text-weight-semibold mt-3">What to do now:</p>
                                            <ul style="margin-left: 1.5rem;">
                                                <li>Download this key as a file or copy it to your clipboard</li>
                                                <li>Store it in a password manager or write it down</li>
                                                <li>Keep it in a secure location</li>
                                            </ul>
                                        </div>
                                    </div>

                                    <div class="has-text-centered mt-5">
                                        <a href="login.php" class="button is-light">
                                            <span class="icon"><i class="fas fa-sign-in-alt"></i></span>
                                            <span>Continue to Login</span>
                                        </a>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <?php if ($showForm): ?>
                                <form action="signup.php" method="POST" id="signupForm">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">

                                    <div class="field">
                                        <label class="label">First Name</label>
                                        <div class="control has-icons-left">
                                            <input class="input" type="text" name="firstName" placeholder="John"
                                                autocomplete="given-name" maxlength="<?php echo MAX_NAME_LENGTH; ?>" required>
                                            <span class="icon is-small is-left"><i class="fas fa-user"></i></span>
                                        </div>
                                    </div>

                                    <div class="field">
                                        <label class="label">Last Name</label>
                                        <div class="control has-icons-left">
                                            <input class="input" type="text" name="lastName" placeholder="Doe"
                                                autocomplete="family-name" maxlength="<?php echo MAX_NAME_LENGTH; ?>" required>
                                            <span class="icon is-small is-left"><i class="fas fa-user"></i></span>
                                        </div>
                                    </div>

                                    <div class="field">
                                        <label class="label">Email Address</label>
                                        <div class="control has-icons-left">
                                            <input class="input" type="email" name="email" placeholder="alex@example.com"
                                                autocomplete="email" required>
                                            <span class="icon is-small is-left"><i class="fas fa-envelope"></i></span>
                                        </div>
                                        <p class="help">Your email will only be used for password recovery.</p>
                                    </div>

                                    <div class="field">
                                        <label class="label">Password</label>
                                        <div class="control has-icons-left">
                                            <input class="input" type="password" name="password" id="password"
                                                placeholder="Minimum <?php echo MIN_PASSWORD_LENGTH; ?> characters"
                                                autocomplete="new-password" minlength="<?php echo MIN_PASSWORD_LENGTH; ?>" required>
                                            <span class="icon is-small is-left"><i class="fas fa-lock"></i></span>
                                        </div>
                                        <p class="help">Must be at least <?php echo MIN_PASSWORD_LENGTH; ?> characters long</p>
                                    </div>

                                    <div class="field mt-4">
                                        <label class="checkbox">
                                            <input type="checkbox" name="terms_accepted" id="termsAccepted" value="1" required>
                                            I have read and agree to the
                                            <a href="Terms_of_Service_ResearchChatAI.pdf" target="_blank">Terms of Use</a>
                                            and the
                                            <a href="Privacy_Statement_ResearchChatAI.pdf" target="_blank">Privacy Policy</a>.
                                        </label>
                                    </div>

                                    <div class="field mt-4">
                                        <div class="cf-turnstile"
                                             data-sitekey="<?php echo htmlspecialchars($turnstileSiteKey, ENT_QUOTES, 'UTF-8'); ?>"
                                             data-callback="onTurnstileSuccess"
                                             data-expired-callback="onTurnstileExpired"
                                             data-theme="light"></div>
                                    </div>

                                    <div class="field mt-5">
                                        <div class="control">
                                            <button type="submit" id="submitBtn" class="button is-primary is-fullwidth" disabled>
                                                <span class="icon"><i class="fas fa-user-plus"></i></span>
                                                <span>Create Account</span>
                                            </button>
                                        </div>
                                    </div>

                                    <div class="field">
                                        <div class="control">
                                            <a href="login.php" class="button is-light is-fullwidth">
                                                <span class="icon"><i class="fas fa-arrow-left"></i></span>
                                                <span>Back to Login</span>
                                            </a>
                                        </div>
                                    </div>
                                </form>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <script>
        var turnstileVerified = false;

        function onTurnstileSuccess(token) {
            turnstileVerified = true;
            updateSubmitButton();
        }

        function onTurnstileExpired() {
            turnstileVerified = false;
            updateSubmitButton();
        }

        function updateSubmitButton() {
            var btn   = document.getElementById('submitBtn');
            var terms = document.getElementById('termsAccepted');
            if (btn && terms) {
                btn.disabled = !(turnstileVerified && terms.checked);
            }
        }

        document.addEventListener('DOMContentLoaded', function () {
            var terms = document.getElementById('termsAccepted');
            if (terms) terms.addEventListener('change', updateSubmitButton);

            var copyButton = document.getElementById('copyButton');
            if (copyButton) copyButton.addEventListener('click', copyRecoveryKey);

            var downloadButton = document.getElementById('downloadButton');
            if (downloadButton) downloadButton.addEventListener('click', downloadRecoveryKey);

            var signupForm = document.getElementById('signupForm');
            if (signupForm) {
                signupForm.addEventListener('submit', function (event) {
                    if (document.getElementById('password').value.length < <?php echo MIN_PASSWORD_LENGTH; ?>) {
                        alert('Password must be at least <?php echo MIN_PASSWORD_LENGTH; ?> characters long.');
                        event.preventDefault();
                    }
                });
            }
        });

        function copyRecoveryKey() {
            var field  = document.getElementById('recoveryKeyField');
            var button = document.getElementById('copyButton');
            if (!field || !button) return;

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(field.value)
                    .then(function () { showSuccess(button, 'Copied!'); })
                    .catch(function () { tryLegacyCopy(field, button); });
            } else {
                tryLegacyCopy(field, button);
            }
        }

        function tryLegacyCopy(field, button) {
            try {
                field.select();
                field.setSelectionRange(0, 99999);
                if (document.execCommand('copy')) {
                    showSuccess(button, 'Copied!');
                } else {
                    alert('Copy failed. Please copy the text manually.');
                }
            } catch (err) {
                alert('Copy failed. Please copy the text manually.');
            }
        }

        function downloadRecoveryKey() {
            var field  = document.getElementById('recoveryKeyField');
            var button = document.getElementById('downloadButton');
            if (!field || !button) return;

            var content = 'ResearchChatAI - Recovery Key\n' +
                '========================================\n\n' +
                'Recovery Key: ' + field.value + '\n\n' +
                'IMPORTANT INSTRUCTIONS:\n' +
                '- Keep this key in a safe, secure location\n' +
                '- You will need this key if you ever forget your password\n' +
                '- Without this key, you cannot recover your encrypted messages\n' +
                '- We cannot regenerate this key for you\n\n' +
                'Store this file securely and delete it from Downloads after saving it to a password manager.\n\n' +
                'Generated: ' + new Date().toLocaleString();

            try {
                var blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
                var url  = URL.createObjectURL(blob);
                var link = document.createElement('a');
                link.href     = url;
                link.download = 'ResearchChatAI-Recovery-Key.txt';
                document.body.appendChild(link);
                link.click();
                setTimeout(function () {
                    document.body.removeChild(link);
                    URL.revokeObjectURL(url);
                }, 100);
                showSuccess(button, 'Downloaded!');
            } catch (err) {
                alert('Failed to download. Please copy the key manually.');
            }
        }

        function showSuccess(button, message) {
            var originalHTML = button.innerHTML;
            button.classList.remove('is-light');
            button.classList.add('is-success');
            button.innerHTML = '<span class="icon"><i class="fas fa-check"></i></span><span>' + message + '</span>';
            button.disabled  = true;
            setTimeout(function () {
                button.classList.remove('is-success');
                button.classList.add('is-light');
                button.innerHTML = originalHTML;
                button.disabled  = false;
            }, 2000);
        }
    </script>
</body>

</html>
