<?php
/**
 * user-update-password.php
 *
 * Updates user password and re-encrypts private key with new password.
 * Supports legacy MD5 passwords and modern Argon2id hashed passwords.
 *
 * ResearchChatAI
 * Author: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

session_start();

// =============================================================================
// SECURITY HEADERS
// =============================================================================

// Prevent MIME-type sniffing
header("X-Content-Type-Options: nosniff");

// Set JSON content type
header('Content-Type: application/json');

// Prevent caching of sensitive operations
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// =============================================================================
// CONSTANTS
// =============================================================================

define('MIN_PASSWORD_LENGTH', 8);
define('MD5_HASH_LENGTH', 32);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send JSON response and exit
 *
 * @param string $status Status code ('good' or 'bad')
 * @param string $message Optional message for debugging
 * @param int $httpCode HTTP status code
 */
function sendResponse(string $status, string $message = '', int $httpCode = 200): void
{
    http_response_code($httpCode);
    echo json_encode([
        'status' => $status,
        'message' => $message
    ]);
    exit;
}

/**
 * Validate password requirements
 *
 * @param string $password Password to validate
 * @return array Result with 'valid' boolean and 'message' string
 */
function validatePassword(string $password): array
{
    $result = ['valid' => false, 'message' => ''];
    
    if (empty($password)) {
        $result['message'] = 'Password cannot be empty';
        return $result;
    }
    
    if (strlen($password) < MIN_PASSWORD_LENGTH) {
        $result['message'] = 'Password must be at least ' . MIN_PASSWORD_LENGTH . ' characters long';
        return $result;
    }
    
    $result['valid'] = true;
    return $result;
}

/**
 * Verify password against stored hash (supports legacy MD5 and Argon2id)
 *
 * @param string $password Plain text password
 * @param string $storedHash Stored password hash
 * @return bool True if password matches
 */
function verifyPassword(string $password, string $storedHash): bool
{
    // Try modern password_verify first (Argon2id)
    if (password_verify($password, $storedHash)) {
        return true;
    }
    
    // Fallback to legacy MD5 (for migration)
    if (strlen($storedHash) === MD5_HASH_LENGTH && 
        ctype_xdigit($storedHash) && 
        hash_equals($storedHash, md5($password))) {
        return true;
    }
    
    return false;
}

/**
 * Decrypt private key with old password
 *
 * @param string $oldPassword User's old password
 * @param string $privateKeyEnc Base64-encoded encrypted private key
 * @param string $keySalt Base64-encoded key salt
 * @return string|false Decrypted private key or false on failure
 */
function decryptPrivateKey(string $oldPassword, string $privateKeyEnc, string $keySalt)
{
    try {
        // Decode base64 values
        $decodedSalt = base64_decode($keySalt, true);
        $encodedPrivateKey = base64_decode($privateKeyEnc, true);
        
        // Validate decoded values
        if ($decodedSalt === false || strlen($decodedSalt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            error_log("Invalid key salt format");
            return false;
        }
        
        if ($encodedPrivateKey === false || strlen($encodedPrivateKey) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            error_log("Invalid encrypted private key format");
            return false;
        }
        
        // Derive encryption key from old password
        $oldKey = sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            $oldPassword,
            $decodedSalt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
        
        // Extract nonce and ciphertext
        $nonce = substr($encodedPrivateKey, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($encodedPrivateKey, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        
        // Decrypt private key
        $privateKey = sodium_crypto_secretbox_open($ciphertext, $nonce, $oldKey);
        
        // Clear old key from memory
        sodium_memzero($oldKey);
        
        if ($privateKey === false) {
            error_log("Failed to decrypt private key - wrong password");
            return false;
        }
        
        return $privateKey;
        
    } catch (Exception $e) {
        error_log("Error decrypting private key: " . $e->getMessage());
        return false;
    }
}

/**
 * Re-encrypt private key with new password
 *
 * @param string $privateKey Decrypted private key
 * @param string $newPassword User's new password
 * @param string $keySalt Base64-encoded key salt
 * @return string|false Base64-encoded encrypted private key or false on failure
 */
function reencryptPrivateKey(string $privateKey, string $newPassword, string $keySalt)
{
    try {
        $decodedSalt = base64_decode($keySalt, true);
        
        if ($decodedSalt === false) {
            return false;
        }
        
        // Derive new encryption key from new password
        $newKey = sodium_crypto_pwhash(
            SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            $newPassword,
            $decodedSalt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
        
        // Encrypt with new key
        $newNonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $newCiphertext = sodium_crypto_secretbox($privateKey, $newNonce, $newKey);
        $newEncrypted = base64_encode($newNonce . $newCiphertext);
        
        // Clear new key from memory
        sodium_memzero($newKey);
        
        return $newEncrypted;
        
    } catch (Exception $e) {
        error_log("Error re-encrypting private key: " . $e->getMessage());
        return false;
    }
}

/**
 * Update user password in database
 *
 * @param object $database Medoo database instance
 * @param int $userID User ID
 * @param string $oldPassword Current password
 * @param string $newPassword New password
 * @return array Result with 'success' boolean and 'message' string
 */
function updateUserPassword($database, int $userID, string $oldPassword, string $newPassword): array
{
    $result = ['success' => false, 'message' => ''];
    
    try {
        // Fetch user data
        $user = $database->get("users", [
            "userPassword",
            "privateKeyEnc",
            "keySalt"
        ], [
            "userID" => $userID
        ]);
        
        if (!$user) {
            $result['message'] = 'User not found';
            return $result;
        }
        
        // Verify old password
        if (!verifyPassword($oldPassword, $user['userPassword'])) {
            $result['message'] = 'Current password is incorrect';
            return $result;
        }
        
        // Hash new password
        $newHash = password_hash($newPassword, PASSWORD_ARGON2ID);
        
        if ($newHash === false) {
            $result['message'] = 'Failed to hash new password';
            error_log("password_hash failed for user " . $userID);
            return $result;
        }
        
        // Prepare update data
        $updateData = [
            "userPassword" => $newHash,
            "userLastActiveDate" => date('Y-m-d H:i:s')
        ];
        
        // Handle encryption key re-encryption if applicable
        $hasEncryption = !empty($user['keySalt']) && !empty($user['privateKeyEnc']);
        
        if ($hasEncryption) {
            // Decrypt private key using old password (private key is never stored server-side)
            $privateKey = decryptPrivateKey(
                $oldPassword,
                $user['privateKeyEnc'],
                $user['keySalt']
            );

            if ($privateKey === false) {
                $result['message'] = 'Failed to decrypt encryption keys';
                return $result;
            }
            
            // Re-encrypt private key with new password
            $newEncrypted = reencryptPrivateKey(
                $privateKey,
                $newPassword,
                $user['keySalt']
            );
            
            if ($newEncrypted === false) {
                // Clear private key from memory
                sodium_memzero($privateKey);
                $result['message'] = 'Failed to re-encrypt private key';
                return $result;
            }
            
            $updateData["privateKeyEnc"] = $newEncrypted;
            
            // Clear private key from memory
            sodium_memzero($privateKey);
        }
        
        // Update database
        $updateResult = $database->update("users", $updateData, [
            "userID" => $userID
        ]);
        
        if ($updateResult === false) {
            $result['message'] = 'Database update failed';
            error_log("Failed to update password for user " . $userID);
            return $result;
        }
        
        $result['success'] = true;
        $result['message'] = 'Password updated successfully';
        
        error_log("Password updated successfully for user " . $userID);
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error updating password for user " . $userID . ": " . $e->getMessage());
        $result['message'] = 'An error occurred while updating password';
        return $result;
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Authentication check
if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    sendResponse('bad', 'Unauthorized', 401);
}

// Verify user ID exists in session
if (!isset($_SESSION['userID'])) {
    sendResponse('bad', 'Invalid session', 400);
}

// CSRF token validation
if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token'])) {
    error_log("CSRF token missing in password update request");
    sendResponse('bad', 'Invalid request', 403);
}

if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    error_log("CSRF token validation failed in password update request");
    sendResponse('bad', 'Invalid request', 403);
}

// Verify this is a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('bad', 'Invalid request method', 405);
}

// Get and validate input
$oldPassword = $_POST['oldPassword'] ?? '';
$newPassword = $_POST['newPassword'] ?? '';

if (empty($oldPassword)) {
    sendResponse('bad', 'Current password is required', 400);
}

// Validate new password
$passwordValidation = validatePassword($newPassword);
if (!$passwordValidation['valid']) {
    sendResponse('bad', $passwordValidation['message'], 400);
}

// Load database
require '../MySQL/medoo-Credentials.php';
use Medoo\Medoo;

// Get user ID and sanitize
$userID = (int)$_SESSION['userID'];

if ($userID <= 0) {
    sendResponse('bad', 'Invalid user ID', 400);
}

// Perform password update
$updateResult = updateUserPassword($database, $userID, $oldPassword, $newPassword);

if ($updateResult['success']) {
    // Regenerate session ID after password change for security
    session_regenerate_id(true);
    
    sendResponse('good', 'Password updated successfully', 200);
} else {
    // Don't expose detailed error messages to client for security
    $clientMessage = ($updateResult['message'] === 'Current password is incorrect') 
        ? 'Current password is incorrect' 
        : 'Failed to update password';
    
    sendResponse('bad', $clientMessage, 400);
}