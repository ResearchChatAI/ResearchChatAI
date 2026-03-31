<?php
/**
 * user-update.php
 *
 * Updates user profile information including name, email, and institution.
 * Validates input and ensures users can only update their own profile.
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

require_once __DIR__ . '/../Util/crypto.php';

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

define('MAX_NAME_LENGTH', 100);
define('MAX_INSTITUTION_LENGTH', 200);
define('MAX_EMAIL_LENGTH', 254); // RFC 5321

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send JSON response and exit
 *
 * @param string $status Status code ('good' or 'bad')
 * @param string $message Optional message
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
 * Validate and sanitize name input
 *
 * @param string $name Name to validate
 * @param string $fieldName Field name for error messages
 * @return array Result with 'valid' boolean, 'sanitized' string, and 'message' string
 */
function validateName(string $name, string $fieldName): array
{
    $result = ['valid' => false, 'sanitized' => '', 'message' => ''];
    
    // Trim whitespace
    $name = trim($name);
    
    // Check if empty
    if (empty($name)) {
        $result['message'] = $fieldName . ' is required';
        return $result;
    }
    
    // Check length
    if (strlen($name) > MAX_NAME_LENGTH) {
        $result['message'] = $fieldName . ' must be ' . MAX_NAME_LENGTH . ' characters or less';
        return $result;
    }
    
    // Check for control characters
    if (preg_match('/[\x00-\x1F\x7F]/', $name)) {
        $result['message'] = $fieldName . ' contains invalid characters';
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $name;
    return $result;
}

/**
 * Validate email address
 *
 * @param string $email Email to validate
 * @return array Result with 'valid' boolean, 'sanitized' string, and 'message' string
 */
function validateEmail(string $email): array
{
    $result = ['valid' => false, 'sanitized' => '', 'message' => ''];
    
    // Trim and lowercase
    $email = trim(strtolower($email));
    
    // Check if empty
    if (empty($email)) {
        $result['message'] = 'Email is required';
        return $result;
    }
    
    // Check length (RFC 5321)
    if (strlen($email) > MAX_EMAIL_LENGTH) {
        $result['message'] = 'Email address is too long';
        return $result;
    }
    
    // Validate format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $result['message'] = 'Invalid email format';
        return $result;
    }
    
    // Check for injection attempts
    if (preg_match('/[\r\n]/', $email) || strpos($email, "\0") !== false) {
        $result['message'] = 'Invalid email format';
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $email;
    return $result;
}

/**
 * Validate and sanitize institution input
 *
 * @param string $institution Institution name to validate
 * @return array Result with 'valid' boolean, 'sanitized' string, and 'message' string
 */
function validateInstitution(string $institution): array
{
    $result = ['valid' => true, 'sanitized' => '', 'message' => ''];
    
    // Trim whitespace
    $institution = trim($institution);
    
    // Institution is optional, so empty is valid
    if (empty($institution)) {
        $result['sanitized'] = '';
        return $result;
    }
    
    // Check length
    if (strlen($institution) > MAX_INSTITUTION_LENGTH) {
        $result['valid'] = false;
        $result['message'] = 'Institution name must be ' . MAX_INSTITUTION_LENGTH . ' characters or less';
        return $result;
    }
    
    // Check for control characters
    if (preg_match('/[\x00-\x1F\x7F]/', $institution)) {
        $result['valid'] = false;
        $result['message'] = 'Institution name contains invalid characters';
        return $result;
    }
    
    $result['sanitized'] = $institution;
    return $result;
}

/**
 * Update user profile information
 *
 * @param object $database Medoo database instance
 * @param int $userID User ID to update
 * @param string $name First name
 * @param string $surname Last name
 * @param string $email Email address
 * @param string $institution Institution name
 * @return array Result with 'success' boolean and 'message' string
 */
function updateUserProfile($database, int $userID, string $name, string $surname, string $email, string $institution): array
{
    $result = ['success' => false, 'message' => ''];
    
    try {
        // Check if email is already taken by another user
        $existingUser = $database->get('users', 'userID', [
            'userEmail' => $email,
            'userID[!]' => $userID
        ]);
        
        if ($existingUser) {
            $result['message'] = 'Email address is already in use by another account';
            return $result;
        }
        
        // Update user profile
        $updateResult = $database->update('users', [
            'userName' => encryptString($name),
            'userSurname' => encryptString($surname),
            'userEmail' => $email,
            'userInstitution' => encryptString($institution),
            'userLastActiveDate' => date('Y-m-d H:i:s')
        ], [
            'userID' => $userID
        ]);
        
        if ($updateResult === false) {
            $result['message'] = 'Database update failed';
            error_log("Failed to update profile for user " . $userID);
            return $result;
        }
        
        $result['success'] = true;
        $result['message'] = 'Profile updated successfully';
        
        error_log("Profile updated successfully for user " . $userID);
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error updating profile for user " . $userID . ": " . $e->getMessage());
        $result['message'] = 'An error occurred while updating profile';
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
    error_log("CSRF token missing in profile update request");
    sendResponse('bad', 'Invalid request', 403);
}

if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    error_log("CSRF token validation failed in profile update request");
    sendResponse('bad', 'Invalid request', 403);
}

// Verify this is a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('bad', 'Invalid request method', 405);
}

// Get session user ID
$sessionUserID = (int)$_SESSION['userID'];

if ($sessionUserID <= 0) {
    sendResponse('bad', 'Invalid session user ID', 400);
}

// Get posted user ID and verify authorization
$postedUserID = isset($_POST['userID']) ? (int)$_POST['userID'] : 0;

// CRITICAL: User can only update their own profile
if ($sessionUserID !== $postedUserID) {
    error_log("Authorization violation: User " . $sessionUserID . " attempted to update user " . $postedUserID);
    sendResponse('bad', 'Unauthorized - you can only update your own profile', 403);
}

// Get and validate input
$name = $_POST['name'] ?? '';
$surname = $_POST['surname'] ?? '';
$email = $_POST['email'] ?? '';
$institution = $_POST['institution'] ?? '';

// Validate first name
$nameValidation = validateName($name, 'First name');
if (!$nameValidation['valid']) {
    sendResponse('bad', $nameValidation['message'], 400);
}

// Validate last name
$surnameValidation = validateName($surname, 'Last name');
if (!$surnameValidation['valid']) {
    sendResponse('bad', $surnameValidation['message'], 400);
}

// Validate email
$emailValidation = validateEmail($email);
if (!$emailValidation['valid']) {
    sendResponse('bad', $emailValidation['message'], 400);
}

// Validate institution
$institutionValidation = validateInstitution($institution);
if (!$institutionValidation['valid']) {
    sendResponse('bad', $institutionValidation['message'], 400);
}

// Load database
require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';

// Perform profile update with sanitized data
$updateResult = updateUserProfile(
    $database,
    $sessionUserID,
    $nameValidation['sanitized'],
    $surnameValidation['sanitized'],
    $emailValidation['sanitized'],
    $institutionValidation['sanitized']
);

if ($updateResult['success']) {
    sendResponse('good', 'Profile updated successfully', 200);
} else {
    sendResponse('bad', $updateResult['message'], 400);
}