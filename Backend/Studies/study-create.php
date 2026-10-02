<?php
/**
 * study-create.php
 *
 * Creates a new study with secure random code generation.
 * Validates user authorization and input data.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
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

header("X-Content-Type-Options: nosniff");
header('Content-Type: application/json');
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// =============================================================================
// CONSTANTS
// =============================================================================

define('STUDY_CODE_LENGTH', 48);
define('MAX_STUDY_NAME_LENGTH', 200);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send JSON response and exit
 *
 * @param string $status Status code ('good' or 'bad')
 * @param string $message Optional message
 * @param int|null $studyID Optional study ID for successful creation
 * @param int $httpCode HTTP status code
 */
function sendResponse(string $status, string $message = '', ?int $studyID = null, int $httpCode = 200): void
{
    http_response_code($httpCode);
    
    $response = ['status' => $status];
    
    if ($message !== '') {
        $response['message'] = $message;
    }
    
    if ($studyID !== null) {
        $response['studyID'] = $studyID;
    }
    
    echo json_encode($response);
    exit;
}

/**
 * Generate cryptographically secure random key
 *
 * @param int $length Length of the key to generate
 * @return string Random alphanumeric key
 */
function generateSecureRandomKey(int $length): string
{
    // Generate random bytes and convert to hex
    $randomBytes = random_bytes((int)ceil($length / 2));
    $hexString = bin2hex($randomBytes);
    
    // If we need an odd length, truncate
    return substr($hexString, 0, $length);
}

/**
 * Validate study name
 *
 * @param string $name Study name to validate
 * @return array Result with 'valid' boolean, 'sanitized' string, and 'message' string
 */
function validateStudyName(string $name): array
{
    $result = ['valid' => false, 'sanitized' => '', 'message' => ''];
    
    $name = trim($name);
    
    if (empty($name)) {
        $result['message'] = 'Study name is required';
        return $result;
    }
    
    if (strlen($name) > MAX_STUDY_NAME_LENGTH) {
        $result['message'] = 'Study name must be ' . MAX_STUDY_NAME_LENGTH . ' characters or less';
        return $result;
    }
    
    // Check for control characters
    if (preg_match('/[\x00-\x1F\x7F]/', $name)) {
        $result['message'] = 'Study name contains invalid characters';
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $name;
    return $result;
}

/**
 * Create a new study in the database
 *
 * @param object $database Medoo database instance
 * @param int $userID User ID who owns the study
 * @param string $studyName Name of the study
 * @return array Result with 'success' boolean, 'studyID' int, and 'message' string
 */
function createStudy($database, int $userID, string $studyName): array
{
    $result = ['success' => false, 'studyID' => null, 'message' => ''];
    
    try {
        // Generate secure random study code
        $studyCode = generateSecureRandomKey(STUDY_CODE_LENGTH);
        
        // Insert study into database
        $database->insert("studies", [
            "studyOwner" => $userID,
            "studyName" => $studyName,
            "studyCode" => $studyCode,
            "openaiApiKey" => "",
            "openrouterApiKey" => "",
            "isEncrypted" => 1,
            "studyCreatedDate" => date('Y-m-d H:i:s')
        ]);
        
        // Get inserted ID
        $insertedID = $database->id();
        
        if (!$insertedID) {
            error_log("Failed to create study for user $userID");
            $result['message'] = 'Failed to create study';
            return $result;
        }
        
        $result['success'] = true;
        $result['studyID'] = (int)$insertedID;
        $result['message'] = 'Study created successfully';
        
        error_log("Study $insertedID created successfully for user $userID");
        
        return $result;
        
    } catch (Exception $e) {
        error_log("Error creating study for user $userID: " . $e->getMessage());
        $result['message'] = 'An error occurred while creating the study';
        return $result;
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Authentication check
if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    sendResponse('bad', 'Unauthorized', null, 401);
}

// Verify user ID exists in session
if (!isset($_SESSION['userID'])) {
    sendResponse('bad', 'Invalid session', null, 400);
}

// CSRF token validation
if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token'])) {
    error_log("CSRF token missing in study creation request");
    sendResponse('bad', 'Invalid request', null, 403);
}

if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    error_log("CSRF token validation failed in study creation request");
    sendResponse('bad', 'Invalid request', null, 403);
}

// Verify this is a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('bad', 'Invalid request method', null, 405);
}

// Get session user ID
$sessionUserID = (int)$_SESSION['userID'];

if ($sessionUserID <= 0) {
    sendResponse('bad', 'Invalid session user ID', null, 400);
}

// Get posted user ID and verify authorization
$postedUserID = isset($_POST['studyOwner']) ? (int)$_POST['studyOwner'] : 0;

// CRITICAL: User can only create studies for themselves
if ($sessionUserID !== $postedUserID) {
    error_log("Authorization violation: User $sessionUserID attempted to create study for user $postedUserID");
    sendResponse('bad', 'Unauthorized - you can only create studies for yourself', null, 403);
}

// Get and validate study name
$studyName = $_POST['studyName'] ?? '';

$nameValidation = validateStudyName($studyName);
if (!$nameValidation['valid']) {
    sendResponse('bad', $nameValidation['message'], null, 400);
}

// Load database
require '../MySQL/medoo.php';
require '../MySQL/medoo-Credentials.php';

// Create study with sanitized data
$createResult = createStudy(
    $database,
    $sessionUserID,
    $nameValidation['sanitized']
);

if ($createResult['success']) {
    sendResponse('good', $createResult['message'], $createResult['studyID'], 200);
} else {
    sendResponse('bad', $createResult['message'], null, 500);
}
?>