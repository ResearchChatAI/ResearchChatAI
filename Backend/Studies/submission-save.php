<?php
/**
 * submission-save.php
 *
 * PUBLIC ENDPOINT - Saves participant submissions without authentication.
 * Validates input, encrypts data if enabled, and stores in database.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

// =============================================================================
// SECURITY HEADERS
// =============================================================================

// Allow cross-origin requests (public endpoint for participants)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Response headers
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('Connection: close');

// =============================================================================
// CONSTANTS
// =============================================================================

define('MAX_SUBMISSION_TEXT_LENGTH', 50000); // 50KB text limit
define('MAX_PARTICIPANT_ID_LENGTH', 100);
define('MAX_CONDITION_LENGTH', 100);
define('MAX_PASSED_VARIABLES_LENGTH', 10000);
define('MAX_NUMBER_MESSAGES', 10000);
define('MAX_DURATION', 86400); // 24 hours in seconds

// =============================================================================
// DEPENDENCIES
// =============================================================================

require_once('../MySQL/medoo-Credentials.php');
require_once('../Util/crypto.php');

use Medoo\Medoo;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send JSON response and exit
 *
 * @param string $status Status code ('success' or 'error')
 * @param string $message Optional error message
 * @param int $httpCode HTTP status code
 */
function sendResponse(string $status, string $message = '', int $httpCode = 200): void
{
    http_response_code($httpCode);
    
    $response = ['status' => $status];
    
    if ($message !== '') {
        $response['message'] = $message;
    }
    
    echo json_encode($response);
    exit;
}

/**
 * Validate participant ID
 *
 * @param mixed $participantID Participant ID to validate
 * @return array Result with 'valid' boolean, 'sanitized' string, and 'message' string
 */
function validateParticipantID($participantID): array
{
    $result = ['valid' => false, 'sanitized' => '', 'message' => ''];
    
    if ($participantID === null || $participantID === '') {
        $result['message'] = 'Participant ID is required';
        return $result;
    }
    
    $participantID = trim((string)$participantID);
    
    if ($participantID === '') {
        $result['message'] = 'Participant ID cannot be empty';
        return $result;
    }
    
    if (strlen($participantID) > MAX_PARTICIPANT_ID_LENGTH) {
        $result['message'] = 'Participant ID too long';
        return $result;
    }
    
    // Check for control characters
    if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $participantID)) {
        $result['message'] = 'Participant ID contains invalid characters';
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $participantID;
    return $result;
}

/**
 * Validate submission text
 *
 * @param mixed $submissionText Submission text to validate
 * @return array Result with 'valid' boolean, 'sanitized' string, and 'message' string
 */
function validateSubmissionText($submissionText): array
{
    $result = ['valid' => false, 'sanitized' => '', 'message' => ''];
    
    if ($submissionText === null || $submissionText === '') {
        $result['message'] = 'Submission text is required';
        return $result;
    }
    
    $submissionText = trim((string)$submissionText);
    
    if ($submissionText === '') {
        $result['message'] = 'Submission text cannot be empty';
        return $result;
    }
    
    if (strlen($submissionText) > MAX_SUBMISSION_TEXT_LENGTH) {
        $result['message'] = 'Submission text exceeds maximum length';
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $submissionText;
    return $result;
}

/**
 * Validate study code
 *
 * @param mixed $studyCode Study code to validate
 * @return array Result with 'valid' boolean, 'sanitized' string, and 'message' string
 */
function validateStudyCode($studyCode): array
{
    $result = ['valid' => false, 'sanitized' => '', 'message' => ''];
    
    if ($studyCode === null || $studyCode === '') {
        $result['message'] = 'Study code is required';
        return $result;
    }
    
    $studyCode = trim((string)$studyCode);
    
    if ($studyCode === '') {
        $result['message'] = 'Study code cannot be empty';
        return $result;
    }
    
    if (strlen($studyCode) > 64) {
        $result['message'] = 'Study code too long';
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $studyCode;
    return $result;
}

/**
 * Validate numeric field
 *
 * @param mixed $value Value to validate
 * @param string $fieldName Field name for error messages
 * @param int $min Minimum value
 * @param int $max Maximum value
 * @param bool $required Whether field is required
 * @return array Result with 'valid' boolean, 'sanitized' int/null, and 'message' string
 */
function validateNumericField($value, string $fieldName, int $min, int $max, bool $required = false): array
{
    $result = ['valid' => false, 'sanitized' => null, 'message' => ''];
    
    if ($value === null || $value === '') {
        if ($required) {
            $result['message'] = "$fieldName is required";
            return $result;
        }
        $result['valid'] = true;
        return $result;
    }
    
    if (!is_numeric($value)) {
        $result['message'] = "$fieldName must be a number";
        return $result;
    }
    
    $numValue = (int)$value;
    
    if ($numValue < $min || $numValue > $max) {
        $result['message'] = "$fieldName must be between $min and $max";
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $numValue;
    return $result;
}

/**
 * Validate text field
 *
 * @param mixed $value Value to validate
 * @param string $fieldName Field name for error messages
 * @param int $maxLength Maximum length
 * @param bool $required Whether field is required
 * @return array Result with 'valid' boolean, 'sanitized' string/null, and 'message' string
 */
function validateTextField($value, string $fieldName, int $maxLength, bool $required = false): array
{
    $result = ['valid' => false, 'sanitized' => null, 'message' => ''];
    
    if ($value === null || $value === '') {
        if ($required) {
            $result['message'] = "$fieldName is required";
            return $result;
        }
        $result['valid'] = true;
        return $result;
    }
    
    $value = trim((string)$value);
    
    if (strlen($value) > $maxLength) {
        $result['message'] = "$fieldName exceeds maximum length";
        return $result;
    }
    
    // Check for null bytes
    if (strpos($value, "\0") !== false) {
        $result['message'] = "$fieldName contains invalid characters";
        return $result;
    }
    
    $result['valid'] = true;
    $result['sanitized'] = $value;
    return $result;
}

/**
 * Validate datetime field
 *
 * @param mixed $value Value to validate
 * @param string $fieldName Field name for error messages
 * @param bool $required Whether field is required
 * @return array Result with 'valid' boolean, 'sanitized' string/null, and 'message' string
 */
function validateDateTimeField($value, string $fieldName, bool $required = false): array
{
    $result = ['valid' => false, 'sanitized' => null, 'message' => ''];
    
    if ($value === null || $value === '') {
        if ($required) {
            $result['message'] = "$fieldName is required";
            return $result;
        }
        $result['valid'] = true;
        return $result;
    }
    
    $value = trim((string)$value);
    
    // Try to parse as datetime
    $timestamp = strtotime($value);
    
    if ($timestamp === false) {
        $result['message'] = "$fieldName is not a valid datetime";
        return $result;
    }
    
    // Check if date is reasonable (not in far future)
    $now = time();
    $oneYearFromNow = $now + (365 * 24 * 60 * 60);
    
    if ($timestamp > $oneYearFromNow) {
        $result['message'] = "$fieldName is too far in the future";
        return $result;
    }
    
    // Convert to standard format
    $result['valid'] = true;
    $result['sanitized'] = date('Y-m-d H:i:s', $timestamp);
    return $result;
}

/**
 * Get and validate study
 *
 * @param Medoo $database Database connection
 * @param string $studyCode Study code
 * @return array|false Study data or false if invalid
 */
function getStudy(Medoo $database, string $studyCode)
{
    try {
        $study = $database->get('studies', [
            'studyID',
            'isEncrypted',
            'encryptionMode',
            'studyOwner',
            'dataCollectionActive'
        ], [
            'studyCode' => $studyCode
        ]);
        
        if (!$study) {
            return false;
        }
        
        // Check if data collection is active (if field exists)
        if (isset($study['dataCollectionActive']) && $study['dataCollectionActive'] != 1) {
            error_log("Submission attempt for inactive study: $studyCode");
            return false;
        }
        
        return $study;
        
    } catch (Exception $e) {
        error_log("Error retrieving study: " . $e->getMessage());
        return false;
    }
}

/**
 * Save submission to database
 *
 * @param Medoo $database Database connection
 * @param array $study Study data
 * @param array $data Validated submission data
 * @return bool Success status
 */
function saveSubmission(Medoo $database, array $study, array $data): bool
{
    try {
        // Get public key for encryption if needed
        $publicKey = null;
        if (!empty($study['isEncrypted'])) {
            $publicKey = $database->get('users', 'publicKey', [
                'userID' => $study['studyOwner']
            ]);
        }

        // Check if submission was pre-encrypted client-side
        $clientEncType = $data['encryptionType'] ?? null;
        $isPreEncrypted = ($clientEncType === 'e2e');

        $submissionTextToStore = $data['submissionText'];
        $passedVariablesToStore = $data['passedVariables'];

        if ($isPreEncrypted) {
            // Data arrives pre-encrypted from the browser — store as-is
        } elseif (!empty($study['isEncrypted']) && $publicKey) {
            // Fallback: server-side encryption if client didn't encrypt
            $encrypted = encryptMessageWithPublicKey($submissionTextToStore, $publicKey);
            if ($encrypted !== false) {
                $submissionTextToStore = $encrypted;
            } else {
                error_log("Failed to encrypt submission text for study {$study['studyID']}");
            }

            if ($passedVariablesToStore !== null) {
                $encrypted = encryptMessageWithPublicKey($passedVariablesToStore, $publicKey);
                if ($encrypted !== false) {
                    $passedVariablesToStore = $encrypted;
                } else {
                    error_log("Failed to encrypt passed variables for study {$study['studyID']}");
                }
            }
        }

        // Determine encryption type for this submission
        $encryptionType = 'NA';
        if ($isPreEncrypted) {
            $encryptionType = 'e2e';
        } elseif (!empty($study['isEncrypted']) && $publicKey) {
            $encryptionType = 'server';
        }

        $database->insert('submissions', [
            'participantID'    => $data['participantID'],
            'studyID'          => $study['studyID'],
            'submissionText'   => $submissionTextToStore,
            'numberMessages'   => $data['numberMessages'],
            'condition'        => $data['condition'],
            'passedVariables'  => $passedVariablesToStore,
            'startTime'        => $data['startTime'],
            'submissionTime'   => $data['endTime'],
            'duration'         => $data['duration'],
            'encryptionType'   => $encryptionType,
        ]);
        
        $insertedID = $database->id();
        
        if (!$insertedID) {
            error_log("Failed to insert submission for study {$study['studyID']}");
            return false;
        }
        
        error_log("Submission saved successfully: Study {$study['studyID']}, Participant {$data['participantID']}, ID $insertedID");
        
        return true;
        
    } catch (Exception $e) {
        error_log("Error saving submission: " . $e->getMessage());
        return false;
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Verify this is a POST request
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendResponse('error', 'Invalid request method', 405);
}

// Get and validate required fields
$participantIDValidation = validateParticipantID($_POST['participantID'] ?? null);
if (!$participantIDValidation['valid']) {
    sendResponse('error', $participantIDValidation['message'], 400);
}

$submissionTextValidation = validateSubmissionText($_POST['submissionText'] ?? null);
if (!$submissionTextValidation['valid']) {
    sendResponse('error', $submissionTextValidation['message'], 400);
}

$studyCodeValidation = validateStudyCode($_POST['studyCode'] ?? null);
if (!$studyCodeValidation['valid']) {
    sendResponse('error', $studyCodeValidation['message'], 400);
}

// Validate optional numeric fields
$numberMessagesValidation = validateNumericField(
    $_POST['numberMessages'] ?? null,
    'Number of messages',
    0,
    MAX_NUMBER_MESSAGES,
    false
);
if (!$numberMessagesValidation['valid']) {
    sendResponse('error', $numberMessagesValidation['message'], 400);
}

$durationValidation = validateNumericField(
    $_POST['duration'] ?? null,
    'Duration',
    0,
    MAX_DURATION,
    false
);
if (!$durationValidation['valid']) {
    sendResponse('error', $durationValidation['message'], 400);
}

// Validate optional text fields
$conditionValidation = validateTextField(
    $_POST['condition'] ?? null,
    'Condition',
    MAX_CONDITION_LENGTH,
    false
);
if (!$conditionValidation['valid']) {
    sendResponse('error', $conditionValidation['message'], 400);
}

$passedVariablesValidation = validateTextField(
    $_POST['passedVariables'] ?? null,
    'Passed variables',
    MAX_PASSED_VARIABLES_LENGTH,
    false
);
if (!$passedVariablesValidation['valid']) {
    sendResponse('error', $passedVariablesValidation['message'], 400);
}

// Validate datetime fields
$startTimeValidation = validateDateTimeField($_POST['startTime'] ?? null, 'Start time', false);
if (!$startTimeValidation['valid']) {
    sendResponse('error', $startTimeValidation['message'], 400);
}

$endTimeValidation = validateDateTimeField($_POST['endTime'] ?? null, 'End time', false);
if (!$endTimeValidation['valid']) {
    sendResponse('error', $endTimeValidation['message'], 400);
}

// Get and validate study
$study = getStudy($database, $studyCodeValidation['sanitized']);

if (!$study) {
    sendResponse('error', 'Invalid study code or data collection is not active', 400);
}

// Prepare validated data
$validatedData = [
    'participantID'    => $participantIDValidation['sanitized'],
    'submissionText'   => $submissionTextValidation['sanitized'],
    'numberMessages'   => $numberMessagesValidation['sanitized'],
    'condition'        => $conditionValidation['sanitized'],
    'passedVariables'  => $passedVariablesValidation['sanitized'],
    'startTime'        => $startTimeValidation['sanitized'],
    'endTime'          => $endTimeValidation['sanitized'],
    'duration'         => $durationValidation['sanitized'],
    'encryptionType'   => $_POST['encryptionType'] ?? null
];

// Save submission
if (!saveSubmission($database, $study, $validatedData)) {
    sendResponse('error', 'Failed to save submission', 500);
}

// Success response
sendResponse('success');
?>