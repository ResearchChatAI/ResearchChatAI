<?php
/**
 * messages-download.php
 *
 * Downloads study messages as CSV file after verifying user ownership.
 * Supports encrypted messages with private key decryption.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 */

declare(strict_types=1);

// Error reporting for development (disable in production)
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

// =============================================================================
// SESSION INITIALIZATION
// =============================================================================

// Disable HTTP caching before session starts
session_cache_limiter('nocache');
session_start();

// =============================================================================
// AUTHENTICATION CHECK
// =============================================================================

if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    http_response_code(401);
    exit('Unauthorized - please log in');
}

if (!isset($_SESSION['userID'])) {
    http_response_code(400);
    exit('Invalid session');
}

// =============================================================================
// SECURITY HEADERS
// =============================================================================

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
header('Expires: Tue, 01 Jan 2000 00:00:00 GMT');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

// Force OPcache to re-validate this script
if (function_exists('opcache_invalidate')) {
    opcache_invalidate(__FILE__, true);
}

// =============================================================================
// DEPENDENCIES
// =============================================================================

require_once __DIR__ . '/../MySQL/medoo.php';
require_once __DIR__ . '/../MySQL/medoo-Credentials.php';
require_once __DIR__ . '/../Util/crypto.php';

use Medoo\Medoo;
/** @var Medoo $database – defined in medoo-Credentials.php */

// =============================================================================
// CONSTANTS
// =============================================================================

// CSV columns in fixed order
define('CSV_COLUMNS', [
    'messageID',
    'participantID',
    'condition',
    'messageText',
    'messageDateTime',
    'senderType',
    'passedVariables',
    'encryptionType'
]);

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Send error response and exit
 *
 * @param string $message Error message
 * @param int $httpCode HTTP status code
 */
function sendError(string $message, int $httpCode = 400): void
{
    http_response_code($httpCode);
    exit($message);
}

/**
 * Validate CSV delimiter parameter
 *
 * @param string|null $sepParam Separator parameter from request
 * @return string CSV delimiter character
 */
function validateDelimiter(?string $sepParam): string
{
    if ($sepParam === null) {
        return ',';
    }
    
    $sep = strtolower(trim($sepParam));
    
    // Only allow comma or semicolon
    return in_array($sep, ['semicolon', ';'], true) ? ';' : ',';
}

/**
 * Verify study exists and user owns it
 *
 * @param Medoo $database Database connection
 * @param string $studyCode Study code
 * @param int $userID User ID
 * @return array|false Study data or false if not found/unauthorized
 */
function verifyStudyAccess(Medoo $database, string $studyCode, int $userID)
{
    try {
        // Get study with owner information
        $study = $database->get('studies', [
            'studyID',
            'studyOwner',
            'isEncrypted',
            'studyName'
        ], [
            'studyCode' => $studyCode
        ]);
        
        if (!$study) {
            return false;
        }
        
        // CRITICAL: Verify user owns this study
        $studyOwnerID = (int)$study['studyOwner'];
        
        if ($studyOwnerID !== $userID) {
            error_log("Authorization violation: User $userID attempted to download messages for study owned by $studyOwnerID");
            return false;
        }
        
        return $study;
        
    } catch (Exception $e) {
        error_log("Error verifying study access: " . $e->getMessage());
        return false;
    }
}

/**
 * Decrypt message fields if encryption is enabled
 *
 * @param array $row Message row
 * @param string|null $privateKey Private key for decryption
 * @return array Decrypted message row
 */
function decryptMessageRow(array $row, ?string $privateKey): array
{
    if ($privateKey === null || $privateKey === '') {
        return $row;
    }
    
    try {
        // Decrypt messageText
        if (isset($row['messageText']) && $row['messageText'] !== '') {
            $decrypted = decryptMessageWithPrivateKey($row['messageText'], $privateKey);
            if ($decrypted !== false && $decrypted !== $row['messageText']) {
                $row['messageText'] = $decrypted;
            }
        }
        
        // Decrypt passedVariables
        if (isset($row['passedVariables']) && $row['passedVariables'] !== '') {
            $decrypted = decryptMessageWithPrivateKey($row['passedVariables'], $privateKey);
            if ($decrypted !== false && $decrypted !== $row['passedVariables']) {
                $row['passedVariables'] = $decrypted;
            }
        }
        
    } catch (Exception $e) {
        error_log("Error decrypting message row: " . $e->getMessage());
    }
    
    return $row;
}

/**
 * Generate safe filename for CSV download
 *
 * @param string $studyCode Study code
 * @return string Safe filename
 */
function generateCsvFilename(string $studyCode): string
{
    // Sanitize study code to prevent path traversal
    $safeStudyCode = preg_replace('/[^a-zA-Z0-9_-]/', '', $studyCode);
    
    // Generate timestamp
    $timestamp = date('Y-m-d_H-i-s');
    
    return sprintf('researchChatAI-messages-%s-%s.csv', $safeStudyCode, $timestamp);
}

/**
 * Stream CSV data to output
 *
 * @param Medoo $database Database connection
 * @param array $study Study information
 * @param string $delimiter CSV delimiter
 * @param string|null $privateKey Private key for decryption
 */
function streamCsvData(Medoo $database, array $study, string $delimiter, ?string $privateKey): void
{
    // Open output stream
    $output = fopen('php://output', 'wb');
    
    if ($output === false) {
        sendError('Unable to open output stream', 500);
    }
    
    // Write UTF-8 BOM for Excel compatibility
    fwrite($output, "\xEF\xBB\xBF");
    
    // Write header row
    fputcsv($output, CSV_COLUMNS, $delimiter);
    
    try {
        // Query messages in chronological order
        $rows = $database->select('messages', CSV_COLUMNS, [
            'studyID' => $study['studyID'],
            'ORDER' => ['messageDateTime' => 'ASC']
        ]);
        
        $rowCount = 0;
        
        // Process and write each row
        foreach ($rows as $row) {
            // Decrypt if encryption is enabled
            if (!empty($study['isEncrypted'])) {
                $row = decryptMessageRow($row, $privateKey);
            }
            
            // Ensure fixed column order
            $line = [];
            foreach (CSV_COLUMNS as $col) {
                $line[] = $row[$col] ?? '';
            }
            
            fputcsv($output, $line, $delimiter);
            $rowCount++;
        }
        
        fclose($output);
        
        // Log successful download
        error_log("Messages CSV downloaded for study {$study['studyID']}: $rowCount rows");
        
    } catch (Exception $e) {
        error_log("Error streaming CSV data: " . $e->getMessage());
        fclose($output);
        sendError('Error generating CSV file', 500);
    }
}

// =============================================================================
// MAIN LOGIC
// =============================================================================

// Verify this is a GET request
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    sendError('Invalid request method', 405);
}

// Get and validate session user ID
$sessionUserID = (int)$_SESSION['userID'];

if ($sessionUserID <= 0) {
    sendError('Invalid session user ID', 400);
}

// Validate studyCode parameter
$studyCode = filter_input(INPUT_GET, 'studyCode', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

if (!$studyCode || trim($studyCode) === '') {
    sendError('Missing or invalid studyCode parameter', 400);
}

$studyCode = trim($studyCode);

// Verify study exists and user has access
$study = verifyStudyAccess($database, $studyCode, $sessionUserID);

if (!$study) {
    sendError('Invalid studyCode or you do not have permission to access this study', 403);
}

// Check for JSON format (used by client-side decryption CSV download)
$format = $_GET['format'] ?? 'csv';

if ($format === 'json') {
    // Return raw JSON rows (ciphertext for encrypted, plaintext for unencrypted)
    header('Content-Type: application/json; charset=utf-8');

    try {
        $rows = $database->select('messages', CSV_COLUMNS, [
            'studyID' => $study['studyID'],
            'ORDER' => ['messageDateTime' => 'ASC']
        ]);

        echo json_encode($rows ?: [], JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        error_log("Error fetching messages JSON: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Failed to fetch messages']);
    }
    exit;
}

// Validate and get CSV delimiter
$delimiter = validateDelimiter($_GET['sep'] ?? null);

// Decryption now happens client-side; pass null so no server-side decryption occurs
$privateKey = null;

// Generate safe filename
$filename = generateCsvFilename($studyCode);

// Set CSV response headers
header('Access-Control-Allow-Origin: *');
header('Content-Type: text/csv; charset=utf-8');
header("Content-Disposition: attachment; filename=\"$filename\"");

// Stream CSV data (no server-side decryption)
streamCsvData($database, $study, $delimiter, $privateKey);

exit;