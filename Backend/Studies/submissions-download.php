<?php
/**
 * submissions-download.php
 *
 * Downloads study submissions as CSV file after verifying user ownership.
 * Supports encrypted submissions with private key decryption and HTML stripping.
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
    'submissionID',
    'participantID',
    'condition',
    'submissionText',
    'submissionTime',
    'startTime',
    'duration',
    'numberMessages',
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
            error_log("Authorization violation: User $userID attempted to download submissions for study owned by $studyOwnerID");
            return false;
        }
        
        return $study;
        
    } catch (Exception $e) {
        error_log("Error verifying study access: " . $e->getMessage());
        return false;
    }
}

/**
 * Decrypt submission fields if encryption is enabled
 *
 * @param array $row Submission row
 * @param string|null $privateKey Private key for decryption
 * @return array Decrypted submission row
 */
function decryptSubmissionRow(array $row, ?string $privateKey): array
{
    if ($privateKey === null || $privateKey === '') {
        return $row;
    }
    
    try {
        // Decrypt submissionText
        if (isset($row['submissionText']) && $row['submissionText'] !== '') {
            $decrypted = decryptMessageWithPrivateKey($row['submissionText'], $privateKey);
            if ($decrypted !== false && $decrypted !== $row['submissionText']) {
                $row['submissionText'] = $decrypted;
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
        error_log("Error decrypting submission row: " . $e->getMessage());
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
    
    return sprintf('researchChatAI-submissions-%s-%s.csv', $safeStudyCode, $timestamp);
}

/**
 * Stream CSV data to output
 *
 * @param Medoo $database Database connection
 * @param array $study Study information
 * @param string $delimiter CSV delimiter
 * @param bool $stripHtml Whether to strip HTML from submission text
 * @param string|null $privateKey Private key for decryption
 */
function streamCsvData(Medoo $database, array $study, string $delimiter, bool $stripHtml, ?string $privateKey): void
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
        // Query submissions in chronological order
        $rows = $database->select('submissions', CSV_COLUMNS, [
            'studyID' => $study['studyID'],
            'ORDER' => ['submissionTime' => 'ASC']
        ]);
        
        $rowCount = 0;
        
        // Process and write each row
        foreach ($rows as $row) {
            // Decrypt if encryption is enabled
            if (!empty($study['isEncrypted'])) {
                $row = decryptSubmissionRow($row, $privateKey);
            }
            
            // Ensure fixed column order and apply HTML stripping
            $line = [];
            foreach (CSV_COLUMNS as $col) {
                $val = $row[$col] ?? '';
                
                // Strip HTML tags from submission text if requested
                if ($stripHtml && $col === 'submissionText') {
                    $val = strip_tags($val);
                }
                
                $line[] = $val;
            }
            
            fputcsv($output, $line, $delimiter);
            $rowCount++;
        }
        
        fclose($output);
        
        // Log successful download
        error_log("Submissions CSV downloaded for study {$study['studyID']}: $rowCount rows");
        
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

// Validate and get CSV delimiter
$delimiter = validateDelimiter($_GET['sep'] ?? null);

// Check for JSON format (used by client-side decryption CSV download)
$format = $_GET['format'] ?? 'csv';

if ($format === 'json') {
    // Return raw JSON rows (ciphertext for encrypted, plaintext for unencrypted)
    header('Content-Type: application/json; charset=utf-8');

    try {
        $rows = $database->select('submissions', CSV_COLUMNS, [
            'studyID' => $study['studyID'],
            'ORDER' => ['submissionTime' => 'ASC']
        ]);

        echo json_encode($rows ?: [], JSON_UNESCAPED_UNICODE);
    } catch (Exception $e) {
        error_log("Error fetching submissions JSON: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Failed to fetch submissions']);
    }
    exit;
}

// Validate HTML stripping option
$stripHtml = filter_input(INPUT_GET, 'stripHtml', FILTER_VALIDATE_BOOLEAN) ?: false;

// Decryption now happens client-side; pass null so no server-side decryption occurs
$privateKey = null;

// Generate safe filename
$filename = generateCsvFilename($studyCode);

// Set CSV response headers
header('Access-Control-Allow-Origin: *');
header('Content-Type: text/csv; charset=utf-8');
header("Content-Disposition: attachment; filename=\"$filename\"");

// Stream CSV data (no server-side decryption)
streamCsvData($database, $study, $delimiter, $stripHtml, $privateKey);

exit;