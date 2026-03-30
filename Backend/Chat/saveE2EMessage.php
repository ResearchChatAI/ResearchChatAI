<?php
declare(strict_types=1);

/* ------------------------------------------------------------------
 *  saveE2EMessage.php  –  ResearchChatAI
 *
 *  Persists a pre-encrypted message (participant or AI) to the DB.
 *  Used exclusively in End-to-End encryption mode where all encryption
 *  happens client-side. The server never sees plaintext.
 *
 *  Expects POST parameters:
 *    studyCode       – alphanumeric study identifier
 *    participantID   – alphanumeric participant identifier
 *    encryptedMsg    – client-encrypted message (e2e:b64:b64:b64 format)
 *    senderType      – "Participant" or "AI"
 *    condition       – experimental condition number
 *    passedVariables – encrypted passed variables (optional)
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 * ------------------------------------------------------------------ */

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-cache, no-store');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

require_once('../MySQL/medoo-Credentials.php');

/* ------------------------------------------------------------------
 *  Validate input
 * ------------------------------------------------------------------ */
$studyCode       = $_POST['studyCode'] ?? null;
$participantID   = $_POST['participantID'] ?? null;
$encryptedMsg    = $_POST['encryptedMsg'] ?? '';
$senderType      = $_POST['senderType'] ?? '';
$condition       = $_POST['condition'] ?? -1;
$passedVariables = $_POST['passedVariables'] ?? '';
$encryptionType  = $_POST['encryptionType'] ?? 'e2e';

if (!$studyCode || !preg_match('/^[a-zA-Z0-9]+$/', (string) $studyCode)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing or invalid studyCode']);
    exit;
}

if (!$participantID || !preg_match('/^[a-zA-Z0-9_\-]{1,64}$/', (string) $participantID)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing or invalid participantID']);
    exit;
}

if (!in_array($senderType, ['Participant', 'AI'], true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid senderType']);
    exit;
}

if (trim($encryptedMsg) === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Empty encrypted message']);
    exit;
}

/* Guard against oversized payloads (max ~2 MB) */
if (strlen($encryptedMsg) > 2 * 1024 * 1024) {
    http_response_code(413);
    echo json_encode(['error' => 'Message too large']);
    exit;
}

$condition = is_numeric($condition) ? (int) $condition : -1;

/* ------------------------------------------------------------------
 *  Verify study exists and uses E2E encryption
 * ------------------------------------------------------------------ */
$study = $database->get('studies', [
    'studyID',
    'encryptionMode',
], ['studyCode' => $studyCode]);

if (!$study) {
    http_response_code(404);
    echo json_encode(['error' => 'Study not found']);
    exit;
}

if (($study['encryptionMode'] ?? 'server') !== 'e2e') {
    http_response_code(400);
    echo json_encode(['error' => 'Study does not use end-to-end encryption']);
    exit;
}

/* ------------------------------------------------------------------
 *  Store pre-encrypted message (no server-side encryption needed)
 * ------------------------------------------------------------------ */
$database->insert('messages', [
    'participantID'   => $participantID,
    'studyID'         => $study['studyID'],
    'messageText'     => $encryptedMsg,
    'senderType'      => $senderType,
    'messageDateTime' => date('Y-m-d H:i:s'),
    'condition'       => $condition,
    'passedVariables' => $passedVariables,
    'encryptionType'  => in_array($encryptionType, ['e2e', 'NA'], true) ? $encryptionType : 'e2e',
]);

echo json_encode(['ok' => true]);
