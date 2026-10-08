<?php
declare(strict_types=1);

/* ------------------------------------------------------------------
 *  saveResponse.php  –  ResearchChatAI
 *
 *  Third step of the three-phase streaming architecture:
 *    1. prepareChat.php  → saves participant message, builds AI config
 *    2. Node stream-proxy → pipes AI response to browser (long-lived)
 *    3. saveResponse.php  → persists AI response to DB  ← YOU ARE HERE
 *
 *  Called by the frontend JS after the SSE stream completes.
 *  Receives the fully-accumulated AI response text and saves it.
 *  This is a fast, non-blocking request (~50-150 ms).
 *
 *  Security notes:
 *  - Input validation mirrors prepareChat.php for consistency.
 *  - Message size is capped to prevent abuse.
 *  - No internal details are leaked in error responses.
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

/* Handle CORS preflight */
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

/* ------------------------------------------------------------------
 *  Dependencies
 * ------------------------------------------------------------------ */
require_once('../MySQL/medoo-Credentials.php');
require_once('../Util/crypto.php');

/* ------------------------------------------------------------------
 *  POST payload  (with input validation)
 * ------------------------------------------------------------------ */
$studyCode       = $_POST['studyCode'] ?? null;
$participantID   = $_POST['participantID'] ?? null;
$message         = $_POST['message'] ?? '';
$reasoning       = $_POST['reasoning'] ?? '';
$condition       = $_POST['condition'] ?? -1;
$passedVariables = $_POST['passedVariables'] ?? '';

/* --- Sanitize / validate (same rules as prepareChat.php) --- */

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

$condition = is_numeric($condition) ? (int) $condition : -1;

if (trim((string) $message) === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Empty AI message — nothing to save']);
    exit;
}

/* Guard against oversized messages (max ~1 MB — well above any normal AI response) */
if (strlen((string) $message) > 1024 * 1024) {
    http_response_code(413);
    echo json_encode(['error' => 'AI message too large']);
    exit;
}

/* ------------------------------------------------------------------
 *  Study lookup  (minimal — only fields needed for encryption)
 * ------------------------------------------------------------------ */
$study = $database->get('studies', [
    'studyID',
    'studyOwner',
    'isEncrypted'
], ['studyCode' => $studyCode]);

if (!$study) {
    http_response_code(404);
    echo json_encode(['error' => 'Study not found']);
    exit;
}

$publicKey = null;
if (!empty($study['isEncrypted'])) {
    $publicKey = $database->get('users', 'publicKey', ['userID' => $study['studyOwner']]);
}

/* ------------------------------------------------------------------
 *  Encrypt if needed & persist
 * ------------------------------------------------------------------ */
$aiMsgToStore = (!empty($study['isEncrypted']) && $publicKey)
    ? encryptMessageWithPublicKey($message, $publicKey)
    : $message;

/* The reply is stored in messages.messageText, which holds 65,535 bytes. The database
   would cut off a longer reply, and an encrypted one that is cut off can no longer be
   decrypted. So a reply that does not fit is shortened until it does, with a note at
   the end. The participant has already seen the whole reply. */
$messageFieldBytes = 65535;
if (strlen($aiMsgToStore) > $messageFieldBytes) {
    $note = "\n\n[Shortened by ResearchChatAI: this reply had " . mb_strlen($message, 'UTF-8')
          . " characters, too many to store in full. The participant saw the complete reply.]";
    $keep = (int) (strlen($message) * $messageFieldBytes / strlen($aiMsgToStore)) - strlen($note) - 64;
    for ($attempt = 0; $attempt < 8 && $keep > 0; $attempt++) {
        $shortened    = mb_strcut($message, 0, $keep, 'UTF-8') . $note;
        $aiMsgToStore = (!empty($study['isEncrypted']) && $publicKey)
            ? encryptMessageWithPublicKey($shortened, $publicKey)
            : $shortened;
        if (strlen($aiMsgToStore) <= $messageFieldBytes) break;
        $keep -= 1024;
    }
}

$aiVarsToStore = (!empty($study['isEncrypted']) && $publicKey)
    ? encryptMessageWithPublicKey($passedVariables, $publicKey)
    : $passedVariables;

$encryptionType = (!empty($study['isEncrypted']) && $publicKey) ? 'server' : 'NA';

$database->insert('messages', [
    'participantID'   => $participantID,
    'studyID'         => $study['studyID'],
    'messageText'     => $aiMsgToStore,
    'senderType'      => 'AI',
    'messageDateTime' => date('Y-m-d H:i:s'),
    'condition'       => $condition,
    'passedVariables' => $aiVarsToStore,
    'encryptionType'  => $encryptionType,
]);

echo json_encode(['ok' => true]);
