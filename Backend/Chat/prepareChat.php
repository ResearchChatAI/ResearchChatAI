<?php
declare(strict_types=1);

/* ------------------------------------------------------------------
 *  prepareChat.php  –  ResearchChatAI
 *
 *  Receives a participant message, saves it, and prepares a one-time
 *  config file for the Node proxy to call the AI provider.
 *
 *  Three-phase architecture:
 *    1. prepareChat.php  → this file (saves user msg, returns token)
 *    2. stream-proxy.js  → Node proxy (pipes AI response to browser)
 *    3. saveResponse.php → persists AI response to DB
 *
 *  The PHP worker is freed in ~150 ms. The Node proxy holds the
 *  long-lived connection to the AI provider (seconds to minutes).
 *
 *  Provider-specific logic lives in connectors/:
 *    connectors/openai.php      – OpenAI (Chat Completions + Responses API)
 *    connectors/openrouter.php  – OpenRouter
 *    connectors/custom.php      – researcher-defined JSON connector
 *
 *  Shared helper functions live in payload.php (same directory).
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

/* ------------------------------------------------------------------
 *  Dependencies
 * ------------------------------------------------------------------ */
require_once('../MySQL/medoo-Credentials.php');
require_once('../Util/crypto.php');
require_once(__DIR__ . '/payload.php');

use Medoo\Medoo;


/* ==================================================================
 *  1. VALIDATE INPUT
 * ================================================================== */

$studyID         = $_POST['studyID'] ?? null;
$participantID   = $_POST['participantID'] ?? null;
$chatHistoryRaw  = $_POST['chatHistory'] ?? '[]';
$messageText     = $_POST['messageText'] ?? null;
$uploadedFile    = $_POST['filename'] ?? null;
$studyCode       = $_POST['studyCode'] ?? null;
$condition       = $_POST['condition'] ?? -1;
$passedVariables = $_POST['passedVariables'] ?? '';
$streamFlag      = isset($_POST['stream']) && ($_POST['stream'] === '1' || $_POST['stream'] === 1);

/* studyCode: alphanumeric only */
if (!$studyCode || !preg_match('/^[a-zA-Z0-9]+$/', (string) $studyCode)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing or invalid studyCode']);
    exit;
}

/* participantID: alphanumeric + underscore/dash, max 64 chars */
if (!$participantID || !preg_match('/^[a-zA-Z0-9_\-]{1,64}$/', (string) $participantID)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing or invalid participantID']);
    exit;
}

$condition = is_numeric($condition) ? (int) $condition : -1;

if ((is_null($messageText) || trim((string) $messageText) === '') && empty($uploadedFile)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing messageText or uploaded file']);
    exit;
}

/* Reject oversized chat history (max ~2 MB) */
if (strlen($chatHistoryRaw) > 2 * 1024 * 1024) {
    http_response_code(413);
    echo json_encode(['error' => 'Chat history too large']);
    exit;
}

/* Build image URL if a file was uploaded */
$baseURL  = $env['BASE_URL'] ?? 'https://researchchatai.com/';
$imageUrl = '';
if (!empty($uploadedFile)) {
    $safeFile = preg_replace('/[^A-Za-z0-9.\-_]/', '_', basename($uploadedFile));
    $imageUrl = rtrim($baseURL, '/') . '/Uploads/' . $safeFile;
}


/* ==================================================================
 *  2. LOAD STUDY & DECRYPT SECRETS
 * ================================================================== */

$study = $database->get('studies', [
    'studyID',
    'modelProvider',
    'openaiApiKey',
    'studyOwner',
    'openaiModel',
    'openaiTemperature',
    'openaiReasoningEffort',
    'openrouterApiKey',
    'openrouterModel',
    'openrouterTemperature',
    'customConnectorConfiguration',
    'customConnectorEnableStreaming',
    'isEncrypted',
], ['studyCode' => $studyCode]);

if (!$study) {
    http_response_code(404);
    echo json_encode(['error' => 'Study not found']);
    exit;
}

$publicKey = null;
if (!empty($study['isEncrypted'])) {
    $study['openaiApiKey']          = decryptString($study['openaiApiKey'] ?? '');
    $study['openrouterApiKey']      = decryptString($study['openrouterApiKey'] ?? '');
    $study['openaiReasoningEffort'] = decryptString($study['openaiReasoningEffort'] ?? '');
    $study['customConnectorConfiguration'] = decryptString($study['customConnectorConfiguration'] ?? '');
    $publicKey = $database->get('users', 'publicKey', ['userID' => $study['studyOwner']]);
}

/* Custom connectors may force streaming on */
if (($study['modelProvider'] ?? '') === 'custom' && !empty($study['customConnectorEnableStreaming'])) {
    $streamFlag = true;
}


/* ==================================================================
 *  3. LOAD CONNECTOR  (provider-specific config)
 *
 *  Each connector file sets $connector — an array describing the
 *  API endpoint, authentication, payload template, and response paths.
 *  See connectors/openai.php for the full schema documentation.
 * ================================================================== */

$providerFile = match ($study['modelProvider'] ?? 'custom') {
    'openai'     => 'openai.php',
    'openrouter' => 'openrouter.php',
    default      => 'custom.php',
};
require(__DIR__ . '/connectors/' . $providerFile);
/* $connector is now set */


/* ==================================================================
 *  4. BUILD CHAT HISTORY
 * ================================================================== */

$chatHistory = json_decode($chatHistoryRaw, true) ?: [];

$currentUser = ['role' => 'user', 'content' => []];
if (!is_null($messageText) && trim($messageText) !== '') {
    $currentUser['content'][] = ['type' => 'text', 'text' => $messageText];
}
if ($imageUrl !== '') {
    $currentUser['content'][] = ['type' => 'image_url', 'image_url' => ['url' => $imageUrl]];
}
if (!empty($currentUser['content'])) {
    $chatHistory[] = $currentUser;
}

$vars = [
    'chatHistory'   => $chatHistory,
    'messageText'   => $messageText,
    'participantID' => $participantID,
    'studyID'       => $studyID,
];


/* ==================================================================
 *  5. PERSIST PARTICIPANT MESSAGE
 * ================================================================== */

$displayText      = is_null($messageText) ? '' : $messageText;
$messageTextForDb = $displayText . ($uploadedFile ? ' [[Attachment: ' . basename($uploadedFile) . ']]' : '');

$msgToStore = (!empty($study['isEncrypted']) && $publicKey)
    ? encryptMessageWithPublicKey($messageTextForDb, $publicKey)
    : $messageTextForDb;

$passedVarsToStore = (!empty($study['isEncrypted']) && $publicKey)
    ? encryptMessageWithPublicKey($passedVariables, $publicKey)
    : $passedVariables;

$encryptionType = (!empty($study['isEncrypted']) && $publicKey) ? 'server' : 'NA';

$database->insert('messages', [
    'participantID'   => $participantID,
    'studyID'         => $study['studyID'],
    'messageText'     => $msgToStore,
    'senderType'      => 'Participant',
    'messageDateTime' => date('Y-m-d H:i:s'),
    'condition'       => $condition,
    'passedVariables' => $passedVarsToStore,
    'encryptionType'  => $encryptionType,
]);
$messageID = $database->id();

/* Persist uploaded file metadata (if any) */
if ($uploadedFile) {
    $uploadDir = '../../Uploads/';
    $filePath  = $uploadDir . basename($uploadedFile);
    if (file_exists($filePath)) {
        $fileSize = filesize($filePath);
        $fileType = mime_content_type($filePath) ?: '';
        $width = $height = null;
        if (strpos($fileType, 'image/') === 0 && ($dims = getimagesize($filePath))) {
            [$width, $height] = $dims;
        }
        $database->insert('files', [
            'studyID'      => $study['studyID'],
            'researcherID' => $study['studyOwner'],
            'messageID'    => $messageID,
            'fileName'     => basename($uploadedFile),
            'filePath'     => $filePath,
            'fileSize'     => $fileSize,
            'fileType'     => $fileType,
            'width'        => $width,
            'height'       => $height,
            'uploadedAt'   => date('Y-m-d H:i:s'),
            'deleted'      => 0,
        ]);
    }
}


/* ==================================================================
 *  6. BUILD PAYLOAD & WRITE CONFIG FILE
 *
 *  Resolve the connector template into a concrete HTTP request,
 *  apply provider-specific normalization, validate the target URL,
 *  and write everything to a one-time config file. The Node proxy
 *  reads + deletes this file when the frontend sends the token.
 * ================================================================== */

$req     = renderTemplate($connector['request'], $vars);
$payload = buildPayload($connector, $vars);

if ($streamFlag) {
    $payload['stream'] = true;
}

/* Provider-specific payload normalization (URL-driven, not provider-name-driven,
   so custom connectors pointing at these APIs also get normalized correctly) */
$targetUrl = $req['url'] ?? '';

if (str_contains($targetUrl, 'openrouter.ai') && isset($payload['messages']) && is_array($payload['messages'])) {
    $payload['messages'] = normalizeForOpenRouter($payload['messages']);
}

if (strpos($targetUrl, '/v1/responses') !== false && isset($payload['messages'])) {
    $payload['input'] = messagesToResponsesInput($payload['messages'], $payload['system'] ?? null);
    unset($payload['messages'], $payload['system']);
}

/* SSRF protection: validate the upstream URL */
try {
    validateUpstreamUrl($targetUrl);
} catch (RuntimeException $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
    exit;
}

/* Resolve auth config into plain HTTP headers */
$headers = $req['headers'] ?? [];
if (!empty($req['auth']) && is_array($req['auth'])) {
    $headers = resolveAuthHeaders($headers, $req['auth']);
}

/* Generate a cryptographically secure one-time token */
$token     = bin2hex(random_bytes(32));
$configDir = $env['STREAM_CONFIG_DIR'] ?? '/tmp/rcai_stream_configs';

if (!is_dir($configDir)) {
    mkdir($configDir, 0700, true);
}

$configFile = $configDir . '/' . $token . '.json';
$configData = [
    'createdAt' => time(),
    'url'       => $targetUrl,
    'method'    => $req['method'] ?? 'POST',
    'headers'   => $headers,
    'payload'   => $payload,
    'timeoutMs' => (int) ($req['timeoutMs'] ?? 60000),
];

error_log("[SERVER DEBUG] Payload: " . json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
error_log("CONFIG DIR: " . $configDir);
error_log("CONFIG PATH: " . $configFile);
error_log("DIR EXISTS: " . (is_dir($configDir) ? 'YES' : 'NO'));
error_log("DIR WRITABLE: " . (is_writable($configDir) ? 'YES' : 'NO'));

$written = file_put_contents($configFile, json_encode($configData, JSON_UNESCAPED_UNICODE), LOCK_EX);
if ($written === false) {
    error_log('[ResearchChatAI] Failed to write config: ' . $configFile);
    http_response_code(500);
    echo json_encode(['error' => 'Failed to prepare AI request']);
    exit;
}
chmod($configFile, 0600);

error_log("WRITE RESULT: " . (file_exists($configFile) ? 'FILE CREATED' : 'FILE NOT CREATED'));


/* ==================================================================
 *  7. RESPOND TO FRONTEND
 *
 *  Return the one-time token. The frontend sends this to the Node
 *  proxy, which reads the config file and calls the AI provider.
 *  resultPath/reasoningPath tell the frontend how to extract the
 *  AI message from the raw JSON response (non-streaming only).
 * ================================================================== */

echo json_encode([
    'mode'                => $streamFlag ? 'stream' : 'request',
    'requestToken'        => $token,
    'studyID'             => $study['studyID'],
    'resultPath'          => $connector['response']['resultPath'] ?? null,
    'reasoningPath'       => $connector['response']['reasoningPath'] ?? null,
    'extractors'          => $connector['response']['stream']['extractors'] ?? null,
    'reasoningExtractors' => $connector['response']['stream']['reasoningExtractors'] ?? null,
]);
