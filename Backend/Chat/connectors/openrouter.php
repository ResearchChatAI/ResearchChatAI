<?php
declare(strict_types=1);

/* ------------------------------------------------------------------
 *  connectors/openrouter.php  –  ResearchChatAI
 *
 *  Builds the connector configuration for the OpenRouter provider.
 *
 *  Expects in scope (set by prepareChat.php before including):
 *    $study      – study row from DB (with decrypted keys if encrypted)
 *    $streamFlag – bool, whether streaming is requested
 *
 *  Sets:
 *    $connector  – fully configured connector array
 *
 *  OpenRouter uses the standard Chat Completions format but requires
 *  HTTP-Referer and X-Title headers for attribution. The message
 *  normalization (flattening multi-part content) is handled during
 *  payload post-processing in prepareChat.php via normalizeForOpenRouter().
 * 
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 * ------------------------------------------------------------------ */

$connector = [
    'version' => '1',
    'request' => [
        'url'       => 'https://openrouter.ai/api/v1/chat/completions',
        'method'    => 'POST',
        'timeoutMs' => 30000,
        'auth'      => ['type' => 'bearer', 'token' => $study['openrouterApiKey'] ?? ''],
        'headers'   => [
            'Content-Type' => 'application/json',
            'HTTP-Referer' => 'researchchatai',
            'X-Title'      => 'researchchatai',
        ],
        'stream' => $streamFlag,
    ],
    'aiPayload' => [
        'model'       => $study['openrouterModel'] ?? 'nvidia/llama-3.1-nemotron-70b-instruct',
        'temperature' => (float) ($study['openrouterTemperature'] ?? 0.9),
        'seed'        => 1106,
        'max_tokens'  => 1500,
        'stream'      => $streamFlag,
    ],
    'history'  => ['mode' => 'array'],
    'response' => [
        'resultPath' => '$.choices[0].message.content',
    ],
];

/* ---- Response limit (optional, per study) ----
 *
 * Studies created before this setting existed have no value. They keep the
 * original limit and timeout above, so they send exactly the same request
 * as before. Only a study with a value gets its own limit, plus the longer
 * timeout that models which think before answering need.
 *
 * The value is read here on its own (and not added to the column list in
 * prepareChat.php) so that a database without the column simply behaves
 * as before instead of failing.
 */

$maxTokensSetting = $study['openrouterMaxTokens'] ?? null;
if ($maxTokensSetting === null && isset($database, $study['studyID'])) {
    try {
        $maxTokensSetting = $database->get('studies', 'openrouterMaxTokens', ['studyID' => $study['studyID']]);
    } catch (\Throwable $e) {
        $maxTokensSetting = null;
    }
}

if (is_numeric($maxTokensSetting) && (int) $maxTokensSetting > 0) {
    $connector['aiPayload']['max_tokens'] = min((int) $maxTokensSetting, 128000);
    $connector['request']['timeoutMs']    = 120000;
}
