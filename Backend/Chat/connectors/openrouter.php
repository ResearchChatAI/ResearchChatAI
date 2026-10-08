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
        'timeoutMs' => 120000,
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
        /* Longest reply the model may produce, thinking included. OpenRouter
           lowers the value by itself for models that cannot produce this much. */
        'max_tokens'  => 16000,
        'stream'      => $streamFlag,
    ],
    'history'  => ['mode' => 'array'],
    'response' => [
        'resultPath' => '$.choices[0].message.content',
    ],
];
