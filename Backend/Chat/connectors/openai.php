<?php
declare(strict_types=1);

/* ------------------------------------------------------------------
 *  connectors/openai.php  –  ResearchChatAI
 *
 *  Builds the connector configuration for the OpenAI provider.
 *
 *  Expects in scope (set by prepareChat.php before including):
 *    $study      – study row from DB (with decrypted keys if encrypted)
 *    $streamFlag – bool, whether streaming is requested
 *
 *  Sets:
 *    $connector  – fully configured connector array
 *
 *  Handles:
 *    - Chat Completions API (/v1/chat/completions) for most models
 *    - Responses API (/v1/responses) for GPT-5+ models
 *    - Reasoning effort parameter for supported models
 *    - Temperature suppression for models that don't support it
 *    - Seed removal for GPT-5+ (not supported)
 *
 *  Models added after GPT-5 (GPT-5.6, GPT-6) are described in
 *  ../openai-models.php and handled by their own block below. The code
 *  after that block is the original logic for the older models and must
 *  keep producing exactly the same request for them.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 * ------------------------------------------------------------------ */

$model   = $study['openaiModel'] ?? 'gpt-4o-mini';
$modelLc = strtolower($model);
$apiKey  = $study['openaiApiKey'] ?? '';
$temp    = (float) ($study['openaiTemperature'] ?? 0.9);
$effort  = $study['openaiReasoningEffort'] ?? '';
$isGpt5  = str_starts_with($modelLc, 'gpt-5');

/* ---- Models added after GPT-5: described in openai-models.php ---- */

$openaiModels = require __DIR__ . '/../openai-models.php';
$modelInfo    = $openaiModels[$model] ?? null;

if ($modelInfo !== null && $modelInfo['group'] === 'current') {
    /* An effort this model doesn't accept (e.g. one saved for another model)
       would make every request fail, so the model's own default is used instead */
    if (!in_array($effort, $modelInfo['efforts'], true)) {
        $effort = '';
    }

    $aiPayload = [
        'model'  => $model,
        'stream' => $streamFlag,
    ];

    if ($effort === 'none') {
        /* No reasoning, so there is no summary to ask for */
        $aiPayload['reasoning'] = ['effort' => 'none'];
    } else {
        $aiPayload['reasoning'] = ['summary' => 'auto'];
        if ($effort !== '') {
            $aiPayload['reasoning']['effort'] = $effort;
        }
    }

    /* These models only accept a temperature while reasoning is switched off */
    if ($modelInfo['temperature'] === 'effort-none' && $effort === 'none') {
        $aiPayload['temperature'] = $temp;
    }

    $connector = [
        'version' => '1',
        'request' => [
            'url'       => 'https://api.openai.com/v1/responses',
            'method'    => 'POST',
            /* Deep reasoning can take minutes before the first byte arrives */
            'timeoutMs' => in_array($effort, ['high', 'xhigh'], true) ? 300000 : 120000,
            'auth'      => ['type' => 'bearer', 'token' => $apiKey],
            'headers'   => ['Content-Type' => 'application/json'],
            'stream'    => $streamFlag,
        ],
        'aiPayload' => $aiPayload,
        'history'   => ['mode' => 'array'],
        'response'  => [
            'resultPath'    => '$.output_text',
            'reasoningPath' => '$.reasoning.summary',
            'stream'        => [
                'linePrefix' => 'data: ',
                'doneSignal' => '[DONE]',
                'extractors' => [
                    ['filter' => ['type' => 'response.output_text.delta'], 'tokenPath' => '$.delta'],
                    ['filter' => ['type' => 'response.completed'],         'tokenPath' => '$.response.output_text'],
                ],
            ],
        ],
    ];

    return;
}

/* ---- Older models: original logic, unchanged ---- */

/* ---- Base connector (Chat Completions API) ---- */

$connector = [
    'version' => '1',
    'request' => [
        'url'       => 'https://api.openai.com/v1/chat/completions',
        'method'    => 'POST',
        'timeoutMs' => 120000,
        'auth'      => ['type' => 'bearer', 'token' => $apiKey],
        'headers'   => ['Content-Type' => 'application/json'],
        'stream'    => $streamFlag,
    ],
    'aiPayload' => [
        'model'       => $model,
        'temperature' => $temp,
        'seed'        => 1106,
        'stream'      => $streamFlag,
    ],
    'history'  => ['mode' => 'array'],
    'response' => [
        'resultPath'    => '$.choices[0].message.content',
        'reasoningPath' => '$.choices[0].message.reasoning',
    ],
];

/* ---- GPT-5+: switch to the Responses API ---- */

if ($isGpt5) {
    $connector['request']['url'] = 'https://api.openai.com/v1/responses';

    $summaryMode = empty($effort) ? 'auto' : 'detailed';
    $connector['aiPayload']['reasoning'] = array_merge(
        $connector['aiPayload']['reasoning'] ?? [],
        ['summary' => $summaryMode]
    );

    $connector['response']['resultPath']   = '$.output_text';
    $connector['response']['reasoningPath'] = '$.reasoning.summary';
    $connector['response']['stream'] = [
        'linePrefix' => 'data: ',
        'doneSignal' => '[DONE]',
        'extractors' => [
            ['filter' => ['type' => 'response.output_text.delta'], 'tokenPath' => '$.delta'],
            ['filter' => ['type' => 'response.completed'],         'tokenPath' => '$.response.output_text'],
        ],
    ];

    /* GPT-5 doesn't support the seed parameter */
    unset($connector['aiPayload']['seed']);
}

/* ---- Reasoning effort (Responses API only) ---- */

if (!empty($effort)) {
    $endpoint = strtolower($connector['request']['url']);
    if (strpos($endpoint, '/v1/responses') !== false) {
        $connector['aiPayload']['reasoning'] = array_merge(
            $connector['aiPayload']['reasoning'] ?? [],
            ['effort' => $effort]
        );
    }
}

/* ---- Temperature: suppress for models that don't support non-default ---- */

if ($isGpt5 && abs($temp - 1.0) > 1e-9) {
    unset($connector['aiPayload']['temperature']);
}
