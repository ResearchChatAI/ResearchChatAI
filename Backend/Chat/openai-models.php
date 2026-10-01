<?php
declare(strict_types=1);

/* ------------------------------------------------------------------
 *  openai-models.php  –  ResearchChatAI
 *
 *  The OpenAI models that can be selected in the study settings and
 *  what each of them supports. One entry per model ID, in the order
 *  they appear in the dropdown.
 *
 *  Used by:
 *    connectors/openai.php     – builds the API request for 'current' models
 *    chat-backend-create.php   – model dropdown, reasoning effort options, notes
 *
 *  Keys per model:
 *    label         Name shown in the dropdown.
 *    group         'current' or 'older' (dropdown group).
 *    api           'responses' (/v1/responses) or 'chat' (/v1/chat/completions).
 *    efforts       Reasoning effort values the model accepts ([] = no reasoning setting).
 *    temperature   When the study's temperature is sent to OpenAI:
 *                    'always'        with every request
 *                    'effort-none'   only when reasoning effort is "none"
 *                    'never'         the model does not accept a temperature
 *                    'default-only'  only when it is exactly 1.0
 *    shutdown      Date (YYYY-MM-DD) on which OpenAI switches the model off, or null.
 *    verification  true if OpenAI asks for a verified organization.
 *
 *  IMPORTANT: models in the 'older' group are listed here only so the
 *  editor can show them. Their requests are still built by the original
 *  code in connectors/openai.php. That code must stay as it is: studies
 *  that already use these models have to keep sending exactly the same
 *  request (replicability).
 *
 *  To add a model, add an entry with group 'current'. When OpenAI
 *  announces a shutdown date, fill in 'shutdown'; the editor then warns
 *  researchers who use the model.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 * ------------------------------------------------------------------ */

return [

    /* ---- Current models ---- */

    'gpt-6-sol' => [
        'label'        => 'GPT-6 Sol',
        'group'        => 'current',
        'api'          => 'responses',
        'efforts'      => ['none', 'low', 'medium', 'high', 'xhigh'],
        'temperature'  => 'effort-none',
        'shutdown'     => null,
        'verification' => true,
    ],
    'gpt-6-astra' => [
        'label'        => 'GPT-6 Astra',
        'group'        => 'current',
        'api'          => 'responses',
        'efforts'      => ['low', 'medium', 'high', 'xhigh'],
        'temperature'  => 'never',
        'shutdown'     => null,
        'verification' => true,
    ],
    'gpt-6-luna' => [
        'label'        => 'GPT-6 Luna',
        'group'        => 'current',
        'api'          => 'responses',
        'efforts'      => ['none', 'low', 'medium', 'high', 'xhigh'],
        'temperature'  => 'effort-none',
        'shutdown'     => null,
        'verification' => true,
    ],
    'gpt-5.6-sol' => [
        'label'        => 'GPT-5.6 Sol',
        'group'        => 'current',
        'api'          => 'responses',
        'efforts'      => ['none', 'low', 'medium', 'high', 'xhigh'],
        'temperature'  => 'effort-none',
        'shutdown'     => null,
        'verification' => true,
    ],
    'gpt-5.6-terra' => [
        'label'        => 'GPT-5.6 Terra',
        'group'        => 'current',
        'api'          => 'responses',
        'efforts'      => ['none', 'low', 'medium', 'high', 'xhigh'],
        'temperature'  => 'effort-none',
        'shutdown'     => null,
        'verification' => true,
    ],
    'gpt-5.6-luna' => [
        'label'        => 'GPT-5.6 Luna',
        'group'        => 'current',
        'api'          => 'responses',
        'efforts'      => ['none', 'low', 'medium', 'high', 'xhigh'],
        'temperature'  => 'effort-none',
        'shutdown'     => null,
        'verification' => true,
    ],

    /* ---- Older models (requests built by the original code in connectors/openai.php) ---- */

    'gpt-5' => [
        'label'        => 'GPT-5',
        'group'        => 'older',
        'api'          => 'responses',
        'efforts'      => ['minimal', 'low', 'medium', 'high'],
        'temperature'  => 'default-only',
        'shutdown'     => '2026-12-11',
        'verification' => true,
    ],
    'gpt-5-mini' => [
        'label'        => 'GPT-5-mini',
        'group'        => 'older',
        'api'          => 'responses',
        'efforts'      => ['minimal', 'low', 'medium', 'high'],
        'temperature'  => 'default-only',
        'shutdown'     => '2026-12-11',
        'verification' => true,
    ],
    'gpt-4o' => [
        'label'        => 'GPT-4o',
        'group'        => 'older',
        'api'          => 'chat',
        'efforts'      => [],
        'temperature'  => 'always',
        'shutdown'     => null,
        'verification' => false,
    ],
    'gpt-4o-mini' => [
        'label'        => 'GPT-4o Mini',
        'group'        => 'older',
        'api'          => 'chat',
        'efforts'      => [],
        'temperature'  => 'always',
        'shutdown'     => null,
        'verification' => false,
    ],
    'gpt-4' => [
        'label'        => 'GPT-4',
        'group'        => 'older',
        'api'          => 'chat',
        'efforts'      => [],
        'temperature'  => 'always',
        'shutdown'     => '2026-10-23',
        'verification' => false,
    ],
    'gpt-4-turbo' => [
        'label'        => 'GPT-4 Turbo',
        'group'        => 'older',
        'api'          => 'chat',
        'efforts'      => [],
        'temperature'  => 'always',
        'shutdown'     => '2026-10-23',
        'verification' => false,
    ],
];
