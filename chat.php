<?php

/**
 * chat.php
 *
 * Participant-facing chat interface for AI-powered research studies.
 * Renders the conversation UI and handles real-time message exchange
 * with AI providers via a three-phase architecture:
 *   1. prepareChat.php  → saves participant message, returns token
 *   2. stream-proxy.js  → Node proxy forwards request to AI provider
 *   3. saveResponse.php → persists AI response to database
 *
 * Supports streaming (SSE) and non-streaming (JSON) modes across
 * OpenAI (Chat Completions + Responses API), OpenRouter, and
 * custom connectors.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting (disable display for participants, log all errors)
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

// =============================================================================
// DEPENDENCIES
// =============================================================================

require 'Backend/MySQL/medoo.php';
require 'Backend/MySQL/medoo-Credentials.php';
require 'Backend/Util/crypto.php';

// =============================================================================
// SECURITY HEADERS
// =============================================================================

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// =============================================================================
// ERROR UI
// =============================================================================

/**
 * Display a styled error page and terminate execution.
 * Used for validation failures and missing study configurations.
 */
function showErrorPage($message)
{
    echo "<!DOCTYPE html>
    <html>
    <head>
        <title>Error - ResearchChatAI</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <!-- ===================================================================

             CSS STYLES

             =================================================================== 

             Embedded styles for chat interface, modals, and form elements

             =================================================================== -->

        <style>
            body { font-family: Arial, sans-serif; background: #f8f8f8; padding: 40px; text-align: center; }
            .error-box { background: #fff; padding: 30px; border-radius: 8px; display: inline-block; border: 1px solid #ccc; }
            .error-box h2 { color: #e74c3c; }
            button { margin-top: 20px; padding: 10px 20px; font-size: 16px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class='error-box'>
            <h2>Error</h2>
            <p>$message</p>
            <button onclick='window.close();'>Close Window</button>
        </div>
    </body>
    </html>";
    exit;
}

// =============================================================================
// INPUT VALIDATION
// =============================================================================

// Get and validate GET parameters from URL
// These parameters control the study session:
// - studyCode: Identifies the study configuration
// - participantID: Unique identifier for the participant  
// - condition: Experimental condition number (optional)
// - Additional custom variables can be passed via GET
$studyCode = $_GET['studyCode'] ?? '';
$participantID = $_GET['participantID'] ?? '';
$condition = $_GET['condition'] ?? '';
$getVariables  = $_GET;

// Validate studyCode (non-empty, alphanumeric)
if (!preg_match('/^[a-zA-Z0-9]+$/', $studyCode)) {
    showErrorPage("Missing or invalid study code.");
}

// Validate participantID (optional but if present, should be alphanumeric or empty)
if (!empty($participantID) && !preg_match('/^[a-zA-Z0-9_-]{1,64}$/', $participantID)) {
    // Participant ID validation relaxed for compatibility
}

// Validate condition (optional but if present, must be numeric)
if (!empty($condition) && !is_numeric($condition)) {
    showErrorPage("Invalid condition value.");
}

// =========================================================================
// BASE URL CONFIGURATION
// =========================================================================

$baseURL = $env['BASE_URL'] ?? 'https://researchchatai.com/';

// =============================================================================
// STUDY LOOKUP & DECRYPTION
// =============================================================================

// Retrieve study configuration from database using study code
// This loads all study settings, AI configuration, and UI customization
$study = $database->get(
    "studies",
    "*",
    [
        "studyCode" => $studyCode
    ]
);

// Show error if study is not found
if (!$study || !is_array($study)) {
    showErrorPage("Study not found. Please check the link you were provided.");
}

// -------------------------------------------------------------------------
// DECRYPT ENCRYPTED STUDY FIELDS
// -------------------------------------------------------------------------
// If encryption is enabled for this study, decrypt sensitive fields
// (AI instructions, API keys, participant instructions, etc.)
if (!empty($study['isEncrypted'])) {
    $decryptFields = [
        'openaiApiKey',
        'openrouterApiKey',
        'experimentalConditions',
        'aiInstructions',
        'participantInstructions',
        'aiName',
        'aiStatusMessage',
        'aiDescription',
        'firstAiMessage',
        'aiTypingBubbleText',
        'aiTypingBubbleDelay',
        'openaiHideReasoning',
        'aiDelay',
        'aiDelayIsPerCharacter',
        'aiDelayBeforeFirstMessage',
        'maxNumberAiMessages',
        'maxAiMessagesReachedText',
        'maxNumberParticipantMessages',
        'maxParticipantMessagesReachedText'
    ];
    foreach ($decryptFields as $field) {
        if (isset($study[$field])) {
            $study[$field] = decryptString($study[$field]);
        }
    }
}

// =============================================================================
// CONDITION ASSIGNMENT
// =============================================================================

// -------------------------------------------------------------------------
// CONDITION ASSIGNMENT LOGIC
// -------------------------------------------------------------------------
// Automatically assigns experimental conditions to participants based on
// their participantID or URL parameters. If no condition is specified,
// uses hash-based distribution to ensure balanced assignment.

// Calculate condition number
$conditionNumber = isset($_GET['condition']) ? intval($_GET['condition']) - 1 : -1;

// Decode and validate experimental conditions
$conditions = json_decode($study['experimentalConditions'], true);
if (!is_array($conditions) || count($conditions) == 0) {
    showErrorPage("Study configuration is missing or corrupted.");
}

$conditionCount = count($conditions);
if ($conditionNumber < 0 || $conditionNumber >= $conditionCount) {
    $conditionNumber = rand(0, $conditionCount - 1);
}

// Setup default variable
if (!isset($enableImageUpload)) {
    $enableImageUpload = getStudyValue("enableImageUpload", 0);
}

// Redirect if study is not active
if ($study['dataCollectionActive'] == 0) {
    header("Location: study-closed.html");
    exit();
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Process template string by replacing {{variable}} placeholders with GET parameters
 * 
 * Allows dynamic text personalization using URL parameters. For example:
 * "Hello {{name}}" with ?name=John becomes "Hello John"
 * 
 * @param string $template Template string with {{key}} placeholders
 * @return string Processed string with placeholders replaced
 */
function processTemplate($template)
{
    global $getVariables;

    // Replace all placeholders in the format {{key}} with the corresponding GET variable value
    $processedTemplate = preg_replace_callback('/\{\{(\w+)\}\}/', function ($matches) use ($getVariables) {
        $key = $matches[1]; // Extract the key from the placeholder
        // Replace with the value if it exists in $_GET, or an empty string if not
        return isset($getVariables[$key]) ? $getVariables[$key] : '';
    }, $template);

    return $processedTemplate;
}

/**
 * Get a study-level configuration value with placeholder processing.
 * Falls back to $default if the field is empty or missing.
 */
function getStudyValue(string $key, $default = 0)
{
    global $study;

    return isset($study) && is_array($study) && isset($study[$key]) && $study[$key] != "" ? processTemplate($study[$key]) : processTemplate($default);
}

/**
 * Validate a CSS color value against safe patterns.
 * Returns the value unchanged if valid, or $default if not.
 */
function sanitizeCssColor(string $value, string $default): string
{
    $value = trim($value);
    if (preg_match('/^#([0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/', $value)) {
        return $value;
    }
    if (preg_match('/^rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}(\s*,\s*(0|1|0?\.\d+))?\s*\)$/', $value)) {
        return $value;
    }
    static $namedColors = ['black','white','red','green','blue','yellow','orange','purple',
        'pink','gray','grey','transparent','inherit','initial','unset'];
    if (in_array(strtolower($value), $namedColors, true)) {
        return $value;
    }
    return $default;
}

/**
 * Get a condition-specific study value from the experimental conditions array.
 * Falls back to condition 0's value, then to $fallbackValue.
 */
function getConditionalStudyValue($attributeKey, $fallbackValue = "")
{
    global $study, $conditionNumber;

    // Decode the JSON from the specified attribute key in the $study array
    $attributeArray = json_decode(getStudyValue($attributeKey, '[]'), true);

    // Initialize the selected attribute value
    $selectedAttribute = "";
    if (!empty($attributeArray)) {
        // Retrieve the attribute value for the specified condition
        $selectedAttribute = $attributeArray[$conditionNumber][$attributeKey] ?? "";

        // If the selected attribute is empty, use the default condition's value
        if (empty($selectedAttribute) && isset($attributeArray[0][$attributeKey])) {
            $selectedAttribute = $attributeArray[0][$attributeKey];
        }
    }

    // Return the fallback value if the selected attribute is still empty
    return $selectedAttribute !== "" ? processTemplate($selectedAttribute) : processTemplate($fallbackValue);
}

// =============================================================================
// STUDY SETTINGS EXTRACTION
// =============================================================================
// Extract and process all study configuration values from database
// Includes AI model settings, UI customization, message limits, etc.

$pillplacement = getStudyValue("hideSubmissionWindow", 0);

// Check if study is active
if ($study['dataCollectionActive'] == 0) {
    // navigate to study-closed.html
    header("Location: study-closed.html");
    exit();
}
?>

<!-- =========================================================================
     PARTICIPANT CHAT INTERFACE - HTML STRUCTURE
     =========================================================================
     This is the main participant-facing interface for AI-powered research studies.
     Displays chat window, message input, timer, word counter, and submission form.
     ========================================================================= -->
<!DOCTYPE html>
<html>

<head>
    <!-- Meta tags and page configuration -->
    <title>ResearchChatAI</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <!--Chat Style-->
    <link rel="stylesheet" href="src/CSS/chat.css?v=2412170846">
    <!--FontAwesome-->
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/solid.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/light.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/regular.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/brands.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/fontawesome.min.css">

    <!--Dynamic style based on user preference in backend-->
    <style>
        .chat-container .chat-bubble .text {
            background-color:
                <?php echo sanitizeCssColor(getStudyValue("aiBubbleBgColor", "#ecf0f1"), "#ecf0f1"); ?>;
            color:
                <?php echo sanitizeCssColor(getStudyValue("aiBubbleTextColor", "#000000"), "#000000"); ?>;
        }

        .chat-container .chat-bubble.own .text {
            background-color:
                <?php echo sanitizeCssColor(getStudyValue("userBubbleBgColor", "#0984e3"), "#0984e3"); ?>;
            color:
                <?php echo sanitizeCssColor(getStudyValue("userBubbleTextColor", "#ffffff"), "#ffffff"); ?>;
        }

        .chat-container .text-input #send-button {
            background-color:
                <?php echo sanitizeCssColor(getStudyValue("sendButtonBgColor", "#00b894"), "#00b894"); ?>;
            color:
                <?php echo sanitizeCssColor(getStudyValue("sendButtonTextColor", "#ffffff"), "#ffffff"); ?>;
        }

        #submit-pill {
            background-color:
                <?php echo sanitizeCssColor(getStudyValue("nextButtonBgColor", "#477eac"), "#477eac"); ?>;
            color:
                <?php echo sanitizeCssColor(getStudyValue("nextButtonTextColor", "#ffffff"), "#ffffff"); ?>;
        }

        #submit-pill .divider {
            background-color:
                <?php echo sanitizeCssColor(getStudyValue("nextButtonTextColor", "#ffffff"), "#ffffff"); ?>;
        }

        #submit-pill .icon {
            color:
                <?php echo sanitizeCssColor(getStudyValue("nextButtonTextColor", "#ffffff"), "#ffffff"); ?>;
        }

        /* ===================================================================
         * REASONING DISPLAY STYLES
         * ===================================================================
         * Styles for collapsible reasoning sections in AI messages
         * Used when AI provider returns structured reasoning (e.g., O1 models)
         */
        .reasoning-container {
            font-size: 0.85em;
            margin: 8px 0 0 0;
            padding-left: 0px;
            padding-right: 0px;
            /* gap above, no extra gap inside block */
            color: #5d5d5d;
        }

        .reasoning-toggle {
            cursor: pointer;
            color: #666;
            display: inline-flex;
            align-items: center;
            margin-bottom: 2px;
            /* tight title-to-content spacing */
        }

        .reasoning-toggle .chevron {
            margin-left: 6px;
            margin-top: 4px;
        }

        .reasoning-content {
            display: none;
            margin-top: 0;
            /* no extra gap under title */
            color: #555;
            max-height: none;
            /* show full content, no scroll */
            overflow: visible;
            padding-right: 0;
        }

        .reasoning-content strong {
            margin-top: 9px;
            display: none;
        }

        .reasoning-content p {
            margin-top: 0px;
        }

        .reasoning-title {
            font-size: 16px;
            font-weight: 600;
        }

        .reasoning-title.shimmering {
            animation: shimmer 2s infinite;
            background: linear-gradient(135deg, #ffffff, #5E5E5E, #ffffff);
            background-clip: text;
            color: transparent;
            background-size: 200% 100%;
        }

        @keyframes shimmer {
            0% {
                background-position: 200% 0;
            }

            100% {
                background-position: -200% 0;
            }
        }

        /* Remove bottom margin when a bubble contains a reasoning container */
        #message-list .chat-bubble:has(.reasoning-container) .text {
            margin-bottom: 0 !important;
        }

        /* Fallback for browsers without :has() */
        #message-list .chat-bubble.with-reasoning .text {
            margin-bottom: 0 !important;
        }

        /* Decoration on the <p> */
        .reasoning-content p {
            position: relative;
            padding-left: calc(10px + 12px);
            margin-bottom: 12px;
        }

        /* 10px circle at top-left */
        .reasoning-content p::before {
            content: "";
            position: absolute;
            top: calc(8px - 5px);
            left: 0;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #555;
        }

        /* 1px vertical line below the dot, to the bottom of the <p> */
        .reasoning-content p::after {
            content: "";
            position: absolute;
            left: calc(10px / 2);
            /* centers under dot */
            top: calc(10px + 7px);
            /* starts after 7px gap */
            bottom: calc(-12px + 4px);
            /* extends to bottom of the paragraph */
            width: 0;
            border-left: 1px solid #ececec;
        }

        /* Disable dot decoration for the final "Done" line */
        .reasoning-content p.no-line::after {
            content: none;
            display: none;
        }
    </style>

</head>

<!-- ===================================================================
     PAGE BODY - CHAT INTERFACE
     =================================================================== -->

<body>
    <!-- This is needed to set up the modal used for the alerts later -->
    <div id="customAlert" class="modal">
        <div class="modal-content">
            <p>Are you sure you want to continue? You will not be able to come back to this page.</p>
            </p>
            <button id="submitBtn">Yes, continue!</button>
            <button id="cancelBtn">No, I am not done yet</button>
        </div>
    </div>

    <div id="timeUpModal" class="modal">
        <div class="modal-content">
            <p>
                <?php echo getStudyValue("endOfTimerMessage", "Your time is up."); ?>
            </p>
            <button id="timeIsUpOkBtn">Ok</button>
        </div>
    </div>

    <!-- ===================================================================
         WELCOME MODAL
         =================================================================== 
         Optional welcome message shown before chat starts
         Can include study instructions, consent information, etc.
         =================================================================== -->

    <div id="welcomeModal" class="modal">
        <div class="modal-content">
            <p><?php echo getStudyValue("welcomeMessage", "Welcome to this study!"); ?></p>
            <button id="startButton" onclick="closeWelcomeModal()">Start</button>
        </div>
    </div>

    <?php $isPreview = getStudyValue("isPreview", 0); ?>
    <?php if ($isPreview == 1): ?>
        <div class="preview-container" id="preview">
            PREVIEW ONLY - TESTING FUNCTIONALITY AND LOOKS ONLY - PREVIEW ONLY
        </div>
    <?php endif; ?>

    <div class="content">
        <div class="container">
            <div class="left-column">
                <?php $hideInstructionsWindow = getStudyValue("hideInstructionsWindow", 0);
                if ($hideInstructionsWindow == 0): ?>
                    <div id="taskDescription">
                        <div class="title" style="cursor: pointer;" onclick="toggleText()">Instructions <i id="toggleIcon"
                                class="fas fa-chevron-up"></i>
                        </div>
                        <div id="descriptionContent" style="display:block;">
                            <?php echo getConditionalStudyValue("participantInstructions"); ?>
                            <br>
                        </div>
                    </div>
                <?php endif; ?>

                <?php
                // Configure word count display and enforcement
                $hideWordCount = getStudyValue("hideWordCount", 1);
                $disableMaxWordCount = getStudyValue("disableMaxWordCount", 1);
                ?>

                <?php if ($pillplacement == 0): ?>
                    <div class="pill-container">
                        <?php

                        if ($hideWordCount == 0 || $disableMaxWordCount == 0): ?>
                            <div class="pill1">
                                <span id="wordCountDisplay"></span>
                            </div>
                        <?php endif; ?>

                        <?php
                        // Configure timer display based on study settings
                        $hideTimer = getStudyValue("hideTimer", 1);

                        if ($hideTimer == 0): ?>
                            <div class="pill">
                                <span id="timers">10:00</span> <span id="status">minutes left</span>
                            </div>
                        <?php endif; ?>

                        <!-- Submit button pill -->
                        <?php $hideNextButton = getStudyValue("hideNextButton", 1);
                        if ($hideNextButton == 0): ?>
                            <div class="pill3" id="submit-pill">
                                <span><?php echo getStudyValue("nextButtonLabel", "End interaction"); ?></span>
                                <span class="divider"></span>
                                <span class="icon"><i class="fa fa-arrow-circle-right"></i></span>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

                <?php $hideSubmissionWindow = getStudyValue("hideSubmissionWindow", 0);
                if ($hideSubmissionWindow == 0): ?>
                    <textarea id="taskSubmissionTextarea"
                        placeholder="<?php echo getStudyValue("submissionPlaceholder", "Please provide your answer here."); ?>"></textarea>
                <?php endif; ?>
            </div>

            <div class="right-column">
                <?php if ($pillplacement == 1): ?>
                    <div class="pill-container">
                        <?php
                        // Configure timer display based on study settings
                        $hideTimer = getStudyValue("hideTimer", 1);

                        if ($hideTimer == 0): ?>
                            <div class="pill">
                                <span id="timers">10:00</span> <span id="status">minutes left</span>
                            </div>
                        <?php endif; ?>

                        <!-- Submit button pill -->
                        <?php $hideNextButton = getStudyValue("hideNextButton", 1);
                        if ($hideNextButton == 0): ?>
                            <div class="pill3" id="submit-pill">
                                <span><?php echo getStudyValue("nextButtonLabel", "End interaction"); ?></span>
                                <span class="divider"></span>
                                <span class="icon"><i class="fa fa-arrow-circle-right"></i></span>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

                <div class="chat-container inline">
                    <nav class="top-nav-bar">
                        <div class="user-info">
                            <?php $hideAiAvatar = getStudyValue("hideAiAvatar", 0);
                            if ($hideAiAvatar == 0): ?>
                                <img src="<?php echo getConditionalStudyValue("aiAvatarURL"); ?>" alt="ResearchChat"
                                    class="avatar <?php echo getStudyValue("aiAvatarRound", 0) == 1 ? "round" : ""; ?>"
                                    <?php echo getConditionalStudyValue("aiAvatarURL") == "" ? "style='display:none;'" : ""; ?>>
                            <?php endif; ?>
                            <div class="user-details">
                                <span class="username" <?php echo getConditionalStudyValue("aiName") == "" ? "style='display:none;'" : ""; ?>><?php echo getConditionalStudyValue("aiName"); ?></span>
                                <?php
                                $hideAiStatusMessage = getConditionalStudyValue("aiStatusMessage") == "";
                                if ($hideAiStatusMessage == 0): ?>
                                    <span class="status"><?php echo getConditionalStudyValue("aiStatusMessage"); ?></span>
                                <?php endif; ?>
                            </div>
                        </div>
                        <?php
                        $disableDeleteChatButton = getStudyValue("disableDeleteChatButton", 0);
                        if ($disableDeleteChatButton == 0): ?>
                            <button class="menu-button" aria-label="Open menu">
                                <div id="resetChatButton"> <img src="src/IMG/RobinMenu.jpg" alt="Menu" class="menu-icon" />
                                </div>
                            </button>
                        <?php endif; ?>
                    </nav>

                    <?php
                    $hideAiDescription = getConditionalStudyValue("aiDescription") == "";
                    if ($hideAiDescription == 0): ?>
                        <div class="title" id="chatTitle">
                            <span><?php echo getConditionalStudyValue("aiDescription"); ?></span>
                        </div>
                    <?php endif; ?>

                    <div id="message-list">
                        <?php
                        $firstAiMessageRaw = getConditionalStudyValue("firstAiMessage", "");
                        $hasFirstAiMessage = ($firstAiMessageRaw !== "");
                        ?>
                        <?php if ($hasFirstAiMessage): ?>
                            <div class="chat-bubble" id="first-ai-message" style="display:none;">
                                <span class="text"></span>
                                <br>
                            </div>
                        <?php endif; ?>

                        <div class="chat-bubble typing" id="typing-dots" style="display:none;">
                            <span class="text">
                                <?php $aiTypingBubbleText = getConditionalStudyValue("aiTypingBubbleText", ""); ?>
                                <?php if (trim($aiTypingBubbleText) === "<DOTS>"): ?>
                                    <img src="src/IMG/message-dot-1.gif" loop>
                                    <img src="src/IMG/message-dot-2.gif" loop>
                                    <img src="src/IMG/message-dot-3.gif" loop>
                                <?php else: ?>
                                    <!-- Intentionally empty to avoid duplicate 'thinking' text -->
                                <?php endif; ?>
                            </span>
                        </div>
                    </div>
                    <div class="text-input-container">
                        <!-- Upload status bar -->
                        <div id="upload-status" style="display: none;"></div>
                        <?php $enableImageUpload = getStudyValue("enableImageUpload", 0); ?>
                        <div class="text-input" style="<?php echo $enableImageUpload == 0 ? "" : ""; ?>">
                            <!-- Image upload button -->
                            <?php
                            if ($enableImageUpload == 1): ?>
                                <div id="image-upload-button">
                                    <i class="fa fa-images"></i>
                                    <!-- Hidden file input for image uploads -->
                                    <input type="file" id="file-input" accept="image/*" style="display: none;">
                                </div>
                            <?php endif; ?>

                            <!-- Message input textfield -->
                            <input type="text" id="message-textfield" placeholder="Write your message" value=""
                                style="<?php echo $enableImageUpload == 0 ? "width: calc(100% - 24px - 6px - 45px);" : ""; ?>" />
                            <!-- Send message button container -->
                            <div id="send-button">
                                <i class="fas fa-arrow-up"></i>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- ===================================================================
         LEGAL NOTICE MODAL
         =================================================================== 
         Terms of Service and Privacy Policy acknowledgment
         Must be accepted before using the chat interface
         =================================================================== -->
    <div id="legalModal" class="modal">
        <div class="modal-content">
            <p>By clicking on the below button, I confirm that I have read and agree with the <a
                    href="https://about.researchchatai.com/wp-content/uploads/2025/07/Terms_of_Service_ResearchChatAI.pdf"
                    target="_blank">Terms of Service</a> and the <a
                    href="https://about.researchchatai.com/wp-content/uploads/2025/07/Privacy_Statement_ResearchChatAI.pdf"
                    target="_blank">Privacy Policy</a> of ResearchChatAI.</p>
            <button id="legalOkButton" onclick="closeLegalModal()">I agree</button>
        </div>
    </div>

    <!-- ===================================================================
         JAVASCRIPT - CHAT FUNCTIONALITY
         =================================================================== 
         All client-side logic for message handling, streaming, UI updates
         Supports both streaming (SSE) and non-streaming (JSON) AI responses
         =================================================================== -->
    <script>
        // -----------------------------------------------------------------------
        // CONFIGURATION VARIABLES FROM PHP
        // -----------------------------------------------------------------------
        // These variables are populated from the database study settings

        var hideWelcomeMessage = <?php echo getStudyValue("hideWelcomeMessage", 1); ?>;
        var hideLegalNotice = <?php echo getStudyValue("hideLegalNotice", 1); ?>;

        // =========================================================================
        // INITIALIZATION - DOCUMENT READY
        // =========================================================================
        // Main initialization when DOM is fully loaded

        document.addEventListener('DOMContentLoaded', function() {
            if (hideWelcomeMessage === 0) {
                $("#welcomeModal").css("display", "flex");
            } else if (hideLegalNotice === 0) {
                // Show the legal modal if the welcome message is hidden
                $("#legalModal").css("display", "flex");
            }
        });

        // -----------------------------------------------------------------------
        // MODAL CONTROL FUNCTIONS
        // -----------------------------------------------------------------------

        /**
         * Close the welcome modal and mark as seen
         */
        function closeWelcomeModal() {
            $('#welcomeModal').hide();
            handleFirstAiMessage();
            if (hideLegalNotice === 0) {
                $("#legalModal").css("display", "flex");
            }
        }

        /**
         * Close the legal notice modal
         */

        function closeLegalModal() {
            $('#legalModal').hide();
            handleFirstAiMessage();
        }
    </script>

    <!--Basic CHAT Functionality-->
    <script type="text/javascript" src="src/JS/jquery-3.7.1.min.js"></script>
    <script src="src/JS/tinymce/tinymce.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/@tinymce/tinymce-jquery@1/dist/tinymce-jquery.min.js"></script>
    <script src="src/JS/linkify.min.js"></script>
    <script src="src/JS/linkify-string.min.js"></script>
    <script src="src/JS/showdown.min.js"></script>

    <?php
    // Check if modelProvider == "openai"
    if ($study["modelProvider"] == "openai") {
        // Check if openaiEnableStreaming == 1
        if ($study["openaiEnableStreaming"] == 1) {
            $streaming = 1;
        } else {
            $streaming = 0;
        }
    } else if ($study["modelProvider"] == "openrouter") {
        // Check if openrouterEnableStreaming == 1
        if ($study["openrouterEnableStreaming"] == 1) {
            $streaming = 1;
        } else {
            $streaming = 0;
        }
    } else {
        if ($study["customConnectorEnableStreaming"] == 1) {
            $streaming = 1;
        } else {
            $streaming = 0;
        }
    }
    ?>

    <script type="text/javascript">
        var baseURL = <?php echo json_encode($baseURL); ?>;
        var instructions = <?php echo json_encode(getConditionalStudyValue("aiInstructions")); ?>;
        var aiDelay = <?php echo json_encode(getConditionalStudyValue("aiDelay")); ?>;
        var aiDelayIsPerCharacter = parseInt(<?php echo json_encode(getConditionalStudyValue("aiDelayIsPerCharacter", 0)); ?>) || 0;
        var aiDelayBeforeFirstMessage = parseInt(<?php echo json_encode(getConditionalStudyValue("aiDelayBeforeFirstMessage", 0)); ?>) || 0;
        var aiTypingBubbleDelay = <?php echo json_encode(getConditionalStudyValue("aiTypingBubbleDelay")); ?>;
        // -----------------------------------------------------------------------
        // FIRST AI MESSAGE CONFIGURATION


        // -----------------------------------------------------------------------
        // Optional pre-loaded message displayed when chat starts

        var firstAiMessage = <?php echo json_encode($firstAiMessageRaw ?? ""); ?>;
        // Maximum number of AI messages allowed

        var MAX_AI_MSGS = parseInt(<?php echo json_encode(getStudyValue("maxNumberAiMessages", 0)); ?>) || 0;
        // Maximum number of participant messages allowed

        var MAX_USER_MSGS = parseInt(<?php echo json_encode(getStudyValue("maxNumberParticipantMessages", 0)); ?>) || 0;

        // --- Global reasoning UI controls ---
        // Determine if current model is GPT‑5 (only then we show reasoning by default)
        var MODEL_PROVIDER = <?php echo json_encode($study["modelProvider"] ?? ""); ?>;
        var MODEL_NAME = <?php
                            $modelName = "";
                            if (($study["modelProvider"] ?? "") === "openai") {
                                $modelName = $study["openaiModel"] ?? "";
                            } else if (($study["modelProvider"] ?? "") === "openrouter") {
                                $modelName = $study["openrouterModel"] ?? "";
                            } else {
                                $modelName = ""; // custom: default to hidden unless explicitly enabled elsewhere
                            }
                            echo json_encode($modelName);
                            ?>;
        var OPENAI_HIDE_REASONING = parseInt(<?php echo getStudyValue("openaiHideReasoning", 0); ?>) || 0;
        var CUSTOM_HIDE_REASONING = parseInt(<?php echo json_encode($study["customConnectorHideReasoning"] ?? 0); ?>) || 0;
        // If false, no reasoning UI appears at all (no chevron, no block).
        window.REASONING_VISIBLE = (/^gpt-5/i.test(String(MODEL_NAME || "")) && (OPENAI_HIDE_REASONING !== 1)) || (MODEL_PROVIDER === "custom" && CUSTOM_HIDE_REASONING !== 1);
        // If true, each reasoning block starts expanded; if false, collapsed.
        window.REASONING_DEFAULT_OPEN = false;

        //Get URL parameters
        var studyCode = getURLParameter('studyCode');
        var participantID = getURLParameter('participantID');
        // -----------------------------------------------------------------------
        // STREAMING MODE CONFIGURATION


        // -----------------------------------------------------------------------
        // Determine if AI responses should stream in real-time or return complete

        var streaming = <?php echo is_numeric($streaming) ? $streaming : json_encode($streaming); ?>;

        // Get the study start time using JS as 0000-00-00 00:00:00	
        var startTime = new Date();
        var numberMessages = 0;

        const variablesString = "<?php
                                    // Filter out 'studyCode' and 'participantID' (case-insensitive)
                                    $filteredVariables = array_filter($getVariables, function ($key) {
                                        return strcasecmp($key, 'studyCode') !== 0 && strcasecmp($key, 'participantID') !== 0 && strcasecmp($key, 'condition') !== 0;
                                    }, ARRAY_FILTER_USE_KEY);

                                    // Build the string
                                    $output = [];
                                    foreach ($filteredVariables as $key => $value) {
                                        $output[] = htmlspecialchars($key) . '=' . htmlspecialchars($value);
                                    }

                                    // Join the output with ' || ' separator
                                    echo implode(' || ', $output);
                                    ?>";

        // Maximum length of messages to be sent to ChatGPT. This does not include the system message (i.e., the instructions).
        var maxMessageLength = 200000;

        var markdownConverter = new showdown.Converter();
        markdownConverter.setOption('simplifiedAutoLink', 'true');
        markdownConverter.setFlavor('github');

        // Reasoning UI state (per assistant message)
        // Old REASONING_BUFFERS kept for compatibility with some calls; new REASONING_STATE is authoritative.
        const REASONING_BUFFERS = Object.create(null);
        const REASONING_CONTAINERS = Object.create(null);
        const REASONING_STATE = Object.create(null); // msgId -> { parts:{key:{text,finalized}}, order:[key], raw:'', sawSummary:boolean }

        const REASONING_START_TS = Object.create(null);

        // --- AI message limit state & helpers ---
        // Message counters for enforcing limits

        var aiMessageCount = 0; // assistant-only messages

        // -----------------------------------------------------------------------
        // MESSAGE LIMIT ENFORCEMENT
        // -----------------------------------------------------------------------

        /**
         * Lock chat interface when AI message limit is reached
         * Disables input and shows limit reached message
         */
        function lockChatBecauseLimitReached() {
            // Disable input & send
            $('#message-textfield').prop('disabled', true);
            $('#send-button').addClass('disabled').css('pointer-events', 'none');
            $("#typing-dots").hide();

            // Optional: show a final notice bubble (customizable with a study field)
            /*const notice = <?php echo json_encode(getStudyValue('maxAiMessagesReachedText', 'The limit of AI messages has been reached, you can no longer send messages for this study.')); ?>;
            $('<div class="chat-bubble deleteable"><span class="text">' + notice + '</span></div>')
                .insertBefore("#typing-dots");*/
        }

        function maybeLockIfLimitReached() {
            if (MAX_AI_MSGS > 0 && aiMessageCount >= MAX_AI_MSGS) {
                lockChatBecauseLimitReached();
                return true;
            }
            return false;
        }

        // --- Participant (user) message limit state & helpers ---
        var userMessageCount = 0;

        function lockChatBecauseUserLimitReached() {
            // Disable input & send
            $('#message-textfield').prop('disabled', true);
            $('#send-button').addClass('disabled').css('pointer-events', 'none');

            // Optional: show a notice bubble
            /*const noticeUser = <?php echo json_encode(getStudyValue('maxParticipantMessagesReachedText', 'Your message limit has reached, you can no longer send messages in this study.')); ?>;
            $('<div class="chat-bubble deleteable"><span class="text">' + noticeUser + '</span></div>')
                .insertBefore("#typing-dots");*/
        }

        function maybeLockIfUserLimitReached() {
            if (MAX_USER_MSGS > 0 && userMessageCount >= MAX_USER_MSGS) {
                lockChatBecauseUserLimitReached();
                return true;
            }
            return false;
        }

        /**
         * Finalize the reasoning title for a message
         * Extracts and formats the title from reasoning content
         * 
         * @param {string} msgId - Message ID
         */
        function finalizeReasoningTitle(msgId) {
            const st = ensureReasoningState(msgId);
            if (st.finalizedTitle) return;
            st.finalizedTitle = true;

            const $c = REASONING_CONTAINERS[msgId];
            // Resolve start time robustly (prefer per-bubble stored ts)
            const containerTs = $c && $c.data('startTs') ? $c.data('startTs') : 0;
            const start = (window.__assistantMsgStartTimes && window.__assistantMsgStartTimes[msgId]) || REASONING_START_TS[msgId] || containerTs || 0;
            const now = (window.performance && performance.now) ? performance.now() : Date.now();
            const elapsedSec = start ? Math.max(0, Math.round(((now - start) / 1000))) : 0;
            if ($c) {
                const $title = $c.find('.reasoning-title');
                $title.removeClass('shimmering').text(`Thought for ${elapsedSec} seconds`);
                // Add "Done" notice at the end of the reasoning content
                const $content = $c.find('.reasoning-content');
                if ($content.length && !$content.data('doneAppended')) {
                    $content.append('<p class="no-line">Done</p>');
                    $content.data('doneAppended', true);
                }
            }
        }

        /**
         * Ensure reasoning container exists for a message
         * Creates the collapsible reasoning UI structure if not present
         * 
         * @param {string} msgId - Message ID
         */
        function ensureReasoningContainer(msgId) {
            // If reasoning UI is globally disabled, do not create anything.
            if (!window.REASONING_VISIBLE) {
                REASONING_CONTAINERS[msgId] = null;
                REASONING_BUFFERS[msgId] = REASONING_BUFFERS[msgId] || '';
                return null;
            }

            // Locate the assistant bubble for this message
            let $bubble = $(`#message-list .chat-bubble.deleteable[data-msg-id="${msgId}"]`);
            if (!$bubble.length) {
                // Fallback to latest assistant bubble if something went out of order
                $bubble = $("#message-list .chat-bubble.deleteable").not('.own').last();
                if (!$bubble.length) {
                    $bubble = $('<div class="chat-bubble deleteable"><span class="text"></span></div>');
                    $("#typing-dots").before($bubble);
                }
            }
            if (!$bubble.is(':visible')) {
                $bubble.show();
                $('#typing-dots').hide();
            }

            // If the bubble already has a reasoning container (e.g., created under a different msgId), reuse it.
            const $existing = $bubble.children('.reasoning-container').first();
            if ($existing.length) {
                REASONING_CONTAINERS[msgId] = $existing;
                // Mirror the existing start timestamp to this msgId mapping
                const ts = $existing.data('startTs') || REASONING_START_TS[msgId] || ((window.performance && performance.now) ? performance.now() : Date.now());
                REASONING_START_TS[msgId] = ts;
                return $existing;
            }

            if (!REASONING_CONTAINERS[msgId]) {
                const isOpen = !!window.REASONING_DEFAULT_OPEN;
                const $container = $(`
                    <div class="reasoning-container ${isOpen ? 'open' : ''}">
                        <div class="reasoning-toggle">
                            <span class="reasoning-title">Thinking…</span>
                            <span class="chevron fas fa-chevron-right"></span>
                        </div>
                        <div class="reasoning-content" style="display:${isOpen ? 'block' : 'none'};"></div>
                    </div>
                `);
                $container.find('.reasoning-title').addClass('shimmering');
                // Set initial chevron icon state
                const $chev = $container.find('.chevron');
                $chev.removeClass('fa-chevron-right fa-chevron-down').addClass(isOpen ? 'fa-chevron-down' : 'fa-chevron-right');
                // Record a start timestamp at the container level for robust duration calculations
                const ts = REASONING_START_TS[msgId] || ((window.performance && performance.now) ? performance.now() : Date.now());
                REASONING_START_TS[msgId] = ts;
                $container.data('startTs', ts);
                $container.find('.reasoning-toggle').on('click', function() {
                    const open = $container.hasClass('open');
                    if (open) {
                        $container.removeClass('open');
                        $container.find('.reasoning-content').hide();
                        $chev.removeClass('fa-chevron-down').addClass('fa-chevron-right');
                    } else {
                        $container.addClass('open');
                        $container.find('.reasoning-content').show();
                        $chev.removeClass('fa-chevron-right').addClass('fa-chevron-down');
                    }
                });
                $bubble.append($container);
                // Add fallback class for margin removal (for browsers without :has())
                $bubble.addClass('with-reasoning');
                REASONING_CONTAINERS[msgId] = $container;
                // keep legacy buffer in sync, but use REASONING_STATE for rendering
                REASONING_BUFFERS[msgId] = '';
            }
            return REASONING_CONTAINERS[msgId];
        }

        /**
         * Ensure reasoning state object exists for message
         * Creates tracking object if not present
         * 
         * @param {string} msgId - Message ID
         */

        function ensureReasoningState(msgId) {
            if (!REASONING_STATE[msgId]) {
                REASONING_STATE[msgId] = {
                    parts: {},
                    order: [],
                    raw: '',
                    sawSummary: false
                };
            }
            if (window.REASONING_VISIBLE) {
                ensureReasoningContainer(msgId);
            }
            return REASONING_STATE[msgId];
        }

        // Extracts a reasoning title from the reasoning text
        /**
         * Extract reasoning title from text
         * Looks for markdown-style headers or uses default
         * 
         * @param {string} txt - Reasoning text
         * @return {string} Extracted title
         */
        function extractReasoningTitle(txt) {
            if (!txt) return '';
            // Prefer the last Markdown bold line that looks like a headline
            const re = /(?:^|\n)\s*\*\*(.+?)\*\*\s*(?:\n|$)/g;
            let m, last = '';
            while ((m = re.exec(txt)) !== null) {
                last = (m[1] || '').trim();
            }
            if (last) return last;
            // Fallback: first non-empty line stripped of basic MD
            const first = (txt.split('\n').find(l => l.trim()) || '')
                .replace(/[\*_#>`~]/g, '')
                .trim();
            return first.slice(0, 80);
        }

        // Remove the leading headline from the content body so it isn't duplicated under the chevron label.
        /**
         * Remove leading title from markdown text
         * Used to avoid showing title twice in reasoning display
         * 
         * @param {string} txt - Markdown text
         * @param {string} title - Title to remove
         * @return {string} Text without leading title
         */

        function stripLeadingTitleFromMarkdown(txt, title) {
            if (!txt) return '';
            const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const t = title ? escapeRe(title) : null;

            if (t) {
                // **Title**
                let re = new RegExp('^\\s*\\*\\*' + t + '\\*\\*\\s*\\n+', 'i');
                if (re.test(txt)) return txt.replace(re, '');
                // # Title
                re = new RegExp('^\\s*#\\s*' + t + '\\s*\\n+', 'i');
                if (re.test(txt)) return txt.replace(re, '');
                // ## Title
                re = new RegExp('^\\s*##\\s*' + t + '\\s*\\n+', 'i');
                if (re.test(txt)) return txt.replace(re, '');
                // Plain first line equals title
                re = new RegExp('^\\s*' + t + '\\s*\\n+', 'i');
                if (re.test(txt)) return txt.replace(re, '');
            }
            // Generic: if the very first line is any bold headline, drop it
            const m = txt.match(/^\s*\*\*.+?\*\*\s*\n+/);
            if (m) return txt.slice(m[0].length);
            return txt;
        }

        function renderReasoning(msgId) {
            const st = ensureReasoningState(msgId);
            const $c = REASONING_CONTAINERS[msgId];
            if (!$c) return;

            console.log(st);

            let text = '';
            if (st.sawSummary && st.order.length) {
                // Join parts with a BLANK LINE so Markdown starts new paragraphs/headings
                text = st.order.map(k => st.parts[k]?.text || '').filter(Boolean).join('\n\n');
            } else {
                // Fallback: raw stream (when no summary events are present)
                text = st.raw || '';
            }

            // Title shown next to the chevron (don’t overwrite after finalization)
            if (!st.finalizedTitle) {
                const title = extractReasoningTitle(text) || 'Thinking…';
                $c.find('.reasoning-title').text(title);
            }

            // For the very first reasoning block, keep the headline in the inline content.
            // If multiple blocks (summary parts) exist, strip the duplicate headline to avoid repetition.
            let body;
            if (st.sawSummary) {
                body = text; //stripLeadingTitleFromMarkdown(text, title);
            } else {
                // Raw stream with no summary parts yet — treat as first block
                body = text;
            }

            // keep legacy buffer updated so other code paths (if any) remain harmless
            REASONING_BUFFERS[msgId] = text;

            body = body.replace(/\\n/g, "\n");
            $c.find('.reasoning-content').html(markdownConverter.makeHtml(body));
        }

        /**
         * Set reasoning part content (for structured reasoning chunks)
         * 
         * @param {string} msgId - Message ID
         * @param {string} itemId - Reasoning item ID
         * @param {number} summaryIndex - Summary index
         * @param {string} text - Reasoning text content
         * @param {boolean} finalized - Whether this part is complete
         */

        function reasoningPartSet(msgId, itemId, summaryIndex, text, finalized) {
            const st = ensureReasoningState(msgId);
            st.sawSummary = true;
            const key = String(itemId) + ':' + String(summaryIndex ?? 0);
            if (!st.parts[key]) {
                st.parts[key] = {
                    text: '',
                    finalized: false
                };
                st.order.push(key);
            }
            if (typeof text === 'string') {
                st.parts[key].text = text;
            }
            if (finalized === true) {
                st.parts[key].finalized = true;
            }
            renderReasoning(msgId);
        }

        /**
         * Append delta to reasoning part (streaming update)
         * 
         * @param {string} msgId - Message ID
         * @param {string} itemId - Reasoning item ID
         * @param {number} summaryIndex - Summary index
         * @param {string} delta - Text to append
         */

        function reasoningPartDelta(msgId, itemId, summaryIndex, delta) {
            if (!delta) return;
            const st = ensureReasoningState(msgId);
            st.sawSummary = true;
            const key = String(itemId) + ':' + String(summaryIndex ?? 0);
            if (!st.parts[key]) {
                st.parts[key] = {
                    text: '',
                    finalized: false
                };
                st.order.push(key);
            }
            st.parts[key].text += delta;
            renderReasoning(msgId);
            console.debug('[Reasoning Δ part]', msgId, key, delta);
        }

        // Legacy helpers now route through the state machine.
        // They only render when NO summary parts are being streamed (to avoid duplicate content).
        /**
         * Update reasoning text with new content (streaming)
         * 
         * @param {string} msgId - Message ID
         * @param {string} delta - Text to append
         */

        function updateReasoningText(msgId, delta) {
            if (!delta) return;
            const st = ensureReasoningState(msgId);
            if (st.sawSummary) return; // summary is authoritative; ignore raw deltas to cut repetition
            st.raw = (st.raw || '') + delta;
            renderReasoning(msgId);
            console.debug('[Reasoning Δ raw]', msgId, delta);
        }

        /**
         * Set final reasoning text (non-streaming mode)
         * 
         * @param {string} msgId - Message ID
         * @param {string} text - Complete reasoning text
         */

        function setReasoningFinal(msgId, text) {
            if (!text) return;
            const st = ensureReasoningState(msgId);
            if (st.sawSummary) return; // if summary exists, do not re-append a final raw blob
            const prev = st.raw || '';
            let next = text;
            if (prev && text && text.indexOf(prev) === 0) {
                next = text; // final is a superset -> replace
            } else if (!prev) {
                next = text; // nothing streamed -> set
            } else if (text.length > prev.length && text.includes(prev)) {
                next = text; // final wraps previous somewhere
            } else if (text !== prev) {
                next = prev + '\n' + text; // conservative merge
            }
            st.raw = next;
            renderReasoning(msgId);
            console.debug('[Reasoning ✓ raw]', msgId, next);
        }

        // --- Back-compat shim: some non-streaming paths called appendReasoning(...) previously.
        // Accepts either (msgId, text) or (text) — in the latter case we attach to the latest assistant bubble.
        /**
         * Append reasoning content intelligently
         * Handles paragraph breaks and list formatting
         * 
         * @param {string} a - Existing content
         * @param {string} b - New content to append
         * @return {string} Combined content
         */

        function appendReasoning(a, b) {
            try {
                var hasTwo = (typeof b === 'string' && b.length >= 0);
                var text = hasTwo ? b : (typeof a === 'string' ? a : '');
                if (!text) return;
                var msgId = null;

                if (hasTwo) {
                    // Called as appendReasoning(msgId, text)
                    msgId = String(a);
                } else {
                    // Called as appendReasoning(text): attach to the latest assistant bubble
                    var $last = $("#message-list .chat-bubble.deleteable").not('.own').last();
                    if ($last.length) {
                        msgId = $last.attr('data-msg-id');
                        if (!msgId) {
                            // Assign a single stable id if missing
                            msgId = 'msg-' + Date.now();
                            $last.attr('data-msg-id', msgId);
                        }
                    } else {
                        // Create a new assistant bubble if none exists yet
                        var $bubble = $('<div class="chat-bubble deleteable"><span class="text"></span></div>');
                        $("#typing-dots").before($bubble);
                        // Assign a single stable id
                        msgId = 'msg-' + Date.now();
                        $bubble.attr('data-msg-id', msgId);
                    }
                }

                // Respect global visibility: if reasoning is hidden, do nothing (but avoid errors).
                if (!window.REASONING_VISIBLE) return;

                setReasoningFinal(msgId, text);
                finalizeReasoningTitle(msgId);
            } catch (e) {
                console.warn('[appendReasoning shim]', e);
            }
        }

        // Prevent pasting into the chat text field if setting is enabled
        var disableCopyPasteChat = <?php echo getStudyValue("disableCopyPasteChat", 0); ?>;
        if (disableCopyPasteChat == 1) {
            /**
             * Prevent pasting in message textfield if configured
             */

            $('#message-textfield').on('paste', function(e) {
                e.preventDefault();
            });
        }

        function handleFirstAiMessage() {
            var $first = $('#first-ai-message');
            if (!$first.length) return; // nothing to do
            if ($first.is(':visible')) return; // already shown/started
            if (!firstAiMessage || !firstAiMessage.trim()) return;
            var isStreaming = (streaming === 1);
            var baseDelay = Math.max(0, pickDelay(aiDelay));
            var perCharEnabled = (aiDelayIsPerCharacter === 1) && !isStreaming;
            var applyToFirst = (aiDelayBeforeFirstMessage === 1);

            function showNow() {
                firstAiMessage = firstAiMessage.replace(/\\n/g, "<br>");
                $first.show().find('.text').html(firstAiMessage);
            }

            function showAfter(ms) {
                setTimeout(showNow, Math.max(0, ms));
            }

            function typewriter(intervalMs) {
                firstAiMessage = firstAiMessage.replace(/\\n/g, "<br>");
                var text = firstAiMessage,
                    idx = 0;
                $first.show();
                var $span = $first.find('.text');
                $span.text('');

                function nextChunk() {
                    if (idx >= text.length) {
                        return;
                    }
                    // Pick a random chunk size between 20 and 50
                    var chunkSize = Math.floor(Math.random() * (50 - 20 + 1)) + 20;
                    var nextIdx = Math.min(idx + chunkSize, text.length);
                    $span.html($span.html() + text.slice(idx, nextIdx));
                    idx = nextIdx;
                    if (idx < text.length) {
                        // Wait between 0.5 and 1.5 seconds before next chunk
                        var delay = Math.random() * 1000;
                        setTimeout(nextChunk, delay);
                    }
                }
                nextChunk();
            }

            // If no delay for first message, show immediately
            if (!applyToFirst) {
                console.log("No delay for first AI message");
                showNow();
                return;
            }

            // Apply delay before showing the first AI message
            if (isStreaming) {
                if (baseDelay > 0) {
                    console.log("Delaying first AI message by", baseDelay, "ms");
                    setTimeout(function() {
                        typewriter(25);
                    }, baseDelay);
                } else {
                    console.log("No delay for first AI message");
                    typewriter(25);
                }
            } else {
                if (perCharEnabled && baseDelay > 0) {
                    console.log("Delaying first AI message by", baseDelay * firstAiMessage.length, "ms");
                    showAfter(baseDelay * firstAiMessage.length);
                } else if (baseDelay > 0) {
                    console.log("Delaying first AI message by", baseDelay, "ms");
                    showAfter(baseDelay);
                } else {
                    console.log("No delay for first AI message");
                    showNow();
                }
            }
        }

        // Ensure it actually runs once the DOM is ready (and after modals possibly block initial view)
        if (document.readyState === 'complete' || document.readyState === 'interactive') {
            console.log("Document ready, handling first AI message");
            setTimeout(handleFirstAiMessage, 0);
        } else {
            console.log("Document not ready, waiting for DOMContentLoaded");
            window.addEventListener('DOMContentLoaded', handleFirstAiMessage);
        }

        // -----------------------------------------------------------------------
        // EVENT HANDLERS - USER INTERACTIONS
        // -----------------------------------------------------------------------

        /**
         * Handle send button click - validates input and sends message
         */

        $("#send-button").click(function() {
            if ((MAX_AI_MSGS > 0 && aiMessageCount >= MAX_AI_MSGS) ||
                (MAX_USER_MSGS > 0 && userMessageCount >= MAX_USER_MSGS)) {
                maybeLockIfLimitReached();
                maybeLockIfUserLimitReached();
                return;
            }

            var newMessage = $('#message-textfield').val();

            // Abort if no text and no image
            if (!newMessage.trim() && (!imgURL || !imgURL.trim())) {
                return;
            }

            // Count this participant message (text or image)
            userMessageCount++;

            // -----------------------------------------------------------------------
            // UI: Display user message bubble and image thumbnail
            // -----------------------------------------------------------------------
            if (imgURL && imgURL.trim() && !window.thumbnailAppended) {
                $('<div class="chat-bubble own deleteable image-thumbnail">' +
                    '<img src="' + imgURL + '" alt="Image" style="max-width: 100px; max-height: 100px; margin-bottom: 5px; cursor: pointer;" onclick="openLightbox(\'' + imgURL + '\')" />' +
                    '</div>').insertBefore("#typing-dots");
                window.thumbnailAppended = true;
            }
            if (newMessage.trim()) {
                $('<div class="chat-bubble own deleteable"><span class="text">' + newMessage + '</span></div>')
                    .insertBefore("#typing-dots");
            }

            $('#message-textfield').val('').prop('disabled', true);

            // Apply typing bubble delay
            console.log("Configured AI typing bubble delay is", aiTypingBubbleDelay, "ms");
            var thisAiTypingBubbleDelay = Math.max(0, pickDelay(aiTypingBubbleDelay));
            console.log("Applying AI typing bubble delay of", thisAiTypingBubbleDelay, "ms");
            setTimeout(function() {
                sendMessage(studyCode, participantID, newMessage);
            }, thisAiTypingBubbleDelay);
        });

        // -----------------------------------------------------------------------
        // MESSAGE SENDING - CORE FUNCTION
        // -----------------------------------------------------------------------

        /**
         * Send participant message to AI and handle response
         * Supports both streaming (SSE) and non-streaming (JSON) modes
         * 
         * @param {string} studyCode - Study identifier
         * @param {string} participantID - Participant identifier
         * @param {string} newMessage - Message text from participant
         */
        function sendMessage(studyCode, participantID, newMessage) {
            const isStreaming = streaming === 1;

            // Compile current chat history including the new user message
            const chatHist = compileChatHistory(true);
            console.log(JSON.stringify(chatHist));

            let effectiveMessageText = newMessage;
            const lastUserTurn = [...chatHist].reverse().find(m => m.role === 'user');

            const isImageOnlyTurn =
                lastUserTurn &&
                Array.isArray(lastUserTurn.content) &&
                lastUserTurn.content.length === 1 &&
                lastUserTurn.content[0].type === 'image_url' &&
                (!newMessage || !newMessage.trim());

            // Minimal caption helps providers/models that require non-empty "prompt"
            if (isImageOnlyTurn) {
                effectiveMessageText = 'Please describe and analyze this image.';
            }

            var defaultTypingText = "<?php echo getConditionalStudyValue('aiTypingBubbleText', ''); ?>";
            const $assistantBubble = $('<div class="chat-bubble deleteable"><span class="text">' + defaultTypingText + '</span></div>')
                .insertBefore("#typing-dots");
            // assign unique id to this assistant message (for reasoning stream)
            if (!window.__msgSeq) window.__msgSeq = 0;
            const messageId = ++window.__msgSeq;
            $assistantBubble.attr('data-msg-id', messageId);
            if (!window.__assistantMsgStartTimes) window.__assistantMsgStartTimes = Object.create(null);
            window.__assistantMsgStartTimes[messageId] = (window.performance && performance.now) ? performance.now() : Date.now();
            window.__lastAssistantBubble = $assistantBubble;

            // Show indicators based on the configured text
            if (defaultTypingText.trim() === "<DOTS>") {
                // Show animated dots only when explicitly requested
                $assistantBubble.hide();
                $("#typing-dots").show();
            } else {
                // For any other value (including empty string), show exactly one indicator
                if (defaultTypingText.trim() === "") {
                    // No custom text → show dots bubble only
                    $("#typing-dots").show();
                    $assistantBubble.hide();
                } else {
                    // Custom text → use assistant bubble only
                    $("#typing-dots").hide();
                    $assistantBubble.show();
                }
            }
            $('#message-list').scrollTop($('#message-list')[0].scrollHeight);
            numberMessages++;

            /* ==========================================================
             *  AI REQUEST – three-phase architecture
             *
             *  Both streaming and non-streaming go through:
             *    1. prepareChat.php  → saves user msg, returns token
             *    2. Node proxy       → forwards request to AI provider
             *    3. saveResponse.php → persists AI response to DB
             *
             *  The PHP worker is freed in ~150ms regardless of how long
             *  the AI takes to respond.
             * ========================================================== */

            /* Small JSONPath extractor for non-streaming response parsing.
               Handles paths like "$.choices[0].message.content" */
            function _extractPath(obj, pathStr) {
                if (!pathStr || !obj) return null;
                var segs = pathStr.replace(/^\$\.?/, '').split(/\.(?![^\[]*\])/);
                var cur = obj;
                for (var i = 0; i < segs.length; i++) {
                    if (cur == null) return null;
                    var m = segs[i].match(/^(.+)\[(\d+)\]$/);
                    if (m) {
                        cur = cur[m[1]];
                        if (cur == null) return null;
                        cur = cur[parseInt(m[2], 10)];
                    } else {
                        cur = cur[segs[i]];
                    }
                }
                return cur;
            }

            /* Check whether a parsed SSE object matches an extractor filter.
               Filter keys are JSONPath-lite strings (e.g. "$.type", "$.delta.type").
               Returns true if ALL filter entries match (or if filter is empty/null). */
            function _matchExtractorFilter(obj, filter) {
                if (!filter || typeof filter !== 'object') return true;
                for (const key in filter) {
                    if (!filter.hasOwnProperty(key)) continue;
                    if (_extractPath(obj, key) !== filter[key]) return false;
                }
                return true;
            }

            /* Flatten a reasoning summary that may be a string or array of parts */
            function _flattenReasoning(val) {
                if (typeof val === 'string') return val;
                if (Array.isArray(val)) {
                    return val.map(function(p) {
                        if (typeof p === 'string') return p;
                        if (p && typeof p.text === 'string') return p.text;
                        return '';
                    }).filter(Boolean).join('\n');
                }
                return '';
            }

            // Common params for prepareChat.php (both paths)
            const params = new URLSearchParams({
                studyCode: studyCode,
                participantID: participantID,
                chatHistory: JSON.stringify(chatHist),
                messageText: effectiveMessageText,
                condition: <?php echo $conditionNumber + 1; ?>,
                passedVariables: variablesString,
                filename: uploadedFilename,
                stream: isStreaming ? 1 : 0
            });

            // Save references for the save call after response completes
            var _saveStudyCode = studyCode;
            var _saveParticipantID = participantID;
            var _saveCondition = <?php echo $conditionNumber + 1; ?>;
            var _savePassedVars = variablesString;

            /* ---------- STREAMING ---------- */
            if (isStreaming) {
                var baseDelayStream = Math.max(0, pickDelay(aiDelay));
                var releaseAt = Date.now() + baseDelayStream;
                var holdBuffer = '';
                var reasoningExtractors = null;
                var contentExtractors = null;

                setTimeout(function() {
                    // Step 1: Call prepareChat.php → get one-time stream token
                    fetch(baseURL + 'Backend/Chat/prepareChat.php', {
                            method: 'POST',
                            body: params
                        })
                        .then(function(prepRes) {
                            return prepRes.json();
                        })
                        .then(function(prepData) {
                            if (prepData.error) throw new Error(prepData.error);
                            reasoningExtractors = prepData.reasoningExtractors || null;
                            contentExtractors = prepData.extractors || null;

                            // Step 2: Stream via Node proxy using the one-time token
                            return fetch(baseURL + 'Backend/Chat/stream', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'Accept': 'text/event-stream',
                                    'Cache-Control': 'no-cache',
                                    'Pragma': 'no-cache'
                                },
                                body: JSON.stringify({
                                    requestToken: prepData.requestToken
                                })
                            });
                        })
                        .then(function(res) {
                            if (!res.ok || !res.body) {
                                return res.text().then(function(t) {
                                    throw new Error(t || ('HTTP ' + res.status));
                                });
                            }
                            return res.body.getReader();
                        })
                        .then(function(reader) {
                            const decoder = new TextDecoder('utf-8');
                            let buffer = '';
                            let assistantText = '';
                            let reasoningAgg = '';
                            let lastReasoningItemId = null;
                            const ITEM_TO_MSG = Object.create(null);
                            const thisMsgId = messageId;
                            const SUMMARY_SOURCE_BY_MSG = Object.create(null);
                            const SUMMARY_SEEN_FOR_ITEM = Object.create(null);

                            function splitConcatenatedJSON(s) {
                                const out = [];
                                let i = 0,
                                    n = s.length;
                                while (i < n) {
                                    while (i < n && /\s/.test(s[i])) i++;
                                    if (i >= n) break;
                                    const ch = s[i];
                                    if (ch === '{' || ch === '[') {
                                        let start = i,
                                            depth = 0,
                                            inStr = false,
                                            esc = false;
                                        while (i < n) {
                                            const c = s[i];
                                            if (inStr) {
                                                if (esc) {
                                                    esc = false;
                                                } else if (c === '\\') esc = true;
                                                else if (c === '"') inStr = false;
                                            } else {
                                                if (c === '"') inStr = true;
                                                else if (c === '{' || c === '[') depth++;
                                                else if (c === '}' || c === ']') {
                                                    depth--;
                                                    if (depth === 0) {
                                                        i++;
                                                        break;
                                                    }
                                                }
                                            }
                                            i++;
                                        }
                                        out.push(s.slice(start, i));
                                    } else {
                                        let start = i;
                                        while (i < n && s[i] !== '{' && s[i] !== '[') i++;
                                        out.push(s.slice(start, i));
                                    }
                                }
                                return out.filter(t => t.length > 0);
                            }

                            function extractReasoningSummary(obj) {
                                if (!obj) return '';
                                if (typeof obj === 'string') return obj;
                                if (Array.isArray(obj)) {
                                    const parts = [];
                                    for (const p of obj) {
                                        if (typeof p === 'string') parts.push(p);
                                        else if (p && typeof p === 'object' && typeof p.text === 'string') parts.push(p.text);
                                    }
                                    return parts.join('\n').trim();
                                }
                                return '';
                            }

                            function handleEvent(evt) {
                                const lines = evt.replace(/\r\n/g, '\n').split('\n');
                                for (const line of lines) {
                                    if (!line.startsWith('data: ')) continue;
                                    const payload = line.slice(6).trim();
                                    if (!payload) continue;
                                    if (payload === '[DONE]') return;

                                    const parts = splitConcatenatedJSON(payload);
                                    for (const part of parts) {
                                        const trimmed = part.trim();
                                        let obj = null;
                                        if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
                                            try {
                                                obj = JSON.parse(trimmed);
                                            } catch {
                                                obj = null;
                                            }
                                        }

                                        if (obj) {
                                            if (obj.type) {
                                                if (obj.type === 'response.output_item.added' && obj.item && obj.item.type === 'reasoning') {
                                                    lastReasoningItemId = obj.item.id;
                                                    ITEM_TO_MSG[obj.item.id] = thisMsgId;
                                                    ensureReasoningState(thisMsgId);
                                                    ensureReasoningContainer(thisMsgId);
                                                }

                                                if (obj.type === 'response.reasoning_summary_text.delta') {
                                                    const msgModeText = SUMMARY_SOURCE_BY_MSG[thisMsgId];
                                                    if (msgModeText && msgModeText !== 'text') continue;
                                                    SUMMARY_SOURCE_BY_MSG[thisMsgId] = 'text';
                                                    SUMMARY_SEEN_FOR_ITEM[obj.item_id] = true;
                                                    const tgtText = ITEM_TO_MSG[obj.item_id] || thisMsgId;
                                                    reasoningPartDelta(tgtText, obj.item_id, obj.summary_index ?? 0, obj.delta || '');
                                                }

                                                if (obj.type === 'response.reasoning_summary_text.done') {
                                                    const msgModeTextDone = SUMMARY_SOURCE_BY_MSG[thisMsgId];
                                                    if (msgModeTextDone && msgModeTextDone !== 'text') continue;
                                                    SUMMARY_SOURCE_BY_MSG[thisMsgId] = 'text';
                                                    SUMMARY_SEEN_FOR_ITEM[obj.item_id] = true;
                                                    const tgtTextDone = ITEM_TO_MSG[obj.item_id] || thisMsgId;
                                                    reasoningPartSet(tgtTextDone, obj.item_id, obj.summary_index ?? 0, obj.text || '', true);
                                                }

                                                if (obj.type === 'response.reasoning_summary_part.added' || obj.type === 'response.reasoning_summary_part.done') {
                                                    const msgModePart = SUMMARY_SOURCE_BY_MSG[thisMsgId];
                                                    if (msgModePart && msgModePart !== 'part') continue;
                                                    SUMMARY_SOURCE_BY_MSG[thisMsgId] = 'part';
                                                    const tgtPart = ITEM_TO_MSG[obj.item_id] || thisMsgId;
                                                    SUMMARY_SEEN_FOR_ITEM[obj.item_id] = true;
                                                    if (obj.part && (obj.part.type === 'output_text' || obj.part.type === 'summary_text')) {
                                                        reasoningPartSet(tgtPart, obj.item_id, obj.summary_index ?? 0, obj.part.text || '', obj.type.endsWith('.done'));
                                                    }
                                                }

                                                if (obj.type === 'content_block_delta' && obj.delta &&
                                                    obj.delta.type === 'text_delta' &&
                                                    typeof obj.delta.text === 'string') {
                                                    if (!$assistantBubble.is(':visible')) {
                                                        $assistantBubble.show();
                                                        $('#typing-dots').hide();
                                                    }
                                                    assistantText += obj.delta.text;
                                                    $assistantBubble.find('.text').text(assistantText);
                                                    continue;
                                                }

                                                if (obj.type === 'response.output_text.delta' && typeof obj.delta === 'string') {
                                                    if (!$assistantBubble.is(':visible')) {
                                                        $assistantBubble.show();
                                                        $('#typing-dots').hide();
                                                    }
                                                    assistantText += obj.delta;
                                                    $assistantBubble.find('.text').text(assistantText);
                                                }

                                                if (obj.type === 'response.reasoning.delta' && typeof obj.delta === 'string') {
                                                    updateReasoningText(thisMsgId, obj.delta);
                                                    continue;
                                                }

                                                if ((obj.type === 'response.output_item.added' || obj.type === 'response.output_item.done') &&
                                                    obj.item && obj.item.type === 'reasoning') {
                                                    if (SUMMARY_SEEN_FOR_ITEM[obj.item.id] || SUMMARY_SOURCE_BY_MSG[thisMsgId]) continue;
                                                    const rs = extractReasoningSummary(obj.item.summary);
                                                    if (rs) {
                                                        const finalized = (obj.type === 'response.output_item.done');
                                                        SUMMARY_SOURCE_BY_MSG[thisMsgId] = 'summary';
                                                        SUMMARY_SEEN_FOR_ITEM[obj.item.id] = true;
                                                        reasoningPartSet(thisMsgId, obj.item.id, 0, rs, finalized);
                                                    }
                                                    continue;
                                                }

                                                if (obj.type === 'response.completed') {
                                                    const st = ensureReasoningState(thisMsgId);
                                                    let rs = '';
                                                    if (obj.response && obj.response.reasoning) {
                                                        rs = extractReasoningSummary(obj.response.reasoning.summary) || '';
                                                    }
                                                    if (rs && !st.sawSummary) {
                                                        reasoningPartSet(thisMsgId, 'final', 0, rs, true);
                                                    }
                                                    const finalText = obj.response && obj.response.output_text;
                                                    if (typeof finalText === 'string' && finalText.length && !assistantText) {
                                                        assistantText = finalText;
                                                        if (!$assistantBubble.is(':visible')) {
                                                            $assistantBubble.show();
                                                            $('#typing-dots').hide();
                                                        }
                                                        $assistantBubble.find('.text').text(assistantText);
                                                    }
                                                    finalizeReasoningTitle(thisMsgId);
                                                    continue;
                                                }

                                                if (obj.type === 'response.error') {
                                                    console.error('Responses API error:', obj);
                                                    $assistantBubble.find('.text').text('Sorry — the model returned an error.');
                                                    $('#typing-dots').hide();
                                                    $('#message-textfield').prop('disabled', false).focus();
                                                    return;
                                                }

                                                /* ---- Generic reasoning extractor fallback (custom connectors) ---- */
                                                if (reasoningExtractors && Array.isArray(reasoningExtractors)) {
                                                    for (const ext of reasoningExtractors) {
                                                        if (_matchExtractorFilter(obj, ext.filter)) {
                                                            const token = ext.tokenPath ? _extractPath(obj, ext.tokenPath) : null;
                                                            if (typeof token === 'string' && token) {
                                                                ensureReasoningContainer(thisMsgId);
                                                                updateReasoningText(thisMsgId, token);
                                                            }
                                                            break;
                                                        }
                                                    }
                                                }

                                                continue;
                                            }

                                            /* ---- Chat Completions format (no .type field) ---- */
                                            if (obj.choices && obj.choices[0] && obj.choices[0].delta) {
                                                const d = obj.choices[0].delta;
                                                if (typeof d.content === 'string') {
                                                    if (!$assistantBubble.is(':visible')) {
                                                        $assistantBubble.show();
                                                        $('#typing-dots').hide();
                                                    }
                                                    assistantText += d.content;
                                                    $assistantBubble.find('.text').text(assistantText);
                                                }
                                                /* Array-typed content chunks: [{type:"text",text:"..."}, {type:"thinking",...}] */
                                                if (Array.isArray(d.content)) {
                                                    for (const chunk of d.content) {
                                                        if (chunk.type === 'text' && typeof chunk.text === 'string') {
                                                            if (!$assistantBubble.is(':visible')) {
                                                                $assistantBubble.show();
                                                                $('#typing-dots').hide();
                                                            }
                                                            assistantText += chunk.text;
                                                            $assistantBubble.find('.text').text(assistantText);
                                                        }
                                                        if (chunk.type === 'thinking') {
                                                            /* Nested: {type:"thinking", thinking:[{type:"text", text:"..."}]} */
                                                            if (Array.isArray(chunk.thinking)) {
                                                                for (const t of chunk.thinking) {
                                                                    if (typeof t.text === 'string' && t.text) {
                                                                        ensureReasoningContainer(thisMsgId);
                                                                        updateReasoningText(thisMsgId, t.text);
                                                                    }
                                                                }
                                                            }
                                                            /* Flat: {type:"thinking", text:"..."} */
                                                            if (typeof chunk.text === 'string' && chunk.text) {
                                                                ensureReasoningContainer(thisMsgId);
                                                                updateReasoningText(thisMsgId, chunk.text);
                                                            }
                                                        }
                                                    }
                                                }
                                                /* Reasoning fields (various provider conventions) */
                                                if (typeof d.reasoning === 'string' && d.reasoning.trim() !== '') {
                                                    ensureReasoningContainer(thisMsgId);
                                                    updateReasoningText(thisMsgId, d.reasoning);
                                                }
                                                if (typeof d.reasoning_content === 'string' && d.reasoning_content.trim() !== '') {
                                                    ensureReasoningContainer(thisMsgId);
                                                    updateReasoningText(thisMsgId, d.reasoning_content);
                                                }
                                                continue;
                                            }

                                            if (typeof obj.reasoning === 'string') {
                                                const s = obj.reasoning.trim();
                                                if (s && !/^(detailed|concise|brief)$/i.test(s)) {
                                                    reasoningAgg += (reasoningAgg ? '\n' : '') + s;
                                                }
                                                continue;
                                            }
                                        }

                                        /* ---- Non-JSON payload ---- */
                                        if (!obj && trimmed) {
                                            if (!$assistantBubble.is(':visible')) {
                                                $assistantBubble.show();
                                                $('#typing-dots').hide();
                                            }
                                            assistantText += trimmed;
                                            $assistantBubble.find('.text').text(assistantText);
                                        }
                                    }
                                }
                            } // end handleEvent

                            function pump() {
                                return reader.read().then(({
                                    done,
                                    value
                                }) => {
                                    if (done) {
                                        try {
                                            if (buffer && buffer.trim()) {
                                                handleEvent(buffer.replace(/\r\n/g, '\n'));
                                                buffer = '';
                                            }
                                        } catch (e) {
                                            console.warn('Leftover SSE flush failed:', e);
                                        }

                                        try {
                                            finalizeReasoningTitle(thisMsgId);
                                            if (assistantText.trim()) {
                                                assistantText = assistantText.replace(/\\n/g, "\n");
                                                $assistantBubble.find('.text').html(markdownConverter.makeHtml(assistantText));
                                            }
                                        } catch (e) {
                                            console.warn('Markdown render failed:', e);
                                        }

                                        $('#typing-dots').hide();

                                        // Step 3: Save the AI response to the database
                                        var saveParams = new URLSearchParams({
                                            studyCode: _saveStudyCode,
                                            participantID: _saveParticipantID,
                                            message: assistantText,
                                            reasoning: reasoningAgg,
                                            condition: _saveCondition,
                                            passedVariables: _savePassedVars
                                        });
                                        console.log("Saving AI response with params:", saveParams.toString());
                                        fetch(baseURL + 'Backend/Chat/saveResponse.php', {
                                            method: 'POST',
                                            headers: {
                                                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
                                            },
                                            body: saveParams
                                        }).catch(function(err) {
                                            console.error('Failed to save AI response:', err);
                                        });

                                        aiMessageCount++;
                                        const lockedAi = maybeLockIfLimitReached();
                                        const lockedUser = maybeLockIfUserLimitReached();
                                        if (!lockedAi && !lockedUser) {
                                            $('#message-textfield').prop('disabled', false).focus();
                                        }

                                        return;
                                    }

                                    buffer += decoder.decode(value, {
                                        stream: true
                                    });
                                    buffer = buffer.replace(/\r\n/g, '\n');

                                    let idx;
                                    while ((idx = buffer.indexOf('\n\n')) !== -1) {
                                        const evt = buffer.slice(0, idx);
                                        buffer = buffer.slice(idx + 2);
                                        handleEvent(evt);
                                    }

                                    return pump();
                                }).catch(err => {
                                    console.error('Streaming read failed:', err);
                                    $('#typing-dots').hide();
                                    $assistantBubble.find('.text').text('Connection error while streaming. Please try again.');
                                    $('#message-textfield').prop('disabled', false).focus();
                                    alert('Connection error while streaming. Please try again.');
                                });
                            }

                            return pump();
                        })
                        .catch(function(err) {
                            console.error('Fetch failed:', err);
                            $('#typing-dots').hide();
                            $assistantBubble.find('.text').text('Request failed to start. Check console for details.');
                            $('#message-textfield').prop('disabled', false).focus();
                            var msg = 'Your message could not be sent. Please try again.';
                            try {
                                var parsed = JSON.parse(err.message);
                                if (parsed.error) msg = 'Error: ' + (typeof parsed.error === 'string' ? parsed.error : parsed.error.message || JSON.stringify(parsed.error));
                            } catch (_) {
                                if (err.message) msg = 'Error: ' + err.message;
                            }
                            alert(msg);
                        })
                }, baseDelayStream);
            }
            /* ---------- NON‑STREAMING ---------- */
            else {
                // Step 1: Call prepareChat.php → get one-time request token + extraction paths
                fetch(baseURL + 'Backend/Chat/prepareChat.php', {
                        method: 'POST',
                        body: params
                    })
                    .then(function(prepRes) {
                        return prepRes.json();
                    })
                    .then(function(prepData) {
                        if (prepData.error) throw new Error(prepData.error);

                        var resultPath = prepData.resultPath;
                        var reasoningPath = prepData.reasoningPath;

                        // Step 2: Send request via Node proxy → get full JSON response
                        return fetch(baseURL + 'Backend/Chat/stream', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                body: JSON.stringify({
                                    requestToken: prepData.requestToken
                                })
                            })
                            .then(function(proxyRes) {
                                if (!proxyRes.ok) {
                                    return proxyRes.text().then(function(t) {
                                        throw new Error(t || ('HTTP ' + proxyRes.status));
                                    });
                                }
                                return proxyRes.json();
                            })
                            .then(function(aiJson) {
                                /* -- Extract the AI message text -- */
                                var rawMsg = resultPath ? _extractPath(aiJson, resultPath) : null;

                                // Fallback: Responses API top-level convenience field
                                if (rawMsg == null && typeof aiJson.output_text === 'string') {
                                    rawMsg = aiJson.output_text;
                                }
                                // Fallback: Chat Completions format
                                if (rawMsg == null && aiJson.choices && aiJson.choices[0] && aiJson.choices[0].message) {
                                    rawMsg = aiJson.choices[0].message.content;
                                }
                                // Fallback: Responses API output array (message items)
                                if (rawMsg == null && Array.isArray(aiJson.output)) {
                                    for (var oi = 0; oi < aiJson.output.length; oi++) {
                                        var item = aiJson.output[oi];
                                        if (item && item.type === 'message' && Array.isArray(item.content)) {
                                            for (var ci = 0; ci < item.content.length; ci++) {
                                                if (item.content[ci] && item.content[ci].type === 'output_text' && typeof item.content[ci].text === 'string') {
                                                    rawMsg = item.content[ci].text;
                                                    break;
                                                }
                                            }
                                            if (rawMsg != null) break;
                                        }
                                    }
                                }
                                var msgText = (typeof rawMsg === 'string') ? rawMsg : (rawMsg != null ? JSON.stringify(rawMsg) : '');

                                /* -- Extract reasoning summary -- */
                                var rawReasoning = reasoningPath ? _extractPath(aiJson, reasoningPath) : null;
                                var reasoning = _flattenReasoning(rawReasoning);

                                // Ignore reasoning values that are just config labels
                                if (reasoning && /^(auto|detailed|concise|brief)$/i.test(reasoning.trim())) {
                                    reasoning = '';
                                }
                                // Fallback: Responses API output array (reasoning items)
                                if (!reasoning && Array.isArray(aiJson.output)) {
                                    for (var ri = 0; ri < aiJson.output.length; ri++) {
                                        var rItem = aiJson.output[ri];
                                        if (rItem && rItem.type === 'reasoning' && rItem.summary) {
                                            reasoning = _flattenReasoning(rItem.summary);
                                            if (reasoning) break;
                                        }
                                    }
                                }

                                // Compute display delay
                                var baseDelay = Math.max(0, pickDelay(aiDelay));
                                var perCharEnabled = (aiDelayIsPerCharacter === 1);
                                var delayMs = 0;
                                if (perCharEnabled && baseDelay > 0) {
                                    delayMs = baseDelay * msgText.length;
                                } else if (baseDelay > 0) {
                                    delayMs = baseDelay;
                                }

                                if ($assistantBubble.is(':hidden')) {
                                    $("#typing-dots").show();
                                }

                                setTimeout(function() {
                                    if ($assistantBubble.is(':hidden')) {
                                        $assistantBubble.show();
                                        $("#typing-dots").hide();
                                    }
                                    msgText = msgText.replace(/\\n/g, "\n");
                                    $assistantBubble.find('.text').html(markdownConverter.makeHtml(msgText));
                                    appendReasoning(messageId, reasoning);
                                    setTimeout(function() {
                                        finalizeReasoningTitle(messageId);
                                    }, 0);

                                    // Step 3: Save the AI response to the database
                                    var saveParams = new URLSearchParams({
                                        studyCode: _saveStudyCode,
                                        participantID: _saveParticipantID,
                                        message: msgText,
                                        reasoning: reasoning,
                                        condition: _saveCondition,
                                        passedVariables: _savePassedVars
                                    });
                                    fetch(baseURL + 'Backend/Chat/saveResponse.php', {
                                        method: 'POST',
                                        body: saveParams
                                    }).catch(function(err) {
                                        console.error('Failed to save AI response:', err);
                                    });

                                    aiMessageCount++;
                                    $("#typing-dots").hide();

                                    const lockedAi = maybeLockIfLimitReached();
                                    const lockedUser = maybeLockIfUserLimitReached();
                                    if (!lockedAi && !lockedUser) {
                                        $('#message-textfield').prop('disabled', false);
                                    }

                                    $('#message-list').scrollTop($('#message-list')[0].scrollHeight);
                                }, delayMs);
                            });
                    })
                    .catch(function(err) {
                        console.error('Non-streaming request failed:', err);
                        $("#typing-dots").hide();
                        $('#message-textfield').prop('disabled', false);
                        $(".chat-bubble.own:last").remove();
                        var msg = 'Your message could not be sent. Please try again.';
                        try {
                            var parsed = JSON.parse(err.message);
                            if (parsed.error) msg = 'Error: ' + (typeof parsed.error === 'string' ? parsed.error : parsed.error.message || JSON.stringify(parsed.error));
                        } catch (_) {
                            if (err.message) msg = 'Error: ' + err.message;
                        }
                        alert(msg);
                    });
            }

            imgURL = '';
            uploadedFilename = '';
            window.thumbnailAppended = false;
            resetUpload();
        }

        $('#message-textfield').keyup(function(e) {
            if (e.which == 13) {
                if ((MAX_AI_MSGS > 0 && aiMessageCount >= MAX_AI_MSGS) ||
                    (MAX_USER_MSGS > 0 && userMessageCount >= MAX_USER_MSGS)) {
                    maybeLockIfLimitReached();
                    maybeLockIfUserLimitReached();
                    return;
                }
                $('#send-button').click();
            }
        });

        $("#resetChatButton").click(function() {
            let result = confirm("Are you sure you want to reset the chat?");
            if (!result) {
                return;
            }

            // Hide typing buttons
            $("#typing-dots").hide();

            aiMessageCount = 0;
            userMessageCount = 0;

            // Enable text input
            $("#message-textfield").prop('disabled', false);

            $("#message-list .deleteable").each(function(index, message) {
                message.remove();
            });
        });

        var imgURL = ''; // Declare imgURL globally
        var uploadedFilename = '';

        function compileChatHistory(skipNewestUserTurn = false) {
            // We walk newest → oldest (DOM reversed) to easily skip the newest user turn if requested
            var chatHistory = [];
            var messagesCharaterCount = 0;

            let skippedUser = false; // whether we've skipped the newest user text bubble
            let skippedPairedImage = false; // whether we also skipped its paired image (if any)
            let skippedStandaloneImage = false; // for image-only newest turn

            const nodes = $("#message-list").children().get().reverse();

            for (let i = 0; i < nodes.length; i++) {
                const $node = $(nodes[i]);

                // Skip typing indicator
                if ($node.hasClass("typing")) continue;

                // Skip the pre-rendered first AI message bubble (UI-only; not context)
                //if ($node.attr('id') === 'first-ai-message') continue;

                // Skip fully hidden bubbles, just in case
                if (!$node.is(':visible')) continue;

                // ----- USER TEXT BUBBLE -----
                if ($node.hasClass("own") && !$node.hasClass("image-thumbnail")) {
                    if (messagesCharaterCount >= maxMessageLength) continue;

                    // If requested, skip the **newest** user turn (first user text bubble we encounter in reversed walk)
                    if (skipNewestUserTurn && !skippedUser) {
                        skippedUser = true;

                        // If there is an immediately previous node (older in time in normal order,
                        // but next in this reversed traversal) that's an image-thumbnail (paired image),
                        // skip that too so it doesn't end up in history without its text.
                        if (i + 1 < nodes.length) {
                            const $older = $(nodes[i + 1]);
                            if ($older.hasClass("image-thumbnail")) {
                                skippedPairedImage = true;
                                // Mark it skipped by advancing i once more
                                i += 1;
                                continue;
                            }
                        }
                        continue;
                    }

                    var currentText = $node.find('span.text').text().trim();

                    // Build a user message with text
                    var messageContent = {
                        role: "user",
                        content: [{
                            type: "text",
                            text: currentText
                        }]
                    };

                    // If the immediately previous node (older in time; next in reversed order) is an image-thumbnail, attach it
                    if (i + 1 < nodes.length) {
                        const $older = $(nodes[i + 1]);
                        if ($older.hasClass("image-thumbnail")) {
                            messageContent.content.push({
                                type: "image_url",
                                image_url: {
                                    url: $older.find("img").attr("src")
                                }
                            });
                            // We consumed that image; skip it on the next loop
                            i += 1;
                        }
                    }

                    chatHistory.unshift(messageContent);
                    messagesCharaterCount += currentText.length;
                    continue;
                }

                // ----- IMAGE-ONLY TURN (no user text bubble after it) -----
                if ($node.hasClass("image-thumbnail")) {
                    // If skipNewestUserTurn is true and we haven't skipped any user text yet,
                    // check whether this *is* the newest user turn as an image-only message.
                    // In reversed traversal, the very first image we see that does NOT have a newer user
                    // text bubble next to it is the newest image-only turn.
                    if (skipNewestUserTurn && !skippedUser && !skippedStandaloneImage) {
                        const $newerNormalOrder = $(nodes[i - 1] || null); // newer in normal order is previous in reversed
                        const newerIsUserText = $newerNormalOrder && $newerNormalOrder.hasClass("own") && !$newerNormalOrder.hasClass("image-thumbnail");
                        if (!newerIsUserText) {
                            skippedStandaloneImage = true;
                            // Skip this image-only newest turn; it will be sent via messageText + filename
                            continue;
                        }
                    }

                    // If the next newer node (in normal order, i.e. previous in reversed) is a user text bubble,
                    // that image will be attached in that branch, so ignore here.
                    const $newer = $(nodes[i - 1] || null);
                    if ($newer && $newer.hasClass("own") && !$newer.hasClass("image-thumbnail")) {
                        continue;
                    }

                    // Standalone image older in the history → include it
                    const imgSrc = $node.find("img").attr("src");
                    if (imgSrc) {
                        chatHistory.unshift({
                            role: "user",
                            content: [{
                                type: "image_url",
                                image_url: {
                                    url: imgSrc
                                }
                            }]
                        });
                    }
                    continue;
                }

                // ----- ASSISTANT BUBBLE -----
                if (!$node.hasClass("own")) {
                    var currentTextA = $node.find('span.text').text().trim();
                    if (currentTextA !== "") {
                        chatHistory.unshift({
                            role: "assistant",
                            content: currentTextA
                        });
                        messagesCharaterCount += currentTextA.length;
                    }
                    continue;
                }
            }

            // System prompt always first
            chatHistory.unshift({
                role: "system",
                content: instructions
            });

            console.log(chatHistory);
            return chatHistory;
        }

        function getURLParameter(name) {
            var parameter = decodeURIComponent((new RegExp('[?|&]' + name + '=' + '([^&;]+?)(&|#|;|$)').exec(location.search) || [null, ''])[1].replace(/\+/g, '%20')) || null;

            if (isEmptyOrSpaces(parameter)) {
                parameter = randomStr();
            }

            return parameter
        }

        function isEmptyOrSpaces(str) {
            return str === null || str.match(/^ *$/) !== null;
        }

        function randomStr() {
            let result = '';
            let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            let charactersLength = characters.length;
            for (let i = 0; i < 24; i++) {
                result += characters.charAt(Math.floor(Math.random() * charactersLength));
            }
            return result;
        }

        function pickDelay(value) {
            if (value == null) return 0;
            if (typeof value !== 'string') value = String(value);
            var v = value.trim();
            if (v.length === 0) return 0;
            if (v.indexOf(';') !== -1) {
                var parts = v.split(';');
                if (parts.length >= 2) {
                    var a = parseInt(parts[0], 10);
                    var b = parseInt(parts[1], 10);
                    if (isFinite(a) && isFinite(b)) {
                        if (a > b) {
                            var t = a;
                            a = b;
                            b = t;
                        }
                        return Math.floor(Math.random() * (b - a + 1)) + a;
                    }
                }
                return 0;
            }
            var n = parseInt(v, 10);
            return isFinite(n) ? n : 0;
        }

        <?php $hideAiStatusMessage = getStudyValue("hideAiStatusMessage", 1);
        if ($hideAiStatusMessage == 0): ?>
            $("#chatTitle").text("<?php getStudyValue("aiStatusMessage"); ?>");
        <?php endif; ?>
    </script>
    <!-- END OF CHAT FUNCTIONALITY -->

    <!-- Activate the text input functionality -->
    <script>
        var hideWordCount = <?php echo getStudyValue("hideWordCount", 1); ?>;
        var disabledMaxWordCount = <?php echo getStudyValue("disableMaxWordCount", 1); ?>;
        var wordLimit = <?php echo getStudyValue("maxWordCount", 0); ?>;
        var preventGoingOverMaxWordCount = <?php echo getStudyValue("preventGoingOverMaxWordCount", 0); ?>;
        var disableCopyPasteSubmission = <?php echo getStudyValue("disableCopyPasteSubmission", 0); ?>;

        tinymce.init({
            selector: '#taskSubmissionTextarea',
            license_key: 'gpl',
            menubar: false,
            plugins: ['wordcount'],
            toolbar: 'undo redo | blocks | bold italic backcolor | ' +
                'alignleft aligncenter alignright alignjustify | ' +
                'bullist numlist outdent indent | removeformat',
            setup: function(editor) {

                let lastValidContent = ''; // Keep track of the last valid content

                // Set the initial word count display to "0 / wordLimit"
                updateWordCount(editor, wordLimit);

                editor.on('keyup', function() {
                    updateWordCount(editor, wordLimit);
                });

                editor.on('paste', function() {
                    setTimeout(function() {
                        updateWordCount(editor, wordLimit);
                    }, 0);
                });

                function updateWordCount(editor, limit) {
                    const content = editor.getContent({
                        format: 'text'
                    }).trim();
                    const wordCount = content.split(/\s+/).filter(word => word.length > 0).length;

                    if (preventGoingOverMaxWordCount) {
                        if (wordCount > limit) {
                            editor.setContent(lastValidContent); // Revert to the last valid state
                            moveCursorToEnd(editor); // Move cursor to the end after resetting content
                        } else {
                            lastValidContent = editor.getContent(); // Update the last valid state
                        }
                    }

                    // Update word count display in the format "X words" or "X / Y words"
                    if (disabledMaxWordCount) {
                        const wordCountDisplay = document.getElementById('wordCountDisplay');

                        // Check if word count display exists
                        if (wordCountDisplay === null) {
                            return;
                        }

                        // Check if word count should be plural
                        if (wordCount === 1) {
                            wordCountDisplay.textContent = `${wordCount} word`;
                        } else {
                            wordCountDisplay.textContent = `${wordCount} words`;
                        }
                    } else {
                        const wordCountDisplay = document.getElementById('wordCountDisplay');

                        // Check if word count display exists
                        if (wordCountDisplay === null) {
                            return;
                        }

                        wordCountDisplay.textContent = `${wordCount} / ${limit} words`;

                        // Add red-text class when the word count reaches the limit
                        if (wordCount >= limit) {
                            wordCountDisplay.classList.add('wordlimitreached');
                        } else {
                            wordCountDisplay.classList.remove('wordlimitreached');
                        }
                    }
                }

                function moveCursorToEnd(editor) {
                    editor.focus(); // Ensure the editor is focused
                    const editorContent = editor.getContent({
                        format: 'html'
                    });
                    editor.setContent(editorContent); // Set the content again to force cursor update
                    editor.selection.select(editor.getBody(), true); // Select the entire content
                    editor.selection.collapse(false); // Collapse the selection to the end
                }
            },
            paste_preprocess: (plugin, args) => {
                if (disableCopyPasteSubmission) {
                    args.stopImmediatePropagation();
                    args.stopPropagation();
                    args.preventDefault();
                }
            }
        });
    </script>

    <!-- Timer and TinyMCE Disable Logic -->
    <script type="text/javascript">
        // Set the countdown time (10 minutes in seconds)
        let countdownTime = <?php echo isset($study) && is_array($study) && isset($study["timerDuration"]) ? $study["timerDuration"] : 10; ?> * 60;
        const timerElement = document.getElementById('timers');
        const statusElement = document.getElementById('status');
        let lastValidContent = ''; // Variable to store the last valid content

        // Initial display
        updateTimerDisplay(countdownTime);

        // Update the countdown every second
        const interval = setInterval(function() {
            countdownTime--;

            // Update the displayed time
            updateTimerDisplay(countdownTime);

            // Check if time is up
            if (countdownTime <= 0) {
                clearInterval(interval);
                var hideEndOfTimerMessage = <?php echo getStudyValue("hideEndOfTimerMessage", 1); ?>;
                var endOfTimerForceSubmit = <?php echo getStudyValue("endOfTimerForceSubmit", 0); ?>;

                if (hideEndOfTimerMessage == 0) {
                    document.querySelector('.pill').classList.add('red');
                    statusElement.textContent = '(Time is up!)';

                    // Disable TinyMCE editor
                    //disableTinyMCE();

                    // Show the time-up modal
                    const timeUpModal = document.getElementById('timeUpModal');
                    timeUpModal.style.display = 'flex'; // Show the modal

                    // Add event listener to the modal button
                    document.getElementById('timeIsUpOkBtn').addEventListener('click', function() {
                        if (endOfTimerForceSubmit == 1) {
                            submit();
                        } else {
                            // Close modal
                            timeUpModal.style.display = 'none';
                        }
                    });
                } else {
                    // Check if force submit is enabled
                    if (endOfTimerForceSubmit == 1) {
                        submit();
                    }
                }
            }
        }, 1000);

        // Function to update timer display in MM:SS format
        function updateTimerDisplay(time) {
            if (timerElement === null) {
                return;
            }

            let minutes = Math.floor(time / 60);
            let seconds = time % 60;

            // Format minutes and seconds to always have two digits
            minutes = minutes < 10 ? '0' + minutes : minutes;
            seconds = seconds < 10 ? '0' + seconds : seconds;

            // Update the timer text
            timerElement.textContent = `${minutes}:${seconds}`;
        }

        // Function to disable TinyMCE editor when time is up
        function disableTinyMCE() {
            let editorInstance = tinymce.get('taskSubmissionTextarea');
            if (editorInstance) {
                // Correct method to set editor to readonly
                editorInstance.mode.set('readonly');
            } else {
                console.error('TinyMCE editor instance not found.');
            }
        }
    </script>

    <!-- Modal Logic -->
    <script>
        // Get the modal and buttons
        const modal = document.getElementById('customAlert');
        const confirmBtn = document.getElementById('submitBtn');
        const cancelBtn = document.getElementById('cancelBtn');

        // Check if submit-pill exists
        if (document.getElementById('submit-pill') !== null) {
            // Add event listener to the pill3
            document.getElementById('submit-pill').addEventListener('click', function() {
                // Show the custom modal
                modal.style.display = 'flex';
            });

            confirmBtn.addEventListener('click', function() {
                submit();
            });

            // When the user clicks "No"
            cancelBtn.addEventListener('click', function() {
                // Hide the modal and do nothing
                modal.style.display = 'none';
            });
        }

        function submit() {
            // Get new text message
            // Check if taskSubmissionTextarea exists
            var newSubmission = "[NO TEXT]";
            if (tinymce.get("taskSubmissionTextarea") !== null) {
                newSubmission = tinymce.get("taskSubmissionTextarea").getContent();
            }

            if (newSubmission.trim() === "") {
                newSubmission = "[NO TEXT]";
            }

            //  Check whether the message contains texts
            // if (isEmptyOrSpaces(newSubmission)) {
            //    alert("Please answer the question before continuing.")
            //     return;
            //}

            //Send post request
            $.post('Backend/Studies/submission-save.php', {
                submissionText: newSubmission,
                studyCode: studyCode,
                participantID: participantID,
                startTime: startTime.toISOString().slice(0, 19).replace('T', ' '),
                endTime: new Date().toISOString().slice(0, 19).replace('T', ' '),
                passedVariables: variablesString,
                numberMessages: numberMessages,
                duration: ((new Date() - startTime) / 1000).toString(),
                condition: <?php echo $conditionNumber + 1; ?>
            }, function(data) {
                console.log(data);

                // Check if taskSubmissionTextarea exists
                if (tinymce.get("taskSubmissionTextarea") !== null) {
                    // Clear the text input
                    tinymce.get("taskSubmissionTextarea").setContent("");
                }

                var redirectURL = "<?php echo getStudyValue("redirectURL", ""); ?>";
                if (redirectURL !== "") {
                    // Append all participantID + Condition + all other potentially passed variables
                    redirectURL += "?participantID=" + participantID + "&condition=<?php echo $conditionNumber + 1; ?>&" + variablesString;
                    window.location.href = redirectURL;
                } else {
                    window.location.href = "done.html";
                }

            }).fail(function(data) {
                alert("Something went wrong. Please try again.")
                console.log(data);
                console.log(data.responseText);
            });
        }
    </script>

    <!-- Adjustment of sizing and heights depending on different options -->
    <script type="text/javascript">
        function adjustHeights() {
            var pillHeight = 0;
            var instructionsHeight = 0;
            var chatHeight = 0;
            var isPillInRightContainer = false;

            // Check if pill-container is in the DOM and get its height
            if ($('.pill-container').length) {
                pillHeight = $('.pill-container').height();

                // Dynamically check if the pill-container is in the right or left container
                if ($('.pill-container').closest('.right-column').length) {
                    isPillInRightContainer = true; // Pill is in the right container
                } else if ($('.pill-container').closest('.left-column').length) {
                    isPillInRightContainer = false; // Pill is in the left container
                }
            }

            if ($('#taskDescription').length) {
                instructionsHeight = $('#taskDescription').height();
            }

            if (isPillInRightContainer == true) {
                var topOffset = pillHeight; // Adjust this value to set the distance from the top
                $("#taskDescription").css({
                    'top': topOffset + 'px', // Set the top offset
                    //'height': $(window).height() - 35 - topOffset + 'px' // Adjust the height relative to the top
                });
            }

            // Adjust the height of the .tox-tinymce element
            $(".tox-tinymce").height(
                $(window).height() - instructionsHeight - (isPillInRightContainer ? -pillHeight : pillHeight) - 78
            );

            // Adjust height of the chatbox on the right
            if (isPillInRightContainer == true) {
                $(".chat-container").height(
                    $(window).height() - 72 + (isPillInRightContainer ? -pillHeight : pillHeight)
                );
                const chatContainer = document.querySelector('.chat-container');
                if (chatContainer) {
                    chatContainer.style.borderRadius = '16px 0px 16px 16px';
                }

            } else {
                $(".chat-container").height(
                    $(window).height() - 72
                );
            }

            const hideInstructionsWindow = <?php echo isset($study) && is_array($study) && isset($study["hideInstructionsWindow"]) ? $study["hideInstructionsWindow"] : 1; ?>;
            const hideSubmissionWindow = <?php echo isset($study) && is_array($study) && isset($study["hideSubmissionWindow"]) ? $study["hideSubmissionWindow"] : 1; ?>;

            if (hideInstructionsWindow == 1 && hideSubmissionWindow == 1) {

                const leftColumn = document.querySelector('.left-column');
                if (leftColumn) {
                    leftColumn.style.display = 'none';
                }

                const rightColumn = document.querySelector('.right-column');
                if (rightColumn) {
                    rightColumn.style.margin = '0 auto';
                }

            }
        }

        // Function to adjust height on both document ready and window load
        function setupHeightAdjustment() {
            // Adjust heights initially on document ready
            adjustHeights();

            // Listen for window resize and adjust heights dynamically
            $(window).resize(function() {
                adjustHeights();
            });
        }

        // Adjust heights when DOM is ready
        $(document).ready(function() {
            setupHeightAdjustment();
        });

        // Adjust heights when the entire page (including resources) is loaded
        $(window).on("load", function() {
            adjustHeights();
        });
    </script>

    <!-- Allowing the instructions to be collapsed -->
    <script type="text/javascript">
        function toggleText() {
            var content = document.getElementById('descriptionContent');
            var icon = document.getElementById('toggleIcon');
            if (content.style.display === "none") {
                content.style.display = "block";
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
            } else {
                content.style.display = "none";
                icon.classList.remove('fa-chevron-up');
                icon.classList.add('fa-chevron-down');
            }
            adjustHeights()
        }
    </script>

    <!-- Lightbox Modal -->
    <div class="lightbox" id="lightbox">
        <span class="lightbox-close" id="lightbox-close" onclick="closeLightbox()">&times;</span>
        <img id="lightbox-image" src="" alt="Enlarged Image" />
    </div>

    <script>
        // Trigger file input click on button click
        var imageUploadButton = document.getElementById('image-upload-button');
        if (imageUploadButton) {
            document.addEventListener('DOMContentLoaded', function() {
                imageUploadButton.addEventListener('click', function() {
                    var fileInput = document.getElementById('file-input');
                    if (fileInput) {
                        fileInput.click(); // Triggers the hidden file input
                    }
                });

                // Handle file upload
                document.getElementById('file-input').addEventListener('change', function() {
                    const file = this.files[0];
                    if (!file) return; // Ensure a file is selected

                    const formData = new FormData();
                    formData.append('image', file);

                    // Send file to server
                    fetch('Backend/Chat/message-image-upload.php', {
                            method: 'POST',
                            body: formData,
                        })
                        .then((response) => response.json())
                        .then((data) => {
                            const statusBar = document.getElementById('upload-status');
                            if (data.status === 'success') {
                                imgURL = data.url || ''; // Extract image URL from response
                                uploadedFilename = data.filename || '';

                                if (!imgURL) {
                                    console.error('Image URL is missing in the response.');
                                    return;
                                }

                                console.log(imgURL); // Log the URL to ensure it's valid

                                // Show success message with the thumbnail and remove icon
                                statusBar.innerHTML = `
                                <img id="thumbnail" src="${imgURL}" alt="Thumbnail" style="max-width: 100px; max-height: 100px; margin-top: 10px;border-radius:10px; cursor: pointer;" />
                                <span class="upload-text">Image successfully uploaded (${file.name})</span>
                                <span id="remove-upload" class="remove-upload" style="cursor: pointer;">&times;</span>`;
                                statusBar.style.display = 'flex';
                                statusBar.style.backgroundColor = '#00b894'; // Green for success
                                statusBar.style.color = '#fff'; // White text
                                statusBar.classList.add('success');

                                // Attach event listener for the "X" to remove upload
                                document.getElementById('remove-upload').addEventListener('click', function() {
                                    resetUpload(); // Call the resetUpload function when "X" is clicked
                                });

                                // Attach click event to the thumbnail to open the lightbox
                                document.getElementById('thumbnail').addEventListener('click', function() {
                                    openLightbox(imgURL);
                                });
                            } else {
                                // Show error message in case of failure
                                statusBar.innerHTML = `
                                <span class="upload-text">${(data.message || 'Upload failed').replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":"&#39;"})[c])}, please try again!</span>`;
                                statusBar.style.display = 'flex';
                                statusBar.style.backgroundColor = '#e74c3c'; // Red for error
                                statusBar.style.color = '#fff'; // White text
                                statusBar.classList.add('error');
                            }
                        })
                        .catch((error) => {
                            console.error('Error:', error);
                        });
                });

            });
        }
    </script>

    <script>
        function openLightbox(imageUrl) {
            const lightbox = document.getElementById('lightbox');
            const lightboxImage = document.getElementById('lightbox-image');
            if (imageUrl) {
                lightboxImage.src = imageUrl;
                lightbox.style.display = 'flex'; // Show the lightbox
            }
        }

        /**
         * Close the image lightbox
         */

        function closeLightbox() {
            const lightbox = document.getElementById('lightbox');
            const lightboxImage = document.getElementById('lightbox-image');
            lightbox.style.display = 'none'; // Hide the lightbox
            lightboxImage.src = ''; // Clear the image source
        }

        function resetUpload() {
            const statusBar = document.getElementById('upload-status');
            statusBar.innerHTML = ''; // Clear the status bar
            statusBar.style.display = 'none'; // Hide the status bar
        }
    </script>

</body>

</html>