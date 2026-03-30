<?php
/**
 * chat-backend-create.php
 *
 * Study configuration interface for researchers to create and edit studies.
 * Allows configuration of AI models, UI customization, and participant settings.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

session_start();

// =============================================================================
// SECURITY HEADERS
// =============================================================================

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// =============================================================================
// AUTHENTICATION CHECK
// =============================================================================

if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
  // Detect HTTPS
  $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') 
             || $_SERVER['SERVER_PORT'] == 443
             || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
  
  $protocol = $isHttps ? 'https://' : 'http://';
  $hostname = $_SERVER['HTTP_HOST'];
  $path = dirname($_SERVER['PHP_SELF']);
  
  header('Location: ' . $protocol . $hostname . ($path === '/' ? '' : $path) . '/login.php');
  exit;
}

if (!isset($_SESSION['userID'])) {
  session_destroy();
  header('Location: login.php');
  exit;
}

// =============================================================================
// CSRF TOKEN GENERATION
// =============================================================================

if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

// =============================================================================
// DATABASE CONNECTION
// =============================================================================

require 'Backend/MySQL/medoo.php';
require 'Backend/MySQL/medoo-Credentials.php';
require 'Backend/Util/crypto.php';

// =============================================================================
// CONFIGURATION
// =============================================================================

// Determine base URL from environment
$baseURL = $env['BASE_URL'] ?? '';

// =============================================================================
// VALIDATE INPUT AND AUTHORIZATION
// =============================================================================

// Get and type-cast user ID
$userID = (int)$_SESSION['userID'];

// Validate study ID parameter
if (!isset($_GET['studyID'])) {
  header('Location: index.php');
  exit;
}

$studyID = (int)$_GET['studyID'];

if ($studyID <= 0) {
  header('Location: index.php');
  exit;
}

// Get user data
$user = $database->get("users", "*", ["userID" => $userID]);

if (!$user) {
  session_destroy();
  header('Location: login.php');
  exit;
}

// Get study data
$study = $database->get("studies", "*", ["studyID" => $studyID]);

// CRITICAL: Verify user owns this study
if (!$study) {
  header('Location: access-denied.php');
  exit;
}

$studyOwnerID = (int)$study["studyOwner"];

if ($studyOwnerID !== $userID) {
  error_log("Authorization violation: User $userID attempted to edit study $studyID owned by $studyOwnerID");
  header('Location: access-denied.php');
  exit;
}

// =============================================================================
// DECRYPT STUDY FIELDS IF ENCRYPTION IS ENABLED
// =============================================================================

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
    'openaiReasoningEffort',
    'openaiHideReasoning',
    'aiDelay',
    'aiDelayIsPerCharacter',
    'aiDelayBeforeFirstMessage',
    'customConnectorConfiguration'
  ];
  
  foreach ($decryptFields as $field) {
    if (isset($study[$field]) && $study[$field] !== '') {
      $decrypted = decryptString($study[$field]);
      if ($decrypted !== false) {
        $study[$field] = $decrypted;
      }
    }
  }
}

// =============================================================================
// FETCH STATISTICS
// =============================================================================

// Count messages
$numberMessages = $database->count("messages", [
  "studyID" => $studyID,
  "senderType" => "Participant"
]);

// Get unique participants
$participantIDs = $database->select("messages", "*", [
  "studyID" => $studyID,
  "senderType" => "Participant"
]);
$numberParticipants = count(array_unique(array_column($participantIDs, 'participantID')));

// Count submissions
$numberSubmissions = $database->count("submissions", ["studyID" => $studyID]);

// =============================================================================
// ESCAPE OUTPUT VARIABLES FOR XSS PROTECTION
// =============================================================================

$displayStudyName = htmlspecialchars($study["studyName"] ?? '', ENT_QUOTES, 'UTF-8');
$displayUserName = htmlspecialchars($user["userName"] ?? '', ENT_QUOTES, 'UTF-8');
$displayUserSurname = htmlspecialchars($user["userSurname"] ?? '', ENT_QUOTES, 'UTF-8');
$displayFullName = $displayUserName . ' ' . $displayUserSurname;
$safeStudyCode = htmlspecialchars($study["studyCode"] ?? '', ENT_QUOTES, 'UTF-8');
$safeCsrfToken = htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8');
$safeBaseURL = htmlspecialchars($baseURL, ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Edit study</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
  <!--FontAwesome-->
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/solid.min.css">
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/light.min.css">
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/regular.min.css">
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/brands.min.css">
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/fontawesome.min.css">
  <!--Coloris color picker-->
  <link rel="stylesheet" href="src/CSS/coloris.min.css">
  <!--IziToast-->
  <link rel="stylesheet" href="src/CSS/iziToast.min.css">
  <!--RadioAccordion-->
  <link rel="stylesheet" href="src/CSS/mb.radioAccordion.css?v=2410231008">
  <!--Stepper-->
  <link rel="stylesheet" href="src/CSS/mb.stepper.css">
  <!--Color picker-->
  <link rel="stylesheet" href="src/CSS/mb.colorPicker.css">

  <style>
    /* Hide the labels in all rows for the passed variable, only for the first one show them */
    #passedVariablesList .columns label,
    #previewPassedVariablesList .columns label,
    #linkBuilderPassedVariablesList .columns label,
    #experimentalConditionsList .columns label {
      display: none;
    }

    /* Show the labels in the first row for the passed variable */
    #passedVariablesList .columns:first-child label,
    #previewPassedVariablesList .columns:first-child label,
    #linkBuilderPassedVariablesList .columns:first-child label,
    #experimentalConditionsList .columns:first-child label {
      display: block;
    }

    .mbHelpButton {
      cursor: pointer;
      height: 24px;
      width: 24px;
      border-radius: 50%;
      display: inline-block;
      text-align: center;
      line-height: 24px;
      margin-left: 5px;
      background-color: #eff5fb;
      color: #296fa8;
      border-style: none;
      font-size: 11px;
      vertical-align: top;
    }

    .mbHelpButton:hover {
      background-color: #deecfa;
    }

    .mbHelpButton.big {
      height: 29px;
      width: 29px;
      line-height: 29px;
      font-size: 12px;
      margin-top: 4px;
    }

    .mbHelpBox {
      display: none;
    }

    .mbHelpBox.display {
      display: block;
    }

    .mbHelpBox p {
      font-size: 14px;
    }

    .mbHelpBox .colWithIcon {
      width: 70px;
      flex: none;
      display: flex;
      align-items: center;
    }

    .mbHelpBox .column:nth-of-type(2) {
      display: flex;
      align-items: center;
    }

    .mbHelpBox .icon {
      background-color: rgba(0, 0, 0, 0.05);
      padding: 10px;
      border-radius: 50%;
      width: 40px;
      height: 40px;
    }

    #aiAvatarPreview.round {
      border-radius: 50%;
    }

    .statusCheckContainer.ok .is-warning,
    .statusCheckContainer.ok .is-danger {
      display: none;
    }

    .statusCheckContainer.warning .is-success,
    .statusCheckContainer.warning .is-danger {
      display: none;
    }

    .statusCheckContainer.error .is-success,
    .statusCheckContainer.error .is-warning,
    .statusCheckContainer.error .is-info {
      display: none;
    }

    .statusCheckContainer.info .is-success,
    .statusCheckContainer.info .is-warning,
    .statusCheckContainer.info .is-danger {
      display: none;
    }

    .statusCheckContainer.ok .is-info,
    .statusCheckContainer.warning .is-info {
      display: none;
    }
  </style>
</head>

<body>
  <!-- Navbar START-->
  <nav class="navbar" role="navigation" aria-label="main navigation">
    <div class="navbar-brand">
      <a class="navbar-item" href="index.php">
        <b>ResearchChatAI</b>
      </a>

      <a role="button" class="navbar-burger" aria-label="menu" aria-expanded="false" data-target="navbarBasicExample">
        <span aria-hidden="true"></span>
        <span aria-hidden="true"></span>
        <span aria-hidden="true"></span>
      </a>
    </div>

    <div id="navbarBasicExample" class="navbar-menu">
      <div class="navbar-start">
        <a class="navbar-item" href="index.php">
          Home
        </a>

        <a class="navbar-item" href="/documentation/">
          Documentation
        </a>
        <a class="navbar-item" href="status.php">
          System Status
        </a>
      </div>

      <div class="navbar-end">
        <div class="navbar-item has-dropdown is-hoverable">
          <a class="navbar-link">
            Account
          </a>

          <div class="navbar-dropdown  is-right">
            <div class="dropdown-item">
              <b><?php echo $displayFullName; ?></b>
            </div>
            <a class="navbar-item" href="profile-edit.php">
              Edit profile
            </a>
            <hr class="navbar-divider">
            <a href="logout.php" class="navbar-item">
              Logout
            </a>
          </div>
        </div>
      </div>
    </div>
  </nav>
  <!-- Navbar END-->

  <!--Header START-->
  <div class="container" style="max-width: 760px;">
    <section class="section">
      <h1 class="title is-1 mb-1" id="studyName">
        <?php echo $displayStudyName; ?>
      </h1>
      <h1 class="label mt-9" style="font-weight: normal;">
        <b id="numberResponses"><?php echo $numberParticipants; ?></b> respondents |
        <b id="numberDataPoints"><?php echo $numberMessages; ?></b> messages |
        <b id="numberSubmission"><?php echo $numberSubmissions; ?></b> submissions
      </h1>
      <div class="columns mt-4" style="flex-wrap: wrap; justify-content: center;">
        <div class="column">
          <a class="button is-info is-light is-fullwidth" href="chat-backend-create.php?studyID=<?php echo $studyID; ?>">
            <span class="icon is-small">
              <i class="fa fa-tasks"></i>
            </span>
            <span>Edit study</span>
          </a>
        </div>
        <div class="column">
          <a class="button is-info is-light is-fullwidth" href="chat-backend-review.php?studyID=<?php echo $studyID; ?>">
            <span class="icon is-small">
              <i class="fa fa-table"></i>
            </span>
            <span>View data</span>
          </a>
        </div>
        <div class="column">
          <a class="button is-info is-light is-fullwidth js-modal-trigger" data-target="previewModal" onclick="updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </a>
        </div>
      </div>
      <div class="columns" style="flex-wrap: wrap; justify-content: center;">
        <div class="column">
          <a class="button is-success is-light is-fullwidth"
            href="Backend/Studies/study-export.php?studyID=<?= $studyID ?>" download onclick="iziToast.success({title: 'Export', message: 'Your study has been exported. The download should start momentarily.', position: 'bottomRight'});">
            <span class="icon is-small">
              <i class="fa fa-file-export"></i>
            </span>
            <span>Export</span>
          </a>
        </div>
        <div class="column">
          <button class="button is-warning is-light js-modal-trigger is-fullwidth" data-target="renameStudyModal">
            <span class="icon is-small">
              <i class="fa fa-pencil"></i>
            </span>
            <span>Rename study</span>
          </button>
        </div>
        <div class="column">
          <button class="button is-danger is-light js-modal-trigger is-fullwidth" data-target="deleteStudyModal">
            <span class="icon is-small">
              <i class="fa fa-trash"></i>
            </span>
            <span>Delete study</span>
          </button>
        </div>
      </div>
    </section>
  </div>
  <!--Header END-->

  <!---Separator START-->
  <div style="background-color: #ff7f50ae; height:10px"></div>
  <!---Separator END-->

  <!-- Stepper START -->
  <ol class="c-stepper">
    <li class="c-stepper__item current">
      <a class="stepper" id="experimentalSetupStep" data-target="experimentalSetupContainer">
        <div class="c-stepper__icon">
          <i class="fas fa-sliders-v"></i>
        </div>
        <h3 class="c-stepper__title">Step 1</h3>
        <p class="c-stepper__desc">Study setup</p>
      </a>
    </li>
    <li class="c-stepper__item inactive">
      <a class="stepper" id="aiAttributesStep" data-target="aiAttributesContainer">
        <div class="c-stepper__icon">
          <i class="fas fa-robot"></i>
        </div>
        <h3 class="c-stepper__title">Step 2</h3>
        <p class="c-stepper__desc">AI attributes</p>
      </a>
    </li>
    <li class="c-stepper__item inactive">
      <a class="stepper" id="aiInstructionsStep" data-target="aiInstructionsContainer">
        <div class="c-stepper__icon">
          <i class="fas fa-comments"></i>
        </div>
        <h3 class="c-stepper__title">Step 3</h3>
        <p class="c-stepper__desc">AI instructions</p>
      </a>
    </li>
    <li class="c-stepper__item inactive">
      <a class="stepper" id="participantInstructionsStep" data-target="participantSettingsContainer">
        <div class="c-stepper__icon">
          <i class="fas fa-users"></i>
        </div>
        <h3 class="c-stepper__title">Step 4</h3>
        <p class="c-stepper__desc">Participant settings</p>
      </a>
    </li>
    <li class="c-stepper__item inactive">
      <a class="stepper" id="distributionStep" data-target="distributionContainer" onclick="conductPrelaunchCheck();">
        <div class="c-stepper__icon">
          <i class="fas fa-share-alt"></i>
        </div>
        <h3 class="c-stepper__title">Step 5</h3>
        <p class="c-stepper__desc">Distribution</p>
      </a>
    </li>
  </ol>

  <!------------------------------------------------------------>
  <!------------------------------------------------------------>
  <!------------------------------------------------------------>

  <div id="experimentalSetupContainer" class="stepContainer">
    <div class="container" style="max-width: 760px; margin-top: 48px;">
      <section class="section has-background-warning-light">
        <p class="title is-3">Step 1: Study setup</p>
        <p>The below settings cover some basic logistics relating to the study setup. As for all other settings as well, you can still come back later and change any of these in case you are unsure.</p>
      </section>
    </div>

    <!--Experimental conditions START-->
    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3" id="experimentalConditionsTitle">Experimental conditions <button class="mbHelpButton big" mbHelpTarget="#experimentalConditionsHelp"><i class="fa fa-question"></i></button></h4>
        <!--Help START-->
        <div class="mbHelpBox notification is-info is-light mt-5" id="experimentalConditionsHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> In ResearchChatAI you can easily implement different experimental conditions. For example, half of the participants might communicate with an enthusiastic AI and the other half with a more sober AI. By default, ResearchChatAI randomly assigns participants to one of the experimental conditions. Alternatively, you can assign experimental conditions before participants open ResearchChatAI (e.g., in a Qualtrics survey). Learn more in Step 5 or <a href="<?php echo $baseURL; ?>documentation.php?tile=ExperimentalConditions" target="_blank">here</a>.</p>
            </div>
          </div>
        </div>
        <!--Help END-->
        <div class="field mt-5" id="experimentalConditionsList">
        </div>

        <!--no experimental conditions message-->
        <div class="notification is-light mt-5 has-text-centered" id="noExperimentalConditionsMessage">
          No conditions have been added yet.

          <div class="field mt-2">
            <button class="button is-primary is-light is-small addExperimentalConditionButton" onclick="addExperimentalCondition();">
              <span class="icon is-small">
                <i class="fa fa-plus"></i>
              </span>
              <span>Add experimental condition</span>
            </button>
          </div>
        </div>

        <div class="field mt-5 mb-5" id="addExperimentalConditionMainButtonContainer">
          <button class="button is-primary is-light addExperimentalConditionButton" onclick="addExperimentalCondition();">
            <span class="icon is-small">
              <i class="fa fa-plus"></i>
            </span>
            <span>Add experimental condition</span>
          </button>
        </div>

      </section>
      <!--Experimental conditions END-->
    </div>

    <hr>

    <!--Survey flow START-->
    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3" id="welcomeMessageTitle">
          "Welcome"-message
          <button class="mbHelpButton big" mbHelpTarget="#welcomeMessageHelp"><i class="fa fa-question"></i></button>
          <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(1);updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </button>
        </h4>
        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light" id="welcomeMessageHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> This message will be shown right after ResearchChatAI is launched. A "welcome"-message can be helpflul to simply greet participants or to highlight certain information (e.g., "Please make sure to finish within the allocated time").</p>
            </div>
          </div>
        </div>
        <!--Help box END-->

        <!--Welcome message START-->
        <div class="field">
          <label class="checkbox">
            <input type="checkbox" id="hideWelcomeMessageCheckbox" class="trackChanges mbToggle" fieldKey="hideWelcomeMessage" saveIndicatorElement="#welcomeMessageTitle" mbtoggletargets="#welcomeMessageInputContainer" mbtogglecheckedaction="hide" <?php echo ($study["hideWelcomeMessage"] == 1) ? "checked" : ""; ?> />
            Hide "welcome"-message
          </label>

          <div id="welcomeMessageInputContainer" <?php echo ($study["hideWelcomeMessage"] == 1) ? "style='display: none;'" : ""; ?>>
            <label class="label mt-3">"Welcome"-message text</label>
            <textarea class="textarea trackChanges" fieldKey="welcomeMessage" saveIndicatorElement="#welcomeMessageTitle" id="welcomeMessageInput"
              placeholder="e.g., Thank you for participating in this research study. Please make sure to finish on time to not delay the session." style="min-height: 75px; height: 75px;"><?php echo $study["welcomeMessage"]; ?></textarea>
          </div>
        </div>
        <!--Welcome message END-->
      </section>
    </div>

    <hr>

    <!--Legal notice START-->
    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3" id="legalNoticeTitle">
          Legal notice
          <button class="mbHelpButton big" mbHelpTarget="#legalNoticeHelp"><i class="fa fa-question"></i></button>
        </h4>
        <div class="mbHelpBox notification is-info is-light" id="legalNoticeHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> In accordance with EU law, participants receive a legal notice on their first visit to ResearchChatAI, requesting their agreement to the Terms of Service and License Agreement. You may hide this notice, but if you do, you must obtain these consents elsewhere in your survey flow (e.g., in a Qualtrics survey) before participants interact with ResearchChatAI. The Terms of Service are available at <a href="<?php echo $baseURL; ?>Terms_of_Service_ResearchChatAI.pdf" target="_blank">here</a> and the License Agreement at <a href="<?php echo $baseURL; ?>Privacy_Statement_ResearchChatAI.pdf" target="_blank">here</a>.</p>
            </div>
          </div>
        </div>
        <div class="field">
          <label class="checkbox">
            <input type="checkbox" id="hideLegalNoticeCheckbox" class="trackChanges mbToggle" fieldKey="hideLegalNotice" saveIndicatorElement="#legalNoticeTitle" mbtoggletargets="#legalNoticeWarningBox" mbtogglecheckedaction="show" <?php echo ($study["hideLegalNotice"] == 1) ? "checked" : ""; ?> />
            Hide legal notice on start
          </label>
        </div>
        <div class="mbHelpBox display notification is-danger is-light mt-3" id="legalNoticeWarningBox" <?php echo ($study["hideLegalNotice"] == 1) ? "" : "style='display: none;'"; ?>>
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-exclamation-triangle"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Warning:</b> You have disabled the legal notice that appears when participants first open ResearchChatAI. Make sure that participants provide their agreement to the Terms of Service and License Agreement elsewhere in your survey flow before interacting with ResearchChatAI to maintain compliance with EU law. The Terms of Service are available <a href="<?php echo $baseURL; ?>Terms_of_Service_ResearchChatAI.pdf" target="_blank">here</a> and the License Agreement <a href="<?php echo $baseURL; ?>Privacy_Statement_ResearchChatAI.pdf" target="_blank">here</a></p>
            </div>
          </div>
        </div>
      </section>
    </div>
    <!--Legal notice END-->

    <hr>

    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3" id="closeButtonTitle">
          "Close"-button
          <button class="mbHelpButton big" mbHelpTarget="#closeButtonHelp"><i class="fa fa-question"></i></button>
          <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(1);updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light" id="closeButtonHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> The "close"-button is prominently displayed in the user interface. In case you provide a "redirect website URL" (e.g., to follow-up Qualtrics survey), ResearchChatAI will forward participants to this website once they click the close button. In case you leave this field empty, the window will simply be closed when clicking on the button.</p>
            </div>
          </div>
        </div>
        <!--Help box END-->

        <!--End of survey START-->
        <div class="field">
          <label class="checkbox">
            <input id="hideNextButtonCheckbox" type="checkbox" class="trackChanges mbToggle" fieldKey="hideNextButton" saveIndicatorElement="#closeButtonTitle" mbtoggletargets="#nextButtonSettings" mbtogglecheckedaction="hide" <?php echo ($study["hideNextButton"] == 1) ? "checked" : ""; ?> />
            Hide "close"-button
          </label>
        </div>

        <div id="nextButtonSettings" <?php echo ($study["hideNextButton"] == 1) ? "style='display: none;'" : ""; ?>>
          <div class="field mt-4">
            <label class="label">"Close"-button label</label>
            <input type="text" id="nextButtonLabelInput" class="input trackChanges" fieldKey="nextButtonLabel" saveIndicatorElement="#closeButtonTitle" placeholder="Default: End interaction" value="<?php echo $study["nextButtonLabel"]; ?>">
          </div>

          <div class="columns mt-3">
            <div class="column">
              <label class="label has-text-left">"Close"-button background color</label>
              <div class="control circle colorPickerContainer" id="nextButtonBgColorContainer">
                <input class="coloris trackChanges" fieldKey="nextButtonBgColor" saveIndicatorElement="#closeButtonTitle" type="text"
                  placeholder="Default: #477eac" value="<?php echo $study["nextButtonBgColor"]; ?>" data-coloris>
              </div>
            </div>
            <div class="column">
              <label class="label has-text-left">"Close"-button text color</label>
              <div class="control circle colorPickerContainer" id="nextButtonTextColorContainer">
                <input class="coloris trackChanges" fieldKey="nextButtonTextColor" saveIndicatorElement="#closeButtonTitle" type="text"
                  placeholder="Default: #ffffff" value="<?php echo $study["nextButtonTextColor"]; ?>" data-coloris>
              </div>
            </div>
          </div>

          <div class="field mt-4">
            <label class="label">Redirect Website URL (optional)</label>
            <input type="text" id="redirectURLInput" class="input trackChanges" fieldKey="redirectURL" saveIndicatorElement="#closeButtonTitle" placeholder="e.g., https://qualtrics.com/..." value="<?php echo $study["redirectURL"]; ?>">
          </div>

          <!--Protip START-->
          <div class="mbHelpBox display notification is-info is-light mt-5">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-lightbulb-on"></i>
                </span>
              </div>
              <div class="column">
                <p><b>ProTip:</b> In case you forward participants to another website (e.g., a follow-up Qualtrics survey), ResearchChatAI will forward the participantID, condition number, and all embedded variables. This makes it easy to match data accross different data sources and maintain a consistent user experience.</p>
              </div>
            </div>
          </div>
          <!--Protip END-->
        </div>

      </section>

      <!--Go to next step button with arrow right-->
      <section class="section mt-5" style="margin-bottom: 120px;">
        <button class="button is-primary is-pulled-right goToStepButton" data-target="2">Go to Step 2 <i
            class="fas fa-arrow-right ml-2"></i></button>
      </section>
    </div>
    <!--Survey flow END-->

  </div>

  <!------------------------------------------------------------>
  <!------------------------------------------------------------>
  <!------------------------------------------------------------>

  <div id="aiAttributesContainer" class="stepContainer" style="display: none;">
    <div class="container" style="max-width: 760px; margin-top: 48px;">
      <section class="section has-background-warning-light">
        <p class="title is-3">Step 2: AI attributes</p>
        <p>Below you can set the attributes of the AI assistant that will be used in the chat, such as its name, avatar, and description. You can also adapt the colors of the chat interface.
        </p>
      </section>
    </div>

    <!--AI attribute settings for name, (optional) avatar, and (optional) description, user text bubble color, ai text bubble color START-->
    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3 scrollHeading mt-5" id="aiIdentifyTitle">
          AI identity & introduction
          <button class="mbHelpButton big" mbHelpTarget="#aiAttributesHelp">
            <i class="fa fa-question"></i>
          </button>
          <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(currentlyActiveAiAttributesCondition+1);updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light mt-3" id="aiAttributesHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> Below you can set the attributes of the AI assistant that will be used in the chat, such as its name, avatar, and description. You can also adapt the colors of the chat interface. You can adapt each setting for different experimental conditions. Importantly, these settings do not affect the AI's behavior, but only its appearance.</p>
            </div>
          </div>
        </div>
        <!--Help box END-->

        <div class="tabs is-boxed mt-5" id="aiAttributesConditionsTabs">
          <ul>
          </ul>
        </div>

        <div class="field">

          <!--Conditions Specifications START-->
          <div class="field" id="aiAttributesConditionSpecificationContainer">
            These are the AI' attributes for <span id="aiAttributesConditionName"></span>. You can add experimental conditions in Step 1.
          </div>
          <!--Conditions Specifications END-->

          <!--button to copy attributes from one condition to another-->
          <div class="columns">
            <div class="column">
              <button class="button is-info is-light is-small is-fullwidth" id="copyAttributesButton" onclick="copyAiAttributes();">
                <span class="icon is-small">
                  <i class="fa fa-copy"></i>
                </span>
                <span>Copy attributes to all other conditions</span>
              </button>
            </div>
            <div class="column">
              <button class="button is-danger is-light is-small is-fullwidth" id="copyAttributesButton" onclick="eraseAiAttributes();">
                <span class="icon is-small">
                  <i class="fa fa-eraser"></i>
                </span>
                <span>Reset attributes for this condition</span>
              </button>
            </div>
          </div>

          <hr>

          <div class="field">
            <span class="label has-text-left" id="aiNameLabelContainer"><span id="aiNameLabel">AI name</span> <button class="mbHelpButton" mbHelpTarget="#aiNameHelp"><i class="fa fa-question"></i></button></span>
            <div class="control">
              <input id="aiNameInput" class="input" saveIndicatorElement="#aiNameLabel" type="text"
                placeholder="e.g., AI Assitant Arran" value="" style="max-width: 450px;">
            </div>
            <!--Help box START-->
            <div class="mbHelpBox notification is-info is-light mt-3" id="aiNameHelp">
              <div class="columns">
                <div class="column colWithIcon">
                  <span class="icon">
                    <i class="fa fa-question"></i>
                  </span>
                </div>
                <div class="column">
                  <p><b>Help:</b> This is the name of the AI that will be displayed at the top of the chat window. Importantly, you must also include this name in the AI's instructions, otherwise the AI will not be aware of it.</p>
                </div>
              </div>
            </div>
            <!--Help box END-->
          </div>

          <hr>

          <span class="label has-text-left" id="aiAvatarLabelContainer"><span id="aiAvatarLabel">AI avatar</span> <button class="mbHelpButton" mbHelpTarget="#aiAvatarHelp"><i class="fa fa-question"></i></button></span>

          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="aiAvatarHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p>
                  <b>Help:</b> This is the "profile picture" of the AI. You can either choose one of the preconfigured avatars or upload your own image. Enableing "Rounded corners" will give the avatar a round shape. Make sure that any image you upload is squared (i.e., has 1:1 ratio) as it might otherwise be distorted. You can adapt the avatar for different experimental conditions. Find out more <a href="<?php echo $baseURL; ?>documentation.php?tile=ExperimentalConditions" target="_blank">here</a>.
                </p>
              </div>
            </div>
          </div>
          <!--Help box END-->

          <div id="avatarContainer" <?php echo ($study["hideAiAvatar"] == 1) ? "style='display: none;'" : ""; ?>>
            <div class="field mt-0">
              <label class="checkbox">
                <input type="checkbox" id="aiAvatarRoundCheckbox" class="trackChanges" fieldKey="aiAvatarRound" saveIndicatorElement="#aiAvatarLabelContainer" <?php echo ($study["aiAvatarRound"] == 1) ? "checked" : ""; ?> onclick="$('#aiAvatarPreview').toggleClass('round');" />
                Rounded corners (for all conditions)
              </label>
            </div>

            <div class="columns" id="avatarUploadContainer">
              <div class="column">
                <button class="button is-info is-light is-fullwidth js-modal-trigger" data-target="avatarSelectionModal" id="selectAvatarButton">
                  <span class="icon is-small">
                    <i class="fa fa-images"></i>
                  </span>
                  <span>Choose avatar</span>
                </button>
              </div>
              <div class="column is-1" style="text-align: center; padding-top:19px;">
                OR
              </div>
              <div class="column">
                <button class="button is-info is-light is-fullwidth" id="uploadAvatarButton" onclick="$('#avatarFileUpload').click();">
                  <span class="icon is-small">
                    <i class="fa fa-upload"></i>
                  </span>
                  <span>Upload image</span>
                </button>
                <input type="file" id="avatarFileUpload" accept="image/*" style="display:none;" />
                <p class="help">Note: 128x128 pixels recommended. Max file size: 1MB.</p>
              </div>
            </div>

            <div class="mt-3" id="aiAvatarPreviewContainer" style="display: none;">
              <div style="display: flex; align-items: center;">
                <span class="p-3 has-background-light" style="height: 88px;">
                  <img src="" class="<?php echo ($study["aiAvatarRound"] == 1) ? "round" : ""; ?>" style="height: 64px; width: 64px;" id="aiAvatarPreview" />
                </span>
                <button class="button is-danger is-light ml-4" id="removeAvatarButton">
                  <span class="icon is-small">
                    <i class="fa fa-trash"></i>
                  </span>
                  <span>
                    Remove avatar
                  </span>
                </button>
              </div>
            </div>
          </div>

          <hr>

          <!--Option to hide AI status-->
          <span class="label has-text-left mt-5" id="aiStatusMessageLabelContainer"><span id="aiStatusMessageLabel">AI status message</span> <button class="mbHelpButton" mbHelpTarget="#aiStatusHelp"><i class="fa fa-question"></i></button></span>
          <div class="field mt-1" id="aiStatusMessageInputContainer">
            <div class="control">
              <input id="aiStatusMessageInput" class="input" type="text"
                placeholder="e.g., Your teacher for today" value="" style="max-width: 450px;">
            </div>
          </div>
          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="aiStatusHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p>
                  <b>Help:</b> This status messages will be shown directly below the AI's name in the chat window. For example, you can use it to give the AI a specific framing, such as "Responds within seconds" or the function title of "Investment Specialist". If not needed, you can simply hide this message.
                </p>
              </div>
            </div>
          </div>
          <!--Help box END-->

          <hr>

          <!--Option to hide AI description-->
          <span class="label has-text-left mt-5" id="aiDescriptionLabelContainer"><span id="aiDescriptionLabel">AI description</span> <button class="mbHelpButton" mbHelpTarget="#aiDescriptionHelp"><i class="fa fa-question"></i></button></span>
          <div class="field mt-1" id="aiDescriptionInputContainer">
            <div class="control">
              <input id="aiDescriptionInput" class="input" type="text"
                placeholder="Default: I am a helpful assistant." value="" style="max-width: 450px;">
            </div>
          </div>
          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="aiDescriptionHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p>
                  <b>Help:</b> This description will be shown at the top of the chat window. For example, you can use it to give the AI a specific framing, such as "You are talking to an AI", "Please be friendly", or "All interactions are being recorded for quality assurance purposes". If not needed, you can simply hide this message.
                </p>
              </div>
            </div>
          </div>
          <!--Help box END-->

          <hr>

          <!--Option to hide first message of AI-->
          <span class="label has-text-left mt-5" id="firstAiMessageLabelContainer"><span id="firstAiMessageLabel">First AI message</span> <button class="mbHelpButton" mbHelpTarget="#aiFirstMessageHelp"><i class="fa fa-question"></i></button></span>

          <div class="field mt-1" id="firstAiMessageInputContainer">
            <div class="control">
              <input id="firstAiMessageInput" class="input" type="text"
                placeholder="Default: Hi there! How can I help you?" value="" style="max-width: 450px;">
            </div>
          </div>
          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="aiFirstMessageHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p>
                  <b>Help:</b> This is the first message shown in the chat window. For example, you can can have the AI greet participants with a short "Hi there. How can I help you?" or a more extensive introduction. Later on in the conversation, the AI will be aware of having greeted participants in this way. If not needed, you can simply hide this message.
                </p>
              </div>
            </div>
          </div>
          <!--Help box END-->

          <hr>

          <!--Option for typing bubble text (defailt: Three dots are shown; not shown when streaming is enabled)-->
          <span class="label has-text-left mt-5" id="aiTypingBubbleLabelContainer"><span id="aiTypingBubbleLabel">AI "typing bubble"-text</span> <button class="mbHelpButton" mbHelpTarget="#aiTypingHelp"><i class="fa fa-question"></i></button></span>
          <div class="field mt-1" id="aiTypingBubbleTextInputContainer">
            <div class="control">
              <input id="aiTypingBubbleTextInput" class="input" type="text"
                placeholder="Default: [None]" value="" style="max-width: 450px;">
            </div>
          </div>
          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="aiTypingHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p>
                  <b>Help:</b> This is the text that will be shown in the typing bubble while the AI is typing. By default, no text is shown. You can change this text to anything you like (e.g., "Thinking..."). When setting this value to "&lt;DOTS&gt;", three dots will be shown.
                </p>
              </div>
            </div>
          </div>
          <!--Help box END-->

          <!-- AI typing bubble delay START -->
          <span class="label has-text-left mt-5" id="aiTypingBubbleDelayLabelContainer"><span id="aiTypingBubbleDelayLabel">AI "typing bubble" delay</span> <button class="mbHelpButton" mbHelpTarget="#aiTypingBubbleDelayHelp"><i class="fa fa-question"></i></button></span>
          <div class="field mt-1" id="aiTypingBubbleDelayInputContainer">
            <div class="control">
              <input id="aiTypingBubbleDelayInput" class="input" fieldKey="aiTypingBubbleDelay" type="text"
                placeholder="e.g., 1000 or 1000;3000" value="" style="max-width: 450px;">
            </div>
          </div>
          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="aiTypingBubbleDelayHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p>
                  <b>Help:</b> This controls how long to wait <em>before</em> showing the AI typing bubble. Importantly, this delay also postpones when the AI begins generating its answer. The field accepts two formats: <code>NUMBER</code> (a fixed delay in milliseconds, such as 1000) or <code>MIN;MAX</code> (a range in milliseconds, such as 1000;3000) from which a random value is chosen for each event.
                </p>
              </div>
            </div>
          </div>
          <!--Help box END-->

          <hr>

          <!--Option to set artificial delay for AI messages-->
          <span class="label has-text-left mt-5" id="aiDelayLabelContainer"><span id="aiDelayLabel">AI delay (in miliseconds)</span> <button class="mbHelpButton" mbHelpTarget="#aiDelayHelp"><i class="fa fa-question"></i></button></span>
          <div class="field mt-1" id="aiDelayInputContainer">
            <div class="control">
              <input id="aiDelayInput" class="input" type="text"
                placeholder="Default: 0" value="" style="max-width: 450px;">
            </div>
          </div>

          <!-- Per-character delay toggle -->
          <div class="field mt-3">
            <label class="checkbox">
              <input id="aiDelayIsPerCharacterCheckbox" type="checkbox" />
              Apply delay per character (non-streaming only)
            </label>
          </div>

          <!-- Delay before first AI message toggle -->
          <div class="field mt-3">
            <label class="checkbox">
              <input id="aiDelayBeforeFirstMessageCheckbox" type="checkbox" />
              Apply delay to the first AI message
            </label>
          </div>

          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="aiDelayHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p>
                  <b>Help:</b> Set a base delay (in <i>milliseconds</i>) that is added before each AI message to simulate a more human‑like cadence. By default, the AI responds instantly. Enter the base delay (e.g., <code>500</code>) to enable it. These settings (including the checkboxes) are <b>per condition</b>, so you can vary timing across experimental conditions.
                  <br><br>
                  <b>Apply delay per character:</b> When enabled, the base delay is multiplied by the message length in characters (e.g., <code>baseDelay × numCharacters</code>), leading to longer waits for longer messages and shorter waits for shorter messages. As streamed message always appear in chunks, this setting only applies to non-streamed messages.
                  <br><br>
                  <b>Apply delay to the first AI message:</b> When enabled, the same rules are also applied to the very first AI message (if a first message is enabled for that condition).
                  <br><br>
                  <b>Formats:</b> In addition to a single number in milliseconds (e.g., <code>500</code>), you may also provide a range using <code>MIN;MAX</code> (e.g., <code>1000;3000</code>). When a range is provided, a random value from that range is used each time. Like other timing settings, the chosen delay occurs <em>before</em> the AI starts composing its response.
                </p>
              </div>
            </div>
          </div>

          <!--Protip START-->
          <div class="mbHelpBox display notification is-info is-light mt-5">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-lightbulb-on"></i>
                </span>
              </div>
              <div class="column">
                <p><b>ProTip:</b> All of the above AI attributes support embedded variables <code>{{...}}</code>.
              </div>
            </div>
          </div>
          <!--Protip END-->

      </section>
    </div>

    <hr>

    <div class="container" style="max-width: 760px;">
      <section class="section">

        <!--Send button text and background color-->
        <div class="field">
          <h4 class="title is-3 scrollHeading" id="chatAppearanceTitle">Chat appearance
            <button class="mbHelpButton big" mbHelpTarget="#chatAppearanceHelp"><i class="fa fa-question"></i></button>
            <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(currentlyActiveAiAttributesCondition+1);updatePreviewIframe();">
              <span class="icon is-small">
                <i class="fa fa-eye"></i>
              </span>
              <span>Preview</span>
            </button>
          </h4>

          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="chatAppearanceHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p>
                  <b>Help:</b> The chat appearance settings allow you to customize the look and feel of the chat window. The <b>"send"-button</b> is the button that participants click to send their message. The <b>"user bubble"</b> is the chat bubble that shows the participant's messages. The <b>"AI bubble"</b> is the chat bubble that shows the AI's messages. You can customize the background and text color of each of these elements.
                </p>
              </div>
            </div>
          </div>
          <!--Help box END-->

          <div class="columns">
            <div class="column">
              <label class="label has-text-left">"Send"-button background color</label>
              <div class="control circle colorPickerContainer">
                <input id="sendButtonBgColorInput" class="coloris trackChanges" fieldKey="sendButtonBgColor" saveIndicatorElement="#chatAppearanceTitle" type="text"
                  placeholder="Default: #00b894" value="<?php echo $study["sendButtonBgColor"]; ?>" data-coloris>
              </div>
            </div>
            <div class="column">
              <label class="label has-text-left">"Send"-button text color</label>
              <div class="control circle colorPickerContainer">
                <input id="sendButtonTextColorInput" class="coloris trackChanges" fieldKey="sendButtonTextColor" saveIndicatorElement="#chatAppearanceTitle" type="text"
                  placeholder="Default: #ffffff" value="<?php echo $study["sendButtonTextColor"]; ?>" data-coloris>
              </div>
            </div>
          </div>

          <!--User text bubble text and background color-->
          <div class="columns mt-2">
            <div class="column">
              <label class="label has-text-left">"User bubble" background color</label>
              <div class="control circle colorPickerContainer">
                <input id="userBubbleBgColorInput" class="coloris trackChanges" fieldKey="userBubbleBgColor" saveIndicatorElement="#chatAppearanceTitle" type="text"
                  placeholder="Default: #0984e3" value="<?php echo $study["userBubbleBgColor"]; ?>" data-coloris>
              </div>
            </div>
            <div class="column">
              <label class="label has-text-left">"User bubble" text color</label>
              <div class="control circle colorPickerContainer">
                <input id="userBubbleTextColorInput" class="coloris trackChanges" fieldKey="userBubbleTextColor" saveIndicatorElement="#chatAppearanceTitle"
                  type="text" placeholder="Default: #ffffff" value="<?php echo $study["userBubbleTextColor"]; ?>" data-coloris>
              </div>
            </div>
          </div>

          <!--AI text bubble text and background color-->
          <div class="columns mt-2">
            <div class="column">
              <label class="label has-text-left">"AI bubble" background color</label>
              <div class="control circle colorPickerContainer">
                <input id="aiBubbleBgColorInput" class="coloris trackChanges" fieldKey="aiBubbleBgColor" saveIndicatorElement="#chatAppearanceTitle" type="text"
                  placeholder="Default: #dfe6e9" value="<?php echo $study["aiBubbleBgColor"]; ?>" data-coloris>
              </div>
            </div>
            <div class="column">
              <label class="label has-text-left">"AI bubble" text color</label>
              <div class="control circle colorPickerContainer">
                <input id="aiBubbleTextColorInput" class="coloris trackChanges" fieldKey="aiBubbleTextColor" saveIndicatorElement="#chatAppearanceTitle" type="text"
                  placeholder="Default: #000000" value="<?php echo $study["aiBubbleTextColor"]; ?>" data-coloris>
              </div>
            </div>
          </div>

      </section>

      <!--Go to next step button with arrow right-->
      <section class="section mt-5" style="margin-bottom: 120px;">
        <button class="button is-primary is-pulled-right goToStepButton" data-target="3">Go to Step 3 <i
            class="fas fa-arrow-right ml-2"></i></button>
      </section>
    </div>
    <!--AII attribute settings END-->
  </div>

  <!------------------------------------------------------------>
  <!------------------------------------------------------------>
  <!------------------------------------------------------------>

  <div id="aiInstructionsContainer" class="stepContainer" style="display: none;">
    <div class="container" style="max-width: 760px; margin-top: 48px;">
      <section class="section has-background-warning-light">
        <p class="title is-3">Step 3: AI instructions</p>
        <p>
          Below you can provide instructions for the AI as well as custom settings for the LLM (Large Language Model) that will be used to power the chat.
        </p>
      </section>
    </div>

    <!--AI Instructions START-->
    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3 scrollHeading" id="gptInstructionsTitle">
          AI Instructions
          <button class="mbHelpButton big" mbHelpTarget="#gptInstructionsHelp">
            <i class="fa fa-question"></i>
          </button>
          <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(currentlyActiveGPTInstructionsCondition+1);updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light mt-3" id="gptInstructionsHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> The AI instructions tell the AI how to behave and provide the AI with relevant background information. These instructions can be as simple as "You are a helpful assistant" or span multiple paragraphs. You can use different AI instructions for different experimental conditions.
            </div>
          </div>
        </div>
        <!--Help box END-->

        <div class="tabs is-boxed mt-5" id="gptInstructionsConditionsTabs">
          <ul>
          </ul>
        </div>

        <div class="field">
          <!--Conditions Specifications START-->
          <div class="field" id="gptInstructionsConditionSpecificationContainer">
          </div>
          <!--Conditions Specifications END-->

          <!--Instructions text-->
          <label class="label has-text-left mt-5" id="gptInstructionsLabel">Instructions</label>
          <div class="control">
            <textarea class="textarea" placeholder="e.g., You are a helpful assistant..." style="max-width: 450px;"
              id="gptInstructionsInput"></textarea>
            <p class="help">
              Note: This field supports embedded variables (i.e., <code>{{...}}</code>).
            </p>
          </div>
        </div>
    </div>
    </section>
    <!--AI Instructions END-->

    <hr>

    <!--LLM API Settings START-->
    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3 scrollHeading" id="llmSettingsTitle">
          LLM settings
          <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(currentlyActiveGPTInstructionsCondition+1);updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </button>
        </h4>
        <p>
          Chat replies can be generated using one of three methods. You can use <strong>OpenAI's LLMs</strong>, such as ChatGPT or GPT-4o, by entering your OpenAI API key and selecting a model. You can also use a wide range of other models through <a href="https://openrouter.ai" target="_blank">OpenRouter</a>, such as Llama, Claude, or Gemini, by providing your OpenRouter API key and specifying the model name. OpenAI and OpenRouter models always use the seed <i>1106</i>, as long as the seed parameter is supported by the chosen model. A third option is to use a <strong>Custom Connector</strong>. This allows you to connect to any LLM endpoint by pasting a JSON configuration that follows our <a href="https://github.com/ResearchChatAI" target="_blank">Custom Connector v1 specification</a>. Regardless of which option you choose, please ensure that your account or endpoint is properly funded and that you are aware of potential usage costs. Different models vary in price, and especially for longer conversations, the total cost can be significant.
        </p>

        <div class="formRadioGroup mt-5">
          <div id="openAiModelProviderRadioButton" class="radioButton <?php echo ($study["modelProvider"] == "openai") ? "active" : ""; ?>" fieldKey="modelProvider" fieldValue="openai" saveIndicatorElement="#llmSettingsTitle" radioAccordionTarget="#followUpOpenAI">
            <span>Use OpenAI</span>
            <span class="circle"><i class="fas fa-check"></i></span>
          </div>
          <div id="followUpOpenAI" class="followUpContainer mt-3 mb-5" <?php echo ($study["modelProvider"] != "openai") ? "style='display:none;'" : ""; ?>>
            <div class="field mt-5">
              <label class="label has-text-left" id="openAiKeyLabel"> OpenAI API Key</label>
              <div class="control">
                <input id="openAiApiKeyInput" class="input trackChanges" fieldKey="openaiApiKey" saveIndicatorElement="#openAiKeyLabel" type="text"
                  placeholder="e.g., sk-..." value="<?php echo $study["openaiApiKey"]; ?>" style="max-width: 450px;">
                <p class="help">Note: You require an OpenAI API key to use their services.</p>
                </p>
              </div>
            </div>

            <div class="field mt-5">
              <label class="label has-text-left" id="openAiTemperatureLabel">Temperature</label>
              <div class="control">
                <input id="openaiTemperatureInput" class="input trackChanges" fieldKey="openaiTemperature" saveIndicatorElement="#openAiTemperatureLabel" type="text"
                  placeholder="Default: 0.8" value="<?php echo $study["openaiTemperature"]; ?>" style="max-width: 450px;">
                <p class="help">Note: The temperature parameter controls the randomness of the output. Lower temperatures make the model more confident, while higher temperatures make the model more creative. The default value is 0.8.</p>
              </div>
            </div>

            <!--Select model-->
            <div class="field mt-5">
              <label class="label has-text-left" id="openAiModelLabel">OpenAI Model</label>
              <div class="control">
                <div class="select">
                  <select id="modelSelect" class="trackChanges" fieldKey="openaiModel" saveIndicatorElement="#openAiModelLabel" onchange="document.getElementById('gpt5VerificationNotice').style.display=(this.value.startsWith('gpt-5'))?'':'none'">
                    <option value="gpt-5" <?php echo ($study["openaiModel"] == "gpt-5") ? "selected" : ""; ?>>GPT-5</option>
                    <option value="gpt-5-mini" <?php echo ($study["openaiModel"] == "gpt-5-mini") ? "selected" : ""; ?>>GPT-5-mini</option>
                    <option value="gpt-4o" <?php echo ($study["openaiModel"] == "gpt-4o") ? "selected" : ""; ?>>GPT-4o</option>
                    <option value="gpt-4o-mini" <?php echo ($study["openaiModel"] == "gpt-4o-mini") ? "selected" : ""; ?>>GPT-4o Mini</option>
                    <option value="gpt-4" <?php echo ($study["openaiModel"] == "gpt-4") ? "selected" : ""; ?>>GPT-4</option>
                    <option value="gpt-4-turbo" <?php echo ($study["openaiModel"] == "gpt-4-turbo") ? "selected" : ""; ?>>GPT-4 Turbo</option>
                  </select>
                </div>
              </div>
            </div>
            <div id="gpt5VerificationNotice"
              class="help has-text-danger"
              style="display: <?php echo (strncmp($study["openaiModel"], "gpt-5", 5) === 0) ? "" : "none"; ?>;">
              GPT-5 requires that your OpenAI account is verified. <a href="https://lyfeai.com.au/openai-id-verification-gpt5-access/" target="_blank" rel="noopener">Learn more.</a>
            </div>

            <!-- Reasoning effort (GPT-5 and mini models only) -->
            <div class="field mt-5" id="reasoningEffortField" style="display:none;">
              <label class="label has-text-left" id="openAiReasoningLabel">Reasoning Effort</label>
              <div class="control">
                <div class="select">
                  <select id="openaiReasoningSelect" class="trackChanges" fieldKey="openaiReasoningEffort" saveIndicatorElement="#openAiReasoningLabel">
                    <option value="" <?php echo ($study["openaiReasoningEffort"] == "") ? "selected" : ""; ?>>Default</option>
                    <option value="minimal" <?php echo ($study["openaiReasoningEffort"] == "minimal") ? "selected" : ""; ?>>Minimal</option>
                    <option value="low" <?php echo ($study["openaiReasoningEffort"] == "low") ? "selected" : ""; ?>>Low</option>
                    <option value="medium" <?php echo ($study["openaiReasoningEffort"] == "medium") ? "selected" : ""; ?>>Medium</option>
                    <option value="high" <?php echo ($study["openaiReasoningEffort"] == "high") ? "selected" : ""; ?>>High</option>
                  </select>
                </div>
              </div>
              <!-- Hide reasoning traces (GPT-5 and mini models only) -->
              <div class="field mt-3">
                <label class="checkbox">
                  <input type="checkbox" class="trackChanges" fieldKey="openaiHideReasoning" saveIndicatorElement="#openAiReasoningLabel" <?php echo ($study["openaiHideReasoning"] == 1) ? "checked" : ""; ?> />
                  Hide reasoning in chat
                </label>
                <p class="help">Note: When enabled, any available reasoning section from GPT‑5 models will be hidden from participants in the chat UI.</p>
              </div>
            </div>

            <!--Checkbox to enable streaming-->
            <div class="field mt-5">
              <label class="checkbox">
                <input type="checkbox" class="trackChanges" fieldKey="openaiEnableStreaming" saveIndicatorElement="#openAiModelLabel" <?php echo ($study["openaiEnableStreaming"] == 1) ? "checked" : ""; ?> />
                Enable streaming
              </label>
              <p class="help">Note: When "streaming" is enabled, parts of the AI's message will already be shown as the remainder is still being generated. This can make the conversation feel more natural as users need to wait less long for (parts of) the AI's response.</p>
            </div>
          </div>

          <div id="openRouterModelProviderRadioButton" class="radioButton <?php echo ($study["modelProvider"] == "openrouter") ? "active" : ""; ?>" fieldKey="modelProvider" fieldValue="openrouter" saveIndicatorElement="#llmSettingsTitle" radioAccordionTarget="#followUpOpenRouter">
            <span>Use OpenRouter</span>
            <span class="circle"><i class="fa fa-check"></i></span>
          </div>
          <div id="followUpOpenRouter" class="followUpContainer mt-3 mb-5" <?php echo ($study["modelProvider"] != "openrouter") ? "style='display:none;'" : ""; ?>>
            <!--OpenRouter API key-->
            <div class="field mt-5">
              <label class="label has-text-left" id="openRouterKeyLabel">OpenRouter API Key</label>
              <div class="control">
                <input id="openRouterApiKeyInput" class="input trackChanges" fieldKey="openrouterApiKey" saveIndicatorElement="#openRouterKeyLabel" type="text"
                  placeholder="e.g., sk-..." value="<?php echo $study["openrouterApiKey"]; ?>" style="max-width: 450px;">
                <p class="help">Note: You require an OpenRouter API key to use their services.</p>
                <p class="help">The backend uses a fixed seed of 1106.</p>
              </div>
            </div>

            <!--OpenRouter temperature-->
            <div class="field mt-5">
              <label class="label has-text-left" id="openRouterTemperatureLabel">Temperature</label>
              <div class="control">
                <input id="openrouterTemperatureInput" class="input trackChanges" fieldKey="openrouterTemperature" saveIndicatorElement="#openRouterTemperatureLabel" type="text"
                  placeholder="Default: 0.8" value="<?php echo $study["openrouterTemperature"]; ?>" style="max-width: 450px;">
                <p class="help">Note: The temperature parameter controls the randomness of the output. Lower temperatures make the model more confident, while higher temperatures make the model more creative. The default value is 0.8.</p>
              </div>
            </div>

            <!--Select model-->
            <div class="field mt-5">
              <label class="label has-text-left" id="openRouterModelLabel">OpenRouter Model</label>
              <div class="control">
                <input class="input trackChanges" fieldKey="openrouterModel" saveIndicatorElement="#openRouterModelLabel" type="text"
                  placeholder="e.g., anthropic/claude-3.5-sonnet" value="<?php echo $study["openrouterModel"]; ?>" style="max-width: 450px;">
                <p class="help">Note: You can use any model offered by OpenRouter. Simply provide here the full model name, such as "nvidia/llama-3.1-nemotron-70b-instruct" or "google/gemini-flash-1.5-8b". See a full list of models offered by OpenRouter here: <a href="https://openrouter.ai/docs/models" target="_blank">https://openrouter.ai/docs/models</a>. Please be aware that model names might change and that this will require you to update the name here.</p>
              </div>
            </div>

            <!--Checkbox to enable streaming-->
            <div class="field mt-5">
              <label class="checkbox">
                <input type="checkbox" class="trackChanges" fieldKey="openrouterEnableStreaming" saveIndicatorElement="#openRouterModelLabel" <?php echo ($study["openrouterEnableStreaming"] == 1) ? "checked" : ""; ?> />
                Enable streaming
              </label>
              <p class="help">Note: Note: When "streaming" is enabled, parts of the AI's message will already be shown as the remainder is still being generated. This can make the conversation feel more natural as users need to wait less long for (parts of) the AI's response.</p>
            </div>
          </div>

          <!-- ===== Custom Connector ===== -->
          <div id="customModelProviderRadioButton"
            class="radioButton <?php echo ($study["modelProvider"] == "custom") ? "active" : ""; ?>"
            fieldKey="modelProvider"
            fieldValue="custom"
            saveIndicatorElement="#llmSettingsTitle"
            radioAccordionTarget="#followUpCustom">
            <span>Use Custom&nbsp;Connector</span>
            <span class="circle"><i class="fa fa-check"></i></span>
          </div>

          <div id="followUpCustom"
            class="followUpContainer mt-3 mb-5"
            <?php echo ($study["modelProvider"] != "custom") ? "style='display:none;'" : ""; ?>>

            <!-- Explanation -->
            <div class="content mb-4">
              <p>
                Custom connectors let you connect to almost any AI model API, giving you
                even more flexibility than accessing models through OpenRouter. While we do
                not actively maintain these configurations and they may break at any point,
                we provide some popular templates below for easy setup. You can also write
                your own connector JSON from scratch at any time.
              </p>
            </div>

            <!-- Quick-start templates -->
            <div class="field mb-5">
              <label class="label has-text-left">Quick-start templates</label>

              <label class="label has-text-left" style="font-size:0.85rem;font-style:italic;">Anthropic Claude</label>
              <div class="table-container">
                <table class="table is-fullwidth is-hoverable" style="max-width:650px;">
                  <tbody>
                    <tr>
                      <td>No Streaming</td>
                      <td class="has-text-right" style="width:100px;">
                        <button class="button is-small is-info is-outlined js-choose-connector-tpl"
                          data-template="anthropic-no-streaming.json">Choose</button>
                      </td>
                    </tr>
                    <tr>
                      <td>Streaming</td>
                      <td class="has-text-right" style="width:100px;">
                        <button class="button is-small is-info is-outlined js-choose-connector-tpl"
                          data-template="anthropic-streaming.json">Choose</button>
                      </td>
                    </tr>
                    <tr>
                      <td>Streaming + Extended Thinking</td>
                      <td class="has-text-right" style="width:100px;">
                        <button class="button is-small is-info is-outlined js-choose-connector-tpl"
                          data-template="anthropic-streaming-thinking.json">Choose</button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <label class="label has-text-left" style="font-size:0.85rem;font-style:italic;">Mistral</label>
              <div class="table-container">
                <table class="table is-fullwidth is-hoverable" style="max-width:650px;">
                  <tbody>
                    <tr>
                      <td>No Streaming</td>
                      <td class="has-text-right" style="width:100px;">
                        <button class="button is-small is-info is-outlined js-choose-connector-tpl"
                          data-template="mistral-no-streaming.json">Choose</button>
                      </td>
                    </tr>
                    <tr>
                      <td>Streaming</td>
                      <td class="has-text-right" style="width:100px;">
                        <button class="button is-small is-info is-outlined js-choose-connector-tpl"
                          data-template="mistral-streaming.json">Choose</button>
                      </td>
                    </tr>
                    <tr>
                      <td>Streaming + Reasoning</td>
                      <td class="has-text-right" style="width:100px;">
                        <button class="button is-small is-info is-outlined js-choose-connector-tpl"
                          data-template="mistral-streaming-reasoning.json">Choose</button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <label class="label has-text-left" style="font-size:0.85rem;font-style:italic;">Google Gemini</label>
              <div class="table-container">
                <table class="table is-fullwidth is-hoverable" style="max-width:650px;">
                  <tbody>
                    <tr>
                      <td>No Streaming</td>
                      <td class="has-text-right" style="width:100px;">
                        <button class="button is-small is-info is-outlined js-choose-connector-tpl"
                          data-template="gemini-no-streaming.json">Choose</button>
                      </td>
                    </tr>
                    <tr>
                      <td>Streaming</td>
                      <td class="has-text-right" style="width:100px;">
                        <button class="button is-small is-info is-outlined js-choose-connector-tpl"
                          data-template="gemini-streaming.json">Choose</button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- Connector JSON -->
            <div class="field mt-5">
              <label class="label has-text-left" id="customConfigLabel">Connector&nbsp;JSON</label>
              <div class="control">
                <textarea id="customConfigInput"
                  class="textarea trackChanges"
                  fieldKey="customConnectorConfiguration"
                  saveIndicatorElement="#llmSettingsTitle"
                  placeholder='Paste your connector JSON here…'
                  style="max-width:650px;min-height:220px;"><?php
                                                            echo htmlspecialchars($study["customConnectorConfiguration"] ?? '', ENT_QUOTES);
                                                            ?></textarea>
                <p class="help">
                  Provide JSON that follows the <b>Custom&nbsp;Connector&nbsp;v1</b> spec. Learn more <a href="https://github.com/ResearchChatAI" target="_blank">here</a>.
                </p>
              </div>
            </div>

            <!-- Streaming toggle -->
            <div class="field mt-4">
              <div class="field mt-5">
                <label class="checkbox">
                  <input type="checkbox" class="trackChanges" fieldKey="customConnectorEnableStreaming" saveIndicatorElement="#customConfigLabel" <?php echo ($study["customConnectorEnableStreaming"] == 1) ? "checked" : ""; ?> />
                  Enable streaming&nbsp;
                  <span class="has-text-grey-light">
                    (still requires further specification in the connector JSON)
                  </span>
                </label>
              </div>
            </div>

            <!-- Hide reasoning traces -->
            <div class="field mt-4">
              <div class="field mt-3">
                <label class="checkbox">
                  <input type="checkbox" class="trackChanges" fieldKey="customConnectorHideReasoning" saveIndicatorElement="#customConfigLabel" <?php echo ($study["customConnectorHideReasoning"] == 1) ? "checked" : ""; ?> />
                  Hide reasoning in chat
                </label>
                <p class="help">Note: When enabled, any available reasoning section will be hidden from participants in the chat UI.</p>
              </div>
            </div>
          </div>
          <!-- ===== /Custom Connector ===== -->

        </div>
      </section>

      <hr>
      <!--Encryption Settings START-->
      <section class="section">
        <h4 class="title is-3 scrollHeading" id="encryptionSettingsTitle">
          Encryption
          <button class="mbHelpButton big" mbHelpTarget="#encryptionHelp">
            <i class="fa fa-question"></i>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light mt-3" id="encryptionHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> Choose how participant messages are protected. Both options encrypt stored data so that only you can read it. The difference is whether the ResearchChatAI server ever sees messages in plain text during processing.</p>
            </div>
          </div>
        </div>
        <!--Help box END-->

        <p>Choose how messages between participants and the AI are protected. This setting affects how data flows through our servers and how your API key is handled.</p>

        <div class="formRadioGroup mt-5">

          <!-- Server-Side Encryption -->
          <div class="radioButton <?php echo (($study["encryptionMode"] ?? 'server') == "server") ? "active" : ""; ?>"
            fieldKey="encryptionMode"
            fieldValue="server"
            saveIndicatorElement="#encryptionSettingsTitle"
            radioAccordionTarget="#followUpEncryptionServer">
            <span>Server-Side Encryption</span>
            <span class="circle"><i class="fa fa-check"></i></span>
          </div>
          <div id="followUpEncryptionServer" class="followUpContainer mt-3 mb-5"
            <?php echo (($study["encryptionMode"] ?? 'server') != "server") ? "style='display:none;'" : ""; ?>>
            <div class="notification is-light is-info">
              <p>
                <strong><i class="fa fa-shield-alt mr-1"></i> How it works:</strong>
                All conversation data is encrypted before it is saved in our database using your personal public key. This means that once a message is stored, <strong>only you can decrypt and read it</strong> &mdash; we as platform operators cannot access stored conversations.
              </p>
              <p class="mt-3">
                During message processing, the server briefly handles messages in plain text in order to forward them to the AI provider. We do not log, inspect, or store these plain-text messages.
                Your <strong>API key is securely managed on the server</strong> and is never exposed to participants or transmitted to the browser.
              </p>
              <p class="mt-3 has-text-grey">
                <i class="fa fa-info-circle mr-1"></i>
                This is the recommended setting for most studies. It provides strong data protection while keeping your API key safe.
              </p>
            </div>
          </div>

          <!-- End-to-End Encryption -->
          <div class="radioButton <?php echo (($study["encryptionMode"] ?? 'server') == "e2e") ? "active" : ""; ?>"
            fieldKey="encryptionMode"
            fieldValue="e2e"
            saveIndicatorElement="#encryptionSettingsTitle"
            radioAccordionTarget="#followUpEncryptionE2E">
            <span>End-to-End Encryption</span>
            <span class="circle"><i class="fa fa-check"></i></span>
          </div>
          <div id="followUpEncryptionE2E" class="followUpContainer mt-3 mb-5"
            <?php echo (($study["encryptionMode"] ?? 'server') != "e2e") ? "style='display:none;'" : ""; ?>>
            <div class="notification is-light is-success">
              <p>
                <strong><i class="fa fa-lock mr-1"></i> How it works:</strong>
                Messages are sent <strong>directly from the participant&rsquo;s device to the AI provider</strong>, completely bypassing the ResearchChatAI server. Before any data is sent back to ResearchChatAI for storage, it is encrypted on the participant&rsquo;s device using your public key. This means that we as platform operators <strong>can never, at any point, see the messages in plain text</strong>.
              </p>
            </div>
            <div class="notification is-light is-info mt-3">
              <p>
                <strong><i class="fa fa-exclamation-triangle mr-1"></i> Important: API Key Exposure Risk</strong>
              </p>
              <p class="mt-2">
                Because messages are sent directly from the participant&rsquo;s browser to the AI provider, <strong>your API key must be delivered to the browser</strong>. A technically savvy participant could extract the API key and use it for their own purposes, potentially incurring charges on your account.
              </p>
              <p class="mt-2"><strong>To minimize risk, you should:</strong></p>
              <ul class="mt-1" style="margin-left: 1.5em; list-style: disc;">
                <li><strong>Create a dedicated API key</strong> for this study only</li>
                <li>Set strict <strong>spending limits</strong> on the API key used for this study</li>
                <li><strong>Do not reuse</strong> this API key for other purposes</li>
                <li><strong>Delete the API key immediately</strong> after the study is completed</li>
              </ul>
              <p class="mt-3">
                <strong>By selecting end-to-end encryption, you accept the risk that an unauthorized user could steal and misuse the API key.</strong>
              </p>
            </div>
          </div>

        </div>
      </section>
      <!--Encryption Settings END-->

      <!--Go to next step button with arrow right-->
      <section class="section mt-5" style="margin-bottom: 120px;">
        <button class="button is-primary is-pulled-right goToStepButton" data-target="4">Go to Step 4 <i
            class="fas fa-arrow-right ml-2"></i></button>
      </section>
    </div>
    <!--LLM API Settings END-->
  </div>

  <!------------------------------------------------------------>
  <!------------------------------------------------------------>
  <!------------------------------------------------------------>

  <!--Participant instructions START-->
  <div id="participantSettingsContainer" class="stepContainer" style="display: none;">
    <div class="container" style="max-width: 760px; margin-top: 48px;">
      <section class="section has-background-warning-light">
        <p class="title is-3">Step 4: Participant settings</p>
        <p>Provide here the instructions for participants (e.g., their task or assignment). If not needed, you can hide the
          "Instruction"-window all together. You can also format the instructions to make them more readable (e.g., use bold text and bullet lists).</p>
        </p>
      </section>
    </div>

    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3 scrollHeading" id="participantInstructionsTitle">
          Participant instructions
          <button class="mbHelpButton big" mbHelpTarget="#participantInstructionsHelp">
            <i class="fa fa-question"></i>
          </button>
          <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(currentlyActiveParticipantInstructionsCondition+1);updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light mt-3" id="participantInstructionsHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> In the "participant instructions"-window, you can provide instructions to the participants about the task they need to complete. You can customize the instructions for each condition, using formatting to make them more easily readable and understandable. If not needed, you can hide this window.
            </div>
          </div>
        </div>
        <!--Help box END-->

        <div class="field mt-5">
          <label class="checkbox">
            <input type="checkbox" id="hideInstructionsWindowCheckbox" class="trackChanges mbToggle" fieldKey="hideInstructionsWindow" saveIndicatorElement="#participantInstructionsTitle" mbToggleTargets="#participantInstructionsContainer" mbToggleCheckedAction="hide" <?php echo ($study["hideInstructionsWindow"] == 1) ? "checked" : ""; ?> />
            Hide "Participant instructions"-window
          </label>
        </div>

        <div id="participantInstructionsContainer" <?php echo ($study["hideInstructionsWindow"] == 1) ? "style='display: none;'" : ""; ?>>
          <hr>

          <div class="tabs is-boxed mt-5" id="participantInstructionsConditionsTabs">
            <ul>
            </ul>
          </div>

          <!--Conditions Specifications START-->
          <div class="field" id="conditionSpecificationParticipantInstructionsContainer">

          </div>
          <!--Conditions Specifications END-->

          <!--Instructions text-->
          <h4 class="title is-4 mb-1 mt-5">Instructions</h4>
          Give instructions to the participants about the task they need to complete.
          <div class="field mt-3">
            <div class="control">
              <textarea class="textarea" placeholder="e.g., Please answer the following questions..."
                style="max-width: 450px;" id="participantInstructionsTextInput"></textarea>
              <p class="help">
                Note: This field supports embedded variables (i.e., <code>{{...}}</code>).</p>
              </p>
            </div>
          </div>
        </div>

      </section>
    </div>

    <!-- Participant instructions END -->

    <hr>

    <!--Submissions Window START-->
    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3" id="submissionsWindowTitle">Submissions window
          <button class="mbHelpButton big" mbHelpTarget="#submissionsWindowHelp">
            <i class="fa fa-question"></i>
          </button>
          <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(currentlyActiveParticipantInstructionsCondition+1);updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light mt-3" id="submissionsWindowHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> In the "submissions"-window, participants can provide a submission to a specific assignment. They will then see a text editor on the left side of the screen where they can write. If not needed, you can hide this window. You can set a placeholder that will be shown inside the text editor (e.g., "Provide your submission here...").</p>
            </div>
          </div>
        </div>
        <!--Help box END-->

        <div class="field mt-5">
          <label class="checkbox">
            <input type="checkbox" id="hideSubmissionsWindowCheckbox" class="trackChanges mbToggle" fieldKey="hideSubmissionWindow" saveIndicatorElement="#submissionsWindowTitle" mbToggleTargets="#submissionPlaceholderInputContainer, #wordCountSettingsContainer, #disableCopyPasteSubmissionContainer" mbToggleCheckedAction="hide" <?php echo ($study["hideSubmissionWindow"] == 1) ? "checked" : ""; ?> />
            Hide "Submissions"-window
          </label>
        </div>
        <div class="field mt-5" id="submissionPlaceholderInputContainer" <?php echo ($study["hideSubmissionWindow"] == 1) ? "style='display: none;'" : ""; ?>>
          <label class="label has-text-left">"Submission"-placeholder text</label>
          <div class="control">
            <input id="submissionPlaceholderInput" class="input trackChanges" fieldKey="submissionPlaceholder" saveIndicatorElement="#submissionsWindowTitle" type="text"
              placeholder="Default: Please provide your answer here." value="<?php echo $study["submissionPlaceholder"]; ?>" style="max-width: 450px;">
          </div>
        </div>

        <!--Toggle for DisableCopyPaste-->
        <div id="disableCopyPasteSubmissionContainer" class="field mt-5" <?php echo ($study["hideSubmissionWindow"] == 1) ? "style='display: none;'" : ""; ?>>
          <label class="checkbox">
            <input type="checkbox" class="trackChanges" fieldKey="disableCopyPasteSubmission" saveIndicatorElement="#submissionsWindowTitle" <?php echo ($study["disableCopyPasteSubmission"] == 1) ? "checked" : ""; ?> />
            Disable paste into submission window
          </label>
          <p class="help">Note: When "paste into submission window" is disabled, participants will not be able to copy and paste text into the text editor.</p>
        </div>

        <div id="wordCountSettingsContainer" <?php echo ($study["hideSubmissionWindow"] == 1) ? "style='display: none;'" : ""; ?>>
          <hr>

          <h4 class="title is-4 mb-1 mt-5">Word count</h4>
          <div class="field">
            <label class="checkbox">
              <input id="hideWordCountCheckbox" type="checkbox" class="trackChanges mbToggle" fieldKey="hideWordCount" saveIndicatorElement="#submissionsWindowTitle" mbToggleTargets="#targetWordCountSettingsContainer" mbToggleCheckedAction="hide" <?php echo ($study["hideWordCount"] == 1) ? "checked" : ""; ?> />
              Hide word count
            </label>
          </div>

          <!--Ability to toggle maximum word count, set maximum word count, and toggle to prevent participants to go over the word count-->
          <div class="field mt-5" id="targetWordCountSettingsContainer" <?php echo ($study["hideWordCount"] == 1) ? "style='display: none;'" : ""; ?>>
            <span class="label has-text-left">Target word count <button class="mbHelpButton big" mbHelpTarget="#targetWordCountHelp"><i class="fa fa-question"></i></button></span>
            <!--toglle for maximum word count-->
            <div class="control">
              <label class="checkbox">
                <input id="maxWordCountCheckbox" type="checkbox" class="trackChanges mbToggle" fieldKey="disableMaxWordCount" saveIndicatorElement="#submissionsWindowTitle" mbToggleTargets="#targetWordCountExtraSettingsContainer" mbToggleCheckedAction="hide" <?php echo ($study["disableMaxWordCount"] == 1) ? "checked" : ""; ?>>
                Disable target word count
              </label>
            </div>
            <div id="targetWordCountExtraSettingsContainer" <?php echo ($study["disableMaxWordCount"] == 1) ? "style='display: none;'" : ""; ?>>
              <div class="field mt-2">
                <div class="field">
                  <label class="checkbox">
                    <input id="preventGoingOverMaxWordCountCheckbox" type="checkbox" class="trackChanges" fieldKey="preventGoingOverMaxWordCount" saveIndicatorElement="#submissionsWindowTitle" <?php echo ($study["preventGoingOverMaxWordCount"] == 1) ? "checked" : ""; ?>>
                    Prevent participants from going over the target word count (i.e., hard maximum)
                  </label>
                </div>
              </div>
              <div class="control mt-2">
                <input id="maxWordCountInput" class="input trackChanges" fieldKey="maxWordCount" saveIndicatorElement="#submissionsWindowTitle" type="number"
                  placeholder="e.g., 100" value="<?php echo $study["maxWordCount"]; ?>" style="max-width: 450px;">
              </div>
            </div>
          </div>
          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="targetWordCountHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p><b>Help:</b> The target word count allows researchers to remind participants how many words they are expected to write. This will be shown together with their current word count (e.g., "120 / 500 words"). If you enable the "prevent participants from going over the target word count" option, participants will not be able to enter more words than the target word count.</p>
              </div>
            </div>
          </div>
          <!--Help box END-->
        </div>

      </section>
    </div>
    <!--Submissions Window END-->

    <hr>

    <!--Chat settings (disableCopyPasteChat, disableDelteChatButton, enableImageUpload, enableFileUpload) START-->
    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3" id="chatSettingsTitle">
          Chat settings
          <button class="mbHelpButton big" mbHelpTarget="#chatSettingsHelp">
            <i class="fa fa-question"></i>
          </button>
          <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(currentlyActiveParticipantInstructionsCondition+1);updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light mt-3" id="chatSettingsHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> In the chat settings, you can set whether participants are allowed to copy-paste text into the chat window. You can also set whether participants are allowed to delete their messages and whether they can upload files.
              </p>
            </div>
          </div>
        </div>
        <!--Help box END-->
        <div class="field mt-5">
          <label class="checkbox">
            <input type="checkbox" class="trackChanges mbToggle" fieldKey="disableCopyPasteChat" saveIndicatorElement="#chatSettingsTitle" <?php echo ($study["disableCopyPasteChat"] == 1) ? "checked" : ""; ?> />
            Disable paste into chat window
            <button class="mbHelpButton" mbHelpTarget="#disableCopyPasteChatHelp"><i class="fa fa-question"></i></button>
          </label>
          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="disableCopyPasteChatHelp" style="display: none;">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p><b>Help:</b> When paste into chat window is disabled, participants will not be able to copy and paste text into the chat window.</p>
              </div>
            </div>
          </div>
          <!--Help box END-->
        </div>
        <div class="field mt-5">
          <label class="checkbox">
            <input type="checkbox" class="trackChanges mbToggle" fieldKey="disableDeleteChatButton" saveIndicatorElement="#chatSettingsTitle" <?php echo ($study["disableDeleteChatButton"] == 1) ? "checked" : ""; ?> />
            Disable "chat delete"-button
            <button class="mbHelpButton" mbHelpTarget="#deleteChatHelp"><i class="fa fa-question"></i></button>
          </label>
          <div class="mbHelpBox notification is-info is-light mt-3" id="deleteChatHelp" style="display: none;">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p><b>Help:</b> The "chat delete"-button allows participants to delete all messages from the chat window. This can give them a fresh start for their conversation. Importantly, messages are only visually deleted but still remain in the database accessible to the researcher.</p>
              </div>
            </div>
          </div>
        </div>

        <div class="field mt-5">
          <label class="label has-text-left" id="maxNumberAiMessagesLabel">
            Maximum number of AI messages
            <button class="mbHelpButton" mbHelpTarget="#maxNumberAiMessagesHelp"><i class="fa fa-question"></i></button>
          </label>
          <div class="control">
            <input id="maxNumberAiMessagesInput" class="input trackChanges" fieldKey="maxNumberAiMessages" saveIndicatorElement="#chatSettingsTitle" type="text"
              placeholder="Default: no limit" value="<?php echo $study["maxNumberAiMessages"] ?: ''; ?>" style="max-width: 450px;">
          </div>
          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="maxNumberAiMessagesHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p><b>Help:</b> Here you can set a maximum number of AI messages that participants can receive during their chat session. Once the limit is reached, participants will no longer be able to receive additional messages from the AI and can also not send new messages. Default: no limit.</p>
              </div>
            </div>
          </div>
          <!--Help box END-->
        </div>
       
        <div class="field mt-5">
          <label class="label has-text-left" id="maxNumberParticipantMessagesLabel">
            Maximum number of participant messages
            <button class="mbHelpButton" mbHelpTarget="#maxNumberParticipantMessagesHelp"><i class="fa fa-question"></i></button>
          </label>
          <div class="control">
            <input id="maxNumberParticipantMessagesInput" class="input trackChanges" fieldKey="maxNumberParticipantMessages" saveIndicatorElement="#chatSettingsTitle" type="text"
              placeholder="Default: no limit" value="<?php echo $study["maxNumberParticipantMessages"] ?: ''; ?>" style="max-width: 450px;">
          </div>

          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="maxNumberParticipantMessagesHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p><b>Help:</b> Here you can set a maximum number of messages that participants can send during their chat session. Once the limit is reached, participants will no longer be able to send new messages. Default: no limit.</p>
              </div>
            </div>
          </div>
          <!--Help box END-->
        </div>

        <div class="field mt-5">
          <label class="checkbox">
            <input type="checkbox" class="trackChanges mbToggle" fieldKey="enableImageUpload" saveIndicatorElement="#chatSettingsTitle" <?php echo ($study["enableImageUpload"] == 1) ? "checked" : ""; ?> mbtoggletargets="#imageUploadInfoBox, #modelSupportWarningBox" mbToggleCheckedAction="show" />
            Enable image upload
          </label>
          <div class="mbHelpBox display notification is-danger is-light mt-5" id="imageUploadInfoBox" <?php echo ($study["enableImageUpload"] == 1) ? "" : "style='display: none;'"; ?>>
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-exclamation-triangle"></i>
                </span>
              </div>
              <div class="column">
                <p><b>Warning:</b> All images and other files uploaded will be deleted 30 days after upload – so <b>you must download them within 30 days</b>. This is done to keep storage requirements for ResearchChatAI manageable. Normal messages and submissions are retained indefinitely.</p>
              </div>
            </div>
          </div>
          <div class="mbHelpBox display notification is-warning is-light mt-5" id="modelSupportWarningBox" <?php echo ($study["enableImageUpload"] == 1) ? "" : "style='display: none;'"; ?>>
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-exclamation-triangle"></i>
                </span>
              </div>
              <div class="column">
                <p><b>Important note:</b> Not all AI models support image uploads. Please ensure you check and test your model's compatibility before relying on this feature.</p>
              </div>
            </div>
          </div>
        </div>
        <!--<div class="field mt-5">
          <label class="checkbox">
            <input type="checkbox" class="trackChanges mbToggle" fieldKey="enableFileUpload" saveIndicatorElement="#chatSettingsTitle" <?php echo ($study["enableFileUpload"] == 1) ? "checked" : ""; ?> />
            Enable file upload
          </label>
          <p class="help">Note: When file upload is enabled, participants will be able to upload files in the chat window. You can set the maximum file size in the "File upload settings".</p>
        </div>-->
      </section>
    </div>
    <hr>

    <!--General settins (timer, word count) START-->
    <div class="container" style="max-width: 760px;">
      <section class="section">
        <h4 class="title is-3" id="timerSettingsTitle">
          Timer settings
          <button class="mbHelpButton big" mbHelpTarget="#timerHelp">
            <i class="fa fa-question"></i>
          </button>
          <button class="button is-info is-light is-small js-modal-trigger" data-target="previewModal" id="previewParticipantInstructionsButton" style="margin-top: 3px;position: absolute;right: 48px;" onclick="$('#previewConditionSelect').val(currentlyActiveParticipantInstructionsCondition+1);updatePreviewIframe();">
            <span class="icon is-small">
              <i class="fa fa-eye"></i>
            </span>
            <span>Preview</span>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light mt-3" id="timerHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> You can set a timer for the participants. The timer will be shown to the participants and will count down from the set duration. In this way, you can ensure that participants do not spend too much time on a single task. You can also set a message that will be shown to the participants when the timer is up. If you enable the "force submission when timer ends" option, the system will automatically submit the participant's response when the timer is up.</p>
            </div>
          </div>
        </div>
        <!--Help box END-->

        <div class="field mt-3">
          <label class="checkbox">
            <input type="checkbox" class="trackChanges mbToggle" fieldKey="hideTimer" saveIndicatorElement="#timerSettingsTitle" <?php echo ($study["hideTimer"] == 1) ? "checked" : ""; ?> mbtoggletargets="#timerSettingsContainer" mbToggleCheckedAction="hide" />
            Hide timer
          </label>
        </div>

        <div id="timerSettingsContainer" <?php echo ($study["hideTimer"] == 1) ? "style='display: none;'" : ""; ?>>
          <div class="field mt-5">
            <label class="label has-text-left">Timer duration (in minutes)</label>
            <div class="control">
              <input id="timerDurationInput" class="input trackChanges" fieldKey="timerDuration" saveIndicatorElement="#timerSettingsTitle" type="text"
                placeholder="Default: 10 min" value="<?php echo $study["timerDuration"]; ?>" style="max-width: 450px;">
            </div>
          </div>
          <div class="field mt-5">
            <label class="label has-text-left">"End of timer"-message <button class="mbHelpButton" mbHelpTarget="#endOfTimerMessageHelp"><i class="fa fa-question"></i></button></label>
            <label class="checkbox">
              <input type="checkbox" id="hideEndOfTimerMessageCheckbox" class="trackChanges mbToggle"
                fieldKey="hideEndOfTimerMessage" saveIndicatorElement="#timerSettingsTitle" mbToggleTargets="#endOfTimerMessageInputContainer" mbToggleCheckedAction="hide" <?php echo ($study["hideEndOfTimerMessage"] == 1) ? "checked" : ""; ?> />
              Hide "end of timer"-message
            </label>
          </div>
          <div class="field mt-3" id="endOfTimerMessageInputContainer" <?php echo ($study["hideEndOfTimerMessage"] == 1) ? "style='display:none;'" : ""; ?>>
            <div class="control">
              <input id="endOfTimerMessageInput" class="input trackChanges" fieldKey="endOfTimerMessage" saveIndicatorElement="#timerSettingsTitle" type="text"
                placeholder="Default: Your time is up." value="<?php echo $study["endOfTimerMessage"]; ?>"
                style="max-width: 450px;">
            </div>
          </div>
          <!--Help box START-->
          <div class="mbHelpBox notification is-info is-light mt-3" id="endOfTimerMessageHelp">
            <div class="columns">
              <div class="column colWithIcon">
                <span class="icon">
                  <i class="fa fa-question"></i>
                </span>
              </div>
              <div class="column">
                <p><b>Help:</b> This message will be shown to participants once the timer is up. You can, for example, ask participants to submit now.</p>
              </div>
            </div>
          </div>
          <!--Help box END-->

          <div class="field mt-5">
            <label class="label has-text-left">"End of timer"-behavior <button class="mbHelpButton" mbHelpTarget="#endOfTimerBehaviorHelp"><i class="fa fa-question"></i></button></label>
            <label class="checkbox">
              <input type="checkbox" class="trackChanges"
                fieldKey="endOfTimerForceSubmit" saveIndicatorElement="#timerSettingsTitle" <?php echo ($study["endOfTimerForceSubmit"] == 1) ? "checked" : ""; ?> />
              Force submission when timer ends
            </label>
            <!--Help box START-->
            <div class="mbHelpBox notification is-info is-light mt-3" id="endOfTimerBehaviorHelp">
              <div class="columns">
                <div class="column colWithIcon">
                  <span class="icon">
                    <i class="fa fa-question"></i>
                  </span>
                </div>
                <div class="column">
                  <p><b>Help:</b> When "Force submission when timer ends" is enabled, ResearchChatAI automatically submits when the time is up. If the "end of timer"-message is enabled, this message will be shown before the submission.</p>
                </div>
              </div>
            </div>
            <!--Help box END-->
          </div>
        </div>
    </div>
    <!--General settings (timer, word count) END-->

    <!--Go to next step button with arrow right-->
    <section class="section mt-5" style="margin-bottom: 120px;">
      <button class="button is-primary is-pulled-right goToStepButton" data-target="5" onclick="conductPrelaunchCheck();">Go to Step 5 <i
          class="fas fa-arrow-right ml-2"></i></button>
    </section>
  </div>
  <!--Participant instructions END-->
  </div>

  <!------------------------------------------------------------>
  <!------------------------------------------------------------>
  <!------------------------------------------------------------>

  <div id="distributionContainer" class="stepContainer" style="display: none;">
    <div class="container" style="max-width: 760px; margin-top: 48px;">
      <section class="section has-background-warning-light">
        <p class="title is-3">Step 5: Distribution</p>
        <p>You can either deploy ResearchChatAI in its own window or embed it in your existing survey (e.g., Qualtrics). The below wizard will help you generate the correct link and embed code for your study.</p>
      </section>
    </div>

    <!--Redirection START-->
    <div class="container" style="max-width: 760px;">

      <!--Prelaunch check START-->
      <!--Box checking whether API keys are set, model is provided for openRouter, AI instructions are provided, participant instructions are provided, and ai attributes are set not only for one but all conditions. organized by overall step 1-4. gree, yellow, red color coding. button to jump to the respective step-->
      <section class="section">
        <h4 class="title is-3">
          Prelaunch check
          <button class="mbHelpButton big" mbHelpTarget="#prelaunchCheckHelp">
            <i class="fa fa-question"></i>
          </button>
          <!--refresh button at the right-->
          <button class="button is-info is-light is-small" style="margin-top: 3px;position: absolute;right: 48px;" onclick="conductPrelaunchCheck();">
            <span class="icon is-small">
              <i class="fa fa-sync"></i>
            </span>
            <span>Re-check</span>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light mt-3" id="prelaunchCheckHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> The "prelaunch check" helps you make sure that everything works correclty. Green checks indicate that everything is set up correctly. Warnings in yellow are not critical but should be addressed if possible. Issues in red must be addressed before launching the study.</p>
            </div>
          </div>
        </div>
        <!--Help box END-->

        <div class="mt-5">
          <label class="label has-text-left">Step 1: Study setup</label>
          <!--welcome message-->
          <div class="statusCheckContainer ok" id="welcomeMessageStatusCheck">
            <div class="notification mb-2 p-2 is-light is-success">
              <span class="icon mr-2">
                <i class="fa fa-check"></i>
              </span>
              <span>"Welcome"-message OK</span>
            </div>
            <div class="notification mb-2 p-2 is-light is-warning">
              <span class="icon mr-2">
                <i class="fa fa-exclamation-triangle"></i>
              </span>
              <span>No text for "Welcome"-message provided; using default text</span>
            </div>
          </div>

          <!--"Close"-button-->
          <div class="statusCheckContainer warning" id="closeButtonStatusCheck">
            <div class="notification mb-2 p-2 is-light is-success">
              <span class="icon mr-2">
                <i class="fa fa-check"></i>
              </span>
              <span>"Close"-button OK</span>
            </div>
            <div class="notification mb-2 p-2 is-light is-warning">
              <span class="icon mr-2">
                <i class="fa fa-exclamation-triangle"></i>
              </span>
              <span>No text for "Close"-button provided; using default text</span>
            </div>
          </div>

          <label class="label has-text-left mt-5">Step 2: AI attributes</label>
          <!--AI name-->
          <div class="statusCheckContainer ok" id="aiAttributesStatusCheck">
            <div class="notification mb-2 p-2 is-light is-success">
              <span class="icon mr-2">
                <i class="fa fa-check"></i>
              </span>
              <span>AI attributes OK</span>
            </div>
            <div class="notification mb-2 p-2 is-light is-warning">
              <span class="icon mr-2">
                <i class="fa fa-exclamation-triangle"></i>
              </span>
              <span>No AI name provided for some of the conditions; no name will be shown</span>
            </div>
          </div>
          <!--Chat appearance-->
          <div class="statusCheckContainer error" id="chatAppearanceStatusCheck">
            <div class="notification mb-2 p-2 is-light is-success">
              <span class="icon mr-2">
                <i class="fa fa-check"></i>
              </span>
              <span>Chat appearance OK</span>
            </div>
            <div class="notification mb-2 p-2 is-light is-danger">
              <span class="icon mr-2">
                <i class="fa fa-hand-paper"></i>
              </span>
              <span>Some colors are missing for chat appearance</span>
            </div>
          </div>

          <label class="label has-text-left mt-5">Step 3: AI instructions</label>
          <!--AI instructions-->
          <div class="statusCheckContainer ok" id="aiInstructionsStatusCheck">
            <div class="notification mb-2 p-2 is-light is-success">
              <span class="icon mr-2">
                <i class="fa fa-check"></i>
              </span>
              <span>AI instructions OK</span>
            </div>
            <div class="notification mb-2 p-2 is-light is-warning">
              <span class="icon mr-2">
                <i class="fa fa-exclamation-triangle"></i>
              </span>
              <span>No text provided for AI instructions for some conditions; AI will behave generically</span>
            </div>
          </div>
          <!--LLM Settings-->
          <div class="statusCheckContainer error" id="llmSettingsStatusCheck">
            <div class="notification mb-2 p-2 is-light is-success">
              <span class="icon mr-2">
                <i class="fa fa-check"></i>
              </span>
              <span>LLM settings OK</span>
            </div>
            <div class="notification mb-2 p-2 is-light is-warning">
              <span class="icon mr-2">
                <i class="fa fa-exclamation-triangle"></i>
              </span>
              <span>API key not provided in expected format</span>
            </div>
            <div class="notification mb-2 p-2 is-light is-danger">
              <span class="icon mr-2">
                <i class="fa fa-hand-paper"></i>
              </span>
              <span>No API key provided; impossible to send messages to the AI</span>
            </div>
            <div class="notification mb-2 p-2 is-light is-info">
              <span class="icon mr-2">
                <i class="fa fa-info-circle"></i>
              </span>
              <span>Custom connector selected; connection cannot be automatically verified. Please ensure your connector endpoint is working correctly.</span>
            </div>
          </div>

          <label class="label has-text-left mt-5">Step 4: Participant settings</label>
          <!--Participant instructions-->
          <div class="statusCheckContainer ok" id="participantInstructionsStatusCheck">
            <div class="notification mb-2 p-2 is-light is-success">
              <span class="icon mr-2">
                <i class="fa fa-check"></i>
              </span>
              <span>Participant instructions OK</span>
            </div>
            <div class="notification mb-2 p-2 is-light is-warning">
              <span class="icon mr-2">
                <i class="fa fa-exclamation-triangle"></i>
              </span>
              <span>No text provided for participant instructions; instructions will be left blank</span>
            </div>
          </div>
        </div>
      </section>
    </div>

    <hr>
    <div class="container" style="max-width: 760px;">

      <!-- Participant identifier START-->
      <section class="section">
        <h4 class="title is-3">
          Distribute study
          <button class="mbHelpButton big" mbHelpTarget="#distributeStudyHelp">
            <i class="fa fa-question"></i>
          </button>
        </h4>

        <!--Help box START-->
        <div class="mbHelpBox notification is-info is-light mt-3" id="distributeStudyHelp">
          <div class="columns">
            <div class="column colWithIcon">
              <span class="icon">
                <i class="fa fa-question"></i>
              </span>
            </div>
            <div class="column">
              <p><b>Help:</b> You can either deploy ResearchChatAI in its own window or embed it in your existing survey (e.g., Qualtrics). The below wizard will help you generate the correct link and embed code for your study. It can also help you to pass a participant identifier and experimental condition to ResearchChatAI through the link.</p>
            </div>
          </div>
        </div>
        <!--Help box END-->

        <!--Link START-->
        <div class="formRadioGroup">
          <div class="radioButton <?php echo ($study["distributionMode"] == "link") ? "active" : ""; ?>" fieldKey="distributionMode" fieldValue="link" radioAccordionTarget="#followUpDistributionModeLink">
            <span><b>Stand-alone:</b> ResearchChatAI will open in its own window
            </span>
            <span class="circle"><i class="fas fa-check"></i></span>
          </div>
          <div id="followUpDistributionModeLink" class="followUpContainer mt-3 mb-5" <?php echo ($study["distributionMode"] != "link") ? "style='display:none;'" : ""; ?>>

            <div class="field mt-5">
              <span>
                <label class="checkbox">
                  <input type="checkbox" id="includeParticipantIdInLinkCheckbox" class="trackChanges mbToggle" fieldKey="includeParticipantIdInLink" mbtoggletargets="#participantIdShareLinkInputContainer" mbtogglecheckedaction="show" <?php echo ($study["includeParticipantIdInLink"] == 1) ? "checked" : ""; ?> onclick="updateDistributionLink()" />
                  Pass a participant identifier to ResearchChatAI
                </label>
                <button class="mbHelpButton" mbHelpTarget="#inlcudeParticipantIdInLinkHelp"><i class="fa fa-question"></i></button>
              </span>

              <!--Participant ID input-->
              <div class="field mt-3 ml-5 has-background-light p-2 pl-5" id="participantIdShareLinkInputContainer" <?php echo ($study["includeParticipantIdInLink"] == 1) ? "" : "style='display:none;'"; ?>>
                <label class="label has-text-left" style="display: inline; line-height: 40px;">Participant ID: </label>
                <input class="input ml-2 trackChanges" id="participantIdShareLinkInput" fieldKey="participantIdInLink" type="text" placeholder="e.g., TestUser, ${e://Field/participantID}" style="max-width: 280px;" value="<?php echo $study["participantIdInLink"]; ?>" oninput="updateDistributionLink()" />
              </div>
            </div>

            <!--Help box START-->
            <div class="mbHelpBox notification is-info is-light mt-3" id="inlcudeParticipantIdInLinkHelp">
              <div class="columns">
                <div class="column colWithIcon">
                  <span class="icon">
                    <i class="fa fa-question"></i>
                  </span>
                </div>
                <div class="column">
                  <p><b>Help:</b> By default, ResearchChatAI will generate a unique participantID for each participant. However, you can pass a participantID to ResearchChatAI through the link in case participants are already asigned a unique identifier before-hand (e.g., in a preceeding Qualtrics survey).</p>
                </div>
              </div>
            </div>
            <!--Help box END-->

            <div class="field mt-3">
              <span>
                <label class="checkbox">
                  <input type="checkbox" id="includeConditionInLinkCheckbox" class="trackChanges mbToggle" fieldKey="includeConditionInLink" <?php echo ($study["includeConditionInLink"] == 1) ? "checked" : ""; ?> onclick="updateDistributionLink()" mbToggleTargets="#experimentalConditionLinkSelectContainer" mbToggleCheckedAction="show" />
                  Pass an experimental condition to ResearchChatAI
                </label>
                <button class="mbHelpButton" mbHelpTarget="#inlcudeConditionInLinkHelp"><i class="fa fa-question"></i></button>
              </span>

              <!--Select experimental condition from list (1, 2, 3, 4-->
              <div class="field mt-3 ml-5 has-background-light p-2 pl-5" id="experimentalConditionLinkSelectContainer" <?php echo ($study["includeConditionInLink"] == 1) ? "" : "style='display:none;'"; ?>>
                <label class="label has-text-left mb-0" style="display: inline-block; line-height: 40px;">Experimental condition: </label>
                <div class="control" style="display: inline-block; max-width: 320px;vertical-align:top;">
                  <div class="select">
                    <select id="experimentalConditionLinkSelect" class="" fieldKey="conditionInLink" onchange="updateDistributionLink()">
                    </select>
                  </div>
                </div>
              </div>

              <!--Help box START-->
              <div class="mbHelpBox notification is-info is-light mt-3" id="inlcudeConditionInLinkHelp">
                <div class="columns">
                  <div class="column colWithIcon">
                    <span class="icon">
                      <i class="fa fa-question"></i>
                    </span>
                  </div>
                  <div class="column">
                    <p><b>Help:</b> By default, ResearchChatAI will randomly assign participants to different experimental conditions. However, you can pass an experimental condition to ResearchChatAI through the link in case participants are already asigned to an experimental condition before-hand (e.g., in a preceeding Qualtrics survey).</p>
                  </div>
                </div>
              </div>
              <!--Help box END-->

              <div class="field is-grouped mt-5 mb-1">
                <label class="label" style="line-height: 30px;">Distribution link</label>
                <div class="control ml-auto">
                  <button class="button is-info is-light is-small" style="min-width: 130px" id="copyStudyLinkButton">
                    <span class="icon is-small">
                      <i class="fa fa-copy"></i>
                    </span>
                    <span class="buttonText">Copy link</span>
                  </button>
                </div>
              </div>
              <div class="field">
                <div class="control">
                  <textarea class="textarea" placeholder="Distribution link" id="studyLinkInput" style="word-wrap:break-word;word-break:break-all;font-size:12px;min-height:55px;"></textarea>
                </div>
              </div>

              <p class="help">
                Note: Use the above link to share with participants directly or to include it in your survey. In Qualtrics, you can use "piped text", such as <code>${e://Field/participantID}</code>, to automatically inject data in the link. When using embedded variables in your study, make sure to include them in the link.
              </p>
            </div>
          </div>
          <!--Link END-->

          <!------------------------------------------------------------>

          <!--Embed START-->
          <div class="radioButton <?php echo ($study["distributionMode"] == "embed") ? "active" : ""; ?>" fieldKey="distributionMode" fieldValue="embed" radioAccordionTarget="#followUpDistributionModeEmbed">
            <span><b>Embedded:</b> ResearchChatAI will open inside your existing survey
            </span>
            <span class="circle"><i class="fas fa-check"></i></span>
          </div>
          <div id="followUpDistributionModeEmbed" class="followUpContainer mt-3 mb-5" <?php echo ($study["distributionMode"] != "embed") ? "style='display:none;'" : ""; ?>>
            <div class="field mt-5">
              <span>
                <label class="checkbox">
                  <input type="checkbox" id="includeParticipantIdInEmbedCheckbox" class="trackChanges mbToggle" mbtoggletargets="#participantIdEmbedInputContainer" mbToggleCheckedAction="show" fieldKey="includeParticipantIdInEmbed" <?php echo ($study["includeParticipantIdInEmbed"] == 1) ? "checked" : ""; ?> onclick="updateDistributionLink()" />
                  Pass a participant identifier to ResearchChatAI
                </label>
                <button class="mbHelpButton" mbHelpTarget="#inlcudeParticipantIdInEmbedHelp"><i class="fa fa-question"></i></button>
              </span>

              <!--Participant ID input-->
              <div class="field mt-3 ml-5 has-background-light p-2 pl-5" id="participantIdEmbedInputContainer" <?php echo ($study["includeParticipantIdInEmbed"] == 1) ? "" : "style='display:none;'"; ?>>
                <label class="label has-text-left" style="display: inline; line-height: 40px;">Participant ID: </label>
                <input class="input ml-2 trackChanges" id="participantIdEmbedInput" fieldKey="participantIdInEmbed" type="text" placeholder="e.g., TestUser, ${e://Field/participantID}" style="max-width: 280px;" value="<?php echo $study["participantIdInEmbed"]; ?>" oninput="updateDistributionLink()" />
              </div>

              <!--Help box START-->
              <div class="mbHelpBox notification is-info is-light mt-3" id="inlcudeParticipantIdInEmbedHelp">
                <div class="columns">
                  <div class="column colWithIcon">
                    <span class="icon">
                      <i class="fa fa-question"></i>
                    </span>
                  </div>
                  <div class="column">
                    <p><b>Help:</b> Including the participantID in the embed code is highly recommended when embedding ResearchChatAI in your survey. This allows you to match participant data in ResearchChatAI (e.g., specific messages) with your survey data. If the participantID is not included, ResearchChatAI will automatically generate a random identigier for each user.</p>
                  </div>
                </div>
              </div>
              <!--Help box END-->
            </div>

            <div class="field mt-3">
              <span>
                <label class="checkbox">
                  <input type="checkbox" id="includeConditionInEmbedCheckbox" class="trackChanges mbToggle" mbtoggletargets="#experimentalConditionEmbedSelectContainer" mbToggleCheckedAction="show" fieldKey="includeConditionInEmbed" <?php echo ($study["includeConditionInEmbed"] == 1) ? "checked" : ""; ?> onclick="updateDistributionLink()" />
                  Pass an experimental condition to ResearchChatAI
                </label>
                <button class="mbHelpButton" mbHelpTarget="#inlcudeConditionInEmbedHelp"><i class="fa fa-question"></i></button>
              </span>

              <!--Select experimental condition from list (1, 2, 3, 4-->
              <div class="field mt-3 ml-5 has-background-light p-2 pl-5" id="experimentalConditionEmbedSelectContainer" <?php echo ($study["includeConditionInEmbed"] == 1) ? "" : "style='display:none;'"; ?>>
                <label class="label has-text-left mb-0" style="display: inline-block; line-height: 40px;">Experimental condition: </label>
                <div class="control" style="display: inline-block; max-width: 320px;vertical-align:top;">
                  <div class="select">
                    <select id="experimentalConditionEmbedSelect" class="" fieldKey="conditionInEmbed" onchange="updateDistributionLink()">
                    </select>
                  </div>
                </div>
              </div>

              <!--Help box START-->
              <div class="mbHelpBox notification is-info is-light mt-3" id="inlcudeConditionInEmbedHelp">
                <div class="columns">
                  <div class="column colWithIcon">
                    <span class="icon">
                      <i class="fa fa-question"></i>
                    </span>
                  </div>
                  <div class="column">
                    <p><b>Help:</b> This option is only useful if the condition is determined before participants enter ResearchChatAI. If your survey assigns participants to experimental conditions before they interact with ResearchChatAI, you can pass the experimental condition to ResearchChatAI. This ensures that participants are correctly placed into the same condition. If you want ResearchChatAI to randomly assign the condition, you can leave this option unchecked.</p>
                  </div>
                </div>
              </div>
              <!--Help box END-->
            </div>

            <!--Two columns where user can enter max-width and max-height-->
            <div class="columns mt-0">
              <div class="column pb-0">
                <div class="field">
                  <span class="label has-text-left">Max width (px or %) <button class="mbHelpButton" mbHelpTarget="#embedDimensionsHelp"><i class="fa fa-question"></i></button></span>
                  <div class="control">
                    <input id="studyEmbedWidthInput" class="input trackChanges" fieldKey="studyEmbedWidth" type="text"
                      placeholder="Default: 600px" value="<?php echo $study["studyEmbedWidth"]; ?>" style="max-width: 450px;" oninput="updateDistributionLink()">
                  </div>
                </div>
              </div>
              <div class="column pb-0">
                <div class="field">
                  <span class="label has-text-left">Max height (px or %) <button class="mbHelpButton" mbHelpTarget="#embedDimensionsHelp"><i class="fa fa-question"></i></button></span>
                  <div class="control">
                    <input id="studyEmbedHeightInput" class="input trackChanges" fieldKey="studyEmbedHeight" type="text"
                      placeholder="Default: 750px" value="<?php echo $study["studyEmbedHeight"]; ?>" style="max-width: 450px;" oninput="updateDistributionLink()">
                  </div>
                </div>
              </div>
            </div>
            <!--Help box START-->
            <div class="mbHelpBox notification is-info is-light mt-3" id="embedDimensionsHelp">
              <div class="columns">
                <div class="column colWithIcon">
                  <span class="icon">
                    <i class="fa fa-question"></i>
                  </span>
                </div>
                <div class="column">
                  <p><b>Help:</b> You can set the maximum width and height of the embedded ResearchChatAI window. This can be useful to ensure that the chat window fits well within your survey. If you leave these fields empty, the default values will be used.</p>
                </div>
              </div>
            </div>
            <!--Help box END-->

            <div class="field is-grouped mt-4 mb-1">
              <label class="label" style="line-height: 30px;">Embed code</label>
              <div class="control ml-auto">
                <button class="button is-info is-light is-small" style="min-width: 130px" id="copyStudyEmbedButton">
                  <span class="icon is-small">
                    <i class="fa fa-copy"></i>
                  </span>
                  <span class="buttonText">Copy code</span>
                </button>
              </div>
            </div>

            <textarea class="textarea mt-1" placeholder="Distribution link" id="studyEmbedInput" style="word-wrap:break-word;word-break:break-all;font-size:12px;min-height:70px;word-wrap:break-word;word-break:break-all;"></textarea>

            <p class="help">
              Note: Use the above code to include ResearchChatAI directly in your survey (e.g., on Qualtrics). In Qualtrics, you can use "piped text", such as <code>${e://Field/participantID}</code>, to automatically inject data in the link. When using embedded variables in your study, make sure to include them in the link.
            </p>
          </div>
          <!--Embed END-->
        </div>
      </section>
    </div>

    <div class="container" style="max-width: 760px;">
      <hr>

      <!--Data collection status-->
      <section class="section">
        <h4 class="title is-3">Data collection status</h4>

        <p>
          Data collection is currently <b id="dataCollectionStatusLabel"><?php echo ($study["dataCollectionActive"] == 1) ? "active" : "paused"; ?></b>. You can pause or continue data collection at any time. In this way, you prevent new participants from joining the study while still allowing existing participants to finish their conversation.

        <div class="columns mt-4">
          <div class="column">
            <button class="button is-light is-fullwidth is-danger"
              id="pauseDataCollectionButton" style="margin: 0 auto; max-width: 450px;" <?php echo ($study["dataCollectionActive"] == 0) ? "disabled" : ""; ?> onclick="pauseDataCollection();">
              <span class="icon is-small">
                <i class="fa fa-pause"></i>
              </span>
              <span class="mbButtonLabel">Pause data collection</span>
            </button>
          </div>
          <div class="column">
            <button class="button is-light is-fullwidth is-success"
              id="continueDataCollectionButton" style="margin: 0 auto; max-width: 450px;" <?php echo ($study["dataCollectionActive"] == 1) ? "disabled" : ""; ?> onclick="continueDataCollection();">
              <span class="icon is-small">
                <i class="fa fa-play"></i>
              </span>
              <span class="mbButtonLabel">Continue data collection</span>
            </button>
          </div>
        </div>
      </section>
    </div>
    <!--Redirection END-->
  </div>

  <!---------------------------------->
  <!--------------Modals-------------->
  <!---------------------------------->

  <!-- Rename Study Modal START-->
  <div class="modal" id="renameStudyModal">
    <div class="modal-background"></div>
    <div class="modal-card">
      <header class="modal-card-head">
        <p class="modal-card-title">Rename study</p>
        <button class="delete" aria-label="close"></button>
      </header>
      <section class="modal-card-body">
        <div class="field">
          <label class="label has-text-left">New study name</label>
          <div class="control">
            <input id="newStudyNameInput" class="input" type="text" placeholder="Study name" value=""
              style="max-width: 450px;" value="">
            <p class="help">This name will not be visible to participants</p>
          </div>
        </div>
      </section>
      <footer class="modal-card-foot">
        <div class="buttons">
          <button class="button is-success saveNewNameButton">Save</button>
          <button class="button cancel">Cancel</button>
        </div>
      </footer>
    </div>
  </div>
  <!-- Rename Study Modal END-->

  <!-- Delete Study Modal START-->
  <div class="modal" id="deleteStudyModal">
    <div class="modal-background"></div>
    <div class="modal-card">
      <header class="modal-card-head">
        <p class="modal-card-title">Delete study</p>
        <button class="delete" aria-label="close"></button>
      </header>
      <section class="modal-card-body">
        Are you sure that you want to delete this study? This cannot be undone.
      </section>
      <footer class="modal-card-foot">
        <div class="buttons">
          <button class="button is-danger deleteStudyButton">Delete</button>
          <button class="button cancel">Cancel</button>
        </div>
      </footer>
    </div>
  </div>
  <!-- Delete Study Modal END-->

  <!-- Delete Condition Modal START-->
  <div class="modal" id="deleteExperimentalConditionModal">
    <div class="modal-background"></div>
    <div class="modal-card">
      <header class="modal-card-head">
        <p class="modal-card-title">Delete experimental condition</p>
        <button class="delete" aria-label="close"></button>
      </header>
      <section class="modal-card-body">
        Are you sure that you want to delete this experimental condition? All AI and participant instructions will be deleted for this condition. After deletion, conditions will be renumbered.<b><u>This cannot be undone.</u></b>
      </section>
      <footer class="modal-card-foot">
        <div class="buttons">
          <button class="button is-danger" id="deleteExperimentalConditionButton" onclick="deleteExperimentalCondition()">Delete</button>
          <button class="button cancel">Cancel</button>
        </div>
      </footer>
    </div>
  </div>
  <!-- Delete Condition Modal END-->

  <!-- Connector Template Wizard Modal START -->
  <div class="modal" id="connectorWizardModal">
    <div class="modal-background"></div>
    <div class="modal-card">
      <header class="modal-card-head">
        <p class="modal-card-title" id="connectorWizardTitle">Configure Template</p>
        <button class="delete" aria-label="close"></button>
      </header>
      <section class="modal-card-body">
        <p class="mb-4" id="connectorWizardDescription"></p>
        <p class="mb-4 has-text-grey">
          The values you enter below will be prefilled into the connector JSON for you.
          You can still make changes to the JSON directly afterwards.
        </p>
        <div id="connectorWizardFields"></div>
      </section>
      <footer class="modal-card-foot">
        <div class="buttons">
          <button class="button is-success" id="connectorWizardApply">Apply template</button>
          <button class="button cancel">Cancel</button>
        </div>
      </footer>
    </div>
  </div>
  <!-- Connector Template Wizard Modal END -->

  <!--Preview modal START-->
  <div class="modal" id="previewModal">
    <div class="modal-background"></div>
    <div class="modal-card" style="width: 100%; max-width: calc(100% - 120px);height: 100%; max-height: calc(100% - 120px);">
      <header class="modal-card-head">
        <p class="modal-card-title">Preview study</p>
        <button class="delete" aria-label="close" onclick="$('#previewIframe').attr('src', '');"></button>
      </header>
      <section class="modal-card-body">
        <div style="height: 50px;">
          <!--condition selector-->
          <div class="field" style="display: flex; justify-content: space-between;">
            <div class="control">
              <label class="label has-text-left" style="display: inline-block; line-height: 40px;">Experimental condition:</label>
              <div class="select ml-2" style="display: inline-block;">
                <select id="previewConditionSelect" onchange="updatePreviewIframe()">
                </select>
              </div>
            </div>
            <div>
              <div class="control">
                <button class="button is-info is-light" onclick="window.open($('#previewIframe').attr('src'), '_blank'); closeAllModals();">
                  <i class="fa fa-external-link mr-2"></i>
                  Open in new window
                </button>
                <button class="button is-info is-light ml-2" onclick="updatePreviewIframe()">
                  <i class="fa fa-sync-alt mr-2"></i>
                  Refresh
                </button>
              </div>
            </div>
          </div>
        </div>
        <iframe id="previewIframe" src="" style="width: 100%; height: calc(100% - 50px); border: none;"></iframe>
      </section>
    </div>
  </div>
  <!--Preview modal END-->

  <!--Modal for Avatar Selection START-->
  <div class="modal" id="avatarSelectionModal">
    <div class="modal-background"></div>
    <div class="modal-card">
      <header class="modal-card-head">
        <p class="modal-card-title">Select Avatar</p>
        <button class="delete" aria-label="close"></button>
      </header>
      <section class="modal-card-body p-5">
        <div class="columns is-multiline">
          <div class="column is-one-quarter">
            <figure class="image is-128x128">
              <img src="src/IMG/avatars/RobotIcon.png" alt="Avatar 1" class="avatarSelection">
            </figure>
          </div>
          <div class="column is-one-quarter">
            <figure class="image is-128x128">
              <img src="src/IMG/avatars/RobotPepperGreen.png" alt="Avatar 2" class="avatarSelection">
            </figure>
          </div>
        </div>
      </section>
      <footer class="modal-card-foot">
        <div class="buttons">
          <button class="button cancel">Close</button>
        </div>
      </footer>
    </div>
  </div>

  <!--Dummy file input for image upload-->
  <input type="file" id="fileInput" accept="image/*" style="display: none;">

  <!--Load jQuery-->
  <script type="text/javascript" src="src/JS/jquery-3.7.1.min.js"></script>
  <!--Load tinymce-->
  <script type="text/javascript" src="src/JS/tinymce/tinymce.min.js"></script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/npm/@tinymce/tinymce-jquery@1/dist/tinymce-jquery.min.js"></script>
  <!--Coloris color picker-->
  <script type="text/javascript" src="src/JS/coloris.min.js"></script>
  <!--iziToast-->
  <script type="text/javascript" src="src/JS/iziToast.js"></script>
  <!--General JS-->
  <script type="text/javascript" src="src/JS/general.js?v=20260308"></script>
  <!--Toggles: Code to enable/disable elements using checkboxes-->
  <script type="text/javascript" src="src/JS/mb.toggles.js?v=2410311625"></script>
  <!--Stepper: Code to handle the stepper at the top of the page-->
  <script type="text/javascript" src="src/JS/mb.stepper.js"></script>
  <!--radioAccordion: Code to handle the radio accordion-->
  <script type="text/javascript" src="src/JS/mb.radioAccordion.js"></script>

  <!--Site specific code-->
  <script type="text/javascript">
    // Variables
    var studyID = <?php echo $studyID; ?>;
    var csrfToken = '<?php echo $safeCsrfToken; ?>';
    var studyCode = '<?php echo $safeStudyCode; ?>';
    var baseURL = '<?php echo $safeBaseURL; ?>';

    // Parse experimental conditions from JSON (empty array if not set)
    // Conditions array structure: [{ name: "Control", id: 1 }, { name: "Treatment", id: 2 }, ...]
    var conditions = <?php echo empty($study["experimentalConditions"]) ? '[]' : json_encode(json_decode($study["experimentalConditions"], true) ?: []); ?>;
    var conditionsGptInstructions = <?php echo empty($study["aiInstructions"]) ? '[]' : json_encode(json_decode($study["aiInstructions"], true) ?: []); ?>;
    var conditionsParticipantInstructions = <?php echo empty($study["participantInstructions"]) ? '[]' : json_encode(json_decode($study["participantInstructions"], true) ?: []); ?>;
    var conditionsAiName = <?php echo empty($study["aiName"]) ? '[]' : json_encode(json_decode($study["aiName"], true) ?: []); ?>;
    var conditionsAiAvatar = <?php echo empty($study["aiAvatarURL"]) ? '[]' : json_encode(json_decode($study["aiAvatarURL"], true) ?: []); ?>;
    var conditionsAiDescription = <?php echo empty($study["aiDescription"]) ? '[]' : json_encode(json_decode($study["aiDescription"], true) ?: []); ?>;
    var conditionsAiStatusMessage = <?php echo empty($study["aiStatusMessage"]) ? '[]' : json_encode(json_decode($study["aiStatusMessage"], true) ?: []); ?>;
    var conditionsFirstAiMessage = <?php echo empty($study["firstAiMessage"]) ? '[]' : json_encode(json_decode($study["firstAiMessage"], true) ?: []); ?>;
    var conditionsAiTypingBubbleText = <?php echo empty($study["aiTypingBubbleText"]) ? '[]' : json_encode(json_decode($study["aiTypingBubbleText"], true) ?: []); ?>;
    var conditionsAiTypingBubbleDelay = <?php echo empty($study["aiTypingBubbleDelay"]) ? '[]' : json_encode(json_decode($study["aiTypingBubbleDelay"], true) ?: []); ?>;
    var conditionsAiDelay = <?php echo empty($study["aiDelay"]) ? '[]' : json_encode(json_decode($study["aiDelay"], true) ?: []); ?>;
    var conditionsAiDelayBeforeFirstMessage = <?php echo empty($study["aiDelayBeforeFirstMessage"]) ? '[]' : json_encode(json_decode($study["aiDelayBeforeFirstMessage"], true) ?: []); ?>;
    var conditionsAiDelayIsPerCharacter = <?php echo empty($study["aiDelayIsPerCharacter"]) ? '[]' : json_encode(json_decode($study["aiDelayIsPerCharacter"], true) ?: []); ?>;
    var currentlyActiveAiAttributesCondition = 0;
    var currentlyActiveGPTInstructionsCondition = 0;
    var currentlyActiveParticipantInstructionsCondition = 0;
    var baseURL = <?php echo json_encode($baseURL . 'chat.php?'); ?>;
    var passedVariablesInit = <?php echo empty($study["passedVariables"]) ? '[]' : $study["passedVariables"]; ?>;
    var experimentalConditionToDelete = -1; // This is a helper variable to store the condition that should be deleted

    //Listen for document ready event
    // =========================================================================
    // DOCUMENT READY - MAIN INITIALIZATION
    // =========================================================================
    
    $(document).ready(function() {
      ensureConditionsExist(); // Ensure all conditions exist
      refreshExperimentalConditionsList();
      refreshGptInstructionsConditionsUI();
      refreshParticipantInstructionsConditionsUI();
      refreshAiAttributesConditionsUI();
      updateDistributionLink();
      refreshExperimentalConditionSelect();
      conductPrelaunchCheck();

      // Listen for changes to the input fields with the class .trackChanges
      // -----------------------------------------------------------------------
      // EVENT HANDLERS - FIELD CHANGE TRACKING
      // -----------------------------------------------------------------------
      
      /**
       * Track changes to form fields and auto-save them
       * Automatically called whenever a field with .trackChanges class changes
       */
      $('.trackChanges').on('change', function() {
        // Get the fieldKey attribute
        var fieldKey = $(this).attr('fieldKey');

        // Check whether the field is a checkbox
        if ($(this).is(':checkbox')) {
          // Get the value of the checkbox
          var fieldValue = $(this).is(':checked') ? 1 : 0;
        } else {
          // Get the value of the input field
          var fieldValue = $(this).val();
        }

        // Check whether the field has a  saveIndicatorElement
        if ($(this).attr('saveIndicatorElement')) {
          // Get the saveIndicatorElement
          var saveIndicatorElement = $(this).attr('saveIndicatorElement');

          console.log('saveIndicatorElement', saveIndicatorElement);
          console.log($(saveIndicatorElement));
          // Save the changes
          saveChanges(fieldKey, fieldValue, false, $(saveIndicatorElement));
        } else {
          // Save the changes
          saveChanges(fieldKey, fieldValue);
        }

        conductPrelaunchCheck();
      });

      // Show or hide reasoning effort dropdown based on selected model
      /**
       * Update visibility of reasoning effort slider based on selected model
       * Only show for O1 models that support reasoning effort
       */
      function updateReasoningVisibility() {
        var selected = $('#modelSelect').val() || '';
        if (selected === 'gpt-5' || selected === 'gpt-5-mini') {
          $('#reasoningEffortField').show();
        } else {
          $('#reasoningEffortField').hide();
        }
      }
      $('#modelSelect').on('change', updateReasoningVisibility);
      updateReasoningVisibility();

      // Listen for click on elements with .mbHelpButton
      $('.mbHelpButton').on('click', function() {
        console.log('help button clicked');
        // Get the target of the help button
        var target = $(this).attr("mbHelpTarget");

        // Show the modal with the target
        $(target).toggle();
      });

      // Listen for click on hide timer checkbox --> not using mbToggle because it has a special case
      $('#hideTimerCheckbox').on('change', function() {
        if ($(this).is(':checked')) {
          $('#timerDurationInput').prop('disabled', true);
          $('#endOfTimerMessageInput').prop('disabled', true);
          $('#hideEndOfTimerMessageCheckbox').prop('disabled', true);
        } else {
          $('#timerDurationInput').prop('disabled', false);

          // Check if the end of timer message should be disabled
          if ($('#hideEndOfTimerMessageCheckbox').is(':checked')) {
            $('#endOfTimerMessageInput').prop('disabled', true);
          } else {
            $('#endOfTimerMessageInput').prop('disabled', false);
          }
          $('#hideEndOfTimerMessageCheckbox').prop('disabled', false);
        }
      });

      // Listen for click on showLinkBuilderCheckbox
      $('#includePassedVariablesInURLcheckbox').on('change', function() {
        if ($(this).is(':checked')) {
          // Disable all parameter value input fields in linkBuilderPassedVariablesList, but not the parameter name input fields
          $('#linkBuilderPassedVariablesList input[name="parameterValueInput"]').prop('disabled', false);

        } else {
          // Disable all parameter value input fields in linkBuilderPassedVariablesList
          $('#linkBuilderPassedVariablesList input[name="parameterValueInput"]').prop('disabled', true);
        }

        updateDistributionLink();
      });

      // Listen for click on distributeButton
      $('#distributeButton').on('click', function() {
        // Update the distribution link
        updateDistributionLink();
      });

      // Listen for click on studyLinkCopyButton
      $('#copyStudyLinkButton').on('click', function() {
        // Get the input field
        var copyText = $("#studyLinkInput");

        // Select the text field
        copyText.select();

        // Copy the text inside the text field
        document.execCommand("copy");

        // Show feedback on the button by showing "Copied!" for 3 seconds and then reverting back to "Copy link"
        $('#copyStudyLinkButton .buttonText').text("Copied!");
        $('#copyStudyLinkButton i').removeClass("fa-copy").addClass("fa-check");
        $('#copyStudyLinkButton').removeClass("is-info").addClass("is-success");
        // Remove focus from the input field
        copyText.blur();
        setTimeout(function() {
          $('#copyStudyLinkButton .buttonText').html("Copy link");
          $('#copyStudyLinkButton i').removeClass("fa-check").addClass("fa-copy");
          $('#copyStudyLinkButton').removeClass("is-success").addClass("is-info");
        }, 3000);
      });

      // Listen for click on studyEmbedCopyButton
      $('#copyStudyEmbedButton').on('click', function() {
        // Get the input field
        var copyText = $("#studyEmbedInput");

        // Select the text field
        copyText.select();

        // Copy the text inside the text field
        document.execCommand("copy");

        // Show feedback on the button by showing "Copied!" for 3 seconds and then reverting back to "Copy link"
        $('#copyStudyEmbedButton .buttonText').text("Copied!");
        $('#copyStudyEmbedButton i').removeClass("fa-copy").addClass("fa-check");
        $('#copyStudyEmbedButton').removeClass("is-info").addClass("is-success");
        // Remove focus from the input field
        copyText.blur();
        setTimeout(function() {
          $('#copyStudyEmbedButton .buttonText').html("Copy link");
          $('#copyStudyEmbedButton i').removeClass("fa-check").addClass("fa-copy");
          $('#copyStudyEmbedButton').removeClass("is-success").addClass("is-info");
        }, 3000);
      });

      // Listen for change to aiName input
      $('#aiNameInput').on('change', function() {
        // Get the value of the input
        var aiName = $(this).val();

        // Update AI name in the correct condition
        conditionsAiName[currentlyActiveAiAttributesCondition].aiName = aiName;

        // Save the changes
        saveChanges('aiName', JSON.stringify(conditionsAiName), false, $("#aiNameLabelContainer"));
      });

      // Listen for change to aiDescription input
      $('#aiDescriptionInput').on('change', function() {
        // Get the value of the input
        var aiDescription = $(this).val();

        // Update AI description in the correct condition
        conditionsAiDescription[currentlyActiveAiAttributesCondition].aiDescription = aiDescription;

        // Save the changes
        saveChanges('aiDescription', JSON.stringify(conditionsAiDescription), false, $("#aiDescriptionLabelContainer"));
      });

      // Listen for change to aiStatusMessage input
      $('#aiStatusMessageInput').on('change', function() {
        // Get the value of the input
        var aiStatusMessage = $(this).val();

        // Update AI status message in the correct condition
        conditionsAiStatusMessage[currentlyActiveAiAttributesCondition].aiStatusMessage = aiStatusMessage;

        // Save the changes
        saveChanges('aiStatusMessage', JSON.stringify(conditionsAiStatusMessage), false, $("#aiStatusMessageLabelContainer"));
      });

      // Listen for change to firstAiMessage input
      $('#firstAiMessageInput').on('change', function() {
        // Get the value of the input
        var firstAiMessage = $(this).val();

        // Update first AI message in the correct condition
        conditionsFirstAiMessage[currentlyActiveAiAttributesCondition].firstAiMessage = firstAiMessage;

        // Save the changes
        saveChanges('firstAiMessage', JSON.stringify(conditionsFirstAiMessage), false, $("#firstAiMessageLabelContainer"));
      });

      // Listen for change to aiTypingBubbleText input
      $('#aiTypingBubbleTextInput').on('change', function() {
        // Get the value of the input
        var aiTypingBubbleText = $(this).val();

        // Update AI typing bubble text in the correct condition
        conditionsAiTypingBubbleText[currentlyActiveAiAttributesCondition].aiTypingBubbleText = aiTypingBubbleText;

        // Save the changes
        saveChanges('aiTypingBubbleText', JSON.stringify(conditionsAiTypingBubbleText), false, $("#aiTypingBubbleLabelContainer"));
      });

      // Listen for change to aiTypingBubbleDelay input
      $('#aiTypingBubbleDelayInput').on('change', function() {
        // Get the value of the input
        var aiTypingBubbleDelay = $(this).val();

        // Update AI typing bubble delay in the correct condition
        conditionsAiTypingBubbleDelay[currentlyActiveAiAttributesCondition].aiTypingBubbleDelay = aiTypingBubbleDelay;

        // Save the changes
        saveChanges('aiTypingBubbleDelay', JSON.stringify(conditionsAiTypingBubbleDelay), false, $("#aiTypingBubbleDelayLabelContainer"));
      });

      // Listen for change to aiDelay input
      $('#aiDelayInput').on('change', function() {
        // Get the value of the input
        var aiDelay = $(this).val();

        // Update AI delay in the correct condition
        conditionsAiDelay[currentlyActiveAiAttributesCondition].aiDelay = aiDelay;

        // Save the changes
        saveChanges('aiDelay', JSON.stringify(conditionsAiDelay), false, $("#aiDelayLabelContainer"));
      });

      // Listen for change to aiDelayBeforeFirstMessageCheckbox
      $('#aiDelayBeforeFirstMessageCheckbox').on('change', function() {
        // Get the value of the checkbox
        var aiDelayBeforeFirstMessage = $(this).is(':checked') ? 1 : 0;

        // Update AI delay before first message in the correct condition
        conditionsAiDelayBeforeFirstMessage[currentlyActiveAiAttributesCondition].aiDelayBeforeFirstMessage = aiDelayBeforeFirstMessage;

        // Save the changes
        saveChanges('aiDelayBeforeFirstMessage', JSON.stringify(conditionsAiDelayBeforeFirstMessage), false, $("#aiDelayBeforeFirstMessageLabelContainer"));
      });

      // Listen for change to aiDelayIsPerCharacterCheckbox
      $('#aiDelayIsPerCharacterCheckbox').on('change', function() {
        // Get the value of the checkbox
        var aiDelayIsPerCharacter = $(this).is(':checked') ? 1 : 0;

        // Update AI delay is per character in the correct condition
        conditionsAiDelayIsPerCharacter[currentlyActiveAiAttributesCondition].aiDelayIsPerCharacter = aiDelayIsPerCharacter;

        // Save the changes
        saveChanges('aiDelayIsPerCharacter', JSON.stringify(conditionsAiDelayIsPerCharacter), false, $("#aiDelayIsPerCharacterLabelContainer"));
      });

      // Handle file upload
      document.getElementById('avatarFileUpload').addEventListener('change', function() {
        const file = this.files[0];
        const formData = new FormData();
        formData.append('image', file);

        console.log('Uploading file:', file);

        // Send file to server
        fetch('Backend/Chat/message-image-upload.php', {
            method: 'POST',
            body: formData
          })
          .then(response => response.json())
          .then(data => {
            if (data.status === 'success') {
              var imageFileName = file.name;
              var imageFileUrl = data.url || ''; // Ensure imgURL is set correctly

              console.log('Image uploaded successfully:', imageFileUrl);

              //set #aiAvatarPreview to the uploaded image
              $('#aiAvatarPreview').attr('src', imageFileUrl);
              // Unhide the image preview
              $('#aiAvatarPreviewContainer').show();
              // Hide #avatarUploadContainer
              $('#avatarUploadContainer').hide();

              // Get the current condition and update the avatar
              conditionsAiAvatar[currentlyActiveAiAttributesCondition].aiAvatarURL = imageFileUrl;
              saveChanges('aiAvatarURL', JSON.stringify(conditionsAiAvatar), false, $("#aiAvatarLabelContainer"));
            } else {
              alert(data.message); // Show error message if upload fails
              console.error(data.message);
            }
          })
          .catch(error => {
            console.error('Error:', error);
          });
      });

      // Listen for click on .avatarSelection
      $('.avatarSelection').on('click', function() {
        // Get the src of the clicked avatar
        var avatarSrc = $(this).attr('src');

        // Set the src of the preview image
        $('#aiAvatarPreview').attr('src', avatarSrc);

        // Unhide the image preview
        $('#aiAvatarPreviewContainer').show();
        // Hide #avatarUploadContainer
        $('#avatarUploadContainer').hide();

        // Close modal
        $('#avatarSelectionModal').removeClass('is-active');

        // Get the current condition and update the avatar
        conditionsAiAvatar[currentlyActiveAiAttributesCondition].aiAvatarURL = avatarSrc;
        saveChanges('aiAvatarURL', JSON.stringify(conditionsAiAvatar), false, $("#aiAvatarLabelContainer"));
      });

      // Listen to click on removeAvatarButton
      $('#removeAvatarButton').on('click', function() {
        // Reset the preview image
        $('#aiAvatarPreview').attr('src', '');
        // Hide the image preview
        $('#aiAvatarPreviewContainer').hide();
        // Show #avatarUploadContainer
        $('#avatarUploadContainer').show();

        // Get the current condition and update the avatar
        conditionsAiAvatar[currentlyActiveAiAttributesCondition].aiAvatarURL = '';
        saveChanges('aiAvatarURL', JSON.stringify(conditionsAiAvatar), false, $("#aiAvatarLabelContainer"));
      });
    });

    // =========================================================================

    // DATA COLLECTION CONTROL FUNCTIONS

    // =========================================================================

    /**
     * Pause data collection for the study
     * Updates the dataCollectionActive field to 0 and shows appropriate UI feedback
     */
    function pauseDataCollection() {
      // Hide pause button
      $('#pauseDataCollectionButton').attr("disabled", true);
      // Show continue button
      $('#continueDataCollectionButton').attr("disabled", false);

      // Update label
      $("#dataCollectionStatusLabel").text("paused");

      // Save the changes
      saveChanges('dataCollectionActive', 0);
    }

    /**
     * Resume data collection for the study
     * Updates the dataCollectionActive field to 1 and shows appropriate UI feedback
     */
    function continueDataCollection() {
      // Hide continue button
      $('#continueDataCollectionButton').attr("disabled", true);
      // Show pause button
      $('#pauseDataCollectionButton').attr("disabled", false);

      // Update label
      $("#dataCollectionStatusLabel").text("active");

      // Save the changes
      saveChanges('dataCollectionActive', 1);
    }

    // =========================================================================
    // EXPERIMENTAL CONDITIONS MANAGEMENT
    // =========================================================================
    
    /**
     * Add a new experimental condition to the study
     * Creates a new condition entry and updates all condition-dependent UI elements
     */
    function addExperimentalCondition() {
      // Add a new condition to the conditions array and refresh the UI
      conditions.push({
        number: (conditions.length + 1).toString(),
        name: '',
      });

      // Add new condition to the conditionsGptInstructions array
      conditionsGptInstructions.push({
        number: (conditionsGptInstructions.length + 1).toString(),
        name: '',
        aiInstructions: ''
      });

      // Add new condition to the conditionsParticipantInstructions array
      conditionsParticipantInstructions.push({
        number: (conditionsParticipantInstructions.length + 1).toString(),
        conditionName: '',
        participantInstructions: ''
      });

      // Add new condition to the conditionsAiName array
      conditionsAiName.push({
        number: (conditionsAiName.length + 1).toString(),
        aiName: ''
      });

      // Add new condition to the conditionsAiAvatar array
      conditionsAiAvatar.push({
        number: (conditionsAiAvatar.length + 1).toString(),
        aiAvatarURL: ''
      });

      // Add new condition to the conditionsAiDescription array
      conditionsAiDescription.push({
        number: (conditionsAiDescription.length + 1).toString(),
        aiDescription: ''
      });

      // Add new condition to the conditionsAiStatusMessage array
      conditionsAiStatusMessage.push({
        number: (conditionsAiStatusMessage.length + 1).toString(),
        aiStatusMessage: ''
      });

      // Add new condition to the conditionsFirstAiMessage array
      conditionsFirstAiMessage.push({
        number: (conditionsFirstAiMessage.length + 1).toString(),
        firstAiMessage: ''
      });

      // Add new condition to the conditionsAiTypingBubbleText array
      conditionsAiTypingBubbleText.push({
        number: (conditionsAiTypingBubbleText.length + 1).toString(),
        aiTypingBubbleText: ''
      });

      // Add new condition to the conditionsAiTypingBubbleDelay array
      conditionsAiTypingBubbleDelay.push({
        number: (conditionsAiTypingBubbleDelay.length + 1).toString(),
        aiTypingBubbleDelay: 0
      });

      // Add new condition to the conditionsAiDelayBeforeFirstMessage array
      conditionsAiDelayBeforeFirstMessage.push({
        number: (conditionsAiDelayBeforeFirstMessage.length + 1).toString(),
        aiDelayBeforeFirstMessage: 0
      });

      // Add new condition to the conditionsAiDelay array
      conditionsAiDelay.push({
        number: (conditionsAiDelay.length + 1).toString(),
        aiDelay: 0
      });

      // Add new condition to the conditionsAiDelayIsPerCharacter array
      conditionsAiDelayIsPerCharacter.push({
        number: (conditionsAiDelayIsPerCharacter.length + 1).toString(),
        aiDelayIsPerCharacter: 0
      });

      // Update DOM
      refreshExperimentalConditionsList();
      refreshGptInstructionsConditionsUI();
      refreshParticipantInstructionsConditionsUI();
      refreshAiAttributesConditionsUI();
      refreshExperimentalConditionSelect();

      // Save changes
      saveChanges('experimentalConditions', JSON.stringify(conditions), false, $("#experimentalConditionsTitle"));
      saveChanges('aiInstructions', JSON.stringify(conditionsGptInstructions), true); // true to not send success message
      saveChanges('participantInstructions', JSON.stringify(conditionsParticipantInstructions), true); // true to not send success message
      saveChanges('aiName', JSON.stringify(conditionsAiName), true); // true to not send success message
      saveChanges('aiAvatarURL', JSON.stringify(conditionsAiAvatar), true); // true to not send success message
      saveChanges('aiDescription', JSON.stringify(conditionsAiDescription), true); // true to not send success message
      saveChanges('aiStatusMessage', JSON.stringify(conditionsAiStatusMessage), true); // true to not send success message
      saveChanges('firstAiMessage', JSON.stringify(conditionsFirstAiMessage), true); // true to not send success message
      saveChanges('aiTypingBubbleText', JSON.stringify(conditionsAiTypingBubbleText), true); // true to not send success message
      saveChanges('aiTypingBubbleDelay', JSON.stringify(conditionsAiTypingBubbleDelay), true); // true to not send success message
      saveChanges('aiDelay', JSON.stringify(conditionsAiDelay), true); // true to not send success message
      saveChanges('aiDelayBeforeFirstMessage', JSON.stringify(conditionsAiDelayBeforeFirstMessage), true); // true to not send success message
      saveChanges('aiDelayIsPerCharacter', JSON.stringify(conditionsAiDelayIsPerCharacter), true); // true to not send success message
    };

    // Function to delete experimental condition
    /**
     * Delete an experimental condition from the study
     * Removes the condition and updates all condition-dependent UI elements
     */
    function deleteExperimentalCondition() {
      // Get the condition number to delete
      var experimentalConditionToDelete = $("#deleteExperimentalConditionButton").attr("conditionNumber");

      // Remove the condition from the conditions array
      conditions = conditions.filter(c => c.number !== experimentalConditionToDelete);
      conditionsGptInstructions = conditionsGptInstructions.filter(c => c.number !== experimentalConditionToDelete);
      conditionsParticipantInstructions = conditionsParticipantInstructions.filter(c => c.number !== experimentalConditionToDelete);
      conditionsAiName = conditionsAiName.filter(c => c.number !== experimentalConditionToDelete);
      conditionsAiAvatar = conditionsAiAvatar.filter(c => c.number !== experimentalConditionToDelete);
      conditionsAiDescription = conditionsAiDescription.filter(c => c.number !== experimentalConditionToDelete);
      conditionsAiStatusMessage = conditionsAiStatusMessage.filter(c => c.number !== experimentalConditionToDelete);
      conditionsFirstAiMessage = conditionsFirstAiMessage.filter(c => c.number !== experimentalConditionToDelete);
      conditionsAiTypingBubbleText = conditionsAiTypingBubbleText.filter(c => c.number !== experimentalConditionToDelete);
      conditionsAiTypingBubbleDelay = conditionsAiTypingBubbleDelay.filter(c => c.number !== experimentalConditionToDelete);
      conditionsAiDelay = conditionsAiDelay.filter(c => c.number !== experimentalConditionToDelete);
      conditionsAiDelayBeforeFirstMessage = conditionsAiDelayBeforeFirstMessage.filter(c => c.number !== experimentalConditionToDelete);
      conditionsAiDelayIsPerCharacter = conditionsAiDelayIsPerCharacter.filter(c => c.number !== experimentalConditionToDelete);

      // Renumber conditions
      conditions.forEach((c, index) => c.number = (index + 1).toString());
      conditionsGptInstructions.forEach((c, index) => c.number = (index + 1).toString());
      conditionsParticipantInstructions.forEach((c, index) => c.number = (index + 1).toString());
      conditionsAiName.forEach((c, index) => c.number = (index + 1).toString());
      conditionsAiAvatar.forEach((c, index) => c.number = (index + 1).toString());
      conditionsAiDescription.forEach((c, index) => c.number = (index + 1).toString());
      conditionsAiStatusMessage.forEach((c, index) => c.number = (index + 1).toString());
      conditionsFirstAiMessage.forEach((c, index) => c.number = (index + 1).toString());
      conditionsAiTypingBubbleText.forEach((c, index) => c.number = (index + 1).toString());
      conditionsAiTypingBubbleDelay.forEach((c, index) => c.number = (index + 1).toString());
      conditionsAiDelay.forEach((c, index) => c.number = (index + 1).toString());
      conditionsAiDelayBeforeFirstMessage.forEach((c, index) => c.number = (index + 1).toString());
      conditionsAiDelayIsPerCharacter.forEach((c, index) => c.number = (index + 1).toString());

      // Save changes
      saveChanges('experimentalConditions', JSON.stringify(conditions), false, $("#experimentalConditionsTitle"));
      saveChanges('aiInstructions', JSON.stringify(conditionsGptInstructions), true);
      saveChanges('participantInstructions', JSON.stringify(conditionsParticipantInstructions), true);
      saveChanges('aiName', JSON.stringify(conditionsAiName), true);
      saveChanges('aiAvatarURL', JSON.stringify(conditionsAiAvatar), true);
      saveChanges('aiDescription', JSON.stringify(conditionsAiDescription), true);
      saveChanges('aiStatusMessage', JSON.stringify(conditionsAiStatusMessage), true);
      saveChanges('firstAiMessage', JSON.stringify(conditionsFirstAiMessage), true);
      saveChanges('aiTypingBubbleText', JSON.stringify(conditionsAiTypingBubbleText), true);
      saveChanges('aiTypingBubbleDelay', JSON.stringify(conditionsAiTypingBubbleDelay), true);
      saveChanges('aiDelay', JSON.stringify(conditionsAiDelay), true);
      saveChanges('aiDelayBeforeFirstMessage', JSON.stringify(conditionsAiDelayBeforeFirstMessage), true);
      saveChanges('aiDelayIsPerCharacter', JSON.stringify(conditionsAiDelayIsPerCharacter), true);

      // Refresh the conditions list

      refreshExperimentalConditionsList();
      refreshGptInstructionsConditionsUI();
      refreshParticipantInstructionsConditionsUI();
      refreshAiAttributesConditionsUI();
      refreshExperimentalConditionSelect();

      // Reset the condiiton to delete
      $("#deleteExperimentalConditionButton").attr("conditionNumber", "");

      // Close the modal
      closeAllModals();
    }

    // Function to refresh experimentalConditionsList
    /**
     * Refresh the experimental conditions list UI
     * Rebuilds the conditions table with current data from the conditions array
     */
    function refreshExperimentalConditionsList() {
      // Clear the list
      $('#experimentalConditionsList').empty();

      ensureConditionsExist(); // Ensure all conditions exist

      // Check if there are no conditions to show list or placeholder
      // Ensure at least one condition exists
      if (conditions.length === 0) {
        $("#addExperimentalConditionMainButtonContainer").hide();
        $("#experimentalConditionsList").hide();
        $("#noExperimentalConditionsMessage").show();
      } else {
        $("#addExperimentalConditionMainButtonContainer").show();
        $("#experimentalConditionsList").show();
        $("#noExperimentalConditionsMessage").hide();
      }

      // Check if #disableExperimentalConditionsCheckbox is checked
      if ($('#disableExperimentalConditionsCheckbox').is(':checked')) {
        var conditionsDisabled = true;
      } else {
        var conditionsDisabled = false;
      }

      conditions.forEach(function(condition) {
        const row = $('<div class="columns" conditionNumber="' + condition.number + '">')
          .append(
            $('<div class="column is-one-third">').append(
              $('<div class="field">').append(
                $('<label class="label has-text-left">').text('Condition number'),
                $('<div class="control">').append(
                  $('<input>', {
                    class: 'input',
                    name: 'parameterInput',
                    type: 'text',
                    placeholder: 'e.g., condition',
                    value: condition.number,
                    disabled: true
                  })
                )
              )
            ),
            $('<div class="column is-two-third">').append(
              $('<div class="field">').append(
                $('<label class="label has-text-left">').text('Condition name'),
                $('<div class="control">').append(
                  $('<input>', {
                    class: 'input conditionNameInput',
                    name: 'conditionNameInput',
                    type: 'text',
                    placeholder: 'Default: Condition ' + condition.number,
                    value: condition.name,
                    style: 'width: calc(100% - 55px);',
                    disabled: conditionsDisabled,
                    conditionNumber: condition.number
                  }).on('change', function() {
                    console.log('changed');

                    var conditionNumber = $(this).attr('conditionNumber');

                    // Update condition name for conditions, conditionsGptInstructions, conditionsParticipantInstructions, conditionsAiName, conditionsAiAvatar, conditionsAiDescription, conditionsAiStatusMessage, conditionsFirstAiMessage
                    conditions[conditionNumber - 1].name = $(this).val();
                    conditionsGptInstructions[conditionNumber - 1].name = $(this).val();
                    conditionsParticipantInstructions[conditionNumber - 1].name = $(this).val();
                    conditionsAiName[conditionNumber - 1].name = $(this).val();
                    conditionsAiAvatar[conditionNumber - 1].name = $(this).val();
                    conditionsAiDescription[conditionNumber - 1].name = $(this).val();
                    conditionsAiStatusMessage[conditionNumber - 1].name = $(this).val();
                    conditionsFirstAiMessage[conditionNumber - 1].name = $(this).val();
                    conditionsAiTypingBubbleText[conditionNumber - 1].name = $(this).val();
                    conditionsAiTypingBubbleDelay[conditionNumber - 1].name = $(this).val();
                    conditionsAiDelay[conditionNumber - 1].name = $(this).val();
                    conditionsAiDelayBeforeFirstMessage[conditionNumber - 1].name = $(this).val();
                    conditionsAiDelayIsPerCharacter[conditionNumber - 1].name = $(this).val();

                    refreshExperimentalConditionsList();
                    refreshGptInstructionsConditionsUI();
                    refreshParticipantInstructionsConditionsUI();
                    refreshAiAttributesConditionsUI();
                    refreshExperimentalConditionSelect();

                    // Save changes
                    saveChanges('experimentalConditions', JSON.stringify(conditions), false, $("#experimentalConditionsTitle"));
                    saveChanges('aiInstructions', JSON.stringify(conditionsGptInstructions), true);
                    saveChanges('participantInstructions', JSON.stringify(conditionsParticipantInstructions), true);
                    saveChanges('aiName', JSON.stringify(conditionsAiName), true);
                    saveChanges('aiAvatarURL', JSON.stringify(conditionsAiAvatar), true);
                    saveChanges('aiDescription', JSON.stringify(conditionsAiDescription), true);
                    saveChanges('aiStatusMessage', JSON.stringify(conditionsAiStatusMessage), true);
                    saveChanges('firstAiMessage', JSON.stringify(conditionsFirstAiMessage), true);
                    saveChanges('aiTypingBubbleText', JSON.stringify(conditionsAiTypingBubbleText), true);
                    saveChanges('aiTypingBubbleDelay', JSON.stringify(conditionsAiTypingBubbleDelay), true);
                    saveChanges('aiDelay', JSON.stringify(conditionsAiDelay), true);
                    saveChanges('aiDelayBeforeFirstMessage', JSON.stringify(conditionsAiDelayBeforeFirstMessage), true);
                    saveChanges('aiDelayIsPerCharacter', JSON.stringify(conditionsAiDelayIsPerCharacter), true);
                  }),
                  $('<button>', {
                    class: 'button is-danger is-light ml-2 deleteConditionButton',
                    disabled: conditionsDisabled
                  }).append(
                    $('<span>', {
                      class: 'icon is-small'
                    }).append(
                      $('<i>', {
                        class: 'fa fa-minus-circle'
                      })
                    )
                  ).on('click', function() {
                    $("#deleteExperimentalConditionButton").attr("conditionNumber", condition.number);

                    // Open modal
                    $('#deleteExperimentalConditionModal').addClass('is-active');
                  })
                )
              )
            )
          );

        $('#experimentalConditionsList').append(row);
      });
    }

    /**
     * Refresh all experimental condition dropdown menus
     * Updates select elements throughout the interface with current conditions
     */
    function refreshExperimentalConditionSelect() {
      // Clear the selects
      $('#experimentalConditionLinkSelect').empty();
      $('#experimentalConditionEmbedSelect').empty();
      $("#previewConditionSelect").empty();

      // Check if there are no conditions or show list for link
      if (conditions.length === 0) {
        //$("#includeConditionInLinkCheckbox").hide();
        $("#includeConditionInLinkCheckbox").prop('checked', false);
        $("#experimentalConditionLinkSelect").hide();
        $("#includeConditionInLinkCheckbox").closest("span").hide();
      } else {
        $("#includeConditionInLinkCheckbox").closest("span").show();

        // Check if includeConditionInLinkCheckbox is checked and show the select
        if ($('#includeConditionInLinkCheckbox').is(':checked')) {
          $("#experimentalConditionLinkSelectContainer").show();
        } else {
          $("#experimentalConditionLinkSelectContainer").hide();
        }
      }

      // Check if there are no conditions or show list for embed
      if (conditions.length === 0) {
        $("#includeConditionInEmbedCheckbox").prop('checked', false);
        $("#experimentalConditionEmbedSelect").hide();
        $("#includeConditionInEmbedCheckbox").closest("span").hide();
      } else {
        $("#includeConditionInEmbedCheckbox").closest("span").show();

        // Check if includeConditionInEmbedCheckbox is checked and show the select
        if ($('#includeConditionInEmbedCheckbox').is(':checked')) {
          $("#experimentalConditionEmbedSelectContainer").show();
        } else {
          $("#experimentalConditionEmbedSelectContainer").hide();
        }
      }

      conditions.forEach(function(condition) {
        $('#experimentalConditionLinkSelect').append($('<option>', {
          value: condition.number,
          text: "Condition " + condition.number
        }));

        $('#experimentalConditionEmbedSelect').append($('<option>', {
          value: condition.number,
          text: "Condition " + condition.number
        }));

        $("#previewConditionSelect").append($('<option>', {
          value: condition.number,
          text: "Condition " + condition.number
        }));
      });
    }

    // Function to refresh the conditions UI for GPT instructions, both the tab and the active condition
    /**
     * Refresh the AI instructions interface for condition-specific settings
     * Updates the UI to show instructions for the currently selected condition
     */
    // =========================================================================
    // UI REFRESH FUNCTIONS - CONDITION-SPECIFIC INTERFACES
    // =========================================================================
    
    /**
     * Refresh the AI instructions interface for condition-specific settings
     * Updates the UI to show instructions for the currently selected condition
     */
    function refreshGptInstructionsConditionsUI() {
      // Clear existing tabs
      $('#gptInstructionsConditionsTabs ul').empty();

      ensureConditionsExist();

      // Check if active condition is within bounds
      if (currentlyActiveGPTInstructionsCondition >= conditionsGptInstructions.length) {
        currentlyActiveGPTInstructionsCondition = 0;
      }

      // Add condition tabs
      conditionsGptInstructions.forEach((condition, index) => {
        console.log('condition', condition);
        // Check if condition has name
        var conditionName = condition.name ? condition.name : `Condition ${condition.number}`;
        // Add condition tab and listen for click on the tab
        var tab = $(`<li target="${index}"><a>${conditionName}</a></li>`)
          .on('click', function() {
            currentlyActiveGPTInstructionsCondition = index;
            refreshGptInstructionsConditionsUI();
          });

        // Check if this is the active tab
        if (currentlyActiveGPTInstructionsCondition === index) {
          tab.addClass('is-active');
        }

        // Append the condition tab
        tab.appendTo('#gptInstructionsConditionsTabs ul');
      });

      // Get active condition
      const activeCondition = conditionsGptInstructions[currentlyActiveGPTInstructionsCondition];
      // Get condition name
      const conditionName = activeCondition.name ? activeCondition.name : `Condition ${activeCondition.number}`;

      $('#gptInstructionsConditionSpecificationContainer').text(`These are the AI's instructions for "${conditionName}". You can add experimental conditions in Step 1.`);

      // Update the gptInstructionsLabel and gptInstructionsSpecificationLabel with the current condition name
      $('#gptInstructionsLabel').text(`AI instructions for ${conditionName}`);

      // Check if tinyMCE is initialized
      if (tinyMCE.get('gptInstructionsInput')) {
        tinyMCE.get('gptInstructionsInput').setContent(activeCondition.aiInstructions, {
          format: 'html'
        });
      }

      // Update gptInstructionsInput with the current condition's instructions
      $('#gptInstructionsInput').val(conditionsGptInstructions[currentlyActiveGPTInstructionsCondition].aiInstructions);
    }

    // Function to refresh the conditions UI for participant instructions, both the tab and the active condition
    /**
     * Refresh the participant instructions interface for condition-specific settings
     * Updates the UI to show instructions for the currently selected condition
     */
    function refreshParticipantInstructionsConditionsUI() {
      // Clear existing tabs
      $('#participantInstructionsConditionsTabs ul').empty();

      ensureConditionsExist();

      // Check if active condition is within bounds
      if (currentlyActiveParticipantInstructionsCondition >= conditionsParticipantInstructions.length) {
        currentlyActiveParticipantInstructionsCondition = 0;
      }

      // Add condition tabs
      conditionsParticipantInstructions.forEach((condition, index) => {
        // CHeck if condition has name
        var conditionName = condition.name ? condition.name : `Condition ${condition.number}`;

        // Add condition tab and listen for click on the tab
        var tab = $(`<li target="${index}"><a>${conditionName}</a></li>`);

        tab.on('click', function() {
          currentlyActiveParticipantInstructionsCondition = index;
          refreshParticipantInstructionsConditionsUI();
        });

        // Check if this is the active tab
        if (currentlyActiveParticipantInstructionsCondition === index) {
          tab.addClass('is-active');
        }

        // Append the condition tab
        tab.appendTo('#participantInstructionsConditionsTabs ul');
      });

      // Get the active condition
      const activeCondition = conditionsParticipantInstructions[currentlyActiveParticipantInstructionsCondition];
      // Get condition name
      const conditionName = activeCondition.name ? activeCondition.name : `Condition ${activeCondition.number}`;

      $('#conditionSpecificationParticipantInstructionsContainer').text(`These are the participant's instructions for "${conditionName}". You can add experimental conditions in Step 1.`);

      // Update the participantInstructionsLabel and participantInstructionsSpecificationLabel with the current condition name
      $('#participantInstructionsSpecificationLabel').text(`Specification for ${conditionName}`);
      $('#participantInstructionsLabel').text(`Participant instructions for ${conditionName}`);

      console.log("before");
      // Check if tinyMCE is initialized
      if (tinyMCE.get('participantInstructionsTextInput')) {
        // Update the participant instructions input with the active condition's instructions
        tinyMCE.get('participantInstructionsTextInput').setContent(activeCondition.participantInstructions, {
          format: 'html'
        });
      }
    }

    // Function to refresh conditions UI for ai attributes (aiName, aiAvatar, aiDescription, aiStatusMessage, firstAiMessage)
    /**
     * Refresh the AI attributes interface for condition-specific settings
     * Updates the UI to show AI name, avatar, description, etc. for the current condition
     */
    function refreshAiAttributesConditionsUI() {
      // Clear existing tabs
      $('#aiAttributesConditionsTabs ul').empty();

      ensureConditionsExist();

      // Check if active condition is within bounds
      if (currentlyActiveAiAttributesCondition >= conditionsAiName.length) {
        currentlyActiveAiAttributesCondition = 0;
      }

      // Add condition tabs
      conditions.forEach((condition, index) => {
        // Check if condition has name
        var conditionName = condition.name ? condition.name : `Condition ${condition.number}`;
        // Add condition tab and listen for click on the tab
        var tab = $(`<li target="${index}"><a>${conditionName}</a></li>`)
          .on('click', function() {
            currentlyActiveAiAttributesCondition = index;
            refreshAiAttributesConditionsUI();
          });

        // Check if this is the active tab
        if (currentlyActiveAiAttributesCondition === index) {
          tab.addClass('is-active');
        }

        // Append the condition tab
        tab.appendTo('#aiAttributesConditionsTabs ul');
      });

      // Set gloabl default values for the variables
      var defaultAiName = "e.g., AI Assistant Aaron"
      var defaultAiAvatar = "";
      var defaultAiDescription = "e.g., Please be friendly to the AI";
      var defaultAiStatusMessage = "e.g., Expert on Investments";
      var defaultFirstAiMessage = "e.g., Hello! How can I assist you today?";
      var defaultAiTypingBubbleText = "Default: [None]";
      var defaultAiTypingBubbleDelay = "Default: 0";
      var defaultAiDelay = "Default: 0";

      // Get active condition
      const activeCondition = conditionsAiName[currentlyActiveAiAttributesCondition];

      // Get condtion name
      const conditionName = conditions[currentlyActiveAiAttributesCondition].name ? conditions[currentlyActiveAiAttributesCondition].name : `Condition ${conditions[currentlyActiveAiAttributesCondition].number}`;

      // Update name of aiNameLabel, aiAvatarLabel, aiDescriptionLabel, aiStatusMessageLabel, firstAiMessageLabel
      $('#aiAttributesDefaultSpecificationContainer').hide();
      $('#aiAttributesConditionSpecificationContainer').show();

      // Update labels
      $('#aiAttributesConditionName').text(`${conditionName}`);
      $('#aiNameLabel').text(`AI name for ${conditionName}`);
      $('#aiAvatarLabel').text(`AI avatar for ${conditionName}`);
      $('#aiDescriptionLabel').text(`AI description for ${conditionName}`);
      $('#aiStatusMessageLabel').text(`AI status message for ${conditionName}`);
      $('#firstAiMessageLabel').text(`First AI message for ${conditionName}`);

      // Update the AI attributes input fields with the active condition's values.
      $('#aiNameInput').val(conditionsAiName[currentlyActiveAiAttributesCondition].aiName);
      $('#aiAvatarInput').val(conditionsAiAvatar[currentlyActiveAiAttributesCondition].aiAvatarURL);
      $('#aiDescriptionInput').val(conditionsAiDescription[currentlyActiveAiAttributesCondition].aiDescription);
      $('#aiStatusMessageInput').val(conditionsAiStatusMessage[currentlyActiveAiAttributesCondition].aiStatusMessage);
      $('#firstAiMessageInput').val(conditionsFirstAiMessage[currentlyActiveAiAttributesCondition].firstAiMessage);
      $('#aiTypingBubbleTextInput').val(conditionsAiTypingBubbleText[currentlyActiveAiAttributesCondition].aiTypingBubbleText);
      $('#aiTypingBubbleDelayInput').val(conditionsAiTypingBubbleDelay[currentlyActiveAiAttributesCondition].aiTypingBubbleDelay);
      $('#aiDelayInput').val(conditionsAiDelay[currentlyActiveAiAttributesCondition].aiDelay);
      $('#aiDelayBeforeFirstMessageCheckbox').prop('checked', conditionsAiDelayBeforeFirstMessage[currentlyActiveAiAttributesCondition].aiDelayBeforeFirstMessage == 1);
      $('#aiDelayIsPerCharacterCheckbox').prop('checked', conditionsAiDelayIsPerCharacter[currentlyActiveAiAttributesCondition].aiDelayIsPerCharacter == 1);

      // Set values from default condition as placeholders; if empty in default condition, ues default values
      $('#aiNameInput').attr('placeholder', defaultAiName);
      $('#aiAvatarInput').attr('placeholder', defaultAiAvatar);
      $('#aiDescriptionInput').attr('placeholder', defaultAiDescription);
      $('#aiStatusMessageInput').attr('placeholder', defaultAiStatusMessage);
      $('#firstAiMessageInput').attr('placeholder', defaultFirstAiMessage);
      $('#aiTypingBubbleTextInput').attr('placeholder', defaultAiTypingBubbleText);
      $('#aiTypingBubbleDelayInput').attr('placeholder', defaultAiTypingBubbleDelay);
      $('#aiDelayInput').attr('placeholder', defaultAiDelay);

      // Check if aiAvatar is set for condition
      if (conditionsAiAvatar[currentlyActiveAiAttributesCondition].aiAvatarURL) {
        $('#aiAvatarPreview').attr('src', conditionsAiAvatar[currentlyActiveAiAttributesCondition].aiAvatarURL);
        $('#aiAvatarPreviewContainer').show();
        $('#avatarUploadContainer').hide();
      } else {
        $('#aiAvatarPreview').attr('src', '');
        $('#aiAvatarPreviewContainer').hide();
        $('#avatarUploadContainer').show();
      }

    }

    // Functioin to make sure all conditions are present within thier respective arrays; add conditions if not
    /**
     * Ensure at least one experimental condition exists
     * Creates a default condition if the conditions array is empty
     */
    function ensureConditionsExist() {
      // Make sure there is at least one condition in the conditions array
      if (conditions.length === 0) {
        conditions.push({
          number: '1',
          name: ''
        });

        // Save changes
        saveChanges('experimentalConditions', JSON.stringify(conditions), true);
      }

      // Ensure conditions exist for aiName
      if (conditionsAiName.length < conditions.length || conditionsAiName.length === 0) {
        for (let i = conditionsAiName.length; i < conditions.length; i++) {
          conditionsAiName.push({
            number: (i + 1).toString(),
            name: ``,
            aiName: '',
          });
        }

        // Save changes
        saveChanges('aiName', JSON.stringify(conditionsAiName), true);
      }

      // Ensure conditions exist for aiAvatar
      if (conditionsAiAvatar.length < conditions.length || conditionsAiAvatar.length === 0) {
        for (let i = conditionsAiAvatar.length; i < conditions.length; i++) {
          conditionsAiAvatar.push({
            number: (i + 1).toString(),
            name: ``,
            aiAvatarURL: '',
          });
        }

        // Save changes
        saveChanges('aiAvatarURL', JSON.stringify(conditionsAiAvatar), true);
      }

      // Ensure conditions exist for aiDescription
      if (conditionsAiDescription.length < conditions.length || conditionsAiDescription.length === 0) {
        for (let i = conditionsAiDescription.length; i < conditions.length; i++) {
          conditionsAiDescription.push({
            number: (i + 1).toString(),
            name: ``,
            aiDescription: '',
          });
        }

        // Save changes
        saveChanges('aiDescription', JSON.stringify(conditionsAiDescription), true);
      }

      // Ensure conditions exist for aiStatusMessage
      if (conditionsAiStatusMessage.length < conditions.length || conditionsAiStatusMessage.length === 0) {
        for (let i = conditionsAiStatusMessage.length; i < conditions.length; i++) {
          conditionsAiStatusMessage.push({
            number: (i + 1).toString(),
            name: ``,
            aiStatusMessage: '',
          });
        }

        // Save changes
        saveChanges('aiStatusMessage', JSON.stringify(conditionsAiStatusMessage), true);
      }

      // Ensure conditions exist for firstAiMessage
      if (conditionsFirstAiMessage.length < conditions.length || conditionsFirstAiMessage.length === 0) {
        for (let i = conditionsFirstAiMessage.length; i < conditions.length; i++) {
          conditionsFirstAiMessage.push({
            number: (i + 1).toString(),
            name: ``,
            firstAiMessage: '',
          });
        }

        // Save changes
        saveChanges('firstAiMessage', JSON.stringify(conditionsFirstAiMessage), true);
      }

      // Ensure conditions exist for gptInstructions
      if (conditionsGptInstructions.length < conditions.length || conditionsGptInstructions.length === 0) {
        for (let i = conditionsGptInstructions.length; i < conditions.length; i++) {
          conditionsGptInstructions.push({
            number: (i + 1).toString(),
            name: ``,
            aiInstructions: '',
          });
        }

        // Save changes
        saveChanges('aiInstructions', JSON.stringify(conditionsGptInstructions), true);
      }

      // Ensure conditions exist for participantInstructions
      if (conditionsParticipantInstructions.length < conditions.length || conditionsParticipantInstructions.length === 0) {
        for (let i = conditionsParticipantInstructions.length; i < conditions.length; i++) {
          conditionsParticipantInstructions.push({
            number: (i + 1).toString(),
            name: ``,
            participantInstructions: '',
          });
        }

        // Save changes
        saveChanges('participantInstructions', JSON.stringify(conditionsParticipantInstructions), true);
      }

      // Ensure conditions exist for aiTypingBubbleText
      if (conditionsAiTypingBubbleText.length < conditions.length || conditionsAiTypingBubbleText.length === 0) {
        for (let i = conditionsAiTypingBubbleText.length; i < conditions.length; i++) {
          conditionsAiTypingBubbleText.push({
            number: (i + 1).toString(),
            name: ``,
            aiTypingBubbleText: '',
          });
        }

        // Save changes
        saveChanges('aiTypingBubbleText', JSON.stringify(conditionsAiTypingBubbleText), true);
      }

      // Ensure conditions exist for aiTypingBubbleDelay
      if (conditionsAiTypingBubbleDelay.length < conditions.length || conditionsAiTypingBubbleDelay.length === 0) {
        for (let i = conditionsAiTypingBubbleDelay.length; i < conditions.length; i++) {
          conditionsAiTypingBubbleDelay.push({
            number: (i + 1).toString(),
            name: ``,
            aiTypingBubbleDelay: 0,
          });
        }

        // Save changes
        saveChanges('aiTypingBubbleDelay', JSON.stringify(conditionsAiTypingBubbleDelay), true);
      }

      // Ensure conditions exist for aiDelay
      if (conditionsAiDelay.length < conditions.length || conditionsAiDelay.length === 0) {
        for (let i = conditionsAiDelay.length; i < conditions.length; i++) {
          conditionsAiDelay.push({
            number: (i + 1).toString(),
            name: ``,
            aiDelay: '',
          });
        }

        // Save changes
        saveChanges('aiDelay', JSON.stringify(conditionsAiDelay), true);
      }

      // Ensure conditions exist for aiDelayBeforeFirstMessage
      if (conditionsAiDelayBeforeFirstMessage.length < conditions.length || conditionsAiDelayBeforeFirstMessage.length === 0) {
        for (let i = conditionsAiDelayBeforeFirstMessage.length; i < conditions.length; i++) {
          conditionsAiDelayBeforeFirstMessage.push({
            number: (i + 1).toString(),
            name: ``,
            aiDelayBeforeFirstMessage: 0,
          });
        }

        // Save changes
        saveChanges('aiDelayBeforeFirstMessage', JSON.stringify(conditionsAiDelayBeforeFirstMessage), true);
      }

      // Ensure conditions exist for aiDelayIsPerCharacter
      if (conditionsAiDelayIsPerCharacter.length < conditions.length || conditionsAiDelayIsPerCharacter.length === 0) {
        for (let i = conditionsAiDelayIsPerCharacter.length; i < conditions.length; i++) {
          conditionsAiDelayIsPerCharacter.push({
            number: (i + 1).toString(),
            name: ``,
            aiDelayIsPerCharacter: 0,
          });
        }

        // Save changes
        saveChanges('aiDelayIsPerCharacter', JSON.stringify(conditionsAiDelayIsPerCharacter), true);
      }
    }

    // Refresh URL of iFrame to refresh it (with correct experimental condition)
    /**
     * Update the preview iframe with current study configuration
     * Reloads the chat interface preview with updated settings
     */
    // =========================================================================
    // PREVIEW AND VALIDATION FUNCTIONS
    // =========================================================================
    
    /**
     * Update the preview iframe with current study configuration
     * Reloads the chat interface preview with updated settings
     */
    function updatePreviewIframe() {
      // Get the selected condition
      var selectedCondition = $('#previewConditionSelect').val();

      // Get the iFrame element
      var iframe = document.getElementById('previewIframe');

      // Generate new url
      var newUrl = baseURL + 'studyCode=' + studyCode + '&condition=' + selectedCondition + '&participantID=PREVIEW';

      // Update the iFrame URL
      iframe.src = newUrl;
    }

    // Set correct status for elements inside Step 5: Prelaunch check by checking inputs for welcome message, close button, ai attributes, chat apperance, ai isntructions, particiapnt instructions
    /**
     * Conduct pre-launch validation check for the study
     * Validates all required fields and settings before allowing study launch
     * Updates status indicators for each validation requirement
     */
    function conductPrelaunchCheck() {
      // Check if welcomeMessage is hidden via checkbox
      if ($('#hideWelcomeMessageCheckbox').is(':checked')) {
        $("#welcomeMessageStatusCheck").removeClass("warning").addClass("ok");
      } else {
        // Check if welcomeMessage is empty
        if ($('#welcomeMessageInput').val() === '') {
          $("#welcomeMessageStatusCheck").removeClass("ok").addClass("warning");
        } else {
          $("#welcomeMessageStatusCheck").removeClass("warning").addClass("ok");
        }
      }

      // Check if closeButton is hidden via checkbox
      if ($('#hideNextButtonCheckbox').is(':checked')) {
        $("#closeButtonStatusCheck").removeClass("warning").addClass("ok");
      } else {
        // Check if closeButton is empty
        if ($('#nextButtonLabelInput').val() === '') {
          $("#closeButtonStatusCheck").removeClass("ok").addClass("warning");
        } else {
          $("#closeButtonStatusCheck").removeClass("warning").addClass("ok");
        }
      }

      // Check if ai name is provided for all conditions
      var aiNameStatus = true;
      conditionsAiName.forEach((condition) => {
        if (condition.aiName === '') {
          aiNameStatus = false;
        }
      });
      // Set status for aiAttributes
      if (aiNameStatus) {
        $("#aiAttributesStatusCheck").removeClass("warning").addClass("ok");
      } else {
        $("#aiAttributesStatusCheck").removeClass("ok").addClass("warning");
      }

      // Check if the six color pickers for chat apperance are set
      var chatAppearanceStatus = true;
      if ($('#sendButtonBgColorInput').val() === '') {
        chatAppearanceStatus = false;
      }
      if ($('#sendButtonTextColorInput').val() === '') {
        chatAppearanceStatus = false;
      }
      if ($('#userBubbleBgColorInput').val() === '') {
        chatAppearanceStatus = false;
      }
      if ($('#userBubbleTextColorInput').val() === '') {
        chatAppearanceStatus = false;
      }
      if ($('#aiBubbleBgColorInput').val() === '') {
        chatAppearanceStatus = false;
      }
      if ($('#aiBubbleTextColorInput').val() === '') {
        chatAppearanceStatus = false;
      }
      // Set status for chatApperance
      if (chatAppearanceStatus) {
        $("#chatAppearanceStatusCheck").removeClass("error").addClass("ok");
      } else {
        $("#chatAppearanceStatusCheck").removeClass("ok").addClass("error");
      }

      // Check if aiInstructions are provided for all conditions
      var aiInstructionsStatus = true;
      conditionsGptInstructions.forEach((condition) => {
        if (condition.aiInstructions === '') {
          aiInstructionsStatus = false;
        }
      });

      // Set status for aiInstructions
      if (aiInstructionsStatus) {
        $("#aiInstructionsStatusCheck").removeClass("warning").addClass("ok");
      } else {
        $("#aiInstructionsStatusCheck").removeClass("ok").addClass("warning");
      }

      // Check if participantInstructions are provided for all conditions
      var participantInstructionsStatus = true;
      conditionsParticipantInstructions.forEach((condition) => {
        if (condition.participantInstructions === '') {
          participantInstructionsStatus = false;
        }
      });

      // -----------------------------------------------------------------------
      // PARTICIPANT INSTRUCTIONS VALIDATION
      // -----------------------------------------------------------------------
      
      // Check if participantInstructions are hidden via checkbox
      if ($('#hideInstructionsWindowCheckbox').is(':checked')) {
        participantInstructionsStatus = true;
      }

      // Set status for participantInstructions
      if (participantInstructionsStatus) {
        $("#participantInstructionsStatusCheck").removeClass("warning").addClass("ok");
      } else {
        $("#participantInstructionsStatusCheck").removeClass("ok").addClass("warning");
      }

      // -----------------------------------------------------------------------
      // API KEY VALIDATION
      // -----------------------------------------------------------------------
      
      // Check whether custom connector is selected
      if ($('#customModelProviderRadioButton').hasClass('active')) {
        // Custom connector cannot be automatically verified
        $("#llmSettingsStatusCheck").removeClass("ok").removeClass("warning").removeClass("error").addClass("info");
      } else if ($('#openRouterModelProviderRadioButton').hasClass('active')) {
        // Check whether openRouterApiKeyInput is empty
        if ($('#openRouterApiKeyInput').val() === '') {
          $("#llmSettingsStatusCheck").removeClass("ok").removeClass("warning").removeClass("info").addClass("error");
        } else {
          // Check whether the openRouterApiKeyInput begins with "sk-"
          if ($('#openRouterApiKeyInput').val().startsWith('sk-')) {
            $("#llmSettingsStatusCheck").removeClass("warning").removeClass("error").removeClass("info").addClass("ok");
          } else {
            $("#llmSettingsStatusCheck").removeClass("ok").removeClass("error").removeClass("info").addClass("warning");
          }
        }
      } else {
        // Check whether openAiApiKeyInput  is empty
        if ($('#openAiApiKeyInput').val() === '') {
          $("#llmSettingsStatusCheck").removeClass("ok").removeClass("warning").removeClass("info").addClass("error");
        } else {
          // Check whether the openAiApiKeyInput begins with "sk-" and has a length of 16 characters
          if ($('#openAiApiKeyInput').val().startsWith('sk-')) {
            $("#llmSettingsStatusCheck").removeClass("warning").removeClass("error").removeClass("info").addClass("ok");
          } else {
            $("#llmSettingsStatusCheck").removeClass("ok").removeClass("error").removeClass("info").addClass("warning");
          }
        }
      }
    }

    /**
     * Save study field changes to the server
     * 
     * @param {string} fieldKey - The database field name to update
     * @param {*} fieldValue - The new value for the field
     * @param {boolean} noNotification - If true, suppress success notification
     * @param {jQuery} feedbackElement - Optional element to show inline feedback
     */
    function saveChanges(fieldKey, fieldValue, noNotification, feedbackElement) {
      // Save changes to Backend/Studies/study-update-field.php using ajax
      $.ajax({
        type: "POST",
        url: "Backend/Studies/study-update-field.php",
        data: {
          csrf_token: csrfToken,  // CSRF protection
          studyID: studyID,
          fieldKey: fieldKey,
          fieldValue: fieldValue
        },
        success: function(response) {
          if (noNotification) {
            return;
          }

          if (feedbackElement) {
            // Check if feedback element has child with ".savedIndicator"
            if (feedbackElement.find('.savedIndicator').length === 0) {
              feedbackElement.append('<span class="savedIndicator tag is-success is-light ml-5" counter="1" style="vertical-align:top;"><i class="fas fa-check mr-2"></i> Changes saved</span>');
            } else {
              // increment counter of saveIndicator
              var counter = parseInt(feedbackElement.find('.savedIndicator').attr('counter'));
              counter++;
              feedbackElement.find('.savedIndicator').attr('counter', counter);
            }
          } else {
            iziToast.show({
              title: 'Success',
              message: 'Changes saved successfully',
              color: 'green'
            });
          }

          // Set timer to fade out the saved indicator after 2 seconds
          setTimeout(function() {
            if (feedbackElement) {
              var counter = parseInt(feedbackElement.find('.savedIndicator').attr('counter'));
              counter--;
              if (counter === 0) {
                feedbackElement.find('.savedIndicator').fadeOut(200, function() {
                  $(this).remove();
                });
              } else {
                feedbackElement.find('.savedIndicator').attr('counter', counter);
              }
            }
          }, 1000);

          if (response.status != "good") {
            console.log(response);
            iziToast.show({
              title: 'Error',
              message: 'An error occurred while saving your changes',
              color: 'red'
            });
          }
        },
        error: function(response) {
          console.log(response);

          numberOfSaves--;
          if (numberOfSaves <= 0) {
            $("#saveStatusIndicatorSaving").hide();
            $("#saveStatusIndicatorSaved").show();
          }

          iziToast.show({
            title: 'Error',
            message: 'An error occurred while saving your changes',
            color: 'red'
          });
        }
      });
    }

    /**
     * Copy AI attributes from one condition to another
     * Allows replication of AI name, avatar, description, etc. across conditions
     */
    // =========================================================================
    // UTILITY FUNCTIONS - AI ATTRIBUTES MANAGEMENT
    // =========================================================================
    
    /**
     * Copy AI attributes from one condition to another
     * Allows replication of AI name, avatar, description, etc. across conditions
     */
    function copyAiAttributes() {
      // Get the current condition condition values and copy to all other conditions
      var currentAiName = conditionsAiName[currentlyActiveAiAttributesCondition].aiName;
      var currentAiAvatar = conditionsAiAvatar[currentlyActiveAiAttributesCondition].aiAvatarURL;
      var currentAiDescription = conditionsAiDescription[currentlyActiveAiAttributesCondition].aiDescription;
      var currentAiStatusMessage = conditionsAiStatusMessage[currentlyActiveAiAttributesCondition].aiStatusMessage;
      var currentFirstAiMessage = conditionsFirstAiMessage[currentlyActiveAiAttributesCondition].firstAiMessage;
      var currentAiTypingBubbleText = conditionsAiTypingBubbleText[currentlyActiveAiAttributesCondition].aiTypingBubbleText;
      var currentAiTypingBubbleDelay = conditionsAiTypingBubbleDelay[currentlyActiveAiAttributesCondition].aiTypingBubbleDelay;
      var currentAiDelay = conditionsAiDelay[currentlyActiveAiAttributesCondition].aiDelay;
      var currentAiDelayBeforeFirstMessage = conditionsAiDelayBeforeFirstMessage[currentlyActiveAiAttributesCondition].aiDelayBeforeFirstMessage;
      var currentAiDelayIsPerCharacter = conditionsAiDelayIsPerCharacter[currentlyActiveAiAttributesCondition].aiDelayIsPerCharacter;

      // Loop through all conditions and update the values
      conditionsAiName.forEach((condition, index) => {
        conditionsAiName[index].aiName = currentAiName;
        conditionsAiAvatar[index].aiAvatarURL = currentAiAvatar;
        conditionsAiDescription[index].aiDescription = currentAiDescription;
        conditionsAiStatusMessage[index].aiStatusMessage = currentAiStatusMessage;
        conditionsFirstAiMessage[index].firstAiMessage = currentFirstAiMessage;
        conditionsAiTypingBubbleText[index].aiTypingBubbleText = currentAiTypingBubbleText;
        conditionsAiTypingBubbleDelay[index].aiTypingBubbleDelay = currentAiTypingBubbleDelay;
        conditionsAiDelay[index].aiDelay = currentAiDelay;
        conditionsAiDelayBeforeFirstMessage[index].aiDelayBeforeFirstMessage = currentAiDelayBeforeFirstMessage;
        conditionsAiDelayIsPerCharacter[index].aiDelayIsPerCharacter = currentAiDelayIsPerCharacter;
      });

      // Save changes
      saveChanges('aiName', JSON.stringify(conditionsAiName), false, $("#aiIdentifyTitle"));
      saveChanges('aiAvatarURL', JSON.stringify(conditionsAiAvatar), false, $("#aiIdentifyTitle"));
      saveChanges('aiDescription', JSON.stringify(conditionsAiDescription), false, $("#aiIdentifyTitle"));
      saveChanges('aiStatusMessage', JSON.stringify(conditionsAiStatusMessage), false, $("#aiIdentifyTitle"));
      saveChanges('firstAiMessage', JSON.stringify(conditionsFirstAiMessage), false, $("#aiIdentifyTitle"));
      saveChanges('aiTypingBubbleText', JSON.stringify(conditionsAiTypingBubbleText), false, $("#aiIdentifyTitle"));
      saveChanges('aiTypingBubbleDelay', JSON.stringify(conditionsAiTypingBubbleDelay), false, $("#aiIdentifyTitle"));
      saveChanges('aiDelay', JSON.stringify(conditionsAiDelay), false, $("#aiIdentifyTitle"));
      saveChanges('aiDelayBeforeFirstMessage', JSON.stringify(conditionsAiDelayBeforeFirstMessage), false, $("#aiIdentifyTitle"));
      saveChanges('aiDelayIsPerCharacter', JSON.stringify(conditionsAiDelayIsPerCharacter), false, $("#aiIdentifyTitle"));
    }

    /**
     * Erase all AI attributes for the current condition
     * Resets AI name, avatar, description, status message, etc. to empty values
     */
    function eraseAiAttributes() {
      // Get the current condition and update the avatar
      conditionsAiName[currentlyActiveAiAttributesCondition].aiName = '';
      conditionsAiAvatar[currentlyActiveAiAttributesCondition].aiAvatarURL = '';
      conditionsAiDescription[currentlyActiveAiAttributesCondition].aiDescription = '';
      conditionsAiStatusMessage[currentlyActiveAiAttributesCondition].aiStatusMessage = '';
      conditionsFirstAiMessage[currentlyActiveAiAttributesCondition].firstAiMessage = '';
      conditionsAiTypingBubbleText[currentlyActiveAiAttributesCondition].aiTypingBubbleText = '';
      conditionsAiTypingBubbleDelay[currentlyActiveAiAttributesCondition].aiTypingBubbleDelay = 0;
      conditionsAiDelay[currentlyActiveAiAttributesCondition].aiDelay = '';
      conditionsAiDelayBeforeFirstMessage[currentlyActiveAiAttributesCondition].aiDelayBeforeFirstMessage = 0;
      conditionsAiDelayIsPerCharacter[currentlyActiveAiAttributesCondition].aiDelayIsPerCharacter = 0;

      // Update DOM
      refreshAiAttributesConditionsUI();

      // Save changes
      saveChanges('aiName', JSON.stringify(conditionsAiName), false, $("#aiIdentifyTitle"));
      saveChanges('aiAvatarURL', JSON.stringify(conditionsAiAvatar), false, $("#aiIdentifyTitle"));
      saveChanges('aiDescription', JSON.stringify(conditionsAiDescription), false, $("#aiIdentifyTitle"));
      saveChanges('aiStatusMessage', JSON.stringify(conditionsAiStatusMessage), false, $("#aiIdentifyTitle"));
      saveChanges('firstAiMessage', JSON.stringify(conditionsFirstAiMessage), false, $("#aiIdentifyTitle"));
      saveChanges('aiTypingBubbleText', JSON.stringify(conditionsAiTypingBubbleText), false, $("#aiIdentifyTitle"));
      saveChanges('aiTypingBubbleDelay', JSON.stringify(conditionsAiTypingBubbleDelay), false, $("#aiIdentifyTitle"));
      saveChanges('aiDelay', JSON.stringify(conditionsAiDelay), false, $("#aiIdentifyTitle"));
      saveChanges('aiDelayBeforeFirstMessage', JSON.stringify(conditionsAiDelayBeforeFirstMessage), false, $("#aiIdentifyTitle"));
      saveChanges('aiDelayIsPerCharacter', JSON.stringify(conditionsAiDelayIsPerCharacter), false, $("#aiIdentifyTitle"));
    }

    // Create the distribtuion link. If link builder is enabled, add the passed variables to the URL. If not, add "XYZ" as placeholder for the passed variables.
    /**
     * Update the distribution link based on current settings
     * Generates the study URL with optional participant ID and condition parameters
     */
    function updateDistributionLink() {
      // Check if the link should include participantID and condition
      var includeParticipantIdInLink = $('#includeParticipantIdInLinkCheckbox').is(':checked');
      var includeConditionInLink = $('#includeConditionInLinkCheckbox').is(':checked');

      // Combine base URL with study code
      var distributionLink = baseURL + 'studyCode=' + studyCode;

      // If includeParticipantIdInLink is checked, add participantID to the link
      if (includeParticipantIdInLink) {
        // Check if participantID is set in input field
        var participantID = $('#participantIdShareLinkInput').val();
        if (participantID) {
          distributionLink += '&participantID=' + participantID;
        } else {
          distributionLink += '&participantID=XYZ';
        }
      }

      // If includeConditionInLink is checked, add condition to the link
      if (includeConditionInLink) {
        // Check if conditionNumber is set
        var conditionNumber = $('#experimentalConditionLinkSelect').val();
        if (conditionNumber) {
          distributionLink += '&condition=' + conditionNumber;
        } else {
          distributionLink += '&condition=1';
        }
      }

      // Update the distribution link input field
      $('#studyLinkInput').val(distributionLink);

      ///////SAME FOR EMBED
      // Check if the link should include participantID and condition
      var includeParticipantIdInEmbed = $('#includeParticipantIdInEmbedCheckbox').is(':checked');
      var includeConditionInEmbed = $('#includeConditionInEmbedCheckbox').is(':checked');

      // Combine base URL with study code
      var distributionLinkEmbed = baseURL + 'studyCode=' + studyCode;

      // If includeParticipantIdInLink is checked, add participantID to the link
      if (includeParticipantIdInEmbed) {
        // Check if participantID is set in input field
        var participantIDEmbed = $('#participantIdEmbedInput').val();
        if (participantIDEmbed) {
          distributionLinkEmbed += '&participantID=' + participantIDEmbed;
        } else {
          distributionLinkEmbed += '&participantID=XYZ';
        }
      }

      // If includeConditionInLink is checked, add condition to the link
      if (includeConditionInEmbed) {
        // Check if conditionNumber is set
        var conditionNumberEmbed = $('#experimentalConditionEmbedSelect').val();
        if (conditionNumberEmbed) {
          distributionLinkEmbed += '&condition=' + conditionNumberEmbed;
        } else {
          distributionLinkEmbed += '&condition=1';
        }
      }

      // Get max width and height
      var width = $('#studyEmbedWidthInput').val();
      var height = $('#studyEmbedHeightInput').val();

      // Set default values if empty
      if (width === '') {
        width = '600px';
      } else {
        // Check if px or % is included
        if (!width.includes('px') && !width.includes('%')) {
          width += 'px';
        }
      }
      if (height === '') {
        height = '750px';
      } else {
        // Check if px or % is included
        if (!height.includes('px') && !height.includes('%')) {
          height += 'px';
        }
      }

      // Add link into iframe code (code will then be copied)
      distributionLinkEmbed = `<iframe style="border: none;margin: 0 auto; display: block; width: 100%; max-width: ${width}; height: ${height};" src="${distributionLinkEmbed}"></iframe>`;

      // Update the distribution link input field
      $('#studyEmbedInput').val(distributionLinkEmbed);
    }

    // TinyMCE initialization + Coloris initialization
    // =========================================================================
    // DOCUMENT READY - MAIN INITIALIZATION
    // =========================================================================
    
    $(document).ready(function() {
      // Initialize TinyMCE for the GPT instructions and participant instructions text areas
      $('#gptInstructionsInput').tinymce({
        height: 300,
        menubar: false,
        license_key: 'gpl',
        plugins: [
          'advlist', 'autolink',
          'lists', 'link', 'image', 'charmap', 'preview', 'anchor', 'searchreplace', 'visualblocks',
          'fullscreen', 'insertdatetime', 'table'
        ],
        toolbar: 'undo redo | bold italic | ' +
          'bullist numlist outdent indent | removeformat',
        // Only allow clean and semantic HTML
        valid_elements: 'strong/b,em/i,u,ul,ol,li,p,blockquote',

        // No spans or inline styles
        extended_valid_elements: '',
        valid_styles: {},

        // Clean up paste
        paste_remove_styles: true,
        paste_remove_spans: true,
        paste_strip_class_attributes: 'all',

        // Optional cleanup for empty tags
        paste_preprocess: function(plugin, args) {
          args.content = args.content.replace(/<[^\/>][^>]*>\s*<\/[^>]+>/g, '');
        },
        setup: (editor) => {
          editor.on('change', (e) => {
            console.log("Saving changes");
            // Update the instructions for the active condition
            conditionsGptInstructions[currentlyActiveGPTInstructionsCondition].aiInstructions = editor.getContent();

            // Save changes
            saveChanges('aiInstructions', JSON.stringify(conditionsGptInstructions), false, $("#gptInstructionsTitle"));
          });
          editor.on('init', function(e) {
            // Get GPT instructions from array after checking it exists at that index
            if (conditionsGptInstructions[currentlyActiveGPTInstructionsCondition]) {
              editor.setContent(conditionsGptInstructions[currentlyActiveGPTInstructionsCondition].aiInstructions, {
                format: 'html'
              });
            } else {
              editor.setContent("", {
                format: 'html'
              });
            }
          });
          editor.on('paste cut', function() {
            // Set 100ms delay
            setTimeout(function() {
              //Set the value in the conditionsGptInstructions array
              conditionsGptInstructions[currentlyActiveGPTInstructionsCondition].aiInstructions = editor.getContent();
              // Save changes
              saveChanges('aiInstructions', JSON.stringify(conditionsGptInstructions), false, $("#gptInstructionsTitle"));
            }, 100);
          });
          editor.on('keydown', (e) => {
            // Direct report (some browsers send key='{')
            if (e.key === '{') {
              editor.insertContent('{');
              e.preventDefault();
            }
            if (e.key === '}') {
              editor.insertContent('}');
              e.preventDefault();
            }

            // German Mac layout: Option+8 / Option+9
            if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey && e.key === '8') {
              editor.insertContent('{');
              e.preventDefault();
            }
            if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey && e.key === '9') {
              editor.insertContent('}');
              e.preventDefault();
            }

            // Extra: US layout path: Shift + [ / ]
            if (e.shiftKey && e.key === '[') {
              editor.insertContent('{');
              e.preventDefault();
            }
            if (e.shiftKey && e.key === ']') {
              editor.insertContent('}');
              e.preventDefault();
            }
          });
        }
      });

      $('#participantInstructionsTextInput').tinymce({
        height: 300,
        menubar: false,
        license_key: 'gpl',
        readonly: false, //<?php echo ($study["hideInstructionsWindow"] == 1) ? "true" : "false"; ?>,
        plugins: [
          'advlist', 'autolink',
          'lists', 'link', 'image', 'charmap', 'preview', 'anchor', 'searchreplace', 'visualblocks',
          'fullscreen', 'insertdatetime', 'table'
        ],
        toolbar: 'undo redo | blocks | bold italic backcolor | ' +
          'alignleft aligncenter alignright alignjustify | ' +
          'bullist numlist outdent indent | removeformat',
        // Only allow clean and semantic HTML
        valid_elements: 'strong/b,em/i,u,ul,ol,li,p,blockquote',

        // No spans or inline styles
        extended_valid_elements: '',
        valid_styles: {},

        // Clean up paste
        paste_remove_styles: true,
        paste_remove_spans: true,
        paste_strip_class_attributes: 'all',

        // Optional cleanup for empty tags
        paste_preprocess: function(plugin, args) {
          args.content = args.content.replace(/<[^\/>][^>]*>\s*<\/[^>]+>/g, '');
        },
        setup: (editor) => {
          editor.on('change', (e) => {
            // Update the instructions for the active condition
            conditionsParticipantInstructions[currentlyActiveParticipantInstructionsCondition].participantInstructions = editor.getContent();

            // Save changes
            saveChanges('participantInstructions', JSON.stringify(conditionsParticipantInstructions), false, $("#participantInstructionsTitle"));
          });
          editor.on('init', function(e) {
            // Get participant instructions from array after checking it exists at that index
            if (conditionsParticipantInstructions[currentlyActiveParticipantInstructionsCondition]) {
              editor.setContent(conditionsParticipantInstructions[currentlyActiveParticipantInstructionsCondition].participantInstructions, {
                format: 'html'
              });
            } else {
              editor.setContent("", {
                format: 'html'
              });
            }
          });
          editor.on('paste cut', function() {
            // Set 100ms delay
            setTimeout(function() {
              //Set the value in the conditionsParticipantInstructions array
              conditionsParticipantInstructions[currentlyActiveParticipantInstructionsCondition].participantInstructions = editor.getContent();
              // Save changes
              saveChanges('participantInstructions', JSON.stringify(conditionsParticipantInstructions), false, $("#participantInstructionsTitle"));
            }, 100);
          });
          editor.on('keydown', (e) => {
            // Direct report (some browsers send key='{')
            if (e.key === '{') {
              editor.insertContent('{');
              e.preventDefault();
            }
            if (e.key === '}') {
              editor.insertContent('}');
              e.preventDefault();
            }

            // German Mac layout: Option+8 / Option+9
            if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey && e.key === '8') {
              editor.insertContent('{');
              e.preventDefault();
            }
            if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey && e.key === '9') {
              editor.insertContent('}');
              e.preventDefault();
            }

            // Extra: US layout path: Shift + [ / ]
            if (e.shiftKey && e.key === '[') {
              editor.insertContent('{');
              e.preventDefault();
            }
            if (e.shiftKey && e.key === ']') {
              editor.insertContent('}');
              e.preventDefault();
            }
          });
        }
      });

      // Configure Coloris color picker behavior
      Coloris({
        el: '.coloris',
        swatches: [
          "#ffffff",
          "#dfe6e9",
          "#b2bec3",
          "#636e72",
          "#2d3436",
          "#000000",
          "#ffeaa7",
          "#fdcb6e",
          "#e17055",
          "#d63031",
          "#e84393",
          "#fd79a8",
          "#fab1a0",
          "#55efc4",
          "#00b894",
          "#00cec9",
          "#81ecec",
          "#74b9ff",
          "#0984e3",
          "#6c5ce7",
          "#a29bfe"
        ]
      });

      // =================================================================
      // Custom Connector Template Wizard
      // =================================================================

      var activeTemplate = null;

      // "Choose" button — fetch template JSON, build wizard, open modal
      $('.js-choose-connector-tpl').on('click', function() {
        var filename = $(this).data('template');
        var $btn = $(this);
        $btn.addClass('is-loading');

        $.getJSON('customConnectorTemplates/' + filename + '?v=' + Date.now())
          .done(function(tpl) {
            activeTemplate = tpl;

            $('#connectorWizardTitle').text(tpl.name);
            $('#connectorWizardDescription').text(tpl.description || '');

            // Build form fields
            var $container = $('#connectorWizardFields').empty();
            (tpl.fields || []).forEach(function(field) {
              var $field = $('<div class="field mb-4"></div>');
              $field.append('<label class="label has-text-left">' +
                $('<span>').text(field.label).html() + '</label>');

              if (field.type === 'select') {
                var $select = $('<select class="input" data-field-key="' + field.key + '"></select>');
                (field.options || []).forEach(function(opt) {
                  var $opt = $('<option></option>').val(opt.value).text(opt.label);
                  if (opt.value === field['default']) $opt.attr('selected', true);
                  $select.append($opt);
                });
                $field.append($('<div class="control"></div>').append(
                  $('<div class="select is-fullwidth"></div>').append($select)
                ));
              } else {
                var $input = $('<input class="input" data-field-key="' + field.key + '">')
                  .attr('type', field.inputType || 'text')
                  .attr('placeholder', field.placeholder || '');
                if (field['default']) $input.val(field['default']);
                $field.append($('<div class="control"></div>').append($input));
              }
              $container.append($field);
            });

            openModal(document.getElementById('connectorWizardModal'));
          })
          .fail(function() {
            alert('Failed to load template. Please try again.');
          })
          .always(function() {
            $btn.removeClass('is-loading');
          });
      });

      // "Apply template" handler
      $('#connectorWizardApply').on('click', function() {
        if (!activeTemplate) return;

        // Collect field values
        var values = {};
        var missing = [];
        $('#connectorWizardFields [data-field-key]').each(function() {
          var key = $(this).data('field-key');
          var val = $(this).val();
          if (!val && $(this).is('input')) missing.push(key);
          values[key] = val;
        });
        if (missing.length) {
          alert('Please fill in all fields before applying.');
          return;
        }

        // Replace {{placeholders}} in the connector JSON
        var json = JSON.stringify(activeTemplate.connector);
        Object.keys(values).forEach(function(key) {
          // Handle {{key:int}} for numeric values (unquoted)
          json = json.split('"{{' + key + ':int}}"').join(values[key]);
          json = json.split('{{' + key + '}}').join(values[key]);
        });

        // Pretty-print and fill into textarea
        try {
          json = JSON.stringify(JSON.parse(json), null, 2);
        } catch(e) { /* use as-is if parse fails */ }

        $('#customConfigInput').val(json).trigger('change');

        // Auto-toggle streaming checkbox
        var $streamCb = $('input[fieldKey="customConnectorEnableStreaming"]');
        if (activeTemplate.requiresStreaming && !$streamCb.is(':checked')) {
          $streamCb.prop('checked', true).trigger('change');
        } else if (!activeTemplate.requiresStreaming && $streamCb.is(':checked')) {
          $streamCb.prop('checked', false).trigger('change');
        }

        closeAllModals();
      });

    });
  </script>
</body>

</html>