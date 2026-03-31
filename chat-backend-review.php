<?php
/**
 * chat-backend-review.php
 *
 * Study data review interface showing messages, submissions, and files.
 * Provides download and deletion capabilities with authorization checks.
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
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://code.jquery.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// =============================================================================
// AUTHENTICATION CHECK
// =============================================================================

if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
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
// VALIDATE INPUT AND AUTHORIZATION
// =============================================================================

$userID = (int)$_SESSION['userID'];

$database->update('users', [
    'userLastActiveDate' => date('Y-m-d H:i:s')
], [
    'userID' => $userID
]);

if (!isset($_GET['studyID'])) {
    header('Location: index.php');
    exit;
}

$studyID = (int)$_GET['studyID'];

if ($studyID <= 0) {
    header('Location: index.php');
    exit;
}

$user = $database->get("users", "*", ["userID" => $userID]);

if (!$user) {
    session_destroy();
    header('Location: login.php');
    exit;
}

$study = $database->get("studies", "*", ["studyID" => $studyID]);

// CRITICAL: Verify user owns this study
if (!$study) {
    header('Location: access-denied.php');
    exit;
}

$studyOwnerID = (int)$study["studyOwner"];

if ($studyOwnerID !== $userID) {
    error_log("Authorization violation: User $userID attempted to access study $studyID owned by $studyOwnerID");
    header('Location: access-denied.php');
    exit;
}

// Check if the study owner has a public key (determines if legacy NA messages are encrypted)
$ownerHasPublicKey = (bool) $database->get('users', 'publicKey', ['userID' => $studyOwnerID]);

// =============================================================================
// FETCH STATISTICS
// =============================================================================

$numberMessages = $database->count("messages", [
    "studyID" => $studyID,
    "senderType" => "Participant"
]);

$numberAllMessages = $database->count("messages", [
    "studyID" => $studyID
]);

$messages = $database->select("messages", "*", [
    "studyID" => $studyID,
    "senderType" => "Participant"
]);
$numberParticipants = count(array_unique(array_column($messages, 'participantID')));

$numberSubmissions = $database->count("submissions", [
    "studyID" => $studyID
]);

$numberFiles = $database->count('files', [
    'studyID' => $studyID,
    'deleted' => 0
]);

$oldestFileDate = $database->min('files', 'uploadedAt', [
    'studyID' => $studyID,
    'deleted' => 0
]);

$daysUntilDeletion = 0;
if ($oldestFileDate) {
    $deletionDate = (new DateTime($oldestFileDate))->modify('+30 days');
    $now = new DateTime();
    $interval = $now->diff($deletionDate);
    $daysUntilDeletion = max(0, (int)$interval->format('%a'));
}

// =============================================================================
// PAGINATION SETUP
// =============================================================================

$itemsPerPage = 100;

$messagesPage = isset($_GET['messagesPage']) ? max(1, (int)$_GET['messagesPage']) : 1;
$messagesOffset = ($messagesPage - 1) * $itemsPerPage;
$totalMessagePages = (int)ceil($numberAllMessages / $itemsPerPage);

$submissionsPage = isset($_GET['submissionsPage']) ? max(1, (int)$_GET['submissionsPage']) : 1;
$submissionsOffset = ($submissionsPage - 1) * $itemsPerPage;
$totalSubmissionPages = (int)ceil($numberSubmissions / $itemsPerPage);

$activeTab = isset($_GET['submissionsPage']) ? 'submissions' : 'messages';

// =============================================================================
// ESCAPE OUTPUT VARIABLES FOR XSS PROTECTION
// =============================================================================

$displayStudyName = htmlspecialchars($study["studyName"], ENT_QUOTES, 'UTF-8');
$user["userName"] = decryptString($user["userName"] ?? '');
$user["userSurname"] = decryptString($user["userSurname"] ?? '');
$displayUserName = htmlspecialchars($user["userName"], ENT_QUOTES, 'UTF-8');
$displayUserSurname = htmlspecialchars($user["userSurname"], ENT_QUOTES, 'UTF-8');
$displayFullName = $displayUserName . ' ' . $displayUserSurname;
$safeStudyCode = htmlspecialchars($study["studyCode"], ENT_QUOTES, 'UTF-8');
$safeCsrfToken = htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8');
?>

<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>View data</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
    <!--FontAwesome-->
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/solid.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/light.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/regular.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/brands.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/fontawesome.min.css">
    <!--IziToast-->
    <link rel="stylesheet" href="src/CSS/iziToast.min.css">
</head>

<body>
    <!-- Navbar START-->
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

        <a class="navbar-item" href="https://about.researchchatai.com/documentation/">
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
                    <a class="button is-info is-light is-fullwidth"
                        href="chat-backend-create.php?studyID=<?php echo $studyID; ?>">
                        <span class="icon is-small">
                            <i class="fa fa-tasks"></i>
                        </span>
                        <span>Edit study</span>
                    </a>
                </div>
                <div class="column">
                    <a class="button is-info is-light is-fullwidth"
                        href="chat-backend-review.php?studyID=<?php echo $studyID; ?>">
                        <span class="icon is-small">
                            <i class="fa fa-table"></i>
                        </span>
                        <span>View data</span>
                    </a>
                </div>
                <div class="column">
                    <button class="button is-warning is-light js-modal-trigger is-fullwidth"
                        data-target="renameStudyModal">
                        <span class="icon is-small">
                            <i class="fa fa-pencil"></i>
                        </span>
                        <span>Rename study</span>
                    </button>
                </div>
                <div class="column">
                    <button class="button is-danger is-light js-modal-trigger is-fullwidth"
                        data-target="deleteStudyModal">
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

    <div class="tabs is-centered is-boxed" style="max-width: 760px; margin: 0 auto; margin-top: 48px;">
        <ul>
            <li class="<?php echo $activeTab==='messages'?'is-active':'';?>" id="messagesTab">
                <a href="?studyID=<?php echo $studyID;?>#messagesTab">
                    <span class="icon is-small"><i class="fa fa-comment"></i></span>
                    <span>Messages</span>
                </a>
            </li>
            <li class="<?php echo $activeTab==='submissions'?'is-active':'';?>" id="submissionsTab">
                <a href="?studyID=<?php echo $studyID;?>&submissionsPage=1#submissionsTab">
                    <span class="icon is-small"><i class="fa fa-lightbulb"></i></span>
                    <span>Submissions</span>
                </a>
            </li>
        </ul>
    </div>

    <!------------------>
    <!--Messages START-->
    <!------------------>

    <div id="messageDataContainer" <?php echo $activeTab === 'messages' ? '' : 'style="display:none;"'; ?>>
        <div class="container mt-5" style="max-width: 760px; margin-top: 48px;">
            <section class="section has-background-info-light">
                <p class="title is-3">View messages.</p>
                <p>
                    Below you can see all messages sent to and by the AI. Messages sent by participants have a blue
                    backround. You can filter the messages by participant number and message type. You can export the
                    data
                    to a CSV-file by clicking the "Export data"-button. To see the submissions provided by participants,
                    click
                    on the "Submissions"-tab above.
                </p>
                </p>

            </section>
        </div>
        <?php if ($numberFiles > 0): ?>
        <div class="container mt-5" style="max-width: 760px;">
            <div class="notification is-danger is-light has-text-centered mb-4">
                <b>Important notice.</b> Files uploaded to this study are only saved for 30 days and will be deleted afterwards. Please make sure to download them before.<br>
                <b>The first files will be deleted in <?php echo $daysUntilDeletion; ?> days.</b>
            </div>
        </div>
        <?php endif; ?>

        <section class="section">
            <!--Table Action Buttons START-->
            <div class="has-text-right mb-4">
                <!-- Add Download full CSV trigger for Messages -->
                <button class="button is-info is-light mr-2 js-modal-trigger" data-target="downloadFullCSVModalMessages">
                    <span class="icon is-small"><i class="fa fa-download"></i></span>
                    <span>Download full CSV</span>
                </button>
                <!--Download files button-->
                <button id="downloadFilesButton" class="button is-info is-light mr-2" <?php echo $numberFiles ? '' : 'disabled'; ?>>
                    <span class="icon is-small"><i class="fa fa-file-archive"></i></span>
                    <span>Download files</span>
                </button>
                <!--Filter button-->
                <button id="filterButton" class="button is-warning is-light mr-2 js-modal-trigger"
                    data-target="filterModalMessages">
                    <span class="icon is-small">
                        <i class="fa fa-filter"></i>
                    </span>
                    <span>Filter</span>
                </button>
                 <!--Delete files button-->
                <button id="deleteFilesButtonTrigger" class="button is-danger is-light mr-2 js-modal-trigger" data-target="deleteFilesModal" <?php echo $numberFiles ? '' : 'disabled'; ?>>
                    <span class="icon is-small"><i class="fa fa-trash"></i></span>
                    <span>Delete files</span>
                </button>
                <!--emptyTableButton-->
                <button class="button is-danger is-light js-modal-trigger" data-target="deleteMessagesModal">
                    <span class="icon is-small">
                        <i class="fa fa-trash"></i>
                    </span>
                    <span>Delete all messages</span>
                </button>
            </div>
            <!--Table Action Buttons END-->

            <!--Output Tabel START-->
            <?php
            // get paginated messages (newest first)
            $messages = $database->select(
                "messages",
                "*",
                [
                    "studyID" => $studyID,
                    "ORDER"   => ["messageID" => "DESC"],
                    "LIMIT"   => [$messagesOffset, $itemsPerPage]
                ]
            );
// Decryption now happens client-side in the browser using forge.js
// The private key is in sessionStorage (derived during login)
            ?>


            <?php if (count($messages) <= 0): ?>

                <div class="columns" id="uploadNoAttributesAddedYet">
                    <div class="column pt-2">
                        <div class="has-background-warning-light has-text-centered p-3">
                            No data yet.
                        </div>
                    </div>
                </div>

            <?php else: ?>

                <div class="has-background-warning-light mt-5 mb-3" style="max-height: 50px; padding: 12px;display: none;"
                    id="filterWarningMessages">
                    <p class="has-text-centered">
                        <i class="fa fa-filter"></i>
                        Filters are currently applied! <a href="#" id="resetFilterMessages">Reset</a>
                    </p>
                </div>
                <?php
                /* -------- top‑of‑table pagination & range indicator (Messages) -------- */
                // calculate the current slice
                $currentStart = $messagesOffset + 1;
                $currentEnd   = min($messagesOffset + $itemsPerPage, $numberAllMessages);

                // sliding window for page buttons
                $maxButtons = 10;
                $half       = floor($maxButtons / 2);
                $startPage  = max(1, $messagesPage - $half);
                $endPage    = min($totalMessagePages, $startPage + $maxButtons - 1);
                if ($endPage - $startPage + 1 < $maxButtons) {
                    $startPage = max(1, $endPage - $maxButtons + 1);
                }
                ?>
                <nav class="pagination is-centered mb-1" role="navigation" aria-label="pagination">
                    <?php if ($messagesPage > 1): ?>
                        <a class="pagination-previous" href="?studyID=<?php echo $studyID; ?>&messagesPage=<?php echo $messagesPage - 1; ?>#messagesTab">Previous</a>
                    <?php else: ?>
                        <a class="pagination-previous" disabled>Previous</a>
                    <?php endif; ?>

                    <?php if ($messagesPage < $totalMessagePages): ?>
                        <a class="pagination-next" href="?studyID=<?php echo $studyID; ?>&messagesPage=<?php echo $messagesPage + 1; ?>#messagesTab">Next</a>
                    <?php else: ?>
                        <a class="pagination-next" disabled>Next</a>
                    <?php endif; ?>

                    <ul class="pagination-list">
                        <?php
                        // first page + leading ellipsis
                        if ($startPage > 1) {
                            echo '<li><a class="pagination-link" href="?studyID=' . $studyID . '&messagesPage=1#messagesTab">1</a></li>';
                            if ($startPage > 2) {
                                echo '<li><span class="pagination-ellipsis">&hellip;</span></li>';
                            }
                        }

                        // window
                        for ($i = $startPage; $i <= $endPage; $i++) {
                            if ($i === $messagesPage) {
                                echo '<li><a class="pagination-link is-current" aria-current="page">' . $i . '</a></li>';
                            } else {
                                echo '<li><a class="pagination-link" href="?studyID=' . $studyID . '&messagesPage=' . $i . '#messagesTab">' . $i . '</a></li>';
                            }
                        }

                        // trailing ellipsis + last page
                        if ($endPage < $totalMessagePages) {
                            if ($endPage < $totalMessagePages - 1) {
                                echo '<li><span class="pagination-ellipsis">&hellip;</span></li>';
                            }
                            echo '<li><a class="pagination-link" href="?studyID=' . $studyID . '&messagesPage=' . $totalMessagePages . '#messagesTab">' . $totalMessagePages . '</a></li>';
                        }
                        ?>
                    </ul>
                </nav>
                <p class="has-text-right mb-4">Showing <?php echo $currentStart; ?>–<?php echo $currentEnd; ?> of <?php echo $numberAllMessages; ?> messages</p>

                <?php
                $table  = "<table class='table is-fullwidth is-bordered is-hoverable' id='messagesTable'>";
                $table .= "<thead><tr>
                                <th>MessageID</th>
                                <th>ParticipantID</th>
                                <th>Condition</th>
                                <th>Message</th>
                                <th>Date Time</th>
                                <th>Sender</th>
                                <th>Passed variables</th>
                                </tr></thead><tbody>";

                foreach ($messages as $message) {
                    // Escape all output for XSS protection - handle null values
                    $messageID = htmlspecialchars((string)($message['messageID'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $participantID = htmlspecialchars($message['participantID'] ?? '', ENT_QUOTES, 'UTF-8');
                    $condition = htmlspecialchars($message['condition'] ?? '', ENT_QUOTES, 'UTF-8');
                    $messageDateTime = htmlspecialchars($message['messageDateTime'] ?? '', ENT_QUOTES, 'UTF-8');
                    $senderType = htmlspecialchars($message['senderType'] ?? '', ENT_QUOTES, 'UTF-8');

                    $encType = $message['encryptionType'] ?? 'NA';
                    $msgText = $message['messageText'] ?? '';
                    $varsText = $message['passedVariables'] ?? '';

                    // Determine if row is encrypted based on encryptionType column and study settings
                    // e2e/server → encrypted; NA + owner has public key → legacy server-encrypted; NA + no key → plaintext
                    $isEncryptedRow = ($encType === 'e2e' || $encType === 'server' || ($encType === 'NA' && $ownerHasPublicKey));

                    if ($isEncryptedRow && !empty($msgText)) {
                        $encMsg = htmlspecialchars($msgText, ENT_QUOTES, 'UTF-8');
                        $msgTd = "<td class='encrypted-cell' data-enc=\"{$encMsg}\"><i class='fa fa-lock'></i> Encrypted</td>";
                    } else {
                        $msgTd = "<td>" . htmlspecialchars($msgText, ENT_QUOTES, 'UTF-8') . "</td>";
                    }

                    if ($isEncryptedRow && !empty($varsText)) {
                        $encVars = htmlspecialchars($varsText, ENT_QUOTES, 'UTF-8');
                        $varsTd = "<td class='encrypted-vars-cell' data-enc-vars=\"{$encVars}\"><i class='fa fa-lock'></i> Encrypted</td>";
                    } else {
                        $varsTd = "<td>" . htmlspecialchars($varsText, ENT_QUOTES, 'UTF-8') . "</td>";
                    }

                    // Lock icon with tooltip next to MessageID for encrypted rows
                    $encLock = '';
                    if ($encType === 'e2e') {
                        $encLock = ' <i class="fa fa-lock" title="End-to-end encrypted" style="color:#3273dc;cursor:help;"></i>';
                    } elseif ($encType === 'server' || ($encType === 'NA' && $ownerHasPublicKey)) {
                        $encLock = ' <i class="fa fa-lock" title="Server-side encrypted" style="color:#3273dc;cursor:help;"></i>';
                    }

                    $rowClass = ($message['senderType'] ?? '') === 'Participant' ? " class='has-background-info-light'" : '';
                    $table   .= "<tr{$rowClass}>
                                    <td>{$messageID}{$encLock}</td>
                                    <td>{$participantID}</td>
                                    <td>{$condition}</td>
                                    {$msgTd}
                                    <td>{$messageDateTime}</td>
                                    <td>{$senderType}</td>
                                    {$varsTd}
                                 </tr>";
                }

                $table .= "</tbody></table>";
                echo $table;
                ?>
                <!--Download full CSV modal Messages START-->
                <div class="modal" id="downloadFullCSVModalMessages">
                    <div class="modal-background"></div>
                    <div class="modal-card">
                        <header class="modal-card-head">
                            <p class="modal-card-title">Download full CSV</p>
                            <button class="delete" aria-label="close"></button>
                        </header>
                        <section class="modal-card-body">
                            <!-- Separator choice -->
                            <div class="field">
                                <label class="label">Separator</label>
                                <div class="control">
                                    <label class="radio">
                                        <input type="radio" name="csvSepMessages" value="comma" checked> Comma (,)
                                    </label>
                                    <label class="radio">
                                        <input type="radio" name="csvSepMessages" value="semicolon"> Semicolon (;)
                                    </label>
                                </div>
                            </div>
                            You're about to download the complete messages dataset (all <?php echo $numberAllMessages; ?> rows). This may take a while.
                        </section>
                        <footer class="modal-card-foot">
                            <button class="button is-success" id="confirmDownloadFullCSVButtonMessages">Download</button>
                            <button class="button cancel">Cancel</button>
                        </footer>
                    </div>
                </div>
                <!--Download full CSV modal Messages END-->
            <?php endif; ?>
            <!--Output Tabel END-->
        </section>
    </div>

    <!---------------->
    <!--Messages END-->
    <!---------------->

    <!------------------->
    <!--Submissions START-->
    <!------------------->

    <div id="submissionDataContainer" <?php echo $activeTab === 'submissions' ? '' : 'style="display:none;"'; ?>>
        <div class="container mt-5" style="max-width: 760px; margin-top: 48px;">
            <section class="section has-background-info-light">
                <p class="title is-3">View submissions.</p>
                <p>
                    Below you can see all submissions provided by participants. You can filter the submissions by
                    participant
                    number and message type. You can export the data to a CSV-file by clicking the "Export data"-button.
                    To see the messages sent to and by the AI, click on the "Messages"-tab above.
                </p>
                </p>
            </section>
        </div>
        <section class="section">
            <!--Table Action Buttons START-->
            <div class="has-text-right mb-4">
                <!-- Full CSV modal trigger for Submissions -->
                <button class="button is-info is-light mr-2 js-modal-trigger" data-target="downloadFullCSVModalSubmissions">
                    <span class="icon is-small"><i class="fa fa-download"></i></span>
                    <span>Download full CSV</span>
                </button>
                <!--Filter Button-->
                <button id="filterButtonSubmissions" class="button is-warning is-light mr-2 js-modal-trigger"
                    data-target="filterModalSubmissions">
                    <span class="icon is-small">
                        <i class="fa fa-filter"></i>
                    </span>
                    <span>Filter</span>
                </button>
                <!--Empty Table Button-->
                <button class="button is-danger is-light ml-2 js-modal-trigger" data-target="deleteSubmissionsModal">
                    <span class="icon is-small">
                        <i class="fa fa-trash"></i>
                    </span>
                    <span>Delete all submissions</span>
                </button>
            </div>
            <!--Table Action Buttons END-->

            <!--Filter Warning START-->
            <div class="has-background-warning-light mt-5 mb-3" style="max-height: 50px; padding: 12px; display: none;"
                id="filterWarningSubmissions">
                <p class="has-text-centered">
                    <i class="fa fa-filter"></i>
                    Filters are currently applied! <a href="#" id="resetFilterSubmissions">Reset</a>
                </p>
            </div>
            <!--Filter Warning END-->

            <!--Submissions Table START-->
            <?php
            // get paginated submissions (newest first)
            $submissions = $database->select(
                "submissions",
                "*",
                [
                    "studyID" => $studyID,
                    "ORDER"   => ["submissionID" => "DESC"],
                    "LIMIT"   => [$submissionsOffset, $itemsPerPage]
                ]
            );
            // Submission decryption happens client-side (same as messages)
            ?>

            <?php if (count($submissions) <= 0): ?>

                <div class="columns" id="uploadNoAttributesAddedYet">
                    <div class="column pt-2">
                        <div class="has-background-warning-light has-text-centered p-3">
                            No data yet.
                        </div>
                    </div>
                </div>

            <?php else: ?>
                <?php
                $currentStartSub = $submissionsOffset + 1;
                $currentEndSub   = min($submissionsOffset + $itemsPerPage, $numberSubmissions);

                $maxButtonsSub = 10;
                $halfSub       = floor($maxButtonsSub / 2);
                $startPageSub  = max(1, $submissionsPage - $halfSub);
                $endPageSub    = min($totalSubmissionPages, $startPageSub + $maxButtonsSub - 1);
                if ($endPageSub - $startPageSub + 1 < $maxButtonsSub) {
                    $startPageSub = max(1, $endPageSub - $maxButtonsSub + 1);
                }
                ?>
                <nav class="pagination is-centered mb-1" role="navigation" aria-label="pagination">
                    <?php if ($submissionsPage > 1): ?>
                        <a class="pagination-previous" href="?studyID=<?php echo $studyID; ?>&submissionsPage=<?php echo $submissionsPage - 1; ?>#submissionsTab">Previous</a>
                    <?php else: ?>
                        <a class="pagination-previous" disabled>Previous</a>
                    <?php endif; ?>

                    <?php if ($submissionsPage < $totalSubmissionPages): ?>
                        <a class="pagination-next" href="?studyID=<?php echo $studyID; ?>&submissionsPage=<?php echo $submissionsPage + 1; ?>#submissionsTab">Next</a>
                    <?php else: ?>
                        <a class="pagination-next" disabled>Next</a>
                    <?php endif; ?>

                    <ul class="pagination-list">
                        <?php
                        if ($startPageSub > 1) {
                            echo '<li><a class="pagination-link" href="?studyID=' . $studyID . '&submissionsPage=1#submissionsTab">1</a></li>';
                            if ($startPageSub > 2) {
                                echo '<li><span class="pagination-ellipsis">&hellip;</span></li>';
                            }
                        }

                        for ($i = $startPageSub; $i <= $endPageSub; $i++) {
                            if ($i === $submissionsPage) {
                                echo '<li><a class="pagination-link is-current" aria-current="page">' . $i . '</a></li>';
                            } else {
                                echo '<li><a class="pagination-link" href="?studyID=' . $studyID . '&submissionsPage=' . $i . '#submissionsTab">' . $i . '</a></li>';
                            }
                        }

                        if ($endPageSub < $totalSubmissionPages) {
                            if ($endPageSub < $totalSubmissionPages - 1) {
                                echo '<li><span class="pagination-ellipsis">&hellip;</span></li>';
                            }
                            echo '<li><a class="pagination-link" href="?studyID=' . $studyID . '&submissionsPage=' . $totalSubmissionPages . '#submissionsTab">' . $totalSubmissionPages . '</a></li>';
                        }
                        ?>
                    </ul>
                </nav>
                <p class="has-text-right mb-4">Showing <?php echo $currentStartSub; ?>–<?php echo $currentEndSub; ?> of <?php echo $numberSubmissions; ?> submissions</p>

                <?php
                $table  = "<table class='table is-fullwidth is-bordered is-hoverable' id='submissionsTable'>";
                $table .= "<thead><tr>
                                <th>SubmissionID</th>
                                <th>ParticipantID</th>
                                <th>Condition</th>
                                <th>SubmissionText</th>
                                <th>SubmissionTime</th>
                                <th>StartTime</th>
                                <th>Duration</th>
                                <th>NumberMessages</th>
                                <th>PassedVariables</th>
                                </tr></thead><tbody>";

                foreach ($submissions as $submission) {
                    // Escape all output for XSS protection - handle null values
                    $submissionID = htmlspecialchars((string)($submission['submissionID'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $participantID = htmlspecialchars($submission['participantID'] ?? '', ENT_QUOTES, 'UTF-8');
                    $condition = htmlspecialchars($submission['condition'] ?? '', ENT_QUOTES, 'UTF-8');
                    $submissionTime = htmlspecialchars($submission['submissionTime'] ?? '', ENT_QUOTES, 'UTF-8');
                    $startTime = htmlspecialchars($submission['startTime'] ?? '', ENT_QUOTES, 'UTF-8');
                    $duration = htmlspecialchars((string)($submission['duration'] ?? ''), ENT_QUOTES, 'UTF-8');
                    $numberMessages = htmlspecialchars((string)($submission['numberMessages'] ?? ''), ENT_QUOTES, 'UTF-8');

                    $encType = $submission['encryptionType'] ?? 'NA';
                    $subText = $submission['submissionText'] ?? '';
                    $varsText = $submission['passedVariables'] ?? '';

                    // Determine if row is encrypted based on encryptionType column and study settings
                    $isEncryptedRow = ($encType === 'e2e' || $encType === 'server' || ($encType === 'NA' && $ownerHasPublicKey));

                    if ($isEncryptedRow && !empty($subText)) {
                        $encText = htmlspecialchars($subText, ENT_QUOTES, 'UTF-8');
                        $textTd = "<td class='encrypted-cell' data-enc=\"{$encText}\"><i class='fa fa-lock'></i> Encrypted</td>";
                    } else {
                        $textTd = "<td>" . htmlspecialchars($subText, ENT_QUOTES, 'UTF-8') . "</td>";
                    }

                    if ($isEncryptedRow && !empty($varsText)) {
                        $encVars = htmlspecialchars($varsText, ENT_QUOTES, 'UTF-8');
                        $varsTd = "<td class='encrypted-vars-cell' data-enc-vars=\"{$encVars}\"><i class='fa fa-lock'></i> Encrypted</td>";
                    } else {
                        $varsTd = "<td>" . htmlspecialchars($varsText, ENT_QUOTES, 'UTF-8') . "</td>";
                    }

                    // Lock icon with tooltip next to SubmissionID for encrypted rows
                    $encLock = '';
                    if ($encType === 'e2e') {
                        $encLock = ' <i class="fa fa-lock" title="End-to-end encrypted" style="color:#3273dc;cursor:help;"></i>';
                    } elseif ($encType === 'server' || ($encType === 'NA' && $ownerHasPublicKey)) {
                        $encLock = ' <i class="fa fa-lock" title="Server-side encrypted" style="color:#3273dc;cursor:help;"></i>';
                    }

                    $table .= "<tr>
                                   <td>{$submissionID}{$encLock}</td>
                                   <td>{$participantID}</td>
                                   <td>{$condition}</td>
                                   {$textTd}
                                   <td>{$submissionTime}</td>
                                   <td>{$startTime}</td>
                                   <td>{$duration}</td>
                                   <td>{$numberMessages}</td>
                                   {$varsTd}
                                 </tr>";
                }

                $table .= "</tbody></table>";
                echo $table;
                ?>
                <!--Download full CSV modal Submissions START-->
                <div class="modal" id="downloadFullCSVModalSubmissions">
                    <div class="modal-background"></div>
                    <div class="modal-card">
                        <header class="modal-card-head">
                            <p class="modal-card-title">Download full CSV</p>
                            <button class="delete" aria-label="close"></button>
                        </header>
                        <section class="modal-card-body">
                            <div class="field">
                                <label class="label">Separator</label>
                                <div class="control">
                                    <label class="radio">
                                    <input type="radio" name="csvSepSubmissions" value="comma" checked> Comma (,)
                                    </label>
                                    <label class="radio">
                                    <input type="radio" name="csvSepSubmissions" value="semicolon"> Semicolon (;)
                                    </label>
                                </div>
                            </div>
                            <div class="field">
                                <label class="checkbox">
                                    <input type="checkbox" id="stripHtmlSubmissions"> Remove HTML formatting
                                </label>
                            </div>
                            You're about to download the complete submissions dataset (all <?php echo $numberSubmissions; ?> rows). This may take a while.
                        </section>
                        <footer class="modal-card-foot">
                <button class="button is-success" id="confirmDownloadFullCSVButtonSubmissions">Download</button>
                            <button class="button cancel">Cancel</button>
                        </footer>
                    </div>
                </div>
                <!--Download full CSV modal Submissions END-->

            <?php endif; ?>
            <!--Submissions Table END-->
        </section>
    </div>

    <!----------------->
    <!--Submissions END-->
    <!----------------->

    <!-- Filter Modal Messages START -->
    <div id="filterModalMessages" class="modal">
        <div class="modal-background"></div>
        <div class="modal-card">
            <header class="modal-card-head">
                <p class="modal-card-title">Filter Messages</p>
                <button class="delete" aria-label="close"></button>
            </header>
            <section class="modal-card-body">
                <!-- Participant Filter START -->
                <div class="field">
                    <label class="label">Search Participant</label>
                    <div class="control">
                        <input id="participantSearchFilterModalMessages" class="input" type="text"
                            placeholder="Search participants">
                    </div>
                </div>

                <div class="field mt-5">
                    <label class="label" style="position: relative;">Select Participants
                        <button class="button is-danger is-light is-small" id="uncheckAllParticipantsButton"
                            style="position: absolute; right: 0px;">
                            <span>Uncheck all</span>
                        </button>
                    </label>
                    <div class="table-container" style="max-height: 200px; overflow-y: auto;">
                        <table class="table is-fullwidth is-bordered is-hoverable">
                            <thead>
                                <tr>
                                    <th>Participant</th>
                                    <th>Messages Sent</th>
                                    <th>Select</th>
                                </tr>
                            </thead>
                            <tbody id="participantTableFilterModalMessages">
                                <!-- Filter Data based on the original table -->
                                <?php
                                $participants = array_unique(array_column($messages, 'participantID'));
                                foreach ($participants as $participant) {
                                    $numMessages = count(array_filter($messages, function ($message) use ($participant) {
                                        return $message['participantID'] == $participant;
                                    }));
                                    echo "<tr>";
                                    echo "<td>$participant</td>";
                                    echo "<td>$numMessages</td>";
                                    echo "<td><input type='checkbox' name='participantMessages' checked></td>";
                                    echo "</tr>";
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                <!-- Participant Filter END -->

                <!-- Message Type Filter START -->
                <div class="field mt-5">
                    <label class="label">
                        Select Message Type
                    </label>
                    <div class="control">
                        <label class="checkbox">
                            <input type="checkbox" name="messageType" value="aiMessages" checked> AI Messages
                        </label>
                    </div>
                    <div class="control">
                        <label class="checkbox">
                            <input type="checkbox" name="messageType" value="participantMessages" checked> Participant
                            Messages
                        </label>
                    </div>
                </div>
                <!-- Message Type Filter END -->
            </section>

            <footer class="modal-card-foot">
                <button class="button is-success" id="applyFilterButtonFilterModalMessages">Apply Filter</button>
                <button class="button is-warning" id="resetButtonFilterModalMessages">Reset</button>
                <button class="button close">Cancel</button>
            </footer>
        </div>
    </div>

    <!-- Filter Modal Submissions START -->
    <div id="filterModalSubmissions" class="modal">
        <div class="modal-background"></div>
        <div class="modal-card">
            <header class="modal-card-head">
                <p class="modal-card-title">Filter Submissions</p>
                <button class="delete" aria-label="close"></button>
            </header>
            <section class="modal-card-body">
                <!-- Participant Filter START -->
                <div class="field">
                    <label class="label">Search Participant</label>
                    <div class="control">
                        <input id="participantSearchFilterModalSubmissions" class="input" type="text"
                            placeholder="Search participants">
                    </div>
                </div>

                <div class="field mt-5">
                    <label class="label" style="position: relative;">Select Participants
                        <button class="button is-danger is-light is-small" id="uncheckAllParticipantsButtonSubmissions"
                            style="position: absolute; right: 0px;">
                            <span>Uncheck all</span>
                        </button>
                    </label>
                    <div class="table-container" style="max-height: 200px; overflow-y: auto;">
                        <table class="table is-fullwidth is-bordered is-hoverable">
                            <thead>
                                <tr>
                                    <th>Participant</th>
                                    <th>Select</th>
                                </tr>
                            </thead>
                            <tbody id="participantTableFilterModalSubmissions">
                                <?php
                                $participants = array_unique(array_column($submissions, 'participantID'));
                                foreach ($participants as $participant) {
                                    echo "<tr>";
                                    echo "<td>$participant</td>";
                                    echo "<td><input type='checkbox' name='participantSubmissions' checked></td>";
                                    echo "</tr>";
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                <!-- Participant Filter END -->
            </section>

            <footer class="modal-card-foot">
                <button class="button is-success" id="applyFilterButtonFilterModalSubmissions">Apply Filter</button>
                <button class="button is-warning" id="resetButtonFilterModalSubmissions">Reset</button>
                <button class="button close">Cancel</button>
            </footer>
        </div>
    </div>
        <!-- Filter Modal Submissions END -->
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
    <!--Delete messages modal START-->
    <div class="modal" id="deleteMessagesModal">
        <div class="modal-background"></div>
        <div class="modal-card">
            <header class="modal-card-head">
                <p class="modal-card-title">Delete data</p>
                <button class="delete" aria-label="close"></button>
            </header>
            <section class="modal-card-body">
                Are you sure that you want to delete all messages for this study? This cannot be undone.
            </section>
            <footer class="modal-card-foot">
                <div class="buttons">
                    <button class="button is-danger" id="deleteMessagesButton">Delete</button>
                    <button class="button cancel">Cancel</button>
                </div>
            </footer>
        </div>
    </div>
    <!--Delete messages modal END-->

    <!--Delete submissions modal START-->
    <div class="modal" id="deleteSubmissionsModal">
        <div class="modal-background"></div>
        <div class="modal-card">
            <header class="modal-card-head">
                <p class="modal-card-title">Delete data</p>
                <button class="delete" aria-label="close"></button>
            </header>
            <section class="modal-card-body">
                Are you sure that you want to delete all submissions for this study? This cannot be undone.
            </section>
            <footer class="modal-card-foot">
                <div class="buttons">
                    <button class="button is-danger" id="deleteSubmissionsButton">Delete</button>
                    <button class="button cancel">Cancel</button>
                </div>
            </footer>
        </div>
    </div>
    <!--Delete submissions modal END-->

    <!--Delete files modal START-->
    <div class="modal" id="deleteFilesModal">
        <div class="modal-background"></div>
        <div class="modal-card">
            <header class="modal-card-head">
                <p class="modal-card-title">Delete files</p>
                <button class="delete" aria-label="close"></button>
            </header>
            <section class="modal-card-body">
                Are you sure that you want to delete all uploaded images for this study? This cannot be undone.
            </section>
            <footer class="modal-card-foot">
                <div class="buttons">
                    <button class="button is-danger" id="deleteFilesButton">Delete</button>
                    <button class="button cancel">Cancel</button>
                </div>
            </footer>
        </div>
    </div>
    <!--Delete files modal END-->

    <!--jQuery-->
    <script type="text/javascript" src="src/JS/jquery-3.7.1.min.js"></script>
    <!--iziToast-->
    <script type="text/javascript" src="src/JS/iziToast.js"></script>
    <!--General JS-->
    <script type="text/javascript" src="src/JS/general.js?v=20260308"></script>
    <!--forge.js for client-side RSA decryption (PKCS1v1.5 + RSA-OAEP)-->
    <script src="https://cdn.jsdelivr.net/npm/node-forge@1.3.1/dist/forge.min.js"></script>
    <!--Basic Site Functionality-->
    <script type="text/javascript">
        // CSRF token and study data for JavaScript
        var csrfToken = '<?php echo $safeCsrfToken; ?>';
        var studyCode = '<?php echo $safeStudyCode; ?>';
        var studyID = <?php echo $studyID; ?>;

        $(document).ready(function() {
            ////////////////////////////////////////
            // General side functionality that applies to both tables
            ////////////////////////////////////////

            // Toggle tabs
            $('#messagesTab').click(function() {
                $('#messageDataContainer').show();
                $('#submissionDataContainer').hide();
                $('#messagesTab').addClass('is-active');
                $('#submissionsTab').removeClass('is-active');
            });
            $('#submissionsTab').click(function() {
                $('#messageDataContainer').hide();
                $('#submissionDataContainer').show();
                $('#messagesTab').removeClass('is-active');
                $('#submissionsTab').addClass('is-active');
            });

            // Listen for click on close buttons
            $('.delete, .close, .modal-background').click(function() {
                $(this).closest('.modal').removeClass('is-active');
            });

            // Listen for deleteMessagesButton click
            $('#deleteMessagesButton').click(function() {
                // Show loading indicator in button
                $('#deleteMessagesButton').addClass('is-loading');

                // Send request to delete all data
                $.ajax({
                    type: "POST",
                    url: "Backend/Studies/messages-delete-all.php",
                    data: {
                        studyCode: studyCode
                    },
                    success: function(response) {
                        // Reload page
                        location.reload();
                    },
                    error: function(data) {
                        // Remove loading indicator
                        $('#deleteMessagesButton').removeClass('is-loading');

                        // Output data
                        console.log(data);

                        // Show toast
                        iziToast.error({
                            title: 'Error',
                            message: 'An error occurred while deleting data.',
                            position: 'bottomRight'
                        });
                    }
                });
            });

            // Listen for deleteSubmissionsButton click
            $('#deleteSubmissionsButton').click(function() {
                // Show loading indicator in button
                $('#deleteSubmissionsButton').addClass('is-loading');

                // Send request to delete all data
                $.ajax({
                    type: "POST",
                    url: "Backend/Studies/submissions-delete-all.php",
                    data: {
                        studyCode: studyCode
                    },
                    success: function(response) {
                        // Reload page
                        location.reload();
                    },
                    error: function(data) {
                        // Remove loading indicator
                        $('#deleteSubmissionsButton').removeClass('is-loading');

                        // Output data
                        console.log(data);

                        // Show toast
                        iziToast.error({
                            title: 'Error',
                            message: 'An error occurred while deleting data.',
                            position: 'bottomRight'
                        });
                    }
                });
            });

            // Listen for deleteFilesButton click
            $('#deleteFilesButton').click(function() {
                $('#deleteFilesButton').addClass('is-loading');

                $.ajax({
                    type: "POST",
                    url: "Backend/Studies/files-delete-all.php",
                    data: {
                        csrf_token: csrfToken,
                        studyCode: studyCode
                    },
                    success: function(response) {
                        location.reload();
                    },
                    error: function(data) {
                        $('#deleteFilesButton').removeClass('is-loading');
                        console.log(data);
                        iziToast.error({
                            title: 'Error',
                            message: 'An error occurred while deleting data.',
                            position: 'bottomRight'
                        });
                    }
                });
            });

        });

        // Format date (YYYY-MM-DD_HH:MM:SS)
        function getFormattedDate() {
            var date = new Date();
            var str = date.getFullYear() + "-" + (date.getMonth() + 1) + "-" + date.getDate() + "_" + date.getHours() + ":" + date.getMinutes() + ":" + date.getSeconds();

            return str;
        }

        // Function saving changes
        function saveChanges(fieldKey, fieldValue, noNotification) {
            // Save changes to Backend/Studies/study-update-field.php using ajax
            $.ajax({
                type: "POST",
                url: "Backend/Studies/study-update-field.php",

                data: {
                    csrf_token: csrfToken,
                    studyID: studyID,
                    fieldKey: fieldKey,
                    fieldValue: fieldValue
                },
                success: function(response) {
                    if (noNotification) {
                        return;
                    }

                    if (response.status == "good") {
                        iziToast.show({
                            title: 'Changes saved',
                            message: 'Your changes have successfully been saved',
                            color: 'green'
                        });
                    } else {
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
                    iziToast.show({
                        title: 'Error',
                        message: 'An error occurred while saving your changes',
                        color: 'red'
                    });
                }
            });
        }

        ////////////////////////////////////////
        // Client-side Decryption (forge.js)
        ////////////////////////////////////////

        var _studyIsEncrypted = <?php echo $ownerHasPublicKey ? 'true' : 'false'; ?>;

        /**
         * Decrypt a ciphertext string using the private key from sessionStorage.
         * Supports two formats:
         *   - Server-side (openssl_seal): base64(envKey):base64(iv):base64(sealed)
         *     Uses PKCS1v1.5 RSA + RC4 envelope (openssl_seal default)
         *   - E2E: e2e:base64(encKey):base64(iv):base64(data)
         *     Uses RSA-OAEP + AES-256-CBC
         *
         * @param {string} ciphertext The encrypted string
         * @param {forge.pki.privateKey} forgePrivateKey Parsed forge private key
         * @returns {string|null} Decrypted plaintext or null on failure
         */
        function decryptMessage(ciphertext, forgePrivateKey) {
            if (!ciphertext || !forgePrivateKey) return null;

            try {
                if (ciphertext.startsWith('e2e:')) {
                    // E2E format: e2e:base64(rsaEncAesKey):base64(iv):base64(aesCiphertext)
                    var parts = ciphertext.split(':');
                    if (parts.length !== 4) return null;

                    var encAesKey = forge.util.decode64(parts[1]);
                    var iv = forge.util.decode64(parts[2]);
                    var aesCiphertext = forge.util.decode64(parts[3]);

                    // RSA-OAEP decrypt the AES key (SHA-1 matches Web Crypto default)
                    var aesKey = forgePrivateKey.decrypt(encAesKey, 'RSA-OAEP', {
                        md: forge.md.sha1.create()
                    });

                    // AES-256-CBC decrypt the data
                    var decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
                    decipher.start({ iv: iv });
                    decipher.update(forge.util.createBuffer(aesCiphertext));
                    var ok = decipher.finish();
                    if (!ok) return null;

                    return decipher.output.toString('utf8');
                } else {
                    // Server-side format: base64(envKey):base64(iv):base64(sealedData)
                    // openssl_seal uses RC4 by default, but our code uses AES-256-CBC
                    var parts = ciphertext.split(':');
                    if (parts.length !== 3) return null;

                    var envKey = forge.util.decode64(parts[0]);
                    var iv = forge.util.decode64(parts[1]);
                    var sealedData = forge.util.decode64(parts[2]);

                    // RSA PKCS1v1.5 decrypt the envelope key
                    var aesKey = forgePrivateKey.decrypt(envKey, 'RSAES-PKCS1-V1_5');

                    // AES-256-CBC decrypt the data
                    var decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
                    decipher.start({ iv: iv });
                    decipher.update(forge.util.createBuffer(sealedData));
                    var ok = decipher.finish();
                    if (!ok) return null;

                    return decipher.output.toString('utf8');
                }
            } catch (e) {
                console.error('Decryption error:', e);
                return null;
            }
        }

        /**
         * Decrypt all .encrypted-cell and .encrypted-vars-cell elements on the page
         */
        function decryptAllCells(forgePrivateKey) {
            // Decrypt message/submission text cells
            document.querySelectorAll('.encrypted-cell').forEach(function(td) {
                var enc = td.getAttribute('data-enc');
                if (!enc) return;
                var plaintext = decryptMessage(enc, forgePrivateKey);
                if (plaintext !== null) {
                    td.textContent = plaintext;
                    td.classList.remove('encrypted-cell');
                }
            });

            // Decrypt passed variables cells
            document.querySelectorAll('.encrypted-vars-cell').forEach(function(td) {
                var enc = td.getAttribute('data-enc-vars');
                if (!enc) return;
                var plaintext = decryptMessage(enc, forgePrivateKey);
                if (plaintext !== null) {
                    td.textContent = plaintext;
                    td.classList.remove('encrypted-vars-cell');
                }
            });
        }

        // On page load: attempt to decrypt if study is encrypted
        var _forgePrivateKey = null;
        $(document).ready(function() {
            if (!_studyIsEncrypted) return;

            var pemKey = sessionStorage.getItem('privateKey');
            if (!pemKey) {
                // Show notice to log in again
                var notice = '<div class="notification is-warning mt-3 mb-3" style="max-width: 760px; margin: 0 auto;">'
                    + '<i class="fa fa-lock"></i> <b>Encrypted data.</b> Please log in again to view encrypted messages. '
                    + 'Your private key is needed to decrypt the data and is only available in the browser session where you logged in.'
                    + '</div>';
                $('#messageDataContainer .section:first').after(notice);
                $('#submissionDataContainer .section:first').after(notice);
                return;
            }

            try {
                _forgePrivateKey = forge.pki.privateKeyFromPem(pemKey);
                decryptAllCells(_forgePrivateKey);
            } catch (e) {
                console.error('Failed to parse private key:', e);
            }
        });

        ////////////////////////////////////////
        // CSV Download Logic (client-side decryption)
        ////////////////////////////////////////

        /**
         * Escape a value for CSV (RFC 4180)
         */
        function csvEscape(val, sep) {
            if (val === null || val === undefined) val = '';
            val = String(val);
            if (val.indexOf(sep) !== -1 || val.indexOf('"') !== -1 || val.indexOf('\n') !== -1 || val.indexOf('\r') !== -1) {
                return '"' + val.replace(/"/g, '""') + '"';
            }
            return val;
        }

        /**
         * Build CSV string from JSON rows, decrypting encrypted fields
         */
        function buildCsvFromJson(rows, columns, encryptedFields, sep, stripHtml, forgeKey) {
            var lines = [];
            // BOM + header
            lines.push(columns.map(function(c) { return csvEscape(c, sep); }).join(sep));

            rows.forEach(function(row) {
                var line = columns.map(function(col) {
                    var val = row[col] ?? '';
                    // Decrypt if this is an encrypted field based on encryptionType
                    var encType = row['encryptionType'] || 'NA';
                    var isEncrypted = (encType === 'e2e' || encType === 'server' || (encType === 'NA' && _studyIsEncrypted));
                    if (encryptedFields.indexOf(col) !== -1 && isEncrypted && val && forgeKey) {
                        var decrypted = decryptMessage(val, forgeKey);
                        if (decrypted !== null) val = decrypted;
                    }
                    if (stripHtml && col === 'submissionText') {
                        var tmp = document.createElement('div');
                        tmp.innerHTML = val;
                        val = tmp.textContent || tmp.innerText || '';
                    }
                    return csvEscape(val, sep);
                });
                lines.push(line.join(sep));
            });

            return '\uFEFF' + lines.join('\r\n');
        }

        function triggerCsvDownload(csvString, filename) {
            var blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        }

        // Full CSV Download (Messages) modal confirm button
        $('#confirmDownloadFullCSVButtonMessages').click(function() {
            var btn = $(this);
            btn.addClass('is-loading');

            var sep = $('input[name="csvSepMessages"]:checked').val() === 'semicolon' ? ';' : ',';
            var url = 'Backend/Studies/messages-download.php?studyCode=' + studyCode + '&format=json';

            fetch(url, { credentials: 'same-origin' })
                .then(function(response) {
                    if (!response.ok) throw new Error('Network response was not ok (status ' + response.status + ')');
                    return response.text();
                })
                .then(function(text) {
                    var rows;
                    try {
                        rows = JSON.parse(text);
                    } catch (e) {
                        console.error('Invalid JSON response:', text.substring(0, 500));
                        throw new Error('Server returned invalid JSON');
                    }
                    if (rows.error) throw new Error(rows.error);
                    var columns = ['messageID', 'participantID', 'condition', 'messageText',
                                   'messageDateTime', 'senderType', 'passedVariables'];
                    var csv = buildCsvFromJson(rows, columns, ['messageText', 'passedVariables'], sep, false, _forgePrivateKey);
                    triggerCsvDownload(csv, 'messages_' + getFormattedDate() + '.csv');
                })
                .catch(function(error) {
                    console.error('Download error:', error);
                    iziToast.error({
                        title: 'Error',
                        message: 'Could not download CSV.',
                        position: 'bottomRight'
                    });
                })
                .finally(function() {
                    btn.removeClass('is-loading');
                });
        });

        // Full CSV Download (Submissions) modal confirm button
        $('#confirmDownloadFullCSVButtonSubmissions').click(function() {
            var btn = $(this);
            btn.addClass('is-loading');

            var sep = $('input[name="csvSepSubmissions"]:checked').val() === 'semicolon' ? ';' : ',';
            var strip = $('#stripHtmlSubmissions').prop('checked');
            var url = 'Backend/Studies/submissions-download.php?studyCode=' + studyCode + '&format=json';

            fetch(url, { credentials: 'same-origin' })
                .then(function(response) {
                    if (!response.ok) throw new Error('Network response was not ok (status ' + response.status + ')');
                    return response.text();
                })
                .then(function(text) {
                    var rows;
                    try {
                        rows = JSON.parse(text);
                    } catch (e) {
                        console.error('Invalid JSON response:', text.substring(0, 500));
                        throw new Error('Server returned invalid JSON');
                    }
                    if (rows.error) throw new Error(rows.error);
                    var columns = ['submissionID', 'participantID', 'condition', 'submissionText',
                                   'submissionTime', 'startTime', 'duration', 'numberMessages',
                                   'passedVariables'];
                    var csv = buildCsvFromJson(rows, columns, ['submissionText', 'passedVariables'], sep, strip, _forgePrivateKey);
                    triggerCsvDownload(csv, 'submissions_' + getFormattedDate() + '.csv');
                })
                .catch(function(error) {
                    console.error('Download error:', error);
                    iziToast.error({
                        title: 'Error',
                        message: 'Could not download CSV.',
                        position: 'bottomRight'
                    });
                })
                .finally(function() {
                    btn.removeClass('is-loading');
                });
        });

        // Download all files as zip
        $('#downloadFilesButton').click(function() {
            var btn = $(this);
            if (btn.prop('disabled')) return;
            btn.addClass('is-loading').prop('disabled', true);
            iziToast.info({
                title: 'Please wait',
                message: 'Preparing download...',
                position: 'bottomRight'
            });

            var url = 'Backend/Studies/files-download.php?studyCode=' + studyCode;
            fetch(url, {credentials: 'same-origin'})
                .then(function(response) {
                    if (!response.ok) throw new Error('Network response was not ok');
                    return response.blob();
                })
                .then(function(blob) {
                    var downloadUrl = URL.createObjectURL(blob);
                    var a = document.createElement('a');
                    a.href = downloadUrl;
                    a.download = 'files_' + getFormattedDate() + '.zip';
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    URL.revokeObjectURL(downloadUrl);
                })
                .catch(function(error) {
                    console.error('Download error:', error);
                    iziToast.error({
                        title: 'Error',
                        message: 'Could not download files.',
                        position: 'bottomRight'
                    });
                })
                .finally(function() {
                    btn.removeClass('is-loading').prop('disabled', false);
                });
        });

        ////////////////////////////////////////
        // Filter Modal Logic for Messages Table
        ////////////////////////////////////////

        $(document).ready(function() {
            // Search participant logic
            $('#participantSearchFilterModalMessages').on('input', function() {
                var searchQuery = $(this).val().toLowerCase();
                $('#participantTableFilterModalMessages tr').each(function() {
                    var participantName = $(this).find('td:first').text().toLowerCase();
                    $(this).toggle(participantName.includes(searchQuery));
                });
            });

            // Uncheck/check all participants toggle
            $('#uncheckAllParticipantsButton').click(function() {
                var anyChecked = $('#participantTableFilterModalMessages input[type="checkbox"]:checked').length > 0;
                $('#participantTableFilterModalMessages input[type="checkbox"]').prop('checked', !anyChecked);
            });

            // Apply filter to messagesTable
            $('#applyFilterButtonFilterModalMessages').click(function() {
                var selectedParticipants = [];
                $('#participantTableFilterModalMessages input[type="checkbox"]:checked').each(function() {
                    selectedParticipants.push($(this).closest('tr').find('td:first').text());
                });

                var selectedMessageTypes = [];
                $('#filterModalMessages input[name="messageType"]:checked').each(function() {
                    selectedMessageTypes.push($(this).val());
                });

                $('#messagesTable tbody tr').each(function() {
                    var participantID = $(this).find('td:nth-child(2)').text();
                    var senderType = $(this).find('td:nth-child(6)').text().trim();
                    var messageType = (senderType === 'AI') ? 'aiMessages' : 'participantMessages';
                    $(this).toggle(selectedParticipants.includes(participantID) && selectedMessageTypes.includes(messageType));
                });

                var anyHidden = $('#messagesTable tbody tr:hidden').length > 0;
                $('#filterWarningMessages').toggle(anyHidden);
                $('#filterModalMessages').removeClass('is-active');
            });

            // Reset filter (from warning banner)
            $('#resetFilterMessages').click(function(e) {
                e.preventDefault();
                $('#filterModalMessages input[type="checkbox"]').prop('checked', true);
                $('#participantSearchFilterModalMessages').val('');
                $('#participantTableFilterModalMessages tr').show();
                $('#messagesTable tbody tr').show();
                $('#filterWarningMessages').hide();
            });

            // Reset button inside modal
            $('#resetButtonFilterModalMessages').click(function() {
                $('#filterModalMessages input[type="checkbox"]').prop('checked', true);
                $('#filterModalMessages input[name="messageType"]').prop('checked', true);
                $('#participantSearchFilterModalMessages').val('');
                $('#participantTableFilterModalMessages tr').show();
            });
        });

        ////////////////////////////////////////
        // Filter Modal Logic for Submissions Table
        ////////////////////////////////////////

        $(document).ready(function() {
            // Search participant logic
            $('#participantSearchFilterModalSubmissions').on('input', function() {
                var searchQuery = $(this).val().toLowerCase();
                $('#participantTableFilterModalSubmissions tr').each(function() {
                    var participantName = $(this).find('td:first').text().toLowerCase();
                    $(this).toggle(participantName.includes(searchQuery));
                });
            });

            // Uncheck/check all participants toggle
            $('#uncheckAllParticipantsButtonSubmissions').click(function() {
                var anyChecked = $('#participantTableFilterModalSubmissions input[type="checkbox"]:checked').length > 0;
                $('#participantTableFilterModalSubmissions input[type="checkbox"]').prop('checked', !anyChecked);
            });

            // Apply filter to submissionsTable
            $('#applyFilterButtonFilterModalSubmissions').click(function() {
                var selectedParticipants = [];
                $('#participantTableFilterModalSubmissions input[type="checkbox"]:checked').each(function() {
                    selectedParticipants.push($(this).closest('tr').find('td:first').text());
                });

                $('#submissionsTable tbody tr').each(function() {
                    var participantID = $(this).find('td:nth-child(2)').text();
                    $(this).toggle(selectedParticipants.includes(participantID));
                });

                var anyHidden = $('#submissionsTable tbody tr:hidden').length > 0;
                $('#filterWarningSubmissions').toggle(anyHidden);
                $('#filterModalSubmissions').removeClass('is-active');
            });

            // Reset filter (from warning banner)
            $('#resetFilterSubmissions').click(function(e) {
                e.preventDefault();
                $('#filterModalSubmissions input[type="checkbox"]').prop('checked', true);
                $('#participantSearchFilterModalSubmissions').val('');
                $('#participantTableFilterModalSubmissions tr').show();
                $('#submissionsTable tbody tr').show();
                $('#filterWarningSubmissions').hide();
            });

            // Reset button inside modal
            $('#resetButtonFilterModalSubmissions').click(function() {
                $('#filterModalSubmissions input[type="checkbox"]').prop('checked', true);
                $('#participantSearchFilterModalSubmissions').val('');
                $('#participantTableFilterModalSubmissions tr').show();
            });
        });
    </script>
</body>

</html>