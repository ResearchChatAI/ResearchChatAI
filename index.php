<?php

/**
 * index.php
 *
 * Main dashboard showing user's studies overview with statistics.
 * Allows creating, importing, and deleting studies.
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 */

// Error reporting for development (disable in production)
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
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
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://code.jquery.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

// =============================================================================
// AUTHENTICATION CHECK
// =============================================================================

if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
  header('Location: https://about.researchchatai.com');
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
// DATABASE CONNECTION AND USER DATA
// =============================================================================

require 'Backend/MySQL/medoo.php';
require 'Backend/MySQL/medoo-Credentials.php';

$userID = (int)$_SESSION['userID'];

// Fetch user data
$user = $database->get("users", "*", ["userID" => $userID]);

if (!$user) {
  session_destroy();
  header('Location: login.php');
  exit;
}

// Update last active timestamp
$database->update("users", [
  "userLastActiveDate" => date('Y-m-d H:i:s')
], [
  "userID" => $userID
]);

// =============================================================================
// FETCH STUDIES AND STATISTICS
// =============================================================================

$studies = $database->select("studies", "*", ["studyOwner" => $userID]);

// =============================================================================
// CHECK FOR MODEL STATUS WARNINGS
// =============================================================================

$yesterday = (new DateTime())->modify('-1 day')->format('Y-m-d');

$downModels = $database->query("
    SELECT provider
    FROM api_checks
    WHERE DATE(timestamp) = '$yesterday'
    GROUP BY provider
    HAVING SUM(CASE WHEN status = '200' THEN 1 ELSE 0 END) = 0
")->fetchAll(PDO::FETCH_COLUMN);

// Check if any user studies use models that were down
$showModelWarning = false;

if (!empty($studies)) {
  foreach ($studies as $study) {
    $modelName = '';

    if ($study["modelProvider"] === "openai" && !empty($study["openaiModel"])) {
      $modelName = $study["openaiModel"];
    } elseif ($study["modelProvider"] === "openrouter" && !empty($study["openrouterModel"])) {
      $modelName = $study["openrouterModel"];
    }

    $provider = $study["modelProvider"] ?? null;
    $providerLabel = match (strtolower($provider ?? '')) {
      "openai" => "OpenAI",
      "openrouter" => "OpenRouter",
      default => null
    };

    $fullProviderKey = ($providerLabel && $modelName) ? "$providerLabel - $modelName" : null;

    if ($fullProviderKey && in_array($fullProviderKey, $downModels, true)) {
      $showModelWarning = true;
      break;
    }
  }
}

// =============================================================================
// FETCH STATISTICS (OPTIMIZED BULK QUERIES)
// =============================================================================

$studyIDs = array_column($studies, 'studyID');
$messageCounts = [];
$participantCounts = [];

if (!empty($studyIDs)) {
  // Bulk query: Total messages per study
  $messageCountsRaw = $database->select(
    "messages",
    ["studyID", "cnt" => $database->raw("COUNT(*)")],
    [
      "studyID" => $studyIDs,
      "senderType" => "Participant",
      "GROUP" => "studyID"
    ]
  );

  foreach ($messageCountsRaw as $row) {
    $messageCounts[$row['studyID']] = (int)$row['cnt'];
  }

  // Bulk query: Distinct participants per study
  $participantRows = $database->select(
    "messages",
    ["studyID", "participantID"],
    [
      "studyID" => $studyIDs,
      "senderType" => "Participant"
    ]
  );

  $participantCountsTemp = [];
  foreach ($participantRows as $row) {
    $participantCountsTemp[$row['studyID']][$row['participantID']] = true;
  }

  foreach ($participantCountsTemp as $sid => $plist) {
    $participantCounts[$sid] = count($plist);
  }
}

// Escape user data for safe output
$displayName = htmlspecialchars($user['userName'], ENT_QUOTES, 'UTF-8');
$displaySurname = htmlspecialchars($user['userSurname'], ENT_QUOTES, 'UTF-8');
$displayFullName = $displayName . ' ' . $displaySurname;

?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Projects Overview - ResearchChatAI</title>

  <!-- Stylesheets -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma-tooltip/dist/css/bulma-tooltip.min.css">
  <link rel="stylesheet" href="src/CSS/studies-overview.css">

  <!-- FontAwesome -->
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/solid.min.css">
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/light.min.css">
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/regular.min.css">
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/brands.min.css">
  <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/fontawesome.min.css">
</head>

<body>
  <!-- Navigation Bar -->
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
        <a class="navbar-item" href="index.php">Home</a>
        <a class="navbar-item" href="/documentation/">Documentation</a>
        <a class="navbar-item" href="status.php">System Status</a>
      </div>

      <div class="navbar-end">
        <div class="navbar-item has-dropdown is-hoverable">
          <a class="navbar-link">Account</a>

          <div class="navbar-dropdown is-right">
            <div class="dropdown-item">
              <b><?php echo $displayFullName; ?></b>
            </div>
            <a class="navbar-item" href="profile-edit.php">Edit profile</a>
            <hr class="navbar-divider">
            <a href="logout.php" class="navbar-item">Logout</a>
          </div>
        </div>
      </div>
    </div>
  </nav>

  <!-- Maintenance Notice -->
  <!--<section class="section has-background-danger" style="padding: 1.25rem 1rem;">
    <div class="container has-text-centered">
      <p class="title is-4 has-text-white">
        <span class="icon">
          <i class="fas fa-tools"></i>
        </span>
        <span>
          Planned Maintenance – February 25, 2026
        </span>
      </p>
      <p class="has-text-white is-size-5">
        ResearchChatAI will undergo scheduled maintenance on
        <b>February 25, 2026</b> from <b>06:00 AM</b> until
        <b>23:59 (Amsterdam Time)</b>.
        During this time, the platform may be temporarily unavailable.
      </p>
    </div>
  </section>-->

  <!-- Main Content -->
  <div class="container" style="margin-top: 48px;">
    <!-- Welcome Section -->
    <section class="section has-background-success-light">
      <p class="title is-3">Welcome to ResearchChatAI!</p>
      <p>
        ResearchChatAI allows you to easily setup and conduct studies with sophisticated AI agents.
        You have full control over the AI's attributes (e.g., name, appearance) and behavior
        (i.e., via LLM instructions).
        Begin by clicking on the <b>Add study</b> button below. Afterwards, ResearchChatAI will
        guide you through the <b>5 simple steps</b> of setting up your study. Watch
        <a href="/documentation/" target="_blank">this video</a> to learn
        more about getting started with ResearchChatAI.
      </p>

      <hr style="margin: 1rem 0;">

      <div class="is-flex is-align-items-center is-flex-wrap-wrap is-justify-content-space-between" style="margin-bottom: 0.5rem; gap: 0.5rem;">
        <p class="has-text-weight-semibold" style="margin: 0;">
          <span class="icon"><i class="fas fa-quote-left"></i></span> If you use ResearchChatAI, please cite:
        </p>
        <div class="buttons are-small" style="margin: 0;">
          <button class="button is-success is-light" id="copyApaBtn" onclick="copyApaCitation()">
            <span class="icon"><i class="fas fa-copy"></i></span>
            <span>Copy APA</span>
          </button>
          <button class="button is-info is-light" onclick="downloadRIS()">
            <span class="icon"><i class="fas fa-download"></i></span>
            <span>RIS</span>
          </button>
          <button class="button is-info is-light" onclick="downloadBibTeX()">
            <span class="icon"><i class="fas fa-download"></i></span>
            <span>BibTeX</span>
          </button>
        </div>
      </div>
      <p id="apaCitation" style="font-size: 0.92rem; line-height: 1.5; padding: 0.75rem; background: rgba(255,255,255,0.6); border-radius: 6px; border-left: 3px solid #48c78e;">
        Becker, Marc, David de Jong, Roman Briker, Kars Mennens, Jonas Heller, Dominik Mahr, &amp; Dhruv Grewal (2026). Using customized, conversational AI agents in leadership and management research: Benefits, practical illustrations, and best practices. <i>The Leadership Quarterly</i>, <i>37</i>(3), 101952. <a href="https://doi.org/10.1016/j.leaqua.2026.101952" target="_blank">https://doi.org/10.1016/j.leaqua.2026.101952</a>
      </p>

      <script>
      function copyApaCitation() {
        var text = 'Becker, M., de Jong, D., Briker, R., Mennens, K., Heller, J., Mahr, D., & Grewal, D. (2026). Using customized, conversational AI agents in leadership and management research: Benefits, practical illustrations, and best practices. The Leadership Quarterly, 37(3), 101952. https://doi.org/10.1016/j.leaqua.2026.101952';
        navigator.clipboard.writeText(text).then(function() {
          var btn = document.getElementById('copyApaBtn');
          var origHTML = btn.innerHTML;
          btn.innerHTML = '<span class="icon"><i class="fas fa-check"></i></span><span>Copied!</span>';
          btn.classList.remove('is-success');
          btn.classList.add('is-primary');
          setTimeout(function() { btn.innerHTML = origHTML; btn.classList.remove('is-primary'); btn.classList.add('is-success'); }, 2000);
        });
      }

      function downloadRIS() {
        var ris = "TY  - JOUR\n" +
          "T1  - Using customized, conversational AI agents in leadership and management research: Benefits, practical illustrations, and best practices\n" +
          "AU  - Becker, Marc\n" +
          "AU  - de Jong, David\n" +
          "AU  - Briker, Roman\n" +
          "AU  - Mennens, Kars\n" +
          "AU  - Heller, Jonas\n" +
          "AU  - Mahr, Dominik\n" +
          "AU  - Grewal, Dhruv\n" +
          "JO  - The Leadership Quarterly\n" +
          "VL  - 37\n" +
          "IS  - 3\n" +
          "SP  - 101952\n" +
          "PY  - 2026\n" +
          "DA  - 2026/07/01/\n" +
          "SN  - 1048-9843\n" +
          "DO  - https://doi.org/10.1016/j.leaqua.2026.101952\n" +
          "UR  - https://www.sciencedirect.com/science/article/pii/S1048984326000111\n" +
          "KW  - Artificial Intelligence\n" +
          "KW  - AI\n" +
          "KW  - Tool\n" +
          "KW  - Conversational AI\n" +
          "KW  - Generative AI\n" +
          "ER  - \n";
        downloadFile(ris, 'Becker_et_al_2026_ResearchChatAI.ris', 'application/x-research-info-systems');
      }

      function downloadBibTeX() {
        var bib = "@article{becker2026researchChatAI,\n" +
          "  title     = {Using customized, conversational {AI} agents in leadership and management research: Benefits, practical illustrations, and best practices},\n" +
          "  author    = {Becker, Marc and de Jong, David and Briker, Roman and Mennens, Kars and Heller, Jonas and Mahr, Dominik and Grewal, Dhruv},\n" +
          "  journal   = {The Leadership Quarterly},\n" +
          "  volume    = {37},\n" +
          "  number    = {3},\n" +
          "  pages     = {101952},\n" +
          "  year      = {2026},\n" +
          "  doi       = {10.1016/j.leaqua.2026.101952},\n" +
          "  issn      = {1048-9843}\n" +
          "}\n";
        downloadFile(bib, 'Becker_et_al_2026_ResearchChatAI.bib', 'application/x-bibtex');
      }

      function downloadFile(content, filename, mimeType) {
        var blob = new Blob([content], { type: mimeType });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(a.href);
      }
      </script>
    </section>

    <!-- Model Warning Section -->
    <?php if ($showModelWarning): ?>
      <section class="section has-background-danger-light" style="margin-top: 10px;">
        <div class="container">
          <p class="title is-5 has-text-danger-dark">
            <span class="icon">
              <i class="fas fa-exclamation-triangle"></i>
            </span>
            <span>Warning: Some of your studies use AI models that might not function properly</span>
          </p>
          <p>
            Please visit <a href="status.php">the system status page</a> for model details.
            For ongoing studies, consider switching to a functional or more stable model if issues persist.
          </p>
        </div>
      </section>
    <?php endif; ?>

    <!-- Studies Section -->
    <section class="section">
      <div class="container">
        <h1 class="title" style="position: relative;">
          Your Studies
          <div style="position: absolute; right: 0px; top: 0px;">
            <button class="button is-info is-light js-modal-trigger" data-target="importModal">
              <span class="icon is-small">
                <i class="fa fa-file-import"></i>
              </span>
              <span>Import Study</span>
            </button>
            <button class="button is-primary is-light js-modal-trigger" data-target="createStudyModal">
              <span class="icon is-small">
                <i class="fa fa-plus"></i>
              </span>
              <span>Add Study</span>
            </button>
          </div>
        </h1>

        <?php if (count($studies) === 0): ?>
          <!-- No Studies Message -->
          <div class="grid is-flex is-justify-content-center is-align-items-center" style="height: 300px;">
            <div class="has-text-centered has-background-light p-5">
              <p class="is-size-4">No studies yet.</p>
              <button class="button js-modal-trigger is-text has-text-link" data-target="createStudyModal">
                Click here to add your first study
              </button>
            </div>
          </div>
        <?php else: ?>
          <!-- Studies Grid -->
          <div class="grid">
            <?php foreach ($studies as $study):
              $sid = (int)$study['studyID'];
              $numberMessages = $messageCounts[$sid] ?? 0;
              $numberParticipants = $participantCounts[$sid] ?? 0;

              // Format last edited date
              if ($study["lastEdited"] === null) {
                $lastEdited = "Never";
              } else {
                $lastEdited = date("M d Y, H:i", strtotime($study["lastEdited"]));
              }

              // Determine model name
              $modelName = '';
              if ($study["modelProvider"] === "openai" && !empty($study["openaiModel"])) {
                $modelName = $study["openaiModel"];
              } elseif ($study["modelProvider"] === "openrouter" && !empty($study["openrouterModel"])) {
                $modelName = $study["openrouterModel"];
              } elseif ($study["modelProvider"] === "custom") {
                $modelName = "Custom Connector";
              } else {
                $modelName = "Model: Not specified";
              }

              // Check if model is down
              $provider = $study["modelProvider"] ?? null;
              $providerLabel = match (strtolower($provider ?? '')) {
                "openai" => "OpenAI",
                "openrouter" => "OpenRouter",
                default => null
              };

              $fullProviderKey = ($providerLabel && $modelName) ? "$providerLabel - $modelName" : null;
              $isModelDown = $fullProviderKey && in_array($fullProviderKey, $downModels, true);

              // Escape for safe output
              $studyName = htmlspecialchars($study["studyName"], ENT_QUOTES, 'UTF-8');
              $modelNameEscaped = htmlspecialchars($modelName, ENT_QUOTES, 'UTF-8');
            ?>

              <!-- Study Card -->
              <div class="card">
                <header class="card-header">
                  <p class="card-header-title"><?php echo $studyName; ?></p>
                </header>

                <div class="card-content">
                  <div class="content">
                    <ul>
                      <li>
                        <i class="fas fa-users has-text-primary has-background-primary-light"></i>
                        <b><?php echo $numberParticipants; ?></b>&nbsp;participants
                      </li>
                      <li>
                        <i class="fas fa-comment has-text-primary has-background-primary-light"></i>
                        <b><?php echo $numberMessages; ?></b>&nbsp;messages
                      </li>
                      <li>
                        <i class="fas fa-microchip has-text-primary has-background-primary-light"></i>
                        <div class="is-flex is-align-items-center" style="min-width: 0;">
                          <span style="display: inline-block; max-width: 130px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;"
                            title="<?php echo $modelNameEscaped; ?>">
                            <b class="has-text-weight-medium"><?php echo $modelNameEscaped; ?></b>
                          </span>
                          <?php if ($isModelDown): ?>
                            <a href="status.php" class="ml-2 has-tooltip-left"
                              data-tooltip="Model had issues, see status page"
                              style="color: #f14668;">
                              <i class="fas fa-exclamation-triangle"></i>
                            </a>
                          <?php endif; ?>
                        </div>
                      </li>
                      <li>
                        <i class="fas fa-calendar-alt has-text-primary has-background-primary-light"></i>
                        Last edited&nbsp;<b><?php echo htmlspecialchars($lastEdited, ENT_QUOTES, 'UTF-8'); ?></b>
                      </li>
                    </ul>
                  </div>
                </div>

                <footer class="card-footer">
                  <a href="#" class="card-footer-item has-text-danger js-modal-trigger delete-study-link"
                    data-target="deleteStudyModal"
                    data-study-id="<?php echo $sid; ?>">Delete</a>
                  <a href="chat-backend-create.php?studyID=<?php echo $sid; ?>"
                    class="card-footer-item has-text-dark">Open</a>
                </footer>
              </div>

            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </div>
    </section>
  </div>

  <!-- Create Study Modal -->
  <div class="modal" id="createStudyModal">
    <div class="modal-background"></div>
    <div class="modal-card">
      <header class="modal-card-head">
        <p class="modal-card-title">Create New Study</p>
        <button class="delete" aria-label="close"></button>
      </header>
      <section class="modal-card-body">
        <div class="field">
          <label class="label has-text-left">New Study Name</label>
          <div class="control">
            <input id="newStudyNameInput" class="input" type="text"
              placeholder="Study name" value="" style="max-width: 450px;">
            <p class="help">This name will not be visible to participants</p>
          </div>
        </div>
      </section>
      <footer class="modal-card-foot">
        <div class="buttons">
          <button class="button is-success createStudyButton">Create Study</button>
          <button class="button cancel">Cancel</button>
        </div>
      </footer>
    </div>
  </div>

  <!-- Delete Study Modal -->
  <div class="modal" id="deleteStudyModal">
    <div class="modal-background"></div>
    <div class="modal-card">
      <header class="modal-card-head">
        <p class="modal-card-title">Delete Study</p>
        <button class="delete" aria-label="close"></button>
      </header>
      <section class="modal-card-body">
        Are you sure that you want to delete this study? This action cannot be undone.
      </section>
      <footer class="modal-card-foot">
        <div class="buttons">
          <button class="button is-danger deleteProjectButton">Delete</button>
          <button class="button cancel">Cancel</button>
        </div>
      </footer>
    </div>
  </div>

  <!-- Import Study Modal -->
  <div class="modal" id="importModal">
    <div class="modal-background"></div>
    <div class="modal-card">
      <header class="modal-card-head">
        <p class="modal-card-title">Import Study</p>
        <button class="delete" aria-label="close" id="importModalClose"></button>
      </header>
      <section class="modal-card-body">
        <form id="importForm">
          <div class="field">
            <label class="label">New Study Name</label>
            <div class="control">
              <input class="input" type="text" name="studyName"
                placeholder="Enter new study name" required>
            </div>
          </div>

          <div class="field">
            <label class="label">Select JSON File</label>
            <div class="control">
              <input class="input" type="file" name="jsonFile" accept=".json" required>
            </div>
          </div>

          <input type="hidden" name="studyOwner" value="<?php echo $userID; ?>">
          <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">

          <div class="field">
            <div class="control">
              <button class="button is-success" type="submit">Import</button>
              <button class="button cancel-import" type="button">Cancel</button>
            </div>
          </div>
        </form>
      </section>
    </div>
  </div>

  <!-- Scripts -->
  <script src="https://code.jquery.com/jquery-3.6.3.min.js"
    integrity="sha256-pvPw+upLPUjgMXY0G+8O0xUf+/Im1MZjXxxgOcBQBXU=" crossorigin="anonymous"></script>
  <script type="text/javascript">
    var csrfToken = '<?php echo $csrfToken; ?>';
    var userID = <?php echo $userID; ?>;
    var studyToDelete = null;

    $(document).ready(function() {
      /**
       * Create study
       */
      $('.createStudyButton').click(function() {
        var studyName = $('#newStudyNameInput').val().trim();

        if (studyName === '') {
          alert('Please enter a study name');
          return;
        }

        closeAllModals();

        $.post('Backend/Studies/study-create.php', {
          csrf_token: csrfToken,
          studyOwner: userID,
          studyName: studyName
        }, function(data) {
          if (data.status !== 'good') {
            console.log(data);
            alert('An error occurred while creating the study');
            return;
          }
          window.location.href = 'chat-backend-create.php?studyID=' + data.studyID;
        }).fail(function(xhr, status, error) {
          console.log(xhr);
          alert('An error occurred while creating the study');
        });
      });

      /**
       * Delete study
       */
      $(document).on('click', '.delete-study-link', function(e) {
        e.preventDefault();
        studyToDelete = $(this).data('study-id');
      });

      $('.deleteProjectButton').click(function() {
        if (!studyToDelete) {
          alert('No study selected for deletion');
          return;
        }

        closeAllModals();

        $.post('Backend/Studies/study-delete.php', {
          csrf_token: csrfToken,
          studyID: studyToDelete
        }, function(data) {
          if (data.status !== 'good') {
            console.log(data);
            alert('An error occurred while deleting the study');
            return;
          }
          location.reload();
        }).fail(function(xhr, status, error) {
          console.log(xhr);
          alert('An error occurred while deleting the study');
        });
      });

      /**
       * Import study
       */
      $('#importForm').submit(function(event) {
        event.preventDefault();

        var formData = new FormData(this);

        $.ajax({
          url: 'Backend/Studies/study-import.php',
          type: 'POST',
          data: formData,
          processData: false,
          contentType: false,
          success: function(response) {
            if (response.status === 'good') {
              if (response.missingColumns && response.missingColumns.length) {
                var message = 'Import completed with missing columns: ' +
                  response.missingColumns.join(', ');
                alert(message);
              }
              window.location.href = 'chat-backend-create.php?studyID=' + response.studyID;
            } else {
              alert('Error: ' + (response.message || 'Unknown error'));
            }
          },
          error: function(xhr, status, error) {
            alert('An unexpected error occurred: ' + error);
            console.log(xhr);
          }
        });
      });

      /**
       * Modal controls
       */
      function openModal($el) {
        $el.classList.add('is-active');
      }

      function closeModal($el) {
        $el.classList.remove('is-active');
      }

      function closeAllModals() {
        (document.querySelectorAll('.modal') || []).forEach(function($modal) {
          closeModal($modal);
        });
      }

      window.closeAllModals = closeAllModals;

      (document.querySelectorAll('.js-modal-trigger') || []).forEach(function($trigger) {
        var modal = $trigger.dataset.target;
        var $target = document.getElementById(modal);

        $trigger.addEventListener('click', function() {
          openModal($target);
        });
      });

      (document.querySelectorAll('.modal-background, .modal-close, .modal-card-head .delete, .cancel') || [])
      .forEach(function($close) {
        var $target = $close.closest('.modal');
        $close.addEventListener('click', function() {
          closeModal($target);
        });
      });

      $('#importModalClose, .cancel-import').click(function() {
        location.reload();
      });

      document.addEventListener('keydown', function(event) {
        if (event.key === "Escape") {
          closeAllModals();
        }
      });

      /**
       * Navbar burger toggle
       */
      $('.navbar-burger').click(function() {
        $('.navbar-burger').toggleClass('is-active');
        $('.navbar-menu').toggleClass('is-active');
      });
    });
  </script>
</body>

</html>