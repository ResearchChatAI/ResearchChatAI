<?php
/**
 * profile-edit.php
 *
 * User profile editing page with account management features.
 * Allows users to update personal information, change password, and delete account.
 *
 * ResearchChatAI
 * Author: Marc Becker, David de Jong
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

// Prevent clickjacking attacks
header("X-Frame-Options: DENY");

// Prevent MIME-type sniffing
header("X-Content-Type-Options: nosniff");

// Enable XSS protection in older browsers
header("X-XSS-Protection: 1; mode=block");

// Control referrer information leakage
header("Referrer-Policy: strict-origin-when-cross-origin");

// Restrict browser features and APIs
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");

// Content Security Policy - prevent XSS and injection attacks
// Note: 'unsafe-inline' needed for inline scripts
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://code.jquery.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");

// Force HTTPS in production (uncomment when using HTTPS)
// header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

// =============================================================================
// AUTHENTICATION CHECK
// =============================================================================

if (!isset($_SESSION['pm_loggedin']) || $_SESSION['pm_loggedin'] !== true) {
    header('Location: access-denied.php');
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
require_once 'Backend/Util/crypto.php';

$userID = $_SESSION['userID'];

// Update user's last active timestamp
$database->update('users', [
    'userLastActiveDate' => date('Y-m-d H:i:s')
], [
    'userID' => $userID
]);

// Fetch user information
$userInfo = $database->get("users", [
    "userID",
    "userName",
    "userSurname",
    "userEmail",
    "userInstitution"
], [
    "userID" => $userID
]);

// Verify user exists
if (!$userInfo) {
    session_destroy();
    header('Location: login.php');
    exit;
}

// Decrypt and escape output for XSS prevention
$userInfo['userName'] = decryptString($userInfo['userName'] ?? '');
$userInfo['userSurname'] = decryptString($userInfo['userSurname'] ?? '');
$displayName = htmlspecialchars($userInfo['userName'], ENT_QUOTES, 'UTF-8');
$displaySurname = htmlspecialchars($userInfo['userSurname'], ENT_QUOTES, 'UTF-8');
$displayEmail = htmlspecialchars($userInfo['userEmail'], ENT_QUOTES, 'UTF-8');
$userInfo['userInstitution'] = decryptString($userInfo['userInstitution'] ?? '');
$displayInstitution = htmlspecialchars($userInfo['userInstitution'], ENT_QUOTES, 'UTF-8');
$displayFullName = $displayName . ' ' . $displaySurname;

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Edit Profile - ResearchChatAI</title>
    
    <!-- Stylesheets -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
    <link rel="stylesheet" href="src/CSS/login.css">
    <link rel="stylesheet" href="src/CSS/iziToast.min.css">
    
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

    <!-- Profile Edit Section -->
    <section class="section">
        <div class="container" style="max-width:640px">
            <h1 class="title">Your Profile</h1>
            
            <!-- Profile Information Form -->
            <div class="box">
                <h2 class="subtitle">Personal Information</h2>
                
                <!-- First Name -->
                <div class="field">
                    <label class="label">First Name</label>
                    <div class="control">
                        <input 
                            class="input" 
                            type="text" 
                            placeholder="Jane" 
                            value="<?php echo $displayName; ?>" 
                            name="name"
                            maxlength="100"
                            autocomplete="given-name"
                        >
                    </div>
                </div>
                
                <!-- Last Name -->
                <div class="field">
                    <label class="label">Last Name</label>
                    <div class="control">
                        <input 
                            class="input" 
                            type="text" 
                            placeholder="Doe" 
                            value="<?php echo $displaySurname; ?>"
                            name="surname"
                            maxlength="100"
                            autocomplete="family-name"
                        >
                    </div>
                </div>
                
                <!-- Institution -->
                <div class="field">
                    <label class="label">Institution</label>
                    <div class="control">
                        <input 
                            class="input" 
                            type="text" 
                            placeholder="e.g., XYZ University"
                            value="<?php echo $displayInstitution; ?>" 
                            name="institution"
                            maxlength="200"
                            autocomplete="organization"
                        >
                    </div>
                </div>
                
                <!-- Email -->
                <div class="field">
                    <label class="label">Email</label>
                    <div class="control has-icons-left">
                        <input 
                            class="input" 
                            type="email" 
                            placeholder="e.g., jane.doe@xyzuniversity.nl"
                            value="<?php echo $displayEmail; ?>" 
                            name="email"
                            autocomplete="email"
                        >
                        <span class="icon is-small is-left">
                            <i class="fas fa-envelope"></i>
                        </span>
                    </div>
                    <p class="help">Your email is used for password recovery.</p>
                </div>
                
                <!-- Action Buttons -->
                <div class="field is-grouped">
                    <div class="control">
                        <button class="button is-primary" id="saveProfile">
                            <span class="icon">
                                <i class="fas fa-save"></i>
                            </span>
                            <span>Save Changes</span>
                        </button>
                    </div>
                    <div class="control">
                        <a class="button is-light" href="profile-edit.php">Cancel</a>
                    </div>
                </div>
            </div>

            <!-- Password Change Form -->
            <div class="box">
                <h2 class="subtitle">Change Password</h2>
                
                <div class="field">
                    <label class="label">Current Password</label>
                    <div class="control has-icons-left">
                        <input 
                            class="input" 
                            type="password" 
                            placeholder="Enter current password" 
                            name="oldPassword"
                            autocomplete="current-password"
                        >
                        <span class="icon is-small is-left">
                            <i class="fas fa-lock"></i>
                        </span>
                    </div>
                </div>
                
                <div class="field">
                    <label class="label">New Password</label>
                    <div class="control has-icons-left">
                        <input 
                            class="input" 
                            type="password" 
                            placeholder="Enter new password" 
                            name="newPassword"
                            autocomplete="new-password"
                            minlength="8"
                        >
                        <span class="icon is-small is-left">
                            <i class="fas fa-lock"></i>
                        </span>
                    </div>
                    <p class="help">Must be at least 8 characters long</p>
                </div>
                
                <!-- Action Buttons -->
                <div class="field is-grouped">
                    <div class="control">
                        <button class="button is-primary" id="savePassword">
                            <span class="icon">
                                <i class="fas fa-key"></i>
                            </span>
                            <span>Update Password</span>
                        </button>
                    </div>
                    <div class="control">
                        <a class="button is-light" href="profile-edit.php">Cancel</a>
                    </div>
                </div>
            </div>

            <!-- Danger Zone -->
            <div class="box has-background-danger-light">
                <h2 class="subtitle has-text-danger">
                    <span class="icon-text">
                        <span class="icon">
                            <i class="fas fa-exclamation-triangle"></i>
                        </span>
                        <span>Danger Zone</span>
                    </span>
                </h2>
                
                <div class="content">
                    <p>
                        Deleting your account will permanently remove all your studies, messages, and uploaded files. 
                        <strong>This action cannot be undone.</strong>
                    </p>
                    
                    <button class="button is-danger" id="deleteAccountButton">
                        <span class="icon">
                            <i class="fas fa-trash-alt"></i>
                        </span>
                        <span>Delete My Account</span>
                    </button>
                </div>
            </div>
        </div>
    </section>

    <!-- Scripts -->
    <script src="https://code.jquery.com/jquery-3.6.3.min.js"
        integrity="sha256-pvPw+upLPUjgMXY0G+8O0xUf+/Im1MZjXxxgOcBQBXU=" crossorigin="anonymous"></script>
    <script src="src/JS/iziToast.js" type="text/javascript"></script>
    <script type="text/javascript">
        // CSRF token for AJAX requests
        var csrfToken = '<?php echo $csrfToken; ?>';
        
        $(document).ready(function() {
            /**
             * Save profile information
             */
            $('#saveProfile').click(function() {
                var name = $('input[name="name"]').val().trim();
                var surname = $('input[name="surname"]').val().trim();
                var institution = $('input[name="institution"]').val().trim();
                var email = $('input[name="email"]').val().trim();
                
                // Client-side validation
                if (!name || !surname) {
                    iziToast.error({
                        title: 'Validation Error',
                        message: 'First name and last name are required.',
                        position: 'topRight'
                    });
                    return;
                }
                
                if (!email || !isValidEmail(email)) {
                    iziToast.error({
                        title: 'Validation Error',
                        message: 'Please enter a valid email address.',
                        position: 'topRight'
                    });
                    return;
                }
                
                // Show loading state
                $('#saveProfile').addClass('is-loading').prop('disabled', true);
                
                // Send update request with CSRF token
                $.ajax({
                    type: 'POST',
                    url: 'Backend/Users/user-update.php',
                    data: {
                        csrf_token: csrfToken,
                        userID: <?php echo (int)$userID; ?>,
                        name: name,
                        surname: surname,
                        institution: institution,
                        email: email
                    },
                    success: function(response) {
                        $('#saveProfile').removeClass('is-loading').prop('disabled', false);
                        
                        iziToast.success({
                            title: 'Success',
                            message: 'Profile updated successfully.',
                            position: 'topRight'
                        });
                        
                        // Reload page after 1 second to show updated name in navbar
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    },
                    error: function(xhr) {
                        $('#saveProfile').removeClass('is-loading').prop('disabled', false);
                        
                        iziToast.error({
                            title: 'Error',
                            message: 'Could not update profile. Please try again later.',
                            position: 'topRight'
                        });
                    }
                });
            });

            /**
             * Update password
             */
            $('#savePassword').click(function() {
                var oldPassword = $('input[name="oldPassword"]').val();
                var newPassword = $('input[name="newPassword"]').val();
                
                // Client-side validation
                if (!oldPassword || !newPassword) {
                    iziToast.error({
                        title: 'Validation Error',
                        message: 'Please enter both current and new passwords.',
                        position: 'topRight'
                    });
                    return;
                }
                
                if (newPassword.length < 8) {
                    iziToast.error({
                        title: 'Validation Error',
                        message: 'New password must be at least 8 characters long.',
                        position: 'topRight'
                    });
                    return;
                }
                
                // Show loading state
                $('#savePassword').addClass('is-loading').prop('disabled', true);
                
                // Send update request with CSRF token
                $.ajax({
                    type: 'POST',
                    url: 'Backend/Users/user-update-password.php',
                    data: {
                        csrf_token: csrfToken,
                        oldPassword: oldPassword,
                        newPassword: newPassword
                    },
                    success: function(response) {
                        $('#savePassword').removeClass('is-loading').prop('disabled', false);
                        
                        if (response.status === 'good') {
                            iziToast.success({
                                title: 'Success',
                                message: 'Password updated successfully.',
                                position: 'topRight'
                            });
                            
                            // Clear password fields
                            $('input[name="oldPassword"]').val('');
                            $('input[name="newPassword"]').val('');
                        } else {
                            iziToast.error({
                                title: 'Error',
                                message: response.message || 'Current password is incorrect.',
                                position: 'topRight'
                            });
                        }
                    },
                    error: function(xhr) {
                        $('#savePassword').removeClass('is-loading').prop('disabled', false);
                        
                        iziToast.error({
                            title: 'Error',
                            message: 'Could not update password. Please verify your current password is correct.',
                            position: 'topRight'
                        });
                    }
                });
            });

            /**
             * Delete account
             */
            $('#deleteAccountButton').click(function() {
                // Double confirmation for account deletion
                iziToast.question({
                    timeout: false,
                    close: false,
                    overlay: true,
                    displayMode: 'once',
                    id: 'deleteConfirm',
                    zindex: 999,
                    title: 'Delete Account',
                    message: 'Are you absolutely sure? This will permanently delete all your data and cannot be undone.',
                    position: 'center',
                    buttons: [
                        ['<button><b>Cancel</b></button>', function (instance, toast) {
                            instance.hide({ transitionOut: 'fadeOut' }, toast, 'button');
                        }],
                        ['<button class="button is-danger">Yes, Delete Everything</button>', function (instance, toast) {
                            instance.hide({ transitionOut: 'fadeOut' }, toast, 'button');
                            
                            // Show loading state
                            $('#deleteAccountButton').addClass('is-loading').prop('disabled', true);
                            
                            // Send delete request with CSRF token
                            $.ajax({
                                type: 'POST',
                                url: 'Backend/Users/user-delete.php',
                                data: {
                                    csrf_token: csrfToken
                                },
                                success: function(response) {
                                    if (response.status === 'good') {
                                        iziToast.success({
                                            title: 'Account Deleted',
                                            message: 'Your account has been permanently removed.',
                                            position: 'topRight'
                                        });
                                        
                                        // Redirect to login after 1.5 seconds
                                        setTimeout(function() {
                                            window.location.href = 'login.php';
                                        }, 1500);
                                    } else {
                                        $('#deleteAccountButton').removeClass('is-loading').prop('disabled', false);
                                        
                                        iziToast.error({
                                            title: 'Error',
                                            message: 'Could not delete account. Please try again later.',
                                            position: 'topRight'
                                        });
                                    }
                                },
                                error: function(xhr) {
                                    $('#deleteAccountButton').removeClass('is-loading').prop('disabled', false);
                                    
                                    iziToast.error({
                                        title: 'Error',
                                        message: 'Could not delete account. Please try again later.',
                                        position: 'topRight'
                                    });
                                }
                            });
                        }, true]
                    ]
                });
            });

            /**
             * Email validation helper
             */
            function isValidEmail(email) {
                var re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                return re.test(email);
            }

            /**
             * Toggle navbar burger menu
             */
            $('.navbar-burger').click(function() {
                $('.navbar-burger').toggleClass('is-active');
                $('.navbar-menu').toggleClass('is-active');
            });
        });
    </script>
</body>

</html>