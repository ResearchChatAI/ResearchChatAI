<?php
require 'Backend/MySQL/medoo.php';
require 'Backend/MySQL/medoo-Credentials.php';
require_once 'Backend/Util/crypto.php';

use Medoo\Medoo;

// Generate last 30 days
$today = new DateTime();
$days = [];
for ($i = 30; $i >= 1; $i--) {
    $days[] = (clone $today)->modify("-$i days")->format('Y-m-d');
}
$days[] = $today->format('Y-m-d'); // Add today

// Fetch from DB
$thirtyDaysAgo = (new DateTime())->modify('-30 days')->format('Y-m-d');

$rows = $database->select("api_checks", [
    "provider",
    "day" => Medoo::raw("DATE(`timestamp`)"),
    "up_count" => Medoo::raw("SUM(CASE WHEN `status` = '200' THEN 1 ELSE 0 END)"),
    "total_count" => Medoo::raw("COUNT(*)")
], [
    "timestamp[>=]" => $thirtyDaysAgo,
    "GROUP" => ["provider", "day"],
    "ORDER" => ["provider" => "ASC", "day" => "ASC"]
]);

$data = [];

foreach ($rows as $row) {
    [$platform, $model] = explode(" - ", $row['provider'], 2);
    $day = $row['day'];
    $ratio = $row['total_count'] > 0 ? $row['up_count'] / $row['total_count'] : 0;

    if (!isset($data[$platform])) $data[$platform] = [];
    if (!isset($data[$platform][$model])) {
        foreach ($days as $d) $data[$platform][$model][$d] = 'no-data';
    }

    $data[$platform][$model][$day] = $ratio == 1 ? 'up' : ($ratio > 0 ? 'partial' : 'down');
}
?>

<?php
// Determine which tile is active
$activeTile = isset($_GET['tile']) ? $_GET['tile'] : null;
?>

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>System Status Page</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">
 
    <link rel="stylesheet" href="src/CSS/studies-overview.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/solid.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/light.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/regular.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/brands.min.css">
    <link rel="stylesheet" href="src/FONTS/font-awesome-5.6.3/css/fontawesome.min.css">
</head>

<style>
        .model { margin-top: 20px; }
        .bar {
            display: flex;
            justify-content: space-between;
            width: 100%;
        }
        .day {
            flex: 1;
            height: 20px;
            border-radius: 2px;
            margin: 0 2px;
            background: #ccc;
        }
        .up { background: #4caf50; }
        .partial { background: #ffc107; }
        .down { background: #f44336; }
        .no-data { background: #e0e0e0; }

        .label-row {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            margin-top: 4px;
        }

        .uptime-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 6px;
            font-size: 13px;
            color: #555;
        }

        .uptime-row .center {
            text-align: center;
            flex-grow: 1;
        }

        .uptime-row span {
            width: 100px;
        }

        .platform {
            margin-top: 20px;
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

            <a role="button" class="navbar-burger" aria-label="menu" aria-expanded="false"
                data-target="navbarBasicExample">
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
                            <b><?php echo htmlspecialchars(decryptString($user["userName"] ?? ''), ENT_QUOTES, 'UTF-8') . " " . htmlspecialchars(decryptString($user["userSurname"] ?? ''), ENT_QUOTES, 'UTF-8'); ?></b>
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

     <div class="container" style="margin-top: 48px;">
    <section class="section has-background-success-light">
      <p class="title is-3">Model System Status</p>
      <p>
        This page provides an overview of the operational status and 30-day uptime performance of the most frequently used models integrated within the ResearchChatAI platform (OpenRouter offers a larger variety of models to use of which the status is not tested frequently). Each model is monitored daily to ensure stability, responsiveness, and reliability. <br><br>
        If a model experienced downtime or partial service interruptions in the past 30 days, it will be reflected in the uptime history below. Use this information to assess the consistency of your selected models.
     </p>
  </div>


    <div class="container" style="margin-top: 48px;margin-bottom: 48px;">
       
        <?php foreach ($data as $platform => $models): ?>
            <div class="platform">
                <h2><b><?php echo htmlspecialchars($platform); ?></b></h2>
                <?php foreach ($models as $model => $statuses): ?>
                    <div class="model">
                        <h3><?php echo htmlspecialchars($model); ?></h3>
                        <div class="bar">
                            <?php
                            $upCount = 0;
                            $total = 0;
                            foreach ($days as $day):
                                $status = $statuses[$day];
                                if ($status === 'up') $upCount++;
                                if ($status !== 'no-data') $total++;
                            ?>
                                <div class="day <?php echo $status; ?>" title="<?php echo $day; ?>"></div>
                            <?php endforeach; ?>
                        </div>

                        <div class="uptime-row">
                            <span style="text-align:left;">30 days ago</span>
                            <div class="center">
                                <?php
                                    $uptime = $total > 0 ? round($upCount / $total * 100, 2) : 0;
                                    echo "30-day uptime: {$uptime}%";
                                ?>
                            </div>
                            <span style="text-align:right;">Today</span>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endforeach; ?>

    </div>
    </section>

    <script>
        document.getElementById('searchInput').addEventListener('input', function () {
            const query = this.value.toLowerCase();
            const tiles = document.querySelectorAll('#tilesContainer .tile');

            tiles.forEach(tile => {
                const title = tile.getAttribute('data-title').toLowerCase();
                if (title.includes(query)) {
                    tile.style.display = '';
                } else {
                    tile.style.display = 'none';
                }
            });
        });

    </script>
</body>

</html>