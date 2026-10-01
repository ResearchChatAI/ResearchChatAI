<?php
declare(strict_types=1);

/**
 * stress_test.php – ResearchChatAI
 *
 * Fires N parallel requests to OpenAI's API and reports CPU, RAM,
 * response times, and error rates as a shareable HTML page.
 *
 * Usage:
 *   https://researchchatai.com/stress_test.php
 *     ?key=YOUR_STRESS_KEY        required
 *     &users=50                   parallel requests per batch (default: 20, max: 200)
 *     &batches=3                  number of batches (default: 3, max: 10)
 *     &delay=5                    seconds between batches (default: 5)
 *     &model=gpt-5-mini           OpenAI model (default: gpt-5-mini)
 *     &reasoning=high             low | medium | high (default: low; only for gpt-5/gpt-5-mini)
 *
 * ResearchChatAI
 * Authors: Marc Becker, David de Jong
 * License: MIT
 */

set_time_limit(0);
ini_set('display_errors', '0');
error_reporting(E_ALL);


/* ==================================================================
 *  1. LOAD .env
 * ================================================================== */

function loadEnvStress(string $path): array
{
    if (!file_exists($path)) {
        return [];
    }
    $env = [];
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (str_starts_with(trim($line), '#') || !str_contains($line, '=')) {
            continue;
        }
        [$name, $value] = array_map('trim', explode('=', $line, 2));
        $env[$name] = $value;
    }
    return $env;
}

$env = loadEnvStress($_SERVER['HOME'] . '/.env');


/* ==================================================================
 *  2. SECURITY
 * ================================================================== */

$providedKey = $_GET['key'] ?? '';
$expectedKey = $env['STRESS_KEY'] ?? '';

if (empty($expectedKey) || !hash_equals($expectedKey, $providedKey)) {
    http_response_code(403);
    $envPath = $_SERVER['HOME'] . '/.env';
    $diag = '';
    if (empty($expectedKey)) {
        $real = realpath($envPath);
        $diag = '<h2>Diagnostic: STRESS_KEY not found</h2>'
            . '<p>Checked: <code>' . htmlspecialchars($envPath) . '</code> → '
            . ($real
                ? '<strong>file exists</strong> at <code>' . htmlspecialchars($real) . '</code> — add <code>STRESS_KEY=your_secret</code> to it'
                : '<strong>file does not exist</strong>') . '</p>';
    }
    die('<!DOCTYPE html><html><head><title>403</title></head><body>'
        . '<h1>403 Forbidden</h1>'
        . '<p>Add <code>?key=YOUR_STRESS_KEY</code> to the URL.</p>'
        . $diag . '</body></html>');
}


/* ==================================================================
 *  3. PARAMETERS
 * ================================================================== */

$users   = min(1000, max(1,  (int) ($_GET['users']   ?? 20)));
$batches = min(10,  max(1,  (int) ($_GET['batches'] ?? 3)));
$delay   = min(60,  max(0,  (int) ($_GET['delay']   ?? 5)));

$validModels = ['gpt-6-sol', 'gpt-6-astra', 'gpt-6-luna', 'gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5', 'gpt-5-mini', 'gpt-4o', 'gpt-4o-mini'];
$model = in_array($_GET['model'] ?? '', $validModels, true) ? ($_GET['model']) : 'gpt-5-mini';

$validEfforts = ['low', 'medium', 'high'];
$reasoning = in_array($_GET['reasoning'] ?? '', $validEfforts, true) ? ($_GET['reasoning']) : 'low';

$overlap  = (int) ($_GET['overlap'] ?? 0) > 0 ? 1 : 0;  // 0 = sequential (wait for batch to finish + delay), 1 = overlapping (batches start $delay seconds apart)

$defaultMessage = 'A researcher is designing a study on AI-assisted decision-making. '
    . 'They plan to show participants an AI recommendation and then ask them to make a final choice. '
    . 'Identify three potential confounds in this design, explain why each is a problem, '
    . 'and suggest a concrete methodological fix for each one.';
$testMessage = !empty($_GET['message']) ? urldecode($_GET['message']) : $defaultMessage;

$openaiKey = $env['OPENAI_API'] ?? $env['OPENAI_API_KEY'] ?? '';
if (empty($openaiKey)) {
    die('<h1>Configuration Error</h1><p>OPENAI_API not found in .env</p>');
}


/* ==================================================================
 *  4. FUNCTIONS
 * ================================================================== */

function sample_server_stats(): array
{
    $cpu = $procs = 0;
    if (function_exists('shell_exec')) {
        $cpu   = (float) trim((string) (shell_exec('ps -u $(whoami) -o pcpu= | awk \'{sum+=$1} END {printf "%.1f", sum}\'') ?? '0'));
        $procs = (int)   trim((string) (shell_exec('ps -u $(whoami) --no-headers | wc -l') ?? '0'));
    }
    $memTotal = $memAvailable = 0;
    if (is_readable('/proc/meminfo')) {
        foreach (file('/proc/meminfo', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            if (preg_match('/^(MemTotal|MemAvailable):\s+(\d+)\s+kB/', $line, $m)) {
                if ($m[1] === 'MemTotal')     $memTotal     = (int) $m[2];
                if ($m[1] === 'MemAvailable') $memAvailable = (int) $m[2];
            }
        }
    }
    $usedMb  = round(($memTotal - $memAvailable) / 1024, 1);
    $totalMb = round($memTotal / 1024, 1);
    return [
        'ts'        => microtime(true),
        'cpu'       => round($cpu, 1),
        'procs'     => $procs,
        'mem_used'  => $usedMb,
        'mem_total' => $totalMb,
        'mem_pct'   => $totalMb > 0 ? round($usedMb / $totalMb * 100, 1) : 0.0,
    ];
}


function run_openai_batch(int $count, string $model, string $apiKey, string $reasoning, string $message, int $batchNum = 1, int $totalBatches = 1): array
{
    $responsesModels = ['gpt-6-sol', 'gpt-6-astra', 'gpt-6-luna', 'gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5', 'gpt-5-mini'];
    $useResponsesApi = in_array($model, $responsesModels, true);
    $url = $useResponsesApi
        ? 'https://api.openai.com/v1/responses'
        : 'https://api.openai.com/v1/chat/completions';
    $maxTokens = ($reasoning === 'high') ? 2000 : (($reasoning === 'medium') ? 1000 : 400);

    $payload = $useResponsesApi
        ? json_encode(['model' => $model, 'input' => $message, 'max_output_tokens' => $maxTokens,
                       'reasoning' => ['effort' => $reasoning]], JSON_THROW_ON_ERROR)
        : json_encode(['model' => $model, 'messages' => [['role' => 'user', 'content' => $message]],
                       'max_tokens' => $maxTokens], JSON_THROW_ON_ERROR);

    $headers = ['Authorization: Bearer ' . $apiKey, 'Content-Type: application/json'];

    $mh = curl_multi_init();
    $handles = [];
    for ($i = 0; $i < $count; $i++) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => 120,
            CURLOPT_CONNECTTIMEOUT => 10,
        ]);
        curl_multi_add_handle($mh, $ch);
        $handles[$i] = $ch;
    }

    $running = null;
    $midSnapshot = null;
    $midCaptured = false;
    $loopStart = microtime(true);
    $lastHeartbeat = microtime(true);

    do {
        curl_multi_exec($mh, $running);
        $wait = curl_multi_select($mh, 0.5);
        if ($wait === -1) usleep(10000);

        if (!$midCaptured && (microtime(true) - $loopStart) >= 3.0) {
            $midSnapshot = sample_server_stats();
            $midCaptured = true;
        }

        // Heartbeat every 5s: keeps the browser connection alive and updates progress text
        if (microtime(true) - $lastHeartbeat >= 5.0) {
            $elapsed = (int) round(microtime(true) - $loopStart);
            $msg = "Batch {$batchNum}/{$totalBatches} in progress — {$elapsed}s elapsed, {$running} requests pending\xe2\x80\xa6";
            echo '<script>document.getElementById("prog-text").textContent=' . json_encode($msg) . ';</script>' . "\n";
            flush();
            $lastHeartbeat = microtime(true);
        }
    } while ($running > 0);

    $results = [];
    foreach ($handles as $i => $ch) {
        $info  = curl_getinfo($ch);
        $body  = (string) curl_multi_getcontent($ch);
        $code  = (int) $info['http_code'];
        $results[$i] = [
            'http_code'       => $code,
            'total_ms'        => (int) round($info['total_time']         * 1000),
            'ttfb_ms'         => (int) round($info['starttransfer_time'] * 1000),
            'connect_ms'      => (int) round($info['connect_time']       * 1000),
            'pretransfer_ms'  => (int) round($info['pretransfer_time']   * 1000),
            'namelookup_ms'   => (int) round($info['namelookup_time']    * 1000),
            'success'         => ($code === 200),
            'curl_errno'      => curl_errno($ch),
            'curl_error'      => curl_error($ch),
            'os_errno'        => (int) ($info['os_errno'] ?? 0),
            'body_preview'    => $code !== 200 ? substr($body, 0, 300) : '',
        ];
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
    }
    curl_multi_close($mh);

    $results['_mid'] = $midSnapshot;
    return $results;
}


function compute_batch_stats(array $results, array $before, array $after, int $batchNum): array
{
    $mid  = $results['_mid'] ?? null;
    $reqs = array_filter($results, fn($k) => is_int($k), ARRAY_FILTER_USE_KEY);
    $times   = array_column(array_values($reqs), 'total_ms');
    $success = array_filter($reqs, fn($r) => (bool) $r['success']);
    $failure = array_filter($reqs, fn($r) => !(bool) $r['success']);
    sort($times);
    $n = count($times);
    $pct = static function (float $p) use ($times, $n): int {
        if ($n === 0) return 0;
        return (int) $times[max(0, min($n - 1, (int) ceil($p / 100 * $n) - 1))];
    };
    return [
        'batch'        => $batchNum,
        'total'        => $n,
        'success'      => count($success),
        'failure'      => count($failure),
        'success_rate' => $n > 0 ? round(count($success) / $n * 100, 1) : 0.0,
        'avg_ms'       => $n > 0 ? (int) round(array_sum($times) / $n) : 0,
        'min_ms'       => $n > 0 ? (int) $times[0] : 0,
        'max_ms'       => $n > 0 ? (int) $times[$n - 1] : 0,
        'p50_ms'       => $pct(50),
        'p95_ms'       => $pct(95),
        'p99_ms'       => $pct(99),
        'cpu_before'   => $before['cpu'],
        'cpu_mid'      => $mid['cpu'] ?? null,
        'cpu_after'    => $after['cpu'],
        'mem_before'   => $before['mem_used'],
        'mem_mid'      => $mid['mem_used'] ?? null,
        'mem_after'    => $after['mem_used'],
        'mem_total'    => $before['mem_total'],
        'errors'       => array_values(array_slice($failure, 0, 20)),
        'times'        => $times,   // sorted individual ms values for histogram
    ];
}


function build_batch_row(array $s): string
{
    $rateClass = $s['success_rate'] >= 99 ? 'good' : ($s['success_rate'] >= 90 ? 'warn' : 'bad');
    $failClass = $s['failure'] > 0 ? ' class="fail-cell"' : '';
    $cpuMid    = $s['cpu_mid']  !== null ? number_format($s['cpu_mid'],  1) . '%' : '&mdash;';
    $memMid    = $s['mem_mid']  !== null ? number_format($s['mem_mid'],  1)       : '&mdash;';
    $started = isset($s['started_at_s']) ? sprintf('T+%.0fs', $s['started_at_s']) : '—';
    $ended   = isset($s['ended_at_s'])   ? sprintf('T+%.0fs', $s['ended_at_s'])   : '—';
    return sprintf(
        '<tr><td>%d</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td%s>%d</td>'
        . '<td class="rate %s">%s%%</td>'
        . '<td>%s ms</td><td>%s ms</td><td>%s ms</td><td>%s ms</td>'
        . '<td>%.1f%% / %s / %.1f%%</td>'
        . '<td>%.1f / %s / %.1f MB</td></tr>',
        $s['batch'], $started, $ended, $s['total'], $s['success'], $failClass, $s['failure'],
        $rateClass, number_format($s['success_rate'], 1),
        number_format($s['avg_ms']), number_format($s['p50_ms']),
        number_format($s['p95_ms']), number_format($s['p99_ms']),
        $s['cpu_before'], $cpuMid, $s['cpu_after'],
        $s['mem_before'], $memMid, $s['mem_after']
    );
}


/* ==================================================================
 *  5. STREAM: output HTML progressively so nginx stays happy
 * ================================================================== */

// Kill any existing output buffers so flush() actually sends to nginx
while (ob_get_level() > 0) {
    ob_end_clean();
}

header('Content-Type: text/html; charset=utf-8');
header('X-Accel-Buffering: no');     // tell nginx/proxy: do not buffer this response
header('Cache-Control: no-cache, no-store');

/**
 * Pad output to 4 KB so it clears nginx's default proxy buffer,
 * then flush PHP's and the web server's output buffers.
 */
function stream_flush(): void
{
    echo "\n" . str_repeat(' ', 4096);
    flush();
}

$startTime = date('Y-m-d H:i:s');

// ---- Output the full HTML shell immediately ----
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ResearchChatAI Stress Test — Running...</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body   { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #f5f6fa; color: #2d3436; line-height: 1.5; }
  header { background: #2d3436; color: #fff; padding: 24px 32px; }
  header h1 { font-size: 1.4rem; font-weight: 700; }
  header p  { margin-top: 6px; opacity: .7; font-size: .85rem; }
  .wrap  { max-width: 1140px; margin: 0 auto; padding: 32px 20px; }
  section { margin-bottom: 40px; }
  h2 { font-size: 1rem; font-weight: 700; text-transform: uppercase; letter-spacing: .06em;
       color: #636e72; border-bottom: 2px solid #dfe6e9; padding-bottom: 8px; margin-bottom: 16px; }

  /* Progress */
  #progress { background:#fff; border-radius:10px; padding:24px 28px; margin-bottom:32px;
              box-shadow:0 1px 4px rgba(0,0,0,.08); }
  #progress p { font-size:.9rem; color:#636e72; margin-bottom:12px; }
  .prog-bar  { background:#dfe6e9; border-radius:6px; height:10px; overflow:hidden; }
  .prog-fill { background:#0984e3; height:100%; transition:width .4s ease; }

  /* Cards */
  .cards { display: flex; flex-wrap: wrap; gap: 14px; }
  .card  { background: #fff; border-radius: 10px; padding: 18px 22px; flex: 1; min-width: 140px;
           box-shadow: 0 1px 4px rgba(0,0,0,.08); }
  .card .lbl { font-size: .72rem; text-transform: uppercase; letter-spacing: .07em; color: #636e72; }
  .card .val { font-size: 2rem; font-weight: 800; margin-top: 2px; }
  .card .val.good { color: #00b894; }
  .card .val.warn { color: #e17055; }
  .card .val.bad  { color: #d63031; }

  /* Tables */
  .tbl-wrap { overflow-x: auto; }
  table  { width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px;
           box-shadow: 0 1px 4px rgba(0,0,0,.08); overflow: hidden; white-space: nowrap; }
  th     { background: #2d3436; color: #fff; padding: 10px 14px; font-size: .78rem;
           text-align: left; font-weight: 600; letter-spacing: .03em; }
  td     { padding: 10px 14px; font-size: .83rem; border-bottom: 1px solid #f0f2f3; }
  tr:last-child td { border-bottom: none; }
  tr:nth-child(even) { background: #fafbfc; }
  .fail-cell { color: #d63031; font-weight: 700; }
  .rate.good  { color: #00b894; font-weight: 700; }
  .rate.warn  { color: #e17055; font-weight: 700; }
  .rate.bad   { color: #d63031; font-weight: 700; }
  .no-errors  { text-align: center; color: #00b894; padding: 16px !important; }

  /* Charts */
  .charts { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
  .chart-box { background: #fff; border-radius: 10px; padding: 20px;
               box-shadow: 0 1px 4px rgba(0,0,0,.08); }
  .chart-box h3 { font-size: .78rem; text-transform: uppercase; letter-spacing: .06em;
                  color: #636e72; margin-bottom: 14px; }
  .chart-box.full { grid-column: 1 / -1; }

  @media (max-width: 900px) { .charts { grid-template-columns: 1fr; } .chart-box.full { grid-column: auto; } }
  @media (max-width: 580px) { .cards { flex-direction: column; } }
</style>
</head>
<body>

<header>
  <h1>ResearchChatAI &mdash; Stress Test Report</h1>
  <p>
    <?= htmlspecialchars($startTime) ?> &nbsp;&middot;&nbsp;
    Model: <strong><?= htmlspecialchars($model) ?></strong> &nbsp;&middot;&nbsp;
    Reasoning: <strong><?= htmlspecialchars($reasoning) ?></strong> &nbsp;&middot;&nbsp;
    <?= $users ?> parallel requests/batch &nbsp;&middot;&nbsp;
    <?= $batches ?> batch<?= $batches !== 1 ? 'es' : '' ?> &nbsp;&middot;&nbsp;
    <?= $delay ?>s delay &nbsp;&middot;&nbsp;
    Mode: <strong><?= $overlap ? 'overlapping' : 'sequential' ?></strong>
  </p>
</header>

<div class="wrap">

  <!-- Live progress (removed when done) -->
  <div id="progress">
    <p id="prog-text">Starting batch 1 of <?= $batches ?>…</p>
    <div class="prog-bar"><div class="prog-fill" id="prog-fill" style="width:0%"></div></div>
  </div>

  <!-- Summary cards (hidden until all batches done) -->
  <section id="sec-cards" style="display:none">
    <div class="cards">
      <div class="card"><div class="lbl">Total Requests</div><div class="val" id="c-total">—</div></div>
      <div class="card"><div class="lbl">Success Rate</div><div class="val" id="c-rate">—</div></div>
      <div class="card"><div class="lbl">Avg Response</div><div class="val" id="c-avg">—</div></div>
      <div class="card"><div class="lbl">P95 Response</div><div class="val" id="c-p95">—</div></div>
      <div class="card"><div class="lbl">Failed Requests</div><div class="val" id="c-fail">—</div></div>
      <div class="card"><div class="lbl">Peak CPU</div><div class="val" id="c-cpu">—</div></div>
    </div>
  </section>

  <!-- Batch results (rows streamed in as each batch completes) -->
  <section>
    <h2>Batch Results</h2>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>Batch</th><th>Started</th><th>Ended</th><th>Total</th><th>OK</th><th>Fail</th><th>Rate</th>
            <th>Avg</th><th>P50</th><th>P95</th><th>P99</th>
            <th>CPU before / mid / after</th>
            <th>RAM used before / mid / after</th>
          </tr>
        </thead>
        <tbody id="batch-body"></tbody>
      </table>
    </div>
  </section>

  <!-- Charts (hidden until all batches done) -->
  <section id="sec-charts" style="display:none">
    <h2>Charts</h2>
    <div class="charts">
      <div class="chart-box"><h3>Response Time per Batch (ms)</h3><canvas id="chartLatency"></canvas></div>
      <div class="chart-box"><h3>Response Time Distribution — all requests</h3><canvas id="chartHist"></canvas></div>
      <div class="chart-box"><h3>CPU Usage (%)</h3><canvas id="chartCpu"></canvas></div>
      <div class="chart-box"><h3>RAM Used (MB)</h3><canvas id="chartMem"></canvas></div>
    </div>
  </section>

  <!-- Error log (hidden until all batches done) -->
  <section id="sec-errors" style="display:none">
    <h2>Error Log</h2>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>Batch</th><th>HTTP</th><th>Total</th><th>DNS</th><th>Connect</th><th>TLS done</th><th>curl errno</th><th>OS errno</th><th>Body / Error</th></tr></thead>
        <tbody id="error-body"></tbody>
      </table>
    </div>
  </section>

</div><!-- /.wrap -->
<?php
stream_flush();   // send the shell to the browser immediately


/* ==================================================================
 *  6. RUN BATCHES — flush each result as it arrives
 * ================================================================== */

$allStats      = [];
$lastHeartbeat = microtime(true);
$testStartTime = microtime(true);   // reference point for "started at" column

if ($overlap === 0) {

    /* ----------------------------------------------------------
     *  SEQUENTIAL mode: wait for each batch to finish, then delay
     * ---------------------------------------------------------- */
    for ($b = 1; $b <= $batches; $b++) {
        $batchStartedAt = round(microtime(true) - $testStartTime, 0);
        $before      = sample_server_stats();
        $batchResult = run_openai_batch($users, $model, $openaiKey, $reasoning, $testMessage, $b, $batches);
        $after       = sample_server_stats();
        $batchEndedAt = round(microtime(true) - $testStartTime, 0);
        $stats       = compute_batch_stats($batchResult, $before, $after, $b);
        $stats['started_at_s'] = $batchStartedAt;
        $stats['ended_at_s']   = $batchEndedAt;
        $allStats[]  = $stats;

        $row      = build_batch_row($stats);
        $pct      = (int) round($b / $batches * 100);
        $progText = $b < $batches
            ? "Batch $b done — waiting {$delay}s before next batch…"
            : 'All batches complete!';

        echo '<script>';
        echo 'document.getElementById("batch-body").insertAdjacentHTML("beforeend",' . json_encode($row) . ');';
        echo 'document.getElementById("prog-text").textContent=' . json_encode($progText) . ';';
        echo 'document.getElementById("prog-fill").style.width=' . json_encode($pct . '%') . ';';
        echo '</script>';
        stream_flush();

        if ($b < $batches && $delay > 0) {
            sleep($delay);
        }
    }

} else {

    /* ----------------------------------------------------------
     *  OVERLAPPING mode: batches start $delay seconds apart,
     *  regardless of whether the previous batch has finished.
     *  One shared curl_multi handle holds all in-flight requests.
     * ---------------------------------------------------------- */

    // Pre-compute request config (same logic as run_openai_batch)
    $responsesModels = ['gpt-6-sol', 'gpt-6-astra', 'gpt-6-luna', 'gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5', 'gpt-5-mini'];
    $useResponsesApi = in_array($model, $responsesModels, true);
    $url       = $useResponsesApi
        ? 'https://api.openai.com/v1/responses'
        : 'https://api.openai.com/v1/chat/completions';
    $maxTokens = ($reasoning === 'high') ? 2000 : (($reasoning === 'medium') ? 1000 : 400);
    $payload   = $useResponsesApi
        ? json_encode(['model' => $model, 'input' => $testMessage, 'max_output_tokens' => $maxTokens,
                       'reasoning' => ['effort' => $reasoning]], JSON_THROW_ON_ERROR)
        : json_encode(['model' => $model, 'messages' => [['role' => 'user', 'content' => $testMessage]],
                       'max_tokens' => $maxTokens], JSON_THROW_ON_ERROR);
    $curlOpts  = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . $openaiKey, 'Content-Type: application/json'],
        CURLOPT_TIMEOUT        => 120,
        CURLOPT_CONNECTTIMEOUT => 10,
    ];

    $mh         = curl_multi_init();
    $handleMeta = [];   // (int)$ch => batch number
    $batchState = [];   // batchNum => ['before','startedAt','pending','results','mid','midDone']
    $nextBatch  = 1;
    $running    = null;
    $loopStart  = microtime(true);

    do {
        $elapsed = microtime(true) - $loopStart;

        // Launch the next batch when its scheduled start time arrives
        while ($nextBatch <= $batches && $elapsed >= ($nextBatch - 1) * $delay) {
            $b = $nextBatch++;
            $batchState[$b] = [
                'before'    => sample_server_stats(),
                'startedAt' => microtime(true),
                'pending'   => $users,
                'results'   => [],
                'mid'       => null,
                'midDone'   => false,
            ];
            for ($i = 0; $i < $users; $i++) {
                $ch = curl_init($url);
                curl_setopt_array($ch, $curlOpts);
                curl_multi_add_handle($mh, $ch);
                $handleMeta[(int) $ch] = $b;
            }
        }

        if ($running > 0) {
            curl_multi_exec($mh, $running);
            $wait = curl_multi_select($mh, 0.5);
            if ($wait === -1) usleep(10000);
        } else {
            // No active handles yet (gap between batch completions and next batch start)
            usleep(100000);
            curl_multi_exec($mh, $running);
        }

        // Mid-batch snapshots (3s after each batch starts)
        foreach ($batchState as $b => &$bs) {
            if (!$bs['midDone'] && (microtime(true) - $bs['startedAt']) >= 3.0) {
                $bs['mid']     = sample_server_stats();
                $bs['midDone'] = true;
            }
        }
        unset($bs);

        // Heartbeat every 5s
        if (microtime(true) - $lastHeartbeat >= 5.0) {
            $parts = [];
            foreach ($batchState as $b => $bs) {
                if ($bs['pending'] > 0) {
                    $parts[] = "Batch {$b}: {$bs['pending']} pending";
                }
            }
            $msg = count($parts) ? implode(' · ', $parts) : 'Finishing…';
            echo '<script>document.getElementById("prog-text").textContent=' . json_encode($msg) . ';</script>' . "\n";
            flush();
            $lastHeartbeat = microtime(true);
        }

        // Process completions
        while (($info = curl_multi_info_read($mh)) !== false) {
            if ($info['msg'] !== CURLMSG_DONE) {
                continue;
            }
            $ch   = $info['handle'];
            $b    = $handleMeta[(int) $ch];
            $ci   = curl_getinfo($ch);
            $body = (string) curl_multi_getcontent($ch);
            $code = (int) $ci['http_code'];

            $batchState[$b]['results'][] = [
                'http_code'      => $code,
                'total_ms'       => (int) round($ci['total_time']         * 1000),
                'ttfb_ms'        => (int) round($ci['starttransfer_time'] * 1000),
                'connect_ms'     => (int) round($ci['connect_time']       * 1000),
                'pretransfer_ms' => (int) round($ci['pretransfer_time']   * 1000),
                'namelookup_ms'  => (int) round($ci['namelookup_time']    * 1000),
                'success'        => ($code === 200),
                'curl_errno'     => curl_errno($ch),
                'curl_error'     => curl_error($ch),
                'os_errno'       => (int) ($ci['os_errno'] ?? 0),
                'body_preview'   => $code !== 200 ? substr($body, 0, 300) : '',
            ];
            $batchState[$b]['pending']--;
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
            unset($handleMeta[(int) $ch]);

            // When every handle for this batch is done → compute stats + stream row
            if ($batchState[$b]['pending'] === 0) {
                $after        = sample_server_stats();
                $batchEndedAt = round(microtime(true) - $testStartTime, 0);
                $indexed = [];
                foreach ($batchState[$b]['results'] as $i => $r) {
                    $indexed[$i] = $r;
                }
                $indexed['_mid'] = $batchState[$b]['mid'];
                $stats      = compute_batch_stats($indexed, $batchState[$b]['before'], $after, $b);
                $stats['started_at_s'] = round($batchState[$b]['startedAt'] - $testStartTime, 0);
                $stats['ended_at_s']   = $batchEndedAt;
                $allStats[] = $stats;
                $done       = count($allStats);
                $pct        = (int) round($done / $batches * 100);
                $progText   = $done < $batches
                    ? "Batch {$b} complete ({$done}/{$batches})…"
                    : 'All batches complete!';
                $row = build_batch_row($stats);
                echo '<script>';
                echo 'document.getElementById("batch-body").insertAdjacentHTML("beforeend",' . json_encode($row) . ');';
                echo 'document.getElementById("prog-text").textContent=' . json_encode($progText) . ';';
                echo 'document.getElementById("prog-fill").style.width=' . json_encode($pct . '%') . ';';
                echo '</script>';
                stream_flush();
            }
        }

        $elapsed = microtime(true) - $loopStart;
    } while ($running > 0 || $nextBatch <= $batches);

    curl_multi_close($mh);

}


/* ==================================================================
 *  7. FINALIZE — inject summary cards, charts, error log
 * ================================================================== */

$totalReqs    = (int) array_sum(array_column($allStats, 'total'));
$totalSuccess = (int) array_sum(array_column($allStats, 'success'));
$totalFail    = (int) array_sum(array_column($allStats, 'failure'));
$overallRate  = $totalReqs > 0 ? round($totalSuccess / $totalReqs * 100, 1) : 0.0;
$overallAvg   = count($allStats) > 0
    ? (int) round(array_sum(array_column($allStats, 'avg_ms')) / count($allStats)) : 0;
$overallP95   = count($allStats) > 0 ? (int) max(array_column($allStats, 'p95_ms')) : 0;

$allCpuValues = array_filter(array_merge(
    array_column($allStats, 'cpu_before'),
    array_column($allStats, 'cpu_mid'),
    array_column($allStats, 'cpu_after'),
), fn($v) => $v !== null);
$peakCpu = count($allCpuValues) > 0 ? (float) max($allCpuValues) : 0.0;

$rateCardClass = $overallRate >= 99 ? 'good' : ($overallRate >= 90 ? 'warn' : 'bad');
$failCardClass = $totalFail > 0 ? 'bad' : 'good';

// Build error rows HTML
$errorRowsHtml = '';
foreach ($allStats as $s) {
    foreach ($s['errors'] as $err) {
        if ($err['curl_errno'] !== 0) {
            $detail = 'curl ' . $err['curl_errno'] . ': ' . $err['curl_error'];
        } elseif (!empty($err['body_preview'])) {
            $detail = substr($err['body_preview'], 0, 200);
        } else {
            $detail = 'No response body (connection reset or dropped by peer)';
        }
        $errorRowsHtml .= sprintf(
            '<tr><td>%d</td><td>%d</td><td>%d ms</td><td>%d ms</td><td>%d ms</td><td>%d ms</td><td>%d</td><td>%d</td><td>%s</td></tr>',
            $s['batch'],
            $err['http_code'],
            $err['total_ms'],
            $err['namelookup_ms'],
            $err['connect_ms'],
            $err['pretransfer_ms'],
            $err['curl_errno'],
            $err['os_errno'],
            htmlspecialchars($detail)
        );
    }
}
if ($errorRowsHtml === '') {
    $errorRowsHtml = '<tr><td colspan="4" class="no-errors">No errors — all requests succeeded</td></tr>';
}

// Collect all individual response times for histogram
$allTimes = [];
foreach ($allStats as $s) {
    $allTimes = array_merge($allTimes, $s['times']);
}
sort($allTimes);

// Chart data
$chartData = json_encode([
    'labels'   => array_map(fn($s) => 'Batch ' . $s['batch'], $allStats),
    'avg_ms'   => array_column($allStats, 'avg_ms'),
    'p95_ms'   => array_column($allStats, 'p95_ms'),
    'p99_ms'   => array_column($allStats, 'p99_ms'),
    'cpu_b'    => array_column($allStats, 'cpu_before'),
    'cpu_m'    => array_column($allStats, 'cpu_mid'),
    'cpu_a'    => array_column($allStats, 'cpu_after'),
    'mem_b'    => array_column($allStats, 'mem_before'),
    'mem_m'    => array_column($allStats, 'mem_mid'),
    'mem_a'    => array_column($allStats, 'mem_after'),
    'all_times'=> $allTimes,
], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

?>
<script>
// Remove progress bar, show finished sections
document.getElementById('progress').remove();
document.getElementById('sec-cards').style.display   = '';
document.getElementById('sec-charts').style.display  = '';
document.getElementById('sec-errors').style.display  = '';

// Fill summary cards
document.getElementById('c-total').textContent = <?= json_encode($totalReqs) ?>;
document.getElementById('c-rate').textContent  = <?= json_encode(number_format($overallRate, 1) . '%') ?>;
document.getElementById('c-avg').textContent   = <?= json_encode(number_format($overallAvg) . ' ms') ?>;
document.getElementById('c-p95').textContent   = <?= json_encode(number_format($overallP95) . ' ms') ?>;
document.getElementById('c-fail').textContent  = <?= json_encode($totalFail) ?>;
document.getElementById('c-cpu').textContent   = <?= json_encode(number_format($peakCpu, 1) . '%') ?>;

// Colour the rate / fail cards
document.getElementById('c-rate').className = 'val <?= $rateCardClass ?>';
document.getElementById('c-fail').className = 'val <?= $failCardClass ?>';

// Error log
document.getElementById('error-body').innerHTML = <?= json_encode($errorRowsHtml) ?>;

// Charts
document.title = 'ResearchChatAI Stress Test Report';
const D = <?= $chartData ?>;
const baseOpts = {
  responsive: true, maintainAspectRatio: true,
  plugins: { legend: { position: 'bottom', labels: { boxWidth: 11, font: { size: 11 } } } },
  scales: {
    x: { grid: { display: false }, ticks: { font: { size: 11 } } },
    y: { beginAtZero: true, ticks: { font: { size: 11 } } }
  }
};
new Chart(document.getElementById('chartLatency'), {
  type: 'bar',
  data: { labels: D.labels, datasets: [
    { label: 'Avg',  data: D.avg_ms, backgroundColor: '#74b9ff' },
    { label: 'P95',  data: D.p95_ms, backgroundColor: '#0984e3' },
    { label: 'P99',  data: D.p99_ms, backgroundColor: '#2d3436' },
  ]},
  options: { ...baseOpts, scales: { ...baseOpts.scales,
    y: { ...baseOpts.scales.y, title: { display: true, text: 'ms' } } } }
});

// Histogram: bucket all individual response times
(function() {
  const times = D.all_times;
  if (!times || !times.length) return;
  const maxT    = Math.max(...times);
  const bucket  = 1000;  // 1-second buckets
  const nBuck   = Math.ceil(maxT / bucket) + 1;
  const counts  = new Array(nBuck).fill(0);
  times.forEach(t => counts[Math.floor(t / bucket)]++);
  const labels  = counts.map((_, i) => `${i + 1}s`);
  new Chart(document.getElementById('chartHist'), {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Requests', data: counts, backgroundColor: '#a29bfe',
                                  borderColor: '#6c5ce7', borderWidth: 1 }] },
    options: { ...baseOpts,
      plugins: { ...baseOpts.plugins, legend: { display: false } },
      scales: { ...baseOpts.scales,
        x: { ...baseOpts.scales.x, title: { display: true, text: 'Response time' } },
        y: { beginAtZero: true, title: { display: true, text: 'Requests' },
             ticks: { font: { size: 11 }, stepSize: 1 } } } }
  });
})();
new Chart(document.getElementById('chartCpu'), {
  type: 'bar',
  data: { labels: D.labels, datasets: [
    { label: 'Before',     data: D.cpu_b, backgroundColor: '#81ecec' },
    { label: 'Mid (peak)', data: D.cpu_m, backgroundColor: '#00b894' },
    { label: 'After',      data: D.cpu_a, backgroundColor: '#55efc4' },
  ]},
  options: { ...baseOpts, scales: { ...baseOpts.scales,
    y: { beginAtZero: true, max: 100, title: { display: true, text: '%' }, ticks: { font: { size: 11 } } } } }
});
new Chart(document.getElementById('chartMem'), {
  type: 'bar',
  data: { labels: D.labels, datasets: [
    { label: 'Before', data: D.mem_b, backgroundColor: '#fdcb6e' },
    { label: 'Mid',    data: D.mem_m, backgroundColor: '#e17055' },
    { label: 'After',  data: D.mem_a, backgroundColor: '#fab1a0' },
  ]},
  options: { ...baseOpts, scales: { ...baseOpts.scales,
    y: { beginAtZero: false, title: { display: true, text: 'MB' }, ticks: { font: { size: 11 } } } } }
});
</script>
</body>
</html>
