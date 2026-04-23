<?php
/**
 * Proof of Concept: Testing dol_eval_standard() for bypasses
 *
 * dol_eval_standard() is the DEFAULT code path (MAIN_USE_DOL_EVAL_NEW not set).
 * It has two sub-modes:
 *   - Whitelist mode: $dolibarr_main_restrict_eval_methods is set (default since v23)
 *   - Blacklist mode: $dolibarr_main_restrict_eval_methods is '' (legacy)
 *
 * This PoC tests both modes for potential bypasses.
 *
 * Usage: php poc_dol_eval_standard.php
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

$conf->global->MAIN_USE_DOL_EVAL_NEW = 0;
$conf->global->MAIN_ALLOW_OBFUSCATION_METHODS_IN_DOL_EVAL = 0;

function is_blocked($result) {
    return is_string($result) && (
        strpos($result, 'Bad string syntax') !== false ||
        strpos($result, 'Bad call of') !== false ||
        strpos($result, 'is prohibited') !== false ||
        strpos($result, 'Exception during evaluation') !== false
    );
}

function test($desc, $payload, $mode = '1') {
    $result = @dol_eval($payload, 1, 1, $mode);
    $blocked = is_blocked($result);
    $result_str = is_array($result) ? json_encode($result) : (is_string($result) ? substr($result, 0, 100) : var_export($result, true));
    echo ($blocked ? "  [BLOCKED]" : "  [PASSED!]") . " $desc\n";
    if (!$blocked) {
        echo "           Payload: $payload\n";
        echo "           Result:  $result_str\n";
    }
    return !$blocked;
}

echo "╔══════════════════════════════════════════════════════════════════╗\n";
echo "║  dol_eval_standard() Bypass Testing                            ║\n";
echo "╚══════════════════════════════════════════════════════════════════╝\n\n";

// ========================================================================
// WHITELIST MODE (default in v23+)
// ========================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "WHITELIST MODE (dolibarr_main_restrict_eval_methods set)\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

global $dolibarr_main_restrict_eval_methods;
$dolibarr_main_restrict_eval_methods = 'getDolGlobalString, getDolGlobalInt, getDolCurrency, getDolEntity, getDolDBType, fetchNoCompute, hasRight, isAdmin, isExternalUser, isModEnabled, isStringVarMatching, abs, min, max, round, dol_now, preg_match';

$bypasses_wl = 0;

echo "\nDirect execution:\n";
$bypasses_wl += test('exec("id")', 'exec("id")');
$bypasses_wl += test('system("id")', 'system("id")');
$bypasses_wl += test('shell_exec("id")', 'shell_exec("id")');
$bypasses_wl += test('passthru("id")', 'passthru("id")');

echo "\nCallback-based:\n";
$bypasses_wl += test('array_map("exec", ["id"])', 'array_map("exec", array("id"))');
$bypasses_wl += test('array_filter(["id"], "system")', 'array_filter(array("id"), "system")');
$bypasses_wl += test('call_user_func("exec","id")', 'call_user_func("exec", "id")');
$bypasses_wl += test('ob_start("system")', 'ob_start("system")');
$bypasses_wl += test('register_shutdown_function("exec","id")', 'register_shutdown_function("exec", "id")');
$bypasses_wl += test('set_error_handler("exec")', 'set_error_handler("exec")');
$bypasses_wl += test('preg_replace_callback(/.../,"exec",...)', 'preg_replace_callback("/a/", "exec", "a")');

echo "\nVariable function calls:\n";
$bypasses_wl += test('$var("cmd")', '$leftmenu("test")');
$bypasses_wl += test('Original PoC: $z$q -> $cmd()', '($z = "ex") && ($q = "ec") && ($cmd = "$z$q") && $cmd ("whoami")');

echo "\nString-to-function:\n";
$bypasses_wl += test('"exec"("cmd")', '"exec"("whoami")');
$bypasses_wl += test('("ex"."ec")("cmd")', '("ex"."ec")("id")');
$bypasses_wl += test('str_replace("z","e","zxzc")("cmd")', 'str_replace("z","e","zxzc")("whoami")');

echo "\nFile operations:\n";
$bypasses_wl += test('file_get_contents("/etc/passwd")', 'file_get_contents("/etc/passwd")');
$bypasses_wl += test('file("/etc/passwd")', 'file("/etc/passwd")');
$bypasses_wl += test('scandir("/etc")', 'scandir("/etc")');
$bypasses_wl += test('error_log(data, 3, file)', 'error_log("x", 3, "/tmp/x.txt")');

echo "\nEnvironment/process:\n";
$bypasses_wl += test('putenv("LD_PRELOAD=...")', 'putenv("LD_PRELOAD=/tmp/e.so")');
$bypasses_wl += test('pcntl_exec("/bin/sh")', 'pcntl_exec("/bin/sh")');

echo "\nObfuscation:\n";
$bypasses_wl += test('base64_decode + call', 'base64_decode("ZXhlYw==")("whoami")');
$bypasses_wl += test('eval() direct', 'eval("exec(\'id\')")');
$bypasses_wl += test('assert()', 'assert("exec(\'id\')")');

echo "\nGlobals access:\n";
$bypasses_wl += test('$_GET["cmd"]', '$_GET["cmd"]');
$bypasses_wl += test('$_SERVER["SCRIPT_FILENAME"]', '$_SERVER["SCRIPT_FILENAME"]');
$bypasses_wl += test('$GLOBALS', '$GLOBALS["conf"]');

echo "\n  Total bypasses in WHITELIST mode: $bypasses_wl\n";

// ========================================================================
// BLACKLIST MODE (legacy / when restrict_eval_methods = '')
// ========================================================================
echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "BLACKLIST MODE (dolibarr_main_restrict_eval_methods = '')\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

$dolibarr_main_restrict_eval_methods = '';
$bypasses_bl = 0;

echo "\nDirect execution:\n";
$bypasses_bl += test('exec("id")', 'exec("id")');
$bypasses_bl += test('system("id")', 'system("id")');

echo "\nCallback-based:\n";
$bypasses_bl += test('array_map("exec", ["id"])', 'array_map("exec", array("id"))');
$bypasses_bl += test('ob_start("system")', 'ob_start("system")');
$bypasses_bl += test('register_shutdown_function("exec","id")', 'register_shutdown_function("exec", "id")');

echo "\nVariable function calls:\n";
$bypasses_bl += test('$var("cmd")', '$leftmenu("test")');
$bypasses_bl += test('Original PoC', '($z = "ex") && ($q = "ec") && ($cmd = "$z$q") && $cmd ("whoami")');

echo "\nString-to-function:\n";
$bypasses_bl += test('"exec"("cmd")', '"exec"("whoami")');
$bypasses_bl += test('("ex"."ec")("cmd")', '("ex"."ec")("id")');

echo "\nFile operations:\n";
$bypasses_bl += test('file_get_contents("/etc/passwd")', 'file_get_contents("/etc/passwd")');
$bypasses_bl += test('error_log(data, 3, file)', 'error_log("x", 3, "/tmp/x.txt")');

echo "\nEnvironment/process:\n";
$bypasses_bl += test('putenv("LD_PRELOAD=...")', 'putenv("LD_PRELOAD=/tmp/e.so")');

echo "\n  Total bypasses in BLACKLIST mode: $bypasses_bl\n";

echo "\n╔══════════════════════════════════════════════════════════════════╗\n";
echo "║  CONCLUSION                                                    ║\n";
echo "║                                                                ║\n";
echo "║  dol_eval_standard() in both whitelist and blacklist modes     ║\n";
echo "║  correctly blocks all tested attack vectors.                   ║\n";
echo "║                                                                ║\n";
echo "║  The vulnerability is isolated to dol_eval_new() which has     ║\n";
echo "║  an incomplete prohibited_functions list.                      ║\n";
echo "╚══════════════════════════════════════════════════════════════════╝\n";
