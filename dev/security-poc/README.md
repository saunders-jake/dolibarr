# Public ticket document link — PoC helper

This directory contains a small proof-of-concept helper for the public ticket document download URL (`htdocs/public/ticket/document.php`).

## Why this exists

The script reproduces the same `securekey` formula Dolibarr uses when `TICKET_ENABLE_PUBLIC_INTERFACE` is enabled:

`sha256("dolibarr-" + relative_file_path + "-" + $dolibarr_main_instance_unique_id)`

See `htdocs/public/ticket/document.php` and `htdocs/ticket/class/actions_ticket.class.php`.

## Usage

```bash
php dev/security-poc/poc_public_ticket_document.php \
  --instance-id 'YOUR_DOLIBARR_MAIN_INSTANCE_UNIQUE_ID' \
  --file 'TICKETREF/poc-secret.txt'
```

Optional: HTTP probe (requires a reachable Dolibarr base URL):

```bash
php dev/security-poc/poc_public_ticket_document.php \
  --instance-id 'YOUR_ID' \
  --file 'TICKETREF/poc-secret.txt' \
  --base-url 'https://dolibarr.example.com' \
  --entity 1
```

Or use the shell wrapper:

```bash
export DOLI_BASE_URL='https://dolibarr.example.com'
export DOLI_INSTANCE_UNIQUE_ID='...'
export DOLI_FILE='TICKETREF/poc-secret.txt'
./dev/security-poc/poc_public_ticket_document.sh
```

## Preconditions on the target instance

1. `TICKET_ENABLE_PUBLIC_INTERFACE` must be set (public ticket interface enabled).
2. The file must exist under the ticket document directory at  
   `{multidir_output[ticket]}/{file}` as used by `getMultidirOutput()` for module `ticket`.
3. You must know `dolibarr_main_instance_unique_id` from `conf.php` (or from a leaked link).

## This workspace

There is **no** Dolibarr web instance or `conf.php` in this CI workspace, so the PoC **verifies the hash algorithm locally** and only performs an HTTP request when you pass `--base-url`.
