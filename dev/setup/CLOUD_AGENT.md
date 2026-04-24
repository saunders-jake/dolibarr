# Dolibarr setup in this workspace (Cloud Agent / CI)

## What you have here

- **`htdocs/conf/conf.php`** is present but **empty** (0 bytes). Dolibarr treats that as “not installed”: the app redirects to **`/install/`** until configuration is written.
- This VM has **PHP** and **curl**, but **no Docker**, **no `mysql`/`mariadb` client**, and **no database server** listening on `127.0.0.1:3306` or `:5432`.
- So there is **no pre-provisioned Dolibarr instance** to hit unless you start one yourself (Docker on your machine, or a remote URL).

## Intended ways to get a runnable instance

### Option A — Docker (recommended in repo docs)

See **`dev/build/docker/README.md`**. On a host **with Docker**:

```bash
cd dev/build/docker
export HOST_USER_ID=$(id -u) HOST_GROUP_ID=$(id -g)
export MYSQL_ROOT_PWD="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16; echo)"
docker compose build && docker compose up -d
```

Then open **`http://0.0.0.0:8080`** and complete the installer wizard (or use your org’s forced-install flow).

### Option B — Your own stack

Install MariaDB/MySQL (or PostgreSQL), point the web server at **`htdocs/`**, run **`/install/`**, then use your real base URL for API or PoC scripts.

### Option C — PHP built-in server (after `conf.php` exists)

From repo root, **only after** `htdocs/conf/conf.php` is valid:

```bash
php -S 127.0.0.1:8765 -t htdocs
```

Browse `http://127.0.0.1:8765/`. This is suitable for quick checks; production should use Apache/nginx.

## CI / PHPUnit database setup (reference)

The script **`dev/setup/phpunit/setup_conf.sh`** generates a **`conf.php`** for Travis-style runs (example instance id `travis1234567890`) and expects **MySQL/MariaDB** on localhost. It is **not** run automatically in this cloud workspace.

## SQLite note (this tree)

Running **`php htdocs/install/step1.php ... sqlite3 ...`** in this workspace hit a **PHP fatal error** in `DoliDBSqlite3` (`dbIF()` reflection). Do not assume SQLite install works without fixing that driver first.

## Security PoC against a real instance

After you have a URL and `dolibarr_main_instance_unique_id` from **`conf.php`**, use:

```bash
php dev/security-poc/poc_public_ticket_document.php --instance-id '…' --file '…' --base-url 'http://127.0.0.1:8080'
```

See **`dev/security-poc/README.md`**.
