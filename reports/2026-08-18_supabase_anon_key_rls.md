# CRITICAL-CLASS CONFIG: Supabase anon key + open RLS + GraphQL write permissions (CF Optimizer)
SEVERITY: HIGH (was: Low — upgraded after GraphQL discovery)

## Summary
Production app bundle at app.cfoptimizer.com/assets/index-DO8kisOM.js ships a live Supabase
anon key for hyrcvhzrnfbppyzuuosp.supabase.co. With ONLY that key (no account, no login):
- LIVE billing/config data is readable (subscription_plans x3, token_packages x4 incl. live
  Stripe price_id price_1TS4ZtRxKwHk31G9oV6pgdgc)
- UPDATE and DELETE permissions EXECUTE on financial tables (proven zero-row on
  bank_transactions — affectedCount 0, no permission error)
- Full ~300-table schema + insert/update/delete mutations exposed via GraphQL introspection
  (bank_transactions, ar_invoices, security_audit_log, token_transactions, unipile_emails,
  user_roles, connected_bank_accounts, ...)

## Evidence (all with anon key only)
1. Key: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imh5cmN2aHpybmZicHB5enV1b3NwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQwNzUwMTYsImV4cCI6MjA2OTY1MTAxNn0.oPFqmWy5GJ49E4gRrPEP9I9u4S0UwvPQXof3aHgJBak
2. READ live data (REST + GraphQL both):
   - /rest/v1/subscription_plans?select=* -> 3 rows: Starter Plan $99.00/mo 150 tokens,
     Enterprise Custom, Growth Plan (created 2026-05/06)
   - /rest/v1/token_packages?select=* -> 4 rows: "1,000 CFO Tokens" $25.00,
     "2,250 CFO Tokens" ... with stripe_price_id price_1TS4ZtRxKwHk31G9oV6pgdgc
3. WRITE permission executes (zero-row probe, no data touched):
   - mutation updatebank_transactionsCollection(set:{name:"x"}, filter:{id:{eq:ZEROS}})
     -> {"affectedCount": 0}   (no 42501 -> UPDATE grant + RLS pass)
   - mutation deleteFrombank_transactionsCollection(filter:{id:{eq:ZEROS}})
     -> {"affectedCount": 0}   (DELETE grant + RLS pass)
4. GraphQL introspection with anon key returns insertInto*/update*/deleteFrom* mutations
   for ~300 tables (PostGraphile only exposes mutations the role may execute).
5. RLS present only where explicitly written: qbo_connections -> 42501 permission denied.
6. Realtime: anon subscription accepted on public.prospects (phx_reply ok).
7. Negative controls: JWT secret not crackable (rockyou 14.3M exhausted); bundle contains
   no service_role/Stripe/secret keys; storage empty; auth token oracle identical errors
   (no user enumeration); no PII observed (no customers/leads rows).

## Impact
- Confidentiality: internal billing/pricing configuration readable by anyone (incl. live
  Stripe price IDs, plan margins, token allowances).
- Integrity: anonymous write path exists for bank_transactions + (by schema grant) the
  financial tables; currently tables are empty, so no real records were modified.
  Demonstrated capability without touching data.
- Latent: once the app ingests real customer/bank/AR data, the same anon key exposes it
  (REST + GraphQL + realtime), i.e. full unauthenticated data access on the product.

## Root cause
Supabase defaults + permissive grants: anon role granted SELECT/INSERT/UPDATE/DELETE on
public schema tables, RLS not enabled (or policies permitting anon) on ~300 tables,
GraphQL enabled with schema visible to anon.

## Recommendation
Enable RLS on ALL tables with restrictive policies; revoke anon INSERT/UPDATE/DELETE;
disable GraphQL for anon or require auth; verify what the app actually needs from anon
(auth-user_id policy pattern). Rotate anon key after fixing (it's public anyway).

## Status
READY TO SUBMIT (responsible disclosure to support@cfoptimizer.com — no rewards, per
https://www.cfoptimizer.com/vulnerability-reporting-policy/). Stopped at zero-row write
probes; no data modified; no PII encountered.
