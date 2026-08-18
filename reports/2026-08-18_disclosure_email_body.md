To: support@cfoptimizer.com
Subject: Vulnerability Report

Hello,

I'm a security researcher disclosing a configuration vulnerability in the Cash Flow Optimizer
application per your Vulnerability Reporting Policy (https://www.cfoptimizer.com/vulnerability-reporting-policy/).
All testing was read-only; no data was modified and no customer data was accessed.

== Affected system ==
app.cfoptimizer.com (Supabase backend hyrcvhzrnfbppyzuuosp.supabase.co, GraphQL and PostgREST).

== Summary ==
The production JavaScript bundle ships a live Supabase "anon" API key. With ONLY that publicly
embedded key (no account, no login), an unauthenticated attacker can:
  1. READ live billing/configuration data (subscription plans and token packages, including a
     live Stripe price ID).
  2. EXECUTE UPDATE and DELETE operations against database tables (permission confirmed with
     zero-row probes), including financial-transaction tables.
  3. Enumerate the full database schema (~300 tables) and all insert/update/delete mutations
     via GraphQL introspection.

== Steps to reproduce ==
  1. GET https://app.cfoptimizer.com/assets/index-DO8kisOM.js  (the anon key is in this file)
  2. Data read (REST):
       curl -H "apikey: <anon_key>" -H "Authorization: Bearer <anon_key>" \
         "https://hyrcvhzrnfbppyzuuosp.supabase.co/rest/v1/subscription_plans?select=*&limit=3"
       -> 200 with live rows (Starter Plan $99/mo, Enterprise Custom, Growth Plan)
       curl ... /rest/v1/token_packages?select=*&limit=3
       -> 200 with 4 live rows incl. Stripe price id price_1TS4ZtRxKwHk31G9oV6pgdgc
  3. Write permissions (zero-row proof, no data touched):
       POST /graphql/v1  {"query":"mutation{updatebank_transactionsCollection(set:{name:\"x\"},
         filter:{id:{eq:\"00000000-0000-0000-0000-000000000000\"}}){affectedCount}}"}
       -> {"affectedCount": 0}   (no permission error; anon UPDATE grant on bank_transactions)
       POST /graphql/v1  {"query":"mutation{deleteFrombank_transactionsCollection(
         filter:{id:{eq:\"00000000-0000-0000-0000-000000000000\"}}){affectedCount}}"}
       -> {"affectedCount": 0}   (anon DELETE grant)
  4. Schema disclosure:
       POST /graphql/v1 introspection returns ~300 collections with insert/update/delete
       mutations (bank_transactions, ar_invoices, security_audit_log, token_transactions,
       unipile_emails, user_roles, connected_bank_accounts, ...).

The anon key (public by design): eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imh5cmN2aHpybmZicHB5enV1b3NwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQwNzUwMTYsImV4cCI6MjA2OTY1MTAxNn0.oPFqmWy5GJ49E4gRrPEP9I9u4S0UwvPQXof3aHgJBak

== Impact ==
- Confidentiality: internal pricing/billing configuration (incl. live Stripe price IDs) is
  readable by anyone.
- Integrity: an unauthenticated write path exists for financial tables; tables are currently
  empty of customer records, so no records were modified — but the capability is live and will
  extend to any future customer/bank/AR data automatically (REST + GraphQL + Realtime all
  accept the anon key).
- Worst case: once customer financial data exists, full unauthenticated read/write of it.

== Root cause ==
Supabase project configured with permissive anon grants: anon role has SELECT/INSERT/UPDATE/DELETE
on public-schema tables, Row Level Security is not enabled (or permits anon) on ~300 tables, and
GraphQL is exposed to the anon role. (qbo_connections is the one table I found properly protected,
returning permission denied.)

== Recommendation ==
- Enable RLS on ALL tables with restrictive policies (anon should get no direct table access;
  use auth.uid()-scoped policies).
- Revoke INSERT/UPDATE/DELETE from the anon role.
- Disable GraphQL for the anon role or remove it entirely.
- Rotate the anon key after fixes (it is public regardless, but rotate to avoid stale caches).

I stopped at zero-row write probes and have not modified or retained any data. Please let me
know if you'd like to verify anything together. I'm happy to remain anonymous or be credited
as you prefer.

Regards,
[researcher]
