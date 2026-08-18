# Supabase anon key in prod bundle + RLS missing on 14 tables (CF Optimizer)

## Summary
The production SPA bundle at https://app.cfoptimizer.com/assets/index-DO8kisOM.js (466KB)
contains a live Supabase anon key for project `hyrcvhzrnfbppyzuuosp.supabase.co`
(JWT: role=anon, exp 2035-01-28). With only that key, PostgREST allows anonymous
SELECT on 14 tables including financial/aggregator tables; the tables are currently
EMPTY (0 rows), so no customer data exposure is demonstrated today.

## Evidence
1. Key in bundle: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imh5cmN2aHpybmZicHB5enV1b3NwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTQwNzUwMTYsImV4cCI6MjA2OTY1MTAxNn0.oPFqmWy5GJ49E4gRrPEP9I9u4S0UwvPQXof3aHgJBak`
2. Anon SELECT allowed (HTTP 200 + Content-Range `*/0`, i.e. zero rows — RLS grants SELECT, tables empty):
   prospects, profiles, leads, customers, deals, cash_flow_periods, cf_reports,
   crm_pipeline_settings, company_memberships, user_sessions, plaid_items, equipment,
   cs_bank_monthly, unipile_accounts
3. Properly denied: qbo_connections -> HTTP 42501 permission denied (QuickBooks OAuth tokens protected).
4. Auth settings (anon): only email provider enabled, anonymous_users=false.

## Impact
Latent configuration risk, no demonstrated data loss:
- RLS is missing on tables that will hold Plaid aggregator metadata (plaid_items),
  Unipile messaging-account references (unipile_accounts), bank monthly cash-flow data
  (cs_bank_monthly), customers, leads and prospects.
- The anon key is public by design (client-side), so once any of these tables receives
  rows, the data becomes readable by anyone without authentication.
- Honest note: today the database is empty; no PII or financial records were readable.
  QBO connections are correctly protected.

## Recommendation
Enable RLS + restrictive policies on all tables; keep anon role to auth-required schema
only. Verify the empty state is intentional (dev/staging data in a prod project).

## Status
READY TO SUBMIT (disclosure-only program, no rewards). Class: insecure default
configuration / missing RLS. Severity: Low (no data readable; latent exposure).
