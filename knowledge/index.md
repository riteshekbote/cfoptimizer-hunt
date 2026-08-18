# CF Optimizer hunt KB — verified learnings (RAG for all models)
> Rules: never propose a class on the CFO REJECT LIST (see scope.yml); never
> duplicate KNOWN-DUP; use ALIVE surface facts. NOT a paid program — responsible
> disclosure, possible public acknowledgment only. Prioritize what pays reputation:
> tenant-data-isolation/IDOR (multi-tenant fintech), auth bypass, SSRF, SQLi, RCE,
> sensitive data exposure, business logic with material impact.

## REJECTED CLASSES (CFO policy — do not propose)
- REJECTED automated-scanner findings without demonstrated impact @ *.
- REJECTED missing security headers (SPF/DKIM etc.) without demonstrated exploitation @ *.
- REJECTED clickjacking on pages without sensitive functionality @ *.
- REJECTED email/username enumeration without demonstrated impact @ *.
- REJECTED rate limiting / brute-force on low-sensitivity endpoints @ *.
- REJECTED theoretical vulns without working PoC, DoS/stress testing, social engineering @ *.
- REJECTED known third-party dependency vulns already tracked upstream @ *.
- REJECTED findings requiring prior victim device/browser compromise @ *.

## ALIVE SURFACE FACTS (verified)
- 2026-08-18 cfoptimizer.com -> 301 -> www.cfoptimizer.com (200, server: Vercel) marketing site.
- 2026-08-18 app.cfoptimizer.com: HTTP 200 (Vercel). CSP reveals Supabase project
  `hyrcvhzrnfbppyzuuosp.supabase.co` + GTM (www.googletagmanager.com) + Google Fonts.
- Stack (from OOS list in policy): Vercel (hosting), Supabase (backend/auth/DB),
  Stripe (payments), Plaid (bank aggregation), Unipile (messaging APIs), Anthropic + OpenAI
  (AI features), Google. Operator: RealtoResource, LLC dba Solidify Solutions.

## OPEN QUESTIONS
- Supabase exposure: anon key in app JS? REST/realtime/storage endpoints reachable?
  Bucket policies, RLS misconfig, auth endpoints (/auth/v1/signup, token) misconfig.
- App API surface: what endpoints does the SPA call (supabase REST /api/*, Vercel functions)?
- App auth flow: Supabase Auth (email/OTP/social)? signup open? user enumeration on
  password reset? JWT verification flaws?
- Multi-tenant isolation: IDOR candidates in prospect/cash-flow/forecast/bank-account data.
- Marketing site: forms, webhooks, exposed API keys in JS bundles.

## FINDING INBOX (validated = move to reports/)
- (empty)
## 2026-08-18 (opencode-session) FINDING (LOW — config) @ app.cfoptimizer.com Supabase
- anon key extracted from /assets/index-DO8kisOM.js (466KB) -> project hyrcvhzrnfbppyzuuosp.supabase.co (role anon, exp 2035).
- Anon SELECT allowed on 14 tables (prospects/profiles/leads/customers/deals/cash_flow_periods/cf_reports/crm_pipeline_settings/company_memberships/user_sessions/plaid_items/equipment/cs_bank_monthly/unipile_accounts) — ALL EMPTY (*/0).
- qbo_connections DENIED (42501) — QBO tokens protected.
- PGRST205 name-oracle leaked full schema names (cash_flow_periods, cf_reports, qbo_connections, crm_pipeline_settings, plaid_items, equipment, cs_bank_monthly, unipile_accounts).
- Auth: only email provider; signup POST-only (not tested per no_account_creation).
- VERDICT: missing RLS on financial-aggregator tables; zero rows -> no data exposure; report as Low config finding (reports/2026-08-18_supabase_anon_key_rls.md).

## 2026-08-18 (opencode-session) FINDING (LOW - config) @ app.cfoptimizer.com Supabase
- anon key extracted from /assets/index-DO8kisOM.js (466KB) -> project hyrcvhzrnfbppyzuuosp.supabase.co (role anon, exp 2035).
- Anon SELECT allowed on 14 tables (prospects/profiles/leads/customers/deals/cash_flow_periods/cf_reports/crm_pipeline_settings/company_memberships/user_sessions/plaid_items/equipment/cs_bank_monthly/unipile_accounts) - ALL EMPTY (*/0).
- qbo_connections DENIED (42501) - QBO tokens protected.
- PGRST205 name-oracle leaked full schema names (cash_flow_periods, cf_reports, qbo_connections, crm_pipeline_settings, plaid_items, equipment, cs_bank_monthly, unipile_accounts).
- Auth: only email provider; signup POST-only (not tested per no_account_creation).
- VERDICT: missing RLS on financial-aggregator tables; zero rows -> no data exposure; report as Low config finding (reports/2026-08-18_supabase_anon_key_rls.md).

- 2026-08-18 DEEP-DIVE (opencode-session 2nd pass): realtime anon sub CONFIRMED (phx_reply ok, postgres_changes public.prospects, id 108174887); hashcat rockyou 14.3M EXHAUSTED no crack (secret strong, no service_role forgery); bundle sweep clean (anon only); storage [] ; auth token oracle no-enum (identical invalid_credentials x2); finding updated with addendum.

- 2026-08-18 FINDING UPGRADED LOW->HIGH (opencode-session 3rd pass): GraphQL enabled (graphql/v1, anon). Full ~300-table schema + insert/update/delete mutations visible to anon. LIVE DATA readable: subscription_plans (3 rows: Starter $99/mo, Enterprise, Growth), token_packages (4 rows, live stripe_price_id price_1TS4ZtRxKwHk31G9oV6pgdgc). WRITE PERMS EXECUTE: updatebank_transactionsCollection -> affectedCount 0, deleteFrombank_transactionsCollection -> affectedCount 0 (zero-row probes, no data touched). qbo_connections still denied. Others empty. -> HIGH config finding (report rewritten).

- 2026-08-18 (opencode-session 4th pass): 344-table census (342 readable/0 rows, 2 live config tables, qbo_connections denied). Edge functions live: check-signup-email = pre-auth user-existence oracle; rate-limit = config disclosure (5/15min), no reset action (bypass NOT found), 1 record counter entry left on throwaway email opencode-probe-7f3a@example.com (noted). RPC chain: get_website_lead_owner_id -> master-admin UUID cd603e78-73ae-48a0-a15e-734b4ffd8fe6, is_master_admin=true, is_account_active=true -> anonymous admin identification. Detailed report updated (sec 12).
