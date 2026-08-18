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
