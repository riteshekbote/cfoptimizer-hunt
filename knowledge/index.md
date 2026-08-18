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