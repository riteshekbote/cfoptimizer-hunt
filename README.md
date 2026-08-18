# cfoptimizer-hunt

24/7 multi-model bug-hunting automation for the **Cash Flow Optimizer** vulnerability reporting policy.

- **NOTE**: NOT a formal bug bounty — responsible disclosure only, no monetary rewards (possible public acknowledgment)
- **Scope**: `cfoptimizer.com` (marketing), `app.cfoptimizer.com` (app, live), any CFO-exposed APIs
- **Disclosure**: email `support@cfoptimizer.com`, subject **"Vulnerability Report"**, ack within 3 business days
- **Operator**: RealtoResource, LLC dba Solidify Solutions
- 5 opencode models (Big Pickle, Nemotron 3 Ultra, Longcat, Ling 3.0, Laguna) hunt in parallel every 10 minutes
- Subdomain recon pipeline (subfinder + crt.sh + wayback + dnsx + httpx) daily at 02:20 UTC
- JS recon pipeline (endpoint/sourcemap/secret extraction from live app bundles) every 5 minutes
- All testing **read-only / non-destructive** — stop immediately + report if any customer PII is encountered; no public disclosure before fix opportunity

## Out of scope (report to providers directly)
Vercel, Supabase, Stripe, Plaid, Intuit, Unipile, Anthropic, Google, OpenAI — *unless directly exposing CFO data*

## Stack (verified seed)
- **Vercel** hosting (both www + app)
- **Supabase** project `hyrcvhzrnfbppyzuuosp.supabase.co` (visible in app CSP) — check anon key, RLS, storage buckets, auth endpoints
- **Stripe** (payments), **Plaid** (bank aggregation), **Unipile** (messaging), **Anthropic/OpenAI** (AI)

## What pays (reputation — no cash)
XSS, CSRF, SQLi, auth bypass, **IDOR/tenant-data isolation** (multi-tenant fintech = prime class), SSRF, RCE, sensitive data exposure, security misconfig affecting customer data, business logic with material impact. See `scope.yml` for the rejected list.

| Artifact | Purpose |
|---|---|
| `recon/scope.txt` | Seed subdomain list |
| `inventory/` | Recon + JS inventory results |
| `leads/` | Candidate findings (UNVALIDATED) |
| `reports/` | Ranked hypotheses + valid findings |
| `knowledge/index.md` | Verified learnings + rejected classes (RAG) |
| `findings.md` | JS recon output |
| `scope.yml` | Program scope + rules (edit to adjust) |

## Reporting
Email `support@cfoptimizer.com` with subject "Vulnerability Report": vulnerability type+description, affected systems/endpoints, repro steps + working PoC, impact. PGP key available on request.