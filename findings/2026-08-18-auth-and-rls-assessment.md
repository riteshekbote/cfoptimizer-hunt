# CF Optimizer — Authenticated Supabase Surface Assessment (2026-08-18)

Scope: app.cfoptimizer.com (SPA) + Supabase project hyrcvhzrnfbppyzuuosp.supabase.co (anon key extracted from /assets/index-DO8kisOM.js)

## Confirmed behaviors
- Open signup: POST /auth/v1/signup with ANY email returns access_token (authenticated, aud=authenticated) immediately. auth/v1/settings reports `disable_signup:false`, `mailer_autoconfirm:true` (no email verification). Fresh account auto-creates: profiles row, company_memberships row (role=admin, 5-char company_code), 30-day trial.
- RLS: reads scoped to auth.uid() (profiles/leads/company_memberships/user_sessions/clients/customers/company_data/bank_transactions/ar_invoices/token_transactions/chat_messages/deals/deal_notes/entities/tasks/todos/job_sections all return [] for fresh user; cross-tenant company_code filter returns []). INSERT into leads blocked by RLS.
- Custom trigger blocks PATCH of billing/token/subscription/affiliate columns: `42501 Direct modification of billing, token, subscription, or affiliate fields is not allowed. Use the appropriate server-side function.`
- Mass-assignment allowed on non-privileged profile fields (username/phone/display_name/avatar_url/theme) — user-owned, no impact.
- profiles.company_id is writable via PATCH but unique-constrained per profile (per-user companies).
- account_status check constraint: values limited (banned rejected).
- Email change: correctly requires confirmation (new_email pending, not applied).
- Stripe webhook edge function (functions.supabase.co/stripe-webhook): proper signature verification (invalid signature rejected).
- Storage: no buckets; Edge functions: only stripe-webhook deployed.

## Candidate findings (responsible disclosure, LOW/INFO)
1. [LOW] Unverified signup on fintech platform: open signup + mailer_autoconfirm=true → any throwaway email gets authenticated session + admin workspace. Abuse surface: trial/affiliate/token abuse, platform spam. Standard Supabase misconfig.
2. [INFO] Protected-column enumeration via trigger error message (billing/token/subscription/affiliate).
3. [INFO] 5-char company_code invite identifiers displayed in UI (UVJMW/7RCQA/P9SDQ/7YRBW style, 62^5 ≈ 916M — not brute-forceable).

## NOT vulnerable (tested)
- RLS on all known tables (read/write/insert)
- Cross-tenant data access via company_code
- Stripe webhook signature forgery
- Password reset link (redirectTo = own origin /sign-in, safe)
- Storage bucket guessing

## Context
White-label multi-tenant platform by Solidify Solutions (RealtoResource, LLC). Same Supabase project likely shared across white-label brands. Contact: support@cfoptimizer.com, subject "Vulnerability Report".

## Follow-up deep-dive (session 2) — additional results
- RPC surface: only `is_master_admin(_user_id)` (false for all non-master) and `get_admin_user_id(_user_id)` (echoes input uid when no membership; returns admin id otherwise). No exploitable RPCs.
- INSERT policies tested: `company_memberships` (own user_id only; forged user_id → 42501), `leads` (42501), `token_transactions` (42501, enum values discovered: purchase/bonus/refund/usage are valid but blocked), `user_sessions` (OPEN for own user_id — row created with login_at default; forged uid blocked).
- `customers` table exists with user_id/email/phone/status columns — RLS-scoped ([]).
- **RLS gap found: company_memberships INSERT policy does NOT validate `company_admin_id`/`company_code` ownership.** Attacker can insert `{user_id: own, company_admin_id: <any real auth uid>, role: "admin", company_code: <any 5-char code>}` — passes RLS (auth.uid()=user_id) and the unique constraint (user_id, company_admin_id). Only FK (company_admin_id must be a real auth user) and the unique key stop it. Impact: if attacker learns a victim's auth uid + company code, they become an admin member of the victim's tenant → all RLS-scoped data (profiles, leads, clients, bank data) becomes readable. Enumeration of (uid, code) pairs via API is currently blocked (RLS-scoped reads, no invite flow in SPA). Codes are 5-char alnum (~916M space, not brute-forceable directly); uids are UUIDs.
- No edge functions besides stripe-webhook (signature properly verified); no storage buckets; no other RPCs; email change requires confirmation.
- White-label platform: solidifysolutions.com is an unrelated WordPress sales consultancy — NOT the platform vendor. Platform branding: "solidify-blue" theme.

## Verdict
Supabase layer is well-defended (RLS everywhere except the membership-insert admin_id check; billing/token/affiliate columns trigger-protected; Stripe webhook valid). Reportable items for responsible disclosure:
1. [LOW] Open signup with mailer_autoconfirm=true (no email verification) on a fintech app — abuse of trials/affiliate/token system, spam.
2. [LOW/MED] Missing ownership check on company_memberships.company_admin_id at INSERT (cross-tenant membership primitive; exploitation requires a leaked uid+code).
3. [INFO] Protected-column enumeration via trigger 42501 message; user_sessions rows insertable for self.

## Session 3 — two-account PoC (triager re-evaluation) — FINDING DISPROVEN
Full exploit attempt with real accounts (victim B + attacker A):
1. A reads B's profile by company_code filter → [] (baseline, isolated)
2. A INSERT company_memberships {user_id: A, company_admin_id: B (real uid), role: "admin", company_code: B's code, is_active: true} → **SUCCESS, row persisted** (id returned)
3. A re-queries ALL tables (profiles, leads, clients, customers, company_data, chat_messages, tasks, todos, deal_notes, entities, job_sections, bank_transactions, ar_invoices) → **ALL []**

CONCLUSION: every SELECT RLS policy is `user_id = auth.uid()` (user-scoped), NOT company-membership-scoped. The tenant model is per-user (company_id unique per profile), so the inserted membership row is visible ONLY to the attacker themselves (their own rows) and to no other user or victim UI. No confidentiality impact, no integrity impact visible to any other party, no enumeration path.

TRIAGER VERDICT: **NOT REPORTABLE** — no security impact demonstrated. Classify as "missing server-side input validation on a self-referential row; zero cross-user impact". Finding downgraded from LOW/MED to NOT-A-FINDING. (Do not submit.)
