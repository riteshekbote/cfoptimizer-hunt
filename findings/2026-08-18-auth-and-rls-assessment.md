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
