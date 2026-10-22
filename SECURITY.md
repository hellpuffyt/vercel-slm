# Security Policy

Report vulnerabilities privately via https://github.com/hellpuffyt/vercel-slm/security/advisories/new
(please do not open a public issue).

## Deployment notes
- `SUPABASE_SERVICE_ROLE` bypasses Row Level Security; keep it only in server-side environment variables.
- `API_KEY` is a single shared secret compared in constant time. Rotate it if a client leaks it.
- Submitted log lines may contain personal data. Raw messages are uploaded to the `EVIDENCE_BUCKET`; keep that
  bucket **private** (the stored public URL then won't resolve; use signed URLs when reading) and set a retention policy.
- The source IP recorded for an incident comes from the message text or `X-Forwarded-For`, both client-controlled.
