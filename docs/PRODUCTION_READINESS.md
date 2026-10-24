# Production readiness — vercel-slm

Audit date: 2026-10-22.

## Scope
One Vercel Node serverless function (`api/detect.js`) that classifies submitted log lines with regex rules, stores
incidents/counters in Supabase (Postgres + Storage) and posts webhook alerts. The repository had no README; its
purpose was reconstructed from the code. Pure logic lives in `lib/detect-core.js`.

## Platforms / prerequisites
Node.js 20+ (tests run on Node 24 locally; CI matrix 20/22/24). A real deployment needs a Vercel project and a
Supabase project — neither was available, so no live request was made.

## Clean clone
`git clone … && npm ci && npm test` — result recorded in the hand-back / below.

## Commands and outcomes
| Command | Exit | Result |
|---|---|---|
| baseline: no lockfile, no tests, no README | — | `npm install` adds 9 packages; nothing to run |
| baseline: `createClient(undefined, undefined)` (what the module did at import without env) | — | throws `supabaseUrl is required.` → every request failed |
| baseline: original counter id for two events 1 s apart | — | different ids → brute force could never reach 3 |
| `npm test` (after fixes) | 0 | 13 passed, 0 failed, 0 skipped |
| `npm audit` | 0 | 0 vulnerabilities |
| `docs/schema.sql` + sample insert/update on throwaway PostgreSQL 17 | 0 | ok |

## Bugs fixed (regression tests)
1. Brute-force window never accumulated — `test/detect-core.test.js` "counter id is stable…", `test/handler.test.js` "third failed login…".
2. Import-time crash without env — "default export fails closed…".
3. Evidence URL always null (supabase-js v1 field) — "finding creates an incident with evidence URL".
4. Invalid timestamp → 500 — "invalid timestamp is a 400".
5. 500 responses leaked internal error text — "database errors return a generic 500…".
6. Non-constant-time API key comparison; unbounded message size (64 KiB cap → 413).

## Security review
- Auth: shared `x-api-key`, constant-time compare, fails closed when unset.
- Secrets: none in tree or history (regex scan).
- Data: raw messages (may contain personal data) are uploaded to Storage; keep the bucket private (SECURITY.md).
- Spoofable `log_source` (message IP / X-Forwarded-For) — documented.
- Webhook content truncated to Discord's 2000-char limit; excerpt is attacker-controlled text (Discord markdown).
- Workflow: `contents: read`, actions pinned to SHAs resolved via the GitHub API.

## CI
`.github/workflows/ci.yml` (npm ci, test, audit --audit-level=high; Node 20/22/24). Default branch: no workflow
(never run); audit branch: pending until pushed.

## Limitations / unverified
- No live Supabase or Vercel run; Supabase calls are verified only against a fake with the supabase-js v2 call shapes.
- Counter update is not atomic. Regex rules are naive.
- No license file (owner decision).

## Acceptance checklist
| # | Item | Expected | Command/test | Result | Actual | Reference |
|---|---|---|---|---|---|---|
| 1 | Method/auth gate | 405 / 401 | handler.test.js | pass | — | api/detect.js |
| 2 | Benign input | 200, nothing stored | handler.test.js | pass | — | api/detect.js |
| 3 | Finding → incident + evidence | 201, row + URL | handler.test.js | pass | — | api/detect.js |
| 4 | Brute force | 3rd failure in 5 min → incident + alert | handler.test.js | pass | — | lib/detect-core.js |
| 5 | Critical alert | webhook post | handler.test.js | pass | — | api/detect.js |
| 6 | Robust input | 400 / 413, no crash | detect-core.test.js | pass | — | lib/detect-core.js |
| 7 | Misconfiguration | fails closed | handler.test.js | pass | — | api/detect.js |
| 8 | Schema matches inserts | DDL + inserts succeed | local PostgreSQL 17 | pass | — | docs/schema.sql |
| 9 | Live deploy | request round-trips | Vercel + Supabase | not run | no accounts | — |

## Classification proposal
**Partially Verified** — handler logic fully unit-tested against a fake Supabase; no live Supabase/Vercel deployment tested.

## Tested commit
Branch `audit/production-readiness`, commit adding this file, 2026-10-22.
