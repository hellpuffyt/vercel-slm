# Contributing

- Node.js 20+. `npm ci` then `npm test` (Node's built-in test runner; no network, Supabase is faked).
- Keep detection logic in `lib/detect-core.js` (pure functions) and add a test for every rule change or bug fix.
- Never commit `.env*` files or real keys.
