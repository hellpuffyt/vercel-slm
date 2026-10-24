# Changelog

All notable changes to this project are documented here (format: Keep a Changelog).

## [Unreleased]
### Fixed
- Brute-force detection never triggered: the counter id was derived from `now - 5 min` in whole seconds, so it changed every second. Counters now use fixed 5-minute windows.
- Importing the function crashed (`supabaseUrl is required`) when Supabase env vars were missing, failing every request. The client is now created lazily and requests fail closed.
- Evidence URL was always `null` (read the supabase-js v1 `publicURL` field); now uses v2 `data.publicUrl`.
- Invalid `timestamp` values caused a 500 (`RangeError`); now a 400.
### Security
- API key compared in constant time; 500 responses no longer echo internal error details; message size capped at 64 KiB (413).
### Added
- README, tests (`node --test`), CI, `package-lock.json`, `.gitignore`, `.env.example`, `SECURITY.md`, `CONTRIBUTING.md`, `.editorconfig`, `docs/PRODUCTION_READINESS.md`.
### Changed
- Dropped the `uuid` dependency in favour of `crypto.randomUUID()`.
