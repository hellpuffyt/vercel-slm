-- Tables the function writes to, inferred from api/detect.js.
-- Run in the Supabase SQL editor. Validated against a local PostgreSQL 17 (not against a live Supabase project).
create table if not exists incidents (
  incident_id     text primary key,
  created_at      timestamptz not null,
  log_source      text,
  findings        text[] not null,
  message_excerpt text,
  evidence_path   text,
  extra           jsonb
);

create table if not exists counters (
  counter_id   text primary key,      -- "<ip>-<window_start>"
  ip           text not null,
  window_start bigint not null,       -- unix seconds, multiple of 300
  count        integer not null default 0,
  last_seen    timestamptz not null
);

-- The function uses the service-role key, which bypasses RLS. Enable RLS so that
-- anon/authenticated clients cannot read incidents through the public API.
alter table incidents enable row level security;
alter table counters enable row level security;
