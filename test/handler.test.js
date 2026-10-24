import { test } from "node:test";
import assert from "node:assert/strict";
import defaultHandler, { createHandler } from "../api/detect.js";

const KEY = "test-" + "api-key";

function fakeSupabase() {
  const tables = { incidents: [], counters: [] };
  const uploads = [];
  const from = (name) => {
    const filters = [];
    const api = {
      insert: async (rows) => { tables[name].push(...rows); return { data: rows, error: null }; },
      select: () => api,
      eq: (col, val) => { filters.push([col, val]); return api; },
      maybeSingle: async () => ({ data: tables[name].find((r) => filters.every(([c, v]) => r[c] === v)) ?? null, error: null }),
      update: (patch) => ({
        eq: async (col, val) => { for (const r of tables[name]) if (r[col] === val) Object.assign(r, patch); return { error: null }; },
      }),
    };
    return api;
  };
  const storage = {
    from: (bucket) => ({
      upload: async (path) => { uploads.push(`${bucket}/${path}`); return { error: null }; },
      getPublicUrl: (path) => ({ data: { publicUrl: `https://storage.example/${bucket}/${path}` } }),
    }),
  };
  return { from, storage, tables, uploads };
}

function call(handler, { method = "POST", headers = { "x-api-key": KEY }, body } = {}) {
  return new Promise((resolve) => {
    const res = {
      code: 200,
      status(c) { this.code = c; return this; },
      json(b) { resolve({ status: this.code, body: b }); return this; },
    };
    handler({ method, headers, body, socket: { remoteAddress: "127.0.0.1" } }, res);
  });
}

function setup(nowMs = Date.UTC(2025, 0, 1, 12, 0, 0)) {
  const db = fakeSupabase();
  const posts = [];
  const handler = createHandler({
    getSupabase: () => db,
    apiKey: KEY,
    webhook: "https://hooks.example/alert",
    fetchImpl: async (url, init) => { posts.push(JSON.parse(init.body)); return { ok: true }; },
    now: () => nowMs,
  });
  return { db, posts, handler };
}

test("rejects non-POST and missing/wrong API key", async () => {
  const { handler } = setup();
  assert.equal((await call(handler, { method: "GET" })).status, 405);
  assert.equal((await call(handler, { headers: {} , body: { message: "x" } })).status, 401);
  assert.equal((await call(handler, { headers: { "x-api-key": "nope" }, body: { message: "x" } })).status, 401);
});

test("benign message returns no findings and touches no storage", async () => {
  const { handler, db } = setup();
  const r = await call(handler, { body: { message: "GET /health 200" } });
  assert.deepEqual(r, { status: 200, body: { ok: true, findings: [] } });
  assert.equal(db.tables.incidents.length, 0);
});

test("finding creates an incident with evidence URL (supabase-js v2 shape)", async () => {
  const { handler, db } = setup();
  const r = await call(handler, { body: { message: "UA sqlmap from 10.1.2.3" } });
  assert.equal(r.status, 201);
  assert.equal(db.tables.incidents.length, 1);
  assert.equal(r.body.incident.log_source, "10.1.2.3");
  // Regression: read v1's `publicURL`, so evidence_path was always null.
  assert.match(r.body.incident.evidence_path, /^https:\/\/storage\.example\/evidence\/inc-/);
});

test("third failed login from one IP within 5 minutes raises a brute-force incident and alert", async () => {
  const t0 = Date.UTC(2025, 0, 1, 12, 0, 0);
  const db = fakeSupabase();
  const posts = [];
  let now = t0;
  const handler = createHandler({
    getSupabase: () => db, apiKey: KEY, webhook: "https://hooks.example/alert",
    fetchImpl: async (u, init) => { posts.push(JSON.parse(init.body)); return { ok: true }; },
    now: () => now,
  });
  const results = [];
  for (const dt of [0, 20_000, 40_000]) {
    now = t0 + dt;
    results.push(await call(handler, { body: { message: "Failed login from 203.0.113.9" } }));
  }
  assert.deepEqual(results.map((r) => r.body.bruteForce), [false, false, true]);
  assert.equal(db.tables.counters.length, 1);
  assert.equal(db.tables.counters[0].count, 3);
  assert.ok(db.tables.incidents.some((i) => i.findings.includes("brute-force")));
  assert.equal(posts.length, 1);
  assert.match(posts[0].content, /Brute-force detected/);
});

test("critical finding sends an alert", async () => {
  const { handler, posts } = setup();
  await call(handler, { body: { message: "id=1 or 1=1" } });
  assert.equal(posts.length, 1);
  assert.match(posts[0].content, /Possible SQL injection/);
});

test("database errors return a generic 500 without internal details", async () => {
  const handler = createHandler({
    getSupabase: () => { throw new Error("connection string secret-detail"); },
    apiKey: KEY,
  });
  const r = await call(handler, { body: { message: "Failed login" } });
  assert.deepEqual(r, { status: 500, body: { ok: false, error: "internal_error" } });
});

test("invalid timestamp is a 400, not a crash", async () => {
  const { handler } = setup();
  const r = await call(handler, { body: { message: "Failed login", timestamp: "not-a-date" } });
  assert.equal(r.status, 400);
});

test("default export fails closed without env instead of crashing at import", async () => {
  // Regression: createClient(undefined, undefined) ran at import time and threw,
  // taking down every request (including 401/405 paths).
  delete process.env.API_KEY;
  const r = await call(defaultHandler, { headers: {}, body: { message: "x" } });
  assert.equal(r.status, 401);
});
