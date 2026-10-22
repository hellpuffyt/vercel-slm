import { test } from "node:test";
import assert from "node:assert/strict";
import {
  apiKeyMatches,
  counterId,
  detectRules,
  extractIp,
  parsePayload,
  windowStart,
  MAX_MESSAGE_BYTES,
} from "../lib/detect-core.js";

test("detectRules flags each rule", () => {
  const rules = (t) => detectRules(t).map((f) => f.rule);
  assert.deepEqual(rules("Failed login for user=admin from 10.0.0.1"), ["failed-login", "admin-access"]);
  assert.deepEqual(rules("GET /?id=1 UNION SELECT password FROM users"), ["sql-injection"]);
  assert.deepEqual(rules("UA: sqlmap/1.7"), ["suspicious-user-agent"]);
  assert.deepEqual(rules("GET /index.html 200"), []);
});

test("extractIp finds the first IPv4 address", () => {
  assert.equal(extractIp("from 192.168.1.20 port 22"), "192.168.1.20");
  assert.equal(extractIp("no address"), null);
});

test("counter id is stable within a 5-minute window", () => {
  // Regression: the id used (now - 5 min) in whole seconds, so it changed every second and
  // repeated failures never accumulated in one counter (brute force was never detected).
  const t0 = Date.UTC(2025, 0, 1, 12, 0, 1);
  assert.equal(counterId("1.2.3.4", t0), counterId("1.2.3.4", t0 + 1_000));
  assert.equal(counterId("1.2.3.4", t0), counterId("1.2.3.4", t0 + 290_000));
  assert.notEqual(counterId("1.2.3.4", t0), counterId("1.2.3.4", t0 + 300_000));
  assert.equal(windowStart(t0) % 300, 0);
});

test("apiKeyMatches is strict and fails closed", () => {
  const key = "k-" + "123456";
  assert.equal(apiKeyMatches(key, key), true);
  assert.equal(apiKeyMatches(key, key + "x"), false);
  assert.equal(apiKeyMatches(key, undefined), false);
  assert.equal(apiKeyMatches(undefined, undefined), false);
  assert.equal(apiKeyMatches("", ""), false);
});

test("parsePayload accepts objects and strings, rejects bad timestamps and huge bodies", () => {
  const now = Date.UTC(2025, 0, 1);
  assert.deepEqual(parsePayload({ message: "m", meta: { a: 1 } }, now), {
    message: "m", timestamp: new Date(now).toISOString(), meta: { a: 1 },
  });
  assert.equal(parsePayload("raw line", now).message, "raw line");
  // Regression: new Date("garbage").toISOString() threw RangeError -> 500.
  assert.equal(parsePayload({ message: "m", timestamp: "garbage" }, now).status, 400);
  assert.equal(parsePayload({ message: "x".repeat(MAX_MESSAGE_BYTES + 1) }, now).status, 413);
});
