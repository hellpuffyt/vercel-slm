// Pure, dependency-free logic for the log-detection endpoint (unit-testable).
import { timingSafeEqual } from "node:crypto";

export const FAILED_LOGIN_RE = /failed login|authentication failed|invalid credentials|login failed|status=FAILED/i;
export const SQLI_RE = /(\bunion\b.*\bselect\b)|(\bor\s+1\s*=\s*1\b)|(\binject\b)|(\bselect\s+\*\b)|(\bunion select\b)/i;
export const SUSPICIOUS_UA_RE = /(curl|sqlmap|nikto|fuzzer|masscan|nmap|python-requests)/i;
export const IP_RE = /\b(\d{1,3}\.){3}\d{1,3}\b/;

export const BRUTE_FORCE_WINDOW_SECONDS = 5 * 60;
export const BRUTE_FORCE_THRESHOLD = 3;
export const MAX_MESSAGE_BYTES = 64 * 1024;
export const EXCERPT_CHARS = 800;

export function detectRules(text) {
  const findings = [];
  if (FAILED_LOGIN_RE.test(text)) {
    findings.push({ rule: "failed-login", severity: "medium", desc: "Failed login attempt" });
  }
  if (/user=admin|username=admin|user:admin/i.test(text)) {
    findings.push({ rule: "admin-access", severity: "high", desc: "Admin user access attempt" });
  }
  if (SQLI_RE.test(text)) {
    findings.push({ rule: "sql-injection", severity: "critical", desc: "Possible SQL injection" });
  }
  if (SUSPICIOUS_UA_RE.test(text)) {
    findings.push({ rule: "suspicious-user-agent", severity: "medium", desc: "Suspicious user agent / scanner" });
  }
  return findings;
}

export function extractIp(text) {
  if (!text) return null;
  const m = text.match(IP_RE);
  return m ? m[0] : null;
}

/**
 * Start (unix seconds) of the fixed 5-minute window containing `nowMs`.
 * Every event in the same window maps to the same counter row.
 */
export function windowStart(nowMs) {
  return Math.floor(nowMs / 1000 / BRUTE_FORCE_WINDOW_SECONDS) * BRUTE_FORCE_WINDOW_SECONDS;
}

export function counterId(ip, nowMs) {
  return `${ip}-${windowStart(nowMs)}`;
}

/** Constant-time API key check; false when no key is configured. */
export function apiKeyMatches(expected, provided) {
  if (!expected || typeof provided !== "string") return false;
  const a = Buffer.from(expected);
  const b = Buffer.from(provided);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Normalise the request body into { message, timestamp, meta } or return { error }. */
export function parsePayload(body, nowMs) {
  const message =
    body && typeof body === "object" && typeof body.message === "string"
      ? body.message
      : typeof body === "string"
        ? body
        : JSON.stringify(body ?? "");
  if (Buffer.byteLength(message) > MAX_MESSAGE_BYTES) {
    return { error: "payload_too_large", status: 413 };
  }
  let timestamp = new Date(nowMs).toISOString();
  if (body && typeof body === "object" && body.timestamp !== undefined) {
    const t = new Date(body.timestamp);
    if (Number.isNaN(t.getTime())) return { error: "invalid_timestamp", status: 400 };
    timestamp = t.toISOString();
  }
  const meta = body && typeof body === "object" ? body.meta ?? null : null;
  return { message, timestamp, meta };
}
