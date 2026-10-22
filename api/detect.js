// api/detect.js — Vercel serverless function: rule-based detection on submitted log lines.
import { randomUUID } from "node:crypto";
import { createClient } from "@supabase/supabase-js";
import {
  BRUTE_FORCE_THRESHOLD,
  EXCERPT_CHARS,
  FAILED_LOGIN_RE,
  apiKeyMatches,
  counterId,
  detectRules,
  extractIp,
  parsePayload,
  windowStart,
} from "../lib/detect-core.js";

/**
 * Environment (Vercel project settings):
 *   SUPABASE_URL, SUPABASE_SERVICE_ROLE, API_KEY   (required)
 *   ALERT_WEBHOOK   (optional, Discord-style webhook)
 *   EVIDENCE_BUCKET (optional, default "evidence")
 */

async function storeEvidence(supabase, bucket, incidentId, message) {
  try {
    const path = `${incidentId}.txt`;
    const { error } = await supabase.storage.from(bucket).upload(path, Buffer.from(String(message)), {
      contentType: "text/plain",
      upsert: true,
    });
    if (error) {
      console.warn("storeEvidence: upload error", error.message);
      return null;
    }
    // supabase-js v2 returns { data: { publicUrl } }. The URL only works for a public bucket;
    // for a private bucket store the path and create signed URLs when reading.
    const { data } = supabase.storage.from(bucket).getPublicUrl(path);
    return data?.publicUrl || null;
  } catch (err) {
    console.warn("storeEvidence exception:", err?.message || err);
    return null;
  }
}

async function saveIncident(supabase, incidentObj) {
  const { data, error } = await supabase.from("incidents").insert([incidentObj]);
  if (error) {
    console.error("saveIncident error:", error.message);
    throw new Error(error.message);
  }
  return data;
}

// Counts failed logins per IP in a fixed 5-minute window (read-modify-write; not atomic).
async function updateCounter(supabase, ip, nowMs) {
  if (!ip) return null;
  try {
    const id = counterId(ip, nowMs);
    const { data: existing, error } = await supabase.from("counters").select("*").eq("counter_id", id).maybeSingle();
    if (error) console.warn("updateCounter select error:", error.message);

    if (!existing) {
      const { error: insErr } = await supabase.from("counters").insert([
        { counter_id: id, ip, window_start: windowStart(nowMs), count: 1, last_seen: new Date(nowMs).toISOString() },
      ]);
      if (insErr) console.warn("updateCounter insert error:", insErr.message);
      return 1;
    }
    const newCount = (existing.count || 0) + 1;
    const { error: updErr } = await supabase
      .from("counters")
      .update({ count: newCount, last_seen: new Date(nowMs).toISOString() })
      .eq("counter_id", id);
    if (updErr) console.warn("updateCounter update error:", updErr.message);
    return newCount;
  } catch (err) {
    console.warn("updateCounter exception:", err?.message || err);
    return null;
  }
}

async function sendAlertWebhook(fetchImpl, webhook, title, body) {
  if (!webhook) return;
  try {
    await fetchImpl(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: `**${title}**\n${body}`.slice(0, 2000) }),
    });
  } catch (err) {
    console.warn("sendAlertWebhook error:", err?.message || err);
  }
}

export function createHandler({ getSupabase, apiKey, webhook = "", bucket = "evidence", fetchImpl = fetch, now = Date.now }) {
  return async function handler(req, res) {
    if (req.method !== "POST") {
      return res.status(405).json({ ok: false, error: "Method not allowed" });
    }
    if (!apiKeyMatches(apiKey, req.headers["x-api-key"])) {
      return res.status(401).json({ ok: false, error: "Unauthorized" });
    }

    const nowMs = now();
    const parsed = parsePayload(req.body, nowMs);
    if (parsed.error) {
      return res.status(parsed.status).json({ ok: false, error: parsed.error });
    }
    const { message, timestamp, meta } = parsed;

    try {
      const findings = detectRules(message);
      if (findings.length === 0) {
        return res.status(200).json({ ok: true, findings: [] });
      }

      const supabase = getSupabase();
      // NOTE: an IP in the message and X-Forwarded-For are client-controlled values.
      const realIp =
        extractIp(message) ||
        req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
        req.headers["x-source"] ||
        req.socket?.remoteAddress ||
        "unknown";

      const incidentId = `inc-${randomUUID()}`;
      const excerpt = message.slice(0, EXCERPT_CHARS);
      const evidencePath = await storeEvidence(supabase, bucket, incidentId, message);

      const incident = {
        incident_id: incidentId,
        created_at: timestamp,
        log_source: realIp,
        findings: findings.map((f) => f.rule),
        message_excerpt: excerpt,
        evidence_path: evidencePath,
        extra: { findings, meta },
      };
      await saveIncident(supabase, incident);

      let bruteForceTriggered = false;
      if (FAILED_LOGIN_RE.test(message)) {
        const count = await updateCounter(supabase, realIp, nowMs);
        if (typeof count === "number" && count >= BRUTE_FORCE_THRESHOLD) {
          await saveIncident(supabase, {
            incident_id: `bf-${randomUUID()}`,
            created_at: new Date(nowMs).toISOString(),
            log_source: realIp,
            findings: ["brute-force"],
            message_excerpt: `Multiple failed login attempts detected from IP ${realIp} (count=${count})`,
            extra: { attempts: count },
          });
          bruteForceTriggered = true;
          await sendAlertWebhook(fetchImpl, webhook, "Brute-force detected", `IP ${realIp} had ${count} failed logins in 5m`);
        }
      }

      const critical = findings.find((f) => f.severity === "critical");
      if (critical) {
        await sendAlertWebhook(fetchImpl, webhook, "Critical finding detected", `${critical.desc}\nIP: ${realIp}\nExcerpt: ${excerpt}`);
      }

      return res.status(201).json({ ok: true, incident, bruteForce: bruteForceTriggered });
    } catch (err) {
      console.error("Handler exception:", err?.message || err);
      // Do not echo internal error details (DB messages etc.) to the caller.
      return res.status(500).json({ ok: false, error: "internal_error" });
    }
  };
}

let client = null;
function getSupabaseFromEnv() {
  if (!client) {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE;
    if (!url || !key) throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE must be set");
    client = createClient(url, key, { auth: { persistSession: false } });
  }
  return client;
}

// Env is read per request so a misconfigured deployment fails closed (401/500) instead of crashing at import.
export default function handler(req, res) {
  return createHandler({
    getSupabase: getSupabaseFromEnv,
    apiKey: process.env.API_KEY,
    webhook: process.env.ALERT_WEBHOOK || "",
    bucket: process.env.EVIDENCE_BUCKET || "evidence",
  })(req, res);
}
