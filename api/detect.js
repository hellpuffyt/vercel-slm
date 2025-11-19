// api/detect.js
import { createClient } from "@supabase/supabase-js";
import { v4 as uuidv4 } from "uuid";

/**
 * Full serverless detect.js
 *
 * Requirements (Vercel env):
 *   SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE
 *   API_KEY
 * Optional:
 *   ALERT_WEBHOOK  (discord/slack webhook)
 *   EVIDENCE_BUCKET (defaults to 'evidence')
 */

// ---- read env ----
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;
const API_KEY = process.env.API_KEY;
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK || "";
const EVIDENCE_BUCKET = process.env.EVIDENCE_BUCKET || "evidence";

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.warn("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE env var.");
}

// init supabase client with service role (server-only)
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false },
});

// ---- simple detection regexes ----
const FAILED_LOGIN_RE = /failed login|authentication failed|invalid credentials|login failed|status=FAILED/i;
const SQLI_RE = /(\bunion\b.*\bselect\b)|(\bor\s+1\s*=\s*1\b)|(\binject\b)|(\bselect\s+\*\b)|(\bunion select\b)/i;
const SUSPICIOUS_UA_RE = /(curl|sqlmap|nikto|fuzzer|masscan|nmap|python-requests)/i;
const IP_RE = /\b(\d{1,3}\.){3}\d{1,3}\b/;

// ---- helper: detect rules ----
function detectRules(text) {
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

// ---- helper: extract ip from text ----
function extractIp(text) {
  if (!text) return null;
  const m = text.match(IP_RE);
  return m ? m[0] : null;
}

// ---- helper: store evidence to supabase storage (optional) ----
async function storeEvidence(incidentId, message) {
  try {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) return null;
    // create a small text file with the raw message
    const path = `${incidentId}.txt`;
    const { error } = await supabase.storage.from(EVIDENCE_BUCKET).upload(path, Buffer.from(String(message)), {
      contentType: "text/plain",
      upsert: true,
    });
    if (error) {
      console.warn("storeEvidence: upload error", error.message);
      return null;
    }
    // public URL (only works if bucket is public) - for private, you'd generate signed URL
    const { publicURL } = supabase.storage.from(EVIDENCE_BUCKET).getPublicUrl(path);
    return publicURL || null;
  } catch (err) {
    console.warn("storeEvidence exception:", err?.message || err);
    return null;
  }
}

// ---- helper: save incident to incidents table ----
async function saveIncident(incidentObj) {
  const { data, error } = await supabase.from("incidents").insert([incidentObj]);
  if (error) {
    console.error("saveIncident error:", error);
    throw new Error(error.message);
  }
  return data;
}

// ---- helper: update counters for brute-force detection (5 min window) ----
async function updateCounter(ip) {
  if (!ip) return null;
  try {
    const now = Date.now();
    const windowStart = Math.floor((now - 5 * 60 * 1000) / 1000); // seconds rounded
    const counterId = `${ip}-${windowStart}`;

    // try to fetch existing counter for this bucket (exact counter_id)
    const { data: existing, error } = await supabase
      .from("counters")
      .select("*")
      .eq("counter_id", counterId)
      .maybeSingle();

    if (error) {
      console.warn("updateCounter select error:", error.message);
    }

    if (!existing) {
      // create new counter record
      const { error: insErr } = await supabase.from("counters").insert([
        {
          counter_id: counterId,
          ip,
          window_start: windowStart,
          count: 1,
          last_seen: new Date().toISOString(),
        },
      ]);
      if (insErr) console.warn("updateCounter insert error:", insErr.message);
      return 1;
    } else {
      const newCount = (existing.count || 0) + 1;
      const { error: updErr } = await supabase
        .from("counters")
        .update({ count: newCount, last_seen: new Date().toISOString() })
        .eq("counter_id", counterId);
      if (updErr) console.warn("updateCounter update error:", updErr.message);
      return newCount;
    }
  } catch (err) {
    console.warn("updateCounter exception:", err?.message || err);
    return null;
  }
}

// ---- helper: send alert to webhook (discord/slack etc) ----
async function sendAlertWebhook(title, body) {
  if (!ALERT_WEBHOOK) return;
  try {
    await fetch(ALERT_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // Discord webhook expects { content: "..." } — adapt as needed for Slack
      body: JSON.stringify({ content: `**${title}**\n${body}` }),
    });
  } catch (err) {
    console.warn("sendAlertWebhook error:", err?.message || err);
  }
}

// ---- main handler ----
export default async function handler(req, res) {
  // Accept only POST
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  // API key protection
  if (!API_KEY || req.headers["x-api-key"] !== API_KEY) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }

  try {
    // parse payload (accept string or object)
    const payload = req.body;
    const message = payload?.message || (typeof payload === "string" ? payload : JSON.stringify(payload));
    const timestamp = payload?.timestamp || new Date().toISOString();
    const meta = payload?.meta || null;

    // detect rules
    const findings = detectRules(String(message));
    // if nothing suspicious, we still optionally store a minimal record or return empty findings
    if (!findings || findings.length === 0) {
      return res.status(200).json({ ok: true, findings: [] });
    }

    // gather info
    const ipFromMessage = extractIp(String(message));
    const realIp = ipFromMessage || req.headers["x-forwarded-for"]?.split(",")[0] || req.headers["x-source"] || req.socket?.remoteAddress || "unknown";

    // incident id + excerpt
    const incidentId = `inc-${uuidv4()}`;
    const excerpt = String(message).slice(0, 800);

    // store evidence (optional) - returns public URL or null
    const evidencePath = await storeEvidence(incidentId, message);

    // build incident object to insert
    const incident = {
      incident_id: incidentId,
      created_at: new Date(timestamp).toISOString(),
      log_source: realIp,
      findings: findings.map((f) => f.rule),
      message_excerpt: excerpt,
      evidence_path: evidencePath,
      extra: { findings, meta },
    };

    // save to incidents table
    await saveIncident(incident);

    // if message indicates failed login -> update counters and check brute-force threshold
    let bruteForceTriggered = false;
    if (FAILED_LOGIN_RE.test(String(message))) {
      const count = await updateCounter(realIp);
      if (typeof count === "number" && count >= 3) {
        // create a brute-force incident row
        const bfIncident = {
          incident_id: `bf-${uuidv4()}`,
          created_at: new Date().toISOString(),
          log_source: realIp,
          findings: ["brute-force"],
          message_excerpt: `Multiple failed login attempts detected from IP ${realIp} (count=${count})`,
          extra: { attempts: count },
        };
        await saveIncident(bfIncident);
        bruteForceTriggered = true;
        // notify
        await sendAlertWebhook("Brute-force detected", `IP ${realIp} had ${count} failed logins in 5m`);
      }
    }

    // If any critical severity, send alert as well
    const critical = findings.find((f) => f.severity === "critical");
    if (critical) {
      await sendAlertWebhook("Critical finding detected", `${critical.desc}\nIP: ${realIp}\nExcerpt: ${excerpt}`);
    }

    // respond with created incident
    return res.status(201).json({ ok: true, incident, bruteForce: bruteForceTriggered });
  } catch (err) {
    console.error("Handler exception:", err);
    return res.status(500).json({ ok: false, error: "internal_error", details: String(err) });
  }
}
