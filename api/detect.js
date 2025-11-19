// api/detect.js
import { createClient } from "@supabase/supabase-js";
import { v4 as uuidv4 } from "uuid";

// read from env
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;
const EVIDENCE_BUCKET = process.env.EVIDENCE_BUCKET || "evidence";
const ALERT_EMAILS = (process.env.ALERT_EMAILS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

// quick sanity log if missing
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.warn("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE env var");
}

// init supabase client with service role
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false },
});

// simple detectors
const FAILED_LOGIN_RE = /failed login|authentication failed|invalid credentials|login failed/i;
const SQLI_RE = /(\%27)|(')|(\-\-)|(\%23)|(#)|(\%3D)|(\bOR\b\s+\b1\b=\b1\b)/i;
const SUSPICIOUS_UA_RE = /(curl|sqlmap|nikto|fuzzer|masscan|nmap|python-requests)/i;
const IP_RE = /(?:\d{1,3}\.){3}\d{1,3}/;

function detectRules(text) {
  const findings = [];
  if (FAILED_LOGIN_RE.test(text)) findings.push("FAILED_LOGIN");
  if (SQLI_RE.test(text)) findings.push("SQL_INJECTION_PATTERN");
  if (SUSPICIOUS_UA_RE.test(text)) findings.push("SUSPICIOUS_USER_AGENT");
  return findings;
}
function extractIp(text) {
  const m = text.match(IP_RE);
  return m ? m[0] : null;
}

async function storeEvidence(incidentId, message) {
  try {
    const filename = `${incidentId}/${Date.now()}.log`;
    const buffer = Buffer.from(String(message), "utf8");

    const { error: uploadError } = await supabase.storage
      .from(EVIDENCE_BUCKET)
      .upload(filename, buffer, {
        contentType: "text/plain",
      });

    if (uploadError) {
      console.error("Evidence upload error:", uploadError);
      return null;
    }

    const { data, error: urlError } = await supabase.storage
      .from(EVIDENCE_BUCKET)
      .createSignedUrl(filename, 60 * 60 * 24);

    if (urlError) {
      console.error("Signed URL error:", urlError);
      return null;
    }

    return data?.signedUrl || null;
  } catch (err) {
    console.error("storeEvidence exception:", err);
    return null;
  }
}

async function saveIncident(incident) {
  try {
    const { error } = await supabase.from("incidents").insert(incident);
    if (error) {
      console.error("Insert Incident Error:", error);
    }
  } catch (err) {
    console.error("saveIncident exception:", err);
  }
}

// stubbed alerts (no SendGrid here)
async function sendAlert(incident) {
  if (!ALERT_EMAILS.length) return;
  // You can implement SendGrid here later.
  console.log("Alert emails configured but email sending is disabled in this build.", ALERT_EMAILS);
}

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return res.status(405).json({ error: "Only POST allowed" });
    }

    const payload = req.body;
    const message =
      payload?.message ||
      (typeof payload === "string" ? payload : JSON.stringify(payload));

    const findings = detectRules(message);
    const ip = extractIp(message);

    if (findings.length === 0) {
      return res.status(200).json({ ok: true, findings: [] });
    }

    const incidentId = `inc-${uuidv4()}`;
    const excerpt = String(message).slice(0, 800);
    const evidencePath = await storeEvidence(incidentId, message);

    const incident = {
      incident_id: incidentId,
      created_at: new Date().toISOString(),
      log_source: req.headers["x-source"] || "vercel",
      findings,
      message_excerpt: excerpt,
      evidence_path: evidencePath,
      extra: payload?.meta || null,
    };

    await saveIncident(incident);
    await sendAlert(incident);

    return res.status(201).json({ ok: true, incident });
  } catch (err) {
    console.error("Handler exception:", err);
    return res.status(500).json({ error: "internal_error", details: String(err) });
  }
}
