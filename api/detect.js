// api/detect.js
import { createClient } from "@supabase/supabase-js";
import sgMail from "@sendgrid/mail";
import { v4 as uuidv4 } from "uuid";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;
const EVIDENCE_BUCKET = process.env.EVIDENCE_BUCKET || "evidence";

const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const ALERT_EMAILS = (process.env.ALERT_EMAILS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

if (SENDGRID_API_KEY) sgMail.setApiKey(SENDGRID_API_KEY);

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false },
});

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
  const filename = `${incidentId}/${Date.now()}.log`;

  const { error } = await supabase.storage
    .from(EVIDENCE_BUCKET)
    .upload(filename, new Blob([message]), {
      contentType: "text/plain",
    });

  if (error) {
    console.error("Upload error:", error);
    return null;
  }

  const { data } = await supabase.storage
    .from(EVIDENCE_BUCKET)
    .createSignedUrl(filename, 86400);

  return data?.signedUrl || null;
}

async function saveIncident(incident) {
  const { error } = await supabase.from("incidents").insert(incident);
  if (error) console.error("DB insert error:", error);
}

async function sendAlert(incident) {
  if (!SENDGRID_API_KEY || ALERT_EMAILS.length === 0) return;

  const msg = {
    to: ALERT_EMAILS,
    from: process.env.ALERT_SENDER,
    subject: `⚠ Security Alert: ${incident.findings.join(", ")}`,
    text: `Incident: ${incident.incident_id}
Findings: ${incident.findings.join(", ")}
Evidence: ${incident.evidence_path}`
  };

  try { await sgMail.send(msg); } catch(e){ console.error(e); }
}

export default async function handler(req, res){
  if(req.method !== "POST") return res.status(405).json({ error: "POST only" });

  const message = req.body?.message || JSON.stringify(req.body);
  const findings = detectRules(message);
  const ip = extractIp(message);

  if(findings.length===0) return res.status(200).json({ ok:true, findings:[] });

  const incidentId = `inc-${uuidv4()}`;
  const evidencePath = await storeEvidence(incidentId, message);

  const incident = {
    incident_id: incidentId,
    created_at: new Date().toISOString(),
    log_source: req.headers["x-source"] || "vercel",
    findings,
    message_excerpt: message.slice(0,800),
    evidence_path: evidencePath,
    extra: req.body?.meta || null
  };

  await saveIncident(incident);
  await sendAlert(incident);
  return res.status(201).json({ ok:true, incident });
}
