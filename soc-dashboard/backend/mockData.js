// Mock telemetry generator for the SOC dashboard.
// Shapes here intentionally mirror the Module 2 / 3 / 4 / 5 output
// contracts defined in distribution.docx, so swapping this generator
// for real service calls later is a drop-in replacement.

const SAFE_DOMAINS = [
  "google.com", "github.com", "cloudflare.com", "isro.gov.in",
  "microsoft.com", "npmjs.org", "wikipedia.org", "nic.in",
  "office365.com", "zoom.us", "slack.com", "ubuntu.com",
  "python.org", "amazon.in", "mail.google.com",
];

const DGA_DOMAINS = [
  "x89vf2qlmn3.top", "qxz78m4v.net", "kj4h2ndqp9x.xyz",
  "z0nq8vft2r.top", "b7mxqk1z9p.info", "vh3nxz88kq.top",
  "3f9mqz71xv.xyz", "n0xk9vqz2m.club",
];

const PHISHING_DOMAINS = [
  "isro-login-portal.com", "paypa1.com", "goog1e.com",
  "isro-auth-verification.top", "secure-nic-in.com",
  "microsft-update.com", "verify-employee-portal.in",
];

const TUNNELING_DOMAINS = [
  "aW5mb3JtYXRpb24tZXhmaWw.data.attacker-c2.com",
  "dGhpc2lzYXRlc3Q.payload.exfil-node.net",
  "cGFzc3dvcmRkdW1w.leak.badactor.top",
];

const QUERY_TYPES = ["A", "AAAA", "TXT", "NULL", "CNAME"];

const INTEL_SOURCES = ["AlienVault_OTX", "URLhaus", "MISP"];

const DEVICE_NAMES = [
  "WKSTN-ENG-014", "WKSTN-ENG-027", "SRV-FILE-02", "WKSTN-HR-009",
  "SRV-DB-PRIMARY", "WKSTN-ADMIN-003", "LAPTOP-FIELD-11", "SRV-MAIL-01",
  "WKSTN-LAB-021", "IOT-SENSOR-GATE-04",
];

function randomClientPool(n = 10) {
  return Array.from({ length: n }, (_, i) => ({
    ip: `192.168.1.${10 + i}`,
    hostname: DEVICE_NAMES[i % DEVICE_NAMES.length],
  }));
}

const CLIENTS = randomClientPool(10);

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function round(n, d = 2) {
  return Math.round(n * 10 ** d) / 10 ** d;
}

// Weighted category roll: mostly benign traffic, occasional threats.
function rollCategory() {
  const r = Math.random();
  if (r < 0.72) return "safe";
  if (r < 0.85) return "dga";
  if (r < 0.94) return "phishing";
  return "tunneling";
}

let eventCounter = 0;

function generateEvent() {
  eventCounter += 1;
  const category = rollCategory();
  const client = pick(CLIENTS);
  let domain, dga_score, is_dga, is_blacklisted, threat_source, threat_type,
    query_type = "A", composite_risk, verdict, reason;

  const inference_time_ms = round(0.8 + Math.random() * 4, 2);

  switch (category) {
    case "dga":
      domain = pick(DGA_DOMAINS);
      dga_score = round(0.75 + Math.random() * 0.24, 2);
      is_dga = true;
      is_blacklisted = false;
      composite_risk = round(Math.min(0.99, dga_score + Math.random() * 0.05), 2);
      verdict = "BLOCK";
      reason = "DGA_Detected";
      break;
    case "phishing":
      domain = pick(PHISHING_DOMAINS);
      dga_score = round(Math.random() * 0.2, 2);
      is_dga = false;
      is_blacklisted = true;
      threat_source = pick(INTEL_SOURCES);
      threat_type = "phishing";
      composite_risk = round(0.85 + Math.random() * 0.14, 2);
      verdict = "BLOCK";
      reason = "Threat_Intel_Match";
      break;
    case "tunneling":
      domain = pick(TUNNELING_DOMAINS);
      query_type = pick(["TXT", "NULL"]);
      dga_score = round(0.2 + Math.random() * 0.3, 2);
      is_dga = false;
      is_blacklisted = false;
      composite_risk = round(0.7 + Math.random() * 0.28, 2);
      verdict = composite_risk > 0.8 ? "BLOCK" : "FLAG";
      reason = "DNS_Tunneling_Suspected";
      break;
    default:
      domain = pick(SAFE_DOMAINS);
      dga_score = round(Math.random() * 0.15, 2);
      is_dga = false;
      is_blacklisted = false;
      composite_risk = round(Math.random() * 0.2, 2);
      verdict = "ALLOW";
      reason = "Clean";
  }

  return {
    id: `evt_${Date.now()}_${eventCounter}`,
    timestamp: new Date().toISOString(),
    client_ip: client.ip,
    client_hostname: client.hostname,
    domain,
    query_type,
    dga_score,
    is_dga,
    intel_match: is_blacklisted,
    is_blacklisted,
    threat_source: threat_source || null,
    threat_type: threat_type || null,
    composite_risk,
    verdict, // ALLOW | FLAG | BLOCK
    reason,
    response_time_ms: verdict === "ALLOW" ? round(1 + Math.random() * 3, 2) : round(3 + Math.random() * 6, 2),
    inference_time_ms,
  };
}

function clientHealthSnapshot(recentEvents) {
  return CLIENTS.map((c) => {
    const own = recentEvents.filter((e) => e.client_ip === c.ip);
    const blocked = own.filter((e) => e.verdict === "BLOCK").length;
    const total = own.length;
    let status = "healthy";
    if (blocked >= 3) status = "compromised";
    else if (blocked >= 1) status = "suspicious";
    return {
      ip: c.ip,
      hostname: c.hostname,
      status, // healthy | suspicious | compromised
      queries_last_window: total,
      blocked_last_window: blocked,
      last_seen: total > 0 ? own[own.length - 1].timestamp : null,
    };
  });
}

module.exports = {
  generateEvent,
  clientHealthSnapshot,
  CLIENTS,
};
