const express = require("express");
const http = require("http");
const cors = require("cors");
const multer = require("multer");
const { Server } = require("socket.io");
const { generateEvent, clientHealthSnapshot } = require("./mockData");

const PORT = process.env.PORT || 4000;
const EVENT_INTERVAL_MS = 1200;
const MAX_BUFFER = 500;

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 25 * 1024 * 1024 } });

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// In-memory rolling telemetry buffer (Module 6 acts as the gateway;
// a real deployment would back this with Postgres/Timescale/Mongo).
let eventBuffer = [];
const forensicReports = [];

function pushEvent(evt) {
  eventBuffer.push(evt);
  if (eventBuffer.length > MAX_BUFFER) eventBuffer.shift();
  io.emit("dns:event", evt);
}

// --- Add this endpoint to accept real events from Module 1 ---
app.post("/api/ingest", (req, res) => {
  const evt = {
    id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    client_ip: req.body.client_ip || "127.0.0.1",
    client_hostname: req.body.client_hostname || "LOCAL-CLIENT",
    domain: req.body.domain,
    query_type: req.body.query_type || "A",
    dga_score: req.body.dga_score ?? 0.0,
    is_dga: req.body.is_dga ?? false,
    intel_match: req.body.intel_match ?? false,
    is_blacklisted: req.body.is_blacklisted ?? false,
    threat_source: req.body.threat_source || null,
    threat_type: req.body.threat_type || null,
    composite_risk: req.body.composite_risk ?? 0.0,
    verdict: req.body.verdict, // "ALLOW" or "BLOCK"
    reason: req.body.reason,
    response_time_ms: req.body.response_time_ms ?? 2.5,
    inference_time_ms: req.body.inference_time_ms ?? 1.2,
  };

  pushEvent(evt);
  res.sendStatus(200);
});

// --- COMMENT OUT OR REMOVE THE MOCK INTERVAL GENERATOR ---
// setInterval(() => {
//   pushEvent(generateEvent());
// }, EVENT_INTERVAL_MS);
// setInterval(() => {
//   pushEvent(generateEvent());
// }, EVENT_INTERVAL_MS);

// --- REST API -------------------------------------------------------

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime_s: Math.round(process.uptime()) });
});

app.get("/api/queries", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, MAX_BUFFER);
  res.json(eventBuffer.slice(-limit).reverse());
});

app.get("/api/stats", (req, res) => {
  const total = eventBuffer.length;
  const blocked = eventBuffer.filter((e) => e.verdict === "BLOCK").length;
  const flagged = eventBuffer.filter((e) => e.verdict === "FLAG").length;
  const allowed = eventBuffer.filter((e) => e.verdict === "ALLOW").length;
  const avgResponse =
    total === 0 ? 0 : round(eventBuffer.reduce((s, e) => s + e.response_time_ms, 0) / total, 2);
  const byReason = {};
  eventBuffer
    .filter((e) => e.verdict !== "ALLOW")
    .forEach((e) => {
      byReason[e.reason] = (byReason[e.reason] || 0) + 1;
    });

  res.json({
    total_queries: total,
    blocked,
    flagged,
    allowed,
    avg_response_time_ms: avgResponse,
    block_rate: total === 0 ? 0 : round((blocked / total) * 100, 1),
    threats_by_reason: byReason,
  });
});

app.get("/api/clients", (req, res) => {
  res.json(clientHealthSnapshot(eventBuffer));
});

app.get("/api/threats/recent", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, MAX_BUFFER);
  res.json(
    eventBuffer
      .filter((e) => e.verdict !== "ALLOW")
      .slice(-limit)
      .reverse()
  );
});

// Passive forensics upload — mirrors Module 5's output contract:
// [{ src_ip, domain, detected_by, timestamp }, ...]
app.post("/api/forensics/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const filename = req.file.originalname;
  const isValidType = /\.(pcap|pcapng|tsv|log)$/i.test(filename);
  if (!isValidType) {
    return res.status(400).json({ error: "Expected a .pcap, .pcapng, .tsv, or .log file" });
  }

  // Mock forensic correlation — in production this proxies to Module 5,
  // whose real output contract is: [{ src_ip, domain, detected_by, timestamp }]
  const findingsCount = 3 + Math.floor(Math.random() * 5);
  const detectors = ["ML_DGA", "STIX_Feed", "DNS_Tunneling", "Typosquat_Heuristic"];
  const suspectDomains = ["malicious-c2.com", "x89vf2qlmn3.top", "isro-login-portal.com"];
  const clientPool = clientHealthSnapshot(eventBuffer);

  const detail = Array.from({ length: findingsCount }, (_, i) => ({
    src_ip: clientPool[i % clientPool.length].ip,
    domain: suspectDomains[i % suspectDomains.length],
    detected_by: detectors[i % detectors.length],
    timestamp: new Date(Date.now() - i * 60000).toISOString(),
  }));

  const report = {
    report_id: `fr_${Date.now()}`,
    filename,
    uploaded_at: new Date().toISOString(),
    size_bytes: req.file.size,
    findings: findingsCount,
    compromised_hosts: [...new Set(detail.map((f) => f.src_ip))].length,
    detail,
  };

  forensicReports.unshift(report);
  res.json(report);
});

app.get("/api/forensics/reports", (req, res) => {
  res.json(forensicReports);
});

function round(n, d = 2) {
  return Math.round(n * 10 ** d) / 10 ** d;
}

io.on("connection", (socket) => {
  socket.emit("dns:snapshot", eventBuffer.slice(-50).reverse());
});

server.listen(PORT, () => {
  console.log(`SOC Dashboard gateway listening on :${PORT}`);
  console.log(`REST:      http://localhost:${PORT}/api/*`);
  console.log(`WebSocket: ws://localhost:${PORT}`);
});

