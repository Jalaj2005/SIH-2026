const express = require("express");
const http = require("http");
const cors = require("cors");
const multer = require("multer");
const { Server } = require("socket.io");
const { clientHealthSnapshot } = require("./mockData");

const PORT = process.env.PORT || 4000;
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

console.log("Mock telemetry disabled - waiting for real events on POST /api/ingest");

// --- REST API -------------------------------------------------------

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime_s: Math.round(process.uptime()) });
});

app.post("/api/ingest", (req, res) => {
  const body = req.body || {};
  const evt = {
    id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
    client_ip: body.client_ip || "127.0.0.1",
    client_hostname: body.client_hostname || "LOCAL-CLIENT",
    domain: body.domain,
    query_type: body.query_type || "A",
    dga_score: body.dga_score ?? 0.0,
    is_dga: body.is_dga ?? false,
    intel_match: body.intel_match ?? false,
    is_blacklisted: body.is_blacklisted ?? false,
    threat_source: body.threat_source || null,
    threat_type: body.threat_type || null,
    composite_risk: body.composite_risk ?? 0.0,
    verdict: body.verdict,
    reason: body.reason || "Unknown",
    response_time_ms: body.response_time_ms ?? 2.5,
    inference_time_ms: body.inference_time_ms ?? 1.2,
  };

  pushEvent(evt);
  res.sendStatus(200);
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
const MODULE5_URL = process.env.MODULE5_URL || "http://127.0.0.1:8005/analyze";

app.post("/api/forensics/upload", upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const filename = req.file.originalname;
  const isValidType = /\.(pcap|pcapng|tsv|log)$/i.test(filename);
  if (!isValidType) {
    return res.status(400).json({ error: "Expected a .pcap, .pcapng, .tsv, or .log file" });
  }

  try {
    // Proxy to Module 5's forensics service. Their contract:
    //   POST multipart/form-data, field name "file"
    //   -> { total_queries_analyzed, compromises_found, results: [{ src_ip, domain, detected_by, timestamp }] }
    const form = new FormData();
    form.append("file", new Blob([req.file.buffer]), filename);

    const module5Res = await fetch(MODULE5_URL, { method: "POST", body: form });
    if (!module5Res.ok) {
      throw new Error(`Module 5 responded ${module5Res.status}`);
    }
    const raw = await module5Res.json();

    // Adapt Module 5's shape to the shape the dashboard UI expects.
    const detail = raw.results || [];
    const report = {
      report_id: `fr_${Date.now()}`,
      filename,
      uploaded_at: new Date().toISOString(),
      size_bytes: req.file.size,
      total_queries_analyzed: raw.total_queries_analyzed ?? null,
      findings: raw.compromises_found ?? detail.length,
      compromised_hosts: [...new Set(detail.map((f) => f.src_ip))].length,
      detail,
    };

    forensicReports.unshift(report);
    res.json(report);
  } catch (err) {
    console.error("Module 5 forensics call failed:", err.message);
    res.status(502).json({ error: "Forensics service unavailable. Is Module 5 running on :8005?" });
  }
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
