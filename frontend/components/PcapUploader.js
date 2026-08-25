"use client";

import { useCallback, useRef, useState } from "react";
import { uploadPcap } from "@/lib/api";

export default function PcapUploader({ onReport }) {
  const [dragging, setDragging] = useState(false);
  const [status, setStatus] = useState("idle"); // idle | uploading | done | error
  const [error, setError] = useState(null);
  const [lastReport, setLastReport] = useState(null);
  const inputRef = useRef(null);

  const handleFile = useCallback(
    async (file) => {
      if (!file) return;
      setStatus("uploading");
      setError(null);
      try {
        const report = await uploadPcap(file);
        setLastReport(report);
        setStatus("done");
        onReport?.(report);
      } catch (err) {
        setError(err.message || "Upload failed");
        setStatus("error");
      }
    },
    [onReport]
  );

  return (
    <div className="bg-panel border border-border rounded-lg flex flex-col h-full">
      <div className="border-b border-border px-4 py-3">
        <h2 className="font-display text-sm font-semibold tracking-wide">Passive Forensics</h2>
        <p className="text-[11px] text-text-dim font-mono mt-0.5">.pcap / .pcapng / zeek dns.log (.tsv)</p>
      </div>

      <div className="p-4 flex-1 flex flex-col gap-3">
        <label
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            handleFile(e.dataTransfer.files?.[0]);
          }}
          className={`flex flex-col items-center justify-center gap-2 rounded-md border border-dashed px-4 py-8 text-center cursor-pointer transition-colors ${
            dragging ? "border-safe bg-safe/5" : "border-border-bright hover:border-safe/40"
          }`}
        >
          <span className="font-mono text-xs text-text-muted">
            {status === "uploading" ? "Analyzing capture…" : "Drop a capture file or click to browse"}
          </span>
          <span className="font-mono text-[10px] text-text-dim">max 25MB</span>
          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng,.tsv,.log"
            className="hidden"
            onChange={(e) => handleFile(e.target.files?.[0])}
          />
        </label>

        {status === "error" && (
          <p className="text-crit text-xs font-mono">{error}</p>
        )}

        {lastReport && status === "done" && (
          <div className="border border-border rounded-md p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs text-text-primary truncate">{lastReport.filename}</span>
              <span className="font-mono text-[10px] text-text-dim">
                {(lastReport.size_bytes / 1024).toFixed(1)} KB
              </span>
            </div>
            <div className="flex gap-4 font-mono text-[11px]">
              <span className="text-warn">{lastReport.findings} findings</span>
              <span className="text-crit">{lastReport.compromised_hosts} hosts flagged</span>
            </div>
            <ul className="space-y-1 max-h-32 overflow-y-auto">
              {lastReport.detail.map((d, i) => (
                <li key={i} className="font-mono text-[10px] text-text-muted flex justify-between gap-2">
                  <span className="truncate">{d.src_ip} → {d.domain}</span>
                  <span className="text-text-dim shrink-0">{d.detected_by}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
