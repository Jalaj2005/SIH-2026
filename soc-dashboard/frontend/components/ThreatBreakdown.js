"use client";

import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from "recharts";

const REASON_COLOR = {
  DGA_Detected: "#f0a83c",
  Threat_Intel_Match: "#ef5b5b",
  DNS_Tunneling_Suspected: "#9c8bf5",
};

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-panel-raised border border-border-bright rounded px-3 py-2 font-mono text-xs">
      <p className="text-text-primary">{label}</p>
      <p className="text-text-muted">{payload[0].value} events</p>
    </div>
  );
}

export default function ThreatBreakdown({ threatsByReason }) {
  const data = Object.entries(threatsByReason || {}).map(([reason, count]) => ({
    reason: reason.replaceAll("_", " "),
    key: reason,
    count,
  }));

  return (
    <div className="bg-panel border border-border rounded-lg flex flex-col h-full">
      <div className="border-b border-border px-4 py-3">
        <h2 className="font-display text-sm font-semibold tracking-wide">Blocked Traffic by Reason</h2>
        <p className="text-[11px] text-text-dim font-mono mt-0.5">rolling buffer window</p>
      </div>
      <div className="flex-1 p-4 min-h-[220px]">
        {data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-text-dim text-sm">
            No threats detected yet
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%" minHeight={200}>
            <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="reason"
                width={140}
                tick={{ fill: "#6f7f9e", fontSize: 11, fontFamily: "var(--font-mono-data)" }}
                axisLine={{ stroke: "#202c47" }}
                tickLine={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={16}>
                {data.map((d) => (
                  <Cell key={d.key} fill={REASON_COLOR[d.key] || "#2dd4c8"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
