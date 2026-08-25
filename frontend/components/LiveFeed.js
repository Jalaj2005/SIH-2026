const VERDICT_STYLE = {
  ALLOW: "text-safe bg-safe/10 border-safe/25",
  FLAG: "text-warn bg-warn/10 border-warn/25",
  BLOCK: "text-crit bg-crit/10 border-crit/25",
};

function timeOnly(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-IN", { hour12: false });
}

function riskColor(risk) {
  if (risk >= 0.8) return "text-crit";
  if (risk >= 0.5) return "text-warn";
  return "text-text-muted";
}

export default function LiveFeed({ events }) {
  return (
    <div className="bg-panel border border-border rounded-lg overflow-hidden flex flex-col h-full">
      <div className="scan-sweep flex items-center justify-between border-b border-border px-4 py-3">
        <div>
          <h2 className="font-display text-sm font-semibold tracking-wide">Live Query Stream</h2>
          <p className="text-[11px] text-text-dim font-mono mt-0.5">
            cache → stix/taxii → blacklist → ai/ml scoring
          </p>
        </div>
        <span className="font-mono text-[10px] uppercase tracking-widest text-text-dim">
          {events.length} events buffered
        </span>
      </div>

      <div className="overflow-y-auto flex-1 max-h-[520px]">
        <table className="w-full text-left font-mono text-[12px]">
          <thead className="sticky top-0 bg-panel-raised z-10">
            <tr className="text-text-dim uppercase text-[10px] tracking-wider">
              <th className="px-4 py-2 font-medium">Time</th>
              <th className="px-3 py-2 font-medium">Verdict</th>
              <th className="px-3 py-2 font-medium">Domain</th>
              <th className="px-3 py-2 font-medium">Client</th>
              <th className="px-3 py-2 font-medium">Type</th>
              <th className="px-3 py-2 font-medium">Risk</th>
              <th className="px-4 py-2 font-medium">Reason</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr
                key={e.id}
                className={`border-t border-border/60 hover:bg-panel-raised/60 ${
                  e.verdict === "BLOCK" ? "row-in-crit" : "row-in"
                }`}
              >
                <td className="px-4 py-2 text-text-muted whitespace-nowrap">{timeOnly(e.timestamp)}</td>
                <td className="px-3 py-2">
                  <span
                    className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold tracking-wide ${VERDICT_STYLE[e.verdict]}`}
                  >
                    {e.verdict}
                  </span>
                </td>
                <td className="px-3 py-2 max-w-[220px] truncate text-text-primary" title={e.domain}>
                  {e.domain}
                </td>
                <td className="px-3 py-2 text-text-muted whitespace-nowrap">{e.client_ip}</td>
                <td className="px-3 py-2 text-text-dim">{e.query_type}</td>
                <td className={`px-3 py-2 font-semibold ${riskColor(e.composite_risk)}`}>
                  {e.composite_risk.toFixed(2)}
                </td>
                <td className="px-4 py-2 text-text-muted whitespace-nowrap">{e.reason}</td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-text-dim">
                  Waiting for first telemetry event…
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
