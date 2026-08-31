const STATUS_STYLE = {
  healthy: { dot: "bg-safe", label: "text-safe", text: "Healthy" },
  suspicious: { dot: "bg-warn", label: "text-warn", text: "Suspicious" },
  compromised: { dot: "bg-crit", label: "text-crit", text: "Compromised" },
};

export default function ClientHealth({ clients }) {
  const sorted = [...clients].sort((a, b) => {
    const order = { compromised: 0, suspicious: 1, healthy: 2 };
    return order[a.status] - order[b.status];
  });

  return (
    <div className="bg-panel border border-border rounded-lg flex flex-col h-full">
      <div className="border-b border-border px-4 py-3">
        <h2 className="font-display text-sm font-semibold tracking-wide">Client Device Health</h2>
        <p className="text-[11px] text-text-dim font-mono mt-0.5">internal ip attribution</p>
      </div>
      <div className="flex-1 overflow-y-auto divide-y divide-border/60 max-h-[430px]">
        {sorted.map((c) => {
          const s = STATUS_STYLE[c.status];
          return (
            <div key={c.ip} className="flex items-center justify-between px-4 py-2.5">
              <div className="flex items-center gap-2.5 min-w-0">
                <span className={`h-2 w-2 rounded-full shrink-0 ${s.dot} ${c.status !== "healthy" ? "pulse-dot" : ""}`} />
                <div className="min-w-0">
                  <p className="text-sm text-text-primary truncate">{c.hostname}</p>
                  <p className="font-mono text-[11px] text-text-dim">{c.ip}</p>
                </div>
              </div>
              <div className="text-right shrink-0">
                <p className={`text-[11px] font-medium ${s.label}`}>{s.text}</p>
                <p className="font-mono text-[10px] text-text-dim">
                  {c.blocked_last_window}/{c.queries_last_window} blocked
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
