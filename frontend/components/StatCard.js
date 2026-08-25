export default function StatCard({ label, value, sub, accent = "text-primary" }) {
  return (
    <div className="bg-panel border border-border rounded-lg px-5 py-4 flex flex-col gap-1.5">
      <span className="font-mono text-[11px] uppercase tracking-[0.14em] text-text-dim">
        {label}
      </span>
      <span className={`font-display text-3xl font-semibold ${accent}`}>{value}</span>
      {sub && <span className="text-xs text-text-muted">{sub}</span>}
    </div>
  );
}
