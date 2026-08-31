export default function StatusPill({ connected }) {
  return (
    <div
      className={`flex items-center gap-2 rounded-full border px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider ${
        connected
          ? "border-safe/30 bg-safe/10 text-safe"
          : "border-crit/30 bg-crit/10 text-crit"
      }`}
    >
      <span
        className={`pulse-dot h-1.5 w-1.5 rounded-full ${connected ? "bg-safe" : "bg-crit"}`}
      />
      {connected ? "Gateway Live" : "Reconnecting…"}
    </div>
  );
}
