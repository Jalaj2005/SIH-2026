"use client";

import { useEffect, useState, useCallback } from "react";
import { getSocket } from "@/lib/socket";
import { fetchStats, fetchQueries, fetchClients } from "@/lib/api";
import StatCard from "@/components/StatCard";
import StatusPill from "@/components/StatusPill";
import LiveFeed from "@/components/LiveFeed";
import ClientHealth from "@/components/ClientHealth";
import ThreatBreakdown from "@/components/ThreatBreakdown";
import PcapUploader from "@/components/PcapUploader";

const MAX_FEED_ROWS = 60;

export default function Dashboard() {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [clients, setClients] = useState([]);
  const [apiError, setApiError] = useState(false);

  const refreshStatsAndClients = useCallback(async () => {
    try {
      const [s, c] = await Promise.all([fetchStats(), fetchClients()]);
      setStats(s);
      setClients(c);
      setApiError(false);
    } catch {
      setApiError(true);
    }
  }, []);

  useEffect(() => {
    const socket = getSocket();
    socket.connect();

    socket.on("connect", () => setConnected(true));
    socket.on("disconnect", () => setConnected(false));

    socket.on("dns:snapshot", (snapshot) => {
      setEvents(snapshot.slice(0, MAX_FEED_ROWS));
    });

    socket.on("dns:event", (evt) => {
      setEvents((prev) => [evt, ...prev].slice(0, MAX_FEED_ROWS));
    });

    (async () => {
      try {
        setEvents(await fetchQueries(MAX_FEED_ROWS));
      } catch {
        setApiError(true);
      }
      await refreshStatsAndClients();
    })();

    const poll = setInterval(refreshStatsAndClients, 3000);

    return () => {
      clearInterval(poll);
      socket.off("connect");
      socket.off("disconnect");
      socket.off("dns:snapshot");
      socket.off("dns:event");
      socket.disconnect();
    };
  }, [refreshStatsAndClients]);

  return (
    <div className="min-h-screen px-6 py-6 lg:px-10 lg:py-8 max-w-[1440px] mx-auto">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between mb-8">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-safe mb-1">
            SIH1524 · Module 6 · ISRO
          </p>
          <h1 className="font-display text-2xl sm:text-3xl font-bold tracking-tight">
            DNS Sentinel <span className="text-text-dim font-normal">/ SOC Console</span>
          </h1>
        </div>
        <div className="flex items-center gap-3">
          {apiError && (
            <span className="font-mono text-[11px] text-crit">API unreachable — is the backend running?</span>
          )}
          <StatusPill connected={connected} />
        </div>
      </header>

      <section className="grid grid-cols-2 lg:grid-cols-5 gap-3 mb-6">
        <StatCard label="Total Queries" value={stats?.total_queries ?? "—"} sub="rolling buffer" />
        <StatCard
          label="Blocked"
          value={stats?.blocked ?? "—"}
          sub={`${stats?.block_rate ?? 0}% block rate`}
          accent="text-crit"
        />
        <StatCard label="Flagged" value={stats?.flagged ?? "—"} sub="tunneling suspects" accent="text-warn" />
        <StatCard label="Allowed" value={stats?.allowed ?? "—"} sub="resolved & cached" accent="text-safe" />
        <StatCard
          label="Avg Latency"
          value={stats ? `${stats.avg_response_time_ms}ms` : "—"}
          sub="target < 100ms"
        />
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="lg:col-span-2">
          <LiveFeed events={events} />
        </div>
        <div>
          <ClientHealth clients={clients} />
        </div>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <ThreatBreakdown threatsByReason={stats?.threats_by_reason} />
        </div>
        <div>
          <PcapUploader />
        </div>
      </section>

      <footer className="mt-8 pt-4 border-t border-border">
        <p className="font-mono text-[10px] text-text-dim">
          Module 6 gateway — telemetry shown here uses a mock generator matching the Module 2/3/4/5 output
          contracts. Point NEXT_PUBLIC_API_URL at the real backend to go live.
        </p>
      </footer>
    </div>
  );
}
