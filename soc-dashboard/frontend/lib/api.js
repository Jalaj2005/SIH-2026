export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000";

async function getJSON(path) {
  const res = await fetch(`${API_URL}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Request failed: ${path}`);
  return res.json();
}

export const fetchStats = () => getJSON("/api/stats");
export const fetchQueries = (limit = 50) => getJSON(`/api/queries?limit=${limit}`);
export const fetchClients = () => getJSON("/api/clients");
export const fetchRecentThreats = (limit = 20) => getJSON(`/api/threats/recent?limit=${limit}`);
export const fetchForensicReports = () => getJSON("/api/forensics/reports");

export async function uploadPcap(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_URL}/api/forensics/upload`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Upload failed" }));
    throw new Error(err.error || "Upload failed");
  }
  return res.json();
}
