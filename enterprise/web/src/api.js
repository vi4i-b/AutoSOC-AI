// Thin API client for the AutoSOC enterprise backend.
//
// The JWT is sent on every request; a super-admin additionally selects a
// tenant via the X-Tenant-ID header. The backend already gates each action by
// permission, so the UI only decorates — it never grants access it doesn't have.

const BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

function headers(token, tenantId) {
  const h = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
  if (tenantId) h["X-Tenant-ID"] = tenantId;
  return h;
}

export async function login(username, password, tenantId) {
  const res = await fetch(`${BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, tenant_id: tenantId || null }),
  });
  if (!res.ok) throw new Error(`Login failed (${res.status})`);
  return res.json();
}

export async function fetchMap(token, tenantId) {
  const res = await fetch(`${BASE}/network/map`, { headers: headers(token, tenantId) });
  if (!res.ok) throw new Error(`Map fetch failed (${res.status})`);
  return res.json();
}

export async function nodeAction(token, tenantId, agentUid, action) {
  const res = await fetch(`${BASE}/network/nodes/${encodeURIComponent(agentUid)}/action`, {
    method: "POST",
    headers: headers(token, tenantId),
    body: JSON.stringify({ action }),
  });
  if (!res.ok) throw new Error(`Action '${action}' failed (${res.status})`);
  return res.json();
}

export async function askAi(token, tenantId, message) {
  const res = await fetch(`${BASE}/ai/query`, {
    method: "POST",
    headers: headers(token, tenantId),
    body: JSON.stringify({ message }),
  });
  if (!res.ok) throw new Error(`AI query failed (${res.status})`);
  return res.json();
}

// Real-time map updates over WebSocket (falls back to polling if it closes).
export function openMapStream(token, tenantId, onSnapshot, onClose) {
  const wsBase = BASE.replace(/^http/, "ws");
  const params = new URLSearchParams({ token });
  if (tenantId) params.set("tenant", tenantId);
  const ws = new WebSocket(`${wsBase}/network/stream?${params.toString()}`);
  ws.onmessage = (ev) => {
    try { onSnapshot(JSON.parse(ev.data)); } catch { /* ignore malformed frame */ }
  };
  ws.onclose = () => onClose && onClose();
  return ws;
}
