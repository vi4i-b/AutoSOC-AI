// Minimal shell: log in, then show the interactive network map.
import React, { useState } from "react";
import { login } from "./api";
import NetworkMap from "./NetworkMap";

export default function App() {
  const [session, setSession] = useState(null); // { token, tenantId }
  const [form, setForm] = useState({ username: "", password: "", tenant: "" });
  const [error, setError] = useState("");

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      const r = await login(form.username, form.password, form.tenant || null);
      setSession({ token: r.access_token, tenantId: r.tenant_id || form.tenant || null });
    } catch (err) {
      setError(err.message);
    }
  };

  if (session) {
    return (
      <div style={{ height: "100vh", display: "flex", flexDirection: "column", background: "#07111b" }}>
        <header style={header}>
          <b style={{ color: "#f4f8fc" }}>Auto<span style={{ color: "#77beff" }}>SOC</span></b>
          <span style={{ color: "#93a9c2", marginLeft: 12 }}>Network Topology</span>
          <button style={logout} onClick={() => setSession(null)}>Log out</button>
        </header>
        <div style={{ flex: 1 }}>
          <NetworkMap token={session.token} tenantId={session.tenantId} />
        </div>
      </div>
    );
  }

  return (
    <div style={loginWrap}>
      <form onSubmit={submit} style={loginCard}>
        <h2 style={{ color: "#f4f8fc", margin: "0 0 4px" }}>AutoSOC Enterprise</h2>
        <p style={{ color: "#93a9c2", marginTop: 0, fontSize: 13 }}>Sign in to your SOC console</p>
        <input style={input} placeholder="Username" value={form.username}
               onChange={(e) => setForm({ ...form, username: e.target.value })} />
        <input style={input} type="password" placeholder="Password" value={form.password}
               onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <input style={input} placeholder="Tenant ID (optional)" value={form.tenant}
               onChange={(e) => setForm({ ...form, tenant: e.target.value })} />
        {error && <div style={{ color: "#ff6b7a", fontSize: 13 }}>{error}</div>}
        <button style={button} type="submit">Sign in</button>
      </form>
    </div>
  );
}

const header = { display: "flex", alignItems: "center", padding: "12px 20px", borderBottom: "1px solid #1d3347" };
const logout = { marginLeft: "auto", background: "#243244", color: "#dbe8f4", border: "none", borderRadius: 8, padding: "6px 14px", cursor: "pointer" };
const loginWrap = { height: "100vh", display: "grid", placeItems: "center", background: "#07111b" };
const loginCard = { display: "flex", flexDirection: "column", gap: 10, width: 320, padding: 28, background: "#0d1b2a", border: "1px solid #1d3347", borderRadius: 16 };
const input = { height: 40, borderRadius: 10, border: "1px solid #29425c", background: "#0a1522", color: "#f4f8fc", padding: "0 12px" };
const button = { height: 44, borderRadius: 12, border: "none", background: "#2b7fff", color: "#fff", fontWeight: 700, cursor: "pointer" };
