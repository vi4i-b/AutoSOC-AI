// Interactive network topology map (React + Cytoscape.js).
//
// - Renders tenant-scoped nodes/edges from the backend.
// - Live status via WebSocket (Active / Under attack / Isolated / Offline /
//   Suspected compromise) with color coding.
// - Right-click / tap a node → context menu whose actions are exactly those the
//   current JWT is allowed to perform (the server sends `data.actions`).
import React, { useEffect, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { fetchMap, nodeAction, askAi, openMapStream } from "./api";

const STATUS_COLOR = {
  active: "#5dd39e",
  under_attack: "#ff6b7a",
  isolated: "#ffd36b",
  offline: "#6e86a0",
  suspected_compromise: "#b79cff",
  gateway: "#2b7fff",
};

const ACTION_LABEL = {
  isolate: "🔒 Isolate",
  process_tree: "🌳 Process tree",
  ask_ai: "🤖 Ask AI",
  rollback: "↩️ Rollback",
};

export default function NetworkMap({ token, tenantId }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [menu, setMenu] = useState(null); // { x, y, node }
  const [toast, setToast] = useState("");

  const style = useMemo(() => [
    {
      selector: "node",
      style: {
        "background-color": (n) => STATUS_COLOR[n.data("type") === "gateway" ? "gateway" : n.data("status")] || "#6e86a0",
        label: "data(label)",
        color: "#dbe8f4",
        "font-size": 11,
        "text-valign": "bottom",
        "text-margin-y": 6,
        width: (n) => (n.data("type") === "gateway" ? 46 : 30),
        height: (n) => (n.data("type") === "gateway" ? 46 : 30),
        "border-width": (n) => (n.data("status") === "under_attack" ? 4 : 0),
        "border-color": "#ff6b7a",
      },
    },
    {
      selector: "edge",
      style: { width: 2, "line-color": "#20344a", "curve-style": "bezier", "target-arrow-shape": "none" },
    },
  ], []);

  // Initialize Cytoscape once.
  useEffect(() => {
    const cy = cytoscape({ container: containerRef.current, style, elements: [], layout: { name: "grid" } });
    cyRef.current = cy;
    cy.on("cxttap tap", "node", (evt) => {
      const node = evt.target;
      if (node.data("type") === "gateway") return;
      const pos = evt.renderedPosition || { x: 100, y: 100 };
      setMenu({ x: pos.x, y: pos.y, node: node.data() });
    });
    cy.on("tap", (evt) => { if (evt.target === cy) setMenu(null); });
    return () => cy.destroy();
  }, [style]);

  // Load once, then subscribe to live updates.
  useEffect(() => {
    let ws;
    let cancelled = false;

    const render = (snapshot) => {
      const cy = cyRef.current;
      if (!cy || cancelled) return;
      cy.json({ elements: { nodes: snapshot.nodes, edges: snapshot.edges } });
      cy.layout({ name: "concentric", concentric: (n) => (n.data("type") === "gateway" ? 10 : 1), minNodeSpacing: 40 }).run();
    };

    fetchMap(token, tenantId).then(render).catch((e) => setToast(e.message));
    ws = openMapStream(token, tenantId, render, () => {
      // On disconnect, degrade to periodic polling.
      const poll = setInterval(() => fetchMap(token, tenantId).then(render).catch(() => {}), 5000);
      ws = { close: () => clearInterval(poll) };
    });

    return () => { cancelled = true; ws && ws.close && ws.close(); };
  }, [token, tenantId]);

  const runAction = async (action, nodeData) => {
    setMenu(null);
    try {
      if (action === "ask_ai") {
        const q = window.prompt(`Ask the AI analyst about ${nodeData.label}:`, "suspicious process on host");
        if (!q) return;
        const r = await askAi(token, tenantId, q);
        setToast(r.matched ? `AI: ${r.mitre} ${r.name} (${r.severity})` : "AI: no MITRE match");
        return;
      }
      const r = await nodeAction(token, tenantId, nodeData.id, action);
      setToast(`${action}: ${JSON.stringify(r).slice(0, 120)}`);
    } catch (e) {
      setToast(e.message);
    }
  };

  return (
    <div style={{ position: "relative", width: "100%", height: "100%", background: "#07111b" }}>
      <div ref={containerRef} style={{ width: "100%", height: "100%" }} />

      {menu && (
        <ul style={menuStyle(menu)} onMouseLeave={() => setMenu(null)}>
          <li style={menuHeader}>{menu.node.label} · {menu.node.status}</li>
          {(menu.node.actions || []).map((a) => (
            <li key={a} style={menuItem} onClick={() => runAction(a, menu.node)}>
              {ACTION_LABEL[a] || a}
            </li>
          ))}
          {(!menu.node.actions || menu.node.actions.length === 0) && (
            <li style={{ ...menuItem, color: "#6e86a0", cursor: "default" }}>No permitted actions</li>
          )}
        </ul>
      )}

      {toast && (
        <div style={toastStyle} onClick={() => setToast("")}>{toast}</div>
      )}
    </div>
  );
}

const menuStyle = (m) => ({
  position: "absolute", left: m.x, top: m.y, listStyle: "none", margin: 0, padding: 6,
  background: "#111c2b", border: "1px solid #20344a", borderRadius: 10, minWidth: 180,
  boxShadow: "0 8px 24px rgba(0,0,0,.5)", zIndex: 10,
});
const menuHeader = { padding: "6px 10px", color: "#77beff", fontWeight: 700, fontSize: 12, borderBottom: "1px solid #20344a", marginBottom: 4 };
const menuItem = { padding: "8px 10px", color: "#dbe8f4", cursor: "pointer", borderRadius: 6, fontSize: 13 };
const toastStyle = { position: "absolute", bottom: 16, left: "50%", transform: "translateX(-50%)", background: "#0d1b2a", color: "#dbe8f4", padding: "10px 16px", borderRadius: 10, border: "1px solid #20344a", cursor: "pointer" };
