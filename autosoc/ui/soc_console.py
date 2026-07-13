"""SOC Operations Console — a dedicated window for analysts and sysadmins.

This is the "work surface" a Tier-1/Tier-2 SOC analyst lives in during a
shift. It centralizes the daily loop:

  * **Triage Queue** — every security event AutoSOC recorded, newest first,
    with severity filtering and one-click promotion to an incident.
  * **Incidents** — case management: status, severity, assignee, MITRE
    ATT&CK technique, running investigation notes.
  * **Endpoints & Agents** — the fleet of hosts reporting in, their health,
    and an enrollment-token generator for onboarding new endpoints.
  * **Threat Intel** — an IOC watchlist to record and look up indicators.
  * **Log Search** — free-text search over centrally ingested logs.
  * **Metrics** — shift KPIs (open cases, alert volume, fleet health).

Everything is backed by the same SQLite store as the dashboard, so the two
windows stay in sync.
"""

import secrets
import tkinter as tk
from datetime import datetime

import customtkinter as ctk

from autosoc.logging_setup import get_logger
from autosoc.ui import theme
from autosoc.ui.theme import apply_window_icon

log = get_logger("ui.soc_console")

SEVERITIES = ["Low", "Medium", "High", "Critical"]
INCIDENT_STATUSES = ["Open", "Investigating", "Contained", "Resolved", "False Positive"]
IOC_TYPES = ["ip", "domain", "url", "hash", "email"]

SEVERITY_COLORS = {
    "Low": theme.ACCENT_GREEN,
    "Medium": theme.ACCENT_YELLOW,
    "High": "#ff9f6e",
    "Critical": theme.STATUS_DANGER,
    "info": theme.TEXT_MUTED,
}


class SOCConsoleWindow(ctk.CTkToplevel):
    def __init__(self, master, db, current_user):
        super().__init__(master)
        self.db = db
        self.current_user = current_user or {}
        self.actor = self.current_user.get("username", "analyst")
        self.selected_incident_id = None

        self.title("AutoSOC — SOC Operations Console")
        self.geometry("1180x780")
        self.minsize(1000, 680)
        self.configure(fg_color=theme.BG_DEEP)
        apply_window_icon(self)

        self._build_header()
        self.tabview = ctk.CTkTabview(
            self,
            fg_color=theme.BG_SIDEBAR,
            segmented_button_selected_color=theme.ACCENT_BLUE,
            segmented_button_selected_hover_color=theme.ACCENT_BLUE_HOVER,
        )
        self.tabview.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self.tab_triage = self.tabview.add("Triage Queue")
        self.tab_incidents = self.tabview.add("Incidents")
        self.tab_agents = self.tabview.add("Endpoints & Agents")
        self.tab_intel = self.tabview.add("Threat Intel")
        self.tab_logs = self.tabview.add("Log Search")
        self.tab_metrics = self.tabview.add("Metrics")

        self._build_triage_tab()
        self._build_incidents_tab()
        self._build_agents_tab()
        self._build_intel_tab()
        self._build_logs_tab()
        self._build_metrics_tab()

        self.refresh_all()

    # ── header ───────────────────────────────────────────────────────

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(16, 10))

        title_stack = ctk.CTkFrame(header, fg_color="transparent")
        title_stack.pack(side="left")
        ctk.CTkLabel(
            title_stack,
            text="SOC Operations Console",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=theme.TEXT_PRIMARY,
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_stack,
            text="Centralized triage, case management, endpoint fleet, and threat intelligence",
            font=ctk.CTkFont(size=12),
            text_color=theme.TEXT_MUTED,
        ).pack(anchor="w")

        role = self.current_user.get("role", "Analyst")
        ctk.CTkLabel(
            header,
            text=f"Operator: {self.actor}  ·  {role}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=theme.STATUS_GOOD,
        ).pack(side="right")

        ctk.CTkButton(
            header,
            text="Refresh",
            width=90,
            height=32,
            corner_radius=12,
            fg_color=theme.BTN_NEUTRAL,
            hover_color=theme.BTN_NEUTRAL_HOVER,
            command=self.refresh_all,
        ).pack(side="right", padx=(0, 12))

    def refresh_all(self):
        self._refresh_triage()
        self._refresh_incidents()
        self._refresh_agents()
        self._refresh_intel()
        self._refresh_logs()
        self._refresh_metrics()

    # ── shared helpers ───────────────────────────────────────────────

    def _scroll_frame(self, parent):
        frame = ctk.CTkScrollableFrame(
            parent,
            fg_color=theme.BG_CONSOLE,
            corner_radius=14,
            scrollbar_button_color="#23384d",
            scrollbar_button_hover_color=theme.ACCENT_BLUE,
        )
        frame.grid_columnconfigure(0, weight=1)
        return frame

    @staticmethod
    def _clear(frame):
        for child in frame.winfo_children():
            child.destroy()

    # ── Triage Queue ─────────────────────────────────────────────────

    def _build_triage_tab(self):
        tab = self.tab_triage
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        ctk.CTkLabel(bar, text="Severity filter:", text_color=theme.TEXT_MUTED,
                     font=ctk.CTkFont(size=12)).pack(side="left", padx=(2, 8))
        self.triage_filter = ctk.CTkOptionMenu(
            bar,
            values=["All", "Critical", "High", "Medium", "Low"],
            width=140,
            fg_color=theme.BG_CARD,
            button_color=theme.BTN_NEUTRAL,
            button_hover_color=theme.BTN_NEUTRAL_HOVER,
            command=lambda _v: self._refresh_triage(),
        )
        self.triage_filter.set("All")
        self.triage_filter.pack(side="left")
        self.triage_count = ctk.CTkLabel(bar, text="", text_color=theme.TEXT_MUTED, font=ctk.CTkFont(size=12))
        self.triage_count.pack(side="right", padx=6)

        self.triage_list = self._scroll_frame(tab)
        self.triage_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _refresh_triage(self):
        self._clear(self.triage_list)
        wanted = self.triage_filter.get() if hasattr(self, "triage_filter") else "All"
        events = self.db.get_recent_security_events(200)
        shown = 0
        for row in events:
            created_at, event_type, severity, source, details = row[0], row[1], row[2], row[3], row[4]
            if wanted != "All" and (severity or "") != wanted:
                continue
            self._triage_row(shown, created_at, event_type, severity, source, details)
            shown += 1
        if shown == 0:
            ctk.CTkLabel(self.triage_list, text="No security events match this filter.",
                         text_color=theme.TEXT_MUTED, font=ctk.CTkFont(size=12)).grid(
                row=0, column=0, sticky="w", padx=12, pady=12)
        self.triage_count.configure(text=f"{shown} event(s)")

    def _triage_row(self, index, created_at, event_type, severity, source, details):
        card = ctk.CTkFrame(self.triage_list, fg_color=theme.BG_PANEL, corner_radius=12)
        card.grid(row=index, column=0, sticky="ew", padx=8, pady=5)
        card.grid_columnconfigure(1, weight=1)

        color = SEVERITY_COLORS.get(severity, theme.TEXT_MUTED)
        ctk.CTkLabel(card, text="●", text_color=color, font=ctk.CTkFont(size=16)).grid(
            row=0, column=0, rowspan=2, sticky="n", padx=(12, 8), pady=10)

        ctk.CTkLabel(
            card,
            text=f"{event_type}  ·  {severity or 'info'}",
            text_color=theme.TEXT_SOFT,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        ).grid(row=0, column=1, sticky="ew", padx=4, pady=(10, 0))
        ctk.CTkLabel(
            card,
            text=f"{created_at}  ·  source: {source}\n{details}",
            text_color="#85a3bd",
            font=ctk.CTkFont(size=11),
            anchor="w",
            justify="left",
            wraplength=640,
        ).grid(row=1, column=1, sticky="ew", padx=4, pady=(0, 10))

        ctk.CTkButton(
            card,
            text="→ Incident",
            width=100,
            height=30,
            corner_radius=10,
            fg_color=theme.ACCENT_RED_DARK,
            hover_color=theme.ACCENT_RED_DARK_HOVER,
            command=lambda: self._promote_event(event_type, severity, source, details),
        ).grid(row=0, column=2, rowspan=2, padx=12, pady=10)

    def _promote_event(self, event_type, severity, source, details):
        incident_severity = severity if severity in SEVERITIES else "Medium"
        incident_id = self.db.create_incident(
            title=f"{event_type} from {source}",
            severity=incident_severity,
            source="triage",
            summary=details,
            created_by=self.actor,
        )
        self.db.add_audit_event("incident_created", self.actor,
                                f"Incident #{incident_id} promoted from event '{event_type}'.")
        self._refresh_incidents()
        self._refresh_metrics()
        self.tabview.set("Incidents")

    # ── Incidents ────────────────────────────────────────────────────

    def _build_incidents_tab(self):
        tab = self.tab_incidents
        tab.grid_columnconfigure(0, weight=2)
        tab.grid_columnconfigure(1, weight=3)
        tab.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 6))
        ctk.CTkLabel(bar, text="Status:", text_color=theme.TEXT_MUTED, font=ctk.CTkFont(size=12)).pack(
            side="left", padx=(2, 8))
        self.incident_filter = ctk.CTkOptionMenu(
            bar,
            values=["All"] + INCIDENT_STATUSES,
            width=150,
            fg_color=theme.BG_CARD,
            button_color=theme.BTN_NEUTRAL,
            button_hover_color=theme.BTN_NEUTRAL_HOVER,
            command=lambda _v: self._refresh_incidents(),
        )
        self.incident_filter.set("All")
        self.incident_filter.pack(side="left")
        ctk.CTkButton(
            bar, text="+ New Incident", width=140, height=30, corner_radius=10,
            fg_color=theme.ACCENT_BLUE, hover_color=theme.ACCENT_BLUE_HOVER,
            command=self._new_incident_dialog,
        ).pack(side="right", padx=6)

        self.incident_list = self._scroll_frame(tab)
        self.incident_list.grid(row=1, column=0, sticky="nsew", padx=(10, 6), pady=(0, 10))

        self.incident_detail = ctk.CTkFrame(tab, fg_color=theme.BG_PANEL, corner_radius=14)
        self.incident_detail.grid(row=1, column=1, sticky="nsew", padx=(6, 10), pady=(0, 10))
        self.incident_detail.grid_columnconfigure(0, weight=1)
        self._render_incident_placeholder()

    def _render_incident_placeholder(self):
        self._clear(self.incident_detail)
        ctk.CTkLabel(
            self.incident_detail,
            text="Select an incident to view and update it.",
            text_color=theme.TEXT_MUTED,
            font=ctk.CTkFont(size=13),
        ).grid(row=0, column=0, padx=20, pady=20)

    def _refresh_incidents(self):
        self._clear(self.incident_list)
        status = self.incident_filter.get() if hasattr(self, "incident_filter") else "All"
        incidents = self.db.list_incidents(status=status)
        if not incidents:
            ctk.CTkLabel(self.incident_list, text="No incidents yet. Promote an event or create one.",
                         text_color=theme.TEXT_MUTED, font=ctk.CTkFont(size=12)).grid(
                row=0, column=0, sticky="w", padx=12, pady=12)
            return
        for index, row in enumerate(incidents):
            self._incident_list_row(index, row)

    def _incident_list_row(self, index, row):
        incident_id, title, severity, status = row[0], row[1], row[2], row[3]
        card = ctk.CTkFrame(self.incident_list, fg_color=theme.BG_PANEL, corner_radius=12)
        card.grid(row=index, column=0, sticky="ew", padx=8, pady=5)
        card.grid_columnconfigure(1, weight=1)

        color = SEVERITY_COLORS.get(severity, theme.TEXT_MUTED)
        ctk.CTkLabel(card, text="●", text_color=color, font=ctk.CTkFont(size=15)).grid(
            row=0, column=0, sticky="n", padx=(12, 8), pady=10)

        stack = ctk.CTkFrame(card, fg_color="transparent")
        stack.grid(row=0, column=1, sticky="ew", pady=8)
        ctk.CTkLabel(stack, text=f"#{incident_id}  {title}", text_color=theme.TEXT_SOFT,
                     font=ctk.CTkFont(size=13, weight="bold"), anchor="w", justify="left",
                     wraplength=280).pack(anchor="w")
        ctk.CTkLabel(stack, text=f"{severity} · {status}", text_color="#85a3bd",
                     font=ctk.CTkFont(size=11), anchor="w").pack(anchor="w")

        ctk.CTkButton(card, text="Open", width=70, height=28, corner_radius=10,
                      fg_color=theme.BTN_NEUTRAL, hover_color=theme.BTN_NEUTRAL_HOVER,
                      command=lambda: self._open_incident(incident_id)).grid(
            row=0, column=2, padx=10, pady=10)

    def _open_incident(self, incident_id):
        self.selected_incident_id = incident_id
        record = self.db.get_incident(incident_id)
        if not record:
            return
        self._clear(self.incident_detail)
        detail = self.incident_detail
        detail.grid_rowconfigure(7, weight=1)

        (iid, title, severity, status, source, assignee, mitre, summary, created_by, created_at, updated_at) = record

        ctk.CTkLabel(detail, text=f"Incident #{iid}", text_color=theme.TEXT_PRIMARY,
                     font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))
        ctk.CTkLabel(detail, text=title, text_color=theme.TEXT_SOFT, font=ctk.CTkFont(size=13),
                     wraplength=520, justify="left", anchor="w").grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

        controls = ctk.CTkFrame(detail, fg_color="transparent")
        controls.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))

        ctk.CTkLabel(controls, text="Status", text_color=theme.TEXT_MUTED,
                     font=ctk.CTkFont(size=11)).grid(row=0, column=0, sticky="w", padx=(0, 6))
        status_menu = ctk.CTkOptionMenu(controls, values=INCIDENT_STATUSES, width=150,
                                        fg_color=theme.BG_CARD, button_color=theme.BTN_NEUTRAL,
                                        button_hover_color=theme.BTN_NEUTRAL_HOVER,
                                        command=lambda v: self._update_incident_field(iid, "status", v))
        status_menu.set(status)
        status_menu.grid(row=0, column=1, sticky="w", padx=(0, 16))

        ctk.CTkLabel(controls, text="Severity", text_color=theme.TEXT_MUTED,
                     font=ctk.CTkFont(size=11)).grid(row=0, column=2, sticky="w", padx=(0, 6))
        sev_menu = ctk.CTkOptionMenu(controls, values=SEVERITIES, width=120,
                                     fg_color=theme.BG_CARD, button_color=theme.BTN_NEUTRAL,
                                     button_hover_color=theme.BTN_NEUTRAL_HOVER,
                                     command=lambda v: self._update_incident_field(iid, "severity", v))
        sev_menu.set(severity if severity in SEVERITIES else "Medium")
        sev_menu.grid(row=0, column=3, sticky="w")

        meta = ctk.CTkFrame(detail, fg_color="transparent")
        meta.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 8))
        meta.grid_columnconfigure(1, weight=1)
        meta.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(meta, text="Assignee", text_color=theme.TEXT_MUTED,
                     font=ctk.CTkFont(size=11)).grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.incident_assignee = ctk.CTkEntry(meta, height=30, width=140, fg_color=theme.BG_FIELD,
                                              border_color=theme.FIELD_BORDER)
        self.incident_assignee.insert(0, assignee or "")
        self.incident_assignee.grid(row=0, column=1, sticky="ew", padx=(0, 12))

        ctk.CTkLabel(meta, text="MITRE ATT&CK", text_color=theme.TEXT_MUTED,
                     font=ctk.CTkFont(size=11)).grid(row=0, column=2, sticky="w", padx=(0, 6))
        self.incident_mitre = ctk.CTkEntry(meta, height=30, width=140, fg_color=theme.BG_FIELD,
                                           border_color=theme.FIELD_BORDER, placeholder_text="e.g. T1566")
        self.incident_mitre.insert(0, mitre or "")
        self.incident_mitre.grid(row=0, column=3, sticky="ew", padx=(0, 8))

        ctk.CTkButton(meta, text="Save", width=70, height=30, corner_radius=10,
                      fg_color=theme.ACCENT_BLUE, hover_color=theme.ACCENT_BLUE_HOVER,
                      command=lambda: self._save_incident_meta(iid)).grid(row=0, column=4, padx=(4, 0))

        ctk.CTkLabel(detail, text=f"Source: {source or '—'}  ·  Opened: {created_at}  ·  By: {created_by or '—'}",
                     text_color=theme.TEXT_FAINT, font=ctk.CTkFont(size=11)).grid(
            row=4, column=0, sticky="w", padx=16, pady=(0, 6))

        if summary:
            summary_box = ctk.CTkTextbox(detail, height=70, fg_color=theme.BG_CONSOLE, corner_radius=12,
                                         text_color=theme.TEXT_SOFT, font=ctk.CTkFont(size=11), wrap="word")
            summary_box.grid(row=5, column=0, sticky="ew", padx=16, pady=(0, 8))
            summary_box.insert("end", summary)
            summary_box.configure(state="disabled")

        ctk.CTkLabel(detail, text="Investigation notes", text_color=theme.TEXT_MUTED,
                     font=ctk.CTkFont(size=12, weight="bold")).grid(row=6, column=0, sticky="w", padx=16, pady=(2, 4))

        self.notes_box = ctk.CTkTextbox(detail, fg_color=theme.BG_CONSOLE, corner_radius=12,
                                        text_color=theme.TEXT_SOFT, font=ctk.CTkFont(size=11), wrap="word")
        self.notes_box.grid(row=7, column=0, sticky="nsew", padx=16, pady=(0, 8))
        self.notes_box.configure(state="normal")
        self.notes_box.delete("0.0", "end")
        notes = self.db.get_incident_notes(iid)
        if notes:
            for created, author, note in notes:
                self.notes_box.insert("end", f"[{created}] {author}: {note}\n")
        else:
            self.notes_box.insert("end", "No notes yet.\n")
        self.notes_box.configure(state="disabled")

        add_note_row = ctk.CTkFrame(detail, fg_color="transparent")
        add_note_row.grid(row=8, column=0, sticky="ew", padx=16, pady=(0, 14))
        add_note_row.grid_columnconfigure(0, weight=1)
        self.note_entry = ctk.CTkEntry(add_note_row, height=34, fg_color=theme.BG_FIELD,
                                       border_color=theme.FIELD_BORDER, placeholder_text="Add an investigation note…")
        self.note_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.note_entry.bind("<Return>", lambda e: self._add_note(iid))
        ctk.CTkButton(add_note_row, text="Add", width=80, height=34, corner_radius=10,
                      fg_color=theme.ACCENT_BLUE, hover_color=theme.ACCENT_BLUE_HOVER,
                      command=lambda: self._add_note(iid)).grid(row=0, column=1)

    def _update_incident_field(self, incident_id, field, value):
        self.db.update_incident(incident_id, **{field: value})
        self.db.add_audit_event("incident_updated", self.actor,
                                f"Incident #{incident_id} {field} -> {value}.")
        self._refresh_incidents()
        self._refresh_metrics()

    def _save_incident_meta(self, incident_id):
        self.db.update_incident(
            incident_id,
            assignee=self.incident_assignee.get().strip(),
            mitre=self.incident_mitre.get().strip(),
        )
        self.db.add_audit_event("incident_updated", self.actor, f"Incident #{incident_id} metadata saved.")
        self._open_incident(incident_id)

    def _add_note(self, incident_id):
        note = self.note_entry.get().strip()
        if not note:
            return
        self.db.add_incident_note(incident_id, note, author=self.actor)
        self._open_incident(incident_id)

    def _new_incident_dialog(self):
        dialog = _TextPromptDialog(self, "New Incident", "Incident title:")
        self.wait_window(dialog)
        title = (dialog.result or "").strip()
        if not title:
            return
        incident_id = self.db.create_incident(title=title, severity="Medium", source="manual",
                                               created_by=self.actor)
        self.db.add_audit_event("incident_created", self.actor, f"Incident #{incident_id} created manually.")
        self._refresh_incidents()
        self._refresh_metrics()
        self._open_incident(incident_id)

    # ── Endpoints & Agents ───────────────────────────────────────────

    def _build_agents_tab(self):
        tab = self.tab_agents
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        ctk.CTkLabel(bar, text="Registered endpoints reporting to this AutoSOC instance.",
                     text_color=theme.TEXT_MUTED, font=ctk.CTkFont(size=12)).pack(side="left", padx=2)
        ctk.CTkButton(bar, text="Generate Enrollment Token", width=210, height=30, corner_radius=10,
                      fg_color=theme.ACCENT_BLUE, hover_color=theme.ACCENT_BLUE_HOVER,
                      command=self._generate_enrollment_token).pack(side="right", padx=6)

        self.agent_list = self._scroll_frame(tab)
        self.agent_list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _refresh_agents(self):
        self._clear(self.agent_list)
        agents = self.db.list_agents()
        if not agents:
            ctk.CTkLabel(
                self.agent_list,
                text=("No endpoints enrolled yet.\n\n"
                      "Generate an enrollment token, then install the AutoSOC agent on a server or workstation "
                      "and register it against this token. See docs/AGENTS_AND_ROADMAP.md for the agent design."),
                text_color=theme.TEXT_MUTED, font=ctk.CTkFont(size=12), justify="left",
            ).grid(row=0, column=0, sticky="w", padx=12, pady=12)
            return
        for index, row in enumerate(agents):
            self._agent_row(index, row)

    def _agent_row(self, index, row):
        agent_pk, agent_id, hostname, platform, ip_address, status, labels, last_seen, created_at = row
        card = ctk.CTkFrame(self.agent_list, fg_color=theme.BG_PANEL, corner_radius=12)
        card.grid(row=index, column=0, sticky="ew", padx=8, pady=5)
        card.grid_columnconfigure(1, weight=1)

        online = status == "online"
        color = theme.STATUS_GOOD if online else (theme.ACCENT_YELLOW if status == "pending" else theme.TEXT_MUTED)
        ctk.CTkLabel(card, text="●", text_color=color, font=ctk.CTkFont(size=15)).grid(
            row=0, column=0, rowspan=2, sticky="n", padx=(12, 8), pady=10)

        ctk.CTkLabel(card, text=f"{hostname or agent_id}  ·  {platform or 'unknown'}",
                     text_color=theme.TEXT_SOFT, font=ctk.CTkFont(size=13, weight="bold"),
                     anchor="w").grid(row=0, column=1, sticky="ew", padx=4, pady=(10, 0))
        detail = f"id: {agent_id}  ·  ip: {ip_address or '—'}  ·  status: {status}"
        if labels:
            detail += f"  ·  {labels}"
        detail += f"\nlast seen: {last_seen or 'never'}  ·  enrolled: {created_at}"
        ctk.CTkLabel(card, text=detail, text_color="#85a3bd", font=ctk.CTkFont(size=11),
                     anchor="w", justify="left").grid(row=1, column=1, sticky="ew", padx=4, pady=(0, 10))

        ctk.CTkButton(card, text="Remove", width=80, height=28, corner_radius=10,
                      fg_color="transparent", hover_color=theme.BTN_OUTLINE_HOVER,
                      border_width=1, border_color=theme.BTN_OUTLINE_BORDER,
                      command=lambda: self._remove_agent(agent_id)).grid(row=0, column=2, rowspan=2, padx=12, pady=10)

    def _remove_agent(self, agent_id):
        self.db.delete_agent(agent_id)
        self.db.add_audit_event("agent_removed", self.actor, f"Agent {agent_id} removed.")
        self._refresh_agents()
        self._refresh_metrics()

    def _generate_enrollment_token(self):
        token = "enr_" + secrets.token_urlsafe(24)
        agent_id = "agent_" + secrets.token_hex(6)
        self.db.register_agent(agent_id=agent_id, enrollment_token=token, labels="pending-enrollment")
        self.db.add_audit_event("agent_enrollment_token", self.actor,
                                f"Enrollment token generated for {agent_id}.")
        self._refresh_agents()
        _InfoDialog(
            self,
            "Enrollment Token",
            (
                "Provision a new endpoint with these values.\n\n"
                f"Agent ID:\n{agent_id}\n\n"
                f"Enrollment token:\n{token}\n\n"
                "On the endpoint, install the AutoSOC agent and run:\n"
                f"  autosoc-agent enroll --server <this-host> \\\n"
                f"    --agent-id {agent_id} --token <token>\n\n"
                "The agent then ships logs and heartbeat to this console.\n"
                "Design details: docs/AGENTS_AND_ROADMAP.md"
            ),
        )

    # ── Threat Intel (IOCs) ──────────────────────────────────────────

    def _build_intel_tab(self):
        tab = self.tab_intel
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(2, weight=1)

        add_bar = ctk.CTkFrame(tab, fg_color=theme.BG_PANEL, corner_radius=12)
        add_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        add_bar.grid_columnconfigure(1, weight=1)

        self.ioc_type = ctk.CTkOptionMenu(add_bar, values=IOC_TYPES, width=110,
                                          fg_color=theme.BG_CARD, button_color=theme.BTN_NEUTRAL,
                                          button_hover_color=theme.BTN_NEUTRAL_HOVER)
        self.ioc_type.set("ip")
        self.ioc_type.grid(row=0, column=0, padx=(10, 8), pady=10)
        self.ioc_value = ctk.CTkEntry(add_bar, height=34, fg_color=theme.BG_FIELD,
                                      border_color=theme.FIELD_BORDER,
                                      placeholder_text="Indicator value (IP, domain, URL, hash, email)")
        self.ioc_value.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=10)
        self.ioc_severity = ctk.CTkOptionMenu(add_bar, values=SEVERITIES, width=110,
                                              fg_color=theme.BG_CARD, button_color=theme.BTN_NEUTRAL,
                                              button_hover_color=theme.BTN_NEUTRAL_HOVER)
        self.ioc_severity.set("Medium")
        self.ioc_severity.grid(row=0, column=2, padx=(0, 8), pady=10)
        ctk.CTkButton(add_bar, text="Add IOC", width=100, height=34, corner_radius=10,
                      fg_color=theme.ACCENT_BLUE, hover_color=theme.ACCENT_BLUE_HOVER,
                      command=self._add_ioc).grid(row=0, column=3, padx=(0, 10), pady=10)

        lookup_bar = ctk.CTkFrame(tab, fg_color="transparent")
        lookup_bar.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 6))
        lookup_bar.grid_columnconfigure(0, weight=1)
        self.ioc_lookup = ctk.CTkEntry(lookup_bar, height=34, fg_color=theme.BG_FIELD,
                                       border_color=theme.FIELD_BORDER,
                                       placeholder_text="Look up an indicator against the watchlist…")
        self.ioc_lookup.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.ioc_lookup.bind("<Return>", lambda e: self._lookup_ioc())
        ctk.CTkButton(lookup_bar, text="Look up", width=100, height=34, corner_radius=10,
                      fg_color=theme.BTN_NEUTRAL, hover_color=theme.BTN_NEUTRAL_HOVER,
                      command=self._lookup_ioc).grid(row=0, column=1)
        self.ioc_lookup_result = ctk.CTkLabel(tab, text="", text_color=theme.TEXT_MUTED,
                                              font=ctk.CTkFont(size=12), anchor="w")
        self.ioc_lookup_result.grid(row=1, column=0, sticky="ew", padx=12, pady=(44, 0))

        self.ioc_list = self._scroll_frame(tab)
        self.ioc_list.grid(row=2, column=0, sticky="nsew", padx=10, pady=(6, 10))

    def _add_ioc(self):
        value = self.ioc_value.get().strip()
        if not value:
            return
        result = self.db.add_ioc(self.ioc_type.get(), value, self.ioc_severity.get(), added_by=self.actor)
        if result is None:
            self.ioc_lookup_result.configure(text=f"IOC already on the watchlist: {value}", text_color=theme.STATUS_WARN)
        else:
            self.db.add_audit_event("ioc_added", self.actor, f"{self.ioc_type.get()}:{value} added to watchlist.")
            self.ioc_value.delete(0, "end")
        self._refresh_intel()

    def _lookup_ioc(self):
        value = self.ioc_lookup.get().strip()
        if not value:
            return
        matches = self.db.match_iocs(value)
        if matches:
            hit = matches[0]
            self.ioc_lookup_result.configure(
                text=f"⚠ MATCH: {hit[1]} {hit[2]} · severity {hit[3]} · {hit[4] or 'no note'}",
                text_color=theme.STATUS_DANGER,
            )
        else:
            self.ioc_lookup_result.configure(text=f"No watchlist match for {value}.", text_color=theme.STATUS_GOOD)

    def _refresh_intel(self):
        self._clear(self.ioc_list)
        iocs = self.db.list_iocs()
        if not iocs:
            ctk.CTkLabel(self.ioc_list, text="Watchlist is empty. Add indicators above.",
                         text_color=theme.TEXT_MUTED, font=ctk.CTkFont(size=12)).grid(
                row=0, column=0, sticky="w", padx=12, pady=12)
            return
        for index, row in enumerate(iocs):
            ioc_id, ioc_type, value, severity, note, added_by, created_at = row
            card = ctk.CTkFrame(self.ioc_list, fg_color=theme.BG_PANEL, corner_radius=12)
            card.grid(row=index, column=0, sticky="ew", padx=8, pady=4)
            card.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(card, text="●", text_color=SEVERITY_COLORS.get(severity, theme.TEXT_MUTED),
                         font=ctk.CTkFont(size=14)).grid(row=0, column=0, padx=(12, 8), pady=8)
            ctk.CTkLabel(card, text=f"{ioc_type}: {value}   ({severity})",
                         text_color=theme.TEXT_SOFT, font=ctk.CTkFont(size=12, weight="bold"),
                         anchor="w").grid(row=0, column=1, sticky="ew", pady=8)
            ctk.CTkButton(card, text="✕", width=36, height=28, corner_radius=10,
                          fg_color="transparent", hover_color=theme.BTN_OUTLINE_HOVER,
                          border_width=1, border_color=theme.BTN_OUTLINE_BORDER,
                          command=lambda i=ioc_id: self._delete_ioc(i)).grid(row=0, column=2, padx=10, pady=6)

    def _delete_ioc(self, ioc_id):
        self.db.delete_ioc(ioc_id)
        self._refresh_intel()

    # ── Log Search ───────────────────────────────────────────────────

    def _build_logs_tab(self):
        tab = self.tab_logs
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        bar.grid_columnconfigure(0, weight=1)
        self.log_query = ctk.CTkEntry(bar, height=34, fg_color=theme.BG_FIELD, border_color=theme.FIELD_BORDER,
                                      placeholder_text="Search ingested logs (message, source, agent)…")
        self.log_query.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.log_query.bind("<Return>", lambda e: self._refresh_logs())
        ctk.CTkButton(bar, text="Search", width=100, height=34, corner_radius=10,
                      fg_color=theme.ACCENT_BLUE, hover_color=theme.ACCENT_BLUE_HOVER,
                      command=self._refresh_logs).grid(row=0, column=1, padx=(0, 6))
        ctk.CTkButton(bar, text="Add test log", width=110, height=34, corner_radius=10,
                      fg_color=theme.BTN_NEUTRAL, hover_color=theme.BTN_NEUTRAL_HOVER,
                      command=self._add_test_log).grid(row=0, column=2)

        self.log_output = ctk.CTkTextbox(tab, fg_color=theme.BG_CONSOLE, corner_radius=12,
                                         text_color=theme.TEXT_SOFT, font=ctk.CTkFont(family="Consolas", size=12),
                                         wrap="none")
        self.log_output.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _refresh_logs(self):
        query = self.log_query.get().strip() if hasattr(self, "log_query") else ""
        rows = self.db.search_logs(query)
        self.log_output.configure(state="normal")
        self.log_output.delete("0.0", "end")
        if not rows:
            self.log_output.insert("end",
                                   "No ingested logs yet.\n\n"
                                   "Logs arrive here from enrolled agents (see Endpoints tab) or via the "
                                   "ingestion API. Use 'Add test log' to try the search.\n")
        else:
            for created_at, agent_id, source, severity, message in rows:
                self.log_output.insert("end", f"{created_at} | {severity:<8} | {agent_id or '-':<16} | {source or '-':<14} | {message}\n")
        self.log_output.configure(state="disabled")

    def _add_test_log(self):
        self.db.add_ingested_log(
            message=f"Synthetic test log generated at {datetime.now().strftime('%H:%M:%S')}",
            agent_id="local-console", source="manual-test", severity="info",
        )
        self._refresh_logs()

    # ── Metrics ──────────────────────────────────────────────────────

    def _build_metrics_tab(self):
        tab = self.tab_metrics
        tab.grid_columnconfigure((0, 1, 2), weight=1)

        self.metric_cards = {}
        specs = [
            ("open_incidents", "Open Incidents", theme.ACCENT_YELLOW, 0, 0),
            ("critical_incidents", "Critical / High", theme.STATUS_DANGER, 0, 1),
            ("resolved_incidents", "Resolved", theme.ACCENT_GREEN, 0, 2),
            ("events_24h", "Security Events", theme.ACCENT_CYAN, 1, 0),
            ("agents_total", "Enrolled Endpoints", "#c58fff", 1, 1),
            ("iocs_total", "Watchlist IOCs", "#ff9f6e", 1, 2),
        ]
        for key, label, color, r, c in specs:
            card = ctk.CTkFrame(tab, fg_color=theme.BG_PANEL, corner_radius=16)
            card.grid(row=r, column=c, sticky="nsew", padx=10, pady=10)
            ctk.CTkLabel(card, text=label, text_color=theme.TEXT_MUTED,
                         font=ctk.CTkFont(size=13)).pack(anchor="w", padx=16, pady=(16, 4))
            value = ctk.CTkLabel(card, text="0", text_color=color, font=ctk.CTkFont(size=34, weight="bold"))
            value.pack(anchor="w", padx=16, pady=(0, 16))
            self.metric_cards[key] = value

        self.metrics_note = ctk.CTkLabel(
            tab,
            text="",
            text_color=theme.TEXT_MUTED,
            font=ctk.CTkFont(size=12),
            justify="left",
        )
        self.metrics_note.grid(row=2, column=0, columnspan=3, sticky="w", padx=16, pady=12)

    def _refresh_metrics(self):
        if not hasattr(self, "metric_cards"):
            return
        status_counts = self.db.incident_status_counts()
        incidents = self.db.list_incidents(limit=1000)
        open_count = sum(count for status, count in status_counts.items()
                         if status not in ("Resolved", "False Positive"))
        resolved = status_counts.get("Resolved", 0)
        crit_high = sum(1 for row in incidents if row[2] in ("Critical", "High")
                        and row[3] not in ("Resolved", "False Positive"))

        self.metric_cards["open_incidents"].configure(text=str(open_count))
        self.metric_cards["critical_incidents"].configure(text=str(crit_high))
        self.metric_cards["resolved_incidents"].configure(text=str(resolved))
        self.metric_cards["events_24h"].configure(text=str(self.db.count_rows("security_events")))
        self.metric_cards["agents_total"].configure(text=str(self.db.count_rows("agents")))
        self.metric_cards["iocs_total"].configure(text=str(self.db.count_rows("iocs")))

        self.metrics_note.configure(
            text=("KPIs are computed live from the local store. Connect endpoint agents and enable "
                  "Telegram alerting to turn this into a continuously updating operations picture.")
        )


class _TextPromptDialog(ctk.CTkToplevel):
    def __init__(self, master, title, prompt):
        super().__init__(master)
        self.result = None
        self.title(title)
        self.geometry("420x170")
        self.configure(fg_color=theme.BG_PANEL)
        self.attributes("-topmost", True)
        self.transient(master)

        ctk.CTkLabel(self, text=prompt, text_color=theme.TEXT_SOFT,
                     font=ctk.CTkFont(size=13)).pack(anchor="w", padx=20, pady=(20, 8))
        self.entry = ctk.CTkEntry(self, height=38, fg_color=theme.BG_FIELD, border_color=theme.FIELD_BORDER)
        self.entry.pack(fill="x", padx=20)
        self.entry.focus()
        self.entry.bind("<Return>", lambda e: self._ok())

        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=16)
        ctk.CTkButton(row, text="Cancel", width=90, height=34, fg_color=theme.BTN_NEUTRAL,
                      hover_color=theme.BTN_NEUTRAL_HOVER, command=self._cancel).pack(side="right", padx=(8, 0))
        ctk.CTkButton(row, text="Create", width=90, height=34, fg_color=theme.ACCENT_BLUE,
                      hover_color=theme.ACCENT_BLUE_HOVER, command=self._ok).pack(side="right")

    def _ok(self):
        self.result = self.entry.get()
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()


class _InfoDialog(ctk.CTkToplevel):
    def __init__(self, master, title, body):
        super().__init__(master)
        self.title(title)
        self.geometry("520x420")
        self.configure(fg_color=theme.BG_PANEL)
        self.attributes("-topmost", True)
        self.transient(master)

        ctk.CTkLabel(self, text=title, text_color=theme.TEXT_PRIMARY,
                     font=ctk.CTkFont(size=18, weight="bold")).pack(anchor="w", padx=20, pady=(18, 8))
        box = ctk.CTkTextbox(self, fg_color=theme.BG_CONSOLE, corner_radius=12,
                             text_color=theme.TEXT_SOFT, font=ctk.CTkFont(family="Consolas", size=12), wrap="word")
        box.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        box.insert("end", body)
        box.configure(state="disabled")
        ctk.CTkButton(self, text="Close", height=34, fg_color=theme.ACCENT_BLUE,
                      hover_color=theme.ACCENT_BLUE_HOVER, command=self.destroy).pack(pady=(0, 16))
