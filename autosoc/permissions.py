"""Role-based access control.

Four roles with increasing capability:

    viewer     — read-only (dashboards, search, details)
    analyst    — + triage: create/update incidents, run scans, add rules
    responder  — + response: isolate endpoints, block IPs, harden ports,
                 remove agents
    admin      — + administration: manage users/invites/settings/AI keys,
                 delete detection rules

Actions are checked with :func:`has_permission`. Until the first ``admin``
account exists the deployment is in **bootstrap** mode and everyone is treated
as admin, so a fresh install (or an upgrade of an existing single-user setup)
is never locked out.
"""

from __future__ import annotations

ROLES: tuple[str, ...] = ("viewer", "analyst", "responder", "admin")

# Canonical action names checked across the UI.
ACTIONS: tuple[str, ...] = (
    "view",           # see dashboards, search, details
    "scan",           # run network scans
    "triage",         # create/update incidents, IOCs, notes
    "add_rule",       # create/enable/disable detection rules
    "respond",        # isolate endpoint, block IP, harden ports
    "manage_agents",  # remove/administer agents
    "manage_rules",   # delete detection rules
    "admin",          # users, invites, settings, AI keys, firewall integration
)

_ROLE_ACTIONS: dict[str, set[str]] = {
    "viewer": {"view"},
    "analyst": {"view", "scan", "triage", "add_rule"},
    "responder": {"view", "scan", "triage", "add_rule", "respond", "manage_agents"},
    "admin": set(ACTIONS),
}


def normalize_role(role: str | None) -> str:
    """Map arbitrary/legacy role strings to a canonical role."""
    value = (role or "").strip().lower()
    if value in _ROLE_ACTIONS:
        return value
    # Legacy labels used before RBAC existed.
    legacy = {
        "user": "analyst",
        "analyst": "analyst",
        "system user": "responder",
        "sysadmin": "admin",
        "administrator": "admin",
        "operator": "responder",
    }
    return legacy.get(value, "analyst")


def has_permission(role: str | None, action: str, *, bootstrap: bool = False) -> bool:
    """True when a role may perform an action (or the deployment is bootstrapping)."""
    if bootstrap:
        return True
    return action in _ROLE_ACTIONS.get(normalize_role(role), set())


def role_summary(role: str | None) -> str:
    canonical = normalize_role(role)
    return {
        "viewer": "Read-only access.",
        "analyst": "Triage incidents, run scans, add detection rules.",
        "responder": "Everything an analyst can do, plus isolate/block/harden and manage agents.",
        "admin": "Full access, including users, invites, settings and AI keys.",
    }[canonical]
