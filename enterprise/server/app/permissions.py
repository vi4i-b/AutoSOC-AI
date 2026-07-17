"""Granular permission catalog (Zero Trust / least privilege).

Employees are granted an explicit subset of these; the OS-bootstrap
super-admin implicitly holds all of them and bypasses tenant scoping. Every
sensitive endpoint declares the exact permission it needs, so a compromised
low-privilege token cannot pivot into destructive actions.
"""

from __future__ import annotations

# permission_key: human description (shown in the admin UI)
PERMISSIONS: dict[str, str] = {
    "network:view": "View the network topology map",
    "network:isolate": "Isolate a node from the network",
    "agent:view": "View enrolled agents and their status",
    "agent:process_tree": "Inspect an agent's process tree",
    "agent:isolate": "Trigger endpoint isolation on an agent",
    "incident:view": "View incidents and alerts",
    "incident:respond": "Respond to incidents (block / rollback)",
    "ai:query": "Ask the AI analyst about events",
    "user:manage": "Create employees and assign permissions",
    "tenant:manage": "Create and manage tenants",
    "settings:manage": "Manage integrations and secret keys",
}

ALL_PERMISSIONS: frozenset[str] = frozenset(PERMISSIONS)

# Convenience bundles the admin UI can offer as starting points.
ROLE_TEMPLATES: dict[str, list[str]] = {
    "viewer": ["network:view", "agent:view", "incident:view"],
    "analyst": ["network:view", "agent:view", "agent:process_tree",
                "incident:view", "incident:respond", "ai:query"],
    "responder": ["network:view", "network:isolate", "agent:view",
                  "agent:process_tree", "agent:isolate", "incident:view",
                  "incident:respond", "ai:query"],
    "tenant_admin": sorted(ALL_PERMISSIONS - {"tenant:manage"}),
}


def is_valid_permission(perm: str) -> bool:
    return perm in ALL_PERMISSIONS


def sanitize(perms: list[str]) -> list[str]:
    """Drop unknown permissions; preserve order without duplicates."""
    seen: set[str] = set()
    out: list[str] = []
    for perm in perms or []:
        if perm in ALL_PERMISSIONS and perm not in seen:
            seen.add(perm)
            out.append(perm)
    return out
