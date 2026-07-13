"""Unified response actions.

When AutoSOC decides to block a source IP (traffic spike, canary trip,
brute-force), the action should reach wherever the customer actually enforces
policy. :class:`ResponseController` fans a block out to, in order:

  1. the **block-list feed** (always) — recorded in the DB and served to
     network appliances (FortiGate/Palo Alto/etc.) at ``/blocklist.txt``;
  2. the configured **appliance** (e.g. FortiGate REST push), if any;
  3. the **local host firewall** (netsh/iptables), when relevant.

Each channel reports success/failure independently; a failure in one does not
stop the others. The controller returns a combined, human-readable summary.
"""

from autosoc.logging_setup import get_logger
from autosoc.system.appliance import connector_from_settings
from autosoc.system.firewall import get_firewall

log = get_logger("system.response")


class ResponseController:
    def __init__(self, db, local_firewall=None):
        self.db = db
        self.local_firewall = local_firewall if local_firewall is not None else get_firewall()

    def appliance(self):
        # Rebuilt each call so settings changes take effect without a restart.
        return connector_from_settings(self.db)

    def block_ip(self, ip, reason="", actor="autosoc", use_local=True):
        """Block an IP across every configured channel.

        Returns ``(any_success, summary_text, channel_results)``.
        """
        results = []

        # 1) Block-list feed (always recorded).
        feed_ok = self.db.add_blocked_ip(ip, reason=reason, severity="High", added_by=actor)
        results.append(("feed", feed_ok, "added to block-list feed" if feed_ok else "invalid IP"))

        # 2) Appliance push.
        connector = self.appliance()
        if connector.name != "feed-only":
            appl_ok, appl_msg = connector.block_ip(ip, reason=reason)
            results.append((connector.name, appl_ok, appl_msg))

        # 3) Local host firewall.
        if use_local and self.local_firewall is not None:
            fw_ok, _rule, fw_msg = self.local_firewall.block_ip(ip)
            results.append((self.local_firewall.name, fw_ok, fw_msg))

        any_success = any(ok for _name, ok, _msg in results)
        summary = "; ".join(f"{name}: {'ok' if ok else 'failed'} ({msg})" for name, ok, msg in results)
        self.db.add_security_event(
            "response_block", "High", ip,
            f"Block requested by {actor}. Reason: {reason}. Channels -> {summary}",
        )
        log.info("Block %s -> %s", ip, summary)
        return any_success, summary, results

    def unblock_ip(self, ip, actor="autosoc"):
        results = []
        self.db.remove_blocked_ip(ip)
        results.append(("feed", True, "removed from block-list feed"))
        connector = self.appliance()
        if connector.name != "feed-only":
            ok, msg = connector.unblock_ip(ip)
            results.append((connector.name, ok, msg))
        summary = "; ".join(f"{name}: {msg}" for name, _ok, msg in results)
        self.db.add_audit_event("response_unblock", actor, f"Unblock {ip}. {summary}")
        return True, summary, results
