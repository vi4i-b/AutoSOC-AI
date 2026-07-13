"""Network firewall appliance connectors (FortiGate, and the vendor-neutral feed).

Most organizations don't filter at the host — they filter at a network
firewall (FortiGate, Palo Alto, MikroTik, pfSense…). AutoSOC supports two
integration styles:

1. **External block-list feed (vendor-neutral, recommended).** AutoSOC serves
   the list of blocked IPs at ``GET /blocklist.txt`` (see
   :mod:`autosoc.agents.server`). The appliance is configured once to poll
   that URL and drop those IPs:
     * FortiGate — Security Fabric → External Connectors → Threat Feed (IP Address)
     * Palo Alto — External Dynamic List (EDL)
     * pfSense — pfBlockerNG URL list
     * MikroTik — a scheduled ``/tool fetch`` + address-list import
   No credentials leave the appliance; AutoSOC never writes into its config.

2. **Direct API push (FortiGate REST).** When you want AutoSOC to actively
   push a block, :class:`FortiGateConnector` adds the IP as a firewall address
   object and appends it to an address group that a deny policy references.
   Requires a FortiGate API token; see docs/AGENTS_AND_ROADMAP.md for the
   one-time policy setup.

Connectors never raise on network/API failure — they return
``(ok, message)`` so the response pipeline can log and continue.
"""

import ipaddress

import requests

from autosoc.logging_setup import get_logger

log = get_logger("system.appliance")

REQUEST_TIMEOUT = (6, 12)


def _valid_ip(ip):
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return None


class ApplianceConnector:
    """Interface implemented by every appliance backend."""

    name = "none"

    def block_ip(self, ip, reason=""):
        raise NotImplementedError

    def unblock_ip(self, ip):
        raise NotImplementedError

    def test_connection(self):
        raise NotImplementedError


class NullConnector(ApplianceConnector):
    """Used when no appliance is configured; the block-list feed still works."""

    name = "feed-only"

    def block_ip(self, ip, reason=""):
        return True, "No appliance configured; IP added to the block-list feed only."

    def unblock_ip(self, ip):
        return True, "No appliance configured."

    def test_connection(self):
        return True, "Feed-only mode. Point your firewall at the /blocklist.txt threat feed."


class FortiGateConnector(ApplianceConnector):
    """FortiGate FortiOS REST API (v2/cmdb).

    Blocks by creating an address object and adding it to an address group
    (default ``AutoSOC_Blocklist``) that a deny firewall policy must already
    reference. Authenticates with an API token.
    """

    name = "fortigate"

    def __init__(self, host, api_token, vdom="root", address_group="AutoSOC_Blocklist", verify_tls=True):
        self.host = (host or "").rstrip("/")
        if self.host and "://" not in self.host:
            self.host = "https://" + self.host
        self.api_token = api_token or ""
        self.vdom = vdom or "root"
        self.address_group = address_group or "AutoSOC_Blocklist"
        self.verify_tls = verify_tls

    def _url(self, path):
        return f"{self.host}/api/v2/cmdb/{path}"

    def _params(self):
        return {"vdom": self.vdom, "access_token": self.api_token}

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"}

    def _address_name(self, ip):
        return f"AutoSOC_{ip}"

    def test_connection(self):
        if not self.host or not self.api_token:
            return False, "FortiGate host and API token are required."
        try:
            resp = requests.get(
                self._url(f"firewall/addrgrp/{self.address_group}"),
                params=self._params(), headers=self._headers(),
                timeout=REQUEST_TIMEOUT, verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            return False, self._redact(f"Connection failed: {exc}")
        if resp.status_code == 200:
            return True, f"Connected. Address group '{self.address_group}' is reachable."
        if resp.status_code == 404:
            return False, (f"Connected, but address group '{self.address_group}' does not exist. "
                           "Create it and reference it in a deny policy first.")
        if resp.status_code in (401, 403):
            return False, "Authentication failed (check the API token and trusted-host settings)."
        return False, f"FortiGate returned HTTP {resp.status_code}."

    def block_ip(self, ip, reason=""):
        normalized = _valid_ip(ip)
        if not normalized:
            return False, f"Invalid IP: {ip}"
        if not self.host or not self.api_token:
            return False, "FortiGate host and API token are required."

        name = self._address_name(normalized)
        # 1) Create/update the address object (idempotent: create, else update).
        address_body = {"name": name, "subnet": f"{normalized}/32",
                        "comment": (reason or "Blocked by AutoSOC")[:255]}
        try:
            create = requests.post(
                self._url("firewall/address"), params=self._params(), headers=self._headers(),
                json=address_body, timeout=REQUEST_TIMEOUT, verify=self.verify_tls,
            )
            if create.status_code == 500 or (create.status_code == 200 and create.json().get("status") == "error"):
                requests.put(
                    self._url(f"firewall/address/{name}"), params=self._params(), headers=self._headers(),
                    json=address_body, timeout=REQUEST_TIMEOUT, verify=self.verify_tls,
                )
            # 2) Append the address to the block group.
            append = requests.post(
                self._url(f"firewall/addrgrp/{self.address_group}/member"),
                params=self._params(), headers=self._headers(),
                json={"name": name}, timeout=REQUEST_TIMEOUT, verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            return False, self._redact(f"FortiGate API error: {exc}")

        if append.status_code in (200, 424):  # 424 = already a member
            return True, f"IP {normalized} pushed to FortiGate group '{self.address_group}'."
        return False, f"FortiGate group update returned HTTP {append.status_code}."

    def unblock_ip(self, ip):
        normalized = _valid_ip(ip)
        if not normalized:
            return False, f"Invalid IP: {ip}"
        name = self._address_name(normalized)
        try:
            resp = requests.delete(
                self._url(f"firewall/addrgrp/{self.address_group}/member/{name}"),
                params=self._params(), headers=self._headers(),
                timeout=REQUEST_TIMEOUT, verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            return False, self._redact(f"FortiGate API error: {exc}")
        if resp.status_code in (200, 404):
            return True, f"IP {normalized} removed from FortiGate group."
        return False, f"FortiGate returned HTTP {resp.status_code}."

    def _redact(self, text):
        if self.api_token:
            text = text.replace(self.api_token, "***TOKEN***")
        return text


def connector_from_settings(db) -> ApplianceConnector:
    """Build the configured appliance connector from stored settings."""
    fw_type = (db.get_setting("firewall_type", "") or "").strip().lower()
    if fw_type == "fortigate":
        return FortiGateConnector(
            host=db.get_setting("firewall_host", ""),
            api_token=db.get_setting("firewall_token", ""),
            vdom=db.get_setting("firewall_vdom", "root") or "root",
            address_group=db.get_setting("firewall_group", "AutoSOC_Blocklist") or "AutoSOC_Blocklist",
            verify_tls=(db.get_setting("firewall_verify_tls", "1") or "1") != "0",
        )
    return NullConnector()
