"""Detection rule engine.

A small SIEM-style correlation layer on top of the data AutoSOC already
collects: ingested logs (agent + syslog) and endpoint telemetry (listening
ports, connections, processes). Rules are stored in the database, seeded with
a default baseline (see :mod:`autosoc.detection.default_rules`), and can be
added, removed, enabled, or disabled at runtime.

When a rule matches, the engine raises a security event and — depending on the
rule — opens an incident and/or blocks the source IP through the response
pipeline.
"""

from autosoc.detection.engine import RuleEngine

__all__ = ["RuleEngine"]
