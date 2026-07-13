"""Endpoint agent collector.

``server.CollectorService`` is an HTTP listener embedded in AutoSOC that
receives enrollment, telemetry, and log data from endpoint agents and writes
them into the shared database. The agent itself is a standalone stdlib script
(``agent/autosoc_agent.py`` at the repo root) that the collector serves over
``GET /agent`` so a server can be onboarded with a single command.
"""
