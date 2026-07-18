# SOC Analyst Toolkit — demand analysis & tool landscape

> Research backing AutoSOC's feature roadmap: what security-operations analysts
> and system administrators actually do, the tools they reach for, and where a
> lightweight product like AutoSOC fits (and deliberately does not compete).

This document answers three questions:

1. **What does a SOC analyst actually do all day?** (so we build for the workflow, not a feature checklist)
2. **Which tools do they use, and why?** (the standard toolset, by function)
3. **What is the real demand — especially for SMBs and MSSPs — and how does AutoSOC map to it?**

---

## 1. The SOC analyst workflow

A Security Operations Center runs a tiered workflow. Understanding it is the
difference between a tool that gets opened once and one that lives on the
analyst's second monitor.

| Tier | Role | Core activity | What they need from tooling |
|------|------|---------------|-----------------------------|
| **Tier 1** | Triage analyst | Watch the alert queue, dismiss false positives, escalate real ones | Fast triage queue, good signal-to-noise, one-click enrichment & context |
| **Tier 2** | Incident responder | Investigate escalations, scope the blast radius, contain | Pivoting across logs/endpoints, host isolation, timeline building |
| **Tier 3** | Threat hunter / IR lead | Proactive hunting, deep forensics, detection engineering | Raw data access, custom queries, YARA/Sigma, memory/disk forensics |
| **SOC manager** | Metrics & coverage | MTTR, coverage vs MITRE ATT&CK, reporting | Dashboards, case management, audit trail, compliance evidence |

The loop every analyst runs, dozens of times a day:

```
   detect  ─►  triage  ─►  investigate  ─►  contain  ─►  eradicate  ─►  recover  ─►  report
   (SIEM/EDR) (queue)     (pivot+enrich)  (isolate)   (remove)      (restore)   (case+metrics)
```

Two frictions dominate that loop and are where products win or lose:

- **Enrichment friction** — "is this IP/hash/domain actually bad?" An analyst
  should not leave the console to answer this. Native threat-intel lookup is
  table stakes. *(AutoSOC: the Threat Intel tab's **Enrich** action.)*
- **Pivot friction** — "what else did this host/user do around that time?" The
  analyst needs to move from an alert to the surrounding logs, the process
  tree, and the network connections in seconds. *(AutoSOC: Log Analysis window
  + endpoint Details + process/socket telemetry.)*

---

## 2. The standard toolset, by function

These are the categories a SOC is built from. For each we list the tools an
analyst expects to see, and note AutoSOC's relationship to them (replace /
integrate / hand-off).

### SIEM & log analytics — *the system of record*
The central place logs land, get correlated, and get searched.
- **Splunk** — the enterprise incumbent; powerful, expensive.
- **Elastic / ELK (Elasticsearch + Kibana)** — the open-source default.
- **Wazuh** — open-source SIEM/XDR, popular with SMBs and MSSPs.
- **Microsoft Sentinel, IBM QRadar, Graylog** — other common choices.

> **AutoSOC:** is a lightweight SIEM-lite for small estates *and* a good
> citizen — the **Log Destination** feature forwards every ingested log onward
> to any of the above over syslog, so AutoSOC can front-end or feed a bigger
> SIEM rather than fight it.

### EDR / XDR — *endpoint visibility & response*
Telemetry from the hosts themselves, plus the ability to act on them.
- **CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint** — commercial EDR/XDR.
- **osquery** — endpoints queried like a SQL database (processes, sockets, users, packages).
- **Velociraptor** — DFIR-grade hunting and live response at fleet scale.
- **Wazuh agent, Sysmon** — host IDS, file-integrity monitoring, rich Windows telemetry.

> **AutoSOC:** ships its own cross-platform (Linux **and Windows**) agent that
> reports process trees, listening sockets/connections, resource health, and
> logs, and can **isolate a host** (iptables / netsh) on command — the core
> EDR response primitive, without an enterprise EDR price tag.

### Threat intelligence — *"is this indicator bad?"*
- **VirusTotal** — file/URL/IP/domain reputation across 90+ engines.
- **AbuseIPDB** — crowd-sourced IP abuse-confidence scoring.
- **AlienVault OTX** — community "threat pulse" indicator feeds.
- **MISP** — IOC storage & sharing platform. **GreyNoise / Shodan** — internet scan context.

> **AutoSOC:** the **Enrich** action queries VirusTotal, AbuseIPDB and OTX
> directly and normalizes their verdicts into one view; the IOC watchlist is
> the local MISP-lite.

### Network security monitoring / IDS-IPS
- **Suricata** — high-performance IDS/IPS + NSM (Emerging Threats / Talos rules).
- **Zeek (formerly Bro)** — protocol metadata logging, the hunter's favorite.
- **Snort** — the classic signature IDS. **Arkime** — full-packet capture & search.
- **nmap** — service discovery / port scanning.

> **AutoSOC:** ingests IDS/appliance logs via the **syslog receiver**, runs
> **nmap**-based endpoint port scans (comparing external ports to what the
> agent reports — a hidden-service/rootkit tell), and pushes blocks to a
> firewall via a **threat-feed / EDL** or the FortiGate API.

### Detection engineering
- **MITRE ATT&CK** — the shared taxonomy of adversary techniques.
- **Sigma** — vendor-neutral detection rules that compile to any SIEM's query language.
- **YARA** — pattern matching to classify malware and files.
- **Atomic Red Team** — small portable tests that fire a technique so you can confirm your detection works.

> **AutoSOC:** ships a **detection-rule engine** with ~35 built-in rules mapped
> to ATT&CK, editable in-app; rules run on both ingested logs and endpoint
> telemetry.

### DFIR & malware analysis
- **Volatility** — memory forensics. **The Sleuth Kit / Autopsy** — disk forensics.
- **Plaso / log2timeline** — super-timelines. **KAPE** — rapid artifact collection.
- **CyberChef** — decode/deobfuscate swiss-army knife.
- **Cuckoo / CAPE, Any.run, Joe Sandbox** — malware sandboxes.

> **AutoSOC:** hands off to these — the Analyst Toolkit window detects which are
> installed locally. AutoSOC is not a forensics suite and does not pretend to be.

### Purple-team / validation *(authorized use only)*
- **Metasploit** — exploitation framework, used in a SOC context to **validate that detections fire**.
- **Caldera** — MITRE's automated adversary emulation.
- **Atomic Red Team** — per-technique detection tests.

> **AutoSOC:** references these for authorized detection-validation and
> purple-team exercises. AutoSOC itself is a **defensive** product — it does not
> automate exploitation; these are operator-run tools the analyst launches
> separately during sanctioned testing.

### SOAR & case management
- **TheHive + Cortex** — incident case management with analyzer orchestration.
- **Shuffle, Tines, Splunk SOAR** — response-playbook automation.

> **AutoSOC:** built-in **incident** cases with notes/severity/status, and
> automated response **playbooks** (detect → isolate host → push firewall block
> → notify, with rollback).

---

## 3. Demand analysis — who pays, and for what

The enterprise SOC market is saturated with expensive, heavy platforms. The
underserved demand — and AutoSOC's target — is at the **small/medium business**
and **MSSP** (Managed Security Service Provider) end:

**What SMBs actually need (and can't get affordably today):**
1. **One pane of glass** without a six-figure SIEM license or a dedicated SIEM
   engineer. → *AutoSOC's SOC console.*
2. **Endpoint visibility + a kill switch** on Windows and Linux servers without
   per-endpoint enterprise-EDR pricing. → *AutoSOC agent + isolation.*
3. **Answers, not just alerts** — built-in enrichment so a non-specialist admin
   can tell a real threat from noise. → *Enrich + detection rules mapped to ATT&CK.*
4. **A path that grows with them** — the ability to forward everything to a
   "real" SIEM later without re-tooling. → *Log Destination forwarding.*
5. **Compliance evidence** out of the box — an audit trail, access control, and
   retention controls to pass an ISO 27001 / SOC 2 / PCI-DSS assessment. →
   *See [COMPLIANCE.md](COMPLIANCE.md).*

**What MSSPs need on top of that:** multi-tenancy, per-client isolation, and
lightweight agents that deploy with one command. → *the `enterprise/` SOAR/EDR
stack covers multi-tenancy; the desktop app covers the single-tenant SMB case.*

**The positioning, in one line:** AutoSOC is the *"SOC-in-a-box"* for the
organization that has servers worth protecting but not an enterprise security
budget — deliberately **lightweight**, **cross-platform**, and **interoperable**
with the heavy tools rather than trying to replace all of them.

---

## 4. How this maps to AutoSOC features

| Analyst need | Standard tool | AutoSOC capability | Status |
|--------------|---------------|--------------------|--------|
| Central logs & search | Splunk / ELK / Wazuh | Ingestion + Log Analysis window + forwarding | ✅ shipping |
| Endpoint telemetry | osquery / EDR | Cross-platform agent (Linux + Windows) | ✅ shipping |
| Host containment | EDR isolate | iptables / netsh isolation + command channel | ✅ shipping |
| Indicator reputation | VirusTotal / AbuseIPDB / OTX | Enrich action (all three) | ✅ shipping |
| Detection rules | Sigma / ATT&CK | Rule engine, ~35 ATT&CK-mapped built-ins | ✅ shipping |
| IDS / appliance logs | Suricata / FortiGate | Syslog receiver + firewall feed/API | ✅ shipping |
| Port/attack-surface scan | nmap | Endpoint port scan vs reported listeners | ✅ shipping |
| Case management | TheHive | Incidents with notes/status/severity | ✅ shipping |
| Automated response | SOAR | Isolate + firewall-block playbooks w/ rollback | ✅ shipping |
| Forensics / memory | Volatility / TSK | Hand-off (toolkit detects local installs) | ➡️ integrate |
| Threat-intel sharing | MISP | Local IOC watchlist (MISP-lite) | ◐ partial |
| Sandbox detonation | Cuckoo / Any.run | — | 🗺️ roadmap |

Legend: ✅ shipping · ◐ partial · ➡️ hand-off to external tool · 🗺️ roadmap.

---

*In-app: open **SOC Console → 🧰 Analyst Toolkit** to see this catalog with
live detection of which CLI tools are installed on the current host.*
