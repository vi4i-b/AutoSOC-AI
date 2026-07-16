# AutoSOC — Demo Video Script (90–120s)

A tight product/investor demo. Goal: show **alert → AI explanation →
one-click containment** on a real machine. Shoot the app at 1440p, dark room,
calm confident voice. Timestamps are targets.

## Shot list

**0:00–0:08 — Hook (title card + one line)**
- Visual: AutoSOC logo animates in (use `docs/presentation/index.html` slide 1
  as the intro card, or a clean title).
- VO: *"Most companies get breached — and never notice. AutoSOC changes that."*

**0:08–0:22 — The console (establish)**
- Visual: open the app; pan across the dashboard — metrics, scan console, AI
  copilot. Open the SOC Console.
- VO: *"AutoSOC is a full security operations center in one window — detection,
  agents, response — set up in an afternoon, not a quarter."*

**0:22–0:40 — Onboard a server (the "wow, that's easy" moment)**
- Visual: SOC Console → Endpoints → **Start Collector** → **Copy Install
  Command**. Switch to a server terminal, paste the one-liner, hit enter.
  Cut back to the console: the endpoint appears **online**. Click **Details** —
  show processes, IPs, and "which process opens which port".
- VO: *"One command onboards any server. Now we see its processes, its network
  connections — everything."*

**0:40–1:00 — Detection + AI explanation (the value)**
- Visual: trigger a detection (e.g. run a benign `nc -e`-style command or a
  test log line). A rule fires — a red **[RULE] Reverse shell** alert appears;
  a security event lands in the Triage Queue. Show the AI copilot / incident
  summary explaining it in plain language.
- VO: *"AutoSOC ships the detection rules a SIEM makes you write — mapped to
  MITRE ATT&CK — and the AI explains what happened, in plain language."*

**1:00–1:18 — One-click response (the moment that sells)**
- Visual: on the flagged endpoint, click **Isolate** → confirm. Cut to the
  endpoint: `ping` to the internet now fails, but the console still sees it.
  The endpoint shows a pulsing 🔒 **ISOLATED** badge. Then click **Release**.
- VO: *"And you respond in one click — the compromised host is cut off the
  network instantly, while you keep control of it."*

**1:18–1:30 — Close (differentiation + CTA)**
- Visual: cut to the differentiation table (presentation slide 5) or a clean
  end card.
- VO: *"Not another SIEM. Not just a scanner. AI-native, multilingual,
  all-in-one — and affordable. AutoSOC."*

## Practical tips

- Pre-stage everything: collector running, one server already enrolled as a
  backup in case live onboarding is slow.
- Use a **safe, synthetic** trigger for the detection (a crafted log line or
  the built-in canary self-test) — never real malware.
- Record the isolation on a disposable VM you fully control.
- Keep cuts fast; let the 🔒 ISOLATED animation breathe for ~2 seconds.
- Add subtle captions of the action ("Onboarding server", "Rule fired",
  "Endpoint isolated") for muted autoplay on social.
- Export a 15-second cut (onboard → isolate) for ads/social top-of-funnel.
