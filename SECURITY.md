# AutoSOC Security Model

This document describes how AutoSOC handles secrets, credentials, privileges,
and data — and what operators must know before deploying it.

## Secrets

- All secrets (`TELEGRAM_BOT_TOKEN`, `NVIDIA_API_KEY`, `OPENAI_API_KEY`) are
  read from environment variables or a local `.env` file.
- `.env` is git-ignored; only `.env.example` (a template without values) is
  committed. **Never commit a real `.env`.**
- The Telegram bot token is embedded in API URLs, so every error message from
  the Telegram client is redacted (`***TOKEN***`) before it reaches the UI or
  logs (`autosoc/telegram/client.py`).
- Log output (`autosoc.log`) never includes tokens, passwords, or password
  hashes.

## Password storage

- Local account passwords are hashed with **PBKDF2-HMAC-SHA256**
  (260,000 iterations, 16-byte random salt) — `autosoc/security_utils.py`.
- Legacy unsalted SHA-256 hashes are still *verified* for backward
  compatibility, but are transparently re-hashed to PBKDF2 on the next
  successful login (`needs_rehash`).
- Password comparisons use `hmac.compare_digest` (constant-time).
- Password policy: minimum 8 characters with at least one letter and one
  digit (`autosoc/validators.py`).

## Account lockout (anti-brute-force)

- After **5 failed logins within 15 minutes**, the account is locked until
  the window passes (`autosoc/database.py`: `MAX_FAILED_LOGINS`,
  `LOCKOUT_WINDOW_SECONDS`).
- Lockouts and all login attempts are written to the audit journal.

## Data storage

- The SQLite database, "remember me" file, AI memory, and logs live in a
  per-user data directory:
  - Windows: `%APPDATA%\AutoSOC`
  - Linux: `~/.local/share/autosoc` (or `$XDG_DATA_HOME/autosoc`)
- On Linux the directory is created with mode `0700` and data files are
  `chmod 0600` (owner-only).
- Files that older versions left in the working directory are migrated
  automatically on first run.

## Privileges

- Firewall management needs elevation: **Administrator** on Windows
  (netsh advfirewall), **root** on Linux (iptables). The UI warns when
  privileges are missing instead of failing silently.
- Failed-login monitoring reads the Windows Security log (admin) or
  `/var/log/auth.log` (root or `adm` group on Ubuntu).
- Packet sniffing (Guard) requires Npcap on Windows or libpcap + root on
  Linux.
- System commands are always executed as argument lists without a shell
  (`autosoc/system/commands.py`) — no shell injection surface — and with
  timeouts.

## Network actions

- Scan targets are validated (`is_safe_scan_target`) before being passed to
  nmap: single IP, CIDR, hostname, or `localhost`; shell metacharacters are
  rejected.
- **Only scan hosts and networks you own or are authorized to test.**
- Firewall rules created by AutoSOC are tagged with the `AutoSOC_` prefix so
  they can be identified and removed; "allow" only removes AutoSOC's own
  block rule and never creates a broad allow rule.
- The Port Canary intentionally binds decoy listeners on `0.0.0.0` so it can
  detect LAN scanners. Restrict it with `AUTOSOC_CANARY_HOST` if needed.

## Telegram

- Alerts are sent only to the chat id linked to the current account; a chat
  id can be linked to a single account (unique index in the database).
- Dynamic values interpolated into Markdown alerts are escaped
  (`escape_markdown`) to prevent formatting injection.
- Be aware that scan results (IPs, open ports) are transmitted to the
  Telegram Bot API when alerts are enabled.

## AI providers

- When NVIDIA/OpenAI/Ollama integration is configured, scan context (device
  IPs, open ports, recent security events) is included in prompts sent to the
  provider. If that data must not leave the machine, use the local Ollama
  provider or leave all AI keys empty (built-in expert mode answers offline).

## Reporting a vulnerability

Open a GitHub issue marked `[security]`, or contact the maintainers
directly. Please do not publish exploit details before a fix is available.
