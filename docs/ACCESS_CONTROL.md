# AutoSOC — Secure Access & Onboarding Options

How to make sure only an authorized circle of people can reach the console.
Options are ordered from quickest-to-ship to enterprise-grade; they can be
combined. Current state and the concrete change needed are noted for each.

## Where AutoSOC is today

- Login accepts **OS accounts** (Windows `LogonUserW` / Linux PAM) and **local
  AutoSOC accounts** (PBKDF2-hashed).
- Registration is **open** in the login window, and every account has the same
  rights. There is a `role` field but it is not yet enforced.
- **Account lockout** (5 fails / 15 min) is active.

So the first priority for "only certain people" is to close open registration
and enforce roles.

## Option 1 — Invite-only registration (fastest)

Disable self-service registration; accounts are created only by an admin or
via a one-time invite code.

- Add an `AUTOSOC_ALLOW_REGISTRATION=false` flag; hide the Register button.
- Add single-use invite codes (a table of hashed codes with expiry); the
  registration form requires a valid code.
- **Effort:** small. **Best for:** small teams, MSSP onboarding.

## Option 2 — Role-Based Access Control (RBAC)

Enforce the existing `role` field: e.g. `viewer` (read-only), `analyst`
(triage, incidents), `responder` (isolate/block), `admin` (users, rules,
settings). Gate every sensitive action (isolate, block, delete rule, manage
keys) behind a role check.

- **Effort:** medium. **Best for:** any multi-person deployment. This is the
  single most important addition for "restricted access", because it limits
  *what* each authorized person can do, not just *who* logs in.

## Option 3 — Multi-Factor Authentication (TOTP)

Add a second factor with time-based one-time passwords (Google
Authenticator / Authy), using the standard `pyotp` library.

- On first login the user scans a QR code; subsequent logins require the
  6-digit code. Store the per-user secret in the owner-only DB.
- Optionally require MFA only for privileged roles.
- **Effort:** medium. **Best for:** protecting a security tool that itself is a
  high-value target. Strongly recommended.

## Option 4 — Corporate identity (SSO / LDAP / Active Directory)

Let the customer manage accounts centrally:

- **LDAP / Active Directory** bind — authenticate against the company
  directory; group membership maps to AutoSOC roles.
- **SSO via OIDC / SAML** (Okta, Entra ID, Google Workspace, Keycloak) — no
  passwords stored in AutoSOC at all; access follows the company's joiner/
  leaver process automatically.
- **Effort:** larger. **Best for:** enterprise and data-center customers — this
  is usually a purchasing requirement.

## Option 5 — Network & device restrictions (defence in depth)

Independent of login, limit *where* the console and services can be reached:

- Bind the collector/syslog/feed to a management interface, not `0.0.0.0`;
  front them with a **TLS reverse proxy** and mutual-TLS or an IP allow-list.
- Require the app to run only inside a management VLAN / VPN.
- Device certificates for agents (mTLS) instead of a shared bearer token.

## Recommended path

1. **Now:** invite-only registration + enforce RBAC (Options 1 + 2).
2. **Next:** TOTP MFA for admin/responder roles (Option 3).
3. **For enterprise/data-center deals:** SSO/LDAP (Option 4) + TLS + mTLS for
   agents (Option 5).

## Hardening already in place

- Passwords: PBKDF2-HMAC-SHA256 with per-user salt; constant-time compare;
  legacy hashes auto-upgraded.
- Account lockout after repeated failures; all logins audited.
- Secrets (bot token, API keys) live in the owner-only local DB / `.env`, never
  in the repo, and are redacted from error messages.
- Data directory is `0700`, data files `0600` on Linux.
