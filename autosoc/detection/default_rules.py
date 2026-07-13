"""Default detection rules — the baseline shipped by most SIEMs.

These mirror the out-of-the-box content common to Splunk ES, Microsoft
Sentinel, Elastic SIEM, Wazuh, and the Sigma community ruleset, adapted to the
telemetry AutoSOC collects. Each rule maps to a MITRE ATT&CK technique.

Rule schema:
    rule_key       stable unique id
    name           short title
    description    what it detects / why it matters
    category       MITRE tactic-style grouping
    severity       Low | Medium | High | Critical
    mitre          ATT&CK technique id(s)
    rule_type      log_match | telemetry_conn_ioc | telemetry_listen_port
                   | telemetry_conn_port | telemetry_process
    pattern        regex (log_match / telemetry_process)
    threshold      matches within window to trigger (<=1 = every match)
    window_seconds sliding window for threshold rules
    ports          comma-separated ports (telemetry port rules)
    auto_incident  1 = open an incident when it fires
    auto_block     1 = block the source IP through the response pipeline
"""

# Ports commonly used by reverse shells / C2 / backdoors.
SUSPICIOUS_PORTS = "4444,1337,31337,6667,6666,9001,5555,12345,1080,4445,8081,2323"

# Offensive / miner / recon tool process names.
SUSPICIOUS_PROCESS_RE = (
    r"^(nc|ncat|netcat|socat|mimikatz|nmap|masscan|zmap|responder|hydra|"
    r"xmrig|minerd|cryptonight|cpuminer|kworkerds|kinsing|tsunami|"
    r"chisel|frpc|ngrok|telnet)$"
)

DEFAULT_RULES = [
    # ── Credential Access / Brute force ──────────────────────────────
    {
        "rule_key": "ssh_brute_force",
        "name": "SSH / login brute-force",
        "description": "Repeated failed logins from one source in a short window (password guessing).",
        "category": "Credential Access",
        "severity": "High",
        "mitre": "T1110",
        "rule_type": "log_match",
        "pattern": r"Failed password|authentication failure|Invalid user|Failed keyboard-interactive",
        "threshold": 5,
        "window_seconds": 60,
        "auto_incident": 1,
        "auto_block": 0,
    },
    {
        "rule_key": "fortigate_admin_bruteforce",
        "name": "FortiGate admin login brute-force",
        "description": "Repeated FortiGate admin/user login failures (device-side brute force).",
        "category": "Credential Access",
        "severity": "High",
        "mitre": "T1110",
        "rule_type": "log_match",
        "pattern": r"action=\"?login\"?[^\n]*status=\"?failed\"?|logdesc=\"[^\"]*login failed",
        "threshold": 5,
        "window_seconds": 120,
        "auto_incident": 1,
    },
    {
        "rule_key": "account_lockout",
        "name": "Account locked out",
        "description": "An account was locked after too many failed attempts.",
        "category": "Credential Access",
        "severity": "Medium",
        "mitre": "T1110",
        "rule_type": "log_match",
        "pattern": r"account locked|pam_faillock|user account has been locked|Account locked due to",
        "threshold": 1,
    },
    # ── Initial Access / Valid accounts ──────────────────────────────
    {
        "rule_key": "root_login",
        "name": "Root / admin interactive login",
        "description": "A successful privileged login. Legitimate for admins, high value for attackers.",
        "category": "Initial Access",
        "severity": "Medium",
        "mitre": "T1078",
        "rule_type": "log_match",
        "pattern": r"session opened for user root|Accepted (password|publickey) for root|"
                   r"action=\"?login\"?[^\n]*user=\"?admin\"?[^\n]*status=\"?success",
        "threshold": 1,
    },
    {
        "rule_key": "ssh_accepted_login",
        "name": "Successful SSH login",
        "description": "An SSH session was accepted. Baseline visibility for access review.",
        "category": "Initial Access",
        "severity": "Low",
        "mitre": "T1021.004",
        "rule_type": "log_match",
        "pattern": r"Accepted (password|publickey|keyboard-interactive) for",
        "threshold": 1,
    },
    # ── Persistence ──────────────────────────────────────────────────
    {
        "rule_key": "new_user_created",
        "name": "New user account created",
        "description": "A local account was created — a common persistence step.",
        "category": "Persistence",
        "severity": "Medium",
        "mitre": "T1136.001",
        "rule_type": "log_match",
        "pattern": r"new user:|useradd\[|adduser\[|new account added",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "user_added_to_priv_group",
        "name": "User added to privileged group",
        "description": "A user was added to sudo/wheel/admin — privilege escalation or persistence.",
        "category": "Privilege Escalation",
        "severity": "High",
        "mitre": "T1098",
        "rule_type": "log_match",
        "pattern": r"to group '?(sudo|wheel|admin|root|docker)'?|usermod[^\n]*-G[^\n]*(sudo|wheel|admin)",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "cron_modified",
        "name": "Scheduled task / cron modified",
        "description": "A cron/at job was installed or edited — persistence via scheduling.",
        "category": "Persistence",
        "severity": "Medium",
        "mitre": "T1053.003",
        "rule_type": "log_match",
        "pattern": r"crontab\[[0-9]+\].*(REPLACE|BEGIN EDIT)|systemctl (enable|start) .*timer",
        "threshold": 1,
    },
    # ── Privilege Escalation ─────────────────────────────────────────
    {
        "rule_key": "sudo_command",
        "name": "Sudo command executed",
        "description": "A command was run via sudo. Baseline for privilege-use review.",
        "category": "Privilege Escalation",
        "severity": "Low",
        "mitre": "T1548.003",
        "rule_type": "log_match",
        "pattern": r"sudo:[^\n]*COMMAND=",
        "threshold": 1,
    },
    {
        "rule_key": "sudo_auth_failure",
        "name": "Sudo authentication failure",
        "description": "Failed sudo attempts — possible privilege-escalation probing.",
        "category": "Privilege Escalation",
        "severity": "Medium",
        "mitre": "T1548.003",
        "rule_type": "log_match",
        "pattern": r"sudo:[^\n]*authentication failure|sudo:[^\n]*incorrect password attempts",
        "threshold": 3,
        "window_seconds": 120,
    },
    # ── Execution / Command & Control ────────────────────────────────
    {
        "rule_key": "reverse_shell",
        "name": "Reverse shell / netcat usage",
        "description": "Interactive shell over a socket (nc/bash /dev/tcp/socat) — hands-on-keyboard.",
        "category": "Execution",
        "severity": "Critical",
        "mitre": "T1059",
        "rule_type": "log_match",
        "pattern": r"/bin/(ba)?sh -i|bash -i >& ?/dev/tcp|nc(at)? +-[a-z]*e|socat[^\n]*exec|"
                   r"mkfifo[^\n]*\| ?/bin/sh",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "download_and_execute",
        "name": "Download piped to shell",
        "description": "curl/wget output piped straight into a shell — remote code execution.",
        "category": "Execution",
        "severity": "High",
        "mitre": "T1059.004",
        "rule_type": "log_match",
        "pattern": r"(curl|wget)[^\n]*\| ?(ba)?sh|(curl|wget)[^\n]*-o ?/tmp/",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "web_shell_indicator",
        "name": "Web shell indicator",
        "description": "Known web-shell names or PHP code-exec functions in logs.",
        "category": "Persistence",
        "severity": "Critical",
        "mitre": "T1505.003",
        "rule_type": "log_match",
        "pattern": r"\b(c99|r57|wso|b374k|weevely)\b|eval\(base64_decode|passthru\(|"
                   r"shell_exec\(|system\(\$_(GET|POST|REQUEST)",
        "threshold": 1,
        "auto_incident": 1,
    },
    # ── Defense Evasion ──────────────────────────────────────────────
    {
        "rule_key": "security_service_stopped",
        "name": "Security service stopped/disabled",
        "description": "A security tool (auditd, firewall, AV/EDR) was stopped — defense evasion.",
        "category": "Defense Evasion",
        "severity": "High",
        "mitre": "T1562.001",
        "rule_type": "log_match",
        "pattern": r"(Stopped|Stopping|Disabled|masked)[^\n]*"
                   r"(auditd|firewalld|ufw|apparmor|clamav|falcon|wazuh|osquery|crowdstrike)",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "log_cleared",
        "name": "Log cleared / tampered",
        "description": "Audit or system logs were cleared or truncated — anti-forensics.",
        "category": "Defense Evasion",
        "severity": "High",
        "mitre": "T1070",
        "rule_type": "log_match",
        "pattern": r"journalctl[^\n]*--vacuum|rm[^\n]*/var/log|truncate[^\n]*/var/log|"
                   r"cleared|history -c",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "firewall_config_change",
        "name": "Firewall / device config change",
        "description": "A firewall rule or device configuration was changed.",
        "category": "Defense Evasion",
        "severity": "Medium",
        "mitre": "T1562.004",
        "rule_type": "log_match",
        "pattern": r"iptables[^\n]*(-D|-F)|ufw[^\n]*(disable|delete)|"
                   r"type=\"?event\"?[^\n]*subtype=\"?system\"?[^\n]*cfgpath|logdesc=\"[^\"]*[Cc]onfig",
        "threshold": 1,
    },
    # ── Impact / DoS ─────────────────────────────────────────────────
    {
        "rule_key": "kernel_fault",
        "name": "Kernel fault / OOM / crash",
        "description": "Segfault, OOM-killer, or kernel panic — instability or exploitation attempt.",
        "category": "Impact",
        "severity": "Medium",
        "mitre": "T1499",
        "rule_type": "log_match",
        "pattern": r"segfault|Out of memory: Kill|kernel panic|general protection fault",
        "threshold": 1,
    },
    # ── Discovery ────────────────────────────────────────────────────
    {
        "rule_key": "host_enumeration",
        "name": "Host / account enumeration",
        "description": "Recon commands enumerating users, groups, or system info.",
        "category": "Discovery",
        "severity": "Low",
        "mitre": "T1087",
        "rule_type": "log_match",
        "pattern": r"\bnet (user|group|localgroup)\b|whoami /priv|systeminfo|\bgetent passwd\b|\bid -a\b",
        "threshold": 1,
    },
    {
        "rule_key": "network_recon_tool",
        "name": "Network scanning tool used",
        "description": "Invocation of nmap/masscan and similar scanners in logs.",
        "category": "Discovery",
        "severity": "Medium",
        "mitre": "T1046",
        "rule_type": "log_match",
        "pattern": r"\b(nmap|masscan|zmap|nikto|dirb|gobuster)\b",
        "threshold": 1,
    },
    # ── Credential Access ────────────────────────────────────────────
    {
        "rule_key": "shadow_file_access",
        "name": "Password hash file access",
        "description": "Reading /etc/shadow or dumping password hashes.",
        "category": "Credential Access",
        "severity": "High",
        "mitre": "T1003.008",
        "rule_type": "log_match",
        "pattern": r"(cat|less|cp|scp|vi|nano)[^\n]*/etc/shadow|\bunshadow\b",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "credential_dumping",
        "name": "Credential dumping (LSASS/mimikatz)",
        "description": "Tools or access patterns used to dump credentials from memory.",
        "category": "Credential Access",
        "severity": "Critical",
        "mitre": "T1003.001",
        "rule_type": "log_match",
        "pattern": r"mimikatz|procdump[^\n]*lsass|gsecdump|sekurlsa|comsvcs\.dll[^\n]*MiniDump",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "ssh_key_theft",
        "name": "SSH private key access",
        "description": "Reading or copying SSH private keys.",
        "category": "Credential Access",
        "severity": "Medium",
        "mitre": "T1552.004",
        "rule_type": "log_match",
        "pattern": r"(cat|cp|scp|tar)[^\n]*(id_rsa|id_ed25519|\.ssh/[^\n]*key)",
        "threshold": 1,
    },
    # ── Persistence ──────────────────────────────────────────────────
    {
        "rule_key": "authorized_keys_modified",
        "name": "SSH authorized_keys modified",
        "description": "An attacker-planted key grants persistent SSH access.",
        "category": "Persistence",
        "severity": "High",
        "mitre": "T1098.004",
        "rule_type": "log_match",
        "pattern": r"(>>|tee|echo)[^\n]*authorized_keys",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "systemd_persistence",
        "name": "New systemd service / rc persistence",
        "description": "A new service or startup script — a persistence mechanism.",
        "category": "Persistence",
        "severity": "Medium",
        "mitre": "T1543.002",
        "rule_type": "log_match",
        "pattern": r"/etc/systemd/system/[^\n]*\.service|/etc/rc\.local|/etc/init\.d/",
        "threshold": 1,
    },
    # ── Defense Evasion ──────────────────────────────────────────────
    {
        "rule_key": "encoded_command_exec",
        "name": "Encoded command execution",
        "description": "Base64/obfuscated payload decoded and piped to a shell.",
        "category": "Defense Evasion",
        "severity": "High",
        "mitre": "T1140",
        "rule_type": "log_match",
        "pattern": r"base64 (-d|--decode)[^\n]*\| ?(ba)?sh|powershell[^\n]*-e(nc|ncodedcommand)|"
                   r"python[^\n]*base64[^\n]*decode",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "selinux_disabled",
        "name": "SELinux / audit disabled",
        "description": "Mandatory access control or auditing turned off.",
        "category": "Defense Evasion",
        "severity": "High",
        "mitre": "T1562.001",
        "rule_type": "log_match",
        "pattern": r"setenforce 0|SELINUX=disabled|auditctl -e 0|systemctl (stop|disable) auditd",
        "threshold": 1,
    },
    {
        "rule_key": "immutable_flag_set",
        "name": "File made immutable (chattr +i)",
        "description": "Marking a file immutable to resist removal — evasion/persistence.",
        "category": "Defense Evasion",
        "severity": "Medium",
        "mitre": "T1222.002",
        "rule_type": "log_match",
        "pattern": r"chattr \+i",
        "threshold": 1,
    },
    # ── Lateral Movement ─────────────────────────────────────────────
    {
        "rule_key": "remote_exec_tool",
        "name": "Remote execution tool (PsExec/WMI/WinRM)",
        "description": "Remote command execution frameworks used for lateral movement.",
        "category": "Lateral Movement",
        "severity": "High",
        "mitre": "T1021.002",
        "rule_type": "log_match",
        "pattern": r"\bpsexec\b|wmic[^\n]*process call create|winrs |Invoke-Command[^\n]*-ComputerName",
        "threshold": 1,
        "auto_incident": 1,
    },
    # ── Collection / Exfiltration ────────────────────────────────────
    {
        "rule_key": "data_exfiltration",
        "name": "Possible data exfiltration",
        "description": "Bulk transfer of data off the host (scp/rsync/curl upload/tunneling tool).",
        "category": "Exfiltration",
        "severity": "Medium",
        "mitre": "T1048",
        "rule_type": "log_match",
        "pattern": r"scp [^\n]*@|rsync [^\n]*::|curl [^\n]*-T |\b(dnscat|iodine)\b",
        "threshold": 1,
    },
    # ── Impact ───────────────────────────────────────────────────────
    {
        "rule_key": "destructive_command",
        "name": "Destructive command",
        "description": "Mass deletion or disk wipe — data destruction / anti-forensics.",
        "category": "Impact",
        "severity": "Critical",
        "mitre": "T1485",
        "rule_type": "log_match",
        "pattern": r"rm -rf /(\s|\*|$)|dd if=[^\n]*of=/dev/(sd|nvme|vd)|\bmkfs\.[a-z0-9]+ /dev/|"
                   r":\(\)\{ ?:\|:& ?\};:",
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "ransomware_indicator",
        "name": "Ransomware indicator",
        "description": "Ransom notes or recovery-deletion typical of ransomware.",
        "category": "Impact",
        "severity": "Critical",
        "mitre": "T1486",
        "rule_type": "log_match",
        "pattern": r"YOUR FILES[^\n]*ENCRYPTED|how[_ ]?to[_ ]?decrypt|README[_ ]?FOR[_ ]?DECRYPT|"
                   r"vssadmin[^\n]*delete shadows|wbadmin delete catalog|bcdedit[^\n]*recoveryenabled no",
        "threshold": 1,
        "auto_incident": 1,
    },

    # ── Network telemetry rules ──────────────────────────────────────
    {
        "rule_key": "conn_to_bad_ip",
        "name": "Connection to blocked / IOC IP",
        "description": "An endpoint is talking to an IP on the block-list or IOC watchlist (C2 / exfil).",
        "category": "Command and Control",
        "severity": "Critical",
        "mitre": "T1071",
        "rule_type": "telemetry_conn_ioc",
        "threshold": 1,
        "auto_incident": 1,
        "auto_block": 1,
    },
    {
        "rule_key": "suspicious_listener",
        "name": "Listener on suspicious port",
        "description": "A process is listening on a port commonly used by backdoors / C2.",
        "category": "Persistence",
        "severity": "High",
        "mitre": "T1571",
        "rule_type": "telemetry_listen_port",
        "ports": SUSPICIOUS_PORTS,
        "threshold": 1,
        "auto_incident": 1,
    },
    {
        "rule_key": "conn_to_c2_port",
        "name": "Connection to C2-style port",
        "description": "An outbound connection to a remote port commonly used by C2 frameworks.",
        "category": "Command and Control",
        "severity": "High",
        "mitre": "T1571",
        "rule_type": "telemetry_conn_port",
        "ports": SUSPICIOUS_PORTS,
        "threshold": 1,
    },
    {
        "rule_key": "suspicious_process",
        "name": "Suspicious / offensive tool running",
        "description": "A process matching known offensive, recon, or crypto-miner tool names is running.",
        "category": "Execution",
        "severity": "High",
        "mitre": "T1059",
        "rule_type": "telemetry_process",
        "pattern": SUSPICIOUS_PROCESS_RE,
        "threshold": 1,
        "auto_incident": 1,
    },
]
