class RiskAnalyzer:
    SEVERITY_WEIGHTS = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4,
    }

    def __init__(self):
        self.threats = {
            21: {
                "service": "FTP",
                "risk": "Critical",
                "category": "Legacy file transfer",
                "desc": "Plain-text credentials and file transfers are easy to intercept.",
                "prevention": "Disable if unused or replace with SFTP/FTPS and restrict source IPs.",
            },
            22: {
                "service": "SSH",
                "risk": "Medium",
                "category": "Remote administration",
                "desc": "Secure by design, but often targeted with password spraying and brute-force.",
                "prevention": "Use keys only, disable password auth, and allow trusted IPs only.",
            },
            23: {
                "service": "Telnet",
                "risk": "Critical",
                "category": "Legacy remote admin",
                "desc": "No transport encryption and very high abuse potential.",
                "prevention": "Replace with SSH and block internet exposure immediately.",
            },
            25: {
                "service": "SMTP",
                "risk": "Medium",
                "category": "Mail relay exposure",
                "desc": "Misconfigured SMTP can be abused for spam relaying or banner enumeration.",
                "prevention": "Restrict relaying, enforce auth, and limit to known peers.",
            },
            53: {
                "service": "DNS",
                "risk": "Medium",
                "category": "Infrastructure exposure",
                "desc": "Open resolvers and recursive DNS can be abused for amplification attacks.",
                "prevention": "Disable recursion for untrusted clients and restrict external access.",
            },
            80: {
                "service": "HTTP",
                "risk": "Medium",
                "category": "Web exposure",
                "desc": "Unencrypted web traffic can leak credentials and session data.",
                "prevention": "Redirect to HTTPS, harden headers, and reduce public attack surface.",
            },
            110: {
                "service": "POP3",
                "risk": "High",
                "category": "Legacy mail access",
                "desc": "Legacy mail protocols are often left with weak auth and poor encryption.",
                "prevention": "Prefer IMAPS and restrict access by network zone.",
            },
            139: {
                "service": "NetBIOS",
                "risk": "High",
                "category": "Legacy discovery",
                "desc": "Exposes hostnames, shares, and legacy trust relationships.",
                "prevention": "Disable where possible and isolate from untrusted segments.",
            },
            143: {
                "service": "IMAP",
                "risk": "Medium",
                "category": "Mail access",
                "desc": "Unhardened IMAP increases credential-stuffing and weak-auth risk.",
                "prevention": "Require TLS, strong auth, and known source ranges.",
            },
            445: {
                "service": "SMB",
                "risk": "Critical",
                "category": "Lateral movement",
                "desc": "Frequently targeted by worms, ransomware, and lateral movement toolkits.",
                "prevention": "Disable SMBv1, patch aggressively, and never expose broadly.",
            },
            1433: {
                "service": "MS-SQL",
                "risk": "High",
                "category": "Database exposure",
                "desc": "Directly exposed databases are attractive brute-force and data-theft targets.",
                "prevention": "Allow only app tiers/admin jump hosts and review auth and backups.",
            },
            1521: {
                "service": "Oracle DB",
                "risk": "High",
                "category": "Database exposure",
                "desc": "Oracle listeners often leak metadata and invite targeted credential attacks.",
                "prevention": "Restrict listener access and isolate the database network.",
            },
            3306: {
                "service": "MySQL",
                "risk": "Critical",
                "category": "Database exposure",
                "desc": "Broadly reachable MySQL often leads to credential attacks and data theft.",
                "prevention": "Keep private, require strong auth, and allow only application hosts.",
            },
            3389: {
                "service": "RDP",
                "risk": "Critical",
                "category": "Remote administration",
                "desc": "High-value target for brute-force, stolen credentials, and ransomware operators.",
                "prevention": "Require NLA, VPN/bastion, MFA, and strict source IP filtering.",
            },
            5432: {
                "service": "PostgreSQL",
                "risk": "High",
                "category": "Database exposure",
                "desc": "Public database listeners increase risk of credential attacks and data exposure.",
                "prevention": "Keep private and enforce network-level allow lists.",
            },
            5900: {
                "service": "VNC",
                "risk": "Critical",
                "category": "Remote desktop",
                "desc": "VNC is commonly exposed with weak auth and little transport protection.",
                "prevention": "Disable if possible or keep behind VPN with strong access control.",
            },
            6379: {
                "service": "Redis",
                "risk": "Critical",
                "category": "In-memory database",
                "desc": "Unauthenticated or weakly secured Redis is a common takeover target.",
                "prevention": "Bind privately, require auth, and never expose to the internet.",
            },
            8080: {
                "service": "HTTP-Alt",
                "risk": "Medium",
                "category": "Alt web exposure",
                "desc": "Alternate web listeners are often forgotten and left unhardened.",
                "prevention": "Review ownership, patching, and restrict unnecessary exposure.",
            },
            8443: {
                "service": "HTTPS-Alt",
                "risk": "Low",
                "category": "Alt secure web",
                "desc": "Usually legitimate, but still needs ownership and certificate review.",
                "prevention": "Verify TLS config and keep management interfaces restricted.",
            },
            27017: {
                "service": "MongoDB",
                "risk": "Critical",
                "category": "Database exposure",
                "desc": "Public MongoDB has a long history of abuse, data theft, and ransom wipes.",
                "prevention": "Keep private, enable auth, and isolate from untrusted networks.",
            },
        }

    def analyze(self, ports_list):
        findings = []
        for port_info in ports_list:
            port_num = int(port_info["port"])
            if port_num in self.threats:
                info = dict(self.threats[port_num])
                findings.append(
                    {
                        "port": port_num,
                        "info": info,
                        "severity_weight": self.SEVERITY_WEIGHTS.get(info["risk"], 1),
                    }
                )
        return findings

    def calculate_risk_score(self, findings):
        total_weight = sum(item.get("severity_weight", 1) for item in findings)
        return min(total_weight * 8, 100)
