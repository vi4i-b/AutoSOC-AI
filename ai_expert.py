import os
import requests


class AISecurityExpert:
    SYSTEM_PROMPT = (
        "You are a cybersecurity specialist. Answer only questions related to IT security, "
        "network defense, phishing, brute-force, malware, hardening, incident response, "
        "authentication, logging, and system protection. If the user asks about unrelated topics, "
        "politely refuse and steer the conversation back to cybersecurity. Keep answers practical."
    )

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip()
        self.knowledge_base = {
            "Windows": {
                445: "SMB is exposed. Disable SMBv1 and restrict access by firewall.",
                3389: "RDP is exposed. Enable NLA, use strong passwords, and limit source IPs.",
                135: "RPC exposure can leak system metadata. Do not expose it externally.",
            },
            "Linux": {
                22: "SSH is open. Prefer key-based auth and disable password login.",
                80: "HTTP is open. Redirect to HTTPS and deploy TLS properly.",
                21: "FTP is open. Prefer SFTP or FTPS because FTP is not encrypted.",
            },
            "Network Device": {
                80: "A device admin panel may be exposed. Change defaults and disable WAN admin access.",
                23: "Telnet is insecure. Disable it and migrate to SSH.",
                554: "RTSP may expose camera streams. Require authentication and segment the network.",
            },
        }
        self.port_catalog = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 1433: "MS-SQL", 1521: "Oracle DB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
        }

    def generate_instruction(self, device_type, port, service):
        vendor = (device_type or "").lower()
        if "microsoft" in vendor or "windows" in vendor:
            group = "Windows"
        elif "ubuntu" in vendor or "linux" in vendor or "debian" in vendor:
            group = "Linux"
        elif any(name in vendor for name in ["tp-link", "asus", "cisco", "huawei", "mikrotik"]):
            group = "Network Device"
        else:
            group = "Unknown"

        if group in self.knowledge_base and port in self.knowledge_base[group]:
            return self.knowledge_base[group][port]

        return (
            f"{service} on port {port} can increase attack surface. If you do not need it, "
            "close it in the firewall and verify patching and access control."
        )

    def summarize_scan(self, devices):
        if not devices:
            return "No scan context is available yet. Run a scan first, then ask me to explain the result."

        lines = []
        for device in devices:
            vendor = list(device.get("vendor", {}).values())[0] if device.get("vendor") else "Unknown device"
            open_ports = device.get("ports", [])
            if open_ports:
                port_list = ", ".join(
                    f"{item['port']} ({self.port_catalog.get(item['port'], item.get('name', 'service'))})"
                    for item in open_ports
                )
                lines.append(f"{device['ip']} / {vendor}: open ports -> {port_list}.")
            else:
                lines.append(f"{device['ip']} / {vendor}: no open services detected across the selected 22 ports.")
        return "\n".join(lines)

    def _is_security_question(self, prompt):
        keywords = [
            "security", "cyber", "phishing", "brute", "malware", "ransomware", "firewall",
            "port", "network", "hardening", "vulnerability", "threat", "incident", "soc",
            "ssh", "rdp", "smb", "telegram", "ddos", "auth", "attack", "defense",
            "tehluke", "tehluk", "tehlukesizlik", "phish", "scan",
        ]
        prompt = prompt.lower()
        return any(keyword in prompt for keyword in keywords)

    def _query_openai(self, question, devices=None):
        if not self.api_key:
            return None

        context = self.summarize_scan(devices or [])
        payload = {
            "model": self.model,
            "input": [
                {"role": "system", "content": [{"type": "text", "text": self.SYSTEM_PROMPT}]},
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": f"Scan context:\n{context}\n\nUser question:\n{question}",
                        }
                    ],
                },
            ],
            "temperature": 0.3,
        }

        try:
            response = requests.post(
                "https://api.openai.com/v1/responses",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            text = data.get("output_text", "").strip()
            return text or None
        except Exception as exc:
            return f"LLM request failed: {exc}"

    def answer_question(self, question, devices=None):
        prompt = (question or "").strip()
        if not prompt:
            return "Ask a cybersecurity question. Example: 'How do I protect against phishing?'"

        if self._is_security_question(prompt):
            llm_answer = self._query_openai(prompt, devices)
            if llm_answer:
                return llm_answer

        lowered = prompt.lower()
        if any(word in lowered for word in ["scan", "result", "netic", "nəticə", "open port"]):
            return self.summarize_scan(devices or [])

        if any(word in lowered for word in ["risk", "threat", "danger", "tehluke", "təhlükə"]):
            findings = []
            for device in devices or []:
                vendor = list(device.get("vendor", {}).values())[0] if device.get("vendor") else "Device"
                for port in device.get("ports", []):
                    findings.append(
                        f"{device['ip']} port {port['port']}: "
                        f"{self.generate_instruction(vendor, int(port['port']), port.get('name', 'service'))}"
                    )
            return "\n".join(findings[:6]) if findings else "No notable risk was found in the latest scan context."

        for port, service in self.port_catalog.items():
            if str(port) in lowered:
                return self.generate_instruction("unknown", port, service)

        if not self._is_security_question(prompt):
            return "I only answer cybersecurity-related questions. Ask about phishing, brute-force, ports, malware, hardening, or network defense."

        return "I can explain the latest scan, evaluate open ports, and recommend hardening steps."


if __name__ == "__main__":
    expert = AISecurityExpert()
    print(expert.generate_instruction("Microsoft Corporation", 445, "SMB"))
