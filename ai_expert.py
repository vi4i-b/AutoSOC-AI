import json
import os
from collections import Counter
from datetime import datetime

import requests

from database import SOCDatabase
from runtime_support import load_env_file


class AISecurityExpert:
    SYSTEM_PROMPT = (
        "You are AutoSOC, a cybersecurity assistant that should feel like a real SOC copilot. "
        "Answer in the user's language when possible, especially Russian, Azerbaijani, or English. "
        "Use the full dialog context, remember the active topic, connect follow-up questions to previous turns, "
        "and personalize answers based on the recent scan context, shared team memory, and persistent memory. "
        "Focus on defensive cybersecurity topics: SOC operations, phishing, brute-force, malware, "
        "incident response, hardening, monitoring, SIEM, firewalling, exposed ports, authentication, "
        "network defense, ransomware, detection, and remediation. "
        "When the user asks a short follow-up like 'why', 'how', 'what next', or references 'this port'/'this threat', "
        "infer the target from recent context instead of asking them to repeat themselves. "
        "If the topic is unrelated to cybersecurity, refuse briefly and redirect back to cybersecurity. "
        "When scan context is provided, use it directly and give practical next steps."
    )

    def __init__(self):
        load_env_file()
        self.provider = os.getenv("AI_PROVIDER", "auto").strip().lower()
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat").strip()
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3.1:8b").strip()
        self.memory_file = os.getenv("AI_MEMORY_FILE", "ai_memory.json").strip() or "ai_memory.json"
        self.history_limit = 16
        self.shared_db = SOCDatabase()
        self.port_catalog = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 1433: "MS-SQL", 1521: "Oracle DB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
        }
        self.security_keywords = [
            "security", "cyber", "phishing", "phish", "brute", "malware", "ransomware",
            "firewall", "port", "network", "hardening", "vulnerability", "threat", "incident",
            "soc", "ssh", "rdp", "smb", "ddos", "auth", "attack", "defense", "forensic", "siem",
            "безопас", "фиш", "брут", "атака", "угроз", "инцидент", "защит", "сеть", "порт",
            "кибер", "шифров", "фаервол", "вирус", "вредонос",
            "təhlük", "tehluk", "fişinq", "hücum", "tehlukesizlik", "şəbək", "müdafiə",
            "zərərli", "fişing", "sızma",
        ]
        self.followup_markers = [
            "why", "how", "what next", "and then", "what about", "this", "that", "it",
            "почему", "как", "что дальше", "а если", "это", "этот", "эта", "оно",
            "niyə", "necə", "sonra nə", "bəs", "bu", "o",
        ]
        self.conversation_history = []
        self.memory = self._load_memory()
        self.live_provider = self._resolve_live_provider()

    def _default_memory(self):
        return {
            "preferred_language": "",
            "active_topic": "",
            "user_profile": {
                "focus_area": "",
                "last_target_ip": "",
            },
            "known_ports": [],
            "recent_findings": [],
            "conversation_summary": "",
            "shared_lessons": [],
            "last_updated": "",
        }

    def _load_memory(self):
        if not os.path.exists(self.memory_file):
            return self._default_memory()

        try:
            with open(self.memory_file, "r", encoding="utf-8") as memory_file:
                data = json.load(memory_file)
                memory = self._default_memory()
                if isinstance(data, dict):
                    memory.update(data)
                return memory
        except (OSError, json.JSONDecodeError):
            return self._default_memory()

    def _save_memory(self):
        self.memory["last_updated"] = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        try:
            with open(self.memory_file, "w", encoding="utf-8") as memory_file:
                json.dump(self.memory, memory_file, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _ollama_health_url(self):
        if self.ollama_url.endswith("/api/chat"):
            return self.ollama_url[:-9] + "/api/tags"
        return self.ollama_url.rstrip("/") + "/api/tags"

    def _is_ollama_available(self):
        try:
            response = requests.get(self._ollama_health_url(), timeout=3)
            return response.ok
        except Exception:
            return False

    def _resolve_live_provider(self):
        provider = self.provider or "auto"
        if provider == "openai":
            return "openai" if self.api_key else None
        if provider == "ollama":
            return "ollama" if self._is_ollama_available() else None
        if provider == "auto":
            if self.api_key:
                return "openai"
            if self._is_ollama_available():
                return "ollama"
        return None

    def reset_history(self):
        self.conversation_history = []
        self.memory["active_topic"] = ""
        self.memory["conversation_summary"] = ""
        self._save_memory()

    def detect_language(self, text):
        lowered = (text or "").lower()
        if any(token in lowered for token in ["привет", "здрав", "как дела", "безопас", "фиш", "брут", "атака"]):
            return "ru"
        if any(token in lowered for token in ["salam", "necə", "təhlük", "tehluk", "fişinq", "şəbəkə", "hücum"]):
            return "az"
        return "en"

    def localized(self, language, key):
        phrases = {
            "ru": {
                "greeting": "Привет. Я AutoSOC, помощник по кибербезопасности. Помогаю разбирать угрозы, порты, hardening и результаты сканирования.",
                "redirect": "Я отвечаю по темам кибербезопасности. Спроси про фишинг, brute-force, malware, hardening, открытые порты или защиту сети.",
                "no_scan": "Пока нет контекста сканирования. Запусти скан, и я помогу разобрать результат.",
                "fallback": "Сейчас я отвечаю встроенным экспертным режимом.",
                "hello_help": "Можно спросить, например: «Почему опасен 445 порт?», «Что делать после обнаружения RDP?» или «Разбери последний скан».",
            },
            "az": {
                "greeting": "Salam. Mən AutoSOC təhlükəsizlik köməkçisiyəm. Təhdidlər, portlar, hardening və scan nəticələrini izah edə bilərəm.",
                "redirect": "Mən əsasən kibertəhlükəsizlik mövzularına cavab verirəm. Fişinq, brute-force, malware, hardening, açıq portlar və şəbəkə müdafiəsi barədə soruşun.",
                "no_scan": "Hələ scan konteksti yoxdur. Əvvəl scan başladın, sonra nəticəni birlikdə izah edərəm.",
                "fallback": "Hazırda daxili ekspert rejimində cavab verirəm.",
                "hello_help": "Məsələn soruşa bilərsiniz: «445 portu niyə təhlükəlidir?», «RDP açıqdırsa nə etməliyəm?» və ya «Son scan-i izah et».",
            },
            "en": {
                "greeting": "Hello. I am AutoSOC, your cybersecurity assistant. I can explain threats, open ports, hardening steps, and scan results.",
                "redirect": "I answer cybersecurity topics. Ask about phishing, brute-force, malware, hardening, open ports, or network defense.",
                "no_scan": "There is no scan context yet. Run a scan first and I will help interpret it.",
                "fallback": "I am answering with the built-in expert mode right now.",
                "hello_help": "You can ask, for example: 'Why is port 445 risky?', 'What should I do after exposed RDP?', or 'Explain the last scan.'",
            },
        }
        return phrases.get(language, phrases["en"])[key]

    def is_greeting(self, text):
        lowered = (text or "").strip().lower()
        greetings = [
            "hello", "hi", "hey", "yo", "good morning", "good evening",
            "привет", "здравствуйте", "здравствуй", "добрый день",
            "salam", "sabahınız xeyir", "axşamınız xeyir", "necəsən", "necesen",
        ]
        return any(lowered == item or lowered.startswith(f"{item} ") for item in greetings)

    def is_security_question(self, text):
        lowered = (text or "").lower()
        return any(keyword in lowered for keyword in self.security_keywords)

    def infer_topic(self, question, devices=None):
        lowered = (question or "").lower()
        for port, service in self.port_catalog.items():
            if str(port) in lowered:
                return f"port_{port}_{service.lower()}"

        if any(word in lowered for word in ["phishing", "phish", "фиш", "fiş"]):
            return "phishing"
        if any(word in lowered for word in ["brute", "парол", "password", "брут"]):
            return "brute_force"
        if any(word in lowered for word in ["malware", "virus", "вирус", "ransomware", "zərərli"]):
            return "malware"
        if any(word in lowered for word in ["scan", "result", "результ", "nəticə"]):
            return "scan_analysis"
        if any(word in lowered for word in ["incident", "response", "инцидент"]):
            return "incident_response"

        if self._is_followup_question(question):
            return self.memory.get("active_topic") or self._get_last_port_topic(devices)

        return ""

    def _is_followup_question(self, question):
        lowered = (question or "").strip().lower()
        return len(lowered.split()) <= 6 or any(marker in lowered for marker in self.followup_markers)

    def _get_last_port_topic(self, devices=None):
        known_ports = self.memory.get("known_ports") or []
        if known_ports:
            return f"port_{known_ports[-1]}"

        for device in devices or []:
            ports = device.get("ports", [])
            if ports:
                return f"port_{ports[0].get('port')}"
        return ""

    def summarize_scan(self, devices, language="en"):
        if not devices:
            return self.localized(language, "no_scan")

        lines = []
        for device in devices:
            vendor = list(device.get("vendor", {}).values())[0] if device.get("vendor") else "Unknown device"
            open_ports = device.get("ports", [])
            if open_ports:
                port_list = ", ".join(
                    f"{item['port']} ({self.port_catalog.get(int(item['port']), item.get('name', 'service'))})"
                    for item in open_ports
                )
                if language == "ru":
                    lines.append(f"{device['ip']} / {vendor}: открытые порты -> {port_list}.")
                elif language == "az":
                    lines.append(f"{device['ip']} / {vendor}: açıq portlar -> {port_list}.")
                else:
                    lines.append(f"{device['ip']} / {vendor}: open ports -> {port_list}.")
            else:
                if language == "ru":
                    lines.append(f"{device['ip']} / {vendor}: по выбранным портам открытых сервисов не найдено.")
                elif language == "az":
                    lines.append(f"{device['ip']} / {vendor}: seçilmiş portlar üzrə açıq servis tapılmadı.")
                else:
                    lines.append(f"{device['ip']} / {vendor}: no open services were detected on the selected ports.")
        return "\n".join(lines)

    def generate_instruction(self, device_type, port, service, language="en"):
        if port == 445:
            if language == "ru":
                return "Открыт SMB. Отключи SMBv1, ограничь доступ по firewall, проверь патчи и запрети доступ извне."
            if language == "az":
                return "SMB açıqdır. SMBv1-i söndür, firewall ilə məhdudlaşdır, patch-ləri yoxla və internetdən girişi bağla."
            return "SMB is exposed. Disable SMBv1, restrict it with the firewall, verify patching, and block internet exposure."
        if port == 3389:
            if language == "ru":
                return "Открыт RDP. Включи NLA, задай сильные пароли, ограничь доступ по IP и включи MFA через VPN или бастион."
            if language == "az":
                return "RDP açıqdır. NLA aktiv et, güclü parol təyin et, IP-ləri məhdudlaşdır və MFA üçün VPN/bastion istifadə et."
            return "RDP is exposed. Enable NLA, require strong passwords, restrict source IPs, and put MFA behind a VPN or bastion."
        if port == 22:
            if language == "ru":
                return "Открыт SSH. Используй ключи, отключи вход по паролю, ограничь trusted IP и контролируй неудачные попытки входа."
            if language == "az":
                return "SSH açıqdır. Açar əsaslı giriş istifadə et, parol girişini söndür, trusted IP-ləri məhdudlaşdır və uğursuz login-ləri izlə."
            return "SSH is open. Prefer keys, disable password login, limit trusted source IPs, and monitor failed login attempts."

        if language == "ru":
            return f"{service} на порту {port} расширяет поверхность атаки. Если сервис не нужен, закрой его и проверь контроль доступа."
        if language == "az":
            return f"{service} xidməti {port}-cu portda hücum səthini artırır. Lazım deyilsə, bağla və giriş nəzarətini yoxla."
        return f"{service} on port {port} increases attack surface. If you do not need it, close it and verify access controls."

    def _extract_findings(self, devices=None):
        findings = []
        known_ports = []
        target_ip = ""

        for device in devices or []:
            if not target_ip:
                target_ip = device.get("ip", "")
            vendor = list(device.get("vendor", {}).values())[0] if device.get("vendor") else "Device"
            for port in device.get("ports", []):
                port_num = int(port.get("port"))
                known_ports.append(port_num)
                findings.append({
                    "ip": device.get("ip", ""),
                    "vendor": vendor,
                    "port": port_num,
                    "service": self.port_catalog.get(port_num, port.get("name", "service")),
                })

        self.memory["known_ports"] = known_ports[-12:]
        if target_ip:
            self.memory["user_profile"]["last_target_ip"] = target_ip
        self.memory["recent_findings"] = findings[-12:]

    def _remember_turn(self, question, answer, topic=""):
        self.conversation_history.append({"role": "user", "content": question})
        self.conversation_history.append({"role": "assistant", "content": answer})
        self.conversation_history = self.conversation_history[-self.history_limit:]

        if topic:
            self.memory["active_topic"] = topic

        short_answer = answer.replace("\n", " ").strip()
        short_answer = short_answer[:220]
        self.memory["conversation_summary"] = f"User asked: {question[:120]}. Assistant answered: {short_answer}"
        lessons = self.memory.get("shared_lessons") or []
        lessons.append(
            {
                "question": question[:160],
                "answer": short_answer,
                "topic": topic or self.memory.get("active_topic", ""),
            }
        )
        self.memory["shared_lessons"] = lessons[-12:]
        self._save_memory()

    def _memory_context(self):
        preferred_language = self.memory.get("preferred_language") or "unknown"
        active_topic = self.memory.get("active_topic") or "none"
        target_ip = self.memory.get("user_profile", {}).get("last_target_ip") or "unknown"
        findings = self.memory.get("recent_findings") or []
        lessons = self.memory.get("shared_lessons") or []
        finding_text = ", ".join(
            f"{item['ip']}:{item['port']}({item['service']})" for item in findings[-6:]
        ) or "none"
        lesson_text = " | ".join(
            f"{item.get('topic') or 'general'} -> {item.get('question', '')[:60]}"
            for item in lessons[-4:]
        ) or "none"

        return (
            f"Preferred language: {preferred_language}\n"
            f"Active topic: {active_topic}\n"
            f"Last target IP: {target_ip}\n"
            f"Recent findings: {finding_text}\n"
            f"Shared lessons: {lesson_text}\n"
            f"Conversation summary: {self.memory.get('conversation_summary', '')}"
        )

    def _shared_security_context(self):
        try:
            scans = self.shared_db.get_all_scans()[:8]
            events = self.shared_db.get_recent_security_events(8)
        except Exception:
            return "Shared security telemetry unavailable."

        target_counts = Counter(row[1] for row in scans if row[1])
        event_counts = Counter(row[1] for row in events if row[1])
        avg_risk = 0
        if scans:
            avg_risk = round(sum(int(row[2] or 0) for row in scans) / len(scans))

        hottest_targets = ", ".join(f"{target}({count})" for target, count in target_counts.most_common(4)) or "none"
        hottest_events = ", ".join(f"{event}({count})" for event, count in event_counts.most_common(4)) or "none"
        recent_scan_lines = "; ".join(
            f"{row[0]} target={row[1]} risk={row[2]} summary={row[3]}"
            for row in scans[:5]
        ) or "none"
        recent_event_lines = "; ".join(
            f"{row[0]} type={row[1]} severity={row[2]} source={row[3]}"
            for row in events[:5]
        ) or "none"

        return (
            f"Average recent scan risk: {avg_risk}%\n"
            f"Most frequent targets across all users: {hottest_targets}\n"
            f"Most frequent security events across all users: {hottest_events}\n"
            f"Recent scans across all users: {recent_scan_lines}\n"
            f"Recent events across all users: {recent_event_lines}"
        )

    def build_input(self, question, devices=None):
        language = self.detect_language(question)
        topic = self.infer_topic(question, devices)
        context = self.summarize_scan(devices or [], language)
        input_items = [
            {"role": "system", "content": [{"type": "input_text", "text": self.SYSTEM_PROMPT}]},
            {"role": "system", "content": [{"type": "input_text", "text": f"Persistent memory:\n{self._memory_context()}"}]},
            {"role": "system", "content": [{"type": "input_text", "text": f"Shared team security memory:\n{self._shared_security_context()}"}]},
            {"role": "system", "content": [{"type": "input_text", "text": f"Latest scan context:\n{context}"}]},
        ]

        if topic:
            input_items.append(
                {"role": "system", "content": [{"type": "input_text", "text": f"Current inferred topic: {topic}"}]}
            )

        for item in self.conversation_history[-self.history_limit:]:
            input_items.append(
                {"role": item["role"], "content": [{"type": "input_text", "text": item["content"]}]}
            )

        input_items.append({"role": "user", "content": [{"type": "input_text", "text": question}]})
        return input_items

    def query_openai(self, question, devices=None):
        if not self.api_key:
            return None

        payload = {
            "model": self.model,
            "input": self.build_input(question, devices),
            "temperature": 0.2,
        }

        try:
            response = requests.post(
                "https://api.openai.com/v1/responses",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=60,
            )
            response.raise_for_status()
            data = response.json()
            text = data.get("output_text", "").strip()
            if text:
                self._remember_turn(question, text, self.infer_topic(question, devices))
                return text
            return "The model returned an empty response."
        except Exception as exc:
            return f"LLM request failed: {exc}"

    def query_ollama(self, question, devices=None):
        language = self.detect_language(question)
        topic = self.infer_topic(question, devices)
        payload = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "system", "content": f"Persistent memory:\n{self._memory_context()}"},
                {"role": "system", "content": f"Shared team security memory:\n{self._shared_security_context()}"},
                {"role": "system", "content": f"Latest scan context:\n{self.summarize_scan(devices or [], language)}"},
            ],
            "stream": False,
        }

        if topic:
            payload["messages"].append({"role": "system", "content": f"Current inferred topic: {topic}"})

        payload["messages"].extend(self.conversation_history[-self.history_limit:])
        payload["messages"].append({"role": "user", "content": question})

        try:
            response = requests.post(self.ollama_url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            text = data.get("message", {}).get("content", "").strip()
            if text:
                self._remember_turn(question, text, topic)
                return text
            return "Local model returned an empty response."
        except Exception as exc:
            return f"Ollama request failed: {exc}"

    def _port_guidance_from_memory(self, language):
        active_topic = self.memory.get("active_topic", "")
        if not active_topic.startswith("port_"):
            return ""

        parts = active_topic.split("_")
        port = None
        for item in parts:
            if item.isdigit():
                port = int(item)
                break
        if port is None:
            return ""

        service = self.port_catalog.get(port, "service")
        return self.generate_instruction("unknown", port, service, language)

    def local_fallback_answer(self, question, devices=None):
        language = self.detect_language(question)
        lowered = (question or "").lower()
        topic = self.infer_topic(question, devices)

        if self.is_greeting(question):
            return f"{self.localized(language, 'greeting')} {self.localized(language, 'hello_help')}"

        if any(word in lowered for word in ["who are you", "что ты умеешь", "sən nə edirsən", "what can you do", "nə edə bilirsən"]):
            if language == "ru":
                return "Я анализирую риски по открытым портам, запоминаю тему диалога, учитываю последний скан и могу объяснять, что делать дальше по hardening, phishing, brute-force и malware."
            if language == "az":
                return "Mən açıq port risklərini analiz edirəm, dialoqun mövzusunu yadda saxlayıram, son scan-i nəzərə alıram və hardening, fişinq, brute-force, malware üzrə növbəti addımları izah edirəm."
            return "I analyze open-port risk, remember the current topic, use the last scan, and explain next steps for hardening, phishing, brute-force, and malware defense."

        if any(word in lowered for word in ["phishing", "phish", "fişinq", "фиш"]):
            if language == "ru":
                return "Для защиты от фишинга включи MFA, проверяй домен отправителя, не открывай неожиданные вложения, внедри фильтрацию почты и обучи пользователей сообщать о подозрительных письмах."
            if language == "az":
                return "Fişinqdən qorunmaq üçün MFA aktiv et, göndərənin domenini yoxla, şübhəli link və əlavələri açma, email filtrasiya tətbiq et və istifadəçiləri maarifləndir."
            return "To reduce phishing risk, enable MFA, verify sender domains, avoid unexpected links or attachments, deploy email filtering, and train users to report suspicious messages."

        if any(word in lowered for word in ["brute", "брут", "парол", "password attack"]):
            if language == "ru":
                return "От brute-force помогают MFA, rate limiting, блокировка после нескольких неудачных попыток, сильные пароли, ограничение по IP и мониторинг входов."
            if language == "az":
                return "Brute-force hücumuna qarşı MFA, rate limiting, uğursuz cəhdlərdən sonra bloklama, güclü parollar, IP məhdudiyyəti və login monitorinqi kömək edir."
            return "Protect against brute-force with MFA, rate limiting, temporary lockout after failed attempts, strong password policy, IP restrictions, and login monitoring."

        if any(word in lowered for word in ["malware", "virus", "вирус", "zərərli", "ransomware"]):
            if language == "ru":
                return "Против malware и ransomware нужны быстрые патчи, EDR/AV, минимальные привилегии, сегментация сети, offline-бэкапы и мониторинг lateral movement."
            if language == "az":
                return "Malware və ransomware üçün sürətli patching, EDR/AV, minimal hüquqlar, şəbəkə seqmentasiyası, offline backup və lateral movement monitorinqi vacibdir."
            return "For malware and ransomware defense, patch quickly, deploy EDR/AV, minimize privileges, segment the network, keep offline backups, and monitor lateral movement."

        if any(word in lowered for word in ["scan", "result", "nəticə", "результ", "open port", "açıq port"]):
            return self.summarize_scan(devices or [], language)

        if any(word in lowered for word in ["risk", "threat", "danger", "угроз", "təhlük", "tehluk"]):
            findings = []
            for item in (self.memory.get("recent_findings") or [])[-6:]:
                findings.append(
                    f"{item['ip']} port {item['port']}: {self.generate_instruction(item['vendor'], item['port'], item['service'], language)}"
                )
            if findings:
                return "\n".join(findings)

        for port, service in self.port_catalog.items():
            if str(port) in lowered:
                return self.generate_instruction("unknown", port, service, language)

        if topic and topic.startswith("port_"):
            remembered = self._port_guidance_from_memory(language)
            if remembered:
                return remembered

        if self._is_followup_question(question):
            remembered = self._port_guidance_from_memory(language)
            if remembered:
                if language == "ru":
                    return f"Судя по контексту, речь всё ещё о последнем обсуждаемом сервисе.\n{remembered}"
                if language == "az":
                    return f"Kontekstdən görünür ki, söhbət hələ də son müzakirə olunan servisdəndir.\n{remembered}"
                return f"From the context, this still seems to be about the last discussed service.\n{remembered}"

        if self.is_security_question(question):
            if language == "ru":
                return "Я понял, что вопрос по безопасности. Уточни тему или привяжи ее к последнему скану: фишинг, открытый порт, hardening, malware, brute-force или инцидент."
            if language == "az":
                return "Sualın təhlükəsizliklə bağlı olduğunu anladım. Mövzunu bir az dəqiqləşdirin və ya son scan-ə bağlayın: fişinq, açıq port, hardening, malware, brute-force və ya insident."
            return "I understand this is a security question. Narrow it down or connect it to the last scan: phishing, open port, hardening, malware, brute-force, or incident response."

        return self.localized(language, "redirect")

    def answer_question(self, question, devices=None):
        prompt = (question or "").strip()
        if not prompt:
            return self.localized(self.memory.get("preferred_language") or "en", "hello_help")

        language = self.detect_language(prompt)
        self.memory["preferred_language"] = language
        self._extract_findings(devices)

        if self.is_greeting(prompt):
            answer = f"{self.localized(language, 'greeting')} {self.localized(language, 'hello_help')}"
            self._remember_turn(prompt, answer, self.infer_topic(prompt, devices))
            return answer

        self.live_provider = self._resolve_live_provider()

        provider_answer = None
        if self.live_provider == "openai":
            provider_answer = self.query_openai(prompt, devices)
        elif self.live_provider == "ollama":
            provider_answer = self.query_ollama(prompt, devices)

        if provider_answer and not provider_answer.startswith("LLM request failed:") and not provider_answer.startswith("Ollama request failed:"):
            return provider_answer

        fallback = self.local_fallback_answer(prompt, devices)
        technical_prefixes = ("LLM request failed:", "Ollama request failed:")
        if provider_answer and provider_answer.startswith(technical_prefixes):
            if language == "ru":
                fallback = f"{fallback}\n\nТехническая заметка: {provider_answer}"
            elif language == "az":
                fallback = f"{fallback}\n\nTexniki qeyd: {provider_answer}"
            else:
                fallback = f"{fallback}\n\nTechnical note: {provider_answer}"

        self._remember_turn(prompt, fallback, self.infer_topic(prompt, devices))
        return fallback


if __name__ == "__main__":
    expert = AISecurityExpert()
    print(expert.answer_question("hello"))
