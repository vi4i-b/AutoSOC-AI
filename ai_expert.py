import os
import requests


class AISecurityExpert:
    SYSTEM_PROMPT = (
        "You are AutoSOC AI, a SOC analyst and cybersecurity expert. "
        "You answer in the user's language when possible, especially Russian, Azerbaijani, or English. "
        "Focus on defensive cybersecurity topics: SOC operations, phishing, brute-force, malware, "
        "incident response, hardening, monitoring, SIEM, firewalling, exposed ports, authentication, "
        "network defense, ransomware, detection, and remediation. "
        "If the user starts with a greeting or a general message, respond naturally and guide them into a security-focused conversation. "
        "If the topic is unrelated to cybersecurity, refuse briefly and redirect back to cybersecurity. "
        "When scan context is provided, use it in the answer."
    )

    def __init__(self):
        self.provider = os.getenv("AI_PROVIDER", "openai").strip().lower()
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat").strip()
        self.ollama_model = os.getenv("OLLAMA_MODEL", "llama3.1:8b").strip()
        self.conversation_history = []
        self.history_limit = 12
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
            "təhlük", "tehluk", "fişinq", "hücum", "tehlukesizlik", "şəbək", "port", "müdafiə",
            "zərərli", "fişing", "sızma",
        ]

    def reset_history(self):
        self.conversation_history = []

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
                "greeting": "Привет. Я AutoSOC AI, помощник по кибербезопасности. Могу помочь с фишингом, brute-force, открытыми портами, hardening и разбором скана.",
                "redirect": "Я отвечаю по темам кибербезопасности. Спроси про фишинг, brute-force, malware, hardening, порты или защиту сети.",
                "no_scan": "Пока нет контекста сканирования. Сначала запусти скан, и я помогу разобрать результат.",
                "fallback": "Сейчас живой LLM недоступен, поэтому я отвечаю в локальном режиме.",
                "hello_help": "Можешь спросить, например: «Как защититься от фишинга?» или «Насколько опасен порт 3389?»",
            },
            "az": {
                "greeting": "Salam. Mən AutoSOC AI təhlükəsizlik köməkçisiyəm. Fişinq, brute-force, açıq portlar, hardening və scan nəticələri ilə kömək edə bilərəm.",
                "redirect": "Mən əsasən kibertəhlükəsizlik mövzularına cavab verirəm. Fişinq, brute-force, malware, hardening, portlar və şəbəkə müdafiəsi barədə soruşun.",
                "no_scan": "Hələ scan konteksti yoxdur. Əvvəl scan başladın, sonra nəticəni birlikdə izah edərəm.",
                "fallback": "Hazırda canlı LLM əlçatan deyil, buna görə lokal rejimdə cavab verirəm.",
                "hello_help": "Məsələn soruşa bilərsiniz: «Fişinqdən necə qorunum?» və ya «3389 portu təhlükəlidirmi?»",
            },
            "en": {
                "greeting": "Hello. I am AutoSOC AI, your cybersecurity assistant. I can help with phishing, brute-force, open ports, hardening, and scan analysis.",
                "redirect": "I answer cybersecurity topics. Ask about phishing, brute-force, malware, hardening, ports, or network defense.",
                "no_scan": "There is no scan context yet. Run a scan first and I will help interpret it.",
                "fallback": "Live LLM is unavailable right now, so I am answering in local mode.",
                "hello_help": "You can ask, for example: 'How do I protect against phishing?' or 'Is port 3389 dangerous?'",
            },
        }
        return phrases.get(language, phrases["en"])[key]

    def is_greeting(self, text):
        lowered = (text or "").strip().lower()
        greetings = [
            "hello", "hi", "hey", "yo", "good morning", "good evening",
            "привет", "здравствуйте", "здравствуй", "добрый день",
            "salam", "sabahiniz xeyir", "axşamınız xeyir", "necəsən", "necesen",
        ]
        return any(lowered == item or lowered.startswith(f"{item} ") for item in greetings)

    def is_security_question(self, text):
        lowered = (text or "").lower()
        return any(keyword in lowered for keyword in self.security_keywords)

    def summarize_scan(self, devices, language="en"):
        if not devices:
            return self.localized(language, "no_scan")

        lines = []
        for device in devices:
            vendor = list(device.get("vendor", {}).values())[0] if device.get("vendor") else "Unknown device"
            open_ports = device.get("ports", [])
            if open_ports:
                port_list = ", ".join(
                    f"{item['port']} ({self.port_catalog.get(item['port'], item.get('name', 'service'))})"
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
                    lines.append(f"{device['ip']} / {vendor}: по выбранным 22 портам открытых сервисов не найдено.")
                elif language == "az":
                    lines.append(f"{device['ip']} / {vendor}: seçilmiş 22 port üzrə açıq servis tapılmadı.")
                else:
                    lines.append(f"{device['ip']} / {vendor}: no open services detected across the selected 22 ports.")
        return "\n".join(lines)

    def generate_instruction(self, device_type, port, service, language="en"):
        vendor = (device_type or "").lower()
        if port == 445:
            if language == "ru":
                return "Открыт SMB. Отключи SMBv1, ограничь доступ через firewall и проверь обновления."
            if language == "az":
                return "SMB açıqdır. SMBv1-i söndür, firewall ilə məhdudlaşdır və yeniləmələri yoxla."
            return "SMB is exposed. Disable SMBv1, restrict access by firewall, and verify patching."
        if port == 3389:
            if language == "ru":
                return "Открыт RDP. Включи NLA, задай сильные пароли и ограничь доступ по IP."
            if language == "az":
                return "RDP açıqdır. NLA aktiv et, güclü parol istifadə et və giriş IP-lərini məhdudlaşdır."
            return "RDP is exposed. Enable NLA, require strong passwords, and restrict source IPs."
        if port == 22:
            if language == "ru":
                return "Открыт SSH. Лучше использовать ключи, отключить вход по паролю и ограничить trusted IP."
            if language == "az":
                return "SSH açıqdır. Açar əsaslı girişdən istifadə et, parol ilə girişi söndür və trusted IP-ləri məhdudlaşdır."
            return "SSH is open. Prefer key-based auth, disable password login, and limit trusted source IPs."

        if language == "ru":
            return f"Сервис {service} на порту {port} расширяет поверхность атаки. Если он не нужен, закрой его через firewall и проверь настройки доступа."
        if language == "az":
            return f"{service} xidməti Port {port} üzərində hücum səthini artırır. Lazım deyilsə, firewall ilə bağla və giriş nəzarətini yoxla."
        return f"{service} on port {port} increases attack surface. If you do not need it, close it in the firewall and verify access control."

    def build_input(self, question, devices=None):
        language = self.detect_language(question)
        context = self.summarize_scan(devices or [], language)
        input_items = [
            {"role": "system", "content": [{"type": "text", "text": self.SYSTEM_PROMPT}]},
            {"role": "system", "content": [{"type": "text", "text": f"Latest scan context:\n{context}"}]},
        ]

        for item in self.conversation_history[-self.history_limit:]:
            input_items.append(
                {"role": item["role"], "content": [{"type": "text", "text": item["content"]}]}
            )

        input_items.append({"role": "user", "content": [{"type": "text", "text": question}]})
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
                self._remember_turn(question, text)
                return text
            return "The model returned an empty response."
        except Exception as exc:
            return f"LLM request failed: {exc}"

    def query_ollama(self, question, devices=None):
        payload = {
            "model": self.ollama_model,
            "messages": [{"role": "system", "content": self.SYSTEM_PROMPT}],
            "stream": False,
        }

        language = self.detect_language(question)
        payload["messages"].append(
            {"role": "system", "content": f"Latest scan context:\n{self.summarize_scan(devices or [], language)}"}
        )
        payload["messages"].extend(self.conversation_history[-self.history_limit:])
        payload["messages"].append({"role": "user", "content": question})

        try:
            response = requests.post(self.ollama_url, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            text = data.get("message", {}).get("content", "").strip()
            if text:
                self._remember_turn(question, text)
                return text
            return "Local model returned an empty response."
        except Exception as exc:
            return f"Ollama request failed: {exc}"

    def _remember_turn(self, question, answer):
        self.conversation_history.append({"role": "user", "content": question})
        self.conversation_history.append({"role": "assistant", "content": answer})
        self.conversation_history = self.conversation_history[-self.history_limit:]

    def local_fallback_answer(self, question, devices=None):
        language = self.detect_language(question)
        lowered = (question or "").lower()

        if self.is_greeting(question):
            return f"{self.localized(language, 'greeting')} {self.localized(language, 'hello_help')}"

        if any(word in lowered for word in ["who are you", "что ты умеешь", "sən nə edirsən", "what can you do", "что умеешь", "nə edə bilirsən"]):
            if language == "ru":
                return "Я могу объяснять риски открытых портов, помогать с hardening, разбирать scan results, и подсказывать меры защиты от phishing, brute-force и malware."
            if language == "az":
                return "Mən açıq port risklərini izah edə, hardening addımları təklif edə, scan nəticələrini şərh edə və fişinq, brute-force, malware mövzularında kömək edə bilərəm."
            return "I can explain open port risks, suggest hardening steps, interpret scan results, and help with phishing, brute-force, and malware defense."

        if any(word in lowered for word in ["phishing", "phish", "fişinq", "фиш"]):
            if language == "ru":
                return "Для защиты от фишинга включи MFA, проверяй домен отправителя, не открывай неожиданные вложения, используй почтовую фильтрацию и обучай сотрудников сообщать о подозрительных письмах."
            if language == "az":
                return "Fişinqdən qorunmaq üçün MFA aktiv et, göndərənin domenini yoxla, şübhəli link və əlavələri açma, email filtrasiya tətbiq et və işçiləri maarifləndir."
            return "To reduce phishing risk, enable MFA, verify sender domains, avoid unexpected links or attachments, deploy email filtering, and train users to report suspicious messages."

        if any(word in lowered for word in ["brute", "брут", "парол", "password attack"]):
            if language == "ru":
                return "От brute-force помогают MFA, rate limiting, блокировка после нескольких неудачных попыток, сильные пароли, ограничение по IP и мониторинг входов."
            if language == "az":
                return "Brute-force hücumuna qarşı MFA, rate limiting, uğursuz cəhdlərdən sonra bloklama, güclü parollar, IP məhdudiyyəti və login monitorinqi kömək edir."
            return "Protect against brute-force with MFA, rate limiting, temporary lockout after failed attempts, strong password policy, IP restrictions, and login monitoring."

        if any(word in lowered for word in ["malware", "virus", "вирус", "zərərli", "ransomware"]):
            if language == "ru":
                return "Против malware и ransomware: быстрые патчи, EDR/AV, минимальные привилегии, сегментация сети, резервные копии offline и мониторинг lateral movement."
            if language == "az":
                return "Malware və ransomware üçün: sürətli patching, EDR/AV, minimal hüquqlar, şəbəkə seqmentasiyası, offline backup və lateral movement monitorinqi vacibdir."
            return "For malware and ransomware defense, patch quickly, deploy EDR/AV, minimize privileges, segment the network, keep offline backups, and monitor lateral movement."

        if any(word in lowered for word in ["scan", "result", "nəticə", "результ", "open port", "açıq port"]):
            return self.summarize_scan(devices or [], language)

        if any(word in lowered for word in ["risk", "threat", "danger", "угроз", "təhlük", "tehluk"]):
            findings = []
            for device in devices or []:
                vendor = list(device.get("vendor", {}).values())[0] if device.get("vendor") else "Device"
                for port in device.get("ports", []):
                    findings.append(
                        f"{device['ip']} port {port['port']}: {self.generate_instruction(vendor, int(port['port']), port.get('name', 'service'), language)}"
                    )
            if findings:
                return "\n".join(findings[:6])

        for port, service in self.port_catalog.items():
            if str(port) in lowered:
                return self.generate_instruction("unknown", port, service, language)

        if self.is_security_question(question):
            if language == "ru":
                return "Я понял, что вопрос про безопасность, но сейчас работаю в локальном режиме. Уточни тему: фишинг, открытый порт, hardening, malware, brute-force или разбор скана."
            if language == "az":
                return "Sualın təhlükəsizliklə bağlı olduğunu başa düşdüm, amma indi lokal rejimdəyəm. Mövzunu bir az dəqiqləşdirin: fişinq, açıq port, hardening, malware, brute-force və ya scan nəticəsi."
            return "I understand this is a security question, but I am in local mode right now. Narrow it down a bit: phishing, open ports, hardening, malware, brute-force, or scan analysis."

        return f"{self.localized(language, 'fallback')} {self.localized(language, 'redirect')}"

    def answer_question(self, question, devices=None):
        prompt = (question or "").strip()
        if not prompt:
            language = "en"
            return self.localized(language, "hello_help")

        language = self.detect_language(prompt)
        if self.is_greeting(prompt):
            return f"{self.localized(language, 'greeting')} {self.localized(language, 'hello_help')}"

        provider_answer = None
        if self.provider == "ollama":
            provider_answer = self.query_ollama(prompt, devices)
        else:
            provider_answer = self.query_openai(prompt, devices)

        if provider_answer and not provider_answer.startswith("LLM request failed:") and not provider_answer.startswith("Ollama request failed:"):
            return provider_answer

        fallback = self.local_fallback_answer(prompt, devices)
        if provider_answer and (provider_answer.startswith("LLM request failed:") or provider_answer.startswith("Ollama request failed:")):
            if language == "ru":
                return f"{fallback}\n\nТехническая заметка: {provider_answer}"
            if language == "az":
                return f"{fallback}\n\nTexniki qeyd: {provider_answer}"
            return f"{fallback}\n\nTechnical note: {provider_answer}"
        return fallback


if __name__ == "__main__":
    expert = AISecurityExpert()
    print(expert.answer_question("hello"))
