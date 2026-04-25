import os

import requests

from runtime_support import load_env_file


class NvidiaSecurityAI:
    DEFAULT_SYSTEM_PROMPT = "Ты — аналитик безопасности AutoSOC. Проанализируй порты и дай краткий совет на русском."

    def __init__(self):
        load_env_file()
        self.api_key = os.getenv("NVIDIA_API_KEY", "").strip()
        self.model = os.getenv("NVIDIA_MODEL", "deepseek-ai/deepseek-v3").strip() or "deepseek-ai/deepseek-v3"
        self.base_url = os.getenv(
            "NVIDIA_API_BASE_URL",
            "https://integrate.api.nvidia.com/v1/chat/completions",
        ).strip()
        self.timeout = int(os.getenv("NVIDIA_API_TIMEOUT", "18"))
        self.last_error = ""
        self.fallback_models = [
            self.model,
            "deepseek-ai/deepseek-v3",
            "meta/llama-3.1-8b-instruct",
        ]

    @property
    def enabled(self):
        return bool(self.api_key)

    def analyze_ports(self, target, devices):
        if not self.enabled:
            return None

        user_prompt = (
            f"Цель сканирования: {target or 'unknown'}.\n"
            f"Результаты сканирования портов:\n{self._scan_context(devices)}\n\n"
            "Сделай краткий вывод на русском языке в 2-5 предложениях. "
            "Укажи самые рискованные открытые порты и что сделать в первую очередь."
        )
        return self._chat([{"role": "user", "content": user_prompt}])

    def answer_security_question(self, question, devices=None, history=None):
        if not self.enabled:
            return None

        messages = []
        for item in history or []:
            role = item.get("role")
            content = (item.get("content") or "").strip()
            if role in {"user", "assistant"} and content:
                messages.append({"role": role, "content": content})

        if devices:
            messages.append(
                {
                    "role": "system",
                    "content": "Контекст последнего сканирования AutoSOC:\n" + self._scan_context(devices),
                }
            )

        messages.append({"role": "user", "content": question})
        return self._chat(messages)

    def _chat(self, messages):
        self.last_error = ""
        candidate_models = []
        for model_name in self.fallback_models:
            if model_name and model_name not in candidate_models:
                candidate_models.append(model_name)

        for model_name in candidate_models:
            payload = {
                "model": model_name,
                "messages": [{"role": "system", "content": self.DEFAULT_SYSTEM_PROMPT}, *messages],
                "temperature": 0.2,
                "max_tokens": 500,
                "stream": False,
            }

            try:
                response = requests.post(
                    self.base_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=(8, self.timeout),
                )
                response.raise_for_status()
                data = response.json()
                choices = data.get("choices") or []
                message = choices[0].get("message", {}) if choices else {}
                content = self._extract_content(message.get("content"))
                if content:
                    self.last_error = ""
                    return content
                self.last_error = f"NVIDIA returned an empty response for model {model_name}."
            except Exception as exc:
                self.last_error = f"NVIDIA request failed for model {model_name}: {exc}"

        return None

    @staticmethod
    def _extract_content(content):
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append((item.get("text") or "").strip())
            return "\n".join(part for part in parts if part).strip()
        return None

    def _scan_context(self, devices):
        if not devices:
            return "Открытые порты не найдены."

        lines = []
        for device in devices:
            ip = device.get("ip", "unknown")
            vendor_map = device.get("vendor") or {}
            vendor = next(iter(vendor_map.values()), "Unknown device")
            open_ports = device.get("ports", [])
            if open_ports:
                port_list = ", ".join(self._format_port(port_info) for port_info in open_ports)
            else:
                port_list = "открытых отслеживаемых портов нет"
            lines.append(f"- {ip} ({vendor}): {port_list}")
        return "\n".join(lines)

    @staticmethod
    def _format_port(port_info):
        port = port_info.get("port", "unknown")
        name = port_info.get("name") or "service"
        product = port_info.get("product") or ""
        version = port_info.get("version") or ""
        details = " ".join(item for item in [name, product, version] if item).strip()
        return f"{port} ({details})" if details else str(port)
