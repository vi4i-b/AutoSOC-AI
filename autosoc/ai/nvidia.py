import json
import os
import re

import requests

from autosoc.env import load_env_file


class NvidiaSecurityAI:
    DEFAULT_SYSTEM_PROMPT = "Ты — аналитик безопасности AutoSOC. Проанализируй порты и дай краткий совет на русском."

    PHISHING_SYSTEM_PROMPT = (
        "You are a phishing-analysis engine for the AutoSOC security platform. "
        "You receive a URL, page title, a text excerpt from the page, and deterministic "
        "heuristic signals already computed by AutoSOC. Judge how likely the page is a "
        "phishing or credential-harvesting attempt. Pay attention to spelling and grammar "
        "mistakes in the page text (a strong phishing indicator), brand impersonation, "
        "urgency/scare language, and mismatches between the claimed brand and the domain. "
        "Reply ONLY with a compact JSON object: "
        '{\"score\": <0-100 integer>, \"verdict\": \"safe|suspicious|dangerous\", '
        '\"summary\": \"<2-4 sentence explanation>\", '
        '\"spelling_issues\": [\"<word or phrase>\"]}. No text outside the JSON.'
    )

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
        self._refresh_fallback_models()

    def _refresh_fallback_models(self):
        self.fallback_models = [
            self.model,
            "deepseek-ai/deepseek-v3",
            "meta/llama-3.1-8b-instruct",
        ]

    @property
    def enabled(self):
        return bool(self.api_key)

    def configure(self, api_key=None, model=None):
        """Apply a key/model supplied at runtime (e.g. from the UI)."""
        if api_key is not None:
            self.api_key = api_key.strip()
        if model is not None and model.strip():
            self.model = model.strip()
        self._refresh_fallback_models()

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

    def analyze_phishing(self, url, page_title="", page_text="", heuristic_signals=None, heuristic_score=0):
        """Ask the model to judge a page. Returns a dict or None on failure.

        Result: ``{"score": int, "verdict": str, "summary": str, "spelling_issues": [...]}``
        """
        if not self.enabled:
            return None

        signal_lines = "\n".join(
            f"- [{category}] {title}: {detail}"
            for category, title, detail in (heuristic_signals or [])
        ) or "- (no deterministic signals fired)"

        user_prompt = (
            f"URL: {url}\n"
            f"Page title: {page_title or '(none)'}\n"
            f"AutoSOC heuristic score (0-100): {heuristic_score}\n"
            f"AutoSOC heuristic signals:\n{signal_lines}\n\n"
            f"Page text excerpt:\n\"\"\"\n{page_text or '(page text unavailable)'}\n\"\"\"\n\n"
            "Return the JSON verdict now."
        )

        raw = self._chat(
            [{"role": "user", "content": user_prompt}],
            system_prompt=self.PHISHING_SYSTEM_PROMPT,
            temperature=0.1,
            max_tokens=600,
        )
        if not raw:
            return None
        return self._parse_json_verdict(raw)

    @staticmethod
    def _parse_json_verdict(raw):
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return {"summary": raw.strip()[:600]}
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {"summary": raw.strip()[:600]}
        if not isinstance(data, dict):
            return {"summary": raw.strip()[:600]}
        return data

    def _chat(self, messages, system_prompt=None, temperature=0.2, max_tokens=500):
        self.last_error = ""
        candidate_models = []
        for model_name in self.fallback_models:
            if model_name and model_name not in candidate_models:
                candidate_models.append(model_name)

        system = system_prompt or self.DEFAULT_SYSTEM_PROMPT
        for model_name in candidate_models:
            payload = {
                "model": model_name,
                "messages": [{"role": "system", "content": system}, *messages],
                "temperature": temperature,
                "max_tokens": max_tokens,
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
