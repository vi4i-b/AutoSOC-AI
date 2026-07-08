"""AutoSOC AI — desktop cybersecurity assistant.

Package layout:
    autosoc.ui        — CustomTkinter windows (login, dashboard, chat)
    autosoc.system    — OS integration (firewall, privileges, log monitoring)
    autosoc.telegram  — Telegram Bot API client and update listener
    autosoc.ai        — AI providers (NVIDIA endpoint, OpenAI/Ollama expert)
    autosoc.*         — core domain logic (scanner, analyzer, database, auth)
"""

__version__ = "3.0"
APP_NAME = "AutoSOC"
