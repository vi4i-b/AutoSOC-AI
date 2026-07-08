# Навигация по коду AutoSOC AI

Документ помогает быстро понять, какой файл за что отвечает.
Код разбит на слои внутри пакета `autosoc/`.

## Общая картина

```
main.py                  # точка входа: login → dashboard
autosoc/
├── ui/                  # окна (CustomTkinter)
├── system/              # работа с ОС (firewall, логи, привилегии)
├── telegram/            # клиент Telegram-бота и слушатель
├── ai/                  # AI-провайдеры
└── *.py                 # модули основной бизнес-логики
```

## По слоям

### Точка входа

- `main.py` — настраивает логирование и `.env`, открывает окно входа,
  после успешного логина запускает dashboard.

### UI — `autosoc/ui/`

- `login.py` — splash, окно входа и регистрации.
- `dashboard.py` — логика главного окна: скан, управление портами, алерты, AI-панель.
- `dashboard_layout.py` — построение виджетов dashboard (только внешний вид).
- `chat_window.py` — отдельное окно AI-чата (сейчас не используется).
- `theme.py` — общая палитра цветов и иконка окна.

### Системный слой — `autosoc/system/`

- `firewall.py` — backend'ы `netsh` (Windows) и `iptables` (Linux).
  Все правила помечаются префиксом `AutoSOC_`.
- `log_monitor.py` — детектор brute-force: Windows Security log (4625) и
  Linux `/var/log/auth.log`.
- `hardening.py` — остановка сервисов при блокировке порта (SMB, NetBIOS и т.д.).
- `privileges.py` — проверка admin/root.
- `netinfo.py` — локальные IP, определение «цель удалённая или локальная».
- `os_auth.py` — вход по учётке Windows (`LogonUserW`); на Linux отключён.
- `commands.py` — безопасный запуск команд без shell.

### Основные модули — `autosoc/`

- `scanner.py` — скан портов через nmap.
- `analyzer.py` — каталог рискованных портов и risk score.
- `ports.py` — единый список отслеживаемых портов.
- `database.py` — SQLite: пользователи, сканы, settings, audit/security events,
  lockout при переборе пароля.
- `auth.py` — вход, регистрация, политика lockout, remember-me.
- `security_utils.py` — PBKDF2-хэширование паролей.
- `validators.py` — проверка username, пароля, chat ID и цели сканирования.
- `guard.py` — мониторинг всплесков трафика (DDoS).
- `canary.py` — порты-приманки.
- `paths.py` — каталог данных пользователя (`%APPDATA%\AutoSOC` / `~/.local/share/autosoc`).
- `env.py`, `logging_setup.py` — конфигурация и логирование.

### Telegram — `autosoc/telegram/`

- `client.py` — клиент Bot API (токен вырезается из сообщений об ошибках).
- `listener.py` — long-polling слушатель (общий для login и dashboard).

### AI — `autosoc/ai/`

- `nvidia.py` — анализ через NVIDIA API.
- `expert.py` — OpenAI/Ollama + встроенный офлайн-режим эксперта.

## Тесты

Unit-тесты лежат в `tests/`:

```bash
.venv/bin/python -m unittest discover -s tests -v
```
