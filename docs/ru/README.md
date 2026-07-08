# AutoSOC AI

AutoSOC AI — это настольный помощник по кибербезопасности для небольших команд
и локальных сетей. Проект объединяет сетевое сканирование, анализ рискованных
портов, управление системным firewall, AI-пояснения и Telegram-уведомления в
одном приложении.

Работает на **Windows** и **Linux (Ubuntu)**.

## Что делает проект

- Сканирует выбранную цель по отслеживаемым TCP-портам (nmap).
- Выявляет рискованные сервисы и считает risk score.
- Показывает live-dashboard: устройства, открытые порты, risk score, инциденты, статус Telegram.
- Открывает и блокирует порты через системный firewall (netsh на Windows, iptables на Linux).
- Обнаруживает brute-force входов (Windows Security log / Linux auth.log).
- Запускает Port Canary (порты-приманки) и ведёт журнал угроз.
- Отправляет результаты скана и алерты в Telegram.
- Объясняет находки через AI-копилота (NVIDIA API, OpenAI или локальная Ollama — с офлайн-фолбэком).

## Структура проекта

```
main.py                  # точка входа
autosoc/
├── analyzer.py          # каталог рисков и подсчёт score
├── auth.py              # вход, регистрация, lockout, remember-me
├── canary.py            # порты-приманки
├── database.py          # SQLite (пользователи, сканы, события, настройки)
├── env.py               # загрузка .env
├── guard.py             # монитор всплесков трафика (DDoS)
├── logging_setup.py     # логирование в консоль и файл
├── paths.py             # каталог данных пользователя, ресурсы
├── ports.py             # отслеживаемые порты (единый источник)
├── scanner.py           # обёртка над nmap
├── security_utils.py    # PBKDF2-хэширование паролей
├── validators.py        # валидация ввода
├── ai/                  # AI-провайдеры (nvidia.py, expert.py)
├── system/              # интеграция с ОС
│   ├── commands.py      #   безопасный запуск команд (без shell)
│   ├── firewall.py      #   backend'ы netsh / iptables
│   ├── hardening.py     #   сервисный hardening по ОС
│   ├── log_monitor.py   #   мониторинг неудачных входов по ОС
│   ├── netinfo.py       #   локальные IP, определение удалённой цели
│   ├── os_auth.py       #   вход по учётке Windows (LogonUserW)
│   └── privileges.py    #   проверка admin/root
├── telegram/            # клиент бота + long-polling слушатель
└── ui/                  # окна CustomTkinter (login, dashboard, chat)
tests/                   # unit-тесты
```

## Установка

### Ubuntu / Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-tk nmap libpcap0.8

git clone https://github.com/vi4i-b/AutoSOC-AI.git
cd AutoSOC-AI
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env        # затем заполните токены
```

Запуск:

```bash
# Обычный режим (сканирование, dashboard, Telegram, AI):
.venv/bin/python main.py

# С управлением firewall, мониторингом brute-force и Guard (нужен root):
sudo -E .venv/bin/python main.py
```

Особенности Linux:
- Firewall управляется через **iptables**; правила помечаются `AutoSOC_*`.
- Детектор brute-force читает `/var/log/auth.log` (root или группа `adm`).
- Вход по учётной записи ОС доступен только на Windows; на Linux
  зарегистрируйте локальный аккаунт AutoSOC в окне входа.

### Windows

1. Установите Python 3.12+, [Nmap](https://nmap.org/download.html) и
   (опционально, для Guard) [Npcap](https://npcap.com/).
2. `pip install -r requirements.txt`
3. Скопируйте `.env.example` в `.env` и заполните токены.
4. Для управления firewall запускайте от имени администратора:

```powershell
python main.py
```

## Конфигурация (.env)

Полный аннотированный список — в `.env.example`. Ключевые значения:

| Переменная | Назначение |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Токен бота от @BotFather (включает алерты) |
| `NVIDIA_API_KEY` | Модели NVIDIA для копилота |
| `AI_PROVIDER` / `OPENAI_API_KEY` / `OLLAMA_URL` | Выбор AI-провайдера эксперта |
| `AUTOSOC_DATA_DIR` | Переопределение каталога данных |
| `AUTOSOC_LOG_LEVEL` | DEBUG / INFO / WARNING / ERROR |

Данные приложения (БД, логи, память AI) хранятся отдельно для каждого
пользователя: `%APPDATA%\AutoSOC` на Windows, `~/.local/share/autosoc` на Linux.

## Как работает привязка Telegram

1. Запустите приложение и откройте бота (кнопка в окне входа).
2. Отправьте боту `/start` и скопируйте `Telegram Chat ID` из ответа.
3. Вставьте его в форму регистрации (приложение также подхватывает его автоматически).
4. После входа результаты сканов и алерты будут приходить в этот чат.

## Как работает AI

При `AI_PROVIDER=auto` эксперт использует по мере доступности: OpenAI (если
задан `OPENAI_API_KEY`) → локальную Ollama → встроенный офлайн-режим.
Копилот на дашборде дополнительно использует NVIDIA API, если задан
`NVIDIA_API_KEY`. Самый удобный бесплатный локальный вариант —
`Ollama + llama3.1:8b`.

## Тесты

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Сборка бинарника

```bash
pip install -r requirements-dev.txt
python -m PyInstaller --clean main.spec
```

Результат — в `dist/AutoSOC` (`dist/AutoSOC.exe` на Windows).

## Безопасность

Модель безопасности описана в `SECURITY.md`: работа с секретами, хранение
паролей, блокировка аккаунтов, привилегии и то, какие данные покидают машину.
**Сканируйте только те хосты и сети, которыми владеете или на тестирование
которых у вас есть разрешение.**
