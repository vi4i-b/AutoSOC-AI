# AutoSOC AI

AutoSOC AI — это настольный помощник по кибербезопасности для небольших команд и локальных сетей.
Проект объединяет сетевое сканирование, анализ рискованных портов, управление Windows firewall,
AI-пояснения и Telegram-уведомления в одном приложении.

## Что делает проект

- Сканирует выбранную цель по отслеживаемым TCP-портам.
- Выявляет рискованные сервисы и порты.
- Показывает dashboard с количеством устройств, открытых портов, risk score и статусом Telegram.
- Позволяет открывать и закрывать порты прямо из приложения.
- Фиксирует security events и audit events.
- Отправляет результаты скана и уведомления об угрозах в Telegram.
- Привязывает Telegram Chat ID к конкретному пользователю.
- Использует AI-помощника для объяснения результатов и рекомендаций.

## Ключевые возможности

- Регистрация и вход с Telegram Chat ID
- Telegram-бот с командами `/start`, `/id`, `/help`
- Real-time обновление dashboard
- AI-объяснение по открытым портам и рискам
- Port Canary и журнал событий
- Exposure baseline drift между запусками
- Централизованная SQLite-схема
- Усиленное хранение паролей с обратной совместимостью
- Сборка `.exe` через PyInstaller

## Технологии

- Python 3.14
- CustomTkinter
- Requests
- python-nmap
- Scapy
- SQLite
- PyInstaller

## Структура проекта

- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py) - основной dashboard, логика сканирования, Telegram alert, AI-панель, firewall
- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) - окно входа и регистрации, Telegram listener на этапе login
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py) - вход, регистрация, remember me и Telegram-привязка
- [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py) - единая SQLite-схема, scan history, settings, audit и security events
- [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py) - сканирование портов через Nmap
- [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py) - анализ рискованных портов и risk score
- [`guard.py`](/C:/Users/user/PycharmProjects/AutoSOC/guard.py) - мониторинг трафика и автоматическая реакция
- [`log_listener.py`](/C:/Users/user/PycharmProjects/AutoSOC/log_listener.py) - обработка Windows Security log
- [`ai_expert.py`](/C:/Users/user/PycharmProjects/AutoSOC/ai_expert.py) - AI-объяснения и рекомендации
- [`runtime_support.py`](/C:/Users/user/PycharmProjects/AutoSOC/runtime_support.py) - общие runtime helper-ы для `.env`, иконок и Telegram client
- [`security_utils.py`](/C:/Users/user/PycharmProjects/AutoSOC/security_utils.py) - hash/verify логика для паролей
- [`validators.py`](/C:/Users/user/PycharmProjects/AutoSOC/validators.py) - валидация username, password, chat ID и scan target
- [`tests/`](/C:/Users/user/PycharmProjects/AutoSOC/tests) - базовые smoke и unit tests
- [`main.spec`](/C:/Users/user/PycharmProjects/AutoSOC/main.spec) - конфигурация PyInstaller

## Как запустить проект

1. Установите зависимости из [`requirements.txt`](/C:/Users/user/PycharmProjects/AutoSOC/requirements.txt).
2. Добавьте Telegram token в [`.env`](/C:/Users/user/PycharmProjects/AutoSOC/.env).
3. При желании включите локальный AI через Ollama:

```powershell
ollama pull llama3.1:8b
ollama serve
```

4. Используйте такие переменные окружения:

```env
AI_PROVIDER=auto
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
OLLAMA_URL=http://localhost:11434/api/chat
OLLAMA_MODEL=llama3.1:8b
```

5. Запустите приложение:

```powershell
python main.py
```

## Как работает AI

AutoSOC в режиме `AI_PROVIDER=auto`:

- использует OpenAI, если есть `OPENAI_API_KEY`
- иначе пытается использовать локальный `Ollama`
- если оба варианта недоступны, отвечает встроенным экспертным режимом

## Как работает Telegram

1. Запустите приложение.
2. Откройте бота из окна регистрации или напрямую в Telegram.
3. Отправьте боту `/start`.
4. Скопируйте `Telegram Chat ID` из ответа.
5. Вставьте его в форму регистрации.
6. Войдите в систему и запустите scan.
7. Результаты и alert будут отправляться в привязанный чат.

## Как запустить тесты

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Как собрать `.exe`

```powershell
.\.venv\Scripts\python.exe -m PyInstaller --clean main.spec
```

Результат появляется в [`dist/AutoSOC.exe`](/C:/Users/user/PycharmProjects/AutoSOC/dist/AutoSOC.exe).

## Важные замечания

- Приложение рассчитано на Windows, потому что использует `netsh advfirewall`.
- Для корректной работы сканирования и firewall нужен запуск с правами администратора.
- Для сетевого сканирования должен быть установлен `Nmap`.
- Для части sniffing/capture сценариев может потребоваться `Npcap`.
- Ответы Telegram-бота работают, пока запущено приложение, потому что polling идёт внутри него.

## Что запланировано дальше

- anti-phishing модуль
- усиление AI incident copilot
- расширение тестового покрытия
- стабилизация release/install pipeline

## Дополнительные документы

- [`docs/CODE_NAVIGATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/CODE_NAVIGATION.md)
- [`docs/ru/CODE_NAVIGATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/CODE_NAVIGATION.md)
- [`docs/ru/PROGRAMMER_TASKS.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/PROGRAMMER_TASKS.md)
- [`docs/ru/AI_DEVELOPER_TASKS.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/AI_DEVELOPER_TASKS.md)
