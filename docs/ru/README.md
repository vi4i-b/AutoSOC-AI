# AutoSOC AI

AutoSOC AI — это настольный помощник по кибербезопасности для небольших команд и локальных сетей.
Проект объединяет сканирование сети, анализ рискованных портов, управление firewall, AI-пояснения и Telegram-уведомления в одном приложении.

## Что делает проект

- Сканирует выбранную цель по отслеживаемым портам.
- Выявляет рискованные сервисы и порты.
- Показывает панель с количеством устройств, открытых портов, уровнем риска и статусом Telegram.
- Позволяет открывать и закрывать порты прямо из приложения.
- Отправляет результаты скана и уведомления об угрозах в Telegram.
- Привязывает Telegram Chat ID к конкретному пользователю.
- Использует AI-помощника для объяснения результатов и рекомендаций.

## Основные функции

- Система входа и регистрации с Telegram Chat ID
- Telegram-бот с командами `/start`, `/id`, `/help`
- Real-time обновление dashboard
- Прокручиваемая форма регистрации
- Ограничение `1 Telegram Chat ID = 1 аккаунт`
- Управление Windows firewall
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

- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py) - основной dashboard, процесс сканирования, Telegram alert, AI-панель, firewall
- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) - окно входа и регистрации, Telegram listener на этапе login
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py) - аккаунты пользователей, уникальность Telegram ID, логика регистрации
- [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py) - сканирование портов через Nmap
- [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py) - анализ рискованных портов
- [`guard.py`](/C:/Users/user/PycharmProjects/AutoSOC/guard.py) - мониторинг и автоматическая блокировка
- [`ai_expert.py`](/C:/Users/user/PycharmProjects/AutoSOC/ai_expert.py) - AI-объяснения и рекомендации
- [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py) - история сканов, Telegram-данные, настройки
- [`main.spec`](/C:/Users/user/PycharmProjects/AutoSOC/main.spec) - конфигурация PyInstaller

## Как запустить проект

1. Установите зависимости из [`requirements.txt`](/C:/Users/user/PycharmProjects/AutoSOC/requirements.txt).
2. Добавьте Telegram token в [`.env`](/C:/Users/user/PycharmProjects/AutoSOC/.env).
3. Запустите приложение командой:

```powershell
python main.py
```

## Как работает Telegram

1. Запустите приложение.
2. Откройте бота из окна регистрации или напрямую в Telegram.
3. Отправьте боту `/start`.
4. Скопируйте `Telegram Chat ID` из ответа.
5. Вставьте его в форму регистрации.
6. Войдите в систему и запустите скан.
7. Результаты и alert будут отправляться в привязанный чат.

## Как собрать `.exe`

```powershell
.\.venv\Scripts\python.exe -m PyInstaller --clean main.spec
```

Результат появляется в [`dist/main.exe`](/C:/Users/user/PycharmProjects/AutoSOC/dist/main.exe).

## Важные замечания

- Приложение рассчитано на Windows, потому что использует `netsh advfirewall`.
- Для корректной работы сканирования и firewall нужен запуск с правами администратора.
- Ответы Telegram-бота работают, пока запущено приложение, потому что polling идёт внутри него.
