# Навигация по коду AutoSOC AI

Этот документ нужен команде, которая не пишет код каждый день.
Его цель — быстро объяснить, какой файл за что отвечает после последних изменений в проекте.

## Общая логика проекта

Сейчас проект удобнее делить на 6 частей:

1. Вход и регистрация
2. Основной dashboard и UI
3. Сканирование и анализ рисков
4. Мониторинг, firewall и реакция на угрозы
5. Хранение данных и аудит
6. AI, helper и validation слой

Если запомнить совсем коротко:

- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) - вход в приложение
- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py) - основное окно и рабочая логика
- [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py) - сетевое сканирование
- [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py) - определение рисков
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py) - пользователи и Telegram-привязка
- [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py) - история, настройки, audit и security events

## Объяснение по файлам

## 1. `main.py`

Это центральный файл проекта.

Здесь находятся:

- основной dashboard
- карточки с метриками
- управление портами
- консоль сканирования
- Telegram status
- canary и incident reaction
- firewall-операции

Если проблема связана с:

- цифрами на панели
- показом результатов scan
- Telegram alert
- firewall-поведением
- canary / guard реакцией
- AI-панелью

то сначала смотреть нужно [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py).

## 2. `login.py`

Этот файл отвечает за вход и регистрацию.

Что в нём есть:

- splash screen
- форма входа и регистрации
- ввод Telegram Chat ID
- listener бота на этапе login
- автоподстановка Chat ID после `/start`

Если проблема в:

- login окне
- форме регистрации
- scroll в форме
- ответе бота во время регистрации
- первичной валидации пользователя

то смотреть нужно [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py).

## 3. `auth.py`

Этот файл управляет пользовательскими сценариями.

Он делает:

- проверку логина
- регистрацию нового аккаунта
- remember me
- запрет повторного использования одного Telegram Chat ID
- координацию между локальной и Windows-аутентификацией

Если проблема в:

- создании аккаунта
- входе
- уникальности Telegram Chat ID
- remember me
- привязке аккаунта к Telegram

нужно открыть [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py).

## 4. `database.py`

Это единый слой SQLite.

Он хранит:

- историю сканов
- Telegram-данные
- настройки приложения
- security events
- audit events
- exposure baseline

Если проблема связана с сохранением, миграцией или журналами, смотреть нужно [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py).

## 5. `scanner.py`

Этот файл запускает scan через Nmap.

Он:

- проверяет выбранные порты
- возвращает открытые порты
- формирует сводку checked/open/closed/filtered

Если проблема в scan flow, смотреть нужно [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py).

## 6. `analyzer.py`

Этот файл содержит базу рисков.

Он отвечает за:

- какие порты считаются опасными
- какое описание риска показывать
- какой severity учитывать

Если нужно менять risk logic, редактируется [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py).

## 7. `guard.py`

Этот файл отвечает за мониторинг трафика и автоматическую реакцию.

Если проблема в:

- threat monitoring
- threshold
- auto block
- suspicious traffic

смотрите [`guard.py`](/C:/Users/user/PycharmProjects/AutoSOC/guard.py).

## 8. `log_listener.py`

Этот файл отвечает за Windows Security log.

Он:

- отслеживает failed logon events
- ищет brute-force паттерны
- передаёт detection в основной UI

Если проблема в Windows log detection, смотреть нужно [`log_listener.py`](/C:/Users/user/PycharmProjects/AutoSOC/log_listener.py).

## 9. `ai_expert.py`

Этот файл отвечает за AI-пояснения.

Здесь можно менять:

- summary скана
- ответы ассистента
- prompt behavior
- fallback expert mode
- language detection

Файл:
[`ai_expert.py`](/C:/Users/user/PycharmProjects/AutoSOC/ai_expert.py)

## 10. Helper-файлы

### `runtime_support.py`

Здесь собраны общие runtime helper-ы:

- загрузка `.env`
- работа с иконками
- общий Telegram client

Файл:
[`runtime_support.py`](/C:/Users/user/PycharmProjects/AutoSOC/runtime_support.py)

### `security_utils.py`

Здесь лежит логика безопасности паролей:

- hash
- verify
- совместимость со старым форматом
- проверка необходимости rehash

Файл:
[`security_utils.py`](/C:/Users/user/PycharmProjects/AutoSOC/security_utils.py)

### `validators.py`

Здесь находится валидация:

- username
- password
- Telegram Chat ID
- safe scan target

Файл:
[`validators.py`](/C:/Users/user/PycharmProjects/AutoSOC/validators.py)

### `ai_chat_window.py`

Здесь находится AI chat. Кнопка расположена в правом нижнем углу:

- AI-помощник

Файл:
[`ai_chat_window.py`](https://github.com/vi4i-b/AutoSOC-AI/blob/main/ai_chat_window.py)

## 11. Тесты

В папке [`tests/`](/C:/Users/user/PycharmProjects/AutoSOC/tests) находятся базовые smoke и unit tests.

Сейчас особенно важны:

- [`tests/test_database.py`](/C:/Users/user/PycharmProjects/AutoSOC/tests/test_database.py)
- [`tests/test_security_utils.py`](/C:/Users/user/PycharmProjects/AutoSOC/tests/test_security_utils.py)

## Куда смотреть при типичных задачах

### Изменить форму регистрации

Открыть:
[`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py)

Нужные места:

- `def _build_ui(self):`
- `def attempt_register(self):`

### Изменить поведение Telegram

Смотреть:

- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py)
- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)
- [`runtime_support.py`](/C:/Users/user/PycharmProjects/AutoSOC/runtime_support.py)

### Изменить dashboard metrics

Смотреть:
[`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)

Нужные методы:

- `_refresh_dashboard_metrics`
- `_count_live_open_ports`
- `_update_exposure_baseline`

### Изменить firewall behavior

Смотреть:
[`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)

Нужные методы:

- `toggle_port`
- `_set_port_firewall_rule`
- `_block_ip_in_firewall`

### Изменить audit или event хранение

Смотреть:
[`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py)

Нужные методы:

- `add_security_event`
- `add_audit_event`
- `set_setting`

## Если вы не разработчик

Пользуйтесь простым правилом:

- проблема UI -> [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) или [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)
- проблема Telegram -> [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py), [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py), [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)
- проблема пользователя -> [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py), [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py)
- проблема scan -> [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py)
- проблема риска -> [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py)
- проблема validation -> [`validators.py`](/C:/Users/user/PycharmProjects/AutoSOC/validators.py)
- проблема хранения и аудита -> [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py)

## Дополнительные управленческие документы

- [`docs/ru/PROGRAMMER_TASKS.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/PROGRAMMER_TASKS.md)
- [`docs/ru/AI_DEVELOPER_TASKS.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/AI_DEVELOPER_TASKS.md)

Этого документа достаточно, чтобы быстро ориентироваться в кодовой базе.
