# Навигация по коду AutoSOC AI

Этот документ нужен команде, которая не пишет код каждый день.
Его цель — быстро объяснить, какой файл за что отвечает.

## Общая логика проекта

Проект можно разделить на 4 части:

1. Вход и регистрация
2. Основной dashboard
3. Логика кибербезопасности
4. Хранение данных и интеграции

Если запомнить совсем коротко:

- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) - вход в приложение
- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py) - основное окно и логика работы
- [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py) - сканирование портов
- [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py) - определение рисков
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py) - пользователи и Telegram-привязка
- [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py) - история и настройки

## Объяснение по файлам

## 1. `main.py`

Это центральный файл проекта.

Здесь находятся:

- основной dashboard
- верхние карточки с метриками
- управление портами
- консоль сканирования
- Telegram status
- AI-помощник
- отправка alert в Telegram

Если проблема связана с:

- цифрами на панели
- показом результатов скана
- Telegram alert
- блокировкой портов
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

то смотреть нужно [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py).

## 3. `auth.py`

Этот файл управляет пользователями.

Он делает:

- создание таблицы пользователей
- проверку логина
- регистрацию нового аккаунта
- запрет повторного использования одного Telegram Chat ID
- хранение Telegram-привязки

Если проблема в:

- создании аккаунта
- входе
- уникальности Telegram Chat ID
- привязке аккаунта к Telegram

нужно открыть [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py).

## 4. `scanner.py`

Этот файл запускает сканирование через Nmap.

Он:

- проверяет выбранные порты
- возвращает открытые порты
- формирует сводку checked/open/closed/filtered

Если проблема в сканировании, смотреть нужно [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py).

## 5. `analyzer.py`

Этот файл содержит простую базу рисков.

Он отвечает за:

- какие порты считаются опасными
- какое описание риска показывать

Если нужно добавить новые risk ports, редактируется [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py).

## 6. `database.py`

Этот файл хранит:

- историю сканов
- Telegram-данные
- настройки приложения

Если проблема связана с сохранением, смотреть нужно [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py).

## 7. `guard.py`

Этот файл отвечает за мониторинг и автоматическую реакцию.

Если проблема в:

- threat monitoring
- auto block
- suspicious traffic

смотрите [`guard.py`](/C:/Users/user/PycharmProjects/AutoSOC/guard.py).

## 8. `ai_expert.py`

Этот файл отвечает за AI-пояснения.

Здесь можно менять:

- summary скана
- ответы ассистента
- текст рекомендаций

Файл:
[`ai_expert.py`](/C:/Users/user/PycharmProjects/AutoSOC/ai_expert.py)

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

### Изменить dashboard metrics

Смотреть:
[`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)

Нужные методы:

- `_refresh_dashboard_metrics`
- `_count_live_open_ports`
- `_count_live_risky_ports`

### Изменить Telegram-сообщение после скана

Смотреть:
[`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)

Нужные методы:

- `send_telegram_alert`
- `run_logic`
- `_handle_telegram_update`

## Как объяснять проект судьям

Удобная логика объяснения:

1. Пользователь входит через login/registration
2. Привязывает Telegram Chat ID
3. Приложение сканирует порты
4. Выявляет рискованные сервисы
5. Позволяет блокировать порты
6. Показывает результат на экране и отправляет его в Telegram
7. AI объясняет, что делать дальше

## Если вы не разработчик

Пользуйтесь простым правилом:

- проблема UI -> [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) или [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)
- проблема Telegram -> [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py), [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py), [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)
- проблема пользователя -> [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)
- проблема скана -> [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py)
- проблема риска -> [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py)
