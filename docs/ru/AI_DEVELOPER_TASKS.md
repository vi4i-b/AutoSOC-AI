# ТЗ для AI-разработчика: усиление ИИ-модуля AutoSOC

## Цель документа

Этот документ описывает цели и задачи для AI-разработчика, который должен превратить текущий AI-модуль AutoSOC
из полезного помощника в полноценного SOC copilot и anti-phishing analyst.

---

## Главная цель

Сделать ИИ в AutoSOC:

- более точным;
- более полезным в реальных сценариях;
- контекстно осведомлённым;
- объяснимым;
- мультиязычным;
- устойчивым к сбоям внешних LLM;
- полезным не только для scan summary, но и для incident response и anti-phishing.

---

## Блок 1. Улучшение качества ответов ИИ

### Цель

Сделать ответы ИИ конкретными, структурированными и ориентированными на действия.

### Задачи

1. Переделать response style:
   - краткое резюме угрозы;
   - почему это важно;
   - 3-5 конкретных действий;
   - уровень критичности;
   - когда нужна срочная реакция;
   - когда можно просто наблюдать.

2. Ввести structured output format:
   - `summary`
   - `severity`
   - `why_it_matters`
   - `recommended_actions`
   - `verification_steps`
   - `notes`

3. Добавить режимы ответа:
   - для новичка;
   - для SOC analyst;
   - для системного администратора;
   - для руководителя в виде executive summary.

4. Уменьшить общие и размытые фразы:
   - меньше “best practices” без привязки;
   - больше контекста по текущему scan;
   - больше привязки к конкретному IP, порту, сервису, инциденту.

### Критерии готовности

- Ответы стали короче и полезнее.
- В ответах есть конкретные шаги.
- Один и тот же инцидент объясняется по-разному в зависимости от режима пользователя.

---

## Блок 2. Улучшение контекстной памяти и состояния диалога

### Цель

Сделать ИИ действительно контекстным, чтобы он понимал, о чем говорили ранее, и не терял тему.

### Задачи

1. Улучшить short-term memory:
   - хранить последние вопросы и ответы;
   - связывать follow-up вопросы с активной темой;
   - понимать местоименные ссылки вроде “это”, “его”, “эту угрозу”.

2. Улучшить persistent memory:
   - сохранять последние критичные findings;
   - хранить профиль пользователя;
   - помнить последний target/IP;
   - помнить последние инциденты и remediation steps.

3. Разделить память по типам:
   - scan context;
   - incident context;
   - phishing context;
   - user preference context;
   - shared security memory.

4. Сделать memory cleanup strategy:
   - TTL для старого контекста;
   - сжатие истории;
   - summary memory вместо бесконечного накопления текста.

### Критерии готовности

- ИИ понимает follow-up без повторного описания проблемы.
- Память не разрастается бесконтрольно.
- ИИ не путает старый и новый контекст.

---

## Блок 3. Превращение ИИ в incident copilot

### Цель

Сделать ИИ помощником по инцидентам, а не только генератором пояснений.

### Задачи

1. Для сетевых инцидентов добавить playbooks:
   - exposed RDP;
   - SMB exposure;
   - brute-force;
   - suspicious port drift;
   - canary hit;
   - unusual traffic spike.

2. Научить ИИ выдавать:
   - `what happened`
   - `possible impact`
   - `immediate containment`
   - `investigation steps`
   - `hardening recommendations`

3. Добавить incident timeline summarization:
   - что произошло;
   - в какой последовательности;
   - какие действия выполнила система;
   - что ещё должен сделать оператор.

4. Добавить режим “next best action”.

### Критерии готовности

- Для каждого ключевого инцидента есть осмысленный playbook.
- ИИ предлагает расследование и containment, а не только объяснение.

---

## Блок 4. Интеграция ИИ с антифишинговой системой

### Цель

Сделать ИИ сильным аналитиком по phishing-сценариям.

### Задачи

1. Поддержать отдельный phishing context:
   - URL;
   - домен;
   - email body;
   - headers;
   - attachment metadata;
   - signals from detector.

2. Научить ИИ объяснять phishing verdict:
   - почему ссылка подозрительна;
   - какие сигналы сработали;
   - чем это похоже на credential theft;
   - насколько высок риск.

3. Добавить типы ответов:
   - краткий verdict;
   - analyst report;
   - user-facing warning;
   - incident note для Telegram.

4. Генерировать remediation steps:
   - не переходить по ссылке;
   - изолировать письмо;
   - предупредить пользователя;
   - проверить домен и бренд;
   - инициировать password reset при компрометации.

5. Поддержать brand impersonation explanation:
   - визуальное сходство домена;
   - несоответствие бренду;
   - urgency/social engineering patterns.

### Критерии готовности

- ИИ качественно объясняет фишинг-кейсы.
- Verdict сопровождается человеческим объяснением.
- ИИ может сформировать короткое предупреждение для конечного пользователя.

---

## Блок 5. Улучшение провайдерной логики и устойчивости

### Цель

Сделать AI-подсистему устойчивой к сбоям OpenAI/Ollama и предсказуемой по качеству.

### Задачи

1. Улучшить provider orchestration:
   - health checks;
   - timeout policy;
   - retry policy;
   - graceful fallback;
   - явный статус активного провайдера.

2. Добавить quality control:
   - минимальная длина полезного ответа;
   - защита от пустых или бессодержательных ответов;
   - fallback на локальный экспертный режим при слабом результате.

3. Добавить prompt hardening:
   - stronger system prompt;
   - role separation;
   - cleaner context packing;
   - защита от topic drift.

4. Ввести structured telemetry:
   - какой провайдер ответил;
   - latency;
   - success/failure;
   - fallback reason;
   - answer quality marker.

### Критерии готовности

- ИИ не ломается при недоступности внешней модели.
- Пользователь всегда получает ответ или понятный fallback.
- Видно, какой провайдер реально отработал.

---

## Блок 6. Мультиязычность и локализация

### Цель

Улучшить ответы на русском, азербайджанском и английском без деградации качества.

### Задачи

1. Улучшить language detection.
2. Нормализовать термины безопасности на `ru / az / en`.
3. Исправить случаи, где ИИ смешивает языки.
4. Подготовить локализованные шаблоны:
   - incident summary;
   - anti-phishing warning;
   - scan explanation;
   - remediation steps.

### Критерии готовности

- Ответы устойчиво идут на языке пользователя.
- Терминология выглядит профессионально и последовательно.

---

## Блок 7. Оценка качества и AI evals

### Цель

Сделать улучшение ИИ измеримым.

### Задачи

1. Собрать eval dataset:
   - open ports;
   - risky services;
   - brute-force;
   - canary alerts;
   - phishing URLs;
   - phishing emails;
   - benign cases;
   - mixed-language questions.

2. Ввести evaluation criteria:
   - factual accuracy;
   - actionability;
   - relevance to current context;
   - clarity;
   - multilingual quality;
   - phishing explanation quality.

3. Создать ручной evaluation checklist.
4. По возможности добавить полуавтоматический regression evaluation.

### Критерии готовности

- Есть набор типовых кейсов для проверки ИИ.
- Улучшения можно сравнивать до и после.

---

## Блок 8. Рекомендуемая разбивка на этапы

### Этап 1. Core AI quality

- structured answers
- better prompts
- memory cleanup
- provider fallback improvement

### Этап 2. SOC copilot

- incident playbooks
- next best action
- incident timeline summary
- role-based response modes

### Этап 3. Phishing AI analyst

- phishing context support
- verdict explanation
- user warning mode
- analyst report mode

### Этап 4. Evals and hardening

- eval dataset
- multilingual QA
- telemetry
- response quality checks

---

## Итоговые deliverables

AI-разработчик должен передать:

- улучшенный AI-модуль;
- обновлённые prompts и response formats;
- поддержку anti-phishing AI analysis;
- playbooks для основных инцидентов;
- eval-набор и критерии проверки;
- краткий отчёт: что улучшено, как проверялось, какие ограничения остались.
