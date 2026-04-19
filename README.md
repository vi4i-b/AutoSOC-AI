# AutoSOC AI

AutoSOC AI kiçik komandalar və lokal şəbəkələr üçün hazırlanmış masaüstü kibertəhlükəsizlik köməkçisidir.
Layihə şəbəkə skanı, riskli port analizi, Windows firewall idarəsi, AI izahı və Telegram bildirişlərini bir tətbiqdə birləşdirir.

## Layihə nə edir

- Seçilmiş hədəfdə izlənən TCP portları skan edir.
- Riskli servis və portları aşkar edir.
- Dashboard üzərində cihaz sayı, açıq portlar, risk skoru və Telegram statusunu göstərir.
- Portları tətbiqdən açmağa və bağlamağa imkan verir.
- Şübhəli trafik, canary hit və digər təhlükə siqnallarını jurnalına yazır.
- Skan nəticələrini və alertləri Telegram-a göndərir.
- Telegram Chat ID-ni konkret istifadəçi hesabına bağlayır.
- AI köməkçisi vasitəsilə nəticələri izah edir və növbəti addımları təklif edir.

## Cari güclü tərəflər

- Telegram Chat ID ilə qeydiyyat və giriş
- `/start`, `/id`, `/help` komandalarını dəstəkləyən Telegram bot
- Real-time dashboard yenilənməsi
- Riskli portların AI izahı
- Windows firewall üzərindən port idarəsi
- Port Canary və təhlükə jurnalı
- Exposure baseline drift izlənməsi
- Audit event və security event saxlanması
- Gücləndirilmiş parol saxlanması və köhnə hash-lər üçün uyğunluq
- PyInstaller ilə `.exe` build

## Texnologiyalar

- Python 3.14
- CustomTkinter
- Requests
- python-nmap
- Scapy
- SQLite
- PyInstaller

## Layihə strukturu

- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py) - əsas dashboard, skan prosesi, Telegram alertləri, AI paneli, firewall idarəsi
- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) - login və qeydiyyat pəncərəsi, login mərhələsində Telegram listener
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py) - istifadəçi girişi, qeydiyyat, remember me və Telegram bağlanması
- [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py) - vahid SQLite sxemi, scan history, settings, audit və security event-lər
- [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py) - Nmap əsaslı port skanı
- [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py) - riskli portların analizi və risk score
- [`guard.py`](/C:/Users/user/PycharmProjects/AutoSOC/guard.py) - trafik monitorinqi və avtomatik bloklama
- [`log_listener.py`](/C:/Users/user/PycharmProjects/AutoSOC/log_listener.py) - Windows Security log dinləyicisi
- [`ai_expert.py`](/C:/Users/user/PycharmProjects/AutoSOC/ai_expert.py) - AI izah və tövsiyələr
- [`runtime_support.py`](/C:/Users/user/PycharmProjects/AutoSOC/runtime_support.py) - `.env`, ikonlar və Telegram client üçün ortaq runtime helper-lər
- [`security_utils.py`](/C:/Users/user/PycharmProjects/AutoSOC/security_utils.py) - parol hash və verify helper-ləri
- [`validators.py`](/C:/Users/user/PycharmProjects/AutoSOC/validators.py) - username, password, chat ID və scan target validation
- [`tests/`](/C:/Users/user/PycharmProjects/AutoSOC/tests) - əsas smoke və unit test-lər
- [`main.spec`](/C:/Users/user/PycharmProjects/AutoSOC/main.spec) - PyInstaller build konfiqurasiyası

## Layihəni necə işə salmaq olar

1. [`requirements.txt`](/C:/Users/user/PycharmProjects/AutoSOC/requirements.txt) faylındakı asılılıqları quraşdırın.
2. [`.env`](/C:/Users/user/PycharmProjects/AutoSOC/.env) faylına Telegram bot token əlavə edin.
3. İstəyə görə lokal AI üçün Ollama quraşdırın və modeli yükləyin:

```powershell
ollama pull llama3.1:8b
ollama serve
```

4. [`.env`](/C:/Users/user/PycharmProjects/AutoSOC/.env) içində bu dəyərlərdən istifadə edin:

```env
AI_PROVIDER=auto
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
OLLAMA_URL=http://localhost:11434/api/chat
OLLAMA_MODEL=llama3.1:8b
```

5. Tətbiqi bu komanda ilə başladın:

```powershell
python main.py
```

## AI necə işləyir

AutoSOC `AI_PROVIDER=auto` rejimində işləyir:

- `OPENAI_API_KEY` varsa, OpenAI istifadə edir
- OpenAI açarı yoxdursa, işlək `Ollama` instansiyasını yoxlayır
- heç biri yoxdursa, daxili ekspert rejimində cavab verir

Ən rahat pulsuz lokal variant `Ollama + llama3.1:8b` modelidir.

## Telegram necə işləyir

1. Tətbiqi başladın.
2. Login və ya qeydiyyat pəncərəsindən botu açın.
3. Bota `/start` yazın.
4. Botun qaytardığı `Telegram Chat ID` dəyərini kopyalayın.
5. Onu qeydiyyat formasına daxil edin.
6. Hesaba daxil olun və scan başladın.
7. Nəticələr və alert-lər həmin Telegram çata göndəriləcək.

## Testləri necə işlətmək olar

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## `.exe` necə yığılır

```powershell
.\.venv\Scripts\python.exe -m PyInstaller --clean main.spec
```

Nəticə [`dist/AutoSOC.exe`](/C:/Users/user/PycharmProjects/AutoSOC/dist/AutoSOC.exe) faylında yaranır.

## Vacib qeydlər

- Tətbiq Windows üçün nəzərdə tutulub, çünki `netsh advfirewall` istifadə edir.
- Skan və firewall əmrlərinin düzgün işləməsi üçün administrator icazəsi lazımdır.
- Şəbəkə skanı üçün `Nmap` quraşdırılmış olmalıdır.
- Bəzi sniffing və packet capture ssenariləri üçün `Npcap` tələb oluna bilər.
- Telegram bot cavabları tətbiq işləyərkən aktiv olur, çünki polling tətbiqin içində işləyir.

## Növbəti inkişaf istiqamətləri

- Anti-phishing modulu
- AI incident copilot gücləndirilməsi
- Daha geniş regression test suite
- Release və installer axınının daha da sabitləşdirilməsi

## Əlavə sənədlər

- [`docs/CODE_NAVIGATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/CODE_NAVIGATION.md)
- [`docs/HACKATHON_PRESENTATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/HACKATHON_PRESENTATION.md)
- [`docs/ru/README.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/README.md)
- [`docs/ru/CODE_NAVIGATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/CODE_NAVIGATION.md)
- [`docs/ru/HACKATHON_PRESENTATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/HACKATHON_PRESENTATION.md)
- [`docs/ru/PROGRAMMER_TASKS.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/PROGRAMMER_TASKS.md)
- [`docs/ru/AI_DEVELOPER_TASKS.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/AI_DEVELOPER_TASKS.md)
