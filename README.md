# AutoSOC AI

AutoSOC AI kiçik komandalar və lokal şəbəkələr üçün hazırlanmış masaüstü kibertəhlükəsizlik köməkçisidir.
Layihə şəbəkə skanı, riskli port analizi, firewall idarəsi, AI izahı və Telegram bildirişlərini bir tətbiqdə birləşdirir.

## Layihə nə edir

- Seçilmiş hədəfdə izlənən portları skan edir.
- Riskli servis və portları aşkar edir.
- Cihaz sayı, açıq portlar, risk səviyyəsi və Telegram statusunu paneldə göstərir.
- İstifadəçiyə portları tətbiqdən açmağa və bağlamağa imkan verir.
- Skan və təhlükə nəticələrini Telegram-a göndərir.
- Telegram Chat ID-ni konkret istifadəçi hesabına bağlayır.
- AI köməkçisi vasitəsilə nəticələri izah edir və tövsiyə verir.

## Əsas funksiyalar

- Telegram Chat ID ilə qeydiyyat və giriş sistemi
- `/start`, `/id`, `/help` komandalarını dəstəkləyən Telegram bot
- Real-time dashboard yenilənməsi
- Scroll dəstəyi olan qeydiyyat forması
- `1 Telegram Chat ID = 1 hesab` məhdudiyyəti
- Windows firewall üzərindən port idarəsi
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
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py) - istifadəçi hesabları, Telegram ID unikallığı, remember me və qeydiyyat logikası
- [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py) - Nmap əsaslı port skanı
- [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py) - riskli portların analizi
- [`guard.py`](/C:/Users/user/PycharmProjects/AutoSOC/guard.py) - monitorinq və avtomatik bloklama
- [`ai_expert.py`](/C:/Users/user/PycharmProjects/AutoSOC/ai_expert.py) - AI izah və tövsiyələr
- [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py) - skan tarixçəsi, Telegram məlumatları, tətbiq ayarları
- [`main.spec`](/C:/Users/user/PycharmProjects/AutoSOC/main.spec) - PyInstaller build konfiqurasiyası

## Layihəni necə işə salmaq olar

1. [`requirements.txt`](/C:/Users/user/PycharmProjects/AutoSOC/requirements.txt) faylındakı asılılıqları quraşdırın.
2. [`.env`](/C:/Users/user/PycharmProjects/AutoSOC/.env) faylına Telegram bot token əlavə edin.
3. Tətbiqi bu komanda ilə başladın:

```powershell
python main.py
```

## Telegram necə işləyir

1. Tətbiqi başladın.
2. Login və ya qeydiyyat pəncərəsindən botu açın.
3. Bota `/start` yazın.
4. Botun qaytardığı `Telegram Chat ID` dəyərini kopyalayın.
5. Onu qeydiyyat formasına daxil edin.
6. Hesaba daxil olun və skan başladın.
7. Nəticələr və alertlər həmin Telegram çata göndəriləcək.

## `.exe` necə yığılır

```powershell
.\.venv\Scripts\python.exe -m PyInstaller --clean main.spec
```

Nəticə [`dist/main.exe`](/C:/Users/user/PycharmProjects/AutoSOC/dist/main.exe) faylında yaranır.

## Vacib qeydlər

- Tətbiq Windows üçün nəzərdə tutulub, çünki `netsh advfirewall` istifadə edir.
- Skan və firewall əmrlərinin düzgün işləməsi üçün administrator icazəsi lazımdır.
- Telegram bot cavabları tətbiq işləyərkən aktiv olur, çünki polling tətbiqin içində işləyir.

## Əlavə sənədlər

- [`docs/CODE_NAVIGATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/CODE_NAVIGATION.md)
- [`docs/HACKATHON_PRESENTATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/HACKATHON_PRESENTATION.md)
- [`docs/ru/README.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/README.md)
- [`docs/ru/CODE_NAVIGATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/CODE_NAVIGATION.md)
- [`docs/ru/HACKATHON_PRESENTATION.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/HACKATHON_PRESENTATION.md)
