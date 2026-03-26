# AutoSOC AI Kod Naviqasiyası

Bu sənəd kod yazmayan və ya az kod bilən komanda üzvləri üçün hazırlanıb.
Məqsəd sadədir: layihədə hansı faylın nə iş gördüyünü tez başa düşmək.

## Ümumi mənzərə

Layihəni 4 əsas hissəyə bölmək olar:

1. Login və qeydiyyat hissəsi
2. Əsas dashboard və istifadəçi interfeysi
3. Təhlükəsizlik məntiqi
4. Yaddaş və inteqrasiya hissəsi

Ən vacib qısa yaddaş:

- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) - tətbiqə giriş nöqtəsidir
- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py) - əsas tətbiq pəncərəsidir
- [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py) - portları yoxlayır
- [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py) - hansı portların riskli olduğunu təyin edir
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py) - istifadəçi və Telegram bağlanmasını idarə edir
- [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py) - skan tarixçəsi və ayarları saxlayır

## Fayl-fayl izah

## 1. `main.py`

Bu fayl layihənin mərkəzidir.

Burada bunlar yerləşir:

- əsas dashboard
- yuxarıdakı metrik kartları
- port aç / bağla düymələri
- skan konsolu
- Telegram statusu
- AI köməkçi paneli
- real-time panel yenilənməsi
- Telegram-a alert göndərilməsi

Əgər problem bunlardan biri ilə bağlıdırsa:

- dashboard sayları
- skan nəticələrinin görünməsi
- Telegram alerti
- portların bloklanması
- AI cavabları

Birinci baxılacaq fayl [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)-dır.

## 2. `login.py`

Bu fayl giriş ekranını idarə edir.

Burada bunlar var:

- splash screen
- login və qeydiyyat UI
- Telegram Chat ID ilə qeydiyyat
- login pəncərəsində Telegram listener
- `/start` gələndə Chat ID-nin formaya yazılması

Əgər problem bunlarla bağlıdırsa:

- login pəncərəsi
- qeydiyyat forması
- scroll problemi
- `/start` cavabı
- Chat ID sahəsi

Onda [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py)-a baxın.

## 3. `auth.py`

Bu fayl istifadəçi hesablarını idarə edir.

Burada bunlar edilir:

- istifadəçi cədvəli yaradılır
- login yoxlanılır
- yeni hesab yaradılır
- eyni Telegram Chat ID ilə ikinci hesabın yaradılması bloklanır
- login mərhələsi üçün Telegram məlumatları saxlanılır

Əgər problem bunlarla bağlıdırsa:

- qeydiyyat
- login
- Telegram Chat ID unikallığı
- hesab ilə Telegram əlaqəsi

[`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)-a baxın.

## 4. `scanner.py`

Bu fayl Nmap əsaslı skanı edir.

Burada:

- seçilmiş portlar yoxlanılır
- açıq portlar qaytarılır
- neçə portun yoxlandığı barədə xülasə qaytarılır

Əgər problem:

- port skanı
- port sayının səhv görünməsi
- açıq/bağlı port xülasəsi

ilə bağlıdırsa, [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py)-a baxın.

## 5. `analyzer.py`

Bu faylda risk bazası var.

Burada:

- hansı portların riskli sayıldığı qeyd olunub
- risk təsviri verilir

Yeni riskli port əlavə etmək üçün ən rahat fayllardan biri budur:
[`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py)

## 6. `database.py`

Bu fayl əməliyyat məlumatlarını saxlayır.

Burada saxlanılır:

- skan tarixçəsi
- Telegram istifadəçi məlumatları
- tətbiq ayarları

Saxlanma ilə bağlı problem varsa, [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py)-a baxın.

## 7. `guard.py`

Bu fayl monitorinq və avtomatik reaksiya üçündür.

Əgər problem bunlarla bağlıdırsa:

- threat monitorinqi
- avtomatik bloklama
- şübhəli trafik

Fayl:
[`guard.py`](/C:/Users/user/PycharmProjects/AutoSOC/guard.py)

## 8. `ai_expert.py`

Bu fayl AI izahı və tövsiyə hissəsini idarə edir.

Burada dəyişmək olar:

- skan xülasəsi
- AI cavabları
- istifadəçiyə göstərilən tövsiyə mətni

Fayl:
[`ai_expert.py`](/C:/Users/user/PycharmProjects/AutoSOC/ai_expert.py)

## Tipik dəyişikliklər üçün bələdçi

### Qeydiyyat formasını dəyişmək istəyəndə

Baxın:
[`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py)

Açar funksiyalar:

- `def _build_ui(self):`
- `def attempt_register(self):`

### Telegram davranışını dəyişmək istəyəndə

Baxın:

- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) - login mərhələsində bot
- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py) - əsas tətbiqdə bot və alertlər
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py) - istifadəçi ilə Telegram əlaqəsi

### Dashboard rəqəmlərini dəyişmək istəyəndə

Baxın:
[`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)

Açar hissələr:

- `_refresh_dashboard_metrics`
- `_count_live_open_ports`
- `_count_live_risky_ports`

### Telegram-a göndərilən skan məlumatını dəyişmək istəyəndə

Baxın:
[`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)

Açar hissələr:

- `send_telegram_alert`
- `run_logic`
- `_handle_telegram_update`

## Hakimlərə layihəni necə izah etmək olar

Bu sadə ardıcıllıqla danışmaq rahatdır:

1. İstifadəçi login və qeydiyyat ekranından daxil olur
2. Telegram Chat ID hesabla bağlanır
3. Əsas dashboard portları skan edir
4. Tətbiq riskli portları göstərir
5. İstifadəçi portları tətbiqdən bağlaya bilir
6. Nəticələr həm ekranda, həm də Telegram-da göstərilir
7. AI istifadəçiyə növbəti addımı izah edir

## Kod bilməyənlər üçün ən rahat qayda

- UI problemi -> [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) və ya [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)
- Telegram problemi -> [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py), [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py), [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)
- istifadəçi problemi -> [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)
- skan problemi -> [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py)
- risk problemi -> [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py)

Bu sənəd hackathon zamanı layihədə rahat istiqamətlənmək üçün kifayətdir.
