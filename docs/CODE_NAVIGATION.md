# AutoSOC AI Kod Naviqasiyası

Bu sənəd kod yazmayan və ya az kod bilən komanda üzvləri üçün hazırlanıb.
Məqsəd sadədir: layihədə hansı faylın nə iş gördüyünü tez başa düşmək.

## Ümumi mənzərə

Layihəni indi 6 əsas hissəyə bölmək daha rahatdır:

1. Login və qeydiyyat
2. Əsas dashboard və UI
3. Skan və risk analizi
4. Monitorinq, firewall və təhlükə reaksiyası
5. Məlumatların saxlanması və audit
6. AI, helper və validation qatları

Ən vacib qısa yaddaş:

- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) - tətbiqə giriş nöqtəsidir
- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py) - əsas tətbiq pəncərəsidir
- [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py) - portları yoxlayır
- [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py) - hansı portların riskli olduğunu təyin edir
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py) - istifadəçi girişi və Telegram bağlanmasını idarə edir
- [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py) - scan history, settings, audit və security event-ləri saxlayır

## Fayl-fayl izah

## 1. `main.py`

Bu fayl layihənin mərkəzidir.

Burada bunlar yerləşir:

- əsas dashboard
- metrik kartları
- port aç / bağla düymələri
- skan konsolu
- Telegram statusu
- AI köməkçi paneli
- canary və incident reaction
- firewall əməliyyatları

Əgər problem bunlarla bağlıdırsa:

- dashboard sayları
- scan nəticələrinin görünməsi
- Telegram alert-lər
- firewall davranışı
- canary / guard reaksiyası
- AI paneli

birinci baxılacaq fayl [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)-dır.

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

onda [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py)-a baxın.

## 3. `auth.py`

Bu fayl istifadəçi hesablarını idarə edir.

Burada bunlar edilir:

- login yoxlanılır
- yeni hesab yaradılır
- remember me idarə olunur
- eyni Telegram Chat ID ilə ikinci hesab bloklanır
- Windows credential və lokal credential axını koordinator olunur

Əgər problem bunlarla bağlıdırsa:

- qeydiyyat
- login
- Telegram Chat ID unikallığı
- remember me
- hesab ilə Telegram əlaqəsi

[`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)-a baxın.

## 4. `database.py`

Bu fayl vahid SQLite qatıdır.

Burada saxlanılır:

- scan history
- Telegram istifadəçi məlumatları
- tətbiq ayarları
- security events
- audit events
- exposure baseline

Saxlanma, migrasiya və ya jurnal problemi varsa, [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py)-a baxın.

## 5. `scanner.py`

Bu fayl Nmap əsaslı scan edir.

Burada:

- seçilmiş portlar yoxlanılır
- açıq portlar qaytarılır
- checked/open/closed/filtered xülasəsi yaradılır

Əgər problem port scan-dadırsa, [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py)-a baxın.

## 6. `analyzer.py`

Bu faylda risk bazası var.

Burada:

- hansı portların riskli sayıldığı qeyd olunub
- risk severity və prevention təsviri verilir

Yeni riskli port əlavə etmək üçün ən rahat fayllardan biri budur:
[`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py)

## 7. `guard.py`

Bu fayl trafik monitorinqi və avtomatik reaksiya üçündür.

Əgər problem bunlarla bağlıdırsa:

- traffic spike monitorinqi
- threshold
- auto block
- suspicious traffic reaction

fayl:
[`guard.py`](/C:/Users/user/PycharmProjects/AutoSOC/guard.py)

## 8. `log_listener.py`

Bu fayl Windows Security log-u dinləyir.

Burada:

- Event ID 4625 failed logon event-ləri izlənir
- brute-force siqnalları çıxarılır
- source IP tapılır

Əgər problem Windows log reaction ilə bağlıdırsa, [`log_listener.py`](/C:/Users/user/PycharmProjects/AutoSOC/log_listener.py)-a baxın.

## 9. `ai_expert.py`

Bu fayl AI izahı və tövsiyə hissəsini idarə edir.

Burada dəyişmək olar:

- scan xülasəsi
- AI cavabları
- prompt davranışı
- fallback expert mode
- language detection

fayl:
[`ai_expert.py`](/C:/Users/user/PycharmProjects/AutoSOC/ai_expert.py)

## 10. Helper fayllar

### `runtime_support.py`

Burada:

- `.env` oxunması
- ikon helper-ləri
- Telegram client helper-i

fayl:
[`runtime_support.py`](/C:/Users/user/PycharmProjects/AutoSOC/runtime_support.py)

### `security_utils.py`

Burada:

- parol hash
- parol verify
- legacy hash uyğunluğu
- rehash ehtiyacı

fayl:
[`security_utils.py`](/C:/Users/user/PycharmProjects/AutoSOC/security_utils.py)

### `validators.py`

Burada:

- username validation
- password validation
- Telegram Chat ID validation
- safe scan target validation

fayl:
[`validators.py`](/C:/Users/user/PycharmProjects/AutoSOC/validators.py)

## 11. Testlər

[`tests/`](/C:/Users/user/PycharmProjects/AutoSOC/tests) qovluğunda əsas smoke və unit test-lər yerləşir.

Hazırda xüsusilə bunlar vacibdir:

- [`tests/test_database.py`](/C:/Users/user/PycharmProjects/AutoSOC/tests/test_database.py)
- [`tests/test_security_utils.py`](/C:/Users/user/PycharmProjects/AutoSOC/tests/test_security_utils.py)

## Tipik dəyişikliklər üçün bələdçi

### Qeydiyyat formasını dəyişmək istəyəndə

Baxın:
[`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py)

Açar funksiyalar:

- `def _build_ui(self):`
- `def attempt_register(self):`

### Telegram davranışını dəyişmək istəyəndə

Baxın:

- [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py)
- [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)
- [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)
- [`runtime_support.py`](/C:/Users/user/PycharmProjects/AutoSOC/runtime_support.py)

### Dashboard rəqəmlərini dəyişmək istəyəndə

Baxın:
[`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)

Açar hissələr:

- `_refresh_dashboard_metrics`
- `_count_live_open_ports`
- `_update_exposure_baseline`

### Firewall davranışını dəyişmək istəyəndə

Baxın:
[`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)

Açar hissələr:

- `toggle_port`
- `_set_port_firewall_rule`
- `_block_ip_in_firewall`

### Audit və event saxlanmasını dəyişmək istəyəndə

Baxın:
[`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py)

Açar hissələr:

- `add_security_event`
- `add_audit_event`
- `set_setting`

## Kod bilməyənlər üçün ən rahat qayda

- UI problemi -> [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py) və ya [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py)
- Telegram problemi -> [`login.py`](/C:/Users/user/PycharmProjects/AutoSOC/login.py), [`main.py`](/C:/Users/user/PycharmProjects/AutoSOC/main.py), [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py)
- istifadəçi problemi -> [`auth.py`](/C:/Users/user/PycharmProjects/AutoSOC/auth.py), [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py)
- scan problemi -> [`scanner.py`](/C:/Users/user/PycharmProjects/AutoSOC/scanner.py)
- risk problemi -> [`analyzer.py`](/C:/Users/user/PycharmProjects/AutoSOC/analyzer.py)
- validation problemi -> [`validators.py`](/C:/Users/user/PycharmProjects/AutoSOC/validators.py)
- audit və storage problemi -> [`database.py`](/C:/Users/user/PycharmProjects/AutoSOC/database.py)

## Əlavə idarəetmə sənədləri

- [`docs/ru/PROGRAMMER_TASKS.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/PROGRAMMER_TASKS.md)
- [`docs/ru/AI_DEVELOPER_TASKS.md`](/C:/Users/user/PycharmProjects/AutoSOC/docs/ru/AI_DEVELOPER_TASKS.md)

Bu sənəd komandanın layihədə rahat istiqamətlənməsi üçün kifayətdir.
