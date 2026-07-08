# AutoSOC AI Kod Naviqasiyası

Bu sənəd layihədə hansı faylın nə iş gördüyünü tez başa düşmək üçündür.
Kod artıq `autosoc/` paketi daxilində qatlara bölünüb.

## Ümumi mənzərə

```
main.py                  # giriş nöqtəsi: login → dashboard
autosoc/
├── ui/                  # pəncərələr (CustomTkinter)
├── system/              # əməliyyat sistemi ilə iş (firewall, loglar, hüquqlar)
├── telegram/            # Telegram bot müştərisi və dinləyicisi
├── ai/                  # AI provayderləri
└── *.py                 # əsas biznes-məntiq modulları
```

## Qatlar üzrə izah

### Giriş nöqtəsi

- `main.py` — logging və `.env` konfiqurasiyasını qurur, login pəncərəsini açır,
  uğurlu girişdən sonra dashboard-u başladır.

### UI qatı — `autosoc/ui/`

- `login.py` — splash, giriş və qeydiyyat pəncərəsi.
- `dashboard.py` — əsas pəncərənin məntiqi: skan, port idarəsi, alertlər, AI panel.
- `dashboard_layout.py` — dashboard-un vidjetlərinin qurulması (yalnız görünüş).
- `chat_window.py` — ayrıca AI chat pəncərəsi (hazırda istifadə olunmur).
- `theme.py` — ümumi rəng palitrası və pəncərə ikonu.

### Sistem qatı — `autosoc/system/`

- `firewall.py` — Windows üçün `netsh`, Linux üçün `iptables` backend-ləri.
  Bütün qaydalar `AutoSOC_` prefiksi daşıyır.
- `log_monitor.py` — brute-force aşkarlanması: Windows Security log (4625) və
  Linux `/var/log/auth.log`.
- `hardening.py` — port bağlananda xidmətlərin dayandırılması (SMB, NetBIOS və s.).
- `privileges.py` — admin/root yoxlaması.
- `netinfo.py` — lokal IP-lər, hədəfin uzaq olub-olmadığının təyini.
- `os_auth.py` — Windows hesabı ilə giriş (`LogonUserW`); Linux-da deaktivdir.
- `commands.py` — shell istifadə etmədən təhlükəsiz əmr icrası.

### Əsas modullar — `autosoc/`

- `scanner.py` — nmap ilə port skanı.
- `analyzer.py` — riskli portların kataloqu və risk score.
- `ports.py` — izlənən portların vahid siyahısı.
- `database.py` — SQLite: istifadəçilər, skanlar, settings, audit/security events,
  login lockout.
- `auth.py` — giriş, qeydiyyat, lockout siyasəti, remember-me.
- `security_utils.py` — PBKDF2 parol hash-i.
- `validators.py` — username, parol, chat ID və skan hədəfinin yoxlanması.
- `guard.py` — trafik sıçrayışlarının (DDoS) monitorinqi.
- `canary.py` — tələ portları.
- `paths.py` — istifadəçi data qovluğu (`%APPDATA%\AutoSOC` / `~/.local/share/autosoc`).
- `env.py`, `logging_setup.py` — konfiqurasiya və loglama.

### Telegram — `autosoc/telegram/`

- `client.py` — Bot API müştərisi (token error mesajlarından silinir).
- `listener.py` — long-polling dinləyicisi (login və dashboard bunu paylaşır).

### AI — `autosoc/ai/`

- `nvidia.py` — NVIDIA API üzərindən analiz.
- `expert.py` — OpenAI/Ollama + daxili offline ekspert rejimi.

## Testlər

`tests/` qovluğunda unittest-lər var:

```bash
.venv/bin/python -m unittest discover -s tests -v
```
