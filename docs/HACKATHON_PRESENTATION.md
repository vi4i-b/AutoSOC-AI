# AutoSOC AI Təqdimat Sənədi

## Layihənin adı

AutoSOC AI

## Bir cümləlik pitch

AutoSOC AI kiçik komandalar üçün hazırlanmış masaüstü kibertəhlükəsizlik köməkçisidir və riskli portları aşkarlayıb, onları idarə etməyə və nəticələri Telegram vasitəsilə dərhal paylaşmağa imkan verir.

## Problem

Kiçik şirkətlərdə, tələbə komandalarında və lokal administrator mühitində çox vaxt:

- ayrıca SOC komandası olmur
- bahalı təhlükəsizlik sistemləri olmur
- texniki olmayan istifadəçilər riski başa düşmür
- təhlükələrə gec reaksiya verilir

Nəticədə:

- riskli portlar açıq qalır
- istifadəçi təhlükənin nə olduğunu anlamır
- təhlükəsizlik monitorinqi mürəkkəb görünür

## Həll

AutoSOC AI bir pəncərədə bunları birləşdirir:

- port skanı
- risk analizi
- firewall üzərindən port idarəsi
- AI ilə izah
- Telegram alertləri

Bu yanaşma həm texniki, həm də texniki olmayan istifadəçilər üçün prosesi sadələşdirir.

## Layihənin əsas dəyəri

- istifadəsi sadədir
- nəticə real vaxtda görünür
- risk yalnız göstərilmir, həm də üzərində əməliyyat aparmaq olur
- Telegram inteqrasiyası ilə operativ bildiriş verir
- AI sayəsində istifadəçi “nə etməliyəm?” sualına cavab alır

## Əsas funksiyalar

## 1. Giriş və qeydiyyat sistemi

- login və qeydiyyat pəncərəsi
- Telegram Chat ID ilə hesabın bağlanması
- `1 Telegram Chat ID = 1 hesab`

## 2. Telegram inteqrasiyası

- istifadəçi bota `/start` yazır
- bot `Telegram User ID` və `Telegram Chat ID` qaytarır
- istifadəçi həmin Chat ID-ni qeydiyyat zamanı daxil edir
- skan nəticələri və təhlükə alertləri həmin çata göndərilir

## 3. Port skanı

- izlənən TCP portlar Nmap ilə yoxlanılır
- neçə portun yoxlandığı göstərilir
- açıq, bağlı və filtered vəziyyətlər göstərilir

## 4. Risk analizi

- SMB, RDP, FTP, Telnet və digər riskli servislər aşkar edilir
- risk score hesablanır
- istifadəçiyə riskli portlar göstərilir

## 5. Aktiv müdaxilə

- istifadəçi portları tətbiqdən aça və bağlaya bilir
- Windows firewall qaydaları avtomatik tətbiq olunur
- dashboard göstəriciləri real vaxtda yenilənir

## 6. AI köməkçi

- skan nəticələrini izah edir
- remediation təklif edir
- texniki olmayan istifadəçiyə nə etməli olduğunu sadə dillə başa salır

## Niyə hackathon üçün güclü layihədir

- real problemi həll edir
- kibertəhlükəsizlik, AI, avtomatlaşdırma və UI-ni birləşdirir
- canlı demo üçün aydın ssenarisi var
- həm texniki dərinlik, həm də istifadəçi dəyəri göstərir

## Demo ssenarisi

Təqdimat zamanı bu ardıcıllıqla göstərmək rahatdır:

1. Login və qeydiyyat pəncərəsini açın
2. Telegram botu göstərin
3. `/start` yazın
4. Chat ID-nin qaytarıldığını göstərin
5. Bu Chat ID ilə istifadəçi yaradın
6. Hesaba daxil olun
7. Skan başladın
8. Dashboard, riskli portlar və AI xülasəni göstərin
9. Eyni nəticənin Telegram-a getdiyini göstərin
10. Portları bağlayın və panelin real vaxtda dəyişdiyini göstərin

## İnnovasiya nöqtələri

- Telegram əsaslı qeydiyyat və alert axını
- real-time port exposure dashboard
- bir Telegram ID-nin yalnız bir hesaba bağlanması
- kibertəhlükəsizliyi qeyri-texniki istifadəçilər üçün sadələşdirmə
- AI izah qatının təhlükəsizlik prosesinə əlavə edilməsi

## Hədəf istifadəçilər

- kibertəhlükəsizlik öyrənən tələbələr
- kiçik bizneslər
- lokal administratorlar
- ayrıca SOC komandası olmayan startaplar

## Texniki arxitektura

- UI: CustomTkinter
- Skan mühərriki: Nmap
- Monitorinq: Scapy əsaslı guard
- Yaddaş: SQLite
- Bildiriş: Telegram Bot API
- Build: PyInstaller

## Rəqabət üstünlükləri

- quraşdırması və istifadəsi sadədir
- Telegram ilə sürətli bildiriş verir
- yalnız monitorinq etmir, əməliyyat da aparır
- öyrənmə əyrisi aşağıdır
- AI köməkçi izah verir

## Hazırkı vəziyyət

Layihənin hazır versiyasında bunlar işləyir:

- Telegram Chat ID ilə qeydiyyat
- `/start` cavabı
- Telegram-a bağlı alertlər
- canlı dashboard metrikləri
- scroll olan qeydiyyat forması
- `.exe` build

## Gələcək inkişaf istiqamətləri

- daha geniş şəbəkə skanı
- daha inkişaf etmiş threat intelligence
- report export
- mərkəzləşdirilmiş dashboard
- tətbiqdən ayrı çalışan standalone bot servisi

## 1 dəqiqəlik çıxış mətni

"AutoSOC AI kiçik komandalar və SOC komandası olmayan mühitlər üçün hazırlanmış yüngül kibertəhlükəsizlik köməkçisidir. Biz bir masaüstü tətbiqdə port skanı, risk analizi, firewall müdaxiləsi, Telegram alerti və AI izahını birləşdirdik. Məqsədimiz təhlükəsizlik monitorinqini daha əlçatan etməkdir. İstifadəçi tətbiqə daxil olur, Telegram hesabını bağlayır, skan başladır, riskli portları görür, onları bağlayır və eyni nəticəni dərhal Telegram-da alır. Yəni layihə yalnız təhlükəni göstərmir, həm də istifadəçiyə başa düşmək və reaksiya vermək imkanı yaradır."

## Slayd strukturu

1. Problem
2. Bizim həll
3. Demo axını
4. Əsas funksiyalar
5. Texniki arxitektura
6. İstifadəçi dəyəri
7. Gələcək roadmap

## Hakimlərlə danışmaq üçün əsas fikirlər

- Biz texniki güclə yanaşı usability-yə də fokuslandıq
- Layihə kibertəhlükəsizliyi qeyri-ekspertlər üçün daha başadüşülən edir
- Tətbiq monitorinqi və əməliyyatı eyni məkanda birləşdirir
- Telegram alertləri istifadəçiyə tanış və rahat kanalda çatır
- AI qatı təhlükəsizliyi daha izahlı və daha istifadəyə yararlı edir
