# AutoSOC AI 5-7 Dəqiqəlik Çıxış Mətni

Salam. Bizim layihəmizin adı AutoSOC AI-dir.

AutoSOC AI kiçik komandalar, tələbə layihələri, startaplar və lokal administratorlar üçün hazırlanmış masaüstü kibertəhlükəsizlik köməkçisidir. Layihənin əsas məqsədi kibertəhlükəsizlik monitorinqini daha sadə, daha başadüşülən və daha operativ etməkdir. Çünki real həyatda bir çox kiçik komanda ayrıca SOC komandası, bahalı təhlükəsizlik infrastrukturu və ya dərin texniki biliyi olan mütəxəssisə malik olmur. Nəticədə isə şəbəkədə təhlükəli portlar açıq qalır, istifadəçi riski tam anlaya bilmir və təhlükələrə gec reaksiya verilir.

Biz bu problemi daha praktik şəkildə həll etməyə çalışdıq. AutoSOC AI bir tətbiqin içində bir neçə vacib funksiyanı birləşdirir: port skanı, risk analizi, firewall idarəsi, Telegram üzərindən bildirişlər və AI vasitəsilə izah. Yəni istifadəçi yalnız təhlükəni görmür, həm də onun nə demək olduğunu anlayır və dərhal müdaxilə edə bilir.

Layihənin iş prinsipi çox sadədir. İstifadəçi əvvəlcə tətbiqə daxil olur və ya yeni hesab yaradır. Qeydiyyat zamanı Telegram Chat ID hesabla bağlanır. Bunun üçün istifadəçi botumuza `/start` yazır və bot ona həm `Telegram User ID`, həm də `Telegram Chat ID` qaytarır. Daha sonra həmin Chat ID qeydiyyat formuna daxil edilir. Biz burada əlavə təhlükəsizlik və nizam-intizam üçün belə bir məhdudiyyət də əlavə etmişik: bir Telegram Chat ID yalnız bir istifadəçi hesabına bağlana bilər. Bu o deməkdir ki, eyni Telegram identifikatoru ilə sonsuz sayda hesab yaratmaq mümkün deyil.

Bundan sonra istifadəçi tətbiqə daxil olur və əsas dashboard açılır. Əsas dashboard bizim layihənin ən vacib hissəsidir. Burada istifadəçi cihaz sayını, açıq izlənən portları, risk score-u və Telegram statusunu görə bilir. Ən vacib məqamlardan biri budur ki, bu panel statik deyil, real vaxtda yenilənir. Məsələn, əgər istifadəçi portları bağlayırsa, yuxarı paneldəki `Open Ports` və `Risk` göstəriciləri dərhal dəyişir. Bu da istifadəçiyə sistemin hazırkı vəziyyətini canlı şəkildə izləmək imkanı verir.

Port skanı hissəsində biz izlənən TCP portlar üçün Nmap istifadə etmişik. Tətbiq yalnız “açıq portları göstərmək”lə kifayətlənmir. O həm də neçə portun yoxlandığını, neçə portun açıq, bağlı və filtered olduğunu xülasə şəklində göstərir. Bu vacibdir, çünki istifadəçi nəticəyə baxanda tətbiqin həqiqətən bütün izlənən portları yoxladığını görür və “yalnız 2-3 portu göstərdi, bəlkə qalanlarını skan etmədi” kimi bir yanlış təəssürat yaranmır.

Risk analizi hissəsində isə ayrıca bir məntiq var. Məsələn SMB, RDP, FTP, Telnet və bəzi digər xidmətlər daha riskli hesab olunur. Tətbiq bu portları müəyyən edir, onları riskli kimi qeyd edir və nəticəni istifadəçiyə daha aydın göstərir. Beləliklə, istifadəçi təkcə “port açıqdır” məlumatını almır, həm də “bu niyə risklidir?” sualının cavabını alır.

AutoSOC AI-nin güclü tərəflərindən biri odur ki, bu layihə yalnız monitorinq aləti deyil. İstifadəçi portları tətbiqin içindən açıb bağlaya bilir. Bunun üçün Windows firewall qaydaları tətbiq olunur. Yəni bizim həll passiv deyil, aktiv reaksiyanı da dəstəkləyir. Bu, hackathon layihəsi üçün vacib üstünlükdür, çünki biz təkcə problemi göstərmirik, həm də həll mexanizmi təqdim edirik.

Layihənin digər vacib hissəsi Telegram inteqrasiyasıdır. Biz bunu sadəcə əlavə funksiya kimi yox, əsas istifadəçi axınının bir hissəsi kimi qurmuşuq. İstifadəçi botla əlaqə yaradır, hesabını bağlayır və bundan sonra skan nəticələri, təhlükə bildirişləri və port məlumatları birbaşa onun Telegram çatına göndərilir. Bu o deməkdir ki, istifadəçi tətbiqin qarşısında olmasa belə, yenə də vacib məlumatları ala bilir. Xüsusilə kiçik komandalar üçün bu çox rahatdır, çünki hər kəs onsuz da Telegram istifadə edir.

Bundan əlavə, biz layihəyə AI qatını da əlavə etmişik. AI köməkçisi istifadəçiyə skan nəticələrini izah edir, risklərin mənasını sadə dillə açıqlayır və remediation təklifləri verir. Bu hissə xüsusilə texniki olmayan istifadəçilər üçün əhəmiyyətlidir. Çünki kibertəhlükəsizlik alətləri çox vaxt məlumat verir, amma həmin məlumatın nə demək olduğunu istifadəçi başa düşmür. Bizim tətbiq isə istifadəçiyə “nə baş verdi?” və “indi nə etməliyəm?” suallarına cavab verməyə çalışır.

Layihənin texniki tərəfinə qısa baxsaq, interfeys üçün CustomTkinter istifadə etmişik. Şəbəkə skanı üçün Nmap, monitorinq üçün Scapy əsaslı guard məntiqi, məlumatların saxlanması üçün SQLite, bildirişlər üçün Telegram Bot API və paketləmə üçün PyInstaller istifadə olunub. Bu seçimlər layihəni həm praktik, həm də hackathon mühitində nümayiş etdirmək üçün əlverişli edir.

İndi layihənin dəyərini daha aydın göstərmək üçün qısa şəkildə fərqimizi vurğulamaq istəyirəm. Birincisi, biz kibertəhlükəsizlik funksiyasını sadə UI ilə təqdim edirik. İkincisi, Telegram inteqrasiyasını birbaşa istifadəçi hesabı səviyyəsində qurmuşuq. Üçüncüsü, dashboard göstəriciləri real vaxtda dəyişir. Dördüncüsü, tətbiq yalnız analiz etmir, əməliyyat da aparır. Beşincisi isə AI izah qatı layihəni daha əlçatan edir.

Əgər demo ssenarisindən danışsaq, onu çox rahat qurmaq olar. Əvvəlcə login və qeydiyyat pəncərəsini göstəririk. Sonra Telegram botda `/start` komandası ilə Chat ID əldə edirik. Daha sonra həmin Chat ID ilə yeni istifadəçi yaradırıq. Sonra tətbiqə daxil olub skan başladırıq. Dashboard-da cihazları, portları və riskləri göstəririk. Daha sonra eyni nəticənin Telegram-a göndərildiyini göstəririk. Son addım kimi isə portları bağlayıb yuxarı panelin real vaxtda necə dəyişdiyini nümayiş etdiririk. Bu demo həm texniki gücü, həm də istifadəçi dəyərini çox aydın göstərir.

Gələcək inkişaf istiqamətləri də var. Məsələn, daha geniş şəbəkə skanı, daha inkişaf etmiş threat intelligence, report export, mərkəzləşdirilmiş dashboard və tətbiqdən ayrı işləyən standalone bot servisi əlavə edilə bilər. Amma hazırkı mərhələdə belə AutoSOC AI artıq işlək, nümayiş oluna bilən və real problemi hədəfləyən bir həlldir.

Sonda qısa olaraq deyə bilərəm ki, AutoSOC AI bizim tərəfimizdən hazırlanmış yüngül, praktik və istifadəçi yönümlü kibertəhlükəsizlik həllidir. Biz istəyirik ki, kibertəhlükəsizlik yalnız ekspertlər üçün deyil, daha geniş istifadəçi qrupu üçün də əlçatan olsun. AutoSOC AI bu istiqamətdə sadə, anlaşılan və operativ bir addımdır.

Diqqətinizə görə təşəkkür edirəm.
