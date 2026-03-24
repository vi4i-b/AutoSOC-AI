
class RiskAnalyzer:
    def __init__(self):
        # База знаний об угрозах (можно расширять)
        self.threats = {
            21: {"service": "FTP", "risk": "Kritik", "desc": "Şifrələnməmiş fayl ötürülməsi. Məlumatlar oğurlana bilər."},
            23: {"service": "Telnet", "risk": "Kritik", "desc": "Təhlükəli idarəetmə protokolu. SSH-a keçid tövsiyə olunur."},
            80: {"service": "HTTP", "risk": "Orta", "desc": "Şifrələnməmiş veb trafik. HTTPS istifadə edin."},
            139: {"service": "NetBIOS", "risk": "Yüksək", "desc": "Köhnə şəbəkə protokolu. Hücumçular məlumat toplaya bilər."},
            445: {"service": "SMB", "risk": "Yüksək", "desc": "WannaCry və digər viruslar üçün əsas hədəf. Girişi məhdudlaşdırın."},
            3389: {"service": "RDP", "risk": "Yüksək", "desc": "Uzaqdan masaüstü girişi. Brute-force hücumlarına meyyllidir."}
        }

    def analyze(self, ports_list):
        findings = []
        for p in ports_list:
            port_num = int(p['port'])
            if port_num in self.threats:
                findings.append({
                    "port": port_num,
                    "info": self.threats[port_num]
                })
        return findings