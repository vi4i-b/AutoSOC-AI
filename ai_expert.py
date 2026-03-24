class AISecurityExpert:
    def __init__(self):
        # База знаний имитации ИИ (Knowledge Base)
        self.knowledge_base = {
            "Windows": {
                445: "⚠️ SMB Təhlükəsi! WannaCry kimi viruslardan qorunmaq üçün PowerShell-də 'Set-SmbServerConfiguration -EnableSMB1Protocol $false' əmrini icra edərək SMBv1-i söndürün.",
                3389: "⚠️ RDP (Uzaqdan Masaüstü) açıqdır! Brute-force hücumlarından qanmaq üçün NLA (Network Level Authentication) aktivləşdirin və parolu mürəkkəbləşdirin.",
                135: "⚠️ RPC boşluğu! Bu port xarici şəbəkə üçün bağlanmalıdır, əks halda sistem məlumatları sızdıra bilər."
            },
            "Linux": {
                22: "⚠️ SSH girişi aşkarlandı! Təhlükəsizlik üçün '/etc/ssh/sshd_config' faylında 'PasswordAuthentication no' edərək yalnız SSH Key ilə girişi saxlayın.",
                80: "⚠️ HTTP (Şifrələnməmiş trafik)! Məlumatların oğurlanmaması üçün SSL sertifikatı (HTTPS) quraşdırın və WAF (Web Application Firewall) aktiv edin.",
                21: "⚠️ FTP Təhlükəsi! FTP məlumatları şifrələmir. Bunun əvəzinə SFTP və ya FTPS istifadə etməyiniz tövsiyə olunur."
            },
            "Network Device": {
                80: "⚠️ Admin Panel Açıqdır! Router və ya Switch-in idarəetmə panelini xarici internetə bağlayın və default (zavod) parolu daxili idarəetmə interfeysində dəyişin.",
                23: "⚠️ Telnet Təhlükəsi! Telnet şifrələri açıq şəkildə ötürür. Təcili olaraq Telnet-i söndürüb SSH-a keçid edin.",
                554: "⚠️ RTSP (Kamera axını)! IP kameranızın yayımı şifrəsiz ola bilər. Giriş üçün mütləq güclü autentifikasiya tətbiq edin."
            }
        }

    def generate_instruction(self, device_type, port, service):
        """
        ИИ анализирует тип устройства и порт, чтобы выдать точную инструкцию.
        """
        # Определяем группу устройства на основе вендора (Fingerprinting)
        vendor = device_type.lower()

        if "microsoft" in vendor or "windows" in vendor:
            group = "Windows"
        elif "ubuntu" in vendor or "linux" in vendor or "debian" in vendor:
            group = "Linux"
        elif "tp-link" in vendor or "asus" in vendor or "cisco" in vendor or "huawei" in vendor:
            group = "Network Device"
        else:
            group = "Unknown"

        # Ищем специфический совет в базе
        if group in self.knowledge_base and port in self.knowledge_base[group]:
            return self.knowledge_base[group][port]

        # Если порт неизвестен, даем общий совет на основе сервиса
        return f"📍 [Təlimat]: {service} xidməti (Port {port}) risk yarada bilər. Əgər bu portdan istifadə etmirsinizsə, Firewall vasitəsilə onu qapatmağınız və sistem yeniləmələrini yoxlamağınız tövsiyə olunur."


# Тестовый запуск модуля
if __name__ == "__main__":
    expert = AISecurityExpert()
    print(expert.generate_instruction("Microsoft Corporation", 445, "microsoft-ds"))
    print(expert.generate_instruction("TP-Link", 23, "telnet"))