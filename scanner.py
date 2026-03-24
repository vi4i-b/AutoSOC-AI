import nmap


class NetworkScanner:
    def __init__(self):
        # Инициализируем порт-сканер Nmap
        self.nm = nmap.PortScanner()

    def scan_network(self, target):
        """
        Сканирует указанный IP или диапазон (например, 192.168.1.1/24).
        Возвращает список устройств с открытыми портами и данными о вендоре.
        """
        try:
            # -F (Fast mode) - сканируем самые популярные порты для скорости
            # -O (OS detection) требует прав админа, поэтому используем стандартный скан
            self.nm.scan(hosts=target, arguments='-F')

            scan_results = []

            for host in self.nm.all_hosts():
                # Получаем данные о производителе (vendor)
                # Nmap берет их из базы данных соответствия MAC-адресов
                vendor_data = self.nm[host].get('vendor', {})

                # Формируем структуру данных для одного устройства
                device_info = {
                    "ip": host,
                    "status": self.nm[host].state(),
                    "vendor": vendor_data,  # Словарь типа {'00:11:22...': 'TP-Link'}
                    "ports": []
                }

                # Собираем все открытые TCP порты
                if 'tcp' in self.nm[host]:
                    for port in self.nm[host]['tcp']:
                        port_data = self.nm[host]['tcp'][port]
                        if port_data['state'] == 'open':
                            device_info["ports"].append({
                                "port": port,
                                "name": port_data['name'],
                                "product": port_data.get('product', ''),
                                "version": port_data.get('version', '')
                            })

                scan_results.append(device_info)

            return scan_results

        except Exception as e:
            print(f"Skaner xətası: {e}")
            return []


if __name__ == "__main__":
    # Тестовый запуск модуля
    scanner = NetworkScanner()
    print("Skan başlayır...")
    results = scanner.scan_network("127.0.0.1")
    for res in results:
        print(f"IP: {res['ip']}, Vendor: {res['vendor']}")
