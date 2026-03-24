import socket
from collections import Counter
from scapy.all import sniff, IP
import threading
import time

class NetworkGuard:
    def __init__(self, callback_func):
        self.ip_counts = Counter()
        self.callback = callback_func
        self.threshold = 500  # Значение по умолчанию
        self.is_monitoring = False
        self.my_ip = socket.gethostbyname(socket.gethostname())

    def set_threshold(self, value):
        """Метод для динамического изменения порога"""
        self.threshold = int(value)
        print(f"DEBUG: New threshold set to {self.threshold}")

    def start_monitoring(self):
        self.is_monitoring = True
        threading.Thread(target=self._run_sniffer, daemon=True).start()
        threading.Thread(target=self._analyzer_loop, daemon=True).start()

    def _run_sniffer(self):
        sniff(filter="ip", prn=self._process_packet, stop_filter=lambda x: not self.is_monitoring)

    def _process_packet(self, pkt):
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            # Игнорируем себя, чтобы не было ложных срабатываний от собственного сканера
            if src_ip != self.my_ip:
                self.ip_counts[src_ip] += 1

    def _analyzer_loop(self):
        while self.is_monitoring:
            time.sleep(5)
            for ip, count in self.ip_counts.items():
                if count > self.threshold:
                    self._ai_mitigation(ip, count)
            self.ip_counts.clear()

    def _ai_mitigation(self, ip, count):
        reason = f"Həddindən artıq trafik: {count} paket/5san (Limit: {self.threshold})"
        cmd = f'netsh advfirewall firewall add rule name="AutoSOC_Block_{ip}" dir=in action=block remoteip={ip}'
        self.callback(ip, reason, cmd)

    def stop(self):
        self.is_monitoring = False