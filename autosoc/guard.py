"""Traffic-spike (DDoS) monitoring via packet sniffing.

Counts inbound packets per source IP over 5-second windows and fires the
callback when a source exceeds the threshold. Sniffing needs libpcap/Npcap
and elevated privileges; when scapy is unavailable the guard degrades
gracefully and reports why.
"""

import threading
import time
from collections import Counter

from autosoc.logging_setup import get_logger
from autosoc.system.netinfo import local_ip_addresses

try:
    from scapy.all import IP, sniff

    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR = ""
except Exception as exc:  # scapy raises more than ImportError on broken setups
    IP = None
    sniff = None
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(exc)

log = get_logger("guard")

ANALYSIS_INTERVAL_SECONDS = 5


class NetworkGuard:
    def __init__(self, callback_func, threshold=500):
        self.ip_counts = Counter()
        self.callback = callback_func
        self.threshold = int(threshold)
        self.is_monitoring = False
        self.local_ips = set()

    @property
    def available(self) -> bool:
        return SCAPY_AVAILABLE

    @property
    def unavailable_reason(self) -> str:
        if SCAPY_AVAILABLE:
            return ""
        return f"Packet sniffing unavailable (scapy/libpcap): {SCAPY_IMPORT_ERROR}"

    def set_threshold(self, value):
        self.threshold = int(value)

    def start_monitoring(self) -> bool:
        if not SCAPY_AVAILABLE:
            log.warning("%s", self.unavailable_reason)
            return False
        if self.is_monitoring:
            return True

        self.is_monitoring = True
        # Ignore our own traffic so scans do not trigger false positives.
        self.local_ips = local_ip_addresses()
        threading.Thread(target=self._run_sniffer, daemon=True).start()
        threading.Thread(target=self._analyzer_loop, daemon=True).start()
        return True

    def stop(self):
        self.is_monitoring = False

    def _run_sniffer(self):
        try:
            sniff(filter="ip", prn=self._process_packet, stop_filter=lambda _pkt: not self.is_monitoring)
        except Exception as exc:
            self.is_monitoring = False
            log.error("Sniffer stopped: %s", exc)

    def _process_packet(self, pkt):
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            if src_ip not in self.local_ips:
                self.ip_counts[src_ip] += 1

    def _analyzer_loop(self):
        while self.is_monitoring:
            time.sleep(ANALYSIS_INTERVAL_SECONDS)
            for ip, count in self.ip_counts.items():
                if count > self.threshold:
                    reason = (
                        f"Excessive traffic: {count} packets/{ANALYSIS_INTERVAL_SECONDS}s "
                        f"(limit: {self.threshold})"
                    )
                    self.callback(ip, reason)
            self.ip_counts.clear()
