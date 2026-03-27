import socket
import threading
from datetime import datetime


class PortCanary:
    DEFAULT_PORTS = [2222, 2323, 8023]

    def __init__(self, callback, listen_host="0.0.0.0", ports=None, alert_cooldown=8):
        self.callback = callback
        self.listen_host = listen_host
        self.ports = list(ports or self.DEFAULT_PORTS)
        self.alert_cooldown = int(alert_cooldown)
        self.is_running = False
        self.bound_ports = []
        self.failed_ports = {}
        self._listeners = {}
        self._lock = threading.Lock()
        self._last_alert = {}

    def start(self):
        if self.is_running:
            return self.status()

        self.is_running = True
        self.bound_ports = []
        self.failed_ports = {}

        for port in self.ports:
            try:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.listen_host, port))
                listener.listen(8)
                self._listeners[port] = listener
                self.bound_ports.append(port)
                threading.Thread(target=self._accept_loop, args=(port, listener), daemon=True).start()
            except OSError as exc:
                self.failed_ports[port] = str(exc)

        if not self.bound_ports:
            self.is_running = False

        return self.status()

    def stop(self):
        self.is_running = False
        listeners = list(self._listeners.items())
        self._listeners = {}
        for _, listener in listeners:
            try:
                listener.close()
            except OSError:
                pass
        self.bound_ports = []
        return self.status()

    def self_test(self, host="127.0.0.1", port=None, timeout=2):
        target_port = port or (self.bound_ports[0] if self.bound_ports else None)
        if not target_port:
            raise RuntimeError("Port Canary has no active listener for self-test.")

        with socket.create_connection((host, target_port), timeout=timeout) as client:
            client.sendall(b"AUTOSOC_CANARY_TEST")
        return target_port

    def status(self):
        return {
            "running": self.is_running,
            "bound_ports": list(self.bound_ports),
            "failed_ports": dict(self.failed_ports),
        }

    def _accept_loop(self, port, listener):
        while self.is_running:
            try:
                client, address = listener.accept()
            except OSError:
                break

            try:
                client.settimeout(0.3)
                try:
                    client.recv(128)
                except OSError:
                    pass
            finally:
                try:
                    client.close()
                except OSError:
                    pass

            src_ip, src_port = address[0], address[1]
            if self._should_suppress(src_ip, port):
                continue

            self.callback(
                {
                    "timestamp": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
                    "port": port,
                    "source_ip": src_ip,
                    "source_port": src_port,
                    "is_local": src_ip in {"127.0.0.1", "::1"},
                }
            )

    def _should_suppress(self, src_ip, port):
        key = (src_ip, port)
        now = datetime.now().timestamp()
        with self._lock:
            last_seen = self._last_alert.get(key, 0)
            if now - last_seen < self.alert_cooldown:
                return True
            self._last_alert[key] = now
            return False
