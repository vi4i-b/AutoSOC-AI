import os
import re
import threading
import time
from collections import defaultdict, deque

try:
    import pywintypes
    import win32evtlog
    import win32evtlogutil
except ImportError:
    pywintypes = None
    win32evtlog = None
    win32evtlogutil = None


IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


class WindowsLogListener:
    def __init__(
        self,
        on_detection,
        on_error=None,
        log_name="Security",
        event_id=4625,
        threshold=5,
        window_seconds=10,
        poll_interval=1.0,
    ):
        self.on_detection = on_detection
        self.on_error = on_error
        self.log_name = log_name
        self.event_id = int(event_id)
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)
        self.poll_interval = float(poll_interval)

        self._thread = None
        self._stop_event = threading.Event()
        self._last_record_number = None
        self._failed_attempts = defaultdict(deque)
        self._cooldowns = {}

    @property
    def available(self):
        return os.name == "nt" and win32evtlog is not None

    def start(self):
        if self._thread and self._thread.is_alive():
            return True
        if not self.available:
            return False

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._listen_loop, name="AutoSOCLogListener", daemon=True)
        self._thread.start()
        return True

    def stop(self, timeout=2.0):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _listen_loop(self):
        while not self._stop_event.is_set():
            handle = None
            try:
                handle = win32evtlog.OpenEventLog(None, self.log_name)
                if self._last_record_number is None:
                    self._last_record_number = self._get_latest_record_number(handle)

                while not self._stop_event.is_set():
                    self._consume_new_events(handle)
                    self._expire_old_state()
                    self._stop_event.wait(self.poll_interval)
            except Exception as exc:
                self._emit_error(self._format_error(exc))
                self._stop_event.wait(max(self.poll_interval, 2.0))
            finally:
                if handle is not None:
                    try:
                        win32evtlog.CloseEventLog(handle)
                    except Exception:
                        pass

    def _consume_new_events(self, handle):
        oldest_record = win32evtlog.GetOldestEventLogRecord(handle)
        total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
        latest_record = oldest_record + total_records - 1 if total_records else oldest_record - 1

        if self._last_record_number is None:
            self._last_record_number = latest_record
            return

        if self._last_record_number < oldest_record - 1:
            self._last_record_number = oldest_record - 1

        next_record = self._last_record_number + 1
        if next_record > latest_record:
            return

        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ

        while next_record <= latest_record and not self._stop_event.is_set():
            events = win32evtlog.ReadEventLog(handle, flags, next_record)
            if not events:
                break

            for event in events:
                record_number = getattr(event, "RecordNumber", None)
                if record_number is not None:
                    if record_number <= self._last_record_number:
                        continue
                    self._last_record_number = record_number

                self._process_event(event)

            next_record = self._last_record_number + 1

    def _process_event(self, event):
        if (getattr(event, "EventID", 0) & 0xFFFF) != self.event_id:
            return

        source_ip = self._extract_source_ip(event)
        if not source_ip:
            return

        event_time = self._get_event_timestamp(event)
        attempts = self._failed_attempts[source_ip]
        attempts.append(event_time)
        self._trim_attempts(attempts, event_time)

        cooldown_until = self._cooldowns.get(source_ip, 0)
        if len(attempts) > self.threshold and event_time >= cooldown_until:
            self._cooldowns[source_ip] = event_time + self.window_seconds
            self.on_detection(
                {
                    "ip": source_ip,
                    "event_id": self.event_id,
                    "attempt_count": len(attempts),
                    "window_seconds": self.window_seconds,
                    "service": "SSH",
                }
            )

    def _expire_old_state(self):
        current_time = time.time()
        for ip, attempts in list(self._failed_attempts.items()):
            self._trim_attempts(attempts, current_time)
            if not attempts:
                self._failed_attempts.pop(ip, None)
        for ip, cooldown_until in list(self._cooldowns.items()):
            if cooldown_until < current_time:
                self._cooldowns.pop(ip, None)

    def _trim_attempts(self, attempts, current_time):
        cutoff = current_time - self.window_seconds
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

    def _extract_source_ip(self, event):
        inserts = list(getattr(event, "StringInserts", None) or [])
        candidate_indexes = (19, 20, 18)

        for index in candidate_indexes:
            if index < len(inserts):
                ip_address = self._find_ipv4(inserts[index])
                if ip_address:
                    return ip_address

        for value in inserts:
            ip_address = self._find_ipv4(value)
            if ip_address:
                return ip_address

        if win32evtlogutil is None:
            return None

        try:
            message = win32evtlogutil.SafeFormatMessage(event, self.log_name)
        except Exception:
            return None
        return self._find_ipv4(message)

    def _find_ipv4(self, value):
        if not value:
            return None
        match = IPV4_PATTERN.search(str(value))
        if not match:
            return None
        return match.group(0)

    def _get_event_timestamp(self, event):
        generated = getattr(event, "TimeGenerated", None)
        if generated is None:
            return time.time()

        try:
            return float(generated.timestamp())
        except Exception:
            try:
                return time.mktime(generated.timetuple())
            except Exception:
                return time.time()

    def _get_latest_record_number(self, handle):
        oldest_record = win32evtlog.GetOldestEventLogRecord(handle)
        total_records = win32evtlog.GetNumberOfEventLogRecords(handle)
        if not total_records:
            return oldest_record - 1
        return oldest_record + total_records - 1

    def _format_error(self, exc):
        error_code = None
        if pywintypes is not None and isinstance(exc, pywintypes.error):
            error_code = getattr(exc, "winerror", None)
            if error_code is None and exc.args:
                error_code = exc.args[0]

        if error_code == 1314:
            return "Windows log listener requires Administrator rights to read the Security log."

        return f"Windows log listener error: {exc}"

    def _emit_error(self, message):
        if not self.on_error:
            return
        self.on_error(message)
