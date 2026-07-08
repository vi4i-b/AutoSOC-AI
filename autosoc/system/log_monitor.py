"""Failed-login (brute-force) monitoring.

A shared :class:`BruteForceTracker` implements the detection policy
(N failures from one IP inside a sliding window, with a cooldown), while the
platform listeners only extract failed-login events:

    Windows:  Security event log, Event ID 4625 (requires pywin32 + admin)
    Linux:    /var/log/auth.log — sshd "Failed password" and PAM
              "authentication failure" lines (requires read access, i.e.
              root or membership in the ``adm`` group on Ubuntu)

Use :func:`create_log_listener` to get the right listener for the platform.
"""

import os
import re
import threading
import time
from collections import defaultdict, deque

from autosoc.logging_setup import get_logger

try:
    import pywintypes
    import win32evtlog
    import win32evtlogutil
except ImportError:
    pywintypes = None
    win32evtlog = None
    win32evtlogutil = None

log = get_logger("system.log_monitor")

IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


class BruteForceTracker:
    """Sliding-window failure counter shared by all listeners."""

    def __init__(self, threshold=5, window_seconds=10):
        self.threshold = int(threshold)
        self.window_seconds = int(window_seconds)
        self._failed_attempts = defaultdict(deque)
        self._cooldowns = {}

    def register_failure(self, source_ip, event_time=None):
        """Record one failure; returns a detection dict when the threshold trips."""
        event_time = event_time if event_time is not None else time.time()
        attempts = self._failed_attempts[source_ip]
        attempts.append(event_time)
        self._trim(attempts, event_time)

        cooldown_until = self._cooldowns.get(source_ip, 0)
        if len(attempts) > self.threshold and event_time >= cooldown_until:
            self._cooldowns[source_ip] = event_time + self.window_seconds
            return {
                "ip": source_ip,
                "attempt_count": len(attempts),
                "window_seconds": self.window_seconds,
            }
        return None

    def expire_old_state(self, current_time=None):
        current_time = current_time if current_time is not None else time.time()
        for ip, attempts in list(self._failed_attempts.items()):
            self._trim(attempts, current_time)
            if not attempts:
                self._failed_attempts.pop(ip, None)
        for ip, cooldown_until in list(self._cooldowns.items()):
            if cooldown_until < current_time:
                self._cooldowns.pop(ip, None)

    def _trim(self, attempts, current_time):
        cutoff = current_time - self.window_seconds
        while attempts and attempts[0] < cutoff:
            attempts.popleft()


class _BaseLogListener:
    """Common thread lifecycle for the platform listeners."""

    service_name = "Logon"

    def __init__(self, on_detection, on_error=None, threshold=5, window_seconds=10, poll_interval=1.0):
        self.on_detection = on_detection
        self.on_error = on_error
        self.poll_interval = float(poll_interval)
        self.tracker = BruteForceTracker(threshold=threshold, window_seconds=window_seconds)
        self._thread = None
        self._stop_event = threading.Event()

    @property
    def available(self) -> bool:
        raise NotImplementedError

    def start(self) -> bool:
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
        raise NotImplementedError

    def _register_failure(self, source_ip, event_time=None):
        detection = self.tracker.register_failure(source_ip, event_time)
        if detection:
            detection["service"] = self.service_name
            self.on_detection(detection)

    def _emit_error(self, message):
        log.warning("%s", message)
        if self.on_error:
            self.on_error(message)


class WindowsLogListener(_BaseLogListener):
    """Watches the Windows Security event log for failed logons (4625)."""

    service_name = "Windows Logon"

    def __init__(self, on_detection, on_error=None, log_name="Security", event_id=4625, **kwargs):
        super().__init__(on_detection, on_error=on_error, **kwargs)
        self.log_name = log_name
        self.event_id = int(event_id)
        self._last_record_number = None

    @property
    def available(self):
        return os.name == "nt" and win32evtlog is not None

    def _listen_loop(self):
        while not self._stop_event.is_set():
            handle = None
            try:
                handle = win32evtlog.OpenEventLog(None, self.log_name)
                if self._last_record_number is None:
                    self._last_record_number = self._get_latest_record_number(handle)

                while not self._stop_event.is_set():
                    self._consume_new_events(handle)
                    self.tracker.expire_old_state()
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

        self._register_failure(source_ip, self._get_event_timestamp(event))

    def _extract_source_ip(self, event):
        inserts = list(getattr(event, "StringInserts", None) or [])
        candidate_indexes = (19, 20, 18)

        for index in candidate_indexes:
            if index < len(inserts):
                ip_address = _find_ipv4(inserts[index])
                if ip_address:
                    return ip_address

        for value in inserts:
            ip_address = _find_ipv4(value)
            if ip_address:
                return ip_address

        if win32evtlogutil is None:
            return None

        try:
            message = win32evtlogutil.SafeFormatMessage(event, self.log_name)
        except Exception:
            return None
        return _find_ipv4(message)

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


class LinuxAuthLogListener(_BaseLogListener):
    """Tails the auth log for failed SSH/PAM logins on Linux."""

    service_name = "SSH/PAM Logon"

    LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")

    FAILURE_PATTERNS = (
        re.compile(r"Failed password for .+ from (?P<ip>\S+)"),
        re.compile(r"Invalid user .+ from (?P<ip>\S+)"),
        re.compile(r"authentication failure;.*rhost=(?P<ip>[\w.:-]+)"),
    )

    def __init__(self, on_detection, on_error=None, log_path=None, **kwargs):
        super().__init__(on_detection, on_error=on_error, **kwargs)
        self.log_path = log_path or self._detect_log_path()
        self._error_reported = False

    def _detect_log_path(self):
        for candidate in self.LOG_CANDIDATES:
            if os.path.isfile(candidate):
                return candidate
        return None

    @property
    def available(self):
        return os.name == "posix" and bool(self.log_path)

    def _listen_loop(self):
        while not self._stop_event.is_set():
            try:
                with open(self.log_path, "r", encoding="utf-8", errors="replace") as handle:
                    self._error_reported = False
                    handle.seek(0, os.SEEK_END)
                    inode = os.fstat(handle.fileno()).st_ino

                    while not self._stop_event.is_set():
                        line = handle.readline()
                        if line:
                            self._process_line(line)
                            continue

                        self.tracker.expire_old_state()
                        self._stop_event.wait(self.poll_interval)
                        if self._rotated(inode):
                            break
            except PermissionError:
                if not self._error_reported:
                    self._error_reported = True
                    self._emit_error(
                        f"Cannot read {self.log_path}. Run as root or add the user to the 'adm' group "
                        "to enable brute-force monitoring."
                    )
                self._stop_event.wait(30)
            except OSError as exc:
                self._emit_error(f"Auth log listener error: {exc}")
                self._stop_event.wait(5)

    def _rotated(self, previous_inode):
        try:
            return os.stat(self.log_path).st_ino != previous_inode
        except OSError:
            return True

    def _process_line(self, line):
        for pattern in self.FAILURE_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            ip_address = _find_ipv4(match.group("ip"))
            if ip_address:
                self._register_failure(ip_address)
            return


def create_log_listener(on_detection, on_error=None, threshold=5, window_seconds=10, poll_interval=1.0):
    """Failed-login listener for the current platform, or None."""
    kwargs = {
        "on_error": on_error,
        "threshold": threshold,
        "window_seconds": window_seconds,
        "poll_interval": poll_interval,
    }
    if os.name == "nt":
        return WindowsLogListener(on_detection, **kwargs)
    if os.name == "posix":
        return LinuxAuthLogListener(on_detection, **kwargs)
    return None


def _find_ipv4(value):
    if not value:
        return None
    match = IPV4_PATTERN.search(str(value))
    if not match:
        return None
    return match.group(0)
