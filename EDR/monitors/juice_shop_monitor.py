import logging
import time
import threading
import queue
import glob
import os
import re
import socket
from fnmatch import fnmatch
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .base_monitor import BaseMonitor
from multiprocessing import Queue
from multiprocessing.synchronize import Event

class JuiceShopMonitor(BaseMonitor):
    def get_name(self):
        return "juice_shop_monitoring"

    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event, threat_bus: Queue, monitor_queue: Queue):
        super().__init__(agent_config, log_queue, shutdown_event, threat_bus, monitor_queue)

        # Config for log location
        self.log_directory = self.monitor_config.get("log_directory")
        self.log_pattern = self.monitor_config.get("log_pattern")

        # Config for detection rules
        rules = self.config.get("detection_rules", {})
        self.web_attack_patterns = [
            re.compile(p, re.IGNORECASE) for p in rules.get("web_attack_patterns", [])
        ]

        # Config for error spike detection
        self.error_threshold = self.monitor_config.get("error_threshold", 10)
        self.error_time_window = timedelta(minutes=self.monitor_config.get("error_time_window_minutes", 1))
        self.error_tracker = []

        # Internal state for multithreaded tailing
        self._line_queue = queue.Queue()
        self._active_tails = set()
        self.observer = Observer()

        # State for tracking failed login attempts
        self.failed_login_tracker = {}
        self.failed_login_threshold = 5
        self.failed_login_window_seconds = 10
        self.blocked_ips = set()

    def run(self):
        if not self.monitor_config.get("enabled"):
            return

        if not all([self.log_directory, self.log_pattern]):
            self.log_alert("ERROR", "Juice Shop monitor is missing 'log_directory' or 'log_pattern' in config.", "error")
            return

        self.log_alert("LIFECYCLE", f"Starting Juice Shop monitor for directory: {self.log_directory}", "info")

        # Start a watchdog observer to find new log files
        # Make sure the directory exists before scheduling the observer. On
        # some platforms watchdog will raise if the watched path does not
        # exist which caused the monitor to crash with Errno 2.
        if not os.path.isdir(self.log_directory):
            self.log_alert(
                "CONFIG",
                f"Log directory not found, cannot start Juice Shop monitor: {self.log_directory}",
                "error",
            )
            return

        event_handler = self._LogFileHandler(self)
        try:
            self.observer.schedule(event_handler, self.log_directory, recursive=False)
            self.observer.start()
        except (FileNotFoundError, OSError) as e:
            self.log_alert("ERROR", f"Failed to start observer for {self.log_directory}: {e}", "error")
            return

        # Initial scan for existing log files
        self._initial_scan()

        try:
            last_spike_check_time = time.time()
            while not self.shutdown_event.is_set():
                try:
                    log_line = self._line_queue.get(timeout=1)
                    self._analyze_line(log_line)
                except queue.Empty:
                    # Periodically check for error spikes even if there are no new log lines
                    if time.time() - last_spike_check_time > 60:
                        self._analyze_error_spikes()
                        last_spike_check_time = time.time()
                    continue
        except (AttributeError, TypeError, ValueError) as e:
            logging.error("Juice Shop monitor encountered an unhandled exception: %s", e, exc_info=True)
        finally:
            self.log_alert("LIFECYCLE", "Juice Shop monitor shutting down.", "info")
            self.stop()

    def stop(self):
        """Cleanly stops the observer and tailing threads."""
        if self.observer.is_alive():
            self.observer.stop()
            self.observer.join()

    def _initial_scan(self):
        """Scans the directory on startup for existing logs to tail."""
        search_path = os.path.join(self.log_directory, self.log_pattern)
        for filepath in glob.glob(search_path):
            self.start_tailing_thread(filepath, seek_to_end=True)

    def start_tailing_thread(self, filepath, seek_to_end=False):
        """Starts a new thread to tail a specific log file if not already active."""
        if filepath in self._active_tails:
            return

        self.log_alert("LIFECYCLE", f"Starting to tail new log file: {filepath}", "info")
        self._active_tails.add(filepath)

        thread = threading.Thread(target=self._tail_file, args=(filepath, seek_to_end), daemon=True)
        thread.start()

    def _tail_file(self, filepath, seek_to_end):
        """Reads a file and puts new lines into the shared queue."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                if seek_to_end:
                    f.seek(0, 2)
                while not self.shutdown_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    self._line_queue.put(line.strip())
        except FileNotFoundError:
            self.log_alert("ERROR", f"Log file {filepath} was removed before it could be tailed.", "warning")
        except OSError as e:
            logging.error("Error tailing file %s: %s", filepath, e, exc_info=True)
        finally:
            if filepath in self._active_tails:
                self._active_tails.remove(filepath)
            self.log_alert("LIFECYCLE", f"Stopped tailing log file: {filepath}", "info")

    def _analyze_line(self, line):
        """Analyzes a single log line for suspicious patterns and errors."""
        # Check for web attack patterns and block immediately
        for pattern in self.web_attack_patterns:
            if pattern.search(line):
                self.log_alert(
                    "JUICE-SHOP-ATTACK",
                    f"Potential web attack detected. Pattern: '{pattern.pattern}'. Line: {line}"
                )
                
                # Extract IP address for immediate blocking
                ip_match = re.search(r'(?P<ip>(?:\:\:ffff\:)?\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group("ip")
                    # Normalize IP
                    if ip.startswith("::ffff:"):
                        ip = ip.split("::ffff:")[-1]
                    
                    # Block IP immediately on SQL injection detection
                    if ip not in self.blocked_ips:
                        alert = {
                            "@timestamp": datetime.utcnow().isoformat() + "Z",
                            "log": {"level": "info", "logger": "EDRAgent"},
                            "message": f"Blocking IP {ip} due to SQL injection attack detected.",
                            "ecs": {"version": "8.4"},
                            "event": {
                                "kind": "alert",
                                "category": "security",
                                "type": "sql-injection-blocked",
                                "module": "juice_shop_monitoring",
                                "severity": "high"
                            },
                            "action": "block_ip",
                            "host": {"hostname": socket.gethostname()},
                            "process": {"pid": os.getpid(), "name": "juice_shop_monitoring"},
                            "user": {"name": os.getenv("USER", "root")},
                            "details": {
                                "remote_address": ip,
                                "attack_type": "sql_injection",
                                "pattern_detected": pattern.pattern
                            },
                            "custom": {
                                "details": {
                                    "remote_address": ip,
                                    "attack_type": "sql_injection",
                                    "pattern_detected": pattern.pattern
                                }
                            }
                        }
                        self.log_queue.put(alert)
                        self.blocked_ips.add(ip)
                break

        # Track errors for spike detection
        if "error" in line.lower() or " 500 " in line:
            self.error_tracker.append(datetime.now())

        # Brute force detection and alert logic
        match = re.search(r'(?P<ip>(?:\:\:ffff\:)?\d+\.\d+\.\d+\.\d+) - - \[.*\] "POST /rest/user/login HTTP/1\.1" 401', line)
        if match:
            ip = match.group("ip")
            # Normalize IP
            if ip.startswith("::ffff:"):
                ip = ip.split("::ffff:")[-1]
            now = time.time()
            attempts = self.failed_login_tracker.setdefault(ip, [])
            attempts.append(now)
            # Remove attempts outside the window
            while attempts and now - attempts[0] > self.failed_login_window_seconds:
                attempts.pop(0)
            if len(attempts) >= self.failed_login_threshold and ip not in self.blocked_ips:
                alert = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "log": {"level": "warning", "logger": "JuiceShopMonitor"},
                    "message": f"Blocking IP {ip} due to {len(attempts)} failed login attempts in {self.failed_login_window_seconds} seconds.",
                    "ecs": {"version": "8.4"},
                    "event": {
                        "kind": "alert",
                        "category": "security",
                        "type": "brute-force-blocked",
                        "module": "juice_shop_monitoring",
                        "severity": "high"
                    },
                    "action": "block_ip",
                    "host": {"hostname": socket.gethostname()},
                    "process": {"pid": os.getpid(), "name": "juice_shop_monitoring"},
                    "user": {"name": os.getenv("USER", "root")},
                    "details": {
                        "remote_address": ip,
                        "failed_attempts": len(attempts),
                        "time_window_seconds": self.failed_login_window_seconds
                    },
                    "custom": {
                        "details": {
                            "remote_address": ip,
                            "failed_attempts": len(attempts),
                            "time_window_seconds": self.failed_login_window_seconds
                        }
                    }
                }
                self.log_queue.put(alert)
                self.blocked_ips.add(ip)

    def _analyze_error_spikes(self):
        """Checks the error tracker for a spike in errors."""
        now = datetime.now()
        # Filter out old errors
        self.error_tracker = [t for t in self.error_tracker if now - t < self.error_time_window]

        if len(self.error_tracker) >= self.error_threshold:
            self.log_alert(
                "JUICE-SHOP-ERROR-SPIKE",
                f"Error spike detected: {len(self.error_tracker)} errors in the last {self.error_time_window.seconds / 60} minute(s)."
            )
            # Reset tracker after alerting to prevent repeated alerts for the same spike
            self.error_tracker = []

    class _LogFileHandler(FileSystemEventHandler):
        """Watchdog handler to detect new log file creation."""
        def __init__(self, monitor_instance):
            self.monitor = monitor_instance

        def on_created(self, event):
            if not event.is_directory and fnmatch(os.path.basename(event.src_path), self.monitor.log_pattern):
                # When a new log file is created, start reading it from the beginning.
                self.monitor.start_tailing_thread(event.src_path, seek_to_end=False)