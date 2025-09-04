import os
import re
from datetime import datetime, timedelta
from collections import defaultdict
from .base_monitor import BaseMonitor

class SSHMonitor(BaseMonitor):
    def get_name(self):
        return "ssh_monitoring"

    def __init__(self, agent_config, log_queue, shutdown_event):
        super().__init__(agent_config, log_queue, shutdown_event)
        self.fail_tracker = defaultdict(list)
        self.log_inode = None
        self.log_pos = 0

    def run(self):
        if not self.monitor_config.get("enabled"):
            return
        
        log_path = self.monitor_config.get("log_path")
        if not log_path:
            return

        try:
            current_inode = os.stat(log_path).st_ino
            if self.log_inode is None:
                self.log_inode = current_inode
            elif current_inode != self.log_inode:
                self.log_alert("LIFECYCLE", f"Log file {log_path} rotated. Resetting.", "info")
                self.log_inode = current_inode
                self.log_pos = 0
                self.fail_tracker.clear()

            with open(log_path, encoding="utf-8", errors="ignore") as log:
                log.seek(self.log_pos)
                for line in log:
                    match = re.search(r"Failed password for(?: invalid user)?\s+.*? from (\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        self.fail_tracker[match.group(1)].append(datetime.now())
                self.log_pos = log.tell()

        except FileNotFoundError:
            if self.log_pos == 0:
                self.log_alert("ERROR", f"Log file not found: {log_path}", "error")
            return
        except OSError as e:
            self.log_alert("ERROR", f"Error reading log: {e}", "error")
            return

        self._analyze_failures()

    def _analyze_failures(self):
        threshold = self.monitor_config.get("fail_threshold", 5)
        window = timedelta(minutes=self.monitor_config.get("time_window_minutes", 5))
        now = datetime.now()

        for ip, timestamps in list(self.fail_tracker.items()):
            recent_attempts = [t for t in timestamps if now - t < window]
            if len(recent_attempts) >= threshold:
                self.log_alert(
                    "SSH-BRUTE-FORCE",
                    f"Potential attack from IP: {ip}. "
                    f"Failed {len(recent_attempts)} times in the last {window.seconds / 60} minutes.",
                    severity="high", # <-- Assign a severity
                    details={"source_ip": ip} # <-- Add structured details
                )
                del self.fail_tracker[ip]
            else:
                self.fail_tracker[ip] = recent_attempts