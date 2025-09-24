import os
import re
from datetime import datetime, timedelta
from collections import defaultdict
from monitors.base_monitor import BaseMonitor
from multiprocessing import Queue
from multiprocessing.synchronize import Event

class SSHMonitor(BaseMonitor):
    def get_name(self):
        return "ssh_monitoring"

    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event, threat_bus: Queue, monitor_queue: Queue):
        super().__init__(agent_config, log_queue, shutdown_event, threat_bus, monitor_queue)
        self.fail_tracker = defaultdict(list)
        self.log_inode = None
        self.log_pos = 0

    def run(self):
        if not self.monitor_config.get("enabled"):
            return
        
        while not self.shutdown_event.is_set():
            # Check for incoming threat intel messages at the start of each cycle
            self._check_for_intel()

            log_path = self.monitor_config.get("log_path")
            if not log_path:
                self.log_alert("ERROR", "SSH monitor is missing 'log_path' in config.", "error")
                break # Exit the loop if config is missing

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
                # This can happen normally during log rotation, so we don't spam errors
                pass
            except OSError as e:
                self.log_alert("ERROR", f"Error reading log: {e}", "error")

            self._analyze_failures()
            
            # Wait for the specified interval or until shutdown is signaled
            self.shutdown_event.wait(self.interval)

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
                    severity="high",
                    details={"remote_address": ip},
                    action="block_ip"
                )
                del self.fail_tracker[ip]
            else:
                self.fail_tracker[ip] = recent_attempts
