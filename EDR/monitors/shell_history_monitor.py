import os
import re
import time
from monitors.base_monitor import BaseMonitor
from multiprocessing import Queue
from multiprocessing.synchronize import Event

class ShellHistoryMonitor(BaseMonitor):
    def get_name(self):
        return "shell_history_monitoring"

    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event, threat_bus: Queue, monitor_queue: Queue):
        super().__init__(agent_config, log_queue, shutdown_event, threat_bus, monitor_queue)
        self.history_files = self._discover_history_files()
        self.file_trackers = {f: {"inode": None, "pos": 0} for f in self.history_files}
        rules = self.config.get("detection_rules", {})
        self.suspicious_command_patterns = [
            re.compile(p) for p in rules.get("suspicious_commands", [])
        ]

    def _discover_history_files(self) -> list:
        """Finds shell history files for all users."""
        history_files = []
        # Common history file names
        common_files = [".bash_history", ".zsh_history", ".history"]
        
        # Search in home directories
        try:
            for entry in os.scandir("/home"):
                if entry.is_dir():
                    for history_file in common_files:
                        path = os.path.join(entry.path, history_file)
                        if os.path.exists(path):
                            history_files.append(path)
            # Add root's history file
            for history_file in common_files:
                path = os.path.join("/root", history_file)
                if os.path.exists(path):
                    history_files.append(path)
        except OSError as e:
            self.log_alert("ERROR", f"Could not discover shell history files: {e}", "error")
            
        return history_files

    def run(self):
        if not self.monitor_config.get("enabled"):
            return

        self.log_alert("LIFECYCLE", f"Starting shell history monitor. Found {len(self.history_files)} history files.", "info")

        while not self.shutdown_event.is_set():
            self._check_for_intel()
            
            for file_path in self.history_files:
                self._tail_file(file_path)

            self.shutdown_event.wait(self.interval)

    def _tail_file(self, file_path: str):
        """Tails a single shell history file."""
        tracker = self.file_trackers[file_path]
        try:
            current_inode = os.stat(file_path).st_ino
            if tracker["inode"] is None:
                tracker["inode"] = current_inode
            elif current_inode != tracker["inode"]:
                self.log_alert("LIFECYCLE", f"Shell history file {file_path} rotated. Resetting.", "info")
                tracker["inode"] = current_inode
                tracker["pos"] = 0

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(tracker["pos"])
                for line in f:
                    self._analyze_line(line.strip(), file_path)
                tracker["pos"] = f.tell()

        except FileNotFoundError:
            pass  # File might not exist yet or was deleted
        except OSError as e:
            self.log_alert("ERROR", f"Error reading shell history file {file_path}: {e}", "error")

    def _analyze_line(self, line: str, file_path: str):
        """Analyzes a single command for suspicious patterns."""
        if not line:
            return

        for pattern in self.suspicious_command_patterns:
            if pattern.search(line):
                user = os.path.basename(os.path.dirname(file_path))
                details = {
                    "user": user,
                    "file_path": file_path,
                    "command": line,
                    "pattern": pattern.pattern
                }
                self.log_alert(
                    "SUSPICIOUS-COMMAND",
                    f"Suspicious command executed by user '{user}': {line}",
                    severity="high",
                    details=details
                )
                # Publish this event to the bus
                self.publish_threat_intel("SUSPICIOUS_COMMAND_DETECTED", data=details)
                break
