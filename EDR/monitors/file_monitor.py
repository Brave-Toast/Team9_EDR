import os
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .base_monitor import BaseMonitor
from multiprocessing import Queue
from multiprocessing.synchronize import Event

class FileMonitor(BaseMonitor):
    def get_name(self):
        return "file_integrity"

    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event, threat_bus: Queue, monitor_queue: Queue):
        super().__init__(agent_config, log_queue, shutdown_event, threat_bus, monitor_queue)
        self.observer = None
        rules = self.config.get("detection_rules", {})
        self.web_attack_patterns = [
            re.compile(p, re.IGNORECASE) for p in rules.get("web_attack_patterns", [])
        ]

    def start(self):
        """Initializes and starts the file system observer in a background thread."""
        if not self.monitor_config.get("enabled"):
            self.log_alert("LIFECYCLE", "Monitor is disabled.", "info")
            return

        self.observer = Observer()
        event_handler = _FileChangeHandler(self, self.web_attack_patterns)
        
        paths_to_monitor = self.monitor_config.get("paths", [])
        if not paths_to_monitor:
            self.log_alert("CONFIG", "Enabled but no paths are configured.", "warning")
            return

        for path in paths_to_monitor:
            if os.path.exists(path):
                self.observer.schedule(event_handler, path, recursive=True)
                self.log_alert("LIFECYCLE", f"Started monitoring directory: {path}", "info")
            else:
                self.log_alert("CONFIG", f"Directory not found, cannot monitor: {path}", "warning")
        
        if self.observer.emitters:
            self.observer.start()

    def stop(self):
        """Stops the file system observer."""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            self.log_alert("LIFECYCLE", "Monitor stopped.", "info")

    def run(self):
        """The file monitor runs in a background thread, so this method does nothing in the main loop."""



class _FileChangeHandler(FileSystemEventHandler):
    """Handles file system events and forwards them to the agent's logger."""
    def __init__(self, monitor_instance: FileMonitor, suspicious_patterns: list):
        self.monitor = monitor_instance
        self.suspicious_patterns = suspicious_patterns

    def on_created(self, event):
        """Called when a file or directory is created."""
        if event.is_directory:
            self.monitor.log_alert("DIRECTORY", f"Directory Created: {event.src_path}", "info")
        else:
            # For files, scan content for threats, then log creation.
            alerted = self._scan_file_content(event.src_path)
            if not alerted:
                self.monitor.log_alert("FILE", f"File Created: {event.src_path}", "info")

    def on_deleted(self, event):
        """Called when a file or directory is deleted."""
        if event.is_directory:
            self.monitor.log_alert("DIRECTORY", f"Directory Deleted: {event.src_path}", "info")
        else:
            self.monitor.log_alert("FILE", f"File Deleted: {event.src_path}", "info")

    def on_modified(self, event):
        """Called when a file is modified. This is not triggered for directories."""
        if not event.is_directory:
            # Scan content on modification, which is a high-risk event.
            alerted = self._scan_file_content(event.src_path)
            if not alerted:
                self.monitor.log_alert("FILE", f"File Modified: {event.src_path}", "info")

    def on_moved(self, event):
        """Called when a file or directory is moved or renamed."""
        subject_type = "Directory" if event.is_directory else "File"
        self.monitor.log_alert(
            subject_type.upper(),
            f"{subject_type} Moved/Renamed: from {event.src_path} to {event.dest_path}",
            "info"
        )

    def _scan_file_content(self, file_path: str) -> bool:
        """Scans file content and returns True if an alert was logged."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024 * 1024)  # Read first 1MB
                for pattern in self.suspicious_patterns:
                    if pattern.search(content):
                        self.monitor.log_alert(
                            "FILE-CONTENT",
                            f"Suspicious content found in {file_path}. Pattern: {pattern.pattern}"
                        )
                        return True
        except (FileNotFoundError, PermissionError):
            pass
        except IOError as e:
            self.monitor.log_alert("ERROR", f"Could not scan file {file_path}: {e}", "error")
        return False
