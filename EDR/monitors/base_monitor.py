import time
import os
import socket
import psutil
import queue
from multiprocessing import Queue
from multiprocessing.synchronize import Event

class BaseMonitor:
    """
    The base class for all monitoring plugins, designed to be run in a separate process.
    """
    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event, threat_bus: Queue, monitor_queue: Queue):
        self.config = agent_config
        self.log_queue = log_queue
        self.shutdown_event = shutdown_event
        self.threat_bus = threat_bus
        self.monitor_queue = monitor_queue
        self.monitor_config = self.config.get("monitoring", {}).get(self.get_name(), {})
        self.interval = self.config.get("agent", {}).get("heartbeat_interval_seconds", 60)
        self.context = self._get_base_context()

    def _get_base_context(self) -> dict:
        """Gathers common contextual information for enriching alerts."""
        try:
            p = psutil.Process(os.getpid())
            user = p.username()
        except psutil.Error:
            user = "unknown"

        return {
            "host": {
                "hostname": socket.gethostname(),
                "agent_id": self.config.get("agent", {}).get("id", "unknown")
            },
            "process": {
                "pid": os.getpid(),
                "name": self.get_name()
            },
            "user": {
                "name": user
            }
        }

    def get_name(self) -> str:
        """
        Returns the unique name of the monitor.
        This should match its key in the config.json 'monitoring' section.
        """
        raise NotImplementedError

    def log_alert(self, event_type: str, message: str, level: str = "warning", severity: str = "medium", details: dict = None, action: str = None):
        """
        Puts a structured log record onto the shared queue for the main agent.
        """
        log_record = {
            **self.context,
            "level": level,
            "severity": severity,
            "monitor": self.get_name().upper(),
            "event_type": event_type.upper(),
            "message": message,
            "details": details or {},
            "action": action
        }
        self.log_queue.put(log_record)

    def publish_threat_intel(self, event_type: str, data: dict, source: str = None):
        """
        Publishes a message to the shared threat intelligence bus for other monitors to see.
        """
        intel_message = {
            "publisher": self.get_name(),
            "event_type": event_type.upper(),
            "data": data,
            "source": source or self.get_name()
        }
        self.threat_bus.put(intel_message)

    def handle_threat_intel(self, message: dict):
        """
        Placeholder method for monitors to process messages from the threat bus.
        This method should be overridden by monitor subclasses that need to
        subscribe to inter-monitor events.
        """

    def _check_for_intel(self):
        """Checks for and processes any messages on the monitor's input queue."""
        try:
            while not self.monitor_queue.empty():
                message = self.monitor_queue.get_nowait()
                self.handle_threat_intel(message)
        except queue.Empty:
            pass

    def run_wrapper(self):
        """The main execution loop for the monitor process."""
        self.log_alert("LIFECYCLE", f"Process for monitor '{self.get_name()}' started.", "info")
        
        self.start()

        try:
            while not self.shutdown_event.is_set():
                # Check for incoming threat intel messages
                self._check_for_intel()

                if self.monitor_config.get("enabled", False):
                    self.run()
                
                # Use a timeout on sleep to be more responsive
                time.sleep(self.interval)
        finally:
            self.stop()
            self.log_alert("LIFECYCLE", f"Process for monitor '{self.get_name()}' stopping.", "info")

    def run(self):
        """The main execution logic for the monitor, called in each cycle."""
        raise NotImplementedError

    def start(self):
        """For monitors that need to run a one-time setup task."""

    def stop(self):
        """For monitors that need to run a one-time cleanup task."""
