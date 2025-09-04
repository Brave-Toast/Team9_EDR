import time
from multiprocessing import Queue
from multiprocessing.synchronize import Event

class BaseMonitor:
    """
    The base class for all monitoring plugins, designed to be run in a separate process.
    """
    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event):
        self.config = agent_config
        self.log_queue = log_queue
        self.shutdown_event = shutdown_event # <-- Add this
        self.monitor_config = self.config.get("monitoring", {}).get(self.get_name(), {})
        self.interval = self.config.get("agent", {}).get("heartbeat_interval_seconds", 60)

    def get_name(self) -> str:
        """
        Returns the unique name of the monitor.
        This should match its key in the config.json 'monitoring' section.
        """
        raise NotImplementedError

    def log_alert(self, event_type: str, message: str, level: str = "warning", severity: str = "medium", details: dict = None, action: str = None):
        """
        Puts a structured log record onto the shared queue.
        Severity can be: low, medium, high, critical.
        Action can be: kill_process, block_ip, etc.
        """
        log_record = {
            "level": level,
            "severity": severity,
            "monitor": self.get_name().upper(),
            "event_type": event_type.upper(),
            "message": message,
            "details": details or {},
            "action": action # <-- Add the action field
        }
        self.log_queue.put(log_record)

    def run_wrapper(self):
        """The main execution loop for the monitor process."""
        self.log_alert("LIFECYCLE", f"Process for monitor '{self.get_name()}' started.", "info")
        
        # Call the one-time start method if it exists
        self.start()

        try:
            # Loop until the shutdown event is set
            while not self.shutdown_event.is_set():
                if self.monitor_config.get("enabled", False):
                    self.run()
                # Use a timeout on sleep to be more responsive to the shutdown event
                time.sleep(self.interval)
        except KeyboardInterrupt:
            # This allows Ctrl+C to be caught gracefully by the main process
            pass
        finally:
            # Call the one-time stop method if it exists
            self.stop()
            self.log_alert("LIFECYCLE", f"Process for monitor '{self.get_name()}' stopping.", "info")

    def run(self):
        """The main execution logic for the monitor, called in each cycle."""
        raise NotImplementedError

    def start(self):
        """For monitors that need to run a one-time setup task."""

    def stop(self):
        """For monitors that need to run a one-time cleanup task."""