import psutil
from .base_monitor import BaseMonitor
from multiprocessing import Queue
from multiprocessing.synchronize import Event

class NetworkMonitor(BaseMonitor):
    def get_name(self):
        return "network_monitoring"

    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event, threat_bus: Queue, monitor_queue: Queue):
        super().__init__(agent_config, log_queue, shutdown_event, threat_bus, monitor_queue)
        self.reported_conns = set()
        self.suspicious_pids = set()

    def handle_threat_intel(self, message: dict):
        """
        Handles threat intelligence messages from the bus, subscribing to suspicious process events.
        """
        if message.get("event_type") == "SUSPICIOUS_PROCESS_DETECTED":
            pid = message.get("data", {}).get("pid")
            if pid:
                self.log_alert(
                    "THREAT_INTEL_UPDATE",
                    f"Received threat intel: Process PID {pid} is suspicious. Now monitoring its network activity.",
                    level="info",
                    severity="low"
                )
                self.suspicious_pids.add(pid)

    def run(self):
        if not self.monitor_config.get("enabled"):
            return

        # This monitor now focuses on correlating network activity with threat intel
        try:
            # Check all established connections for correlation
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid in self.suspicious_pids and conn.status == 'ESTABLISHED':
                    # Create a unique ID for the connection to avoid duplicate alerts
                    conn_id = (conn.pid, conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                    
                    if conn_id not in self.reported_conns:
                        proc_name = "unknown"
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            # Process might have terminated or we may not have permission to access it
                            pass

                        self.log_alert(
                            "CORRELATED_THREAT_DETECTED",
                            f"Previously flagged suspicious process '{proc_name}' (PID {conn.pid}) established a network connection.",
                            severity="high",
                            details={
                                "pid": conn.pid,
                                "process_name": proc_name,
                                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                                "status": conn.status
                            }
                        )
                        self.reported_conns.add(conn_id)

        except psutil.AccessDenied:
            self.log_alert("ERROR", "Could not access network connections (permission denied).", "warning")
            self.monitor_config['enabled'] = False # Disable to prevent spamming logs
            return
        except psutil.Error as e:
            self.log_alert("ERROR", f"An error occurred while checking network connections: {e}", "error")
            return