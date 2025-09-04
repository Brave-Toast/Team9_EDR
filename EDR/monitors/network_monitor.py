import psutil
from .base_monitor import BaseMonitor

class NetworkMonitor(BaseMonitor):
    def get_name(self):
        return "network_monitoring"

    def __init__(self, agent_config, log_queue, shutdown_event):
        super().__init__(agent_config, log_queue, shutdown_event)
        self.reported_conns = set() # Track reported connections to avoid log spam

    def run(self):
        if not self.monitor_config.get("enabled"):
            return

        listen_ports = set(self.monitor_config.get("listen_ports", []))
        if not listen_ports:
            return

        current_conns = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr and conn.laddr.port in listen_ports:
                    conn_id = (conn.laddr.port, conn.pid)
                    current_conns.add(conn_id)
        except psutil.AccessDenied:
            self.log_alert("ERROR", "Could not access network connections (permission denied).", "warning")
            # To prevent spamming, disable this monitor after the first failure
            self.monitor_config['enabled'] = False
            return
        except RuntimeError as e:
            self.log_alert("ERROR", f"An error occurred while checking network connections: {e}", "error")
            return

        # Find and report new connections
        new_conns = current_conns - self.reported_conns
        for port, pid in new_conns:
            try:
                proc_name = psutil.Process(pid).name() if pid else "N/A"
                self.log_alert(
                    "NETWORK-LISTEN-START",
                    f"New process listening on monitored port: {port}. PID: {pid}, Name: {proc_name}",
                    level="info"
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.log_alert(
                    "NETWORK-LISTEN-START",
                    f"New process with PID {pid} is listening on monitored port: {port}.",
                    level="info"
                )

        # Find and report closed connections
        closed_conns = self.reported_conns - current_conns
        for port, pid in closed_conns:
            self.log_alert(
                "NETWORK-LISTEN-STOP",
                f"A process has stopped listening on monitored port: {port}. It was running with PID: {pid}.",
                level="info"
            )

        # Update the state for the next run
        self.reported_conns = current_conns