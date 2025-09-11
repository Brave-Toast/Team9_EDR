import psutil
import re
from .base_monitor import BaseMonitor
from multiprocessing import Queue
from multiprocessing.synchronize import Event

class ProcessMonitor(BaseMonitor):
    def get_name(self):
        return "process_monitoring"

    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event, threat_bus: Queue, monitor_queue: Queue):
        super().__init__(agent_config, log_queue, shutdown_event, threat_bus, monitor_queue)
        self.known_pids = set()
        self.monitored_procs = {} # Tracks PIDs of specifically monitored processes
        rules = self.config.get("detection_rules", {})
        self.suspicious_command_patterns = [
            re.compile(p) for p in rules.get("suspicious_commands", [])
        ]

    def run(self):
        if not self.monitor_config.get("enabled"):
            return

        current_pids = set(psutil.pids())
        new_pids = current_pids - self.known_pids

        # Scan NEW processes for generic suspicious commands
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                cmdline = " ".join(proc.cmdline() or [])
                if not cmdline:
                    continue
                
                # Example of a CRITICAL alert with an ACTION
                if "ncat" in cmdline and "-e /bin/bash" in cmdline:
                    details = {"pid": proc.pid, "cmdline": cmdline, "name": proc.name()}
                    self.log_alert(
                        "REVERSE-SHELL",
                        f"Potential reverse shell detected! PID: {proc.pid}, CMD: '{cmdline}'",
                        level="critical",
                        severity="critical",
                        details=details,
                        action="kill_process" # <-- Request an active response
                    )
                    # Publish this critical event to the bus
                    self.publish_threat_intel("SUSPICIOUS_PROCESS_DETECTED", data=details)
                    continue # Move to next process after this critical alert

                for pattern in self.suspicious_command_patterns:
                    if pattern.search(cmdline):
                        details = {"pid": proc.pid, "cmdline": cmdline, "name": proc.name(), "pattern": pattern.pattern}
                        self.log_alert(
                            "PROCESS",
                            f"Suspicious command in new process. PID: {proc.pid}, "
                            f"Name: {proc.name()}, CMD: '{cmdline}'"
                        )
                        # Publish this event to the bus
                        self.publish_threat_intel("SUSPICIOUS_PROCESS_DETECTED", data=details)
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Health check for SPECIFICALLY monitored processes
        self._check_specific_processes()

        self.known_pids = current_pids

    def _check_specific_processes(self):
        rules = self.monitor_config.get("processes", [])
        if not rules:
            return

        running_procs_info = {p.pid: p.info for p in psutil.process_iter(['pid', 'name', 'cmdline'])}

        # Check if our tracked PIDs are still running correctly
        for rule_name, proc_info in list(self.monitored_procs.items()):
            pid = proc_info['pid']
            if pid not in running_procs_info or running_procs_info[pid]['name'] != proc_info['name']:
                self.log_alert(
                    "PROCESS-HEALTH",
                    f"Monitored process '{proc_info['name']}' (PID: {pid}) is no longer running or has changed."
                )
                del self.monitored_procs[rule_name]

        # Find any monitored processes that we aren't yet tracking
        for rule in rules:
            rule_name = rule.get("name")
            if rule_name and rule_name not in self.monitored_procs:
                for pid, info in running_procs_info.items():
                    if rule_name.lower() in info['name'].lower() and \
                       rule.get("command_line_contains", "") in " ".join(info['cmdline'] or []):
                        
                        self.monitored_procs[rule_name] = {'pid': pid, 'name': info['name']}
                        self.log_alert(
                            "PROCESS-HEALTH",
                            f"Started tracking monitored process '{info['name']}' with PID {pid}.",
                            level="info"
                        )
                        break
