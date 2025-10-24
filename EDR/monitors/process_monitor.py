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
        user_patterns = rules.get("suspicious_commands", [])
        # Provide a small set of sensible defaults for common reverse-shell
        # and suspicious command invocations so the monitor works out of the
        # box without extra config. Users can override via config.
        default_patterns = [
            r"\b(nc|ncat|netcat)\b",        # netcat variants
            r"\b-n?e\b",                   # -e flag (exec)
            r"\b(/bin/(?:sh|bash))\b",     # direct shell execution
            r"bash\s+-i\b",                # interactive bash
            r"python\s+-c\b",              # python one-liners
            r"perl\s+-e\b",
            r"php\s+-r\b",
        ]
        patterns = user_patterns if user_patterns else default_patterns
        self.suspicious_command_patterns = [re.compile(p, re.IGNORECASE) for p in patterns]

    def run(self):
        if not self.monitor_config.get("enabled"):
            return

        # Initialize known_pids on the first run
        self.known_pids = set(psutil.pids())

        while not self.shutdown_event.is_set():
            # Check for incoming threat intel messages at the start of each cycle
            self._check_for_intel()

            current_pids = set(psutil.pids())
            new_pids = current_pids - self.known_pids

            # Scan NEW processes for generic suspicious commands
            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    cmdline = " ".join(proc.cmdline() or [])
                    if not cmdline:
                        continue
                    
                    # Detect reverse shells and suspicious one-liners using
                    # configured or default regex patterns. We treat commands
                    # matching netcat with an -e flag or interactive shells as
                    # high priority (critical). Other one-liners are reported
                    # as PROCESS-level alerts.
                    matched_critical = False
                    for pattern in self.suspicious_command_patterns:
                        if pattern.search(cmdline):
                            details = {"pid": proc.pid, "cmdline": cmdline, "name": proc.name(), "pattern": pattern.pattern}
                            # Heuristic: netcat/nc with -e or interactive bash are critical
                            if re.search(r"\b(nc|ncat|netcat)\b", cmdline, re.IGNORECASE) and re.search(r"\b-e\b", cmdline):
                                self.log_alert(
                                    "REVERSE-SHELL",
                                    f"Potential reverse shell detected! PID: {proc.pid}, CMD: '{cmdline}'",
                                    level="critical",
                                    severity="critical",
                                    details=details,
                                    action="kill_process"
                                )
                                self.publish_threat_intel("SUSPICIOUS_PROCESS_DETECTED", data=details)
                                matched_critical = True
                                break

                            if re.search(r"bash\s+-i|/bin/(?:sh|bash)", cmdline, re.IGNORECASE):
                                self.log_alert(
                                    "REVERSE-SHELL",
                                    f"Potential interactive shell in new process. PID: {proc.pid}, CMD: '{cmdline}'",
                                    level="critical",
                                    severity="critical",
                                    details=details,
                                    action="kill_process"
                                )
                                self.publish_threat_intel("SUSPICIOUS_PROCESS_DETECTED", data=details)
                                matched_critical = True
                                break

                            # Otherwise, non-critical suspicious command
                            self.log_alert(
                                "PROCESS",
                                f"Suspicious command in new process. PID: {proc.pid}, Name: {proc.name()}, CMD: '{cmdline}'",
                                details={"pattern": pattern.pattern}
                            )
                            self.publish_threat_intel("SUSPICIOUS_PROCESS_DETECTED", data=details)
                            break

                    if matched_critical:
                        continue
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Health check for SPECIFICALLY monitored processes
            self._check_specific_processes()

            self.known_pids = current_pids
            
            # Wait for the specified interval or until shutdown is signaled
            self.shutdown_event.wait(self.interval)

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
