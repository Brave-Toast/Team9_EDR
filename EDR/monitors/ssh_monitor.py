import os
import re
from datetime import datetime, timedelta
from collections import defaultdict
from .base_monitor import BaseMonitor
from multiprocessing import Queue
from multiprocessing.synchronize import Event

class SSHMonitor(BaseMonitor):
    def get_name(self):
        return "ssh_monitoring"

    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event, threat_bus: Queue, monitor_queue: Queue):
        super().__init__(agent_config, log_queue, shutdown_event, threat_bus, monitor_queue)
        self.fail_tracker = defaultdict(list)
        self.blocked_ips = set()
        self.log_inode = None
        self.log_pos = 0
        self.blocking_enabled = self.monitor_config.get("enable_ip_blocking", True)

    def _block_ip(self, ip_address: str):
        """
        Blocks an IP address using the system's firewall.
        """
        try:
            import platform
            system = platform.system().lower()
            
            if system == "linux":
                # Use UFW for Ubuntu/Debian systems
                import subprocess
                try:
                    # First try UFW
                    cmd = f"sudo ufw deny from {ip_address} to any"
                    result = subprocess.run(cmd.split(), check=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.log_alert(
                            "IP_BLOCKED",
                            f"Successfully blocked IP address: {ip_address} using UFW",
                            severity="info"
                        )
                    else:
                        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
                except subprocess.CalledProcessError as e:
                    self.log_alert(
                        "ERROR",
                        f"Failed to block IP {ip_address} using UFW: {str(e)}",
                        severity="error",
                        details={"stdout": e.stdout, "stderr": e.stderr if hasattr(e, 'stderr') else None}
                    )
            elif system == "windows":
                # Use Windows Firewall
                import subprocess
                rule_name = f"EDR_Block_{ip_address.replace('.', '_')}"
                cmd = (
                    f'netsh advfirewall firewall add rule '
                    f'name="{rule_name}" '
                    f'dir=in action=block protocol=any '
                    f'remoteip={ip_address}'
                )
                subprocess.run(cmd, check=True)
                self.log_alert(
                    "IP_BLOCKED",
                    f"Successfully blocked IP address: {ip_address}",
                    severity="info"
                )
            else:
                self.log_alert(
                    "ERROR",
                    f"IP blocking not implemented for {system}",
                    severity="error"
                )
        except (ImportError, ModuleNotFoundError) as e:
            # Handle import-related errors (platform or subprocess modules)
            self.log_alert(
                "ERROR",
                f"Required module not available for IP blocking: {str(e)}",
                severity="error"
            )
        except subprocess.SubprocessError as e:
            # Handle subprocess-related errors not caught by specific handlers above
            self.log_alert(
                "ERROR",
                f"Subprocess error while blocking IP {ip_address}: {str(e)}",
                severity="error"
            )
        except (OSError, PermissionError) as e:
            # Handle OS-level errors (file permissions, resource limits, etc.)
            self.log_alert(
                "ERROR",
                f"System error while blocking IP {ip_address}: {str(e)}",
                severity="error"
            )

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
                        # More comprehensive pattern matching for SSH failures
                        ip_match = None
                        if "Failed password" in line:
                            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                        elif "Invalid user" in line:
                            ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                        elif "Connection closed by authenticating user" in line:
                            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+) port", line)
                        
                        if ip_match and ip_match.group(1) not in self.blocked_ips:
                            self.fail_tracker[ip_match.group(1)].append(datetime.now())
                            self.log_alert(
                                "SSH-ATTEMPT",
                                f"Failed SSH attempt from IP: {ip_match.group(1)}",
                                severity="low",
                                details={"remote_address": ip_match.group(1)}
                            )
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
            if ip in self.blocked_ips:
                continue
                
            recent_attempts = [t for t in timestamps if now - t < window]
            if len(recent_attempts) >= threshold:
                self.log_alert(
                    "SSH-BRUTE-FORCE",
                    f"Potential brute force attack detected from IP: {ip}. "
                    f"Failed {len(recent_attempts)} times in the last {window.seconds / 60} minutes.",
                    severity="high",
                    details={
                        "remote_address": ip,
                        "attempt_count": len(recent_attempts),
                        "window_minutes": window.seconds / 60
                    },
                    action="block_ip"
                )
                if self.blocking_enabled:
                    self._block_ip(ip)
                self.blocked_ips.add(ip)
                del self.fail_tracker[ip]
            else:
                self.fail_tracker[ip] = recent_attempts
