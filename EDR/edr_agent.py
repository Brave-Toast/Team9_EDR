#!/usr/bin/env python3
"""Main entry point for the EDR agent.

This module initializes and orchestrates the EDR agent system. It:
1. Loads and validates configuration
2. Initializes monitoring components
3. Manages monitor process lifecycle
4. Coordinates threat intelligence sharing
5. Handles logging and alerting

The agent uses a multi-process architecture where each monitor runs in its own
process for isolation and reliability. Inter-process communication is handled
via queues for logs and threat intelligence sharing.
"""
# Standard library imports
import importlib
import inspect
import ipaddress
import json
import logging
import os
import pkgutil
import queue
import re
import subprocess
import sys
import time
from multiprocessing import Event, Process, Queue

# Third-party imports
import psutil

# Ensure the project root is on sys.path so absolute package imports work
# when the script is executed directly (e.g. `python EDR/edr_agent.py`).
_script_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.abspath(os.path.join(_script_dir, os.pardir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from EDR.formatters import ECSFormatter, HumanReadableFormatter
from EDR.threat_bus import ThreatBusDispatcher, run_bus_dispatcher_wrapper


def _monitor_process_entry(monitor_qualname, agent_config, log_queue, shutdown_event, threat_bus, monitor_queue):
    """Entry point function for initializing and running a monitor in a child process.

    This function handles the complete lifecycle of a monitor process:
    1. Imports the monitor class by qualified name
    2. Constructs a new instance with provided configuration
    3. Runs the monitor's wrapper method
    4. Captures and reports any errors during startup or execution

    Args:
        monitor_qualname: Fully qualified name of the monitor class (e.g. 'EDR.monitors.network_monitor.NetworkMonitor')
        agent_config: Configuration dictionary for the EDR agent
        log_queue: Queue for sending log messages back to main process
        shutdown_event: Event to signal monitor shutdown
        threat_bus: Queue for sharing threat intelligence between monitors
        monitor_queue: Queue for control messages between agent and monitor

    Note:
        Using a top-level entry point function avoids pickling complex monitor
        instances when multiprocessing start method is 'spawn'.

    Raises:
        Any exception during monitor initialization or execution will be caught,
        logged via the log_queue, printed to stderr, and re-raised.
    """
    try:
        module_name, class_name = monitor_qualname.rsplit('.', 1)
        module = importlib.import_module(module_name)
        monitor_cls = getattr(module, class_name)
        monitor_instance = monitor_cls(
            agent_config=agent_config,
            log_queue=log_queue,
            shutdown_event=shutdown_event,
            threat_bus=threat_bus,
            monitor_queue=monitor_queue,
        )
        monitor_instance.run_wrapper()
    except (ImportError, AttributeError, TypeError, RuntimeError):  # pragma: no cover - runtime safety wrapper
        # If construction or run fails inside the child, capture the full
        # traceback and send it back to the agent via the shared log queue
        # so it can be recorded in the main agent log. Also print to stderr
        # for immediate visibility in child process logs.
        import traceback as _tb
        tb = _tb.format_exc()
        try:
            # Try to push a structured record onto the agent's log queue.
            log_queue.put({
                "level": "error",
                "message": f"Monitor process '{monitor_qualname}' crashed during startup.",
                "details": {"traceback": tb},
                "action": None,
            })
        except (queue.Full, ConnectionError, OSError) as queue_error:
            # Handle specific queue-related errors:
            # - queue.Full: Queue is at capacity
            # - ConnectionError: IPC connection issues
            # - OSError: System-level communication errors
            _tb.print_exc()
            print(f"Failed to send error to log queue: {queue_error}", file=sys.stderr)
        # Also print to stderr to ensure the runtime environment captures it.
        print(tb, file=sys.stderr)
        raise  # Re-raise the original exception with its traceback



# ==============================================================================
# EDR AGENT CORE
# ==============================================================================

class EDRAgent:
    """A modular, multi-process EDR (Endpoint Detection and Response) agent.

    This class serves as the core orchestrator for the EDR system, managing:
    - Monitor process lifecycle and health
    - Configuration validation and distribution
    - Logging and alert generation
    - Threat intelligence sharing between monitors
    - Graceful startup and shutdown

    The agent discovers monitor modules dynamically and runs each in a separate
    process for isolation. Communication between processes is handled via queues:
    - log_queue: Centralized logging from all components
    - threat_bus: Threat intelligence sharing between monitors
    - monitor_queue: Control messages to/from monitors

    Note:
        The number of instance attributes is justified by the complex orchestration
        requirements. Each attribute serves a specific, necessary purpose.
    """

    def __init__(self, config):
        self.config = config
        self.logger = self._setup_logging()
        self.log_queue = Queue()
        self.shutdown_event = Event()
        self.processes = []
        # Track PIDs of processes we've already reported as dead to avoid
        # spamming the log every loop iteration.
        self._logged_dead_pids = set()

        # Queues for the Threat Intelligence Bus
        self.threat_bus_queue = Queue()
        self.monitor_input_queues = {}

        self.action_dispatcher = {
            "kill_process": self._handle_kill_process,
            "block_ip": self._handle_block_ip,
        }
        self.blocked_ips = set()

    def _setup_logging(self):
        """
        Configures the logger based on the output format specified in the config.
        """
        logger = logging.getLogger("EDRAgent")
        log_level = self.config.get("agent", {}).get("log_level", "INFO").upper()
        logger.setLevel(log_level)

        if logger.hasHandlers():
            logger.handlers.clear()

        output_config = self.config.get("output", {})
        output_type = output_config.get("type", "console")
        output_format = output_config.get("format", "json")

        # 1. Always set up the console handler
        console_handler = logging.StreamHandler(sys.stdout)
        if output_format.lower() == "human":
            console_formatter = HumanReadableFormatter()
        else:
            console_formatter = ECSFormatter()
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # 2. If file output is enabled, add a file handler as well
        if output_type.lower() == "file":
            filepath = output_config.get("filepath")
            if not filepath:
                logger.error(
                    "Log output type is 'file' but no 'filepath' is specified. "
                    "Defaulting to console."
                )
            else:
                try:
                    # If the path is a directory, append a default filename
                    if os.path.isdir(filepath):
                        filepath = os.path.join(filepath, "edr_agent.log")

                    # Ensure the directory exists
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)

                    # File logs should always be JSON for machine readability
                    file_handler = logging.FileHandler(filepath)
                    file_handler.setFormatter(ECSFormatter())
                    logger.addHandler(file_handler)

                except (OSError, PermissionError) as e:
                    logger.error(
                        "Failed to create log file at '%s': %s. "
                        "Skipping file logging.",
                        filepath,
                        e
                    )

        return logger

    def _load_and_start_monitors(self):
        """Dynamically loads monitors and starts each in its own process."""
        self.logger.info("Loading and starting monitor processes...")
        monitors_package_path = "EDR.monitors"

        # 1. Discover all monitor classes and create their input queues
        monitor_classes = []
        try:
            monitors_pkg = importlib.import_module(monitors_package_path)
            monitor_path = monitors_pkg.__path__
            base_mod = importlib.import_module(f"{monitors_package_path}.base_monitor")
            BaseMonitor = getattr(base_mod, "BaseMonitor")
        except (ImportError, AttributeError) as e:
            # ImportError covers ModuleNotFoundError and other import issues;
            # AttributeError handles missing attributes like __path__ or BaseMonitor.
            self.logger.error("Failed to import monitors package '%s': %s", monitors_package_path, e)
            return

        for _, module_name, _ in pkgutil.iter_modules(monitor_path):
            if module_name == 'base_monitor':
                continue
            try:
                module = importlib.import_module(f"{monitors_package_path}.{module_name}")
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    try:
                        if issubclass(obj, BaseMonitor) and obj is not BaseMonitor:
                            monitor_classes.append(obj)
                            # Each monitor gets its own input queue for bus messages
                            self.monitor_input_queues[obj.__name__] = Queue()
                    except TypeError:
                        # Not a class that supports issubclass checks; skip
                        continue
            except (ImportError, AttributeError, TypeError) as e:
                self.logger.error(
                    "Failed to load monitor plugin '%s': %s", module_name, e
                )

        # 2. Start the Threat Bus Dispatcher process
        bus_dispatcher = ThreatBusDispatcher(
            self.threat_bus_queue, self.monitor_input_queues, self.shutdown_event
        )
        bus_proc = Process(
            target=run_bus_dispatcher_wrapper, args=(bus_dispatcher,), daemon=True
        )
        self.processes.append(bus_proc)
        bus_proc.start()
        self.logger.info("  -> Started process for ThreatBusDispatcher")

        # 3. Start each monitor process
        for monitor_class in monitor_classes:
            try:
                # Use a module-qualified class name so the child process can
                # import and construct the monitor. Passing the live instance
                # to Process can fail under the 'spawn' start method because
                # many monitor objects (watchdog Observer, compiled regex,
                # threads) are not picklable.
                qualname = f"{monitor_class.__module__}.{monitor_class.__name__}"
                proc = Process(
                    target=_monitor_process_entry,
                    args=(
                        qualname,
                        self.config,
                        self.log_queue,
                        self.shutdown_event,
                        self.threat_bus_queue,
                        self.monitor_input_queues[monitor_class.__name__],
                    ),
                    daemon=True,
                )
                self.processes.append(proc)
                proc.start()
                self.logger.info("  -> Started process for monitor: %s", monitor_class.__name__)
            except (TypeError, KeyError, ValueError, AttributeError, OSError, re.error) as e:
                self.logger.error("Failed to start monitor '%s': %s", monitor_class.__name__, e)

        self.logger.info("All monitor processes have been started.")


    def _process_log_queue(self):
        """
        Checks the log queue, logs messages, and dispatches active responses.
        """
        try:
            while not self.log_queue.empty():
                log_record = self.log_queue.get_nowait()

                log_level_name = log_record.get("level", "info")
                log_func = getattr(self.logger, log_level_name, self.logger.info)
                log_func(log_record)

                if log_record.get("action"):
                    self._dispatch_response(log_record)

        except queue.Empty:
            pass  # No more items in the queue for now
        except ValueError as e:
            self.logger.error("ValueError while processing log record: %s", e)

    def _dispatch_response(self, alert: dict) -> None:
        """Dispatches an active response based on the alert's action field."""
        action = alert.get("action")
        if not action:
            self.logger.warning("Received alert with no action specified: %s", alert)
            return

        handler = self.action_dispatcher.get(action)
        if handler:
            self.logger.warning(
                "Executing active response '%s' for alert: %s",
                action,
                alert.get('message')
            )
            handler(alert)
        else:
            self.logger.warning("Received unknown action request: %s", action)

    def _handle_kill_process(self, alert: dict) -> None:
        """Handles the 'kill_process' action."""
        details = alert.get("details", {})
        pid = details.get("pid")

        if not isinstance(pid, int) or pid <= 0:
            self.logger.error(
                "Invalid or missing PID for kill_process action in alert: %s", alert
            )
            return

        try:
            proc = psutil.Process(pid)
            proc.terminate()
            self.logger.info("Successfully terminated process with PID %d.", pid)
        except ImportError:
            self.logger.error(
                "The 'psutil' library is required for 'kill_process'. Please install it."
            )
        except psutil.NoSuchProcess:
            self.logger.warning(
                "Attempted to kill PID %d, but process was already gone.", pid
            )
        except psutil.AccessDenied as e:
            self.logger.error(
                "Permission denied to kill process with PID %d: %s", pid, e
            )
        except psutil.Error as e:
            self.logger.error(
                "An unexpected psutil error occurred while killing PID %d: %s", pid, e
            )

    def _handle_block_ip(self, alert: dict) -> None:
        """Handles the 'block_ip' action."""
        details = alert.get("details", {})
        ip_addr = details.get("remote_address")

        if not ip_addr or not isinstance(ip_addr, str):
            self.logger.error(
                "Invalid or missing 'remote_address' for block_ip action in alert: %s",
                alert
            )
            return
        if ip_addr.startswith("::ffff:"):
            ip_addr = ip_addr.split("::ffff:")[-1]

        # Track blocked IPs to avoid duplicate UFW commands
        if ip_addr in self.blocked_ips:
            self.logger.info(
                "IP %s is already blocked. Skipping duplicate UFW command.", ip_addr
            )
            return

        try:
            ipaddress.ip_address(ip_addr)
        except ImportError:
            self.logger.warning(
                "Could not import 'ipaddress' module for validation. "
                "Proceeding without validation."
            )
        except ValueError:
            self.logger.error(
                "Invalid IP address format '%s' for block_ip action.", ip_addr
            )
            return

        try:
            # Remove any existing allow rule for this IP to ensure deny takes precedence
            allow_cmd = [
                "sudo", "ufw", "delete", "allow", "from", ip_addr, "to", "any", "port", "3000"
            ]
            subprocess.run(allow_cmd, capture_output=True, text=True, check=False)

            # Insert deny rule at position 1 to give it highest priority
            deny_cmd = ["sudo", "ufw", "insert", "1", "deny", "from", ip_addr]
            result = subprocess.run(
                deny_cmd, capture_output=True, text=True, check=True
            )
            self.logger.info(
                "Successfully blocked IP %s at position 1. UFW output: %s",
                ip_addr,
                result.stdout
            )
            self.blocked_ips.add(ip_addr)
        except FileNotFoundError:
            self.logger.error(
                "Failed to block IP %s: 'ufw' command not found. Is UFW installed?",
                ip_addr
            )
        except subprocess.CalledProcessError as e:
            self.logger.error(
                "Failed to block IP %s. UFW command failed. Error: %s", ip_addr, e.stderr
            )


    def run(self):
        """Main agent loop to manage monitor processes and handle logging."""
        agent_id = self.config.get("agent", {}).get("id", "unknown")
        self.logger.info("EDR Agent starting up. Agent ID: %s", agent_id)

        self._load_and_start_monitors()

        try:
            while True:
                self._process_log_queue()
                for proc in list(self.processes):
                    if not proc.is_alive():
                        if proc.pid in self._logged_dead_pids:
                            continue
                        self._logged_dead_pids.add(proc.pid)
                        exitcode = getattr(proc, "exitcode", None)
                        if exitcode == 0:
                            # Normal/expected exit
                            self.logger.info(
                                "Monitor process exited normally. PID: %s.", proc.pid
                            )
                        else:
                            self.logger.error(
                                "A monitor process has terminated unexpectedly. PID: %s. Exit code: %s. Check logs for details.",
                                proc.pid,
                                exitcode,
                            )
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutdown signal received.")
        finally:
            self.logger.info("Signaling all monitor processes to shut down...")
            self.shutdown_event.set()

            for proc in self.processes:
                proc.join(timeout=10)
                if proc.is_alive():
                    self.logger.warning(
                        "Process %s did not shut down gracefully, terminating.", proc.pid
                    )
                    proc.terminate()

            self._process_log_queue()
            self.logger.info("EDR Agent stopped.")

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
def main():
    """Main entry point for the EDR agent."""
    # Add the project root to the path to allow for absolute imports
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, os.pardir))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    config_path = os.path.join(script_dir, "config.json")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            # Filter out commented lines before parsing
            content = "".join(
                line for line in f if not line.strip().startswith("//")
            )
            config = json.loads(content)
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_path}' not found. Exiting.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(
            f"Error: Could not decode '{config_path}'. Check for syntax errors: {e}"
        )
        sys.exit(1)

    if not config:
        print("Error: Configuration is empty. Exiting.")
        sys.exit(1)

    agent = EDRAgent(config=config)
    agent.run()

if __name__ == "__main__":
    main()
