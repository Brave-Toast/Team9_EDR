#!/usr/bin/env python3
"""
Main entry point for the EDR agent.

This script initializes the EDR agent, loads the configuration, and starts all
the monitoring components. It is responsible for orchestrating the different
parts of the EDR and managing their lifecycle.
"""
import time
import os
import logging
import json
import pkgutil
import importlib
import inspect
import sys
import re
import queue
import subprocess
from multiprocessing import Process, Queue, Event
from multiprocessing.synchronize import Event as EventType
from datetime import datetime

# Add the project root to the Python path to help with module resolution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# Import the base class that all monitors will inherit from
from monitors.base_monitor import BaseMonitor

# ==============================================================================
#  JSON LOG FORMATTER
# ==============================================================================

class ECSFormatter(logging.Formatter):
    """
    Formats log records as a single line of JSON, conforming to the
    Elastic Common Schema (ECS).
    """
    def format(self, record):
        # Start with the base ECS structure
        ecs_log = {
            "@timestamp": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "log": {"level": record.levelname.lower(), "logger": record.name},
            "message": record.getMessage(),
            "ecs": {"version": "8.4"}, # Specify ECS version
        }

        # If the original log message was a dictionary, map its fields to ECS
        if isinstance(record.msg, dict):
            original_msg = record.msg
            ecs_log["message"] = original_msg.get("message", ecs_log["message"])

            # Event fields
            event = {}
            if original_msg.get("event_type"):
                event["kind"] = "alert"
                event["category"] = "security"
                event["type"] = original_msg.get("event_type").lower()
            if original_msg.get("monitor"):
                event["module"] = original_msg.get("monitor").lower()
            if original_msg.get("action"):
                event["action"] = original_msg.get("action")
            if original_msg.get("severity"):
                # ECS severity is a number, but we can use a keyword too
                event["severity"] = original_msg.get("severity")
            if event:
                ecs_log["event"] = event

            # Map context fields (host, process, user)
            if original_msg.get("host"):
                ecs_log["host"] = original_msg.get("host")
            if original_msg.get("process"):
                ecs_log["process"] = original_msg.get("process")
            if original_msg.get("user"):
                ecs_log["user"] = original_msg.get("user")

            # Place all other details under a custom field to avoid conflicts
            if original_msg.get("details"):
                ecs_log["custom"] = {"details": original_msg.get("details")}

        return json.dumps(ecs_log)

class HumanReadableFormatter(logging.Formatter):
    """
    Formats log records for easy reading in a terminal with color.
    """

    COLORS = {
        "INFO": "\x1b[34m",     # Blue
        "WARNING": "\x1b[33m",  # Yellow
        "ERROR": "\x1b[31m",    # Red
        "CRITICAL": "\x1b[41m\x1b[37m", # White text on Red background
        "RESET": "\x1b[0m"
    }

    def format(self, record):
        log_object = {}
        if isinstance(record.msg, dict):
            log_object.update(record.msg)
            if 'message' not in log_object:
                log_object['message'] = str(record.msg)
        else:
            log_object['message'] = record.getMessage()

        level_name = record.levelname
        color = self.COLORS.get(level_name, self.COLORS["RESET"])
        
        event_type = log_object.get("event_type", "LOG")
        title = f"[{level_name}] {event_type}"
        
        output = []
        output.append(f"{color}{'=' * 70}{self.COLORS['RESET']}")
        output.append(f"{color}{title.center(70)}{self.COLORS['RESET']}")
        output.append(f"{color}{'=' * 70}{self.COLORS['RESET']}")

        output.append(f"Timestamp: {datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"Monitor:   {log_object.get('monitor', 'N/A')}")
        output.append(f"Message:   {log_object.get('message', 'N/A')}")
        
        if log_object.get("severity"):
            output.append(f"Severity:  {log_object.get('severity')}")
        if log_object.get("action"):
            output.append(f"Action:    {log_object.get('action')}")

        details = log_object.get("details")
        if details and isinstance(details, dict):
            output.append("Details:")
            for key, value in details.items():
                output.append(f"  -> {key:<12}: {value}")
        
        output.append("\n")

        return "\n".join(output)

# ==============================================================================
# THREAT INTELLIGENCE BUS
# ==============================================================================

class ThreatBusDispatcher:
    """
    A central dispatcher that forwards messages from a central bus to all
    subscribed monitors, creating a publish-subscribe communication channel.
    """
    def __init__(self, bus_queue: Queue, monitor_queues: dict, shutdown_event: EventType):
        self.bus_queue = bus_queue
        self.monitor_queues = monitor_queues
        self.shutdown_event = shutdown_event

    def run(self):
        """Continuously reads from the bus and dispatches to all monitors."""
        while not self.shutdown_event.is_set():
            try:
                message = self.bus_queue.get(timeout=1)
                for monitor_name, queue_ in self.monitor_queues.items():
                    try:
                        # Avoid sending a message back to the sender
                        if message.get("publisher") != monitor_name:
                            queue_.put_nowait(message)
                    except queue.Full:
                        # In a real-world scenario, you'd want to log this
                        # or have a strategy for handling slow consumers.
                        pass
            except queue.Empty:
                continue

def run_bus_dispatcher_wrapper(dispatcher: ThreatBusDispatcher):
    """A wrapper to allow the dispatcher process to handle KeyboardInterrupt gracefully."""
    try:
        dispatcher.run()
    except KeyboardInterrupt:
        # On Ctrl+C, the shutdown_event will be set by the main agent,
        # and the run loop will terminate, allowing a clean exit.
        pass
# ==============================================================================
# EDR AGENT CORE
# ==============================================================================

class EDRAgent:
    """
    A modular, multi-process EDR agent.
    """

    def __init__(self, config):
        self.config = config
        self._validate_config()
        self.logger = self._setup_logging()
        self.log_queue = Queue()
        self.shutdown_event = Event()
        self.processes = []
        
        # Queues for the Threat Intelligence Bus
        self.threat_bus_queue = Queue()
        self.monitor_input_queues = {}

        self.action_dispatcher = {
            "kill_process": self._handle_kill_process,
            "block_ip": self._handle_block_ip,
        }

    def _validate_config(self):
        """Validates the main configuration file."""
        if not isinstance(self.config.get("agent"), dict):
            raise ValueError("Configuration error: 'agent' section is missing or not a dictionary.")
        if not isinstance(self.config.get("monitoring"), dict):
            raise ValueError("Configuration error: 'monitoring' section is missing or not a dictionary.")
        if not isinstance(self.config.get("detection_rules"), dict):
            raise ValueError("Configuration error: 'detection_rules' section is missing or not a dictionary.")
        if not isinstance(self.config.get("output"), dict):
            raise ValueError("Configuration error: 'output' section is missing or not a dictionary.")

        agent_config = self.config["agent"]
        if not isinstance(agent_config.get("id"), str) or not agent_config.get("id"):
            raise ValueError("Configuration error: 'agent.id' is missing or not a non-empty string.")
        if not isinstance(agent_config.get("log_level"), str):
            raise ValueError("Configuration error: 'agent.log_level' is missing or not a string.")
        if not isinstance(agent_config.get("heartbeat_interval_seconds"), int):
            raise ValueError("Configuration error: 'agent.heartbeat_interval_seconds' is missing or not an integer.")

        if not isinstance(self.config.get("platform"), str) or not self.config.get("platform"):
            raise ValueError("Configuration error: 'platform' is missing or not a non-empty string.")

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
                logger.error("Log output type is 'file' but no 'filepath' is specified. Defaulting to console.")
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
                    logger.error("Failed to create log file at '%s': %s. Skipping file logging.", filepath, e)

        return logger

    def _load_and_start_monitors(self):
        """Dynamically loads monitors and starts each in its own process."""
        self.logger.info("Loading and starting monitor processes...")
        monitors_package_path = "monitors"
        
        # 1. Discover all monitor classes and create their input queues
        monitor_classes = []
        for _, module_name, _ in pkgutil.iter_modules([monitors_package_path]):
            if module_name == 'base_monitor':
                continue
            try:
                module = importlib.import_module(f"{monitors_package_path}.{module_name}")
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BaseMonitor) and obj is not BaseMonitor:
                        monitor_classes.append(obj)
                        # Each monitor gets its own input queue for bus messages
                        self.monitor_input_queues[obj.__name__] = Queue()
            except (ImportError, AttributeError, TypeError) as e:
                self.logger.error("Failed to load monitor plugin '%s': %s", module_name, e)

        # 2. Start the Threat Bus Dispatcher process
        bus_dispatcher = ThreatBusDispatcher(
            self.threat_bus_queue, self.monitor_input_queues, self.shutdown_event
        )
        bus_proc = Process(target=run_bus_dispatcher_wrapper, args=(bus_dispatcher,), daemon=True)
        self.processes.append(bus_proc)
        bus_proc.start()
        self.logger.info("  -> Started process for ThreatBusDispatcher")

        # 3. Start each monitor process
        for monitor_class in monitor_classes:
            try:
                monitor_instance = monitor_class(
                    agent_config=self.config, 
                    log_queue=self.log_queue, 
                    shutdown_event=self.shutdown_event,
                    threat_bus=self.threat_bus_queue,
                    monitor_queue=self.monitor_input_queues[monitor_class.__name__]
                )
                
                proc = Process(target=monitor_instance.run_wrapper, daemon=True)
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

        except (queue.Empty, ValueError):
            pass

    def _dispatch_response(self, alert: dict) -> None:
        """Dispatches an active response based on the alert's action field."""
        action = alert.get("action")
        if not action:
            self.logger.warning("Received alert with no action specified: %s", alert)
            return

        handler = self.action_dispatcher.get(action)
        if handler:
            self.logger.warning("Executing active response '%s' for alert: %s", action, alert.get('message'))
            handler(alert)
        else:
            self.logger.warning("Received unknown action request: %s", action)

    def _handle_kill_process(self, alert: dict) -> None:
        """Handles the 'kill_process' action."""
        details = alert.get("details", {})
        pid = details.get("pid")

        if not isinstance(pid, int) or pid <= 0:
            self.logger.error("Invalid or missing PID for kill_process action in alert: %s", alert)
            return

        try:
            import psutil
            p = psutil.Process(pid)
            p.terminate()
            self.logger.info("Successfully terminated process with PID %d.", pid)
        except ImportError:
            self.logger.error("The 'psutil' library is required for 'kill_process'. Please install it.")
        except psutil.NoSuchProcess:
            self.logger.warning("Attempted to kill PID %d, but process was already gone.", pid)
        except psutil.AccessDenied as e:
            self.logger.error("Permission denied to kill process with PID %d: %s", pid, e)
        except psutil.Error as e:
            self.logger.error("An unexpected psutil error occurred while killing PID %d: %s", pid, e)

    def _handle_block_ip(self, alert: dict) -> None:
        """Handles the 'block_ip' action."""
        details = alert.get("details", {})
        ip = details.get("remote_address")

        if not ip or not isinstance(ip, str):
            self.logger.error("Invalid or missing 'remote_address' for block_ip action in alert: %s", alert)
            return

        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ImportError:
            self.logger.warning("Could not import 'ipaddress' module for validation. Proceeding without validation.")
        except ValueError:
            self.logger.error("Invalid IP address format '%s' for block_ip action.", ip)
            return

        try:
            cmd = ["sudo", "ufw", "insert", "1", "deny", "from", ip]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info("Successfully blocked IP %s. UFW output: %s", ip, result.stdout)
        except FileNotFoundError:
            self.logger.error("Failed to block IP %s: 'ufw' command not found. Is UFW installed?", ip)
        except subprocess.CalledProcessError as e:
            self.logger.error("Failed to block IP %s. UFW command failed. Error: %s", ip, e.stderr)


    def run(self):
        """Main agent loop to manage monitor processes and handle logging."""
        agent_id = self.config.get("agent", {}).get("id", "unknown")
        self.logger.info("EDR Agent starting up. Agent ID: %s", agent_id)
        
        self._load_and_start_monitors()

        try:
            while True:
                self._process_log_queue()
                for proc in self.processes:
                    if not proc.is_alive():
                        self.logger.error("A monitor process has terminated unexpectedly. PID: %s. Check logs for details.", proc.pid)
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Shutdown signal received.")
        finally:
            self.logger.info("Signaling all monitor processes to shut down...")
            self.shutdown_event.set()

            for proc in self.processes:
                proc.join(timeout=10)
                if proc.is_alive():
                    self.logger.warning("Process %s did not shut down gracefully, terminating.", proc.pid)
                    proc.terminate()

            self._process_log_queue()
            self.logger.info("EDR Agent stopped.")

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
if __name__ == "__main__":
    CONFIG_PATH = "config.json"
    CONFIG = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            content = "".join(line for line in f if not line.strip().startswith("//"))
            CONFIG = json.loads(content)
    except FileNotFoundError:
        print(f"Error: Configuration file '{CONFIG_PATH}' not found. Exiting.")
        exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Could not decode '{CONFIG_PATH}'. Check for syntax errors: {e}")
        exit(1)

    if CONFIG:
        agent = EDRAgent(config=CONFIG)
        agent.run()
    else:
        print("Error: Configuration is empty. Exiting.")
        exit(1)