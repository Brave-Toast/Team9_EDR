#!/usr/bin/env python3
import time
import os
import logging
import json
import pkgutil
import importlib
import inspect
import sys
import queue
import subprocess
from multiprocessing import Process, Queue, Event

# Add the project root to the Python path to help with module resolution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# Import the base class that all monitors will inherit from
from monitors.base_monitor import BaseMonitor

# ==============================================================================
# CUSTOM JSON FORMATTER
# ==============================================================================

class JsonFormatter(logging.Formatter):
    """
    Formats log records as a single line of JSON.
    """
    def format(self, record):
        log_object = {}
        if isinstance(record.msg, dict):
            # If the message is a dictionary, use it as the base.
            log_object.update(record.msg)
            # Ensure a 'message' field exists for consistency. If the original
            # dict didn't have one, we create one from its string representation.
            if 'message' not in log_object:
                log_object['message'] = str(record.msg)
        else:
            # If the message is a string, get the fully formatted version.
            log_object = {'message': record.getMessage()}

        # Add standard logging fields, overwriting if necessary for consistency.
        log_object['timestamp'] = self.formatTime(record, self.datefmt) 
        log_object['logger'] = record.name
        if record.exc_info:
            log_object['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(log_object)

# ==============================================================================
# EDR AGENT CORE
# ==============================================================================

class EDRAgent:
    """
    A modular, multi-process EDR agent.
    """

    def __init__(self, config):
        self.config = config
        self.logger = self._setup_logging()
        self.log_queue = Queue()
        self.processes = []
        self.shutdown_event = Event()
        self.action_dispatcher = {
            "kill_process": self._handle_kill_process,
            "block_ip": self._handle_block_ip,
        }

    def _setup_logging(self):
        """
        Configures the logger to output JSON to standard output.
        """
        logger = logging.getLogger("EDRAgent")
        log_level = self.config.get("agent", {}).get("log_level", "INFO").upper()
        logger.setLevel(log_level)

        # Prevent duplicate handlers
        if logger.hasHandlers():
            logger.handlers.clear()

        # Create a handler that writes to standard output (the console)
        handler = logging.StreamHandler(sys.stdout)
        
        # Instantiate our custom JSON formatter
        formatter = JsonFormatter()
        
        # Set the formatter for the handler
        handler.setFormatter(formatter)
        
        # Add the handler to the logger
        logger.addHandler(handler)

        return logger

    def _load_and_start_monitors(self):
        """Dynamically loads monitors and starts each in its own process."""
        self.logger.info("Loading and starting monitor processes...")
        monitors_package_path = "monitors"
        
        for _, module_name, _ in pkgutil.iter_modules([monitors_package_path]):
            if module_name == 'base_monitor':
                continue
            try:
                module = importlib.import_module(f"{monitors_package_path}.{module_name}")
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BaseMonitor) and obj is not BaseMonitor:
                        # Instantiate the monitor, giving it the config, queue, and shutdown event
                        monitor_instance = obj(self.config, self.log_queue, self.shutdown_event)
                        
                        # Create a new process targeting the monitor's run_wrapper method
                        proc = Process(target=monitor_instance.run_wrapper, daemon=True)
                        self.processes.append(proc)
                        proc.start()
                        self.logger.info("  -> Started process for monitor: %s", name)
            except (ImportError, AttributeError, TypeError) as e:
                self.logger.error("Failed to load and start monitor plugin '%s': %s", module_name, e)
        
        self.logger.info("All monitor processes have been started.")

    def _process_log_queue(self):
        """
        Checks the log queue, logs messages, and dispatches active responses.
        """
        try:
            while not self.log_queue.empty():
                log_record = self.log_queue.get_nowait()
                
                # --- Part 1: Always log the event ---
                log_level_name = log_record.get("level", "info")
                log_func = getattr(self.logger, log_level_name, self.logger.info)
                log_func(log_record)

                # --- Part 2: Dispatch active response if needed ---
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
            p.terminate()  # or p.kill() for a more forceful stop
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
        ip = details.get("source_ip")

        if not ip or not isinstance(ip, str):
            self.logger.error("Invalid or missing source_ip for block_ip action in alert: %s", alert)
            return

        # Validate the IP address format
        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ImportError:
            self.logger.warning("Could not import 'ipaddress' module for validation. Proceeding without validation.")
        except ValueError:
            self.logger.error("Invalid IP address format '%s' for block_ip action.", ip)
            return

        try:
            # This command is for UFW (Uncomplicated Firewall) on Ubuntu
            # WARNING: This requires the agent to have passwordless sudo permissions for ufw.
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
                # Check if any processes have died unexpectedly
                for proc in self.processes:
                    if not proc.is_alive():
                        self.logger.error("A monitor process has terminated unexpectedly. PID: %s. Check logs for details.", proc.pid)
                        # In a real-world scenario, you might want to restart the process here.
                        # For now, we'll just log it.
                time.sleep(1) # The main loop can sleep for short intervals
        except KeyboardInterrupt:
            self.logger.info("Shutdown signal received.")
        finally:
            self.logger.info("Signaling all monitor processes to shut down...")
            self.shutdown_event.set() # <-- This is the new graceful shutdown signal

            for proc in self.processes:
                proc.join(timeout=10) # Wait for each process to finish
                if proc.is_alive():
                    # If a process is stuck, terminate it forcefully
                    self.logger.warning("Process %s did not shut down gracefully, terminating.", proc.pid)
                    proc.terminate()

            # Process any final logs
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
            # Remove comments from JSON before parsing
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