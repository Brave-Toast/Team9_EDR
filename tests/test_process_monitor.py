import unittest
from unittest.mock import MagicMock, patch
import queue
from multiprocessing import Queue, Event

# Add the project root to the Python path
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from EDR.monitors.process_monitor import ProcessMonitor

class TestProcessMonitor(unittest.TestCase):

    def setUp(self):
        """Set up a test environment for the ProcessMonitor."""
        self.log_queue = Queue()
        self.shutdown_event = Event()
        self.threat_bus = Queue()
        self.monitor_queue = Queue()

        self.config = {
            "agent": {
                "id": "test-agent",
                "log_level": "info",
                "heartbeat_interval_seconds": 60
            },
            "monitoring": {
                "process_monitoring": {
                    "enabled": True,
                    "processes": []
                }
            },
            "detection_rules": {
                "suspicious_commands": ["evil_command"]
            }
        }

        self.monitor = ProcessMonitor(
            agent_config=self.config,
            log_queue=self.log_queue,
            shutdown_event=self.shutdown_event,
            threat_bus=self.threat_bus,
            monitor_queue=self.monitor_queue
        )

    def test_initialization(self):
        """Test that the monitor initializes correctly."""
        self.assertIsInstance(self.monitor, ProcessMonitor)
        self.assertEqual(self.monitor.get_name(), "process_monitoring")

    @patch('psutil.process_iter')
    def test_suspicious_process_detection(self, mock_process_iter):
        """Test that a suspicious process is correctly detected."""
        # Mock a suspicious process
        mock_proc = MagicMock()
        mock_proc.pid = 1234
        mock_proc.name.return_value = "evil_process"
        mock_proc.cmdline.return_value = ["evil_command", "--arg1"]
        
        # Mock psutil.process_iter to return our suspicious process
        mock_process_iter.return_value = [mock_proc]

        # Set initial known PIDs to an empty set
        self.monitor.known_pids = set()

        # Run the monitor's check
        self.monitor.run() # We need to call the run method to trigger the check

        # Check if an alert was logged
        try:
            log_record = self.log_queue.get_nowait()
            self.assertEqual(log_record["event_type"], "PROCESS")
            self.assertIn("Suspicious command in new process", log_record["message"])
            self.assertEqual(log_record["details"]["pid"], 1234)
        except queue.Empty:
            self.fail("No log record found in the queue.")

    def tearDown(self):
        """Clean up after tests."""
        self.shutdown_event.set()
        # It's good practice to empty the queues
        while not self.log_queue.empty():
            self.log_queue.get()
        while not self.threat_bus.empty():
            self.threat_bus.get()
        while not self.monitor_queue.empty():
            self.monitor_queue.get()

if __name__ == '__main__':
    unittest.main()
