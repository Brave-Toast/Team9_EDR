"""Unit tests for the SSHMonitor class.

This module contains tests that verify the SSH monitor's ability to:
1. Detect brute force attacks from auth.log
2. Handle log file rotation
3. Track and alert on failed login attempts
"""
import unittest
from unittest.mock import MagicMock, patch, mock_open
from multiprocessing import Queue, Event
from datetime import datetime

# Import the class to be tested
from EDR.monitors.ssh_monitor import SSHMonitor

class TestSSHMonitor(unittest.TestCase):
    """Test suite for the SSHMonitor class.
    
    Tests monitor functionality for:
    - SSH brute force attack detection
    - Log file rotation handling
    - Failed login tracking
    - Alert generation for security events
    """

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
                "ssh_monitoring": {
                    "enabled": True,
                    "log_path": "/var/log/auth.log",
                    "fail_threshold": 5,
                    "time_window_minutes": 5
                }
            }
        }
        
        self.mock_shutdown_event.is_set.side_effect = [False, True] # Run loop once

        self.monitor = SSHMonitor(
            self.mock_config,
            self.mock_log_queue,
            self.mock_shutdown_event,
            self.mock_threat_bus,
            self.mock_monitor_queue
        )
    
    @patch('os.stat')
    @patch('builtins.open', new_callable=mock_open)
    def test_brute_force_detection(self, mock_file, mock_stat):
        """
        Test if a brute-force attack is detected from log lines.
        """
        # --- Arrange ---
        log_lines = [
            "Oct 22 15:00:00 server sshd[123]: Failed password for user from 10.0.0.1 port 1234 ssh2",
            "Oct 22 15:00:01 server sshd[123]: Failed password for invalid user admin from 10.0.0.1 port 1235 ssh2",
            "Oct 22 15:00:02 server sshd[123]: Failed password for user from 10.0.0.1 port 1236 ssh2",
            "Oct 22 15:00:03 server sshd[123]: Failed password for user from 10.0.0.1 port 1237 ssh2",
            "Oct 22 15:00:04 server sshd[123]: Failed password for user from 10.0.0.1 port 1238 ssh2",
            "Oct 22 15:00:05 server sshd[123]: Failed password for user from 1.2.3.4 port 1238 ssh2" # Different IP
        ]
        mock_file.return_value.readlines.return_value = log_lines
        mock_file.return_value.__iter__.return_value = iter(log_lines)
        
        # Mock os.stat to return a consistent inode
        mock_stat.return_value = MagicMock(st_ino=12345)

        # --- Act ---
        self.monitor.run()

        # --- Assert ---
        # 1. Check that the IP 10.0.0.1 was tracked
        self.assertIn('10.0.0.1', self.monitor.fail_tracker)
        self.assertEqual(len(self.monitor.fail_tracker['10.0.0.1']), 5)
        
        # 2. Check that the alert was sent
        self.mock_log_queue.put.assert_called()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        self.assertEqual(log_call_args['event_type'], 'SSH-BRUTE-FORCE')
        self.assertEqual(log_call_args['severity'], 'high')
        self.assertEqual(log_call_args['action'], 'block_ip')
        self.assertEqual(log_call_args['details']['remote_address'], '10.0.0.1')

        # 3. Check that the other IP was also tracked
        self.assertIn('1.2.3.4', self.monitor.fail_tracker)
        self.assertEqual(len(self.monitor.fail_tracker['1.2.3.4']), 1)

    @patch('os.stat')
    @patch('builtins.open', new_callable=mock_open)
    def test_log_rotation(self, _mock_file, mock_stat):
        """Test if the monitor correctly detects a log file rotation (inode change)."""
        # --- Arrange ---
        # Simulate the inode changing on the second check
        mock_stat.side_effect = [
            MagicMock(st_ino=12345), # First call
            MagicMock(st_ino=67890)  # Second call
        ]
        # Stop the loop after the second run
        self.mock_shutdown_event.is_set.side_effect = [False, False, True]

        # Give the monitor an initial state
        self.monitor.log_inode = 12345
        self.monitor.log_pos = 999
        self.monitor.fail_tracker['1.1.1.1'].append(datetime.now())

        # --- Act ---
        self.monitor.run()

        # --- Assert ---
        # 1. Check that the log rotation was logged
        self.mock_log_queue.put.assert_called()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        self.assertEqual(log_call_args['event_type'], 'LIFECYCLE')
        self.assertIn('rotated. Resetting', log_call_args['message'])

        # 2. Check that the monitor's state was reset
        self.assertEqual(self.monitor.log_inode, 67890)
        self.assertEqual(self.monitor.log_pos, 0)
        self.assertEqual(len(self.monitor.fail_tracker), 0)

if __name__ == '__main__':
    unittest.main()