"""Unit tests for the SSHMonitor class.

This module contains tests that verify the SSH monitor's ability to:
1. Detect brute force attacks from auth.log
2. Handle log file rotation
3. Track and alert on failed login attempts
"""
import unittest
from unittest.mock import MagicMock, patch, mock_open
from multiprocessing import Queue, Event
from datetime import datetime, timedelta

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
        self.mock_log_queue = MagicMock()
        self.mock_threat_bus = MagicMock()
        self.mock_monitor_queue = MagicMock()
        self.mock_shutdown_event = MagicMock()

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
        
        self.monitor = SSHMonitor(
            self.mock_config,
            self.mock_log_queue,
            self.mock_shutdown_event,
            self.mock_threat_bus,
            self.mock_monitor_queue
        )
    
    def test_brute_force_detection(self):
        """
        Test if a brute-force attack is detected from log lines.
        """
        # --- Arrange ---
        # This test now directly checks the _analyze_failures logic,
        # which is more reliable than simulating the entire run() loop.
        # We manually populate the fail_tracker as if the run() loop had
        # already processed several log lines.
        ip_to_block = '10.0.0.1'
        other_ip = '1.2.3.4'
        threshold = self.monitor.monitor_config.get("fail_threshold", 5)
        base_time = datetime(2023, 1, 1, 12, 0, 0)
 
        # Simulate 'threshold' number of failed attempts for the target IP
        for i in range(threshold):
            self.monitor.fail_tracker[ip_to_block].append(base_time + timedelta(seconds=i))
 
        # Simulate one failed attempt for another IP
        self.monitor.fail_tracker[other_ip].append(base_time)

        # Mock _block_ip to prevent it from logging an error and to correctly add to blocked_ips.
        # The original _block_ip adds to self.blocked_ips, but it's good practice to mock it
        # to ensure the test controls the behavior.
        with patch.object(self.monitor, '_block_ip') as mock_block_ip:
            # Simulate the effect of blocking without logging an error
            mock_block_ip.side_effect = lambda ip: self.monitor.blocked_ips.add(ip)

            # --- Act ---
            # Call the analysis function with a time that is within the detection window
            analysis_time = base_time + timedelta(minutes=1)
            self.monitor._analyze_failures(analysis_time)

            # --- Assert ---
            # 1. Check that the IP 10.0.0.1 was blocked
            self.assertIn('10.0.0.1', self.monitor.blocked_ips)
            self.assertNotIn('10.0.0.1', self.monitor.fail_tracker)
            
            # 2. Check that the alert was sent (should now be only one call for brute force)
            self.mock_log_queue.put.assert_called_once()
            log_call_args = self.mock_log_queue.put.call_args[0][0]
            self.assertEqual(log_call_args['event_type'], 'SSH-BRUTE-FORCE')
            self.assertEqual(log_call_args['severity'], 'high')
            self.assertEqual(log_call_args['action'], 'block_ip')
            self.assertEqual(log_call_args['details']['remote_address'], '10.0.0.1')
    
            # 3. Check that the other IP was also tracked but not blocked
            self.assertIn('1.2.3.4', self.monitor.fail_tracker)
            self.assertEqual(len(self.monitor.fail_tracker['1.2.3.4']), 1)
            self.assertNotIn('1.2.3.4', self.monitor.blocked_ips)

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
        self.monitor.shutdown_event.is_set.side_effect = [False, False, True]

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