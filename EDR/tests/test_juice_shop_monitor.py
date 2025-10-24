"""Unit tests for the JuiceShopMonitor class."""
# pylint: disable=protected-access, too-many-instance-attributes
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch
from multiprocessing import Queue, Event

# Import the class to be tested
from EDR.monitors.juice_shop_monitor import JuiceShopMonitor


class TestJuiceShopMonitor(unittest.TestCase):
    """
    Test suite for the JuiceShopMonitor, verifying its ability to detect
    security threats by analyzing Juice Shop access logs.
    """

    def setUp(self):
        """Set up a mock environment for each test."""
        self.mock_log_queue = MagicMock(spec=Queue)
        self.mock_threat_bus = MagicMock(spec=Queue)
        self.mock_monitor_queue = MagicMock(spec=Queue)
        self.mock_shutdown_event = MagicMock(spec=Event)

        # Mock the config.json structure
        self.mock_config = {
            "agent": {"heartbeat_interval_seconds": 60},
            "monitoring": {
                "juice_shop_monitoring": {
                    "enabled": True,
                    "log_directory": "/home/juice/juice-shop/logs/",
                    "log_pattern": "access.log*",
                    "error_threshold": 10,
                    "error_time_window_minutes": 1,
                }
            },
            "detection_rules": {
                "web_attack_patterns": [
                    "SELECT.*FROM",
                    "<script>",
                    "../"
                ]
            }
        }

        # Patch the observer
        patcher = patch('watchdog.observers.Observer')
        self.mock_observer = patcher.start()
        self.addCleanup(patcher.stop)

        self.monitor = JuiceShopMonitor(
            self.mock_config,
            self.mock_log_queue,
            self.mock_shutdown_event,
            self.mock_threat_bus,
            self.mock_monitor_queue
        )

        # Mock time.time() for brute-force window check
        self.mock_time = patch('time.time', MagicMock())
        self.mock_time.start()
        self.addCleanup(self.mock_time.stop)

        # Patch datetime.now() to control the time window
        mock_dt = patch('EDR.monitors.juice_shop_monitor.datetime')
        self.mock_datetime = mock_dt.start()
        self.addCleanup(mock_dt.stop)

    def test_analyze_line_brute_force(self):
        """
        Test detection of a brute-force attack from 401 logs.
        """
        # --- Arrange ---
        log_line = (
            '::ffff:1.2.3.4 - - [22/Oct/2025:15:30:00 +0000] "POST /rest/user/login HTTP/1.1" 401 139'
        )
        threshold = self.monitor.failed_login_threshold  # 5

        # --- Act ---
        # Simulate 5 failed logins within the 10-second window
        for i in range(threshold):
            self.mock_time.return_value = 100 + i  # 100, 101, 102, 103, 104
            self.monitor._analyze_line(log_line)

        # --- Assert ---
        # 1. Check that the alert was logged on the 5th attempt
        self.mock_log_queue.put.assert_called_once()
        log_call_args = self.mock_log_queue.put.call_args[0][0]

        self.assertEqual(log_call_args['event']['type'], 'brute-force-blocked')
        self.assertEqual(log_call_args['action'], 'block_ip')
        self.assertEqual(log_call_args['details']['remote_address'], '1.2.3.4')
        self.assertEqual(log_call_args['details']['failed_attempts'], 5)

        # 2. Check that the IP is now blocked internally
        self.assertIn('1.2.3.4', self.monitor.blocked_ips)

    def test_analyze_line_sql_injection(self):
        """
        Test detection of an SQL injection attack from web attack patterns.
        """
        # --- Arrange ---
        # This log line matches 'SELECT.*FROM' rule
        log_line = (
            '::ffff:2.3.4.5 - - [22/Oct/2025:15:31:00 +0000] "GET /api/Products?search=\' '
            'UNION SELECT 1,2,name,4,5,6,7,8,9 FROM Users-- HTTP/1.1" 200 1205'
        )

        # --- Act ---
        self.monitor._analyze_line(log_line)

        # --- Assert ---
        # 1. Two alerts should be sent: the "ATTACK" detection and the "block_ip" action
        self.assertEqual(self.mock_log_queue.put.call_count, 2)

        # 2. Check the "JUICE-SHOP-ATTACK" alert
        call1_args = self.mock_log_queue.put.call_args_list[0][0][0]
        self.assertEqual(call1_args['event_type'], 'JUICE-SHOP-ATTACK')

        # 3. Check the "sql-injection-blocked" alert
        call2_args = self.mock_log_queue.put.call_args_list[1][0][0]
        self.assertEqual(call2_args['event']['type'], 'sql-injection-blocked')
        self.assertEqual(call2_args['action'], 'block_ip')
        self.assertEqual(call2_args['details']['remote_address'], '2.3.4.5')

        # 4. Check that the IP is now blocked internally
        self.assertIn('2.3.4.5', self.monitor.blocked_ips)

    def test_analyze_error_spike(self):
        """
        Test detection of an error spike.
        """
        # --- Arrange ---
        log_line = (
            '::ffff:3.4.5.6 - - [22/Oct/2025:15:32:00 +0000] "POST /api/Users HTTP/1.1" 500 78'
        )
        threshold = self.monitor.error_threshold  # 10

        # --- Act ---
        # 1. Simulate 11 errors (above threshold) all at the same time
        now = datetime.now()
        self.mock_datetime.now.return_value = now
        for _ in range(threshold + 1):
            self.monitor._analyze_line(log_line)

        # 2. Call the spike analysis function (normally called periodically)
        self.monitor._analyze_error_spikes()

        # --- Assert ---
        # 1. Check that the spike was logged
        self.mock_log_queue.put.assert_called_once()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        self.assertEqual(log_call_args['event_type'], 'JUICE-SHOP-ERROR-SPIKE')
        self.assertIn('Error spike detected: 11 errors', log_call_args['message'])

        # 2. Check that the tracker was reset
        self.assertEqual(len(self.monitor.error_tracker), 0)


if __name__ == '__main__':
    unittest.main()