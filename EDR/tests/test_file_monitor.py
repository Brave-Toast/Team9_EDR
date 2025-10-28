"""
Unit tests for the FileMonitor class.
"""
import unittest
from unittest.mock import MagicMock, patch, mock_open
from multiprocessing import Queue, Event
from EDR.monitors.file_monitor import FileMonitor, _FileChangeHandler


class TestFileMonitor(unittest.TestCase):
    """
    Test suite for the FileMonitor class.
    """

    def setUp(self):
        """Set up a mock environment for each test."""
        # Use plain MagicMocks to ensure all expected attributes are available
        self.mock_log_queue = MagicMock()
        self.mock_threat_bus = MagicMock()
        self.mock_monitor_queue = MagicMock()
        self.mock_shutdown_event = MagicMock()

        # Mock the config.json structure
        self.mock_config = {
            "agent": {"heartbeat_interval_seconds": 60},
            "monitoring": {
                "file_integrity": {
                    "enabled": True,
                    "paths": [
                        "/etc/passwd",
                        "/home/juice/juice-shop"
                    ]
                }
            },
            "detection_rules": {
                "web_attack_patterns": [
                    "<script>",
                    "SELECT.*FROM"
                ]
            }
        }

        # Mock the observer instance returned by Observer() (patch the
        # reference used inside the module under test to avoid starting real
        # watchdog observer threads during unit tests)
        self.mock_observer_instance = MagicMock()
        # pylint: disable=E1101
        patch('EDR.monitors.file_monitor.Observer', return_value=self.mock_observer_instance).start()

        self.monitor = FileMonitor(
            self.mock_config,
            self.mock_log_queue,
            self.mock_shutdown_event,
            self.mock_threat_bus,
            self.mock_monitor_queue
        )

    @patch('os.path.exists', MagicMock(return_value=True))
    def test_start_monitor(self):
        """
        Test that the monitor schedules paths and starts the observer.
        """
        # --- Act ---
        self.monitor.start()

        # --- Assert ---
        # 1. Check that schedule was called for each path in the config
        self.assertEqual(self.mock_observer_instance.schedule.call_count, 2)

        # 2. Check that the observer was started
        self.mock_observer_instance.start.assert_called_once()

    def test_file_change_handler_suspicious_content(self):
        """
        Test the handler's on_created method for a file with bad content.
        """
        # --- Arrange ---
        handler = _FileChangeHandler(self.monitor, self.monitor.web_attack_patterns)
        mock_event = MagicMock(is_directory=False, src_path="/home/juice/juice-shop/test.js")

        # Mock reading the file's content
        m_open = mock_open(read_data="var x = '<script>alert(1)</script>';")

        # --- Act ---
        with patch('builtins.open', m_open):
            handler.on_created(mock_event)

        # --- Assert ---
        # 1. Check that a "FILE-CONTENT" alert was logged
        self.mock_log_queue.put.assert_called_once()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        self.assertEqual(log_call_args['event_type'], 'FILE-CONTENT')
        self.assertIn("Suspicious content found", log_call_args['message'])
        self.assertIn("<script>", log_call_args['message'])

    def test_file_change_handler_normal_file(self):
        """
        Test the handler's on_created method for a file with normal content.
        """
        # --- Arrange ---
        handler = _FileChangeHandler(self.monitor, self.monitor.web_attack_patterns)
        mock_event = MagicMock(is_directory=False, src_path="/home/juice/juice-shop/README.md")

        m_open = mock_open(read_data="This is a normal file.")

        # --- Act ---
        with patch('builtins.open', m_open):
            handler.on_created(mock_event)

        # --- Assert ---
        # 1. Check that a normal "FILE" alert was logged
        self.mock_log_queue.put.assert_called_once()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        self.assertEqual(log_call_args['event_type'], 'FILE')
        self.assertEqual(log_call_args['level'], 'info')
        self.assertIn("File Created", log_call_args['message'])

    def test_file_change_handler_directory(self):
        """
        Test the handler's on_deleted method for a directory.
        """
        # --- Arrange ---
        handler = _FileChangeHandler(self.monitor, self.monitor.web_attack_patterns)
        mock_event = MagicMock(is_directory=True, src_path="/home/juice/juice-shop/temp_dir")

        # --- Act ---
        handler.on_deleted(mock_event)

        # --- Assert ---
        # 1. Check that a "DIRECTORY" alert was logged
        self.mock_log_queue.put.assert_called_once()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        self.assertEqual(log_call_args['event_type'], 'DIRECTORY')
        self.assertEqual(log_call_args['level'], 'info')
        self.assertIn("Directory Deleted", log_call_args['message'])


if __name__ == '__main__':
    unittest.main()
