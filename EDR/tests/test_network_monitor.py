"""
Unit tests for the NetworkMonitor class.
"""
# pylint: disable=protected-access
import sys
import time
import unittest
import threading
from multiprocessing import Event, Queue
from unittest.mock import MagicMock, patch

# Mock scapy before it's imported by the monitor
# This is a common pattern for mocking modules that may not be installed
mock_scapy_all = MagicMock()
mock_scapy_error = MagicMock()
sys.modules['scapy.all'] = mock_scapy_all
sys.modules['scapy.error'] = mock_scapy_error

# Define mock IP and TCP classes
mock_scapy_all.IP = "IP_CLASS"
mock_scapy_all.TCP = "TCP_CLASS"

# Import the class to be tested *after* mocking
from EDR.monitors.network_monitor import NetworkMonitor  # pylint: disable=wrong-import-position


class TestNetworkMonitor(unittest.TestCase):
    """
    Test suite for the NetworkMonitor class, ensuring it correctly
    identifies and reports network threats like SYN floods and port scans.
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
                "network_monitoring": {
                    "enabled": True,
                    "network_interface": "ens33",
                    "syn_flood_threshold": 30,
                    "time_window_seconds": 10,
                    "port_scan_threshold": 15
                }
            }
        }

        # Patch psutil.net_if_addrs to confirm the interface exists
        patcher = patch('psutil.net_if_addrs', MagicMock(return_value={'ens33': []}))
        self.mock_net_if = patcher.start()
        self.addCleanup(patcher.stop)

        # Instantiate the monitor
        self.monitor = NetworkMonitor(
            self.mock_config,
            self.mock_log_queue,
            self.mock_shutdown_event,
            self.mock_threat_bus,
            self.mock_monitor_queue
        )
        # The monitor's internal threads use threading.Event, which is fine
        # We will mock its main loop event
        self.monitor._thread_shutdown_event = MagicMock(spec=threading.Event)
        self.monitor._packet_arrival_event = MagicMock(spec=threading.Event)

    @patch('threading.Thread')
    def test_start_threads(self, mock_thread):
        """
        Test that the start() method launches all background threads.
        """
        # --- Act ---
        self.monitor.start()

        # --- Assert ---
        self.assertEqual(mock_thread.call_count, 4)
        targets = [call[1]['target'] for call in mock_thread.call_args_list]
        self.assertIn(self.monitor.sniff_packets, targets)
        self.assertIn(self.monitor.analyze_traffic, targets)
        self.assertIn(self.monitor.correlate_threats, targets)
        self.assertIn(self.monitor._intel_listener_loop, targets)

    def test_process_packet_syn_flood(self):
        """
        Test processing a SYN packet for SYN flood detection.
        """
        # --- Arrange ---
        # Create a mock scapy packet
        mock_ip_layer = MagicMock(src='1.1.1.1')
        mock_tcp_layer = MagicMock(flags='S', dport=80)

        mock_packet = MagicMock()
        mock_packet.__contains__.side_effect = lambda item: item in [
            mock_scapy_all.IP, mock_scapy_all.TCP
        ]
        mock_packet.__getitem__.side_effect = lambda item: {
            mock_scapy_all.IP: mock_ip_layer,
            mock_scapy_all.TCP: mock_tcp_layer
        }[item]

        # --- Act ---
        self.monitor._thread_shutdown_event.is_set.return_value = False
        with patch('time.time', MagicMock(return_value=100)):
            for _ in range(31):  # Exceed threshold of 30
                self.monitor._process_packet(mock_packet)

        # --- Assert ---
        # 1. Check that the packet_counts deque was populated
        self.assertIn('1.1.1.1', self.monitor.packet_counts)
        self.assertEqual(len(self.monitor.packet_counts['1.1.1.1']), 31)

        # 2. Check that the analysis event was set
        self.monitor._packet_arrival_event.set.assert_called()

    def test_analyze_traffic_syn_flood(self):
        """
        Test the analysis thread logic for detecting a SYN flood.
        """
        # --- Arrange ---
        # Pre-populate the packet counts
        with patch('time.time', MagicMock(return_value=100)):
            for _ in range(31):
                self.monitor.packet_counts['1.1.1.1'].append(time.time())

        # Mock the loop to run once
        self.monitor._thread_shutdown_event.is_set.side_effect = [False, True]
        # Mock the event to signal packets are ready
        self.monitor._packet_arrival_event.wait.return_value = True

        # --- Act ---
        with patch('time.time', MagicMock(return_value=105)):  # Still within 10s window
            self.monitor.analyze_traffic()

        # --- Assert ---
        # 1. Check that the alert was logged
        self.mock_log_queue.put.assert_called()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        self.assertEqual(log_call_args['event_type'], 'DOS_ATTACK_DETECTED')
        self.assertEqual(log_call_args['severity'], 'critical')
        self.assertEqual(log_call_args['action'], 'block_ip')
        self.assertEqual(log_call_args['details']['remote_address'], '1.1.1.1')

        # 2. Check that the IP was added to blocked_ips
        self.assertIn('1.1.1.1', self.monitor.blocked_ips)

    def test_handle_threat_intel(self):
        """
        Test that the monitor subscribes to suspicious PID events.
        """
        # --- Arrange ---
        message = {
            "event_type": "SUSPICIOUS_PROCESS_DETECTED",
            "data": {"pid": 1234}
        }

        # --- Act ---
        self.monitor.handle_threat_intel(message)

        # --- Assert ---
        # 1. Check that the PID was added to the suspicious set
        self.assertIn(1234, self.monitor.suspicious_pids)

        # 2. Check that a confirmation log was generated
        self.mock_log_queue.put.assert_called()
        log_call_args = self.mock_log_queue.put.call_args[0][0]
        self.assertEqual(log_call_args['event_type'], 'THREAT_INTEL_UPDATE')
        self.assertEqual(log_call_args['level'], 'info')

if __name__ == '__main__':
    unittest.main()
