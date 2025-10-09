import unittest
import queue
from unittest import mock
import time
from multiprocessing import Queue, Event
from collections import deque, defaultdict

# Add the project root to the Python path
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) # Add EDR directory to path

# Mock scapy before it's imported by the monitor
sys.modules['scapy.all'] = mock.MagicMock()
sys.modules['scapy.error'] = mock.MagicMock()

from monitors.network_monitor import NetworkMonitor

class TestNetworkMonitor(unittest.TestCase):

    def setUp(self):
        """Set up a test environment for the NetworkMonitor."""
        self.log_queue = Queue()
        self.shutdown_event = Event()
        self.threat_bus = Queue()
        self.monitor_queue = Queue()

        # Configure with low thresholds for easy testing
        self.config = {
            "agent": {"id": "test-agent"},
            "monitoring": {
                "network_monitoring": {
                    "enabled": True,
                    "syn_flood_threshold": 30,
                    "time_window_seconds": 10,
                    "port_scan_threshold": 15,
                    "udp_flood_threshold": 150, # Match config.json
                    "icmp_flood_threshold": 100 # Match config.json
                }
            }
        }

        self.monitor = NetworkMonitor(
            agent_config=self.config,
            log_queue=self.log_queue,
            shutdown_event=self.shutdown_event,
            threat_bus=self.threat_bus,
            monitor_queue=self.monitor_queue
        )

    def test_syn_flood_detection(self):
        """Test that a SYN flood is correctly detected."""
        attacker_ip = "192.168.1.100"
        current_time = time.time()

        # 1. Simulate a SYN flood by populating the packet counter
        # The number of packets (31) is just over the threshold (30)
        packet_timestamps = deque([current_time - (i * 0.1) for i in range(31)])
        packet_timestamps.reverse() # Ensure timestamps are oldest to newest
        self.monitor.syn_packet_counts[attacker_ip] = packet_timestamps

        # 2. Run the specific analysis method for SYN floods
        self.monitor._analyze_syn_flood(current_time) # pylint: disable=protected-access
        time.sleep(0.1)

        # 3. Check that an alert was generated
        try:
            log_record = self.log_queue.get_nowait()
            self.assertEqual(
                log_record["event_type"], "DOS_ATTACK_DETECTED",
                "The event_type of the alert should be 'DOS_ATTACK_DETECTED'."
            )
            self.assertIn(
                "Potential SYN flood attack detected", log_record["message"],
                "The alert message is missing the expected text."
            )
            self.assertEqual(log_record["severity"], "critical", "The alert severity should be 'critical'.")
            self.assertEqual(log_record["action"], "block_ip", "The alert action should be 'block_ip'.")
            self.assertEqual(
                log_record["details"]["remote_address"], attacker_ip,
                "The remote_address in the alert details is incorrect."
            )
            self.assertEqual(
                log_record["details"]["syn_packet_count"], 31,
                "The syn_packet_count in the alert details is incorrect."
            )
        except queue.Empty:
            self.fail("SYN flood was not detected, no log record found in the queue.")

        # 4. Verify the IP was added to the blocked set to prevent re-alerting
        self.assertIn(attacker_ip, self.monitor.blocked_ips, "Attacker IP was not added to the blocked_ips set.")

    def test_no_syn_flood_below_threshold(self):
        """Test that no alert is generated when packet count is below threshold."""
        normal_ip = "192.168.1.101"
        current_time = time.time()

        # Simulate normal traffic (29 packets is below the threshold of 30)
        packet_timestamps = deque([current_time - i for i in range(29)])
        self.monitor.syn_packet_counts[normal_ip] = packet_timestamps

        # Run the analysis
        self.monitor._analyze_syn_flood(current_time) # pylint: disable=protected-access
        time.sleep(0.1)

        # Assert that the log queue is empty
        self.assertTrue(self.log_queue.empty(), "An alert was incorrectly generated for normal traffic.")

    def test_port_scan_detection(self):
        """Test that a port scan is correctly detected."""
        attacker_ip = "10.0.0.5"
        current_time = time.time()

        # 1. Simulate a port scan by populating the tracker
        # The number of ports (16) is just over the threshold (15)
        for i in range(16):
            port = 80 + i # Use a range of ports
            self.monitor.port_scan_tracker[attacker_ip][port].append(current_time - (i * 0.1))

        # 2. Run the specific analysis method for port scans
        self.monitor._analyze_port_scan(current_time) # pylint: disable=protected-access
        time.sleep(0.1)

        # 3. Check that an alert was generated
        try:
            log_record = self.log_queue.get_nowait()
            self.assertEqual(log_record["event_type"], "PORT_SCAN_DETECTED")
            self.assertIn(
                "Potential port scan detected", log_record["message"]
            )
            self.assertEqual(log_record["severity"], "high")
            self.assertEqual(log_record["action"], "block_ip")
            self.assertEqual(
                log_record["details"]["remote_address"], attacker_ip
            )
            self.assertEqual(
                log_record["details"]["port_count"], 16
            )
            self.assertEqual(
                len(log_record["details"]["scanned_ports"]), 16
            )
        except queue.Empty:
            self.fail("Port scan was not detected, no log record found in the queue.")

        # 4. Verify the IP was added to the blocked set
        self.assertIn(attacker_ip, self.monitor.blocked_ips, "Attacker IP was not added to the blocked_ips set.")

    def test_udp_flood_detection(self):
        """Test that a UDP flood is correctly detected."""
        attacker_ip = "192.168.1.102"
        current_time = time.time()

        # 1. Simulate a UDP flood (151 packets > threshold of 150)
        packet_timestamps = deque([current_time - (i * 0.01) for i in range(151)])
        packet_timestamps.reverse() # Ensure timestamps are oldest to newest
        self.monitor.udp_packet_counts[attacker_ip] = packet_timestamps

        # 2. Run the analysis
        self.monitor._analyze_udp_flood(current_time) # pylint: disable=protected-access
        time.sleep(0.1)

        # 3. Check for an alert
        try:
            log_record = self.log_queue.get_nowait()
            self.assertEqual(log_record["event_type"], "DOS_ATTACK_DETECTED")
            self.assertIn("Potential UDP flood attack detected", log_record["message"])
            self.assertEqual(log_record["severity"], "critical")
            self.assertEqual(log_record["action"], "block_ip")
            self.assertEqual(log_record["details"]["remote_address"], attacker_ip)
            self.assertEqual(log_record["details"]["udp_packet_count"], 151)
        except queue.Empty:
            self.fail("UDP flood was not detected, no log record found.")

        # 4. Verify IP is blocked
        self.assertIn(attacker_ip, self.monitor.blocked_ips)

    def test_icmp_flood_detection(self):
        """Test that an ICMP flood is correctly detected."""
        attacker_ip = "192.168.1.103"
        current_time = time.time()

        # 1. Simulate an ICMP flood (101 packets > threshold of 100)
        packet_timestamps = deque([current_time - (i * 0.01) for i in range(101)])
        packet_timestamps.reverse() # Ensure timestamps are oldest to newest
        self.monitor.icmp_packet_counts[attacker_ip] = packet_timestamps

        # 2. Run the analysis
        self.monitor._analyze_icmp_flood(current_time) # pylint: disable=protected-access
        time.sleep(0.1)

        # 3. Check for an alert
        try:
            log_record = self.log_queue.get_nowait()
            self.assertEqual(log_record["event_type"], "DOS_ATTACK_DETECTED")
            self.assertIn("Potential ICMP (Ping) flood attack detected", log_record["message"])
            self.assertEqual(log_record["severity"], "critical")
            self.assertEqual(log_record["action"], "block_ip")
            self.assertEqual(log_record["details"]["remote_address"], attacker_ip)
            self.assertEqual(log_record["details"]["icmp_packet_count"], 101)
        except queue.Empty:
            self.fail("ICMP flood was not detected, no log record found.")

        # 4. Verify IP is blocked
        self.assertIn(attacker_ip, self.monitor.blocked_ips)

    def tearDown(self):
        """Clean up after tests."""
        self.shutdown_event.set()

        # Re-initialize state to prevent leakage
        if hasattr(self, 'monitor'):
            self.monitor.syn_packet_counts = defaultdict(deque)
            self.monitor.udp_packet_counts = defaultdict(deque)
            self.monitor.icmp_packet_counts = defaultdict(deque)
            self.monitor.port_scan_tracker = defaultdict(lambda: defaultdict(deque))
            self.monitor.blocked_ips = set()

        # Empty the queues to ensure clean state for next test
        for q in [self.log_queue, self.threat_bus, self.monitor_queue]:
            try:
                while not q.empty():
                    q.get_nowait()
            except queue.Empty:
                pass

if __name__ == '__main__':
    unittest.main(verbosity=2)