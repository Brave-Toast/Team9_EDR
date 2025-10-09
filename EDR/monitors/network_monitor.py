"""
Network monitoring module for the EDR agent.

This module provides capabilities to monitor network traffic for suspicious
activity, including SYN floods and port scans. It uses scapy for packet
sniffing and analysis.
"""
import threading
import time
from collections import defaultdict, deque
from multiprocessing import Queue
from multiprocessing.synchronize import Event

import psutil
from monitors.base_monitor import BaseMonitor

try:
    from scapy.all import IP, TCP, UDP, ICMP, sniff
    from scapy.error import Scapy_Exception
except ImportError:
    # scapy is not installed, we will raise an error in the run method
    sniff = None
    Scapy_Exception = None


class NetworkMonitor(BaseMonitor):
    """
    Monitors network traffic for threats.
    """
    def get_name(self):
        return "network_monitoring"

    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event,
                 threat_bus: Queue, monitor_queue: Queue):
        super().__init__(agent_config, log_queue, shutdown_event, threat_bus, monitor_queue)
        self.reported_conns = set()
        self.suspicious_pids = set()

        # SYN Flood and Port Scan detection attributes
        self.syn_flood_threshold = self.monitor_config.get("syn_flood_threshold", 30)
        self.port_scan_threshold = self.monitor_config.get("port_scan_threshold", 15)
        self.udp_flood_threshold = self.monitor_config.get("udp_flood_threshold", 150)
        self.icmp_flood_threshold = self.monitor_config.get("icmp_flood_threshold", 100)
        self.time_window = self.monitor_config.get("time_window_seconds", 10)

        self.syn_packet_counts = defaultdict(deque)
        self.udp_packet_counts = defaultdict(deque)
        self.icmp_packet_counts = defaultdict(deque)
        self.port_scan_tracker = defaultdict(lambda: defaultdict(deque))

        self.blocked_ips = set()
        
        # Use a thread-safe event for coordinating threads within this monitor
        self._thread_shutdown_event = threading.Event()
        
        # Event to signal the analysis thread that new packets have arrived
        self._packet_arrival_event = threading.Event()
        self.network_interface = self.monitor_config.get("network_interface")

    def handle_threat_intel(self, message: dict):
        """
        Handles threat intelligence messages from the bus, subscribing to
        suspicious process events.
        """
        if message.get("event_type") == "SUSPICIOUS_PROCESS_DETECTED":
            pid = message.get("data", {}).get("pid")
            if pid:
                self.log_alert(
                    "THREAT_INTEL_UPDATE",
                    f"Received threat intel: Process PID {pid} is suspicious. "
                    "Now monitoring its network activity.",
                    level="info",
                    severity="low"
                )
                self.suspicious_pids.add(pid)

    def _process_packet(self, packet):
        if self._thread_shutdown_event.is_set():
            return

        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            current_time = time.time()

            # TCP Packet Analysis (SYN Flood, Port Scan)
            if TCP in packet:
                tcp_layer = packet[TCP]
                # We are only interested in SYN packets for these detections
                if tcp_layer.flags == 'S':
                    dst_port = tcp_layer.dport
                    self.syn_packet_counts[src_ip].append(current_time)
                    self.port_scan_tracker[src_ip][dst_port].append(current_time)
                    self._packet_arrival_event.set()

            # UDP Flood Analysis
            elif UDP in packet:
                self.udp_packet_counts[src_ip].append(current_time)
                self._packet_arrival_event.set()

            # ICMP Flood Analysis
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                # Type 8 is Echo Request (ping)
                if icmp_layer.type == 8:
                    self.icmp_packet_counts[src_ip].append(current_time)
                    self._packet_arrival_event.set()

    def sniff_packets(self):
        """
        Starts the scapy packet sniffer.
        """
        self.log_alert("LIFECYCLE", "Packet sniffer thread started.", "info")
        try:
            # Sniff in short, non-blocking intervals to allow for graceful shutdown.
            sniff_kwargs = {"prn": self._process_packet, "store": False, "filter": "ip", "timeout": 1}
            if self.network_interface:
                sniff_kwargs["iface"] = self.network_interface

            while not self._thread_shutdown_event.is_set():
                sniff(**sniff_kwargs)

        except Scapy_Exception as e:
            self.log_alert("CRITICAL", f"Scapy sniffing failed: {e}. The agent must be run with root privileges (sudo).", "error")
        except Exception as e: # pylint: disable=broad-exception-caught
            # Catch other potential startup errors, e.g., on different OS
            self.log_alert("CRITICAL", f"An unexpected error occurred starting the sniffer: {e}", "error")

    def analyze_traffic(self):
        """
        Continuously analyzes captured packet data for threats in a tight loop.
        This runs in its own thread for high responsiveness.
        """
        while not self._thread_shutdown_event.is_set():
            # Wait for a signal that packets have arrived, with a timeout.
            # The timeout allows periodic cleanup even with no traffic.
            if not self._packet_arrival_event.wait(timeout=self.time_window):
                continue # Woke up due to timeout, loop again
            self._packet_arrival_event.clear() # Reset the event

            try:
                current_time = time.time()
                self._analyze_syn_flood(current_time)
                self._analyze_udp_flood(current_time)
                self._analyze_icmp_flood(current_time)
                self._analyze_port_scan(current_time)
            except Exception as e: # pylint: disable=broad-exception-caught
                self.log_alert("CRITICAL", f"An unexpected error occurred during traffic analysis: {e}", "error")
                time.sleep(1) # Sleep briefly on error

    def _analyze_syn_flood(self, current_time: float):
        """Analyzes collected SYN packets for flood attacks."""
        # Iterate over a copy of keys to allow for modification during iteration
        for ip in list(self.syn_packet_counts.keys()):
            timestamps = self.syn_packet_counts[ip]
            while timestamps and current_time - timestamps[0] > self.time_window:
                timestamps.popleft()

            if len(timestamps) >= self.syn_flood_threshold:
                if ip not in self.blocked_ips:
                    self.log_alert(
                        "DOS_ATTACK_DETECTED",
                        f"Potential SYN flood attack detected from IP address: {ip}",
                        severity="critical",
                        details={
                            "remote_address": ip,
                            "syn_packet_count": len(timestamps),
                            "time_window_seconds": self.time_window
                        },
                        action="block_ip"
                    )
                    self.blocked_ips.add(ip)
                self.syn_packet_counts[ip].clear() # De-indent to always clear after detection

    def _analyze_udp_flood(self, current_time: float):
        """Analyzes collected UDP packets for flood attacks."""
        # Iterate over a copy of keys to allow for modification during iteration
        for ip in list(self.udp_packet_counts.keys()):
            timestamps = self.udp_packet_counts[ip]
            while timestamps and current_time - timestamps[0] > self.time_window:
                timestamps.popleft()

            if len(timestamps) >= self.udp_flood_threshold:
                if ip not in self.blocked_ips:
                    self.log_alert(
                        "DOS_ATTACK_DETECTED",
                        f"Potential UDP flood attack detected from IP address: {ip}",
                        severity="critical",
                        details={
                            "remote_address": ip,
                            "udp_packet_count": len(timestamps),
                            "time_window_seconds": self.time_window
                        },
                        action="block_ip"
                    )
                    self.blocked_ips.add(ip)
                self.udp_packet_counts[ip].clear()

    def _analyze_icmp_flood(self, current_time: float):
        """Analyzes collected ICMP packets for flood attacks."""
        # Iterate over a copy of keys to allow for modification during iteration
        for ip in list(self.icmp_packet_counts.keys()):
            timestamps = self.icmp_packet_counts[ip]
            while timestamps and current_time - timestamps[0] > self.time_window:
                timestamps.popleft()

            if len(timestamps) >= self.icmp_flood_threshold:
                if ip not in self.blocked_ips:
                    self.log_alert(
                        "DOS_ATTACK_DETECTED",
                        f"Potential ICMP (Ping) flood attack detected from IP address: {ip}",
                        severity="critical",
                        details={
                            "remote_address": ip,
                            "icmp_packet_count": len(timestamps),
                            "time_window_seconds": self.time_window
                        },
                        action="block_ip"
                    )
                    self.blocked_ips.add(ip)
                self.icmp_packet_counts[ip].clear()

    def _analyze_port_scan(self, current_time: float):
        """Analyzes collected connection attempts for port scans."""
        # Iterate over a copy of keys to allow for modification during iteration
        for ip in list(self.port_scan_tracker.keys()):
            port_data = self.port_scan_tracker[ip]
            scanned_ports = set()
            for port, timestamps in list(port_data.items()): # Inner loop is fine
                while timestamps and current_time - timestamps[0] > self.time_window:
                    timestamps.popleft()
                if timestamps:
                    scanned_ports.add(port)
                else:
                    del port_data[port]

            if len(scanned_ports) >= self.port_scan_threshold:
                if ip not in self.blocked_ips:
                    self.log_alert(
                        "PORT_SCAN_DETECTED",
                        f"Potential port scan detected from IP address: {ip}",
                        severity="high",
                        details={
                            "remote_address": ip,
                            "port_count": len(scanned_ports),
                            "time_window_seconds": self.time_window,
                            "scanned_ports": sorted(list(scanned_ports))
                        },
                        action="block_ip"
                    )
                    self.blocked_ips.add(ip)

    def correlate_threats(self):
        """
        Periodically checks network connections of known suspicious processes.
        This runs in its own thread.
        """
        while not self._thread_shutdown_event.is_set():
            try:
                # This check is less time-sensitive, so we can use the main interval.
                if self._thread_shutdown_event.wait(self.interval):
                    break # Exit if shutdown is signaled

                if not self.suspicious_pids:
                    continue

                for conn in psutil.net_connections(kind='inet'):
                    if conn.pid in self.suspicious_pids and conn.status == 'ESTABLISHED':
                        conn_id = (conn.pid, conn.laddr.ip, conn.laddr.port,
                                   conn.raddr.ip, conn.raddr.port)

                        if conn_id not in self.reported_conns:
                            proc_name = "unknown"
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                            self.log_alert(
                                "CORRELATED_THREAT_DETECTED",
                                f"Previously flagged suspicious process '{proc_name}' "
                                f"(PID {conn.pid}) established a network connection.",
                                severity="high",
                                details={
                                    "pid": conn.pid,
                                    "process_name": proc_name,
                                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}",
                                    "status": conn.status
                                }
                            )
                            self.reported_conns.add(conn_id)
            except psutil.AccessDenied:
                self.log_alert("ERROR", "Permission-denied-for-network-connection-correlation.", "error")
                break # Stop this thread if we don't have permissions
            except (psutil.Error, OSError, Exception) as e: # pylint: disable=broad-exception-caught
                self.log_alert("ERROR", f"An error occurred during threat correlation: {e}", "error")
                time.sleep(30) # Wait longer on error

    def run(self):
        """
        Main loop for the network monitor.
        """
        if not self.monitor_config.get("enabled"):
            return

        # The main thread will now wait for the shutdown event, while the background
        # threads (sniffer, analyzer) do the actual work.
        self.shutdown_event.wait()

    def start(self):
        """
        Initializes and starts the background threads for sniffing and analysis.
        """
        if not self.monitor_config.get("enabled") or sniff is None:
            if sniff is None:
                self.log_alert("ERROR", "Scapy is not installed. Network monitoring is disabled.", "error")
            return
        
        if self.network_interface:
            self.log_alert("LIFECYCLE", f"Sniffing explicitly on interface: {self.network_interface}", "info")

            # Add a check to ensure the specified interface exists before starting.
            if self.network_interface not in psutil.net_if_addrs():
                self.log_alert(
                    "CRITICAL",
                    f"The configured network_interface '{self.network_interface}' was not found. Network monitoring will not start.",
                    "error"
                )
                return
        # Start the packet sniffer in a separate thread
        sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        sniffer_thread.start()

        # Start the traffic analysis in a separate thread
        analysis_thread = threading.Thread(target=self.analyze_traffic, daemon=True)
        analysis_thread.start()

        # Start the threat correlation thread
        correlation_thread = threading.Thread(target=self.correlate_threats, daemon=True)
        correlation_thread.start()

        # Start a thread to listen for threat intel messages
        intel_thread = threading.Thread(target=self._intel_listener_loop, daemon=True)
        intel_thread.start()

    def _intel_listener_loop(self):
        """Continuously checks for threat intel messages."""
        while not self._thread_shutdown_event.is_set():
            self._check_for_intel()
            time.sleep(1) # Check for new intel every second

    def stop(self):
        """Signals all internal threads to shut down."""
        self.log_alert("LIFECYCLE", "Signaling internal threads to stop.", "info")
        self._thread_shutdown_event.set()