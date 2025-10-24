# Test Report

- Success: True
- Time (s): 0.03
- Total tests: 15
- Failures: 0
- Errors: 0
- Skipped: 0

## Failures
None

## Errors
None

## Full Runner Output
```
test_file_change_handler_directory (tests.test_file_monitor.TestFileMonitor.test_file_change_handler_directory)
Test the handler's on_deleted method for a directory. ... ok
test_file_change_handler_normal_file (tests.test_file_monitor.TestFileMonitor.test_file_change_handler_normal_file)
Test the handler's on_created method for a file with normal content. ... ok
test_file_change_handler_suspicious_content (tests.test_file_monitor.TestFileMonitor.test_file_change_handler_suspicious_content)
Test the handler's on_created method for a file with bad content. ... ok
test_start_monitor (tests.test_file_monitor.TestFileMonitor.test_start_monitor)
Test that the monitor schedules paths and starts the observer. ... ok
test_analyze_error_spike (tests.test_juice_shop_monitor.TestJuiceShopMonitor.test_analyze_error_spike)
Test detection of an error spike. ... ok
test_analyze_line_brute_force (tests.test_juice_shop_monitor.TestJuiceShopMonitor.test_analyze_line_brute_force)
Test detection of a brute-force attack from 401 logs. ... ok
test_analyze_line_sql_injection (tests.test_juice_shop_monitor.TestJuiceShopMonitor.test_analyze_line_sql_injection)
Test detection of an SQL injection attack from web attack patterns. ... ok
test_analyze_traffic_syn_flood (tests.test_network_monitor.TestNetworkMonitor.test_analyze_traffic_syn_flood)
Test the analysis thread logic for detecting a SYN flood. ... ok
test_handle_threat_intel (tests.test_network_monitor.TestNetworkMonitor.test_handle_threat_intel)
Test that the monitor subscribes to suspicious PID events. ... ok
test_process_packet_syn_flood (tests.test_network_monitor.TestNetworkMonitor.test_process_packet_syn_flood)
Test processing a SYN packet for SYN flood detection. ... ok
test_start_threads (tests.test_network_monitor.TestNetworkMonitor.test_start_threads)
Test that the start() method launches all background threads. ... ok
test_process_health_check (tests.test_process_monitor.TestProcessMonitor.test_process_health_check)
Test if the monitor correctly tracks a configured process. ... ok
test_suspicious_process_detection (tests.test_process_monitor.TestProcessMonitor.test_suspicious_process_detection)
Test if a new, suspicious process is correctly identified. ... ok
test_brute_force_detection (tests.test_ssh_monitor.TestSSHMonitor.test_brute_force_detection)
Test if a brute-force attack is detected from log lines. ... ok
test_log_rotation (tests.test_ssh_monitor.TestSSHMonitor.test_log_rotation)
Test if the monitor correctly detects a log file rotation (inode change). ... ok

----------------------------------------------------------------------
Ran 15 tests in 0.028s

OK

```