"""Unit tests for the XSSSQLMonitor class.

This module contains tests that verify:
1. SQL Injection Detection
   - Pattern matching for various SQL injection techniques
   - Risk scoring for different attack patterns
   - Detection bypass attempt handling

2. XSS Attack Detection
   - Pattern matching for script injection
   - Detection of event handler abuse
   - Encoded payload detection

3. False Positive Handling
   - Legitimate SQL-like content in normal text
   - Basic HTML content validation
   - Common user input patterns
"""
import unittest
from unittest.mock import MagicMock
from multiprocessing import Queue, Event
from EDR.monitors.xss_sql_monitor import XSSSQLMonitor

class TestXSSSQLMonitor(unittest.TestCase):
    """Test suite for the XSSSQLMonitor class.
    
    Tests verify the monitor's ability to:
    - Detect and score SQL injection attempts
    - Identify XSS attack patterns
    - Handle encoded/obfuscated payloads
    - Process full request objects
    - Filter false positives
    """

    def setUp(self):
        """Set up test environment before each test."""
        self.mock_log_queue = MagicMock(spec=Queue)
        self.mock_threat_bus = MagicMock(spec=Queue)
        self.mock_monitor_queue = MagicMock(spec=Queue)
        self.mock_shutdown_event = MagicMock(spec=Event)

        # Mock configuration
        self.mock_config = {
            "agent": {"heartbeat_interval_seconds": 0.1},
            "monitoring": {
                "xss_sql_monitoring": {
                    "enabled": True,
                    "min_risk_score": 3,
                    "block_threshold": 5
                }
            }
        }

        self.monitor = XSSSQLMonitor(
            self.mock_config,
            self.mock_log_queue,
            self.mock_shutdown_event,
            self.mock_threat_bus,
            self.mock_monitor_queue
        )

    def test_sql_injection_detection(self):
        """Test detection of SQL injection patterns."""
        # Test cases for SQL injection
        test_cases = [
            {
                "payload": "' UNION SELECT username,password FROM users--",
                "expected_score": 4,
                "expected_type": "sql_injection",
                "expected_matches": ["union_select"]
            },
            {
                "payload": "1; DROP TABLE users--",
                "expected_score": 5,  # Combined score from DML and comment
                "expected_type": "sql_injection",
                "expected_matches": ["sql_dml_ddl", "sql_comment"]
            },
            {
                "payload": "admin' OR '1'='1",
                "expected_score": 3,
                "expected_type": "sql_injection",
                "expected_matches": ["or_1_eq_1"]
            }
        ]

        for case in test_cases:
            score, matches = self.monitor.detect_sql_injection(case["payload"])
            self.assertGreaterEqual(score, case["expected_score"])
            for match in case["expected_matches"]:
                self.assertIn(match, matches)

    def test_xss_detection(self):
        """Test detection of XSS patterns."""
        # Test cases for XSS
        test_cases = [
            {
                "payload": "<script>alert('XSS')</script>",
                "expected_score": 4,
                "expected_type": "xss",
                "expected_matches": ["script_tag"]
            },
            {
                "payload": "javascript:alert(document.cookie)",
                "expected_score": 3,
                "expected_type": "xss",
                "expected_matches": ["javascript_protocol"]
            },
            {
                "payload": '<img src="x" onerror="alert(1)"',
                "expected_score": 3,
                "expected_type": "xss",
                "expected_matches": ["event_handler"]
            }
        ]

        for case in test_cases:
            score, matches = self.monitor.detect_xss(case["payload"])
            self.assertGreaterEqual(score, case["expected_score"])
            for match in case["expected_matches"]:
                self.assertIn(match, matches)

    def test_request_analysis(self):
        """Test analysis of a full request object."""
        test_request = {
            "method": "POST",
            "path": "/login",
            "params": {
                "username": "admin' OR '1'='1"
            },
            "headers": {
                "user-agent": "Mozilla/5.0",
                "content-type": "application/x-www-form-urlencoded"
            },
            "body": "<script>alert('test')</script>"
        }

        findings = self.monitor.analyze_request(test_request)
        self.assertTrue(findings)
        
        # Should detect both SQL injection in params and XSS in body
        finding_types = [f.type for f in findings]
        self.assertIn("sql_injection", finding_types)
        self.assertIn("xss", finding_types)

    def test_escaping_bypass_detection(self):
        """Test detection of attempts to bypass escaping."""
        test_cases = [
            {
                "payload": "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
                "expected_type": "xss",
                "min_score": 3
            },
            {
                "payload": "%3Cscript%3Ealert(1)%3C/script%3E",
                "expected_type": "xss",
                "min_score": 3
            },
            {
                "payload": "\\x27 UNION SELECT * FROM users--",
                "expected_type": "sql_injection",
                "min_score": 4
            }
        ]

        for case in test_cases:
            if case["expected_type"] == "xss":
                score, matches = self.monitor.detect_xss(case["payload"])
                self.assertGreaterEqual(score, case["min_score"])
                self.assertTrue(matches)
            else:
                score, matches = self.monitor.detect_sql_injection(case["payload"])
                self.assertGreaterEqual(score, case["min_score"])
                self.assertTrue(matches)

    def test_false_positive_reduction(self):
        """Test that common legitimate patterns don't trigger alerts."""
        safe_inputs = [
            "John O'Connor",  # Apostrophe in name
            "<p>Regular HTML paragraph</p>",  # Basic HTML
            "SELECT your preferred option",  # English word
            "The union of two sets",  # Mathematical term
        ]

        for input_text in safe_inputs:
            sql_score, _ = self.monitor.detect_sql_injection(input_text)
            xss_score, _ = self.monitor.detect_xss(input_text)
            
            # Both scores should be below the risk threshold
            self.assertLess(sql_score, self.monitor.sql_threshold)
            self.assertLess(xss_score, self.monitor.xss_threshold)

if __name__ == '__main__':
    unittest.main()