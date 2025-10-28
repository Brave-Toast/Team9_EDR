#!/usr/bin/env python3
"""
XSS and SQL Injection Detection Monitor.

This module provides a monitor that scans incoming requests for potential XSS and SQL injection
attack patterns. It uses a combination of regular expressions to detect suspicious patterns
and assigns risk scores to potential threats.
"""
from __future__ import annotations
import re
import html
import queue
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Any
from urllib.parse import unquote_plus
from multiprocessing import Queue
from multiprocessing.synchronize import Event

from .base_monitor import BaseMonitor


@dataclass
class Finding:
    """
    Represents a detected security threat in a request.
    
    Attributes:
        vector: Location of the threat, e.g., "params.q" or "body"
        type: Type of threat, either "sql_injection" or "xss"
        score: Numeric risk score based on pattern matches
        matches: List of specific pattern types that matched
    """
    vector: str
    type: str
    score: int
    matches: List[str]


class XSSSQLMonitor(BaseMonitor):
    """
    Monitor that detects SQLi and XSS vectors in incoming request-like payloads.
    
    This class provides real-time monitoring and analysis of incoming requests
    to detect potential SQL injection and Cross-Site Scripting (XSS) attacks.
    It uses pattern matching with regular expressions and assigns risk scores
    to potential threats.
    """


    def get_name(self) -> str:
        """
        Get the name of this monitor for configuration purposes.

        Returns:
            str: The name identifier for this monitor ("xss_sql_monitoring")
        """
        return "xss_sql_monitoring"

    def __init__(self, agent_config: dict, log_queue: Queue, shutdown_event: Event,
                 threat_bus: Queue, monitor_queue: Queue):
        """
        Initialize the XSS and SQL injection monitor.

        Args:
            agent_config: Configuration dictionary for the EDR agent
            log_queue: Queue for logging messages
            shutdown_event: Event to signal monitor shutdown
            threat_bus: Queue for publishing detected threats
            monitor_queue: Queue for receiving messages to monitor

        Note:
            The monitor will initialize various regex patterns for detecting
            XSS and SQL injection attempts in requests.
        """
        super().__init__(agent_config, log_queue, shutdown_event, threat_bus, monitor_queue)

        # SQL patterns
        union_pattern = re.compile(r"(?i)\bUNION\b\s+\bSELECT\b")
        select_pattern = re.compile(r"(?i)\bSELECT\b.*?\bFROM\b")
        dml_pattern = re.compile(r"(?i)\b(INSERT|UPDATE|DELETE|DROP|ALTER)\b")
        comment_pattern = re.compile(r"(--|#|/\*)")
        tautology_pattern = re.compile(r"(?i)\bOR\b\s+\d+=\d+")
        or_pattern = re.compile(r"(?i)\bOR\b\s+1=1\b")
        schema_pattern = re.compile(r"(?i)\bINFORMATION_SCHEMA\b")
        delay_pattern = re.compile(r"(?i)(SLEEP|BENCHMARK|WAITFOR)")
        exec_pattern = re.compile(r"(?i)(EXEC|xp_|sp_)")
        semicolon_pattern = re.compile(r";.*?--")
        or_quotes_pattern = re.compile(r"'\s*or\s*'1'='1'")

        self.sql_patterns = [
            (union_pattern, 4, "union_select"),
            (select_pattern, 2, "select_from"),
            (dml_pattern, 3, "sql_dml_ddl"),
            (comment_pattern, 2, "sql_comment"),
            (re.compile(r"'(?:--|;)"), 2, "comment_after_quote"),
            (tautology_pattern, 3, "tautology"),
            (or_pattern, 3, "or_1_eq_1"),
            (schema_pattern, 3, "info_schema"),
            (delay_pattern, 3, "time_delay"),
            (exec_pattern, 3, "stored_procedure_exec"),
            (semicolon_pattern, 2, "semicolon_comment"),
            (or_quotes_pattern, 3, "or_1_equals_1_quotes")
        ]

        # XSS patterns
        script_pattern = re.compile(r"(?i)<script")
        event_pattern = re.compile(r"(?i)on\w+=")
        img_pattern = re.compile(r"(?i)<img.*?onerror")
        js_pattern = re.compile(r"(?i)javascript:")
        iframe_pattern = re.compile(r"(?i)<iframe")
        svg_pattern = re.compile(r"(?i)<svg")
        cookie_pattern = re.compile(r"(?i)(document\.cookie|location\.|alert\()")
        meta_pattern = re.compile(r"(?i)<meta.*?refresh")
        body_pattern = re.compile(r"(?i)<body.*?onload")
        src_pattern = re.compile(r"(?i)<script.*?src=")

        self.xss_patterns = [
            (script_pattern, 5, "script_tag"),
            (event_pattern, 3, "event_handler"),
            (img_pattern, 4, "img_onerror"),
            (js_pattern, 3, "javascript_protocol"),
            (iframe_pattern, 3, "iframe_tag"),
            (svg_pattern, 2, "svg_tag"),
            (cookie_pattern, 2, "suspicious_js_usage"),
            (meta_pattern, 2, "meta_refresh"),
            (body_pattern, 3, "body_onload"),
            (src_pattern, 2, "external_script")
        ]        # thresholds (tune for your environment)
        self.sql_threshold = 3
        self.xss_threshold = 3
        self.max_matches = 10

    @staticmethod
    def _normalize(value: str) -> str:
        """
        Normalize input by URL-decoding and unescaping HTML entities.

        Args:
            value: The string to normalize

        Returns:
            str: The normalized string with URL-decoding and HTML entity unescaping applied
        """
        try:
            v = unquote_plus(value)
        except (TypeError, ValueError):
            v = value
        return html.unescape(v)

    def _score_against_patterns(self, value: str, patterns: List[Tuple[re.Pattern, int, str]]) -> Tuple[int, List[str]]:
        """
        Score a string against a list of regex patterns.

        Args:
            value: The string to analyze
            patterns: List of tuples (regex_pattern, weight, label)

        Returns:
            Tuple[int, List[str]]: Total score and list of matched pattern labels
        """
        score = 0
        matches_set: List[str] = []
        if not value:
            return score, []
        normalized = self._normalize(value)
        for pattern, weight, label in patterns:
            for _ in pattern.finditer(normalized):
                score += weight
                if label not in matches_set:
                    matches_set.append(label)
                    if len(matches_set) >= self.max_matches:
                        break
            if len(matches_set) >= self.max_matches:
                break
        return score, matches_set

    def detect_sql_injection(self, value: str) -> Tuple[int, List[str]]:
        """
        Detect potential SQL injection attempts in a string.

        Args:
            value: The string to analyze

        Returns:
            Tuple[int, List[str]]: Score and list of matched SQL injection patterns
        """
        return self._score_against_patterns(value, self.sql_patterns)

    def detect_xss(self, value: str) -> Tuple[int, List[str]]:
        """
        Detect potential XSS attempts in a string.

        Args:
            value: The string to analyze

        Returns:
            Tuple[int, List[str]]: Score and list of matched XSS patterns
        """
        return self._score_against_patterns(value, self.xss_patterns)

    def analyze_request(self, request: Dict[str, Any]) -> List[Finding]:
        """
        Analyze a request-like dict. Supported keys: headers (dict), params (dict), body (str), path (str).
        Returns a list of Finding dataclass instances for suspicious vectors.
        """
        findings: List[Finding] = []
        vectors: List[Tuple[str, str]] = []

        path = request.get("path", "")
        if path:
            vectors.append(("path", str(path)))

        params = request.get("params", {}) or {}
        if isinstance(params, dict):
            for k, v in params.items():
                vectors.append((f"params.{k}", str(v)))
        else:
            vectors.append(("params", str(params)))

        headers = request.get("headers", {}) or {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                vectors.append((f"headers.{k}", str(v)))
        else:
            vectors.append(("headers", str(headers)))

        body = request.get("body", "")
        if body:
            vectors.append(("body", str(body)))

        for vector_name, value in vectors:
            sql_score, sql_matches = self.detect_sql_injection(value)
            xss_score, xss_matches = self.detect_xss(value)

            if sql_score >= self.sql_threshold:
                findings.append(Finding(vector=vector_name, type="sql_injection", score=sql_score, matches=sql_matches))
            if xss_score >= self.xss_threshold:
                findings.append(Finding(vector=vector_name, type="xss", score=xss_score, matches=xss_matches))

        return findings

    def is_suspicious(self, request: Dict[str, Any]) -> bool:
        """
        Check if a request contains any suspicious patterns.

        Args:
            request: The request dictionary to analyze

        Returns:
            bool: True if any suspicious patterns were detected, False otherwise
        """
        return len(self.analyze_request(request)) > 0

    # Integration points with the agent

    def handle_threat_intel(self, message: dict):
        """
        Process threat intelligence messages and log alerts for detected threats.

        Args:
            message: A dictionary containing request data to analyze
        """
        findings = self.analyze_request(message)
        if findings:
            for finding in findings:
                alert_msg = f"Potential {finding.type} attack detected"
                alert_msg += f" in {finding.vector}"
                self.log_alert(
                    "XSS_SQL_THREAT",
                    alert_msg,
                    details=asdict(finding)
                )

    def run(self):
        """
        Monitor process main loop.

        This method implements the monitor's main loop that processes messages
        from the monitor queue. The loop continues until a shutdown event is set.
        Each message is analyzed for potential security threats.

        The monitor remains idle when no messages are available, checking the
        queue periodically with a 1-second timeout.
        """
        if not self.monitor_config.get("enabled", True):
            return

        # Simple periodic loop to stay alive and respond to bus messages
        while not self.shutdown_event.is_set():
            try:
                message = self.monitor_queue.get(timeout=1)
                self.handle_threat_intel(message)
            except queue.Empty:
                continue