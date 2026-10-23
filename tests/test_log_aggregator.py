#!/usr/bin/env python3
"""
Independent test suite and validation coverage for tools/log_aggregator.py.

Validates:
- JSONLogParser against independent hand-written representative fixtures.
- TextLogParser against standard, ISO8601, and syslog style timestamp formats.
- NginxLogParser against standard Nginx combined log lines and HTTP status codes.
- LogAggregator integration: process_file, _parse_line, level counting, service categorization.
- Edge case handling: malformed JSON, corrupted lines, empty lines, non-crashing parser behavior.
"""

import os
import sys
import unittest
from pathlib import Path

# Add project root and tools directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = PROJECT_ROOT / "tools"
FIXTURES_DIR = PROJECT_ROOT / "tests" / "fixtures"
sys.path.insert(0, str(TOOLS_DIR))
sys.path.insert(0, str(PROJECT_ROOT))

from log_aggregator import (
    JSONLogParser,
    LogAggregator,
    NginxLogParser,
    TextLogParser,
)


class TestJSONLogParser(unittest.TestCase):
    """Validation coverage for JSONLogParser with independent fixtures."""

    def setUp(self):
        self.parser = JSONLogParser()

    def test_parse_standard_json(self):
        """Verify standard JSON schema parsing."""
        line = '{"timestamp": 1700000000, "level": "info", "service": "auth-service", "message": "User logged in successfully", "user_id": 42}'
        entry = self.parser.parse(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["timestamp"], 1700000000)
        self.assertEqual(entry["level"], "info")
        self.assertEqual(entry["service"], "auth-service")
        self.assertEqual(entry["message"], "User logged in successfully")
        self.assertEqual(entry["format"], "json")
        self.assertEqual(entry["fields"]["user_id"], 42)

    def test_parse_alternative_json_keys(self):
        """Verify alternate key fallbacks (time, severity, logger, msg)."""
        line = '{"time": 1700000010, "severity": "error", "logger": "order-book", "msg": "Insufficient liquidity for trade", "order_id": "ord-987"}'
        entry = self.parser.parse(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["timestamp"], 1700000010)
        self.assertEqual(entry["level"], "error")
        self.assertEqual(entry["service"], "order-book")
        self.assertEqual(entry["message"], "Insufficient liquidity for trade")
        self.assertEqual(entry["format"], "json")

    def test_parse_timestamp_at_timestamp_app_lvl(self):
        """Verify @timestamp, app, and lvl fallbacks."""
        line = '{"@timestamp": 1700000020, "lvl": "warn", "app": "risk-engine", "event": "Margin utilization threshold reached", "margin_rate": 0.85}'
        entry = self.parser.parse(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["timestamp"], 1700000020)
        self.assertEqual(entry["level"], "warn")
        self.assertEqual(entry["service"], "risk-engine")
        self.assertEqual(entry["message"], "Margin utilization threshold reached")

    def test_malformed_json_does_not_crash(self):
        """Verify invalid JSON returns None rather than raising an exception."""
        self.assertIsNone(self.parser.parse('{"timestamp": 123, incomplete'))
        self.assertIsNone(self.parser.parse("[1, 2, 3]"))
        self.assertIsNone(self.parser.parse(""))
        self.assertIsNone(self.parser.parse("not json at all"))


class TestTextLogParser(unittest.TestCase):
    """Validation coverage for TextLogParser with independent fixtures."""

    def setUp(self):
        self.parser = TextLogParser()

    def test_parse_standard_timestamp(self):
        """Verify standard YYYY-MM-DD HH:MM:SS format."""
        line = "2024-01-15 14:32:10 [auth] INFO: Session token refreshed for user_123"
        entry = self.parser.parse(line)
        self.assertIsNotNone(entry)
        self.assertIsNotNone(entry["timestamp"])
        self.assertEqual(entry["level"], "info")
        self.assertEqual(entry["service"], "auth")
        self.assertEqual(entry["format"], "text")
        self.assertEqual(entry["message"], line)

    def test_parse_iso8601_timestamp(self):
        """Verify ISO8601 timestamp and error level detection."""
        line = "2024-01-15T14:32:15 [market] ERROR Failed to connect to matching engine"
        entry = self.parser.parse(line)
        self.assertIsNotNone(entry)
        self.assertIsNotNone(entry["timestamp"])
        self.assertEqual(entry["level"], "error")
        self.assertEqual(entry["service"], "market")

    def test_parse_syslog_timestamp(self):
        """Verify Syslog style timestamp and warn level detection."""
        line = "Jan 15 14:32:20 [gateway] WARN Upstream timeout on endpoint /metrics"
        entry = self.parser.parse(line)
        self.assertIsNotNone(entry)
        self.assertIsNotNone(entry["timestamp"])
        self.assertEqual(entry["level"], "warn")
        self.assertEqual(entry["service"], "gateway")

    def test_empty_line_returns_none(self):
        """Verify empty lines return None."""
        self.assertIsNone(self.parser.parse(""))
        self.assertIsNone(self.parser.parse("   \n"))


class TestNginxLogParser(unittest.TestCase):
    """Validation coverage for NginxLogParser with independent fixtures."""

    def setUp(self):
        self.parser = NginxLogParser()

    def test_parse_200_ok(self):
        """Verify successful HTTP 200 log parsing."""
        line = '192.168.1.10 - user_admin [15/Jan/2024:14:32:10 +0000] "GET /api/v1/orders HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"'
        entry = self.parser.parse(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["service"], "nginx")
        self.assertEqual(entry["level"], "info")
        self.assertEqual(entry["format"], "nginx")
        self.assertEqual(entry["fields"]["remote_addr"], "192.168.1.10")
        self.assertEqual(entry["fields"]["remote_user"], "user_admin")
        self.assertEqual(entry["fields"]["request"], "GET /api/v1/orders HTTP/1.1")
        self.assertEqual(entry["fields"]["status"], 200)
        self.assertEqual(entry["fields"]["body_bytes"], "1234")
        self.assertEqual(entry["fields"]["referer"], "https://example.com")
        self.assertEqual(entry["fields"]["user_agent"], "Mozilla/5.0")
        self.assertIsNotNone(entry["timestamp"])

    def test_parse_404_warn_level(self):
        """Verify 4xx status maps to warn level."""
        line = '10.0.0.5 - - [15/Jan/2024:14:32:15 +0000] "POST /api/v1/missing HTTP/1.1" 404 128 "-" "curl/7.88.1"'
        entry = self.parser.parse(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["level"], "warn")
        self.assertEqual(entry["fields"]["status"], 404)

    def test_parse_500_error_level(self):
        """Verify 5xx status maps to error level."""
        line = '172.16.0.2 - - [15/Jan/2024:14:32:20 +0000] "POST /api/v1/execute HTTP/1.1" 500 512 "https://example.com/checkout" "Python-urllib/3.10"'
        entry = self.parser.parse(line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["level"], "error")
        self.assertEqual(entry["fields"]["status"], 500)

    def test_malformed_nginx_line_returns_none(self):
        """Verify malformed Nginx line returns None gracefully."""
        self.assertIsNone(self.parser.parse("192.168.1.1 - incomplete line"))
        self.assertIsNone(self.parser.parse(""))


class TestLogAggregatorFixturesIntegration(unittest.TestCase):
    """Validation coverage for LogAggregator processing independent fixture files."""

    def setUp(self):
        self.aggregator = LogAggregator()

    def test_process_json_fixture_file(self):
        """Verify processing json_logs.log fixture file."""
        filepath = FIXTURES_DIR / "json_logs.log"
        count = self.aggregator.process_file(str(filepath))
        self.assertEqual(count, 3)
        self.assertEqual(len(self.aggregator.entries), 3)

    def test_process_nginx_fixture_file(self):
        """Verify processing nginx_logs.log fixture file."""
        filepath = FIXTURES_DIR / "nginx_logs.log"
        count = self.aggregator.process_file(str(filepath))
        self.assertEqual(count, 3)
        self.assertEqual(self.aggregator.service_counts.get("nginx"), 3)
        self.assertEqual(self.aggregator.level_counts.get("info"), 1)
        self.assertEqual(self.aggregator.level_counts.get("warn"), 1)
        self.assertEqual(self.aggregator.level_counts.get("error"), 1)

    def test_process_text_fixture_file(self):
        """Verify processing text_logs.log fixture file."""
        filepath = FIXTURES_DIR / "text_logs.log"
        count = self.aggregator.process_file(str(filepath))
        self.assertEqual(count, 3)

    def test_process_malformed_fixture_file(self):
        """Verify malformed_logs.log file processes without crashing."""
        filepath = FIXTURES_DIR / "malformed_logs.log"
        # Must not raise an exception
        count = self.aggregator.process_file(str(filepath))
        self.assertGreaterEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
