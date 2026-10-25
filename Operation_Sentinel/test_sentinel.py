"""End-to-end test cases for FSCT 8561. Run with: python3 -m unittest -v test_sentinel.py

The tests use the real provided website and capture, plus the student's real TCP
server. The temporary test account is created in memory (never written to GitHub).
"""
import io
import json
import logging
import socket
import threading
import time
import unittest
from unittest.mock import patch

import requests

from client import ClientConnection
from local_checks import check_http, scan_ports
from pcap_analyzer import analyze_pcap
from security import make_password_record
from server import SentinelServer
from settings import HOST, HTTP_PORT, PCAP_FILE
from test_website import TestHandler, ThreadingHTTPServer

PASSWORD = "temporary_test_password_123!"


class TestOperationSentinel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import pyotp
        cls.secret = pyotp.random_base32()
        cls.account = {
            "username": "student_test", "role": "analyst",
            "password": make_password_record(PASSWORD),
            "totp_secret": cls.secret
        }
        cls.server = SentinelServer((HOST, 0), cls.account, pcap_path=PCAP_FILE)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        cls.web_server = None
        try:
            sock = socket.create_connection((HOST, HTTP_PORT), timeout=0.3)
            sock.close()
        except OSError:
            cls.web_server = ThreadingHTTPServer((HOST, HTTP_PORT), TestHandler)
            cls.web_thread = threading.Thread(target=cls.web_server.serve_forever, daemon=True)
            cls.web_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if cls.web_server is not None:
            cls.web_server.shutdown()
            cls.web_server.server_close()

    def connect(self):
        c = ClientConnection(self.port)
        self.addCleanup(c.close)
        return c

    def auth(self, conn):
        import pyotp
        result = conn.request("LOGIN", username="student_test", password=PASSWORD)
        self.assertEqual(result["code"], "PASSWORD_OK")
        code = pyotp.TOTP(self.secret).now()
        return conn.request("OTP", otp=code)

    def test_01_tcp_ping(self):
        self.assertEqual(self.connect().request("PING")["code"], "PONG")

    def test_02_failed_password(self):
        r = self.connect().request("LOGIN", username="student_test", password="wrong")
        self.assertEqual(r["code"], "AUTH_FAILED")

    def test_03_unauthorized_pcap(self):
        self.assertEqual(self.connect().request("ANALYZE_PCAP")["code"], "UNAUTHORIZED")

    def test_04_otp_before_password(self):
        self.assertEqual(self.connect().request("OTP", otp="123456")["code"], "PASSWORD_REQUIRED")

    def test_05_successful_password_and_otp(self):
        conn = self.connect()
        r = self.auth(conn)
        self.assertEqual(r["code"], "AUTHENTICATED")
        self.assertEqual(conn.request("ANALYZE_PCAP")["code"], "PCAP_RESULT")

    def test_06_totp_replay_rejected(self):
        import pyotp
        # This test consumes a code and then deliberately tries that SAME code again.
        # Reset test-only replay history so this test does not depend on test_05.
        with self.server.otp_lock:
            self.server.used_steps.clear()
        first = self.connect()
        second = self.connect()
        self.assertEqual(first.request("LOGIN", username="student_test", password=PASSWORD)["code"], "PASSWORD_OK")
        self.assertEqual(second.request("LOGIN", username="student_test", password=PASSWORD)["code"], "PASSWORD_OK")
        code = pyotp.TOTP(self.secret).now()
        self.assertEqual(first.request("OTP", otp=code)["code"], "AUTHENTICATED")
        self.assertEqual(second.request("OTP", otp=code)["code"], "OTP_FAILED")

    def test_07_unknown_command(self):
        self.assertEqual(self.connect().request("NOT_A_COMMAND")["code"], "UNKNOWN_COMMAND")

    def test_08_malformed_json(self):
        with socket.create_connection((HOST, self.port), timeout=5) as s:
            s.sendall(b"this is not json\n")
            line = s.makefile("rb").readline()
            self.assertEqual(json.loads(line)["code"], "BAD_JSON")

    def test_09_missing_command(self):
        self.assertEqual(self.connect().request("PING")['code'], "PONG")
        with socket.create_connection((HOST, self.port), timeout=5) as s:
            s.sendall(b'{}\n')
            line = s.makefile("rb").readline()
            self.assertEqual(json.loads(line)["code"], "BAD_REQUEST")

    def test_10_port_scanner_open(self):
        ports = scan_ports(self.port, self.port)
        self.assertEqual(ports[0]["status"], "OPEN")

    def test_11_port_scanner_closed(self):
        with socket.socket() as s:
            s.bind((HOST, 0))
            unused_port = s.getsockname()[1]
        self.assertEqual(scan_ports(unused_port, unused_port)[0]["status"], "CLOSED/UNREACHABLE")

    def test_12_http_configuration_findings(self):
        result = check_http()
        self.assertEqual([row["status"] for row in result["checks"]], [200, 200, 302, 404])
        self.assertTrue(any("Content-Security-Policy" in v for v in result["findings"]))

    def test_13_http_connection_failure(self):
        with patch("local_checks.requests.Session.get", side_effect=requests.ConnectionError("simulated offline")):
            with self.assertRaises(requests.ConnectionError):
                check_http()

    def test_14_pcap_traffic_summary(self):
        r = analyze_pcap()
        self.assertEqual((r["total_packets"], r["tcp_packets"], r["udp_packets"]), (123, 113, 10))

    def test_15_pcap_burst_detection(self):
        r = analyze_pcap()
        self.assertEqual(r["suspicious_sources"], 1)
        self.assertEqual(r["alerts"][0]["source"], "192.0.2.20")
        self.assertGreater(r["alerts"][0]["packets_in_window"], 20)

    def test_16_invalid_port_range(self):
        with self.assertRaises(ValueError):
            scan_ports(1, 1000)

    def test_17_logout_protects_pcap(self):
        conn = self.connect()
        self.assertEqual(conn.request("LOGOUT")["code"], "LOGGED_OUT")
        self.assertEqual(conn.request("ANALYZE_PCAP")["code"], "UNAUTHORIZED")

    def test_18_disconnect(self):
        conn = self.connect()
        self.assertEqual(conn.request("QUIT")["code"], "BYE")
        with self.assertRaises((ConnectionError, OSError, ValueError)):
            conn.request("PING")


if __name__ == "__main__":
    unittest.main(verbosity=2)
