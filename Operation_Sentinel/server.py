"""Operation Sentinel: local stateful TCP service, password+TOTP, and PCAP results."""
import argparse
import json
import logging
import re
import socketserver
import threading

from pcap_analyzer import analyze_pcap
from security import check_password, matching_totp_step
from settings import (ACCOUNT_FILE, HOST, LOG_FILE, MAX_MESSAGE_BYTES,
                      PCAP_FILE, SERVER_PORT, TIMEOUT)


def security_log(event, detail=""):
    # Log event types and usernames only. Never log passwords, OTPs, or TOTP secrets.
    logging.info("%s %s", event, detail)


class SentinelServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, account, pcap_path=PCAP_FILE):
        super().__init__(address, SentinelHandler)
        self.account = account
        self.pcap_path = pcap_path
        self.used_steps = set()  # Prevent a TOTP code from being used twice in this process.
        self.otp_lock = threading.Lock()


class SentinelHandler(socketserver.StreamRequestHandler):
    def send(self, ok, code, **fields):
        reply = {"ok": ok, "code": code}
        reply.update(fields)
        self.wfile.write((json.dumps(reply) + "\n").encode("utf-8"))
        self.wfile.flush()

    def handle(self):
        self.connection.settimeout(300)
        username = None
        authenticated = False
        failures = 0
        security_log("CLIENT_CONNECTED")

        while True:
            try:
                line = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_MESSAGE_BYTES or not line.endswith(b"\n"):
                    self.send(False, "BAD_FRAME", message="Message too long or missing newline")
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                except (UnicodeError, ValueError):
                    self.send(False, "BAD_JSON")
                    continue
                if not isinstance(request, dict) or not isinstance(request.get("cmd"), str):
                    self.send(False, "BAD_REQUEST")
                    continue

                cmd = request["cmd"].upper()
                if cmd == "PING":
                    self.send(True, "PONG")

                elif cmd == "LOGIN":
                    login_name = request.get("username")
                    password = request.get("password")
                    authenticated = False
                    username = None
                    valid_input = (isinstance(login_name, str)
                                   and re.fullmatch(r"[A-Za-z0-9_]{3,32}", login_name)
                                   and isinstance(password, str)
                                   and 0 < len(password) <= 128)
                    account = self.server.account
                    if (valid_input and login_name == account["username"]
                            and check_password(password, account["password"])):
                        username = login_name
                        self.send(True, "PASSWORD_OK", message="Enter current 6-digit TOTP")
                    else:
                        failures += 1
                        security_log("LOGIN_FAILED")
                        self.send(False, "AUTH_FAILED")

                elif cmd == "OTP":
                    code = request.get("otp")
                    if username is None:
                        self.send(False, "PASSWORD_REQUIRED")
                    else:
                        account = self.server.account
                        step = matching_totp_step(account["totp_secret"], code)
                        with self.server.otp_lock:
                            used = (username, step) in self.server.used_steps
                            if step is not None and not used:
                                self.server.used_steps.add((username, step))
                        if step is not None and not used:
                            authenticated = True
                            security_log("LOGIN_SUCCESS", username)
                            self.send(True, "AUTHENTICATED", role=account["role"])
                        else:
                            username = None
                            authenticated = False
                            failures += 1
                            security_log("OTP_FAILED")
                            self.send(False, "OTP_FAILED", message="Invalid, expired, or reused code")

                elif cmd == "ANALYZE_PCAP":
                    if not authenticated or self.server.account.get("role") != "analyst":
                        security_log("UNAUTHORIZED_COMMAND", cmd)
                        self.send(False, "UNAUTHORIZED")
                    else:
                        try:
                            # The PCAP filename is fixed server-side to avoid path traversal.
                            result = analyze_pcap(self.server.pcap_path)
                            security_log("PCAP_ANALYSIS", username)
                            self.send(True, "PCAP_RESULT", result=result)
                        except (OSError, ValueError) as error:
                            security_log("PCAP_FAILED", type(error).__name__)
                            self.send(False, "PCAP_ERROR", message="Cannot analyze capture")
                        except ImportError:
                            security_log("PCAP_FAILED", "SCAPY_MISSING")
                            self.send(False, "SCAPY_MISSING", message="Install Scapy first")
                        except Exception as error:
                            # A corrupted capture or parsing issue should not crash the TCP session.
                            security_log("PCAP_FAILED", type(error).__name__)
                            self.send(False, "PCAP_ERROR", message="Capture could not be analyzed")

                elif cmd == "LOGOUT":
                    username = None
                    authenticated = False
                    self.send(True, "LOGGED_OUT")

                elif cmd == "QUIT":
                    self.send(True, "BYE")
                    break

                else:
                    self.send(False, "UNKNOWN_COMMAND")

                if failures >= 3:
                    # One reply per request; close after the third failed authentication.
                    security_log("RATE_LIMIT_DISCONNECT")
                    break
            except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
                security_log("CLIENT_DISCONNECTED_OR_TIMED_OUT")
                break
        security_log("CLIENT_CLOSED")


def main():
    parser = argparse.ArgumentParser(description="Local Operation Sentinel server")
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        raise SystemExit("Choose a local port from 1024 to 65535")
    if not ACCOUNT_FILE.exists():
        raise SystemExit("No account found. Run python3 setup_account.py first.")
    account = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
    logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    server = SentinelServer((HOST, args.port), account)
    print(f"Sentinel server listening on {HOST}:{args.port} (local only)")
    print("Security events are logged without credentials. Ctrl+C stops the server.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping server")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
