"""Student analyst client: login, local port scan, local HTTP check, server PCAP."""
import getpass
import json
import socket

from local_checks import check_http, scan_ports
from settings import HOST, MAX_MESSAGE_BYTES, SERVER_PORT, TIMEOUT


class ClientConnection:
    def __init__(self, port=SERVER_PORT):
        self.sock = socket.create_connection((HOST, port), timeout=TIMEOUT)
        self.sock.settimeout(TIMEOUT)
        self.reader = self.sock.makefile("rb")
        self.writer = self.sock.makefile("wb")

    def request(self, cmd, **params):
        message = {"cmd": cmd}
        message.update(params)
        raw = (json.dumps(message) + "\n").encode("utf-8")
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("Request is too long")
        self.writer.write(raw)
        self.writer.flush()
        reply = self.reader.readline(MAX_MESSAGE_BYTES + 1)
        if not reply:
            raise ConnectionError("Server disconnected")
        if len(reply) > MAX_MESSAGE_BYTES:
            raise ConnectionError("Server reply is too long")
        return json.loads(reply.decode("utf-8"))

    def close(self):
        try:
            self.reader.close()
            self.writer.close()
            self.sock.close()
        except OSError:
            pass


def pretty_print(value):
    print(json.dumps(value, indent=2))


def main():
    try:
        server = ClientConnection()
    except OSError as error:
        print("Could not connect to local Sentinel server:", error)
        return

    try:
        print("Operation Sentinel - Student Security Assessment")
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        reply = server.request("LOGIN", username=username, password=password)
        print(reply["code"])
        if not reply["ok"]:
            return
        otp = input("Current 6-digit authenticator code: ").strip()
        reply = server.request("OTP", otp=otp)
        print(reply["code"])
        if not reply["ok"]:
            return

        while True:
            print("\n1 - Scan localhost TCP ports 8764-8768")
            print("2 - Check instructor local HTTP website")
            print("3 - Ask authenticated server to analyze supplied PCAP")
            print("4 - Logout and exit")
            choice = input("Choose 1-4: ").strip()
            try:
                if choice == "1":
                    pretty_print(scan_ports())
                elif choice == "2":
                    pretty_print(check_http())
                elif choice == "3":
                    pretty_print(server.request("ANALYZE_PCAP"))
                elif choice == "4":
                    print(server.request("LOGOUT")["code"])
                    print(server.request("QUIT")["code"])
                    break
                else:
                    print("Enter a number from 1 to 4.")
            except (ValueError, OSError, ConnectionError, json.JSONDecodeError) as error:
                print("Check failed:", error)
    except (ConnectionError, TimeoutError, OSError, json.JSONDecodeError) as error:
        print("Connection ended:", error)
    finally:
        server.close()


if __name__ == "__main__":
    main()
