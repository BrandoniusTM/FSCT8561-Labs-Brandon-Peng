"""FSCT 8561: intentionally weak, localhost-only HTTP response test service.
For classroom inspection using requests. No exploit endpoints or real data.
Run: python test_website.py
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8765

class TestHandler(BaseHTTPRequestHandler):
    server_version = "FSCT8561LabHTTP/1.0"
    sys_version = ""

    def do_GET(self):
        if self.path == "/":
            body = b"<html><body><h1>Northstar Demo Portal</h1><p>Training-only HTTP service.</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "training_session=demo123; Path=/")
            # Intentionally omit several security response headers for analysis.
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/health":
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            body = b"Not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"[HTTP test] {self.address_string()} - {fmt % args}")

if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), TestHandler)
    print(f"Training website: http://{HOST}:{PORT}/")
    print("Only accessible on this computer. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
