"""Client-side checks: bounded localhost TCP scan and local HTTP inspection."""
import socket

import requests
from settings import HOST, SERVER_PORT, WEBSITE_URL


def scan_ports(start=8764, end=8768):
    """Only localhost. A successful TCP connection shows an open port, not a vulnerability."""
    if (not isinstance(start, int) or not isinstance(end, int)
            or start < 1 or end > 65535 or start > end or end - start > 29):
        raise ValueError("Choose 1 to 30 ports in the valid TCP range.")
    results = []
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            try:
                sock.connect((HOST, port))
                status = "OPEN"
            except (OSError, TimeoutError):
                status = "CLOSED/UNREACHABLE"
        results.append({"host": HOST, "port": port, "status": status})
    return results


def check_http(url=WEBSITE_URL):
    """Inspect only the instructor's localhost website (never arbitrary URLs)."""
    if url != WEBSITE_URL:
        raise ValueError("Only the supplied local HTTP website is allowed.")

    checks = []
    session = requests.Session()
    session.trust_env = False  # Do not route localhost traffic via an environment proxy.
    for path in ("/", "/health", "/redirect", "/missing"):
        response = session.get(url + path, timeout=4, allow_redirects=False)
        checks.append({
            "path": path,
            "status": response.status_code,
            "content_type": response.headers.get("Content-Type", "not set"),
            "redirect_to": response.headers.get("Location", "")
        })

        if path == "/":
            root = response
    headers = ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options")
    findings = []
    for header in headers:
        if header not in root.headers:
            findings.append(f"Header not present: {header}")

    # Only examine cookie settings, not the cookie VALUE (which may be sensitive).
    cookie = root.headers.get("Set-Cookie", "")
    if cookie:
        for flag in ("HttpOnly", "SameSite"):
            if flag.lower() not in cookie.lower():
                findings.append(f"Cookie attribute not present: {flag}")
        if "secure" not in cookie.lower():
            findings.append("Cookie attribute not present: Secure (local HTTP demo)")

    return {
        "target": url,
        "checks": checks,
        "server": root.headers.get("Server", "not provided"),
        "findings": findings,
        "note": "Missing protections are configuration findings, not proof of an exploit."
    }
