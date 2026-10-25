FSCT 8561 — Midterm local test resources

Files:
  test_website.py: an intentionally misconfigured, LOCAL-ONLY HTTP test website.
  FSCT8561_Operation_Sentinel_Traffic.pcap: synthetic traffic for offline Scapy analysis.

Start the HTTP test website (Python 3 required):
  python test_website.py
  On some systems: python3 test_website.py

Open http://127.0.0.1:8765/ in your browser, or use requests:
  import requests
  r = requests.get('http://127.0.0.1:8765/', timeout=5)
  print(r.status_code)
  print(dict(r.headers))

Other paths: /health, /redirect, /missing
The website deliberately uses plain HTTP and omits some response protections.
Identify and explain observations; do not claim that a missing header alone
proves a successful exploit. The service is for LOCAL testing only.

For port-scanning tests, scan 127.0.0.1 and a bounded range including 8765
while the website is running. Students also implement their own TCP server
on a different port and may scan it. A port scan detects reachability, not
necessarily a vulnerability.

For PCAP analysis, open the supplied .pcap with Scapy rdpcap().
The PCAP uses simulated addresses and is NOT a live capture of this website.

No public targets, internet scanning, real patient information, Docker, or
OWASP Juice Shop are required.
