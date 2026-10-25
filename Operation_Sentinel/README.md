# FSCT 8561 - Operation Sentinel

A **localhost-only** Python client/server security assessment application for the provided midterm resources. The client has a menu for bounded local TCP scanning and local HTTP checks. The server handles password + TOTP authentication and analyzes the supplied synthetic PCAP using Scapy.

**Never use this program against public or third-party systems.** The client and server use **plain TCP**, so passwords and OTPs are **not encrypted during transmission**. This is a classroom design, **not production-ready**.

## Files

- `setup_account.py` - creates an analyst account with a salted PBKDF2 password hash and TOTP secret.
- `server.py` - TCP service on 127.0.0.1:8766; handles login, TOTP, authorization, PCAP analysis and security logging.
- `client.py` - interactive menu; runs localhost scanning and HTTP checking locally and requests PCAP results from the server.
- `security.py` - password and OTP checks.
- `local_checks.py` - bounded TCP-connect scanner and HTTP response/header checks.
- `pcap_analyzer.py` - Scapy analysis of the supplied offline PCAP.
- `settings.py` - fixed localhost test target and ports.
- `test_website.py` - professor's local test website (unchanged).
- `FSCT8561_Operation_Sentinel_Traffic.pcap` - professor's synthetic traffic (unchanged).
- `test_sentinel.py` - 18 automated test cases and expected results.
- `README_Students.txt` - professor's provided resource instructions.

## Setup in Kali Linux (or a local Python environment)

Open a terminal in this folder and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python3 setup_account.py
```

The setup program asks for a username and a password (at least 12 characters), then prints a **TOTP secret one time**. Add the secret as a time-based code in an authenticator application. For a local demonstration, you can use `python3 -c 'import pyotp; print(pyotp.TOTP("YOUR_SECRET").now())'`, but avoid putting real secrets in shell history or screenshots.

**Important:** `sentinel_account.json` contains the secret, so do not upload it to GitHub. `.gitignore` excludes it and log files. Keep account permissions private.

## Start three terminals

All three terminals must be running inside the **same computer/VM**, since the services use `127.0.0.1`.

**Terminal 1 - professor's test website:**

```bash
source .venv/bin/activate
python3 test_website.py
```

Browse to `http://127.0.0.1:8765/`. Available routes: `/`, `/health`, `/redirect`, `/missing`.

**Terminal 2 - Operation Sentinel TCP server:**

```bash
source .venv/bin/activate
python3 server.py
```

Server listens on `127.0.0.1:8766` and logs only security event types to `sentinel_security.log`.

**Terminal 3 - Operation Sentinel client:**

```bash
source .venv/bin/activate
python3 client.py
```

Enter username and password, then the current 6-digit TOTP code. Menu:

1. Scan localhost ports 8764 through 8768 (includes both servers).
2. Check the local website on port 8765.
3. Ask the authenticated server to analyze the supplied PCAP.
4. Logout and exit.

If a TOTP code is refused after previously succeeding, **wait for the next 30-second code**. Reusing the same time step is blocked in the running server.

## Testing

Close the interactive client if needed and run:

```bash
python3 -m unittest -v test_sentinel.py 2>&1 | tee evidence/test_run.txt
```

The automated tests use a temporary account **in memory** and a test server on a temporary localhost port. If the website is already running on 8765, they reuse it; otherwise they start the provided website for the tests. They cover 18 cases including successful/failed authentication, OTP replay rejection, unauthorized requests, open/closed ports, HTTP checks and simulated connection failure, PCAP summary/burst detection, invalid input and disconnection.

You should get `Ran 18 tests` and `OK` if the dependencies are installed and the environment is working. Do **not** claim a PASS without seeing the real result. Attach screenshots or captured output to the midterm PDF.

For a separate manual evidence run, record these commands and outputs:

```bash
python3 --version
python3 -m pip show requests pyotp scapy
python3 client.py
python3 -m unittest -v test_sentinel.py
```

Check that the client can print the scanner's results, the HTTP headers/configuration findings, and the PCAP alert. Screenshot your server and client terminals. **Do not screenshot passwords, OTPs, or the TOTP secret.**

## Security design, scope, and limitations

- Protocol: one UTF-8 JSON object per TCP line (`\n`-terminated); max request 4096 bytes. One TCP connection has its own login/MFA state.
- Public commands: `PING`, `LOGIN`, `OTP`, `QUIT`. Protected: `ANALYZE_PCAP` (requires password + TOTP + analyst role). `LOGOUT` clears session state.
- Server uses a random 16-byte salt and 350,000-iteration PBKDF2-HMAC-SHA256 to verify passwords. OTPs are checked within a small clock window and reused steps are rejected while the server is running.
- Failed logins and unauthorized requests are logged **without** passwords or OTPs; three failed authentication attempts disconnect the client.
- PCAP file is fixed server-side. Client cannot supply arbitrary filenames or scan public hostnames.
- The detector flags **more than 20 IPv4 TCP/UDP packets from the same source IP within a 5-second window**. It is only an indicator and may have false positives and false negatives.
- The HTTP checker examines headers and four expected response paths. Missing headers/cookie flags are not proof an exploit works.
- This plain TCP link has **no encryption**. Passwords, OTPs, and traffic reports may be visible to a local network sniffer in a non-loopback deployment. Before real-world deployment add TLS, stronger rate limiting and account storage, persistent replay protection and security reviews.

## What to submit

1. **One PDF** covering A: architecture, B: threat model, C: protocol, D: components, F: verified evidence and G: reflection, plus a description of E.
2. **GitHub repository link** with this source code, dependencies, and README. Make sure credential files are not committed.
3. Use the professor's naming rule: `FSCT8561-Midterm-FirstName-LastName-StudentNumber.pdf`.

This template is provided to support understanding; adapt the design, verify it, and be prepared to explain every choice yourself as required by the professor's academic integrity policy.
