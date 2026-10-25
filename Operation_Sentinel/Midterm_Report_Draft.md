# FSCT 8561 - Operation Sentinel
## Secure Server Assessment - Midterm Report Draft

**Student:** [Your full name]  
**Student number:** [Your student number]  
**Instructor:** Dr. Maryam R. Aliabadi  
**Submission date:** [Date]

**Important:** This is a student-friendly draft prepared against the professor's uploaded midterm instructions and provided local resources. Read and personalize the explanations. The professor requires independently defensible work and actual test evidence. The 18 development checks used temporary dependency substitutes because Scapy and PyOTP were unavailable in the drafting environment; they are NOT a replacement for running the real test suite on Kali.

## Overview

The purpose of Operation Sentinel is to build one connected Python security program, not separate lab scripts. The analyst uses a TCP client to log in with a password and a time-based one-time password (TOTP). After login, the client can check local TCP ports, inspect the instructor's local HTTP website, or ask the TCP server to examine an offline PCAP. The server only allows PCAP analysis after successful authentication. The program is restricted to localhost for classroom use.

## Part A - System Architecture (10%)

```text
     ANALYST CLIENT - 127.0.0.1                    STUDENT TCP SERVER - 127.0.0.1:8766
  +-----------------------------------+          +--------------------------------------+
  | client.py: password/TOTP + menu    | <--TCP--> | server.py: command handler          |
  | local_checks.py: localhost scan   |  JSONL   | security.py: password + TOTP        |
  | local_checks.py: HTTP checks      |          | pcap_analyzer.py: offline Scapy     |
  +-----------------------------------+          | event log: no passwords or OTPs     |
          |                                      +--------------------------------------+
          | HTTP on port 8765                                    |
          v                                                      v
    Instructor's test_website.py                  Instructor's synthetic Sentinel PCAP
```

**Responsibilities:** The client is responsible for the user menu, localhost port scanning, and checking HTTP response settings. The server accepts socket connections, checks the analyst's password and TOTP code, decides whether a command is allowed, and uses Scapy to read the provided PCAP. The server sends the analysis summary back to the client in JSON.

**Information flow:** The client connects to `127.0.0.1:8766`. It sends a password login request followed by a TOTP request. When both are accepted, it can send `ANALYZE_PCAP`. Port scanning and HTTP checking stay on the client and are restricted to the instructor's local services.

**Why a stateful connection?** I used a stateful design because the server needs to remember whether a client has passed the password step and the OTP step. This login state belongs to the current TCP connection. Logging out or disconnecting ends the session. A stateful design is simple to follow for this lab, but it would need stronger session protection for a real organization.

## Part B - Adversarial Threat Model (15%)

| Threat | Asset | Attack vector | Possible impact | Mitigation in project | Remaining risk |
|---|---|---|---|---|---|
| Malformed TCP message or connection flooding | TCP service availability | Oversized/invalid JSON or many connections | Errors or resource exhaustion | JSON line limit, connection timeout, error replies, localhost binding | Many connections could still use server resources |
| Misuse of a port scanner | Other network devices | Entering unauthorized hosts or very wide ranges | Unapproved scanning | Hardcoded `127.0.0.1`, only 1-30 ports per scan | A localhost scan can still contact services unexpectedly |
| Password guessing and OTP misuse | Analyst login and PCAP command | Guessing passwords, stolen OTP, repeat attempts | Unauthorized access | Salted PBKDF2, separate OTP step, three failures per connection, used-OTP tracking | Attackers can reconnect; unencrypted TCP could expose credentials |
| Malicious or oversized PCAP | PCAP analysis service | Crafted capture or changed file | Memory use, parser crash, misleading results | Fixed server-side PCAP path, errors handled, offline-only capture | `rdpcap()` loads the file into memory; malformed file risks remain |
| Weak HTTP response configuration | Demo website and browser users | Missing headers and unsafe cookie attributes | Greater browser exposure if used with real data | Report missing protections, use only test URL, do not attempt exploitation | Checker does not prove whether the site is exploitable |
| Plain TCP interception and replay | Login credentials and report data | Sniffing or replaying messages if traffic leaves localhost | Information disclosure or command replay | Loopback-only service, TOTP reuse check during the process | There is no TLS; server restart clears remembered TOTP use |

## Part C - Protocol Design (15%)

**Message structure:** Each TCP message is a single UTF-8 JSON object followed by a newline (`\n`). A request uses the key `cmd` and, when needed, extra fields. The server reads one complete line at a time and rejects messages larger than 4096 bytes. Responses use `ok` (true/false), `code`, and sometimes `message`, `role`, or `result`.

| Command | Example fields | Who may use it? | Server response |
|---|---|---|---|
| `PING` | `{"cmd":"PING"}` | Anyone connected | `PONG` |
| `LOGIN` | `{"cmd":"LOGIN","username":"student","password":"[entered password]"}` | Anyone connected | `PASSWORD_OK` or `AUTH_FAILED` |
| `OTP` | `{"cmd":"OTP","otp":"[6 digits]"}` | After correct password | `AUTHENTICATED`, `OTP_FAILED`, or `PASSWORD_REQUIRED` |
| `ANALYZE_PCAP` | `{"cmd":"ANALYZE_PCAP"}` | Authenticated analyst | `PCAP_RESULT` or `UNAUTHORIZED` |
| `LOGOUT` | `{"cmd":"LOGOUT"}` | Any session | `LOGGED_OUT`; clears login state |
| `QUIT` | `{"cmd":"QUIT"}` | Anyone connected | `BYE`; closes TCP connection |

**Login sequence:** (1) TCP connect. (2) Send username and password with `LOGIN`. (3) The server checks a salted PBKDF2-HMAC-SHA256 password hash. (4) After a correct password, send the 6-digit code with `OTP`. (5) The server checks TOTP with a small time tolerance and blocks a repeated time step while running. (6) The authenticated session can use the protected PCAP command.

**Authorization:** The server checks authentication and the analyst role before running `ANALYZE_PCAP`. Sending that command before login produces `UNAUTHORIZED`. The client cannot supply another PCAP filename, which also avoids a simple path-traversal problem.

**Error handling:** Invalid JSON gives `BAD_JSON`. A missing or invalid command gives `BAD_REQUEST` or `UNKNOWN_COMMAND`. A very large/unframed request gives `BAD_FRAME` and disconnects. Three failed authentication attempts on a connection end that connection. Disconnections and timeouts are caught, and event logs do not contain passwords or OTPs.

**Replay and security limits:** The server remembers TOTP steps already used while it remains running, but it does not provide transport encryption, permanent replay tracking, or cryptographic protection for every message. The client-server connection is plain TCP; TOTP does NOT encrypt messages. Before production use, I would add TLS, persistent replay checks, and stronger server-wide rate limiting.

## Part D - Component Design (10%)

### 1. Port scanner

- **Input:** A starting and ending TCP port, with localhost as the fixed target. The menu scans 8764-8768 and includes the student TCP server at 8766.
- **Output:** One result per port: `OPEN` or `CLOSED/UNREACHABLE`.
- **Expected behaviour:** Attempt short TCP connections and report whether a port accepts a connection.
- **Failures:** An invalid port range raises a clear error; timeout or connection refusal is shown as not reachable.
- **Security controls:** Fixed localhost target, 30-port maximum, short timeout. An open port does not prove a vulnerability.

### 2. Authentication and MFA

- **Input:** Username, password, and then a 6-digit TOTP.
- **Output:** `PASSWORD_OK`, `AUTHENTICATED`, or a specific failure code.
- **Expected behaviour:** The server checks a salted hash, then requires TOTP before protected functions.
- **Failures:** Incorrect password, expired/invalid code, reused code, malformed input, and disconnects are handled.
- **Security controls:** PBKDF2-HMAC-SHA256, random salt, comparison-safe verification, attempt limit per connection, code reuse tracking, connection-specific session state.

### 3. HTTP checker

- **Input:** Instructor website fixed at `http://127.0.0.1:8765`; paths `/`, `/health`, `/redirect`, `/missing`.
- **Output:** HTTP status, response content type, redirection, `Server` header, missing security response headers and cookie protection indicators.
- **Expected behaviour:** Use `requests` to inspect the response, without redirect following or exploitation.
- **Failures:** A stopped HTTP service creates a connection error that the client catches.
- **Security controls:** Cannot change target to an outside site. It does not store cookie contents or send attack payloads.

### 4. PCAP analyzer

- **Input:** The fixed synthetic `FSCT8561_Operation_Sentinel_Traffic.pcap`, loaded by Scapy on the server.
- **Output:** Total packets, protocol counts, main source IPs, and any high-rate alerts returned through the authenticated TCP connection.
- **Expected behaviour:** Sort packet times; count IPv4 TCP/UDP packets from each source within a rolling five-second period. Report one alert per source if more than 20 occur.
- **Failures:** Missing/unreadable file or missing Scapy produces a clear response; a bad capture may need more handling in production.
- **Security controls:** No client-selected file path, local offline analysis, and authorized PCAP command only.

**Sensitive information intentionally avoided:** Passwords, OTP codes, and the TOTP secret are never written to the event log. Cookie values are also not written into the report or client output. These values could be used to impersonate a user or access a session if exposed.

## Part E - Full Integrated Implementation (30%)

The folder includes the application source (`client.py`, `server.py`, `security.py`, `local_checks.py`, `pcap_analyzer.py`, `settings.py`), account setup (`setup_account.py`), the provided test website and PCAP, `requirements.txt`, and setup/test instructions in `README.md`.

**How the pieces connect:** The analyst opens `client.py`, logs into `server.py` over a TCP socket, and uses the menu. Options 1 and 2 call the client's port scanner and HTTP checker. Option 3 sends `ANALYZE_PCAP` over that same logged-in connection. The server verifies authorization, calls the Scapy analyzer, and returns the result over the socket. The client prints the JSON summary. Logging and input checks are built into the server.

**Key security comments in the code:** Restrict targets to localhost, salt and hash passwords, use two-factor login, reject protected commands before login, limit input sizes and timeouts, avoid writing secrets to logs, and use a server-controlled PCAP path. There is still no TLS, so the system is a teaching demonstration rather than a secure production service.

## Part F - Comprehensive Testing (15%)

**Evidence status:** The script `test_sentinel.py` has 18 automated test cases. During project preparation, all 18 code-path checks passed using temporary test substitutes for unavailable `pyotp` and Scapy dependencies. **These are development checks, NOT final exam verification.** For your submission, install real dependencies on Kali and run `python3 -m unittest -v test_sentinel.py`, then fill in the actual Kali result and add captured output or screenshots. The raw instructor PCAP and the instructor website were inspected independently.

| Test | Expected result | Development check | Final Kali result / screenshot |
|---|---|---|---|
| T01 TCP connection/PING | `PONG` | DEV PASS | [Fill after test] |
| T02 Wrong password | `AUTH_FAILED` | DEV PASS | [Fill after test] |
| T03 PCAP before login | `UNAUTHORIZED` | DEV PASS | [Fill after test] |
| T04 OTP before password | `PASSWORD_REQUIRED` | DEV PASS | [Fill after test] |
| T05 Valid password + TOTP | `AUTHENTICATED`; PCAP response | DEV PASS | [Fill after test] |
| T06 Reused OTP | `OTP_FAILED` | DEV PASS | [Fill after test] |
| T07 Unknown command | `UNKNOWN_COMMAND` | DEV PASS | [Fill after test] |
| T08 Malformed JSON | `BAD_JSON` | DEV PASS | [Fill after test] |
| T09 Missing command | `BAD_REQUEST` | DEV PASS | [Fill after test] |
| T10 Open TCP port | `OPEN` | DEV PASS | [Fill after test] |
| T11 Closed TCP port | `CLOSED/UNREACHABLE` | DEV PASS | [Fill after test] |
| T12 HTTP status/headers | 200, 200, 302, 404; missing CSP | DEV PASS | [Fill after test] |
| T13 HTTP connection failure | `requests.ConnectionError` caught | DEV PASS | [Fill after test] |
| T14 PCAP traffic summary | 123 total, 113 TCP, 10 UDP | DEV PASS | [Fill after test] |
| T15 PCAP burst alert | One alert for 192.0.2.20 | DEV PASS | [Fill after test] |
| T16 Invalid port range | `ValueError` | DEV PASS | [Fill after test] |
| T17 Logout followed by PCAP | `UNAUTHORIZED` | DEV PASS | [Fill after test] |
| T18 Server disconnect | `BYE`, then connection error | DEV PASS | [Fill after test] |

**Evidence files provided for reference:** `evidence/development_validation_mock_deps.txt` (development-only), `evidence/http_local_observation.json` (actual local HTTP check), and `evidence/pcap_independent_read.txt` (independent reading of the PCAP bytes). **Add a real Kali test capture** such as `evidence/test_run.txt`, along with screenshots, before submitting.

## Part G - Security Analysis and Reflection (5%)

### G1. Which Day 1 threats did the program reduce?

The program reduces some risks by keeping all scans on localhost, requiring password and TOTP login for PCAP analysis, checking input lengths, and avoiding passwords and OTPs in the logs. It also detects possible HTTP configuration problems. However, the connection is still plain TCP, a large number of clients could use up resources, and the packet detector could mistake normal traffic for an attack. Some risks are reduced, but none of these protections makes the project completely secure.

### G2. What suspicious traffic appeared in the PCAP?

The supplied synthetic PCAP contains **123 packets: 113 TCP and 10 UDP**. The main source was the simulated address **192.0.2.20**, with 63 packets in total. Using my threshold of **more than 20 TCP/UDP packets from one IP within five seconds**, this source produced one alert. The triggering frame was **packet 80**, and the five-second window included **21 packets beginning at packet 54**, over approximately **4.96 seconds**. The source **192.0.2.50** reached only 20 packets in any five-second window and did not cross the threshold. This traffic could be suspicious because of its high rate, but I cannot conclude from packet counts alone that it is a DDoS attack. All addresses in this PCAP are simulated training addresses, not live victims.

### G3. What did the HTTP checker find, and why do findings not prove an attack?

The instructor's website returned **200** for `/`, **200** for `/health`, **302** for `/redirect`, and **404** for `/missing`. Its root response exposed a demo `Server` banner. The HTTP checker observed missing `Content-Security-Policy`, `X-Content-Type-Options`, and `X-Frame-Options` headers, along with missing `HttpOnly`, `SameSite`, and `Secure` cookie settings. These are useful configuration observations, but they do not show that somebody exploited the website. This website was intentionally set up with weaker settings for learning, and additional investigation would be needed before calling any issue exploitable.

### G4. What are the confidentiality and replay limits of plain TCP with TOTP?

TCP sends the information reliably, but **plain TCP does not encrypt the information**. If this program were used across a network, someone with access to that traffic might read the password, OTP, or results. TOTP adds a second login step but does not make the connection confidential. The program blocks reuse of an OTP time step while the server is running, but a stolen password or a captured authentication exchange could still create risks, including races and replay problems. The OTP-use list also resets after the server restarts. TLS and stronger session protection would be needed for production.

### G5. What would you improve before production use?

I would first add TLS to protect credentials and reports in transit. I would also use safer account storage, system-wide rate limits, persistent OTP replay tracking, and better server resource limits. For the PCAP analyzer, I would add a file-size check and avoid loading very large captures all at once. The detector should consider additional evidence such as connection state and traffic patterns, rather than only packet rate. Finally, I would test and review the program with more sample cases before allowing anyone else to use it.

## Before submitting (replace or complete)

1. Replace the student's name, ID, and submission date.
2. Run the installation and interactive application in Kali using **real** `requests`, `pyotp`, and Scapy.
3. Run the 18 tests on Kali and replace every `[Fill after test]` with real PASS/FAIL outcomes and screenshot/captured-output references.
4. Add at least one screenshot of the running server, successful login/menu, local port scan, HTTP findings, and PCAP result. Do not show passwords, OTPs, or the account's TOTP secret.
5. Explain each part in your own words and make any code/design changes necessary to independently defend it.
6. Export the final PDF using the professor's filename format and upload source files + README/requirements to GitHub. Never upload `sentinel_account.json` or the log.
