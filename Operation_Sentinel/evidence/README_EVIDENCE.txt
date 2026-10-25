Evidence folder guidance
========================

http_local_observation.json
  Real GET observations of the instructor's supplied local test website,
  measured while running that server in the drafting environment.

pcap_independent_read.txt
  Real metadata/packet observations from the supplied PCAP bytes using
  standard-library parsing. THIS IS NOT A SCAPY-RUN SCREENSHOT.

development_validation_mock_deps.txt
  18 development checks passed. Because pyotp and Scapy could not be
  installed in this particular drafting environment, the checks used
  temporary external substitutes (NOT included with the project).
  DO NOT describe this as final Kali/real-dependency test evidence.

What YOU need to add before submitting
=======================================

Install requests, pyotp, and Scapy in Kali, then run:
  python3 -m unittest -v test_sentinel.py 2>&1 | tee evidence/test_run.txt

Capture screenshots of your actual setup (without secrets), local port
scan, HTTP checker, authenticated PCAP report, and test output. Update the
Part F table with actual PASS/FAIL results and evidence references.
