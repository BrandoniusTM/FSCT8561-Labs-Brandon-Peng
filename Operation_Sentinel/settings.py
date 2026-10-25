"""Shared settings for the LOCAL-ONLY student midterm program."""
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
HOST = "127.0.0.1" 
SERVER_PORT = 8766
HTTP_PORT = 8765
WEBSITE_URL = f"http://{HOST}:{HTTP_PORT}"
ACCOUNT_FILE = PROJECT_DIR / "sentinel_account.json"
PCAP_FILE = PROJECT_DIR / "FSCT8561_Operation_Sentinel_Traffic.pcap"
LOG_FILE = PROJECT_DIR / "sentinel_security.log"
MAX_MESSAGE_BYTES = 4096
TIMEOUT = 12
