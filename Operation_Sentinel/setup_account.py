import getpass
import json
import os
import re

import pyotp
from security import make_password_record
from settings import ACCOUNT_FILE


def main():
    if ACCOUNT_FILE.exists():
        print("Account already exists. Remove or back up the account file to reinitialize.")
        return

    username = input("Choose analyst username (letters, numbers, underscore): ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
        print("Username must be 3-32 letters, numbers, or underscores.")
        return

    password = getpass.getpass("Choose password (at least 12 characters): ")
    if len(password) < 12 or len(password) > 128:
        print("Choose a password between 12 and 128 characters.")
        return

    account = {
        "username": username,
        "role": "analyst",
        "password": make_password_record(password),
        "totp_secret": pyotp.random_base32()
    }

    fd = os.open(ACCOUNT_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        json.dump(account, file, indent=2)
    print("Account created. Add this one-time setup secret to your authenticator:")
    print(account["totp_secret"])
    print("Keep this secret private. It is not saved in security logs or GitHub.")
    print("An authenticator app or a LOCAL pyotp.TOTP(secret).now() can generate codes.")


if __name__ == "__main__":
    main()
