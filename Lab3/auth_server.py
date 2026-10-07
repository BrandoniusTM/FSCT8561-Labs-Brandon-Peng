import socket
import hashlib
import pyotp

HOST = "127.0.0.1"
PORT = 5001


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


users = {
    "alice": {
        "password": hash_password("Cyber123!"),
        "secret": pyotp.random_base32()
    }
}

print("TOTP secret:", users["alice"]["secret"])

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Server is running...")

while True:
    client, address = server.accept()

    message = client.recv(1024).decode()
    parts = message.split("|")

    if len(parts) == 3 and parts[0] == "AUTH":
        username = parts[1]
        password = parts[2]

        if username in users and hash_password(password) == users[username]["password"]:
            client.send(b"OTP_REQUIRED")

            otp_message = client.recv(1024).decode()
            otp = otp_message.split("|")[1]

            totp = pyotp.TOTP(users[username]["secret"])

            if totp.verify(otp):
                client.send(b"ACCESS_GRANTED")
            else:
                client.send(b"ACCESS_DENIED")
        else:
            client.send(b"ACCESS_DENIED")

    client.close()
