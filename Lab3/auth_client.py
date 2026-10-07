import socket
from getpass import getpass

HOST = "127.0.0.1"
PORT = 5001

username = input("Username: ")
password = getpass("Password: ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

message = "AUTH|" + username + "|" + password
client.send(message.encode())

response = client.recv(1024).decode()
print("Server:", response)

if response == "OTP_REQUIRED":
	otp = input("Enter OTP: ")

	client.send(("OTP|" + otp).encode())

	response = client.recv(1024).decode()
	print("Server:", response)

client.close()
