import socket

client = socket.create_connection(("127.0.0.1", 8766))

# Send a request with an incorrect command field
message = '{"wrong_field": "test"}\n'

client.sendall(message.encode())

response = client.recv(4096).decode()

print("Server response:", response)

client.close()
