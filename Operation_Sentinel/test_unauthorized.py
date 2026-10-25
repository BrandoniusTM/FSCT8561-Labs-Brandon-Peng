import socket

client = socket.create_connection(("127.0.0.1", 8766))

message = '{"cmd": "ANALYZE_PCAP"}\n'

client.sendall(message.encode())
response = client.recv(4096).decode()

print("Server response:", response)

client.close()
