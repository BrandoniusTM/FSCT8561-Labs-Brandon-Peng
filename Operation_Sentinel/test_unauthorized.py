import socket

# Connect to the TCP server
client = socket.create_connection(("127.0.0.1", 8766))

# Request PCAP analysis without logging in
message = '{"cmd": "ANALYZE_PCAP"}\n'

client.sendall(message.encode())

# Display the server response
response = client.recv(4096).decode()

print("Server response:", response)

client.close()
