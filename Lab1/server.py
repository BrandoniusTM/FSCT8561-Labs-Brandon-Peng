import socket

HOST = "127.0.0.1"
PORT = 12345

server_socket = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server_socket.bind((HOST, PORT))
server_socket.listen(1)

print("Server is waiting for a connection...")

client_socket, client_address = server_socket.accept()

print("Connected by:", client_address)

username = None
connected = True

while connected:

    try:
        data = client_socket.recv(1024)

        if not data:
            print("Client disconnected unexpectedly")
            break

        message = data.decode()

        print("Received:", message)

        if "|" not in message:
            client_socket.send(
                "ERROR|Invalid command format".encode()
            )
            continue

        command, content = message.split("|", 1)

        if command == "HELLO":

            if content == "":
                client_socket.send(
                    "ERROR|Username required".encode()
                )
            else:
                username = content
                print("Username:", username)

                client_socket.send(
                    "OK|Hello ".encode() + username.encode()
                )

        elif command == "MSG":

            if username is None:
                client_socket.send(
                    "ERROR|HELLO required first".encode()
                )

            elif content == "":
                client_socket.send(
                    "ERROR|Message cannot be empty".encode()
                )

            elif len(content) > 200:
                client_socket.send(
                    "ERROR|Message too long".encode()
                )

            else:
                print(username + " says:", content)

                client_socket.send(
                    ("OK|Message received from " + username).encode()
                )

        elif command == "EXIT":

            client_socket.send(
                "OK|Goodbye".encode()
            )

            connected = False

        else:
            client_socket.send(
                "ERROR|Unknown command".encode()
            )

    except ConnectionResetError:
        print("Connection reset by client")
        break

client_socket.close()
server_socket.close()

print("Server closed")
