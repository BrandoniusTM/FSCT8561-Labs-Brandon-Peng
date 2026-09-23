import socket
import threading

HOST = "127.0.0.1"
PORT = 5000

clients = {}
lock = threading.Lock()


def handle_client(conn, addr):
    username = None

    try:
        # Get the username
        data = conn.recv(1024).decode()

        if data.startswith("HELLO|"):
            username = data.split("|", 1)[1].strip()

            with lock:
                clients[conn] = username

            print(f"{username} connected from {addr}")

        else:
            conn.close()
            return

        # Keep receiving messages from this client
        while True:
            data = conn.recv(1024).decode()

            if not data:
                break

            if data.startswith("MSG|"):
                message = data.split("|", 1)[1]
                full_message = f"{username}: {message}"

                print(full_message)

                # Send message to all other clients
                with lock:
                    for client in clients:
                        if client != conn:
                            try:
                                client.send(full_message.encode())
                            except:
                                pass

            elif data == "EXIT|":
                break

    except ConnectionError:
        print(f"{username} disconnected unexpectedly.")

    finally:
        with lock:
            if conn in clients:
                del clients[conn]

        conn.close()

        if username:
            print(f"{username} disconnected.")


# Create the server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((HOST, PORT))
server.listen()

print(f"Server listening on {HOST}:{PORT}")

while True:
    conn, addr = server.accept()

    # Create a new thread for each client
    thread = threading.Thread(
        target=handle_client,
        args=(conn, addr)
    )

    thread.start()
