import socket
import threading

HOST = "127.0.0.1"
PORT = 5000


def receive_messages(sock):
    while True:
        try:
            message = sock.recv(1024).decode()

            if not message:
                break

            print("\n" + message)

        except ConnectionError:
            break


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

client.connect((HOST, PORT))

username = input("Enter your username: ")

client.send(f"HELLO|{username}".encode())

# Start a thread to receive messages
receive_thread = threading.Thread(
    target=receive_messages,
    args=(client,),
    daemon=True
)

receive_thread.start()

print("Connected to the chat.")
print("Type a message or EXIT| to leave.")

while True:
    message = input()

    if message == "EXIT|":
        client.send("EXIT|".encode())
        break

    client.send(f"MSG|{message}".encode())

client.close()
