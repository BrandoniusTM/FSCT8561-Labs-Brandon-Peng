import socket


def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    result = sock.connect_ex((target, port))

    sock.close()

    return result == 0


target = input("Enter target: ")

while True:
    try:
        start_port = int(input("Enter starting port: "))
        end_port = int(input("Enter ending port: "))

        if 1 <= start_port <= 65535 and 1 <= end_port <= 65535:
            if start_port <= end_port:
                break

        print("Please enter valid port numbers.")

    except ValueError:
        print("Please enter numbers only.")


open_ports = []

print("\nScanning", target)
print("Ports", start_port, "to", end_port)
print()

for port in range(start_port, end_port + 1):

    if scan_port(target, port):
        print("Port", port, "is OPEN")
        open_ports.append(port)

print("\nScan complete.")

if open_ports:
    print("Open ports:", open_ports)
else:
    print("No open ports found.")
    
