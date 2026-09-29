import nmap

scanner = nmap.PortScanner()

target = input("Enter target host: ")

try:
    start_port = int(input("Enter starting port: "))
    end_port = int(input("Enter ending port: "))

    if start_port < 1 or end_port > 65535:
        print("Ports must be between 1 and 65535.")

    elif start_port > end_port:
        print("Starting port must be less than or equal to ending port.")

    else:
        print("\nScanning", target)
        print()

        scanner.scan(
            target,
            str(start_port) + "-" + str(end_port)
        )

        if target not in scanner.all_hosts():
            print("No results found.")
        else:
            print("PORT\tSTATE\tSERVICE")

            if "tcp" in scanner[target]:

                for port in scanner[target]["tcp"]:

                    state = scanner[target]["tcp"][port]["state"]
                    service = scanner[target]["tcp"][port]["name"]

                    print(port, "\t", state, "\t", service)

        print("\nScan complete.")

except ValueError:
    print("Ports must be numbers.")

except nmap.PortScannerError as error:
    print("Nmap error:", error)

except Exception as error:
    print("Error:", error)
