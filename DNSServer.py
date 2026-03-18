import socket

dns_records = {
    "example.com": "192.168.1.100",
    "google.com": "111.111.111.111",
    "yahoo.com": "98.137.246.7",
    "nyu.edu": "222.222.222.222",
    "safebank.com": "12.210.12.210",
    "legitsite.com": "10.10.10.10"
}

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("127.0.0.1", 8053))

# ✅ ADD THIS LINE
server_socket.settimeout(2)

print("DNS Server is running...")

for _ in range(10):
    try:
        data, client_address = server_socket.recvfrom(512)

        domain = data.decode().strip()
        print(f"Received query for: {domain}")

        if domain in dns_records:
            response = dns_records[domain]
        else:
            response = "0.0.0.0"

        server_socket.sendto(response.encode(), client_address)

    except socket.timeout:
        print("No more requests. Exiting...")
        break

    except Exception as e:
        print(f"Error: {e}")

server_socket.close()

