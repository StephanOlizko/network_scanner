import socket
import requests

def scan_ip(ip_address):
    # Scanning IP address using requests
    try:
        response = requests.get(f"http://{ip_address}", timeout=1)
        if response.status_code == 200:
            print(f"IP address {ip_address} is reachable")
        else:
            print(f"IP address {ip_address} is not reachable")
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning IP address: {e}")


def scan_port(ip, port):
    # Scanning port on IP address
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Port {port} on {ip} is open")
        else:
            print(f"Port {port} on {ip} is closed")
        sock.close()
    except socket.error as e:
        print(f"Error occurred while scanning port: {e}")

scan_ip("1.1.1.1")
scan_port("1.1.1.1", 80)