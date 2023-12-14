import socket
import requests
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext

def scan_ip_http(ip_address):
    # Scanning IP address using requests
    try:
        response = requests.get(f"http://{ip_address}", timeout=2)
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Error occurred while scanning IP address: {e}")
        return False

def scan_ip_https(ip_address):
    # Scanning IP address using requests
    try:
        response = requests.get(f"https://{ip_address}", timeout=2)
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Error occurred while scanning IP address: {e}")
        return False


def get_host_info(ip):
    # Получаем имя хоста
    host_name = socket.getfqdn(ip)

    # Получаем информацию о стране и провайдере
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    data = response.json()
    country = data.get('country')
    provider = data.get('org')
    city = data.get('city')
    region = data.get('region')
    location = data.get('loc')
    org = data.get('org')
    timezone = data.get('timezone')

    return {
        'host_name': host_name,
        'ip': ip,
        'city': city,
        'region': region,
        'country': country,
        'location': location,
        'org': org,
        'timezone': timezone,
        'provider': provider
    }


def scan_port(ip, port):
    # Scanning port on IP address
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            sock.close()
            return True
        else:
            sock.close()
            return False
    except socket.error as e:
        messagebox.showerror("Error", f"Error occurred while scanning port: {e}")
        return False

def load_port_info(filename):
    port_description = {}

    with open(filename, "r", encoding="UTF-8-sig") as f:
        for line in f:
            port, protocol, description = int(line.split()[0]), line.split()[1], " ".join(line.split()[2:])
            port_description[port] = {"protocol": protocol, "description": description}

    return port_description

def determine_services(open_ports):
    # Determine services running on open ports
    services = load_port_info(INFO_FILE)
    result = {}

    for port in open_ports:
        if port in services.keys():
            result[port] = services[port]
    
    return result

INFO_FILE = "port_info.txt"

def scan_ip_range(ip_address_range, port_range):
    # Scanning IP address range
    result_text.delete(1.0, tk.END)  # Clear previous results
    for ip in ip_address_range:
        if scan_ip_http(ip) or scan_ip_https(ip):
            open_ports = []
            for port in port_range:
                if scan_port(ip, port):
                    open_ports.append(port)
            if open_ports:
                result_text.insert(tk.END, f"Open ports on {ip}: {open_ports}\n")
                result_text.insert(tk.END, f"Services running on open ports: \n")
                for port, service in determine_services(open_ports).items():
                    result_text.insert(tk.END, f"{port} - {service['protocol']} - {service['description']}\n")
                result_text.insert(tk.END, "\n")
            else:
                result_text.insert(tk.END, f"No open ports on {ip}\n")
        else:
            result_text.insert(tk.END, f"IP address {ip} is not reachable\n")

def estimated_time(ip_address_range, port_range):
    # Calculate estimated time to scan IP address range
    # 0.5 seconds for scanning one port
    # 2 seconds for scanning one IP address
    return len(ip_address_range) * len(port_range) * 0.5 + len(ip_address_range) * 2

def start_scan():
    ip_address_range = []
    port_range = []

    for port in port_entry.get().split(","):
        if "-" in port:
            start, end = port.split("-")
            port_range.extend(range(int(start), int(end)+1))
        else:
            port_range.append(int(port))
    
    for ip in ip_entry.get().split(","):
        if "-" in ip:
            start, end = ip.split("-")
            ip_address_range.extend([".".join(start.split(".")[:-1]) + "." + str(i) for i in range(int(start.split(".")[-1]), int(end.split(".")[-1])+1)])
        else:
            ip_address_range.append(ip.strip())

    messagebox.showinfo("Information", f"Scanning IP address range. Please wait... Maximum time to scan: {estimated_time(ip_address_range, port_range)} seconds")
    
    estimated_scan_time = estimated_time(ip_address_range, port_range)
    result_text.delete(1.0, tk.END)  # Clear previous results
    result_text.insert(tk.END, f"Estimated time to scan IP address range: {estimated_scan_time} seconds\n")
    scan_ip_range(ip_address_range, port_range)



# Create GUI
root = tk.Tk()
root.title("Network Scanner")
root.geometry("600x600")  # Increase the window size

ip_label = tk.Label(root, text="IP Address Range:")
ip_label.pack()

ip_entry = tk.Entry(root, width=50)
ip_entry.pack()
ip_entry.insert(tk.END, "1.1.1.1-1.1.1.3, 8.8.8.8")  # Default IP address range

port_label = tk.Label(root, text="Port Range:")
port_label.pack()

port_entry = tk.Entry(root, width=50)
port_entry.pack()
port_entry.insert(tk.END, "80, 443, 8080-8090")  # Default port range

scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack()

result_text = scrolledtext.ScrolledText(root, width=60, height=20)  # Increase the size of the scrolled text widget
result_text.pack()

root.mainloop()
