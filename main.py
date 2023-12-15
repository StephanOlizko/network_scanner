import socket
import requests
import tkinter as tk
from tkinter import messagebox
from tkinter import scrolledtext
from tkinter import ttk

INFO_FILE = "port_info.txt"

def scan_ip_http(ip_address):
    try:
        response = requests.get(f"http://{ip_address}", timeout=2)
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning IP address: {e}")
        return False

def scan_ip_https(ip_address):
    try:
        response = requests.get(f"https://{ip_address}", timeout=2)
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error occurred while scanning IP address: {e}")
        return False


def get_host_info(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=1)

    data = response.json()
    host_name = data.get('hostname')
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
        print(f"Error occurred while scanning port: {e}")
        return False

def load_port_info(filename):
    port_description = {}

    with open(filename, "r", encoding="UTF-8-sig") as f:
        for line in f:
            port, protocol, description = int(line.split()[0]), line.split()[1], " ".join(line.split()[2:])
            port_description[port] = {"protocol": protocol, "description": description}

    return port_description

def determine_services(open_ports):
    services = load_port_info(INFO_FILE)
    result = {}

    for port in open_ports:
        if port in services.keys():
            result[port] = services[port]
    
    return result

def scan_ip_range(ip_address_range, port_range):
    result_text.delete(1.0, tk.END)  
    open_ports = set()
    for ip in ip_address_range:
        if scan_ip_http(ip) or scan_ip_https(ip):
            open_ports_ip = []
            for port in port_range:
                if scan_port(ip, port):
                    open_ports_ip.append(port)
                    open_ports.add(port)
            if open_ports_ip:
                result_text.insert(tk.END, f"Open ports on {ip}: {open_ports_ip}\n")
            else:
                result_text.insert(tk.END, f"No open ports on {ip}\n")
        else:
            result_text.insert(tk.END, f"IP address {ip} is not reachable\n")
    
    result_text.insert(tk.END, f"\nServices running on open ports: \n")
    for port, service in determine_services(open_ports).items():
        result_text.insert(tk.END, f"{port} - {service['protocol']} - {service['description']}\n")
    result_text.insert(tk.END, "\n")

def estimated_time(ip_address_range, port_range):
    return len(ip_address_range) * len(port_range) * 0.5 + len(ip_address_range) * 2

#Генерация диапазона ip адресов
def generate_ip_range(ip_range_str):
    parts = ip_range_str.split('.')
    ip_range = []

    for i in range(len(parts)):
        if '-' in parts[i]:
            start, end = map(int, parts[i].split('-'))
            for j in range(start, end + 1):
                new_parts = parts[:i] + [str(j)] + parts[i+1:]
                ip_range.append('.'.join(new_parts))

    return ip_range

def start_scan():
    ip_combobox.delete(0, tk.END)
    ip_combobox.insert(tk.END, ip_entry.get())
    show_host_info()

    ip_address_range = []
    port_range = []

    if all_ports_var.get() == 1:
        port_range = list(range(1, 1024))
    else:
        for port in port_entry.get().split(","):
            if "-" in port:
                start, end = port.split("-")
                port_range.extend(range(int(start), int(end)+1))
            else:
                port_range.append(int(port))
    
    for ip in ip_entry.get().split(","):
        if "-" in ip:
            ip_address_range.extend(generate_ip_range(ip))
            ip_address_range = list(map(str.strip, ip_address_range))
        else:
            ip_address_range.append(ip.strip())

    messagebox.showinfo("Information", f"Scanning IP address range. Please wait... Maximum time to scan: {estimated_time(ip_address_range, port_range)} seconds")

    estimated_scan_time = estimated_time(ip_address_range, port_range)
    result_text.delete(1.0, tk.END)  # Clear previous results
    result_text.insert(tk.END, f"Estimated time to scan IP address range: {estimated_scan_time} seconds\n")
    scan_ip_range(ip_address_range, port_range)

def show_host_info():
    ip_address_range = []

    for ip in ip_entry.get().split(","):
        if "-" in ip:
            ip_address_range.extend(generate_ip_range(ip))
            ip_address_range = list(map(str.strip, ip_address_range))
        else:
            ip_address_range.append(ip.strip())

    if ip_address_range:
        result_text_inf.delete(1.0, tk.END)  
        for ip in ip_address_range:
            host_info = get_host_info(ip)
            result_text_inf.insert(tk.END, f"Host Name: {host_info['host_name']}\n"
                                   f"IP: {host_info['ip']}\n"
                                   f"City: {host_info['city']}\n"
                                   f"Region: {host_info['region']}\n"
                                   f"Country: {host_info['country']}\n"
                                   f"Location: {host_info['location']}\n"
                                   f"Organization: {host_info['org']}\n"
                                   f"Timezone: {host_info['timezone']}\n"
                                   f"Provider: {host_info['provider']}\n\n")
    else:
        messagebox.showinfo("Host Information", "Please select an IP address")

def analyse_results():
    scan_text = result_text.get(1.0, tk.END)
    host_text = result_text_inf.get(1.0, tk.END)

    filter_by = filter_combobox.get()
    filter_text = filter_entry.get()
    sort_by = sort_combobox.get()


    results = []
    for line in scan_text.split("\n"):
        if "Services" in line or "IP" in line:
            break
        if line:
            ip, ports = line.split(":")
            results.append({
                "ip": ip.split()[-1],
                "open_ports": [int(port.strip()) for port in ports[2:][:-1].split(",")]
            })

    host_info = []
    for line in host_text.split("\n\n"):
        if line != "\n" and line:
            host_info.append({
                "ip": line.split("\n")[1].split()[-1],
                "host_name": line.split("\n")[0].split()[-1],
                "city": line.split("\n")[2].split()[-1],
                "region": line.split("\n")[3].split()[-1],
                "country": line.split("\n")[4].split()[-1],
                "location": line.split("\n")[5].split()[-1],
                "org": line.split("\n")[6].split()[-1],
                "timezone": line.split("\n")[7].split()[-1],
                "provider": line.split("\n")[8].split()[-1]
            })
    
    if filter_by == "ip":
        host_info = [info for info in host_info if filter_text in info["ip"]]
    elif filter_by == "host_name":
        host_info = [info for info in host_info if filter_text in info["host_name"]]
    elif filter_by == "city":
        host_info = [info for info in host_info if filter_text in info["city"]]
    elif filter_by == "region":
        host_info = [info for info in host_info if filter_text in info["region"]]
    elif filter_by == "country":
        host_info = [info for info in host_info if filter_text in info["country"]]
    elif filter_by == "location":
        host_info = [info for info in host_info if filter_text in info["location"]]
    elif filter_by == "org":
        host_info = [info for info in host_info if filter_text in info["org"]]
    elif filter_by == "timezone":
        host_info = [info for info in host_info if filter_text in info["timezone"]]
    elif filter_by == "provider":
        host_info = [info for info in host_info if filter_text in info["provider"]]
    else:
        pass
    
    results = [result for result in results if result["ip"] in [info["ip"] for info in host_info]]
    

    if sort_by == "IP Address":
        results = sorted(results, key=lambda x: x["ip"])
    elif sort_by == "Open Ports":
        results = sorted(results, key=lambda x: len(x["open_ports"]), reverse=True)
    

    statistics_text.delete(1.0, tk.END)
    statistics_text.insert(tk.END, f"Total number of hosts: {len(results)}\n")
    statistics_text.insert(tk.END, f"Total number of open ports: {sum([len(result['open_ports']) for result in results])}\n")
    statistics_text.insert(tk.END, f"Average number of open ports: {sum([len(result['open_ports']) for result in results])/len(results)}\n")
    statistics_text.insert(tk.END, f"Maximum number of open ports: {max([len(result['open_ports']) for result in results])}\n")
    statistics_text.insert(tk.END, f"Minimum number of open ports: {min([len(result['open_ports']) for result in results])}\n")

    statistics_text.insert(tk.END, "\n")
    for result in results:
        statistics_text.insert(tk.END, f"IP: {result['ip']}\n")
        statistics_text.insert(tk.END, f"Open Ports: {result['open_ports']}\n")
        statistics_text.insert(tk.END, "\n")


root = tk.Tk()
root.title("Network Scanner")
root.geometry("600x500")

notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

tab1 = ttk.Frame(notebook)
notebook.add(tab1, text='Scan')

ip_label = tk.Label(tab1, text="IP Address Range:")
ip_label.pack()

ip_entry = tk.Entry(tab1, width=50)
ip_entry.pack()
ip_entry.insert(tk.END, "8.8.8.8, 1.1.1.1-3")  

port_label = tk.Label(tab1, text="Port Range:")
port_label.pack()

port_entry = tk.Entry(tab1, width=50)
port_entry.pack()
port_entry.insert(tk.END, "443, 50-55, 80")  

all_ports_var = tk.IntVar()
all_ports_checkbox = tk.Checkbutton(tab1, text="All Ports", variable=all_ports_var)
all_ports_checkbox.pack()

scan_button = tk.Button(tab1, text="Start Scan", command=start_scan)
scan_button.pack()

result_text = scrolledtext.ScrolledText(tab1, width=60, height=20) 
result_text.pack()

tab2 = ttk.Frame(notebook)
notebook.add(tab2, text='Host Info')

ip_label_inf = tk.Label(tab2, text="IP Address Range:")
ip_label_inf.pack()

ip_combobox = ttk.Entry(tab2, width=50)
ip_combobox.pack()
ip_combobox.insert(tk.END, ip_entry.get())

show_info_button = tk.Button(tab2, text="Show Host Info", command=show_host_info)
show_info_button.pack()

result_text_inf = scrolledtext.ScrolledText(tab2, width=60, height=22)  
result_text_inf.pack()


tab3 = ttk.Frame(notebook)
notebook.add(tab3, text='Analyse')

filter_by_label = tk.Label(tab3, text="Filter by:")
filter_by_label.pack()

filter_combobox = ttk.Combobox(tab3, values=["ip", "host_name", "city", "region", "country", "location", "org", "timezone", "provider"], state="readonly")
filter_combobox.pack()

filter_label = tk.Label(tab3, text="Filter:")
filter_label.pack()

filter_entry = tk.Entry(tab3, width=50)
filter_entry.pack()

sort_label = tk.Label(tab3, text="Sort by:")
sort_label.pack()

sort_combobox = ttk.Combobox(tab3, values=["IP Address", "Open Ports"], state="readonly")
sort_combobox.pack()

analyse_button = tk.Button(tab3, text="Analyse", command=analyse_results)
analyse_button.pack()

statistics_label = tk.Label(tab3, text="Statistics:")
statistics_label.pack()

statistics_text = tk.Text(tab3, width=60, height=20)
statistics_text.pack()


root.mainloop()
