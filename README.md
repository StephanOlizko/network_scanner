# Network Scanner

This is a Python-based network scanner. It scans a range of IP addresses and ports to determine which services are running on a network.

## Files

- `main.py`: This is the main script that runs the network scanner. It uses the `socket` library to connect to IP addresses and ports, and it uses the `port_info.txt` file to determine which services are typically associated with each port.

- `port_info.txt`: This file contains information about various ports and the services typically associated with them. It is used by the `main.py` script to determine which services are running on each scanned port.

## Installation

1. Ensure you have Python installed on your system. You can download Python from the [official website](https://www.python.org/downloads/).

2. Clone this repository to your local machine:

```sh
git clone https://github.com/yourusername/network-scanner.git

