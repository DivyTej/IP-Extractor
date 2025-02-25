# IP-Extractor

A Python script that extracts **public IPv4** and **IPv6** addresses from **pcap** or **pcapng** capture files, excluding any **private**, **local**, or **multicast** IP addresses.

---

## Overview

The **IP-Extractor** is a Python-based tool designed to extract public IP addresses from network capture files. It supports both **IPv4** and **IPv6**, and filters out any private, local (loopback), or multicast addresses. This tool is useful for network analysis and security investigations, enabling you to identify external IPs in captured network traffic.

---

## Features

### Main Features

1. **Extracts public IP addresses**: Filters out private, local (loopback), and multicast IP addresses.
2. **Supports both IPv4 and IPv6**: Handles both IPv4 and IPv6 addresses in capture files.
3. **Graceful handling of interruptions**: Cleanly exits when `Ctrl+C` is pressed, allowing users to cancel at any time.
4. **Multiplatform support**: Works across different operating systems that support Python.

---

## Prerequisites

- **Python 3.6+**
- Required Python libraries:
  - `pyshark`
  - `ipaddress`

You can install the necessary dependencies using `pip`:

```bash
pip install pyshark
```

---

## Installation

1. Clone the repository (if applicable):
   ```bash
   git clone https://github.com/yourusername/ip-extractor.git
   cd ip-extractor
   ```

2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

1. Run the script:
   ```bash
   python ip_extractor.py <path_to_pcap_file>
   ```

   Example:
   ```bash
   python ip_extractor.py capture.pcap
   ```

2. The script will output a list of public IP addresses found in the capture file:
   ```
   Public IPs (IPv4 and IPv6):
   203.0.113.45
   2001:db8::1
   ```

3. If the file does not exist or is invalid, the script will display an error message:
   ```
   Error: The file capture.pcap does not exist.
   ```

---

## Example Workflow

### Input File
- A PCAP file (`capture.pcap`) containing network traffic.

### Running the Script
1. Execute the script:
   ```bash
   python ip_extractor.py capture.pcap
   ```

2. Example output:
   ```
   Public IPs (IPv4 and IPv6):
   203.0.113.45
   2001:db8::1
   ```

---

## How It Works

1. **Private IP Ranges**:
   - IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `127.0.0.0/8` (localhost).
   - IPv6: `fc00::/7` (Unique Local Address) and `::1/128` (loopback).

2. **Multicast IP Ranges**:
   - IPv4: `224.0.0.0/4`.
   - IPv6: `ff00::/8`.

3. **Public IP Extraction**:
   - The script reads the PCAP file using `pyshark`.
   - It iterates through each packet, extracting source and destination IPs.
   - It filters out private, local, and multicast IPs, leaving only public IPs.

---

## Contributions

Contributions, issues, and feature requests are welcome! Fork the repository, make changes, and submit a pull request.

---

## Contact

For questions or support, please contact [Divy Tej](https://linkedin.com/in/divytej).

---
