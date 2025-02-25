# IP-Extractor

This Python script extracts **public IPv4** and **IPv6** addresses from a **pcap** or **pcapng** capture file, excluding any **private**, **local**, or **multicast** IP addresses.

## Features

- **Extracts public IP addresses**: Filters out private, local (loopback), and multicast IP addresses.
- Supports **IPv4** and **IPv6**.
- Gracefully handles `KeyboardInterrupt` for clean exits when you press `Ctrl+C`.
- Useful for network analysis to identify malicious or suspicious external IPs.

## Prerequisites

- **Python 3.6+**
- Required Python libraries:
  - `pyshark`
  - `ipaddress`

You can install the necessary dependencies using `pip`:

```bash
pip install pyshark
