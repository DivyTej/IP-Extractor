import pyshark
import ipaddress
import sys
import os  # To check if the file exists

# Define private IP address ranges (for both IPv4 and IPv6)
PRIVATE_IPV4_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8")  # Localhost range for IPv4
]

PRIVATE_IPV6_RANGES = [
    ipaddress.IPv6Network("fc00::/7"),  # Unique Local Address (ULA)
    ipaddress.IPv6Network("::1/128")  # Loopback for IPv6
]

# Define multicast IP address ranges
MULTICAST_IPV4_RANGE = ipaddress.IPv4Network("224.0.0.0/4")
MULTICAST_IPV6_RANGE = ipaddress.IPv6Network("ff00::/8")

def is_public_ipv4(ip):
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        for private_range in PRIVATE_IPV4_RANGES:
            if ip_obj in private_range:
                return False
        if ip_obj in MULTICAST_IPV4_RANGE:
            return False
        return True
    except ValueError:
        return False

def is_public_ipv6(ip):
    try:
        ip_obj = ipaddress.IPv6Address(ip)
        for private_range in PRIVATE_IPV6_RANGES:
            if ip_obj in private_range:
                return False
        if ip_obj in MULTICAST_IPV6_RANGE:
            return False
        return True
    except ValueError:
        return False

def extract_public_ips(pcap_file):
    public_ips = set()

    # Check if the file exists before trying to capture packets
    if not os.path.isfile(pcap_file):
        print(f"Error: The file {pcap_file} does not exist.")
        sys.exit(1)

    # Read the pcap file using pyshark
    try:
        cap = pyshark.FileCapture(pcap_file)
    except Exception as e:
        print(f"Error while reading the pcap file: {e}")
        sys.exit(1)

    try:
        for pkt in cap:
            if hasattr(pkt, 'ip'):
                # Check for IPv4 source and destination addresses
                if hasattr(pkt.ip, 'src') and hasattr(pkt.ip, 'dst'):
                    src_ip = pkt.ip.src
                    dst_ip = pkt.ip.dst
                    # Add public IPv4 addresses to the set
                    if is_public_ipv4(src_ip):
                        public_ips.add(src_ip)
                    if is_public_ipv4(dst_ip):
                        public_ips.add(dst_ip)

            if hasattr(pkt, 'ipv6'):
                # Check for IPv6 source and destination addresses
                if hasattr(pkt.ipv6, 'src') and hasattr(pkt.ipv6, 'dst'):
                    src_ip = pkt.ipv6.src
                    dst_ip = pkt.ipv6.dst
                    # Add public IPv6 addresses to the set
                    if is_public_ipv6(src_ip):
                        public_ips.add(src_ip)
                    if is_public_ipv6(dst_ip):
                        public_ips.add(dst_ip)

    except KeyboardInterrupt:
        print("\nProcess interrupted. Exiting...")
        sys.exit(0)

    # Return the list of public IPs
    return public_ips

def main():
    try:
        # Get the pcap file path from command line argument
        if len(sys.argv) != 2:
            print("Usage: python script.py <path_to_pcap_file>")
            sys.exit(1)

        pcap_file = sys.argv[1].strip()
        
        # Extract public IPs from the given file
        public_ips = extract_public_ips(pcap_file)

        print("\nPublic IPs (IPv4 and IPv6):")
        for ip in public_ips:
            print(ip)
    
    except KeyboardInterrupt:
        print("\nProcess interrupted. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
