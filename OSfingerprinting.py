from scapy.all import *

# Define attack signatures
attack_signatures = {
    "port_scan": {
        "ports": [22, 80, 443],  # Example port numbers for scanning
        "threshold": 10  # Example threshold for number of port scan attempts
    },
    "os_fingerprinting": {
        "tcp_flags": "S",
        "ttl_range": (0, 64)  # Example TTL range for OS fingerprinting
    }
    # Add more attack signatures as needed
}

# Packet capture and analysis function
def analyze_packet(packet):
    # Extract relevant packet attributes
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    flags = packet[TCP].flags
    ttl = packet[IP].ttl

    # Check for port scanning activity
    if "port_scan" in attack_signatures:
        ports = attack_signatures["port_scan"]["ports"]
        threshold = attack_signatures["port_scan"]["threshold"]

        if dport in ports:
            # Increment the port scan counter for the source IP
            if src_ip in port_scan_counter:
                port_scan_counter[src_ip] += 1
            else:
                port_scan_counter[src_ip] = 1

            # Generate an alert if the threshold is exceeded
            if port_scan_counter[src_ip] >= threshold:
                print(f"[ALERT] Potential port scan detected from {src_ip} to port {dport} on {dst_ip}")

    # Check for OS fingerprinting activity
    if "os_fingerprinting" in attack_signatures:
        if flags == attack_signatures["os_fingerprinting"]["tcp_flags"]:
            min_ttl, max_ttl = attack_signatures["os_fingerprinting"]["ttl_range"]
            if min_ttl <= ttl <= max_ttl:
                print(f"[ALERT] Potential OS fingerprinting detected from {src_ip} to {dst_ip}")

# Initialize the port scan counter
port_scan_counter = {}

# Start capturing packets
sniff(filter="tcp", prn=analyze_packet)
