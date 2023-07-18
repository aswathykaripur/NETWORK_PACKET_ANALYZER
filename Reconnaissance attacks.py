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
    },
    "network_mapping": {
        "icmp_type": 8  # ICMP Echo Request (ping)
    },
    "dns_enumeration": {
        "query_types": ["ANY", "AXFR", "NS"],
        "threshold": 5  # Example threshold for number of DNS enumeration attempts
    },
    "whois": {
        "query_ports": [43]  # WHOIS query port
    },
    "dns_zone_transfer": {
        "query_types": ["AXFR"],
        "threshold": 1  # Example threshold for number of DNS zone transfer attempts
    }
    # Add more attack signatures as needed
}

# Packet capture and analysis function
def analyze_packet(packet):
    # Extract relevant packet attributes
    if packet.haslayer(IP):
        # Extract relevant packet attributes
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    sport = packet.sport
    dport = packet.dport

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
        if packet.haslayer(TCP) and packet.haslayer(IP):
            if packet[TCP].flags == attack_signatures["os_fingerprinting"]["tcp_flags"]:
                min_ttl, max_ttl = attack_signatures["os_fingerprinting"]["ttl_range"]
                if min_ttl <= packet[IP].ttl <= max_ttl:
                    print(f"[ALERT] Potential OS fingerprinting detected from {src_ip} to {dst_ip}")

    # Check for network mapping (ICMP Echo Request)
    if "network_mapping" in attack_signatures:
        if packet.haslayer(ICMP):
            if packet[ICMP].type == attack_signatures["network_mapping"]["icmp_type"]:
                print(f"[ALERT] Network mapping (ping) detected from {src_ip} to {dst_ip}")

    # Check for DNS enumeration activity
    if "dns_enumeration" in attack_signatures:
        if packet.haslayer(DNS):
            dns_qr = packet[DNS].qr
            dns_qd = packet[DNS].qd.qname.decode()

            if dns_qr == 0 and dns_qd in attack_signatures["dns_enumeration"]["query_types"]:
                # Increment the DNS enumeration counter for the source IP
                if src_ip in dns_enum_counter:
                    dns_enum_counter[src_ip] += 1
                else:
                    dns_enum_counter[src_ip] = 1

                # Generate an alert if the threshold is exceeded
                if dns_enum_counter[src_ip] >= attack_signatures["dns_enumeration"]["threshold"]:
                    print(f"[ALERT] Potential DNS enumeration detected from {src_ip} to {dst_ip}")

    # Check for WHOIS query activity
    if "whois" in attack_signatures:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            if dport in attack_signatures["whois"]["query_ports"]:
                print(f"[ALERT] WHOIS query detected from {src_ip} to {dst_ip}")

    # Check for DNS zone transfer activity
    if "dns_zone_transfer" in attack_signatures:
        if packet.haslayer(DNS):
            dns_qr = packet[DNS].qr
            dns_qd = packet[DNS].qd.qname.decode()

            if dns_qr == 0 and dns_qd in attack_signatures["dns_zone_transfer"]["query_types"]:
                # Increment the DNS zone transfer counter for the source IP
                if src_ip in dns_zone_transfer_counter:
                    dns_zone_transfer_counter[src_ip] += 1
                else:
                    dns_zone_transfer_counter[src_ip] = 1

                # Generate an alert if the threshold is exceeded
                if dns_zone_transfer_counter[src_ip] >= attack_signatures["dns_zone_transfer"]["threshold"]:
                    print(f"[ALERT] Potential DNS zone transfer detected from {src_ip} to {dst_ip}")


# Initialize the counters
port_scan_counter = {}
dns_enum_counter = {}
dns_zone_transfer_counter = {}

# Start capturing packets
sniff(filter="tcp or icmp or udp", prn=analyze_packet)
