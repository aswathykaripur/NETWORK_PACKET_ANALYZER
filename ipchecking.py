# Packet capture and analysis function
def analyze_packet(packet):
    if packet.haslayer(IP):
        # Extract relevant packet attributes
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if "port_scan" in attack_signatures:
            # ... (Rest of the code for port scanning detection)

        if "os_fingerprinting" in attack_signatures:
            # ... (Rest of the code for OS fingerprinting detection)

        if "network_mapping" in attack_signatures:
            # ... (Rest of the code for network mapping detection)

        if "dns_enumeration" in attack_signatures:
            # ... (Rest of the code for DNS enumeration detection)

        if "whois" in attack_signatures:
            # ... (Rest of the code for WHOIS query detection)

        if "dns_zone_transfer" in attack_signatures:
            # ... (Rest of the code for DNS zone transfer detection)
