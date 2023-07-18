from scapy.all import *


def packet_handler(packet):
    # Define your custom packet handling logic here
    # Extract relevant information from the packet
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport
    dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport

    # Print or process the extracted information as per your requirements
    print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Source Port: {src_port} | Destination Port: {dst_port}")

    # You can perform further analysis or actions based on the packet content


# Sniff packets on the specified network interface (change 'eth0' to the appropriate interface name)
sniff(iface='Wi-Fi', prn=packet_handler)
