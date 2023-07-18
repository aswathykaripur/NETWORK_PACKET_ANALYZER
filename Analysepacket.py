from scapy.all import *

def packet_handler(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload_size = len(packet[TCP].payload)
                packet_type = "TCP"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload_size = len(packet[UDP].payload)
                packet_type = "UDP"
            elif ICMP in packet:
                src_port = None
                dst_port = None
                payload_size = len(packet[ICMP].payload)
                packet_type = "ICMP"
            else:
                src_port = None
                dst_port = None
                payload_size = None
                packet_type = "Other"

            print("Source IP:", src_ip)
            print("Destination IP:", dst_ip)
            print("Protocol:", protocol)
            print("Source Port:", src_port)
            print("Destination Port:", dst_port)
            print("Packet Type:", packet_type)
            print("Payload Size:", payload_size)
            print("--------------------------")
        else:
            print("Non-IP packet")

    except Exception as e:
        print(f"Error occurred: {str(e)}")



    # You can perform further analysis or actions based on the packet content


# Sniff packets on the specified network interface (change 'eth0' to the appropriate interface name)
packets = sniff(iface='Wi-Fi', count=100, prn=packet_handler)

# Save the captured packets to a PCAP file (change 'captured_packets.pcap' to the desired file name)
wrpcap('C:\\Users\\mcasw\\OneDrive\\Desktop\\captured packets\\captured_packets.pcap',packets)

# Analyze the captured packets
for packet in packets:
    packet_handler(packet)
