from scapy.all import *

def packet_handler(packet):
    # Process and print the captured packet
    print(packet.summary())

# Sniff network traffic on a specific interface (e.g., eth0)
sniff(iface="Wi-Fi", prn=packet_handler)
