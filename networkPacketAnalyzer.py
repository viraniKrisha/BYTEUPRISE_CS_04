from scapy.all import sniff, conf, IP, TCP, UDP
from datetime import datetime
import sys

# Define a callback function to process each captured packet
def packet_callback(packet):
    # Print packet summary
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if IP in packet:
        print(f"IP Packet: {packet[IP].src} -> {packet[IP].dst}")
    if TCP in packet:
        print(f"TCP Segment: {packet[TCP].sport} -> {packet[TCP].dport}")
    elif UDP in packet:
        print(f"UDP Datagram: {packet[UDP].sport} -> {packet[UDP].dport}")
    print("=" * 50)

# Main function to start the packet sniffer
def main():
    # Specify the network interface to capture packets from
    interface = input("Enter the network interface to sniff on (e.g., Ethernet, Wi-Fi): ")

    print(f"Starting packet capture on interface {interface}")
    print("Press Ctrl+C to stop.")

    try:
        # Set the L3 socket configuration
        conf.L3socket
        # Start sniffing packets
        sniff(iface=interface, prn=packet_callback, store=0, filter="ip")
    except PermissionError as e:
        print(f"Error: {e}")
        print("You need to run this script as an administrator.")
        sys.exit(1)
    except RuntimeError as e:
        print(f"Runtime Error: {e}")
        print("Ensure Npcap is installed and in WinPcap API-compatible mode.")
        sys.exit(1)

if __name__ == "__main__":
    main()
