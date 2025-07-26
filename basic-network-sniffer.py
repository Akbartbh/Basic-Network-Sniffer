from scapy.all import sniff, IP, TCP

def packet_handler(packet):
    """
    This function is called for each captured packet.
    It prints a summary of the packet and extracts IP and TCP information if available.
    """
    print(packet.summary())

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"  Source IP: {src_ip}, Destination IP: {dst_ip}")

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"  Source Port: {src_port}, Destination Port: {dst_port}")

def start_sniffer(interface=None, count=0):
    """
    Starts the network sniffer.

    Args:
        interface (str, optional): The network interface to sniff on (e.g., "eth0", "Wi-Fi").
                                  If None, Scapy attempts to use the default interface.
        count (int, optional): The number of packets to sniff. 0 means sniff indefinitely.
    """
    print(f"Starting sniffer on interface: {interface if interface else 'default'}")
    print("Press Ctrl+C to stop.")
    try:
        sniff(iface=interface, prn=packet_handler, count=count, store=0)
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__": 
    # Example usage:
    # Sniff 10 packets on the default interface
    # start_sniffer(count=10)

    # Sniff indefinitely on a specific interface (e.g., "eth0" or "Wi-Fi")
    start_sniffer(interface="Wi-Fi") # Replace "Wi-Fi" with your actual interface name