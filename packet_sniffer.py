from scapy.all import sniff, IP, TCP, UDP, ICMP
import argparse

def packet_callback(packet):
    """Process each captured packet"""
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Determine protocol name
        if protocol == 1:
            proto_name = "ICMP"
        elif protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        else:
            proto_name = f"Protocol #{protocol}"
        
        print(f"Source: {ip_src} -> Destination: {ip_dst} | Protocol: {proto_name}")
        
        # If TCP, show port information
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"  TCP: Source Port {src_port} -> Destination Port {dst_port}")
            
            # Check for HTTP traffic
            if dst_port == 80 or src_port == 80:
                print("  -> HTTP Traffic")
                if packet[TCP].payload:
                    try:
                        payload = packet[TCP].payload.load.decode('utf-8', errors='ignore')
                        if payload.startswith(('GET', 'POST', 'PUT', 'DELETE')):
                            print(f"  HTTP Request: {payload.split()[0]} {payload.split()[1]}")
                    except:
                        pass
        
        # If UDP, show port information
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  UDP: Source Port {src_port} -> Destination Port {dst_port}")
            
            # Check for DNS traffic
            if dst_port == 53 or src_port == 53:
                print("  -> DNS Traffic")
        
        # If ICMP
        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"  ICMP: Type {icmp_type}, Code {icmp_code}")
        
        print("-" * 80)

def main():
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer")
    parser.add_argument("-i", "--interface", default=None, help="Network interface to sniff on")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    args = parser.parse_args()
    
    print("Starting packet sniffer...")
    print("Press Ctrl+C to stop")
    print("=" * 80)
    
    try:
        sniff(iface=args.interface, prn=packet_callback, count=args.count, store=False)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped by user")
    except Exception as e:
        print(f"Error: {e}")
        print("Try running with sudo/administrator privileges")

if __name__ == "__main__":
    main()
