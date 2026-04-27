from scapy.all import sniff, IP

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        proto_name = ""

        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        elif protocol == 1:
            proto_name = "ICMP"
        else:
            proto_name = str(protocol)

        print("Packet Captured:")
        print("Source IP:", src_ip)
        print("Destination IP:", dst_ip)
        print("Protocol:", proto_name)
        print("-" * 50)

print("Starting Network Sniffer...")
sniff(prn=packet_callback, store=False)