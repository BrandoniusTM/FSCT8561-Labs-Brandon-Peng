from scapy.all import rdpcap, IP, TCP, UDP

packets = rdpcap("botnet-capture-20110812-rbot.pcap")

tcp_count = 0
udp_count = 0
shown = 0

for pkt in packets:
    if TCP in pkt:
        tcp_count += 1
    if UDP in pkt:
        udp_count += 1

    if IP in pkt and (TCP in pkt or UDP in pkt) and shown < 20:
        if TCP in pkt:
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        else:
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        print(
            "Source:", pkt[IP].src,
            "Destination:", pkt[IP].dst,
            "Protocol:", protocol,
            "Source port:", src_port,
            "Destination port:", dst_port,
        )
        shown += 1

print("\nTraffic Summary")
print("Total TCP packets:", tcp_count)
print("Total UDP packets:", udp_count)
