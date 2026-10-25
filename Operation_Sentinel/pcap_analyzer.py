from collections import Counter, defaultdict, deque

from settings import PCAP_FILE


def analyze_pcap(path=PCAP_FILE, limit=20, seconds=5):
    """Flag >20 TCP/UDP IPv4 packets from one source within any 5 seconds.

    A burst is worth investigating, but is NOT proof of a DDoS attack.
    """
    from scapy.all import IP, TCP, UDP, rdpcap

    packets = rdpcap(str(path))
    tcp_count = 0
    udp_count = 0
    sources = Counter()
    recent = defaultdict(deque)
    alerts = []
    alerted_ips = set()

    indexed = sorted(enumerate(packets, start=1), key=lambda x: float(x[1].time))

    for packet_number, pkt in indexed:
        if TCP in pkt:
            tcp_count += 1
        if UDP in pkt:
            udp_count += 1

        if IP not in pkt or not (TCP in pkt or UDP in pkt):
            continue

        ip = pkt[IP].src
        sources[ip] += 1
        timestamp = float(pkt.time)
        window = recent[ip]
        while window and timestamp - window[0][0] > seconds:
            window.popleft()
        window.append((timestamp, packet_number))

        if len(window) > limit and ip not in alerted_ips:
            alerted_ips.add(ip)
            alerts.append({
                "source": ip,
                "packets_in_window": len(window),
                "window_seconds": round(timestamp - window[0][0], 3),
                "first_packet": window[0][1],
                "trigger_packet": packet_number,
                "reason": f"More than {limit} TCP/UDP packets within {seconds} seconds"
            })

    return {
        "total_packets": len(packets),
        "tcp_packets": tcp_count,
        "udp_packets": udp_count,
        "other_packets": len(packets) - sum(1 for p in packets if TCP in p or UDP in p),
        "top_sources": [{"source": k, "packets": v} for k, v in sources.most_common(5)],
        "threshold": f"More than {limit} IPv4 TCP/UDP packets in {seconds}s from one IP",
        "suspicious_sources": len(alerts),
        "alerts": alerts,
        "warning": "A high packet rate is only an indicator, not proof of an attack."
    }
