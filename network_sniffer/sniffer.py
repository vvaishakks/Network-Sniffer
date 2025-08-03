from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

conf.use_pcap = True  # Ensure WinPcap/Npcap is used

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print("\n🧾 New Packet:")
        print(f"🌐 From: {ip_layer.src}")
        print(f"➡️ To:   {ip_layer.dst}")
        
        proto = ip_layer.proto
        protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")
        print(f"📦 Protocol: {protocol_name}")

        if packet.haslayer(TCP):
            print(f"🔐 TCP Ports: {packet[TCP].sport} ➡️ {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"📨 UDP Ports: {packet[UDP].sport} ➡️ {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print("📣 ICMP Packet (Ping/Control)")

print("📡 Sniffing network traffic...\n")
sniff(filter="ip", prn=process_packet, count=10)
