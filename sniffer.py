from scapy.all import sniff

def handle_packet(pkt):
    # print(pkt.summary())
    if pkt.haslayer("IP"):
        src = pkt["IP"].src
        dst = pkt["IP"].dst
        proto = pkt["IP"].proto # 6 = TCP, 17 = UDP
        size = len(pkt)
        print(f"{src} -> {dst} | proto={proto} | {size} bytes")

sniff(prn=handle_packet, count=10)