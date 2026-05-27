from scapy.all import sniff
from datetime import datetime
import socket

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def handle_packet(pkt):
    piip = get_local_ip()
    # print(pkt.summary())

    if pkt.haslayer("IP"):
        src = pkt["IP"].src
        dst = pkt["IP"].dst

        if pkt.haslayer("TCP"):
            sport = pkt["TCP"].sport
            dport = pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            sport = pkt["UDP"].sport
            dport = pkt["UDP"].dport
        
        proto = pkt["IP"].proto # 6 = TCP, 17 = UDP
        size = len(pkt)
        chksum = pkt["IP"].chksum

        now = datetime.now()
        time = now.strftime("%Y-%m-%d %H:%M:%S")

        if src == piip:
            direction = "outbound"
        elif dst == piip:
            direction = "inbound"
        else:
            direction = "unknown"
        
        print(f"{time} | {chksum} | {src}:{sport} -> {dst}:{dport} | proto={proto} | {direction} | {size} bytes")

sniff(prn=handle_packet, count=10)