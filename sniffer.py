from scapy.all import sniff
from datetime import datetime
import socket
import sqlite3
from pathlib import Path
import signal

def alarm_handler(signum, frame):
    flush_buffer()
    signal.alarm(30) # Reset alarm

def shutdown_handler(signum, frame):
    flush_buffer()
    exit(0)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

buffer = []
piip = get_local_ip()
MAX_SIZE = 100

def handle_packet(pkt):
    global buffer
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
        else:
            sport = None
            dport = None
        
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
        
        # print(f"{time} | {chksum} | {src}:{sport} -> {dst}:{dport} | proto={proto} | {direction} | {size} bytes") # debug print

        record = [time, src, sport, dst, dport, proto, direction, size]
        buffer.append(record)

        if len(buffer) >= MAX_SIZE:
            flush_buffer()

def table_init():
    db = sqlite3.connect("traffic.db")
    cursor = db.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic(
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            source_ip TEXT,
            source_port INTEGER,
            destination_ip TEXT,
            destination_port INTEGER,
            prototype TEXT,
            direction TEXT,
            packet_size INTEGER
        )
    ''')
    db.commit()
    db.close()


def flush_buffer():
    if not buffer: # Guard against signal alarm fire on empty buffer
        return
    
    db = sqlite3.connect("traffic.db")
    cursor = db.cursor()

    cursor.executemany('''INSERT INTO traffic(timestamp, source_ip, source_port, destination_ip, destination_port, prototype, direction, packet_size)
        VALUES(?,?,?,?,?,?,?,?)
        ''', buffer)
    db.commit()

    buffer[:] = []
    db.close()


def main():
    file = Path("traffic.db")
    if not file.exists():
        table_init()
    
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(30)

    sniff(prn=handle_packet, filter="not (udp port 5353)")



if __name__ == "__main__":
    main()