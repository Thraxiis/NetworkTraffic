from scapy.all import sniff
from datetime import datetime
import socket
import sqlite3
from pathlib import Path
import signal
import geoip2.database
import ipaddress

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

MAX_SIZE = 100
buffer = []
piip = get_local_ip()
city_reader = geoip2.database.Reader("GeoLite2-City.mmdb")
asn_reader = geoip2.database.Reader("GeoLite2-ASN.mmdb")
socket.setdefaulttimeout(2)

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return True

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
        
        # print(f"{time} | {chksum} | {src}:{sport} -> {dst}:{dport} | 
        # proto={proto} | {direction} | {size} bytes") # debug print

        record = {
            "timestamp": time,
            "source_ip": src,
            "source_port": sport,
            "destination_ip": dst,
            "destination_port": dport,
            "destination_domain": None,
            "country": None,
            "city": None,
            "organization": None,
            "prototype": proto,
            "direction": direction,
            "packet_size": size
        }
        # [time, src, sport, dst, dport, proto, direction, size]
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
            destination_domain TEXT,
            country TEXT, 
            city TEXT, 
            organization TEXT,
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

    for rec in buffer:
        if not is_private(rec["destination_ip"]):
            try:
                rec["destination_domain"] = socket.gethostbyaddr(rec["destination_ip"])[0]
            except:
                rec["destination_domain"] = None

            try:
                city_response = city_reader.city(rec["destination_ip"])
                rec["country"] = city_response.country.name
                rec["city"] = city_response.city.name
            except:
                rec["country"] = None
                rec["city"] = None
            
            try:
                rec["organization"] = asn_reader.asn(rec["destination_ip"]).autonomous_system_organization
            except:
                rec["organization"] = None
        else:
            rec["destination_domain"] = "local"
            rec["country"] = "local"
            rec["city"] = "local"
            rec["organization"] = "local"

    cursor.executemany('''INSERT INTO traffic(
            timestamp, source_ip, source_port, 
            destination_ip, destination_port, destination_domain, country,
            city, organization, prototype, direction, packet_size
        )
        VALUES(:timestamp, :source_ip, :source_port, :destination_ip, 
                :destination_port, :destination_domain, :country,
                :city, :organization, :prototype, :direction, :packet_size
                )
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