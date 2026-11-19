"""
Generates MIXED_TRAFFIC_ATTACK_AND_BENIGN.pcap
Contains both realistic Benign conversations (normal browsing, API, DB)
and volumetric DDoS Floods (SYN Flood + UDP Flood).
"""
import os
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

def build_mixed_pcap():
    pkts = []
    t = 1700000000.0
    server_ip = "192.168.1.50"

    # ==========================================
    # PART 1: BENIGN TRAFFIC (3 Normal Users)
    # ==========================================

    # User 1: Legitimate HTTPS Web Browsing (192.168.1.105 -> 192.168.1.50:443)
    u1_ip = "192.168.1.105"
    u1_port = 51234
    p = Ether()/IP(src=u1_ip, dst=server_ip)/TCP(sport=u1_port, dport=443, flags="S", seq=100); p.time = t; pkts.append(p); t += 0.01
    p = Ether()/IP(src=server_ip, dst=u1_ip)/TCP(sport=443, dport=u1_port, flags="SA", seq=500, ack=101); p.time = t; pkts.append(p); t += 0.01
    p = Ether()/IP(src=u1_ip, dst=server_ip)/TCP(sport=u1_port, dport=443, flags="A", seq=101, ack=501); p.time = t; pkts.append(p); t += 0.01
    for req_i in range(15):
        t += 0.02
        req = Ether()/IP(src=u1_ip, dst=server_ip)/TCP(sport=u1_port, dport=443, flags="PA", seq=101 + req_i*100, ack=501 + req_i*500)/Raw(load=b"GET /dashboard HTTP/1.1\r\nHost: server\r\n\r\n")
        req.time = t; pkts.append(req)
        t += 0.01
        resp = Ether()/IP(src=server_ip, dst=u1_ip)/TCP(sport=443, dport=u1_port, flags="PA", seq=501 + req_i*500, ack=101 + (req_i+1)*100)/Raw(load=b"HTTP/1.1 200 OK\r\n\r\n" + b"Z"*450)
        resp.time = t; pkts.append(resp)

    # User 2: Legitimate API Queries (192.168.1.106 -> 192.168.1.50:8080)
    u2_ip = "192.168.1.106"
    u2_port = 52345
    p = Ether()/IP(src=u2_ip, dst=server_ip)/TCP(sport=u2_port, dport=8080, flags="S", seq=200); p.time = t; pkts.append(p); t += 0.01
    p = Ether()/IP(src=server_ip, dst=u2_ip)/TCP(sport=8080, dport=u2_port, flags="SA", seq=600, ack=201); p.time = t; pkts.append(p); t += 0.01
    p = Ether()/IP(src=u2_ip, dst=server_ip)/TCP(sport=u2_port, dport=8080, flags="A", seq=201, ack=601); p.time = t; pkts.append(p); t += 0.01
    for req_i in range(12):
        t += 0.02
        req = Ether()/IP(src=u2_ip, dst=server_ip)/TCP(sport=u2_port, dport=8080, flags="PA", seq=201 + req_i*80, ack=601 + req_i*300)/Raw(load=b"GET /api/v1/status HTTP/1.1\r\n\r\n")
        req.time = t; pkts.append(req)
        t += 0.01
        resp = Ether()/IP(src=server_ip, dst=u2_ip)/TCP(sport=8080, dport=u2_port, flags="PA", seq=601 + req_i*300, ack=201 + (req_i+1)*80)/Raw(load=b"status: ok")
        resp.time = t; pkts.append(resp)

    # User 3: Legitimate Database/Service (192.168.1.107 -> 192.168.1.50:3306)
    u3_ip = "192.168.1.107"
    u3_port = 53456
    p = Ether()/IP(src=u3_ip, dst=server_ip)/TCP(sport=u3_port, dport=3306, flags="S", seq=300); p.time = t; pkts.append(p); t += 0.01
    p = Ether()/IP(src=server_ip, dst=u3_ip)/TCP(sport=3306, dport=u3_port, flags="SA", seq=700, ack=301); p.time = t; pkts.append(p); t += 0.01
    p = Ether()/IP(src=u3_ip, dst=server_ip)/TCP(sport=u3_port, dport=3306, flags="A", seq=301, ack=701); p.time = t; pkts.append(p); t += 0.01
    for req_i in range(10):
        t += 0.02
        req = Ether()/IP(src=u3_ip, dst=server_ip)/TCP(sport=u3_port, dport=3306, flags="PA", seq=301 + req_i*50, ack=701 + req_i*150)/Raw(load=b"SELECT * FROM metrics")
        req.time = t; pkts.append(req)
        t += 0.01
        resp = Ether()/IP(src=server_ip, dst=u3_ip)/TCP(sport=3306, dport=u3_port, flags="PA", seq=701 + req_i*150, ack=301 + (req_i+1)*50)/Raw(load=b"RESULT_OK")
        resp.time = t; pkts.append(resp)

    # ==========================================
    # PART 2: DDOS ATTACK TRAFFIC (4 Botnet Floods)
    # ==========================================

    # Attack Bot 1: SYN Flood on port 443 (50 SYN packets, 0 ACKs)
    for p_idx in range(50):
        t += 0.0003
        p = Ether()/IP(src="198.51.100.10", dst=server_ip)/TCP(sport=4440, dport=443, flags="S", seq=1000 + p_idx)
        p.time = t; pkts.append(p)

    # Attack Bot 2: SYN Flood on port 80 (50 SYN packets, 0 ACKs)
    for p_idx in range(50):
        t += 0.0003
        p = Ether()/IP(src="198.51.100.11", dst=server_ip)/TCP(sport=4441, dport=80, flags="S", seq=2000 + p_idx)
        p.time = t; pkts.append(p)

    # Attack Bot 3: UDP Reflection Flood on port 53 (50 packets, 512B payload)
    for p_idx in range(50):
        t += 0.0002
        p = Ether()/IP(src="203.0.113.20", dst=server_ip)/UDP(sport=5000, dport=53)/Raw(load=b"X"*512)
        p.time = t; pkts.append(p)

    # Attack Bot 4: UDP Amplification Flood on port 5000 (50 packets, 512B payload)
    for p_idx in range(50):
        t += 0.0002
        p = Ether()/IP(src="203.0.113.21", dst=server_ip)/UDP(sport=5001, dport=5000)/Raw(load=b"Y"*512)
        p.time = t; pkts.append(p)

    # Chronological sort
    pkts.sort(key=lambda p: float(p.time))

    out_paths = [
        "MIXED_TRAFFIC_ATTACK_AND_BENIGN.pcap",
        "data/sample_pcaps/MIXED_TRAFFIC_ATTACK_AND_BENIGN.pcap"
    ]

    for out_p in out_paths:
        wrpcap(out_p, pkts)
        print(f"Saved {len(pkts)} packets to {out_p} ({os.path.getsize(out_p)} bytes)")

if __name__ == "__main__":
    build_mixed_pcap()
