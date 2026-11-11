"""
CYBERGUARD AI - PCAP Traffic Analyzer
Module 3: PCAP File Validation, Flow Extraction, and Threat Classification

Safely validates uploaded PCAP/PCAPNG network packet captures, groups packets
into bidirectional 5-tuple flows, computes flow statistics, and classifies traffic.
"""

import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import struct
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd

try:
    from scapy.all import rdpcap, IP, TCP, UDP, wrpcap, Ether
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from src.preprocessing import ALL_FLOW_FEATURES


PCAP_MAGIC_NUMBERS = [
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (identical endian)
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (swapped endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (swapped)
    b"\x0a\x0d\x0d\x0a"   # PCAPNG format
]


def validate_pcap_file(file_bytes: bytes, max_size_mb: int = 25) -> Tuple[bool, str]:
    """
    Safely validates uploaded file headers and sizes to prevent injection or DoS.
    """
    if len(file_bytes) > max_size_mb * 1024 * 1024:
        return False, f"File exceeds maximum allowed size ({max_size_mb} MB)."

    if len(file_bytes) < 24:
        return False, "File is too small to be a valid PCAP capture header."

    magic = file_bytes[:4]
    if magic not in PCAP_MAGIC_NUMBERS:
        return False, "Invalid file format: Missing standard PCAP / PCAPNG magic header."

    return True, "Valid PCAP header detected."


def parse_pcap_to_flows(pcap_path_or_bytes) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Parses PCAP capture and groups packets into 5-tuple bidirectional flows.
    """
    if not HAS_SCAPY:
        raise RuntimeError("Scapy is required for PCAP parsing. Run `pip install scapy`.")

    import tempfile
    temp_path = None
    if isinstance(pcap_path_or_bytes, bytes):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(pcap_path_or_bytes)
            temp_path = tmp.name
        packets = rdpcap(temp_path)
    else:
        packets = rdpcap(pcap_path_or_bytes)

    if temp_path and os.path.exists(temp_path):
        try:
            os.remove(temp_path)
        except Exception:
            pass

    # Group packets into flows: key = (proto, ip1, port1, ip2, port2)
    flows_dict: Dict[Tuple, List[Dict[str, Any]]] = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        proto = int(ip.proto)
        src_ip = ip.src
        dst_ip = ip.dst
        pkt_len = int(len(pkt))
        ts = float(pkt.time)

        src_port = 0
        dst_port = 0
        is_syn = 0
        is_ack = 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            flags = int(tcp.flags)
            is_syn = 1 if (flags & 0x02) else 0
            is_ack = 1 if (flags & 0x10) else 0
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)

        # Standardize bidirectional flow key
        if (src_ip, src_port) < (dst_ip, dst_port):
            flow_key = (proto, src_ip, src_port, dst_ip, dst_port)
            direction = "fwd"
        else:
            flow_key = (proto, dst_ip, dst_port, src_ip, src_port)
            direction = "bwd"

        if flow_key not in flows_dict:
            flows_dict[flow_key] = []

        flows_dict[flow_key].append({
            "timestamp": ts,
            "length": pkt_len,
            "direction": direction,
            "is_syn": is_syn,
            "is_ack": is_ack,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto
        })

    flow_records = []
    total_packets = len(packets)

    for flow_key, pkt_list in flows_dict.items():
        if not pkt_list:
            continue

        proto, ip1, p1, ip2, p2 = flow_key
        pkt_list.sort(key=lambda x: x["timestamp"])

        t_start = pkt_list[0]["timestamp"]
        t_end = pkt_list[-1]["timestamp"]
        duration_sec = max(t_end - t_start, 0.0001)
        duration_us = duration_sec * 1_000_000.0

        fwd_pkts = sum(1 for p in pkt_list if p["direction"] == "fwd")
        bwd_pkts = sum(1 for p in pkt_list if p["direction"] == "bwd")
        total_pkts = len(pkt_list)

        total_bytes = sum(p["length"] for p in pkt_list)
        fwd_bytes = sum(p["length"] for p in pkt_list if p["direction"] == "fwd")

        syn_count = sum(p["is_syn"] for p in pkt_list)
        ack_count = sum(p["is_ack"] for p in pkt_list)

        avg_pkt_size = total_bytes / max(total_pkts, 1)
        pps = total_pkts / duration_sec
        bps = total_bytes / duration_sec
        ratio = fwd_pkts / max(bwd_pkts, 1)

        # Inter-arrival time
        iats = [pkt_list[i]["timestamp"] - pkt_list[i-1]["timestamp"] for i in range(1, len(pkt_list))]
        mean_iat_us = (sum(iats) / max(len(iats), 1)) * 1_000_000.0 if iats else duration_us

        flow_records.append({
            "Flow_Duration": round(duration_us, 2),
            "Flow_Packets_Sec": round(pps, 2),
            "Flow_Bytes_Sec": round(bps, 2),
            "Fwd_Bwd_Packet_Ratio": round(ratio, 4),
            "SYN_Flag_Count": syn_count,
            "Avg_Packet_Size": round(avg_pkt_size, 2),
            "Total_Fwd_Packets": fwd_pkts,
            "Total_Bwd_Packets": bwd_pkts,
            "ACK_Flag_Count": ack_count,
            "Flow_IAT_Mean": round(mean_iat_us, 2),
            "Subflow_Fwd_Bytes": round(float(fwd_bytes), 2),
            "Protocol": proto,
            "Src_IP": ip1,
            "Dst_IP": ip2,
            "Src_Port": p1,
            "Dst_Port": p2
        })

    df_flows = pd.DataFrame(flow_records)
    telemetry = {
        "total_packets": total_packets,
        "total_flows_reconstructed": len(df_flows),
        "unique_endpoints": len(set([f[1] for f in flows_dict.keys()] + [f[3] for f in flows_dict.keys()]))
    }
    return df_flows, telemetry


def generate_sample_pcaps(output_dir: str):
    """
    Generates authentic synthetic PCAP captures for offline testing without external tools.
    """
    if not HAS_SCAPY:
        return

    os.makedirs(output_dir, exist_ok=True)
    
    # 1. SYN Flood PCAP
    syn_pkts = []
    t = 1700000000.0
    for i in range(120):
        t += 0.0003
        pkt = Ether() / IP(src=f"198.51.100.{10 + (i % 20)}", dst="192.168.1.50") / TCP(sport=1024 + i, dport=443, flags="S", seq=1000 + i)
        pkt.time = t
        syn_pkts.append(pkt)
    wrpcap(os.path.join(output_dir, "syn_flood_sample.pcap"), syn_pkts)

    # 2. UDP Flood PCAP
    udp_pkts = []
    t = 1700000000.0
    for i in range(150):
        t += 0.0002
        payload = b"X" * 512
        pkt = Ether() / IP(src=f"203.0.113.{5 + (i % 30)}", dst="192.168.1.50") / UDP(sport=5000 + i, dport=53) / payload
        pkt.time = t
        udp_pkts.append(pkt)
    wrpcap(os.path.join(output_dir, "udp_flood_sample.pcap"), udp_pkts)

    # 3. Benign Browsing PCAP (Bidirectional 3-way handshake + HTTP transaction)
    benign_pkts = []
    t = 1700000000.0
    client_ip = "192.168.1.105"
    server_ip = "142.250.190.138"
    c_port = 54321
    s_port = 80
    
    # Handshake
    p1 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=c_port, dport=s_port, flags="S", seq=100)
    p1.time = t; benign_pkts.append(p1)
    t += 0.015
    p2 = Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=s_port, dport=c_port, flags="SA", seq=500, ack=101)
    p2.time = t; benign_pkts.append(p2)
    t += 0.005
    p3 = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=c_port, dport=s_port, flags="A", seq=101, ack=501)
    p3.time = t; benign_pkts.append(p3)
    
    # Data exchange
    for _ in range(8):
        t += 0.02
        req = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=c_port, dport=s_port, flags="PA", seq=101, ack=501) / (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        req.time = t; benign_pkts.append(req)
        t += 0.03
        resp = Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=s_port, dport=c_port, flags="PA", seq=501, ack=150) / (b"HTTP/1.1 200 OK\r\nContent-Length: 650\r\n\r\n" + b"A" * 600)
        resp.time = t; benign_pkts.append(resp)
        
    wrpcap(os.path.join(output_dir, "benign_traffic_sample.pcap"), benign_pkts)
    print(f"[PCAP Generator] Sample test pcaps generated at {output_dir}")


if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data", "sample_pcaps")
    generate_sample_pcaps(out_dir)
