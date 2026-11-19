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


def _parse_pcap_native(data_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Pure-Python robust fallback PCAP parser.
    Parses standard IPv4, TCP/UDP packets, flags, and timestamps with zero dependencies.
    """
    if len(data_bytes) < 24:
        return []

    endian = "<" if struct.unpack("<I", data_bytes[:4])[0] == 0xa1b2c3d4 else ">"
    offset = 24
    parsed_packets = []

    while offset + 16 <= len(data_bytes):
        hdr = data_bytes[offset:offset+16]
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", hdr)
        offset += 16

        if offset + incl_len > len(data_bytes):
            break

        pkt_data = data_bytes[offset:offset+incl_len]
        offset += incl_len
        ts = float(ts_sec) + float(ts_usec) / 1_000_000.0

        if len(pkt_data) < 34:
            continue

        eth_type = struct.unpack("!H", pkt_data[12:14])[0]
        ip_offset = 14
        if eth_type == 0x8100 and len(pkt_data) >= 38:  # 802.1Q VLAN Tagged
            eth_type = struct.unpack("!H", pkt_data[16:18])[0]
            ip_offset = 18

        if eth_type != 0x0800:  # Only IPv4
            continue

        ip_header = pkt_data[ip_offset:]
        if len(ip_header) < 20:
            continue

        ihl = (ip_header[0] & 0x0F) * 4
        proto = int(ip_header[9])
        src_ip = ".".join(str(b) for b in ip_header[12:16])
        dst_ip = ".".join(str(b) for b in ip_header[16:20])

        l4_data = ip_header[ihl:]
        src_port, dst_port = 0, 0
        is_syn, is_ack = 0, 0

        if proto == 6 and len(l4_data) >= 14:  # TCP
            src_port, dst_port = struct.unpack("!HH", l4_data[:4])
            flags = l4_data[13]
            is_syn = 1 if (flags & 0x02) else 0
            is_ack = 1 if (flags & 0x10) else 0
        elif proto == 17 and len(l4_data) >= 4:  # UDP
            src_port, dst_port = struct.unpack("!HH", l4_data[:4])

        parsed_packets.append({
            "timestamp": ts,
            "length": incl_len,
            "is_syn": is_syn,
            "is_ack": is_ack,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "proto": proto
        })

    return parsed_packets


def parse_pcap_to_flows(pcap_path_or_bytes) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Parses PCAP capture and groups packets into 5-tuple bidirectional flows.
    Uses Scapy when available, and automatically falls back to native binary parser.
    """
    raw_bytes = None
    if isinstance(pcap_path_or_bytes, bytes):
        raw_bytes = pcap_path_or_bytes
    elif isinstance(pcap_path_or_bytes, str) and os.path.exists(pcap_path_or_bytes):
        with open(pcap_path_or_bytes, "rb") as f:
            raw_bytes = f.read()

    pkt_items: List[Dict[str, Any]] = []

    # Method A: Try Scapy if available in system
    if HAS_SCAPY:
        try:
            from scapy.all import rdpcap as _rdpcap, IP as _IP, TCP as _TCP, UDP as _UDP
            import tempfile
            temp_path = None
            if raw_bytes is not None:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
                    tmp.write(raw_bytes)
                    temp_path = tmp.name
                packets = _rdpcap(temp_path)
            else:
                packets = _rdpcap(pcap_path_or_bytes)

            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

            for pkt in packets:
                if not pkt.haslayer(_IP):
                    continue
                ip = pkt[_IP]
                proto = int(ip.proto)
                src_ip = ip.src
                dst_ip = ip.dst
                pkt_len = int(len(pkt))
                ts = float(pkt.time)
                src_port = 0
                dst_port = 0
                is_syn = 0
                is_ack = 0

                if pkt.haslayer(_TCP):
                    tcp = pkt[_TCP]
                    src_port = int(tcp.sport)
                    dst_port = int(tcp.dport)
                    flags = int(tcp.flags)
                    is_syn = 1 if (flags & 0x02) else 0
                    is_ack = 1 if (flags & 0x10) else 0
                elif pkt.haslayer(_UDP):
                    udp = pkt[_UDP]
                    src_port = int(udp.sport)
                    dst_port = int(udp.dport)

                pkt_items.append({
                    "timestamp": ts,
                    "length": pkt_len,
                    "is_syn": is_syn,
                    "is_ack": is_ack,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "proto": proto
                })
        except Exception:
            pkt_items = []

    # Method B: Robust native fallback if Scapy was unavailable or failed
    if not pkt_items and raw_bytes is not None:
        pkt_items = _parse_pcap_native(raw_bytes)

    # Group packets into bidirectional flows: key = (proto, min_endpoint, max_endpoint)
    flows_dict: Dict[Tuple, List[Dict[str, Any]]] = {}

    for item in pkt_items:
        src_ip = item["src_ip"]
        dst_ip = item["dst_ip"]
        src_port = item["src_port"]
        dst_port = item["dst_port"]
        proto = item["proto"]

        if (src_ip, src_port) <= (dst_ip, dst_port):
            flow_key = (proto, src_ip, src_port, dst_ip, dst_port)
        else:
            flow_key = (proto, dst_ip, dst_port, src_ip, src_port)

        if flow_key not in flows_dict:
            flows_dict[flow_key] = []

        flows_dict[flow_key].append(dict(item))

    flow_records = []
    total_packets = len(pkt_items)

    for flow_key, pkt_list in flows_dict.items():
        if not pkt_list:
            continue

        pkt_list.sort(key=lambda x: x["timestamp"])

        # The initial packet defines the conversation initiator (Forward Client)
        fwd_src_ip = pkt_list[0]["src_ip"]
        fwd_src_port = pkt_list[0]["src_port"]
        fwd_dst_ip = pkt_list[0]["dst_ip"]
        fwd_dst_port = pkt_list[0]["dst_port"]
        proto = pkt_list[0]["proto"]

        t_start = pkt_list[0]["timestamp"]
        t_end = pkt_list[-1]["timestamp"]
        duration_sec = max(t_end - t_start, 0.0001)
        duration_us = duration_sec * 1_000_000.0

        fwd_pkts = 0
        bwd_pkts = 0
        fwd_bytes = 0
        bwd_bytes = 0

        for p in pkt_list:
            if (p["src_ip"], p["src_port"]) == (fwd_src_ip, fwd_src_port):
                fwd_pkts += 1
                fwd_bytes += p["length"]
            else:
                bwd_pkts += 1
                bwd_bytes += p["length"]

        total_pkts = len(pkt_list)
        total_bytes = sum(p["length"] for p in pkt_list)

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
            "Src_IP": fwd_src_ip,
            "Dst_IP": fwd_dst_ip,
            "Src_Port": fwd_src_port,
            "Dst_Port": fwd_dst_port
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
    
    # 1. SYN Flood PCAP (Multi-stream high-rate SYN flood targeting port 443)
    syn_pkts = []
    t = 1700000000.0
    for bot_idx in range(4):
        bot_ip = f"198.51.100.{10 + bot_idx}"
        sport = 4440 + bot_idx
        for p_idx in range(50):
            t += 0.0003
            pkt = Ether() / IP(src=bot_ip, dst="192.168.1.50") / TCP(sport=sport, dport=443, flags="S", seq=1000 + p_idx)
            pkt.time = t
            syn_pkts.append(pkt)
    wrpcap(os.path.join(output_dir, "syn_flood_sample.pcap"), syn_pkts)

    # 2. UDP Flood PCAP (Multi-stream high-rate UDP reflection flood targeting port 53)
    udp_pkts = []
    t = 1700000000.0
    for bot_idx in range(4):
        bot_ip = f"203.0.113.{5 + bot_idx}"
        sport = 5000 + bot_idx
        for p_idx in range(50):
            t += 0.0002
            payload = b"X" * 512
            pkt = Ether() / IP(src=bot_ip, dst="192.168.1.50") / UDP(sport=sport, dport=53) / payload
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

    # 4. Master Full-Spectrum DDoS Attack Capture (Benign handshake + Multi-vector botnet flood)
    master_pkts = list(benign_pkts) + list(syn_pkts) + list(udp_pkts)
    master_pkts.sort(key=lambda p: float(p.time))
    wrpcap(os.path.join(output_dir, "ddos_attack_capture.pcap"), master_pkts)
    print(f"[PCAP Generator] All test pcaps successfully generated at {output_dir}")


if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data", "sample_pcaps")
    generate_sample_pcaps(out_dir)
