"""
MLCS PBL - DDoS Detection Using Flow Data
Data Generation Module

Generates realistic network flow statistics modeled after standard benchmark
datasets such as CICIDS2017 and CICDDoS2019 (CICFlowMeter output).
Includes Benign traffic and major volumetric DDoS attack vectors:
  - SYN Flood
  - UDP Flood
  - HTTP Flood
"""

import numpy as np
import pandas as pd
import os
from typing import Tuple, Optional


def generate_flow_dataset(
    n_samples: int = 25000,
    benign_ratio: float = 0.50,
    random_state: int = 42,
    output_path: Optional[str] = None,
) -> pd.DataFrame:
    """
    Generate synthetic yet mathematically authentic flow statistics.
    
    Parameters:
        n_samples: Total number of flow records to generate.
        benign_ratio: Proportion of benign flows in the dataset.
        random_state: Seed for reproducibility.
        output_path: Optional file path to persist the generated CSV.
        
    Returns:
        pd.DataFrame: Network flow records with both binary and multi-class labels.
    """
    np.random.seed(random_state)
    
    n_benign = int(n_samples * benign_ratio)
    n_attack = n_samples - n_benign
    
    # Attack breakdown: 40% SYN Flood, 35% UDP Flood, 25% HTTP Flood
    n_syn = int(n_attack * 0.40)
    n_udp = int(n_attack * 0.35)
    n_http = n_attack - n_syn - n_udp

    records = []

    # 1. Benign Traffic (Normal browsing, streaming, API traffic)
    # Balanced fwd/bwd packets, legitimate TCP handshakes, realistic durations & IAT
    for _ in range(n_benign):
        flow_duration = float(np.random.exponential(scale=3_500_000) + 15_000)  # microseconds (15ms - ~15s)
        fwd_pkts = int(np.random.negative_binomial(5, 0.3) + 3)
        bwd_pkts = int(max(1, np.random.normal(loc=fwd_pkts * 0.9, scale=fwd_pkts * 0.25) + 1))
        
        tot_pkts = fwd_pkts + bwd_pkts
        avg_pkt_size = float(np.random.normal(loc=650, scale=180))
        avg_pkt_size = float(np.clip(avg_pkt_size, 64, 1500))
        
        tot_bytes = tot_pkts * avg_pkt_size
        duration_sec = max(flow_duration / 1_000_000.0, 0.0001)
        
        packets_sec = tot_pkts / duration_sec
        bytes_sec = tot_bytes / duration_sec
        fwd_bwd_ratio = fwd_pkts / max(bwd_pkts, 1)
        
        # Protocol: 85% TCP (6), 15% UDP (17)
        is_tcp = np.random.rand() < 0.85
        protocol = 6 if is_tcp else 17
        
        syn_count = 1 if is_tcp else 0
        ack_count = int(max(1, tot_pkts * 0.6)) if is_tcp else 0
        flow_iat_mean = flow_duration / max(tot_pkts - 1, 1)
        subflow_fwd_bytes = fwd_pkts * (avg_pkt_size * 0.8)
        
        dst_port = int(np.random.choice([80, 443, 8080, 53, 22, 3306], p=[0.35, 0.45, 0.08, 0.07, 0.03, 0.02]))
        src_port = int(np.random.randint(1024, 65535))

        records.append({
            "Flow_Duration": round(flow_duration, 2),
            "Total_Fwd_Packets": fwd_pkts,
            "Total_Bwd_Packets": bwd_pkts,
            "Flow_Packets_Sec": round(packets_sec, 2),
            "Flow_Bytes_Sec": round(bytes_sec, 2),
            "Fwd_Bwd_Packet_Ratio": round(fwd_bwd_ratio, 4),
            "SYN_Flag_Count": syn_count,
            "ACK_Flag_Count": ack_count,
            "Avg_Packet_Size": round(avg_pkt_size, 2),
            "Flow_IAT_Mean": round(flow_iat_mean, 2),
            "Subflow_Fwd_Bytes": round(subflow_fwd_bytes, 2),
            "Protocol": protocol,
            "Src_Port": src_port,
            "Dst_Port": dst_port,
            "Attack_Type": "Benign",
            "Label": "Benign",
            "Binary_Label": 0
        })

    # 2. SYN Flood Attack (Volumetric TCP SYN flood without finishing handshake)
    # High SYN count, zero/minimal backward packets, small packet sizes (~40-64 bytes),
    # very high packets/sec, very high Fwd/Bwd ratio
    for _ in range(n_syn):
        flow_duration = float(np.random.exponential(scale=450_000) + 1_000)  # Short bursts
        fwd_pkts = int(np.random.randint(25, 250))
        bwd_pkts = int(np.random.choice([0, 1], p=[0.92, 0.08]))  # Victims rarely respond or dropped
        
        tot_pkts = fwd_pkts + bwd_pkts
        avg_pkt_size = float(np.random.normal(loc=54, scale=6))  # Tiny TCP SYN packets
        avg_pkt_size = float(np.clip(avg_pkt_size, 40, 80))
        
        tot_bytes = tot_pkts * avg_pkt_size
        duration_sec = max(flow_duration / 1_000_000.0, 0.0001)
        
        packets_sec = tot_pkts / duration_sec
        bytes_sec = tot_bytes / duration_sec
        fwd_bwd_ratio = fwd_pkts / max(bwd_pkts, 1)
        
        syn_count = int(np.random.randint(max(1, fwd_pkts - 5), fwd_pkts + 1))
        ack_count = 0  # Attackers do not send ACKs
        flow_iat_mean = flow_duration / max(tot_pkts - 1, 1)
        subflow_fwd_bytes = fwd_pkts * avg_pkt_size
        
        dst_port = int(np.random.choice([80, 443, 8080], p=[0.6, 0.3, 0.1]))
        src_port = int(np.random.randint(1024, 65535))

        records.append({
            "Flow_Duration": round(flow_duration, 2),
            "Total_Fwd_Packets": fwd_pkts,
            "Total_Bwd_Packets": bwd_pkts,
            "Flow_Packets_Sec": round(packets_sec, 2),
            "Flow_Bytes_Sec": round(bytes_sec, 2),
            "Fwd_Bwd_Packet_Ratio": round(fwd_bwd_ratio, 4),
            "SYN_Flag_Count": syn_count,
            "ACK_Flag_Count": ack_count,
            "Avg_Packet_Size": round(avg_pkt_size, 2),
            "Flow_IAT_Mean": round(flow_iat_mean, 2),
            "Subflow_Fwd_Bytes": round(subflow_fwd_bytes, 2),
            "Protocol": 6,  # TCP
            "Src_Port": src_port,
            "Dst_Port": dst_port,
            "Attack_Type": "SYN_Flood",
            "Label": "Attack",
            "Binary_Label": 1
        })

    # 3. UDP Flood Attack (Massive stateless UDP payload stream)
    # Huge byte and packet rate, Protocol 17, zero TCP flags (SYN=0, ACK=0),
    # Fwd/Bwd ratio very high, fixed or repetitive packet size
    for _ in range(n_udp):
        flow_duration = float(np.random.exponential(scale=600_000) + 2_000)
        fwd_pkts = int(np.random.randint(50, 400))
        bwd_pkts = 0  # UDP flood targets don't reply back to spoofed IPs
        
        tot_pkts = fwd_pkts + bwd_pkts
        avg_pkt_size = float(np.random.normal(loc=512, scale=80))
        avg_pkt_size = float(np.clip(avg_pkt_size, 128, 1400))
        
        tot_bytes = tot_pkts * avg_pkt_size
        duration_sec = max(flow_duration / 1_000_000.0, 0.0001)
        
        packets_sec = tot_pkts / duration_sec
        bytes_sec = tot_bytes / duration_sec
        fwd_bwd_ratio = float(fwd_pkts)  # bwd is 0, ratio = fwd
        
        flow_iat_mean = flow_duration / max(tot_pkts - 1, 1)
        subflow_fwd_bytes = fwd_pkts * avg_pkt_size
        
        dst_port = int(np.random.choice([53, 123, 389, 5000, 80], p=[0.4, 0.2, 0.15, 0.15, 0.1]))
        src_port = int(np.random.randint(1024, 65535))

        records.append({
            "Flow_Duration": round(flow_duration, 2),
            "Total_Fwd_Packets": fwd_pkts,
            "Total_Bwd_Packets": bwd_pkts,
            "Flow_Packets_Sec": round(packets_sec, 2),
            "Flow_Bytes_Sec": round(bytes_sec, 2),
            "Fwd_Bwd_Packet_Ratio": round(fwd_bwd_ratio, 4),
            "SYN_Flag_Count": 0,
            "ACK_Flag_Count": 0,
            "Avg_Packet_Size": round(avg_pkt_size, 2),
            "Flow_IAT_Mean": round(flow_iat_mean, 2),
            "Subflow_Fwd_Bytes": round(subflow_fwd_bytes, 2),
            "Protocol": 17,  # UDP
            "Src_Port": src_port,
            "Dst_Port": dst_port,
            "Attack_Type": "UDP_Flood",
            "Label": "Attack",
            "Binary_Label": 1
        })

    # 4. HTTP Flood Attack (Application-layer L7 flood mimicking valid requests)
    # Valid TCP handshake (SYN=1, ACK>0), high request frequency,
    # HTTP payload sizes (e.g. 700 - 1450 bytes), high packets/sec, victim overwhelmed with 503/408
    for _ in range(n_http):
        flow_duration = float(np.random.exponential(scale=1_200_000) + 10_000)
        fwd_pkts = int(np.random.randint(30, 200))
        bwd_pkts = int(np.random.randint(1, 10))  # Target struggles to respond
        
        tot_pkts = fwd_pkts + bwd_pkts
        avg_pkt_size = float(np.random.normal(loc=980, scale=150))
        avg_pkt_size = float(np.clip(avg_pkt_size, 400, 1500))
        
        tot_bytes = tot_pkts * avg_pkt_size
        duration_sec = max(flow_duration / 1_000_000.0, 0.0001)
        
        packets_sec = tot_pkts / duration_sec
        bytes_sec = tot_bytes / duration_sec
        fwd_bwd_ratio = fwd_pkts / max(bwd_pkts, 1)
        
        syn_count = 1
        ack_count = int(fwd_pkts * 0.7)
        flow_iat_mean = flow_duration / max(tot_pkts - 1, 1)
        subflow_fwd_bytes = fwd_pkts * avg_pkt_size
        
        dst_port = int(np.random.choice([80, 443, 8080], p=[0.7, 0.25, 0.05]))
        src_port = int(np.random.randint(1024, 65535))

        records.append({
            "Flow_Duration": round(flow_duration, 2),
            "Total_Fwd_Packets": fwd_pkts,
            "Total_Bwd_Packets": bwd_pkts,
            "Flow_Packets_Sec": round(packets_sec, 2),
            "Flow_Bytes_Sec": round(bytes_sec, 2),
            "Fwd_Bwd_Packet_Ratio": round(fwd_bwd_ratio, 4),
            "SYN_Flag_Count": syn_count,
            "ACK_Flag_Count": ack_count,
            "Avg_Packet_Size": round(avg_pkt_size, 2),
            "Flow_IAT_Mean": round(flow_iat_mean, 2),
            "Subflow_Fwd_Bytes": round(subflow_fwd_bytes, 2),
            "Protocol": 6,  # TCP
            "Src_Port": src_port,
            "Dst_Port": dst_port,
            "Attack_Type": "HTTP_Flood",
            "Label": "Attack",
            "Binary_Label": 1
        })

    df = pd.DataFrame(records)
    # Shuffle records
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"[Dataset Generator] Successfully saved {len(df)} flow records to {output_path}")

    return df


if __name__ == "__main__":
    raw_path = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "network_flows.csv")
    generate_flow_dataset(n_samples=25000, benign_ratio=0.5, random_state=42, output_path=raw_path)
