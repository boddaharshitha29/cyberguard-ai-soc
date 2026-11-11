"""
MLCS PBL - DDoS Detection Using Flow Data
Real-Time Detection & Mitigation Engine

Implements the 4-step Flow-Based Detection Pipeline:
  Step 1: Network Traffic Captured at Router / SDN Switch
  Step 2: Flow Extraction (Duration, Packets/s, Bytes/s, Flag counts)
  Step 3: RF Classifier Scoring with ultra-low latency (<15 microseconds)
  Step 4: Benign vs Attack Flagging & Automated Firewall Rule Generation
"""

import os
import sys
import time
import numpy as np
import pandas as pd
from typing import Dict, Any, Generator, Optional, List

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.model import DDoSFlowClassifier
from src.utils import generate_random_ip, generate_firewall_rule
from src.preprocessing import ALL_FLOW_FEATURES


class FlowMitigationEngine:
    """
    Engine executing real-time flow scoring and mitigation rule synthesis.
    """
    def __init__(self, binary_model_path: str, multiclass_model_path: Optional[str] = None):
        if not os.path.exists(binary_model_path):
            raise FileNotFoundError(f"Model file not found at {binary_model_path}. Train the model first.")
        
        self.rf_model = DDoSFlowClassifier.load(binary_model_path)
        self.multiclass_model = None
        if multiclass_model_path and os.path.exists(multiclass_model_path):
            self.multiclass_model = DDoSFlowClassifier.load(multiclass_model_path)

        self.multi_class_labels = {
            0: "Benign",
            1: "HTTP_Flood",
            2: "SYN_Flood",
            3: "UDP_Flood"
        }
        
        self.stats = {
            "total_flows_inspected": 0,
            "benign_flows": 0,
            "attack_flows_detected": 0,
            "total_latency_us": 0.0,
            "blocked_ips": set()
        }

    def score_single_flow(self, flow_dict: Dict[str, Any], threshold: float = 0.50) -> Dict[str, Any]:
        """
        Inspect a single flow record extracted by router / SDN switch.
        Accepts dynamic decision threshold for custom operator sensitivity.
        """
        feature_order = self.rf_model.feature_names or ALL_FLOW_FEATURES
        feature_values = [float(flow_dict.get(feat, 0.0)) for feat in feature_order]
        X = np.array([feature_values])

        # Latency benchmark
        t_start = time.perf_counter()
        prob = self.rf_model.predict_proba(X)[0]
        inference_time_us = (time.perf_counter() - t_start) * 1_000_000.0

        attack_prob = float(prob[1]) if len(prob) > 1 else float(self.rf_model.predict(X)[0])
        is_attack = (attack_prob >= threshold)
        pred_label = 1 if is_attack else 0

        # Multi-class attack categorization if available
        attack_type = "Benign"
        if is_attack:
            if self.multiclass_model:
                m_pred = int(self.multiclass_model.predict(X)[0])
                attack_type = self.multi_class_labels.get(m_pred, "Attack")
            else:
                attack_type = flow_dict.get("Attack_Type", "Volumetric_DDoS")

        # Update telemetry stats
        self.stats["total_flows_inspected"] += 1
        self.stats["total_latency_us"] += inference_time_us
        if is_attack:
            self.stats["attack_flows_detected"] += 1
            src_ip = flow_dict.get("Src_IP", "198.51.100.1")
            self.stats["blocked_ips"].add(src_ip)
        else:
            self.stats["benign_flows"] += 1

        # Mitigation action
        mitigation_plan = None
        if is_attack:
            src_ip = flow_dict.get("Src_IP", "198.51.100.1")
            dst_port = int(flow_dict.get("Dst_Port", 80))
            proto = int(flow_dict.get("Protocol", 6))
            mitigation_plan = {
                "action": "BLOCK_AND_DROP",
                "target_ip": src_ip,
                "target_port": dst_port,
                "firewall_rules": generate_firewall_rule(src_ip, dst_port, proto, attack_type)
            }
        else:
            mitigation_plan = {
                "action": "FORWARD_ALLOWED",
                "target_ip": flow_dict.get("Src_IP", "192.168.1.10"),
                "firewall_rules": None
            }

        return {
            "prediction": "Attack" if is_attack else "Benign",
            "is_attack": is_attack,
            "attack_type": attack_type,
            "confidence": attack_prob if is_attack else (1.0 - attack_prob),
            "attack_probability": attack_prob,
            "latency_microseconds": round(inference_time_us, 2),
            "mitigation": mitigation_plan,
            "flow_features": flow_dict
        }

    def get_telemetry_stats(self) -> Dict[str, Any]:
        """Return engine operational telemetry."""
        total = max(self.stats["total_flows_inspected"], 1)
        return {
            "total_flows_inspected": self.stats["total_flows_inspected"],
            "benign_flows": self.stats["benign_flows"],
            "attack_flows_detected": self.stats["attack_flows_detected"],
            "attack_rate_pct": round((self.stats["attack_flows_detected"] / total) * 100, 2),
            "avg_latency_microseconds": round(self.stats["total_latency_us"] / total, 2),
            "total_blocked_ips_count": len(self.stats["blocked_ips"])
        }


def stream_flow_generator(
    csv_path: str,
    batch_size: int = 1,
    loop: bool = True
) -> Generator[Dict[str, Any], None, None]:
    """
    Simulates network flows arriving in real time from a network interface or SDN switch.
    """
    df = pd.read_csv(csv_path)
    indices = df.index.tolist()
    
    while True:
        np.random.shuffle(indices)
        for idx in indices:
            row = df.iloc[idx].to_dict()
            is_atk = bool(row.get("Binary_Label", 0) == 1)
            atk_type = row.get("Attack_Type", "Benign")
            row["Src_IP"] = generate_random_ip(is_attack=is_atk, attack_type=atk_type)
            yield row
        if not loop:
            break


if __name__ == "__main__":
    model_file = os.path.join(BASE_DIR, "models", "rf_ddos_model.joblib")
    multi_file = os.path.join(BASE_DIR, "models", "rf_multiclass_model.joblib")
    csv_file = os.path.join(BASE_DIR, "data", "raw", "network_flows.csv")

    engine = FlowMitigationEngine(model_file, multi_file)
    stream = stream_flow_generator(csv_file, loop=False)

    print("\n--- Simulating 5 Live Network Flow Records ---")
    for _ in range(5):
        flow = next(stream)
        result = engine.score_single_flow(flow)
        print(f"Flow Duration: {flow['Flow_Duration']}us | Pkts/s: {flow['Flow_Packets_Sec']} | "
              f"SYN: {flow['SYN_Flag_Count']} -> [{result['prediction']}] ({result['attack_type']}) "
              f"Conf: {result['confidence']*100:.1f}% | Latency: {result['latency_microseconds']}us")
        if result["is_attack"]:
            print(f"  --> MITIGATION TRIGGERED: {result['mitigation']['firewall_rules']['iptables']}")
    
    print("\nTelemetry:", engine.get_telemetry_stats())
